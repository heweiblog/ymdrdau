#!/usr/bin/python3
# -*- coding: utf-8 -*-

from configparser import ConfigParser
import time, logging, logging.handlers, json, requests, subprocess, urllib3
import multiprocessing, random, string, uuid, base64, hashlib, zlib, dns, dns.resolver
from Crypto.Cipher import AES
from time import sleep
from iscpy.iscpy_dns.named_importer_lib import *
import sys, daemon

urllib3.disable_warnings()

conf = {}

try:
	config = ConfigParser()
	config.read('./etc/ymdrdau.ini')

	network = {}
	network['ip'] = config.get('local-net', 'ip')
	network['port'] = config.getint('local-net', 'port')
	conf['local-net'] = network
	
	log = {}
	log['path'] = config.get('log', 'path')
	conf['log'] = log

	named = {}
	named['dnstap_file'] = config.get('named', 'dnstap_file')
	named['local_root'] = config.get('named', 'local_root')
	conf['named'] = named
	
	upload = {}
	upload['ip'] = config.get('upload', 'ip')
	upload['port'] = config.get('upload', 'port')
	upload['delay'] = config.getint('upload', 'delay')
	conf['upload'] = upload

	server = {}
	server['org_id'] = config.get('server', 'org_id')
	server['area_id'] = config.get('server', 'area_id')
	conf['server'] = server

	security = {}
	security['user_pwd'] = config.get('security', 'user_pwd')
	security['data_pwd'] = config.get('security', 'data_pwd')
	security['aes_key'] = config.get('security', 'aes_key')
	security['aes_iv'] = config.get('security', 'aes_iv')
	security['hash_mode'] = config.get('security', 'hash_mode')
	security['encrypt_mode'] = config.get('security', 'encrypt_mode')
	security['compress_mode'] = config.get('security', 'compress_mode')
	conf['security'] = security

	print(conf)

	logger = logging.getLogger('ymdrdau')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler(conf['log']['path'])
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s|%(lineno)d|%(levelname)s|%(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	share_delay = multiprocessing.Value('d', conf['upload']['delay'])

except Exception as e:
	print('load conf error:',e)
	sys.exit(1)


class AESCipher:
	def __init__(self, key, iv):
		self.key = key 
		self.iv = iv 
	def __pad(self, text):
		text_length = len(text)
		amount_to_pad = AES.block_size - (text_length % AES.block_size)
		if amount_to_pad == 0:
			amount_to_pad = AES.block_size
		pad = chr(amount_to_pad)
		return text + (pad * amount_to_pad).encode('utf-8')
	def __unpad(self, text):
		pad = text[-1]
		return text[:-pad]
	def encrypt(self, raw):
		raw = self.__pad(raw)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return cipher.encrypt(raw)
	def decrypt(self, enc):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv )
		return self.__unpad(cipher.decrypt(enc))#.decode("utf-8"))


def get_root_copy_list():
	root_local_file = conf['named']['local_root']
	try:
		with open(root_local_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['server-addresses']
			root_copy_list = []
			for k in servers:
				root_copy_list.append(k)
			return root_copy_list
				
	except Exception as e:
		logger.error('get root copy list error:'+str(e))
	return []


def get_recursion_iter_data():
	dnstap_file = conf['named']['dnstap_file']
	target_file = '/tmp/root_zone.txt'
	root_copy_list = get_root_copy_list()
	root_ip_list = [
		'202.12.27.33',
		'2001:dc3::35',
		'199.9.14.201',
		'2001:500:200::b',
		'192.33.4.12',
		'2001:500:2::c',
		'199.7.91.13',
		'2001:500:2d::d',
		'192.203.230.10',
		'2001:500:a8::e',
		'192.5.5.241',
		'2001:500:2f::f',
		'192.112.36.4',
		'2001:500:12::d0d',
		'198.97.190.53',
		'2001:500:1::53',
		'198.41.0.4',
		'2001:503:ba3e::2:30',
		'192.36.148.17',
		'2001:7fe::53',
		'192.58.128.30',
		'2001:503:c27::2:30',
		'193.0.14.129',
		'2001:7fd::1',
		'199.7.83.42',
		'2001:500:9f::42'
	] + root_copy_list 

	root_list = {
		'm': ['202.12.27.33','2001:dc3::35'],
		'b': ['199.9.14.201','2001:500:200::b'],
		'c': ['192.33.4.12','2001:500:2::c'],
		'd': ['199.7.91.13','2001:500:2d::d'],
		'e': ['192.203.230.10','2001:500:a8::e'],
		'f': ['192.5.5.241','2001:500:2f::f'],
		'g': ['192.112.36.4','2001:500:12::d0d'],
		'h': ['198.97.190.53','2001:500:1::53'],
		'a': ['198.41.0.4','2001:503:ba3e::2:30'],
		'i': ['192.36.148.17','2001:7fe::53'],
		'j': ['192.58.128.30','2001:503:c27::2:30'],
		'k': ['193.0.14.129','2001:7fd::1'],
		'l': ['199.7.83.42','2001:500:9f::42'],
		'root_copy': root_copy_list
	}

	root_request_stat = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'f':0, 'g':0, 'h':0, 'i':0, 'j':0, 'k':0, 'l':0, 'm':0, 'root_copy':0}
	delay_stat = root_request_stat.copy()
	root_response_stat = root_request_stat.copy()

	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except Exception as e:
		logger.error('get recursion stat dnstap-read error:'+str(e))
		return '' 

	root_request,root_response = {},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				if l[5].split(':')[-1] == '53':
				#after add root 13 delay stat
					if '->' in l:
						domain = l[5].split(':53')[0]
						if domain in root_ip_list:
							if domain in root_request:
								root_request[domain] += 1
							else:
								root_request[domain] = 1
					elif '<-' in l:
						domain = l[5].split(':53')[0]
						if domain in root_ip_list:
							if domain in root_response:
								root_response[domain] += 1
							else:
								root_response[domain] = 1

		for k in root_list:
			for ip in root_list[k]:
				if ip in root_request:
					root_request_stat[k] += root_request[ip]
				if ip in root_response:
					root_response_stat[k] += root_response[ip]
				
		dns_query = dns.message.make_query('.', 'NS')
		for k in root_list:
			if root_response_stat[k] > 0 and len(root_list[k]) > 0: 
				try:
					begin = datetime.datetime.now()
					response = dns.query.udp(dns_query, root_list[k][0], port = 53,timeout = 2)
					end = datetime.datetime.now()
					delay_stat[k] = (end - begin).microseconds//1000
				except Exception as e:
					logger.warning(k+' get root delay error:'+str(e))
		
		iter_data = {
			'nodeId': '03211101',
			'rootList':[		
				{
					'ns':'a.root-servers.net',
					'queryCnt':str(root_request_stat['a']),
					'sucRespCnt':str(root_response_stat['a']),
					'resolveAvgT':str(delay_stat['a'])
				},
				{
					'ns':'b.root-servers.net',
					'queryCnt':str(root_request_stat['b']),
					'sucRespCnt':str(root_response_stat['b']),
					'resolveAvgT':str(delay_stat['d'])
				},
				{
					'ns':'c.root-servers.net',
					'queryCnt':str(root_request_stat['c']),
					'sucRespCnt':str(root_response_stat['c']),
					'resolveAvgT':str(delay_stat['c'])
				},
				{
					'ns':'d.root-servers.net',
					'queryCnt':str(root_request_stat['d']),
					'sucRespCnt':str(root_response_stat['d']),
					'resolveAvgT':str(delay_stat['d'])
				},
				{
					'ns':'e.root-servers.net',
					'queryCnt':str(root_request_stat['e']),
					'sucRespCnt':str(root_response_stat['e']),
					'resolveAvgT':str(delay_stat['e'])
				},
				{
					'ns':'f.root-servers.net',
					'queryCnt':str(root_request_stat['f']),
					'sucRespCnt':str(root_response_stat['f']),
					'resolveAvgT':str(delay_stat['f'])
				},
				{
					'ns':'g.root-servers.net',
					'queryCnt':str(root_request_stat['g']),
					'sucRespCnt':str(root_response_stat['g']),
					'resolveAvgT':str(delay_stat['g'])
				},
				{
					'ns':'h.root-servers.net',
					'queryCnt':str(root_request_stat['h']),
					'sucRespCnt':str(root_response_stat['h']),
					'resolveAvgT':str(delay_stat['h'])
				},
				{
					'ns':'i.root-servers.net',
					'queryCnt':str(root_request_stat['i']),
					'sucRespCnt':str(root_response_stat['i']),
					'resolveAvgT':str(delay_stat['i'])
				},
				{
					'ns':'j.root-servers.net',
					'queryCnt':str(root_request_stat['j']),
					'sucRespCnt':str(root_response_stat['j']),
					'resolveAvgT':str(delay_stat['j'])
				},
				{
					'ns':'k.root-servers.net',
					'queryCnt':str(root_request_stat['k']),
					'sucRespCnt':str(root_response_stat['k']),
					'resolveAvgT':str(delay_stat['k'])
				},
				{
					'ns':'l.root-servers.net',
					'queryCnt':str(root_request_stat['l']),
					'sucRespCnt':str(root_response_stat['l']),
					'resolveAvgT':str(delay_stat['l'])
				},
				{
					'ns':'m.root-servers.net',
					'queryCnt':str(root_request_stat['m']),
					'sucRespCnt':str(root_response_stat['m']),
					'resolveAvgT':str(delay_stat['m'])
				}
			],
			'rcopyRCnt':str(root_response_stat['root_copy']),
			'rcopyRAvgT':str(delay_stat['root_copy']),
			'tldList':[
				{
					'tldName':'com',
					'queryCnt':'123',
					'sucRespCnt':'122',
					'resolveAvgT':'66'
				},
				{
					'tldName':'net',
					'queryCnt':'123',
					'sucRespCnt':'122',
					'resolveAvgT':'66'
				},
				{
					'tldName':'org',
					'queryCnt':'123',
					'sucRespCnt':'122',
					'resolveAvgT':'66'
				},
				{
					'tldName':'cn',
					'queryCnt':'123',
					'sucRespCnt':'122',
					'resolveAvgT':'66'
				}
			],
			'statPeriod':'300',
			'timeStamp':time.strftime('%Y-%m-%dT%H:%M:%SZ')
		}

		data = json.dumps(iter_data,ensure_ascii=False,indent=4)
		print(data)
		logger.info(data)

		#return json.dumps(iter_data)
		return data

	except Exception as e:
		logger.warning('get recursion root 13 stat error:'+str(e))

	return '' 


# '2' '54' json_str_data
def upload_data(subsysid, intfid, json_data):
	
	while True:
		try:
			hashMode        = conf['security']['hash_mode']
			encryptMode     = conf['security']['encrypt_mode']
			compressMode    = conf['security']['compress_mode']
			
			url                 = 'https://'+conf['upload']['ip']+':'+conf['upload']['port']+'/'+intfid+'/'+conf['server']['org_id']
			randVal             = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
			user_pwd            = bytes(conf['security']['user_pwd'], 'utf-8')
			data_pwd            = bytes(conf['security']['data_pwd'], 'utf-8')
			commandVersion      = 'v0.1'
			data                = bytes(json_data,'utf-8')
			
			if hashMode == '0':
				_hashed_pwd = user_pwd + randVal
			elif hashMode == '1':
				_hashed_pwd = hashlib.md5(user_pwd + randVal).hexdigest()
			elif hashMode == '2':
				_hashed_pwd = hashlib.sha1(user_pwd + randVal).hexdigest()
			elif hashMode == '3':
				_hashed_pwd = hashlib.sha256(user_pwd + randVal).hexdigest()
			elif hashMode == '11': pass
			else :
				_hashed_pwd = user_pwd + randVal

			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
			
			if compressMode == '0': _compressed_data = data
			elif compressMode == '1': _compressed_data = zlib.compress(data)
			
			if encryptMode == '1':
				e = AESCipher(conf['security']['aes_key'].encode('utf-8'), conf['security']['aes_iv'].encode('utf-8'))
				_encrypted_data = e.encrypt(_compressed_data)
			elif encryptMode == '2'   : pass
			elif encryptMode == '11'   : pass
			elif encryptMode == '12'   : pass
			elif encryptMode == '13'   : pass
			elif encryptMode == '14'   : pass
			else: _encrypted_data = _compressed_data
			
			data = base64.b64encode(_encrypted_data)
			
			if hashMode == '0':
				_hashed_data = _compressed_data + data_pwd
			elif hashMode == '1':
				_hashed_data = hashlib.md5(_compressed_data + data_pwd).hexdigest()
			elif hashMode == '2':
				_hashed_data = hashlib.sha1(_compressed_data + data_pwd).hexdigest()
			elif hashMode == '3':
				_hashed_data = hashlib.sha256(_compressed_data + data_pwd).hexdigest()
			elif hashMode == '11': pass
			else :
				_hashed_pwd = data_pwd + randVal
			
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
			
			requestData = {
				'uuid'          : str(uuid.uuid4()),
				'orgId'         : conf['server']['org_id'],
				'subsysId'      : subsysid,
				'intfId'        : intfid,
				'intfVer'       : commandVersion,
				'timeStamp'     : time.strftime('%Y-%m-%dT%H:%M:%SZ'),
				'randVal'       : randVal.decode(),
				'pwdHash'       : pwdHash.decode(),
				'encryptMode'   : encryptMode,
				'hashMode'      : hashMode,
				'compressMode'  : compressMode,
				'dataTag'       : '0',
				'data'          : data.decode(),
				'dataHash'      : dataHash.decode()
			}

			#print(requestData)
			data = json.dumps(requestData,ensure_ascii=False,indent=4)
			print(data)
			#logger.info(requestData)
			logger.info(data)
            
			ret = requests.post(url, json.dumps(requestData), verify=False)
			retData = json.loads(ret.text)
			if retData.get('errorCode') == '0':
				logger.info('upload recursion iter data success!!')
				break
			else:
				logger.warning('upload recursion iter data failed : {}'.format(ret.text))
				sleep(5)
				continue

		except Exception as e:
			print('catch a exception: {}'.format(e))
			logger.warning('catch a exception: {}'.format(e))
			sleep(5)
			continue



def upload_task():
	while True:
		# int(share_delay.value) 根据周期统计
		# sleep(conf['upload']['delay'])
		sleep(2)
		print(111111)
		data = get_recursion_iter_data()
		upload_data('2', '54', data)


#if __name__ == '__main__':
with daemon.DaemonContext():

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p1 = multiprocessing.Process(target = upload_task, args = ())
		p1.start()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())

