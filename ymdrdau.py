#!/usr/bin/python3
# -*- coding: utf-8 -*-

from configparser import ConfigParser
import time, logging, logging.handlers, json, requests
import multiprocessing, random, string, uuid, base64, hashlib, zlib
from Crypto.Cipher import AES
from time import sleep
import sys, daemon

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
	
	upload = {}
	upload['ip'] = config.get('upload', 'ip')
	upload['port'] = config.get('upload', 'port')
	conf['upload'] = upload

	server = {}
	server['orgid'] = config.get('server', 'orgid')
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
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

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


def get_recursion_iter_data():
	return 'test_data'


# '2' '54' json_str_data
def upload_data(subsysid, intfid, json_data):
	
	while True:
		try:
			hashMode        = conf['security']['hash_mode']
			encryptMode     = conf['security']['encrypt_mode']
			compressMode    = conf['security']['compress_mode']
			
			url                 = 'https://'+conf['upload']['ip']+':'+conf['upload']['port']+'/'+intfid+'/'+conf['server']['orgid']
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
				'orgId'         : conf['server']['orgid'],
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

			print(requestData)
            
			ret = requests.post(url, json.dumps(requestData), verify=False)
			retData = json.loads(ret.text)
			if retData.get('errorCode') == '0':
				logger.info('upload recursion iter data success!!')
				break
			else:
				logger.warning('upload recursion iter data failed : {}'.ret.text)
				sleep(5)
				continue

		except Exception as e:
			print(e)
			logger.warning(e)
			sleep(5)
			continue



def upload_task():
	while True:
		time.sleep(1)
		print(111111)
		logger.info(111111)
		# get_data()
		# upload_data
		upload_data('2', '54', '{1:1,2:2}')


#with daemon.DaemonContext():
if __name__ == '__main__':

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p1 = multiprocessing.Process(target = upload_task, args = ())
		p1.start()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())

