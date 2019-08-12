#!/usr/bin/python3
# -*- coding: utf-8 -*-

from configparser import ConfigParser
import time, logging, logging.handlers
import multiprocessing, random, string, uuid, base64, hashlib, zlib
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
	security['pwd'] = config.get('security', 'pwd')
	security['aeskey'] = config.get('security', 'aeskey')
	security['aesiv'] = config.get('security', 'aesiv')
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


def get_recursion_iter_data():
	return 'test_data'


# '2' '54'
def upload_data(subsysid, intfid, json_data):
	
	while True:
		try:
			hashMode        = conf['security']['hash_mode']
			encryptMode     = conf['security']['encrypt_mode']
			compressMode    = conf['security']['compress_mode']
			
			url                 = 'https://'+conf['upload']['ip']+':'+conf['upload']['port']+'/'+intfid+'/'+conf['server']['orgid']
			randVal             = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
			lPwd                = bytes(conf['security']['pwd'], 'utf-8')
			commandVersion      = 'v0.1'
			data                = bytes(json_data,'utf-8')
			
			if hashMode == '0':
				_hashed_pwd = lPwd + randVal
				pwdHash = base64.b64encode(_hashed_pwd)
			elif hashMode == '1':
				_hashed_pwd = hashlib.md5(lPwd + randVal).digest()
				pwdHash = base64.b64encode(_hashed_pwd)
			elif hashMode == '2':
				_hashed_pwd = hashlib.sha1(lPwd + randVal).digest()
				pwdHash = base64.b64encode(_hashed_pwd)
			elif hashMode == '3':
				_hashed_pwd = hashlib.sha256(lPwd + randVal).digest()
				pwdHash = base64.b64encode(_hashed_pwd)
			elif hashMode == '11':
				pass
			else :
				_hashed_pwd = lPwd + randVal
				pwdHash = base64.b64encode(_hashed_pwd)
			
			if compressMode == '0': _compressed_data = data
			elif compressMode == '1': _compressed_data = zlib.compress(data)

            if (confDict['listen_aes_key'] is not None) and (encryptMode == '1'): 
                e = AESCipher(confDict['listen_aes_key'].encode('utf-8'), confDict['listen_aes_iv'].encode('utf-8'))
                _encrypted_data = e.encrypt(_compressed_data)
            elif encryptMode == '2'   : pass
            elif encryptMode == '11'  : pass
            elif encryptMode == '12'  : pass
            elif encryptMode == '13'  : pass
            elif encryptMode == '14'  : pass
            else: _encrypted_data = _compressed_data
                   
            data = base64.b64encode(_encrypted_data)

            if hashMode == '0':  
                _hashed_data = _compressed_data + lPwd
                dataHash = base64.b64encode(_hashed_data)
            elif hashMode == '1':  
                _hashed_data = hashlib.md5(_compressed_data + lPwd).digest()
                dataHash = base64.b64encode(_hashed_data)
            elif hashMode == '2':  
                _hashed_data = hashlib.sha1(_compressed_data + lPwd).digest()
                dataHash = base64.b64encode(_hashed_data)
            elif hashMode == '3':  
                _hashed_data = hashlib.sha256(_compressed_data + lPwd).digest()
                dataHash = base64.b64encode(_hashed_data)
            elif hashMode == '11': pass
            else :  
                _hashed_pwd = lPwd + randVal
                pwdHash = base64.b64encode(_hashed_pwd)

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
            
            ret =requests.post(url, json.dumps(requestData), verify=False)
            retData = json.loads(ret.text)
            if retData.get('errorCode') == '0':
                LOG.info('{} to uploadToDMS {} success'.format(UPLOAD, uploadType))
                #直到上传数据成功为止
                break
            else:
                LOG.error('{} {}Failed to uploadToDMS {} {}'.format(UPLOAD,CERROR,uploadType,ret.text))
                sleep(5)
                continue

        except Exception as r:
            r = traceback.format_exc()
            LOG.error('{} {}Failed to uploadToDMS {} {}{}'.format(UPLOAD,CERROR,uploadType,r,CEND))
            sleep(5)
            continue



def upload_task():
	while True:
		time.sleep(1)
		print(111111)
		logger.info(111111)
		# get_data()
		# upload_data


#with daemon.DaemonContext():
if __name__ == '__main__':

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p1 = multiprocessing.Process(target = upload_task, args = ())
		p1.start()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())

