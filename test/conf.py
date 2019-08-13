# -*- coding: utf-8 -*-

from configparser import ConfigParser
import sys

Conf = {}

try:
	config = ConfigParser()
	config.read('./etc/ymdrdau.ini')

	network = {}
	network['ip'] = config.get('local-net', 'ip')
	network['port'] = config.getint('local-net', 'port')
	Conf['local-net'] = network
	
	log = {}
	log['path'] = config.get('log', 'path')
	Conf['log'] = log
	
	'''
	security = {}
	security['gPwd'] = config.get('security', 'secret')
	security['gAESKey'] = config.get('security', 'aes_key')
	security['gAESIV'] = config.get('security', 'aes_iv')
	Conf['security'] = security

	named = {}
	named['home'] = config.get('named-conf', 'home')
	named['switch'] = config.get('named-conf', 'switch')
	named['std'] = config.get('named-conf', 'std')
	named['local'] = config.get('named-conf', 'local')
	Conf['named-conf'] = named

	source ={}
	source['root_source'] = config.get('source', 'root_source')
	source['standard_source'] = config.get('source', 'standard_source')
	source['exigency_source'] = config.get('source', 'exigency_source')
	Conf['source'] = source

	server ={}
	server['dns_id'] = config.get('server', 'dns_id')
	server['zone_room_id'] = config.get('server', 'zone_room_id')
	server['server_id'] = config.get('server', 'server_id')
	Conf['server'] = server
	'''

except Exception as e:
	print('load conf error:',e)
	sys.exit(1)


