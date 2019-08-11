#!/usr/bin/python3
# -*- coding: utf-8 -*-

from conf import Conf
import time, logging, logging.handlers
import multiprocessing
import sys, daemon

#Conf = {'local-net': {'ip': '0.0.0.0', 'port': 18899}, 'log': {'path': 'test.log'}}

def upload_task():
	print(Conf)
	i = 0
	while True:
		time.sleep(1)
		logger.info('test')
		i+=1
		print(i)

try:
	logger = logging.getLogger('ymdrdau')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler(Conf['log']['path'])
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)
except Exception as e:
	print('load conf error:',e)
	sys.exit(1)



if '__main__' == __name__:
	print(Conf)
	#with daemon.DaemonContext():
	if True:
		logger.info('main process start at: %s' % time.ctime())
		while True:
			p1 = multiprocessing.Process(target = upload_task, args = ())
			p1.start()
			p1.join()

		logger.info('main process end at: %s' % time.ctime())
 
'''
with daemon.DaemonContext():
	logger = logging.getLogger('ymdrdau')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler(Conf['log']['path'])
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	print(Conf)

	while True:
		p1 = multiprocessing.Process(target = upload_task, args = ())
		p1.start()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())

'''
