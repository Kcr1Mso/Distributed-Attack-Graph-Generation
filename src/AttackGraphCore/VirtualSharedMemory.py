# coding=gbk
'''
Created on 2017年10月16日

@author: RHy0ThoM
'''

import queue
from multiprocessing.managers import BaseManager

task_queue=queue.Queue()
result_queue=queue.Queue()

def QueueManager(BaseManager):
    pass

QueueManager.register('get_task_queue',callable=lambda:task_queue)
QueueManager.register('get_result_queue',callable=lambda:result_queue)



manager=QueueManager(address=('',5000),authkey=b'abc')

manager.start()

task=manager.get_task_queue()
result=manager.get_result_queue()

def WriteToSharedMemory(ip,ips):
    pass

def ReadAndUpdateSharedMemory():
    pass

def ReadFromSharedMemory(rqp):
    pass 