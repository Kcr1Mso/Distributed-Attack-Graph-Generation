# coding=gbk
'''
Created on 2017��10��24��

@author: RHy0ThoM
'''

import queue
import time, sys
from multiprocessing.managers import BaseManager
from AttackGraphCore.DepthFirstSearch import PERFORMDFS
from NetworkModel.HyperGraph import HyperGraph
from AttackGraphStructure.AttackGraph import AttackGraph


# �������Ƶ�QueueManager:111
class QueueManager(BaseManager):
    pass

# �������QueueManagerֻ�������ϻ�ȡQueue������ע��ʱֻ�ṩ����:
QueueManager.register('get_task_queue')
QueueManager.register('get_result_queue')

# ���ӵ���������Ҳ��������task_master.py�Ļ���:
server_addr = '10.1.112.30'
print('Connect to server %s...' % server_addr)
# �˿ں���֤��ע�Ᵽ����task_master.py���õ���ȫһ��:
m = QueueManager(address=(server_addr, 5000), authkey=b'abc')
# ����������:
m.connect()
# ��ȡQueue�Ķ���:
task = m.get_task_queue()
result = m.get_result_queue()
# ��task����ȡ����,���ѽ��д��result����:
TargetNetwork=HyperGraph( )
IPRGS=[]
partialAttackGraph=AttackGraph()
try:
    PERFORMDFS(TargetNetwork, IPRGS)
    time.sleep(1)
    result.put()
except queue.Empty:
    print('task queue is empty.')
# �������:
print('worker exit.')