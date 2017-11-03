 # coding=gbk
'''
Created on 2017��10��24��

@author: RHy0ThoM
'''

import queue
from multiprocessing.managers import BaseManager
import random

# ��������Ķ���:
task_queue = queue.Queue()
# ���ս���Ķ���:
result_queue = queue.Queue()

# ��BaseManager�̳е�QueueManager:
class QueueManager(BaseManager):
    pass

# ������Queue��ע�ᵽ������, callable����������Queue����:
QueueManager.register('get_task_queue', callable=lambda: task_queue)
QueueManager.register('get_result_queue', callable=lambda: result_queue)
# �󶨶˿�5000, ������֤��'abc':
manager = QueueManager(address=('10.1.112.30', 5000), authkey=b'abc')
# ����Queue:
manager.start()
# ���ͨ��������ʵ�Queue����:
task = manager.get_task_queue()
result = manager.get_result_queue()
# �ż��������ȥ:
for i in range(10):
    n = random.randint(0, 10000)
    print('Put task %d...' % n)
    task.put(n)
# ��result���ж�ȡ���:
print('Try get results...')
for i in range(10):
    r = result.get(timeout=60)
    print('Result: %s' % r)
# �ر�:
manager.shutdown()
print('master exit.')
