# coding=gbk
'''
Created on 2017年10月16日

@author: RHy0ThoM
'''

import random,time,queue
from multiprocessing.managers import BaseManager 

task_queue=queue.Queue()

result_queue=queue.Queue()

