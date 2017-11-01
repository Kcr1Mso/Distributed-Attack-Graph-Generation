# coding=gbk
'''
Created on 2017��10��24��

@author: RHy0ThoM
'''

import time
from queue import Queue
from multiprocessing.managers import BaseManager
from AttackGraphCore.Job import Job


class Client:

    def __init__(self):
        # �ɷ���ȥ����ҵ����
        self.dispatched_job_queue = Queue()
        # ��ɵ���ҵ����
        self.finished_job_queue = Queue()

    def start(self):
        # ���ɷ���ҵ���к������ҵ����ע�ᵽ������
        BaseManager.register('get_dispatched_job_queue')
        BaseManager.register('get_finished_job_queue')

        # ����master
        server = '127.0.0.1'
        print('Connect to server %s...' % server)
        manager = BaseManager(address=(server, 8888), authkey='jobs')
        manager.connect()

        # ʹ������ע��ķ�����ȡ����
        dispatched_jobs = manager.get_dispatched_job_queue()
        finished_jobs = manager.get_finished_job_queue()

        # ������ҵ�����ؽ��������ֻ��ģ����ҵ���У����Է��ص��ǽ��յ�����ҵ
        while True:
            job = dispatched_jobs.get(timeout=1)
            print('Run job: %s ' % job.job_id)
            time.sleep(1)
            finished_jobs.put(job)

if __name__ == "__main__":
    Client = Client()
    Client.start()