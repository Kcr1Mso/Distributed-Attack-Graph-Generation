 # coding=gbk
'''
Created on 2017��10��24��

@author: RHy0ThoM
'''

from multiprocessing.managers import BaseManager
from queue import Queue
from AttackGraphCore.Job import Job

class Server:

    def __init__(self):
        # �ɷ���ȥ����ҵ����
        self.dispatched_job_queue = Queue()
        # ��ɵ���ҵ����
        self.finished_job_queue = Queue()

    def get_dispatched_job_queue(self):
        return self.dispatched_job_queue

    def get_finished_job_queue(self):
        return self.finished_job_queue

    def start(self):
        # ���ɷ���ҵ���к������ҵ����ע�ᵽ������
        BaseManager.register('get_dispatched_job_queue', callable=self.get_dispatched_job_queue)
        BaseManager.register('get_finished_job_queue', callable=self.get_finished_job_queue)

        # �����˿ں���������
        manager = BaseManager(address=('0.0.0.0', 8888), authkey='jobs')
        manager.start()

        # ʹ������ע��ķ�����ȡ����
        dispatched_jobs = manager.get_dispatched_job_queue()
        finished_jobs = manager.get_finished_job_queue()

        # ����һ���ɷ�10����ҵ���ȵ�10����ҵ��������󣬼������ɷ�10����ҵ
        job_id = 0
        while True:
            for i in range(0, 10):
                job_id = job_id + 1
                job = Job(job_id)
                print('Dispatch job: %s' % job.job_id)
                dispatched_jobs.put(job)

            while not dispatched_jobs.empty():
                job = finished_jobs.get(60)
                print('Finished Job: %s' % job.job_id)

        manager.shutdown()

if __name__ == "__main__":
    Server = Server()
    Server.start()
