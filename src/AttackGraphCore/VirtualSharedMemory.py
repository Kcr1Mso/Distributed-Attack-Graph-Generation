# coding=gbk
'''
Created on 2017年10月16日

@author: RHy0ThoM
'''

from AttackGraphStructure.Privilege import Privilege

class PrivilegeStatus:
    def __init__(self, x = False):
        self.expanded = x
    def setExpanded(self, x = False):
        self.expanded = x

class Memory:
    def __init__(self,x,y):
        self.privileges=x
        self.status=y

SharedMemory = []

def WriteToSharedMemory(ip,ips):
    SharedMemory.append(Memory(ip,ips))

def ReadFromSharedMemory(ip):
    for memory in SharedMemory:
        if memory.privileges == ip:
            return memory.status
    else:
        return PrivilegeStatus()

def ReadAndUpdateSharedMemory(ip,ips):
    for memory in SharedMemory:
        if memory.privileges == ip:
            x = memory.status
            memory.status = ips
            return x
    else:
        return PrivilegeStatus()