# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from AttackGraphStructure.AttackElementNode import AttackElementNode

class ISUsage(AttackElementNode):
    '''
    classdocs
    '''
    ISUsage=''      #string

    def __init__(self, IPAddress, CPEId, ApplicationName, ISUsage):
        '''
        Constructor
        '''
        AttackElementNode.__init__(self, IPAddress, CPEId, ApplicationName)
        self.ISUsage=ISUsage