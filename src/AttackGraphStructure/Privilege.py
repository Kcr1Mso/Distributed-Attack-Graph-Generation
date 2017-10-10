# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from AttackGraphStructure.AttackElementNode import AttackElementNode

class Privilege(AttackElementNode):
    '''
    classdocs
    '''
    Category=''     #Enum

    def __init__(self,IPAddress, CPEId, ApplicationName, Category):
        '''
        Constructor
        '''

        self.Category=Category
        