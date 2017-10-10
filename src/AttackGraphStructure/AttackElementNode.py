# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from AttackGraphStructure.AttackGraphNode import AttackGraphNode

class AttackElementNode(AttackGraphNode):
    '''
    classdocs
    '''
    IPAddress=''     #string
    CPEId=''        #string
    ApplicationName=''      #string
    
    def __init__(self, IPAddress, CPEId, ApplicationName):
        '''
        Constructor
        '''

        self.IPAddress=IPAddress
        self.CPEId=CPEId
        self.ApplicationName=ApplicationName
        