# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from NetworkModel.NetworkInterface import NetworkInterface

class CommunicationLink(object):
    '''
    classdocs
    '''

    SourceNetworkInterface=NetworkInterface
    TargetNetworkInterface=NetworkInterface
    
    
    
    def __init__(self, SourceNetworkInterface,TargetNetworkInterface):
        '''
        Constructor
        '''
        self.SourceNetworkInterface=SourceNetworkInterface
        self.TargetNetworkInterface=TargetNetworkInterface
        