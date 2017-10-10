# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from NetworkModel.InformationSource import InformationSource

class CredentialStore(InformationSource):
    '''
    classdocs
    '''


    def __init__(self, name, ReferencedSoftware, Preconditions, Postconditions, params):
        '''
        Constructor
        '''
        InformationSource.__init__(self, name, ReferencedSoftware, Preconditions, Postconditions)