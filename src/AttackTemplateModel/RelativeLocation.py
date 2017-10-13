# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from enum import Enum

class RelativeLocation(Enum):
    '''
    classdocs
    '''
    RelativeLocation=Enum('AttackerApplication',
                          'VictimApplication',
                          'BackendApplication', 
                          'IntermediateApplication'
                          )

    def __init__(self, params):
        '''
        Constructor
        '''
        