# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''

from enum import Enum

class RelativeLocation(Enum):
    '''
    classdocs
    '''
    RelativeLocation=Enum('Attacker Application',
                          'Victim Application',
                          'Backend Application', 
                          'Intermediate Application'
                          )

    def __init__(self, params):
        '''
        Constructor
        '''
        