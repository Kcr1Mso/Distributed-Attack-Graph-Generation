# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''

from asyncio.locks import Condition

class DirectCondition(Condition):
    '''
    classdocs
    '''
    CPEId=''        #string

    def __init__(self, Category, RelativeLocation, CPEId):
        '''
        Constructor
        '''
        Condition.__init__(self,Category,RelativeLocation)
        self.CPEId=CPEId