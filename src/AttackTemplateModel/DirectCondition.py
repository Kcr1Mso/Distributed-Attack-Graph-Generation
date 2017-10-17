# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from AttackTemplateModel.Condition import Condition

class DirectCondition(Condition):
    '''
    classdocs
    '''
    CPEId=''        #string

    def __init__(self, Category, ExistIn, CPEId):
        '''
        Constructor
        '''
        Condition.__init__(self,Category,ExistIn)
        self.CPEId=CPEId