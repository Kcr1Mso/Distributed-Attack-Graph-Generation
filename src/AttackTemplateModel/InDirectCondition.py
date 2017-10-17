
# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from AttackTemplateModel.Condition import Condition

class InDirectCondition(Condition):
    '''
    classdocs
    '''
    ProductType=''      #enum

    def __init__(self, Category, ExistIn, ProductType):
        '''
        Constructor
        '''
        Condition.__init__(self,Category,ExistIn)
        self.ProductType=ProductType
        