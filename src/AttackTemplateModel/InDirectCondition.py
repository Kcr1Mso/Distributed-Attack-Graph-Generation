
# coding=gbk
'''
Created on 2017��9��26��

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
        
        '''
        The product types are defined in the system.A product type can be mail server,mail client,web server,web client,
        ftp client,database server application,etc.
        '''
        