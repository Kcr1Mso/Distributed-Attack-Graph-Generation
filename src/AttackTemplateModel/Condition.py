# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''

from AttackGraphStructure.Category import Category
from AttackTemplateModel.RelativeLocation import RelativeLocation

class Condition(object):
    '''
    classdocs
    '''
    Category=Category     #enum
    ExistIn=RelativeLocation     #enum
    
    def __init__(self,Category,ExistIn):
        self.Category=Category
        self.ExistIn=RelativeLocation
