# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''

from AttackGraphStructure.Category import Category
from AttackTempleModel.RelativeLocation import RelativeLocation

class Condition(object):
    '''
    classdocs
    '''
    Category=''     #enum
    RelativeLocation=''     #enum
    
    def __init__(self,Category,RelativeLocation):
        self.Category=Category
        self.RelativeLocation=RelativeLocation
