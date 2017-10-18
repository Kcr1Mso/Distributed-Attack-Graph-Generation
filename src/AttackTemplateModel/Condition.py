# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from AttackGraphStructure.Category import Category
from AttackTemplateModel.RelativeLocation import RelativeLocation

'''
A condition represents a right that can be gained on a software application.

A condition is independent from any IP network and does not specify an IP
address in its definition.
'''

class Condition(object):
    '''
    classdocs
    '''
    Category=Category     #enum
    ExistIn=RelativeLocation     #enum
    
    '''
    ExistIn represents the location of the software application on which the right is gained.
    The location is determined relative to the attacker and victim software application.It can
    be attacker software application,victim software application or an intermediate software application
    that is located between the attacker and victim application and can intercept the traffic between them.
    '''
    
    def __init__(self,Category,ExistIn):
        self.Category=Category
        self.ExistIn=ExistIn
