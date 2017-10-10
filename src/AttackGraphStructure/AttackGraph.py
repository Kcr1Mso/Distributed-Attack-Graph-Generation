# coding=gbk
'''
Created on 2017年10月9日

@author: RHy0ThoM
'''
from AttackGraphStructure.Privilege import Privilege
from AttackGraphStructure.PrivilegeConjunctionNode import PrivilegeConjunctionNode
from AttackGraphStructure.VExploit import VExploit
from AttackGraphStructure.ISUsage import ISUsage
from AttackGraphStructure.AttackGraphEdge import AttackGraphEdge

class AttackGraph(object):
    '''
    classdocs
    '''
    Privilege=Privilege
    PrivilegeConjunctionNode=PrivilegeConjunctionNode
    VExploit=VExploit
    ISUsage=ISUsage
    AttackGraphEdge=AttackGraphEdge

    def __init__(self):
        '''
        Constructor
        '''
        pass
        