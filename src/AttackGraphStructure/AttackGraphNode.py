# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from AttackGraphStructure.AttackGraphEdge import AttackGraphEdge
class AttackGraphNode(object):
    '''
    classdocs
    '''
    InEdge=[]       #list
    
    OutEdge=[]      #list

    def __init__(self):
        '''
        Constructor
        '''
        self.InEdges=AttackGraphEdge()
        self.OutEdges=AttackGraphEdge()