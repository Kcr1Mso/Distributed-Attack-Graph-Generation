# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from AttackGraphStructure.AttackGraphNode import AttackGraphNode

class AttackGraphEdge(object):
    '''
    classdocs
    '''
    
    SourceNode=AttackGraphNode
    TargetNode=AttackGraphNode
    
    '''
    SourceNode denotes the source and TargetNode denotes the target node for the edge e. 
    '''
    
    def __init__(self):
        '''
        Constructor
        '''
        self.SourceNode=AttackGraphNode()
        self.TargetNode=AttackGraphNode()