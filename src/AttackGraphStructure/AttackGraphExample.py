# coding=gbk
'''
Created on 2017年9月29日

@author: RHy0ThoM
'''

from AttackGraphStructure.Privilege import Privilege
from AttackGraphStructure.AttackGraphEdge import AttackGraphEdge
from AttackGraphStructure.AttackGraph import AttackGraph


privilege_1=Privilege(
                      '192.168.0.2',
                      'cpe:/o:microsoft:windows_xp::sp2',
                      'Host 1 windows XP',
                      'File Access'    
    )

privilege_2=Privilege(
                      '192.168.0.2',
                      'cpe:/o:microsoft:windows_xp::sp2',
                      'Host 1 windows XP',
                      'File Access'
    )

attackgraphedge_1=AttackGraphEdge()
attackgraphedge_1.SourceNode=privilege_1
attackgraphedge_1.TargetNode=privilege_2

AttackGraph_1=AttackGraph()
AttackGraph_1.Privilege=privilege_1
AttackGraph_1.AttackGraphEdge=attackgraphedge_1
print(AttackGraph_1.Privilege.ApplicationName)
print(AttackGraph_1.Privilege.Category)
print(AttackGraph_1.AttackGraphEdge.SourceNode)
print(AttackGraph_1.AttackGraphEdge.TargetNode)