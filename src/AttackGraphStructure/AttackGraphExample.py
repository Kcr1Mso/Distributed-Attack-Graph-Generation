# coding=gbk
'''
Created on 2017年9月29日

@author: RHy0ThoM
'''

from AttackGraphStructure.Privilege import Privilege
from AttackGraphStructure.AttackGraph import AttackGraph
from AttackGraphStructure.AttackGraphEdge import AttackGraphEdge
from AttackGraphStructure.VExploit import VExploit

privilege_1=Privilege(
                      '192.168.0.2',
                      'cpe:/o:microsoft:windows_xp::sp2',
                      'Host 1 windows XP',
                      'File Access'    
    )

vexploit_1=VExploit('75.62.2.22',
                    'CVE-2010-3004',
                    'cpe:/o:microsoft:internet_explorer:10',
                    'Host 2 Internet Explorer',
                    )

vexploit_2=VExploit('75.62.2.22',
                    'CVE-2011-3644',
                    'cpe:/o:microsoft:thunderbird:17.0.2',
                    'Host 2 Mozilla Thunderbird',
    )

privilege_2=Privilege(
                      '192.168.0.2',
                      'cpe:/o:microsoft:windows_xp::sp2',
                      'Host 1 windows XP',
                      'File Access'
    )

attackgraphedge_1=AttackGraphEdge()
attackgraphedge_2=AttackGraphEdge()
attackgraphedge_1.SourceNode=privilege_1
attackgraphedge_1.TargetNode=vexploit_1
attackgraphedge_2.SourceNode=privilege_1
attackgraphedge_2.TargetNode=vexploit_2

AttackGraph_1=AttackGraph()
AttackGraph_1.Privilege=privilege_1
AttackGraph_1.Privilege.OutEdge=[attackgraphedge_1,
                                 attackgraphedge_2
                                 ]
AttackGraph_1.AttackGraphEdge=attackgraphedge_1
print(AttackGraph_1.Privilege.ApplicationName)
print(AttackGraph_1.Privilege.Category)
print(AttackGraph_1.AttackGraphEdge.SourceNode.OutEdge)