 # coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from AttackGraphStructure.AttackGraph import AttackGraph
from AttackGraphStructure.AttackElementNode import AttackGraphNode
from AttackTemplateModel.Vulnerability import Vulnerability

class PrivilegeConjunction:
    def __init__(self, x ='and'):
        self.Node = x

partialAttackGraph =  AttackGraph()                            # 部分攻击图 攻击图类
#更新攻击图
def UpdateAttackGraph(SP,REQPS,GPS,TSA):                       #
# 跨越搜索代理代码的全局变量
# SP可以是信息源的漏洞
# REQPS是必需的权限
# GPS是获得的特权
# TSA是目标软件应用
    if  isinstance(SP , Vulnerability):                        #漏洞   如何表示存在于？
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #创建漏洞利用节点
    else:
        exp = CreateInformationSourceUsageNode(SP,TSA)         #创建信息源使用节点
    if len(REQPS)>1:
        prjc = PrivilegeConjunction()                          #特权连接  类？
        partialAttackGraph.addNode(prjc)                       #部分攻击图 添加节点
        for reqp in REQPS :
            partialAttackGraph.addEdge(reqp,prjc)              #部分攻击图 添加边
    else:
        if len(REQPS) == 1:
            partialAttackGraph.addEdge(REQPS[0],exp)
    for gp in GPS :
        partialAttackGraph.addEdge(exp,gp)


#创建漏洞节点
def CreateVunlnerabilityExploitNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'VulnerabilityExploit'
    Node.CPE_ID = TSA.CPEId
    Node.CVE_ID = SP.CVEId
    Node.IPAddress = TSA.HostIPAddress
    Node.ApplicationName = TSA.name
    return Node

#创建信息源使用节点
def CreateInformationSourceUsageNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'InformationSource'
    Node.CPE_ID = TSA.CPEId
    Node.IPAddress = TSA.HostIPAddress
#Node.ApplicationName = TSA.name
    Node.InformationSourceName = SP.name
    return Node



