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
def UpdateAttackGraph(SP,reqprgs,GPS,TSA):                       #
# 跨越搜索代理代码的全局变量
# SP可以是信息源的漏洞
# REQPS是必需的权限
# GPS是获得的特权
# TSA是目标软件应用
    print(isinstance(SP , Vulnerability))
    if  isinstance(SP , Vulnerability):                        #漏洞   如何表示存在于？
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #创建漏洞利用节点
        print('----------isinstance---------------')
    else:
        print('------------informationsoucernode----------------')
        exp = CreateInformationSourceUsageNode(SP,TSA)         #创建信息源使用节点
    partialAttackGraph.addNode(exp)
    print('-----------REQPS--------------------')
    print(reqprgs)
    print('------------------------------------')
    try:
        if len(reqprgs)>1:
            print('----------reqps-----------------')
            prjc = PrivilegeConjunction()                          #特权连接  类？
            partialAttackGraph.addNode(prjc)                       #部分攻击图 添加节点
            for reqp in REQPS :
                partialAttackGraph.addEdge(reqp,prjc)              #部分攻击图 添加边
        else:
            print('----------reqps!!!!-----------------')
            if len(reqprgs) == 1:
                partialAttackGraph.addEdge(reqprgs[0],exp)
    except TypeError:
        print('TypeError')
    for gp in GPS :
        partialAttackGraph.addEdge(exp,gp)
    print(partialAttackGraph.Node)
    print(partialAttackGraph.Edge)

def CreateVunlnerabilityExploitNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'VulnerabilityExploit'
    Node.CPEId = TSA.CPEId
    Node.CVEId = SP.CVEId
    Node.HostIPAddress = TSA.HostIPAddress
    #Node.ApplicationName = TSA.name
    return Node

def CreateInformationSourceUsageNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'InformationSource'
    Node.CPEId = TSA.CPEId
    Node.HostIPAddress = TSA.HostIPAddress
    #Node.ApplicationName = TSA.name
    Node.InformationSourceName = SP.name
    return Node
