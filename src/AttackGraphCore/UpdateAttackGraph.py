# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

from AttackGraphStructure.AttackGraph import AttackGraph

partialAttackGraph =  AttackGraph()                            # 部分攻击图 攻击图类
#更新攻击图
def UpdateAttackGraph(SP,REQPS,GPS,TSA):                       #
# 跨越搜索代理代码的全局变量
# SP可以是信息源的漏洞
# REQPS是必需的权限
# GPS是获得的特权
# TSA是目标软件应用
    if SP in AttackGraph.VExploit:                                   #漏洞   如何表示存在于？
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #创建漏洞利用节点
    else:
        exp = CreateInformationSourceUsageNode(SP,TSA)         #创建信息源使用节点
    if REQPS.size()>1:
        prjc = PrivilegeConjunction()                          #特权连接  类？
        partialAttackGraph.addNode(prjc)                       #部分攻击图 添加节点
        for reqp in REQPS :
            partialAttackGraph.addEdge(reqp,prjc)              #部分攻击图 添加边
    else:
        if REQPS.size() == 1:
            partialAttackGraph.addEdge(REQPS.get(0),exp)
    for gp in GPS :
        partialAttackGraph.addEdge(exp,gp)


def CreateVunlnerabilityExploitNode(SP,TSA):
    pass

def CreateInformationSourceUsageNode(SP,TSA):
    pass

def PrivilegeConjunction():
    pass

