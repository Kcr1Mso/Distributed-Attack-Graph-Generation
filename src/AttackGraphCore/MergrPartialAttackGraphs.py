# coding=gbk
'''
Created on 2017年10月11日

@author: RHy0ThoM
'''
#合并部分攻击图

from AttackGraphStructure.AttackGraph import AttackGraph
from AttackGraphStructure.AttackGraphNode import AttackGraphNode
from _overlapped import NULL

def MergrPartialAttackGraphs(PGS):  
    # PGS是由搜索代理产生的部分攻击图
    if PGS.size() ==0:                                        #PGS具有size方法
        return AttackGraph()                                  #需定义攻击图函数
    ag = PGS.removeFirst()                                    #删除第一
# 更新攻击图的权限
    phm = FormHashMap(ag.privileges())                        #表格哈希图(ag的特权)
# 由其标识符映射的权限的哈希
    for prag in PGS :                                         #PSG应该是一个表
        for p in prag.privileges():                           #p是prag的特权
            esp = phm.get(p.id())                             #phm具有get方法，p具有id方法
            if esp != NULL:
                if p.outEdges.size()>0 :                      #p具有 出边 属性，属性有size方法
                    if esp.outEdges.size() == 0:              #esp具有出边属性，属性有size方法
# 从攻击图中删除现有权限，并添加特权及其子树替换现有权限
                        ag.addNodeWithItsSubTree(p)           #添加节点与它的子树
                        UpdateInEdgesOfExistingNode(esp,p)    #更新现有节点边缘 函数
                        ag.removeNode(esp)                    #ag具有 删除节点 的方法
                        phm.put(p.id(),p)                     #phm具有put方法，放入p的id和p本身
            else:
                ag.addNodeWithItsSubTree(p)                   #添加节点与它的子树
                phm.put(p.id(),p)
# 删除攻击图的重复漏洞利用和信息源使用节点
    exhm = {}                                                 #哈希表类? 在python中由字典代替
    expl = ag.vulnerabilityExploits                           #ag具有 漏洞利用 的属性
    expl.extend(ag.informationSourceUsages)                   #添加所有方法   ag的属性 信息来源用途
    for expn in expl:
        esxpn = exhm.get(expn.IPAddress,NULL)                 #exhm同phm一样
        if esxpn != NULL :
            for onn in esxpn.outNeighbourNodes():             #esxpn的外邻居节点
                ag.addEdge(expn,onn)                          #添加边
            UpdateInEdgesOfExistingNode(esxpn,expn)           #现有节点边缘更新
            ag.removeNode(esxpn)                              #删除节点esxpn
        exhm.update({expn.IPAddress:expn})                        #expn出ehm的栈
    return ag

#转化为哈希表
def FormHashMap(ps = []):
    find_ps = {}
    for i in ps:
        find_ps.update({i.IPAddress:i})
    return find_ps

#更新节点并添加入边
def UpdateInEdgesOfExistingNode(nodeA=AttackGraphNode(),nodeB=AttackGraphNode()):
    nodeB.inEdges.extend(nodeA.inEdges.extend)