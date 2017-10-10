# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''

from AttackGraphStructure.AttackGraph import AttackGraph

partialAttackGraph =  AttackGraph()                            # ���ֹ���ͼ ����ͼ��
#���¹���ͼ
def UpdateAttackGraph(SP,REQPS,GPS,TSA):                       #
# ��Խ������������ȫ�ֱ���
# SP��������ϢԴ��©��
# REQPS�Ǳ����Ȩ��
# GPS�ǻ�õ���Ȩ
# TSA��Ŀ�����Ӧ��
    if SP in AttackGraph.VExploit:                                   #©��   ��α�ʾ�����ڣ�
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #����©�����ýڵ�
    else:
        exp = CreateInformationSourceUsageNode(SP,TSA)         #������ϢԴʹ�ýڵ�
    if REQPS.size()>1:
        prjc = PrivilegeConjunction()                          #��Ȩ����  �ࣿ
        partialAttackGraph.addNode(prjc)                       #���ֹ���ͼ ��ӽڵ�
        for reqp in REQPS :
            partialAttackGraph.addEdge(reqp,prjc)              #���ֹ���ͼ ��ӱ�
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

