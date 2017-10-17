 # coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''

from AttackGraphStructure.AttackGraph import AttackGraph
from AttackGraphStructure.AttackElementNode import AttackGraphNode
from AttackTemplateModel.Vulnerability import Vulnerability

class PrivilegeConjunction:
    def __init__(self, x ='and'):
        self.Node = x

partialAttackGraph =  AttackGraph()                            # ���ֹ���ͼ ����ͼ��
#���¹���ͼ
def UpdateAttackGraph(SP,REQPS,GPS,TSA):                       #
# ��Խ������������ȫ�ֱ���
# SP��������ϢԴ��©��
# REQPS�Ǳ����Ȩ��
# GPS�ǻ�õ���Ȩ
# TSA��Ŀ�����Ӧ��
    if  isinstance(SP , Vulnerability):                        #©��   ��α�ʾ�����ڣ�
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #����©�����ýڵ�
    else:
        exp = CreateInformationSourceUsageNode(SP,TSA)         #������ϢԴʹ�ýڵ�
    if len(REQPS)>1:
        prjc = PrivilegeConjunction()                          #��Ȩ����  �ࣿ
        partialAttackGraph.addNode(prjc)                       #���ֹ���ͼ ��ӽڵ�
        for reqp in REQPS :
            partialAttackGraph.addEdge(reqp,prjc)              #���ֹ���ͼ ��ӱ�
    else:
        if len(REQPS) == 1:
            partialAttackGraph.addEdge(REQPS[0],exp)
    for gp in GPS :
        partialAttackGraph.addEdge(exp,gp)


#����©���ڵ�
def CreateVunlnerabilityExploitNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'VulnerabilityExploit'
    Node.CPE_ID = TSA.CPEId
    Node.CVE_ID = SP.CVEId
    Node.IPAddress = TSA.HostIPAddress
    Node.ApplicationName = TSA.name
    return Node

#������ϢԴʹ�ýڵ�
def CreateInformationSourceUsageNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'InformationSource'
    Node.CPE_ID = TSA.CPEId
    Node.IPAddress = TSA.HostIPAddress
#Node.ApplicationName = TSA.name
    Node.InformationSourceName = SP.name
    return Node



