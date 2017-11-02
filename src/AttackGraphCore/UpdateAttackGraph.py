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
def UpdateAttackGraph(SP,reqprgs,GPS,TSA):                       #
# ��Խ������������ȫ�ֱ���
# SP��������ϢԴ��©��
# REQPS�Ǳ����Ȩ��
# GPS�ǻ�õ���Ȩ
# TSA��Ŀ�����Ӧ��
    print(isinstance(SP , Vulnerability))
    if  isinstance(SP , Vulnerability):                        #©��   ��α�ʾ�����ڣ�
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #����©�����ýڵ�
        print('----------isinstance---------------')
    else:
        print('------------informationsoucernode----------------')
        exp = CreateInformationSourceUsageNode(SP,TSA)         #������ϢԴʹ�ýڵ�
    partialAttackGraph.addNode(exp)
    print('-----------REQPS--------------------')
    print(reqprgs)
    print('------------------------------------')
    try:
        if len(reqprgs)>1:
            print('----------reqps-----------------')
            prjc = PrivilegeConjunction()                          #��Ȩ����  �ࣿ
            partialAttackGraph.addNode(prjc)                       #���ֹ���ͼ ��ӽڵ�
            for reqp in REQPS :
                partialAttackGraph.addEdge(reqp,prjc)              #���ֹ���ͼ ��ӱ�
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
