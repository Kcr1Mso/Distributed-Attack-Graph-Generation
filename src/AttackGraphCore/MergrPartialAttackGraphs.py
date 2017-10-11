# coding=gbk
'''
Created on 2017��10��11��

@author: RHy0ThoM
'''
#�ϲ����ֹ���ͼ

def MergrPartialAttackGraphs(PGS):  
    # PGS����������������Ĳ��ֹ���ͼ
    if PGS.size() ==0:                                        #PGS����size����
        return AttackGraph()                                  #�趨�幥��ͼ����
    ag = PGS.removeFirst()                                    #ɾ����һ
# ���¹���ͼ��Ȩ��
    phm = FormHashMap(ag.privileges())                        #����ϣͼ(ag����Ȩ)
# �����ʶ��ӳ���Ȩ�޵Ĺ�ϣ
    for prag in PSG :                                         #PSGӦ����һ����
        for p in prag.privileges():                           #p��prag����Ȩ
            esp = phm.get(p.id())                             #phm����get������p����id����
            if esp != NULL:
                if p.outEdges.size()>0 :                      #p���� ���� ���ԣ�������size����
                    if esp.outEdges.size() == 0:              #esp���г������ԣ�������size����
# �ӹ���ͼ��ɾ������Ȩ�ޣ��������Ȩ���������滻����Ȩ��
                        ag.addNodeWithItsSubTree(p)           #��ӽڵ�����������
                        UpdateInEdgesOfExistingNode(esp,p)    #�������нڵ��Ե ����
                        ag.removeNode(esp)                    #ag���� ɾ���ڵ� �ķ���
                        phm.put(p.id(),p)                     #phm����put����������p��id��p����
            else:
                ag.addNodeWithItsSubTree(p)                   #��ӽڵ�����������
                phm.put(p.id(),p)
# ɾ������ͼ���ظ�©�����ú���ϢԴʹ�ýڵ�
    exhm = HashMap()                                          #��ϣ����
    expl = ag.vulnerabilityExploits                           #ag���� ©������ ������
    expl.addAll(ag.informationSourceUsages)                   #������з���   ag������ ��Ϣ��Դ��;
    for expn in expl:
        esxpn = exhm.get(expn.id())                           #exhmͬphmһ��
        if esxpn != null :
            for onn in esxpn.outNeighbourNodes():             #esxpn�����ھӽڵ�
                ag,addEdge(expn,onn)                          #��ӱ�
            UpdateInEdgesOfExistingNode(esxpn,expn)           #���нڵ��Ե����
            ag,removeNode(esxpn)                              #ɾ���ڵ�esxpn
        ehm.put(expn.id(),expn)                               #expn��ehm��ջ
    return ag
