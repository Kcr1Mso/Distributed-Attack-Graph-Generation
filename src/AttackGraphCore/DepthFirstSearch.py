# coding=gbk
''' 
Created on 2017��9��26��

@author: RHy0ThoM
'''
from inspect import stack
from AttackGraphCore.FindGainedPrivileges import FindGainedPrivileges
from AttackGraphCore.CheckExploitability import CheckExploitability
from AttackGraphCore.UpdateAttackGraph import UpdateAttackGraph

from _overlapped import NULL
from NetworkModel.HyperGraph import HyperGraph

RHG=HyperGraph()


def PERFORMDFS(RHG,IPRGS):
    
    '''
    RHG    Reachability hyper-graph
    IPRGS    initial attacker privileges
    '''
    
    MainStack=stack()       #Create Search Main Stack
    SharedMemory={}
    foundPrivileges =  []
    
    for ip in IPRGS :
        ips = PrivilegeStatus()                                #��Ȩ״̬�ࣿ   Ӧ���Ǹ���������
        ips.setExpanded(True)                                  # ����չ��
        SharedMemory.update({ip:ips})                          # д�빲���ڴ�
        MainStack.push(ip)
        foundPrivileges.append(ip)                             # ������Ȩ
    while True :
        if MainStack.isEmpty == False:
            cp = MainStack.pop()                               # ������ջ����Ȩ�޵�����¼�����������
        else:
            eps = GetWorkFromOtherAgents()                     # ����������������õ�����
            if len(eps) == 0 :                                 #epsΪ��
                break
            else:
                MainStack.push(eps)
                foundPrivileges.extend(eps)
                continue
        hv = RHG.findVertexForPriv(cp)                         # �ҵ�һ������
        ches = RHG.findContainingEdges(hv)                     # �ҵ�������Ե
        gprgs = []                                             # List�ࣿ �����ı�
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  # ����Ŀ�����Ӧ�ó���
            for tsa in tsas :
                for v in tsa.vulnerabilities():                # tsa��©��
                    reqprgs = CheckExploitability(v,cp,tsa)    # �������
                    if reqprgs != NULL :                       # ©�����Ա�����������
                        vgps = FindGainedPrivileges(v,cp,tsa)  # Ѱ�һ����Ȩ
                        gprgs.extend(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                for tis in tsa.infoSources():                  # ��Ϣ��Դ
                    reqprgs = CheckExploitability(tis,cp,tsa)  # �������
                    if reqprgs != NULL:                        # ��ϢԴ���Ա�������ʹ��
                        isgps = FindGainedPrivileges(tis,cp,tsa)
                        gprgs.extend(isgps)
                        UpdateAttackGraph(tis,reqprgs,isgps,tsa)
        for gp in gprgs :
            newgps = PrivilegeStatus()
            newgps.setExpanded(True)
            oldgps = SharedMemory.get(gp)      # ���͸��¹����ڴ�
            SharedMemory.update({gp:newgps})
            # ��ȡ�͸��¹����ڴ���һ��ԭ�Ӳ������ɸ���������Ȩ�޵�״̬���������״̬
            if oldgps.expanded == False :
                MainStack.push(gp)
            foundPrivileges.append(gp)

def WriteToSharedMemory(ip,ips):
    pass

def GetWorkFromOtherAgents():
    pass


#Ȩ��״̬�ࣺ�������Ȩ���Ƿ������
class PrivilegeStatus:
    def __init__(self, x = False):
        self.expanded = x
    def setExpanded(self, x = False):
        self.expanded = x

#����Ŀ�����Ӧ�ó���
def FindTargetSoftwareApps(he):
    softwareApps = []
    for i in he:
        softwareApps.extend(i.SoftwareApplications)
    return softwareApps

def ReadAndUpdateSharedMemory():
    pass