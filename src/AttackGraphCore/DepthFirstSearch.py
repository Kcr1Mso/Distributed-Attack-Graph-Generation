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

def PERFORMDFS(RHG,IPRGS):
    
    '''
    RHG    Reachability hyper-graph
    IPRGS    initial attacker privileges
    '''
    
    MainStack=stack()       #Create Search Main Stack
    
    for ip in IPRGS :           #initial privileges
        '''
        
        '''
        ips = PrivilegeStatus()         #initial privileges status
        ips.setExpanded(True)                                  
        '''
        if the privilege has not already been expanded,the agent sets its expansion status to true
        and pushes the privilege to its search stack to expand it later
        '''
        WriteToSharedMemory(ip,ips)                            
        MainStack.push(ip)
        foundPrivileges.add(ip)                                
    while True :
        if MainStack.siza() > 0:
            cp = MainStack.pop()                               # ������ջ����Ȩ�޵�����¼�����������
        else:
            eps = GetWorkFromOtherAgents()                     # ����������������õ�����
            if eps.size() == 0 :
                break
            else:
                MainStack.push(eps)
                foundPrivileges.addAll(eps)
                continue
        hv = FindVertexForPriv(cp,RHG)                         # �ҵ�һ������
        ches = FindContainingEdges(hv,RHG)                     # �ҵ�������Ե
        gprgs = []                                         
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  # ����Ŀ�����Ӧ�ó���
            for tsa in tsas :
                for v in tsa.vulnerabilities():                # tsa��©��
                    reqprgs = CheckExploitability(v,cp,tsa)    # �������
                    if reqprgs != NULL :                       # ©�����Ա�����������
                        vgps = FindGainedPrivileges(v,cp,tsa)  # Ѱ�һ����Ȩ
                        gprgs.addAll(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                for tis in tsa.infoSources():                  # ��Ϣ��Դ
                    reqprgs = CheckExploitability(tis,cp,tsa)  # �������
                    if reqprgs != NULL:                        # ��ϢԴ���Ա�������ʹ��
                        isgps = FindGainedPrivileges(tis,cp,tsa)
                        gprgs.addAll(isgps)
                        UpdateAttackGraph(tis,reqprgs,isgps,tsa)
        for gp in gprgs :
            newgps = PrivilegeStatus()
            newgps.setExpanded(True)
            oldgps = ReadAndUpdateSharedMemory(gp,newgps)      # ���͸��¹����ڴ�
            # ��ȡ�͸��¹����ڴ���һ��ԭ�Ӳ������ɸ���������Ȩ�޵�״̬���������״̬
            if oldgps.expanded == False :
                MainStack.push(gp)
            foundPrivileges.add(gp)  

def foundPrivileges():
    def add(ip):
        pass
    def addAll():
        pass

def WriteToSharedMemory(ip,ips):
    pass

def GetWorkFromOtherAgents():
    pass

def PrivilegeStatus():
    pass

def FindVertexForPriv():
    pass

def FindContainingEdges():
    pass

def FindTargetSoftwareApps():
    pass

def ReadAndUpdateSharedMemory():
    pass