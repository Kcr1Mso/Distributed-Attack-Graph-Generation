# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''
from inspect import stack


def PERFORMDFS(RHG,IPRGS):
    '''
    RHG    Reachability hyper-graph
    IPRGS    initial attacker privileges
    '''
    
    MainStack=stack()       #Create Search Main Stack
    
    for ip in IPRGS :
        ips = PrivilegeStatus()                                #��Ȩ״̬�ࣿ
        ips.setExpanded(true)                                  # ����չ��
        WriteToSharedMemory(ip,ips)                            # д�빲���ڴ�
        MainStack.push(ip)
        foundPrivileges.add(ip)                                # ������Ȩ
    while true :
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
        gprgs = List()                                         # List�ࣿ �����ı�
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  # ����Ŀ�����Ӧ�ó���
            for tsa in tsas :
                for v in tsa.vulnerabilities():                # tsa��©��
                    reqorgs = CheckExploitability(v,cp,tsa)    # �������
                    if reqprgs != null :                       # ©�����Ա�����������
                        vgps = FindGainedPrivileges(v,cp,tsa)  # Ѱ�һ����Ȩ
                        gprgs.addAll(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                for tis in tsa.infoSources():                  # ��Ϣ��Դ
                    reqprgs = CheckExploitability(tis,cp,tsa)  # �������
                    if reqprgs != null:                        # ��ϢԴ���Ա�������ʹ��
                        isgps = FindGainedPrivileges(tis,cp,tsa)
                        gprgs.addAll(isgps)
                        UpdateAttackGraph(tis,reqprgs,isgps,tsa)
        for gp in gprgs :
            newgps = PrivilegeStatus()
            newgps.setExpanded(true)
            oldgps = ReadAndUpdateSharedMemory(gp,newgps)      # ���͸��¹����ڴ�
            # ��ȡ�͸��¹����ڴ���һ��ԭ�Ӳ������ɸ���������Ȩ�޵�״̬���������״̬
            if oldgps.expanded == false :
                MainStack.push(gp)
            foundPrivileges.add(gp)  
    