# coding=gbk
'''
Created on 2017年9月26日

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
            cp = MainStack.pop()                               # 在主堆栈上有权限的情况下继续进行搜索
        else:
            eps = GetWorkFromOtherAgents()                     # 从其他代理人那里得到工作
            if eps.size() == 0 :
                break
            else:
                MainStack.push(eps)
                foundPrivileges.addAll(eps)
                continue
        hv = FindVertexForPriv(cp,RHG)                         # 找到一个顶点
        ches = FindContainingEdges(hv,RHG)                     # 找到包含边缘
        gprgs = []                                         
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  # 查找目标软件应用程序
            for tsa in tsas :
                for v in tsa.vulnerabilities():                # tsa的漏洞
                    reqprgs = CheckExploitability(v,cp,tsa)    # 检查利用
                    if reqprgs != NULL :                       # 漏洞可以被攻击者利用
                        vgps = FindGainedPrivileges(v,cp,tsa)  # 寻找获得特权
                        gprgs.addAll(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                for tis in tsa.infoSources():                  # 信息来源
                    reqprgs = CheckExploitability(tis,cp,tsa)  # 检查利用
                    if reqprgs != NULL:                        # 信息源可以被攻击者使用
                        isgps = FindGainedPrivileges(tis,cp,tsa)
                        gprgs.addAll(isgps)
                        UpdateAttackGraph(tis,reqprgs,isgps,tsa)
        for gp in gprgs :
            newgps = PrivilegeStatus()
            newgps.setExpanded(True)
            oldgps = ReadAndUpdateSharedMemory(gp,newgps)      # 读和更新共享内存
            # 读取和更新共享内存是一种原子操作，可更新其输入权限的状态并返回其旧状态
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