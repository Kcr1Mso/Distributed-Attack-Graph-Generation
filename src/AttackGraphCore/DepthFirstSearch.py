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
        examining the Boolen expansion status of it stored in the virtual 
        shared memory
        '''
        #ips = PrivilegeStatus()         #initial privileges status
        #ips.setExpanded(True)                                  
        '''
        if the privilege has not already been expanded,the agent sets its expansion status to true
        and pushes the privilege to its search stack to expand it later
        '''
        #WriteToSharedMemory(ip,ips)                            
        MainStack.push(ip)
        foundPrivileges.add(ip)                                
    while True :
        if MainStack.siza() > 0:
            cp = MainStack.pop()
            '''                               
             continue to the search while there are privileges on the main stack
             '''
        else:
            #eps = GetWorkFromOtherAgents()                     #request privileges from other agents to expand
            #if eps.size() == 0 :
                break
            #else:
                #MainStack.push(eps)
                #foundPrivileges.addAll(eps)
                #continue
        hv = FindVertexForPriv(cp,RHG)                         
        ches = FindContainingEdges(hv,RHG)                     
        gprgs = []                                         
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  #find software application S related with P
            for tsa in tsas :
                for v in tsa.vulnerabilities():                
                    reqprgs = CheckExploitability(v,cp,tsa)    
                    # check exploitability of vulnerabilities in reachable software application
                    # check usability of information sources in reachable software applications
                    if reqprgs != NULL :
                        vgps = FindGainedPrivileges(v,cp,tsa)
                        #find privileges gained from exploitable vulnerabilities and usable information sources
                        gprgs.addAll(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                        #update the partial attack graph managed by this agent with gained privileges
                        #their corresponding exploited vulnerabilities and information sources
                for tis in tsa.InformationSource():                  
                    reqprgs = CheckExploitability(tis,cp,tsa)  
                    if reqprgs != NULL:                        
                        isgps = FindGainedPrivileges(tis,cp,tsa)
                        gprgs.addAll(isgps)
                        UpdateAttackGraph(tis,reqprgs,isgps,tsa)
                        '''
        for gp in gprgs :
            newgps = PrivilegeStatus()
            newgps.setExpanded(True)
            oldgps = ReadAndUpdateSharedMemory(gp,newgps)      # 读和更新共享内存
            # 读取和更新共享内存是一种原子操作，可更新其输入权限的状态并返回其旧状态
            if oldgps.expanded == False :
                MainStack.push(gp)
            foundPrivileges.add(gp)
            '''  

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

def FindTargetSoftwareApps(he):         #find software application S related with P
    return he.TargetNetworkInterface.Host.SoftwareApplication

def ReadAndUpdateSharedMemory():
    pass