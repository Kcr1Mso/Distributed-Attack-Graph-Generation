# coding=gbk
''' 
Created on 2017年9月26日

@author: RHy0ThoM
'''
from AttackGraphCore.FindGainedPrivileges import FindGainedPrivileges
from AttackGraphCore.CheckExploitability import CheckExploitability,foundPrivileges
from AttackGraphCore.UpdateAttackGraph import UpdateAttackGraph

from _overlapped import NULL

#栈操作出错
class StackException(Exception):                  #栈操作出错
    def __init__(self,data):
        self.data=data
    def __str__(self):
        return self.data

#主堆栈类
class CreateMainStack:
    def __init__(self, size = 20):
        self.stack = []
        self.size = size
        self.top = -1
    def setSize(self, size):
        self.size = size
    def push(self, element):
        if self.isFull():
            raise StackException('MainStackOverflow')
        else:
            self.stack.append(element)
            self.top = self.top +1
    def pop(self):
        if self.isEmpty():
            raise StackException('MainStackUnderflow')
        else:
            element = self.stack[-1]
            self.top = self.top -1
            del self.stack[-1]
            return element
    def Top(self):
        return self.top
    def empty(self):
        self.stack = []
        self.top = -1
    def isEmpty(self):
        if self.top == -1:
            return True
        else:
            return False
    def isFull(self):
        if self.top == self.size -1:
            return True
        else:
            return False

def PERFORMDFS(RHG,IPRGS):
    
    '''
    RHG    Reachability hyper-graph
    IPRGS    initial attacker privileges
    '''
    
    MainStack=CreateMainStack()       #Create Search Main Stack
    SharedMemory={}
    foundPrivileges =  []
    
    for ip in IPRGS :
        #ips = PrivilegeStatus()                                #特权状态类？   应该是个网络主机
        #ips.setExpanded(True)                                  # 设置展开
        #SharedMemory.update({ip:ips})                          # 写入共享内存
        print('initial privilege ipaddress')
        print(ip.IPAddress)
        print('---------------------------')
        MainStack.push(ip)
        foundPrivileges.append(ip)                             # 发现特权
        print('foundprivilegs')
        print(foundPrivileges[0].Category)
        print('---------------------------')
    while True :
        if MainStack.isEmpty() == False:
            cp = MainStack.pop()                               # 在主堆栈上有权限的情况下继续进行搜索
        else:
            #eps = GetWorkFromOtherAgents()                     # 从其他代理人那里得到工作
            #if len(eps) == 0 :                                 #eps为表？
                break
            #else:
            #    MainStack.push(eps)
            #    foundPrivileges.extend(eps)
            #    continue
        hv = RHG.findVertexForPriv(cp)                         # 找到一个顶点
        print('findvertexforpriv')
        print(hv.NetworkInterfaces[0].IPAddress)
        print('---------------------------')
        ches = RHG.findContainingEdges(hv)                     # 找到包含边缘
        print(ches[0][1].NetworkInterfaces[0].IPAddress)#ches [[organization,dmz]]
        gprgs = []                                             # List类？ 单纯的表？
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  # 查找目标软件应用程序
            print(tsas[0].CPEId)
            for tsa in tsas :
                '''
                for v in tsa.vulnerabilities():                # tsa的漏洞
                    reqprgs = CheckExploitability(v,cp,tsa)    # 检查利用
                    if reqprgs != NULL :                       # 漏洞可以被攻击者利用
                        vgps = FindGainedPrivileges(v,cp,tsa)  # 寻找获得特权
                        gprgs.extend(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                        '''
                for tis in tsa.InformationSource:                  # 信息来源
                    reqprgs = CheckExploitability(tis,cp,tsa)  # 检查利用
                    print(reqprgs)
                    if reqprgs != NULL:                        # 信息源可以被攻击者使用
                        isgps = FindGainedPrivileges(tis,cp,tsa)
                        gprgs.extend(isgps)
                        UpdateAttackGraph(tis,reqprgs,isgps,tsa)
        for gp in gprgs :
            newgps = PrivilegeStatus()
            newgps.setExpanded(True)
            oldgps = SharedMemory.get(gp)      # 读和更新共享内存 
            SharedMemory.update({gp:newgps})
            # 读取和更新共享内存是一种原子操作，可更新其输入权限的状态并返回其旧状态
            if oldgps.expanded == False :
                MainStack.push(gp)
            foundPrivileges.append(gp)

def WriteToSharedMemory(ip,ips):
    pass

def GetWorkFromOtherAgents():
    pass


#权限状态类：用来标记权限是否遍历过
class PrivilegeStatus:
    def __init__(self, x = False):
        self.expanded = x
    def setExpanded(self, x = False):
        self.expanded = x

#查找目标软件应用程序
def FindTargetSoftwareApps(he):#he [organization,dmz]
    softwareApps = []
    for i in he:
        print(i.SoftwareApplications[0].CPEId)
        print('------------------------------')
        softwareApps.extend(i.SoftwareApplications)
    return softwareApps

def ReadAndUpdateSharedMemory():
    pass

