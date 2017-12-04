# -*- coding:utf-8 -*-
import Queue
import time, sys
import pygraphviz as pgv
from multiprocessing.managers import BaseManager
#条件
class Condition:
    def __init__(self, Category = '', ExistIn = '',CPEID = '',IPAddress = ''):
        self.CPEID = CPEID
        self.Category = Category
        self.ExistIn = ExistIn
        self.IPAddress = IPAddress
    def show(self):
        print ("Condition:", "Category =" ,self.Category ,"ExistIn =" , self.ExistIn , "CPEID =" , self.CPEID)
    def sping(self):
        return 'Privilege\nIPAddress:' + self.IPAddress + '\nCategory:' + self.Category + '\nCPEId:' + self.CPEID + '\nApplication Name:' + self.ExistIn


#漏洞
class Vulnerability:
    def __init__(self, CVEId = '', Preconditions = [], Postconditions = []):
        self.CVEId = CVEId
        self.Preconditions = Preconditions
        self.Postconditions = Postconditions
#信息源节点
class InformationSource:
    def __init__(self, name = '', ReferencedSoftware = [], Preconditions = [], Postconditions = []):
        self.name = name
        self.ReferencedSoftware = ReferencedSoftware
        self.Preconditions = Preconditions
        self.Postconditions = Postconditions
#应用程序
class SoftwareApplication:
    def __init__(self, CPEID='', HostIPAddress='', Port=0, BackendApplications=[], InformationSources=[], Vulnerabilities=[]):
        self.CPEID = CPEID
        self.HostIPAddress = HostIPAddress
        self.Port = Port
        self.BackendApplications = BackendApplications
        self.InformationSources = InformationSources
        self.Vulnerabilities = Vulnerabilities
#网络接口
class NetworkInterface:
    def __init__(self, IPAddress ='', Link ='', Host =''):
        self.IPAddress = IPAddress
        self.Link = Link
        self.Host = Host
#网络主机
class NetworkHost:
    def __init__(self,IPAddress='',NetworkInterfaces=[],SoftwareApplications=[]):
        self.IPAddress = IPAddress
        self.NetworkInterfaces = NetworkInterfaces
        self.SoftwareApplications = SoftwareApplications
#攻击图节点
class AttackGraphNode:
    def __init__(self, Type = '' ,IPAddress='', CPEId='', ApplicationName='',InEdge = [],OutEdge = [],CVEId = '' , x ='' ,y =''):
        self.Type = Type
        self.IPAddress=IPAddress
        self.CPEId=CPEId
        self.ApplicationName=ApplicationName
        self.InEdge = InEdge
        self.OutEdge = OutEdge
        self.CVEId = CVEId
        self.InformationSourceName = x
        self.Category = y
    def show(self):
        print (self.Type)
        print (self.IPAddress)
        print (self.CPEId)
        print (self.ApplicationName)
        print (self.InEdge)
        print (self.OutEdge)
        print (self.CVEId)
        print (self.InformationSourceName)
    def sping(self):
        if self.Type == 'VulnerabilityExploit':
            return 'Vulnerability Exploit\nIPAddress:'+self.IPAddress+'\nCVEId:'+self.CVEId+'\nCPEId:'+self.CPEId+'\nApplication Name:'+self.ApplicationName
        if self.Type == 'InformationSource':
            return 'Information Source Usage\nIPAddress:' + self.IPAddress + '\nCPEId:' + self.CPEId + '\nApplication Name:' + self.ApplicationName + '\nInformation Source Name' + self.InformationSourceName


#攻击图边
class AttackGraphEdge:
    def __init__(self , SourceNode = AttackGraphNode() , TargetNode =AttackGraphNode()):
        self.SourceNode = SourceNode
        self.TargetNode = TargetNode
#攻击图
class AttackGraph:
    def __init__(self, x=[], y=[]):
        self.Node = x
        self.Edge = y

    def addNode(self, node):
        self.Node.append(node)

    def addEdge(self, nodeA, nodeB):
        self.Edge.append([nodeA, nodeB])

    def removeNode(self, node):
        self.Node.remove(node)
        for i in self.Edge:
            if i.SourceNode == node:
                self.Edge.remove(i)
            elif i.TargetNode == node:
                self.Edge.remove(i)

    def privileges(self):
        find_p = []
        for i in self.Node:
            if i.Type == 'Privilege':
                find_p.append(i)
        return find_p

    def vulnerabilityExploits(self):
        find_v = []
        for i in self.Node:
            if i.Type == 'VulnerabilityExploit':
                find_v.append(i)
        return find_v

    def informationSourceUsages(self):
        find_i = []
        for i in self.Node:
            if i.Type == 'InformationSourceUsage':
                find_i.append(i)
        return find_i

    def addNodeWithItsSubTree(self, nodeP=AttackGraphNode()):  # 添加节点与它的子树
        self.Node.append(nodeP)
        self.Edge.extend(nodeP.outEdges)
        for i in nodeP.outEdges:
            self.addNodeWithItsSubTree(i.TargetNode)

#特权状态类
class PrivilegeStatus:
    def __init__(self, x = False):
        self.expanded = x
    def setExpanded(self, x = False):
        self.expanded = x

#内存类
class Memory:
    def __init__(self,x = Condition(),y = PrivilegeStatus()):
        self.privileges=x
        self.status=y

SharedMemory = []

def WriteToSharedMemory(ip= Condition(),ips=PrivilegeStatus()):
    SharedMemory.append(Memory(ip,ips))

def ReadFromSharedMemory(ip = Condition()):
    for memory in SharedMemory:
        if memory.privileges == ip:
            return memory.status
    else:
        return PrivilegeStatus()

def ReadAndUpdateSharedMemory(ip= Condition(),ips=PrivilegeStatus()):
    for memory in SharedMemory:
        if memory.privileges == ip:
            x = memory.status
            memory.status = ips
            return x
    else:
        return PrivilegeStatus()

def MergrPartialAttackGraphs(PGS=[]):
    # PGS是由搜索代理产生的部分攻击图
    if len(PGS) ==0:                                        #PGS具有size方法
        return AttackGraph()                                  #需定义攻击图函数
    ag = PGS.pop()                                    #删除第一
# 更新攻击图的权限
    phm = FormHashMap(ag.privileges())                        #表格哈希图(ag的特权)
# 由其标识符映射的权限的哈希
    for prag in PGS :                                         #PSG应该是一个表
        for p in prag.privileges():                           #p是prag的特权
            esp = phm.get(p.IPAddress,0)                             #phm具有get方法，p具有id方法
            if esp != 0:
                if len(p.OutEdge)>0 :                      #p具有 出边 属性，属性有size方法
                    if len(esp.OutEdge) == 0:              #esp具有出边属性，属性有size方法
# 从攻击图中删除现有权限，并添加特权及其子树替换现有权限
                        ag.addNodeWithItsSubTree(p)           #添加节点与它的子树
                        UpdateInEdgesOfExistingNode(esp,p)    #更新现有节点边缘 函数
                        ag.removeNode(esp)                    #ag具有 删除节点 的方法
                        phm.put(p.id(),p)                     #phm具有put方法，放入p的id和p本身
            else:
                ag.addNodeWithItsSubTree(p)                   #添加节点与它的子树
                phm.pop(p.IPAddress,p)
# 删除攻击图的重复漏洞利用和信息源使用节点
    exhm = {}                                                 #哈希表类? 在python中由字典代替
    expl = ag.vulnerabilityExploits                           #ag具有 漏洞利用 的属性
    expl.extend(ag.informationSourceUsages)                   #添加所有方法   ag的属性 信息来源用途
    for expn in expl:
        esxpn = exhm.get(expn.IPAddress,0)                 #exhm同phm一样
        if esxpn != 0 :
            for onn in esxpn.outNeighbourNodes():             #esxpn的外邻居节点
                ag.addEdge(expn,onn)                          #添加边
            UpdateInEdgesOfExistingNode(esxpn,expn)           #现有节点边缘更新
            ag.removeNode(esxpn)                              #删除节点esxpn
        exhm.update({expn.IPAddress:expn})                        #expn出ehm的栈
    return ag

#转化为哈希表
def FormHashMap(ps = []):
    find_ps = {}
    for i in ps:
        find_ps.update({i.IPAddress:i})
    return find_ps

#更新节点并添加入边
def UpdateInEdgesOfExistingNode(nodeA=AttackGraphNode(),nodeB=AttackGraphNode()):
    nodeB.InEdge.extend(nodeA.InEdge)


#寻找获得权限 需要进行修改
def FindGainedPrivileges(SP, CP, TSA):
    print ("FindGainedPrivileges",SP.Preconditions[0],CP,TSA)
    CP.show()
    SP.Preconditions[0].show()
    if ((CP.CPEID == SP.Preconditions[0].CPEID) and (CP.Category == SP.Preconditions[0].Category)):
        return SP.Postconditions
    else:
        return []

#寻找权限子函数 源操作 需要重新定义
def FormPrivileges(preConditions, CP, TSA):
    print (preConditions , CP , TSA)
    for i in TSA.InformationSources:
        if ((CP.CPEID == i.Preconditions[0].CPEID) and (CP.Category == i.Preconditions[0].Category)) :
            return [CP]
    for i in TSA.Vulnerabilities:
        if ((CP.CPEID == i.Preconditions[0].CPEID) and (CP.Category == i.Preconditions[0].Category)):
            return [CP]
    return []


partialAttackGraph =  AttackGraph()                            # 部分攻击图 攻击图类
#更新攻击图
def UpdateAttackGraph(SP,reqprgs,GPS,TSA):                       #
# 跨越搜索代理代码的全局变量
# SP可以是信息源的漏洞
# REQPS是必需的权限   是一个权限点列表  并不是权限表
# GPS是获得的特权
# TSA是目标软件应用
    if  isinstance(SP , Vulnerability):                        #漏洞   如何表示存在于？
        exp = CreateVunlnerabilityExploitNode(SP,TSA)          #创建漏洞利用节点
    else:
        REQPS = reqprgs[0]
        exp = CreateInformationSourceUsageNode(SP,REQPS)         #创建信息源使用节点
    partialAttackGraph.addNode(exp)
#    if len(reqprgs)>1:
#        prjc = PrivilegeConjunction()                          #特权连接  类？
#        partialAttackGraph.addNode(prjc)                       #部分攻击图 添加节点
#        for reqp in reqprgs :
#            partialAttackGraph.addEdge(reqp,prjc)              #部分攻击图 添加边
#    else:
    if len(reqprgs) == 1:
        partialAttackGraph.addEdge(reqprgs[0],exp)
    for gp in GPS :
        partialAttackGraph.addEdge(exp,gp)
    print(partialAttackGraph.Node)
    print(partialAttackGraph.Edge)

def CreateVunlnerabilityExploitNode(SP,TSA):
    Node = AttackGraphNode()
    Node.Type = 'VulnerabilityExploit'
    Node.CPEId = TSA.CPEID
    Node.CVEId = SP.CVEId
    Node.IPAddress = TSA.HostIPAddress
    Node.ApplicationName = TSA.BackendApplications[0]
    return Node

def CreateInformationSourceUsageNode(SP,REQPS):
    Node = AttackGraphNode()
    Node.Type = 'InformationSource'
    Node.CPEId = REQPS.CPEID
    Node.IPAddress = REQPS.IPAddress
    Node.InformationSourceName = SP.name
    Node.ApplicationName = REQPS.ExistIn
    return Node




def CheckExploitability(SP,CP,TSA) :
    '''
    SP can be a vulnerabilities or information source
    CP is the current privilege
    TSA is the target software application
    '''
    reqprgs = FormPrivileges(SP.Preconditions,CP,TSA)

   # if not(CP in reqprgs):
   #     return []
#    for rqp in reqprgs :
#        if not(rqp in foundPrivileges):                        # 发现特权
#            rqps = ReadFromSharedMemory(rqp)                   # 从共享内存读取
#            if rqps.expanded == True:
# 如果没有扩展特权，那么这意味着到目前为止，它不是由任何代理生成的
#                return reqprgs.remove(rqp)
    return reqprgs

#查找目标软件应用程序
def FindTargetSoftwareApps(he):#he [organization,dmz]
    softwareApps = []
    for i in he:
        softwareApps.extend(i.SoftwareApplications)
    return softwareApps


# 主堆栈类
class CreateMainStack:
    def __init__(self, size=20):
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
            self.top = self.top + 1

    def pop(self):
        if self.isEmpty():
            raise StackException('MainStackUnderflow')
        else:
            element = self.stack[-1]
            self.top = self.top - 1
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
        if self.top == self.size - 1:
            return True
        else:
            return False

#定义超图：由顶点和超边两个表（超边为多个定点的表）
class HyperGraph:
    def __init__(self, x = [] , y = []):
        self.Node = x
        self.Edge = y
    def findVertexForPriv(self , x):
        for i in self.Node:
            for j in i.SoftwareApplications:
                if j.CPEID == x.CPEID:
                    print (j.CPEID)
                    return i
        else:
            return 0

    def findContainingEdges(self , x):
        find_edges = []
        for i in self.Edge:
            for j in i:
                if j == x :
                    find_edges.append(i)
                    break
        return find_edges


def PERFORMDFS(RHG, IPRGS):
    '''
    RHG    Reachability hyper-graph
    IPRGS    initial attacker privileges
    '''

    MainStack = CreateMainStack()  # Create Search Main Stack


    for ip in IPRGS:
        ips = PrivilegeStatus()  # 特权状态类？   应该是个网络主机
        ips.setExpanded(True)  # 设置展开
        WriteToSharedMemory(ip, ips)  # 写入共享内存
        print (SharedMemory)
        MainStack.push(ip)
        foundPrivileges.append(ip)  # 发现特权
    while True:
        if MainStack.isEmpty() == False:
            cp = MainStack.pop()  # 在主堆栈上有权限的情况下继续进行搜索
            print('---------MainStack.pop------------------')
            cp.show()
            print('----------------------------------------')
        else:
            # eps = GetWorkFromOtherAgents()                     # 从其他代理人那里得到工作
            # if len(eps) == 0 :                                 #eps为表？
            break
            # else:
            #    MainStack.push(eps)
            #    foundPrivileges.extend(eps)
            #    continue
        hv = RHG.findVertexForPriv(cp)  # 找到一个顶点
        print('---------hv------------------')
        print (hv)
        print('----------------------------------------')
        ches = RHG.findContainingEdges(hv)  # 找到包含边缘
        print('---------ches------------------')
        print (ches)
        print('----------------------------------------')
        gprgs = []
        for he in ches:
            tsas = FindTargetSoftwareApps(he)  # 查找目标软件应用程序
            print(tsas[0].CPEID)
            for tsa in tsas:
                for v in tsa.Vulnerabilities:  # 遍历tsa中的漏洞
                    print(v)
                    reqprgs = CheckExploitability(v, cp, tsa)
                    if reqprgs != []:  # 漏洞可以被攻击者利用
                        vgps = FindGainedPrivileges(v, cp, tsa)  # 寻找获得特权
                        gprgs.extend(vgps)
                        UpdateAttackGraph(v, reqprgs, vgps, tsa)

                for tis in tsa.InformationSources:  # 信息来源
                    reqprgs = CheckExploitability(tis, cp, tsa)  # 检查利用
                    if reqprgs != []:  # 信息源可以被攻击者使用
                        isgps = FindGainedPrivileges(tis, cp, tsa)
                        gprgs.extend(isgps)
                        UpdateAttackGraph(tis, reqprgs, isgps, tsa)
        for gp in gprgs:
            gp.show()
            newgps = PrivilegeStatus()
            newgps.setExpanded(True)
            oldgps = ReadFromSharedMemory(gp)  # 读和更新共享内存
            ReadAndUpdateSharedMemory(gp, newgps)
            # 读取和更新共享内存是一种原子操作，可更新其输入权限的状态并返回其旧状态
            if oldgps.expanded == False:
                MainStack.push(gp)
            foundPrivileges.append(gp)


# 创建类似的QueueManager:
class QueueManager(BaseManager):
    pass

# 由于这个QueueManager只从网络上获取Queue，所以注册时只提供名字:
QueueManager.register('get_task_queue')
QueueManager.register('get_result_queue')

# 连接到服务器，也就是运行task_master.py的机器:
server_addr = '10.52.182.83'
print('Connect to server %s...' % server_addr)
# 端口和验证码注意保持与task_master.py设置的完全一致:
m = QueueManager(address=(server_addr, 5000), authkey=b'abc')
# 从网络连接:
m.connect()
# 获取Queue的对象:
task = m.get_task_queue()
result = m.get_result_queue()
# 从task队列取任务,并把结果写入result队列:



if __name__ == '__main__':

    TargetNetwork = task.get(timeout=1)
    IPRGS = []
    IPRGS = task.get(timeout=1)



    foundPrivileges = []

    PERFORMDFS(TargetNetwork,IPRGS)

    result.put(foundPrivileges)
    result.put(partialAttackGraph)



