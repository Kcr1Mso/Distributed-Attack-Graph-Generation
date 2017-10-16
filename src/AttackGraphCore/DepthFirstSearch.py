# coding=gbk
''' 
Created on 2017��9��26��

@author: RHy0ThoM
'''
from AttackGraphCore.FindGainedPrivileges import FindGainedPrivileges
from AttackGraphCore.CheckExploitability import CheckExploitability,foundPrivileges
from AttackGraphCore.UpdateAttackGraph import UpdateAttackGraph

from _overlapped import NULL

#ջ��������
class StackException(Exception):                  #ջ��������
    def __init__(self,data):
        self.data=data
    def __str__(self):
        return self.data

#����ջ��
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
        #ips = PrivilegeStatus()                                #��Ȩ״̬�ࣿ   Ӧ���Ǹ���������
        #ips.setExpanded(True)                                  # ����չ��
        #SharedMemory.update({ip:ips})                          # д�빲���ڴ�
        print('initial privilege ipaddress')
        print(ip.IPAddress)
        print('---------------------------')
        MainStack.push(ip)
        foundPrivileges.append(ip)                             # ������Ȩ
        print('foundprivilegs')
        print(foundPrivileges[0].Category)
        print('---------------------------')
    while True :
        if MainStack.isEmpty() == False:
            cp = MainStack.pop()                               # ������ջ����Ȩ�޵�����¼�����������
        else:
            #eps = GetWorkFromOtherAgents()                     # ����������������õ�����
            #if len(eps) == 0 :                                 #epsΪ��
                break
            #else:
            #    MainStack.push(eps)
            #    foundPrivileges.extend(eps)
            #    continue
        hv = RHG.findVertexForPriv(cp)                         # �ҵ�һ������
        print('findvertexforpriv')
        print(hv.NetworkInterfaces[0].IPAddress)
        print('---------------------------')
        ches = RHG.findContainingEdges(hv)                     # �ҵ�������Ե
        print(ches[0][1].NetworkInterfaces[0].IPAddress)#ches [[organization,dmz]]
        gprgs = []                                             # List�ࣿ �����ı�
        for he in ches :
            tsas = FindTargetSoftwareApps(he)                  # ����Ŀ�����Ӧ�ó���
            print(tsas[0].CPEId)
            for tsa in tsas :
                '''
                for v in tsa.vulnerabilities():                # tsa��©��
                    reqprgs = CheckExploitability(v,cp,tsa)    # �������
                    if reqprgs != NULL :                       # ©�����Ա�����������
                        vgps = FindGainedPrivileges(v,cp,tsa)  # Ѱ�һ����Ȩ
                        gprgs.extend(vgps)
                        UpdateAttackGraph(v,reqprgs,vgps,tsa)
                        '''
                for tis in tsa.InformationSource:                  # ��Ϣ��Դ
                    reqprgs = CheckExploitability(tis,cp,tsa)  # �������
                    print(reqprgs)
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
def FindTargetSoftwareApps(he):#he [organization,dmz]
    softwareApps = []
    for i in he:
        print(i.SoftwareApplications[0].CPEId)
        print('------------------------------')
        softwareApps.extend(i.SoftwareApplications)
    return softwareApps

def ReadAndUpdateSharedMemory():
    pass

