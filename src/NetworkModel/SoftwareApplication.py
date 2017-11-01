# coding=gbk
''' 
Created on 2017年9月26日

@author: RHy0ThoM
'''
from AttackTemplateModel.Vulnerability import Vulnerability

class SoftwareApplication(object):
    '''
    classdocs
    
    <CPEId,HostIPAdress,Port,BackendApplications,InformationSources>
    
    '''
    CPEId=''    #string
    '''
    CPEId denotes the software product identifier。
    '''
    HostIPAddress=''     #string
    '''
    HostIPAddress denotes the IP address on which the software application is serving
    '''
    Port=0      #Integer
    '''
    Port denotes the port on which it is serving
    '''
    BackendApplication=[]       #list
    '''
    BackendApplications refers to the software applications whose services are used by this software application
    '''
    InformationSource=[]        #list
    '''
    InformationSources is a list of information sources contained by the software application such as
     credentials store, cookies, DNS table, routing table, databases.
    '''
    
    Vulnerabilities=[]
    def __init__(self, CPEId, HostIPAddress, Port, BackendApplication, InformationSource, Vulnerabilities):
        '''
        Constructor
        '''
        self.CPEId=CPEId
        self.HostIPAddress=HostIPAddress
        self.Port=Port
        self.BackendApplication=BackendApplication
        self.InformationSource=InformationSource
        self.Vulnerabilities=Vulnerabilities
        