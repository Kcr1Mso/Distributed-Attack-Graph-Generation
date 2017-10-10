# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''
from NetworkModel.NetworkHost import NetworkHost
from NetworkModel.CommunicationLink import CommunicationLink

class NetworkInterface(NetworkHost):
    '''
    classdocs
    
    A network interface denotes a OSI Layer 3 interface on a network host and is a three element tuple
    
    <IPAdress,Link,Host>
    '''
    IPAdress=''         #string    the IP address associated with the network interface
    Link=CommunicationLink()        #the communication link connected to the network interface
    Host=NetworkHost()          #the network host containing the network interface

    def __init__(self, NetworkInterface, SoftwareApplication, IPAdress,Link,Host):
        '''
        Constructor
        '''
        NetworkHost.__init__(self, NetworkInterface, SoftwareApplication)
        self.IPAdress=IPAdress
        self.Link=Link
        self.Host=Host
        