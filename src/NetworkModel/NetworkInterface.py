# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

class NetworkInterface(object):
    '''
    classdocs
    
    A network interface denotes a OSI Layer 3 interface on a network host and is a three element tuple
    
    <IPAdress,Link,Host>
    '''
    IPAddress=''         #string    the IP address associated with the network interface
    Link=[]                   #the communication link connected to the network interface
    Host=0          #the network host containing the network interface

    def __init__(self,IPAddress,Link,Host):
        '''
        Constructor
        '''
        self.IPAddress=IPAddress
        self.Link=Link
        self.Host=Host
        
        
class CommunicationLink(object):
    '''
    classdocs
    '''

    SourceNetworkInterface=NetworkInterface
    TargetNetworkInterface=NetworkInterface
    
    
    
    def __init__(self, SourceNetworkInterface,TargetNetworkInterface):
        '''
        Constructor
        '''
        self.SourceNetworkInterface=SourceNetworkInterface
        self.TargetNetworkInterface=TargetNetworkInterface
  
        