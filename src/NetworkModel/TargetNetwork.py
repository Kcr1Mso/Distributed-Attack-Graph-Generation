# coding=gbk
'''
Created on 2017年10月10日

@author: RHy0ThoM
'''
from NetworkModel.NetworkHost import NetworkHost
from NetworkModel.NetworkInterface import NetworkInterface
from NetworkModel.NetworkInterface import CommunicationLink
from NetworkModel.SoftwareApplication import SoftwareApplication

Organization=NetworkHost()      #origin attack
DMZ=NetworkHost()               #4 web servers    &&    2 Database    &&    1 Mail
ALAN=NetworkHost()              
LAN1=NetworkHost()
LAN2=NetworkHost()

TargetNetwork=[Organization,DMZ,ALAN,LAN1,LAN2]

CommunicationLink_1=CommunicationLink(Organization,DMZ)

CommunicationLink_2=CommunicationLink(DMZ,ALAN)
CommunicationLink_3=CommunicationLink(DMZ,LAN1)
CommunicationLink_4=CommunicationLink(DMZ,LAN2)

CommunicationLink_5=CommunicationLink(ALAN,LAN1)
CommunicationLink_6=CommunicationLink(ALAN,LAN2)

CommunicationLink_7=CommunicationLink(LAN1,LAN2)

Organization.NetworkInterface.append(NetworkInterface('75.62.134.65',
                                                      CommunicationLink_1,
                                                      80
    ))

print(Organization.NetworkInterface[0].IPAddress)


DMZ.NetworkInterface.append(NetworkInterface('75.62.132.64',
                                             [CommunicationLink_2,CommunicationLink_3,CommunicationLink_4],
                                             80
                                             ))

DMZ.SoftwareApplication.append(SoftwareApplication('cpe:/a:apache:http_server:2.4.3',
                                                   '75.62.132.65',
                                                   80,
                                                   [],
                                                   [],
                                                   ))
print(DMZ.SoftwareApplication[0].HostIPAddress)
print(Organization.NetworkInterface[0].Link.TargetNetworkInterface.SoftwareApplication[0].HostIPAddress)
