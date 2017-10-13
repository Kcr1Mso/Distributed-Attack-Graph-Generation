# coding=gbk
'''
Created on 2017年10月13日

@author: RHy0ThoM
'''
from AttackGraphCore import DepthFirstSearch
from NetworkModel.NetworkHost import NetworkHost
from NetworkModel.NetworkInterface import NetworkInterface
from NetworkModel.NetworkInterface import CommunicationLink
from NetworkModel.SoftwareApplication import SoftwareApplication
from NetworkModel.HyperGraph import HyperGraph
from AttackGraphStructure.AttackGraph import AttackGraph
from AttackGraphCore.MergrPartialAttackGraphs import MergrPartialAttackGraphs
from AttackGraphCore.UpdateAttackGraph import partialAttackGraph

if __name__ == '__main__':

    Organization=NetworkHost()      #origin attack
    DMZ=NetworkHost()               #4 web servers    &&    2 Database    &&    1 Mail
    ALAN=NetworkHost()              
    LAN1=NetworkHost()
    LAN2=NetworkHost()

    CommunicationLink_1=CommunicationLink(Organization,DMZ)

    CommunicationLink_2=CommunicationLink(DMZ,ALAN)
    CommunicationLink_3=CommunicationLink(DMZ,LAN1)
    CommunicationLink_4=CommunicationLink(DMZ,LAN2)
    
    CommunicationLink_5=CommunicationLink(ALAN,LAN1)
    CommunicationLink_6=CommunicationLink(ALAN,LAN2)
    
    CommunicationLink_7=CommunicationLink(LAN1,LAN2)
    
    TargetNetwork=HyperGraph()
    
    TargetNetwork.Node=[Organization,DMZ,ALAN,LAN1,LAN2]
    TargetNetwork.Edge=[CommunicationLink_1,CommunicationLink_2,CommunicationLink_3,CommunicationLink_4,
                          CommunicationLink_5,CommunicationLink_6,CommunicationLink_7
                          ]
    
    Organization.NetworkInterface.append(NetworkInterface('75.62.134.65',
                                                          CommunicationLink_1,
                                                          80
        ))
    
    DMZ.NetworkInterface.append(NetworkInterface('75.62.132.64',
                                                 [CommunicationLink_2,CommunicationLink_3,CommunicationLink_4],
                                                 80
                                                 ))
    
    InternetExplorer=SoftwareApplication('cpe:/a:microsoft:internet_explorer:10',
                                         '75.62.132.65',
                                         34,
                                         [],
                                         [],
                                         )
    
    MozillaThunderbird=SoftwareApplication('cpe:/a:mozilla:thunderbird:17.0.2',
                                           '75.62.132.65',
                                           48,
                                           [],
                                           [],
                                           )
    
    DMZ.SoftwareApplication.append(SoftwareApplication('cpe:/o:mircosoft:windows_xp::sp2',
                                                       '75.62.132.65',
                                                       80,
                                                       [InternetExplorer,MozillaThunderbird],
                                                       [],
                                                       ))
    
    
    
    
    IPRGS=[]
    
    DepthFirstSearch.PERFORMDFS(TargetNetwork, IPRGS)
    MergrPartialAttackGraphs(partialAttackGraph)
    print()