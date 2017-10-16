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
#from AttackGraphCore.MergrPartialAttackGraphs import MergrPartialAttackGraphs
from AttackGraphCore.UpdateAttackGraph import partialAttackGraph
from NetworkModel.InformationSource import InformationSource
from AttackTemplateModel.Vulnerability import Vulnerability
from AttackGraphStructure.Privilege import Privilege

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
    
    Vulnerability_IE=Vulnerability('CVE-2012-4076',
                                   [],
                                   []
                                   )
    
    Privilege_IE=Privilege('88.132.3.24',
                           'cpe:/a:microsoft:internet_explorer:10',
                           'InternetExplorer',
                           'user'
                           )
    AccessPrivilege_IE=Privilege('88.132.3.24',
                                 'cpe:/a:microsoft:internet_explorer:10',
                                 'InternetExplorer',
                                 'root'
                                 )
    
    InitialPrivilege=Privilege('88.132.3.24',
                               'cpe:/o:microsoft:windows_xp::sp2',
                               'Host 1 Windows XP',
                               'user'       
        )
    
    
    InformationSource_IE=InformationSource('InformationSource_IE',
                                           [],
                                           [DMZ,
                                            InitialPrivilege,
                                            [Organization,DMZ],
                                            Privilege_IE
                                            ],
                                           [AccessPrivilege_IE]
                                           )
    
    TargetNetwork=HyperGraph()
    
    TargetNetwork.Node=[Organization,DMZ,ALAN,LAN1,LAN2]
    TargetNetwork.Edge=[[Organization,DMZ]]
    
    NetworkInterface_o=NetworkInterface('88.132.3.22',
                                        CommunicationLink_1,
                                        Organization)
    NetworkInterface_d=NetworkInterface('88.132.3.24',
                                        [CommunicationLink_2,CommunicationLink_3,CommunicationLink_4],
                                        DMZ
                                        )
    
    Organization.NetworkInterfaces=[NetworkInterface_o]
    
    DMZ.NetworkInterfaces=[NetworkInterface_d]
    
    
    print(DMZ.NetworkInterfaces[0].IPAddress)
    print('------------------')
    InternetExplorer=SoftwareApplication('cpe:/a:microsoft:internet_explorer:10',
                                         '88.132.3.24',
                                         34,
                                         [],
                                         [InformationSource_IE],
                                         )
    
    MozillaThunderbird=SoftwareApplication('cpe:/a:mozilla:thunderbird:17.0.2',
                                           '88.132.3.24',
                                           48,
                                           [],
                                           [],
                                           )
    
    DMZ.SoftwareApplications.append(SoftwareApplication('cpe:/o:mircosoft:windows_7::sp2',
                                                       '88.132.3.24',
                                                       80,
                                                       [InternetExplorer,MozillaThunderbird],
                                                       [],
                                                       ))
    
    
    
    
    IPRGS=[InitialPrivilege]
    attackgraph=AttackGraph()
    
    #print(DMZ.NetworkInterfaces[1].IPAddress)        
    
    DepthFirstSearch.PERFORMDFS(TargetNetwork, IPRGS)
    #attackgraph=MergrPartialAttackGraphs(partialAttackGraph)
    print(partialAttackGraph.Node)