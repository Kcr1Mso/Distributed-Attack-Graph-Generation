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
from NetworkModel.InformationSource import InformationSource
from AttackTemplateModel.Vulnerability import Vulnerability
from AttackGraphStructure.Privilege import Privilege
from AttackTemplateModel.DirectCondition import DirectCondition
from AttackTemplateModel.InDirectCondition import InDirectCondition

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
        
    precondition_win7=DirectCondition('user',
                                      'VictimApplication',
                                      'cpe:/o:microsoft:windows_7::sp2'
                                      )
    postcondition_win7=InDirectCondition('root',
                                         'AttackApplication',
                                         'WebClient'
                                         )
    
    Vulnerability_win7=Vulnerability('CVE-2012-4076',
                                     [precondition_win7],
                                     [postcondition_win7]
                                     )
    
    Privilege_win7=Privilege('88.132.3.24',
                            'cpe:/o:microsoft:windows_7::sp2',
                            'Host 1 Windows 7',
                            'user' 
                            )
    
    AccessPrivilege_win7=Privilege('88.132.3.24',
                                   'cpe:/o:microsoft:windows_7::sp2',
                                   'Host 1 Windows 7',
                                   'root'
                                   )
    
    InitialPrivilege=Privilege('88.132.3.24',
                               'cpe:/o:microsoft:windows_7::sp2',
                               'Host 1 Windows 7',
                               'user'       
        )

    InternetExplorer=SoftwareApplication('cpe:/a:microsoft:internet_explorer:10',
                                         '88.132.3.24',
                                         34,
                                         [],
                                         [],
                                         )
    
    MozillaThunderbird=SoftwareApplication('cpe:/a:mozilla:thunderbird:17.0.2',
                                           '88.132.3.24',
                                           48,
                                           [],
                                           [],
                                           )
    
    InformationSource_win7=InformationSource('Host 1 Windows 7',
                                            [InternetExplorer,MozillaThunderbird],
                                            [precondition_win7],
                                            [postcondition_win7] 
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

    
    DMZ.SoftwareApplications.append(SoftwareApplication('cpe:/o:mircosoft:windows_7::sp2',
                                                       '88.132.3.24',
                                                       80,
                                                       [InternetExplorer,MozillaThunderbird],
                                                       [InformationSource_win7],
                                                       ))
    
    
    
    
    IPRGS=[InitialPrivilege]
    attackgraph=AttackGraph()
    
    DepthFirstSearch.PERFORMDFS(TargetNetwork, IPRGS)
#     attackgraph=MergrPartialAttackGraphs()
    print(partialAttackGraph.Node[0].CPE_ID)
    print(partialAttackGraph.Node[0].Type)
    print(partialAttackGraph.Node[0].InformationSourceName)
    print(partialAttackGraph.Node[1].Type)
    print(partialAttackGraph.Node[1].InformationSourceName)