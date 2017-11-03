# coding=gbk
'''
Created on 2017年10月13日

@author: RHy0ThoM
'''
from AttackGraphCore import DepthFirstSearch
from AttackGraphCore.UpdateAttackGraph import partialAttackGraph
#from AttackGraphCore.MergrPartialAttackGraphs import MergrPartialAttackGraphs
from NetworkModel.NetworkHost import NetworkHost
from NetworkModel.NetworkInterface import NetworkInterface
from NetworkModel.NetworkInterface import CommunicationLink
from NetworkModel.SoftwareApplication import SoftwareApplication
from NetworkModel.HyperGraph import HyperGraph
from NetworkModel.InformationSource import InformationSource
from AttackGraphStructure.AttackGraph import AttackGraph
from AttackGraphStructure.Privilege import Privilege
from AttackTemplateModel.DirectCondition import DirectCondition
#from AttackTemplateModel.InDirectCondition import InDirectCondition
from AttackTemplateModel.Vulnerability import Vulnerability
from graphviz import Digraph


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
postcondition_win7=DirectCondition('user',
                                         'VictimApplication',
                                         'cpe:/a:microsoft:internet_explorer:10'
                                         )
Vulnerability_win7=Vulnerability('CVE-2012-4576',
                                     [precondition_win7],
                                     [postcondition_win7]
                                     )
    
precondition_IE=DirectCondition('user',
                                    'VictimApplication',
                                    'cpe:/a:microsoft:internet_explorer:10'
                                    )
postcondition_IE_1=DirectCondition('FileAccess',
                                       'VictimApplication',
                                       'cpe:/o:microsoft:windows_7::sp2'
                                       )
postcondition_IE_2=DirectCondition('MemoryAccess',
                                       'IntermediateApplication',
                                       'cpe:/a:microsoft:internet_explorer:10'
                                       )
Vulnerability_IE=Vulnerability('CVE-2010-3004',
                                   [precondition_IE],
                                   [postcondition_IE_1]
                                   )

precondition_MT=('user',
                     'VictimApplication',
                     'cpe:/a:mozilla:thunderbird:17.0.2'
                     )
postcondition_MT=('FileAccess',
                      'IntermediateApplication',
                      'cpe:/a:mozilla:thunderbird:17.0.2'
                      )
Vulnerability_MT=Vulnerability('CVE-2011-3544',
                                   [precondition_MT],
                                   [postcondition_MT]
                                   )

'''
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
    
    
    Privilege_IE=Privilege('75.62.2.22',
                           'cpe:/a:microsoft:internet_explorer:10',
                           'Host 2 Internet Explorer',
                           'FileAccess'
                           )
    AccessPrivilege_IE_1=Privilege('75.62.2.22',
                                   'cpe:/a:microsoft:internet_explorer:10',
                                   'Host 2 Internet Explorer',
                                   'FileAccess'
                                   )
    AccessPrivilege_IE_2=Privilege('75.62.2.22',
                                   'cpe:/a:microsoft:internet_explorer:10',
                                   'Host 2 Internet Explorer',
                                   'MemoryAccess')
    
    
    Privilege_MT=Privilege('75.62.2.22',
                           'cpe:/a:mozilla:thunderbird:17.0.2',
                           'Host 2 Mozilla Thunderbird',
                           'FileAccess'
                           )
    '''
InitialPrivilege=Privilege('88.132.3.24',
                               'cpe:/o:microsoft:windows_7::sp2',
                               'Host 1 Windows 7',
                               'FileAccess '       
        )

InformationSource_aws=InformationSource('ApacheWebServer',
                                            [],
                                            [],
                                            [],
                                            )
ApacheWebServer=SoftwareApplication('cpe:/a:apache:http_server:2.2.4',
                                        '75.62.3.33',
                                        76,
                                        [],
                                        [InformationSource_aws],
                                        [],
                                        )

InformationSource_IE=InformationSource('Host 2 Internet Explorer',
                                           [],
                                           [precondition_IE],
                                           [postcondition_IE_1]
                                           )

InternetExplorer=SoftwareApplication('cpe:/a:microsoft:internet_explorer:10',
                                         '75.62.2.22',
                                         34,
                                         [],
                                         [InformationSource_IE],
                                         [Vulnerability_IE],
                                         )
    

MozillaThunderbird=SoftwareApplication('cpe:/a:mozilla:thunderbird:17.0.2',
                                           '75.62.2.22',
                                           48,
                                           [],
                                           [],
                                           [Vulnerability_MT],
                                           )

InformationSource_win7=InformationSource('Host 1 Windows 7',
                                            [InternetExplorer,MozillaThunderbird],
                                            [precondition_win7],
                                            [postcondition_win7]
                                             )



TargetNetwork=HyperGraph()
    
TargetNetwork.Node=[Organization,DMZ,ALAN,LAN1,LAN2]
TargetNetwork.Edge=[[Organization,DMZ],[DMZ,ALAN],[DMZ,LAN1],[DMZ,LAN2],[ALAN,LAN1],[ALAN,LAN2],[LAN1,LAN2]]


NetworkInterface_o=NetworkInterface('88.132.3.24',
                                        CommunicationLink_1,
                                        Organization)

NetworkInterface_d=NetworkInterface('75.62.2.22',
                                        [CommunicationLink_2,CommunicationLink_3,CommunicationLink_4],
                                        DMZ
                                        )
    
NetworkInterface_a=NetworkInterface('75.62.3.35',
                                        [CommunicationLink_5,CommunicationLink_6],
                                        ALAN
                                        )
NetworkInterface_1=NetworkInterface('75.62.3.33',
                                        [CommunicationLink_7],
                                        LAN1
                                        )
    
    
Organization.NetworkInterfaces=[NetworkInterface_o]
Organization.SoftwareApplications.append(SoftwareApplication('cpe:/o:mircosoft:windows_7::sp2',
                                                                 '88.132.3.24',
                                                                 54,
                                                                 [],
                                                                 [InformationSource_win7],
                                                                 [Vulnerability_win7],
                                                                 ))
    
DMZ.NetworkInterfaces=[NetworkInterface_d]
DMZ.SoftwareApplications.append(InternetExplorer)
#DMZ.SoftwareApplications.append(MozillaThunderbird)
    
ALAN.NetworkInterfaces=[NetworkInterface_a]
ALAN.SoftwareApplications.append(SoftwareApplication('cpe:/o:mircosoft:windows_7::sp2',
                                                         '75.62.3.35',
                                                         99,
                                                         [],
                                                         [InformationSource_win7],
                                                         [Vulnerability_win7],
                                                         ))
    
LAN1.NetworkInterfaces=[NetworkInterface_1]
    
'''
    print(Organization.NetworkInterfaces[0].IPAddress)
    print(DMZ.NetworkInterfaces[0].IPAddress)
    print(LAN1.NetworkInterfaces[0].IPAddress)
    print('------------------')
    '''

InitialPrivilege_IE=Privilege('75.62.2.22',
                                  'cpe:/a:microsoft:internet_explorer:10',
                                  'Host 2 Internet Explorer',
                                  'FileAccess'
                                  )
        
IPRGS=[InitialPrivilege]
attackgraph=AttackGraph()

if __name__ == '__main__':
    DepthFirstSearch.PERFORMDFS(TargetNetwork, IPRGS)
    print('------------final answer---------------')
    print(partialAttackGraph.Node[0].CPEId)
    print(partialAttackGraph.Node[0].Type)
    print(partialAttackGraph.Node[1].CPEId)
    print(partialAttackGraph.Node[1].Type )
    print(partialAttackGraph.Node[1].HostIPAddress)
    print(partialAttackGraph.Node[2].Type)
    print(partialAttackGraph.Node[2].CPEId)
    print(partialAttackGraph.Node[3].Type)
    print(partialAttackGraph.Node[3].HostIPAddress)
    print(partialAttackGraph.Node[4].HostIPAddress)
    print(partialAttackGraph.Edge[0][1].HostIPAddress)
    print(partialAttackGraph.Edge)
    print('---------------------------------------')
    dot=Digraph(comment='Attack Graph')
    dot.node(InitialPrivilege.IPAddress)
    for i in partialAttackGraph.Node :
        dot.node(i.HostIPAddress)
    dot.render('test-output/AttackGraph.gv', view=True)