class AttackGraphNode(object):
    '''
    classdocs
    '''
    InEdge = []  # list

    OutEdge = []  # list

    def __init__(self):
        '''
        Constructor
        '''
        pass



class AttackElementNode(AttackGraphNode):
    '''
    classdocs
    '''
    IPAddress=''     #string
    CPEId=''        #string
    ApplicationName=''      #string
    
    def __init__(self, IPAddress, CPEId, ApplicationName):
        '''
        Constructor
        '''

        self.IPAddress=IPAddress
        self.CPEId=CPEId
        self.ApplicationName=ApplicationName
  


class ISUsage(AttackElementNode):
    '''
    classdocs
    '''
    ISUsage=''      #string

    def __init__(self, IPAddress, CPEId, ApplicationName, ISUsage):
        '''
        Constructor
        '''
        AttackElementNode.__init__(self, IPAddress, CPEId, ApplicationName)
        self.ISUsage=ISUsage
        
        
        
class Privilege(AttackElementNode):
    '''
    classdocs
    '''
    Category=''     #Enum

    def __init__(self,IPAddress, CPEId, ApplicationName, Category):
        '''
        Constructor
        '''
        AttackElementNode.__init__(self, IPAddress, CPEId, ApplicationName)
        self.Category=Category
 
 
 
 
class PrivilegeConjunctionNode(AttackGraphNode):
    '''
    classdocs
    '''
    


    def __init__(self, params):
        '''
        Constructor
        '''

class VExploit(AttackElementNode):
    '''
    classdocs
    '''
    CVEId=''        #string

    def __init__(self, IPAdress, CPEId, ApplicationName, CVEId):
        '''
        Constructor
        '''
        AttackElementNode.__init__(self, IPAdress, CPEId, ApplicationName)
        self.CVEId=CVEId

