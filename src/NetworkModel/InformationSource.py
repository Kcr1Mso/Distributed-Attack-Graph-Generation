# coding=gbk
'''
Created on 2017年9月26日

@author: RHy0ThoM
'''

class InformationSource(object):
    '''
    classdocs
    
    An information source denotes a sensitive data store that is contained by a software application and can be accessed 
    and used by an attacker. It is represented by a three tuple
    <ReferencedSoftware;Preconditions; Postconditions>
    '''
    name=''     #string
    
    ReferencedSoftware=[]       #list
    '''
    The postconditions are gained on the software applications referenced by the information source that are stored by 
    the element ReferencedSoftware.
    '''
    Preconditions=[]        #list
    '''
     In order to use an information source, an attacker should satisfy the preconditions that are stored in the list 
     Preconditions for the information source
    '''
    Postconditions=[]       #list
    '''
    After successfully benefiting from the information source, the attacker gains the postconditions that are stored 
    in the list Postconditions for the information source. 
    '''
    def __init__(self, name, ReferencedSoftware, Preconditions, Postconditions):
        '''
        Constructor
        '''
        self.name=name
        self.ReferencedSoftware=ReferencedSoftware
        self.Preconditions=Preconditions
        self.Postconditions=Postconditions
        