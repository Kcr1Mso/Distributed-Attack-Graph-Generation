# coding=gbk
'''
Created on 2017年10月9日

@author: RHy0ThoM
'''

from AttackTemplateModel.RelativeLocation import RelativeLocation


def FindGainedPrivileges(SP,CP,TSA):

# SP can be a vulnerability or information source
# CP is the current privilege
# TSA is the target software application

    BA = RelativeLocation('BackendApplication')
    
    '''                  
    account for relative location value of backend application
    for postconditions 
    '''
    
    gprgs=[]
    
    for psc in SP.postConditions():
        if psc.ExistsIn == BA:                                
            for bsa in TSA.backendSoftwareApps():             
                gprgs.addAll(FormPrivileges(psc,CP.softwareApp,bsa))
            
        else:
            gprgs = FormPrivileges(psc,CP.softwareApp,TSA)
    return gprgs

def FormPrivileges(psc,softwareApp,TSA):
    pass