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
    
    '''                  
    account for relative location value of backend application
    for postconditions 
    '''
    
    gprgs = []
    BA=RelativeLocation.BackendApplication

    for psc in SP.Postconditions:                             #后置条件
        print(psc.ExistIn)
        print(BA)
        if psc.ExistIn == BA:              #存在于
            print('psc.existin')
            for bsa in TSA.backendSoftwareApps:               #后端软件应用程序
                gprgs.extend(FormPrivileges(psc,CP.ApplicationName,bsa))
                #  gprgs添加所有   表格特权 (psc,CP的软件应用,bsa)
        else:
            print('psc.existin')
            gprgs = FormPrivileges(psc,CP.ApplicationName,TSA)
    return gprgs                                              #gprgs 是一个表


def FormPrivileges(PreConditions, SoftwareApp, TSA):
    for i in TSA.InformationSource:
        print('------cond-----------')
        print(PreConditions)
        print(i.Preconditions)
        print(i.name)
        print(SoftwareApp)
        print(i.Postconditions)
        print('---------------------')
        if PreConditions == i.Preconditions:
            if SoftwareApp == i.name:
                print(i.Postconditions)
                print('----------1111---------')
                return i.Postconditions
    else:
        return []
    '''
    for i in TSA.vulnerabilities:
        if PreConditions in i.Preconditions:
            if SoftwareApp == i.name:
                return i.Postconditions
'''