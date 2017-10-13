# coding=gbk
'''
Created on 2017年10月9日

@author: RHy0ThoM
'''

def FindGainedPrivileges(SP,CP,TSA):

# SP can be a vulnerability or information source
# CP is the current privilege
# TSA is the target software application
    
    '''                  
    account for relative location value of backend application
    for postconditions 
    '''
    
    gprgs = []

    for psc in SP.postConditions:                             #后置条件
        if psc.Existsln == "BackendApplication":              #存在于
            for bsa in TSA.backendSoftwareApps:               #后端软件应用程序
                gprgs.extend(FormPrivileges(psc,CP.softwareApp,bsa))
                #  gprgs添加所有   表格特权 (psc,CP的软件应用,bsa)
        else:
            gprgs = FormPrivileges(psc,CP.softwareApp,TSA)
    return gprgs                                              #gprgs 是一个表


def FormPrivileges(psc,softwareApp,TSA):
    pass