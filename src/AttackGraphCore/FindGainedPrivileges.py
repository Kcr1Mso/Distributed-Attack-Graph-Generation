# coding=gbk
'''
Created on 2017��10��9��

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

    for psc in SP.postConditions:                             #��������
        if psc.Existsln == "BackendApplication":              #������
            for bsa in TSA.backendSoftwareApps:               #������Ӧ�ó���
                gprgs.extend(FormPrivileges(psc,CP.softwareApp,bsa))
                #  gprgs�������   �����Ȩ (psc,CP�����Ӧ��,bsa)
        else:
            gprgs = FormPrivileges(psc,CP.softwareApp,TSA)
    return gprgs                                              #gprgs ��һ����


def FormPrivileges(psc,softwareApp,TSA):
    pass