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

    for psc in SP.Postconditions:                             #��������
        if psc.ExistIn == "BackendApplication":              #������
            for bsa in TSA.backendSoftwareApps:               #������Ӧ�ó���
                gprgs.extend(FormPrivileges(psc,CP.ApplicationName,bsa))
                #  gprgs�������   �����Ȩ (psc,CP�����Ӧ��,bsa)
        else:
            gprgs = FormPrivileges(psc,CP.ApplicationName,TSA)
    return gprgs                                              #gprgs ��һ����


def FormPrivileges(PreConditions, SoftwareApp, TSA):
    print('----------------------------------')
    print(PreConditions)
    print(SoftwareApp)
    for i in TSA.InformationSource:
        print(i.Preconditions)
        print(i.name)
        if PreConditions == i.Preconditions:
            if SoftwareApp == i.name:
                return i.Postconditions
    '''
    for i in TSA.vulnerabilities:
        if PreConditions in i.Preconditions:
            if SoftwareApp == i.name:
                return i.Postconditions
'''