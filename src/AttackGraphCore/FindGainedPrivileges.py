# coding=gbk
'''
Created on 2017��10��9��

@author: RHy0ThoM
'''

from AttackTempleModel.RelativeLocation import RelativeLocation

#Ѱ�һ����Ȩ
def FindGainedPrivileges(SP,CP,TSA):

# SP��������ϢԴ��©��
# CP��Ŀǰ����Ȩ
# TSA��Ŀ�����Ӧ��
    BA = RelativeLocation('BackendApplication')                  #���λ��    ���Ӧ�ó���
# �ʺź��Ӧ�ó���ĺ������������λ��ֵ
    for psc in SP.postConditions():                           #��������
        if psc.ExistsIn == BA:                                #������
            for bsa in TSA.backendSoftwareApps():             #������Ӧ�ó���
                gprgs.addAll(FormPrivileges(psc,CP.softwareApp,bsa))
                #  gprgs�������   �����Ȩ (psc,CP�����Ӧ��,bsa)
        else:
            gprgs = FormPrivileges(psc,CP.softwareApp,TSA)
    return gprgs

