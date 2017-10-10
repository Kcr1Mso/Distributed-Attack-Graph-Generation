# coding=gbk
'''
Created on 2017年10月9日

@author: RHy0ThoM
'''

from AttackTempleModel.RelativeLocation import RelativeLocation

#寻找获得特权
def FindGainedPrivileges(SP,CP,TSA):

# SP可以是信息源的漏洞
# CP是目前的特权
# TSA是目标软件应用
    BA = RelativeLocation('BackendApplication')                  #相对位置    后端应用程序
# 帐号后端应用程序的后置条件的相对位置值
    for psc in SP.postConditions():                           #后置条件
        if psc.ExistsIn == BA:                                #存在于
            for bsa in TSA.backendSoftwareApps():             #后端软件应用程序
                gprgs.addAll(FormPrivileges(psc,CP.softwareApp,bsa))
                #  gprgs添加所有   表格特权 (psc,CP的软件应用,bsa)
        else:
            gprgs = FormPrivileges(psc,CP.softwareApp,TSA)
    return gprgs

