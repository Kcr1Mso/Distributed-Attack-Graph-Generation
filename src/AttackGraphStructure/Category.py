# coding=gbk
'''
Created on 2017��9��26��

@author: RHy0ThoM
'''
from enum import Enum

class Category(Enum):
    '''
    classdocs
    '''
    Category=Enum('Random Code Execution',
                  
                  
                  'File Access'         #Application or OS file
                  'Memory Access'       #Application or OS level
                  'Security Information'        #Credentials
                  
                  
                  )

    def __init__(self):
        '''
        Constructor
        '''
        