# coding=gbk
'''
Created on 2017年10月12日

@author: RHy0ThoM
'''
from _overlapped import NULL

#定义超图：由顶点和超边两个表（超边为多个定点的表）
class HyperGraph:
    def __init__(self, x = [] , y = []):
        self.Node = x
        self.Edge = y
    def findVertexForPriv(self , x):
        for i in self.Node:
            if i.NetworkInterfaces[1].IPAddress == x.IPAddress:
                print(i.NetworkInterfaces[1].IPAddress)
                return i
        else:
            return NULL
    def findContainingEdges(self , x):
        find_edges = []
        for i in self.Edge:
            for j in i:
                if j == x :
                    find_edges.append(i)
                    break
        return find_edges