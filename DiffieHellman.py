# coding:gbk
"""
@Time ： ${2024年6月} 15:55
@Auth ： 甄五四
"""
# -*- coding: utf-8 -*-
import pyDHE
def DH_Original(group):
    # 根据int型group自动选择素数和本原根并生成DHE对象及公私钥对
    DH_Object = pyDHE.new(group)
    print("正在生成本机DH公私钥...")
    DH_PublicKey = DH_Object.getPublicKey()
    # 生成公钥
    DH_PrivateKey = DH_Object.a
    # 生成私钥
    print("本机DH公钥：", str(DH_PublicKey)[0:20])
    print("本机DH私钥：", str(DH_PrivateKey)[0:20])
    return DH_Object, DH_PrivateKey, DH_PublicKey
def DH_FinalKeyGenerator(DH_Object, DH_OppositePublicKey):
    # DHE对象使用对方发来的公钥生成最终的共享DH密钥
    DH_FinalKey = DH_Object.update(DH_OppositePublicKey)
    print("本机计算的DH共享密钥：", str(DH_FinalKey)[0:20])
    print()
    return DH_FinalKey
