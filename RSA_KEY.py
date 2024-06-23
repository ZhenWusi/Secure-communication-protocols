# coding:gbk
"""
@Time ： ${2024年6月} 15:57
@Auth ： 甄五四
"""
# coding:gbk
'''
RSA加解密生成，本课程设计加解密和签名验证密钥一样
'''
from Crypto import Random
from Crypto.PublicKey import RSA
def generate_and_store_keys(identity):
    random_generator = Random.new().read
    # 随机数生成器
    # 生成用于RSA加密的公私钥对
    rsa_encryption = RSA.generate(2048, random_generator)
    private_pem_encryption = rsa_encryption.exportKey()
    public_pem_encryption = rsa_encryption.publickey().exportKey()
    with open(f'RSA_Private{identity}.pem', 'wb') as f:
        f.write(private_pem_encryption)
    with open(f'RSA_Public{identity}.pem', 'wb') as f:
        f.write(public_pem_encryption)
# 生成Alice的公私钥对
generate_and_store_keys('Alice')
# 生成Bob的公私钥对
generate_and_store_keys('Bob')
