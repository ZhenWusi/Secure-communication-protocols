# coding:gbk
"""
@Time ： ${2024年6月} 15:57
@Auth ： 甄五四
"""
# coding:gbk
# 导入所需的库
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_v1_5 as ED_PKCS1_v1_5
from Crypto.Hash import SHA256
import base64

# RSASSA-PSS 签名方案
# PSS (Probabilistic Signature Scheme) 是一种基于 RSA 的签名方案，通常被认为比传统的 PKCS#1 v1.5 签名方案更加安全。
# 它采用了一种随机化的方式来生成签名，以增加签名的不可预测性和安全性。
# 随机性：PSS 在生成签名时引入随机盐值，使得即使同一消息多次签名，生成的签名也不同。这种随机性提高了安全性，防止了一些攻击方法。
# 消息扩展：PSS 使用了一个哈希函数（如 SHA-256）对消息进行扩展，然后对扩展后的消息进行签名。
def rsa_sign(data, privatePemPath):
    """
    使用 RSA 私钥对数据进行签名
    :param data: 需要签名的数据
    :param privatePemPath: RSA 私钥的文件路径
    :return: base64 编码的签名
    """
    try:
        # 读取私钥文件
        with open(privatePemPath, 'rb') as private_key_file:
            pri_key = RSA.import_key(private_key_file.read())  # 导入私钥
            signer = pss.new(pri_key)  # 创建 PSS 签名对象
            hash_obj = SHA256.new(data.encode('utf-8'))  # 计算数据的 SHA256 哈希值
            signature = base64.b64encode(signer.sign(hash_obj))  # 使用私钥对哈希值进行签名并进行 base64 编码
            return signature
    except Exception as e:
        print('签名失败:', e)
        return None

def rsa_verify(signature, data, publicPemPath):
    """
    使用 RSA 公钥验证签名
    :param signature: base64 编码的签名
    :param data: 原始数据
    :param publicPemPath: RSA 公钥的文件路径
    :return: 签名验证结果，True 表示验证通过，False 表示验证失败
    """
    try:
        # 读取公钥文件
        with open(publicPemPath, 'rb') as public_key_file:
            pub_key = RSA.import_key(public_key_file.read())  # 导入公钥
            hash_obj = SHA256.new(data.encode('utf-8'))  # 计算数据的 SHA256 哈希值
            verifier = pss.new(pub_key)  # 创建 PSS 验证对象
            verifier.verify(hash_obj, base64.b64decode(signature))  # 使用公钥验证签名
            return True
    except (ValueError, TypeError) as e:
        print('验签失败:', e)
        return False
# PKCS#1 v1.5：一种经典的 RSA 加密和签名填充方案,本课设用此实现加解密
def rsa_encrypt(publicPemPath, RSA_DecryptText):
    """
    使用 RSA 公钥对数据进行加密
    :param publicPemPath: RSA 公钥的文件路径
    :param RSA_DecryptText: 需要加密的数据
    :return: base64 编码的加密数据
    """
    with open(publicPemPath, 'r') as f:
        key = f.read()  # 读取公钥文件内容
        rsakey = RSA.import_key(key)  # 导入公钥
        cipher = ED_PKCS1_v1_5.new(rsakey)  # 创建 PKCS1_v1_5 加密对象
        RSA_EncrptText = base64.b64encode(cipher.encrypt(RSA_DecryptText.encode('utf-8')))  # 使用公钥加密数据并进行 base64 编码
    return RSA_EncrptText

def rsa_decrypt(privatePemPath, RSA_EncrptText):
    """
    使用 RSA 私钥对数据进行解密
    :param privatePemPath: RSA 私钥的文件路径
    :param RSA_EncrptText: base64 编码的加密数据
    :return: 解密后的原始数据
    """
    with open(privatePemPath, 'r') as f:
        key = f.read()  # 读取私钥文件内容
        rsakey = RSA.import_key(key)  # 导入私钥
        cipher = ED_PKCS1_v1_5.new(rsakey)  # 创建 PKCS1_v1_5 解密对象
        RSA_DecryptText = cipher.decrypt(base64.b64decode(RSA_EncrptText), "ERROR")  # 使用私钥解密数据
    return RSA_DecryptText
