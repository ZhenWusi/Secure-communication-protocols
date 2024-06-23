# coding:gbk
"""
@Time ： ${2024年6月} 15:56
@Auth ： 甄五四
"""
# coding:gbk
'''
Outputs:    timeStamp() 生成时间戳
            sendTo(theSocket, message, hint=None) 向对方套接字发送消息
            readFrom(theSocket, hint=None) 从对方套接字接收消息
            sendLegalInfoTo(theSocket, privatePemPath, publicPemPath) 生成随机数让对方进行合法性校验
            readLegalInfoFrom(theSocket, publicPemPath) 校验对方身份的合法性
            RSA_SignatureTo(theSocket, RSA_DecryptText, privatePemPath) 向对方发送时间戳，签名，校验信息
            RSA_VerifyFrom(theSocket, publicPemPath) 校验对方发来的时间戳，签名，校验信息
            communicatePackageReceiver(theSocket, TDES_Key, publicPemPath) 发送通信数据包
            communicatePackageReceiver(theSocket, TDES_Key, publicPemPath) 接收通信数据包
            sendingThread(theSocket, TDES_Key, privatePemPath) 发送通信数据包的线程方法
            receivingThread(theSocket, TDES_Key, publicPemPath) 接收通信数据包的线程方法
'''
import random
import time
import RSA_SVED
import hashlib
# 实现RSA 签名 验签 加密 解密的底层模块
import TDES
# 实现3DES算法加解密的底层模块
# 定义一个全局字典，用于存储已使用的Nonce
used_nonces = {}
def generate_nonce():
    # 生成一次性随机数Nonce，并检查是否已存在于字典中，如果存在则重新生成
    while True:
        nonce = str(random.randint(1, 2**16))
        if nonce not in used_nonces:
            used_nonces[nonce] = True
            return nonce
def timeStamp():
    # 生成时间戳
    currentTime = time.strftime('%Y年%m月%d日 %H:%M:%S', time.localtime(time.time()))
    return currentTime
def sendTo(theSocket, message, hint=None):
    nonce = generate_nonce()
    timestamp = timeStamp()
    print(f"发送时间戳: {timestamp}")
    message_with_nonce = f"{message}-{nonce}-{timestamp}"
    hash_value = hashlib.sha256(message_with_nonce.encode()).hexdigest()
    message_to_send = f"{message_with_nonce}-{hash_value}"
    theSocket.send(message_to_send.encode('utf-8'))
    if hint is not None:
        print(hint)

def readFrom(theSocket, hint=None):
    message_received = theSocket.recv(1024).decode('utf-8')
    if hint is not None:
        print(hint)
    parts = message_received.split('-')
    if len(parts) < 4:
        print("消息格式不正确！")
        return None
    message = '-'.join(parts[:-3])
    nonce = parts[-3]
    timestamp = parts[-2]
    received_hash = parts[-1]
    print(f"接收到的消息: {message}")
    print(f"接收到的时间戳: {timestamp}")
    if not timestamp:
        print("时间戳不存在或格式错误！")
        return None
    if nonce in used_nonces:
        print("Nonce已被使用过，可能是重放攻击！")
        return None
    hash_value = hashlib.sha256(f"{message}-{nonce}-{timestamp}".encode()).hexdigest()
    if hash_value != received_hash:
        print("消息摘要不匹配，可能是被篡改的消息！")
        return None
    used_nonces[nonce] = True
    return message
def sendLegalInfoTo(theSocket, privatePemPath, publicPemPath):
    # 向对方发送随机数等校验信息进行合法性认证
    LegalMessage = str(random.randint(2**31, 2**32))
    RSA_EncryptSignatureTo(theSocket, LegalMessage, privatePemPath, publicPemPath)
    # 先用对方RSA公钥对生成的随机数加密
    # 然后用自己的私钥对RSA密文的SHA256值签名
    # 最后把时间戳、签名、RSA密文发过去
def readLegalInfoFrom(theSocket, publicPemPath):
    # 对对方的随机数等信息进行合法性校验
    legal = RSA_VerifyFrom(theSocket, publicPemPath)
    # 收到对方时间戳
    # 收到对方签名后用对方的公钥解签，得到签名中的SHA256值
    # 对一同发来的RSA密文（校验信息）作SHA256
    # 如果两个SHA256值相等则验证对方为合法
    return legal
    # 返回是否合法
def RSA_EncryptSignatureTo(theSocket, RSA_DecryptText, privatePemPath, publicPemPath):
    # 输入str类型的RSA_DecryptText
    # 先用对方公钥加密，再对密文的SHA256值签名
    # 如果先签名后加密会导致加密的输入太长而无法加密！！！
    print()
    print('正在用对方RSA公钥加密，加密前为：', RSA_DecryptText)
    RSA_EncryptText = str(RSA_SVED.rsa_encrypt(publicPemPath, RSA_DecryptText))
    # 先用对方RSA公钥加密生成str型RSA密文
    print('正在用本机RSA私钥对密文Hash值签名')
    RSA_Signature = RSA_SVED.rsa_sign(RSA_EncryptText, privatePemPath)
    # 再对RSA密文签名生成bytes类型的RSA签名
    sendTo(theSocket, RSA_EncryptText, '已发送校验信息：' + RSA_EncryptText)
    sendTo(theSocket, RSA_Signature, '已发送RSA签名：' + str(RSA_Signature))
    print()


def RSA_VerifyFrom(theSocket, publicPemPath):
    # 验签
    print()
    RSA_EncryptText = readFrom(theSocket, '已收到校验信息')
    # str型校验信息
    print('校验信息为：', RSA_EncryptText)
    RSA_Signature = readFrom(theSocket, '已收到对方的RSA签名').replace("b'", '').replace("'", '').encode('UTF-8')
    print('签名为：', RSA_Signature)
    legal = RSA_SVED.rsa_verify(RSA_Signature, RSA_EncryptText, publicPemPath)
    print('对方身份是否合法：', legal)
    print()
    return legal, RSA_EncryptText
    # 返回boolean值表示是否合法，str型的校验信息，即 RSA密文


def communicatePackageSender(theSocket, TDES_Key, privatePemPath, publicPemPath, TDES_DecryptText):
    # 对str型的原始明文TDES_DecryptText进行一系列操作后发包
    prpcryptObject = TDES.prpcrypt()
    # 新建TDES对象
    TDES_EncryptText = TDES.DES_Encrypt(prpcryptObject, TDES_DecryptText, TDES_Key)
    # 加密原始明文生成str型 TDES密文
    RSA_EncryptSignatureTo(theSocket, TDES_EncryptText, privatePemPath, publicPemPath)
    # 对TDES密文用对方公钥加密后签名，连同校验信息一并发送给服务器
    print()
    # 发送完一个数据包后换行
def communicatePackageReceiver(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # 按序接收对方发来的时间戳，签名，TDES密文
    # 对签名进行校验，无误后再进行TDES解密
    legalClient, RSA_DecryptText = RSA_VerifyFrom(theSocket, publicPemPath)
    # 返回值为boolean型值是否合法和str型校验信息
    RSA_DecryptText = RSA_DecryptText.replace("b'", '').replace("'", '')
    # 仍为str型，规范化便于使用rsa_decrypt()解密
    if legalClient:
        # 如果对方合法则对密文进行解密
        TDES_EncryptText = str(RSA_SVED.rsa_decrypt(privatePemPath, RSA_DecryptText))
        # 用自己的私钥解密RSA密文得到TDES密文
        # 返回bytes型TDES密文后转为str
        TDES_EncryptText = str(TDES_EncryptText).replace("b'", '').replace("'", '')
        # str型，将TDES密文规范化便于TDES_Decrypt()解密
        prpcryptBob = TDES.prpcrypt()
        # 新建TDES对象
        TDES_DecryptText = TDES.DES_Decrypt(prpcryptBob, TDES_EncryptText, TDES_Key)
        # 解密得到str型的TDES明文
        return TDES_DecryptText
        # 返回str型的TDES明文


def sendingThread(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # 主模块中线程调用的发送函数
    while True:
        TDES_DecryptText = input('输入英文或输入quit结束发送：')
        communicatePackageSender(theSocket, TDES_Key, privatePemPath, publicPemPath, TDES_DecryptText)
        if TDES_DecryptText == 'quit':
            # 发送线程结束
            print('发送线程结束')
            print()
            break



def receivingThread(theSocket, TDES_Key, privatePemPath, publicPemPath):
    # 主模块中线程调用的监听函数
    while True:
        TDES_DecryptText = communicatePackageReceiver(theSocket, TDES_Key, privatePemPath, publicPemPath)
        if TDES_DecryptText[0:5] == 'quit':
            # 监听线程结束
            print('监听线程结束')
            print()
            break



