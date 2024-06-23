# coding:gbk
"""
@Time ： ${2024年6月} 15:58
@Auth ： 甄五四
"""
# coding:gbk
'''
三重DES加解密
'''
from Crypto.Cipher import DES3
import base64
class prpcrypt():
    def __init__(self):
        self.mode = DES3.MODE_ECB
        # 加密模式
        self.BS = DES3.block_size
    def pad(self, s):
        bw = self.BS - len(s) % self.BS
        if bw != 8:
            # 每8位一组，不足8位需要补位。
            lackLength = self.BS - len(s) % self.BS
            midStr = (self.BS - len(s) % self.BS) * chr(32)
            return s + midStr.encode('UTF-8')
            # 返回 补位后的bytes串
        else:
            return s
            # 直接返回
    def unpad(self, s):
        bw = self.BS - len(s) % self.BS
        if bw !=8:
            return s[0:-ord(s[-1])]
        return s
    def encrypt(self, text, key):
        # 加密
        text = self.pad(text)
        cryptor = DES3.new(key, self.mode)
        x = len(text) % 8
        if x != 0:
            text = text + '\0' * (8 - x)
        self.ciphertext = cryptor.encrypt(text)
        return base64.standard_b64encode(self.ciphertext).decode("utf-8")
    def decrypt(self, text, key):
        # 解密
        cryptor = DES3.new(key, self.mode)
        de_text = base64.standard_b64decode(text)
        plain_text = cryptor.decrypt(de_text)
        st = str(plain_text.decode("utf-8")).rstrip('\0')
        out = self.unpad(st)
        return out

def DES_Encrypt(prpcrypt, TDES_DecryptText, TDES_Key):
    # 加密：传入一个3DES对象，str型的明文和24位str型密钥
    TDES_DecryptText = TDES_DecryptText.encode('UTF-8')
    TDES_Key = TDES_Key.encode('UTF-8')
    TDES_EncryptText = prpcrypt.encrypt(TDES_DecryptText, TDES_Key)
    print('生成3DES密文为：', TDES_EncryptText)
    return TDES_EncryptText
    # 返回TDES加密的str密文
def DES_Decrypt(prpcypt, TDES_EncryptText, TDES_Key):
    # 解密：传入一个3DES对象，str型的密文和24位str型密钥
    print('3DES密文为：', TDES_EncryptText)
    TDES_EncryptText = TDES_EncryptText.encode('UTF-8')
    TDES_Key = TDES_Key.encode('UTF-8')
    TDES_DecryptText = prpcypt.decrypt(TDES_EncryptText, TDES_Key)
    print('解密得到3DES明文为：', TDES_DecryptText)
    print()
    return TDES_DecryptText.strip(chr(32))
    # 去掉填充的空格后返回str类型的明文
