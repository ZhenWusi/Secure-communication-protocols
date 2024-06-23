# 安全通信协议

基于RSA实现加密解密，签名验签 

基于SHA256计算Hash值 

基于3DES加解密,基于DH实现密钥交换

若出现进程阻塞问题

`netstat -ano|findstr 9999（端口号)`查看端口占用情况

`taskkill /PID 8456(进程号) /F `中止对应进程

首先你需要配置环境，我的代码在python3.12.4运行，相关python包可通过
`pip install -r requirements`安装

首先运行`BobServer.py`启动服务器，之后运行`AliceClient.py`
可以运行`RSA_KEY.py`生产Bob和Alice的公私钥

DiffieHellman中为DH密钥交换相关代码

RSA_SVED为RSA加解密、签名验签代码

TDES为3DES加解密代码

Function涉及协议通信过程中收发信息，身份验证随机数生产、时间戳等相关函数

该课设已同步到，后期根据需要完善，如有疑问，欢迎留言！

    By 九九
    2024年6月15
