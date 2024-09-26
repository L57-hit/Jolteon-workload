import paramiko

# 加载私钥
private_key = paramiko.RSAKey(filename='/home/lty/.ssh/mykey.pem')

# 创建 SSH 客户端
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# 使用私钥连接到服务器
client.connect('hostname', username='user', pkey=private_key)

# 执行命令
stdin, stdout, stderr = client.exec_command('ls')
print(stdout.read().decode())

client.close()

