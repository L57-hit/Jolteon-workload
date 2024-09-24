from paramiko import SSHClient, RSAKey, AutoAddPolicy

client = SSHClient()
client.set_missing_host_key_policy(AutoAddPolicy())
private_key = RSAKey(filename='~/.ssh/aws')
print("Using private key:", private_key)
client.connect('hostname', username='your_user', pkey=private_key)

