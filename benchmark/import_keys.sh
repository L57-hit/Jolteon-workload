#!/bin/bash

# 配置密钥名称和公钥路径
KEY_NAME="mykey.pem"
PUBLIC_KEY_FILE="mykey.pub"

# 获取所有支持的区域
for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
    echo "正在将密钥导入区域: $region"
    # 导入密钥
    aws ec2 import-key-pair --key-name "$KEY_NAME" --public-key-material fileb://$PUBLIC_KEY_FILE --region "$region"
done

