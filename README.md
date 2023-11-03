# 作用

将公开的网页加上登录框

# 配置参考config.json

```json
[
    {
        "port": 18900,
        "addr": "http://127.0.0.1:8080",
        "users": [
            {
                "name": "root",
                "password": "$2b$12$knfPHgT/GUF2sMWZ53zLLeQyhMqpvsLt7sqQ7DQ2we2YjCbxtv9C2"
            },
            {
                "name": "admin",
                "password": "$2b$12$qQ32KLi2Fh/XcjVFUJeIveDIiQ5OCG2HxYNc1tUCyn7nLz.JdazQi"
            }
        ]
    }
]
```

port: 监听端口
addr：代理的地址
users：用户信息列表
users/name：用户名
users/password：经过bcrypt加密后的密码，参考下面

# 生成bcrypt加密后的密码

```shell
./httpp.exe -genpass -password helloword
```

