# FinalTun
Inspired by KCPTun and FinalSpeed

```

                 +---------------------------------------+
                 |                                       |
                 |                KCPTUN                 |
                 |                                       |
 +--------+      |  +------------+       +------------+  |      +--------+
 |        |      |  |            |       |            |  |      |        |
 | Client | +--> |  |Final Client| +---> |Final Client|  | +--> | Server |
 |        |      |  |            |       |            |  |      |        |
 +--------+      |  +------------+       +------------+  |      +--------+
                 |                                       |
                 |                                       |
                 +---------------------------------------+

```

# Quick Start

1. 假定服务器IP为: `xxx.xxx.xxx.xxx`

2. 在服务器端开启ssh -D     (监听127.0.0.1:8080端口, 其他proxy工具也可以)
`ssh -D 127.0.0.1:8080 user@localhost`

3. 在服务器启动finaltun server:
`server -t "127.0.0.1:8080" -m tcp/kcp`     // 所有数据包转发到sshd进程的socks 8080端口

 ----------------------------  分割线，上面是服务器，下面是客户端  ----------------------------
4. 在本地启动finaltun client
`client -r "xxx.xxx.xxx.xxx:29900" -m tcp/kcp`    // 连接到finaltun server，默认finaltun server端口是29900

5. 浏览器就可以连接12948端口进行socks5代理访问了。   // 默认finaltun client的端口是12948

```注意：这个例子是为了让你快速上手，正确的姿势应该是是在客户端开启ssh -D，详见 使用案例```
