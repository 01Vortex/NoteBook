ifconfig /all 获取获取域名、IP地址、DHCP服务器、网关、MAC地址、主机名

net time /domain 查看域名、时间

net view /domain 查看域内所有共享

net view ip 查看对方局域网内开启了哪些共享

net config workstation 查看域名、机器名等

net user 用户名 密码 /add 建立用户

net user 用户名 /del #删除用户

net user guest /active:yes 激活guest账户

net user 查看账户

net user 账户名 查看指定账户信息

net user /domain 查看域内有哪些用户，Windows NT Workstation 计算机上可用，由此可以此判断用户是否是域成员。

net user 用户名 /domain 查看账户信息

net group /domain 查看域中的组

net group "domain admins" /domain 查看当前域的管理用户

query user 查看当前在线的用户

net localgroup 查看所有的本地组

net localgroup administrators 查看administrators组中有哪些用户

net localgroup administrators 用户名 /add 把用户添加到管理员组中

net start 查看开启服务

net start 服务名 开启某服务

net stop 服务名 停止某服务

net share 查看本地开启的共享

net share ipc$ 开启ipc$共享

net share ipc$ /del 删除ipc$共享

net share c$ /del 删除C：共享

\\192.168.0.108\c 访问默认共享c盘

dsquery server 查看所有域控制器

dsquery subnet 查看域内内子网

dsquery group 查看域内工作组

dsquery site 查看域内站点

netstat -a 查看开启了哪些端口,常用netstat -an

netstat -n 查看端口的网络连接情况，常用netstat -an

netstat -v 查看正在进行的工作

netstat -p 协议名 例：netstat -p tcq/ip 查看某协议使用情况（查看tcp/ip协议使用情况）

netstat -s 查看正在使用的所有协议使用情况

nbtstat -A ip 对方136到139其中一个端口开了的话，就可查看对方最近登陆的用户名（03前的为用户名）-注意：参数-A要大写

reg save hklm\sam sam.hive 导出用户组信息、权限配置

reg save hklm\system system.hive 导出SYSKEY

net use \\目标IP\ipc$ 密码 /u:用户名 连接目标机器

at \\目标IP 21:31 c:\server.exe 在某个时间启动某个应用

wmic /node:"目标IP" /password:"123456" /user:"admin" 连接目标机器

psexec.exe \\目标IP -u username -p password -s cmd 在目标机器上执行cmd

finger username @host 查看最近有哪些用户登陆

route print 显示出IP路由，将主要显示网络地址Network addres，子网掩码Netmask，网关地址Gateway addres，接口地址Interface

arp 查看和处理ARP缓存，ARP是名字解析的意思，负责把一个IP解析成一个物理性的MAC地址。

arp -a 将显示出全部信息

nslookup IP地址侦测器

tasklist 查看当前进程

taskkill /pid PID数 终止指定PID进程

whoami 查看当前用户及权限

systeminfo 查看计算机信息（版本，位数，补丁情况）

ver 查看计算机操作系统版本

tasklist /svc 查看当前计算机进程情况

netstat -ano 查看当前计算机进程情况

wmic product > ins.txt 查看安装软件以及版本路径等信息，重定向到ins.txt
