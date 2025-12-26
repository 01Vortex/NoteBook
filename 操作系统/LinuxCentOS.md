

> CentOS 是基于 Red Hat Enterprise Linux (RHEL) 的免费开源发行版，广泛用于服务器环境
> 本笔记基于 CentOS 7.9，涵盖系统管理从入门到进阶的完整知识

---

## 目录

1. [基础概念](#1-基础概念)
2. [系统安装与初始化](#2-系统安装与初始化)
3. [文件与目录管理](#3-文件与目录管理)
4. [用户与权限管理](#4-用户与权限管理)
5. [软件包管理](#5-软件包管理)
6. [进程管理](#6-进程管理)
7. [服务管理](#7-服务管理)
8. [网络配置](#8-网络配置)
9. [磁盘与存储](#9-磁盘与存储)
10. [日志管理](#10-日志管理)
11. [定时任务](#11-定时任务)
12. [防火墙配置](#12-防火墙配置)
13. [Shell 脚本](#13-shell-脚本)
14. [性能监控与优化](#14-性能监控与优化)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 CentOS？

CentOS（Community Enterprise Operating System）是一个基于 RHEL 源代码重新编译的免费 Linux 发行版。它具有企业级的稳定性，是服务器领域最流行的 Linux 发行版之一。

**CentOS 7 特点：**
- 内核版本：3.10.x
- 默认文件系统：XFS
- 服务管理：systemd
- 防火墙：firewalld
- 支持周期：2014-2024（已结束，但仍广泛使用）

**注意：** CentOS 8 已停止维护，CentOS Stream 是滚动更新版本。生产环境建议考虑 Rocky Linux 或 AlmaLinux 作为替代。

### 1.2 Linux 目录结构

```
/                   # 根目录
├── bin             # 基本命令（所有用户）
├── sbin            # 系统管理命令（root）
├── boot            # 启动文件、内核
├── dev             # 设备文件
├── etc             # 配置文件
├── home            # 用户主目录
├── lib             # 库文件
├── lib64           # 64位库文件
├── media           # 可移动媒体挂载点
├── mnt             # 临时挂载点
├── opt             # 第三方软件
├── proc            # 进程信息（虚拟文件系统）
├── root            # root 用户主目录
├── run             # 运行时数据
├── srv             # 服务数据
├── sys             # 系统信息（虚拟文件系统）
├── tmp             # 临时文件
├── usr             # 用户程序
│   ├── bin         # 用户命令
│   ├── sbin        # 系统管理命令
│   ├── lib         # 库文件
│   ├── local       # 本地安装的软件
│   └── share       # 共享数据
└── var             # 可变数据
    ├── log         # 日志文件
    ├── cache       # 缓存
    └── lib         # 程序数据
```

### 1.3 基本命令格式

```bash
命令 [选项] [参数]

# 示例
ls -la /home

# 获取帮助
man ls          # 手册页
ls --help       # 简短帮助
info ls         # 详细信息
```

---

## 2. 系统安装与初始化

### 2.1 系统信息查看

```bash
# 查看系统版本
cat /etc/redhat-release
cat /etc/centos-release
uname -a

# 查看内核版本
uname -r

# 查看系统架构
arch
uname -m

# 查看主机名
hostname
hostnamectl

# 查看系统运行时间
uptime

# 查看系统资源
free -h         # 内存
df -h           # 磁盘
lscpu           # CPU
```

### 2.2 初始化配置

```bash
# 设置主机名
hostnamectl set-hostname myserver

# 设置时区
timedatectl set-timezone Asia/Shanghai
timedatectl

# 同步时间
yum install -y ntpdate
ntpdate ntp.aliyun.com

# 或使用 chrony（推荐）
yum install -y chrony
systemctl start chronyd
systemctl enable chronyd
chronyc sources

# 关闭 SELinux（开发环境）
# 临时关闭
setenforce 0

# 永久关闭
vi /etc/selinux/config
# SELINUX=disabled

# 查看 SELinux 状态
getenforce
sestatus

# 关闭防火墙（开发环境）
systemctl stop firewalld
systemctl disable firewalld

# 配置 yum 源（阿里云）
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
yum clean all
yum makecache

# 安装常用工具
yum install -y vim wget curl net-tools lsof tree htop
```

### 2.3 SSH 配置

```bash
# 安装 SSH
yum install -y openssh-server openssh-clients

# 启动 SSH
systemctl start sshd
systemctl enable sshd

# 配置 SSH
vi /etc/ssh/sshd_config

# 常用配置
Port 22                     # 端口
PermitRootLogin yes         # 允许 root 登录
PasswordAuthentication yes  # 密码认证
PubkeyAuthentication yes    # 公钥认证

# 重启 SSH
systemctl restart sshd

# 生成密钥对
ssh-keygen -t rsa -b 4096

# 复制公钥到远程服务器
ssh-copy-id user@remote_host

# 免密登录配置
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

---

## 3. 文件与目录管理

### 3.1 目录操作

```bash
# 查看当前目录
pwd

# 切换目录
cd /path/to/dir
cd ~           # 用户主目录
cd -           # 上一个目录
cd ..          # 上级目录

# 创建目录
mkdir dir1
mkdir -p dir1/dir2/dir3    # 递归创建
mkdir -m 755 dir1          # 指定权限

# 删除目录
rmdir dir1                 # 删除空目录
rm -r dir1                 # 递归删除
rm -rf dir1                # 强制递归删除（危险！）

# 列出目录内容
ls
ls -l          # 详细信息
ls -la         # 包含隐藏文件
ls -lh         # 人类可读大小
ls -lt         # 按时间排序
ls -lS         # 按大小排序
ls -R          # 递归列出

# 目录树
tree
tree -L 2      # 限制深度
tree -d        # 只显示目录
```

### 3.2 文件操作

```bash
# 创建文件
touch file.txt
echo "content" > file.txt      # 覆盖写入
echo "content" >> file.txt     # 追加写入

# 复制文件
cp file1 file2
cp -r dir1 dir2                # 递归复制目录
cp -p file1 file2              # 保留属性
cp -a dir1 dir2                # 归档复制

# 移动/重命名
mv file1 file2
mv file1 /path/to/dir/

# 删除文件
rm file.txt
rm -f file.txt                 # 强制删除
rm -i file.txt                 # 交互确认

# 查看文件内容
cat file.txt                   # 全部内容
head -n 10 file.txt            # 前 10 行
tail -n 10 file.txt            # 后 10 行
tail -f file.txt               # 实时跟踪
less file.txt                  # 分页查看
more file.txt                  # 分页查看

# 文件信息
file file.txt                  # 文件类型
stat file.txt                  # 详细信息
wc -l file.txt                 # 行数
wc -w file.txt                 # 单词数
wc -c file.txt                 # 字节数
```

### 3.3 文件查找

```bash
# find 命令
find /path -name "*.txt"           # 按名称
find /path -type f                 # 文件
find /path -type d                 # 目录
find /path -size +100M             # 大于 100MB
find /path -mtime -7               # 7天内修改
find /path -user root              # 属于 root
find /path -perm 755               # 权限为 755
find /path -name "*.log" -delete   # 查找并删除
find /path -name "*.txt" -exec cat {} \;  # 执行命令

# locate 命令（更快，需要更新数据库）
updatedb
locate filename

# which/whereis
which python                       # 命令路径
whereis python                     # 相关文件路径

# grep 搜索文件内容
grep "pattern" file.txt
grep -r "pattern" /path/           # 递归搜索
grep -i "pattern" file.txt         # 忽略大小写
grep -n "pattern" file.txt         # 显示行号
grep -v "pattern" file.txt         # 反向匹配
grep -E "regex" file.txt           # 正则表达式
```

### 3.4 文件压缩与解压

```bash
# tar 命令
# 参数：c-创建 x-解压 v-详细 f-文件 z-gzip j-bzip2

# 创建 tar.gz
tar -czvf archive.tar.gz dir/
tar -czvf archive.tar.gz file1 file2

# 解压 tar.gz
tar -xzvf archive.tar.gz
tar -xzvf archive.tar.gz -C /target/dir/

# 创建 tar.bz2
tar -cjvf archive.tar.bz2 dir/

# 解压 tar.bz2
tar -xjvf archive.tar.bz2

# 查看压缩包内容
tar -tzvf archive.tar.gz

# zip/unzip
yum install -y zip unzip
zip -r archive.zip dir/
unzip archive.zip
unzip archive.zip -d /target/dir/

# gzip/gunzip
gzip file.txt           # 压缩（删除原文件）
gzip -k file.txt        # 保留原文件
gunzip file.txt.gz      # 解压
```

### 3.5 链接

```bash
# 硬链接（共享 inode，不能跨文件系统，不能链接目录）
ln file1 file2

# 软链接（符号链接，类似快捷方式）
ln -s /path/to/file link_name
ln -s /path/to/dir link_name

# 查看链接
ls -l link_name
readlink link_name

# 删除链接
rm link_name
unlink link_name
```

---

## 4. 用户与权限管理

### 4.1 用户管理

```bash
# 查看当前用户
whoami
id

# 查看用户信息
id username
cat /etc/passwd

# 创建用户
useradd username
useradd -m username                # 创建主目录
useradd -g group username          # 指定主组
useradd -G group1,group2 username  # 指定附加组
useradd -s /bin/bash username      # 指定 shell
useradd -d /home/custom username   # 指定主目录

# 设置密码
passwd username
echo "password" | passwd --stdin username

# 修改用户
usermod -g newgroup username       # 修改主组
usermod -G group1,group2 username  # 修改附加组
usermod -aG group username         # 添加到组
usermod -s /sbin/nologin username  # 禁止登录
usermod -L username                # 锁定用户
usermod -U username                # 解锁用户

# 删除用户
userdel username
userdel -r username                # 同时删除主目录

# 切换用户
su - username
sudo command                       # 以 root 执行
sudo -u username command           # 以指定用户执行
```

### 4.2 组管理

```bash
# 查看组
cat /etc/group
groups username

# 创建组
groupadd groupname
groupadd -g 1001 groupname         # 指定 GID

# 修改组
groupmod -n newname oldname        # 重命名
groupmod -g 1002 groupname         # 修改 GID

# 删除组
groupdel groupname

# 用户与组
gpasswd -a username groupname      # 添加用户到组
gpasswd -d username groupname      # 从组删除用户
```

### 4.3 权限管理

```bash
# 权限说明
# r(4) - 读  w(2) - 写  x(1) - 执行
# 文件：rwx = 读内容、写内容、执行
# 目录：rwx = 列出内容、创建/删除文件、进入目录

# 查看权限
ls -l file.txt
# -rw-r--r-- 1 root root 0 Jan 1 00:00 file.txt
# 类型 所有者权限 组权限 其他权限

# 修改权限
chmod 755 file.txt                 # 数字方式
chmod u+x file.txt                 # 符号方式
chmod g-w file.txt
chmod o=r file.txt
chmod a+x file.txt                 # 所有人
chmod -R 755 dir/                  # 递归

# 修改所有者
chown user file.txt
chown user:group file.txt
chown -R user:group dir/           # 递归

# 修改所属组
chgrp group file.txt
chgrp -R group dir/

# 特殊权限
# SUID(4) - 执行时以文件所有者身份运行
# SGID(2) - 执行时以文件所属组身份运行
# Sticky(1) - 只有所有者能删除文件

chmod 4755 file                    # SUID
chmod 2755 dir                     # SGID
chmod 1777 dir                     # Sticky

# 默认权限
umask                              # 查看
umask 022                          # 设置
# 文件默认权限 = 666 - umask
# 目录默认权限 = 777 - umask
```

### 4.4 sudo 配置

```bash
# 编辑 sudoers 文件
visudo

# 常用配置
# 允许用户执行所有命令
username ALL=(ALL) ALL

# 允许用户无密码执行
username ALL=(ALL) NOPASSWD: ALL

# 允许组执行所有命令
%groupname ALL=(ALL) ALL

# 允许执行特定命令
username ALL=(ALL) /usr/bin/systemctl restart nginx

# 查看 sudo 权限
sudo -l
```

---

## 5. 软件包管理

### 5.1 YUM 包管理

```bash
# 查看已安装的包
yum list installed
rpm -qa

# 搜索软件包
yum search keyword
yum list available | grep keyword

# 查看包信息
yum info package_name
rpm -qi package_name

# 安装软件包
yum install package_name
yum install -y package_name        # 自动确认
yum localinstall package.rpm       # 安装本地 rpm

# 更新软件包
yum update                         # 更新所有
yum update package_name            # 更新指定包
yum check-update                   # 检查更新

# 卸载软件包
yum remove package_name
yum autoremove                     # 删除不需要的依赖

# 清理缓存
yum clean all
yum makecache

# 查看包文件
rpm -ql package_name               # 列出文件
rpm -qf /path/to/file              # 查找文件属于哪个包

# 包组管理
yum grouplist
yum groupinstall "Development Tools"
yum groupremove "Development Tools"
```

### 5.2 配置 YUM 源

```bash
# 备份原有源
cd /etc/yum.repos.d/
mkdir backup
mv *.repo backup/

# 配置阿里云源
curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo

# 配置 EPEL 源
yum install -y epel-release
# 或手动配置
curl -o /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo

# 更新缓存
yum clean all
yum makecache

# 自定义 YUM 源
cat > /etc/yum.repos.d/custom.repo << 'EOF'
[custom]
name=Custom Repository
baseurl=http://repo.example.com/centos/7/
enabled=1
gpgcheck=0
EOF
```

### 5.3 源码编译安装

```bash
# 安装编译工具
yum groupinstall -y "Development Tools"
yum install -y gcc gcc-c++ make autoconf automake

# 典型编译流程
tar -xzvf software.tar.gz
cd software
./configure --prefix=/usr/local/software
make
make install

# 配置环境变量
echo 'export PATH=/usr/local/software/bin:$PATH' >> /etc/profile
source /etc/profile
```

---

## 6. 进程管理

### 6.1 查看进程

```bash
# ps 命令
ps aux                             # 所有进程
ps -ef                             # 完整格式
ps aux | grep nginx                # 过滤
ps -u username                     # 用户进程
ps --forest                        # 树形显示

# top 命令（实时监控）
top
# 快捷键：
# P - 按 CPU 排序
# M - 按内存排序
# k - 杀死进程
# q - 退出

# htop（更友好）
yum install -y htop
htop

# 查看进程树
pstree
pstree -p                          # 显示 PID

# 查看进程详情
cat /proc/PID/status
cat /proc/PID/cmdline
ls -l /proc/PID/fd                 # 文件描述符
```

### 6.2 进程控制

```bash
# 前台/后台运行
command &                          # 后台运行
nohup command &                    # 后台运行，忽略挂断信号
nohup command > output.log 2>&1 &  # 重定向输出

# 作业控制
jobs                               # 查看后台作业
fg %1                              # 调到前台
bg %1                              # 放到后台
Ctrl+Z                             # 暂停当前进程
Ctrl+C                             # 终止当前进程

# 杀死进程
kill PID                           # 发送 SIGTERM
kill -9 PID                        # 强制杀死 SIGKILL
kill -15 PID                       # 优雅终止
killall process_name               # 按名称杀死
pkill pattern                      # 按模式杀死
pkill -u username                  # 杀死用户所有进程

# 信号列表
kill -l
# 常用信号：
# 1  SIGHUP   - 重新加载配置
# 9  SIGKILL  - 强制终止
# 15 SIGTERM  - 优雅终止（默认）
# 18 SIGCONT  - 继续
# 19 SIGSTOP  - 暂停
```

### 6.3 进程优先级

```bash
# 查看优先级
ps -el | grep PID
top                                # NI 列

# nice 值范围：-20（最高优先级）到 19（最低优先级）

# 启动时设置优先级
nice -n 10 command

# 修改运行中进程优先级
renice 10 -p PID
renice -5 -u username              # 修改用户所有进程
```

---

## 7. 服务管理

### 7.1 systemd 服务管理

CentOS 7 使用 systemd 管理服务，取代了 SysVinit。

```bash
# 服务状态
systemctl status service_name
systemctl is-active service_name
systemctl is-enabled service_name

# 启动/停止/重启
systemctl start service_name
systemctl stop service_name
systemctl restart service_name
systemctl reload service_name      # 重新加载配置

# 开机启动
systemctl enable service_name
systemctl disable service_name
systemctl is-enabled service_name

# 列出服务
systemctl list-units --type=service
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service

# 查看服务依赖
systemctl list-dependencies service_name

# 查看服务日志
journalctl -u service_name
journalctl -u service_name -f      # 实时跟踪
journalctl -u service_name --since "1 hour ago"
```

### 7.2 创建自定义服务

```bash
# 创建服务文件
cat > /etc/systemd/system/myapp.service << 'EOF'
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=myuser
Group=mygroup
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/start.sh
ExecStop=/opt/myapp/bin/stop.sh
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10

# 环境变量
Environment=JAVA_HOME=/usr/local/java
EnvironmentFile=/opt/myapp/env.conf

# 资源限制
LimitNOFILE=65536
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF

# 重新加载配置
systemctl daemon-reload

# 启动服务
systemctl start myapp
systemctl enable myapp
```

### 7.3 运行级别

```bash
# 查看当前运行级别
systemctl get-default
runlevel

# 运行级别对应
# 0 - poweroff.target    关机
# 1 - rescue.target      单用户模式
# 2 - multi-user.target  多用户（无网络）
# 3 - multi-user.target  多用户（有网络）
# 4 - multi-user.target  未使用
# 5 - graphical.target   图形界面
# 6 - reboot.target      重启

# 设置默认运行级别
systemctl set-default multi-user.target
systemctl set-default graphical.target

# 切换运行级别
systemctl isolate multi-user.target
init 3
```

---

## 8. 网络配置

### 8.1 网络信息查看

```bash
# 查看 IP 地址
ip addr
ip a
ifconfig                           # 需要 net-tools

# 查看路由
ip route
route -n

# 查看网络连接
netstat -tunlp                     # 监听端口
netstat -an                        # 所有连接
ss -tunlp                          # 更快的替代

# 查看 DNS
cat /etc/resolv.conf

# 网络测试
ping host
traceroute host
mtr host                           # 更好的 traceroute
nslookup domain
dig domain
curl -I http://example.com
wget http://example.com/file
```

### 8.2 网络配置

```bash
# 配置文件位置
/etc/sysconfig/network-scripts/ifcfg-eth0

# 静态 IP 配置
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 << 'EOF'
TYPE=Ethernet
BOOTPROTO=static
NAME=eth0
DEVICE=eth0
ONBOOT=yes
IPADDR=192.168.1.100
NETMASK=255.255.255.0
GATEWAY=192.168.1.1
DNS1=8.8.8.8
DNS2=8.8.4.4
EOF

# DHCP 配置
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 << 'EOF'
TYPE=Ethernet
BOOTPROTO=dhcp
NAME=eth0
DEVICE=eth0
ONBOOT=yes
EOF

# 重启网络
systemctl restart network
# 或
nmcli connection reload
nmcli connection up eth0

# 使用 nmcli 配置
nmcli connection show
nmcli connection modify eth0 ipv4.addresses 192.168.1.100/24
nmcli connection modify eth0 ipv4.gateway 192.168.1.1
nmcli connection modify eth0 ipv4.dns "8.8.8.8 8.8.4.4"
nmcli connection modify eth0 ipv4.method manual
nmcli connection up eth0
```

### 8.3 主机名与 hosts

```bash
# 设置主机名
hostnamectl set-hostname myserver

# 配置 hosts
cat >> /etc/hosts << 'EOF'
192.168.1.100 server1
192.168.1.101 server2
192.168.1.102 server3
EOF
```

### 8.4 端口与连接

```bash
# 查看监听端口
netstat -tunlp
ss -tunlp
lsof -i :80

# 查看端口占用
lsof -i :8080
fuser 8080/tcp

# 测试端口连通性
telnet host port
nc -zv host port
curl telnet://host:port

# 查看网络统计
netstat -s
ss -s
```

---

## 9. 磁盘与存储

### 9.1 磁盘信息

```bash
# 查看磁盘
lsblk
fdisk -l
df -h                              # 文件系统使用情况
df -i                              # inode 使用情况
du -sh /path                       # 目录大小
du -sh *                           # 当前目录下各项大小
du -h --max-depth=1                # 一级目录大小

# 查看磁盘 IO
iostat -x 1
iotop
```

### 9.2 磁盘分区

```bash
# 分区工具
fdisk /dev/sdb                     # MBR 分区（<2TB）
gdisk /dev/sdb                     # GPT 分区（>2TB）
parted /dev/sdb                    # 通用工具

# fdisk 操作
fdisk /dev/sdb
# n - 新建分区
# p - 主分区
# 1 - 分区号
# 回车 - 默认起始扇区
# +10G - 大小
# w - 保存退出

# 刷新分区表
partprobe /dev/sdb
```

### 9.3 文件系统

```bash
# 格式化
mkfs.xfs /dev/sdb1                 # XFS（推荐）
mkfs.ext4 /dev/sdb1                # EXT4

# 挂载
mount /dev/sdb1 /mnt/data
mount -t xfs /dev/sdb1 /mnt/data

# 卸载
umount /mnt/data
umount -l /mnt/data                # 延迟卸载

# 查看挂载
mount | grep sdb
cat /proc/mounts

# 永久挂载（/etc/fstab）
echo '/dev/sdb1 /mnt/data xfs defaults 0 0' >> /etc/fstab

# fstab 格式
# 设备 挂载点 文件系统 选项 dump fsck
# /dev/sdb1 /mnt/data xfs defaults 0 0
# UUID=xxx /mnt/data xfs defaults 0 0

# 查看 UUID
blkid /dev/sdb1

# 验证 fstab
mount -a
```

### 9.4 LVM 逻辑卷

```bash
# 安装 LVM
yum install -y lvm2

# 创建物理卷
pvcreate /dev/sdb /dev/sdc
pvs
pvdisplay

# 创建卷组
vgcreate vg_data /dev/sdb /dev/sdc
vgs
vgdisplay

# 创建逻辑卷
lvcreate -L 50G -n lv_data vg_data
lvcreate -l 100%FREE -n lv_data vg_data  # 使用所有空间
lvs
lvdisplay

# 格式化并挂载
mkfs.xfs /dev/vg_data/lv_data
mkdir /data
mount /dev/vg_data/lv_data /data

# 扩展逻辑卷
lvextend -L +10G /dev/vg_data/lv_data
# 或
lvextend -l +100%FREE /dev/vg_data/lv_data

# 扩展文件系统
xfs_growfs /data                   # XFS
resize2fs /dev/vg_data/lv_data     # EXT4
```

### 9.5 Swap 交换分区

```bash
# 查看 swap
free -h
swapon -s

# 创建 swap 文件
dd if=/dev/zero of=/swapfile bs=1M count=2048
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# 永久启用
echo '/swapfile swap swap defaults 0 0' >> /etc/fstab

# 关闭 swap
swapoff /swapfile
swapoff -a
```

---

## 10. 日志管理

### 10.1 系统日志

```bash
# 日志目录
/var/log/

# 重要日志文件
/var/log/messages      # 系统日志
/var/log/secure        # 安全日志（登录、sudo）
/var/log/dmesg         # 内核启动日志
/var/log/cron          # 定时任务日志
/var/log/maillog       # 邮件日志
/var/log/boot.log      # 启动日志
/var/log/yum.log       # YUM 日志

# 查看日志
tail -f /var/log/messages
tail -100 /var/log/secure
grep "error" /var/log/messages
```

### 10.2 journalctl

```bash
# 查看所有日志
journalctl

# 查看最新日志
journalctl -f                      # 实时跟踪
journalctl -n 100                  # 最新 100 条

# 按服务查看
journalctl -u nginx
journalctl -u nginx -f

# 按时间查看
journalctl --since "2024-01-01"
journalctl --since "1 hour ago"
journalctl --since "2024-01-01" --until "2024-01-02"

# 按优先级查看
journalctl -p err                  # 错误及以上
journalctl -p warning

# 按进程查看
journalctl _PID=1234

# 查看内核日志
journalctl -k
journalctl --dmesg

# 磁盘使用
journalctl --disk-usage

# 清理日志
journalctl --vacuum-size=500M
journalctl --vacuum-time=7d
```

### 10.3 日志轮转

```bash
# logrotate 配置
cat /etc/logrotate.conf

# 自定义轮转配置
cat > /etc/logrotate.d/myapp << 'EOF'
/var/log/myapp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload myapp > /dev/null 2>&1 || true
    endscript
}
EOF

# 手动执行轮转
logrotate -f /etc/logrotate.d/myapp

# 测试配置
logrotate -d /etc/logrotate.d/myapp
```

---

## 11. 定时任务

### 11.1 crontab

```bash
# 编辑定时任务
crontab -e

# 查看定时任务
crontab -l

# 删除所有定时任务
crontab -r

# 指定用户
crontab -u username -e

# crontab 格式
# 分 时 日 月 周 命令
# *  *  *  *  *  command

# 示例
# 每分钟执行
* * * * * /path/to/script.sh

# 每小时执行
0 * * * * /path/to/script.sh

# 每天凌晨 2 点执行
0 2 * * * /path/to/script.sh

# 每周一凌晨 3 点执行
0 3 * * 1 /path/to/script.sh

# 每月 1 号凌晨 4 点执行
0 4 1 * * /path/to/script.sh

# 每 5 分钟执行
*/5 * * * * /path/to/script.sh

# 每天 9 点到 18 点每小时执行
0 9-18 * * * /path/to/script.sh

# 工作日执行
0 9 * * 1-5 /path/to/script.sh

# 输出重定向
0 2 * * * /path/to/script.sh >> /var/log/script.log 2>&1

# 禁止邮件通知
0 2 * * * /path/to/script.sh > /dev/null 2>&1
```

### 11.2 系统级定时任务

```bash
# 系统定时任务目录
/etc/crontab              # 系统 crontab
/etc/cron.d/              # 自定义任务
/etc/cron.hourly/         # 每小时
/etc/cron.daily/          # 每天
/etc/cron.weekly/         # 每周
/etc/cron.monthly/        # 每月

# 查看 cron 服务状态
systemctl status crond

# 查看 cron 日志
tail -f /var/log/cron
```

### 11.3 at 一次性任务

```bash
# 安装 at
yum install -y at
systemctl start atd
systemctl enable atd

# 创建一次性任务
at 10:00
at> /path/to/script.sh
at> Ctrl+D

# 指定时间
at 10:00 tomorrow
at now + 1 hour
at 2024-01-01 10:00

# 查看任务
atq

# 删除任务
atrm job_number
```

---

## 12. 防火墙配置

### 12.1 firewalld

```bash
# 服务管理
systemctl start firewalld
systemctl stop firewalld
systemctl enable firewalld
systemctl status firewalld

# 查看状态
firewall-cmd --state
firewall-cmd --list-all

# 区域管理
firewall-cmd --get-zones
firewall-cmd --get-default-zone
firewall-cmd --set-default-zone=public

# 开放端口
firewall-cmd --zone=public --add-port=80/tcp --permanent
firewall-cmd --zone=public --add-port=8080-8090/tcp --permanent
firewall-cmd --reload

# 关闭端口
firewall-cmd --zone=public --remove-port=80/tcp --permanent
firewall-cmd --reload

# 开放服务
firewall-cmd --zone=public --add-service=http --permanent
firewall-cmd --zone=public --add-service=https --permanent
firewall-cmd --reload

# 查看开放的端口和服务
firewall-cmd --list-ports
firewall-cmd --list-services

# 富规则（高级）
# 允许特定 IP 访问
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.100" accept'

# 允许特定 IP 访问特定端口
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port protocol="tcp" port="3306" accept'

# 拒绝特定 IP
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.100" reject'

firewall-cmd --reload
```

### 12.2 iptables

```bash
# 安装 iptables
yum install -y iptables-services
systemctl stop firewalld
systemctl disable firewalld
systemctl start iptables
systemctl enable iptables

# 查看规则
iptables -L -n
iptables -L -n -v
iptables -L -n --line-numbers

# 清空规则
iptables -F
iptables -X
iptables -Z

# 设置默认策略
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 允许本地回环
iptables -A INPUT -i lo -j ACCEPT

# 允许已建立的连接
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 允许 SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# 允许 HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 允许特定 IP
iptables -A INPUT -s 192.168.1.100 -j ACCEPT

# 允许特定网段
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT

# 拒绝特定 IP
iptables -A INPUT -s 192.168.1.100 -j DROP

# 保存规则
service iptables save
# 或
iptables-save > /etc/sysconfig/iptables

# 恢复规则
iptables-restore < /etc/sysconfig/iptables
```

---

## 13. Shell 脚本

### 13.1 脚本基础

```bash
#!/bin/bash
# 这是注释

# 变量
name="World"
echo "Hello, $name"
echo "Hello, ${name}!"

# 只读变量
readonly PI=3.14159

# 删除变量
unset name

# 特殊变量
$0    # 脚本名
$1    # 第一个参数
$#    # 参数个数
$@    # 所有参数（独立）
$*    # 所有参数（整体）
$?    # 上一命令退出状态
$$    # 当前进程 PID
$!    # 后台进程 PID

# 字符串操作
str="Hello World"
echo ${#str}           # 长度
echo ${str:0:5}        # 截取
echo ${str/World/Linux}  # 替换

# 数组
arr=(a b c d)
echo ${arr[0]}         # 第一个元素
echo ${arr[@]}         # 所有元素
echo ${#arr[@]}        # 数组长度
arr[4]=e               # 添加元素

# 运算
a=10
b=3
echo $((a + b))
echo $((a - b))
echo $((a * b))
echo $((a / b))
echo $((a % b))
echo $((a ** b))

# 或使用 expr
expr $a + $b
```

### 13.2 流程控制

```bash
# if 语句
if [ condition ]; then
    commands
elif [ condition ]; then
    commands
else
    commands
fi

# 条件判断
# 数值比较
[ $a -eq $b ]    # 等于
[ $a -ne $b ]    # 不等于
[ $a -gt $b ]    # 大于
[ $a -lt $b ]    # 小于
[ $a -ge $b ]    # 大于等于
[ $a -le $b ]    # 小于等于

# 字符串比较
[ "$str1" = "$str2" ]   # 相等
[ "$str1" != "$str2" ]  # 不相等
[ -z "$str" ]           # 为空
[ -n "$str" ]           # 不为空

# 文件判断
[ -e file ]    # 存在
[ -f file ]    # 是文件
[ -d file ]    # 是目录
[ -r file ]    # 可读
[ -w file ]    # 可写
[ -x file ]    # 可执行
[ -s file ]    # 大小不为 0

# 逻辑运算
[ cond1 ] && [ cond2 ]   # 与
[ cond1 ] || [ cond2 ]   # 或
[ ! cond ]               # 非

# for 循环
for i in 1 2 3 4 5; do
    echo $i
done

for i in {1..10}; do
    echo $i
done

for ((i=0; i<10; i++)); do
    echo $i
done

for file in /path/*; do
    echo $file
done

# while 循环
while [ condition ]; do
    commands
done

# 读取文件
while read line; do
    echo $line
done < file.txt

# case 语句
case $var in
    pattern1)
        commands
        ;;
    pattern2)
        commands
        ;;
    *)
        default commands
        ;;
esac
```

### 13.3 函数

```bash
# 定义函数
function_name() {
    commands
    return value
}

# 或
function function_name {
    commands
}

# 调用函数
function_name arg1 arg2

# 函数参数
greet() {
    echo "Hello, $1!"
    echo "参数个数: $#"
}
greet "World"

# 返回值
add() {
    return $(($1 + $2))
}
add 3 5
echo $?  # 8

# 或使用 echo 返回
add() {
    echo $(($1 + $2))
}
result=$(add 3 5)
echo $result
```

### 13.4 实用脚本示例

```bash
#!/bin/bash
# 服务器初始化脚本

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查 root 权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "请使用 root 用户运行此脚本"
        exit 1
    fi
}

# 配置 YUM 源
config_yum() {
    log_info "配置 YUM 源..."
    mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
    curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
    yum clean all && yum makecache
}

# 安装常用工具
install_tools() {
    log_info "安装常用工具..."
    yum install -y vim wget curl net-tools lsof tree htop
}

# 关闭 SELinux
disable_selinux() {
    log_info "关闭 SELinux..."
    setenforce 0
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
}

# 配置时区
config_timezone() {
    log_info "配置时区..."
    timedatectl set-timezone Asia/Shanghai
}

# 主函数
main() {
    check_root
    config_yum
    install_tools
    disable_selinux
    config_timezone
    log_info "初始化完成！"
}

main "$@"
```

```bash
#!/bin/bash
# 备份脚本

BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d_%H%M%S)
MYSQL_USER="root"
MYSQL_PASS="password"
KEEP_DAYS=7

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份 MySQL
backup_mysql() {
    local db=$1
    local file="$BACKUP_DIR/mysql_${db}_${DATE}.sql.gz"
    mysqldump -u$MYSQL_USER -p$MYSQL_PASS $db | gzip > $file
    echo "MySQL 备份完成: $file"
}

# 备份目录
backup_dir() {
    local src=$1
    local name=$(basename $src)
    local file="$BACKUP_DIR/${name}_${DATE}.tar.gz"
    tar -czvf $file $src
    echo "目录备份完成: $file"
}

# 清理旧备份
cleanup() {
    find $BACKUP_DIR -type f -mtime +$KEEP_DAYS -delete
    echo "清理 $KEEP_DAYS 天前的备份"
}

# 执行备份
backup_mysql "mydb"
backup_dir "/var/www/html"
cleanup
```

---

## 14. 性能监控与优化

### 14.1 系统监控

```bash
# CPU 监控
top
htop
mpstat 1                           # CPU 统计
vmstat 1                           # 虚拟内存统计
sar -u 1 5                         # CPU 使用率

# 内存监控
free -h
vmstat 1
sar -r 1 5                         # 内存使用率
cat /proc/meminfo

# 磁盘监控
iostat -x 1
iotop
sar -d 1 5                         # 磁盘 IO

# 网络监控
iftop                              # 网络流量
nethogs                            # 进程网络使用
sar -n DEV 1 5                     # 网络统计
ss -s                              # 连接统计

# 综合监控
dstat
glances                            # 需要安装
nmon                               # 需要安装
```

### 14.2 性能优化

```bash
# 内核参数优化
cat >> /etc/sysctl.conf << 'EOF'
# 网络优化
net.ipv4.tcp_max_syn_backlog = 65535
net.core.somaxconn = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 65535

# 内存优化
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5

# 文件描述符
fs.file-max = 6553560
EOF

sysctl -p

# 文件描述符限制
cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF

# 查看当前限制
ulimit -a
ulimit -n                          # 文件描述符
ulimit -u                          # 进程数
```

### 14.3 故障排查

```bash
# 系统负载高
top                                # 查看 CPU 使用
ps aux --sort=-%cpu | head         # CPU 占用最高的进程
ps aux --sort=-%mem | head         # 内存占用最高的进程

# 磁盘空间不足
df -h                              # 查看磁盘使用
du -sh /* | sort -rh | head        # 查找大目录
find / -type f -size +100M         # 查找大文件
lsof +D /path                      # 查看目录被谁占用

# 内存不足
free -h
ps aux --sort=-%mem | head
cat /proc/meminfo

# 网络问题
ping host                          # 连通性
traceroute host                    # 路由追踪
netstat -tunlp                     # 端口监听
ss -s                              # 连接统计
tcpdump -i eth0 port 80            # 抓包

# 进程问题
strace -p PID                      # 跟踪系统调用
lsof -p PID                        # 进程打开的文件
```

---

## 15. 常见错误与解决方案

### 15.1 网络相关错误

**错误：ping: unknown host**
```bash
# 原因：DNS 配置问题
# 解决：
cat /etc/resolv.conf
# 添加 DNS
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# 或检查网络配置
cat /etc/sysconfig/network-scripts/ifcfg-eth0
systemctl restart network
```

**错误：Connection refused**
```bash
# 原因：服务未启动或端口未开放
# 解决：
# 1. 检查服务状态
systemctl status service_name

# 2. 检查端口监听
netstat -tunlp | grep port

# 3. 检查防火墙
firewall-cmd --list-ports
firewall-cmd --add-port=80/tcp --permanent
firewall-cmd --reload
```

**错误：No route to host**
```bash
# 原因：路由或防火墙问题
# 解决：
# 1. 检查路由
ip route
route -n

# 2. 检查防火墙
systemctl status firewalld
iptables -L -n
```

### 15.2 磁盘相关错误

**错误：No space left on device**
```bash
# 原因：磁盘空间不足
# 解决：
# 1. 查看磁盘使用
df -h

# 2. 查找大文件
du -sh /* | sort -rh | head
find / -type f -size +100M -exec ls -lh {} \;

# 3. 清理日志
> /var/log/messages
journalctl --vacuum-size=500M

# 4. 清理 YUM 缓存
yum clean all

# 5. 清理临时文件
rm -rf /tmp/*
```

**错误：Read-only file system**
```bash
# 原因：文件系统只读（可能磁盘错误）
# 解决：
# 1. 检查磁盘
dmesg | tail
fsck /dev/sda1

# 2. 重新挂载
mount -o remount,rw /
```

**错误：inode 耗尽**
```bash
# 原因：小文件太多
# 解决：
# 1. 查看 inode 使用
df -i

# 2. 查找文件数量多的目录
find / -xdev -printf '%h\n' | sort | uniq -c | sort -rn | head

# 3. 清理小文件
find /path -type f -delete
```

### 15.3 权限相关错误

**错误：Permission denied**
```bash
# 原因：权限不足
# 解决：
# 1. 检查权限
ls -la file

# 2. 修改权限
chmod 755 file
chown user:group file

# 3. 检查 SELinux
getenforce
setenforce 0
```

**错误：sudo: command not found**
```bash
# 原因：用户不在 sudoers 中
# 解决：
# 以 root 登录
visudo
# 添加
username ALL=(ALL) ALL
```

### 15.4 服务相关错误

**错误：Failed to start service**
```bash
# 解决：
# 1. 查看详细错误
systemctl status service_name -l
journalctl -u service_name

# 2. 检查配置文件
# 3. 检查端口占用
netstat -tunlp | grep port

# 4. 检查日志
tail -f /var/log/messages
```

**错误：Job for xxx.service failed**
```bash
# 解决：
# 1. 查看日志
journalctl -xe
journalctl -u service_name --no-pager

# 2. 检查配置语法
nginx -t
httpd -t
```

### 15.5 YUM 相关错误

**错误：Cannot find a valid baseurl for repo**
```bash
# 原因：YUM 源配置问题或网络问题
# 解决：
# 1. 检查网络
ping mirrors.aliyun.com

# 2. 重新配置 YUM 源
curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
yum clean all
yum makecache
```

**错误：Multilib version problems**
```bash
# 原因：32位和64位包冲突
# 解决：
yum clean all
package-cleanup --cleandupes
yum update
```

**错误：GPG key retrieval failed**
```bash
# 解决：
# 1. 导入 GPG key
rpm --import https://www.redhat.com/security/team/key/

# 2. 或禁用 GPG 检查（不推荐）
yum install package --nogpgcheck
```

### 15.6 SSH 相关错误

**错误：Connection refused (port 22)**
```bash
# 解决：
# 1. 检查 SSH 服务
systemctl status sshd
systemctl start sshd

# 2. 检查防火墙
firewall-cmd --add-service=ssh --permanent
firewall-cmd --reload
```

**错误：Permission denied (publickey)**
```bash
# 解决：
# 1. 检查密钥权限
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa

# 2. 检查 SSH 配置
vi /etc/ssh/sshd_config
# PubkeyAuthentication yes
# AuthorizedKeysFile .ssh/authorized_keys

# 3. 检查 SELinux
restorecon -Rv ~/.ssh
```

**错误：Host key verification failed**
```bash
# 解决：
# 删除旧的 host key
ssh-keygen -R hostname
# 或
rm ~/.ssh/known_hosts
```

---

## 附录：常用命令速查表

```bash
# ========== 系统信息 ==========
uname -a                # 系统信息
cat /etc/redhat-release # 版本
hostname                # 主机名
uptime                  # 运行时间
free -h                 # 内存
df -h                   # 磁盘

# ========== 文件操作 ==========
ls -la                  # 列出文件
cp -r src dst           # 复制
mv src dst              # 移动
rm -rf path             # 删除
find / -name "*.log"    # 查找
grep "pattern" file     # 搜索

# ========== 用户管理 ==========
useradd username        # 创建用户
passwd username         # 设置密码
usermod -aG group user  # 添加到组
userdel -r username     # 删除用户

# ========== 权限管理 ==========
chmod 755 file          # 修改权限
chown user:group file   # 修改所有者

# ========== 进程管理 ==========
ps aux                  # 查看进程
top                     # 实时监控
kill -9 PID             # 杀死进程

# ========== 服务管理 ==========
systemctl start svc     # 启动
systemctl stop svc      # 停止
systemctl restart svc   # 重启
systemctl enable svc    # 开机启动
systemctl status svc    # 状态

# ========== 网络管理 ==========
ip addr                 # IP 地址
netstat -tunlp          # 端口监听
ping host               # 测试连通
curl url                # HTTP 请求

# ========== 防火墙 ==========
firewall-cmd --list-all
firewall-cmd --add-port=80/tcp --permanent
firewall-cmd --reload
```

---

> 💡 **学习建议**：
> 1. 多动手实践，在虚拟机中练习
> 2. 遇到问题先看日志：`journalctl`、`/var/log/`
> 3. 善用 `man` 和 `--help` 查看帮助
> 4. 危险操作前先备份
> 5. 生产环境谨慎使用 `rm -rf`
