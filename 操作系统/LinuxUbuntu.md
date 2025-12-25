# Ubuntu 22.04 LTS 完整学习笔记

> Ubuntu 是目前最流行的 Linux 发行版之一，基于 Debian，以易用性著称。22.04 LTS（Long Term Support）是长期支持版本，官方支持到 2027 年，非常适合服务器和日常使用。
>
> 本笔记从零开始，涵盖从基础命令到高级运维的所有内容。

---

## 目录

1. [Linux 基础概念](#1-linux-基础概念)
2. [系统安装与初始配置](#2-系统安装与初始配置)
3. [文件系统与目录结构](#3-文件系统与目录结构)
4. [基础命令](#4-基础命令)
5. [用户与权限管理](#5-用户与权限管理)
6. [软件包管理](#6-软件包管理)
7. [文本处理](#7-文本处理)
8. [进程管理](#8-进程管理)
9. [磁盘与存储管理](#9-磁盘与存储管理)
10. [网络配置与管理](#10-网络配置与管理)
11. [服务管理](#11-服务管理)
12. [Shell 脚本编程](#12-shell-脚本编程)
13. [系统监控与性能优化](#13-系统监控与性能优化)
14. [安全加固](#14-安全加固)
15. [常用服务部署](#15-常用服务部署)
16. [故障排查](#16-故障排查)
17. [常见错误汇总](#17-常见错误汇总)

---

## 1. Linux 基础概念

### 1.1 什么是 Linux？

Linux 是一个开源的类 Unix 操作系统内核，由 Linus Torvalds 于 1991 年创建。

**Linux 发行版** = Linux 内核 + 软件包 + 包管理器 + 桌面环境（可选）

常见发行版：
| 发行版 | 特点 | 包管理器 |
|--------|------|----------|
| Ubuntu | 易用，社区活跃 | apt/dpkg |
| CentOS/RHEL | 企业级，稳定 | yum/dnf |
| Debian | 稳定，Ubuntu 的上游 | apt/dpkg |
| Arch Linux | 滚动更新，DIY | pacman |
| Alpine | 轻量，容器常用 | apk |

### 1.2 为什么选择 Ubuntu 22.04 LTS？

- **长期支持**：5 年安全更新（到 2027 年）
- **稳定性**：经过充分测试
- **软件丰富**：apt 仓库包含大量软件
- **社区活跃**：遇到问题容易找到解决方案
- **企业认可**：很多云服务商默认提供 Ubuntu

### 1.3 终端与 Shell

**终端（Terminal）**：与系统交互的窗口，可以理解为"命令行界面"。

**Shell**：命令解释器，接收你输入的命令并执行。

常见 Shell：
- **bash**：Ubuntu 默认 Shell，最常用
- **zsh**：功能更强，支持插件
- **sh**：最基础的 Shell

```bash
# 查看当前使用的 Shell
echo $SHELL

# 查看系统支持的 Shell
cat /etc/shells

# 切换 Shell（临时）
zsh

# 切换默认 Shell
chsh -s /bin/zsh
```

### 1.4 命令行提示符

```bash
username@hostname:~$
│        │        │└─ $ 普通用户，# root 用户
│        │        └─── 当前目录（~ 表示家目录）
│        └──────────── 主机名
└───────────────────── 用户名
```

---

## 2. 系统安装与初始配置

### 2.1 安装方式

1. **物理机安装**：制作 USB 启动盘，从 U 盘启动安装
2. **虚拟机安装**：VMware、VirtualBox、Hyper-V
3. **云服务器**：阿里云、腾讯云、AWS 等直接选择 Ubuntu 镜像
4. **WSL**：Windows 子系统，`wsl --install -d Ubuntu-22.04`

### 2.2 安装后首要配置

#### 更换国内镜像源（加速下载）

```bash
# 备份原文件
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak

# 使用阿里云镜像
sudo tee /etc/apt/sources.list << 'EOF'
deb http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
EOF

# 更新软件源
sudo apt update
```

其他镜像源：
- 清华：`mirrors.tuna.tsinghua.edu.cn`
- 中科大：`mirrors.ustc.edu.cn`
- 网易：`mirrors.163.com`

#### 更新系统

```bash
# 更新软件包列表
sudo apt update

# 升级所有软件包
sudo apt upgrade -y

# 升级系统（包括内核）
sudo apt full-upgrade -y

# 清理不需要的包
sudo apt autoremove -y
```

#### 设置时区

```bash
# 查看当前时区
timedatectl

# 设置为上海时区
sudo timedatectl set-timezone Asia/Shanghai

# 同步时间
sudo apt install ntpdate -y
sudo ntpdate ntp.aliyun.com
```

#### 设置主机名

```bash
# 查看主机名
hostname

# 修改主机名
sudo hostnamectl set-hostname myserver

# 编辑 hosts 文件
sudo nano /etc/hosts
# 添加：127.0.0.1 myserver
```

---

## 3. 文件系统与目录结构

### 3.1 Linux 目录结构

Linux 采用树形目录结构，一切从根目录 `/` 开始：

```
/
├── bin         # 基本命令（ls, cp, mv 等）
├── boot        # 启动文件、内核
├── dev         # 设备文件（硬盘、USB 等）
├── etc         # 系统配置文件（非常重要！）
├── home        # 普通用户的家目录
│   └── username/
├── lib         # 系统库文件
├── media       # 可移动设备挂载点
├── mnt         # 临时挂载点
├── opt         # 第三方软件安装目录
├── proc        # 虚拟文件系统（进程信息）
├── root        # root 用户的家目录
├── run         # 运行时数据
├── sbin        # 系统管理命令
├── srv         # 服务数据
├── sys         # 虚拟文件系统（硬件信息）
├── tmp         # 临时文件（重启会清空）
├── usr         # 用户程序和数据
│   ├── bin/    # 用户命令
│   ├── lib/    # 库文件
│   ├── local/  # 本地安装的软件
│   └── share/  # 共享数据
└── var         # 可变数据（日志、缓存等）
    ├── log/    # 系统日志
    ├── cache/  # 缓存
    └── www/    # Web 服务器文件
```

### 3.2 重要目录说明

| 目录 | 用途 | 常用场景 |
|------|------|----------|
| `/etc` | 配置文件 | 修改系统配置 |
| `/var/log` | 日志文件 | 排查问题 |
| `/home` | 用户数据 | 存放个人文件 |
| `/tmp` | 临时文件 | 临时存储 |
| `/opt` | 第三方软件 | 安装 JDK、Tomcat 等 |
| `/usr/local` | 本地软件 | 编译安装的软件 |

### 3.3 路径表示

```bash
# 绝对路径：从根目录开始
/home/user/documents/file.txt

# 相对路径：从当前目录开始
./file.txt          # 当前目录下的文件
../file.txt         # 上级目录下的文件
~/file.txt          # 家目录下的文件（~ = /home/username）
```

### 3.4 文件类型

```bash
# 使用 ls -l 查看文件类型（第一个字符）
-rw-r--r--  # - 普通文件
drwxr-xr-x  # d 目录
lrwxrwxrwx  # l 符号链接（快捷方式）
crw-rw----  # c 字符设备
brw-rw----  # b 块设备
srwxrwxrwx  # s 套接字
prw-r--r--  # p 管道
```

---

## 4. 基础命令

### 4.1 文件与目录操作

#### 导航命令

```bash
# 显示当前目录
pwd

# 切换目录
cd /path/to/dir     # 切换到指定目录
cd                  # 切换到家目录
cd ~                # 切换到家目录
cd -                # 切换到上一个目录
cd ..               # 切换到上级目录
cd ../..            # 切换到上两级目录

# 列出目录内容
ls                  # 列出文件
ls -l               # 详细信息（长格式）
ls -la              # 包含隐藏文件
ls -lh              # 人类可读的大小
ls -lt              # 按时间排序
ls -lS              # 按大小排序
ls -R               # 递归列出子目录
```

#### 文件操作

```bash
# 创建文件
touch file.txt              # 创建空文件
touch file{1..10}.txt       # 批量创建 file1.txt 到 file10.txt

# 创建目录
mkdir dir                   # 创建目录
mkdir -p a/b/c              # 递归创建多级目录

# 复制
cp file1 file2              # 复制文件
cp -r dir1 dir2             # 复制目录（递归）
cp -p file1 file2           # 保留权限和时间戳
cp -a dir1 dir2             # 完整复制（保留所有属性）

# 移动/重命名
mv file1 file2              # 重命名
mv file1 /path/to/dir/      # 移动文件
mv dir1 dir2                # 移动/重命名目录

# 删除
rm file                     # 删除文件
rm -r dir                   # 删除目录（递归）
rm -f file                  # 强制删除（不提示）
rm -rf dir                  # 强制递归删除（危险！）
rmdir dir                   # 删除空目录
```

> **⚠️ 警告**：`rm -rf /` 会删除整个系统！永远不要执行这个命令！

#### 查看文件内容

```bash
# 查看整个文件
cat file.txt                # 显示全部内容
cat -n file.txt             # 显示行号

# 分页查看
less file.txt               # 分页查看（推荐，支持搜索）
more file.txt               # 分页查看（简单）

# 查看部分内容
head file.txt               # 显示前 10 行
head -n 20 file.txt         # 显示前 20 行
tail file.txt               # 显示后 10 行
tail -n 20 file.txt         # 显示后 20 行
tail -f file.txt            # 实时追踪文件变化（看日志常用）

# 统计
wc file.txt                 # 统计行数、单词数、字节数
wc -l file.txt              # 只统计行数
```

#### 链接

```bash
# 硬链接（指向同一个 inode，删除原文件不影响）
ln file1 file2

# 软链接/符号链接（类似快捷方式，推荐）
ln -s /path/to/file link_name
ln -s /path/to/dir link_name

# 查看链接指向
ls -l link_name
readlink link_name
```

### 4.2 查找命令

#### find - 文件查找

```bash
# 基本语法
find [路径] [条件] [动作]

# 按名称查找
find /home -name "*.txt"           # 查找 .txt 文件
find /home -iname "*.TXT"          # 忽略大小写

# 按类型查找
find /home -type f                 # 查找文件
find /home -type d                 # 查找目录
find /home -type l                 # 查找链接

# 按大小查找
find /home -size +100M             # 大于 100MB
find /home -size -1k               # 小于 1KB

# 按时间查找
find /home -mtime -7               # 7 天内修改的
find /home -mtime +30              # 30 天前修改的
find /home -mmin -60               # 60 分钟内修改的

# 按权限查找
find /home -perm 755               # 权限为 755
find /home -perm -644              # 至少有 644 权限

# 组合条件
find /home -name "*.log" -size +10M
find /home -name "*.tmp" -mtime +7 -delete  # 删除 7 天前的 tmp 文件

# 执行命令
find /home -name "*.txt" -exec cat {} \;    # 对每个文件执行 cat
find /home -name "*.log" -exec rm {} \;     # 删除找到的文件
```

#### locate - 快速查找

```bash
# 安装
sudo apt install mlocate

# 更新数据库
sudo updatedb

# 查找
locate filename
locate -i filename          # 忽略大小写
```

#### which/whereis - 查找命令位置

```bash
which python                # 查找命令的路径
whereis python              # 查找命令、源码、手册的位置
```

### 4.3 帮助命令

```bash
# 查看命令帮助
man ls                      # 查看 ls 的手册
man -k keyword              # 搜索手册

# 简短帮助
ls --help
info ls

# 查看命令类型
type ls                     # 内置命令还是外部命令
```

---

## 5. 用户与权限管理

### 5.1 用户管理

Linux 是多用户系统，每个用户有独立的权限和家目录。

```bash
# 查看当前用户
whoami
id                          # 显示用户 ID 和组 ID

# 查看所有用户
cat /etc/passwd
# 格式：用户名:密码:UID:GID:描述:家目录:Shell

# 创建用户
sudo useradd username                    # 创建用户（基本）
sudo useradd -m -s /bin/bash username    # 创建用户并创建家目录
sudo adduser username                    # 交互式创建（推荐）

# 设置密码
sudo passwd username

# 修改用户
sudo usermod -aG sudo username           # 添加到 sudo 组
sudo usermod -s /bin/zsh username        # 修改 Shell
sudo usermod -d /new/home username       # 修改家目录

# 删除用户
sudo userdel username                    # 删除用户
sudo userdel -r username                 # 删除用户及家目录

# 切换用户
su username                              # 切换用户
su - username                            # 切换用户并加载环境
sudo -i                                  # 切换到 root
```

### 5.2 组管理

```bash
# 查看所有组
cat /etc/group

# 创建组
sudo groupadd groupname

# 删除组
sudo groupdel groupname

# 将用户添加到组
sudo usermod -aG groupname username
sudo gpasswd -a username groupname

# 从组中移除用户
sudo gpasswd -d username groupname

# 查看用户所属的组
groups username
```

### 5.3 文件权限

Linux 权限分为三类用户：
- **Owner（所有者）**：文件的创建者
- **Group（组）**：文件所属的组
- **Others（其他人）**：其他所有用户

权限类型：
- **r（read）**：读取，数值 4
- **w（write）**：写入，数值 2
- **x（execute）**：执行，数值 1

```bash
# 查看权限
ls -l file.txt
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
#  │││ │││ │││
#  │││ │││ └└└─ 其他人权限（r--）
#  │││ └└└───── 组权限（r--）
#  └└└───────── 所有者权限（rw-）
```

#### chmod - 修改权限

```bash
# 数字方式（推荐）
chmod 755 file              # rwxr-xr-x
chmod 644 file              # rw-r--r--
chmod 600 file              # rw-------
chmod 777 file              # rwxrwxrwx（危险！）

# 符号方式
chmod u+x file              # 所有者添加执行权限
chmod g-w file              # 组移除写权限
chmod o=r file              # 其他人只有读权限
chmod a+x file              # 所有人添加执行权限
chmod u=rwx,g=rx,o=r file   # 完整设置

# 递归修改
chmod -R 755 dir/
```

常用权限组合：
| 权限 | 数值 | 说明 |
|------|------|------|
| rwxr-xr-x | 755 | 目录、可执行文件 |
| rw-r--r-- | 644 | 普通文件 |
| rw------- | 600 | 私密文件 |
| rwx------ | 700 | 私密目录 |

#### chown - 修改所有者

```bash
# 修改所有者
sudo chown user file
sudo chown user:group file          # 同时修改所有者和组
sudo chown :group file              # 只修改组

# 递归修改
sudo chown -R user:group dir/
```

### 5.4 sudo 权限

sudo 允许普通用户以 root 权限执行命令。

```bash
# 执行单个命令
sudo apt update

# 切换到 root
sudo -i
sudo su -

# 以其他用户身份执行
sudo -u username command

# 编辑 sudoers 文件（安全方式）
sudo visudo
```

sudoers 配置示例：
```bash
# /etc/sudoers

# 允许 user 执行所有命令
user ALL=(ALL:ALL) ALL

# 允许 user 执行所有命令且不需要密码
user ALL=(ALL:ALL) NOPASSWD: ALL

# 允许 user 只执行特定命令
user ALL=(ALL) /usr/bin/apt, /usr/bin/systemctl
```

### 5.5 特殊权限

#### SUID（Set User ID）

文件执行时以所有者身份运行，而不是执行者身份。

```bash
# 设置 SUID
chmod u+s file
chmod 4755 file

# 查看（s 代替 x）
-rwsr-xr-x

# 典型例子
ls -l /usr/bin/passwd
# -rwsr-xr-x 1 root root ... /usr/bin/passwd
# 普通用户执行 passwd 时以 root 身份运行
```

#### SGID（Set Group ID）

```bash
# 设置 SGID
chmod g+s file
chmod 2755 dir

# 对目录：新建文件继承目录的组
```

#### Sticky Bit

```bash
# 设置 Sticky Bit
chmod +t dir
chmod 1777 dir

# 对目录：只有文件所有者才能删除文件
# 典型例子：/tmp 目录
ls -ld /tmp
# drwxrwxrwt
```

---

## 6. 软件包管理

### 6.1 APT 包管理器

APT（Advanced Package Tool）是 Ubuntu 的包管理器。

```bash
# 更新软件源列表
sudo apt update

# 升级所有软件包
sudo apt upgrade -y

# 升级系统（包括内核）
sudo apt full-upgrade -y
sudo apt dist-upgrade -y

# 搜索软件包
apt search keyword
apt-cache search keyword

# 查看软件包信息
apt show package
apt-cache show package

# 安装软件包
sudo apt install package
sudo apt install package1 package2      # 安装多个
sudo apt install package=version        # 安装指定版本
sudo apt install -y package             # 自动确认

# 卸载软件包
sudo apt remove package                 # 卸载（保留配置）
sudo apt purge package                  # 完全卸载（删除配置）
sudo apt autoremove                     # 删除不需要的依赖

# 清理缓存
sudo apt clean                          # 清理下载的包
sudo apt autoclean                      # 清理旧版本的包
```

### 6.2 dpkg 底层工具

dpkg 是 APT 的底层工具，用于直接操作 .deb 包。

```bash
# 安装 deb 包
sudo dpkg -i package.deb

# 卸载
sudo dpkg -r package
sudo dpkg -P package                    # 完全卸载

# 查看已安装的包
dpkg -l
dpkg -l | grep package

# 查看包的文件列表
dpkg -L package

# 查看文件属于哪个包
dpkg -S /path/to/file

# 修复依赖问题
sudo apt install -f
```

### 6.3 Snap 包管理

Snap 是 Ubuntu 推出的新一代包管理器，软件包自带依赖。

```bash
# 搜索
snap find package

# 安装
sudo snap install package
sudo snap install package --classic     # 经典模式（更多权限）

# 卸载
sudo snap remove package

# 查看已安装
snap list

# 更新
sudo snap refresh
sudo snap refresh package
```

### 6.4 添加第三方软件源

```bash
# 添加 PPA（Personal Package Archive）
sudo add-apt-repository ppa:user/ppa-name
sudo apt update

# 删除 PPA
sudo add-apt-repository --remove ppa:user/ppa-name

# 手动添加软件源
# 1. 添加 GPG 密钥
curl -fsSL https://example.com/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/example.gpg

# 2. 添加软件源
echo "deb [signed-by=/usr/share/keyrings/example.gpg] https://example.com/repo jammy main" | \
    sudo tee /etc/apt/sources.list.d/example.list

# 3. 更新
sudo apt update
```

### 6.5 编译安装软件

有些软件没有预编译包，需要从源码编译。

```bash
# 安装编译工具
sudo apt install build-essential

# 典型编译流程
tar -xzf software.tar.gz
cd software
./configure --prefix=/usr/local
make
sudo make install

# 卸载
sudo make uninstall
# 或手动删除安装的文件
```

---

## 7. 文本处理

### 7.1 文本编辑器

#### nano（简单易用）

```bash
nano file.txt

# 常用快捷键
Ctrl+O      # 保存
Ctrl+X      # 退出
Ctrl+K      # 剪切行
Ctrl+U      # 粘贴
Ctrl+W      # 搜索
Ctrl+G      # 帮助
```

#### vim（强大但需要学习）

```bash
vim file.txt

# 模式
# 普通模式（默认）：移动、删除、复制
# 插入模式：输入文本
# 命令模式：保存、退出等

# 基本操作
i           # 进入插入模式
Esc         # 返回普通模式
:w          # 保存
:q          # 退出
:wq         # 保存并退出
:q!         # 强制退出不保存
:x          # 保存并退出

# 移动
h j k l     # 左下上右
gg          # 文件开头
G           # 文件末尾
0           # 行首
$           # 行尾
w           # 下一个单词
b           # 上一个单词

# 编辑
dd          # 删除行
yy          # 复制行
p           # 粘贴
u           # 撤销
Ctrl+r      # 重做
x           # 删除字符

# 搜索
/keyword    # 向下搜索
?keyword    # 向上搜索
n           # 下一个匹配
N           # 上一个匹配

# 替换
:%s/old/new/g       # 全局替换
:1,10s/old/new/g    # 替换 1-10 行
```

### 7.2 文本处理命令

#### grep - 文本搜索

```bash
# 基本搜索
grep "pattern" file.txt
grep "pattern" file1.txt file2.txt

# 常用选项
grep -i "pattern" file          # 忽略大小写
grep -n "pattern" file          # 显示行号
grep -r "pattern" dir/          # 递归搜索目录
grep -v "pattern" file          # 反向匹配（不包含）
grep -c "pattern" file          # 统计匹配行数
grep -l "pattern" *.txt         # 只显示文件名
grep -w "word" file             # 匹配整个单词
grep -A 3 "pattern" file        # 显示匹配行及后 3 行
grep -B 3 "pattern" file        # 显示匹配行及前 3 行
grep -C 3 "pattern" file        # 显示匹配行及前后 3 行

# 正则表达式
grep -E "pattern1|pattern2" file    # 扩展正则（或）
grep "^start" file                  # 以 start 开头
grep "end$" file                    # 以 end 结尾
grep "a.b" file                     # a 和 b 之间有一个字符
grep "a.*b" file                    # a 和 b 之间有任意字符
```

#### sed - 流编辑器

```bash
# 替换
sed 's/old/new/' file           # 替换每行第一个匹配
sed 's/old/new/g' file          # 替换所有匹配
sed -i 's/old/new/g' file       # 直接修改文件

# 删除
sed '/pattern/d' file           # 删除匹配的行
sed '1d' file                   # 删除第一行
sed '1,5d' file                 # 删除 1-5 行
sed '$d' file                   # 删除最后一行

# 插入
sed '1i\new line' file          # 在第一行前插入
sed '1a\new line' file          # 在第一行后插入

# 打印
sed -n '1,5p' file              # 只打印 1-5 行
sed -n '/pattern/p' file        # 只打印匹配的行
```

#### awk - 文本分析

```bash
# 基本语法
awk '{print}' file              # 打印所有行
awk '{print $1}' file           # 打印第一列
awk '{print $1, $3}' file       # 打印第一和第三列
awk '{print NR, $0}' file       # 打印行号和内容

# 指定分隔符
awk -F: '{print $1}' /etc/passwd    # 以 : 分隔

# 条件过滤
awk '$3 > 100' file             # 第三列大于 100 的行
awk '/pattern/' file            # 匹配 pattern 的行
awk 'NR==1 || NR==5' file       # 第 1 行或第 5 行

# 计算
awk '{sum+=$1} END {print sum}' file    # 求和
awk '{sum+=$1} END {print sum/NR}' file # 平均值

# 格式化输出
awk '{printf "%-10s %5d\n", $1, $2}' file
```

#### sort/uniq - 排序去重

```bash
# 排序
sort file                       # 按字母排序
sort -n file                    # 按数字排序
sort -r file                    # 逆序
sort -k2 file                   # 按第二列排序
sort -t: -k3 -n /etc/passwd     # 指定分隔符，按第三列数字排序

# 去重
uniq file                       # 去除相邻重复行
sort file | uniq                # 先排序再去重
sort file | uniq -c             # 统计重复次数
sort file | uniq -d             # 只显示重复的行
```

#### cut/paste - 列操作

```bash
# 提取列
cut -d: -f1 /etc/passwd         # 以 : 分隔，提取第一列
cut -d: -f1,3 /etc/passwd       # 提取第一和第三列
cut -c1-10 file                 # 提取每行前 10 个字符

# 合并文件
paste file1 file2               # 按列合并
paste -d, file1 file2           # 指定分隔符
```

### 7.3 输入输出重定向

```bash
# 输出重定向
command > file          # 覆盖写入
command >> file         # 追加写入
command 2> file         # 错误输出重定向
command &> file         # 标准输出和错误都重定向
command > file 2>&1     # 同上

# 输入重定向
command < file          # 从文件读取输入

# 管道
command1 | command2     # 将 command1 的输出作为 command2 的输入

# 示例
ls -l | grep ".txt"
cat file | sort | uniq > result.txt
ps aux | grep nginx | awk '{print $2}'
```

---

## 8. 进程管理

### 8.1 查看进程

```bash
# ps - 查看进程快照
ps                      # 当前终端的进程
ps aux                  # 所有进程（BSD 风格）
ps -ef                  # 所有进程（System V 风格）
ps aux | grep nginx     # 查找特定进程

# top - 实时监控
top
# 快捷键：
# q - 退出
# M - 按内存排序
# P - 按 CPU 排序
# k - 杀死进程
# 1 - 显示每个 CPU

# htop - 更好的 top（需安装）
sudo apt install htop
htop

# pgrep - 查找进程 ID
pgrep nginx
pgrep -l nginx          # 显示进程名
```

### 8.2 进程控制

```bash
# 前台/后台运行
command &               # 后台运行
Ctrl+Z                  # 暂停当前进程
bg                      # 将暂停的进程放到后台运行
fg                      # 将后台进程放到前台
jobs                    # 查看后台任务

# nohup - 忽略挂断信号
nohup command &                     # 后台运行，退出终端不会停止
nohup command > output.log 2>&1 &   # 输出到日志

# 杀死进程
kill PID                # 发送 SIGTERM（优雅终止）
kill -9 PID             # 发送 SIGKILL（强制终止）
kill -15 PID            # 发送 SIGTERM
killall process_name    # 按名称杀死所有进程
pkill process_name      # 按名称杀死进程
pkill -u username       # 杀死用户的所有进程

# 常用信号
# SIGTERM (15) - 优雅终止，允许清理
# SIGKILL (9)  - 强制终止，不可捕获
# SIGHUP (1)   - 挂断，常用于重载配置
# SIGINT (2)   - 中断（Ctrl+C）
```

### 8.3 进程优先级

```bash
# 查看优先级（NI 列）
ps -l
top

# nice - 启动时设置优先级（-20 到 19，越小优先级越高）
nice -n 10 command      # 以优先级 10 运行
nice -n -5 command      # 需要 root 权限

# renice - 修改运行中进程的优先级
sudo renice -n 5 -p PID
sudo renice -n -5 -u username   # 修改用户所有进程
```

### 8.4 系统资源查看

```bash
# 内存
free -h                 # 人类可读格式
free -m                 # 以 MB 为单位

# CPU
lscpu                   # CPU 信息
cat /proc/cpuinfo       # 详细 CPU 信息
nproc                   # CPU 核心数

# 系统负载
uptime                  # 运行时间和负载
w                       # 登录用户和负载

# 综合信息
vmstat 1                # 每秒刷新
iostat 1                # IO 统计
```

---

## 9. 磁盘与存储管理

### 9.1 磁盘信息查看

```bash
# 查看磁盘使用情况
df -h                   # 文件系统使用情况
df -i                   # inode 使用情况

# 查看目录大小
du -sh /path            # 目录总大小
du -sh *                # 当前目录下各项大小
du -h --max-depth=1     # 只显示一级子目录

# 查看磁盘设备
lsblk                   # 块设备列表
fdisk -l                # 磁盘分区信息
blkid                   # 设备 UUID
```

### 9.2 磁盘分区

```bash
# 使用 fdisk（MBR 分区）
sudo fdisk /dev/sdb
# 常用命令：
# n - 新建分区
# d - 删除分区
# p - 打印分区表
# w - 保存并退出
# q - 不保存退出

# 使用 gdisk（GPT 分区）
sudo gdisk /dev/sdb

# 使用 parted（推荐，支持大于 2TB）
sudo parted /dev/sdb
# (parted) mklabel gpt
# (parted) mkpart primary ext4 0% 100%
# (parted) print
# (parted) quit
```

### 9.3 文件系统

```bash
# 格式化
sudo mkfs.ext4 /dev/sdb1        # ext4 格式
sudo mkfs.xfs /dev/sdb1         # xfs 格式
sudo mkfs.ntfs /dev/sdb1        # NTFS 格式

# 检查文件系统
sudo fsck /dev/sdb1             # 检查并修复
sudo e2fsck -f /dev/sdb1        # 强制检查 ext 文件系统
```

### 9.4 挂载与卸载

```bash
# 临时挂载
sudo mount /dev/sdb1 /mnt
sudo mount -t ntfs /dev/sdb1 /mnt       # 指定文件系统类型
sudo mount -o ro /dev/sdb1 /mnt         # 只读挂载

# 卸载
sudo umount /mnt
sudo umount /dev/sdb1

# 查看挂载
mount
cat /proc/mounts

# 永久挂载（编辑 /etc/fstab）
sudo nano /etc/fstab
# 格式：设备 挂载点 文件系统 选项 dump fsck
# /dev/sdb1 /data ext4 defaults 0 2
# UUID=xxx /data ext4 defaults 0 2

# 挂载 fstab 中的所有设备
sudo mount -a
```

### 9.5 LVM 逻辑卷管理

LVM 允许动态调整分区大小，非常灵活。

```bash
# 安装
sudo apt install lvm2

# 概念
# PV (Physical Volume) - 物理卷
# VG (Volume Group) - 卷组
# LV (Logical Volume) - 逻辑卷

# 创建物理卷
sudo pvcreate /dev/sdb1 /dev/sdc1
sudo pvs                        # 查看物理卷

# 创建卷组
sudo vgcreate myvg /dev/sdb1 /dev/sdc1
sudo vgs                        # 查看卷组

# 创建逻辑卷
sudo lvcreate -L 10G -n mylv myvg       # 创建 10G 的逻辑卷
sudo lvcreate -l 100%FREE -n mylv myvg  # 使用所有空间
sudo lvs                        # 查看逻辑卷

# 格式化并挂载
sudo mkfs.ext4 /dev/myvg/mylv
sudo mount /dev/myvg/mylv /data

# 扩展逻辑卷
sudo lvextend -L +5G /dev/myvg/mylv     # 增加 5G
sudo resize2fs /dev/myvg/mylv           # 扩展文件系统（ext4）
sudo xfs_growfs /dev/myvg/mylv          # 扩展文件系统（xfs）
```

### 9.6 Swap 交换空间

```bash
# 查看 swap
free -h
swapon --show

# 创建 swap 文件
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# 永久生效
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 调整 swappiness（0-100，越小越少用 swap）
cat /proc/sys/vm/swappiness
sudo sysctl vm.swappiness=10
# 永久生效
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
```

---

## 10. 网络配置与管理

### 10.1 网络信息查看

```bash
# 查看 IP 地址
ip addr
ip a
ifconfig                # 旧命令，需安装 net-tools

# 查看路由表
ip route
route -n

# 查看网络连接
ss -tunlp               # 推荐
netstat -tunlp          # 旧命令

# 查看 DNS
cat /etc/resolv.conf
resolvectl status

# 网络测试
ping google.com
ping -c 4 google.com    # 只 ping 4 次
traceroute google.com   # 追踪路由
mtr google.com          # 更好的 traceroute
curl ifconfig.me        # 查看公网 IP
```

### 10.2 Netplan 网络配置

Ubuntu 22.04 使用 Netplan 管理网络配置。

```bash
# 配置文件位置
/etc/netplan/*.yaml

# 查看当前配置
cat /etc/netplan/00-installer-config.yaml
```

#### DHCP 配置

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: true
```

#### 静态 IP 配置

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 114.114.114.114
```

```bash
# 应用配置
sudo netplan apply

# 测试配置（不应用）
sudo netplan try

# 生成配置
sudo netplan generate
```

### 10.3 防火墙（UFW）

UFW（Uncomplicated Firewall）是 Ubuntu 默认的防火墙工具。

```bash
# 启用/禁用
sudo ufw enable
sudo ufw disable
sudo ufw status
sudo ufw status verbose

# 默认策略
sudo ufw default deny incoming      # 拒绝所有入站
sudo ufw default allow outgoing     # 允许所有出站

# 允许端口
sudo ufw allow 22                   # 允许 SSH
sudo ufw allow 80/tcp               # 允许 HTTP
sudo ufw allow 443/tcp              # 允许 HTTPS
sudo ufw allow 3000:3100/tcp        # 允许端口范围

# 允许服务
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

# 允许特定 IP
sudo ufw allow from 192.168.1.100
sudo ufw allow from 192.168.1.0/24
sudo ufw allow from 192.168.1.100 to any port 22

# 拒绝
sudo ufw deny 23
sudo ufw deny from 192.168.1.100

# 删除规则
sudo ufw delete allow 80
sudo ufw status numbered
sudo ufw delete 2               # 删除第 2 条规则

# 重置
sudo ufw reset
```

### 10.4 SSH 配置

```bash
# 安装 SSH 服务器
sudo apt install openssh-server

# 启动服务
sudo systemctl start ssh
sudo systemctl enable ssh

# 配置文件
sudo nano /etc/ssh/sshd_config
```

常用配置：
```bash
# /etc/ssh/sshd_config

Port 22                         # SSH 端口
PermitRootLogin no              # 禁止 root 登录
PasswordAuthentication yes      # 允许密码登录
PubkeyAuthentication yes        # 允许密钥登录
MaxAuthTries 3                  # 最大尝试次数
ClientAliveInterval 60          # 心跳间隔
ClientAliveCountMax 3           # 心跳次数
```

```bash
# 重启 SSH 服务
sudo systemctl restart ssh

# 生成密钥对
ssh-keygen -t rsa -b 4096
ssh-keygen -t ed25519           # 更安全

# 复制公钥到服务器
ssh-copy-id user@server
# 或手动复制
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

# SSH 连接
ssh user@server
ssh -p 2222 user@server         # 指定端口
ssh -i ~/.ssh/key user@server   # 指定密钥
```

### 10.5 网络工具

```bash
# curl - HTTP 请求
curl https://example.com
curl -o file.html https://example.com       # 下载
curl -O https://example.com/file.zip        # 保留原文件名
curl -I https://example.com                 # 只显示头信息
curl -X POST -d "data" https://example.com  # POST 请求

# wget - 下载
wget https://example.com/file.zip
wget -c https://example.com/file.zip        # 断点续传
wget -r https://example.com                 # 递归下载

# nc (netcat) - 网络调试
nc -zv host port                # 测试端口
nc -l 8080                      # 监听端口

# nmap - 端口扫描
sudo apt install nmap
nmap 192.168.1.1
nmap -sV 192.168.1.1            # 服务版本检测
```

---

## 11. 服务管理

### 11.1 systemd 基础

systemd 是 Ubuntu 的系统和服务管理器。

```bash
# 服务管理
sudo systemctl start service        # 启动服务
sudo systemctl stop service         # 停止服务
sudo systemctl restart service      # 重启服务
sudo systemctl reload service       # 重载配置
sudo systemctl status service       # 查看状态

# 开机自启
sudo systemctl enable service       # 启用开机自启
sudo systemctl disable service      # 禁用开机自启
sudo systemctl is-enabled service   # 检查是否自启

# 查看所有服务
systemctl list-units --type=service
systemctl list-units --type=service --state=running

# 查看服务日志
journalctl -u service
journalctl -u service -f            # 实时查看
journalctl -u service --since today
```

### 11.2 创建自定义服务

```bash
# 创建服务文件
sudo nano /etc/systemd/system/myapp.service
```

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/start.sh
ExecStop=/opt/myapp/stop.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# 重载 systemd 配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start myapp
sudo systemctl enable myapp
```

### 11.3 定时任务

#### cron 定时任务

```bash
# 编辑当前用户的 crontab
crontab -e

# 查看 crontab
crontab -l

# 编辑其他用户的 crontab
sudo crontab -u username -e
```

cron 表达式格式：
```
分 时 日 月 周 命令
*  *  *  *  *  command

# 字段说明
# 分钟 (0-59)
# 小时 (0-23)
# 日期 (1-31)
# 月份 (1-12)
# 星期 (0-7, 0和7都是周日)
```

示例：
```bash
# 每分钟执行
* * * * * /path/to/script.sh

# 每小时执行
0 * * * * /path/to/script.sh

# 每天凌晨 2 点执行
0 2 * * * /path/to/script.sh

# 每周一凌晨 3 点执行
0 3 * * 1 /path/to/script.sh

# 每月 1 号凌晨执行
0 0 1 * * /path/to/script.sh

# 每 5 分钟执行
*/5 * * * * /path/to/script.sh

# 工作日每天 9 点执行
0 9 * * 1-5 /path/to/script.sh
```

#### systemd timer

```bash
# 创建 timer 文件
sudo nano /etc/systemd/system/backup.timer
```

```ini
[Unit]
Description=Daily Backup Timer

[Timer]
OnCalendar=daily
# 或者 OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
# 启用 timer
sudo systemctl enable backup.timer
sudo systemctl start backup.timer

# 查看所有 timer
systemctl list-timers
```

---

## 12. Shell 脚本编程

### 12.1 基础语法

```bash
#!/bin/bash
# 这是注释

# 变量
name="John"
age=25
echo "Hello, $name"
echo "Age: ${age}"

# 只读变量
readonly PI=3.14

# 删除变量
unset name

# 命令替换
current_date=$(date)
current_date=`date`

# 字符串
str1='单引号字符串，不解析变量'
str2="双引号字符串，解析变量 $name"
str3="${str1} ${str2}"

# 字符串长度
echo ${#str1}

# 子字符串
echo ${str1:0:5}        # 从位置 0 开始，取 5 个字符
```

### 12.2 数组

```bash
# 定义数组
arr=(a b c d e)
arr[0]="first"

# 访问元素
echo ${arr[0]}
echo ${arr[@]}          # 所有元素
echo ${#arr[@]}         # 数组长度

# 遍历数组
for item in ${arr[@]}; do
    echo $item
done
```

### 12.3 条件判断

```bash
# if 语句
if [ condition ]; then
    commands
elif [ condition ]; then
    commands
else
    commands
fi

# 文件测试
[ -e file ]     # 文件存在
[ -f file ]     # 是普通文件
[ -d file ]     # 是目录
[ -r file ]     # 可读
[ -w file ]     # 可写
[ -x file ]     # 可执行
[ -s file ]     # 文件大小不为 0

# 字符串测试
[ -z "$str" ]   # 字符串为空
[ -n "$str" ]   # 字符串不为空
[ "$a" = "$b" ] # 字符串相等
[ "$a" != "$b" ]# 字符串不相等

# 数值比较
[ $a -eq $b ]   # 等于
[ $a -ne $b ]   # 不等于
[ $a -gt $b ]   # 大于
[ $a -lt $b ]   # 小于
[ $a -ge $b ]   # 大于等于
[ $a -le $b ]   # 小于等于

# 逻辑运算
[ cond1 ] && [ cond2 ]  # 与
[ cond1 ] || [ cond2 ]  # 或
[ ! cond ]              # 非

# 使用 [[ ]] 更安全（推荐）
[[ -f file && -r file ]]
[[ $str =~ ^[0-9]+$ ]]  # 正则匹配
```

示例：
```bash
#!/bin/bash

file="/etc/passwd"

if [[ -f "$file" ]]; then
    echo "文件存在"
    if [[ -r "$file" ]]; then
        echo "文件可读"
    fi
else
    echo "文件不存在"
fi
```

### 12.4 循环

```bash
# for 循环
for i in 1 2 3 4 5; do
    echo $i
done

for i in {1..10}; do
    echo $i
done

for i in $(seq 1 10); do
    echo $i
done

for file in *.txt; do
    echo $file
done

# C 风格 for 循环
for ((i=0; i<10; i++)); do
    echo $i
done

# while 循环
count=0
while [ $count -lt 5 ]; do
    echo $count
    ((count++))
done

# 读取文件
while read line; do
    echo $line
done < file.txt

# until 循环
until [ $count -ge 5 ]; do
    echo $count
    ((count++))
done

# break 和 continue
for i in {1..10}; do
    if [ $i -eq 5 ]; then
        continue    # 跳过本次
    fi
    if [ $i -eq 8 ]; then
        break       # 退出循环
    fi
    echo $i
done
```

### 12.5 函数

```bash
# 定义函数
function greet() {
    echo "Hello, $1"
}

# 或者
greet() {
    echo "Hello, $1"
}

# 调用函数
greet "World"

# 带返回值的函数
add() {
    local result=$(($1 + $2))
    echo $result
}

sum=$(add 3 5)
echo "Sum: $sum"

# 使用 return（只能返回 0-255 的整数）
check_file() {
    if [ -f "$1" ]; then
        return 0
    else
        return 1
    fi
}

if check_file "/etc/passwd"; then
    echo "文件存在"
fi
```

### 12.6 实用脚本示例

#### 备份脚本

```bash
#!/bin/bash

# 配置
BACKUP_DIR="/backup"
SOURCE_DIR="/var/www"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_${DATE}.tar.gz"
KEEP_DAYS=7

# 创建备份目录
mkdir -p $BACKUP_DIR

# 执行备份
echo "开始备份..."
tar -czf ${BACKUP_DIR}/${BACKUP_FILE} ${SOURCE_DIR}

if [ $? -eq 0 ]; then
    echo "备份成功: ${BACKUP_FILE}"
else
    echo "备份失败!"
    exit 1
fi

# 删除旧备份
echo "清理 ${KEEP_DAYS} 天前的备份..."
find ${BACKUP_DIR} -name "backup_*.tar.gz" -mtime +${KEEP_DAYS} -delete

echo "完成!"
```

#### 系统监控脚本

```bash
#!/bin/bash

# 获取系统信息
echo "========== 系统监控报告 =========="
echo "时间: $(date)"
echo ""

# CPU 使用率
echo "=== CPU 使用率 ==="
top -bn1 | grep "Cpu(s)" | awk '{print "使用率: " 100-$8 "%"}'
echo ""

# 内存使用
echo "=== 内存使用 ==="
free -h | awk 'NR==2{printf "已用: %s / 总计: %s (%.2f%%)\n", $3, $2, $3/$2*100}'
echo ""

# 磁盘使用
echo "=== 磁盘使用 ==="
df -h | awk '$NF=="/"{printf "根分区: %s / %s (%s)\n", $3, $2, $5}'
echo ""

# 网络连接数
echo "=== 网络连接 ==="
echo "TCP 连接数: $(ss -t | wc -l)"
echo ""

# 负载
echo "=== 系统负载 ==="
uptime | awk -F'load average:' '{print "负载: " $2}'
```

#### 日志清理脚本

```bash
#!/bin/bash

LOG_DIR="/var/log"
MAX_SIZE=100  # MB
KEEP_DAYS=30

echo "开始清理日志..."

# 清理大文件
find $LOG_DIR -name "*.log" -size +${MAX_SIZE}M -exec truncate -s 0 {} \;

# 删除旧日志
find $LOG_DIR -name "*.log.*" -mtime +${KEEP_DAYS} -delete
find $LOG_DIR -name "*.gz" -mtime +${KEEP_DAYS} -delete

# 清理 journal 日志
journalctl --vacuum-time=${KEEP_DAYS}d

echo "清理完成!"
```

---

## 13. 系统监控与性能优化

### 13.1 系统监控工具

```bash
# top - 实时进程监控
top

# htop - 更好的 top
sudo apt install htop
htop

# glances - 综合监控
sudo apt install glances
glances

# iotop - IO 监控
sudo apt install iotop
sudo iotop

# nethogs - 网络流量监控
sudo apt install nethogs
sudo nethogs

# dstat - 综合资源统计
sudo apt install dstat
dstat
```

### 13.2 日志查看

```bash
# 系统日志
journalctl                      # 所有日志
journalctl -f                   # 实时查看
journalctl -p err               # 只看错误
journalctl --since "1 hour ago"
journalctl --since "2024-01-01" --until "2024-01-02"

# 传统日志文件
tail -f /var/log/syslog         # 系统日志
tail -f /var/log/auth.log       # 认证日志
tail -f /var/log/kern.log       # 内核日志
tail -f /var/log/nginx/error.log

# 日志轮转配置
cat /etc/logrotate.conf
ls /etc/logrotate.d/
```

### 13.3 性能优化

#### 内核参数优化

```bash
# 查看当前参数
sysctl -a

# 临时修改
sudo sysctl -w net.core.somaxconn=65535

# 永久修改
sudo nano /etc/sysctl.conf
```

常用优化参数：
```bash
# /etc/sysctl.conf

# 网络优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.ip_local_port_range = 1024 65535

# 内存优化
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 5

# 文件描述符
fs.file-max = 2097152
```

```bash
# 应用配置
sudo sysctl -p
```

#### 文件描述符限制

```bash
# 查看当前限制
ulimit -a
ulimit -n               # 文件描述符数量

# 临时修改
ulimit -n 65535

# 永久修改
sudo nano /etc/security/limits.conf
```

```bash
# /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
```

---

## 14. 安全加固

### 14.1 用户安全

```bash
# 禁用 root 远程登录
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no

# 使用密钥登录，禁用密码
# PasswordAuthentication no

# 设置密码策略
sudo apt install libpam-pwquality
sudo nano /etc/security/pwquality.conf
# minlen = 12
# dcredit = -1
# ucredit = -1
# lcredit = -1
# ocredit = -1

# 设置密码过期
sudo chage -M 90 username       # 90 天过期
sudo chage -l username          # 查看密码策略

# 锁定用户
sudo usermod -L username
sudo usermod -U username        # 解锁
```

### 14.2 SSH 安全

```bash
# /etc/ssh/sshd_config

# 修改默认端口
Port 22222

# 禁止 root 登录
PermitRootLogin no

# 禁用密码登录
PasswordAuthentication no

# 只允许特定用户
AllowUsers user1 user2

# 限制登录尝试
MaxAuthTries 3

# 空闲超时
ClientAliveInterval 300
ClientAliveCountMax 2

# 禁用空密码
PermitEmptyPasswords no

# 禁用 X11 转发
X11Forwarding no
```

```bash
# 安装 fail2ban 防暴力破解
sudo apt install fail2ban

# 配置
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
```

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

### 14.3 系统安全

```bash
# 自动安全更新
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# 检查 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 检查无密码用户
awk -F: '($2 == "") {print $1}' /etc/shadow

# 检查 UID 为 0 的用户
awk -F: '($3 == 0) {print $1}' /etc/passwd

# 禁用不需要的服务
sudo systemctl disable cups
sudo systemctl disable avahi-daemon

# 安装安全审计工具
sudo apt install lynis
sudo lynis audit system
```

### 14.4 文件完整性检查

```bash
# 安装 AIDE
sudo apt install aide

# 初始化数据库
sudo aideinit

# 检查文件变化
sudo aide --check
```

---

## 15. 常用服务部署

### 15.1 Nginx

```bash
# 安装
sudo apt install nginx

# 启动
sudo systemctl start nginx
sudo systemctl enable nginx

# 配置文件
/etc/nginx/nginx.conf           # 主配置
/etc/nginx/sites-available/     # 站点配置
/etc/nginx/sites-enabled/       # 启用的站点

# 测试配置
sudo nginx -t

# 重载配置
sudo systemctl reload nginx
```

基本配置示例：
```nginx
# /etc/nginx/sites-available/mysite
server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/mysite;
    index index.html index.php;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }

    # 日志
    access_log /var/log/nginx/mysite.access.log;
    error_log /var/log/nginx/mysite.error.log;
}
```

```bash
# 启用站点
sudo ln -s /etc/nginx/sites-available/mysite /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 15.2 MySQL

```bash
# 安装
sudo apt install mysql-server

# 安全配置
sudo mysql_secure_installation

# 登录
sudo mysql -u root -p

# 创建用户和数据库
CREATE DATABASE mydb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'myuser'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON mydb.* TO 'myuser'@'localhost';
FLUSH PRIVILEGES;

# 允许远程连接
# 1. 修改配置
sudo nano /etc/mysql/mysql.conf.d/mysqld.cnf
# bind-address = 0.0.0.0

# 2. 创建远程用户
CREATE USER 'myuser'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON mydb.* TO 'myuser'@'%';
FLUSH PRIVILEGES;

# 3. 重启服务
sudo systemctl restart mysql
```

### 15.3 Docker

```bash
# 安装 Docker
sudo apt update
sudo apt install ca-certificates curl gnupg

# 添加 Docker 官方 GPG 密钥
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 添加软件源
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 将用户添加到 docker 组（免 sudo）
sudo usermod -aG docker $USER
newgrp docker

# 验证安装
docker run hello-world
```

Docker 常用命令：
```bash
# 镜像管理
docker images                   # 列出镜像
docker pull nginx               # 拉取镜像
docker rmi image_id             # 删除镜像

# 容器管理
docker ps                       # 运行中的容器
docker ps -a                    # 所有容器
docker run -d -p 80:80 nginx    # 运行容器
docker stop container_id        # 停止容器
docker rm container_id          # 删除容器
docker logs container_id        # 查看日志
docker exec -it container_id bash   # 进入容器

# Docker Compose
docker compose up -d            # 启动
docker compose down             # 停止
docker compose logs -f          # 查看日志
```

### 15.4 Node.js

```bash
# 使用 NodeSource 安装
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs

# 或使用 nvm（推荐）
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20

# 验证
node -v
npm -v

# 使用 PM2 管理 Node 应用
npm install -g pm2
pm2 start app.js
pm2 list
pm2 logs
pm2 restart app
pm2 stop app
pm2 startup                     # 开机自启
pm2 save
```

### 15.5 Java (OpenJDK)

```bash
# 安装 JDK
sudo apt install openjdk-17-jdk

# 或安装 JDK 8
sudo apt install openjdk-8-jdk

# 查看版本
java -version
javac -version

# 设置 JAVA_HOME
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64' >> ~/.bashrc
echo 'export PATH=$PATH:$JAVA_HOME/bin' >> ~/.bashrc
source ~/.bashrc

# 切换 Java 版本
sudo update-alternatives --config java
```

---

## 16. 故障排查

### 16.1 系统无法启动

```bash
# 进入恢复模式
# 开机时按住 Shift 或 Esc 进入 GRUB 菜单
# 选择 Advanced options → Recovery mode

# 在恢复模式中
# root - 进入 root shell
# fsck - 检查文件系统
# dpkg - 修复软件包
# network - 启用网络

# 修复 GRUB
sudo grub-install /dev/sda
sudo update-grub

# 修复文件系统
sudo fsck -y /dev/sda1
```

### 16.2 网络问题排查

```bash
# 检查网络接口
ip addr
ip link

# 检查路由
ip route

# 检查 DNS
cat /etc/resolv.conf
nslookup google.com

# 检查连通性
ping 8.8.8.8            # 测试网络
ping google.com         # 测试 DNS

# 检查端口
ss -tunlp
netstat -tunlp

# 检查防火墙
sudo ufw status
sudo iptables -L -n

# 重启网络
sudo systemctl restart NetworkManager
sudo netplan apply
```

### 16.3 磁盘空间不足

```bash
# 查看磁盘使用
df -h

# 查找大文件
du -sh /* | sort -rh | head -20
du -sh /var/* | sort -rh | head -10

# 清理 apt 缓存
sudo apt clean
sudo apt autoremove

# 清理日志
sudo journalctl --vacuum-size=100M
sudo find /var/log -name "*.gz" -delete

# 清理旧内核
dpkg -l | grep linux-image
sudo apt autoremove --purge

# 查找大文件
find / -type f -size +100M 2>/dev/null
```

### 16.4 内存不足

```bash
# 查看内存使用
free -h
top

# 查看内存占用最多的进程
ps aux --sort=-%mem | head -10

# 清理缓存（临时）
sudo sync
sudo echo 3 > /proc/sys/vm/drop_caches

# 检查 OOM Killer 日志
dmesg | grep -i "out of memory"
journalctl | grep -i "oom"
```

### 16.5 CPU 占用过高

```bash
# 查看 CPU 使用
top
htop

# 查看 CPU 占用最多的进程
ps aux --sort=-%cpu | head -10

# 查看进程详情
pidstat 1

# 查看系统调用
strace -p PID

# 查看进程打开的文件
lsof -p PID
```

### 16.6 服务无法启动

```bash
# 查看服务状态
sudo systemctl status service_name

# 查看服务日志
journalctl -u service_name -n 50
journalctl -u service_name --since "10 minutes ago"

# 检查配置文件语法
nginx -t
apache2ctl configtest
mysql --help --verbose | grep -A 1 "Default options"

# 检查端口占用
sudo lsof -i :80
sudo ss -tunlp | grep :80

# 检查权限
ls -la /path/to/files
namei -l /path/to/file
```

---

## 17. 常见错误汇总

### 错误 #1：Permission denied

```
错误信息：bash: ./script.sh: Permission denied

原因：文件没有执行权限

解决：
chmod +x script.sh
# 或
bash script.sh
```

### 错误 #2：Command not found

```
错误信息：bash: xxx: command not found

原因：
1. 命令未安装
2. 命令不在 PATH 中

解决：
# 安装命令
sudo apt install xxx

# 检查 PATH
echo $PATH

# 使用完整路径
/usr/local/bin/xxx
```

### 错误 #3：No space left on device

```
错误信息：No space left on device

原因：磁盘空间不足

解决：
# 查看磁盘使用
df -h

# 清理空间
sudo apt clean
sudo journalctl --vacuum-size=100M
find /tmp -type f -mtime +7 -delete
```

### 错误 #4：Too many open files

```
错误信息：Too many open files

原因：文件描述符数量超过限制

解决：
# 查看当前限制
ulimit -n

# 临时增加
ulimit -n 65535

# 永久修改 /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535
```

### 错误 #5：Connection refused

```
错误信息：Connection refused

原因：
1. 服务未启动
2. 防火墙阻止
3. 端口错误

解决：
# 检查服务状态
sudo systemctl status service_name

# 检查端口监听
ss -tunlp | grep port

# 检查防火墙
sudo ufw status
```

### 错误 #6：apt update 失败

```
错误信息：
E: Failed to fetch http://...
E: Some index files failed to download

原因：
1. 网络问题
2. 软件源不可用
3. DNS 问题

解决：
# 检查网络
ping 8.8.8.8

# 更换镜像源
sudo nano /etc/apt/sources.list

# 清理缓存
sudo rm -rf /var/lib/apt/lists/*
sudo apt update
```

### 错误 #7：dpkg 被锁定

```
错误信息：
E: Could not get lock /var/lib/dpkg/lock-frontend

原因：另一个进程正在使用 apt/dpkg

解决：
# 等待其他进程完成，或

# 查找并结束进程
ps aux | grep -i apt
sudo kill PID

# 删除锁文件（谨慎）
sudo rm /var/lib/dpkg/lock-frontend
sudo rm /var/lib/apt/lists/lock
sudo dpkg --configure -a
```

### 错误 #8：SSH 连接超时

```
错误信息：Connection timed out

原因：
1. 网络不通
2. 防火墙阻止
3. SSH 服务未启动
4. 端口错误

解决：
# 检查网络
ping server_ip

# 检查端口
nc -zv server_ip 22

# 服务器端检查
sudo systemctl status ssh
sudo ufw status
```

### 错误 #9：sudo 密码错误

```
错误信息：Sorry, try again.

原因：
1. 密码确实错误
2. 用户不在 sudoers 中

解决：
# 重置密码（需要 root 或恢复模式）
sudo passwd username

# 添加到 sudo 组
sudo usermod -aG sudo username
```

### 错误 #10：软件包依赖问题

```
错误信息：
Depends: xxx but it is not going to be installed

原因：依赖冲突或版本不匹配

解决：
# 修复依赖
sudo apt install -f

# 强制安装
sudo apt install --fix-broken

# 清理并重试
sudo apt clean
sudo apt update
sudo apt upgrade
```

---

## 附录：常用命令速查表

### 文件操作
```bash
ls -la          # 列出所有文件
cd /path        # 切换目录
cp -r src dst   # 复制
mv src dst      # 移动/重命名
rm -rf dir      # 删除
mkdir -p dir    # 创建目录
touch file      # 创建文件
cat file        # 查看文件
less file       # 分页查看
head/tail file  # 查看开头/结尾
```

### 权限管理
```bash
chmod 755 file      # 修改权限
chown user:group file   # 修改所有者
sudo command        # 以 root 执行
```

### 软件管理
```bash
sudo apt update     # 更新源
sudo apt upgrade    # 升级软件
sudo apt install pkg    # 安装
sudo apt remove pkg     # 卸载
```

### 进程管理
```bash
ps aux          # 查看进程
top/htop        # 实时监控
kill PID        # 终止进程
kill -9 PID     # 强制终止
```

### 网络管理
```bash
ip addr         # 查看 IP
ss -tunlp       # 查看端口
ping host       # 测试连通
curl url        # HTTP 请求
```

### 服务管理
```bash
systemctl start/stop/restart service
systemctl enable/disable service
systemctl status service
journalctl -u service
```

### 系统信息
```bash
uname -a        # 系统信息
df -h           # 磁盘使用
free -h         # 内存使用
uptime          # 运行时间
```

---

> 📝 **学习建议**
> 
> 1. 先在虚拟机中练习，不怕搞坏
> 2. 多用 `man` 和 `--help` 查看帮助
> 3. 遇到错误先看日志：`journalctl` 和 `/var/log/`
> 4. 善用 Tab 键自动补全
> 5. 重要操作前先备份
> 6. 养成写注释的习惯
