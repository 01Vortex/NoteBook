## **文件和目录操作**

- **`ls`**：列出目录内容
  - `ls`：列出当前目录的文件和文件夹
  - `ls -l`：以详细列表形式显示
  - `ls -a`：显示所有文件，包括隐藏文件
  - `ls -lh`：以人类可读的格式显示文件大小

- **`cd`**：更改当前工作目录
  - `cd /path/to/directory`：切换到指定目录
  - `cd ..`：返回上一级目录
  - `cd ~` 或 `cd`：切换到当前用户的主目录

- **`pwd`**：显示当前工作目录的完整路径

- **`mkdir`**：创建新目录
  - `mkdir directory_name`：创建单个目录
  - `mkdir -p /path/to/directory`：创建多级目录

- **`rmdir`**：删除空目录

- **`rm`**：删除文件或目录
  - `rm file`：删除文件
  - `rm -r directory`：递归删除目录及其内容
  - `rm -f file`：强制删除，不提示

- **`cp`**：复制文件或目录
  - `cp source destination`：复制文件
  - `cp -r source_directory destination_directory`：递归复制目录

- **`mv`**：移动或重命名文件或目录
  - `mv source destination`：移动文件或目录
  - `mv old_name new_name`：重命名文件或目录

- **`touch`**：创建空文件或更新文件时间戳
  - `touch file`：创建空文件
  - `touch -a file`：更新文件的访问时间

- **`cat`**：连接文件并打印到标准输出
  - `cat file`：显示文件内容
  - `cat file1 file2 > file3`：合并文件

- **`less`**：分页查看文件内容
  - `less file`：以分页方式查看文件

- **`head`**：查看文件的开头部分
  - `head file`：显示文件的前10行
  - `head -n 20 file`：显示文件的前20行

- **`tail`**：查看文件的末尾部分
  - `tail file`：显示文件的后10行
  - `tail -n 20 file`：显示文件的后20行
  - `tail -f file`：实时查看文件的新增内容

## **系统信息**

- **`uname`**：显示系统信息
  - `uname -a`：显示所有系统信息

- **`df`**：显示文件系统磁盘空间使用情况
  - `df -h`：以人类可读的格式显示

- **`du`**：显示目录或文件的磁盘使用情况
  - `du -sh /path/to/directory`：显示指定目录的总大小

- **`free`**：显示内存使用情况
  - `free -h`：以人类可读的格式显示

- **`top`**：实时显示系统进程和资源使用情况
  - `top`：启动交互式界面
  - `htop`：更高级的进程查看器（需要安装）

- **`ps`**：显示当前进程
  - `ps aux`：显示所有进程

## **权限管理**

- **`chmod`**：更改文件或目录的权限
  - `chmod 755 file`：设置权限为755
  - `chmod +x file`：添加执行权限

- **`chown`**：更改文件或目录的所有者和组
  - `chown user:group file`：更改所有者和组
  - `chown -R user:group directory`：递归更改目录及其内容的所有者和组

- **`sudo`**：以超级用户权限执行命令
  - `sudo command`：以超级用户权限执行命令

## **网络管理**

- **`ping`**：测试与另一台主机的网络连接
  - `ping host`：发送ICMP回显请求

- **`ifconfig`**（旧版）或 **`ip`**（新版）：显示和配置网络接口
  - `ifconfig`：显示网络接口信息
  - `ip addr`：显示IP地址信息
  - `ip route`：显示路由信息

- **`netstat`**：显示网络连接、路由表和网络接口信息
  - `netstat -tuln`：显示监听的TCP和UDP端口

- **`ss`**：比`netstat`更快的替代工具
  - `ss -tuln`：显示监听的TCP和UDP端口

- **`wget`**：非交互式网络下载器
  - `wget URL`：下载文件

- **`curl`**：发送HTTP请求
  - `curl URL`：获取URL内容
  - `curl -O URL`：下载文件

## **文本处理**

- **`grep`**：在文件中搜索指定的模式
  - `grep "pattern" file`：在文件中搜索模式
  - `grep -r "pattern" directory`：递归搜索目录

- **`sed`**：流编辑器，用于文本替换
  - `sed 's/old/new/g' file`：将文件中的old替换为new

- **`awk`**：文本处理工具，用于模式扫描和处理
  - `awk '{print $1}' file`：打印每行的第一个字段

- **`sort`**：对文本文件进行排序
  - `sort file`：对文件进行排序
  - `sort -u file`：对文件进行排序并去重

- **`uniq`**：去除重复的行
  - `uniq file`：去除相邻的重复行
  - `sort file | uniq`：先排序再去除重复行

## **压缩与归档**

- **`tar`**：归档工具
  - `tar -cvf archive.tar file1 file2`：创建归档
  - `tar -xvf archive.tar`：解压归档
  - `tar -czvf archive.tar.gz directory`：创建压缩归档

- **`gzip`**：压缩和解压缩文件
  - `gzip file`：压缩文件
  - `gzip -d file.gz`：解压缩文件

- **`gunzip`**：解压缩文件
  - `gunzip file.gz`：解压缩文件

- **`zip`** 和 **`unzip`**：创建和打开ZIP压缩文件
  - `zip archive.zip file1 file2`：创建ZIP文件
  - `unzip archive.zip`：解压ZIP文件

## **进程管理**

- **`kill`**：终止进程
  - `kill PID`：发送TERM信号终止进程
  - `kill -9 PID`：强制终止进程

- **`pkill`**：根据名称终止进程
  - `pkill process_name`：终止指定名称的进程

- **`pgrep`**：查找进程ID
  - `pgrep process_name`：查找指定名称的进程ID

- **`systemctl`**：管理系统服务
  - `systemctl start service`：启动服务
  - `systemctl stop service`：停止服务
  - `systemctl restart service`：重启服务
  - `systemctl status service`：查看服务状态

## **其他常用命令**

- **`man`**：查看命令的手册页
  - `man command`：查看命令的手册页

- **`history`**：显示命令历史
  - `history`：显示历史命令列表

- **`echo`**：在终端上显示消息
  - `echo "Hello, World!"`：显示消息

- **`alias`**：创建命令别名
  - `alias ll='ls -alF'`：创建别名

- **`export`**：设置环境变量
  - `export PATH=$PATH:/new/path`：添加路径到PATH

- **`source`**：在当前shell环境中执行脚本
  - `source script.sh`：执行脚本
