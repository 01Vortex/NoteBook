# 一、系统管理

1. **更新系统软件包**
   ```bash
   sudo apt update        # 更新软件包列表
   sudo apt upgrade       # 升级已安装的软件包
   sudo apt full-upgrade  # 升级并自动处理依赖关系
   sudo apt autoremove    # 移除不再需要的包
   ```

2. **查看系统信息**
   ```bash
   uname -a               # 查看内核版本和系统架构
   lsb_release -a         # 查看Ubuntu版本信息
   df -h                  # 查看磁盘使用情况
   free -h                # 查看内存使用情况
   top                    # 实时查看系统进程和资源使用
   htop                   # 交互式进程查看器（需安装）
   ```

3. **管理用户和组**
   ```bash
   sudo adduser username  # 添加新用户
   sudo deluser username  # 删除用户
   sudo passwd username   # 修改用户密码
   sudo usermod -aG group username  # 将用户添加到组
   ```

4. **管理服务**
   ```bash
   sudo systemctl start service_name    # 启动服务
   sudo systemctl stop service_name     # 停止服务
   sudo systemctl restart service_name  # 重启服务
   sudo systemctl enable service_name   # 设置服务开机自启
   sudo systemctl disable service_name  # 取消服务开机自启
   sudo systemctl status service_name   # 查看服务状态
   ```

5. **查看日志**
   ```bash
   journalctl -xe         # 查看系统日志
   cat /var/log/syslog    # 查看syslog日志
   cat /var/log/auth.log  # 查看认证日志
   ```

# 二、文件操作

6. **基本文件操作**
   ```bash
   ls                      # 列出当前目录内容
   ls -l                   # 详细列出目录内容
   cd directory            # 切换目录
   pwd                     # 显示当前工作目录
   cp source destination    # 复制文件或目录
   mv source destination    # 移动或重命名文件或目录
   rm file                 # 删除文件
   rm -r directory         # 删除目录及其内容
   mkdir directory        # 创建新目录
   rmdir directory          # 删除空目录
   ```

7. **查找文件**
   ```bash
   find /path -name "filename"    # 在指定路径下查找文件
   locate filename                # 使用locate数据库查找文件
   ```

8. **查看文件内容**
   ```bash
   cat file                     # 显示文件内容
   less file                    # 分页查看文件内容
   head file                    # 查看文件开头部分
   tail file                    # 查看文件结尾部分
   tail -f file                 # 实时查看文件结尾（用于日志文件）
   ```

9. **压缩和解压**
   ```bash
   tar -cvf archive.tar directory    # 创建tar归档
   tar -xvf archive.tar              # 解压tar归档
   tar -czvf archive.tar.gz directory  # 创建gzip压缩的tar归档
   tar -xzvf archive.tar.gz           # 解压gzip压缩的tar归档
   gzip file                          # 压缩文件为.gz
   gunzip file.gz                     # 解压.gz文件
   ```

# 三、网络配置

10. **查看网络接口**
   ```bash
   ifconfig            # 查看网络接口信息（需安装net-tools）
   ip addr             # 查看网络接口信息
   ```

11. **管理网络连接**
   ```bash
   sudo systemctl restart NetworkManager    # 重启网络管理服务
   nmcli device status                      # 查看网络设备状态
   nmcli connection show                    # 查看网络连接
   nmcli connection up connection_name      # 启用网络连接
   nmcli connection down connection_name    # 禁用网络连接
   ```

12. **配置防火墙**
   ```bash
   sudo ufw status             # 查看防火墙状态
   sudo ufw enable             # 启用防火墙
   sudo ufw disable            # 禁用防火墙
   sudo ufw allow 80/tcp       # 允许HTTP流量
   sudo ufw allow from 192.168.1.100  # 允许特定IP的流量
   ```

13. **网络诊断**
   ```bash
   ping hostname_or_ip        # 测试网络连通性
   traceroute hostname_or_ip  # 跟踪路由
   netstat -tuln              # 查看监听的端口
   ```

# 四、软件安装与管理

14. **使用APT包管理器**
   ```bash
   sudo apt update             # 更新软件包列表
   sudo apt install package    # 安装软件包
   sudo apt remove package     # 移除软件包
   sudo apt purge package      # 彻底移除软件包及其配置文件
   sudo apt search keyword     # 搜索软件包
   ```

15. **使用Snap包**
   ```bash
   sudo snap install package    # 安装Snap包
   sudo snap remove package     # 移除Snap包
   snap list                    # 列出已安装的Snap包
   ```

16. **使用PPA（个人包档案）**
   ```bash
   sudo add-apt-repository ppa:user/repository    # 添加PPA
   sudo apt update
   sudo apt install package
   ```

17. **编译安装软件**
   ```bash
   ./configure
   make
   sudo make install
   ```

# 五、权限管理

18. **更改文件权限**
   ```bash
   chmod 755 file             # 修改文件权限
   chmod -R 755 directory     # 递归修改目录权限
   ```

19. **更改文件所有者**
   ```bash
   sudo chown user:group file         # 更改文件所有者
   sudo chown -R user:group directory  # 递归更改目录所有者
   ```

20. **使用sudo**
   ```bash
   sudo command          # 以超级用户权限执行命令
   sudo -i               # 切换到超级用户
   ```

# 六、其他常用命令

21. **查看进程**
   ```bash
   ps aux                # 查看所有进程
   ps -ef                # 查看所有进程（详细信息）
   pkill process_name    # 终止进程
   kill pid              # 终止指定PID的进程
   ```

22. **环境变量**
   ```bash
   echo $PATH            # 查看PATH环境变量
   export PATH=$PATH:/new/path  # 添加新的路径到PATH
   ```

23. **文本处理**
   ```bash
   grep "pattern" file       # 在文件中搜索模式
   sed 's/old/new/g' file    # 替换文件中的文本
   awk '{print $1}' file     # 处理文本文件
   ```

24. **定时任务**
   ```bash
   crontab -e               # 编辑crontab文件
   crontab -l               # 查看crontab任务
   ```

25. **系统重启和关机**
   ```bash
   sudo reboot              # 重启系统
   sudo poweroff            # 关闭系统
   sudo shutdown -h now     # 立即关机
   ```

# 七、脚本编写

26. **基本脚本结构**
   ```bash
   #!/bin/bash
   echo "Hello, World!"
   ```

27. **运行脚本**
   ```bash
   chmod +x script.sh
   ./script.sh
   ```

28. **条件语句**
   ```bash
   if [ condition ]; then
       echo "Condition met"
   else
       echo "Condition not met"
   fi
   ```

29. **循环语句**
   ```bash
   for i in {1..5}; do
       echo "Number $i"
   done

   while [ condition ]; do
       echo "Looping"
   done
   ```

# 八、版本控制

30. **安装Git**
   ```bash
   sudo apt install git
   ```

31. **配置Git**
   ```bash
   git config --global user.name "Your Name"
   git config --global user.email "your_email@example.com"
   ```

32. **基本Git操作**
   ```bash
   git init                # 初始化Git仓库
   git clone repository_url # 克隆远程仓库
   git add file            # 添加文件到暂存区
   git commit -m "message" # 提交更改
   git status              # 查看状态
   git pull                # 拉取远程更改
   git push                # 推送本地更改
   ```

# 九、虚拟化

33. **安装KVM**
   ```bash
   sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils
   sudo adduser $USER libvirt
   sudo adduser $USER libvirt-qemu
   ```

34. **使用VirtualBox**
   ```bash
   sudo apt install virtualbox
   ```

35. **使用LXD**
   ```bash
   sudo snap install lxd
   lxd init
   ```

# 十、容器化

36. **安装Docker**
   ```bash
   sudo apt update
   sudo apt install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
   sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
   sudo apt update
   sudo apt install docker-ce docker-ce-cli containerd.io
   ```

37. **基本Docker操作**
   ```bash
   sudo systemctl start docker
   sudo systemctl enable docker
   docker pull image_name
   docker run -d -p host_port:container_port image_name
   docker ps
   docker stop container_id
   docker rm container_id
   ```
