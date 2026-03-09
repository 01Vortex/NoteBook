## 系统初始配置

### 1. 登录系统

启动完成后，您会看到一个黑色的命令行界面：

```bash
localhost login: root
Password: [输入您安装时设置的root密码，输入时不显示]
```

### 2. 配置网络 (最关键的一步)

Minimal 版本默认网卡是**关闭**的，您需要先联网才能进行后续操作。

1. **查看网卡名称**：
    
    ```bash
    ip addr
    ```
    
    通常名为 `ens33` 或 `eth0`。如果没有看到 IP 地址，说明网卡未启动。
    
2. **编辑网卡配置文件**（以 `ens33` 为例）：
    
    ```bash
    vi /etc/sysconfig/network-scripts/ifcfg-ens33
    ```
    
    _按 `i` 键进入编辑模式_，找到 `ONBOOT=no`，将其改为 `yes`。
    
    ```text
    ONBOOT=yes
    ```
    
    _(可选)_ 如果您需要固定 IP，可以在此文件中配置 `IPADDR`, `GATEWAY`, `DNS1` 等；如果需要动态获取 IP，确保 `BOOTPROTO=dhcp`。
    
3. **保存退出**：  
    按 `Esc` 键，输入 `:wq` 并回车。
    
4. **重启网络服务**：
    
    ```bash
    systemctl restart network
    ```
    
    再次输入 `ip addr` 确认是否获取到了 IP 地址。尝试 `ping www.baidu.com` 测试连通性。
    

### 3. 更换 YUM 源 (必须执行)

由于官方源已停用，必须切换到阿里云或清华大学的 Vault 源。

1. **备份原有配置**：
    
    ```bash
    mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
    ```
    
2. **下载阿里云 CentOS 7 归档源配置**：
    
    ```bash
    curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
    ```
    
    _如果 curl 未安装或失败，可以使用 vi 手动创建文件，内容需将 `mirror.centos.org` 替换为 `vault.centos.org` 或使用阿里提供的特定 EOL 配置。_
    
    **手动修正方法（推荐，更稳妥）：**  
    由于直接下载的文件可能仍指向已失效的地址，建议直接编辑文件将 URL 指向归档库：
    
    ```bash
    sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/CentOS-Base.repo
    sed -i 's/#baseurl/baseurl/g' /etc/yum.repos.d/CentOS-Base.repo
    sed -i 's/metalink/#metalink/g' /etc/yum.repos.d/CentOS-Base.repo
    ```
    
    _(注：如果阿里云源已专门针对 EOL 做了调整，直接使用阿里云 repo 即可；若报错，请确保指向 `vault.centos.org`)_
    
3. **清理并生成缓存**：
    
    ```bash
    yum clean all
    yum makecache
    ```
    
    如果看到 `Metadata cache created`，说明源配置成功。
    

### 4. 系统更新与安装常用工具

现在您可以安装必要的工具了。

1. **更新系统内核及软件**（可选，但建议做）：
    
    ```bash
    yum update -y
    ```
    
2. **安装常用工具包**（Minimal 版通常缺少这些）：
    
    ```bash
    yum install -y vim net-tools wget bash-completion curl git unzip zip
    ```
    
    - `vim`: 更好的文本编辑器
    - `net-tools`: 包含 `ifconfig`, `netstat` 等命令
    - `wget`: 下载工具

### 5. 基础安全与优化配置

1. **设置主机名**：
    
    ```bash
    hostnamectl set-hostname my-centos-server
    # 验证
    hostname
    ```
    
2. **配置防火墙 (Firewalld)**：  
    CentOS 7 默认开启防火墙。
    
    - 查看状态：`systemctl status firewalld`
    - 开放端口（例如开放 Web 服务的 80 端口）：
        
        ```bash
        firewall-cmd --permanent --add-service=http
        firewall-cmd --reload
        ```
        
    - _如果是内网测试环境想暂时关闭防火墙（生产环境严禁关闭）：_
        
        ```bash
        systemctl stop firewalld
        systemctl disable firewalld
        ```
        
3. **配置 SSH 禁止 Root 远程登录 (安全建议)**：  
    编辑 `/etc/ssh/sshd_config`，创建一个普通用户用于日常操作，然后禁用 root 远程登录。
    
    ```bash
    # 创建新用户
    useradd admin_user
    passwd admin_user
    
    # 赋予 sudo 权限
    echo "admin_user ALL=(ALL) ALL" >> /etc/sudoers
    
    # 修改 SSH 配置
    vi /etc/ssh/sshd_config
    # 找到 PermitRootLogin yes 改为 no
    # 找到 PasswordAuthentication yes 保持 yes (除非你用密钥)
    
    # 重启 SSH 服务
    systemctl restart sshd
    ```
    
    _(注意：在退出当前会话前，务必新开一个终端测试新用户能否登录，以免把自己锁在外面！)_
    
4. **时间同步**：  
    安装并配置 NTP 或 Chrony（CentOS 7 默认使用 Chrony）。
    
    ```bash
    yum install -y chrony
    systemctl start chronyd
    systemctl enable chronyd
    # 检查时间
    date
    ```
    

### 6. 可选：安装 EPEL 源

EPEL (Extra Packages for Enterprise Linux) 提供了大量额外的软件包。

```bash
yum install -y epel-release
```

_(如果这一步失败，说明第3步的源配置有问题，请检查网络连接和 repo 文件)_

---





## 剑魂之刃
```
unzip LinuxPanel-*
cd panel
bash update.sh
cd .. && rm -f LinuxPanel-*.zip && rm -rf panel
echo '127.0.0.1 bt.cn' >>/etc/hosts
bt 16 #修复面板
```

































