# [Linux命令手册](https://www.linuxcool.com/)

# Linux CentOS
## 基本知识
**Linux CentOS 7** 是 **社区企业操作系统（Community Enterprise Operating System）** 的第7个主要版本，是一个基于 Red Hat Enterprise Linux（RHEL）源代码构建的 **免费开源企业级 Linux 发行版**。它于2014年发布，2024年6月30日结束生命周期（EOL），至今仍是许多企业服务器的核心系统。

---

### **核心特性与价值**
#### 1. **企业级稳定性**
   - **长期支持（LTS）**：提供长达10年的安全更新（2014-2024）。
   - **保守更新策略**：软件包经过严格测试，避免新版本引入兼容性问题。
   - **高可靠性**：支持关键业务系统（如银行、电信服务器）。

#### 2. **技术架构革新**
   - **内核版本**：初始内核 3.10.x，支持新硬件（如64位ARM、虚拟化优化）。
   - **Systemd 取代 SysVinit**：
     ```bash
     # 服务管理对比
     CentOS 6: service httpd restart   → CentOS 7: systemctl restart httpd
     ```
   - **XFS 为默认文件系统**：支持最大8EB的存储卷（Ext4仅1EB）。

#### 3. **关键组件升级**
   | 组件          | CentOS 6         | CentOS 7               |
   |---------------|------------------|------------------------|
   | 防火墙        | iptables         | **firewalld**（动态管理）|
   | 网络管理      | network-scripts  | **NetworkManager**     |
   | 虚拟化        | Xen/KVM          | **KVM 主导** + Docker 支持 |

---

### **典型应用场景**
1. **Web 服务器**  
   - 支持主流环境：  
     ```bash
     # LAMP 栈安装
     yum install httpd mariadb-server php php-mysql
     systemctl enable httpd mariadb
     ```

2. **私有云与虚拟化**  
   - 运行 OpenStack、KVM 虚拟机（通过 `virt-manager` 管理）。

3. **企业中间件**  
   - 部署 Java 应用（Tomcat/JBoss）、数据库（MySQL/PostgreSQL）。

4. **网络基础设施**  
   - 防火墙（iptables/firewalld）、VPN（OpenVPN）、路由（Quagga）。

---

### **生命周期与替代方案**
#### ⚠️ **终止支持（EOL）影响**
- **安全风险**（2024年6月30日起）：  
  ```bash
  # 检查更新将失效
  yum update  # 返回 "No repositories available"
  ```
- **解决方案**：
  - **迁移到兼容系统**：  
    | 替代发行版      | 特点                          |
    |----------------|------------------------------|
    | **AlmaLinux**  | RHEL 1:1 克隆，由原CentOS创始人支持 |
    | **Rocky Linux**| 社区驱动，红帽官方认证          |
    | **CentOS Stream**| RHEL 上游预览版（非稳定环境适用）|

---

### **基础操作速查**
#### 网络配置
```bash
# 传统方式（CentOS 7兼容）
vi /etc/sysconfig/network-scripts/ifcfg-eth0  
DEVICE=eth0
BOOTPROTO=static
IPADDR=192.168.1.100
NETMASK=255.255.255.0
```

#### 防火墙管理
```bash
# 开放HTTP服务
firewall-cmd --permanent --add-service=http
firewall-cmd --reload
```

#### 系统维护
```bash
# 查看版本
cat /etc/redhat-release  # 输出: CentOS Linux release 7.9.2009 (Core)

# 检查安全更新
yum --security check-update
```

---

### **为什么企业曾青睐 CentOS 7？**
1. **零成本获得RHEL能力**  
   与 RHEL 二进制兼容，无需支付许可费。
2. **硬件兼容性广**  
   支持从老式x86服务器到最新Power9架构。
3. **生态完善**  
   超过90%的企业级软件（如Oracle DB、SAP）提供官方支持。

> 💡 **历史意义**：CentOS 7 是最后一个“传统”CentOS版本。其停用标志着开源企业Linux进入新时代（Rocky/AlmaLinux 崛起）。

---

### **学习资源**
- **官方文档**：[CentOS 7 Documentation](https://docs.centos.org/en-US/centos/install-guide/)  
- **迁移指南**：[从CentOS 7迁移到AlmaLinux](https://wiki.almalinux.org/migration/)  
- **命令对比**：[CentOS 6 vs 7 Cheat Sheet](https://access.redhat.com/sites/default/files/attachments/rhel7_cheatsheet_1214_jcs_print-1.pdf)

> 提示：新项目请选择 **AlmaLinux 9** 或 **RHEL 9** 订阅版，延续企业级稳定性基因。



## CentOS7更换镜像源
由于 CentOS 7 的官方仓库已经 **停止更新和维护**，你需要将默认仓库源替换为一个仍然提供 CentOS 7 软件包的镜像站。以下是使用阿里云镜像的步骤：

### 备份原来的 repo 文件

```bash
sudo mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
```

### 下载阿里云提供的 CentOS-Base.repo 文件

```bash
sudo curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
```

### 清除缓存并生成新缓存

```bash
sudo yum clean all
sudo yum makecache
```

### 尝试更新

```bash
sudo yum update
```


# Linux Ubuntu
**Ubuntu** 是全球最流行的 **开源 Linux 发行版**，由 Canonical 公司主导开发，以“为人类设计的操作系统”为核心理念。其名称源自非洲祖鲁语“**Ubuntu**”（意为“仁爱”或“群在故我在”），体现了开源社区共享精神。以下是深度解析：

---

### **核心特性与定位**
| **维度**       | **特点**                                                                 |
|----------------|--------------------------------------------------------------------------|
| **用户友好性** | 图形安装向导、桌面环境（GNOME默认）、完善的硬件驱动支持                  |
| **发布节奏**   | 每6个月发布新版本（如23.10），**LTS版（长期支持）** 每2年一版（支持5年） |
| **软件生态**   | 超59,000个软件包，支持 Snap/APT/Deb 多格式安装                           |
| **应用场景**   | 从桌面办公到云服务器、物联网设备的全栈覆盖                              |

> 📌 **2023年数据**：Ubuntu占据全球公有云镜像市场**37%份额**（AWS/Azure/GCP默认镜像），桌面Linux市场**35%占有率**（StatCounter）

---

### **技术架构亮点**
#### 1. **革命性软件包管理**
   - **APT**（高级包工具）：自动解决依赖关系
     ```bash
     sudo apt update && sudo apt install nginx # 安装Web服务器
     ```
   - **Snap**：跨发行版容器化软件包
     ```bash
     sudo snap install vscode --classic # 安装Visual Studio Code
     ```

#### 2. **安全强化设计**
   - **AppArmor**：强制访问控制（MAC）限制程序权限
   - **Livepatch**：无需重启的内核热补丁（企业版特性）
   - **Uncomplicated Firewall (UFW)**：简化防火墙配置
     ```bash
     sudo ufw allow 22/tcp # 开放SSH端口
     ```

#### 3. **桌面环境进化**
   ```mermaid
   graph LR
   A[Ubuntu 22.04 LTS] -->|GNOME 42| B[现代化界面]
   B --> C[手势触控支持]
   B --> D[多工作区管理]
   B --> E[原生Wayland显示协议]
   ```

---

### **关键版本对比**
| **版本类型**   | 发布周期       | 支持期限      | 典型版本号       | 适用场景               |
|----------------|---------------|--------------|-----------------|-----------------------|
| **LTS**        | 每2年（4月）  | **5年**      | 20.04/22.04/24.04| 企业服务器/生产环境    |
| **标准版**     | 每6个月（4/10月） | **9个月**    | 23.10/24.10     | 开发者尝鲜新功能       |

> 💡 **当前推荐**：  
> - 服务器：**Ubuntu 22.04 LTS**（支持至2027年）  
> - 桌面：**Ubuntu 24.04 LTS**（2024年最新LTS）

---

### **应用场景实战**
#### 1. **开发者的瑞士军刀**
   ```bash
   # 一键配置Python环境
   sudo apt install python3-pip python3-venv
   python3 -m venv myapp && source myapp/bin/activate
   ```

#### 2. **企业级云平台**
   - **OpenStack** 部署：
     ```bash
     sudo apt install openstack # 云基础设施搭建
     ```
   - **Kubernetes** 支持：
     ```bash
     snap install microk8s --classic # 单机K8s集群
     ```

#### 3. **物联网边缘计算**
   - **Ubuntu Core**：为树莓派等设备设计的轻量级版本
     ```bash
     sudo snap install ubuntu-core-20-pi # 树莓派专用镜像
     ```

---

### **生态系统优势**
1. **云原生整合**  
   - 预配置云工具：`cloud-init`（自动初始化云实例）、`juju`（服务编排）
2. **AI开发支持**  
   - 预装CUDA/NVIDIA驱动、PyTorch/TensorFlow库
3. **企业服务**  
   - **Ubuntu Pro**订阅：提供ESM（扩展安全维护）、合规审计工具

---

### **与Windows/macOS的差异化优势**
| **功能**         | Ubuntu                                | Windows/macOS                  |
|------------------|---------------------------------------|-------------------------------|
| **系统开销**     | 最低1GB内存运行                       | 通常需4GB+内存                |
| **隐私控制**     | 无遥测数据收集（默认关闭）            | 需手动禁用诊断数据            |
| **开发环境**     | 原生支持GCC/LLVM/Docker               | 需安装WSL/Docker Desktop      |
| **成本**         | 完全免费                              | 许可证费用$139-$199           |

---

### **生命周期管理**
#### ⚠️ **终止支持（EOL）应对**
- **标准版**：发布后9个月停止更新 → 需升级到新版本
  ```bash
  sudo do-release-upgrade # 跨版本升级
  ```
- **LTS版**：5年基础支持 + **5年ESM扩展支持**（需Ubuntu Pro订阅）

> **升级路径示例**：  
> Ubuntu 20.04 LTS (2020) → 22.04 LTS (2022) → 24.04 LTS (2024)

---

### **学习资源推荐**
1. **官方文档**：[Ubuntu Server Guide](https://ubuntu.com/server/docs)  
2. **交互教程**：[Linux Journey](https://linuxjourney.com/)  
3. **命令行速查**：[Ubuntu Cheat Sheet](https://files.fosswire.com/2007/08/ubunturef.pdf)  
4. **社区支持**：[Ask Ubuntu](https://askubuntu.com/)（Stack Exchange分支）

---

### **为什么选择Ubuntu？**
- **新硬件兼容性**：首个支持Apple M系列芯片的Linux发行版（Asahi Linux基础）
- **游戏生态突破**：通过Proton兼容超12,000款Steam游戏
- **工业级应用**：特斯拉车载系统、波士顿动力机器人底层平台

> “Ubuntu重新定义了开源系统的易用性边界，它是开发者从Windows/macOS转向Linux的**最低摩擦路径**。” —— Linus Torvalds（Linux创始人）
