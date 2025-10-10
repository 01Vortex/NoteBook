## 出网端口2000-2099
#### 系统1
- 2000 ssh
- 2001 bt面板
- 2002 redis
- 2003 vnc
#### 系统2
- 2010 Grafana  (9000 普罗米修斯)


#### Docker
- 2030 twikoo
- 2031 cloudreve

#### Web1
- 2020 存储库
- 2021 twikoo
- 2022 监控
#### Web2
- 2077 blog
- 2076  nav

## 未出网端口2100-2199
- 2100 hexo
- 2101 Grafana(9000 普罗米修斯)
## 常用命令行
- ssh日志
```
cat /var/log/auth.log | grep ssh
```







# 戴尔服务器配置
## 风扇调速软件设置

**戴尔风扇调速软件：是一款根据温度，调节转速，让服务器  安静运行，降低噪音👉实现高负载不高温，低负载安静运行。

下载地址：[https://www.nas50.cn/?id=7](https://www.nas50.cn/?id=7)    

备用地址：[https://ljk.myds.me:6001/?id=7](https://ljk.myds.me:6001/?id=7)

视频教程：[戴尔风扇调速软件设置教程](https://www.bilibili.com/video/BV1Lh4y1B79H/?t=12.7)

---


**支持范围：**安装2颗CPU的戴尔服务器，理论上支持戴尔11代~15代的服务器。  

**已测试型号：**戴尔R410/510/630/、R710/R720/R730、R930及XD型号，其它型号请自行下载测试。


---

**一、链接设备**

服务器插入鼠标、键盘、显示器，idrac插入网线，服务器上网网口插入网线。**↓物理链接图↓**

[![screenshot-1705853901726.png](https://www.nas50.cn/zb_users/upload/2024/01/202401281706443955771227.png "screenshot-1705853901726.png")](https://www.nas50.cn/zb_users/upload/2024/01/202401281706443955771227.png)

---

**二、设置戴尔idrac**

**（已经设置可略过）**

1、iDrac设置教程：[https://blog.csdn.net/jackmaf/article/details/119373931](https://blog.csdn.net/jackmaf/article/details/119373931)

2、iDrac设置完后，根据自己设置的iDrac地址网页登录成功后，开启lan上IPMI功能即可具体如下：  

登录iDrac网页后台：iDRAC设置→网络→IPMI设置→启用LAN上的IPMI√。

权限：管理员。密钥：全是零。然后《应用》。↓

[![图片1.png](https://www.nas50.cn/zb_users/upload/2024/01/202401281706444497935788.png "图片1.png")](https://www.nas50.cn/zb_users/upload/2024/01/202401281706444497935788.png)

---

**三、下载并安装软件**  

**运行即可**

软件下载：[https://www.nas50.cn/?id=7](https://www.nas50.cn/?id=7)

软件运行环境：Windows系统，需要更新.NET3.5框架（已安装可掠过）

**[![软件界面介绍.png](https://www.nas50.cn/zb_users/upload/2024/01/202401281706447604127683.png "软件界面介绍.png")](https://www.nas50.cn/zb_users/upload/2024/01/202401281706447604127683.png)**

---

  

**四、激活软件**

**软件包内有激活码，**激活后，输入自己的iDrac地址、用户名、密码、即可试用。（完工）  

[![screenshot-1705848672088.png](https://www.nas50.cn/zb_users/upload/2024/01/202401281706444761178585.png "screenshot-1705848672088.png")](https://www.nas50.cn/zb_users/upload/2024/01/202401281706444761178585.png)

---

**小技巧：**

建议使用win虚拟机进行安装此软件，关机暂停虚拟机，开机自动启动（实现服务器关机停止，开机自动温控）

**注意事项：**

控制风扇转速，一定不能太低，根据硬件温度去调节

长期运行：建议CPU温度不高于75°。

**建议值：**

前置硬盘满盘，建议转速不低于12%

服务器后部以及内部安装硬盘，建议转速不低于15% 

内部增加扩展卡比如网卡、显卡等设备，建议转速不低于20%

**噪音分类：**

转速小于12%，**安静**=开空调的声音，适合放在卧室的场景。

转速小于25%，**比较安静**=夏季风扇的声音，适合放在办公室的场景。

转速大于30%，**不影响对话**=商场的声音，但是影响睡眠。

转速大于40%，**影响对话**。

转速大于50%，**不建议长期**呆在这种环境之中。

转速大于70%，**随时准备起飞，**这个转速给服务器一个单独空间吧。

## 链路聚合
# 操作系统配置
## 启用ssh远程连接
### 开启SSH服务

1. **安装OpenSSH服务器**（如果尚未安装的话）：
   
   打开终端，然后输入以下命令来安装OpenSSH服务器：
   ```bash
   sudo apt update
   sudo apt install openssh-server
   ```

2. **启动SSH服务**：
   
   安装完成后，可以通过以下命令启动SSH服务：
   ```bash
   sudo systemctl start ssh
   ```

3. **启用SSH服务在系统启动时自动运行**：
   
   使用下面的命令让SSH服务随系统启动而自动运行：
   ```bash
   sudo systemctl enable ssh
   ```

### 配置使用Ed25519加密

Ed25519是一种高效的椭圆曲线签名算法。要确保你的SSH配置支持Ed25519密钥对，可以进行如下配置：

1. **生成Ed25519密钥对**（如果你还没有Ed25519密钥对的话）：
   
   在客户端机器上，你可以通过以下命令生成Ed25519类型的SSH密钥对：
   ```bash
   ssh-keygen -t ed25519
   ```
   按照提示操作完成密钥对的生成。

2. **将公钥添加到Ubuntu 22.04服务器上的`~/.ssh/authorized_keys`文件中**：
    ==注:==没有authorized_keys文件请先创建
   
   你需要将之前生成的`.pub`公钥文件内容复制到服务器的`~/.ssh/authorized_keys`文件中。可以通过以下命令实现（假设你已经在客户端机器上，并且目标用户是远程服务器上的同一用户）：
   ```bash
   ssh-copy-id -i ~/.ssh/id_ed25519.pub 用户名@服务器IP地址
   ```

3. **检查SSH配置文件是否允许Ed25519**：
   
   确保你的`/etc/ssh/sshd_config`文件中的配置允许Ed25519类型密钥登录。打开配置文件：
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
   查找或添加如下行：
   ```
   PubkeyAuthentication yes
   HostKeyAlgorithms ssh-ed25519
   ```
   如果做了任何修改，记得保存更改后重启SSH服务以使更改生效：
   ```bash
   sudo systemctl restart ssh
   ```

### 安全配置
加强SSH的安全性是保护服务器免受未授权访问的重要步骤。下面是一些推荐的做法来增强SSH的安全配置：

1. **禁用密码登录**：
   使用密钥对认证代替密码认证可以显著提高安全性，因为私钥泄露的难度远高于密码猜测或暴力破解。
   - 编辑`/etc/ssh/sshd_config`文件，找到并修改以下行：
     ```
     PasswordAuthentication no
     ```
   - 确保你已经设置好公钥认证（如使用Ed25519密钥对），否则你可能会被锁定在系统之外。

2. **更改默认端口**：
   将SSH服务从默认的22端口更改为其他端口可以减少自动化的攻击尝试。
   - 在`/etc/ssh/sshd_config`中添加或修改如下行：
     ```
     Port 新端口号
     ```

3. **限制用户访问**：
   通过指定允许连接的用户来进一步限制访问。
   - 同样在`/etc/ssh/sshd_config`中添加或修改：
     ```
     AllowUsers 用户名1 用户名2
     ```
   或者如果你希望根据组来控制访问权限：
     ```
     AllowGroups 组名
     ```

4. **禁用根用户的直接登录**：
   禁止root用户直接登录，并使用普通账户登录后切换到root用户，可以增加额外的安全层。
   - 修改`/etc/ssh/sshd_config`中的：
     ```
     PermitRootLogin no
     ```


5. **启用防火墙规则**：
   配置防火墙仅允许特定IP地址访问SSH服务，或者至少限制尝试连接的频率。
   
6. **定期更新和审计**：
   定期检查SSH配置，安装安全补丁，以及监控登录尝试的日志文件（如`/var/log/auth.log`）以发现任何可疑活动。

完成以上配置后，记得重启SSH服务使更改生效：
```bash
sudo systemctl restart ssh
```

### 可选:使用X11图形页面转发


##  VNC over SSH隧道
###  安装并配置 VNC 服务
- 安装 TigerVNC Server（轻量高效）
```
sudo apt update 
sudo apt install tigervnc-standalone-server tigervnc-common
```

- 设置VNC密码
```
vncpasswd # 输入并确认密码（用于 VNC 客户端连接） # 可选是否设置只读密码
```

- 创建 VNC 启动配置
```
vim ~/.vnc/xstartup
```

内容如下(适用于xfce4,如没有请先安装)
> GNOME 在 VNC 下容易因 Wayland、会话管理、依赖缺失等问题失败，XFCE 是远程桌面的黄金标准。
> **XFCE 只是“安装在系统里”，默认不会启动或替换主桌面 GNOME。只有当你通过 VNC 启动桌面时，才由 `~/.vnc/xstartup` 决定用哪个桌面环境。**

``` shell
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
```
>`startxfce4` 是 XFCE 的标准启动命令，兼容性极佳。


- 赋予执行权限
```
chmod +x ~/.vnc/xstartup
```

- 启动 VNC 服务（分辨率,端口可自定义）
```
vncserver -rfbport 2003 -geometry 1366x768 -depth 16
```
>默认监听端口是 5901（对应 :1），如需多个会话可用 :2 → 5902 等。


### VNC常用命令

- 启动VNC服务器
```
vncserver -rfbport 2003 -geometry 1366x768 -depth 16
```

- 实例列表
```
vncserver -list
```

- 终止实例
```
vncserver -kill :1
```

-  命令大全
```text
    [:<数字>]              指定要使用的X11显示器编号。
    [-display <值>]       是 :<数字> 的别名。
    [-fg]                  如果启用，vncserver将保持在前台运行。
    [-useold]              如果指定，仅当没有VNC服务器已在运行时才启动一个新的。
    [-verbose]             如果指定，则启用调试输出。
    [-dry-run]             如果启用，则不执行实际操作，仅模拟将要执行的操作。
    [-PAMService <值>]    指定用于安全类型Plain、TLSPlain或X509Plain的PAM密码验证的服务名称。默认情况下，如果存在则使用vnc，否则使用tigervnc。
    [-pam_service <值>]   是PAMService的别名。
    [-PlainUsers <值>]    指定安全类型Plain、TLSPlain和X509Plain的授权用户列表。
    [-localhost [是|否]]   如果启用，VNC将仅接受来自本地主机的连接。
    [-desktop <值>]       指定VNC桌面名称。
    [-rfbport <数字>]     提供用于RFB协议的TCP端口。
    [-X509Key <值>]       表示X509证书密钥文件（PEM格式）。用于安全类型X509None、X509Vnc和X509Plain。
    [-X509Cert <值>]      表示对应的X509证书（PEM格式）。
    [-PasswordFile <值>]  指定安全类型VncAuth、TLSVnc和X509Vnc的密码文件。默认使用 ~/.vnc/passwd。
    [-rfbauth <值>]       是PasswordFile的别名。
    [-SecurityTypes <值>] 指定要提供的安全类型的逗号分隔列表（None, VncAuth, Plain, TLSNone, TLSVnc, TLSPlain, X509None, X509Vnc, X509Plain）。默认仅提供VncAuth。
    [-geometry <值>]      指定桌面几何尺寸，例如 <宽度>x<高度>。
    [-wmDecoration <值>]  如果指定，将几何尺寸按给定的<宽度>x<高度>值缩小。
    [-xdisplaydefaults]   如果给定，从localhost:10.0 X服务器获取几何尺寸和像素格式。
    [-xstartup [<值>]]    指定用于启动Xtigervnc的X11会话的脚本。
    [-noxstartup]         禁用X会话启动。
    [-depth <数字>]       指定桌面的位深度，例如16、24或32。
    [-pixelformat <值>]   定义X11服务器像素格式。有效值为rgb888、rgb565、bgr888或bgr565。
    [-autokill [是|否]]   如果启用（默认）——在其X会话终止后，VNC服务器将被杀死。
    [-fp <值>]            指定以冒号分隔的字体位置列表。
    [Xtigervnc 选项...]   有关详细信息，请参阅Xtigervnc(1)手册页。
    [-- <会话>]           指定要启动的X11会话，可以是命令或会话名称。

 要列出用户的所有活动VNC服务器，使用 vncserver
     -list                 如果提供，将列出用户的所有活动VNC服务器。
    [:<数字>]              指定X11显示器编号。
    [-display <值>]       是 :<数字> 的别名。
    [-rfbport <数字>]     提供用于RFB协议的TCP端口。
    [-cleanstale]          如果提供，清理用户陈旧的VNC服务器实例的pid和锁文件。

 要杀死VNC服务器，使用 vncserver
     -kill                 如果提供，杀死用户指定的VNC服务器。
    [:<数字>]              指定X11显示器编号。
    [-display <值>]       是 :<数字> 的别名。
    [-rfbport <数字>]     提供用于RFB协议的TCP端口。
    [-dry-run]             如果启用，则不执行实际操作，仅模拟将要执行的操作。
    [-verbose]             如果指定，则启用调试输出。
    [-clean]               如果指定，还将删除已终止VNC会话的日志文件。

 要转储版本信息，使用 vncserver
    [-version]             转储底层Xtigervnc VNC服务器的版本信息。

```


### MobaXterm 中建立 SSH 隧道
- #### 添加本地端口转发
```
Local port: 5901 
Remote server: localhost 
Remote port: 5901
```
>这样就把服务器的 5901 端口通过 SSH 隧道映射到本地的 5901。

- #### 使用 MobaXterm 内置 VNC 客户端连接
1. SSH 连接成功后，在 MobaXterm 左侧边栏找到 “VNC” 图标（或顶部菜单 Tools → VNC Viewer）
2. 在 VNC 连接地址输入：
```
localhost:5901
```
3. 点击连接，输入之前设置的 VNC 密码

- #### 优化建议（提升流畅度）
1. **降低色彩深度**（启动 VNC 时）：
```   
vncserver :1 -geometry 1920x1080 -depth 16
```
>`-depth 16` 比 24 更节省带宽，肉眼差异不大。

2.  **关闭桌面特效**   

- #### 设置 VNC 服务开机自启（可选）
创建 systemd 服务文件：
```
sudo vim /etc/systemd/system/vncserver@.service
```

内容：
```shell
[Unit] 
Description=Remote desktop service (VNC) 
After=syslog.target network.target 

[Service] 
Type=simple User=你的用户名 WorkingDirectory=/home/你的用户名 ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill %i > /dev/null 2>&1 || :' ExecStart=/usr/bin/vncserver %i -geometry 1920x1080 -depth 16 ExecStop=/usr/bin/vncserver -kill %i

[Install] 
WantedBy=multi-user.target
```

启用服务：
```shell
sudo systemctl daemon-reload 
sudo systemctl enable vncserver@:1.service 
sudo systemctl start vncserver@:1
```



### VNC 卡顿主要原因

|原因|说明|
|---|---|
|1. 色彩深度太高|`-depth 24` → 改为 `-depth 16` 可大幅减少数据量|
|2. 分辨率太高|`1920x1080` 对带宽要求高 → 可适当降低|
|3. 未启用压缩|TigerVNC 支持图像压缩，需手动开启|
|4. 桌面特效未关闭|XFCE/GNOME 的动画、阴影、透明效果加重负担|
|5. 网络延迟/带宽不足|尤其跨公网、WiFi、公司网络等|
|6. 服务器性能不足|CPU/内存占用高，渲染慢|

## 将ddns-go设置为开机自启

**将 `ddns-go` 设置为系统开机自启动服务，确保它在网络就绪后自动运行，并使用指定的配置文件。**

### 1. 创建 systemd 服务文件

使用管理员权限创建一个服务文件：

```bash
sudo nano /etc/systemd/system/ddns-go.service
```

### 2. 编辑服务文件内容（示例）

```ini
[Unit]
Description=DDNS-GO Service
After=network.target

[Service]
User=vortex
ExecStart=/home/vortex/Downloads/ddns-go_6.8.1_linux_x86_64/ddns-go -c /home/vortex/.ddns_go_config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target

```

> ⚠️ 请根据你的实际路径和配置文件路径进行修改。

---

### 3. 重载 systemd 配置

```bash
sudo systemctl daemon-reload
```

### 4. 设置开机自启并启动服务

```bash
sudo systemctl enable ddns-go --now
sudo systemctl start ddns-go
```

### 5. 检查服务状态

```bash
sudo systemctl status ddns-go
```

### 6. 查看日志（可选）

```bash
journalctl -u ddns-go.service -f
```

---

### 注意事项：

- 确保 `ddns-go` 可执行文件有执行权限：
  ```bash
  chmod +x /path/to/ddns-go
  ```

- 如果配置文件在用户目录下（如 `.ddns_go_config.yaml`），请在服务中指定 `User=你的用户名`，否则服务可能无法访问该文件。

- 使用 `-c` 参数指定配置文件路径，确保 `ddns-go` 使用你定义的配置运行。

---

### ✅成功后效果：

- 每次系统重启后，`ddns-go` 会自动运行。
- 使用指定配置文件进行 DDNS 更新。
- 在后台作为服务运行，失败时自动重启。


# 数据库配置
## MySQL排序规则的选择
在MySQL中，选择合适的排序规则（Collation）对于确保数据的正确排序、比较和索引至关重要。以下是选择MySQL数据库排序规则时需要考虑的关键因素和具体建议：

### 1. **理解MySQL的排序规则命名规范**
MySQL的排序规则名称通常遵循以下模式：
```
字符集_语言_语种_CI/CS_AI/AS
```
- **字符集（Character Set）**：如`utf8`, `utf8mb4`, `latin1`等。
- **语言（Language）**：如`en`（英语）、`zh`（中文）等。
- **语种（Country/Region）**：如`US`（美国）、`CN`（中国）等。
- **CI/CS（Case Insensitive/Case Sensitive）**：
  - `CI`：不区分大小写。
  - `CS`：区分大小写。
- **AI/AS（Accent Insensitive/Accent Sensitive）**：
  - `AI`：不区分重音。
  - `AS`：区分重音。

### 2. **选择合适的字符集**
- **UTF-8（`utf8mb4`）**：推荐使用`utf8mb4`，因为它支持完整的Unicode字符集，包括表情符号和其他特殊字符。
  ```sql
  CHARACTER SET utf8mb4
  ```
- **其他字符集**：如果你的应用主要使用特定语言的字符，可以选择相应的字符集，如`latin1`（西欧语言）、`gbk`（简体中文）等。

### 3. **选择区分大小写和重音的排序规则**
- **不区分大小写，不区分重音**：
  - `utf8mb4_general_ci`：适用于大多数场景，性能较好，但不严格按照语言规则排序。
  - `utf8mb4_unicode_ci`：更符合Unicode标准，排序更准确，但性能略低于`general_ci`。
  ```sql
  COLLATE utf8mb4_unicode_ci
  ```
- **区分大小写，不区分重音**：
  - `utf8mb4_general_cs` 或 `utf8mb4_unicode_cs`。
- **不区分大小写，区分重音**：
  - MySQL默认不提供这种排序规则，可能需要自定义或使用其他变体。
- **区分大小写，区分重音**：
  - `utf8mb4_bin`：二进制排序，区分大小写和重音。
  ```sql
  COLLATE utf8mb4_bin
  ```

### 4. **具体应用场景的建议**
- **Web应用（多语言支持）**：
  - 如果你的应用需要支持多种语言，建议使用`utf8mb4_unicode_ci`，因为它对各种语言的支持更好。
  ```sql
  CREATE DATABASE my_database CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```
- **中文应用**：
  - 对于简体中文，可以使用`utf8mb4_unicode_ci`或`utf8mb4_zh_0900_as_cs`（如果需要更精确的中文排序）。
  ```sql
  CREATE DATABASE my_chinese_db CHARACTER SET utf8mb4 COLLATE utf8mb4_zh_0900_as_cs;
  ```
- **高性能需求**：
  - 如果对性能有较高要求，并且可以接受不区分大小写和重音，可以使用`utf8mb4_general_ci`。
  ```sql
  CREATE DATABASE high_perf_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
  ```
- **二进制排序**：
  - 如果需要严格的二进制比较，可以使用`utf8mb4_bin`。
  ```sql
  CREATE DATABASE binary_db CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
  ```

### 5. **查看可用的排序规则**
你可以通过以下命令查看MySQL中可用的排序规则：
```sql
SHOW COLLATION WHERE Charset = 'utf8mb4';
```

### 6. **示例**
假设你正在创建一个支持多语言的Web应用，并且需要不区分大小写和不区分重音的排序规则，可以这样创建数据库：
```sql
CREATE DATABASE multilingual_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 7. **总结**
选择MySQL的排序规则时，主要考虑以下几点：
- **字符集**：推荐使用`utf8mb4`以支持完整的Unicode。
- **大小写和重音的区分**：根据应用需求选择`CI`或`CS`，`AI`或`AS`。
- **语言支持**：选择适合应用语言的排序规则，如`utf8mb4_unicode_ci`适用于多语言环境，`utf8mb4_zh_0900_as_cs`适用于中文环境。
- **性能**：一般来说，`general_ci`比`unicode_ci`性能更好，但排序准确性稍低。

通过综合考虑这些因素，可以选择最适合你应用的MySQL排序规则。



# 常见问题
### 无法连接到本地服务器

- 在MySQL配置文件的[mysqlid]添加，然后重启
```
bind-address = 127.0.0.1
```


# Hexo
## 将Twikoo部署到Docker并修改默认端口
### 命令如下：

```bash
docker run --name twikoo -e TWIKOO_THROTTLE=1000 -p 127.0.0.1:2030:8080 -v ${PWD}/data:/app/data -d imaegoo/twikoo
```

#### 解释：

- `-p 127.0.0.1:2030:8080`：将容器内部的 `8080` 端口映射到宿主机的 `127.0.0.1:2030`。
- 其他参数保持不变：
  - `--name twikoo`：指定容器名称为 `twikoo`。
  - `-e TWIKOO_THROTTLE=1000`：设置环境变量，限制请求频率为每秒 1000 次。
  - `-v ${PWD}/data:/app/data`：将当前目录下的 `data` 文件夹挂载到容器的 `/app/data`，用于持久化数据。
  - `-d imaegoo/twikoo`：后台运行 Twikoo 镜像。

### 验证是否运行成功：

你可以使用以下命令查看容器是否正常运行：

```bash
docker ps -f "name=twikoo"
```

访问 `http://127.0.0.1:2030` 应该就能看到 Twikoo 的响应（通常是健康检查返回的 `{"status":"healthy"}`）。

如需查看日志：

```bash
docker logs twikoo
```




## 安装mongodb-compass

### 步骤 1：下载 MongoDB Compass

首先，你需要从 MongoDB 官方网站下载所需版本的 `.deb` 包。由于直接提供链接可能会导致链接过期或版本不匹配的问题，建议手动访问 [MongoDB Compass 下载页面](https://www.mongodb.com/try/download/compass) 来找到并下载适合你需求的版本。

但是，如果你已经有了下载链接或者知道如何找到它，可以直接使用 `wget` 命令下载。例如，假设你知道了 `mongodb-compass_1.46.6_amd64.deb` 的确切下载链接：

```bash
wget https://downloads.mongodb.com/compass/mongodb-compass_1.46.6_amd64.deb
```

请确保替换上述命令中的 URL 为实际可用的下载链接。

### 步骤 2：安装 MongoDB Compass

一旦你下载了 `.deb` 文件，接下来就可以安装这个包了。打开终端，并导航到包含 `.deb` 文件的目录（如果不在当前目录）。然后执行以下命令来安装：

```bash
sudo dpkg -i mongodb-compass_1.46.6_amd64.deb
```

如果在安装过程中遇到依赖性问题，可以运行以下命令来修复这些问题：

```bash
sudo apt-get install -f
```

这将自动安装任何缺失的依赖项，并完成 MongoDB Compass 的安装过程。

### 步骤 3：启动 MongoDB Compass

安装完成后，你可以通过桌面环境的应用菜单搜索 "MongoDB Compass" 并启动它。或者，在终端中输入以下命令来直接启动 MongoDB Compass：

```bash
mongodb-compass
```

### 注意事项

- **系统架构**：确认你的系统架构是 `amd64`，因为下载的包是针对此架构的。如果不是，请选择适合自己系统架构的版本。
- **更新检查**：虽然你选择了特定版本进行安装，但记得定期检查是否有更适合的新版本发布，以利用最新的功能和安全更新。
- **权限问题**：如果遇到权限问题，确保你在执行命令时使用了 `sudo`，特别是在安装软件包时。


## 跨域
### 案例1
访问目标网站200 ok 但是不能读取其中的资源,在ngnix配置文件解决
### 案例2
2个源网站访问访问目标网站,一个能200 ok且能访问资源,另一个 报错 且不能访问资源,要解决该跨域问题要去项目对应文件添加白名单,在ngnix上是解决不了的