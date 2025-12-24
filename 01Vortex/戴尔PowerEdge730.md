
## 常用命令行
- ssh日志
```
cat /var/log/auth.log | grep ssh
```









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