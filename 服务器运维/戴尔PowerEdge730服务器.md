## 自定义端口
- 2000 ssh
- 2001 bt面板
- 2002 redis
- 2020 存储库
- 2077 blog
- 2076  nav

# 基本配置
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




## X11图形页面转发
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
