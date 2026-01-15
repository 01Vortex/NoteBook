

> Apache Tomcat 是一个开源的 Java Servlet 容器，用于运行 Java Web 应用程序
> 本笔记涵盖 Tomcat 9.x / 10.x 版本，从入门到生产级部署

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [目录结构详解](#3-目录结构详解)
4. [核心配置文件](#4-核心配置文件)
5. [部署应用](#5-部署应用)
6. [连接器配置](#6-连接器配置)
7. [虚拟主机配置](#7-虚拟主机配置)
8. [安全配置](#8-安全配置)
9. [性能优化](#9-性能优化)
10. [日志管理](#10-日志管理)
11. [集群与负载均衡](#11-集群与负载均衡)
12. [SSL/HTTPS 配置](#12-sslhttps-配置)
13. [与 Nginx 整合](#13-与-nginx-整合)
14. [监控与管理](#14-监控与管理)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Tomcat？

Tomcat 是 Apache 软件基金会开发的一个开源 Web 服务器和 Servlet 容器。简单来说，它就是一个能够运行 Java Web 应用的"容器"。

**核心功能：**
- **Servlet 容器**：处理 Java Servlet 请求
- **JSP 引擎**：编译和执行 JSP 页面
- **Web 服务器**：处理静态资源（HTML、CSS、JS、图片等）

**为什么选择 Tomcat？**
- 轻量级，启动快速
- 配置简单，易于上手
- 社区活跃，文档丰富
- 与 Spring Boot 等框架无缝集成


### 1.2 Tomcat 版本选择

| Tomcat 版本 | Servlet 规范 | JSP 规范 | Java 版本要求 | 说明 |
|------------|-------------|---------|--------------|------|
| Tomcat 8.5 | 3.1 | 2.3 | Java 7+ | 长期支持版本，逐渐淘汰 |
| Tomcat 9.x | 4.0 | 2.3 | Java 8+ | **生产环境推荐** |
| Tomcat 10.x | 5.0 | 3.0 | Java 11+ | Jakarta EE 9+，包名变更 |
| Tomcat 11.x | 6.0 | 3.1 | Java 17+ | 最新版本 |

> ⚠️ **注意**：Tomcat 10+ 使用 `jakarta.*` 包名替代了 `javax.*`，迁移时需要修改代码！

### 1.3 Tomcat 架构

```
┌─────────────────────────────────────────────────────────────┐
│                         Server                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                      Service                           │  │
│  │  ┌─────────────┐  ┌─────────────────────────────────┐ │  │
│  │  │  Connector  │  │            Engine               │ │  │
│  │  │  (HTTP)     │──│  ┌─────────────────────────┐   │ │  │
│  │  └─────────────┘  │  │         Host            │   │ │  │
│  │  ┌─────────────┐  │  │  ┌───────────────────┐  │   │ │  │
│  │  │  Connector  │  │  │  │     Context       │  │   │ │  │
│  │  │  (AJP)      │──│  │  │   (Web App)       │  │   │ │  │
│  │  └─────────────┘  │  │  └───────────────────┘  │   │ │  │
│  │                   │  └─────────────────────────┘   │ │  │
│  │                   └─────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**组件说明：**
- **Server**：整个 Tomcat 实例，一个 JVM 只能有一个 Server
- **Service**：将 Connector 和 Engine 组合在一起
- **Connector**：接收客户端请求（HTTP/AJP 协议）
- **Engine**：处理请求的核心引擎
- **Host**：虚拟主机，可配置多个域名
- **Context**：一个 Web 应用程序

---

## 2. 安装与配置

### 2.1 环境准备

首先确保已安装 JDK：

```bash
# 检查 Java 版本
java -version

# 检查 JAVA_HOME 环境变量
echo $JAVA_HOME
```


### 2.2 Linux 安装（推荐）

```bash
# 1. 下载 Tomcat（以 9.0.x 为例）
cd /opt
wget https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.85/bin/apache-tomcat-9.0.85.tar.gz

# 2. 解压
tar -zxvf apache-tomcat-9.0.85.tar.gz

# 3. 重命名（可选，方便管理）
mv apache-tomcat-9.0.85 tomcat9

# 4. 创建专用用户（安全最佳实践）
useradd -r -s /sbin/nologin tomcat
chown -R tomcat:tomcat /opt/tomcat9

# 5. 配置环境变量
cat >> /etc/profile.d/tomcat.sh << 'EOF'
export CATALINA_HOME=/opt/tomcat9
export PATH=$CATALINA_HOME/bin:$PATH
EOF

source /etc/profile.d/tomcat.sh

# 6. 启动 Tomcat
$CATALINA_HOME/bin/startup.sh

# 7. 验证启动
curl http://localhost:8080
```

### 2.3 Windows 安装

```powershell
# 1. 下载 Windows 版本（.zip 格式）
# 从 https://tomcat.apache.org/download-90.cgi 下载

# 2. 解压到指定目录，如 C:\tomcat9

# 3. 配置环境变量
# CATALINA_HOME = C:\tomcat9
# 将 %CATALINA_HOME%\bin 添加到 PATH

# 4. 启动
startup.bat

# 5. 停止
shutdown.bat
```

### 2.4 配置为 Systemd 服务（Linux 生产环境必备）

创建服务文件 `/etc/systemd/system/tomcat.service`：

```ini
[Unit]
Description=Apache Tomcat Web Application Container
After=network.target

[Service]
Type=forking

User=tomcat
Group=tomcat

Environment="JAVA_HOME=/usr/lib/jvm/java-11-openjdk"
Environment="CATALINA_HOME=/opt/tomcat9"
Environment="CATALINA_BASE=/opt/tomcat9"
Environment="CATALINA_PID=/opt/tomcat9/temp/tomcat.pid"
Environment="CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC"

ExecStart=/opt/tomcat9/bin/startup.sh
ExecStop=/opt/tomcat9/bin/shutdown.sh

RestartSec=10
Restart=always

[Install]
WantedBy=multi-user.target
```


```bash
# 启用并启动服务
systemctl daemon-reload
systemctl enable tomcat
systemctl start tomcat

# 常用命令
systemctl status tomcat    # 查看状态
systemctl restart tomcat   # 重启
systemctl stop tomcat      # 停止
journalctl -u tomcat -f    # 查看日志
```

---

## 3. 目录结构详解

```
tomcat/
├── bin/                    # 启动/停止脚本
│   ├── startup.sh          # 启动脚本（Linux）
│   ├── shutdown.sh         # 停止脚本（Linux）
│   ├── catalina.sh         # 核心脚本，包含所有启动参数
│   ├── setenv.sh           # 自定义环境变量（需手动创建）
│   └── *.bat               # Windows 对应脚本
│
├── conf/                   # 配置文件目录（重点！）
│   ├── server.xml          # 主配置文件，定义服务器结构
│   ├── web.xml             # 全局 Web 应用配置
│   ├── context.xml         # 全局 Context 配置
│   ├── tomcat-users.xml    # 用户认证配置
│   ├── logging.properties  # 日志配置
│   └── catalina.policy     # 安全策略文件
│
├── lib/                    # Tomcat 运行所需的 JAR 包
│
├── logs/                   # 日志文件目录
│   ├── catalina.out        # 主日志（stdout/stderr）
│   ├── catalina.YYYY-MM-DD.log  # 按日期分割的日志
│   ├── localhost.YYYY-MM-DD.log # 应用日志
│   └── localhost_access_log.YYYY-MM-DD.txt  # 访问日志
│
├── temp/                   # 临时文件目录
│
├── webapps/                # Web 应用部署目录（重点！）
│   ├── ROOT/               # 默认应用（访问 / 路径）
│   ├── manager/            # 管理应用
│   ├── host-manager/       # 虚拟主机管理
│   └── your-app/           # 你的应用
│
└── work/                   # JSP 编译后的 Servlet 类文件
```

> 💡 **小技巧**：`webapps/ROOT` 是默认应用，访问 `http://localhost:8080/` 就是访问它。如果想让自己的应用成为默认应用，可以删除 ROOT 目录，把自己的应用重命名为 ROOT。

---

## 4. 核心配置文件

### 4.1 server.xml 详解

这是 Tomcat 最重要的配置文件，定义了整个服务器的结构：


```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- Server：整个 Tomcat 实例，port 是关闭端口，shutdown 是关闭命令 -->
<Server port="8005" shutdown="SHUTDOWN">
  
  <!-- 监听器：在特定事件发生时执行操作 -->
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" />
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />

  <!-- 全局资源配置（如 JNDI 数据源） -->
  <GlobalNamingResources>
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>

  <!-- Service：将 Connector 和 Engine 绑定在一起 -->
  <Service name="Catalina">
    
    <!-- HTTP 连接器：处理 HTTP 请求 -->
    <Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443"
               maxThreads="200"
               minSpareThreads="10"
               acceptCount="100"
               URIEncoding="UTF-8" />
    
    <!-- AJP 连接器：与 Apache/Nginx 通信（生产环境常用） -->
    <!-- <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" /> -->
    
    <!-- Engine：请求处理引擎 -->
    <Engine name="Catalina" defaultHost="localhost">
      
      <!-- Realm：用户认证 -->
      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>

      <!-- Host：虚拟主机 -->
      <Host name="localhost" appBase="webapps"
            unpackWARs="true" autoDeploy="true">
        
        <!-- 访问日志 -->
        <Valve className="org.apache.catalina.valves.AccessLogValve" 
               directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />
               
        <!-- Context：单个应用配置（也可以在 context.xml 中配置） -->
        <!-- <Context path="/myapp" docBase="/path/to/myapp" reloadable="true"/> -->
      </Host>
    </Engine>
  </Service>
</Server>
```


### 4.2 web.xml 全局配置

`conf/web.xml` 是所有 Web 应用的默认配置，应用自己的 `WEB-INF/web.xml` 会覆盖这里的配置：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         version="4.0">
  
  <!-- 默认 Servlet：处理静态资源 -->
  <servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    <init-param>
      <param-name>listings</param-name>
      <param-value>false</param-value>  <!-- 禁止目录列表，安全！ -->
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>
  
  <!-- JSP Servlet：处理 JSP 页面 -->
  <servlet>
    <servlet-name>jsp</servlet-name>
    <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>
    <load-on-startup>3</load-on-startup>
  </servlet>
  
  <!-- Session 超时时间（分钟） -->
  <session-config>
    <session-timeout>30</session-timeout>
  </session-config>
  
  <!-- 欢迎页面列表 -->
  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
</web-app>
```

### 4.3 context.xml 应用上下文配置

`conf/context.xml` 是全局 Context 配置，也可以在每个应用的 `META-INF/context.xml` 中单独配置：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Context>
  <!-- 禁用 Session 持久化（开发环境推荐） -->
  <Manager pathname="" />
  
  <!-- 数据源配置示例 -->
  <Resource name="jdbc/mydb"
            auth="Container"
            type="javax.sql.DataSource"
            maxTotal="100"
            maxIdle="30"
            maxWaitMillis="10000"
            username="dbuser"
            password="dbpassword"
            driverClassName="com.mysql.cj.jdbc.Driver"
            url="jdbc:mysql://localhost:3306/mydb?useSSL=false&amp;serverTimezone=UTC"/>
</Context>
```

### 4.4 tomcat-users.xml 用户配置

配置管理界面的访问用户：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users>
  <!-- 角色定义 -->
  <role rolename="manager-gui"/>      <!-- 管理界面访问 -->
  <role rolename="manager-script"/>   <!-- 脚本部署访问 -->
  <role rolename="admin-gui"/>        <!-- 主机管理界面 -->
  
  <!-- 用户定义 -->
  <user username="admin" password="your_secure_password" 
        roles="manager-gui,manager-script,admin-gui"/>
</tomcat-users>
```

> ⚠️ **安全警告**：生产环境中务必使用强密码，并限制管理界面的访问 IP！


### 4.5 setenv.sh 自定义环境变量

在 `bin/` 目录下创建 `setenv.sh`（Linux）或 `setenv.bat`（Windows），用于配置 JVM 参数：

```bash
#!/bin/bash
# bin/setenv.sh - Tomcat 环境变量配置

# JVM 内存配置
CATALINA_OPTS="-Xms512m -Xmx2048m"

# GC 配置（Java 11+）
CATALINA_OPTS="$CATALINA_OPTS -XX:+UseG1GC"
CATALINA_OPTS="$CATALINA_OPTS -XX:MaxGCPauseMillis=200"

# 元空间配置
CATALINA_OPTS="$CATALINA_OPTS -XX:MetaspaceSize=256m"
CATALINA_OPTS="$CATALINA_OPTS -XX:MaxMetaspaceSize=512m"

# 编码设置
CATALINA_OPTS="$CATALINA_OPTS -Dfile.encoding=UTF-8"

# 时区设置
CATALINA_OPTS="$CATALINA_OPTS -Duser.timezone=Asia/Shanghai"

# JMX 远程监控（可选）
# CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote"
# CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.port=9090"
# CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.ssl=false"
# CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.authenticate=false"

# 堆内存溢出时自动 dump
CATALINA_OPTS="$CATALINA_OPTS -XX:+HeapDumpOnOutOfMemoryError"
CATALINA_OPTS="$CATALINA_OPTS -XX:HeapDumpPath=/opt/tomcat9/logs/heapdump.hprof"

export CATALINA_OPTS
```

---

## 5. 部署应用

### 5.1 部署方式对比

| 方式 | 说明 | 适用场景 |
|-----|------|---------|
| 直接复制 WAR | 将 WAR 文件放入 webapps 目录 | 最简单，适合开发测试 |
| 解压目录部署 | 将解压后的目录放入 webapps | 方便修改配置 |
| Context 配置 | 在 server.xml 或独立 XML 中配置 | 灵活，可指定任意路径 |
| Manager 界面 | 通过 Web 界面上传部署 | 可视化操作 |
| Maven 插件 | 使用 tomcat-maven-plugin | CI/CD 集成 |

### 5.2 WAR 包部署

```bash
# 方式一：直接复制 WAR 文件
cp myapp.war /opt/tomcat9/webapps/

# Tomcat 会自动解压并部署
# 访问地址：http://localhost:8080/myapp

# 方式二：部署为 ROOT 应用（默认应用）
rm -rf /opt/tomcat9/webapps/ROOT
cp myapp.war /opt/tomcat9/webapps/ROOT.war
# 访问地址：http://localhost:8080/
```


### 5.3 Context 配置部署

在 `conf/Catalina/localhost/` 目录下创建 XML 文件：

```xml
<!-- conf/Catalina/localhost/myapp.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<Context docBase="/data/apps/myapp" reloadable="false">
  <!-- 应用特定的数据源 -->
  <Resource name="jdbc/mydb"
            auth="Container"
            type="javax.sql.DataSource"
            maxTotal="50"
            maxIdle="10"
            username="root"
            password="password"
            driverClassName="com.mysql.cj.jdbc.Driver"
            url="jdbc:mysql://localhost:3306/mydb"/>
</Context>
```

> 💡 **说明**：文件名决定了访问路径，`myapp.xml` 对应 `/myapp`，`ROOT.xml` 对应 `/`

### 5.4 Maven 插件部署

在 `pom.xml` 中配置：

```xml
<build>
  <plugins>
    <plugin>
      <groupId>org.apache.tomcat.maven</groupId>
      <artifactId>tomcat7-maven-plugin</artifactId>
      <version>2.2</version>
      <configuration>
        <url>http://localhost:8080/manager/text</url>
        <server>tomcat-server</server>
        <path>/myapp</path>
        <username>admin</username>
        <password>admin123</password>
      </configuration>
    </plugin>
  </plugins>
</build>
```

```bash
# 部署命令
mvn tomcat7:deploy      # 首次部署
mvn tomcat7:redeploy    # 重新部署
mvn tomcat7:undeploy    # 卸载应用
```

### 5.5 热部署配置

```xml
<!-- 在 Context 中启用热部署（仅开发环境！） -->
<Context reloadable="true">
  <!-- 监控额外的资源变化 -->
  <WatchedResource>WEB-INF/web.xml</WatchedResource>
  <WatchedResource>WEB-INF/classes</WatchedResource>
  <WatchedResource>${catalina.base}/conf/web.xml</WatchedResource>
</Context>
```

> ⚠️ **警告**：生产环境务必设置 `reloadable="false"`，否则会严重影响性能！

---

## 6. 连接器配置

### 6.1 HTTP 连接器优化

```xml
<Connector port="8080" 
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           connectionTimeout="20000"
           redirectPort="8443"
           
           <!-- 线程池配置 -->
           maxThreads="500"           <!-- 最大工作线程数 -->
           minSpareThreads="50"       <!-- 最小空闲线程数 -->
           acceptCount="200"          <!-- 等待队列长度 -->
           
           <!-- 连接配置 -->
           maxConnections="10000"     <!-- 最大连接数 -->
           keepAliveTimeout="15000"   <!-- Keep-Alive 超时 -->
           maxKeepAliveRequests="100" <!-- 单连接最大请求数 -->
           
           <!-- 编码配置 -->
           URIEncoding="UTF-8"
           useBodyEncodingForURI="true"
           
           <!-- 压缩配置 -->
           compression="on"
           compressionMinSize="2048"
           compressibleMimeType="text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json"
           
           <!-- 安全配置 -->
           server="Apache"            <!-- 隐藏 Tomcat 版本信息 -->
           xpoweredBy="false" />
```


### 6.2 使用线程池（推荐）

```xml
<!-- 定义共享线程池 -->
<Executor name="tomcatThreadPool" 
          namePrefix="catalina-exec-"
          maxThreads="500" 
          minSpareThreads="50"
          maxIdleTime="60000"
          prestartminSpareThreads="true"/>

<!-- 连接器使用线程池 -->
<Connector executor="tomcatThreadPool"
           port="8080" 
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           connectionTimeout="20000"
           redirectPort="8443" />
```

### 6.3 协议选择

| 协议 | 说明 | 适用场景 |
|-----|------|---------|
| HTTP/1.1 (BIO) | 阻塞 IO，每请求一线程 | 已废弃 |
| Http11NioProtocol | 非阻塞 IO | **推荐，默认选择** |
| Http11Nio2Protocol | NIO2 异步 IO | 高并发场景 |
| Http11AprProtocol | APR 本地库 | 极致性能（需安装 APR） |

### 6.4 AJP 连接器（与 Apache/Nginx 配合）

```xml
<!-- AJP 连接器配置 -->
<Connector protocol="AJP/1.3"
           port="8009"
           redirectPort="8443"
           secretRequired="true"
           secret="your_ajp_secret"
           address="127.0.0.1"  <!-- 只监听本地，安全！ -->
           maxThreads="200" />
```

> ⚠️ **安全提示**：Tomcat 9.0.31+ 默认要求 AJP 设置 secret，这是为了防止 Ghostcat 漏洞（CVE-2020-1938）

---

## 7. 虚拟主机配置

### 7.1 配置多个域名

```xml
<Engine name="Catalina" defaultHost="localhost">
  
  <!-- 默认主机 -->
  <Host name="localhost" appBase="webapps"
        unpackWARs="true" autoDeploy="true">
  </Host>
  
  <!-- 虚拟主机 1：www.site1.com -->
  <Host name="www.site1.com" appBase="/data/site1"
        unpackWARs="true" autoDeploy="true">
    <!-- 域名别名 -->
    <Alias>site1.com</Alias>
    
    <Valve className="org.apache.catalina.valves.AccessLogValve"
           directory="logs"
           prefix="site1_access_log" suffix=".txt"
           pattern="%h %l %u %t &quot;%r&quot; %s %b" />
  </Host>
  
  <!-- 虚拟主机 2：www.site2.com -->
  <Host name="www.site2.com" appBase="/data/site2"
        unpackWARs="true" autoDeploy="true">
    <Alias>site2.com</Alias>
  </Host>
  
</Engine>
```

### 7.2 目录结构

```
/data/
├── site1/
│   └── ROOT/           # www.site1.com 的默认应用
│       └── index.html
└── site2/
    └── ROOT/           # www.site2.com 的默认应用
        └── index.html
```


---

## 8. 安全配置

### 8.1 删除默认应用

```bash
# 生产环境必须删除这些默认应用！
cd /opt/tomcat9/webapps
rm -rf docs examples manager host-manager ROOT
```

### 8.2 禁用目录列表

确保 `conf/web.xml` 中：

```xml
<servlet>
  <servlet-name>default</servlet-name>
  <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
  <init-param>
    <param-name>listings</param-name>
    <param-value>false</param-value>  <!-- 必须为 false -->
  </init-param>
</servlet>
```

### 8.3 隐藏版本信息

```xml
<!-- server.xml 中的 Connector -->
<Connector port="8080" 
           server="Apache"           <!-- 自定义 Server 头 -->
           xpoweredBy="false" />     <!-- 禁用 X-Powered-By 头 -->
```

修改错误页面，创建 `conf/Catalina/localhost/ROOT.xml`：

```xml
<Context>
  <Valve className="org.apache.catalina.valves.ErrorReportValve"
         showReport="false"
         showServerInfo="false" />
</Context>
```

### 8.4 限制管理界面访问

编辑 `webapps/manager/META-INF/context.xml`：

```xml
<Context antiResourceLocking="false" privileged="true">
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.0\.0\.1|192\.168\.1\.\d+" />  <!-- 只允许特定 IP -->
</Context>
```

### 8.5 配置安全头

在应用的 `web.xml` 中添加过滤器：

```xml
<filter>
  <filter-name>httpHeaderSecurity</filter-name>
  <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
  <init-param>
    <param-name>antiClickJackingEnabled</param-name>
    <param-value>true</param-value>
  </init-param>
  <init-param>
    <param-name>antiClickJackingOption</param-name>
    <param-value>DENY</param-value>
  </init-param>
</filter>
<filter-mapping>
  <filter-name>httpHeaderSecurity</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

### 8.6 修改关闭端口和命令

```xml
<!-- 修改默认的 8005 端口和 SHUTDOWN 命令 -->
<Server port="8005" shutdown="COMPLEX_SHUTDOWN_COMMAND_12345">
```

或者完全禁用：

```xml
<Server port="-1" shutdown="SHUTDOWN">
```


---

## 9. 性能优化

### 9.1 JVM 参数优化

```bash
# bin/setenv.sh

# 堆内存：根据服务器内存调整，一般为物理内存的 50%-70%
CATALINA_OPTS="-Xms2g -Xmx2g"  # 最小和最大设为相同，避免动态调整

# G1 垃圾收集器（Java 11+ 推荐）
CATALINA_OPTS="$CATALINA_OPTS -XX:+UseG1GC"
CATALINA_OPTS="$CATALINA_OPTS -XX:MaxGCPauseMillis=200"
CATALINA_OPTS="$CATALINA_OPTS -XX:G1HeapRegionSize=16m"

# 元空间
CATALINA_OPTS="$CATALINA_OPTS -XX:MetaspaceSize=256m"
CATALINA_OPTS="$CATALINA_OPTS -XX:MaxMetaspaceSize=512m"

# 字符串去重（节省内存）
CATALINA_OPTS="$CATALINA_OPTS -XX:+UseStringDeduplication"

# GC 日志（排查问题用）
CATALINA_OPTS="$CATALINA_OPTS -Xlog:gc*:file=/opt/tomcat9/logs/gc.log:time,uptime:filecount=5,filesize=10m"

export CATALINA_OPTS
```

### 9.2 连接器参数优化

```xml
<Connector port="8080" 
           protocol="org.apache.coyote.http11.Http11Nio2Protocol"
           
           <!-- 线程配置 -->
           maxThreads="500"
           minSpareThreads="50"
           acceptCount="300"
           
           <!-- 连接配置 -->
           maxConnections="10000"
           connectionTimeout="20000"
           keepAliveTimeout="15000"
           maxKeepAliveRequests="200"
           
           <!-- 启用压缩 -->
           compression="on"
           compressionMinSize="1024"
           compressibleMimeType="text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json,application/xml"
           
           <!-- 禁用 DNS 反向解析（提升性能） -->
           enableLookups="false"
           
           URIEncoding="UTF-8" />
```

### 9.3 禁用不必要的功能

```xml
<!-- 生产环境禁用自动部署 -->
<Host name="localhost" appBase="webapps"
      unpackWARs="false"      <!-- 不自动解压 WAR -->
      autoDeploy="false"      <!-- 不自动部署 -->
      deployOnStartup="true"> <!-- 启动时部署 -->
</Host>
```

### 9.4 Session 优化

```xml
<!-- context.xml -->
<Context>
  <!-- 禁用 Session 持久化 -->
  <Manager pathname="" />
  
  <!-- 或使用 Redis 存储 Session（集群环境） -->
  <!-- 需要 redisson-tomcat 依赖 -->
</Context>
```

```xml
<!-- web.xml 中设置 Session 超时 -->
<session-config>
  <session-timeout>30</session-timeout>  <!-- 30 分钟 -->
  <cookie-config>
    <http-only>true</http-only>
    <secure>true</secure>  <!-- HTTPS 环境 -->
  </cookie-config>
</session-config>
```


---

## 10. 日志管理

### 10.1 日志文件说明

| 日志文件 | 说明 |
|---------|------|
| catalina.out | 标准输出和错误输出，包含所有日志 |
| catalina.YYYY-MM-DD.log | Tomcat 引擎日志 |
| localhost.YYYY-MM-DD.log | 应用日志 |
| localhost_access_log.YYYY-MM-DD.txt | 访问日志 |
| host-manager.YYYY-MM-DD.log | 主机管理日志 |
| manager.YYYY-MM-DD.log | 应用管理日志 |

### 10.2 配置日志级别

编辑 `conf/logging.properties`：

```properties
# 全局日志级别
.level = INFO

# Tomcat 内部日志
org.apache.catalina.level = INFO
org.apache.catalina.startup.level = INFO

# 减少不必要的日志
org.apache.catalina.session.level = WARNING
org.apache.coyote.level = WARNING

# 应用日志
org.springframework.level = INFO
com.mycompany.level = DEBUG
```

### 10.3 访问日志格式

```xml
<Valve className="org.apache.catalina.valves.AccessLogValve"
       directory="logs"
       prefix="access_log"
       suffix=".log"
       rotatable="true"
       fileDateFormat=".yyyy-MM-dd"
       pattern="%h %l %u %t &quot;%r&quot; %s %b %D &quot;%{Referer}i&quot; &quot;%{User-Agent}i&quot;" />
```

**格式说明：**
- `%h` - 客户端 IP
- `%l` - 远程逻辑用户名（通常为 -）
- `%u` - 认证用户名
- `%t` - 时间戳
- `%r` - 请求行（方法 + URL + 协议）
- `%s` - HTTP 状态码
- `%b` - 响应字节数
- `%D` - 处理时间（毫秒）
- `%{Referer}i` - Referer 头
- `%{User-Agent}i` - User-Agent 头

### 10.4 日志轮转（logrotate）

创建 `/etc/logrotate.d/tomcat`：

```
/opt/tomcat9/logs/catalina.out {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
```

### 10.5 使用 Log4j2 替代默认日志

1. 下载 `log4j2-tomcat` 依赖放入 `lib/` 目录
2. 删除 `conf/logging.properties`
3. 创建 `conf/log4j2.xml`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
  <Appenders>
    <RollingFile name="CATALINA" fileName="${sys:catalina.base}/logs/catalina.log"
                 filePattern="${sys:catalina.base}/logs/catalina.%d{yyyy-MM-dd}.log.gz">
      <PatternLayout pattern="%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
      <Policies>
        <TimeBasedTriggeringPolicy />
      </Policies>
      <DefaultRolloverStrategy max="30"/>
    </RollingFile>
  </Appenders>
  <Loggers>
    <Root level="info">
      <AppenderRef ref="CATALINA"/>
    </Root>
  </Loggers>
</Configuration>
```


---

## 11. 集群与负载均衡

### 11.1 Session 复制集群

```xml
<!-- server.xml 中的 Engine 或 Host 内添加 -->
<Cluster className="org.apache.catalina.ha.tcp.SimpleTcpCluster"
         channelSendOptions="8">

  <Manager className="org.apache.catalina.ha.session.DeltaManager"
           expireSessionsOnShutdown="false"
           notifyListenersOnReplication="true"/>

  <Channel className="org.apache.catalina.tribes.group.GroupChannel">
    <Membership className="org.apache.catalina.tribes.membership.McastService"
                address="228.0.0.4"
                port="45564"
                frequency="500"
                dropTime="3000"/>
    
    <Receiver className="org.apache.catalina.tribes.transport.nio.NioReceiver"
              address="auto"
              port="4000"
              autoBind="100"
              selectorTimeout="5000"
              maxThreads="6"/>
    
    <Sender className="org.apache.catalina.tribes.transport.ReplicationTransmitter">
      <Transport className="org.apache.catalina.tribes.transport.nio.PooledParallelSender"/>
    </Sender>
    
    <Interceptor className="org.apache.catalina.tribes.group.interceptors.TcpFailureDetector"/>
    <Interceptor className="org.apache.catalina.tribes.group.interceptors.MessageDispatchInterceptor"/>
  </Channel>

  <Valve className="org.apache.catalina.ha.tcp.ReplicationValve"
         filter=""/>
  <Valve className="org.apache.catalina.ha.session.JvmRouteBinderValve"/>

  <ClusterListener className="org.apache.catalina.ha.session.ClusterSessionListener"/>
</Cluster>
```

应用的 `web.xml` 需要添加：

```xml
<distributable/>
```

### 11.2 使用 Redis 存储 Session（推荐）

使用 Redisson 实现 Session 共享：

1. 下载 `redisson-tomcat-9-x.x.x.jar` 放入 `lib/`
2. 配置 `context.xml`：

```xml
<Context>
  <Manager className="org.redisson.tomcat.RedissonSessionManager"
           configPath="${catalina.base}/conf/redisson.yaml"
           readMode="REDIS"
           updateMode="DEFAULT"/>
</Context>
```

3. 创建 `conf/redisson.yaml`：

```yaml
singleServerConfig:
  address: "redis://127.0.0.1:6379"
  password: "your_redis_password"
  database: 0
  connectionPoolSize: 64
  connectionMinimumIdleSize: 24
```

### 11.3 Nginx 负载均衡配置

```nginx
upstream tomcat_cluster {
    # 负载均衡策略
    # least_conn;  # 最少连接
    # ip_hash;     # IP 哈希（Session 粘滞）
    
    server 192.168.1.101:8080 weight=1 max_fails=3 fail_timeout=30s;
    server 192.168.1.102:8080 weight=1 max_fails=3 fail_timeout=30s;
    server 192.168.1.103:8080 weight=1 backup;  # 备用服务器
    
    keepalive 32;  # 保持连接数
}

server {
    listen 80;
    server_name www.example.com;
    
    location / {
        proxy_pass http://tomcat_cluster;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 30s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```


---

## 12. SSL/HTTPS 配置

### 12.1 生成自签名证书（测试用）

```bash
# 生成密钥库
keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 \
        -keystore /opt/tomcat9/conf/keystore.jks \
        -validity 365 \
        -storepass changeit \
        -keypass changeit \
        -dname "CN=localhost, OU=Dev, O=MyCompany, L=Beijing, ST=Beijing, C=CN"
```

### 12.2 配置 HTTPS 连接器

```xml
<!-- 使用 JKS 密钥库 -->
<Connector port="8443" 
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="200"
           SSLEnabled="true">
  <SSLHostConfig>
    <Certificate certificateKeystoreFile="conf/keystore.jks"
                 certificateKeystorePassword="changeit"
                 type="RSA" />
  </SSLHostConfig>
</Connector>

<!-- 使用 PEM 证书（Let's Encrypt 等） -->
<Connector port="8443" 
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="200"
           SSLEnabled="true">
  <SSLHostConfig>
    <Certificate certificateFile="conf/cert.pem"
                 certificateKeyFile="conf/privkey.pem"
                 certificateChainFile="conf/chain.pem"
                 type="RSA" />
  </SSLHostConfig>
</Connector>
```

### 12.3 强制 HTTPS 跳转

在应用的 `web.xml` 中添加：

```xml
<security-constraint>
  <web-resource-collection>
    <web-resource-name>Secure</web-resource-name>
    <url-pattern>/*</url-pattern>
  </web-resource-collection>
  <user-data-constraint>
    <transport-guarantee>CONFIDENTIAL</transport-guarantee>
  </user-data-constraint>
</security-constraint>
```

或在 `server.xml` 的 HTTP 连接器中配置：

```xml
<Connector port="8080" protocol="HTTP/1.1"
           redirectPort="8443" />
```

### 12.4 SSL 安全加固

```xml
<Connector port="8443" 
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           SSLEnabled="true">
  <SSLHostConfig 
      protocols="TLSv1.2,TLSv1.3"
      ciphers="TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256"
      honorCipherOrder="true">
    <Certificate certificateKeystoreFile="conf/keystore.jks"
                 certificateKeystorePassword="changeit"
                 type="RSA" />
  </SSLHostConfig>
</Connector>
```

---

## 13. 与 Nginx 整合

### 13.1 反向代理配置

```nginx
server {
    listen 80;
    server_name www.example.com;
    
    # 静态资源由 Nginx 处理
    location ~* \.(html|css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$ {
        root /data/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # 动态请求转发给 Tomcat
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```


### 13.2 获取真实客户端 IP

Tomcat 配置 RemoteIpValve：

```xml
<!-- server.xml 的 Host 中添加 -->
<Valve className="org.apache.catalina.valves.RemoteIpValve"
       remoteIpHeader="X-Forwarded-For"
       protocolHeader="X-Forwarded-Proto"
       internalProxies="127\.0\.0\.1|192\.168\.\d+\.\d+" />
```

### 13.3 AJP 协议整合（高性能）

Tomcat 配置：

```xml
<Connector protocol="AJP/1.3"
           port="8009"
           address="127.0.0.1"
           secretRequired="true"
           secret="your_secret_key"
           maxThreads="200" />
```

Nginx 配置（需要 ngx_http_ajp_module）：

```nginx
# 注意：标准 Nginx 不支持 AJP，需要使用 Apache 或编译 AJP 模块
# 推荐使用 HTTP 反向代理
```

---

## 14. 监控与管理

### 14.1 启用 JMX 远程监控

在 `setenv.sh` 中添加：

```bash
# JMX 配置
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote"
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.port=9090"
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.rmi.port=9090"
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.ssl=false"
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.authenticate=true"
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.password.file=/opt/tomcat9/conf/jmxremote.password"
CATALINA_OPTS="$CATALINA_OPTS -Dcom.sun.management.jmxremote.access.file=/opt/tomcat9/conf/jmxremote.access"
CATALINA_OPTS="$CATALINA_OPTS -Djava.rmi.server.hostname=your_server_ip"
```

创建认证文件：

```bash
# conf/jmxremote.access
monitorRole readonly
controlRole readwrite

# conf/jmxremote.password
monitorRole monitor_password
controlRole control_password

# 设置权限
chmod 600 conf/jmxremote.password conf/jmxremote.access
chown tomcat:tomcat conf/jmxremote.password conf/jmxremote.access
```

### 14.2 使用 Manager 应用

确保 `tomcat-users.xml` 配置了管理用户：

```xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-status"/>
  <user username="admin" password="secure_password" roles="manager-gui,manager-status"/>
</tomcat-users>
```

访问 `http://localhost:8080/manager/html` 可以：
- 查看已部署的应用
- 部署/卸载/重载应用
- 查看服务器状态
- 查看 JVM 内存使用

### 14.3 Prometheus 监控

使用 JMX Exporter：

```bash
# 下载 jmx_prometheus_javaagent
wget https://repo1.maven.org/maven2/io/prometheus/jmx/jmx_prometheus_javaagent/0.19.0/jmx_prometheus_javaagent-0.19.0.jar \
     -O /opt/tomcat9/lib/jmx_prometheus_javaagent.jar
```

创建 `conf/prometheus-config.yaml`：

```yaml
lowercaseOutputName: true
lowercaseOutputLabelNames: true
rules:
  - pattern: 'Catalina<type=GlobalRequestProcessor, name=\"(\w+-\w+)-(\d+)\"><>(\w+):'
    name: tomcat_$3_total
    labels:
      port: "$2"
      protocol: "$1"
  - pattern: 'Catalina<j2eeType=Servlet, WebModule=//([-a-zA-Z0-9+&@#/%?=~_|!:.,;]*[-a-zA-Z0-9+&@#/%=~_|]),name=([-a-zA-Z0-9+/$%~_-|!.]*),J2EEApplication=none,J2EEServer=none><>(requestCount|processingTime|errorCount):'
    name: tomcat_servlet_$3_total
    labels:
      module: "$1"
      servlet: "$2"
```

在 `setenv.sh` 中添加：

```bash
CATALINA_OPTS="$CATALINA_OPTS -javaagent:/opt/tomcat9/lib/jmx_prometheus_javaagent.jar=9091:/opt/tomcat9/conf/prometheus-config.yaml"
```


### 14.4 常用监控命令

```bash
# 查看 Tomcat 进程
ps aux | grep tomcat
ps -ef | grep java

# 查看端口占用
netstat -tlnp | grep 8080
ss -tlnp | grep 8080

# 查看线程数
ps -eLf | grep java | wc -l

# 查看内存使用
jstat -gc <pid> 1000 10

# 查看堆内存详情
jmap -heap <pid>

# 生成堆转储
jmap -dump:format=b,file=heapdump.hprof <pid>

# 查看线程栈
jstack <pid> > thread_dump.txt

# 实时监控
top -Hp <pid>  # 查看线程 CPU 使用
```

---

## 15. 常见错误与解决方案

### 15.1 启动失败类

#### 错误：Address already in use

```
java.net.BindException: Address already in use
```

**原因**：端口被占用

**解决方案**：

```bash
# 查找占用端口的进程
netstat -tlnp | grep 8080
lsof -i :8080

# 杀死进程或修改 Tomcat 端口
kill -9 <pid>

# 或修改 server.xml 中的端口
<Connector port="8081" ... />
```

#### 错误：JAVA_HOME is not defined

```
Neither the JAVA_HOME nor the JRE_HOME environment variable is defined
```

**解决方案**：

```bash
# 设置环境变量
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk
export PATH=$JAVA_HOME/bin:$PATH

# 或在 setenv.sh 中设置
echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk' > bin/setenv.sh
```

#### 错误：Permission denied

```
./startup.sh: Permission denied
```

**解决方案**：

```bash
chmod +x bin/*.sh
chown -R tomcat:tomcat /opt/tomcat9
```

### 15.2 内存相关错误

#### 错误：OutOfMemoryError: Java heap space

```
java.lang.OutOfMemoryError: Java heap space
```

**原因**：堆内存不足

**解决方案**：

```bash
# 增加堆内存
CATALINA_OPTS="-Xms1g -Xmx2g"

# 分析内存泄漏
jmap -dump:format=b,file=heap.hprof <pid>
# 使用 MAT 或 VisualVM 分析
```

#### 错误：OutOfMemoryError: Metaspace

```
java.lang.OutOfMemoryError: Metaspace
```

**原因**：元空间不足（类加载过多）

**解决方案**：

```bash
CATALINA_OPTS="-XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=512m"
```

#### 错误：OutOfMemoryError: unable to create new native thread

**原因**：线程数达到系统限制

**解决方案**：

```bash
# 查看当前限制
ulimit -u

# 修改限制 /etc/security/limits.conf
tomcat soft nproc 65535
tomcat hard nproc 65535

# 减少 Tomcat 线程数
<Connector maxThreads="200" ... />
```


### 15.3 部署相关错误

#### 错误：404 Not Found

**可能原因**：
1. 应用未正确部署
2. 访问路径错误
3. web.xml 配置错误

**排查步骤**：

```bash
# 1. 检查应用是否存在
ls -la webapps/

# 2. 检查应用是否解压
ls -la webapps/myapp/

# 3. 检查日志
tail -f logs/localhost.*.log

# 4. 检查 Context 配置
cat conf/Catalina/localhost/myapp.xml
```

#### 错误：ClassNotFoundException / NoClassDefFoundError

```
java.lang.ClassNotFoundException: com.mysql.cj.jdbc.Driver
```

**原因**：缺少依赖 JAR 包

**解决方案**：

```bash
# 将依赖放入正确位置
# 方式1：放入应用的 WEB-INF/lib/
cp mysql-connector-java.jar webapps/myapp/WEB-INF/lib/

# 方式2：放入 Tomcat 的 lib/（全局共享）
cp mysql-connector-java.jar lib/
```

#### 错误：WAR 部署后无法访问

**排查步骤**：

```bash
# 1. 检查 WAR 是否解压
ls webapps/

# 2. 检查解压后的目录结构
ls webapps/myapp/WEB-INF/

# 3. 检查 web.xml 是否存在
cat webapps/myapp/WEB-INF/web.xml

# 4. 查看部署日志
grep -i "deploy" logs/catalina.out
```

### 15.4 连接相关错误

#### 错误：Connection refused

```
java.net.ConnectException: Connection refused
```

**可能原因**：
1. Tomcat 未启动
2. 防火墙阻止
3. 监听地址配置错误

**解决方案**：

```bash
# 检查 Tomcat 是否运行
ps aux | grep tomcat

# 检查端口监听
netstat -tlnp | grep 8080

# 检查防火墙
firewall-cmd --list-ports
firewall-cmd --add-port=8080/tcp --permanent
firewall-cmd --reload

# 检查 Connector 配置（确保没有限制 address）
<Connector port="8080" address="0.0.0.0" ... />
```

#### 错误：Connection reset / Broken pipe

**原因**：连接被意外关闭

**解决方案**：

```xml
<!-- 增加超时时间 -->
<Connector connectionTimeout="60000"
           keepAliveTimeout="30000" ... />
```

#### 错误：Too many open files

```
java.io.IOException: Too many open files
```

**解决方案**：

```bash
# 查看当前限制
ulimit -n

# 修改限制 /etc/security/limits.conf
tomcat soft nofile 65535
tomcat hard nofile 65535

# 或在 systemd 服务中设置
[Service]
LimitNOFILE=65535
```


### 15.5 编码相关错误

#### 错误：中文乱码

**解决方案**：

```xml
<!-- 1. Connector 配置 URIEncoding -->
<Connector port="8080" URIEncoding="UTF-8" ... />

<!-- 2. 应用 web.xml 添加过滤器 -->
<filter>
  <filter-name>encodingFilter</filter-name>
  <filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class>
  <init-param>
    <param-name>encoding</param-name>
    <param-value>UTF-8</param-value>
  </init-param>
  <init-param>
    <param-name>forceEncoding</param-name>
    <param-value>true</param-value>
  </init-param>
</filter>
<filter-mapping>
  <filter-name>encodingFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

```bash
# 3. JVM 参数
CATALINA_OPTS="-Dfile.encoding=UTF-8"
```

### 15.6 SSL/HTTPS 错误

#### 错误：SSL handshake failure

```
javax.net.ssl.SSLHandshakeException
```

**可能原因**：
1. 证书过期
2. 证书不受信任
3. 协议/密码套件不匹配

**解决方案**：

```bash
# 检查证书有效期
keytool -list -v -keystore keystore.jks | grep Valid

# 检查证书链
openssl s_client -connect localhost:8443 -showcerts

# 更新 SSL 配置
<SSLHostConfig protocols="TLSv1.2,TLSv1.3">
```

#### 错误：Keystore was tampered with, or password was incorrect

**解决方案**：

```bash
# 确认密码正确
keytool -list -keystore keystore.jks

# 重新生成密钥库
keytool -genkeypair -alias tomcat -keyalg RSA -keystore new_keystore.jks
```

### 15.7 性能相关问题

#### 问题：响应缓慢

**排查步骤**：

```bash
# 1. 检查 CPU 使用
top -Hp <pid>

# 2. 检查线程状态
jstack <pid> | grep -A 20 "BLOCKED"

# 3. 检查 GC 情况
jstat -gcutil <pid> 1000 10

# 4. 检查连接池
# 查看数据库连接是否耗尽

# 5. 检查线程池
# 查看 maxThreads 是否达到上限
```

#### 问题：频繁 Full GC

**解决方案**：

```bash
# 1. 增加堆内存
CATALINA_OPTS="-Xms4g -Xmx4g"

# 2. 调整 GC 参数
CATALINA_OPTS="$CATALINA_OPTS -XX:+UseG1GC"
CATALINA_OPTS="$CATALINA_OPTS -XX:MaxGCPauseMillis=200"

# 3. 分析内存泄漏
jmap -histo:live <pid> | head -20
```


### 15.8 安全相关错误

#### 错误：AJP Connector - secretRequired

```
The AJP Connector is configured with secretRequired="true" but the secret attribute is either null or ""
```

**原因**：Tomcat 9.0.31+ 默认要求 AJP 设置 secret（防止 Ghostcat 漏洞）

**解决方案**：

```xml
<!-- 方式1：设置 secret -->
<Connector protocol="AJP/1.3" port="8009"
           secretRequired="true"
           secret="your_secret_key" />

<!-- 方式2：禁用 secret 要求（不推荐） -->
<Connector protocol="AJP/1.3" port="8009"
           secretRequired="false" />

<!-- 方式3：注释掉 AJP Connector（如果不需要） -->
```

#### 错误：Manager App 403 Access Denied

**原因**：默认只允许本地访问

**解决方案**：

编辑 `webapps/manager/META-INF/context.xml`：

```xml
<Context antiResourceLocking="false" privileged="true">
  <!-- 注释掉或修改 RemoteAddrValve -->
  <!-- <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" /> -->
  
  <!-- 或添加允许的 IP -->
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|192\.168\.1\.\d+" />
</Context>
```

---

## 附录：快速参考

### 常用命令速查

```bash
# 启动/停止
$CATALINA_HOME/bin/startup.sh
$CATALINA_HOME/bin/shutdown.sh
$CATALINA_HOME/bin/catalina.sh run  # 前台运行（调试用）

# 查看版本
$CATALINA_HOME/bin/version.sh

# 查看日志
tail -f $CATALINA_HOME/logs/catalina.out
tail -f $CATALINA_HOME/logs/localhost.$(date +%Y-%m-%d).log

# 检查配置
$CATALINA_HOME/bin/configtest.sh
```

### 端口说明

| 端口 | 用途 | 配置位置 |
|-----|------|---------|
| 8080 | HTTP 服务 | Connector |
| 8443 | HTTPS 服务 | Connector |
| 8009 | AJP 协议 | Connector |
| 8005 | 关闭命令 | Server |

### 重要文件路径

| 文件 | 说明 |
|-----|------|
| conf/server.xml | 主配置文件 |
| conf/web.xml | 全局 Web 配置 |
| conf/context.xml | 全局 Context 配置 |
| conf/tomcat-users.xml | 用户认证 |
| bin/setenv.sh | JVM 参数配置 |
| logs/catalina.out | 主日志文件 |

---

> 📝 **笔记更新日期**：2024年
> 
> 💡 **建议**：生产环境部署前，务必进行充分的测试，并根据实际业务需求调整配置参数。
