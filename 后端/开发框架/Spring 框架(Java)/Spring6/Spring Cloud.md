

> Spring Cloud Alibaba 是阿里巴巴开源的微服务解决方案，提供了分布式应用开发的一站式解决方案
> 本笔记基于 Java 17 + Spring Boot 3.2.12 + Spring Cloud Alibaba 2023.x

---

## 目录

1. [微服务基础概念](#1-微服务基础概念)
2. [环境搭建](#2-环境搭建)
3. [Nacos 服务注册与发现](#3-nacos-服务注册与发现)
4. [Nacos 配置中心](#4-nacos-配置中心)
5. [OpenFeign 服务调用](#5-openfeign-服务调用)
6. [Gateway 网关](#6-gateway-网关)
7. [Sentinel 流量控制](#7-sentinel-流量控制)
8. [Seata 分布式事务](#8-seata-分布式事务)
9. [RocketMQ 消息队列](#9-rocketmq-消息队列)
10. [链路追踪](#10-链路追踪)
11. [服务监控](#11-服务监控)
12. [Docker 部署](#12-docker-部署)
13. [常见错误与解决方案](#13-常见错误与解决方案)
14. [最佳实践](#14-最佳实践)

---

## 1. 微服务基础概念

### 1.1 什么是微服务？

微服务架构是一种将单一应用程序拆分为一组小型服务的架构风格。每个服务运行在自己的进程中，服务之间通过轻量级的通信机制（通常是 HTTP/REST 或消息队列）进行通信。

**微服务的特点：**
- **单一职责**：每个服务只负责一个业务功能
- **独立部署**：每个服务可以独立部署和扩展
- **技术多样性**：不同服务可以使用不同的技术栈
- **去中心化**：数据管理去中心化，每个服务管理自己的数据
- **容错性**：单个服务故障不会影响整个系统

### 1.2 微服务 vs 单体架构

| 特性 | 单体架构 | 微服务架构 |
|------|----------|------------|
| 部署 | 整体部署 | 独立部署 |
| 扩展 | 整体扩展 | 按需扩展 |
| 技术栈 | 统一 | 可多样 |
| 开发效率 | 初期快 | 初期慢，后期快 |
| 运维复杂度 | 低 | 高 |
| 适用场景 | 小型项目 | 大型复杂项目 |

### 1.3 Spring Cloud Alibaba 生态

```
┌─────────────────────────────────────────────────────────────┐
│                    Spring Cloud Alibaba                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Nacos     │  │  Sentinel   │  │   Seata     │         │
│  │ 注册/配置中心│  │  流量控制   │  │ 分布式事务  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  RocketMQ   │  │   Dubbo     │  │   OSS       │         │
│  │  消息队列   │  │  RPC框架    │  │  对象存储   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                     Spring Cloud                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Gateway    │  │  OpenFeign  │  │  LoadBalancer│        │
│  │   网关      │  │  服务调用   │  │  负载均衡   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                     Spring Boot                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.4 核心组件说明

| 组件 | 功能 | 说明 |
|------|------|------|
| Nacos | 服务注册与配置中心 | 替代 Eureka + Config |
| Sentinel | 流量控制与熔断降级 | 替代 Hystrix |
| Seata | 分布式事务 | 支持 AT、TCC、SAGA 模式 |
| RocketMQ | 消息队列 | 高性能消息中间件 |
| Gateway | API 网关 | 路由、限流、鉴权 |
| OpenFeign | 声明式服务调用 | 简化 HTTP 调用 |
| LoadBalancer | 负载均衡 | 替代 Ribbon |

---

## 2. 环境搭建

### 2.1 版本对应关系

```
Spring Cloud Alibaba 2023.0.1.0
├── Spring Cloud 2023.0.1
├── Spring Boot 3.2.x
├── Nacos 2.3.x
├── Sentinel 1.8.x
├── Seata 2.0.x
└── RocketMQ 5.x
```

### 2.2 父工程 POM

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>cloud-demo</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>
    
    <modules>
        <module>common</module>
        <module>gateway</module>
        <module>user-service</module>
        <module>order-service</module>
        <module>product-service</module>
    </modules>
    
    <properties>
        <java.version>17</java.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        
        <spring-boot.version>3.2.12</spring-boot.version>
        <spring-cloud.version>2023.0.1</spring-cloud.version>
        <spring-cloud-alibaba.version>2023.0.1.0</spring-cloud-alibaba.version>
    </properties>
    
    <!-- 依赖管理 -->
    <dependencyManagement>
        <dependencies>
            <!-- Spring Boot -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring-boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            
            <!-- Spring Cloud -->
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            
            <!-- Spring Cloud Alibaba -->
            <dependency>
                <groupId>com.alibaba.cloud</groupId>
                <artifactId>spring-cloud-alibaba-dependencies</artifactId>
                <version>${spring-cloud-alibaba.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>
    
    <!-- 公共依赖 -->
    <dependencies>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <version>${spring-boot.version}</version>
            </plugin>
        </plugins>
    </build>
</project>
```

### 2.3 项目结构

```
cloud-demo/
├── pom.xml                          # 父工程 POM
├── common/                          # 公共模块
│   ├── pom.xml
│   └── src/main/java/com/example/common/
│       ├── entity/                  # 公共实体
│       ├── dto/                     # 数据传输对象
│       ├── result/                  # 统一响应
│       └── exception/               # 异常处理
├── gateway/                         # 网关服务
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/gateway/
│       └── resources/application.yml
├── user-service/                    # 用户服务
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/user/
│       └── resources/application.yml
├── order-service/                   # 订单服务
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/order/
│       └── resources/application.yml
└── product-service/                 # 商品服务
    ├── pom.xml
    └── src/main/
        ├── java/com/example/product/
        └── resources/application.yml
```


### 2.4 公共模块

```xml
<!-- common/pom.xml -->
<project>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>cloud-demo</artifactId>
        <version>1.0.0</version>
    </parent>
    
    <artifactId>common</artifactId>
    
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>
    </dependencies>
</project>
```

```java
// 统一响应结果
package com.example.common.result;

import lombok.Data;
import java.io.Serializable;

@Data
public class Result<T> implements Serializable {
    
    private Integer code;
    private String message;
    private T data;
    private Long timestamp;
    
    public Result() {
        this.timestamp = System.currentTimeMillis();
    }
    
    public static <T> Result<T> success() {
        return success(null);
    }
    
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(200);
        result.setMessage("success");
        result.setData(data);
        return result;
    }
    
    public static <T> Result<T> error(String message) {
        return error(500, message);
    }
    
    public static <T> Result<T> error(Integer code, String message) {
        Result<T> result = new Result<>();
        result.setCode(code);
        result.setMessage(message);
        return result;
    }
}
```

```java
// 全局异常处理
package com.example.common.exception;

import com.example.common.result.Result;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(BusinessException.class)
    public Result<?> handleBusinessException(BusinessException e) {
        log.error("业务异常: {}", e.getMessage());
        return Result.error(e.getCode(), e.getMessage());
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<?> handleValidationException(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldError().getDefaultMessage();
        log.error("参数校验失败: {}", message);
        return Result.error(400, message);
    }
    
    @ExceptionHandler(Exception.class)
    public Result<?> handleException(Exception e) {
        log.error("系统异常: ", e);
        return Result.error("系统繁忙，请稍后重试");
    }
}

// 业务异常
public class BusinessException extends RuntimeException {
    
    private Integer code;
    
    public BusinessException(String message) {
        super(message);
        this.code = 500;
    }
    
    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
    }
    
    public Integer getCode() {
        return code;
    }
}
```

---

## 3. Nacos 服务注册与发现

### 3.1 Nacos 简介

Nacos（Dynamic Naming and Configuration Service）是阿里巴巴开源的服务发现、配置管理和服务管理平台。它集成了服务注册发现和配置中心的功能。

**Nacos 的核心功能：**
- **服务发现**：支持 DNS 和 RPC 服务发现
- **服务健康检查**：支持传输层和应用层健康检查
- **动态配置**：支持配置的动态更新
- **动态 DNS**：支持权重路由

### 3.2 Nacos 安装

```bash
# Docker 安装（推荐）
docker run -d \
  --name nacos \
  -e MODE=standalone \
  -e NACOS_AUTH_ENABLE=true \
  -e NACOS_AUTH_TOKEN=SecretKey012345678901234567890123456789012345678901234567890123456789 \
  -e NACOS_AUTH_IDENTITY_KEY=serverIdentity \
  -e NACOS_AUTH_IDENTITY_VALUE=security \
  -p 8848:8848 \
  -p 9848:9848 \
  nacos/nacos-server:v2.3.0

# 访问控制台
# http://localhost:8848/nacos
# 默认账号密码：nacos/nacos
```

### 3.3 服务注册

```xml
<!-- user-service/pom.xml -->
<dependencies>
    <dependency>
        <groupId>com.example</groupId>
        <artifactId>common</artifactId>
        <version>1.0.0</version>
    </dependency>
    
    <!-- Nacos 服务发现 -->
    <dependency>
        <groupId>com.alibaba.cloud</groupId>
        <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
    </dependency>
    
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

```yaml
# user-service/src/main/resources/application.yml
server:
  port: 8081

spring:
  application:
    name: user-service
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
        namespace: public
        group: DEFAULT_GROUP
        # 认证配置
        username: nacos
        password: nacos
```

```java
// 启动类
package com.example.user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}
```

```java
// 用户控制器
package com.example.user.controller;

import com.example.common.result.Result;
import com.example.user.entity.User;
import com.example.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    @GetMapping("/{id}")
    public Result<User> getById(@PathVariable Long id) {
        User user = userService.getById(id);
        return Result.success(user);
    }
    
    @PostMapping
    public Result<User> create(@RequestBody User user) {
        userService.save(user);
        return Result.success(user);
    }
}
```

### 3.4 服务发现

```java
// 使用 DiscoveryClient 获取服务实例
package com.example.order.service;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
@RequiredArgsConstructor
public class OrderService {
    
    private final DiscoveryClient discoveryClient;
    private final RestTemplate restTemplate;
    
    public User getUserById(Long userId) {
        // 获取服务实例列表
        List<ServiceInstance> instances = discoveryClient.getInstances("user-service");
        if (instances.isEmpty()) {
            throw new RuntimeException("用户服务不可用");
        }
        
        // 简单负载均衡（随机选择）
        ServiceInstance instance = instances.get(0);
        String url = instance.getUri() + "/user/" + userId;
        
        return restTemplate.getForObject(url, User.class);
    }
}
```

### 3.5 Nacos 集群部署

```yaml
# nacos/conf/cluster.conf
192.168.1.101:8848
192.168.1.102:8848
192.168.1.103:8848
```

```yaml
# application.yml 配置多个 Nacos 地址
spring:
  cloud:
    nacos:
      discovery:
        server-addr: 192.168.1.101:8848,192.168.1.102:8848,192.168.1.103:8848
```


---

## 4. Nacos 配置中心

### 4.1 配置中心简介

Nacos 配置中心支持配置的集中管理和动态更新，无需重启应用即可生效。

**核心概念：**
- **Data ID**：配置文件的唯一标识，格式：`${prefix}-${spring.profiles.active}.${file-extension}`
- **Group**：配置分组，默认 DEFAULT_GROUP
- **Namespace**：命名空间，用于隔离不同环境

### 4.2 添加依赖

```xml
<!-- Nacos 配置中心 -->
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
</dependency>

<!-- Spring Cloud Bootstrap（Spring Boot 3.x 需要） -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-bootstrap</artifactId>
</dependency>
```

### 4.3 配置文件

```yaml
# bootstrap.yml（优先于 application.yml 加载）
spring:
  application:
    name: user-service
  profiles:
    active: dev
  cloud:
    nacos:
      config:
        server-addr: localhost:8848
        namespace: public
        group: DEFAULT_GROUP
        file-extension: yaml
        # 认证配置
        username: nacos
        password: nacos
        # 共享配置
        shared-configs:
          - data-id: common.yaml
            group: DEFAULT_GROUP
            refresh: true
        # 扩展配置
        extension-configs:
          - data-id: redis.yaml
            group: DEFAULT_GROUP
            refresh: true
```

### 4.4 在 Nacos 控制台创建配置

```yaml
# Data ID: user-service-dev.yaml
# Group: DEFAULT_GROUP

server:
  port: 8081

spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/user_db?useUnicode=true&characterEncoding=utf-8
    username: root
    password: root

# 自定义配置
app:
  name: 用户服务
  version: 1.0.0
  config:
    timeout: 3000
    retry: 3
```

### 4.5 读取配置

```java
// 方式一：使用 @Value
@RestController
@RequestMapping("/config")
public class ConfigController {
    
    @Value("${app.name}")
    private String appName;
    
    @Value("${app.config.timeout:5000}")
    private Integer timeout;
    
    @GetMapping("/info")
    public Result<Map<String, Object>> getConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("appName", appName);
        config.put("timeout", timeout);
        return Result.success(config);
    }
}

// 方式二：使用 @ConfigurationProperties
@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppConfig {
    private String name;
    private String version;
    private Config config;
    
    @Data
    public static class Config {
        private Integer timeout;
        private Integer retry;
    }
}

// 使用
@RestController
@RequiredArgsConstructor
public class ConfigController {
    
    private final AppConfig appConfig;
    
    @GetMapping("/config")
    public Result<AppConfig> getConfig() {
        return Result.success(appConfig);
    }
}
```

### 4.6 配置动态刷新

```java
// 方式一：使用 @RefreshScope
@RestController
@RefreshScope
@RequestMapping("/config")
public class ConfigController {
    
    @Value("${app.config.timeout}")
    private Integer timeout;
    
    @GetMapping("/timeout")
    public Result<Integer> getTimeout() {
        return Result.success(timeout);
    }
}

// 方式二：使用 @ConfigurationProperties（自动刷新）
@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppConfig {
    // 配置变更时自动更新
    private String name;
    private Integer timeout;
}

// 方式三：监听配置变更
@Component
@Slf4j
public class NacosConfigListener {
    
    @NacosConfigListener(dataId = "user-service-dev.yaml", groupId = "DEFAULT_GROUP")
    public void onConfigChange(String config) {
        log.info("配置发生变更: {}", config);
        // 处理配置变更逻辑
    }
}
```

### 4.7 多环境配置

```
Nacos 配置列表：
├── user-service.yaml          # 公共配置
├── user-service-dev.yaml      # 开发环境
├── user-service-test.yaml     # 测试环境
└── user-service-prod.yaml     # 生产环境
```

```yaml
# bootstrap.yml
spring:
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}
```

---

## 5. OpenFeign 服务调用

### 5.1 OpenFeign 简介

OpenFeign 是一个声明式的 HTTP 客户端，使得编写 HTTP 客户端变得更加简单。只需要创建一个接口并添加注解即可。

### 5.2 添加依赖

```xml
<!-- OpenFeign -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>

<!-- 负载均衡 -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```

### 5.3 启用 OpenFeign

```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients(basePackages = "com.example.order.feign")
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}
```

### 5.4 定义 Feign 客户端

```java
// 用户服务 Feign 客户端
package com.example.order.feign;

import com.example.common.result.Result;
import com.example.order.feign.fallback.UserFeignFallback;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(
    name = "user-service",           // 服务名称
    fallback = UserFeignFallback.class,  // 降级处理
    configuration = FeignConfig.class    // 自定义配置
)
public interface UserFeignClient {
    
    @GetMapping("/user/{id}")
    Result<User> getById(@PathVariable("id") Long id);
    
    @GetMapping("/user/username/{username}")
    Result<User> getByUsername(@PathVariable("username") String username);
    
    @PostMapping("/user")
    Result<User> create(@RequestBody User user);
}

// 商品服务 Feign 客户端
@FeignClient(name = "product-service", fallback = ProductFeignFallback.class)
public interface ProductFeignClient {
    
    @GetMapping("/product/{id}")
    Result<Product> getById(@PathVariable("id") Long id);
    
    @PutMapping("/product/{id}/stock")
    Result<Boolean> deductStock(@PathVariable("id") Long id, @RequestParam("count") Integer count);
}
```

### 5.5 降级处理

```java
// 降级处理类
package com.example.order.feign.fallback;

import com.example.common.result.Result;
import com.example.order.feign.UserFeignClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class UserFeignFallback implements UserFeignClient {
    
    @Override
    public Result<User> getById(Long id) {
        log.error("调用用户服务失败，用户ID: {}", id);
        return Result.error("用户服务暂时不可用");
    }
    
    @Override
    public Result<User> getByUsername(String username) {
        log.error("调用用户服务失败，用户名: {}", username);
        return Result.error("用户服务暂时不可用");
    }
    
    @Override
    public Result<User> create(User user) {
        log.error("调用用户服务失败");
        return Result.error("用户服务暂时不可用");
    }
}

// 使用 FallbackFactory 获取异常信息
@Slf4j
@Component
public class UserFeignFallbackFactory implements FallbackFactory<UserFeignClient> {
    
    @Override
    public UserFeignClient create(Throwable cause) {
        log.error("调用用户服务异常: ", cause);
        
        return new UserFeignClient() {
            @Override
            public Result<User> getById(Long id) {
                return Result.error("用户服务异常: " + cause.getMessage());
            }
            
            @Override
            public Result<User> getByUsername(String username) {
                return Result.error("用户服务异常: " + cause.getMessage());
            }
            
            @Override
            public Result<User> create(User user) {
                return Result.error("用户服务异常: " + cause.getMessage());
            }
        };
    }
}
```

### 5.6 Feign 配置

```yaml
# application.yml
spring:
  cloud:
    openfeign:
      client:
        config:
          default:  # 全局配置
            connect-timeout: 5000
            read-timeout: 10000
            logger-level: FULL
          user-service:  # 针对特定服务的配置
            connect-timeout: 3000
            read-timeout: 5000
      # 开启 Sentinel 支持
      sentinel:
        enabled: true
```

```java
// 自定义 Feign 配置
@Configuration
public class FeignConfig {
    
    /**
     * 日志级别
     * NONE: 不记录日志
     * BASIC: 只记录请求方法、URL、响应状态码和执行时间
     * HEADERS: 记录请求和响应的头信息
     * FULL: 记录所有信息
     */
    @Bean
    public Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }
    
    /**
     * 请求拦截器（添加公共请求头）
     */
    @Bean
    public RequestInterceptor requestInterceptor() {
        return template -> {
            // 传递请求头
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                // 传递 Token
                String token = request.getHeader("Authorization");
                if (token != null) {
                    template.header("Authorization", token);
                }
                // 传递链路追踪 ID
                String traceId = request.getHeader("X-Trace-Id");
                if (traceId != null) {
                    template.header("X-Trace-Id", traceId);
                }
            }
        };
    }
}
```

### 5.7 使用 Feign 客户端

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class OrderService {
    
    private final UserFeignClient userFeignClient;
    private final ProductFeignClient productFeignClient;
    
    @Transactional(rollbackFor = Exception.class)
    public Order createOrder(OrderDTO orderDTO) {
        // 1. 查询用户信息
        Result<User> userResult = userFeignClient.getById(orderDTO.getUserId());
        if (userResult.getCode() != 200 || userResult.getData() == null) {
            throw new BusinessException("用户不存在");
        }
        User user = userResult.getData();
        
        // 2. 查询商品信息
        Result<Product> productResult = productFeignClient.getById(orderDTO.getProductId());
        if (productResult.getCode() != 200 || productResult.getData() == null) {
            throw new BusinessException("商品不存在");
        }
        Product product = productResult.getData();
        
        // 3. 扣减库存
        Result<Boolean> stockResult = productFeignClient.deductStock(
            orderDTO.getProductId(), orderDTO.getCount());
        if (stockResult.getCode() != 200 || !stockResult.getData()) {
            throw new BusinessException("库存不足");
        }
        
        // 4. 创建订单
        Order order = new Order();
        order.setUserId(user.getId());
        order.setProductId(product.getId());
        order.setCount(orderDTO.getCount());
        order.setAmount(product.getPrice().multiply(new BigDecimal(orderDTO.getCount())));
        order.setStatus(OrderStatus.CREATED);
        
        orderMapper.insert(order);
        
        return order;
    }
}
```


---

## 6. Gateway 网关

### 6.1 Gateway 简介

Spring Cloud Gateway 是 Spring Cloud 官方推出的第二代网关框架，基于 Spring WebFlux 构建，提供了路由、过滤、限流等功能。

**核心概念：**
- **Route（路由）**：网关的基本构建块，由 ID、目标 URI、断言和过滤器组成
- **Predicate（断言）**：匹配 HTTP 请求的条件
- **Filter（过滤器）**：对请求和响应进行处理

### 6.2 添加依赖

```xml
<!-- gateway/pom.xml -->
<dependencies>
    <!-- Gateway -->
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-gateway</artifactId>
    </dependency>
    
    <!-- Nacos 服务发现 -->
    <dependency>
        <groupId>com.alibaba.cloud</groupId>
        <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
    </dependency>
    
    <!-- 负载均衡 -->
    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-loadbalancer</artifactId>
    </dependency>
    
    <!-- Sentinel 限流（可选） -->
    <dependency>
        <groupId>com.alibaba.cloud</groupId>
        <artifactId>spring-cloud-starter-alibaba-sentinel</artifactId>
    </dependency>
    <dependency>
        <groupId>com.alibaba.cloud</groupId>
        <artifactId>spring-cloud-alibaba-sentinel-gateway</artifactId>
    </dependency>
</dependencies>
```

### 6.3 基本配置

```yaml
# gateway/src/main/resources/application.yml
server:
  port: 8080

spring:
  application:
    name: gateway
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
    gateway:
      # 路由配置
      routes:
        # 用户服务路由
        - id: user-service
          uri: lb://user-service
          predicates:
            - Path=/api/user/**
          filters:
            - StripPrefix=1
        
        # 订单服务路由
        - id: order-service
          uri: lb://order-service
          predicates:
            - Path=/api/order/**
          filters:
            - StripPrefix=1
        
        # 商品服务路由
        - id: product-service
          uri: lb://product-service
          predicates:
            - Path=/api/product/**
          filters:
            - StripPrefix=1
      
      # 全局跨域配置
      globalcors:
        cors-configurations:
          '[/**]':
            allowed-origins: "*"
            allowed-methods: "*"
            allowed-headers: "*"
            allow-credentials: true
            max-age: 3600
      
      # 默认过滤器
      default-filters:
        - AddResponseHeader=X-Response-Time, ${spring.cloud.gateway.routes[0].id}
```

### 6.4 断言工厂

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://user-service
          predicates:
            # 路径匹配
            - Path=/api/user/**
            # 请求方法匹配
            - Method=GET,POST
            # 请求头匹配
            - Header=X-Request-Id, \d+
            # Cookie 匹配
            - Cookie=sessionId, .+
            # 查询参数匹配
            - Query=name, .+
            # 时间匹配（在指定时间之后）
            - After=2024-01-01T00:00:00+08:00[Asia/Shanghai]
            # 时间匹配（在指定时间之前）
            - Before=2025-12-31T23:59:59+08:00[Asia/Shanghai]
            # 时间匹配（在指定时间范围内）
            - Between=2024-01-01T00:00:00+08:00[Asia/Shanghai], 2025-12-31T23:59:59+08:00[Asia/Shanghai]
            # 远程地址匹配
            - RemoteAddr=192.168.1.0/24
            # 权重路由
            - Weight=group1, 8
```

### 6.5 过滤器工厂

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://user-service
          predicates:
            - Path=/api/user/**
          filters:
            # 去除路径前缀
            - StripPrefix=1
            # 添加路径前缀
            - PrefixPath=/v1
            # 重写路径
            - RewritePath=/api/(?<segment>.*), /$\{segment}
            # 添加请求头
            - AddRequestHeader=X-Request-Source, gateway
            # 添加响应头
            - AddResponseHeader=X-Response-Time, %{time}
            # 添加请求参数
            - AddRequestParameter=source, gateway
            # 重试
            - name: Retry
              args:
                retries: 3
                statuses: BAD_GATEWAY
                methods: GET
            # 熔断
            - name: CircuitBreaker
              args:
                name: myCircuitBreaker
                fallbackUri: forward:/fallback
            # 限流
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 10
                redis-rate-limiter.burstCapacity: 20
                key-resolver: "#{@ipKeyResolver}"
```

### 6.6 自定义全局过滤器

```java
// 认证过滤器
package com.example.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class AuthGlobalFilter implements GlobalFilter, Ordered {
    
    // 白名单路径
    private static final List<String> WHITE_LIST = Arrays.asList(
        "/api/user/login",
        "/api/user/register",
        "/api/product/list"
    );
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        
        // 白名单放行
        if (isWhiteList(path)) {
            return chain.filter(exchange);
        }
        
        // 获取 Token
        String token = request.getHeaders().getFirst("Authorization");
        
        if (!StringUtils.hasText(token)) {
            log.warn("请求未携带 Token: {}", path);
            return unauthorized(exchange);
        }
        
        // 验证 Token（这里简化处理，实际应该调用认证服务）
        if (!validateToken(token)) {
            log.warn("Token 无效: {}", token);
            return unauthorized(exchange);
        }
        
        // 解析用户信息并传递给下游服务
        String userId = parseUserId(token);
        ServerHttpRequest newRequest = request.mutate()
            .header("X-User-Id", userId)
            .build();
        
        return chain.filter(exchange.mutate().request(newRequest).build());
    }
    
    @Override
    public int getOrder() {
        return -100;  // 优先级最高
    }
    
    private boolean isWhiteList(String path) {
        return WHITE_LIST.stream().anyMatch(path::startsWith);
    }
    
    private boolean validateToken(String token) {
        // 实际应该验证 JWT Token
        return token.startsWith("Bearer ");
    }
    
    private String parseUserId(String token) {
        // 实际应该解析 JWT Token
        return "1";
    }
    
    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }
}
```

```java
// 日志过滤器
@Slf4j
@Component
public class LoggingGlobalFilter implements GlobalFilter, Ordered {
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String method = request.getMethod().name();
        String ip = getClientIp(request);
        
        long startTime = System.currentTimeMillis();
        
        log.info("请求开始: {} {} from {}", method, path, ip);
        
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            long duration = System.currentTimeMillis() - startTime;
            int statusCode = exchange.getResponse().getStatusCode().value();
            log.info("请求结束: {} {} - {} - {}ms", method, path, statusCode, duration);
        }));
    }
    
    @Override
    public int getOrder() {
        return -200;
    }
    
    private String getClientIp(ServerHttpRequest request) {
        String ip = request.getHeaders().getFirst("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddress().getAddress().getHostAddress();
        }
        return ip;
    }
}
```

### 6.7 自定义路由过滤器

```java
// 自定义过滤器工厂
@Component
public class RequestTimeGatewayFilterFactory extends AbstractGatewayFilterFactory<RequestTimeGatewayFilterFactory.Config> {
    
    public RequestTimeGatewayFilterFactory() {
        super(Config.class);
    }
    
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            long startTime = System.currentTimeMillis();
            
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                long duration = System.currentTimeMillis() - startTime;
                if (config.isShowTime()) {
                    exchange.getResponse().getHeaders()
                        .add("X-Response-Time", duration + "ms");
                }
            }));
        };
    }
    
    @Data
    public static class Config {
        private boolean showTime = true;
    }
}
```

```yaml
# 使用自定义过滤器
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://user-service
          predicates:
            - Path=/api/user/**
          filters:
            - RequestTime=true
```


---

## 7. Sentinel 流量控制

### 7.1 Sentinel 简介

Sentinel 是阿里巴巴开源的流量控制组件，以流量为切入点，从流量控制、熔断降级、系统负载保护等多个维度保护服务的稳定性。

**核心功能：**
- **流量控制**：限制 QPS、线程数
- **熔断降级**：慢调用比例、异常比例、异常数
- **热点参数限流**：针对热点参数进行限流
- **系统自适应保护**：根据系统负载自动限流

### 7.2 添加依赖

```xml
<!-- Sentinel -->
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-sentinel</artifactId>
</dependency>

<!-- Sentinel 数据源（Nacos） -->
<dependency>
    <groupId>com.alibaba.csp</groupId>
    <artifactId>sentinel-datasource-nacos</artifactId>
</dependency>
```

### 7.3 配置

```yaml
spring:
  cloud:
    sentinel:
      transport:
        # Sentinel 控制台地址
        dashboard: localhost:8080
        # 与控制台通信的端口
        port: 8719
      # 饥饿加载（启动时加载规则）
      eager: true
      # 规则持久化到 Nacos
      datasource:
        flow:
          nacos:
            server-addr: localhost:8848
            data-id: ${spring.application.name}-flow-rules
            group-id: SENTINEL_GROUP
            data-type: json
            rule-type: flow
        degrade:
          nacos:
            server-addr: localhost:8848
            data-id: ${spring.application.name}-degrade-rules
            group-id: SENTINEL_GROUP
            data-type: json
            rule-type: degrade
```

### 7.4 启动 Sentinel 控制台

```bash
# 下载 Sentinel 控制台
wget https://github.com/alibaba/Sentinel/releases/download/1.8.6/sentinel-dashboard-1.8.6.jar

# 启动
java -Dserver.port=8080 \
     -Dcsp.sentinel.dashboard.server=localhost:8080 \
     -Dproject.name=sentinel-dashboard \
     -jar sentinel-dashboard-1.8.6.jar

# 访问 http://localhost:8080
# 默认账号密码：sentinel/sentinel
```

### 7.5 流量控制

```java
// 使用 @SentinelResource 注解
@RestController
@RequestMapping("/user")
public class UserController {
    
    @GetMapping("/{id}")
    @SentinelResource(
        value = "getUserById",
        blockHandler = "getUserByIdBlockHandler",
        fallback = "getUserByIdFallback"
    )
    public Result<User> getById(@PathVariable Long id) {
        User user = userService.getById(id);
        if (user == null) {
            throw new BusinessException("用户不存在");
        }
        return Result.success(user);
    }
    
    /**
     * 限流/降级处理方法
     * 参数必须与原方法一致，最后加 BlockException
     */
    public Result<User> getUserByIdBlockHandler(Long id, BlockException ex) {
        log.warn("接口被限流: {}", ex.getMessage());
        return Result.error("系统繁忙，请稍后重试");
    }
    
    /**
     * 异常降级处理方法
     * 参数必须与原方法一致，最后加 Throwable
     */
    public Result<User> getUserByIdFallback(Long id, Throwable ex) {
        log.error("接口异常: {}", ex.getMessage());
        return Result.error("服务异常，请稍后重试");
    }
}
```

### 7.6 熔断降级

```java
// 熔断降级配置
@Configuration
public class SentinelConfig {
    
    @PostConstruct
    public void initDegradeRules() {
        List<DegradeRule> rules = new ArrayList<>();
        
        // 慢调用比例熔断
        DegradeRule slowCallRule = new DegradeRule();
        slowCallRule.setResource("getUserById");
        slowCallRule.setGrade(RuleConstant.DEGRADE_GRADE_RT);  // 慢调用比例
        slowCallRule.setCount(500);  // 慢调用阈值（毫秒）
        slowCallRule.setSlowRatioThreshold(0.5);  // 慢调用比例阈值
        slowCallRule.setMinRequestAmount(5);  // 最小请求数
        slowCallRule.setStatIntervalMs(10000);  // 统计时长
        slowCallRule.setTimeWindow(10);  // 熔断时长（秒）
        rules.add(slowCallRule);
        
        // 异常比例熔断
        DegradeRule exceptionRatioRule = new DegradeRule();
        exceptionRatioRule.setResource("createOrder");
        exceptionRatioRule.setGrade(RuleConstant.DEGRADE_GRADE_EXCEPTION_RATIO);
        exceptionRatioRule.setCount(0.5);  // 异常比例阈值
        exceptionRatioRule.setMinRequestAmount(5);
        exceptionRatioRule.setStatIntervalMs(10000);
        exceptionRatioRule.setTimeWindow(10);
        rules.add(exceptionRatioRule);
        
        // 异常数熔断
        DegradeRule exceptionCountRule = new DegradeRule();
        exceptionCountRule.setResource("deleteUser");
        exceptionCountRule.setGrade(RuleConstant.DEGRADE_GRADE_EXCEPTION_COUNT);
        exceptionCountRule.setCount(5);  // 异常数阈值
        exceptionCountRule.setMinRequestAmount(5);
        exceptionCountRule.setStatIntervalMs(60000);
        exceptionCountRule.setTimeWindow(30);
        rules.add(exceptionCountRule);
        
        DegradeRuleManager.loadRules(rules);
    }
}
```

### 7.7 热点参数限流

```java
@GetMapping("/product/{id}")
@SentinelResource(
    value = "getProductById",
    blockHandler = "getProductByIdBlockHandler"
)
public Result<Product> getProductById(@PathVariable Long id) {
    return Result.success(productService.getById(id));
}

// 配置热点参数规则
@PostConstruct
public void initParamFlowRules() {
    ParamFlowRule rule = new ParamFlowRule();
    rule.setResource("getProductById");
    rule.setParamIdx(0);  // 第一个参数
    rule.setCount(10);    // QPS 阈值
    rule.setGrade(RuleConstant.FLOW_GRADE_QPS);
    
    // 针对特定参数值设置不同阈值
    ParamFlowItem item = new ParamFlowItem();
    item.setObject("1");  // 参数值
    item.setClassType(Long.class.getName());
    item.setCount(5);     // 该参数值的 QPS 阈值
    rule.setParamFlowItemList(Collections.singletonList(item));
    
    ParamFlowRuleManager.loadRules(Collections.singletonList(rule));
}
```

### 7.8 Feign 整合 Sentinel

```yaml
# 开启 Feign 对 Sentinel 的支持
spring:
  cloud:
    openfeign:
      sentinel:
        enabled: true
```

```java
// Feign 客户端自动支持 Sentinel
@FeignClient(
    name = "user-service",
    fallback = UserFeignFallback.class
)
public interface UserFeignClient {
    
    @GetMapping("/user/{id}")
    Result<User> getById(@PathVariable("id") Long id);
}

// 降级处理
@Component
public class UserFeignFallback implements UserFeignClient {
    
    @Override
    public Result<User> getById(Long id) {
        return Result.error("用户服务不可用");
    }
}
```

### 7.9 规则持久化到 Nacos

```json
// Nacos 配置：user-service-flow-rules
[
    {
        "resource": "getUserById",
        "limitApp": "default",
        "grade": 1,
        "count": 100,
        "strategy": 0,
        "controlBehavior": 0,
        "clusterMode": false
    }
]

// Nacos 配置：user-service-degrade-rules
[
    {
        "resource": "getUserById",
        "grade": 0,
        "count": 500,
        "slowRatioThreshold": 0.5,
        "minRequestAmount": 5,
        "statIntervalMs": 10000,
        "timeWindow": 10
    }
]
```

---

## 8. Seata 分布式事务

### 8.1 Seata 简介

Seata 是阿里巴巴开源的分布式事务解决方案，提供了 AT、TCC、SAGA 和 XA 四种事务模式。

**核心概念：**
- **TC（Transaction Coordinator）**：事务协调器，维护全局事务的运行状态
- **TM（Transaction Manager）**：事务管理器，定义全局事务的范围
- **RM（Resource Manager）**：资源管理器，管理分支事务

### 8.2 Seata Server 部署

```bash
# Docker 部署
docker run -d \
  --name seata-server \
  -p 8091:8091 \
  -p 7091:7091 \
  -e SEATA_IP=192.168.1.100 \
  -e SEATA_PORT=8091 \
  seataio/seata-server:2.0.0
```

### 8.3 添加依赖

```xml
<!-- Seata -->
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-seata</artifactId>
</dependency>
```

### 8.4 配置

```yaml
# application.yml
seata:
  enabled: true
  application-id: ${spring.application.name}
  tx-service-group: my_tx_group
  registry:
    type: nacos
    nacos:
      server-addr: localhost:8848
      namespace: ""
      group: SEATA_GROUP
      application: seata-server
  config:
    type: nacos
    nacos:
      server-addr: localhost:8848
      namespace: ""
      group: SEATA_GROUP
      data-id: seataServer.properties
```

### 8.5 AT 模式（推荐）

AT 模式是 Seata 默认的事务模式，基于本地事务的两阶段提交协议。

```java
// 订单服务 - 全局事务发起方
@Service
@RequiredArgsConstructor
@Slf4j
public class OrderService {
    
    private final OrderMapper orderMapper;
    private final ProductFeignClient productFeignClient;
    private final AccountFeignClient accountFeignClient;
    
    /**
     * 创建订单（分布式事务）
     */
    @GlobalTransactional(name = "create-order", rollbackFor = Exception.class)
    public Order createOrder(OrderDTO orderDTO) {
        log.info("开始创建订单，XID: {}", RootContext.getXID());
        
        // 1. 创建订单
        Order order = new Order();
        order.setUserId(orderDTO.getUserId());
        order.setProductId(orderDTO.getProductId());
        order.setCount(orderDTO.getCount());
        order.setStatus(OrderStatus.CREATED);
        orderMapper.insert(order);
        
        // 2. 扣减库存（远程调用）
        Result<Boolean> stockResult = productFeignClient.deductStock(
            orderDTO.getProductId(), orderDTO.getCount());
        if (stockResult.getCode() != 200 || !stockResult.getData()) {
            throw new BusinessException("扣减库存失败");
        }
        
        // 3. 扣减余额（远程调用）
        Result<Boolean> accountResult = accountFeignClient.deductBalance(
            orderDTO.getUserId(), order.getAmount());
        if (accountResult.getCode() != 200 || !accountResult.getData()) {
            throw new BusinessException("扣减余额失败");
        }
        
        // 4. 更新订单状态
        order.setStatus(OrderStatus.PAID);
        orderMapper.updateById(order);
        
        log.info("订单创建成功: {}", order.getId());
        return order;
    }
}
```

```java
// 商品服务 - 分支事务参与方
@Service
@RequiredArgsConstructor
public class ProductService {
    
    private final ProductMapper productMapper;
    
    /**
     * 扣减库存
     * 不需要 @GlobalTransactional，Seata 会自动管理分支事务
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean deductStock(Long productId, Integer count) {
        Product product = productMapper.selectById(productId);
        if (product == null) {
            throw new BusinessException("商品不存在");
        }
        if (product.getStock() < count) {
            throw new BusinessException("库存不足");
        }
        
        // 扣减库存
        int rows = productMapper.deductStock(productId, count);
        return rows > 0;
    }
}
```

```sql
-- 需要在每个数据库中创建 undo_log 表
CREATE TABLE `undo_log` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `branch_id` BIGINT NOT NULL,
    `xid` VARCHAR(100) NOT NULL,
    `context` VARCHAR(128) NOT NULL,
    `rollback_info` LONGBLOB NOT NULL,
    `log_status` INT NOT NULL,
    `log_created` DATETIME NOT NULL,
    `log_modified` DATETIME NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `ux_undo_log` (`xid`, `branch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 8.6 TCC 模式

TCC 模式需要手动实现 Try、Confirm、Cancel 三个方法。

```java
// TCC 接口定义
@LocalTCC
public interface AccountTccService {
    
    /**
     * Try 阶段：预留资源
     */
    @TwoPhaseBusinessAction(
        name = "deductBalance",
        commitMethod = "confirm",
        rollbackMethod = "cancel"
    )
    boolean tryDeduct(
        @BusinessActionContextParameter(paramName = "userId") Long userId,
        @BusinessActionContextParameter(paramName = "amount") BigDecimal amount
    );
    
    /**
     * Confirm 阶段：确认提交
     */
    boolean confirm(BusinessActionContext context);
    
    /**
     * Cancel 阶段：回滚
     */
    boolean cancel(BusinessActionContext context);
}

// TCC 实现
@Service
@Slf4j
public class AccountTccServiceImpl implements AccountTccService {
    
    @Autowired
    private AccountMapper accountMapper;
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean tryDeduct(Long userId, BigDecimal amount) {
        log.info("TCC Try: userId={}, amount={}", userId, amount);
        
        // 检查余额并冻结
        Account account = accountMapper.selectById(userId);
        if (account.getBalance().compareTo(amount) < 0) {
            throw new BusinessException("余额不足");
        }
        
        // 冻结金额
        accountMapper.freezeBalance(userId, amount);
        return true;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean confirm(BusinessActionContext context) {
        Long userId = (Long) context.getActionContext("userId");
        BigDecimal amount = (BigDecimal) context.getActionContext("amount");
        
        log.info("TCC Confirm: userId={}, amount={}", userId, amount);
        
        // 扣减冻结金额
        accountMapper.deductFrozenBalance(userId, amount);
        return true;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean cancel(BusinessActionContext context) {
        Long userId = (Long) context.getActionContext("userId");
        BigDecimal amount = (BigDecimal) context.getActionContext("amount");
        
        log.info("TCC Cancel: userId={}, amount={}", userId, amount);
        
        // 解冻金额
        accountMapper.unfreezeBalance(userId, amount);
        return true;
    }
}
```


---

## 9. RocketMQ 消息队列

### 9.1 RocketMQ 简介

RocketMQ 是阿里巴巴开源的分布式消息中间件，具有高性能、高可靠、高实时、分布式等特点。

### 9.2 RocketMQ 部署

```bash
# Docker 部署
# 启动 NameServer
docker run -d \
  --name rmqnamesrv \
  -p 9876:9876 \
  apache/rocketmq:5.1.0 \
  sh mqnamesrv

# 启动 Broker
docker run -d \
  --name rmqbroker \
  -p 10911:10911 \
  -p 10909:10909 \
  -e "NAMESRV_ADDR=rmqnamesrv:9876" \
  --link rmqnamesrv:rmqnamesrv \
  apache/rocketmq:5.1.0 \
  sh mqbroker -n rmqnamesrv:9876

# 启动控制台
docker run -d \
  --name rmqconsole \
  -p 8180:8080 \
  -e "JAVA_OPTS=-Drocketmq.namesrv.addr=rmqnamesrv:9876" \
  --link rmqnamesrv:rmqnamesrv \
  apacherocketmq/rocketmq-console:2.0.0
```

### 9.3 添加依赖

```xml
<!-- RocketMQ -->
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-rocketmq</artifactId>
</dependency>
```

### 9.4 配置

```yaml
spring:
  cloud:
    stream:
      rocketmq:
        binder:
          name-server: localhost:9876
      bindings:
        # 生产者
        order-output:
          destination: order-topic
          content-type: application/json
        # 消费者
        order-input:
          destination: order-topic
          content-type: application/json
          group: order-consumer-group
```

### 9.5 消息生产者

```java
// 方式一：使用 StreamBridge
@Service
@RequiredArgsConstructor
@Slf4j
public class OrderMessageProducer {
    
    private final StreamBridge streamBridge;
    
    /**
     * 发送订单消息
     */
    public void sendOrderMessage(OrderMessage message) {
        log.info("发送订单消息: {}", message);
        streamBridge.send("order-output", message);
    }
    
    /**
     * 发送延迟消息
     */
    public void sendDelayMessage(OrderMessage message, int delayLevel) {
        log.info("发送延迟消息: {}, delayLevel: {}", message, delayLevel);
        streamBridge.send("order-output", 
            MessageBuilder.withPayload(message)
                .setHeader("DELAY", delayLevel)
                .build());
    }
}

// 方式二：使用 RocketMQTemplate
@Service
@RequiredArgsConstructor
@Slf4j
public class RocketMQProducer {
    
    private final RocketMQTemplate rocketMQTemplate;
    
    /**
     * 发送同步消息
     */
    public void sendSync(String topic, Object message) {
        SendResult result = rocketMQTemplate.syncSend(topic, message);
        log.info("同步消息发送结果: {}", result);
    }
    
    /**
     * 发送异步消息
     */
    public void sendAsync(String topic, Object message) {
        rocketMQTemplate.asyncSend(topic, message, new SendCallback() {
            @Override
            public void onSuccess(SendResult sendResult) {
                log.info("异步消息发送成功: {}", sendResult);
            }
            
            @Override
            public void onException(Throwable e) {
                log.error("异步消息发送失败: ", e);
            }
        });
    }
    
    /**
     * 发送单向消息
     */
    public void sendOneWay(String topic, Object message) {
        rocketMQTemplate.sendOneWay(topic, message);
    }
    
    /**
     * 发送延迟消息
     * delayLevel: 1-18 对应 1s 5s 10s 30s 1m 2m 3m 4m 5m 6m 7m 8m 9m 10m 20m 30m 1h 2h
     */
    public void sendDelay(String topic, Object message, int delayLevel) {
        rocketMQTemplate.syncSend(topic, 
            MessageBuilder.withPayload(message).build(), 
            3000, delayLevel);
    }
    
    /**
     * 发送顺序消息
     */
    public void sendOrderly(String topic, Object message, String hashKey) {
        rocketMQTemplate.syncSendOrderly(topic, message, hashKey);
    }
    
    /**
     * 发送事务消息
     */
    public void sendTransaction(String topic, Object message) {
        rocketMQTemplate.sendMessageInTransaction(topic, 
            MessageBuilder.withPayload(message).build(), null);
    }
}
```

### 9.6 消息消费者

```java
// 方式一：使用 @StreamListener（已废弃，推荐使用函数式）
// 方式二：使用函数式编程
@Configuration
public class OrderMessageConsumer {
    
    @Bean
    public Consumer<OrderMessage> orderInput() {
        return message -> {
            log.info("收到订单消息: {}", message);
            // 处理消息
            processOrder(message);
        };
    }
    
    private void processOrder(OrderMessage message) {
        // 业务处理逻辑
    }
}

// 方式三：使用 @RocketMQMessageListener
@Component
@RocketMQMessageListener(
    topic = "order-topic",
    consumerGroup = "order-consumer-group",
    selectorExpression = "*"
)
@Slf4j
public class OrderMessageListener implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到订单消息: {}", message);
        try {
            // 处理消息
            processOrder(message);
        } catch (Exception e) {
            log.error("处理订单消息失败: ", e);
            throw new RuntimeException(e);  // 抛出异常会触发重试
        }
    }
    
    private void processOrder(OrderMessage message) {
        // 业务处理逻辑
    }
}

// 顺序消息消费者
@Component
@RocketMQMessageListener(
    topic = "order-topic",
    consumerGroup = "order-orderly-consumer-group",
    consumeMode = ConsumeMode.ORDERLY
)
public class OrderlyMessageListener implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到顺序消息: {}", message);
    }
}
```

### 9.7 事务消息

```java
// 事务消息监听器
@RocketMQTransactionListener
@Slf4j
public class OrderTransactionListener implements RocketMQLocalTransactionListener {
    
    @Autowired
    private OrderService orderService;
    
    /**
     * 执行本地事务
     */
    @Override
    public RocketMQLocalTransactionState executeLocalTransaction(Message msg, Object arg) {
        try {
            OrderMessage orderMessage = JSON.parseObject(new String((byte[]) msg.getPayload()), OrderMessage.class);
            
            // 执行本地事务
            orderService.createOrder(orderMessage);
            
            log.info("本地事务执行成功");
            return RocketMQLocalTransactionState.COMMIT;
            
        } catch (Exception e) {
            log.error("本地事务执行失败: ", e);
            return RocketMQLocalTransactionState.ROLLBACK;
        }
    }
    
    /**
     * 事务回查
     */
    @Override
    public RocketMQLocalTransactionState checkLocalTransaction(Message msg) {
        OrderMessage orderMessage = JSON.parseObject(new String((byte[]) msg.getPayload()), OrderMessage.class);
        
        // 查询订单是否存在
        Order order = orderService.getByOrderNo(orderMessage.getOrderNo());
        
        if (order != null) {
            log.info("事务回查：订单存在，提交事务");
            return RocketMQLocalTransactionState.COMMIT;
        } else {
            log.info("事务回查：订单不存在，回滚事务");
            return RocketMQLocalTransactionState.ROLLBACK;
        }
    }
}
```

---

## 10. 链路追踪

### 10.1 Micrometer Tracing

Spring Boot 3.x 使用 Micrometer Tracing 替代了 Spring Cloud Sleuth。

```xml
<!-- 链路追踪 -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing-bridge-brave</artifactId>
</dependency>

<!-- Zipkin 报告器 -->
<dependency>
    <groupId>io.zipkin.reporter2</groupId>
    <artifactId>zipkin-reporter-brave</artifactId>
</dependency>

<!-- Feign 追踪 -->
<dependency>
    <groupId>io.github.openfeign</groupId>
    <artifactId>feign-micrometer</artifactId>
</dependency>
```

### 10.2 配置

```yaml
management:
  tracing:
    sampling:
      probability: 1.0  # 采样率，1.0 表示全部采样
  zipkin:
    tracing:
      endpoint: http://localhost:9411/api/v2/spans

logging:
  pattern:
    level: "%5p [${spring.application.name:},%X{traceId:-},%X{spanId:-}]"
```

### 10.3 启动 Zipkin

```bash
# Docker 启动 Zipkin
docker run -d \
  --name zipkin \
  -p 9411:9411 \
  openzipkin/zipkin

# 访问 http://localhost:9411
```

### 10.4 自定义 Span

```java
@Service
@RequiredArgsConstructor
public class OrderService {
    
    private final Tracer tracer;
    
    public Order createOrder(OrderDTO orderDTO) {
        // 创建自定义 Span
        Span span = tracer.nextSpan().name("createOrder").start();
        
        try (Tracer.SpanInScope ws = tracer.withSpan(span)) {
            // 添加标签
            span.tag("userId", String.valueOf(orderDTO.getUserId()));
            span.tag("productId", String.valueOf(orderDTO.getProductId()));
            
            // 业务逻辑
            Order order = doCreateOrder(orderDTO);
            
            // 添加事件
            span.event("order created");
            
            return order;
        } catch (Exception e) {
            span.error(e);
            throw e;
        } finally {
            span.end();
        }
    }
}
```

---

## 11. 服务监控

### 11.1 Spring Boot Actuator

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

```yaml
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    health:
      show-details: always
```

### 11.2 Prometheus + Grafana

```xml
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>
```

```yaml
management:
  metrics:
    export:
      prometheus:
        enabled: true
    tags:
      application: ${spring.application.name}
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'spring-cloud'
    metrics_path: '/actuator/prometheus'
    static_configs:
      - targets: ['user-service:8081', 'order-service:8082']
```

### 11.3 自定义指标

```java
@Component
@RequiredArgsConstructor
public class OrderMetrics {
    
    private final MeterRegistry meterRegistry;
    
    private Counter orderCounter;
    private Timer orderTimer;
    
    @PostConstruct
    public void init() {
        orderCounter = Counter.builder("order.created.count")
            .description("订单创建数量")
            .tag("service", "order-service")
            .register(meterRegistry);
        
        orderTimer = Timer.builder("order.created.time")
            .description("订单创建耗时")
            .tag("service", "order-service")
            .register(meterRegistry);
    }
    
    public void recordOrderCreated() {
        orderCounter.increment();
    }
    
    public void recordOrderTime(long timeMs) {
        orderTimer.record(timeMs, TimeUnit.MILLISECONDS);
    }
}
```


---

## 12. Docker 部署

### 12.1 Dockerfile

```dockerfile
# 多阶段构建
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# 设置时区
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

# 复制 jar 包
COPY --from=builder /app/target/*.jar app.jar

# 暴露端口
EXPOSE 8080

# 启动命令
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 12.2 Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  # Nacos
  nacos:
    image: nacos/nacos-server:v2.3.0
    container_name: nacos
    environment:
      - MODE=standalone
      - NACOS_AUTH_ENABLE=true
      - NACOS_AUTH_TOKEN=SecretKey012345678901234567890123456789012345678901234567890123456789
    ports:
      - "8848:8848"
      - "9848:9848"
    networks:
      - cloud-network

  # Sentinel
  sentinel:
    image: bladex/sentinel-dashboard:1.8.6
    container_name: sentinel
    ports:
      - "8858:8858"
    networks:
      - cloud-network

  # MySQL
  mysql:
    image: mysql:8.0
    container_name: mysql
    environment:
      - MYSQL_ROOT_PASSWORD=root
      - MYSQL_DATABASE=cloud_db
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql
    networks:
      - cloud-network

  # Redis
  redis:
    image: redis:7-alpine
    container_name: redis
    ports:
      - "6379:6379"
    networks:
      - cloud-network

  # Gateway
  gateway:
    build:
      context: ./gateway
      dockerfile: Dockerfile
    container_name: gateway
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - NACOS_SERVER_ADDR=nacos:8848
    depends_on:
      - nacos
    networks:
      - cloud-network

  # User Service
  user-service:
    build:
      context: ./user-service
      dockerfile: Dockerfile
    container_name: user-service
    ports:
      - "8081:8081"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - NACOS_SERVER_ADDR=nacos:8848
      - MYSQL_HOST=mysql
    depends_on:
      - nacos
      - mysql
    networks:
      - cloud-network

  # Order Service
  order-service:
    build:
      context: ./order-service
      dockerfile: Dockerfile
    container_name: order-service
    ports:
      - "8082:8082"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - NACOS_SERVER_ADDR=nacos:8848
      - MYSQL_HOST=mysql
    depends_on:
      - nacos
      - mysql
    networks:
      - cloud-network

networks:
  cloud-network:
    driver: bridge

volumes:
  mysql-data:
```

### 12.3 Kubernetes 部署

```yaml
# user-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
  labels:
    app: user-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
        - name: user-service
          image: user-service:1.0.0
          ports:
            - containerPort: 8081
          env:
            - name: SPRING_PROFILES_ACTIVE
              value: "k8s"
            - name: NACOS_SERVER_ADDR
              value: "nacos:8848"
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: 8081
            initialDelaySeconds: 60
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: 8081
            initialDelaySeconds: 30
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-service
  ports:
    - port: 8081
      targetPort: 8081
  type: ClusterIP
```

---

## 13. 常见错误与解决方案

### 13.1 Nacos 连接失败

**错误信息：**
```
com.alibaba.nacos.api.exception.NacosException: failed to req API
```

**解决方案：**
```yaml
# 检查 Nacos 地址配置
spring:
  cloud:
    nacos:
      discovery:
        server-addr: localhost:8848
        # 如果开启了认证
        username: nacos
        password: nacos
```

```bash
# 检查 Nacos 是否启动
curl http://localhost:8848/nacos/v1/ns/service/list
```

### 13.2 Feign 调用超时

**错误信息：**
```
feign.RetryableException: Read timed out executing GET
```

**解决方案：**
```yaml
spring:
  cloud:
    openfeign:
      client:
        config:
          default:
            connect-timeout: 10000
            read-timeout: 30000
```

### 13.3 Sentinel 规则不生效

**原因：**
1. 资源名称不匹配
2. 规则未正确加载
3. Sentinel 控制台未连接

**解决方案：**
```yaml
spring:
  cloud:
    sentinel:
      transport:
        dashboard: localhost:8080
      eager: true  # 饥饿加载
```

```java
// 检查资源名称
@SentinelResource(value = "getUserById")  // 确保名称一致
```

### 13.4 Seata 事务不回滚

**原因：**
1. 未添加 @GlobalTransactional 注解
2. 异常被捕获未抛出
3. undo_log 表不存在

**解决方案：**
```java
@GlobalTransactional(rollbackFor = Exception.class)
public void createOrder() {
    // 不要捕获异常，让 Seata 处理
}
```

```sql
-- 确保每个数据库都有 undo_log 表
CREATE TABLE `undo_log` (...);
```

### 13.5 Gateway 路由不生效

**原因：**
1. 路由配置错误
2. 服务未注册到 Nacos
3. 断言条件不匹配

**解决方案：**
```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: user-service
          uri: lb://user-service  # 确保服务名正确
          predicates:
            - Path=/api/user/**
          filters:
            - StripPrefix=1
```

### 13.6 配置不刷新

**原因：**
1. 未添加 @RefreshScope
2. bootstrap.yml 配置错误
3. 缺少 spring-cloud-starter-bootstrap 依赖

**解决方案：**
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-bootstrap</artifactId>
</dependency>
```

```java
@RefreshScope
@RestController
public class ConfigController {
    @Value("${app.name}")
    private String appName;
}
```

### 13.7 负载均衡不生效

**原因：** 缺少 LoadBalancer 依赖

**解决方案：**
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```

### 13.8 循环依赖

**错误信息：**
```
The dependencies of some of the beans in the application context form a cycle
```

**解决方案：**
```java
// 使用 @Lazy 延迟加载
@Service
public class OrderService {
    
    @Lazy
    @Autowired
    private UserService userService;
}

// 或使用 Setter 注入
@Service
public class OrderService {
    
    private UserService userService;
    
    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }
}
```


---

## 14. 最佳实践

### 14.1 项目结构规范

```
cloud-demo/
├── pom.xml                          # 父工程
├── common/                          # 公共模块
│   ├── common-core/                 # 核心工具类
│   ├── common-web/                  # Web 相关
│   ├── common-redis/                # Redis 相关
│   └── common-feign/                # Feign 相关
├── gateway/                         # 网关服务
├── auth-service/                    # 认证服务
├── user-service/                    # 用户服务
│   ├── user-api/                    # API 模块（Feign 接口）
│   └── user-biz/                    # 业务模块
├── order-service/                   # 订单服务
│   ├── order-api/
│   └── order-biz/
└── product-service/                 # 商品服务
    ├── product-api/
    └── product-biz/
```

### 14.2 API 模块设计

```java
// user-api 模块
// 定义 Feign 接口和 DTO，供其他服务依赖

// UserFeignClient.java
@FeignClient(name = "user-service", fallbackFactory = UserFeignFallbackFactory.class)
public interface UserFeignClient {
    
    @GetMapping("/user/{id}")
    Result<UserDTO> getById(@PathVariable("id") Long id);
}

// UserDTO.java
@Data
public class UserDTO {
    private Long id;
    private String username;
    private String email;
}

// UserFeignFallbackFactory.java
@Component
public class UserFeignFallbackFactory implements FallbackFactory<UserFeignClient> {
    @Override
    public UserFeignClient create(Throwable cause) {
        return new UserFeignClient() {
            @Override
            public Result<UserDTO> getById(Long id) {
                return Result.error("用户服务不可用: " + cause.getMessage());
            }
        };
    }
}
```

### 14.3 统一异常处理

```java
// 业务异常码枚举
public enum ErrorCode {
    SUCCESS(200, "成功"),
    BAD_REQUEST(400, "请求参数错误"),
    UNAUTHORIZED(401, "未授权"),
    FORBIDDEN(403, "禁止访问"),
    NOT_FOUND(404, "资源不存在"),
    INTERNAL_ERROR(500, "系统内部错误"),
    SERVICE_UNAVAILABLE(503, "服务不可用"),
    
    // 业务错误码
    USER_NOT_FOUND(10001, "用户不存在"),
    USER_ALREADY_EXISTS(10002, "用户已存在"),
    ORDER_NOT_FOUND(20001, "订单不存在"),
    STOCK_NOT_ENOUGH(30001, "库存不足");
    
    private final int code;
    private final String message;
    
    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }
    
    public int getCode() { return code; }
    public String getMessage() { return message; }
}

// 业务异常
public class BusinessException extends RuntimeException {
    private final ErrorCode errorCode;
    
    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
    
    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public ErrorCode getErrorCode() { return errorCode; }
}

// 全局异常处理
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    @ExceptionHandler(BusinessException.class)
    public Result<?> handleBusinessException(BusinessException e) {
        log.warn("业务异常: {}", e.getMessage());
        return Result.error(e.getErrorCode().getCode(), e.getMessage());
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<?> handleValidationException(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
            .map(FieldError::getDefaultMessage)
            .collect(Collectors.joining(", "));
        return Result.error(ErrorCode.BAD_REQUEST.getCode(), message);
    }
    
    @ExceptionHandler(Exception.class)
    public Result<?> handleException(Exception e) {
        log.error("系统异常: ", e);
        return Result.error(ErrorCode.INTERNAL_ERROR.getCode(), "系统繁忙，请稍后重试");
    }
}
```

### 14.4 服务间调用规范

```java
// 1. 使用 Feign 客户端调用
@Service
@RequiredArgsConstructor
public class OrderService {
    
    private final UserFeignClient userFeignClient;
    
    public Order createOrder(OrderDTO dto) {
        // 调用用户服务
        Result<UserDTO> result = userFeignClient.getById(dto.getUserId());
        
        // 检查调用结果
        if (result.getCode() != 200 || result.getData() == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        
        // 业务逻辑
        // ...
    }
}

// 2. 传递请求头（Token、TraceId 等）
@Configuration
public class FeignConfig {
    
    @Bean
    public RequestInterceptor requestInterceptor() {
        return template -> {
            ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                
                // 传递 Token
                String token = request.getHeader("Authorization");
                if (StringUtils.hasText(token)) {
                    template.header("Authorization", token);
                }
                
                // 传递 TraceId
                String traceId = request.getHeader("X-Trace-Id");
                if (StringUtils.hasText(traceId)) {
                    template.header("X-Trace-Id", traceId);
                }
            }
        };
    }
}
```

### 14.5 配置管理规范

```yaml
# Nacos 配置命名规范
# {服务名}-{环境}.yaml

# 公共配置：common.yaml
spring:
  jackson:
    date-format: yyyy-MM-dd HH:mm:ss
    time-zone: Asia/Shanghai

# 服务配置：user-service-dev.yaml
server:
  port: 8081

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/user_db
    username: root
    password: ${MYSQL_PASSWORD:root}

# 敏感配置使用环境变量
app:
  jwt:
    secret: ${JWT_SECRET:default-secret}
```

### 14.6 日志规范

```yaml
# logback-spring.xml
logging:
  level:
    root: INFO
    com.example: DEBUG
    org.springframework.cloud: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] [%X{traceId}] %-5level %logger{36} - %msg%n"
  file:
    name: logs/${spring.application.name}.log
```

```java
// 日志使用规范
@Slf4j
@Service
public class OrderService {
    
    public Order createOrder(OrderDTO dto) {
        log.info("开始创建订单, userId={}, productId={}", dto.getUserId(), dto.getProductId());
        
        try {
            // 业务逻辑
            Order order = doCreateOrder(dto);
            log.info("订单创建成功, orderId={}", order.getId());
            return order;
        } catch (Exception e) {
            log.error("订单创建失败, userId={}, error={}", dto.getUserId(), e.getMessage(), e);
            throw e;
        }
    }
}
```

### 14.7 健康检查

```java
// 自定义健康检查
@Component
public class DatabaseHealthIndicator implements HealthIndicator {
    
    @Autowired
    private DataSource dataSource;
    
    @Override
    public Health health() {
        try (Connection conn = dataSource.getConnection()) {
            if (conn.isValid(1)) {
                return Health.up()
                    .withDetail("database", "MySQL")
                    .withDetail("status", "connected")
                    .build();
            }
        } catch (SQLException e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .build();
        }
        return Health.down().build();
    }
}
```

```yaml
# 健康检查配置
management:
  endpoint:
    health:
      show-details: always
      probes:
        enabled: true
  health:
    livenessstate:
      enabled: true
    readinessstate:
      enabled: true
```

### 14.8 版本管理

```xml
<!-- 统一版本管理 -->
<properties>
    <java.version>17</java.version>
    <spring-boot.version>3.2.12</spring-boot.version>
    <spring-cloud.version>2023.0.1</spring-cloud.version>
    <spring-cloud-alibaba.version>2023.0.1.0</spring-cloud-alibaba.version>
    
    <!-- 其他依赖版本 -->
    <mybatis-plus.version>3.5.5</mybatis-plus.version>
    <hutool.version>5.8.25</hutool.version>
</properties>
```

---

## 总结

Spring Cloud Alibaba 提供了一套完整的微服务解决方案，通过本笔记的学习，你应该能够：

1. **理解微服务架构**：掌握微服务的核心概念和设计原则
2. **服务注册与发现**：使用 Nacos 实现服务的注册和发现
3. **配置中心**：使用 Nacos 实现配置的集中管理和动态刷新
4. **服务调用**：使用 OpenFeign 实现声明式的服务调用
5. **API 网关**：使用 Gateway 实现路由、限流、鉴权等功能
6. **流量控制**：使用 Sentinel 实现限流、熔断、降级
7. **分布式事务**：使用 Seata 实现分布式事务
8. **消息队列**：使用 RocketMQ 实现异步通信
9. **链路追踪**：使用 Micrometer Tracing 实现分布式链路追踪
10. **服务监控**：使用 Actuator + Prometheus + Grafana 实现监控
11. **容器化部署**：使用 Docker 和 Kubernetes 部署微服务

**推荐资源：**
- [Spring Cloud Alibaba 官方文档](https://spring-cloud-alibaba-group.github.io/github-pages/2023/zh-cn/)
- [Nacos 官方文档](https://nacos.io/zh-cn/docs/what-is-nacos.html)
- [Sentinel 官方文档](https://sentinelguard.io/zh-cn/docs/introduction.html)
- [Seata 官方文档](https://seata.io/zh-cn/docs/overview/what-is-seata.html)
- [Spring Cloud 官方文档](https://spring.io/projects/spring-cloud)