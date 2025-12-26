# Spring Boot 3 完整学习笔记

> Spring Boot 3 是 Spring 生态系统的重大升级版本，基于 Spring Framework 6
> 本笔记基于 Java 17 + Spring Boot 3.2.12
> 重点对比 Spring Boot 2.x 的变化

---

## 目录

1. [Spring Boot 3 概述](#1-spring-boot-3-概述)
2. [环境要求与项目搭建](#2-环境要求与项目搭建)
3. [核心变化对比](#3-核心变化对比)
4. [Jakarta EE 迁移](#4-jakarta-ee-迁移)
5. [新特性详解](#5-新特性详解)
6. [配置文件变化](#6-配置文件变化)
7. [Web 开发](#7-web-开发)
8. [数据访问](#8-数据访问)
9. [安全框架](#9-安全框架)
10. [可观测性](#10-可观测性)
11. [GraalVM 原生镜像](#11-graalvm-原生镜像)
12. [迁移指南](#12-迁移指南)
13. [常见错误与解决方案](#13-常见错误与解决方案)
14. [最佳实践](#14-最佳实践)

---

## 1. Spring Boot 3 概述

### 1.1 什么是 Spring Boot 3？

Spring Boot 3 是 Spring Boot 的一个重大版本更新，于 2022 年 11 月发布。它基于 Spring Framework 6，带来了许多重要的变化和新特性。

**核心变化**：
- 最低要求 Java 17（不再支持 Java 8、11）
- 从 Java EE 迁移到 Jakarta EE 9+
- 支持 GraalVM 原生镜像编译
- 全面支持虚拟线程（Java 21）
- 增强的可观测性支持

### 1.2 版本对比

| 特性 | Spring Boot 2.7.x | Spring Boot 3.2.x |
|------|-------------------|-------------------|
| 最低 Java 版本 | Java 8 | Java 17 |
| Spring Framework | 5.3.x | 6.1.x |
| Jakarta EE | Java EE 8 (javax.*) | Jakarta EE 10 (jakarta.*) |
| 原生镜像 | 实验性支持 | 正式支持 |
| 虚拟线程 | 不支持 | 支持（Java 21） |
| Hibernate | 5.6.x | 6.4.x |
| 可观测性 | Micrometer | Micrometer + Observation API |

### 1.3 为什么要升级到 Spring Boot 3？

1. **长期支持**：Spring Boot 2.7 已于 2023 年 11 月停止维护
2. **性能提升**：原生镜像启动速度提升 10 倍以上
3. **新特性**：虚拟线程、Record 类型支持等
4. **安全更新**：持续的安全补丁和漏洞修复
5. **生态系统**：越来越多的库只支持 Spring Boot 3


---

## 2. 环境要求与项目搭建

### 2.1 环境要求

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Spring Boot 3.2.x 环境要求                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Java 版本：Java 17 ~ 21（推荐 Java 21）                                    │
│  构建工具：Maven 3.6.3+ 或 Gradle 7.5+                                      │
│  IDE：IntelliJ IDEA 2023.1+ 或 Eclipse 2023-03+                            │
│                                                                             │
│  注意：Java 8、11、16 都不再支持！                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 创建项目

#### 方式1：Spring Initializr（推荐）

访问 https://start.spring.io/

```
Project: Maven
Language: Java
Spring Boot: 3.2.12
Packaging: Jar
Java: 17 或 21

Dependencies:
- Spring Web
- Spring Data JPA
- MySQL Driver
- Lombok
- Validation
```

#### 方式2：Maven pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <!-- Spring Boot 3 父项目 -->
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.12</version>
        <relativePath/>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <name>demo</name>
    <description>Spring Boot 3 Demo</description>
    
    <!-- 必须使用 Java 17+ -->
    <properties>
        <java.version>17</java.version>
    </properties>
    
    <dependencies>
        <!-- Web Starter -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- Data JPA -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        
        <!-- Validation（注意：不再自动包含） -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <!-- MySQL -->
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <scope>runtime</scope>
        </dependency>
        
        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <!-- Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

### 2.3 项目结构

```
src/
├── main/
│   ├── java/
│   │   └── com/example/demo/
│   │       ├── DemoApplication.java          # 启动类
│   │       ├── controller/                   # 控制器
│   │       ├── service/                      # 服务层
│   │       ├── repository/                   # 数据访问层
│   │       ├── entity/                       # 实体类
│   │       ├── dto/                          # 数据传输对象
│   │       ├── config/                       # 配置类
│   │       └── exception/                    # 异常处理
│   └── resources/
│       ├── application.yml                   # 主配置文件
│       ├── application-dev.yml               # 开发环境配置
│       ├── application-prod.yml              # 生产环境配置
│       └── static/                           # 静态资源
└── test/
    └── java/
        └── com/example/demo/
            └── DemoApplicationTests.java
```

---

## 3. 核心变化对比

### 3.1 包名变化（最重要！）

Spring Boot 3 最大的变化是从 `javax.*` 迁移到 `jakarta.*`。

```java
// ==================== Spring Boot 2.x ====================
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;
import javax.annotation.PostConstruct;
import javax.annotation.Resource;

// ==================== Spring Boot 3.x ====================
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.Resource;
```

**完整的包名映射表**：

| Java EE (javax) | Jakarta EE (jakarta) |
|-----------------|---------------------|
| javax.servlet.* | jakarta.servlet.* |
| javax.persistence.* | jakarta.persistence.* |
| javax.validation.* | jakarta.validation.* |
| javax.annotation.* | jakarta.annotation.* |
| javax.transaction.* | jakarta.transaction.* |
| javax.mail.* | jakarta.mail.* |
| javax.websocket.* | jakarta.websocket.* |
| javax.inject.* | jakarta.inject.* |

**注意**：`java.*` 和 `javax.sql.*` 不变，它们是 JDK 的一部分。


### 3.2 依赖变化

```xml
<!-- ==================== Spring Boot 2.x ==================== -->
<!-- MySQL 驱动 -->
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>

<!-- ==================== Spring Boot 3.x ==================== -->
<!-- MySQL 驱动（新的 artifactId） -->
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
</dependency>
```

```xml
<!-- ==================== Spring Boot 2.x ==================== -->
<!-- Hibernate Validator 自动包含在 spring-boot-starter-web 中 -->

<!-- ==================== Spring Boot 3.x ==================== -->
<!-- 需要单独引入 validation starter -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

### 3.3 配置属性变化

```yaml
# ==================== Spring Boot 2.x ====================
spring:
  redis:
    host: localhost
    port: 6379
  
server:
  max-http-header-size: 8KB

# ==================== Spring Boot 3.x ====================
spring:
  data:
    redis:                    # 移到 spring.data 下
      host: localhost
      port: 6379
  
server:
  max-http-request-header-size: 8KB    # 属性名变化
```

**常见配置属性变化**：

| Spring Boot 2.x | Spring Boot 3.x |
|-----------------|-----------------|
| spring.redis.* | spring.data.redis.* |
| spring.data.elasticsearch.* | spring.elasticsearch.* |
| server.max-http-header-size | server.max-http-request-header-size |
| spring.mvc.throw-exception-if-no-handler-found | 默认为 true |

### 3.4 注解变化

```java
// ==================== Spring Boot 2.x ====================
// 构造器注入需要 @Autowired（可选）
@Service
public class UserService {
    
    private final UserRepository userRepository;
    
    @Autowired  // 可以省略
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}

// ==================== Spring Boot 3.x ====================
// 完全相同，但推荐使用 Lombok 的 @RequiredArgsConstructor
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    // 自动生成构造器
}
```

### 3.5 URL 匹配策略变化

```java
// ==================== Spring Boot 2.x ====================
// 默认：/user 和 /user/ 都能匹配
@GetMapping("/user")
public String getUser() {
    return "user";
}
// 访问 /user ✓
// 访问 /user/ ✓

// ==================== Spring Boot 3.x ====================
// 默认：严格匹配，/user 和 /user/ 不同
@GetMapping("/user")
public String getUser() {
    return "user";
}
// 访问 /user ✓
// 访问 /user/ ✗ (404)

// 如果需要兼容旧行为，添加配置：
// application.yml
spring:
  mvc:
    pathmatch:
      matching-strategy: ant_path_matcher  # 使用旧的匹配策略
```

---

## 4. Jakarta EE 迁移

### 4.1 为什么要迁移？

2017 年，Oracle 将 Java EE 捐赠给 Eclipse 基金会，但由于商标原因，`javax` 命名空间不能继续使用，因此改名为 `jakarta`。

**时间线**：
- Jakarta EE 8：与 Java EE 8 相同，仍使用 `javax.*`
- Jakarta EE 9：包名从 `javax.*` 改为 `jakarta.*`
- Jakarta EE 10：Spring Boot 3 使用的版本

### 4.2 实体类迁移示例

```java
// ==================== Spring Boot 2.x ====================
package com.example.entity;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "sys_user")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "用户名不能为空")
    @Column(nullable = false, length = 50)
    private String username;
    
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @Column(name = "create_time")
    private LocalDateTime createTime;
    
    // getters and setters
}

// ==================== Spring Boot 3.x ====================
package com.example.entity;

import jakarta.persistence.*;           // javax -> jakarta
import jakarta.validation.constraints.*; // javax -> jakarta
import java.time.LocalDateTime;

@Entity
@Table(name = "sys_user")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "用户名不能为空")
    @Column(nullable = false, length = 50)
    private String username;
    
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @Column(name = "create_time")
    private LocalDateTime createTime;
    
    // getters and setters
}
```

### 4.3 Servlet 相关迁移

```java
// ==================== Spring Boot 2.x ====================
import javax.servlet.*;
import javax.servlet.http.*;

@Component
public class MyFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        // ...
        chain.doFilter(request, response);
    }
}

// ==================== Spring Boot 3.x ====================
import jakarta.servlet.*;           // javax -> jakarta
import jakarta.servlet.http.*;      // javax -> jakarta

@Component
public class MyFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        // ...
        chain.doFilter(request, response);
    }
}
```

### 4.4 自动迁移工具

**方式1：IntelliJ IDEA 自动迁移**
1. 打开项目
2. Refactor → Migrate Packages and Classes → Java EE to Jakarta EE

**方式2：OpenRewrite（推荐）**

```xml
<!-- pom.xml 添加插件 -->
<plugin>
    <groupId>org.openrewrite.maven</groupId>
    <artifactId>rewrite-maven-plugin</artifactId>
    <version>5.23.1</version>
    <configuration>
        <activeRecipes>
            <recipe>org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_2</recipe>
        </activeRecipes>
    </configuration>
    <dependencies>
        <dependency>
            <groupId>org.openrewrite.recipe</groupId>
            <artifactId>rewrite-spring</artifactId>
            <version>5.6.0</version>
        </dependency>
    </dependencies>
</plugin>
```

```bash
# 执行迁移
mvn rewrite:run
```


---

## 5. 新特性详解

### 5.1 Java 17+ 新语法支持

#### 5.1.1 Record 类型

Record 是 Java 16 引入的不可变数据类，非常适合用作 DTO。

```java
// ==================== 传统方式（Spring Boot 2.x） ====================
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long id;
    private String username;
    private String email;
}

// ==================== Record 方式（Spring Boot 3.x） ====================
// 自动生成构造器、getter、equals、hashCode、toString
public record UserDTO(
    Long id,
    String username,
    String email
) {}

// 使用方式
UserDTO user = new UserDTO(1L, "张三", "zhangsan@example.com");
System.out.println(user.username());  // 注意：getter 没有 get 前缀
```

**Record 配合 Validation**：

```java
public record CreateUserRequest(
    @NotBlank(message = "用户名不能为空")
    String username,
    
    @Email(message = "邮箱格式不正确")
    String email,
    
    @Size(min = 6, max = 20, message = "密码长度6-20位")
    String password
) {}

// Controller 中使用
@PostMapping("/users")
public Result<UserDTO> createUser(@RequestBody @Valid CreateUserRequest request) {
    // request.username() 获取用户名
    return Result.success(userService.create(request));
}
```

#### 5.1.2 密封类（Sealed Classes）

```java
// 定义密封类，限制哪些类可以继承
public sealed class PaymentResult permits SuccessResult, FailureResult, PendingResult {
    private final String orderId;
    
    protected PaymentResult(String orderId) {
        this.orderId = orderId;
    }
}

// 只有这三个类可以继承 PaymentResult
public final class SuccessResult extends PaymentResult {
    private final String transactionId;
    
    public SuccessResult(String orderId, String transactionId) {
        super(orderId);
        this.transactionId = transactionId;
    }
}

public final class FailureResult extends PaymentResult {
    private final String errorMessage;
    
    public FailureResult(String orderId, String errorMessage) {
        super(orderId);
        this.errorMessage = errorMessage;
    }
}

public final class PendingResult extends PaymentResult {
    public PendingResult(String orderId) {
        super(orderId);
    }
}
```

#### 5.1.3 模式匹配（Pattern Matching）

```java
// ==================== Java 8 方式 ====================
if (obj instanceof String) {
    String str = (String) obj;
    System.out.println(str.length());
}

// ==================== Java 17+ 方式 ====================
if (obj instanceof String str) {
    // 直接使用 str，无需强制转换
    System.out.println(str.length());
}

// Switch 模式匹配（Java 21）
public String handleResult(PaymentResult result) {
    return switch (result) {
        case SuccessResult s -> "支付成功: " + s.getTransactionId();
        case FailureResult f -> "支付失败: " + f.getErrorMessage();
        case PendingResult p -> "支付处理中";
    };
}
```

#### 5.1.4 文本块（Text Blocks）

```java
// ==================== 传统方式 ====================
String json = "{\n" +
    "  \"name\": \"张三\",\n" +
    "  \"age\": 25\n" +
    "}";

// ==================== 文本块方式（Java 15+） ====================
String json = """
    {
      "name": "张三",
      "age": 25
    }
    """;

// 在 SQL 中使用
@Query("""
    SELECT u FROM User u 
    WHERE u.status = :status 
    AND u.createTime > :startTime
    ORDER BY u.createTime DESC
    """)
List<User> findActiveUsers(@Param("status") Integer status, 
                           @Param("startTime") LocalDateTime startTime);
```

### 5.2 虚拟线程（Java 21）

虚拟线程是 Java 21 的重要特性，可以大幅提升高并发场景的性能。

```yaml
# application.yml - 启用虚拟线程
spring:
  threads:
    virtual:
      enabled: true  # 启用虚拟线程
```

```java
// 传统线程 vs 虚拟线程对比
// ==================== 传统线程 ====================
// 每个请求一个平台线程，线程数有限（通常几百个）
// 线程阻塞时，占用系统资源

// ==================== 虚拟线程 ====================
// 每个请求一个虚拟线程，可以创建数百万个
// 虚拟线程阻塞时，不占用平台线程

// 手动创建虚拟线程
Thread.startVirtualThread(() -> {
    // 执行任务
    System.out.println("虚拟线程执行");
});

// 使用虚拟线程执行器
try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
    executor.submit(() -> {
        // 任务1
    });
    executor.submit(() -> {
        // 任务2
    });
}
```

**虚拟线程的优势**：
- 启动速度快（微秒级）
- 内存占用小（约 1KB vs 平台线程 1MB）
- 可以创建大量线程（百万级）
- 阻塞操作不会浪费平台线程

**注意事项**：
- 不要在虚拟线程中使用 `synchronized`，改用 `ReentrantLock`
- 避免长时间的 CPU 密集型操作
- 需要 Java 21+

### 5.3 HTTP Interface（声明式 HTTP 客户端）

Spring Boot 3 引入了类似 Feign 的声明式 HTTP 客户端。

```java
// ==================== 定义接口 ====================
public interface UserClient {
    
    @GetExchange("/users/{id}")
    UserDTO getUser(@PathVariable Long id);
    
    @GetExchange("/users")
    List<UserDTO> listUsers(@RequestParam(required = false) String name);
    
    @PostExchange("/users")
    UserDTO createUser(@RequestBody CreateUserRequest request);
    
    @PutExchange("/users/{id}")
    UserDTO updateUser(@PathVariable Long id, @RequestBody UpdateUserRequest request);
    
    @DeleteExchange("/users/{id}")
    void deleteUser(@PathVariable Long id);
}

// ==================== 配置 ====================
@Configuration
public class HttpClientConfig {
    
    @Bean
    public UserClient userClient() {
        WebClient webClient = WebClient.builder()
            .baseUrl("http://user-service:8080/api")
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        
        HttpServiceProxyFactory factory = HttpServiceProxyFactory
            .builderFor(WebClientAdapter.create(webClient))
            .build();
        
        return factory.createClient(UserClient.class);
    }
}

// ==================== 使用 ====================
@Service
@RequiredArgsConstructor
public class OrderService {
    
    private final UserClient userClient;
    
    public void createOrder(Long userId, OrderDTO order) {
        // 声明式调用，就像调用本地方法一样
        UserDTO user = userClient.getUser(userId);
        // ...
    }
}
```


### 5.4 ProblemDetail（RFC 7807 错误响应）

Spring Boot 3 支持 RFC 7807 标准的错误响应格式。

```java
// ==================== Spring Boot 2.x 自定义错误响应 ====================
@Data
public class ErrorResponse {
    private int code;
    private String message;
    private LocalDateTime timestamp;
}

// ==================== Spring Boot 3.x ProblemDetail ====================
// 标准化的错误响应格式
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(UserNotFoundException.class)
    public ProblemDetail handleUserNotFound(UserNotFoundException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND, 
            ex.getMessage()
        );
        problem.setTitle("用户不存在");
        problem.setType(URI.create("https://api.example.com/errors/user-not-found"));
        problem.setProperty("userId", ex.getUserId());
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "请求参数校验失败"
        );
        problem.setTitle("参数校验错误");
        
        // 添加字段错误详情
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> 
            errors.put(error.getField(), error.getDefaultMessage())
        );
        problem.setProperty("errors", errors);
        
        return problem;
    }
}

// 响应示例
/*
{
    "type": "https://api.example.com/errors/user-not-found",
    "title": "用户不存在",
    "status": 404,
    "detail": "用户ID 123 不存在",
    "instance": "/api/users/123",
    "userId": 123,
    "timestamp": "2024-01-15T10:30:00Z"
}
*/
```

```yaml
# 启用 ProblemDetail
spring:
  mvc:
    problemdetails:
      enabled: true
```

---

## 6. 配置文件变化

### 6.1 配置属性对比

```yaml
# ==================== Spring Boot 2.x ====================
spring:
  # Redis 配置
  redis:
    host: localhost
    port: 6379
    password: 123456
    database: 0
    lettuce:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 0
  
  # Elasticsearch 配置
  elasticsearch:
    rest:
      uris: http://localhost:9200
  
  # 数据源配置
  datasource:
    url: jdbc:mysql://localhost:3306/test
    username: root
    password: 123456
    driver-class-name: com.mysql.cj.jdbc.Driver

server:
  max-http-header-size: 8KB

# ==================== Spring Boot 3.x ====================
spring:
  # Redis 配置（移到 spring.data 下）
  data:
    redis:
      host: localhost
      port: 6379
      password: 123456
      database: 0
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0
  
  # Elasticsearch 配置（简化）
  elasticsearch:
    uris: http://localhost:9200
  
  # 数据源配置（不变）
  datasource:
    url: jdbc:mysql://localhost:3306/test
    username: root
    password: 123456
    driver-class-name: com.mysql.cj.jdbc.Driver

server:
  max-http-request-header-size: 8KB  # 属性名变化
```

### 6.2 完整配置示例

```yaml
# application.yml - Spring Boot 3.2.x 完整配置
server:
  port: 8080
  servlet:
    context-path: /api
  # HTTP 请求头大小限制
  max-http-request-header-size: 8KB
  # 压缩配置
  compression:
    enabled: true
    mime-types: application/json,application/xml,text/html,text/plain

spring:
  application:
    name: demo-service
  
  # 环境配置
  profiles:
    active: dev
  
  # 数据源配置
  datasource:
    url: jdbc:mysql://localhost:3306/demo?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
    username: root
    password: 123456
    driver-class-name: com.mysql.cj.jdbc.Driver
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      idle-timeout: 30000
      connection-timeout: 30000
      max-lifetime: 1800000
  
  # JPA 配置
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.MySQLDialect  # Hibernate 6 不再需要版本号
  
  # Redis 配置（注意路径变化）
  data:
    redis:
      host: localhost
      port: 6379
      password: 
      database: 0
      timeout: 3000ms
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0
          max-wait: -1ms
  
  # Jackson 配置
  jackson:
    date-format: yyyy-MM-dd HH:mm:ss
    time-zone: Asia/Shanghai
    default-property-inclusion: non_null
  
  # 虚拟线程（Java 21）
  threads:
    virtual:
      enabled: true
  
  # MVC 配置
  mvc:
    # 启用 ProblemDetail
    problemdetails:
      enabled: true
    # 路径匹配策略
    pathmatch:
      matching-strategy: path_pattern_parser  # 默认值

# 日志配置
logging:
  level:
    root: INFO
    com.example: DEBUG
    org.springframework.web: DEBUG
    org.hibernate.SQL: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"

# Actuator 配置
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
  # 可观测性配置
  tracing:
    sampling:
      probability: 1.0
  metrics:
    tags:
      application: ${spring.application.name}
```


---

## 7. Web 开发

### 7.1 Controller 层

```java
package com.example.controller;

import com.example.dto.*;
import com.example.service.UserService;
import jakarta.validation.Valid;  // 注意：jakarta
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    /**
     * 查询用户列表
     */
    @GetMapping
    public ResponseEntity<List<UserDTO>> list(
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer size) {
        List<UserDTO> users = userService.list(keyword, page, size);
        return ResponseEntity.ok(users);
    }
    
    /**
     * 查询单个用户
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getById(@PathVariable Long id) {
        UserDTO user = userService.getById(id);
        return ResponseEntity.ok(user);
    }
    
    /**
     * 创建用户（使用 Record 作为请求体）
     */
    @PostMapping
    public ResponseEntity<UserDTO> create(@RequestBody @Valid CreateUserRequest request) {
        UserDTO user = userService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
    
    /**
     * 更新用户
     */
    @PutMapping("/{id}")
    public ResponseEntity<UserDTO> update(
            @PathVariable Long id,
            @RequestBody @Valid UpdateUserRequest request) {
        UserDTO user = userService.update(id, request);
        return ResponseEntity.ok(user);
    }
    
    /**
     * 删除用户
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

### 7.2 DTO 使用 Record

```java
package com.example.dto;

import jakarta.validation.constraints.*;

/**
 * 创建用户请求 - 使用 Record
 */
public record CreateUserRequest(
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 20, message = "用户名长度2-20位")
    String username,
    
    @NotBlank(message = "密码不能为空")
    @Size(min = 6, max = 20, message = "密码长度6-20位")
    String password,
    
    @Email(message = "邮箱格式不正确")
    String email,
    
    @Pattern(regexp = "^1[3-9]\\d{9}$", message = "手机号格式不正确")
    String phone
) {}

/**
 * 更新用户请求
 */
public record UpdateUserRequest(
    @Size(min = 2, max = 20, message = "用户名长度2-20位")
    String username,
    
    @Email(message = "邮箱格式不正确")
    String email,
    
    String phone
) {}

/**
 * 用户响应 DTO
 */
public record UserDTO(
    Long id,
    String username,
    String email,
    String phone,
    Integer status,
    LocalDateTime createTime
) {
    // 可以添加静态工厂方法
    public static UserDTO from(User user) {
        return new UserDTO(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getPhone(),
            user.getStatus(),
            user.getCreateTime()
        );
    }
}
```

### 7.3 全局异常处理

```java
package com.example.exception;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    /**
     * 业务异常
     */
    @ExceptionHandler(BusinessException.class)
    public ProblemDetail handleBusinessException(BusinessException ex) {
        log.warn("业务异常: {}", ex.getMessage());
        
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            ex.getMessage()
        );
        problem.setTitle("业务处理失败");
        problem.setType(URI.create("/errors/business"));
        problem.setProperty("code", ex.getCode());
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }
    
    /**
     * 资源不存在
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ProblemDetail handleNotFound(ResourceNotFoundException ex) {
        log.warn("资源不存在: {}", ex.getMessage());
        
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.NOT_FOUND,
            ex.getMessage()
        );
        problem.setTitle("资源不存在");
        problem.setType(URI.create("/errors/not-found"));
        problem.setProperty("resourceType", ex.getResourceType());
        problem.setProperty("resourceId", ex.getResourceId());
        return problem;
    }
    
    /**
     * 参数校验异常（@Valid）
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        log.warn("参数校验失败");
        
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "请求参数校验失败"
        );
        problem.setTitle("参数校验错误");
        problem.setType(URI.create("/errors/validation"));
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> 
            errors.put(error.getField(), error.getDefaultMessage())
        );
        problem.setProperty("errors", errors);
        
        return problem;
    }
    
    /**
     * 约束违反异常（@Validated）
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ProblemDetail handleConstraintViolation(ConstraintViolationException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.BAD_REQUEST,
            "参数约束违反"
        );
        problem.setTitle("参数校验错误");
        
        Map<String, String> errors = new HashMap<>();
        ex.getConstraintViolations().forEach(violation -> {
            String field = violation.getPropertyPath().toString();
            errors.put(field, violation.getMessage());
        });
        problem.setProperty("errors", errors);
        
        return problem;
    }
    
    /**
     * 其他异常
     */
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleException(Exception ex) {
        log.error("系统异常", ex);
        
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "系统繁忙，请稍后重试"
        );
        problem.setTitle("系统错误");
        problem.setType(URI.create("/errors/internal"));
        return problem;
    }
}
```

### 7.4 自定义异常类

```java
package com.example.exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    
    private final String code;
    
    public BusinessException(String message) {
        super(message);
        this.code = "BUSINESS_ERROR";
    }
    
    public BusinessException(String code, String message) {
        super(message);
        this.code = code;
    }
}

@Getter
public class ResourceNotFoundException extends RuntimeException {
    
    private final String resourceType;
    private final Object resourceId;
    
    public ResourceNotFoundException(String resourceType, Object resourceId) {
        super(String.format("%s [%s] 不存在", resourceType, resourceId));
        this.resourceType = resourceType;
        this.resourceId = resourceId;
    }
}
```


---

## 8. 数据访问

### 8.1 JPA 实体类

```java
package com.example.entity;

import jakarta.persistence.*;  // 注意：jakarta
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "sys_user")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 50, unique = true)
    private String username;
    
    @Column(nullable = false, length = 100)
    private String password;
    
    @Column(length = 100)
    private String email;
    
    @Column(length = 20)
    private String phone;
    
    @Column(nullable = false)
    private Integer status = 1;
    
    @CreationTimestamp
    @Column(name = "create_time", updatable = false)
    private LocalDateTime createTime;
    
    @UpdateTimestamp
    @Column(name = "update_time")
    private LocalDateTime updateTime;
}
```

### 8.2 Repository 层

```java
package com.example.repository;

import com.example.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * 根据用户名查询
     */
    Optional<User> findByUsername(String username);
    
    /**
     * 根据邮箱查询
     */
    Optional<User> findByEmail(String email);
    
    /**
     * 检查用户名是否存在
     */
    boolean existsByUsername(String username);
    
    /**
     * 根据状态查询
     */
    List<User> findByStatus(Integer status);
    
    /**
     * 模糊查询（使用文本块）
     */
    @Query("""
        SELECT u FROM User u 
        WHERE (:keyword IS NULL OR u.username LIKE %:keyword% OR u.email LIKE %:keyword%)
        AND u.status = :status
        ORDER BY u.createTime DESC
        """)
    List<User> search(@Param("keyword") String keyword, @Param("status") Integer status);
    
    /**
     * 更新状态
     */
    @Modifying
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") Integer status);
    
    /**
     * 原生 SQL 查询
     */
    @Query(value = """
        SELECT * FROM sys_user 
        WHERE create_time >= :startTime 
        AND create_time <= :endTime
        """, nativeQuery = true)
    List<User> findByCreateTimeBetween(
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );
}
```

### 8.3 Service 层

```java
package com.example.service;

import com.example.dto.*;
import com.example.entity.User;
import com.example.exception.BusinessException;
import com.example.exception.ResourceNotFoundException;
import com.example.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    /**
     * 查询用户列表
     */
    @Transactional(readOnly = true)
    public List<UserDTO> list(String keyword, Integer page, Integer size) {
        return userRepository.search(keyword, 1)
            .stream()
            .map(UserDTO::from)
            .toList();  // Java 16+ 的 toList()
    }
    
    /**
     * 查询单个用户
     */
    @Transactional(readOnly = true)
    public UserDTO getById(Long id) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("用户", id));
        return UserDTO.from(user);
    }
    
    /**
     * 创建用户
     */
    @Transactional(rollbackFor = Exception.class)
    public UserDTO create(CreateUserRequest request) {
        // 检查用户名是否存在
        if (userRepository.existsByUsername(request.username())) {
            throw new BusinessException("USER_EXISTS", "用户名已存在");
        }
        
        User user = new User();
        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setEmail(request.email());
        user.setPhone(request.phone());
        user.setStatus(1);
        
        userRepository.save(user);
        log.info("创建用户成功: {}", user.getUsername());
        
        return UserDTO.from(user);
    }
    
    /**
     * 更新用户
     */
    @Transactional(rollbackFor = Exception.class)
    public UserDTO update(Long id, UpdateUserRequest request) {
        User user = userRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("用户", id));
        
        // 使用 Optional 处理可选字段
        if (request.username() != null) {
            user.setUsername(request.username());
        }
        if (request.email() != null) {
            user.setEmail(request.email());
        }
        if (request.phone() != null) {
            user.setPhone(request.phone());
        }
        
        userRepository.save(user);
        log.info("更新用户成功: {}", user.getId());
        
        return UserDTO.from(user);
    }
    
    /**
     * 删除用户
     */
    @Transactional(rollbackFor = Exception.class)
    public void delete(Long id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("用户", id);
        }
        userRepository.deleteById(id);
        log.info("删除用户成功: {}", id);
    }
}
```

### 8.4 Hibernate 6 变化

```java
// ==================== Hibernate 5 (Spring Boot 2.x) ====================
spring:
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQL5InnoDBDialect  # 需要指定版本

// ==================== Hibernate 6 (Spring Boot 3.x) ====================
spring:
  jpa:
    properties:
      hibernate:
        dialect: org.hibernate.dialect.MySQLDialect  # 不再需要版本号，自动检测
```

**Hibernate 6 主要变化**：
- 方言类名简化，不再需要版本号
- `@Type` 注解变化
- ID 生成策略优化
- 查询性能提升

---

## 9. 安全框架

### 9.1 Spring Security 配置变化

Spring Security 6 的配置方式有重大变化，废弃了 `WebSecurityConfigurerAdapter`。

```java
// ==================== Spring Boot 2.x (Spring Security 5) ====================
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .csrf().disable();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());
    }
    
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}

// ==================== Spring Boot 3.x (Spring Security 6) ====================
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtFilter;
    private final CustomAuthenticationEntryPoint authEntryPoint;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 禁用 CSRF
            .csrf(csrf -> csrf.disable())
            // 禁用 Session
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 授权配置（新的 Lambda DSL）
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**", "/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // 异常处理
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(authEntryPoint)
            )
            // 添加 JWT 过滤器
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```


### 9.2 主要 API 变化

```java
// ==================== 方法名变化 ====================

// Spring Security 5
.antMatchers("/api/**")
.mvcMatchers("/api/**")
.regexMatchers("/api/.*")

// Spring Security 6
.requestMatchers("/api/**")  // 统一使用 requestMatchers

// ==================== 授权配置变化 ====================

// Spring Security 5
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated();

// Spring Security 6
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated()
);

// ==================== CORS 配置变化 ====================

// Spring Security 5
http.cors().and().csrf().disable();

// Spring Security 6
http
    .cors(Customizer.withDefaults())
    .csrf(csrf -> csrf.disable());

// ==================== 表单登录变化 ====================

// Spring Security 5
http.formLogin()
    .loginPage("/login")
    .defaultSuccessUrl("/home")
    .failureUrl("/login?error");

// Spring Security 6
http.formLogin(form -> form
    .loginPage("/login")
    .defaultSuccessUrl("/home")
    .failureUrl("/login?error")
);
```

### 9.3 JWT 认证过滤器

```java
package com.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        
        try {
            String token = getTokenFromRequest(request);
            
            if (StringUtils.hasText(token) && jwtUtils.validateToken(token)) {
                String username = jwtUtils.getUsernameFromToken(token);
                
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                    );
                
                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            log.error("JWT 认证失败", e);
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

---

## 10. 可观测性

Spring Boot 3 大幅增强了可观测性支持，包括指标、追踪和日志的统一。

### 10.1 添加依赖

```xml
<!-- Actuator -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>

<!-- Micrometer Prometheus -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>

<!-- 分布式追踪 -->
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing-bridge-brave</artifactId>
</dependency>

<!-- Zipkin 报告器 -->
<dependency>
    <groupId>io.zipkin.reporter2</groupId>
    <artifactId>zipkin-reporter-brave</artifactId>
</dependency>
```

### 10.2 配置

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus,loggers
  endpoint:
    health:
      show-details: always
      show-components: always
  
  # 指标配置
  metrics:
    tags:
      application: ${spring.application.name}
    distribution:
      percentiles-histogram:
        http.server.requests: true
  
  # 追踪配置
  tracing:
    sampling:
      probability: 1.0  # 采样率，生产环境建议 0.1
  
  # Zipkin 配置
  zipkin:
    tracing:
      endpoint: http://localhost:9411/api/v2/spans

# 日志配置（包含 traceId）
logging:
  pattern:
    level: "%5p [${spring.application.name:},%X{traceId:-},%X{spanId:-}]"
```

### 10.3 自定义指标

```java
package com.example.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OrderService {
    
    private final Counter orderCounter;
    private final Timer orderTimer;
    
    public OrderService(MeterRegistry registry) {
        // 订单计数器
        this.orderCounter = Counter.builder("orders.created")
            .description("创建订单数量")
            .tag("type", "total")
            .register(registry);
        
        // 订单处理时间
        this.orderTimer = Timer.builder("orders.process.time")
            .description("订单处理时间")
            .register(registry);
    }
    
    public void createOrder(OrderDTO order) {
        orderTimer.record(() -> {
            // 处理订单逻辑
            doCreateOrder(order);
            
            // 增加计数
            orderCounter.increment();
        });
    }
    
    private void doCreateOrder(OrderDTO order) {
        // 实际业务逻辑
    }
}
```

### 10.4 Observation API（新特性）

```java
package com.example.service;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PaymentService {
    
    private final ObservationRegistry observationRegistry;
    
    public PaymentResult processPayment(PaymentRequest request) {
        // 创建观测
        return Observation.createNotStarted("payment.process", observationRegistry)
            .lowCardinalityKeyValue("paymentMethod", request.method())
            .highCardinalityKeyValue("orderId", request.orderId())
            .observe(() -> {
                // 业务逻辑
                return doProcessPayment(request);
            });
    }
    
    private PaymentResult doProcessPayment(PaymentRequest request) {
        // 实际支付处理
        return new PaymentResult("SUCCESS", "txn123");
    }
}
```


---

## 11. GraalVM 原生镜像

Spring Boot 3 正式支持 GraalVM 原生镜像编译，可以大幅提升启动速度和降低内存占用。

### 11.1 原生镜像优势

| 特性 | JVM 模式 | 原生镜像 |
|------|---------|---------|
| 启动时间 | 2-5 秒 | 0.1-0.5 秒 |
| 内存占用 | 200-500 MB | 50-100 MB |
| 预热时间 | 需要预热 | 无需预热 |
| 构建时间 | 快 | 慢（分钟级） |
| 调试 | 方便 | 困难 |

### 11.2 添加依赖

```xml
<!-- pom.xml -->
<build>
    <plugins>
        <plugin>
            <groupId>org.graalvm.buildtools</groupId>
            <artifactId>native-maven-plugin</artifactId>
        </plugin>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
        </plugin>
    </plugins>
</build>
```

### 11.3 构建原生镜像

```bash
# 方式1：使用 Maven 构建
mvn -Pnative native:compile

# 方式2：使用 Spring Boot 构建
mvn spring-boot:build-image -Pnative

# 运行原生镜像
./target/demo
```

### 11.4 原生镜像注意事项

```java
// 1. 反射需要配置
// 创建 src/main/resources/META-INF/native-image/reflect-config.json
[
  {
    "name": "com.example.entity.User",
    "allDeclaredFields": true,
    "allDeclaredMethods": true,
    "allDeclaredConstructors": true
  }
]

// 2. 使用 @RegisterReflectionForBinding 注解
@Configuration
@RegisterReflectionForBinding({User.class, Order.class})
public class NativeConfig {
}

// 3. 动态代理需要配置
// 创建 src/main/resources/META-INF/native-image/proxy-config.json
[
  {
    "interfaces": ["com.example.service.UserService"]
  }
]

// 4. 资源文件需要配置
// 创建 src/main/resources/META-INF/native-image/resource-config.json
{
  "resources": {
    "includes": [
      {"pattern": "application.yml"},
      {"pattern": "templates/.*"}
    ]
  }
}
```

### 11.5 AOT 处理

```java
// Spring Boot 3 引入了 AOT（Ahead-of-Time）处理
// 在构建时生成优化代码

// 运行 AOT 处理
mvn spring-boot:process-aot

// AOT 生成的代码位于
// target/spring-aot/main/sources/
```

---

## 12. 迁移指南

### 12.1 迁移步骤

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Spring Boot 2.x → 3.x 迁移步骤                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Step 1: 升级 Java 版本                                                     │
│          Java 8/11 → Java 17+                                               │
│                                                                             │
│  Step 2: 升级 Spring Boot 版本                                              │
│          2.7.x → 3.2.x                                                      │
│                                                                             │
│  Step 3: 替换 javax → jakarta                                               │
│          使用 IDE 或 OpenRewrite 自动替换                                    │
│                                                                             │
│  Step 4: 更新依赖                                                           │
│          mysql-connector-java → mysql-connector-j                           │
│          添加 spring-boot-starter-validation                                │
│                                                                             │
│  Step 5: 更新配置文件                                                       │
│          spring.redis → spring.data.redis                                   │
│                                                                             │
│  Step 6: 更新 Security 配置                                                 │
│          废弃 WebSecurityConfigurerAdapter                                  │
│          antMatchers → requestMatchers                                      │
│                                                                             │
│  Step 7: 测试验证                                                           │
│          运行所有测试，检查功能是否正常                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.2 使用 OpenRewrite 自动迁移

```xml
<!-- pom.xml 添加插件 -->
<plugin>
    <groupId>org.openrewrite.maven</groupId>
    <artifactId>rewrite-maven-plugin</artifactId>
    <version>5.23.1</version>
    <configuration>
        <activeRecipes>
            <recipe>org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_2</recipe>
        </activeRecipes>
    </configuration>
    <dependencies>
        <dependency>
            <groupId>org.openrewrite.recipe</groupId>
            <artifactId>rewrite-spring</artifactId>
            <version>5.6.0</version>
        </dependency>
    </dependencies>
</plugin>
```

```bash
# 预览变更
mvn rewrite:dryRun

# 执行迁移
mvn rewrite:run
```

### 12.3 常见迁移问题

```java
// 问题1：找不到 javax.* 包
// 解决：替换为 jakarta.*
import javax.servlet.* → import jakarta.servlet.*

// 问题2：WebSecurityConfigurerAdapter 不存在
// 解决：使用 SecurityFilterChain Bean
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // 配置
    return http.build();
}

// 问题3：antMatchers 方法不存在
// 解决：使用 requestMatchers
.antMatchers("/api/**") → .requestMatchers("/api/**")

// 问题4：Redis 配置不生效
// 解决：更新配置路径
spring.redis.* → spring.data.redis.*

// 问题5：Hibernate 方言错误
// 解决：使用新的方言类名
MySQL5InnoDBDialect → MySQLDialect
```

---

## 13. 常见错误与解决方案

### 13.1 编译错误

#### 错误1：找不到 javax 包

```
错误: 程序包javax.servlet不存在
import javax.servlet.http.HttpServletRequest;
```

**解决方案**：
```java
// 替换所有 javax 为 jakarta
import javax.servlet.http.HttpServletRequest;
// 改为
import jakarta.servlet.http.HttpServletRequest;
```

#### 错误2：Java 版本不兼容

```
错误: 无效的源发行版: 17
```

**解决方案**：
```xml
<!-- 确保 pom.xml 中配置正确 -->
<properties>
    <java.version>17</java.version>
</properties>

<!-- 确保 JAVA_HOME 指向 Java 17+ -->
```

### 13.2 运行时错误

#### 错误3：Bean 创建失败

```
Error creating bean with name 'securityFilterChain'
```

**解决方案**：
```java
// 检查 Security 配置是否使用了新的 API
// 废弃的方式
http.authorizeRequests()...

// 新的方式
http.authorizeHttpRequests(auth -> auth...)
```

#### 错误4：URL 匹配失败（404）

```
访问 /api/users/ 返回 404
```

**解决方案**：
```yaml
# Spring Boot 3 默认严格匹配
# 方式1：去掉 URL 末尾的斜杠
# 方式2：配置兼容模式
spring:
  mvc:
    pathmatch:
      matching-strategy: ant_path_matcher
```

#### 错误5：Validation 不生效

```
@Valid 注解不起作用
```

**解决方案**：
```xml
<!-- Spring Boot 3 需要单独引入 validation -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```


### 13.3 依赖错误

#### 错误6：MySQL 驱动找不到

```
Cannot load driver class: com.mysql.cj.jdbc.Driver
```

**解决方案**：
```xml
<!-- 使用新的 artifactId -->
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
</dependency>
```

#### 错误7：Hibernate 方言错误

```
Unable to determine Dialect without JDBC metadata
```

**解决方案**：
```yaml
spring:
  jpa:
    properties:
      hibernate:
        # Hibernate 6 使用新的方言类名
        dialect: org.hibernate.dialect.MySQLDialect
    database-platform: org.hibernate.dialect.MySQLDialect
```

### 13.4 配置错误

#### 错误8：Redis 连接失败

```
Unable to connect to Redis
```

**解决方案**：
```yaml
# 配置路径变化
spring:
  data:           # 注意：多了 data
    redis:
      host: localhost
      port: 6379
```

#### 错误9：Actuator 端点访问不了

```
访问 /actuator/health 返回 404
```

**解决方案**：
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics  # 明确暴露端点
```

### 13.5 测试错误

#### 错误10：测试类找不到

```
@SpringBootTest 测试失败
```

**解决方案**：
```java
// 确保测试类在正确的包下
// 测试类的包路径应该与主类一致或在其子包下

// 主类
package com.example.demo;

// 测试类
package com.example.demo;  // 正确
package com.example.demo.service;  // 正确
package com.other;  // 错误，找不到主类
```

---

## 14. 最佳实践

### 14.1 项目结构最佳实践

```
src/main/java/com/example/demo/
├── DemoApplication.java              # 启动类
├── config/                           # 配置类
│   ├── SecurityConfig.java
│   ├── WebConfig.java
│   └── RedisConfig.java
├── controller/                       # 控制器
│   └── UserController.java
├── service/                          # 服务层
│   ├── UserService.java
│   └── impl/
│       └── UserServiceImpl.java
├── repository/                       # 数据访问层
│   └── UserRepository.java
├── entity/                           # 实体类
│   └── User.java
├── dto/                              # DTO（推荐使用 Record）
│   ├── request/
│   │   └── CreateUserRequest.java
│   └── response/
│       └── UserDTO.java
├── exception/                        # 异常
│   ├── BusinessException.java
│   ├── ResourceNotFoundException.java
│   └── GlobalExceptionHandler.java
├── security/                         # 安全相关
│   ├── JwtUtils.java
│   └── JwtAuthenticationFilter.java
└── util/                             # 工具类
    └── DateUtils.java
```

### 14.2 代码规范最佳实践

```java
/**
 * ✅ 推荐的 Controller 写法
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "用户管理", description = "用户相关接口")
public class UserController {
    
    private final UserService userService;
    
    @Operation(summary = "创建用户")
    @PostMapping
    public ResponseEntity<UserDTO> create(
            @RequestBody @Valid CreateUserRequest request) {
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(userService.create(request));
    }
}

/**
 * ✅ 推荐的 Service 写法
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    
    @Transactional(readOnly = true)
    public UserDTO getById(Long id) {
        return userRepository.findById(id)
            .map(UserDTO::from)
            .orElseThrow(() -> new ResourceNotFoundException("用户", id));
    }
    
    @Transactional(rollbackFor = Exception.class)
    public UserDTO create(CreateUserRequest request) {
        // 业务逻辑
    }
}

/**
 * ✅ 推荐使用 Record 作为 DTO
 */
public record CreateUserRequest(
    @NotBlank String username,
    @Email String email
) {}

public record UserDTO(
    Long id,
    String username,
    String email,
    LocalDateTime createTime
) {
    public static UserDTO from(User user) {
        return new UserDTO(
            user.getId(),
            user.getUsername(),
            user.getEmail(),
            user.getCreateTime()
        );
    }
}
```

### 14.3 配置最佳实践

```yaml
# application.yml - 生产环境配置建议
spring:
  application:
    name: demo-service
  
  # 数据源配置
  datasource:
    url: jdbc:mysql://${DB_HOST:localhost}:${DB_PORT:3306}/${DB_NAME:demo}
    username: ${DB_USER:root}
    password: ${DB_PASSWORD:}
    hikari:
      maximum-pool-size: ${DB_POOL_SIZE:20}
      minimum-idle: 5
  
  # JPA 配置
  jpa:
    hibernate:
      ddl-auto: none  # 生产环境禁用自动建表
    show-sql: false   # 生产环境关闭 SQL 日志
  
  # Redis 配置
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD:}

# 服务器配置
server:
  port: ${SERVER_PORT:8080}
  shutdown: graceful  # 优雅关闭

# 日志配置
logging:
  level:
    root: INFO
    com.example: ${LOG_LEVEL:INFO}
  file:
    name: logs/app.log

# Actuator 配置
management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus
  endpoint:
    health:
      show-details: when_authorized
```

### 14.4 安全最佳实践

```java
/**
 * 安全配置最佳实践
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // 启用方法级安全
@RequiredArgsConstructor
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 1. 禁用不需要的功能
            .csrf(csrf -> csrf.disable())
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable())
            
            // 2. 无状态会话
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // 3. 细粒度的授权配置
            .authorizeHttpRequests(auth -> auth
                // 公开接口
                .requestMatchers("/auth/**", "/public/**").permitAll()
                // Actuator 端点
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/actuator/**").hasRole("ADMIN")
                // API 文档
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                // 其他需要认证
                .anyRequest().authenticated()
            )
            
            // 4. 安全响应头
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny())
                .contentSecurityPolicy(csp -> 
                    csp.policyDirectives("default-src 'self'"))
            );
        
        return http.build();
    }
}
```

---

## 附录：速查表

### A. 包名映射

| javax | jakarta |
|-------|---------|
| javax.servlet.* | jakarta.servlet.* |
| javax.persistence.* | jakarta.persistence.* |
| javax.validation.* | jakarta.validation.* |
| javax.annotation.* | jakarta.annotation.* |
| javax.transaction.* | jakarta.transaction.* |

### B. 配置属性映射

| Spring Boot 2.x | Spring Boot 3.x |
|-----------------|-----------------|
| spring.redis.* | spring.data.redis.* |
| server.max-http-header-size | server.max-http-request-header-size |
| spring.mvc.throw-exception-if-no-handler-found | 默认 true |

### C. Security API 映射

| Spring Security 5 | Spring Security 6 |
|-------------------|-------------------|
| antMatchers() | requestMatchers() |
| mvcMatchers() | requestMatchers() |
| authorizeRequests() | authorizeHttpRequests() |
| WebSecurityConfigurerAdapter | SecurityFilterChain Bean |

### D. 依赖变化

| Spring Boot 2.x | Spring Boot 3.x |
|-----------------|-----------------|
| mysql:mysql-connector-java | com.mysql:mysql-connector-j |
| 自动包含 validation | 需要 spring-boot-starter-validation |

---

> 📝 **笔记完成**
> 
> 本笔记涵盖了 Spring Boot 3 的核心内容：
> - 与 Spring Boot 2.x 的详细对比
> - Jakarta EE 迁移指南
> - Java 17+ 新特性（Record、虚拟线程等）
> - 新的 Security 配置方式
> - 可观测性和原生镜像支持
> - 完整的迁移步骤和常见错误解决方案
> 
> 建议先在测试环境完成迁移验证，再部署到生产环境。
