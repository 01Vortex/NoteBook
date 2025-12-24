# Spring Boot 2 完整学习笔记

> 基于 Spring Boot 2.7.x + Java 8 环境
> Spring Boot 让创建独立的、生产级的 Spring 应用变得简单

---

## 目录

1. [基础概念](#1-基础概念)
2. [项目搭建](#2-项目搭建)
3. [核心配置](#3-核心配置)
4. [Web开发](#4-web开发)
5. [数据访问](#5-数据访问)
6. [事务管理](#6-事务管理)
7. [缓存](#7-缓存)
8. [安全认证](#8-安全认证)
9. [异步与定时任务](#9-异步与定时任务)
10. [日志管理](#10-日志管理)
11. [测试](#11-测试)
12. [部署与监控](#12-部署与监控)
13. [常见错误与解决方案](#13-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Spring Boot？

Spring Boot 是 Spring 家族的一个子项目，它的设计目的是简化 Spring 应用的初始搭建和开发过程。传统的 Spring 开发需要大量的 XML 配置，而 Spring Boot 采用"约定优于配置"的理念，让开发者能够快速上手。

**Spring Boot 的核心特性：**
- **自动配置**：根据添加的依赖自动配置 Spring 应用
- **起步依赖**：简化依赖管理，一个 starter 包含所需的所有依赖
- **内嵌服务器**：内置 Tomcat、Jetty 等服务器，无需部署 WAR 文件
- **生产就绪**：提供健康检查、指标监控等生产级特性
- **无代码生成**：不需要 XML 配置

### 1.2 Spring Boot 与 Spring 的关系

```
┌─────────────────────────────────────────────────────────────┐
│                      Spring Boot                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  Spring Framework                    │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │    │
│  │  │Spring   │ │Spring   │ │Spring   │ │Spring   │   │    │
│  │  │Core     │ │MVC      │ │Data     │ │Security │   │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
│  + 自动配置 + 起步依赖 + 内嵌服务器 + Actuator              │
└─────────────────────────────────────────────────────────────┘
```

Spring Boot 不是替代 Spring，而是在 Spring 的基础上提供了更便捷的开发体验。

### 1.3 核心注解

```java
// ============ @SpringBootApplication ============
// 这是一个组合注解，等价于以下三个注解的组合
@SpringBootApplication
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}

// 等价于：
@SpringBootConfiguration  // 标识这是一个配置类
@EnableAutoConfiguration  // 启用自动配置
@ComponentScan           // 组件扫描
public class MyApplication {
    // ...
}

// ============ 常用注解说明 ============

// @Configuration - 标识配置类
@Configuration
public class AppConfig {
    @Bean
    public MyService myService() {
        return new MyServiceImpl();
    }
}

// @Component - 通用组件
@Component
public class MyComponent { }

// @Service - 业务层组件
@Service
public class UserService { }

// @Repository - 数据访问层组件
@Repository
public class UserRepository { }

// @Controller - Web 控制器
@Controller
public class UserController { }

// @RestController - RESTful 控制器（@Controller + @ResponseBody）
@RestController
public class UserApiController { }

// @Autowired - 自动注入依赖
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
}

// @Value - 注入配置值
@Component
public class MyComponent {
    @Value("${app.name}")
    private String appName;
}

// @ConfigurationProperties - 配置属性绑定
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    private String name;
    private String version;
    // getters and setters
}
```

---

## 2. 项目搭建

### 2.1 使用 Spring Initializr 创建项目

访问 https://start.spring.io/ 或使用 IDE 内置的 Spring Initializr。

**Maven 项目结构：**
```
my-spring-boot-app/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/example/demo/
│   │   │       ├── DemoApplication.java      # 启动类
│   │   │       ├── controller/               # 控制器
│   │   │       ├── service/                  # 业务层
│   │   │       │   └── impl/
│   │   │       ├── repository/               # 数据访问层
│   │   │       ├── entity/                   # 实体类
│   │   │       ├── dto/                      # 数据传输对象
│   │   │       ├── vo/                       # 视图对象
│   │   │       ├── config/                   # 配置类
│   │   │       ├── exception/                # 异常处理
│   │   │       └── util/                     # 工具类
│   │   └── resources/
│   │       ├── application.yml               # 主配置文件
│   │       ├── application-dev.yml           # 开发环境配置
│   │       ├── application-prod.yml          # 生产环境配置
│   │       ├── static/                       # 静态资源
│   │       ├── templates/                    # 模板文件
│   │       └── mapper/                       # MyBatis 映射文件
│   └── test/
│       └── java/
│           └── com/example/demo/
│               └── DemoApplicationTests.java
├── pom.xml
└── README.md
```

### 2.2 pom.xml 配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <!-- 继承 Spring Boot 父项目 -->
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.18</version>
        <relativePath/>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <name>demo</name>
    <description>Spring Boot Demo Project</description>
    
    <properties>
        <java.version>1.8</java.version>
    </properties>
    
    <dependencies>
        <!-- Web 开发 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- 数据访问 - JPA -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        
        <!-- 数据访问 - MyBatis -->
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>2.3.1</version>
        </dependency>
        
        <!-- MySQL 驱动 -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.33</version>
        </dependency>
        
        <!-- Redis -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        
        <!-- 参数校验 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <!-- 安全认证 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        
        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <!-- 监控 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        
        <!-- 配置处理器 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>
        
        <!-- 测试 -->
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

### 2.3 启动类

```java
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
    
    public static void main(String[] args) {
        // 启动 Spring Boot 应用
        SpringApplication.run(DemoApplication.class, args);
    }
}

// 自定义启动配置
@SpringBootApplication
public class DemoApplication {
    
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(DemoApplication.class);
        
        // 自定义配置
        app.setBannerMode(Banner.Mode.OFF);  // 关闭 Banner
        app.setWebApplicationType(WebApplicationType.SERVLET);
        
        // 添加监听器
        app.addListeners(new ApplicationStartedEventListener());
        
        app.run(args);
    }
}
```

---

## 3. 核心配置

### 3.1 配置文件

Spring Boot 支持 `application.properties` 和 `application.yml` 两种格式，推荐使用 YAML 格式。

```yaml
# application.yml
# ============ 服务器配置 ============
server:
  port: 8080
  servlet:
    context-path: /api
  tomcat:
    uri-encoding: UTF-8
    max-threads: 200
    min-spare-threads: 10

# ============ Spring 配置 ============
spring:
  application:
    name: demo-application
  
  # 环境配置
  profiles:
    active: dev
  
  # 数据源配置
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/demo?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: root
    # HikariCP 连接池配置
    hikari:
      minimum-idle: 5
      maximum-pool-size: 20
      idle-timeout: 30000
      pool-name: DemoHikariCP
      max-lifetime: 1800000
      connection-timeout: 30000
  
  # JPA 配置
  jpa:
    database: mysql
    show-sql: true
    hibernate:
      ddl-auto: update
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.MySQL8Dialect
  
  # Redis 配置
  redis:
    host: localhost
    port: 6379
    password: 
    database: 0
    timeout: 10000ms
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
    serialization:
      write-dates-as-timestamps: false
    default-property-inclusion: non_null
  
  # 文件上传配置
  servlet:
    multipart:
      enabled: true
      max-file-size: 10MB
      max-request-size: 100MB

# ============ MyBatis 配置 ============
mybatis:
  mapper-locations: classpath:mapper/**/*.xml
  type-aliases-package: com.example.demo.entity
  configuration:
    map-underscore-to-camel-case: true
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl

# ============ 日志配置 ============
logging:
  level:
    root: INFO
    com.example.demo: DEBUG
    org.springframework.web: INFO
    org.hibernate.SQL: DEBUG
  file:
    name: logs/app.log
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"

# ============ 自定义配置 ============
app:
  name: Demo Application
  version: 1.0.0
  upload-path: /data/uploads
  jwt:
    secret: mySecretKey123456789
    expiration: 86400000
```

### 3.2 多环境配置

```yaml
# application.yml - 主配置文件
spring:
  profiles:
    active: dev  # 激活的环境

---
# application-dev.yml - 开发环境
spring:
  config:
    activate:
      on-profile: dev
  datasource:
    url: jdbc:mysql://localhost:3306/demo_dev
    username: root
    password: root

server:
  port: 8080

logging:
  level:
    root: DEBUG

---
# application-prod.yml - 生产环境
spring:
  config:
    activate:
      on-profile: prod
  datasource:
    url: jdbc:mysql://prod-server:3306/demo_prod
    username: prod_user
    password: ${DB_PASSWORD}  # 从环境变量读取

server:
  port: 80

logging:
  level:
    root: WARN
```

**启动时指定环境：**
```bash
# 方式1：命令行参数
java -jar app.jar --spring.profiles.active=prod

# 方式2：环境变量
export SPRING_PROFILES_ACTIVE=prod
java -jar app.jar

# 方式3：JVM 参数
java -Dspring.profiles.active=prod -jar app.jar
```

### 3.3 配置属性绑定

```java
// ============ 使用 @Value 注入单个值 ============
@Component
public class MyComponent {
    
    @Value("${app.name}")
    private String appName;
    
    @Value("${app.version:1.0.0}")  // 带默认值
    private String version;
    
    @Value("${server.port}")
    private int port;
    
    @Value("${app.features:feature1,feature2}")  // 数组
    private String[] features;
    
    @Value("#{${app.map}}")  // SpEL 表达式注入 Map
    private Map<String, String> map;
}

// ============ 使用 @ConfigurationProperties 绑定对象 ============
@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    
    private String name;
    private String version;
    private String uploadPath;
    
    private Jwt jwt = new Jwt();
    
    @Data
    public static class Jwt {
        private String secret;
        private Long expiration;
    }
}

// 使用配置
@Service
public class MyService {
    
    @Autowired
    private AppProperties appProperties;
    
    public void doSomething() {
        String secret = appProperties.getJwt().getSecret();
    }
}

// ============ 配置校验 ============
@Data
@Validated
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    
    @NotBlank(message = "应用名称不能为空")
    private String name;
    
    @Min(value = 1, message = "版本号必须大于0")
    private Integer version;
    
    @Valid
    private Jwt jwt = new Jwt();
    
    @Data
    public static class Jwt {
        @NotBlank
        private String secret;
        
        @Min(1000)
        private Long expiration;
    }
}
```

### 3.4 自动配置原理

```java
/**
 * Spring Boot 自动配置原理：
 * 
 * 1. @SpringBootApplication 包含 @EnableAutoConfiguration
 * 2. @EnableAutoConfiguration 导入 AutoConfigurationImportSelector
 * 3. AutoConfigurationImportSelector 读取 META-INF/spring.factories
 * 4. 根据条件注解决定是否加载配置类
 */

// 自定义自动配置类
@Configuration
@ConditionalOnClass(MyService.class)  // 类路径存在时生效
@ConditionalOnProperty(prefix = "my", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(MyProperties.class)
public class MyAutoConfiguration {
    
    @Bean
    @ConditionalOnMissingBean  // 容器中不存在时才创建
    public MyService myService(MyProperties properties) {
        return new MyService(properties);
    }
}

// 常用条件注解
@ConditionalOnClass          // 类路径存在指定类
@ConditionalOnMissingClass   // 类路径不存在指定类
@ConditionalOnBean           // 容器中存在指定 Bean
@ConditionalOnMissingBean    // 容器中不存在指定 Bean
@ConditionalOnProperty       // 配置属性满足条件
@ConditionalOnResource       // 资源存在
@ConditionalOnWebApplication // Web 应用环境
@ConditionalOnExpression     // SpEL 表达式为 true
```

---

## 4. Web开发

### 4.1 RESTful API 开发

```java
// ============ 实体类 ============
@Data
@Entity
@Table(name = "user")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String email;
    private Integer age;
    
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createTime;
}

// ============ DTO（数据传输对象） ============
@Data
public class UserDTO {
    
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 20, message = "用户名长度必须在2-20之间")
    private String username;
    
    @NotBlank(message = "邮箱不能为空")
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @NotNull(message = "年龄不能为空")
    @Min(value = 1, message = "年龄必须大于0")
    @Max(value = 150, message = "年龄不能超过150")
    private Integer age;
}

// ============ VO（视图对象） ============
@Data
public class UserVO {
    private Long id;
    private String username;
    private String email;
    private String createTime;
}

// ============ 统一响应结果 ============
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Result<T> {
    private Integer code;
    private String message;
    private T data;
    
    public static <T> Result<T> success(T data) {
        return new Result<>(200, "success", data);
    }
    
    public static <T> Result<T> success() {
        return new Result<>(200, "success", null);
    }
    
    public static <T> Result<T> error(Integer code, String message) {
        return new Result<>(code, message, null);
    }
    
    public static <T> Result<T> error(String message) {
        return new Result<>(500, message, null);
    }
}

// ============ Controller ============
@RestController
@RequestMapping("/api/users")
@Validated
public class UserController {
    
    @Autowired
    private UserService userService;
    
    /**
     * 查询用户列表
     * GET /api/users?page=1&size=10&keyword=张
     */
    @GetMapping
    public Result<Page<UserVO>> list(
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(required = false) String keyword) {
        Page<UserVO> result = userService.findAll(page, size, keyword);
        return Result.success(result);
    }
    
    /**
     * 根据ID查询用户
     * GET /api/users/1
     */
    @GetMapping("/{id}")
    public Result<UserVO> getById(@PathVariable Long id) {
        UserVO user = userService.findById(id);
        return Result.success(user);
    }
    
    /**
     * 创建用户
     * POST /api/users
     */
    @PostMapping
    public Result<UserVO> create(@RequestBody @Valid UserDTO userDTO) {
        UserVO user = userService.create(userDTO);
        return Result.success(user);
    }
    
    /**
     * 更新用户
     * PUT /api/users/1
     */
    @PutMapping("/{id}")
    public Result<UserVO> update(
            @PathVariable Long id,
            @RequestBody @Valid UserDTO userDTO) {
        UserVO user = userService.update(id, userDTO);
        return Result.success(user);
    }
    
    /**
     * 删除用户
     * DELETE /api/users/1
     */
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return Result.success();
    }
    
    /**
     * 批量删除
     * DELETE /api/users?ids=1,2,3
     */
    @DeleteMapping
    public Result<Void> batchDelete(@RequestParam List<Long> ids) {
        userService.batchDelete(ids);
        return Result.success();
    }
}
```

### 4.2 请求参数处理

```java
@RestController
@RequestMapping("/api/demo")
public class DemoController {
    
    // ============ 路径参数 ============
    @GetMapping("/users/{id}")
    public Result<User> getUser(@PathVariable Long id) {
        return Result.success(userService.findById(id));
    }
    
    @GetMapping("/users/{userId}/orders/{orderId}")
    public Result<Order> getOrder(
            @PathVariable Long userId,
            @PathVariable Long orderId) {
        return Result.success(orderService.findByUserAndId(userId, orderId));
    }
    
    // ============ 查询参数 ============
    @GetMapping("/search")
    public Result<List<User>> search(
            @RequestParam String keyword,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer size) {
        return Result.success(userService.search(keyword, status, page, size));
    }
    
    // ============ 请求体 ============
    @PostMapping("/users")
    public Result<User> createUser(@RequestBody @Valid UserDTO userDTO) {
        return Result.success(userService.create(userDTO));
    }
    
    // ============ 表单数据 ============
    @PostMapping("/form")
    public Result<Void> handleForm(
            @RequestParam String name,
            @RequestParam Integer age) {
        return Result.success();
    }
    
    // ============ 请求头 ============
    @GetMapping("/header")
    public Result<String> getHeader(
            @RequestHeader("Authorization") String token,
            @RequestHeader(value = "X-Custom-Header", required = false) String customHeader) {
        return Result.success(token);
    }
    
    // ============ Cookie ============
    @GetMapping("/cookie")
    public Result<String> getCookie(@CookieValue("sessionId") String sessionId) {
        return Result.success(sessionId);
    }
    
    // ============ 文件上传 ============
    @PostMapping("/upload")
    public Result<String> upload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("文件不能为空");
        }
        
        String filename = file.getOriginalFilename();
        String path = "/uploads/" + UUID.randomUUID() + "_" + filename;
        
        try {
            file.transferTo(new File(path));
            return Result.success(path);
        } catch (IOException e) {
            return Result.error("上传失败");
        }
    }
    
    // ============ 多文件上传 ============
    @PostMapping("/uploads")
    public Result<List<String>> uploadMultiple(
            @RequestParam("files") MultipartFile[] files) {
        List<String> paths = new ArrayList<>();
        for (MultipartFile file : files) {
            // 处理每个文件
        }
        return Result.success(paths);
    }
}
```

### 4.3 全局异常处理

```java
// ============ 自定义异常 ============
@Getter
public class BusinessException extends RuntimeException {
    private final Integer code;
    
    public BusinessException(String message) {
        super(message);
        this.code = 500;
    }
    
    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
    }
}

// ============ 全局异常处理器 ============
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    /**
     * 处理业务异常
     */
    @ExceptionHandler(BusinessException.class)
    public Result<Void> handleBusinessException(BusinessException e) {
        log.error("业务异常: {}", e.getMessage());
        return Result.error(e.getCode(), e.getMessage());
    }
    
    /**
     * 处理参数校验异常（@Valid）
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<Void> handleValidException(MethodArgumentNotValidException e) {
        BindingResult bindingResult = e.getBindingResult();
        StringBuilder sb = new StringBuilder();
        for (FieldError fieldError : bindingResult.getFieldErrors()) {
            sb.append(fieldError.getField())
              .append(": ")
              .append(fieldError.getDefaultMessage())
              .append("; ");
        }
        log.error("参数校验失败: {}", sb);
        return Result.error(400, sb.toString());
    }
    
    /**
     * 处理参数校验异常（@Validated）
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public Result<Void> handleConstraintViolationException(ConstraintViolationException e) {
        String message = e.getConstraintViolations().stream()
                .map(ConstraintViolation::getMessage)
                .collect(Collectors.joining("; "));
        log.error("参数校验失败: {}", message);
        return Result.error(400, message);
    }
    
    /**
     * 处理参数绑定异常
     */
    @ExceptionHandler(BindException.class)
    public Result<Void> handleBindException(BindException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        return Result.error(400, message);
    }
    
    /**
     * 处理请求方法不支持异常
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public Result<Void> handleMethodNotSupported(HttpRequestMethodNotSupportedException e) {
        return Result.error(405, "请求方法不支持: " + e.getMethod());
    }
    
    /**
     * 处理资源不存在异常
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public Result<Void> handleNoHandlerFound(NoHandlerFoundException e) {
        return Result.error(404, "资源不存在: " + e.getRequestURL());
    }
    
    /**
     * 处理所有其他异常
     */
    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("系统异常", e);
        return Result.error(500, "系统繁忙，请稍后重试");
    }
}
```

### 4.4 拦截器

```java
// ============ 自定义拦截器 ============
@Component
@Slf4j
public class AuthInterceptor implements HandlerInterceptor {
    
    @Autowired
    private JwtUtils jwtUtils;
    
    /**
     * 请求处理前执行
     */
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        // 放行 OPTIONS 请求
        if ("OPTIONS".equals(request.getMethod())) {
            return true;
        }
        
        // 获取 token
        String token = request.getHeader("Authorization");
        if (StringUtils.isBlank(token)) {
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":401,\"message\":\"未登录\"}");
            return false;
        }
        
        // 验证 token
        try {
            String userId = jwtUtils.parseToken(token);
            request.setAttribute("userId", userId);
            return true;
        } catch (Exception e) {
            log.error("Token 验证失败", e);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":401,\"message\":\"Token无效\"}");
            return false;
        }
    }
    
    /**
     * 请求处理后，视图渲染前执行
     */
    @Override
    public void postHandle(HttpServletRequest request, 
                          HttpServletResponse response, 
                          Object handler, 
                          ModelAndView modelAndView) throws Exception {
        // 可以修改 ModelAndView
    }
    
    /**
     * 请求完成后执行（包括异常情况）
     */
    @Override
    public void afterCompletion(HttpServletRequest request, 
                               HttpServletResponse response, 
                               Object handler, 
                               Exception ex) throws Exception {
        // 清理资源
    }
}

// ============ 注册拦截器 ============
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Autowired
    private AuthInterceptor authInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/**")           // 拦截的路径
                .excludePathPatterns(                  // 排除的路径
                    "/api/auth/login",
                    "/api/auth/register",
                    "/api/public/**"
                );
    }
    
    // 跨域配置
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }
    
    // 静态资源映射
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/uploads/**")
                .addResourceLocations("file:/data/uploads/");
    }
}
```

### 4.5 过滤器

```java
// ============ 自定义过滤器 ============
@Component
@Slf4j
public class RequestLogFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, 
                        ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        long startTime = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        
        // 记录请求信息
        log.info("[{}] {} {} 开始", requestId, httpRequest.getMethod(), httpRequest.getRequestURI());
        
        try {
            chain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            log.info("[{}] {} {} 结束，耗时 {}ms", 
                    requestId, httpRequest.getMethod(), httpRequest.getRequestURI(), duration);
        }
    }
}

// ============ 使用 @WebFilter 注解 ============
@WebFilter(urlPatterns = "/*", filterName = "myFilter")
@Order(1)  // 过滤器顺序
public class MyFilter implements Filter {
    // ...
}

// 需要在启动类添加 @ServletComponentScan
@SpringBootApplication
@ServletComponentScan
public class DemoApplication {
    // ...
}

// ============ 使用 FilterRegistrationBean 注册 ============
@Configuration
public class FilterConfig {
    
    @Bean
    public FilterRegistrationBean<RequestLogFilter> requestLogFilter() {
        FilterRegistrationBean<RequestLogFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RequestLogFilter());
        registration.addUrlPatterns("/*");
        registration.setName("requestLogFilter");
        registration.setOrder(1);
        return registration;
    }
}
```

---

## 5. 数据访问

### 5.1 Spring Data JPA

```java
// ============ 实体类 ============
@Data
@Entity
@Table(name = "user")
@EntityListeners(AuditingEntityListener.class)
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 50)
    private String username;
    
    @Column(nullable = false, length = 100)
    private String password;
    
    @Column(length = 100)
    private String email;
    
    @Enumerated(EnumType.STRING)
    private UserStatus status;
    
    @CreatedDate
    @Column(updatable = false)
    private LocalDateTime createTime;
    
    @LastModifiedDate
    private LocalDateTime updateTime;
    
    // 一对多关系
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Order> orders;
    
    // 多对多关系
    @ManyToMany
    @JoinTable(
        name = "user_role",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles;
}

// ============ Repository 接口 ============
public interface UserRepository extends JpaRepository<User, Long>, 
                                        JpaSpecificationExecutor<User> {
    
    // 方法名查询
    Optional<User> findByUsername(String username);
    
    List<User> findByStatus(UserStatus status);
    
    List<User> findByAgeBetween(Integer minAge, Integer maxAge);
    
    List<User> findByUsernameContaining(String keyword);
    
    boolean existsByEmail(String email);
    
    long countByStatus(UserStatus status);
    
    // @Query 查询
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmailCustom(@Param("email") String email);
    
    @Query("SELECT u FROM User u WHERE u.username LIKE %:keyword% OR u.email LIKE %:keyword%")
    List<User> search(@Param("keyword") String keyword);
    
    // 原生 SQL
    @Query(value = "SELECT * FROM user WHERE status = :status", nativeQuery = true)
    List<User> findByStatusNative(@Param("status") String status);
    
    // 更新操作
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") UserStatus status);
    
    // 删除操作
    @Modifying
    @Transactional
    @Query("DELETE FROM User u WHERE u.id IN :ids")
    int deleteByIds(@Param("ids") List<Long> ids);
}

// ============ Service 层 ============
@Service
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public Page<User> findAll(int page, int size, String keyword) {
        Pageable pageable = PageRequest.of(page - 1, size, Sort.by("createTime").descending());
        
        if (StringUtils.isBlank(keyword)) {
            return userRepository.findAll(pageable);
        }
        
        // 使用 Specification 动态查询
        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.or(
                cb.like(root.get("username"), "%" + keyword + "%"),
                cb.like(root.get("email"), "%" + keyword + "%")
            ));
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        
        return userRepository.findAll(spec, pageable);
    }
    
    @Override
    @Transactional
    public User create(UserDTO dto) {
        User user = new User();
        BeanUtils.copyProperties(dto, user);
        user.setStatus(UserStatus.ACTIVE);
        return userRepository.save(user);
    }
    
    @Override
    @Transactional
    public User update(Long id, UserDTO dto) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new BusinessException("用户不存在"));
        BeanUtils.copyProperties(dto, user, "id", "createTime");
        return userRepository.save(user);
    }
    
    @Override
    @Transactional
    public void delete(Long id) {
        userRepository.deleteById(id);
    }
}
```


---

## 8. 安全认证

### 8.1 Spring Security 基础配置

```java
// ============ 安全配置类 ============
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    
    @Autowired
    private AuthenticationEntryPointImpl authenticationEntryPoint;
    
    @Autowired
    private AccessDeniedHandlerImpl accessDeniedHandler;
    
    /**
     * 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    /**
     * 认证管理器
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    /**
     * 配置认证
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());
    }
    
    /**
     * 配置 HTTP 安全
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // 关闭 CSRF
            .csrf().disable()
            // 不使用 Session
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // 配置请求授权
            .authorizeRequests()
                // 允许匿名访问
                .antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/public/**").permitAll()
                .antMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                // 其他请求需要认证
                .anyRequest().authenticated()
            .and()
            // 异常处理
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            .and()
            // 添加 JWT 过滤器
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        // 允许跨域
        http.cors();
    }
    
    /**
     * 配置静态资源放行
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(
            "/static/**",
            "/favicon.ico",
            "/error"
        );
    }
}
```

### 8.2 JWT 认证实现

```java
// ============ JWT 工具类 ============
@Component
public class JwtUtils {
    
    @Value("${jwt.secret:mySecretKey123456789}")
    private String secret;
    
    @Value("${jwt.expiration:86400000}")
    private Long expiration;
    
    /**
     * 生成 Token
     */
    public String generateToken(String username, Map<String, Object> claims) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
    
    /**
     * 解析 Token
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }
    
    /**
     * 获取用户名
     */
    public String getUsernameFromToken(String token) {
        return parseToken(token).getSubject();
    }
    
    /**
     * 验证 Token
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = parseToken(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}

// ============ JWT 认证过滤器 ============
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtUtils jwtUtils;
    
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 获取 Token
        String token = getTokenFromRequest(request);
        
        if (StringUtils.hasText(token) && jwtUtils.validateToken(token)) {
            try {
                String username = jwtUtils.getUsernameFromToken(token);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                log.error("JWT 认证失败", e);
            }
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

// ============ UserDetailsService 实现 ============
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));
        
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getStatus() == UserStatus.ACTIVE,  // enabled
                true,  // accountNonExpired
                true,  // credentialsNonExpired
                true,  // accountNonLocked
                getAuthorities(user.getRoles())
        );
    }
    
    private Collection<? extends GrantedAuthority> getAuthorities(Set<Role> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());
    }
}
```

### 8.3 认证异常处理

```java
// ============ 认证入口点（未登录处理） ============
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    
    @Override
    public void commence(HttpServletRequest request,
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        
        Result<Void> result = Result.error(401, "未登录或登录已过期");
        response.getWriter().write(new ObjectMapper().writeValueAsString(result));
    }
}

// ============ 访问拒绝处理（权限不足） ============
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    
    @Override
    public void handle(HttpServletRequest request,
                      HttpServletResponse response,
                      AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        
        Result<Void> result = Result.error(403, "权限不足");
        response.getWriter().write(new ObjectMapper().writeValueAsString(result));
    }
}
```

### 8.4 登录认证接口

```java
// ============ 认证控制器 ============
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtUtils jwtUtils;
    
    @Autowired
    private UserService userService;
    
    /**
     * 登录
     */
    @PostMapping("/login")
    public Result<LoginVO> login(@RequestBody @Valid LoginDTO loginDTO) {
        // 认证
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginDTO.getUsername(), 
                loginDTO.getPassword()
            )
        );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // 生成 Token
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        
        String token = jwtUtils.generateToken(userDetails.getUsername(), claims);
        
        LoginVO loginVO = new LoginVO();
        loginVO.setToken(token);
        loginVO.setUsername(userDetails.getUsername());
        
        return Result.success(loginVO);
    }
    
    /**
     * 注册
     */
    @PostMapping("/register")
    public Result<Void> register(@RequestBody @Valid RegisterDTO registerDTO) {
        userService.register(registerDTO);
        return Result.success();
    }
    
    /**
     * 获取当前用户信息
     */
    @GetMapping("/info")
    public Result<UserVO> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        UserVO userVO = userService.findByUsername(username);
        return Result.success(userVO);
    }
    
    /**
     * 退出登录
     */
    @PostMapping("/logout")
    public Result<Void> logout() {
        SecurityContextHolder.clearContext();
        return Result.success();
    }
}

// ============ DTO 类 ============
@Data
public class LoginDTO {
    @NotBlank(message = "用户名不能为空")
    private String username;
    
    @NotBlank(message = "密码不能为空")
    private String password;
}

@Data
public class RegisterDTO {
    @NotBlank(message = "用户名不能为空")
    @Size(min = 4, max = 20, message = "用户名长度4-20位")
    private String username;
    
    @NotBlank(message = "密码不能为空")
    @Size(min = 6, max = 20, message = "密码长度6-20位")
    private String password;
    
    @Email(message = "邮箱格式不正确")
    private String email;
}

@Data
public class LoginVO {
    private String token;
    private String username;
    private List<String> roles;
}
```

### 8.5 方法级权限控制

```java
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    /**
     * 需要 ADMIN 角色
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public Result<List<UserVO>> getAllUsers() {
        return Result.success(userService.findAll());
    }
    
    /**
     * 需要 ADMIN 或 MANAGER 角色
     */
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @GetMapping("/reports")
    public Result<List<Report>> getReports() {
        return Result.success(reportService.findAll());
    }
    
    /**
     * 需要特定权限
     */
    @PreAuthorize("hasAuthority('user:delete')")
    @DeleteMapping("/users/{id}")
    public Result<Void> deleteUser(@PathVariable Long id) {
        userService.delete(id);
        return Result.success();
    }
    
    /**
     * 使用 SpEL 表达式
     */
    @PreAuthorize("#id == authentication.principal.id or hasRole('ADMIN')")
    @GetMapping("/users/{id}")
    public Result<UserVO> getUser(@PathVariable Long id) {
        return Result.success(userService.findById(id));
    }
    
    /**
     * 方法执行后校验
     */
    @PostAuthorize("returnObject.data.username == authentication.name")
    @GetMapping("/profile")
    public Result<UserVO> getProfile() {
        return Result.success(userService.getCurrentUser());
    }
}
```


---

## 9. 定时任务

### 9.1 Spring Task

```java
// ============ 启用定时任务 ============
@SpringBootApplication
@EnableScheduling
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

// ============ 定时任务类 ============
@Component
@Slf4j
public class ScheduledTasks {
    
    /**
     * 固定频率执行（上次开始后间隔）
     */
    @Scheduled(fixedRate = 5000)
    public void fixedRateTask() {
        log.info("固定频率任务执行: {}", LocalDateTime.now());
    }
    
    /**
     * 固定延迟执行（上次结束后间隔）
     */
    @Scheduled(fixedDelay = 5000)
    public void fixedDelayTask() {
        log.info("固定延迟任务执行: {}", LocalDateTime.now());
    }
    
    /**
     * 初始延迟 + 固定频率
     */
    @Scheduled(initialDelay = 1000, fixedRate = 5000)
    public void initialDelayTask() {
        log.info("初始延迟任务执行: {}", LocalDateTime.now());
    }
    
    /**
     * Cron 表达式
     * 秒 分 时 日 月 周
     */
    @Scheduled(cron = "0 0 2 * * ?")  // 每天凌晨2点执行
    public void cronTask() {
        log.info("Cron任务执行: {}", LocalDateTime.now());
    }
    
    /**
     * 从配置文件读取 Cron 表达式
     */
    @Scheduled(cron = "${task.cron.cleanup:0 0 3 * * ?}")
    public void configCronTask() {
        log.info("配置Cron任务执行: {}", LocalDateTime.now());
    }
}

// ============ 定时任务配置 ============
@Configuration
@EnableScheduling
public class ScheduleConfig implements SchedulingConfigurer {
    
    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        taskRegistrar.setScheduler(taskExecutor());
    }
    
    @Bean
    public Executor taskExecutor() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(10);
        scheduler.setThreadNamePrefix("scheduled-task-");
        scheduler.setAwaitTerminationSeconds(60);
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        return scheduler;
    }
}
```

### 9.2 动态定时任务

```java
// ============ 动态任务管理 ============
@Service
@Slf4j
public class DynamicTaskService {
    
    @Autowired
    private ThreadPoolTaskScheduler taskScheduler;
    
    private final Map<String, ScheduledFuture<?>> taskFutures = new ConcurrentHashMap<>();
    
    /**
     * 添加定时任务
     */
    public void addTask(String taskId, String cron, Runnable task) {
        if (taskFutures.containsKey(taskId)) {
            log.warn("任务已存在: {}", taskId);
            return;
        }
        
        ScheduledFuture<?> future = taskScheduler.schedule(task, new CronTrigger(cron));
        taskFutures.put(taskId, future);
        log.info("添加定时任务: {}, cron: {}", taskId, cron);
    }
    
    /**
     * 移除定时任务
     */
    public void removeTask(String taskId) {
        ScheduledFuture<?> future = taskFutures.remove(taskId);
        if (future != null) {
            future.cancel(true);
            log.info("移除定时任务: {}", taskId);
        }
    }
    
    /**
     * 修改定时任务
     */
    public void updateTask(String taskId, String cron, Runnable task) {
        removeTask(taskId);
        addTask(taskId, cron, task);
    }
    
    /**
     * 查询所有任务
     */
    public Set<String> getAllTasks() {
        return taskFutures.keySet();
    }
}

// ============ 任务调度器 Bean ============
@Configuration
public class TaskSchedulerConfig {
    
    @Bean
    public ThreadPoolTaskScheduler threadPoolTaskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(10);
        scheduler.setThreadNamePrefix("dynamic-task-");
        scheduler.initialize();
        return scheduler;
    }
}
```

---

## 10. 异步处理

### 10.1 @Async 异步方法

```java
// ============ 启用异步 ============
@SpringBootApplication
@EnableAsync
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

// ============ 异步配置 ============
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {
    
    @Override
    @Bean("asyncExecutor")
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(100);
        executor.setKeepAliveSeconds(60);
        executor.setThreadNamePrefix("async-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }
    
    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (ex, method, params) -> {
            log.error("异步方法异常: method={}, params={}", method.getName(), params, ex);
        };
    }
}

// ============ 异步服务 ============
@Service
@Slf4j
public class AsyncService {
    
    /**
     * 无返回值的异步方法
     */
    @Async
    public void asyncTask() {
        log.info("异步任务开始执行，线程: {}", Thread.currentThread().getName());
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        log.info("异步任务执行完成");
    }
    
    /**
     * 有返回值的异步方法
     */
    @Async
    public Future<String> asyncTaskWithResult() {
        log.info("异步任务开始执行");
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return new AsyncResult<>("任务执行完成");
    }
    
    /**
     * 使用 CompletableFuture
     */
    @Async
    public CompletableFuture<User> asyncFindUser(Long id) {
        log.info("异步查询用户: {}", id);
        User user = userRepository.findById(id).orElse(null);
        return CompletableFuture.completedFuture(user);
    }
    
    /**
     * 指定线程池
     */
    @Async("asyncExecutor")
    public void asyncTaskWithExecutor() {
        log.info("使用指定线程池执行异步任务");
    }
}

// ============ 调用异步方法 ============
@RestController
@RequestMapping("/api/async")
public class AsyncController {
    
    @Autowired
    private AsyncService asyncService;
    
    @GetMapping("/task")
    public Result<String> executeAsync() {
        asyncService.asyncTask();
        return Result.success("任务已提交");
    }
    
    @GetMapping("/result")
    public Result<String> executeAsyncWithResult() throws Exception {
        Future<String> future = asyncService.asyncTaskWithResult();
        // 等待结果（阻塞）
        String result = future.get(5, TimeUnit.SECONDS);
        return Result.success(result);
    }
    
    @GetMapping("/users")
    public Result<List<User>> getUsers() throws Exception {
        // 并行查询多个用户
        CompletableFuture<User> user1 = asyncService.asyncFindUser(1L);
        CompletableFuture<User> user2 = asyncService.asyncFindUser(2L);
        CompletableFuture<User> user3 = asyncService.asyncFindUser(3L);
        
        // 等待所有任务完成
        CompletableFuture.allOf(user1, user2, user3).join();
        
        List<User> users = Arrays.asList(user1.get(), user2.get(), user3.get());
        return Result.success(users);
    }
}
```

### 10.2 事件驱动

```java
// ============ 自定义事件 ============
@Data
@AllArgsConstructor
public class UserRegisteredEvent {
    private Long userId;
    private String username;
    private String email;
}

// ============ 发布事件 ============
@Service
public class UserService {
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    @Transactional
    public User register(RegisterDTO dto) {
        User user = new User();
        BeanUtils.copyProperties(dto, user);
        user = userRepository.save(user);
        
        // 发布事件
        eventPublisher.publishEvent(new UserRegisteredEvent(
            user.getId(), user.getUsername(), user.getEmail()));
        
        return user;
    }
}

// ============ 监听事件 ============
@Component
@Slf4j
public class UserEventListener {
    
    /**
     * 同步监听
     */
    @EventListener
    public void handleUserRegistered(UserRegisteredEvent event) {
        log.info("用户注册事件: {}", event.getUsername());
    }
    
    /**
     * 异步监听
     */
    @Async
    @EventListener
    public void sendWelcomeEmail(UserRegisteredEvent event) {
        log.info("发送欢迎邮件给: {}", event.getEmail());
        // 发送邮件逻辑
    }
    
    /**
     * 条件监听
     */
    @EventListener(condition = "#event.email != null")
    public void handleWithCondition(UserRegisteredEvent event) {
        log.info("有邮箱的用户注册: {}", event.getEmail());
    }
    
    /**
     * 监听多个事件
     */
    @EventListener({UserRegisteredEvent.class, UserUpdatedEvent.class})
    public void handleMultipleEvents(Object event) {
        log.info("用户事件: {}", event);
    }
}
```

---

## 11. 日志配置

### 11.1 Logback 配置

```xml
<!-- logback-spring.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration scan="true" scanPeriod="60 seconds">
    
    <!-- 定义变量 -->
    <property name="LOG_PATH" value="./logs"/>
    <property name="APP_NAME" value="demo"/>
    
    <!-- 控制台输出 -->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
        </encoder>
    </appender>
    
    <!-- 文件输出 -->
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${LOG_PATH}/${APP_NAME}.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>${LOG_PATH}/${APP_NAME}.%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>100MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <maxHistory>30</maxHistory>
            <totalSizeCap>3GB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
        </encoder>
    </appender>
    
    <!-- 错误日志单独输出 -->
    <appender name="ERROR_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${LOG_PATH}/${APP_NAME}-error.log</file>
        <filter class="ch.qos.logback.classic.filter.ThresholdFilter">
            <level>ERROR</level>
        </filter>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>${LOG_PATH}/${APP_NAME}-error.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <!-- 异步日志 -->
    <appender name="ASYNC_FILE" class="ch.qos.logback.classic.AsyncAppender">
        <discardingThreshold>0</discardingThreshold>
        <queueSize>512</queueSize>
        <appender-ref ref="FILE"/>
    </appender>
    
    <!-- 指定包的日志级别 -->
    <logger name="com.example.demo" level="DEBUG"/>
    <logger name="org.springframework" level="INFO"/>
    <logger name="org.hibernate.SQL" level="DEBUG"/>
    
    <!-- 根日志配置 -->
    <root level="INFO">
        <appender-ref ref="CONSOLE"/>
        <appender-ref ref="ASYNC_FILE"/>
        <appender-ref ref="ERROR_FILE"/>
    </root>
    
    <!-- 多环境配置 -->
    <springProfile name="dev">
        <root level="DEBUG">
            <appender-ref ref="CONSOLE"/>
        </root>
    </springProfile>
    
    <springProfile name="prod">
        <root level="INFO">
            <appender-ref ref="ASYNC_FILE"/>
            <appender-ref ref="ERROR_FILE"/>
        </root>
    </springProfile>
    
</configuration>
```

### 11.2 日志使用

```java
// ============ 使用 Lombok @Slf4j ============
@Slf4j
@Service
public class UserService {
    
    public User findById(Long id) {
        log.debug("查询用户: id={}", id);
        
        User user = userRepository.findById(id).orElse(null);
        
        if (user == null) {
            log.warn("用户不存在: id={}", id);
        } else {
            log.info("查询用户成功: username={}", user.getUsername());
        }
        
        return user;
    }
    
    public void processOrder(Order order) {
        log.info("开始处理订单: orderId={}, userId={}", order.getId(), order.getUserId());
        
        try {
            // 业务逻辑
            log.debug("订单详情: {}", order);
        } catch (Exception e) {
            log.error("订单处理失败: orderId={}", order.getId(), e);
            throw e;
        }
    }
}

// ============ MDC 链路追踪 ============
@Component
public class TraceFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        try {
            String traceId = UUID.randomUUID().toString().replace("-", "");
            MDC.put("traceId", traceId);
            chain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }
}

// logback 配置中使用 traceId
// <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%X{traceId}] [%thread] %-5level %logger{50} - %msg%n</pattern>
```


---

## 12. 测试

### 12.1 单元测试

```java
// ============ Service 层测试 ============
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @InjectMocks
    private UserServiceImpl userService;
    
    @Test
    void findById_WhenUserExists_ShouldReturnUser() {
        // Given
        Long userId = 1L;
        User user = new User();
        user.setId(userId);
        user.setUsername("test");
        
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        
        // When
        User result = userService.findById(userId);
        
        // Then
        assertNotNull(result);
        assertEquals("test", result.getUsername());
        verify(userRepository, times(1)).findById(userId);
    }
    
    @Test
    void findById_WhenUserNotExists_ShouldThrowException() {
        // Given
        Long userId = 1L;
        when(userRepository.findById(userId)).thenReturn(Optional.empty());
        
        // When & Then
        assertThrows(BusinessException.class, () -> userService.findById(userId));
    }
    
    @Test
    void create_ShouldSaveAndReturnUser() {
        // Given
        UserDTO dto = new UserDTO();
        dto.setUsername("newuser");
        dto.setEmail("test@example.com");
        
        User savedUser = new User();
        savedUser.setId(1L);
        savedUser.setUsername("newuser");
        
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        
        // When
        User result = userService.create(dto);
        
        // Then
        assertNotNull(result);
        assertEquals(1L, result.getId());
        verify(userRepository).save(any(User.class));
    }
}
```

### 12.2 集成测试

```java
// ============ Controller 层测试 ============
@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @MockBean
    private UserService userService;
    
    @Test
    void getUser_ShouldReturnUser() throws Exception {
        // Given
        UserVO userVO = new UserVO();
        userVO.setId(1L);
        userVO.setUsername("test");
        
        when(userService.findById(1L)).thenReturn(userVO);
        
        // When & Then
        mockMvc.perform(get("/api/users/1")
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.username").value("test"));
    }
    
    @Test
    void createUser_ShouldReturnCreatedUser() throws Exception {
        // Given
        UserDTO dto = new UserDTO();
        dto.setUsername("newuser");
        dto.setEmail("test@example.com");
        
        UserVO userVO = new UserVO();
        userVO.setId(1L);
        userVO.setUsername("newuser");
        
        when(userService.create(any(UserDTO.class))).thenReturn(userVO);
        
        // When & Then
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.id").value(1));
    }
    
    @Test
    void createUser_WithInvalidData_ShouldReturnBadRequest() throws Exception {
        // Given
        UserDTO dto = new UserDTO();
        dto.setUsername("");  // 空用户名
        
        // When & Then
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400));
    }
}

// ============ Repository 层测试 ============
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserRepositoryTest {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private TestEntityManager entityManager;
    
    @Test
    void findByUsername_ShouldReturnUser() {
        // Given
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("password");
        entityManager.persist(user);
        entityManager.flush();
        
        // When
        Optional<User> found = userRepository.findByUsername("testuser");
        
        // Then
        assertTrue(found.isPresent());
        assertEquals("testuser", found.get().getUsername());
    }
}
```

### 12.3 测试配置

```yaml
# application-test.yml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password: 
  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true
  redis:
    host: localhost
    port: 6379

logging:
  level:
    root: WARN
    com.example.demo: DEBUG
```

---

## 13. 部署与监控

### 13.1 Actuator 监控

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: "*"  # 暴露所有端点
      base-path: /actuator
  endpoint:
    health:
      show-details: always
    shutdown:
      enabled: true  # 启用关闭端点
  info:
    env:
      enabled: true

# 应用信息
info:
  app:
    name: ${spring.application.name}
    version: 1.0.0
    description: Demo Application
```

```java
// ============ 自定义健康检查 ============
@Component
public class CustomHealthIndicator implements HealthIndicator {
    
    @Override
    public Health health() {
        // 检查逻辑
        boolean isHealthy = checkService();
        
        if (isHealthy) {
            return Health.up()
                    .withDetail("service", "running")
                    .withDetail("time", LocalDateTime.now())
                    .build();
        } else {
            return Health.down()
                    .withDetail("error", "Service unavailable")
                    .build();
        }
    }
    
    private boolean checkService() {
        // 实际检查逻辑
        return true;
    }
}

// ============ 自定义端点 ============
@Component
@Endpoint(id = "custom")
public class CustomEndpoint {
    
    @ReadOperation
    public Map<String, Object> info() {
        Map<String, Object> info = new HashMap<>();
        info.put("status", "running");
        info.put("timestamp", System.currentTimeMillis());
        return info;
    }
    
    @WriteOperation
    public void update(@Selector String name, String value) {
        // 更新操作
    }
}
```

### 13.2 Docker 部署

```dockerfile
# Dockerfile
FROM openjdk:11-jre-slim

WORKDIR /app

COPY target/*.jar app.jar

ENV JAVA_OPTS="-Xms512m -Xmx512m"
ENV SPRING_PROFILES_ACTIVE=prod

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/demo
      - SPRING_REDIS_HOST=redis
    depends_on:
      - mysql
      - redis
    networks:
      - app-network

  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=root
      - MYSQL_DATABASE=demo
    volumes:
      - mysql-data:/var/lib/mysql
    networks:
      - app-network

  redis:
    image: redis:6-alpine
    networks:
      - app-network

networks:
  app-network:
    driver: bridge

volumes:
  mysql-data:
```

### 13.3 生产环境配置

```yaml
# application-prod.yml
server:
  port: 8080
  tomcat:
    max-threads: 200
    min-spare-threads: 20
    max-connections: 10000
    accept-count: 100

spring:
  datasource:
    url: jdbc:mysql://${DB_HOST:localhost}:3306/${DB_NAME:demo}?useSSL=true
    username: ${DB_USER:root}
    password: ${DB_PASSWORD:root}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      idle-timeout: 300000
      connection-timeout: 20000
      max-lifetime: 1200000

  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}
    password: ${REDIS_PASSWORD:}
    lettuce:
      pool:
        max-active: 20
        max-idle: 10
        min-idle: 5

logging:
  level:
    root: INFO
  file:
    name: /var/log/app/application.log
```

---

## 14. 常用注解速查

| 注解 | 说明 |
|------|------|
| `@SpringBootApplication` | 启动类注解，组合了 @Configuration、@EnableAutoConfiguration、@ComponentScan |
| `@RestController` | REST 控制器，组合了 @Controller 和 @ResponseBody |
| `@RequestMapping` | 请求映射 |
| `@GetMapping/@PostMapping` | GET/POST 请求映射 |
| `@PathVariable` | 路径参数 |
| `@RequestParam` | 查询参数 |
| `@RequestBody` | 请求体 |
| `@Valid` | 参数校验 |
| `@Service` | 服务层组件 |
| `@Repository` | 数据访问层组件 |
| `@Component` | 通用组件 |
| `@Autowired` | 自动注入 |
| `@Value` | 注入配置值 |
| `@ConfigurationProperties` | 配置属性绑定 |
| `@Transactional` | 事务管理 |
| `@Cacheable` | 缓存查询结果 |
| `@CacheEvict` | 清除缓存 |
| `@Async` | 异步方法 |
| `@Scheduled` | 定时任务 |
| `@PreAuthorize` | 方法级权限控制 |
| `@Slf4j` | Lombok 日志注解 |
