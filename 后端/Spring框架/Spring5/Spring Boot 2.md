

> 基于 Java 8 + Spring Boot 2.7.18
> 
> Spring Boot 是 Spring 框架的"脚手架"，它的核心理念是**约定优于配置**（Convention over Configuration）。简单来说，Spring Boot 帮你做了大量的默认配置，让你可以快速启动一个生产级别的应用，而不用像传统 Spring 那样写一堆 XML 配置文件。

---

## 目录

1. [环境搭建与项目创建](#1-环境搭建与项目创建)
2. [核心概念与启动原理](#2-核心概念与启动原理)
3. [配置文件详解](#3-配置文件详解)
4. [Web开发基础](#4-web开发基础)
5. [数据库集成](#5-数据库集成)
6. [事务管理](#6-事务管理)
7. [缓存集成](#7-缓存集成)
8. [安全集成](#8-安全集成)
9. [消息队列集成](#9-消息队列集成)
10. [任务调度](#10-任务调度)
11. [监控与日志](#11-监控与日志)
12. [API文档集成](#12-api文档集成)
13. [测试](#13-测试)
14. [打包与部署](#14-打包与部署)
15. [常见错误汇总](#15-常见错误汇总)

---

## 1. 环境搭建与项目创建

### 1.1 环境要求

在开始之前，确保你的开发环境满足以下要求：

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| JDK | 8+ | Spring Boot 2.7.x 支持 Java 8、11、17 |
| Maven | 3.5+ | 或 Gradle 6.8+ |
| IDE | 任意 | 推荐 IntelliJ IDEA |

### 1.2 创建项目的三种方式

#### 方式一：Spring Initializr（推荐新手）

访问 [https://start.spring.io](https://start.spring.io)，这是 Spring 官方提供的项目生成器。

配置选项说明：
- **Project**: Maven（传统稳定）或 Gradle（现代灵活）
- **Language**: Java
- **Spring Boot**: 选择 2.7.18
- **Group**: 公司/组织域名倒写，如 `com.example`
- **Artifact**: 项目名，如 `demo`
- **Packaging**: Jar（内嵌服务器）或 War（外部服务器）
- **Java**: 8

#### 方式二：IDEA 直接创建

`File → New → Project → Spring Initializr`

IDEA 内置了 Spring Initializr，本质上和网页版一样，但更方便。

#### 方式三：手动创建（理解原理）

1. 创建普通 Maven 项目
2. 添加 Spring Boot 父依赖
3. 添加所需 starter

### 1.3 pom.xml 详解

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <!-- 继承 Spring Boot 父项目，这是关键！ -->
    <!-- 它帮你管理了所有依赖的版本，避免版本冲突 -->
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.18</version>
        <relativePath/>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    
    <properties>
        <java.version>8</java.version>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    
    <dependencies>
        <!-- Web Starter：包含 Spring MVC、内嵌 Tomcat、JSON 处理等 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- 测试 Starter -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <!-- Spring Boot Maven 插件，用于打包可执行 jar -->
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

> **什么是 Starter？**
> 
> Starter 是 Spring Boot 的核心概念之一。它是一组预定义的依赖集合，帮你把相关的库打包在一起。比如 `spring-boot-starter-web` 包含了：
> - Spring MVC
> - 内嵌 Tomcat
> - Jackson（JSON 处理）
> - Validation（参数校验）
> 
> 你只需要引入一个 starter，就能获得完整的功能支持。

### 1.4 项目结构

```
src/
├── main/
│   ├── java/
│   │   └── com/example/demo/
│   │       ├── DemoApplication.java      # 启动类（必须在根包下）
│   │       ├── controller/               # 控制器层
│   │       ├── service/                  # 业务逻辑层
│   │       ├── repository/               # 数据访问层
│   │       ├── entity/                   # 实体类
│   │       ├── dto/                      # 数据传输对象
│   │       ├── config/                   # 配置类
│   │       └── util/                     # 工具类
│   └── resources/
│       ├── application.yml               # 主配置文件
│       ├── application-dev.yml           # 开发环境配置
│       ├── application-prod.yml          # 生产环境配置
│       ├── static/                       # 静态资源（CSS、JS、图片）
│       └── templates/                    # 模板文件（Thymeleaf等）
└── test/
    └── java/                             # 测试代码
```

### 1.5 启动类

```java
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot 启动类
 * 
 * @SpringBootApplication 是一个组合注解，等价于：
 * - @Configuration：标记为配置类
 * - @EnableAutoConfiguration：开启自动配置
 * - @ComponentScan：组件扫描（扫描当前包及子包）
 */
@SpringBootApplication
public class DemoApplication {
    
    public static void main(String[] args) {
        // SpringApplication.run() 做了什么？
        // 1. 创建 ApplicationContext（Spring 容器）
        // 2. 加载所有配置
        // 3. 执行自动配置
        // 4. 启动内嵌服务器
        // 5. 发布启动完成事件
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

> **⚠️ 常见错误 #1：启动类位置不对**
> 
> 启动类必须放在根包下（如 `com.example.demo`），否则 `@ComponentScan` 扫描不到子包中的组件。
> 
> 错误示例：
> ```
> com.example.demo.config.DemoApplication  ❌ 放在子包里了
> com.example.DemoApplication              ❌ 放在父包里了
> com.example.demo.DemoApplication         ✅ 正确位置
> ```

---

## 2. 核心概念与启动原理

### 2.1 自动配置原理

Spring Boot 的"魔法"核心就是**自动配置**。它是怎么工作的呢？

```
@SpringBootApplication
        ↓
@EnableAutoConfiguration
        ↓
@Import(AutoConfigurationImportSelector.class)
        ↓
读取 META-INF/spring.factories 文件
        ↓
加载所有 AutoConfiguration 类
        ↓
根据 @Conditional 条件判断是否生效
```

简单来说：
1. Spring Boot 启动时会扫描所有 jar 包中的 `META-INF/spring.factories` 文件
2. 这个文件里列出了所有的自动配置类
3. 每个自动配置类都有条件注解（如 `@ConditionalOnClass`）
4. 只有满足条件的配置才会生效

### 2.2 条件注解

条件注解决定了某个配置是否生效：

| 注解 | 说明 | 示例 |
|------|------|------|
| `@ConditionalOnClass` | 类路径存在指定类时生效 | 有 Redis 依赖才配置 Redis |
| `@ConditionalOnMissingClass` | 类路径不存在指定类时生效 | |
| `@ConditionalOnBean` | 容器中存在指定 Bean 时生效 | |
| `@ConditionalOnMissingBean` | 容器中不存在指定 Bean 时生效 | 用户没自定义才用默认的 |
| `@ConditionalOnProperty` | 配置文件中存在指定属性时生效 | |
| `@ConditionalOnWebApplication` | 是 Web 应用时生效 | |

```java
// 示例：只有当用户没有自定义 DataSource 时，才使用默认配置
@Configuration
@ConditionalOnClass(DataSource.class)
public class DataSourceAutoConfiguration {
    
    @Bean
    @ConditionalOnMissingBean
    public DataSource dataSource() {
        // 创建默认数据源
        return new HikariDataSource();
    }
}
```

### 2.3 IoC 与 DI

**IoC（控制反转）**：对象的创建和管理交给 Spring 容器，而不是自己 new。

**DI（依赖注入）**：Spring 自动把依赖的对象注入进来。

```java
// 传统方式（紧耦合）
public class UserService {
    private UserRepository userRepository = new UserRepository(); // 自己创建
}

// Spring 方式（松耦合）
@Service
public class UserService {
    
    @Autowired  // Spring 自动注入
    private UserRepository userRepository;
    
    // 或者使用构造器注入（推荐）
    private final UserRepository userRepository;
    
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}
```

> **为什么推荐构造器注入？**
> 1. 依赖不可变（final）
> 2. 依赖不为空（构造时就注入）
> 3. 方便单元测试（可以传入 Mock 对象）

### 2.4 常用注解速查

#### Bean 定义注解

| 注解 | 说明 | 使用场景 |
|------|------|----------|
| `@Component` | 通用组件 | 不好分类的组件 |
| `@Service` | 业务层 | Service 类 |
| `@Repository` | 数据层 | DAO 类 |
| `@Controller` | 控制层 | MVC 控制器 |
| `@RestController` | REST 控制器 | = @Controller + @ResponseBody |
| `@Configuration` | 配置类 | Java 配置 |
| `@Bean` | 方法级别 | 在配置类中定义 Bean |

#### 依赖注入注解

| 注解 | 说明 |
|------|------|
| `@Autowired` | 按类型注入（Spring） |
| `@Resource` | 按名称注入（JSR-250） |
| `@Qualifier` | 配合 @Autowired 指定名称 |
| `@Value` | 注入配置值 |

```java
@Service
public class UserService {
    
    // 注入配置文件中的值
    @Value("${app.name}")
    private String appName;
    
    // 注入 SpEL 表达式
    @Value("#{systemProperties['user.name']}")
    private String userName;
    
    // 设置默认值
    @Value("${app.timeout:30}")
    private int timeout;
}
```

---

## 3. 配置文件详解

### 3.1 配置文件类型

Spring Boot 支持两种配置文件格式：

| 格式 | 文件名 | 特点 |
|------|--------|------|
| Properties | application.properties | 传统格式，简单直观 |
| YAML | application.yml | 层级结构，更清晰 |

```properties
# application.properties
server.port=8080
spring.datasource.url=jdbc:mysql://localhost:3306/test
spring.datasource.username=root
spring.datasource.password=123456
```

```yaml
# application.yml（推荐）
server:
  port: 8080

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/test
    username: root
    password: 123456
```

> **YAML 注意事项**
> - 使用空格缩进，不能用 Tab
> - 冒号后面必须有空格
> - 大小写敏感

### 3.2 多环境配置

实际开发中，开发、测试、生产环境的配置往往不同。Spring Boot 提供了 Profile 机制。

```
application.yml          # 公共配置
application-dev.yml      # 开发环境
application-test.yml     # 测试环境
application-prod.yml     # 生产环境
```

```yaml
# application.yml
spring:
  profiles:
    active: dev  # 激活开发环境

# 公共配置
app:
  name: MyApp
```

```yaml
# application-dev.yml
server:
  port: 8080
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/dev_db
logging:
  level:
    root: DEBUG
```

```yaml
# application-prod.yml
server:
  port: 80
spring:
  datasource:
    url: jdbc:mysql://prod-server:3306/prod_db
logging:
  level:
    root: WARN
```

激活 Profile 的方式：

```bash
# 方式1：配置文件
spring.profiles.active=prod

# 方式2：命令行参数
java -jar app.jar --spring.profiles.active=prod

# 方式3：环境变量
export SPRING_PROFILES_ACTIVE=prod

# 方式4：JVM 参数
java -Dspring.profiles.active=prod -jar app.jar
```

### 3.3 配置绑定

将配置文件中的值绑定到 Java 对象：

```yaml
# application.yml
app:
  name: MyApp
  version: 1.0.0
  author:
    name: John
    email: john@example.com
  servers:
    - 192.168.1.1
    - 192.168.1.2
```

```java
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    
    private String name;
    private String version;
    private Author author;
    private List<String> servers;
    
    // 必须有 getter/setter
    
    public static class Author {
        private String name;
        private String email;
        // getter/setter
    }
}
```

> **⚠️ 常见错误 #2：@ConfigurationProperties 不生效**
> 
> 需要在启动类或配置类上添加 `@EnableConfigurationProperties(AppProperties.class)`
> 或者在属性类上添加 `@Component`

```java
// 方式1：在属性类上加 @Component
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties { }

// 方式2：在启动类上启用
@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class DemoApplication { }
```

### 3.4 配置加载顺序

Spring Boot 配置有优先级，后加载的会覆盖先加载的：

```
1. 默认属性（SpringApplication.setDefaultProperties）
2. @PropertySource 注解
3. application.properties / application.yml
4. application-{profile}.properties / application-{profile}.yml
5. 命令行参数
6. 环境变量
7. JVM 系统属性
```

> 简单记忆：**外部配置 > 内部配置，命令行 > 配置文件**

---

## 4. Web开发基础

### 4.1 RESTful API 开发

REST（Representational State Transfer）是一种 API 设计风格：

| HTTP 方法 | 操作 | 示例 |
|-----------|------|------|
| GET | 查询 | GET /users |
| POST | 创建 | POST /users |
| PUT | 全量更新 | PUT /users/1 |
| PATCH | 部分更新 | PATCH /users/1 |
| DELETE | 删除 | DELETE /users/1 |

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    // 查询所有用户
    @GetMapping
    public List<User> list() {
        return userService.findAll();
    }
    
    // 根据 ID 查询
    @GetMapping("/{id}")
    public User getById(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    // 创建用户
    @PostMapping
    public User create(@RequestBody @Valid User user) {
        return userService.save(user);
    }
    
    // 更新用户
    @PutMapping("/{id}")
    public User update(@PathVariable Long id, @RequestBody User user) {
        user.setId(id);
        return userService.update(user);
    }
    
    // 删除用户
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        userService.deleteById(id);
    }
    
    // 分页查询
    @GetMapping("/page")
    public Page<User> page(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return userService.findPage(page, size);
    }
}
```

### 4.2 请求参数处理

```java
@RestController
@RequestMapping("/api")
public class ParamController {
    
    // 1. 路径参数 @PathVariable
    // GET /api/users/123
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable("id") Long userId) {
        return userService.findById(userId);
    }
    
    // 2. 查询参数 @RequestParam
    // GET /api/search?keyword=john&page=1
    @GetMapping("/search")
    public List<User> search(
            @RequestParam String keyword,
            @RequestParam(required = false, defaultValue = "1") Integer page) {
        return userService.search(keyword, page);
    }
    
    // 3. 请求体 @RequestBody
    // POST /api/users  Body: {"name":"John","age":25}
    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return userService.save(user);
    }
    
    // 4. 请求头 @RequestHeader
    @GetMapping("/info")
    public String getInfo(@RequestHeader("Authorization") String token) {
        return "Token: " + token;
    }
    
    // 5. Cookie @CookieValue
    @GetMapping("/cookie")
    public String getCookie(@CookieValue("sessionId") String sessionId) {
        return "Session: " + sessionId;
    }
}
```

### 4.3 参数校验

Spring Boot 集成了 Hibernate Validator，可以方便地进行参数校验。

```xml
<!-- 添加依赖（Spring Boot 2.3+ 需要手动添加） -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

```java
// 实体类添加校验注解
public class User {
    
    @NotNull(message = "ID不能为空")
    private Long id;
    
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 20, message = "用户名长度必须在2-20之间")
    private String username;
    
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @Min(value = 0, message = "年龄不能小于0")
    @Max(value = 150, message = "年龄不能大于150")
    private Integer age;
    
    @Pattern(regexp = "^1[3-9]\\d{9}$", message = "手机号格式不正确")
    private String phone;
    
    @Past(message = "生日必须是过去的日期")
    private Date birthday;
    
    // getter/setter
}
```

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // 使用 @Valid 或 @Validated 触发校验
    @PostMapping
    public Result create(@RequestBody @Valid User user) {
        return Result.success(userService.save(user));
    }
    
    // 分组校验
    @PutMapping
    public Result update(@RequestBody @Validated(Update.class) User user) {
        return Result.success(userService.update(user));
    }
}

// 分组接口
public interface Create {}
public interface Update {}

// 实体类使用分组
public class User {
    @NotNull(groups = Update.class)  // 只在更新时校验
    private Long id;
    
    @NotBlank(groups = {Create.class, Update.class})
    private String username;
}
```

常用校验注解：

| 注解 | 说明 |
|------|------|
| `@NotNull` | 不能为 null |
| `@NotEmpty` | 不能为 null 且不能为空（字符串、集合） |
| `@NotBlank` | 不能为 null 且去除空格后长度 > 0 |
| `@Size(min, max)` | 长度范围 |
| `@Min` / `@Max` | 数值范围 |
| `@Email` | 邮箱格式 |
| `@Pattern` | 正则表达式 |
| `@Past` / `@Future` | 过去/未来的日期 |

### 4.4 统一响应格式

实际项目中，API 响应需要统一格式：

```java
/**
 * 统一响应结果
 */
public class Result<T> {
    
    private Integer code;      // 状态码
    private String message;    // 消息
    private T data;            // 数据
    private Long timestamp;    // 时间戳
    
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(200);
        result.setMessage("success");
        result.setData(data);
        result.setTimestamp(System.currentTimeMillis());
        return result;
    }
    
    public static <T> Result<T> error(Integer code, String message) {
        Result<T> result = new Result<>();
        result.setCode(code);
        result.setMessage(message);
        result.setTimestamp(System.currentTimeMillis());
        return result;
    }
    
    // getter/setter
}
```

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @GetMapping("/{id}")
    public Result<User> getById(@PathVariable Long id) {
        User user = userService.findById(id);
        return Result.success(user);
    }
}
```

响应示例：
```json
{
    "code": 200,
    "message": "success",
    "data": {
        "id": 1,
        "username": "john",
        "email": "john@example.com"
    },
    "timestamp": 1703500800000
}
```

### 4.5 全局异常处理

使用 `@ControllerAdvice` 统一处理异常：

```java
/**
 * 全局异常处理器
 */
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    
    /**
     * 处理参数校验异常
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<Void> handleValidationException(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return Result.error(400, message);
    }
    
    /**
     * 处理业务异常
     */
    @ExceptionHandler(BusinessException.class)
    public Result<Void> handleBusinessException(BusinessException e) {
        log.warn("业务异常: {}", e.getMessage());
        return Result.error(e.getCode(), e.getMessage());
    }
    
    /**
     * 处理资源不存在异常
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public Result<Void> handleNotFoundException(ResourceNotFoundException e) {
        return Result.error(404, e.getMessage());
    }
    
    /**
     * 处理所有未捕获的异常
     */
    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("系统异常", e);
        return Result.error(500, "系统繁忙，请稍后重试");
    }
}

/**
 * 自定义业务异常
 */
public class BusinessException extends RuntimeException {
    
    private Integer code;
    
    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
    }
    
    public Integer getCode() {
        return code;
    }
}
```

### 4.6 拦截器

拦截器用于在请求处理前后执行通用逻辑：

```java
/**
 * 登录拦截器
 */
@Component
public class LoginInterceptor implements HandlerInterceptor {
    
    /**
     * 请求处理前执行
     * 返回 true 继续执行，返回 false 中断请求
     */
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        String token = request.getHeader("Authorization");
        if (token == null || !validateToken(token)) {
            response.setStatus(401);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":401,\"message\":\"未登录\"}");
            return false;
        }
        return true;
    }
    
    /**
     * 请求处理后执行（视图渲染前）
     */
    @Override
    public void postHandle(HttpServletRequest request, 
                          HttpServletResponse response, 
                          Object handler, 
                          ModelAndView modelAndView) throws Exception {
        // 可以修改 ModelAndView
    }
    
    /**
     * 请求完成后执行（视图渲染后）
     */
    @Override
    public void afterCompletion(HttpServletRequest request, 
                               HttpServletResponse response, 
                               Object handler, 
                               Exception ex) throws Exception {
        // 清理资源
    }
    
    private boolean validateToken(String token) {
        // 验证 token 逻辑
        return true;
    }
}

/**
 * 注册拦截器
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Autowired
    private LoginInterceptor loginInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(loginInterceptor)
                .addPathPatterns("/api/**")           // 拦截的路径
                .excludePathPatterns("/api/login",    // 排除的路径
                                    "/api/register",
                                    "/api/public/**");
    }
}
```

### 4.7 过滤器

过滤器是 Servlet 规范的一部分，比拦截器更底层：

```java
/**
 * 跨域过滤器
 */
@Component
@Order(1)  // 执行顺序，数字越小越先执行
public class CorsFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, 
                        ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.setHeader("Access-Control-Max-Age", "3600");
        
        chain.doFilter(request, response);
    }
}
```

> **拦截器 vs 过滤器**
> 
> | 特性 | 过滤器 Filter | 拦截器 Interceptor |
> |------|--------------|-------------------|
> | 规范 | Servlet | Spring |
> | 作用范围 | 所有请求 | Spring MVC 请求 |
> | 获取 Bean | 不方便 | 方便 |
> | 执行顺序 | 先于拦截器 | 后于过滤器 |

### 4.8 跨域配置

```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000", "https://example.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }
}

// 或者使用注解（针对单个 Controller）
@RestController
@CrossOrigin(origins = "http://localhost:3000")
public class UserController {
    // ...
}
```

---

## 5. 数据库集成

### 5.1 数据源配置

```xml
<!-- pom.xml 添加依赖 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <scope>runtime</scope>
</dependency>
```

```yaml
# application.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/test?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai
    username: root
    password: 123456
    driver-class-name: com.mysql.cj.jdbc.Driver
    
    # HikariCP 连接池配置（Spring Boot 2.x 默认）
    hikari:
      minimum-idle: 5           # 最小空闲连接数
      maximum-pool-size: 20     # 最大连接数
      idle-timeout: 30000       # 空闲超时时间（毫秒）
      connection-timeout: 30000 # 连接超时时间
      max-lifetime: 1800000     # 连接最大存活时间
```

> **⚠️ 常见错误 #3：时区问题**
> 
> MySQL 8.0+ 需要指定时区，否则会报错：
> ```
> The server time zone value 'xxx' is unrecognized
> ```
> 解决：在 URL 中添加 `serverTimezone=Asia/Shanghai`

### 5.2 JdbcTemplate

Spring 提供的轻量级数据库操作工具：

```java
@Repository
public class UserDao {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // 查询单个对象
    public User findById(Long id) {
        String sql = "SELECT * FROM user WHERE id = ?";
        return jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper<>(User.class), id);
    }
    
    // 查询列表
    public List<User> findAll() {
        String sql = "SELECT * FROM user";
        return jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(User.class));
    }
    
    // 插入
    public int insert(User user) {
        String sql = "INSERT INTO user(username, email, age) VALUES(?, ?, ?)";
        return jdbcTemplate.update(sql, user.getUsername(), user.getEmail(), user.getAge());
    }
    
    // 更新
    public int update(User user) {
        String sql = "UPDATE user SET username = ?, email = ? WHERE id = ?";
        return jdbcTemplate.update(sql, user.getUsername(), user.getEmail(), user.getId());
    }
    
    // 删除
    public int delete(Long id) {
        String sql = "DELETE FROM user WHERE id = ?";
        return jdbcTemplate.update(sql, id);
    }
    
    // 批量插入
    public int[] batchInsert(List<User> users) {
        String sql = "INSERT INTO user(username, email) VALUES(?, ?)";
        return jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                User user = users.get(i);
                ps.setString(1, user.getUsername());
                ps.setString(2, user.getEmail());
            }
            
            @Override
            public int getBatchSize() {
                return users.size();
            }
        });
    }
}
```

### 5.3 Spring Data JPA

JPA（Java Persistence API）是 ORM 规范，Hibernate 是其实现。Spring Data JPA 进一步简化了使用。

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: update  # 自动更新表结构
    show-sql: true      # 显示 SQL
    properties:
      hibernate:
        format_sql: true  # 格式化 SQL
```

```java
/**
 * 实体类
 */
@Entity
@Table(name = "user")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 50)
    private String username;
    
    @Column(unique = true)
    private String email;
    
    private Integer age;
    
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "create_time")
    private Date createTime;
    
    @Enumerated(EnumType.STRING)
    private UserStatus status;
    
    // getter/setter
}

/**
 * Repository 接口
 * 继承 JpaRepository 即可获得基本的 CRUD 方法
 */
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 方法名查询（Spring Data JPA 会自动实现）
    User findByUsername(String username);
    
    List<User> findByAgeGreaterThan(Integer age);
    
    List<User> findByUsernameContaining(String keyword);
    
    List<User> findByStatusAndAgeBetween(UserStatus status, Integer minAge, Integer maxAge);
    
    // @Query 自定义查询
    @Query("SELECT u FROM User u WHERE u.email LIKE %:keyword%")
    List<User> searchByEmail(@Param("keyword") String keyword);
    
    // 原生 SQL
    @Query(value = "SELECT * FROM user WHERE age > ?1", nativeQuery = true)
    List<User> findByAgeNative(Integer age);
    
    // 更新操作
    @Modifying
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") UserStatus status);
}
```

```java
/**
 * Service 层使用
 */
@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("用户不存在"));
    }
    
    public Page<User> findPage(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createTime").descending());
        return userRepository.findAll(pageable);
    }
    
    public User save(User user) {
        user.setCreateTime(new Date());
        return userRepository.save(user);
    }
    
    public void deleteById(Long id) {
        userRepository.deleteById(id);
    }
}
```

JPA 方法名关键字：

| 关键字 | 示例 | JPQL |
|--------|------|------|
| And | findByNameAndAge | where name=? and age=? |
| Or | findByNameOrAge | where name=? or age=? |
| Between | findByAgeBetween | where age between ? and ? |
| LessThan | findByAgeLessThan | where age < ? |
| GreaterThan | findByAgeGreaterThan | where age > ? |
| Like | findByNameLike | where name like ? |
| Containing | findByNameContaining | where name like %?% |
| In | findByAgeIn | where age in (?) |
| OrderBy | findByAgeOrderByNameDesc | where age=? order by name desc |
| Not | findByNameNot | where name <> ? |
| IsNull | findByNameIsNull | where name is null |

### 5.4 MyBatis 集成

MyBatis 是另一个流行的持久层框架，更灵活，适合复杂 SQL。

```xml
<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>2.3.1</version>
</dependency>
```

```yaml
mybatis:
  mapper-locations: classpath:mapper/*.xml  # Mapper XML 文件位置
  type-aliases-package: com.example.entity  # 实体类包名
  configuration:
    map-underscore-to-camel-case: true      # 下划线转驼峰
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl  # 打印 SQL
```

```java
/**
 * Mapper 接口
 */
@Mapper
public interface UserMapper {
    
    // 注解方式
    @Select("SELECT * FROM user WHERE id = #{id}")
    User findById(Long id);
    
    @Insert("INSERT INTO user(username, email) VALUES(#{username}, #{email})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(User user);
    
    @Update("UPDATE user SET username = #{username} WHERE id = #{id}")
    int update(User user);
    
    @Delete("DELETE FROM user WHERE id = #{id}")
    int delete(Long id);
    
    // XML 方式（复杂 SQL 推荐）
    List<User> findByCondition(UserQuery query);
}
```

```xml
<!-- resources/mapper/UserMapper.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" 
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mapper.UserMapper">
    
    <!-- 结果映射 -->
    <resultMap id="userResultMap" type="User">
        <id property="id" column="id"/>
        <result property="username" column="username"/>
        <result property="createTime" column="create_time"/>
    </resultMap>
    
    <!-- 动态 SQL -->
    <select id="findByCondition" resultMap="userResultMap">
        SELECT * FROM user
        <where>
            <if test="username != null and username != ''">
                AND username LIKE CONCAT('%', #{username}, '%')
            </if>
            <if test="minAge != null">
                AND age >= #{minAge}
            </if>
            <if test="maxAge != null">
                AND age &lt;= #{maxAge}
            </if>
            <if test="status != null">
                AND status = #{status}
            </if>
        </where>
        ORDER BY create_time DESC
    </select>
    
    <!-- 批量插入 -->
    <insert id="batchInsert">
        INSERT INTO user(username, email) VALUES
        <foreach collection="list" item="user" separator=",">
            (#{user.username}, #{user.email})
        </foreach>
    </insert>
    
</mapper>
```

> **⚠️ 常见错误 #4：Mapper 扫描不到**
> 
> 解决方案：
> 1. 在 Mapper 接口上加 `@Mapper` 注解
> 2. 或在启动类上加 `@MapperScan("com.example.mapper")`

---

## 6. 事务管理

### 6.1 声明式事务

Spring Boot 默认开启了事务管理，只需使用 `@Transactional` 注解：

```java
@Service
public class OrderService {
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Autowired
    private InventoryService inventoryService;
    
    /**
     * @Transactional 注解说明：
     * - 方法执行成功，自动提交事务
     * - 方法抛出异常，自动回滚事务
     */
    @Transactional
    public Order createOrder(Order order) {
        // 1. 保存订单
        orderRepository.save(order);
        
        // 2. 扣减库存（如果失败，订单也会回滚）
        inventoryService.deduct(order.getProductId(), order.getQuantity());
        
        return order;
    }
    
    /**
     * 只读事务（优化查询性能）
     */
    @Transactional(readOnly = true)
    public List<Order> findAll() {
        return orderRepository.findAll();
    }
}
```

### 6.2 事务属性

```java
@Transactional(
    propagation = Propagation.REQUIRED,     // 传播行为
    isolation = Isolation.DEFAULT,          // 隔离级别
    timeout = 30,                           // 超时时间（秒）
    readOnly = false,                       // 是否只读
    rollbackFor = Exception.class,          // 哪些异常回滚
    noRollbackFor = BusinessException.class // 哪些异常不回滚
)
public void doSomething() { }
```

#### 传播行为（Propagation）

| 传播行为 | 说明 |
|----------|------|
| REQUIRED（默认） | 有事务就加入，没有就新建 |
| REQUIRES_NEW | 总是新建事务，挂起当前事务 |
| SUPPORTS | 有事务就加入，没有就非事务执行 |
| NOT_SUPPORTED | 非事务执行，挂起当前事务 |
| MANDATORY | 必须在事务中，否则抛异常 |
| NEVER | 必须非事务执行，否则抛异常 |
| NESTED | 嵌套事务（保存点） |

```java
@Service
public class UserService {
    
    @Autowired
    private LogService logService;
    
    @Transactional
    public void updateUser(User user) {
        // 更新用户
        userRepository.save(user);
        
        // 记录日志（即使日志失败，用户更新也要成功）
        logService.log("更新用户: " + user.getId());
    }
}

@Service
public class LogService {
    
    // REQUIRES_NEW：新建独立事务，不影响外层事务
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String message) {
        // 保存日志
    }
}
```

#### 隔离级别（Isolation）

| 隔离级别 | 脏读 | 不可重复读 | 幻读 |
|----------|------|------------|------|
| READ_UNCOMMITTED | ✓ | ✓ | ✓ |
| READ_COMMITTED | ✗ | ✓ | ✓ |
| REPEATABLE_READ | ✗ | ✗ | ✓ |
| SERIALIZABLE | ✗ | ✗ | ✗ |

> MySQL 默认是 REPEATABLE_READ，Oracle 默认是 READ_COMMITTED

### 6.3 事务失效场景

> **⚠️ 常见错误 #5：事务不生效**

```java
@Service
public class UserService {
    
    // ❌ 错误1：方法不是 public
    @Transactional
    private void updateUser(User user) { }
    
    // ❌ 错误2：自调用（同一个类中调用）
    public void doSomething() {
        this.updateUser(user);  // 事务不生效！
    }
    
    @Transactional
    public void updateUser(User user) { }
    
    // ❌ 错误3：异常被捕获了
    @Transactional
    public void createUser(User user) {
        try {
            userRepository.save(user);
            throw new RuntimeException("error");
        } catch (Exception e) {
            // 异常被捕获，事务不会回滚！
            log.error("error", e);
        }
    }
    
    // ❌ 错误4：抛出的是 checked 异常
    @Transactional
    public void createUser(User user) throws IOException {
        userRepository.save(user);
        throw new IOException("error");  // 默认不回滚 checked 异常
    }
    
    // ✅ 正确：指定回滚异常
    @Transactional(rollbackFor = Exception.class)
    public void createUser(User user) throws Exception {
        userRepository.save(user);
        throw new IOException("error");  // 会回滚
    }
}
```

解决自调用问题：

```java
@Service
public class UserService {
    
    @Autowired
    private UserService self;  // 注入自己
    
    public void doSomething() {
        self.updateUser(user);  // 通过代理调用，事务生效
    }
    
    @Transactional
    public void updateUser(User user) { }
}
```

---

## 7. 缓存集成

### 7.1 Spring Cache 抽象

Spring 提供了统一的缓存抽象，可以方便地切换不同的缓存实现。

```java
@SpringBootApplication
@EnableCaching  // 开启缓存
public class DemoApplication { }
```

```java
@Service
public class UserService {
    
    /**
     * @Cacheable：查询时先查缓存，没有再查数据库
     * - value/cacheNames：缓存名称
     * - key：缓存 key（SpEL 表达式）
     * - condition：满足条件才缓存
     * - unless：满足条件不缓存
     */
    @Cacheable(value = "users", key = "#id")
    public User findById(Long id) {
        log.info("查询数据库: {}", id);
        return userRepository.findById(id).orElse(null);
    }
    
    /**
     * @CachePut：更新缓存（每次都执行方法）
     */
    @CachePut(value = "users", key = "#user.id")
    public User update(User user) {
        return userRepository.save(user);
    }
    
    /**
     * @CacheEvict：删除缓存
     * - allEntries：删除所有缓存
     * - beforeInvocation：方法执行前删除
     */
    @CacheEvict(value = "users", key = "#id")
    public void deleteById(Long id) {
        userRepository.deleteById(id);
    }
    
    /**
     * @Caching：组合多个缓存操作
     */
    @Caching(
        put = @CachePut(value = "users", key = "#user.id"),
        evict = @CacheEvict(value = "userList", allEntries = true)
    )
    public User save(User user) {
        return userRepository.save(user);
    }
}
```

### 7.2 Redis 缓存

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

```yaml
spring:
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
        max-wait: -1ms
  cache:
    type: redis
    redis:
      time-to-live: 3600000  # 缓存过期时间（毫秒）
      key-prefix: "cache:"   # key 前缀
      use-key-prefix: true
      cache-null-values: true  # 缓存空值（防止缓存穿透）
```

```java
/**
 * Redis 配置类
 */
@Configuration
public class RedisConfig {
    
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // Key 使用 String 序列化
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        
        // Value 使用 JSON 序列化
        Jackson2JsonRedisSerializer<Object> jsonSerializer = 
            new Jackson2JsonRedisSerializer<>(Object.class);
        ObjectMapper om = new ObjectMapper();
        om.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        om.activateDefaultTyping(om.getPolymorphicTypeValidator(), 
            ObjectMapper.DefaultTyping.NON_FINAL);
        jsonSerializer.setObjectMapper(om);
        
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        
        template.afterPropertiesSet();
        return template;
    }
}
```

```java
/**
 * 直接使用 RedisTemplate
 */
@Service
public class RedisService {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    // String 操作
    public void set(String key, Object value, long timeout, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, timeout, unit);
    }
    
    public Object get(String key) {
        return redisTemplate.opsForValue().get(key);
    }
    
    // Hash 操作
    public void hSet(String key, String field, Object value) {
        redisTemplate.opsForHash().put(key, field, value);
    }
    
    public Object hGet(String key, String field) {
        return redisTemplate.opsForHash().get(key, field);
    }
    
    // List 操作
    public void lPush(String key, Object value) {
        redisTemplate.opsForList().leftPush(key, value);
    }
    
    // Set 操作
    public void sAdd(String key, Object... values) {
        redisTemplate.opsForSet().add(key, values);
    }
    
    // 删除
    public Boolean delete(String key) {
        return redisTemplate.delete(key);
    }
    
    // 设置过期时间
    public Boolean expire(String key, long timeout, TimeUnit unit) {
        return redisTemplate.expire(key, timeout, unit);
    }
}
```

---

## 8. 安全集成

### 8.1 Spring Security 基础

Spring Security 是 Spring 家族的安全框架，提供认证和授权功能。

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

> 添加依赖后，所有接口默认需要登录，默认用户名是 `user`，密码在启动日志中。

```java
/**
 * Security 配置类
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    /**
     * 配置认证管理器
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 方式1：内存用户（测试用）
        auth.inMemoryAuthentication()
            .withUser("admin")
            .password(passwordEncoder().encode("123456"))
            .roles("ADMIN")
            .and()
            .withUser("user")
            .password(passwordEncoder().encode("123456"))
            .roles("USER");
        
        // 方式2：数据库用户（生产用）
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());
    }
    
    /**
     * 配置 HTTP 安全
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // 关闭 CSRF（前后端分离项目）
            .csrf().disable()
            
            // 配置请求授权
            .authorizeRequests()
                .antMatchers("/api/public/**", "/login", "/register").permitAll()  // 公开接口
                .antMatchers("/api/admin/**").hasRole("ADMIN")  // 需要 ADMIN 角色
                .antMatchers("/api/**").authenticated()  // 需要登录
                .anyRequest().permitAll()
            
            // 配置登录
            .and()
            .formLogin()
                .loginProcessingUrl("/login")
                .successHandler(loginSuccessHandler())
                .failureHandler(loginFailureHandler())
            
            // 配置登出
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
            
            // 配置异常处理
            .and()
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint())  // 未登录
                .accessDeniedHandler(accessDeniedHandler());  // 无权限
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

```java
/**
 * 自定义 UserDetailsService
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        
        return org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPassword())
            .roles(user.getRoles().toArray(new String[0]))
            .build();
    }
}
```

### 8.2 JWT 认证

JWT（JSON Web Token）是前后端分离项目常用的认证方式。

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

```java
/**
 * JWT 工具类
 */
@Component
public class JwtUtils {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.expiration}")
    private Long expiration;
    
    /**
     * 生成 Token
     */
    public String generateToken(String username) {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
            .signWith(SignatureAlgorithm.HS512, secret)
            .compact();
    }
    
    /**
     * 解析 Token
     */
    public String getUsernameFromToken(String token) {
        return Jwts.parser()
            .setSigningKey(secret)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }
    
    /**
     * 验证 Token
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Token 已过期");
        } catch (Exception e) {
            log.warn("Token 无效");
        }
        return false;
    }
}

/**
 * JWT 过滤器
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtUtils jwtUtils;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain chain) throws ServletException, IOException {
        String token = getTokenFromRequest(request);
        
        if (token != null && jwtUtils.validateToken(token)) {
            String username = jwtUtils.getUsernameFromToken(token);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        
        chain.doFilter(request, response);
    }
    
    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

```yaml
# application.yml
jwt:
  secret: mySecretKey123456789012345678901234567890
  expiration: 86400  # 24小时（秒）
```

---

## 9. 消息队列集成

### 9.1 RabbitMQ

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-amqp</artifactId>
</dependency>
```

```yaml
spring:
  rabbitmq:
    host: localhost
    port: 5672
    username: guest
    password: guest
    virtual-host: /
```

```java
/**
 * RabbitMQ 配置
 */
@Configuration
public class RabbitConfig {
    
    public static final String QUEUE_NAME = "test.queue";
    public static final String EXCHANGE_NAME = "test.exchange";
    public static final String ROUTING_KEY = "test.routing.key";
    
    // 声明队列
    @Bean
    public Queue queue() {
        return new Queue(QUEUE_NAME, true);  // durable=true 持久化
    }
    
    // 声明交换机
    @Bean
    public DirectExchange exchange() {
        return new DirectExchange(EXCHANGE_NAME);
    }
    
    // 绑定队列到交换机
    @Bean
    public Binding binding(Queue queue, DirectExchange exchange) {
        return BindingBuilder.bind(queue).to(exchange).with(ROUTING_KEY);
    }
}

/**
 * 消息生产者
 */
@Service
public class MessageProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void send(String message) {
        rabbitTemplate.convertAndSend(
            RabbitConfig.EXCHANGE_NAME, 
            RabbitConfig.ROUTING_KEY, 
            message
        );
        log.info("发送消息: {}", message);
    }
}

/**
 * 消息消费者
 */
@Component
public class MessageConsumer {
    
    @RabbitListener(queues = RabbitConfig.QUEUE_NAME)
    public void receive(String message) {
        log.info("接收消息: {}", message);
        // 处理消息
    }
}
```

---

## 10. 任务调度

### 10.1 定时任务

```java
@SpringBootApplication
@EnableScheduling  // 开启定时任务
public class DemoApplication { }
```

```java
@Component
public class ScheduledTasks {
    
    /**
     * fixedRate：固定频率执行（上次开始时间算起）
     */
    @Scheduled(fixedRate = 5000)
    public void task1() {
        log.info("每5秒执行一次");
    }
    
    /**
     * fixedDelay：固定延迟执行（上次结束时间算起）
     */
    @Scheduled(fixedDelay = 5000)
    public void task2() {
        log.info("上次执行完成后5秒再执行");
    }
    
    /**
     * initialDelay：首次延迟执行
     */
    @Scheduled(initialDelay = 10000, fixedRate = 5000)
    public void task3() {
        log.info("启动10秒后开始，每5秒执行");
    }
    
    /**
     * cron 表达式：灵活的时间配置
     */
    @Scheduled(cron = "0 0 2 * * ?")  // 每天凌晨2点
    public void task4() {
        log.info("每天凌晨2点执行");
    }
    
    /**
     * 从配置文件读取 cron 表达式
     */
    @Scheduled(cron = "${task.cron}")
    public void task5() {
        log.info("配置文件指定的时间执行");
    }
}
```

Cron 表达式格式：`秒 分 时 日 月 周`

| 字段 | 允许值 | 特殊字符 |
|------|--------|----------|
| 秒 | 0-59 | , - * / |
| 分 | 0-59 | , - * / |
| 时 | 0-23 | , - * / |
| 日 | 1-31 | , - * / ? L W |
| 月 | 1-12 | , - * / |
| 周 | 0-7 (0和7都是周日) | , - * / ? L # |

常用示例：
- `0 0 * * * ?` - 每小时整点
- `0 0 2 * * ?` - 每天凌晨2点
- `0 0 2 1 * ?` - 每月1号凌晨2点
- `0 0 2 ? * MON` - 每周一凌晨2点
- `0 0/30 * * * ?` - 每30分钟

### 10.2 异步任务

```java
@SpringBootApplication
@EnableAsync  // 开启异步
public class DemoApplication { }
```

```java
@Service
public class AsyncService {
    
    /**
     * 异步方法（无返回值）
     */
    @Async
    public void asyncTask() {
        log.info("异步任务开始，线程: {}", Thread.currentThread().getName());
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        log.info("异步任务结束");
    }
    
    /**
     * 异步方法（有返回值）
     */
    @Async
    public Future<String> asyncTaskWithResult() {
        log.info("异步任务开始");
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return new AsyncResult<>("任务完成");
    }
    
    /**
     * 使用 CompletableFuture（推荐）
     */
    @Async
    public CompletableFuture<String> asyncTaskWithCompletableFuture() {
        log.info("异步任务开始");
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return CompletableFuture.completedFuture("任务完成");
    }
}
```

```java
/**
 * 自定义线程池
 */
@Configuration
public class AsyncConfig {
    
    @Bean("taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);           // 核心线程数
        executor.setMaxPoolSize(20);           // 最大线程数
        executor.setQueueCapacity(100);        // 队列容量
        executor.setKeepAliveSeconds(60);      // 空闲线程存活时间
        executor.setThreadNamePrefix("async-"); // 线程名前缀
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }
}

// 使用指定的线程池
@Async("taskExecutor")
public void asyncTask() { }
```

> **⚠️ 常见错误 #6：@Async 不生效**
> 
> 和 @Transactional 一样，@Async 也是基于代理的，自调用不生效。

---

## 11. 监控与日志

### 11.1 日志配置

Spring Boot 默认使用 Logback 作为日志框架。

```yaml
# application.yml
logging:
  level:
    root: INFO
    com.example: DEBUG                    # 指定包的日志级别
    org.springframework.web: WARN
  file:
    name: logs/app.log                    # 日志文件路径
    max-size: 10MB                        # 单个文件最大大小
    max-history: 30                       # 保留天数
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
```

```java
// 使用日志
@Service
public class UserService {
    
    // 方式1：使用 LoggerFactory
    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    
    // 方式2：使用 Lombok 的 @Slf4j 注解（推荐）
    // @Slf4j
    // public class UserService { }
    
    public void doSomething() {
        log.trace("trace 日志");
        log.debug("debug 日志");
        log.info("info 日志");
        log.warn("warn 日志");
        log.error("error 日志");
        
        // 使用占位符（推荐，避免字符串拼接）
        log.info("用户 {} 执行了 {} 操作", userId, action);
        
        // 打印异常堆栈
        try {
            // ...
        } catch (Exception e) {
            log.error("操作失败", e);
        }
    }
}
```

### 11.2 Actuator 监控

Spring Boot Actuator 提供了生产级别的监控功能。

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
        include: "*"  # 暴露所有端点（生产环境要限制）
      base-path: /actuator
  endpoint:
    health:
      show-details: always  # 显示健康检查详情
```

常用端点：

| 端点 | 说明 |
|------|------|
| /actuator/health | 健康检查 |
| /actuator/info | 应用信息 |
| /actuator/metrics | 指标数据 |
| /actuator/env | 环境变量 |
| /actuator/beans | 所有 Bean |
| /actuator/mappings | 所有请求映射 |
| /actuator/loggers | 日志配置 |
| /actuator/threaddump | 线程转储 |
| /actuator/heapdump | 堆转储 |

```java
/**
 * 自定义健康检查
 */
@Component
public class CustomHealthIndicator implements HealthIndicator {
    
    @Override
    public Health health() {
        // 检查某个服务是否可用
        boolean serviceUp = checkService();
        
        if (serviceUp) {
            return Health.up()
                .withDetail("service", "running")
                .build();
        } else {
            return Health.down()
                .withDetail("service", "not available")
                .build();
        }
    }
    
    private boolean checkService() {
        // 检查逻辑
        return true;
    }
}
```

---

## 12. API文档集成

### 12.1 Swagger / SpringDoc

```xml
<!-- SpringDoc OpenAPI（推荐，支持 OpenAPI 3） -->
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-ui</artifactId>
    <version>1.7.0</version>
</dependency>
```

```yaml
springdoc:
  api-docs:
    path: /api-docs
  swagger-ui:
    path: /swagger-ui.html
```

```java
@RestController
@RequestMapping("/api/users")
@Tag(name = "用户管理", description = "用户相关接口")
public class UserController {
    
    @Operation(summary = "获取用户列表", description = "分页查询所有用户")
    @GetMapping
    public Result<Page<User>> list(
            @Parameter(description = "页码") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "每页数量") @RequestParam(defaultValue = "10") int size) {
        return Result.success(userService.findPage(page, size));
    }
    
    @Operation(summary = "获取用户详情")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "成功"),
        @ApiResponse(responseCode = "404", description = "用户不存在")
    })
    @GetMapping("/{id}")
    public Result<User> getById(@PathVariable Long id) {
        return Result.success(userService.findById(id));
    }
    
    @Operation(summary = "创建用户")
    @PostMapping
    public Result<User> create(@RequestBody @Valid User user) {
        return Result.success(userService.save(user));
    }
}
```

访问 `http://localhost:8080/swagger-ui.html` 查看 API 文档。

---

## 13. 测试

### 13.1 单元测试

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

```java
/**
 * Service 层单元测试
 */
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @InjectMocks
    private UserService userService;
    
    @Test
    void findById_shouldReturnUser_whenUserExists() {
        // Given
        User user = new User();
        user.setId(1L);
        user.setUsername("john");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        
        // When
        User result = userService.findById(1L);
        
        // Then
        assertNotNull(result);
        assertEquals("john", result.getUsername());
        verify(userRepository, times(1)).findById(1L);
    }
    
    @Test
    void findById_shouldThrowException_whenUserNotExists() {
        // Given
        when(userRepository.findById(1L)).thenReturn(Optional.empty());
        
        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> {
            userService.findById(1L);
        });
    }
}
```

### 13.2 集成测试

```java
/**
 * Controller 层集成测试
 */
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
    void getById_shouldReturnUser() throws Exception {
        // Given
        User user = new User();
        user.setId(1L);
        user.setUsername("john");
        when(userService.findById(1L)).thenReturn(user);
        
        // When & Then
        mockMvc.perform(get("/api/users/1")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.username").value("john"));
    }
    
    @Test
    void create_shouldReturnCreatedUser() throws Exception {
        // Given
        User user = new User();
        user.setUsername("john");
        user.setEmail("john@example.com");
        
        User savedUser = new User();
        savedUser.setId(1L);
        savedUser.setUsername("john");
        when(userService.save(any(User.class))).thenReturn(savedUser);
        
        // When & Then
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.id").value(1));
    }
}
```

### 13.3 数据库测试

```java
/**
 * Repository 层测试
 */
@DataJpaTest
class UserRepositoryTest {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private TestEntityManager entityManager;
    
    @Test
    void findByUsername_shouldReturnUser() {
        // Given
        User user = new User();
        user.setUsername("john");
        user.setEmail("john@example.com");
        entityManager.persistAndFlush(user);
        
        // When
        User found = userRepository.findByUsername("john");
        
        // Then
        assertNotNull(found);
        assertEquals("john@example.com", found.getEmail());
    }
}
```

---

## 14. 打包与部署

### 14.1 打包

```bash
# Maven 打包
mvn clean package -DskipTests

# 打包后的 jar 在 target 目录下
```

```xml
<!-- pom.xml 配置打包 -->
<build>
    <finalName>app</finalName>  <!-- 指定 jar 名称 -->
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
```

### 14.2 运行

```bash
# 直接运行
java -jar app.jar

# 指定配置文件
java -jar app.jar --spring.profiles.active=prod

# 指定端口
java -jar app.jar --server.port=9090

# 后台运行（Linux）
nohup java -jar app.jar > app.log 2>&1 &

# 指定 JVM 参数
java -Xms512m -Xmx1024m -jar app.jar
```

### 14.3 Docker 部署

```dockerfile
# Dockerfile
FROM openjdk:8-jdk-alpine

# 设置时区
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app

COPY target/app.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
```

```yaml
# docker-compose.yml
version: '3'
services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/test
    depends_on:
      - mysql
      - redis
    
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: 123456
      MYSQL_DATABASE: test
    volumes:
      - mysql_data:/var/lib/mysql
    
  redis:
    image: redis:6
    volumes:
      - redis_data:/data

volumes:
  mysql_data:
  redis_data:
```

```bash
# 构建并启动
docker-compose up -d --build

# 查看日志
docker-compose logs -f app

# 停止
docker-compose down
```

---

## 15. 常见错误汇总

### 错误 #1：启动类位置不对

```
错误信息：Consider defining a bean of type 'xxx' in your configuration.

原因：启动类不在根包下，导致组件扫描不到。

解决：确保启动类在根包（如 com.example.demo）下。
```

### 错误 #2：@ConfigurationProperties 不生效

```
错误信息：配置值为 null

原因：没有启用配置属性绑定。

解决：
1. 在属性类上加 @Component
2. 或在启动类上加 @EnableConfigurationProperties
```

### 错误 #3：MySQL 时区问题

```
错误信息：The server time zone value 'xxx' is unrecognized

原因：MySQL 8.0+ 需要指定时区。

解决：在 URL 中添加 serverTimezone=Asia/Shanghai
```

### 错误 #4：Mapper 扫描不到

```
错误信息：No qualifying bean of type 'xxxMapper'

原因：MyBatis Mapper 接口没有被扫描到。

解决：
1. 在 Mapper 接口上加 @Mapper
2. 或在启动类上加 @MapperScan("com.example.mapper")
```

### 错误 #5：事务不生效

```
原因：
1. 方法不是 public
2. 同一个类中自调用
3. 异常被捕获了
4. 抛出的是 checked 异常

解决：
1. 确保方法是 public
2. 通过注入自己来调用
3. 不要捕获异常，或捕获后重新抛出
4. 使用 rollbackFor = Exception.class
```

### 错误 #6：@Async 不生效

```
原因：和 @Transactional 一样，自调用不生效。

解决：通过注入自己来调用，或使用 AopContext.currentProxy()
```

### 错误 #7：循环依赖

```
错误信息：The dependencies of some of the beans in the application context form a cycle

原因：A 依赖 B，B 又依赖 A。

解决：
1. 使用 @Lazy 延迟加载
2. 使用 setter 注入代替构造器注入
3. 重构代码，消除循环依赖
```

### 错误 #8：端口被占用

```
错误信息：Web server failed to start. Port 8080 was already in use.

解决：
1. 修改端口：server.port=8081
2. 或杀掉占用端口的进程
```

### 错误 #9：JSON 序列化问题

```
错误信息：Could not write JSON: No serializer found for class xxx

原因：实体类没有 getter 方法，或存在循环引用。

解决：
1. 添加 getter 方法
2. 使用 @JsonIgnore 忽略循环引用的字段
3. 使用 DTO 代替实体类返回
```

### 错误 #10：跨域问题

```
错误信息：Access to XMLHttpRequest has been blocked by CORS policy

原因：前端和后端不同源（协议、域名、端口不同）。

解决：
1. 配置 CORS（见 4.8 节）
2. 使用 Nginx 反向代理
```

---

## 附录：常用依赖速查

```xml
<!-- Web -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<!-- 参数校验 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

<!-- JPA -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

<!-- MyBatis -->
<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>2.3.1</version>
</dependency>

<!-- Redis -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>

<!-- Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- RabbitMQ -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-amqp</artifactId>
</dependency>

<!-- Actuator -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>

<!-- Lombok -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>

<!-- MySQL -->
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <scope>runtime</scope>
</dependency>

<!-- API 文档 -->
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-ui</artifactId>
    <version>1.7.0</version>
</dependency>

<!-- JWT -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>

<!-- 测试 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

---

> 📝 **学习建议**
> 
> 1. 先跑通一个简单的 CRUD 项目
> 2. 逐步添加功能：参数校验 → 异常处理 → 数据库 → 缓存 → 安全
> 3. 多看官方文档：https://docs.spring.io/spring-boot/docs/2.7.18/reference/html/
> 4. 遇到问题先看错误日志，再搜索解决方案
