

> Spring Framework 6 是 Spring 生态的重大升级，基于 Java 17+ 和 Jakarta EE 9+
> 本笔记基于 Java 17 + Spring Boot 3.2.12，着重对比 Spring 5 的变化

---

## 目录

1. [重大变化概览](#1-重大变化概览)
2. [环境要求与迁移](#2-环境要求与迁移)
3. [Jakarta EE 迁移](#3-jakarta-ee-迁移)
4. [核心容器增强](#4-核心容器增强)
5. [AOT 编译与原生镜像](#5-aot-编译与原生镜像)
6. [HTTP 接口客户端](#6-http-接口客户端)
7. [可观测性](#7-可观测性)
8. [Web 层变化](#8-web-层变化)
9. [数据访问变化](#9-数据访问变化)
10. [安全性增强](#10-安全性增强)
11. [测试增强](#11-测试增强)
12. [配置属性变化](#12-配置属性变化)
13. [废弃与移除](#13-废弃与移除)
14. [迁移实战](#14-迁移实战)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 重大变化概览

### 1.1 Spring 6 vs Spring 5 核心差异

Spring 6 是一次"断代式"升级，不是简单的功能增加，而是底层基础的全面革新。

| 特性 | Spring 5 | Spring 6 |
|------|----------|----------|
| Java 版本 | Java 8+ | **Java 17+** |
| Java EE | javax.* | **Jakarta EE 9+ (jakarta.*)** |
| Servlet | Servlet 3.1+ | **Servlet 6.0+** |
| JPA | JPA 2.1+ | **JPA 3.0+** |
| Bean Validation | 2.0 | **3.0** |
| 原生编译 | 实验性 | **正式支持 GraalVM** |
| HTTP 客户端 | RestTemplate | **HTTP Interface Client** |
| 可观测性 | Micrometer | **Micrometer + Tracing** |

### 1.2 为什么要升级？

**性能提升：**
- AOT（Ahead-of-Time）编译支持
- GraalVM 原生镜像，启动时间从秒级降到毫秒级
- 内存占用大幅减少

**现代化：**
- 拥抱 Java 17 新特性（Records、Sealed Classes、Pattern Matching）
- Jakarta EE 是未来标准
- 更好的云原生支持

**安全性：**
- 及时的安全更新
- Spring 5.x 将逐步停止维护

### 1.3 版本对应关系

```
Spring Framework 6.0+ ←→ Spring Boot 3.0+
Spring Framework 5.3  ←→ Spring Boot 2.7
Spring Framework 5.2  ←→ Spring Boot 2.3-2.6
```

---

## 2. 环境要求与迁移

### 2.1 最低版本要求

```xml
<!-- Spring 6 / Spring Boot 3 最低要求 -->
Java 17+
Tomcat 10+
Jetty 11+
Undertow 2.3+
Hibernate 6.1+
```

### 2.2 Maven 配置对比

**Spring 5 / Spring Boot 2.x：**
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>

<properties>
    <java.version>11</java.version>
</properties>
```

**Spring 6 / Spring Boot 3.x：**
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.12</version>
</parent>

<properties>
    <java.version>17</java.version>
</properties>
```

### 2.3 Gradle 配置对比

**Spring Boot 2.x：**
```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '2.7.18'
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    sourceCompatibility = '11'
}
```

**Spring Boot 3.x：**
```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.12'
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    sourceCompatibility = '17'
}
```

### 2.4 Java 17 新特性在 Spring 6 中的应用

**Records（记录类）：**
```java
// Spring 5 时代的 DTO
public class UserDTO {
    private String name;
    private int age;
    
    // 构造器、getter、setter、equals、hashCode、toString...
    // 大量样板代码
}

// Spring 6 + Java 17：使用 Record
public record UserDTO(String name, int age) {}

// 直接用于 Controller
@GetMapping("/user/{id}")
public UserDTO getUser(@PathVariable Long id) {
    return new UserDTO("张三", 25);
}

// 直接用于配置绑定
@ConfigurationProperties(prefix = "app")
public record AppProperties(String name, String version, Server server) {
    public record Server(String host, int port) {}
}
```

**Sealed Classes（密封类）：**
```java
// 限制继承关系，增强类型安全
public sealed interface PaymentResult 
    permits PaymentSuccess, PaymentFailure, PaymentPending {
}

public record PaymentSuccess(String transactionId) implements PaymentResult {}
public record PaymentFailure(String errorCode, String message) implements PaymentResult {}
public record PaymentPending(String pendingReason) implements PaymentResult {}

// 配合 Pattern Matching 使用
public String handlePayment(PaymentResult result) {
    return switch (result) {
        case PaymentSuccess s -> "支付成功: " + s.transactionId();
        case PaymentFailure f -> "支付失败: " + f.message();
        case PaymentPending p -> "处理中: " + p.pendingReason();
    };
}
```

**Text Blocks（文本块）：**
```java
// Spring 5：字符串拼接
String sql = "SELECT u.id, u.name, u.email " +
             "FROM users u " +
             "WHERE u.status = 'ACTIVE' " +
             "ORDER BY u.created_at DESC";

// Spring 6 + Java 17：文本块
String sql = """
    SELECT u.id, u.name, u.email
    FROM users u
    WHERE u.status = 'ACTIVE'
    ORDER BY u.created_at DESC
    """;
```

---

## 3. Jakarta EE 迁移

### 3.1 包名变化

这是 Spring 6 最大的破坏性变更！所有 `javax.*` 包都改为 `jakarta.*`。

```java
// ==================== Spring 5 (javax) ====================
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;
import javax.annotation.PostConstruct;
import javax.transaction.Transactional;

// ==================== Spring 6 (jakarta) ====================
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotNull;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
```

### 3.2 完整包名映射表

| 功能 | javax (Spring 5) | jakarta (Spring 6) |
|------|------------------|-------------------|
| Servlet | javax.servlet.* | jakarta.servlet.* |
| JPA | javax.persistence.* | jakarta.persistence.* |
| Validation | javax.validation.* | jakarta.validation.* |
| Transaction | javax.transaction.* | jakarta.transaction.* |
| Annotation | javax.annotation.* | jakarta.annotation.* |
| WebSocket | javax.websocket.* | jakarta.websocket.* |
| Mail | javax.mail.* | jakarta.mail.* |
| JSON-B | javax.json.bind.* | jakarta.json.bind.* |
| Inject | javax.inject.* | jakarta.inject.* |

### 3.3 实体类迁移示例

**Spring 5：**
```java
import javax.persistence.*;
import javax.validation.constraints.*;

@Entity
@Table(name = "users")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 50)
    @Column(nullable = false)
    private String username;
    
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @NotNull
    @Enumerated(EnumType.STRING)
    private UserStatus status;
    
    // getters and setters
}
```

**Spring 6：**
```java
import jakarta.persistence.*;
import jakarta.validation.constraints.*;

@Entity
@Table(name = "users")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 50)
    @Column(nullable = false)
    private String username;
    
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @NotNull
    @Enumerated(EnumType.STRING)
    private UserStatus status;
    
    // getters and setters
}
```

### 3.4 自动迁移工具

**使用 OpenRewrite 自动迁移：**
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

**使用 IntelliJ IDEA 批量替换：**
```
1. Ctrl + Shift + R（全局替换）
2. 勾选 "Regex"
3. 搜索：javax\.
4. 替换：jakarta.
5. 逐个确认或全部替换
```

---

## 4. 核心容器增强

### 4.1 构造器注入优化

Spring 6 进一步强化了构造器注入的推荐地位。

**Spring 5 常见写法：**
```java
@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    // 字段注入：不推荐，难以测试
}
```

**Spring 6 推荐写法：**
```java
@Service
public class UserService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    // 单构造器可省略 @Autowired
    public UserService(UserRepository userRepository, 
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
}

// 或使用 Lombok
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
}
```

### 4.2 @Bean 方法的轻量模式

Spring 6 优化了 `@Bean` 方法的调用机制。

```java
@Configuration
public class AppConfig {
    
    @Bean
    public DataSource dataSource() {
        return new HikariDataSource();
    }
    
    @Bean
    public JdbcTemplate jdbcTemplate() {
        // Spring 6 中，这种调用更高效
        return new JdbcTemplate(dataSource());
    }
}

// 使用 proxyBeanMethods = false 进一步优化（适合简单配置）
@Configuration(proxyBeanMethods = false)
public class LiteConfig {
    
    @Bean
    public MyService myService(MyRepository repository) {
        // 通过参数注入，而非方法调用
        return new MyService(repository);
    }
}
```

### 4.3 新的条件注解

**@ConditionalOnThreading（Spring Boot 3.2+）：**
```java
@Configuration
public class ThreadingConfig {
    
    @Bean
    @ConditionalOnThreading(Threading.VIRTUAL)
    public Executor virtualThreadExecutor() {
        // 仅在启用虚拟线程时创建
        return Executors.newVirtualThreadPerTaskExecutor();
    }
    
    @Bean
    @ConditionalOnThreading(Threading.PLATFORM)
    public Executor platformThreadExecutor() {
        return Executors.newFixedThreadPool(10);
    }
}
```

### 4.4 ProblemDetail 标准错误响应

Spring 6 引入了 RFC 7807 标准的错误响应格式。

**Spring 5 自定义错误响应：**
```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUserNotFound(
            UserNotFoundException ex) {
        Map<String, Object> error = new HashMap<>();
        error.put("code", "USER_NOT_FOUND");
        error.put("message", ex.getMessage());
        error.put("timestamp", LocalDateTime.now());
        return ResponseEntity.status(404).body(error);
    }
}
```

**Spring 6 使用 ProblemDetail：**
```java
import org.springframework.http.ProblemDetail;
import org.springframework.http.HttpStatus;

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
}

// 响应格式（RFC 7807）：
// {
//   "type": "https://api.example.com/errors/user-not-found",
//   "title": "用户不存在",
//   "status": 404,
//   "detail": "ID为123的用户不存在",
//   "instance": "/api/users/123",
//   "userId": 123,
//   "timestamp": "2024-01-15T10:30:00Z"
// }
```

**启用 ProblemDetail：**
```yaml
# application.yml
spring:
  mvc:
    problemdetails:
      enabled: true
```

---

## 5. AOT 编译与原生镜像

### 5.1 什么是 AOT？

AOT（Ahead-of-Time）编译是 Spring 6 的重大特性，它在构建时而非运行时进行部分处理，显著提升启动速度。

**传统 JIT（Just-in-Time）：**
```
启动 → 类加载 → 反射扫描 → Bean 创建 → 应用就绪
      （运行时处理，启动慢）
```

**AOT 编译：**
```
构建时：分析代码 → 生成优化代码 → 预计算 Bean 定义
运行时：直接加载 → 应用就绪
        （启动快，内存少）
```

### 5.2 启用 AOT 处理

```xml
<!-- pom.xml -->
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <executions>
        <execution>
            <id>process-aot</id>
            <goals>
                <goal>process-aot</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

```bash
# 执行 AOT 处理
mvn spring-boot:process-aot

# 生成的文件在 target/spring-aot/main/
```

### 5.3 GraalVM 原生镜像

原生镜像将 Java 应用编译为独立的可执行文件，无需 JVM。

**性能对比：**
| 指标 | JVM 模式 | 原生镜像 |
|------|----------|----------|
| 启动时间 | 2-5 秒 | 50-200 毫秒 |
| 内存占用 | 200-500 MB | 50-100 MB |
| 峰值性能 | 更高 | 略低 |
| 构建时间 | 快 | 慢（分钟级） |

**配置原生镜像构建：**
```xml
<!-- pom.xml -->
<profiles>
    <profile>
        <id>native</id>
        <build>
            <plugins>
                <plugin>
                    <groupId>org.graalvm.buildtools</groupId>
                    <artifactId>native-maven-plugin</artifactId>
                    <executions>
                        <execution>
                            <id>build-native</id>
                            <goals>
                                <goal>compile-no-fork</goal>
                            </goals>
                            <phase>package</phase>
                        </execution>
                    </executions>
                </plugin>
            </plugins>
        </build>
    </profile>
</profiles>
```

```bash
# 构建原生镜像
mvn -Pnative native:compile

# 运行原生镜像
./target/myapp
```

### 5.4 AOT 兼容性注意事项

AOT 和原生镜像对代码有一些限制：

```java
// ❌ 避免：运行时反射
Class<?> clazz = Class.forName("com.example.MyClass");
Object obj = clazz.getDeclaredConstructor().newInstance();

// ✅ 推荐：编译时确定类型
MyClass obj = new MyClass();

// ❌ 避免：动态代理
Proxy.newProxyInstance(...)

// ✅ 推荐：使用接口或 Spring 的 CGLIB 代理

// ❌ 避免：运行时条件 Bean
@Bean
@ConditionalOnExpression("#{systemProperties['feature.enabled']}")
public MyBean myBean() { ... }

// ✅ 推荐：构建时条件
@Bean
@ConditionalOnProperty(name = "feature.enabled", havingValue = "true")
public MyBean myBean() { ... }
```

**注册反射提示：**
```java
// 如果必须使用反射，需要注册提示
@Configuration
@ImportRuntimeHints(MyRuntimeHints.class)
public class AppConfig {
}

public class MyRuntimeHints implements RuntimeHintsRegistrar {
    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        // 注册需要反射的类
        hints.reflection().registerType(MyClass.class, 
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_METHODS);
        
        // 注册资源文件
        hints.resources().registerPattern("config/*.json");
    }
}
```

---

## 6. HTTP 接口客户端

### 6.1 声明式 HTTP 客户端

Spring 6 引入了类似 Feign 的声明式 HTTP 客户端，但是是 Spring 原生的。

**Spring 5 使用 RestTemplate：**
```java
@Service
public class UserClient {
    
    private final RestTemplate restTemplate;
    
    public UserClient(RestTemplateBuilder builder) {
        this.restTemplate = builder
            .rootUri("https://api.example.com")
            .build();
    }
    
    public User getUser(Long id) {
        return restTemplate.getForObject("/users/{id}", User.class, id);
    }
    
    public List<User> getAllUsers() {
        ResponseEntity<List<User>> response = restTemplate.exchange(
            "/users",
            HttpMethod.GET,
            null,
            new ParameterizedTypeReference<List<User>>() {}
        );
        return response.getBody();
    }
    
    public User createUser(User user) {
        return restTemplate.postForObject("/users", user, User.class);
    }
}
```

**Spring 6 声明式 HTTP 接口：**
```java
// 定义接口
public interface UserClient {
    
    @GetExchange("/users/{id}")
    User getUser(@PathVariable Long id);
    
    @GetExchange("/users")
    List<User> getAllUsers();
    
    @PostExchange("/users")
    User createUser(@RequestBody User user);
    
    @PutExchange("/users/{id}")
    User updateUser(@PathVariable Long id, @RequestBody User user);
    
    @DeleteExchange("/users/{id}")
    void deleteUser(@PathVariable Long id);
    
    // 支持响应式
    @GetExchange("/users/{id}")
    Mono<User> getUserReactive(@PathVariable Long id);
    
    // 自定义请求头
    @GetExchange("/users")
    List<User> getUsersWithAuth(@RequestHeader("Authorization") String token);
}
```

### 6.2 配置 HTTP 接口客户端

```java
@Configuration
public class HttpClientConfig {
    
    @Bean
    public UserClient userClient() {
        WebClient webClient = WebClient.builder()
                .baseUrl("https://api.example.com")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
        
        HttpServiceProxyFactory factory = HttpServiceProxyFactory
                .builderFor(WebClientAdapter.create(webClient))
                .build();
        
        return factory.createClient(UserClient.class);
    }
    
    // 使用 RestClient（Spring 6.1+，同步客户端）
    @Bean
    public UserClient userClientSync() {
        RestClient restClient = RestClient.builder()
                .baseUrl("https://api.example.com")
                .build();
        
        HttpServiceProxyFactory factory = HttpServiceProxyFactory
                .builderFor(RestClientAdapter.create(restClient))
                .build();
        
        return factory.createClient(UserClient.class);
    }
}
```

### 6.3 RestClient（Spring 6.1 新增）

RestClient 是 RestTemplate 的现代替代品，提供流畅的 API。

**RestTemplate vs RestClient：**
```java
// Spring 5: RestTemplate
User user = restTemplate.getForObject("/users/{id}", User.class, 1);

// Spring 6: RestClient
User user = restClient.get()
        .uri("/users/{id}", 1)
        .retrieve()
        .body(User.class);
```

**完整示例：**
```java
@Service
public class UserService {
    
    private final RestClient restClient;
    
    public UserService(RestClient.Builder builder) {
        this.restClient = builder
                .baseUrl("https://api.example.com")
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }
    
    // GET 请求
    public User getUser(Long id) {
        return restClient.get()
                .uri("/users/{id}", id)
                .retrieve()
                .body(User.class);
    }
    
    // GET 请求带查询参数
    public List<User> searchUsers(String name, int page) {
        return restClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path("/users")
                        .queryParam("name", name)
                        .queryParam("page", page)
                        .build())
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
    }
    
    // POST 请求
    public User createUser(User user) {
        return restClient.post()
                .uri("/users")
                .contentType(MediaType.APPLICATION_JSON)
                .body(user)
                .retrieve()
                .body(User.class);
    }
    
    // 错误处理
    public User getUserWithErrorHandling(Long id) {
        return restClient.get()
                .uri("/users/{id}", id)
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, (request, response) -> {
                    throw new UserNotFoundException("用户不存在: " + id);
                })
                .onStatus(HttpStatusCode::is5xxServerError, (request, response) -> {
                    throw new ServiceException("服务器错误");
                })
                .body(User.class);
    }
    
    // 获取完整响应
    public ResponseEntity<User> getUserWithResponse(Long id) {
        return restClient.get()
                .uri("/users/{id}", id)
                .retrieve()
                .toEntity(User.class);
    }
}
```

---

## 7. 可观测性

### 7.1 Micrometer Observation API

Spring 6 引入了统一的可观测性 API，整合了指标（Metrics）、追踪（Tracing）和日志（Logging）。

**Spring 5 配置：**
```yaml
# 分散的配置
management:
  metrics:
    export:
      prometheus:
        enabled: true
```

**Spring 6 统一配置：**
```yaml
management:
  observations:
    key-values:
      application: my-app
  tracing:
    sampling:
      probability: 1.0
  metrics:
    distribution:
      percentiles-histogram:
        http.server.requests: true
```

### 7.2 分布式追踪

**添加依赖：**
```xml
<!-- Micrometer Tracing -->
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

**配置：**
```yaml
management:
  tracing:
    sampling:
      probability: 1.0  # 采样率，生产环境建议 0.1
  zipkin:
    tracing:
      endpoint: http://localhost:9411/api/v2/spans

logging:
  pattern:
    level: "%5p [${spring.application.name:},%X{traceId:-},%X{spanId:-}]"
```

### 7.3 自定义 Observation

```java
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

@Service
public class OrderService {
    
    private final ObservationRegistry observationRegistry;
    
    public OrderService(ObservationRegistry observationRegistry) {
        this.observationRegistry = observationRegistry;
    }
    
    public Order createOrder(OrderRequest request) {
        // 创建观测
        return Observation.createNotStarted("order.create", observationRegistry)
                .lowCardinalityKeyValue("order.type", request.getType())
                .highCardinalityKeyValue("user.id", request.getUserId())
                .observe(() -> {
                    // 业务逻辑
                    return doCreateOrder(request);
                });
    }
    
    // 使用注解方式
    @Observed(name = "order.process", 
              contextualName = "process-order",
              lowCardinalityKeyValues = {"order.priority", "high"})
    public void processOrder(Long orderId) {
        // 业务逻辑
    }
}
```

**启用 @Observed 注解：**
```java
@Configuration
public class ObservationConfig {
    
    @Bean
    public ObservedAspect observedAspect(ObservationRegistry registry) {
        return new ObservedAspect(registry);
    }
}
```

---

## 8. Web 层变化

### 8.1 参数名称发现

**Spring 5：**
```java
// 需要 -parameters 编译参数或使用 @RequestParam 指定名称
@GetMapping("/users")
public List<User> getUsers(@RequestParam("name") String name) {
    return userService.findByName(name);
}
```

**Spring 6：**
```java
// 默认使用 LocalVariableTableParameterNameDiscoverer
// 但推荐显式指定，避免依赖编译参数
@GetMapping("/users")
public List<User> getUsers(@RequestParam String name) {
    return userService.findByName(name);
}
```

**确保参数名称可用：**
```xml
<!-- Maven 编译配置 -->
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <configuration>
        <parameters>true</parameters>
    </configuration>
</plugin>
```

### 8.2 路径匹配策略变化

**Spring 5 默认：AntPathMatcher**
```java
// 支持 ** 在路径中间
@GetMapping("/api/**/users")  // 匹配 /api/v1/users, /api/v1/v2/users
```

**Spring 6 默认：PathPatternParser**
```java
// ** 只能在路径末尾
@GetMapping("/api/**/users")  // ❌ 不再支持

// 正确写法
@GetMapping("/api/*/users")   // 匹配 /api/v1/users
@GetMapping("/api/**")        // 匹配 /api/ 下所有路径
```

**恢复旧行为（不推荐）：**
```yaml
spring:
  mvc:
    pathmatch:
      matching-strategy: ant_path_matcher
```

### 8.3 尾部斜杠匹配

**Spring 5：** `/users` 和 `/users/` 默认匹配同一个处理器

**Spring 6：** 默认不再匹配，需要显式配置

```java
// Spring 6 中，这两个是不同的路径
@GetMapping("/users")   // 只匹配 /users
@GetMapping("/users/")  // 只匹配 /users/

// 如果需要同时匹配
@GetMapping({"/users", "/users/"})
public List<User> getUsers() { ... }
```

**全局配置：**
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.setUseTrailingSlashMatch(true);  // 恢复旧行为
    }
}
```

### 8.4 虚拟线程支持（Java 21+）

Spring Boot 3.2+ 支持 Java 21 的虚拟线程。

```yaml
# application.yml
spring:
  threads:
    virtual:
      enabled: true  # 启用虚拟线程
```

```java
// 启用后，所有请求处理都在虚拟线程中执行
@GetMapping("/users")
public List<User> getUsers() {
    // 这个方法在虚拟线程中执行
    // 阻塞操作不会占用平台线程
    return userRepository.findAll();
}
```

**虚拟线程 vs 平台线程：**
| 特性 | 平台线程 | 虚拟线程 |
|------|----------|----------|
| 创建成本 | 高（~1MB 栈空间） | 低（~KB 级别） |
| 数量限制 | 数千个 | 数百万个 |
| 阻塞影响 | 占用 OS 线程 | 不占用 OS 线程 |
| 适用场景 | CPU 密集型 | IO 密集型 |

---

## 9. 数据访问变化

### 9.1 Hibernate 6 变化

Spring 6 使用 Hibernate 6，有一些重要变化：

**ID 生成策略：**
```java
// Spring 5 + Hibernate 5
@Id
@GeneratedValue(strategy = GenerationType.AUTO)
private Long id;  // 可能使用 TABLE 策略

// Spring 6 + Hibernate 6
@Id
@GeneratedValue(strategy = GenerationType.AUTO)
private Long id;  // 默认使用 SEQUENCE 策略

// 推荐：显式指定策略
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
private Long id;
```

**时间类型映射：**
```java
// Hibernate 6 更好地支持 Java 8+ 时间类型
@Entity
public class Event {
    
    @Column
    private LocalDateTime startTime;  // 直接映射，无需转换器
    
    @Column
    private Instant createdAt;
    
    @Column
    private Duration duration;
}
```

### 9.2 JdbcClient（Spring 6.1 新增）

JdbcClient 是 JdbcTemplate 的现代替代品。

**Spring 5 JdbcTemplate：**
```java
@Repository
public class UserRepository {
    
    private final JdbcTemplate jdbcTemplate;
    
    public User findById(Long id) {
        return jdbcTemplate.queryForObject(
            "SELECT * FROM users WHERE id = ?",
            (rs, rowNum) -> new User(
                rs.getLong("id"),
                rs.getString("name"),
                rs.getString("email")
            ),
            id
        );
    }
    
    public List<User> findByStatus(String status) {
        return jdbcTemplate.query(
            "SELECT * FROM users WHERE status = ?",
            (rs, rowNum) -> new User(
                rs.getLong("id"),
                rs.getString("name"),
                rs.getString("email")
            ),
            status
        );
    }
}
```

**Spring 6 JdbcClient：**
```java
@Repository
public class UserRepository {
    
    private final JdbcClient jdbcClient;
    
    public UserRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }
    
    // 查询单个对象
    public Optional<User> findById(Long id) {
        return jdbcClient.sql("SELECT * FROM users WHERE id = :id")
                .param("id", id)
                .query(User.class)
                .optional();
    }
    
    // 查询列表
    public List<User> findByStatus(String status) {
        return jdbcClient.sql("SELECT * FROM users WHERE status = :status")
                .param("status", status)
                .query(User.class)
                .list();
    }
    
    // 使用 Record 映射
    public List<UserDTO> findAllDTO() {
        return jdbcClient.sql("SELECT id, name, email FROM users")
                .query(UserDTO.class)
                .list();
    }
    
    // 插入
    public int insert(User user) {
        return jdbcClient.sql("""
                INSERT INTO users (name, email, status)
                VALUES (:name, :email, :status)
                """)
                .param("name", user.getName())
                .param("email", user.getEmail())
                .param("status", user.getStatus())
                .update();
    }
    
    // 使用对象参数
    public int insertWithObject(User user) {
        return jdbcClient.sql("""
                INSERT INTO users (name, email, status)
                VALUES (:name, :email, :status)
                """)
                .paramSource(user)  // 自动从对象提取参数
                .update();
    }
    
    // 自定义行映射
    public List<User> findWithCustomMapper() {
        return jdbcClient.sql("SELECT * FROM users")
                .query((rs, rowNum) -> {
                    User user = new User();
                    user.setId(rs.getLong("id"));
                    user.setName(rs.getString("name"));
                    return user;
                })
                .list();
    }
}

public record UserDTO(Long id, String name, String email) {}
```

### 9.3 Repository 接口变化

**Spring Data 2.x：**
```java
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 返回 null 表示不存在
    User findByEmail(String email);
}
```

**Spring Data 3.x：**
```java
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 推荐使用 Optional
    Optional<User> findByEmail(String email);
    
    // 新的 List 返回类型方法
    List<User> findAllByStatus(String status);
    
    // 支持 Record 投影
    List<UserProjection> findAllProjectedBy();
}

// Record 投影
public record UserProjection(Long id, String name) {}
```

---

## 10. 安全性增强

### 10.1 Spring Security 6 变化

**配置方式变化：**

**Spring Security 5：**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            .httpBasic();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user").password("{noop}password").roles("USER");
    }
}
```

**Spring Security 6：**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());
        
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
```

### 10.2 方法名变化对照

| Spring Security 5 | Spring Security 6 |
|-------------------|-------------------|
| `authorizeRequests()` | `authorizeHttpRequests()` |
| `antMatchers()` | `requestMatchers()` |
| `mvcMatchers()` | `requestMatchers()` |
| `regexMatchers()` | `requestMatchers()` |
| `access("hasRole('ADMIN')")` | `access(AuthorizationManagers.hasRole("ADMIN"))` |

### 10.3 CSRF 配置变化

```java
// Spring Security 5
http.csrf().disable();
http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

// Spring Security 6
http.csrf(csrf -> csrf.disable());
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
);
```

### 10.4 OAuth2 变化

```java
// Spring Security 6 OAuth2 配置
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/home")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService())
                )
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }
}
```

---

## 11. 测试增强

### 11.1 测试注解变化

**Spring 5：**
```java
@RunWith(SpringRunner.class)
@SpringBootTest
public class UserServiceTest {
    // ...
}
```

**Spring 6（JUnit 5）：**
```java
// 不再需要 @RunWith
@SpringBootTest
class UserServiceTest {
    // ...
}
```

### 11.2 MockMvc 变化

```java
@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void shouldGetUser() throws Exception {
        // Spring 6 推荐使用静态导入
        mockMvc.perform(get("/users/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("张三"));
    }
    
    // 使用 MockMvcTester（Spring 6.2+）
    @Autowired
    private MockMvcTester mockMvcTester;
    
    @Test
    void shouldGetUserWithTester() {
        mockMvcTester.get().uri("/users/1")
                .assertThat()
                .hasStatusOk()
                .bodyJson()
                .extractingPath("$.name")
                .isEqualTo("张三");
    }
}
```

### 11.3 测试容器支持

Spring Boot 3.1+ 增强了 Testcontainers 支持：

```java
@SpringBootTest
@Testcontainers
class UserRepositoryTest {
    
    @Container
    @ServiceConnection  // 自动配置连接
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15");
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    void shouldSaveUser() {
        User user = new User("张三", "zhangsan@example.com");
        User saved = userRepository.save(user);
        assertThat(saved.getId()).isNotNull();
    }
}
```

**动态属性配置（旧方式）：**
```java
@DynamicPropertySource
static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);
}
```

---

## 12. 配置属性变化

### 12.1 属性名变化对照

| Spring Boot 2.x | Spring Boot 3.x | 说明 |
|-----------------|-----------------|------|
| `spring.redis.*` | `spring.data.redis.*` | Redis 配置 |
| `spring.elasticsearch.*` | `spring.elasticsearch.*` | 保持不变 |
| `spring.flyway.url` | `spring.flyway.url` | 保持不变 |
| `server.max-http-header-size` | `server.max-http-request-header-size` | HTTP 头大小 |
| `spring.mvc.throw-exception-if-no-handler-found` | 默认 true | 异常处理 |

### 12.2 Redis 配置迁移

**Spring Boot 2.x：**
```yaml
spring:
  redis:
    host: localhost
    port: 6379
    password: secret
    lettuce:
      pool:
        max-active: 8
```

**Spring Boot 3.x：**
```yaml
spring:
  data:
    redis:
      host: localhost
      port: 6379
      password: secret
      lettuce:
        pool:
          max-active: 8
```

### 12.3 Actuator 端点变化

```yaml
# Spring Boot 3.x Actuator 配置
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
      probes:
        enabled: true  # Kubernetes 探针
  health:
    livenessstate:
      enabled: true
    readinessstate:
      enabled: true
```

### 12.4 日志配置变化

**Logback 配置文件名：**
- Spring Boot 2.x: `logback-spring.xml`
- Spring Boot 3.x: `logback-spring.xml`（保持不变）

**结构化日志（Spring Boot 3.4+）：**
```yaml
logging:
  structured:
    format:
      console: ecs  # Elastic Common Schema
      file: logfmt
```

---

## 13. 废弃与移除

### 13.1 已移除的类和方法

| 移除项 | 替代方案 |
|--------|----------|
| `WebSecurityConfigurerAdapter` | `SecurityFilterChain` Bean |
| `RestTemplate`（未移除但不推荐） | `RestClient` 或 `WebClient` |
| `AsyncRestTemplate` | `WebClient` |
| `CommonsMultipartResolver` | `StandardServletMultipartResolver` |
| `LocaleResolver.setDefaultLocale()` | 构造器参数 |

### 13.2 废弃的注解

```java
// ❌ 已废弃
@RequestMapping(value = "/users", method = RequestMethod.GET)

// ✅ 推荐
@GetMapping("/users")

// ❌ 已废弃
@Autowired
private UserService userService;

// ✅ 推荐：构造器注入
private final UserService userService;

public MyController(UserService userService) {
    this.userService = userService;
}
```

### 13.3 移除的 Spring Boot 属性

```yaml
# ❌ 已移除
spring.data.elasticsearch.client.reactive.endpoints
spring.datasource.initialization-mode

# ✅ 替代
spring.elasticsearch.uris
spring.sql.init.mode
```

---

## 14. 迁移实战

### 14.1 迁移检查清单

```markdown
## 迁移前准备
- [ ] 确认 Java 版本 >= 17
- [ ] 确认所有依赖都有 Jakarta EE 兼容版本
- [ ] 备份项目代码
- [ ] 阅读官方迁移指南

## 代码迁移
- [ ] 更新 parent/BOM 版本
- [ ] javax.* → jakarta.* 包名替换
- [ ] 更新 Spring Security 配置
- [ ] 更新属性配置名称
- [ ] 检查路径匹配规则
- [ ] 更新测试代码

## 验证
- [ ] 编译通过
- [ ] 单元测试通过
- [ ] 集成测试通过
- [ ] 功能测试通过
```

### 14.2 分步迁移策略

**第一步：升级 Java 版本**
```xml
<properties>
    <java.version>17</java.version>
</properties>
```

**第二步：升级 Spring Boot 版本**
```xml
<!-- 先升级到 2.7.x 最新版，解决废弃警告 -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>

<!-- 然后升级到 3.x -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.12</version>
</parent>
```

**第三步：批量替换包名**
```bash
# 使用 sed（Linux/Mac）
find . -name "*.java" -exec sed -i 's/javax\.persistence/jakarta.persistence/g' {} +
find . -name "*.java" -exec sed -i 's/javax\.validation/jakarta.validation/g' {} +
find . -name "*.java" -exec sed -i 's/javax\.servlet/jakarta.servlet/g' {} +
find . -name "*.java" -exec sed -i 's/javax\.annotation/jakarta.annotation/g' {} +

# 或使用 IDE 的全局替换功能
```

**第四步：更新 Security 配置**
```java
// 旧配置
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/**").authenticated();
    }
}

// 新配置
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/**").authenticated()
        );
        return http.build();
    }
}
```

### 14.3 常见第三方库兼容版本

| 库 | Spring Boot 2.x 版本 | Spring Boot 3.x 版本 |
|----|---------------------|---------------------|
| MyBatis | 2.2.x | 3.0.x |
| MyBatis-Plus | 3.5.x | 3.5.5+ |
| Druid | 1.2.x | 1.2.21+ |
| PageHelper | 1.4.x | 2.0.x |
| Swagger | 2.x / 3.0.x | SpringDoc 2.x |
| Hutool | 5.x | 5.8.x+ |

**Swagger/OpenAPI 迁移：**
```xml
<!-- Spring Boot 2.x: Springfox -->
<dependency>
    <groupId>io.springfox</groupId>
    <artifactId>springfox-boot-starter</artifactId>
    <version>3.0.0</version>
</dependency>

<!-- Spring Boot 3.x: SpringDoc -->
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.3.0</version>
</dependency>
```

---

## 15. 常见错误与解决方案

### 15.1 编译错误

**错误：package javax.persistence does not exist**
```java
// 原因：使用了旧的 javax 包
// 解决：替换为 jakarta
import javax.persistence.Entity;  // ❌
import jakarta.persistence.Entity; // ✅
```

**错误：cannot find symbol WebSecurityConfigurerAdapter**
```java
// 原因：该类已被移除
// 解决：使用 SecurityFilterChain Bean 方式配置

// ❌ 旧方式
public class SecurityConfig extends WebSecurityConfigurerAdapter { }

// ✅ 新方式
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 配置
        return http.build();
    }
}
```

**错误：cannot find symbol antMatchers**
```java
// 原因：方法已重命名
// 解决：使用 requestMatchers

http.authorizeRequests().antMatchers("/api/**")  // ❌
http.authorizeHttpRequests(auth -> auth.requestMatchers("/api/**"))  // ✅
```

### 15.2 运行时错误

**错误：No qualifying bean of type 'javax.persistence.EntityManagerFactory'**
```java
// 原因：JPA 依赖版本不兼容
// 解决：确保使用 Jakarta 版本的 JPA

// pom.xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
    <!-- Spring Boot 3.x 会自动使用 Jakarta JPA -->
</dependency>
```

**错误：ClassNotFoundException: javax.servlet.Filter**
```java
// 原因：Servlet API 版本不兼容
// 解决：检查是否有旧版本依赖

// 排查命令
mvn dependency:tree | grep servlet

// 排除旧依赖
<dependency>
    <groupId>some.library</groupId>
    <artifactId>some-artifact</artifactId>
    <exclusions>
        <exclusion>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```

**错误：Failed to determine a suitable driver class**
```yaml
# 原因：数据源配置属性名变化
# 解决：检查配置属性名

# Spring Boot 2.x
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/db

# Spring Boot 3.x（保持不变，但检查驱动类名）
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/db
    driver-class-name: com.mysql.cj.jdbc.Driver
```

### 15.3 路径匹配错误

**错误：No mapping for GET /api/v1/users/**
```java
// 原因：PathPatternParser 不支持 ** 在路径中间
// 解决：调整路径模式

// ❌ Spring 6 不支持
@GetMapping("/api/**/users")

// ✅ 正确写法
@GetMapping("/api/*/users")
@GetMapping("/api/v1/users")
@GetMapping("/api/{version}/users")
```

**错误：路径 /users 和 /users/ 不匹配**
```java
// 原因：Spring 6 默认不匹配尾部斜杠
// 解决方案一：同时映射两个路径
@GetMapping({"/users", "/users/"})

// 解决方案二：全局配置
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        configurer.setUseTrailingSlashMatch(true);
    }
}
```

### 15.4 安全配置错误

**错误：CSRF token 验证失败**
```java
// 原因：Spring Security 6 CSRF 处理方式变化
// 解决：更新 CSRF 配置

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
    );
    return http.build();
}

// 或者对于 REST API 禁用 CSRF
http.csrf(csrf -> csrf.disable());
```

**错误：Access Denied 403**
```java
// 原因：权限表达式变化
// 解决：检查权限配置

// ❌ 旧写法
.antMatchers("/admin/**").access("hasRole('ADMIN')")

// ✅ 新写法
.requestMatchers("/admin/**").hasRole("ADMIN")
// 或
.requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
```

### 15.5 测试错误

**错误：No tests found**
```java
// 原因：JUnit 4 注解在 JUnit 5 中不生效
// 解决：更新测试注解

// ❌ JUnit 4
import org.junit.Test;
import org.junit.runner.RunWith;
@RunWith(SpringRunner.class)

// ✅ JUnit 5
import org.junit.jupiter.api.Test;
// 不需要 @RunWith
```

**错误：MockMvc 返回 404**
```java
// 原因：路径匹配规则变化
// 解决：检查请求路径

// 确保路径完全匹配
mockMvc.perform(get("/users"))   // 不是 /users/
        .andExpect(status().isOk());
```

### 15.6 AOT/原生镜像错误

**错误：Native image build failed - reflection not registered**
```java
// 原因：反射调用未注册
// 解决：添加反射提示

@Configuration
@ImportRuntimeHints(MyHints.class)
public class AppConfig { }

public class MyHints implements RuntimeHintsRegistrar {
    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        hints.reflection().registerType(MyClass.class,
            MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
            MemberCategory.INVOKE_DECLARED_METHODS,
            MemberCategory.DECLARED_FIELDS);
    }
}
```

**错误：Resource not found in native image**
```java
// 原因：资源文件未注册
// 解决：添加资源提示

public class MyHints implements RuntimeHintsRegistrar {
    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        hints.resources().registerPattern("config/*.json");
        hints.resources().registerPattern("templates/*");
    }
}
```

### 15.7 依赖冲突

**错误：NoSuchMethodError / NoClassDefFoundError**
```bash
# 排查依赖冲突
mvn dependency:tree -Dincludes=groupId:artifactId

# 强制使用特定版本
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>conflicting.group</groupId>
            <artifactId>conflicting-artifact</artifactId>
            <version>correct.version</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```

---

## 附录：快速参考

### 包名替换速查

```
javax.annotation      → jakarta.annotation
javax.persistence     → jakarta.persistence
javax.servlet         → jakarta.servlet
javax.transaction     → jakarta.transaction
javax.validation      → jakarta.validation
javax.websocket       → jakarta.websocket
javax.mail            → jakarta.mail
javax.inject          → jakarta.inject
javax.json            → jakarta.json
```

### Spring Security 方法对照

```
authorizeRequests()      → authorizeHttpRequests()
antMatchers()            → requestMatchers()
mvcMatchers()            → requestMatchers()
csrf().disable()         → csrf(c -> c.disable())
formLogin()              → formLogin(Customizer.withDefaults())
httpBasic()              → httpBasic(Customizer.withDefaults())
```

### 配置属性对照

```
spring.redis.*           → spring.data.redis.*
server.max-http-header-size → server.max-http-request-header-size
```

---

> 💡 **迁移建议**：
> 1. 先在测试环境完成迁移，充分测试后再上生产
> 2. 使用 OpenRewrite 等工具自动化大部分迁移工作
> 3. 关注官方迁移指南，及时了解最新变化
> 4. 分步迁移：先升级到 2.7.x 解决废弃警告，再升级到 3.x
> 5. 保持依赖版本一致，避免混用 javax 和 jakarta
