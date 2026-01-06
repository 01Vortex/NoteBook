# Spring Boot 应用企业级开发规范

> 基于 Java 21 + Spring Boot 3.2.x 的企业级后端开发最佳实践
> 本规范涵盖项目结构、代码风格、命名规范、分层架构、异常处理、安全规范等方面

---

## 目录

1. [项目初始化与结构](#1-项目初始化与结构)
2. [命名规范](#2-命名规范)
3. [分层架构规范](#3-分层架构规范)
4. [RESTful API 规范](#4-restful-api-规范)
5. [数据访问层规范](#5-数据访问层规范)
6. [异常处理规范](#6-异常处理规范)
7. [日志规范](#7-日志规范)
8. [配置管理规范](#8-配置管理规范)
9. [安全规范](#9-安全规范)
10. [缓存规范](#10-缓存规范)
11. [异步与定时任务](#11-异步与定时任务)
12. [测试规范](#12-测试规范)
13. [性能优化](#13-性能优化)
14. [部署与运维](#14-部署与运维)
15. [常见错误与踩坑](#15-常见错误与踩坑)

---

## 1. 项目初始化与结构

### 1.1 技术栈选型

```
┌─────────────────────────────────────────────────────────────────────┐
│ 企业级 Spring Boot 技术栈 (2024/2025)                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 核心框架:                                                            │
│ • Java 21 LTS (虚拟线程、Record、Pattern Matching)                  │
│ • Spring Boot 3.2.x (Spring 6.x)                                    │
│ • Spring Security 6.x                                               │
│                                                                      │
│ 数据访问:                                                            │
│ • MyBatis-Plus 3.5.x / Spring Data JPA                              │
│ • MySQL 8.x / PostgreSQL 16.x                                       │
│ • Redis 7.x (Lettuce)                                               │
│                                                                      │
│ 接口文档:                                                            │
│ • SpringDoc OpenAPI 2.x (Swagger 3)                                 │
│                                                                      │
│ 工具库:                                                              │
│ • Lombok                                                            │
│ • MapStruct (对象映射)                                              │
│ • Hutool / Apache Commons                                           │
│ • Jackson (JSON处理)                                                │
│                                                                      │
│ 构建工具:                                                            │
│ • Maven 3.9.x / Gradle 8.x                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 多模块项目结构

企业级项目推荐使用多模块 Maven 结构，便于代码复用和团队协作。

```
my-project/                          # 父工程，统一管理依赖版本和构建配置
├── pom.xml                          # 父 POM 文件，定义所有子模块的公共依赖和插件
├── my-project-common/               # 公共模块
│   ├── pom.xml
│   └── src/main/java/
│       └── com/example/common/
│           ├── constant/            # 常量定义（如状态码、错误码）
│           ├── enums/               # 枚举类（如用户性别、订单状态等）
│           ├── exception/           # 自定义异常类
│           ├── result/              # 统一响应
│           └── utils/               # 纯工具类，无外部依赖
│
├── my-project-domain/               # 领域模块
│   ├── pom.xml
│   └── src/main/java/
│       └── com/example/domain/
│           ├── entity/              # 实体类
│           │   ├── user/            # 用户相关实体
│           │   │   └── User.java    # 用户实体
│           │   └── media/
│           │       └── Media.java   # 媒体实体   
│           ├── query/               # 查询参数对象（如用于动态查询条件封装）
│           └── convert/             # 对象转换器
│
├── my-project-infrastructure/       # 基础设施模块
│   ├── pom.xml
│   ├── src/main/java/com/example/infrastructure/ 基础设施模块(放第三方)
│   │   ├── config/                  # 第三方组件自动配置类
│   │   │   ├── RedisConfig.java     # Redis 配置
│   │   │   ├── MyBatisConfig.java   # MyBatis 配置（若需要）
│   │   │   └── MinioConfig.java
│   │   ├── storage/             # 存储服务实现   
│   │   │   └── MinioImpl.java   # MinIO 存储服务实现（接口应在 api 模块）
│   │   ├── sms/                 # 短信服务实现
│   │   │   └── TencentSmsClientImpl.java
│   │   ├── mapper(repository)/  # 数据访问层实现(MyBatis Mapper)
│   │   │   ├── user/
│   │   │   │   └── UserMapper.java
│   │   │   └── media/
│   │   │       └── MediaMapper.java
│   │   └── util/ # 技术工具类(放需要某些依赖的工具)
│   │       └── SnowflakeID.java # 雪花算法ID生成器
│   └── src/main/resources/
│                └── mapper/          # MyBatis XML 复杂的查询用(优先用注解)
│                
├── my-project-api/                  # API模块(纯接口与数据结构定义,无业务逻辑)
│   ├── pom.xml
│   └── src/main/java/
│       └── com/example/api/
│           ├── dto/                 # 数据传输对象（DTO）
│           │   ├── user/            # 用户领域相关 DTO     
│           │   │   ├── request/     # 请求DTO（如创建用户请求）
│           │   │   │   └──UserInfoRequest.java
│           │   │   ├── response/    # 响应DTO（可选，若使用统一 Result 可省略）
│           │   │   │   └──UserInfoResponse.java 
│           │   │   ├── vo/          # 视图DTO（字段可能脱敏/聚合）
│           │   │   │   └──UserInfoVO.java # 例如：隐藏手机号中间四位
│           │   │   └── UserDTO.java # 通用用户数据传输对象
│           │   └── media/           # 媒体领域相关 DTO(按业务域划分，保持模块内聚)
│           │
│           └── service/             # 服务接口定义 —— 业务能力的抽象契约
│               ├── user/            # 用户相关服务接口
│               │   └── UserService.java
│               └── media/
│                   └── MediaService.java
│
├── my-project-user/                  # 用户模块：实现用户相关的业务逻辑
│   ├── pom.xml
│   └── src/main/java/
│       └── com/example/user/
│           ├── controller
│           │   └── UserController.java
│           └── service
│               └── UserServiceImpl.java  # 用户服务实现
│
├── my-project-media/                  # 媒体模块：实现媒体相关的业务逻辑
│   ├── pom.xml
│   └── src/main/java/
│       └── com/example/media/
│           ├── controller
│           │   └── MediaController.java
│           └── service
│               └── MediaServiceImpl.java  # 用户服务实现
│        
└── my-project-web/                   # Web 模块：应用的启动入口
    ├── pom.xml
    └── src/
        ├── main/
        │   ├── java/
        │   │   └── com/example/
        │   │       ├── controller/  # 控制器
        │   │       ├── exception/      # 配置类
        │   │       │   └── GlobalExceptionHandler.java # 全局异常处理
        │   │       └── Application.java
        │   └── resources/
        │       ├── application.yml # Spring Boot 主配置文件
        │       ├── application-dev.yml # 开发环境配置
        │       └── application-prod.yml # 生产环境配置
        └── test/                    # 测试代码

```

**模块依赖图：**

```
                      web
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        user        media         ...
          │            │            │
          └────────────┼────────────┘
                       ▼
                      api
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
      infrastructure ─────►    domain
             │                   │
             └─────────┬─────────┘
                       ▼
                    common
```

### 1.3 父 POM 配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>my-project</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>pom</packaging>
    <name>My Project</name>
    <description>企业级 Spring Boot 项目</description>

    <!-- 子模块 -->
    <modules>
        <module>my-project-common</module>
        <module>my-project-domain</module>
        <module>my-project-dao</module>
        <module>my-project-service</module>
        <module>my-project-web</module>
    </modules>

    <!-- 版本管理 -->
    <properties>
        <java.version>21</java.version>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        
        <!-- Spring Boot -->
        <spring-boot.version>3.2.12</spring-boot.version>
        
        <!-- 数据库 -->
        <mybatis-plus.version>3.5.5</mybatis-plus.version>
        <mysql.version>8.0.33</mysql.version>
        <druid.version>1.2.21</druid.version>
        
        <!-- 工具 -->
        <lombok.version>1.18.30</lombok.version>
        <mapstruct.version>1.5.5.Final</mapstruct.version>
        <hutool.version>5.8.25</hutool.version>
        
        <!-- API 文档 -->
        <springdoc.version>2.3.0</springdoc.version>
        
        <!-- JWT -->
        <jjwt.version>0.12.5</jjwt.version>
    </properties>

    <!-- 依赖管理 -->
    <dependencyManagement>
        <dependencies>
            <!-- Spring Boot BOM -->
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring-boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>

            <!-- 项目模块 -->
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>my-project-common</artifactId>
                <version>${project.version}</version>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>my-project-domain</artifactId>
                <version>${project.version}</version>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>my-project-dao</artifactId>
                <version>${project.version}</version>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>my-project-service</artifactId>
                <version>${project.version}</version>
            </dependency>

            <!-- MyBatis-Plus -->
            <dependency>
                <groupId>com.baomidou</groupId>
                <artifactId>mybatis-plus-spring-boot3-starter</artifactId>
                <version>${mybatis-plus.version}</version>
            </dependency>

            <!-- Druid 连接池 -->
            <dependency>
                <groupId>com.alibaba</groupId>
                <artifactId>druid-spring-boot-3-starter</artifactId>
                <version>${druid.version}</version>
            </dependency>

            <!-- Hutool -->
            <dependency>
                <groupId>cn.hutool</groupId>
                <artifactId>hutool-all</artifactId>
                <version>${hutool.version}</version>
            </dependency>

            <!-- MapStruct -->
            <dependency>
                <groupId>org.mapstruct</groupId>
                <artifactId>mapstruct</artifactId>
                <version>${mapstruct.version}</version>
            </dependency>

            <!-- SpringDoc OpenAPI -->
            <dependency>
                <groupId>org.springdoc</groupId>
                <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
                <version>${springdoc.version}</version>
            </dependency>

            <!-- JWT -->
            <dependency>
                <groupId>io.jsonwebtoken</groupId>
                <artifactId>jjwt-api</artifactId>
                <version>${jjwt.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <!-- 公共依赖 -->
    <dependencies>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <scope>provided</scope>
        </dependency>
    </dependencies>

    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-maven-plugin</artifactId>
                    <version>${spring-boot.version}</version>
                </plugin>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>3.11.0</version>
                    <configuration>
                        <source>${java.version}</source>
                        <target>${java.version}</target>
                        <annotationProcessorPaths>
                            <path>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok</artifactId>
                                <version>${lombok.version}</version>
                            </path>
                            <path>
                                <groupId>org.mapstruct</groupId>
                                <artifactId>mapstruct-processor</artifactId>
                                <version>${mapstruct.version}</version>
                            </path>
                        </annotationProcessorPaths>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>
</project>
```

---

## 2. 命名规范

良好的命名是代码可读性的基础。遵循统一的命名规范能让团队协作更加顺畅。

### 2.1 包命名

```
┌─────────────────────────────────────────────────────────────────────┐
│ 包命名规范                                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 基本规则:                                                            │
│ • 全部小写                                                          │
│ • 使用公司/组织域名倒序                                              │
│ • 单词之间不使用分隔符                                               │
│                                                                      │
│ 示例:                                                                │
│ com.example.project.controller    # 控制器                          │
│ com.example.project.service       # 服务接口                        │
│ com.example.project.service.impl  # 服务实现                        │
│ com.example.project.dao           # 数据访问                        │
│ com.example.project.entity        # 实体类                          │
│ com.example.project.dto           # 数据传输对象                    │
│ com.example.project.vo            # 视图对象                        │
│ com.example.project.config        # 配置类                          │
│ com.example.project.util          # 工具类                          │
│ com.example.project.constant      # 常量                            │
│ com.example.project.enums         # 枚举                            │
│ com.example.project.exception     # 异常                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 类命名

```java
// ✅ 类命名规范 - 使用 PascalCase（大驼峰）

// 实体类：与数据库表对应，使用名词
public class User { }
public class OrderItem { }
public class ProductCategory { }

// DTO：数据传输对象，添加 DTO 后缀
public class UserDTO { }
public class CreateOrderDTO { }
public class UserLoginDTO { }

// VO：视图对象，添加 VO 后缀
public class UserVO { }
public class OrderDetailVO { }

// Query：查询参数对象，添加 Query 后缀
public class UserQuery { }
public class OrderPageQuery { }

// Controller：添加 Controller 后缀
public class UserController { }
public class OrderController { }

// Service 接口：添加 Service 后缀
public interface UserService { }
public interface OrderService { }

// Service 实现：添加 ServiceImpl 后缀
public class UserServiceImpl implements UserService { }

// Mapper/Repository：添加 Mapper 或 Repository 后缀
public interface UserMapper { }
public interface UserRepository { }

// 配置类：添加 Config 后缀
public class RedisConfig { }
public class SecurityConfig { }

// 异常类：添加 Exception 后缀
public class BusinessException extends RuntimeException { }
public class UserNotFoundException extends BusinessException { }

// 工具类：添加 Utils 或 Helper 后缀
public class DateUtils { }
public class StringHelper { }

// 常量类：添加 Constants 后缀
public class CommonConstants { }
public class RedisConstants { }

// 枚举类：使用名词，不加后缀
public enum UserStatus { }
public enum OrderType { }
```

### 2.3 方法命名

```java
// ✅ 方法命名规范 - 使用 camelCase（小驼峰）

// Controller 层方法
@GetMapping("/users")
public Result<List<UserVO>> listUsers() { }          // 查询列表

@GetMapping("/users/{id}")
public Result<UserVO> getUserById(@PathVariable Long id) { }  // 根据ID查询

@PostMapping("/users")
public Result<Long> createUser(@RequestBody CreateUserDTO dto) { }  // 创建

@PutMapping("/users/{id}")
public Result<Void> updateUser(@PathVariable Long id, @RequestBody UpdateUserDTO dto) { }  // 更新

@DeleteMapping("/users/{id}")
public Result<Void> deleteUser(@PathVariable Long id) { }  // 删除

// Service 层方法
// 查询方法：get/find/query/list/page
UserVO getById(Long id);                    // 根据ID获取单个
UserVO getByUsername(String username);      // 根据条件获取单个
List<UserVO> listByStatus(Integer status);  // 根据条件获取列表
List<UserVO> listAll();                     // 获取所有
PageResult<UserVO> page(UserQuery query);   // 分页查询
boolean existsByUsername(String username);  // 判断是否存在

// 新增方法：save/create/add/insert
Long save(CreateUserDTO dto);               // 保存
void saveBatch(List<CreateUserDTO> list);   // 批量保存

// 更新方法：update/modify/edit
void updateById(Long id, UpdateUserDTO dto);  // 根据ID更新
void updateStatus(Long id, Integer status);   // 更新状态

// 删除方法：delete/remove
void deleteById(Long id);                   // 根据ID删除
void deleteByIds(List<Long> ids);           // 批量删除

// 统计方法：count
long countByStatus(Integer status);         // 统计数量

// 校验方法：check/validate/verify
void checkUsername(String username);        // 校验用户名
boolean validatePassword(String password);  // 验证密码

// 处理方法：handle/process/execute
void handleOrder(Long orderId);             // 处理订单
void processPayment(PaymentDTO dto);        // 处理支付

// 转换方法：convert/transform/parse
UserVO convertToVO(User entity);            // 转换为VO
User parseFromDTO(CreateUserDTO dto);       // 从DTO解析

// ❌ 不好的命名
void doSomething();      // 含义不清
void process();          // 太泛泛
void handle();           // 不知道处理什么
Object getData();        // 返回类型不明确
void setData();          // 不是 setter 却用 set 开头
```

### 2.4 变量命名

```java
// ✅ 变量命名规范 - 使用 camelCase（小驼峰）

// 普通变量
String userName;
Integer orderCount;
List<User> userList;
Map<String, Object> resultMap;

// 布尔变量：使用 is/has/can/should 前缀
boolean isActive;
boolean hasPermission;
boolean canEdit;
boolean shouldNotify;

// 常量：使用 SCREAMING_SNAKE_CASE（全大写下划线分隔）
public static final String DEFAULT_PASSWORD = "123456";
public static final int MAX_RETRY_COUNT = 3;
public static final long TOKEN_EXPIRE_TIME = 7200L;

// 集合变量：使用复数形式
List<User> users;
Set<String> permissions;
Map<Long, Order> orderMap;  // Map 使用 Map 后缀

// 临时变量：避免使用 temp、tmp
// ❌ String temp = user.getName();
// ✅ String currentUserName = user.getName();

// 循环变量
for (User user : users) { }           // 增强 for 循环
for (int i = 0; i < size; i++) { }    // 普通 for 循环，i/j/k 可接受
for (Map.Entry<String, Object> entry : map.entrySet()) { }  // Map 遍历
```

### 2.5 数据库命名

```sql
-- ✅ 数据库命名规范 - 使用 snake_case（下划线分隔）

-- 表名：使用小写，下划线分隔，使用名词复数或业务前缀
CREATE TABLE sys_user (           -- 系统用户表
    id BIGINT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    ...
);

CREATE TABLE sys_role (           -- 系统角色表
    ...
);

CREATE TABLE order_info (         -- 订单信息表
    ...
);

CREATE TABLE order_item (         -- 订单项表
    ...
);

-- 字段名：使用小写，下划线分隔
id                  -- 主键
user_id             -- 外键
user_name           -- 用户名
create_time         -- 创建时间
update_time         -- 更新时间
create_by           -- 创建人
update_by           -- 更新人
is_deleted          -- 逻辑删除标志
status              -- 状态
sort_order          -- 排序

-- 索引名
idx_user_name       -- 普通索引：idx_字段名
uk_user_email       -- 唯一索引：uk_字段名
pk_user_id          -- 主键索引：pk_字段名
```

---

## 3. 分层架构规范

Spring Boot 项目采用经典的分层架构，每一层有明确的职责。

### 3.1 分层架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         分层架构                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Controller 层                             │   │
│  │  • 接收请求，参数校验                                         │   │
│  │  • 调用 Service，返回响应                                     │   │
│  │  • 不包含业务逻辑                                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Service 层                                │   │
│  │  • 业务逻辑处理                                              │   │
│  │  • 事务管理                                                  │   │
│  │  • 调用多个 DAO/Mapper                                       │   │
│  │  • DTO/VO 转换                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    DAO/Mapper 层                             │   │
│  │  • 数据库访问                                                │   │
│  │  • CRUD 操作                                                 │   │
│  │  • 不包含业务逻辑                                            │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Database                                  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

数据流转：
Request → Controller → Service → DAO → Database
                ↓           ↓
              DTO/VO     Entity
```

### 3.2 Controller 层规范

```java
/**
 * 用户管理控制器
 * 
 * Controller 层职责：
 * 1. 接收和校验请求参数
 * 2. 调用 Service 层方法
 * 3. 封装并返回响应结果
 * 4. 不包含任何业务逻辑
 */
@Tag(name = "用户管理", description = "用户相关接口")
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Validated
public class UserController {

    private final UserService userService;

    /**
     * 分页查询用户列表
     */
    @Operation(summary = "分页查询用户")
    @GetMapping
    public Result<PageResult<UserVO>> page(@Valid UserQuery query) {
        return Result.success(userService.page(query));
    }

    /**
     * 根据ID查询用户详情
     */
    @Operation(summary = "查询用户详情")
    @GetMapping("/{id}")
    public Result<UserVO> getById(
            @Parameter(description = "用户ID") @PathVariable Long id) {
        return Result.success(userService.getById(id));
    }

    /**
     * 创建用户
     */
    @Operation(summary = "创建用户")
    @PostMapping
    public Result<Long> create(@Valid @RequestBody CreateUserDTO dto) {
        return Result.success(userService.create(dto));
    }

    /**
     * 更新用户
     */
    @Operation(summary = "更新用户")
    @PutMapping("/{id}")
    public Result<Void> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserDTO dto) {
        userService.update(id, dto);
        return Result.success();
    }

    /**
     * 删除用户
     */
    @Operation(summary = "删除用户")
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return Result.success();
    }

    /**
     * 批量删除用户
     */
    @Operation(summary = "批量删除用户")
    @DeleteMapping("/batch")
    public Result<Void> deleteBatch(@RequestBody List<Long> ids) {
        userService.deleteBatch(ids);
        return Result.success();
    }

    /**
     * 导出用户数据
     */
    @Operation(summary = "导出用户数据")
    @GetMapping("/export")
    public void export(UserQuery query, HttpServletResponse response) {
        userService.export(query, response);
    }
}
```

### 3.3 Service 层规范

```java
/**
 * 用户服务接口
 */
public interface UserService {
    
    PageResult<UserVO> page(UserQuery query);
    
    UserVO getById(Long id);
    
    Long create(CreateUserDTO dto);
    
    void update(Long id, UpdateUserDTO dto);
    
    void delete(Long id);
    
    void deleteBatch(List<Long> ids);
}

/**
 * 用户服务实现
 * 
 * Service 层职责：
 * 1. 实现业务逻辑
 * 2. 事务管理
 * 3. 调用 DAO 层
 * 4. 对象转换（Entity <-> DTO/VO）
 * 5. 参数校验（业务校验）
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final UserConvert userConvert;
    private final PasswordEncoder passwordEncoder;
    private final RoleService roleService;

    @Override
    public PageResult<UserVO> page(UserQuery query) {
        // 1. 构建分页参数
        Page<User> page = new Page<>(query.getPageNum(), query.getPageSize());
        
        // 2. 构建查询条件
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<User>()
                .like(StrUtil.isNotBlank(query.getUsername()), User::getUsername, query.getUsername())
                .eq(query.getStatus() != null, User::getStatus, query.getStatus())
                .orderByDesc(User::getCreateTime);
        
        // 3. 执行查询
        Page<User> result = userMapper.selectPage(page, wrapper);
        
        // 4. 转换并返回
        List<UserVO> voList = userConvert.toVOList(result.getRecords());
        return PageResult.of(voList, result.getTotal());
    }

    @Override
    public UserVO getById(Long id) {
        User user = userMapper.selectById(id);
        if (user == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        return userConvert.toVO(user);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public Long create(CreateUserDTO dto) {
        // 1. 业务校验
        checkUsernameUnique(dto.getUsername());
        
        // 2. 转换实体
        User user = userConvert.toEntity(dto);
        
        // 3. 设置默认值
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setStatus(UserStatus.ACTIVE.getValue());
        
        // 4. 保存数据
        userMapper.insert(user);
        
        // 5. 保存用户角色关联
        if (CollUtil.isNotEmpty(dto.getRoleIds())) {
            roleService.saveUserRoles(user.getId(), dto.getRoleIds());
        }
        
        log.info("创建用户成功: {}", user.getUsername());
        return user.getId();
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void update(Long id, UpdateUserDTO dto) {
        // 1. 查询用户是否存在
        User user = userMapper.selectById(id);
        if (user == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        
        // 2. 业务校验
        if (!user.getUsername().equals(dto.getUsername())) {
            checkUsernameUnique(dto.getUsername());
        }
        
        // 3. 更新数据
        userConvert.updateEntity(dto, user);
        userMapper.updateById(user);
        
        // 4. 更新用户角色
        if (dto.getRoleIds() != null) {
            roleService.updateUserRoles(id, dto.getRoleIds());
        }
        
        log.info("更新用户成功: {}", id);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void delete(Long id) {
        User user = userMapper.selectById(id);
        if (user == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        
        // 逻辑删除
        userMapper.deleteById(id);
        
        // 删除关联数据
        roleService.deleteUserRoles(id);
        
        log.info("删除用户成功: {}", id);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void deleteBatch(List<Long> ids) {
        if (CollUtil.isEmpty(ids)) {
            return;
        }
        userMapper.deleteBatchIds(ids);
        ids.forEach(roleService::deleteUserRoles);
        log.info("批量删除用户成功: {}", ids);
    }

    /**
     * 校验用户名唯一性
     */
    private void checkUsernameUnique(String username) {
        Long count = userMapper.selectCount(
                new LambdaQueryWrapper<User>().eq(User::getUsername, username)
        );
        if (count > 0) {
            throw new BusinessException(ErrorCode.USERNAME_EXISTS);
        }
    }
}
```

### 3.4 DAO/Mapper 层规范

```java
/**
 * 用户 Mapper 接口
 * 
 * DAO 层职责：
 * 1. 数据库 CRUD 操作
 * 2. 不包含业务逻辑
 * 3. 复杂查询使用 XML 或 @Select 注解
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {

    /**
     * 根据用户名查询用户（包含角色信息）
     */
    @Select("""
        SELECT u.*, r.role_name, r.role_code
        FROM sys_user u
        LEFT JOIN sys_user_role ur ON u.id = ur.user_id
        LEFT JOIN sys_role r ON ur.role_id = r.id
        WHERE u.username = #{username}
        AND u.is_deleted = 0
    """)
    @Results({
        @Result(property = "id", column = "id"),
        @Result(property = "roles", column = "id",
                many = @Many(select = "com.example.dao.RoleMapper.selectByUserId"))
    })
    User selectByUsername(String username);

    /**
     * 分页查询用户列表（复杂查询建议使用 XML）
     */
    Page<UserVO> selectUserPage(Page<User> page, @Param("query") UserQuery query);

    /**
     * 批量更新用户状态
     */
    @Update("""
        <script>
        UPDATE sys_user SET status = #{status}, update_time = NOW()
        WHERE id IN
        <foreach collection="ids" item="id" open="(" separator="," close=")">
            #{id}
        </foreach>
        </script>
    """)
    int updateStatusBatch(@Param("ids") List<Long> ids, @Param("status") Integer status);
}
```

**MyBatis XML 示例（复杂查询）：**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" 
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.dao.UserMapper">

    <!-- 结果映射 -->
    <resultMap id="UserVOResultMap" type="com.example.domain.vo.UserVO">
        <id property="id" column="id"/>
        <result property="username" column="username"/>
        <result property="nickname" column="nickname"/>
        <result property="email" column="email"/>
        <result property="phone" column="phone"/>
        <result property="status" column="status"/>
        <result property="createTime" column="create_time"/>
        <collection property="roles" ofType="com.example.domain.vo.RoleVO">
            <id property="id" column="role_id"/>
            <result property="roleName" column="role_name"/>
            <result property="roleCode" column="role_code"/>
        </collection>
    </resultMap>

    <!-- 分页查询用户 -->
    <select id="selectUserPage" resultMap="UserVOResultMap">
        SELECT 
            u.id, u.username, u.nickname, u.email, u.phone, 
            u.status, u.create_time,
            r.id as role_id, r.role_name, r.role_code
        FROM sys_user u
        LEFT JOIN sys_user_role ur ON u.id = ur.user_id
        LEFT JOIN sys_role r ON ur.role_id = r.id
        <where>
            u.is_deleted = 0
            <if test="query.username != null and query.username != ''">
                AND u.username LIKE CONCAT('%', #{query.username}, '%')
            </if>
            <if test="query.status != null">
                AND u.status = #{query.status}
            </if>
            <if test="query.startTime != null">
                AND u.create_time >= #{query.startTime}
            </if>
            <if test="query.endTime != null">
                AND u.create_time &lt;= #{query.endTime}
            </if>
        </where>
        ORDER BY u.create_time DESC
    </select>

</mapper>
```

### 3.5 实体类规范

```java
/**
 * 用户实体类
 * 
 * 实体类规范：
 * 1. 与数据库表一一对应
 * 2. 使用 @TableName 指定表名
 * 3. 使用 @TableId 指定主键
 * 4. 使用 @TableField 处理特殊字段
 * 5. 继承 BaseEntity 复用公共字段
 */
@Data
@EqualsAndHashCode(callSuper = true)
@TableName("sys_user")
public class User extends BaseEntity {

    /**
     * 用户ID
     */
    @TableId(type = IdType.ASSIGN_ID)  // 雪花算法
    private Long id;

    /**
     * 用户名
     */
    private String username;

    /**
     * 密码
     */
    @TableField(select = false)  // 查询时不返回
    private String password;

    /**
     * 昵称
     */
    private String nickname;

    /**
     * 邮箱
     */
    private String email;

    /**
     * 手机号
     */
    private String phone;

    /**
     * 头像
     */
    private String avatar;

    /**
     * 状态：0-禁用，1-启用
     */
    private Integer status;

    /**
     * 最后登录时间
     */
    private LocalDateTime lastLoginTime;

    /**
     * 最后登录IP
     */
    private String lastLoginIp;
}

/**
 * 基础实体类
 * 包含公共字段
 */
@Data
public abstract class BaseEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 创建时间
     */
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createTime;

    /**
     * 更新时间
     */
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;

    /**
     * 创建人
     */
    @TableField(fill = FieldFill.INSERT)
    private Long createBy;

    /**
     * 更新人
     */
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Long updateBy;

    /**
     * 逻辑删除标志
     */
    @TableLogic
    private Integer isDeleted;
}
```

### 3.6 DTO/VO/Query 规范

```java
/**
 * 创建用户 DTO
 * 
 * DTO 用于接收前端传入的数据
 * 包含参数校验注解
 */
@Data
@Schema(description = "创建用户请求")
public class CreateUserDTO {

    @Schema(description = "用户名", example = "admin")
    @NotBlank(message = "用户名不能为空")
    @Size(min = 4, max = 20, message = "用户名长度必须在4-20之间")
    @Pattern(regexp = "^[a-zA-Z][a-zA-Z0-9_]*$", message = "用户名必须以字母开头，只能包含字母、数字、下划线")
    private String username;

    @Schema(description = "密码", example = "123456")
    @NotBlank(message = "密码不能为空")
    @Size(min = 6, max = 20, message = "密码长度必须在6-20之间")
    private String password;

    @Schema(description = "昵称", example = "管理员")
    @Size(max = 50, message = "昵称长度不能超过50")
    private String nickname;

    @Schema(description = "邮箱", example = "admin@example.com")
    @Email(message = "邮箱格式不正确")
    private String email;

    @Schema(description = "手机号", example = "13800138000")
    @Pattern(regexp = "^1[3-9]\\d{9}$", message = "手机号格式不正确")
    private String phone;

    @Schema(description = "角色ID列表")
    private List<Long> roleIds;
}

/**
 * 更新用户 DTO
 */
@Data
@Schema(description = "更新用户请求")
public class UpdateUserDTO {

    @Schema(description = "昵称")
    @Size(max = 50, message = "昵称长度不能超过50")
    private String nickname;

    @Schema(description = "邮箱")
    @Email(message = "邮箱格式不正确")
    private String email;

    @Schema(description = "手机号")
    @Pattern(regexp = "^1[3-9]\\d{9}$", message = "手机号格式不正确")
    private String phone;

    @Schema(description = "状态")
    private Integer status;

    @Schema(description = "角色ID列表")
    private List<Long> roleIds;
}

/**
 * 用户 VO
 * 
 * VO 用于返回给前端的数据
 * 不包含敏感信息（如密码）
 */
@Data
@Schema(description = "用户信息")
public class UserVO {

    @Schema(description = "用户ID")
    private Long id;

    @Schema(description = "用户名")
    private String username;

    @Schema(description = "昵称")
    private String nickname;

    @Schema(description = "邮箱")
    private String email;

    @Schema(description = "手机号")
    private String phone;

    @Schema(description = "头像")
    private String avatar;

    @Schema(description = "状态")
    private Integer status;

    @Schema(description = "状态名称")
    private String statusName;

    @Schema(description = "角色列表")
    private List<RoleVO> roles;

    @Schema(description = "创建时间")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createTime;
}

/**
 * 用户查询参数
 * 
 * Query 用于封装查询条件
 * 继承分页参数
 */
@Data
@EqualsAndHashCode(callSuper = true)
@Schema(description = "用户查询参数")
public class UserQuery extends PageQuery {

    @Schema(description = "用户名")
    private String username;

    @Schema(description = "昵称")
    private String nickname;

    @Schema(description = "状态")
    private Integer status;

    @Schema(description = "开始时间")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime startTime;

    @Schema(description = "结束时间")
    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime endTime;
}

/**
 * 分页查询基类
 */
@Data
@Schema(description = "分页参数")
public class PageQuery {

    @Schema(description = "页码", example = "1")
    @Min(value = 1, message = "页码最小为1")
    private Integer pageNum = 1;

    @Schema(description = "每页条数", example = "10")
    @Min(value = 1, message = "每页条数最小为1")
    @Max(value = 100, message = "每页条数最大为100")
    private Integer pageSize = 10;

    @Schema(description = "排序字段")
    private String orderBy;

    @Schema(description = "排序方式：asc/desc")
    private String orderType;
}
```

### 3.7 对象转换（MapStruct）

```java
/**
 * 用户对象转换器
 * 
 * 使用 MapStruct 进行对象转换
 * 编译时生成实现类，性能优于反射
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserConvert {

    /**
     * Entity -> VO
     */
    @Mapping(target = "statusName", expression = "java(getStatusName(entity.getStatus()))")
    UserVO toVO(User entity);

    /**
     * Entity List -> VO List
     */
    List<UserVO> toVOList(List<User> entities);

    /**
     * DTO -> Entity
     */
    User toEntity(CreateUserDTO dto);

    /**
     * 更新 Entity
     */
    void updateEntity(UpdateUserDTO dto, @MappingTarget User entity);

    /**
     * 获取状态名称
     */
    default String getStatusName(Integer status) {
        return UserStatus.getNameByValue(status);
    }
}
```

---

## 4. RESTful API 规范

### 4.1 URL 设计规范

```
┌─────────────────────────────────────────────────────────────────────┐
│ RESTful URL 设计规范                                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 基本规则:                                                            │
│ • 使用名词复数表示资源                                               │
│ • 使用小写字母和连字符                                               │
│ • 使用 HTTP 方法表示操作                                             │
│ • 版本号放在 URL 中                                                  │
│                                                                      │
│ HTTP 方法:                                                           │
│ • GET    - 查询资源                                                 │
│ • POST   - 创建资源                                                 │
│ • PUT    - 全量更新资源                                             │
│ • PATCH  - 部分更新资源                                             │
│ • DELETE - 删除资源                                                 │
│                                                                      │
│ URL 示例:                                                            │
│ GET    /api/v1/users              # 查询用户列表                    │
│ GET    /api/v1/users/{id}         # 查询单个用户                    │
│ POST   /api/v1/users              # 创建用户                        │
│ PUT    /api/v1/users/{id}         # 更新用户                        │
│ DELETE /api/v1/users/{id}         # 删除用户                        │
│ DELETE /api/v1/users/batch        # 批量删除                        │
│                                                                      │
│ 子资源:                                                              │
│ GET    /api/v1/users/{id}/roles   # 查询用户的角色                  │
│ POST   /api/v1/users/{id}/roles   # 给用户分配角色                  │
│                                                                      │
│ 查询参数:                                                            │
│ GET    /api/v1/users?status=1&page=1&size=10                        │
│ GET    /api/v1/users?sort=createTime,desc                           │
│                                                                      │
│ 操作类接口（非 CRUD）:                                               │
│ POST   /api/v1/users/{id}/enable   # 启用用户                       │
│ POST   /api/v1/users/{id}/disable  # 禁用用户                       │
│ POST   /api/v1/users/{id}/reset-password  # 重置密码                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 统一响应格式

```java
/**
 * 统一响应结果
 */
@Data
@Schema(description = "统一响应结果")
public class Result<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "状态码")
    private Integer code;

    @Schema(description = "消息")
    private String message;

    @Schema(description = "数据")
    private T data;

    @Schema(description = "时间戳")
    private Long timestamp;

    @Schema(description = "请求ID")
    private String requestId;

    private Result() {
        this.timestamp = System.currentTimeMillis();
        this.requestId = MDC.get("traceId");
    }

    public static <T> Result<T> success() {
        return success(null);
    }

    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(ResultCode.SUCCESS.getCode());
        result.setMessage(ResultCode.SUCCESS.getMessage());
        result.setData(data);
        return result;
    }

    public static <T> Result<T> success(String message, T data) {
        Result<T> result = new Result<>();
        result.setCode(ResultCode.SUCCESS.getCode());
        result.setMessage(message);
        result.setData(data);
        return result;
    }

    public static <T> Result<T> fail(String message) {
        return fail(ResultCode.FAIL.getCode(), message);
    }

    public static <T> Result<T> fail(Integer code, String message) {
        Result<T> result = new Result<>();
        result.setCode(code);
        result.setMessage(message);
        return result;
    }

    public static <T> Result<T> fail(ResultCode resultCode) {
        Result<T> result = new Result<>();
        result.setCode(resultCode.getCode());
        result.setMessage(resultCode.getMessage());
        return result;
    }

    public static <T> Result<T> fail(ErrorCode errorCode) {
        Result<T> result = new Result<>();
        result.setCode(errorCode.getCode());
        result.setMessage(errorCode.getMessage());
        return result;
    }
}

/**
 * 响应状态码
 */
@Getter
@AllArgsConstructor
public enum ResultCode {

    SUCCESS(200, "操作成功"),
    FAIL(500, "操作失败"),
    
    // 客户端错误 4xx
    BAD_REQUEST(400, "请求参数错误"),
    UNAUTHORIZED(401, "未授权"),
    FORBIDDEN(403, "禁止访问"),
    NOT_FOUND(404, "资源不存在"),
    METHOD_NOT_ALLOWED(405, "请求方法不允许"),
    
    // 服务端错误 5xx
    INTERNAL_ERROR(500, "服务器内部错误"),
    SERVICE_UNAVAILABLE(503, "服务不可用");

    private final Integer code;
    private final String message;
}

/**
 * 分页结果
 */
@Data
@Schema(description = "分页结果")
public class PageResult<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Schema(description = "数据列表")
    private List<T> list;

    @Schema(description = "总条数")
    private Long total;

    @Schema(description = "当前页码")
    private Integer pageNum;

    @Schema(description = "每页条数")
    private Integer pageSize;

    @Schema(description = "总页数")
    private Integer pages;

    public static <T> PageResult<T> of(List<T> list, Long total) {
        PageResult<T> result = new PageResult<>();
        result.setList(list);
        result.setTotal(total);
        return result;
    }

    public static <T> PageResult<T> of(List<T> list, Long total, Integer pageNum, Integer pageSize) {
        PageResult<T> result = new PageResult<>();
        result.setList(list);
        result.setTotal(total);
        result.setPageNum(pageNum);
        result.setPageSize(pageSize);
        result.setPages((int) Math.ceil((double) total / pageSize));
        return result;
    }

    public static <T> PageResult<T> of(Page<T> page) {
        PageResult<T> result = new PageResult<>();
        result.setList(page.getRecords());
        result.setTotal(page.getTotal());
        result.setPageNum((int) page.getCurrent());
        result.setPageSize((int) page.getSize());
        result.setPages((int) page.getPages());
        return result;
    }
}
```

### 4.3 响应示例

```json
// 成功响应 - 无数据
{
    "code": 200,
    "message": "操作成功",
    "data": null,
    "timestamp": 1704067200000,
    "requestId": "a1b2c3d4"
}

// 成功响应 - 单个对象
{
    "code": 200,
    "message": "操作成功",
    "data": {
        "id": 1,
        "username": "admin",
        "nickname": "管理员",
        "email": "admin@example.com"
    },
    "timestamp": 1704067200000,
    "requestId": "a1b2c3d4"
}

// 成功响应 - 分页数据
{
    "code": 200,
    "message": "操作成功",
    "data": {
        "list": [
            {"id": 1, "username": "admin"},
            {"id": 2, "username": "user"}
        ],
        "total": 100,
        "pageNum": 1,
        "pageSize": 10,
        "pages": 10
    },
    "timestamp": 1704067200000,
    "requestId": "a1b2c3d4"
}

// 失败响应
{
    "code": 400,
    "message": "用户名已存在",
    "data": null,
    "timestamp": 1704067200000,
    "requestId": "a1b2c3d4"
}

// 参数校验失败
{
    "code": 400,
    "message": "参数校验失败",
    "data": {
        "username": "用户名不能为空",
        "password": "密码长度必须在6-20之间"
    },
    "timestamp": 1704067200000,
    "requestId": "a1b2c3d4"
}
```

---

## 5. 数据访问层规范

### 5.1 MyBatis-Plus 配置

```java
/**
 * MyBatis-Plus 配置
 */
@Configuration
@MapperScan("com.example.dao.mapper")
public class MyBatisPlusConfig {

    /**
     * 分页插件
     */
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        
        // 分页插件
        PaginationInnerInterceptor paginationInterceptor = new PaginationInnerInterceptor(DbType.MYSQL);
        paginationInterceptor.setMaxLimit(500L);  // 单页最大500条
        interceptor.addInnerInterceptor(paginationInterceptor);
        
        // 乐观锁插件
        interceptor.addInnerInterceptor(new OptimisticLockerInnerInterceptor());
        
        // 防止全表更新删除插件
        interceptor.addInnerInterceptor(new BlockAttackInnerInterceptor());
        
        return interceptor;
    }

    /**
     * 自动填充处理器
     */
    @Bean
    public MetaObjectHandler metaObjectHandler() {
        return new MyMetaObjectHandler();
    }
}

/**
 * 自动填充处理器
 */
@Component
public class MyMetaObjectHandler implements MetaObjectHandler {

    @Override
    public void insertFill(MetaObject metaObject) {
        LocalDateTime now = LocalDateTime.now();
        Long userId = getCurrentUserId();
        
        this.strictInsertFill(metaObject, "createTime", LocalDateTime.class, now);
        this.strictInsertFill(metaObject, "updateTime", LocalDateTime.class, now);
        this.strictInsertFill(metaObject, "createBy", Long.class, userId);
        this.strictInsertFill(metaObject, "updateBy", Long.class, userId);
        this.strictInsertFill(metaObject, "isDeleted", Integer.class, 0);
    }

    @Override
    public void updateFill(MetaObject metaObject) {
        this.strictUpdateFill(metaObject, "updateTime", LocalDateTime.class, LocalDateTime.now());
        this.strictUpdateFill(metaObject, "updateBy", Long.class, getCurrentUserId());
    }

    private Long getCurrentUserId() {
        try {
            return SecurityUtils.getCurrentUserId();
        } catch (Exception e) {
            return 0L;
        }
    }
}
```

### 5.2 事务管理

```java
/**
 * 事务使用规范
 */
@Service
@RequiredArgsConstructor
public class OrderServiceImpl implements OrderService {

    private final OrderMapper orderMapper;
    private final OrderItemMapper orderItemMapper;
    private final InventoryService inventoryService;

    /**
     * 创建订单 - 标准事务
     * 
     * @Transactional 注意事项：
     * 1. 只能用于 public 方法
     * 2. 同类中方法调用不会触发事务（需要通过代理调用）
     * 3. 默认只对 RuntimeException 回滚
     * 4. rollbackFor 建议设置为 Exception.class
     */
    @Override
    @Transactional(rollbackFor = Exception.class)
    public Long createOrder(CreateOrderDTO dto) {
        // 1. 创建订单
        Order order = new Order();
        order.setOrderNo(generateOrderNo());
        order.setUserId(dto.getUserId());
        order.setStatus(OrderStatus.PENDING.getValue());
        orderMapper.insert(order);

        // 2. 创建订单项
        List<OrderItem> items = dto.getItems().stream()
                .map(item -> {
                    OrderItem orderItem = new OrderItem();
                    orderItem.setOrderId(order.getId());
                    orderItem.setProductId(item.getProductId());
                    orderItem.setQuantity(item.getQuantity());
                    return orderItem;
                })
                .toList();
        orderItemMapper.insertBatch(items);

        // 3. 扣减库存（如果失败会回滚整个事务）
        inventoryService.deductStock(dto.getItems());

        return order.getId();
    }

    /**
     * 只读事务 - 用于查询
     * 可以提高性能，避免脏读
     */
    @Override
    @Transactional(readOnly = true)
    public OrderVO getOrderDetail(Long orderId) {
        Order order = orderMapper.selectById(orderId);
        List<OrderItem> items = orderItemMapper.selectByOrderId(orderId);
        // ... 组装返回
        return null;
    }

    /**
     * 事务传播行为示例
     */
    @Override
    @Transactional(rollbackFor = Exception.class)
    public void processOrder(Long orderId) {
        // 更新订单状态
        updateOrderStatus(orderId, OrderStatus.PROCESSING);
        
        // 发送通知（新事务，失败不影响主事务）
        notificationService.sendNotification(orderId);
        
        // 记录日志（新事务，失败不影响主事务）
        logService.recordLog(orderId, "订单处理中");
    }
}

/**
 * 通知服务 - 使用 REQUIRES_NEW 传播行为
 */
@Service
public class NotificationServiceImpl implements NotificationService {

    /**
     * REQUIRES_NEW: 开启新事务，挂起当前事务
     * 即使这个方法失败，也不会影响调用方的事务
     */
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
    public void sendNotification(Long orderId) {
        // 发送通知逻辑
    }
}

/**
 * 日志服务 - 使用 NOT_SUPPORTED 传播行为
 */
@Service
public class LogServiceImpl implements LogService {

    /**
     * NOT_SUPPORTED: 以非事务方式执行
     * 日志记录不需要事务
     */
    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void recordLog(Long orderId, String message) {
        // 记录日志
    }
}
```

### 5.3 数据库连接池配置

```yaml
# application.yml
spring:
  datasource:
    type: com.alibaba.druid.pool.DruidDataSource
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/mydb?useUnicode=true&characterEncoding=utf8&useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true
    username: root
    password: ${DB_PASSWORD:root}
    
    druid:
      # 初始化连接数
      initial-size: 5
      # 最小空闲连接数
      min-idle: 5
      # 最大活跃连接数
      max-active: 20
      # 获取连接等待超时时间
      max-wait: 60000
      # 检测间隔时间
      time-between-eviction-runs-millis: 60000
      # 连接最小生存时间
      min-evictable-idle-time-millis: 300000
      # 验证查询
      validation-query: SELECT 1
      # 空闲时检测
      test-while-idle: true
      # 获取时检测
      test-on-borrow: false
      # 归还时检测
      test-on-return: false
      # 开启 PSCache
      pool-prepared-statements: true
      max-pool-prepared-statement-per-connection-size: 20
      # 监控统计
      filters: stat,wall,slf4j
      # 合并多个数据源的监控数据
      use-global-data-source-stat: true
      # 慢 SQL 记录
      connection-properties: druid.stat.mergeSql=true;druid.stat.slowSqlMillis=5000
      
      # 监控页面配置
      stat-view-servlet:
        enabled: true
        url-pattern: /druid/*
        login-username: admin
        login-password: admin123
        allow: 127.0.0.1
        
      # Web 监控配置
      web-stat-filter:
        enabled: true
        url-pattern: /*
        exclusions: "*.js,*.gif,*.jpg,*.png,*.css,*.ico,/druid/*"
```

---

## 6. 异常处理规范

### 6.1 异常体系设计

```java
/**
 * 业务异常基类
 */
@Getter
public class BusinessException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Integer code;
    private final String message;

    public BusinessException(String message) {
        super(message);
        this.code = ResultCode.FAIL.getCode();
        this.message = message;
    }

    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
        this.message = message;
    }

    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.code = errorCode.getCode();
        this.message = message;
    }
}

/**
 * 错误码枚举
 */
@Getter
@AllArgsConstructor
public enum ErrorCode {

    // 通用错误 1000-1999
    SYSTEM_ERROR(1000, "系统错误"),
    PARAM_ERROR(1001, "参数错误"),
    DATA_NOT_FOUND(1002, "数据不存在"),
    DATA_ALREADY_EXISTS(1003, "数据已存在"),
    OPERATION_FAILED(1004, "操作失败"),

    // 用户相关 2000-2999
    USER_NOT_FOUND(2000, "用户不存在"),
    USERNAME_EXISTS(2001, "用户名已存在"),
    PASSWORD_ERROR(2002, "密码错误"),
    USER_DISABLED(2003, "用户已禁用"),
    USER_LOCKED(2004, "用户已锁定"),

    // 认证授权 3000-3999
    UNAUTHORIZED(3000, "未登录或登录已过期"),
    TOKEN_INVALID(3001, "Token无效"),
    TOKEN_EXPIRED(3002, "Token已过期"),
    ACCESS_DENIED(3003, "没有访问权限"),

    // 订单相关 4000-4999
    ORDER_NOT_FOUND(4000, "订单不存在"),
    ORDER_STATUS_ERROR(4001, "订单状态错误"),
    STOCK_NOT_ENOUGH(4002, "库存不足");

    private final Integer code;
    private final String message;
}
```

### 6.2 全局异常处理

```java
/**
 * 全局异常处理器
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * 业务异常
     */
    @ExceptionHandler(BusinessException.class)
    public Result<Void> handleBusinessException(BusinessException e) {
        log.warn("业务异常: code={}, message={}", e.getCode(), e.getMessage());
        return Result.fail(e.getCode(), e.getMessage());
    }

    /**
     * 参数校验异常 - @Valid 校验失败
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<Map<String, String>> handleValidException(MethodArgumentNotValidException e) {
        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getFieldErrors().forEach(error -> 
            errors.put(error.getField(), error.getDefaultMessage())
        );
        log.warn("参数校验失败: {}", errors);
        return Result.fail(ResultCode.BAD_REQUEST.getCode(), "参数校验失败");
    }

    /**
     * 参数校验异常 - @Validated 校验失败
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public Result<Void> handleConstraintViolationException(ConstraintViolationException e) {
        String message = e.getConstraintViolations().stream()
                .map(ConstraintViolation::getMessage)
                .collect(Collectors.joining(", "));
        log.warn("参数校验失败: {}", message);
        return Result.fail(ResultCode.BAD_REQUEST.getCode(), message);
    }

    /**
     * 参数绑定异常
     */
    @ExceptionHandler(BindException.class)
    public Result<Void> handleBindException(BindException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining(", "));
        log.warn("参数绑定失败: {}", message);
        return Result.fail(ResultCode.BAD_REQUEST.getCode(), message);
    }

    /**
     * 请求方法不支持
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public Result<Void> handleMethodNotSupportedException(HttpRequestMethodNotSupportedException e) {
        log.warn("请求方法不支持: {}", e.getMethod());
        return Result.fail(ResultCode.METHOD_NOT_ALLOWED);
    }

    /**
     * 请求参数类型不匹配
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public Result<Void> handleTypeMismatchException(MethodArgumentTypeMismatchException e) {
        log.warn("参数类型不匹配: {} = {}", e.getName(), e.getValue());
        return Result.fail(ResultCode.BAD_REQUEST.getCode(), "参数类型不匹配");
    }

    /**
     * 缺少必要参数
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public Result<Void> handleMissingParameterException(MissingServletRequestParameterException e) {
        log.warn("缺少必要参数: {}", e.getParameterName());
        return Result.fail(ResultCode.BAD_REQUEST.getCode(), "缺少必要参数: " + e.getParameterName());
    }

    /**
     * 认证异常
     */
    @ExceptionHandler(AuthenticationException.class)
    public Result<Void> handleAuthenticationException(AuthenticationException e) {
        log.warn("认证失败: {}", e.getMessage());
        return Result.fail(ErrorCode.UNAUTHORIZED);
    }

    /**
     * 授权异常
     */
    @ExceptionHandler(AccessDeniedException.class)
    public Result<Void> handleAccessDeniedException(AccessDeniedException e) {
        log.warn("访问被拒绝: {}", e.getMessage());
        return Result.fail(ErrorCode.ACCESS_DENIED);
    }

    /**
     * 数据库异常
     */
    @ExceptionHandler(DataAccessException.class)
    public Result<Void> handleDataAccessException(DataAccessException e) {
        log.error("数据库异常", e);
        return Result.fail(ResultCode.INTERNAL_ERROR.getCode(), "数据库操作失败");
    }

    /**
     * 其他未知异常
     */
    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("系统异常", e);
        return Result.fail(ResultCode.INTERNAL_ERROR.getCode(), "系统繁忙，请稍后重试");
    }
}
```

---

## 7. 日志规范

### 7.1 日志配置

```xml
<!-- logback-spring.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration scan="true" scanPeriod="30 seconds">

    <!-- 定义变量 -->
    <property name="APP_NAME" value="my-project"/>
    <property name="LOG_PATH" value="./logs"/>
    <property name="LOG_PATTERN" value="%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] [%X{traceId}] %-5level %logger{50} - %msg%n"/>

    <!-- 控制台输出 -->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>${LOG_PATTERN}</pattern>
            <charset>UTF-8</charset>
        </encoder>
    </appender>

    <!-- INFO 日志文件 -->
    <appender name="INFO_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${LOG_PATH}/${APP_NAME}-info.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <fileNamePattern>${LOG_PATH}/history/${APP_NAME}-info.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
            <maxFileSize>100MB</maxFileSize>
            <maxHistory>30</maxHistory>
            <totalSizeCap>10GB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <pattern>${LOG_PATTERN}</pattern>
            <charset>UTF-8</charset>
        </encoder>
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>INFO</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- ERROR 日志文件 -->
    <appender name="ERROR_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${LOG_PATH}/${APP_NAME}-error.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <fileNamePattern>${LOG_PATH}/history/${APP_NAME}-error.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
            <maxFileSize>100MB</maxFileSize>
            <maxHistory>30</maxHistory>
            <totalSizeCap>5GB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <pattern>${LOG_PATTERN}</pattern>
            <charset>UTF-8</charset>
        </encoder>
        <filter class="ch.qos.logback.classic.filter.ThresholdFilter">
            <level>ERROR</level>
        </filter>
    </appender>

    <!-- 异步日志 -->
    <appender name="ASYNC_INFO" class="ch.qos.logback.classic.AsyncAppender">
        <discardingThreshold>0</discardingThreshold>
        <queueSize>512</queueSize>
        <appender-ref ref="INFO_FILE"/>
    </appender>

    <!-- 日志级别配置 -->
    <logger name="com.example" level="DEBUG"/>
    <logger name="org.springframework" level="INFO"/>
    <logger name="org.mybatis" level="INFO"/>
    <logger name="com.alibaba.druid" level="INFO"/>

    <!-- 根日志配置 -->
    <root level="INFO">
        <appender-ref ref="CONSOLE"/>
        <appender-ref ref="ASYNC_INFO"/>
        <appender-ref ref="ERROR_FILE"/>
    </root>

</configuration>
```

### 7.2 日志使用规范

```java
/**
 * 日志使用规范示例
 */
@Service
@Slf4j  // Lombok 注解，自动生成 log 对象
public class UserServiceImpl implements UserService {

    // ✅ 正确的日志使用方式

    @Override
    public UserVO getById(Long id) {
        // 1. 使用占位符，避免字符串拼接
        log.debug("查询用户详情, userId={}", id);
        
        User user = userMapper.selectById(id);
        if (user == null) {
            // 2. 警告级别用于业务异常
            log.warn("用户不存在, userId={}", id);
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        
        return userConvert.toVO(user);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public Long create(CreateUserDTO dto) {
        // 3. 记录关键业务操作
        log.info("创建用户开始, username={}", dto.getUsername());
        
        try {
            User user = userConvert.toEntity(dto);
            userMapper.insert(user);
            
            // 4. 记录操作结果
            log.info("创建用户成功, userId={}, username={}", user.getId(), user.getUsername());
            return user.getId();
            
        } catch (DuplicateKeyException e) {
            // 5. 异常日志包含堆栈信息
            log.error("创建用户失败，用户名重复, username={}", dto.getUsername(), e);
            throw new BusinessException(ErrorCode.USERNAME_EXISTS);
        }
    }

    @Override
    public void processData(List<DataDTO> dataList) {
        // 6. 批量操作记录数量
        log.info("开始处理数据, count={}", dataList.size());
        
        int successCount = 0;
        int failCount = 0;
        
        for (DataDTO data : dataList) {
            try {
                // 处理逻辑
                successCount++;
            } catch (Exception e) {
                failCount++;
                // 7. 循环中的错误日志要控制频率
                log.error("处理数据失败, dataId={}", data.getId(), e);
            }
        }
        
        // 8. 记录处理结果统计
        log.info("数据处理完成, total={}, success={}, fail={}", 
                dataList.size(), successCount, failCount);
    }

    // ❌ 错误的日志使用方式

    public void badExample(Long id) {
        // 1. 不要使用字符串拼接
        log.info("查询用户: " + id);  // ❌
        log.info("查询用户: {}", id);  // ✅

        // 2. 不要在循环中打印大量日志
        for (int i = 0; i < 10000; i++) {
            log.debug("处理第{}条数据", i);  // ❌ 会产生大量日志
        }

        // 3. 不要打印敏感信息
        log.info("用户登录, password={}", password);  // ❌
        log.info("用户登录, username={}", username);  // ✅

        // 4. 不要使用 System.out.println
        System.out.println("调试信息");  // ❌
        log.debug("调试信息");  // ✅

        // 5. 不要忽略异常堆栈
        try {
            // ...
        } catch (Exception e) {
            log.error("发生错误: " + e.getMessage());  // ❌ 丢失堆栈
            log.error("发生错误", e);  // ✅ 保留堆栈
        }

        // 6. 不要在 debug 级别打印大对象
        log.debug("用户信息: {}", user);  // ❌ 可能很大
        log.debug("用户信息: userId={}, username={}", user.getId(), user.getUsername());  // ✅
    }
}
```

### 7.3 链路追踪

```java
/**
 * 链路追踪过滤器
 * 为每个请求生成唯一的 traceId
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceIdFilter implements Filter {

    private static final String TRACE_ID = "traceId";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            // 从请求头获取 traceId，没有则生成新的
            String traceId = ((HttpServletRequest) request).getHeader(TRACE_ID);
            if (StrUtil.isBlank(traceId)) {
                traceId = IdUtil.fastSimpleUUID();
            }
            
            // 放入 MDC
            MDC.put(TRACE_ID, traceId);
            
            // 设置响应头
            ((HttpServletResponse) response).setHeader(TRACE_ID, traceId);
            
            chain.doFilter(request, response);
        } finally {
            // 清理 MDC
            MDC.remove(TRACE_ID);
        }
    }
}

/**
 * 异步任务装饰器
 * 传递 MDC 上下文到异步线程
 */
@Configuration
public class AsyncConfig implements AsyncConfigurer {

    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("async-");
        executor.setTaskDecorator(new MdcTaskDecorator());
        executor.initialize();
        return executor;
    }
}

/**
 * MDC 任务装饰器
 */
public class MdcTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        Map<String, String> contextMap = MDC.getCopyOfContextMap();
        return () -> {
            try {
                if (contextMap != null) {
                    MDC.setContextMap(contextMap);
                }
                runnable.run();
            } finally {
                MDC.clear();
            }
        };
    }
}
```

---

## 8. 配置管理规范

### 8.1 配置文件组织

```yaml
# application.yml - 公共配置
spring:
  application:
    name: my-project
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}
  
  # Jackson 配置
  jackson:
    date-format: yyyy-MM-dd HH:mm:ss
    time-zone: Asia/Shanghai
    default-property-inclusion: non_null
    serialization:
      write-dates-as-timestamps: false
  
  # 文件上传配置
  servlet:
    multipart:
      max-file-size: 10MB
      max-request-size: 100MB

# 服务器配置
server:
  port: 8080
  servlet:
    context-path: /api
  tomcat:
    uri-encoding: UTF-8
    threads:
      max: 200
      min-spare: 10

# MyBatis-Plus 配置
mybatis-plus:
  mapper-locations: classpath*:mapper/**/*.xml
  type-aliases-package: com.example.domain.entity
  configuration:
    map-underscore-to-camel-case: true
    cache-enabled: false
    log-impl: org.apache.ibatis.logging.slf4j.Slf4jImpl
  global-config:
    db-config:
      id-type: assign_id
      logic-delete-field: isDeleted
      logic-delete-value: 1
      logic-not-delete-value: 0

# 日志配置
logging:
  config: classpath:logback-spring.xml
```

```yaml
# application-dev.yml - 开发环境配置
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mydb_dev?useUnicode=true&characterEncoding=utf8&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: root
  
  data:
    redis:
      host: localhost
      port: 6379
      password: 
      database: 0

# 开发环境开启 SQL 日志
logging:
  level:
    com.example.dao: debug

# Swagger 配置
springdoc:
  api-docs:
    enabled: true
  swagger-ui:
    enabled: true
```

```yaml
# application-prod.yml - 生产环境配置
spring:
  datasource:
    url: jdbc:mysql://${DB_HOST:localhost}:${DB_PORT:3306}/${DB_NAME:mydb}?useUnicode=true&characterEncoding=utf8&useSSL=true&serverTimezone=Asia/Shanghai
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
  
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD}
      database: 0

# 生产环境关闭 Swagger
springdoc:
  api-docs:
    enabled: false
  swagger-ui:
    enabled: false

# 生产环境日志级别
logging:
  level:
    root: info
    com.example: info
```

### 8.2 自定义配置类

```java
/**
 * 应用配置属性
 */
@Data
@Component
@ConfigurationProperties(prefix = "app")
@Validated
public class AppProperties {

    /**
     * JWT 配置
     */
    @NestedConfigurationProperty
    private Jwt jwt = new Jwt();

    /**
     * 文件上传配置
     */
    @NestedConfigurationProperty
    private Upload upload = new Upload();

    /**
     * 线程池配置
     */
    @NestedConfigurationProperty
    private ThreadPool threadPool = new ThreadPool();

    @Data
    public static class Jwt {
        /**
         * 密钥
         */
        @NotBlank
        private String secret;

        /**
         * 过期时间（秒）
         */
        @Min(60)
        private Long expiration = 7200L;

        /**
         * 刷新时间（秒）
         */
        private Long refreshExpiration = 604800L;

        /**
         * Token 前缀
         */
        private String tokenPrefix = "Bearer ";

        /**
         * Header 名称
         */
        private String headerName = "Authorization";
    }

    @Data
    public static class Upload {
        /**
         * 上传路径
         */
        @NotBlank
        private String path = "/data/upload";

        /**
         * 允许的文件类型
         */
        private List<String> allowedTypes = List.of("jpg", "jpeg", "png", "gif", "pdf", "doc", "docx");

        /**
         * 最大文件大小（MB）
         */
        private Integer maxSize = 10;
    }

    @Data
    public static class ThreadPool {
        /**
         * 核心线程数
         */
        private Integer coreSize = 10;

        /**
         * 最大线程数
         */
        private Integer maxSize = 50;

        /**
         * 队列容量
         */
        private Integer queueCapacity = 100;

        /**
         * 线程名前缀
         */
        private String namePrefix = "async-";
    }
}
```

```yaml
# application.yml 中的自定义配置
app:
  jwt:
    secret: ${JWT_SECRET:your-secret-key-at-least-256-bits-long}
    expiration: 7200
    refresh-expiration: 604800
  upload:
    path: /data/upload
    allowed-types:
      - jpg
      - jpeg
      - png
      - gif
      - pdf
    max-size: 10
  thread-pool:
    core-size: 10
    max-size: 50
    queue-capacity: 100
```

---

## 9. 安全规范

### 9.1 Spring Security 配置

```java
/**
 * Spring Security 配置
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 禁用 CSRF（前后端分离不需要）
            .csrf(AbstractHttpConfigurer::disable)
            
            // 禁用 Session（使用 JWT）
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // 配置请求授权
            .authorizeHttpRequests(auth -> auth
                // 公开接口
                .requestMatchers("/api/v1/auth/**").permitAll()
                .requestMatchers("/api/v1/public/**").permitAll()
                // Swagger
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                // 静态资源
                .requestMatchers("/static/**", "/favicon.ico").permitAll()
                // 健康检查
                .requestMatchers("/actuator/health").permitAll()
                // 其他请求需要认证
                .anyRequest().authenticated()
            )
            
            // 异常处理
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            )
            
            // 添加 JWT 过滤器
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

### 9.2 JWT 认证

```java
/**
 * JWT 工具类
 */
@Component
@RequiredArgsConstructor
public class JwtUtils {

    private final AppProperties appProperties;
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(
            appProperties.getJwt().getSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * 生成 Token
     */
    public String generateToken(Long userId, String username, List<String> roles) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + appProperties.getJwt().getExpiration() * 1000);

        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("username", username)
                .claim("roles", roles)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    /**
     * 解析 Token
     */
    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * 验证 Token
     */
    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (ExpiredJwtException e) {
            throw new BusinessException(ErrorCode.TOKEN_EXPIRED);
        } catch (JwtException e) {
            throw new BusinessException(ErrorCode.TOKEN_INVALID);
        }
    }

    /**
     * 从 Token 获取用户ID
     */
    public Long getUserId(String token) {
        return Long.parseLong(parseToken(token).getSubject());
    }

    /**
     * 从 Token 获取用户名
     */
    public String getUsername(String token) {
        return parseToken(token).get("username", String.class);
    }

    /**
     * 从 Token 获取角色列表
     */
    @SuppressWarnings("unchecked")
    public List<String> getRoles(String token) {
        return parseToken(token).get("roles", List.class);
    }
}

/**
 * JWT 认证过滤器
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final AppProperties appProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String token = extractToken(request);
        
        if (StrUtil.isNotBlank(token)) {
            try {
                if (jwtUtils.validateToken(token)) {
                    Long userId = jwtUtils.getUserId(token);
                    String username = jwtUtils.getUsername(token);
                    List<String> roles = jwtUtils.getRoles(token);

                    // 创建认证对象
                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .toList();

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(userId, null, authorities);
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // 设置到 SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    
                    // 设置到 MDC（用于日志）
                    MDC.put("userId", String.valueOf(userId));
                    MDC.put("username", username);
                }
            } catch (BusinessException e) {
                log.warn("Token 验证失败: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(appProperties.getJwt().getHeaderName());
        String prefix = appProperties.getJwt().getTokenPrefix();
        
        if (StrUtil.isNotBlank(header) && header.startsWith(prefix)) {
            return header.substring(prefix.length());
        }
        return null;
    }
}
```

### 9.3 权限控制

```java
/**
 * 权限控制示例
 */
@RestController
@RequestMapping("/api/v1/admin")
@Tag(name = "管理员接口")
public class AdminController {

    /**
     * 需要 ADMIN 角色
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public Result<List<UserVO>> listUsers() {
        // ...
    }

    /**
     * 需要特定权限
     */
    @PreAuthorize("hasAuthority('user:delete')")
    @DeleteMapping("/users/{id}")
    public Result<Void> deleteUser(@PathVariable Long id) {
        // ...
    }

    /**
     * 多个角色满足其一
     */
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @GetMapping("/reports")
    public Result<List<ReportVO>> listReports() {
        // ...
    }

    /**
     * 自定义权限表达式
     */
    @PreAuthorize("@permissionService.hasPermission(#id)")
    @PutMapping("/users/{id}")
    public Result<Void> updateUser(@PathVariable Long id, @RequestBody UpdateUserDTO dto) {
        // ...
    }
}

/**
 * 自定义权限服务
 */
@Service("permissionService")
@RequiredArgsConstructor
public class PermissionService {

    /**
     * 检查是否有权限操作指定用户
     */
    public boolean hasPermission(Long userId) {
        Long currentUserId = SecurityUtils.getCurrentUserId();
        // 管理员可以操作所有用户
        if (SecurityUtils.hasRole("ADMIN")) {
            return true;
        }
        // 普通用户只能操作自己
        return currentUserId.equals(userId);
    }
}

/**
 * 安全工具类
 */
public class SecurityUtils {

    /**
     * 获取当前用户ID
     */
    public static Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new BusinessException(ErrorCode.UNAUTHORIZED);
        }
        return (Long) authentication.getPrincipal();
    }

    /**
     * 判断是否有指定角色
     */
    public static boolean hasRole(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_" + role));
    }
}
```

---

## 10. 缓存规范

### 10.1 Redis 配置

```java
/**
 * Redis 配置
 */
@Configuration
@EnableCaching
public class RedisConfig {

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);

        // Key 序列化
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());

        // Value 序列化（使用 JSON）
        Jackson2JsonRedisSerializer<Object> jsonSerializer = 
            new Jackson2JsonRedisSerializer<>(Object.class);
        
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        objectMapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL
        );
        objectMapper.registerModule(new JavaTimeModule());
        jsonSerializer.setObjectMapper(objectMapper);

        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public CacheManager cacheManager(RedisConnectionFactory factory) {
        RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofHours(1))  // 默认过期时间
                .serializeKeysWith(RedisSerializationContext.SerializationPair
                        .fromSerializer(new StringRedisSerializer()))
                .serializeValuesWith(RedisSerializationContext.SerializationPair
                        .fromSerializer(new GenericJackson2JsonRedisSerializer()))
                .disableCachingNullValues();  // 不缓存空值

        // 不同缓存不同配置
        Map<String, RedisCacheConfiguration> cacheConfigurations = new HashMap<>();
        cacheConfigurations.put("user", config.entryTtl(Duration.ofMinutes(30)));
        cacheConfigurations.put("config", config.entryTtl(Duration.ofHours(24)));

        return RedisCacheManager.builder(factory)
                .cacheDefaults(config)
                .withInitialCacheConfigurations(cacheConfigurations)
                .build();
    }
}
```

### 10.2 缓存使用规范

```java
/**
 * 缓存使用示例
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserMapper userMapper;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final String USER_CACHE_KEY = "user:";
    private static final long USER_CACHE_TTL = 30;  // 分钟

    /**
     * 使用 @Cacheable 注解
     * 先查缓存，没有则执行方法并缓存结果
     */
    @Override
    @Cacheable(value = "user", key = "#id", unless = "#result == null")
    public UserVO getById(Long id) {
        log.debug("从数据库查询用户: {}", id);
        User user = userMapper.selectById(id);
        return userConvert.toVO(user);
    }

    /**
     * 使用 @CachePut 注解
     * 执行方法并更新缓存
     */
    @Override
    @CachePut(value = "user", key = "#result.id")
    @Transactional(rollbackFor = Exception.class)
    public UserVO create(CreateUserDTO dto) {
        User user = userConvert.toEntity(dto);
        userMapper.insert(user);
        return userConvert.toVO(user);
    }

    /**
     * 使用 @CacheEvict 注解
     * 删除缓存
     */
    @Override
    @CacheEvict(value = "user", key = "#id")
    @Transactional(rollbackFor = Exception.class)
    public void delete(Long id) {
        userMapper.deleteById(id);
    }

    /**
     * 手动操作缓存
     */
    public UserVO getByIdManual(Long id) {
        String key = USER_CACHE_KEY + id;
        
        // 1. 先查缓存
        UserVO cached = (UserVO) redisTemplate.opsForValue().get(key);
        if (cached != null) {
            return cached;
        }
        
        // 2. 查数据库
        User user = userMapper.selectById(id);
        if (user == null) {
            return null;
        }
        
        UserVO vo = userConvert.toVO(user);
        
        // 3. 写入缓存
        redisTemplate.opsForValue().set(key, vo, USER_CACHE_TTL, TimeUnit.MINUTES);
        
        return vo;
    }

    /**
     * 缓存穿透防护
     * 使用布隆过滤器或缓存空值
     */
    public UserVO getByIdWithNullCache(Long id) {
        String key = USER_CACHE_KEY + id;
        
        // 1. 查缓存
        Object cached = redisTemplate.opsForValue().get(key);
        if (cached != null) {
            // 空值标记
            if ("NULL".equals(cached)) {
                return null;
            }
            return (UserVO) cached;
        }
        
        // 2. 查数据库
        User user = userMapper.selectById(id);
        
        if (user == null) {
            // 缓存空值，防止穿透（短过期时间）
            redisTemplate.opsForValue().set(key, "NULL", 5, TimeUnit.MINUTES);
            return null;
        }
        
        UserVO vo = userConvert.toVO(user);
        redisTemplate.opsForValue().set(key, vo, USER_CACHE_TTL, TimeUnit.MINUTES);
        
        return vo;
    }

    /**
     * 缓存击穿防护
     * 使用分布式锁
     */
    public UserVO getByIdWithLock(Long id) {
        String key = USER_CACHE_KEY + id;
        String lockKey = "lock:" + key;
        
        // 1. 查缓存
        UserVO cached = (UserVO) redisTemplate.opsForValue().get(key);
        if (cached != null) {
            return cached;
        }
        
        // 2. 获取分布式锁
        Boolean locked = redisTemplate.opsForValue()
                .setIfAbsent(lockKey, "1", 10, TimeUnit.SECONDS);
        
        if (Boolean.TRUE.equals(locked)) {
            try {
                // 双重检查
                cached = (UserVO) redisTemplate.opsForValue().get(key);
                if (cached != null) {
                    return cached;
                }
                
                // 查数据库
                User user = userMapper.selectById(id);
                if (user != null) {
                    UserVO vo = userConvert.toVO(user);
                    redisTemplate.opsForValue().set(key, vo, USER_CACHE_TTL, TimeUnit.MINUTES);
                    return vo;
                }
            } finally {
                redisTemplate.delete(lockKey);
            }
        } else {
            // 等待后重试
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return getByIdWithLock(id);
        }
        
        return null;
    }
}
```

### 10.3 Redis Key 规范

```java
/**
 * Redis Key 常量
 */
public class RedisConstants {

    /**
     * Key 前缀
     */
    public static final String KEY_PREFIX = "myproject:";

    /**
     * 用户相关
     */
    public static final String USER_KEY = KEY_PREFIX + "user:";
    public static final String USER_TOKEN_KEY = KEY_PREFIX + "user:token:";
    public static final String USER_PERMISSION_KEY = KEY_PREFIX + "user:permission:";

    /**
     * 验证码
     */
    public static final String CAPTCHA_KEY = KEY_PREFIX + "captcha:";

    /**
     * 分布式锁
     */
    public static final String LOCK_KEY = KEY_PREFIX + "lock:";

    /**
     * 限流
     */
    public static final String RATE_LIMIT_KEY = KEY_PREFIX + "rate:";

    /**
     * 缓存过期时间（秒）
     */
    public static final long USER_EXPIRE = 1800;        // 30分钟
    public static final long TOKEN_EXPIRE = 7200;       // 2小时
    public static final long CAPTCHA_EXPIRE = 300;      // 5分钟
    public static final long LOCK_EXPIRE = 10;          // 10秒
}
```

---

## 11. 异步与定时任务

### 11.1 异步任务配置

```java
/**
 * 异步任务配置
 */
@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(100);
        executor.setKeepAliveSeconds(60);
        executor.setThreadNamePrefix("async-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setTaskDecorator(new MdcTaskDecorator());
        executor.initialize();
        return executor;
    }

    @Override
    public AsyncUncaughtExceptionHandler getAsyncUncaughtExceptionHandler() {
        return (throwable, method, params) -> {
            log.error("异步任务异常: method={}, params={}", method.getName(), params, throwable);
        };
    }
}

/**
 * 异步任务使用示例
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationService {

    private final EmailService emailService;
    private final SmsService smsService;

    /**
     * 异步发送邮件
     */
    @Async
    public void sendEmailAsync(String to, String subject, String content) {
        log.info("开始发送邮件: to={}", to);
        try {
            emailService.send(to, subject, content);
            log.info("邮件发送成功: to={}", to);
        } catch (Exception e) {
            log.error("邮件发送失败: to={}", to, e);
        }
    }

    /**
     * 异步发送短信
     */
    @Async
    public CompletableFuture<Boolean> sendSmsAsync(String phone, String content) {
        log.info("开始发送短信: phone={}", phone);
        try {
            smsService.send(phone, content);
            log.info("短信发送成功: phone={}", phone);
            return CompletableFuture.completedFuture(true);
        } catch (Exception e) {
            log.error("短信发送失败: phone={}", phone, e);
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * 批量异步通知
     */
    public void notifyUsers(List<Long> userIds, String message) {
        List<CompletableFuture<Boolean>> futures = userIds.stream()
                .map(userId -> sendNotificationAsync(userId, message))
                .toList();

        // 等待所有任务完成
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenRun(() -> log.info("所有通知发送完成"));
    }

    @Async
    public CompletableFuture<Boolean> sendNotificationAsync(Long userId, String message) {
        // 发送通知逻辑
        return CompletableFuture.completedFuture(true);
    }
}
```

### 11.2 定时任务配置

```java
/**
 * 定时任务配置
 */
@Configuration
@EnableScheduling
public class ScheduleConfig implements SchedulingConfigurer {

    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(5);
        scheduler.setThreadNamePrefix("schedule-");
        scheduler.setErrorHandler(throwable -> 
            log.error("定时任务执行异常", throwable));
        scheduler.initialize();
        taskRegistrar.setTaskScheduler(scheduler);
    }
}

/**
 * 定时任务示例
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ScheduledTasks {

    private final OrderService orderService;
    private final ReportService reportService;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * 每天凌晨 2 点执行
     * 清理过期订单
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanExpiredOrders() {
        String lockKey = "lock:schedule:cleanExpiredOrders";
        
        // 分布式锁，防止多实例重复执行
        Boolean locked = redisTemplate.opsForValue()
                .setIfAbsent(lockKey, "1", 30, TimeUnit.MINUTES);
        
        if (Boolean.TRUE.equals(locked)) {
            try {
                log.info("开始清理过期订单");
                int count = orderService.cleanExpiredOrders();
                log.info("清理过期订单完成, count={}", count);
            } finally {
                redisTemplate.delete(lockKey);
            }
        } else {
            log.info("其他实例正在执行清理任务，跳过");
        }
    }

    /**
     * 每小时执行一次
     * 生成统计报表
     */
    @Scheduled(cron = "0 0 * * * ?")
    public void generateHourlyReport() {
        log.info("开始生成小时报表");
        reportService.generateHourlyReport();
        log.info("小时报表生成完成");
    }

    /**
     * 每 5 分钟执行一次
     * 检查系统健康状态
     */
    @Scheduled(fixedRate = 5 * 60 * 1000)
    public void healthCheck() {
        log.debug("执行健康检查");
        // 健康检查逻辑
    }

    /**
     * 上次执行完成后 10 秒再执行
     */
    @Scheduled(fixedDelay = 10000)
    public void processQueue() {
        // 处理队列消息
    }

    /**
     * 应用启动后延迟 30 秒执行，然后每分钟执行一次
     */
    @Scheduled(initialDelay = 30000, fixedRate = 60000)
    public void syncData() {
        log.info("同步数据");
        // 数据同步逻辑
    }
}
```

---

## 12. 测试规范

### 12.1 单元测试

```java
/**
 * Service 层单元测试
 */
@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserMapper userMapper;

    @Mock
    private UserConvert userConvert;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    @Test
    @DisplayName("根据ID查询用户 - 用户存在")
    void getById_WhenUserExists_ShouldReturnUserVO() {
        // Given
        Long userId = 1L;
        User user = new User();
        user.setId(userId);
        user.setUsername("admin");

        UserVO expectedVO = new UserVO();
        expectedVO.setId(userId);
        expectedVO.setUsername("admin");

        when(userMapper.selectById(userId)).thenReturn(user);
        when(userConvert.toVO(user)).thenReturn(expectedVO);

        // When
        UserVO result = userService.getById(userId);

        // Then
        assertNotNull(result);
        assertEquals(userId, result.getId());
        assertEquals("admin", result.getUsername());
        verify(userMapper).selectById(userId);
        verify(userConvert).toVO(user);
    }

    @Test
    @DisplayName("根据ID查询用户 - 用户不存在")
    void getById_WhenUserNotExists_ShouldThrowException() {
        // Given
        Long userId = 999L;
        when(userMapper.selectById(userId)).thenReturn(null);

        // When & Then
        BusinessException exception = assertThrows(
            BusinessException.class,
            () -> userService.getById(userId)
        );
        assertEquals(ErrorCode.USER_NOT_FOUND.getCode(), exception.getCode());
    }

    @Test
    @DisplayName("创建用户 - 成功")
    void create_WhenValidInput_ShouldReturnUserId() {
        // Given
        CreateUserDTO dto = new CreateUserDTO();
        dto.setUsername("newuser");
        dto.setPassword("password123");

        User user = new User();
        user.setId(1L);

        when(userMapper.selectCount(any())).thenReturn(0L);
        when(userConvert.toEntity(dto)).thenReturn(user);
        when(passwordEncoder.encode(dto.getPassword())).thenReturn("encodedPassword");
        when(userMapper.insert(any())).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(1L);
            return 1;
        });

        // When
        Long result = userService.create(dto);

        // Then
        assertNotNull(result);
        assertEquals(1L, result);
        verify(userMapper).insert(any());
    }

    @Test
    @DisplayName("创建用户 - 用户名已存在")
    void create_WhenUsernameExists_ShouldThrowException() {
        // Given
        CreateUserDTO dto = new CreateUserDTO();
        dto.setUsername("existinguser");

        when(userMapper.selectCount(any())).thenReturn(1L);

        // When & Then
        BusinessException exception = assertThrows(
            BusinessException.class,
            () -> userService.create(dto)
        );
        assertEquals(ErrorCode.USERNAME_EXISTS.getCode(), exception.getCode());
    }
}
```

### 12.2 集成测试

```java
/**
 * Controller 层集成测试
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional  // 测试后回滚
class UserControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserMapper userMapper;

    @Test
    @DisplayName("分页查询用户列表")
    void listUsers_ShouldReturnPageResult() throws Exception {
        mockMvc.perform(get("/api/v1/users")
                        .param("pageNum", "1")
                        .param("pageSize", "10")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.list").isArray())
                .andExpect(jsonPath("$.data.total").isNumber());
    }

    @Test
    @DisplayName("创建用户 - 成功")
    @WithMockUser(roles = "ADMIN")
    void createUser_WhenValidInput_ShouldReturnUserId() throws Exception {
        CreateUserDTO dto = new CreateUserDTO();
        dto.setUsername("testuser");
        dto.setPassword("password123");
        dto.setNickname("测试用户");
        dto.setEmail("test@example.com");

        mockMvc.perform(post("/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data").isNumber());
    }

    @Test
    @DisplayName("创建用户 - 参数校验失败")
    @WithMockUser(roles = "ADMIN")
    void createUser_WhenInvalidInput_ShouldReturnBadRequest() throws Exception {
        CreateUserDTO dto = new CreateUserDTO();
        dto.setUsername("ab");  // 太短
        dto.setPassword("123");  // 太短

        mockMvc.perform(post("/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400));
    }

    @Test
    @DisplayName("未授权访问")
    void accessProtectedEndpoint_WithoutAuth_ShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/v1/users"))
                .andExpect(status().isUnauthorized());
    }
}
```

---

## 13. 性能优化

### 13.1 数据库优化

```java
/**
 * 数据库查询优化示例
 */
@Service
@RequiredArgsConstructor
public class OrderServiceImpl implements OrderService {

    private final OrderMapper orderMapper;

    /**
     * ✅ 好的做法：只查询需要的字段
     */
    @Override
    public List<OrderSimpleVO> listSimple(OrderQuery query) {
        return orderMapper.selectSimpleList(query);
    }

    /**
     * ❌ 不好的做法：查询所有字段再转换
     */
    public List<OrderSimpleVO> listSimpleBad(OrderQuery query) {
        List<Order> orders = orderMapper.selectList(null);  // 查询所有字段
        return orders.stream()
                .map(this::convertToSimpleVO)
                .toList();
    }

    /**
     * ✅ 好的做法：批量查询
     */
    @Override
    public List<OrderVO> listByIds(List<Long> ids) {
        if (CollUtil.isEmpty(ids)) {
            return Collections.emptyList();
        }
        // 一次查询所有
        return orderMapper.selectBatchIds(ids).stream()
                .map(orderConvert::toVO)
                .toList();
    }

    /**
     * ❌ 不好的做法：循环查询（N+1 问题）
     */
    public List<OrderVO> listByIdsBad(List<Long> ids) {
        return ids.stream()
                .map(id -> orderMapper.selectById(id))  // 每个ID一次查询
                .map(orderConvert::toVO)
                .toList();
    }

    /**
     * ✅ 好的做法：使用分页
     */
    @Override
    public PageResult<OrderVO> page(OrderQuery query) {
        Page<Order> page = new Page<>(query.getPageNum(), query.getPageSize());
        Page<Order> result = orderMapper.selectPage(page, buildWrapper(query));
        return PageResult.of(result);
    }

    /**
     * ❌ 不好的做法：查询所有再分页
     */
    public PageResult<OrderVO> pageBad(OrderQuery query) {
        List<Order> all = orderMapper.selectList(null);  // 查询所有
        // 内存分页
        int start = (query.getPageNum() - 1) * query.getPageSize();
        List<Order> pageList = all.stream()
                .skip(start)
                .limit(query.getPageSize())
                .toList();
        return PageResult.of(pageList, (long) all.size());
    }
}
```

### 13.2 接口性能优化

```java
/**
 * 接口性能优化示例
 */
@RestController
@RequestMapping("/api/v1/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    /**
     * ✅ 使用缓存
     */
    @GetMapping("/{id}")
    @Cacheable(value = "product", key = "#id")
    public Result<ProductVO> getById(@PathVariable Long id) {
        return Result.success(productService.getById(id));
    }

    /**
     * ✅ 使用压缩
     * 在 application.yml 中配置：
     * server.compression.enabled=true
     * server.compression.mime-types=application/json
     * server.compression.min-response-size=1024
     */
    @GetMapping("/list")
    public Result<List<ProductVO>> list() {
        return Result.success(productService.listAll());
    }

    /**
     * ✅ 异步处理
     */
    @PostMapping("/import")
    public Result<String> importProducts(@RequestBody List<ProductDTO> products) {
        String taskId = productService.importAsync(products);
        return Result.success("导入任务已提交", taskId);
    }

    /**
     * ✅ 限流保护
     */
    @GetMapping("/hot")
    @RateLimiter(key = "product:hot", rate = 100, interval = 1)
    public Result<List<ProductVO>> getHotProducts() {
        return Result.success(productService.getHotProducts());
    }
}

/**
 * 限流注解
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimiter {
    String key();
    int rate() default 100;  // 每秒请求数
    int interval() default 1;  // 时间窗口（秒）
}

/**
 * 限流切面
 */
@Aspect
@Component
@RequiredArgsConstructor
public class RateLimiterAspect {

    private final RedisTemplate<String, Object> redisTemplate;

    @Around("@annotation(rateLimiter)")
    public Object around(ProceedingJoinPoint point, RateLimiter rateLimiter) throws Throwable {
        String key = RedisConstants.RATE_LIMIT_KEY + rateLimiter.key();
        
        // 使用 Redis 实现滑动窗口限流
        long now = System.currentTimeMillis();
        long windowStart = now - rateLimiter.interval() * 1000L;
        
        // 移除窗口外的请求
        redisTemplate.opsForZSet().removeRangeByScore(key, 0, windowStart);
        
        // 统计窗口内的请求数
        Long count = redisTemplate.opsForZSet().zCard(key);
        
        if (count != null && count >= rateLimiter.rate()) {
            throw new BusinessException("请求过于频繁，请稍后重试");
        }
        
        // 添加当前请求
        redisTemplate.opsForZSet().add(key, UUID.randomUUID().toString(), now);
        redisTemplate.expire(key, rateLimiter.interval() + 1, TimeUnit.SECONDS);
        
        return point.proceed();
    }
}
```

---

## 14. 部署与运维

### 14.1 Dockerfile

```dockerfile
# 多阶段构建
FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

# 复制 Maven 配置
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

# 下载依赖（利用缓存）
RUN ./mvnw dependency:go-offline -B

# 复制源码
COPY src src

# 构建
RUN ./mvnw package -DskipTests -B

# 运行阶段
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# 创建非 root 用户
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# 复制构建产物
COPY --from=builder /app/target/*.jar app.jar

# JVM 参数
ENV JAVA_OPTS="-Xms512m -Xmx512m -XX:+UseG1GC -XX:MaxGCPauseMillis=200"

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD wget -q --spider http://localhost:8080/actuator/health || exit 1

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

### 14.2 健康检查与监控

```yaml
# application.yml - Actuator 配置
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
      base-path: /actuator
  endpoint:
    health:
      show-details: when_authorized
      probes:
        enabled: true
  health:
    db:
      enabled: true
    redis:
      enabled: true
    diskspace:
      enabled: true
  metrics:
    tags:
      application: ${spring.application.name}
```

```java
/**
 * 自定义健康检查
 */
@Component
public class CustomHealthIndicator implements HealthIndicator {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public Health health() {
        try {
            // 检查 Redis 连接
            redisTemplate.opsForValue().get("health:check");
            return Health.up()
                    .withDetail("redis", "connected")
                    .build();
        } catch (Exception e) {
            return Health.down()
                    .withDetail("redis", "disconnected")
                    .withException(e)
                    .build();
        }
    }
}
```

---

## 15. 常见错误与踩坑

### 15.1 事务相关

```java
/**
 * 事务常见问题
 */
@Service
public class TransactionPitfalls {

    // ❌ 问题1：同类方法调用，事务不生效
    public void methodA() {
        methodB();  // 事务不生效！因为是 this 调用，不经过代理
    }

    @Transactional
    public void methodB() {
        // 数据库操作
    }

    // ✅ 解决方案1：注入自己
    @Autowired
    private TransactionPitfalls self;

    public void methodAFixed() {
        self.methodB();  // 通过代理调用，事务生效
    }

    // ✅ 解决方案2：使用 AopContext
    public void methodAFixed2() {
        ((TransactionPitfalls) AopContext.currentProxy()).methodB();
    }

    // ❌ 问题2：private 方法，事务不生效
    @Transactional
    private void privateMethod() {  // 事务不生效！
        // 数据库操作
    }

    // ❌ 问题3：异常被捕获，事务不回滚
    @Transactional
    public void methodWithCatch() {
        try {
            // 数据库操作
            throw new RuntimeException("error");
        } catch (Exception e) {
            log.error("error", e);  // 异常被捕获，事务不回滚！
        }
    }

    // ✅ 解决方案：手动回滚
    @Transactional
    public void methodWithCatchFixed() {
        try {
            // 数据库操作
            throw new RuntimeException("error");
        } catch (Exception e) {
            log.error("error", e);
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        }
    }

    // ❌ 问题4：检查异常不回滚
    @Transactional
    public void methodWithCheckedException() throws IOException {
        // 数据库操作
        throw new IOException("error");  // 检查异常，默认不回滚！
    }

    // ✅ 解决方案：指定 rollbackFor
    @Transactional(rollbackFor = Exception.class)
    public void methodWithCheckedExceptionFixed() throws IOException {
        // 数据库操作
        throw new IOException("error");  // 会回滚
    }
}
```

### 15.2 循环依赖

```java
/**
 * 循环依赖问题
 */
// ❌ 问题：A 依赖 B，B 依赖 A
@Service
public class ServiceA {
    @Autowired
    private ServiceB serviceB;  // 循环依赖
}

@Service
public class ServiceB {
    @Autowired
    private ServiceA serviceA;  // 循环依赖
}

// ✅ 解决方案1：使用 @Lazy
@Service
public class ServiceA {
    @Autowired
    @Lazy
    private ServiceB serviceB;
}

// ✅ 解决方案2：使用 setter 注入
@Service
public class ServiceA {
    private ServiceB serviceB;

    @Autowired
    public void setServiceB(ServiceB serviceB) {
        this.serviceB = serviceB;
    }
}

// ✅ 解决方案3：重构代码，提取公共逻辑到第三个类
@Service
public class CommonService {
    // 公共逻辑
}

@Service
@RequiredArgsConstructor
public class ServiceA {
    private final CommonService commonService;
}

@Service
@RequiredArgsConstructor
public class ServiceB {
    private final CommonService commonService;
}
```

### 15.3 空指针问题

```java
/**
 * 空指针常见问题
 */
public class NullPointerPitfalls {

    // ❌ 问题1：直接调用可能为 null 的对象方法
    public String getUserName(User user) {
        return user.getName();  // user 可能为 null
    }

    // ✅ 解决方案：空值检查
    public String getUserNameFixed(User user) {
        return user != null ? user.getName() : "";
    }

    // ✅ 使用 Optional
    public String getUserNameOptional(User user) {
        return Optional.ofNullable(user)
                .map(User::getName)
                .orElse("");
    }

    // ❌ 问题2：集合可能为 null
    public void processUsers(List<User> users) {
        for (User user : users) {  // users 为 null 会 NPE
            // 处理
        }
    }

    // ✅ 解决方案
    public void processUsersFixed(List<User> users) {
        if (CollUtil.isEmpty(users)) {
            return;
        }
        for (User user : users) {
            // 处理
        }
    }

    // ❌ 问题3：自动拆箱 NPE
    public void calculate(Integer count) {
        int total = count + 1;  // count 为 null 会 NPE
    }

    // ✅ 解决方案
    public void calculateFixed(Integer count) {
        int total = (count != null ? count : 0) + 1;
    }

    // ❌ 问题4：Map.get() 返回 null
    public void processMap(Map<String, User> userMap) {
        User user = userMap.get("key");
        String name = user.getName();  // user 可能为 null
    }

    // ✅ 解决方案
    public void processMapFixed(Map<String, User> userMap) {
        User user = userMap.get("key");
        if (user != null) {
            String name = user.getName();
        }
        // 或使用 getOrDefault
        User user2 = userMap.getOrDefault("key", new User());
    }
}
```

### 15.4 并发问题

```java
/**
 * 并发常见问题
 */
@Service
public class ConcurrencyPitfalls {

    // ❌ 问题1：非线程安全的成员变量
    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    public String formatDate(Date date) {
        return sdf.format(date);  // 多线程下会出问题
    }

    // ✅ 解决方案1：使用 ThreadLocal
    private static final ThreadLocal<SimpleDateFormat> dateFormat =
            ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd"));

    public String formatDateFixed(Date date) {
        return dateFormat.get().format(date);
    }

    // ✅ 解决方案2：使用 Java 8 的 DateTimeFormatter（线程安全）
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    public String formatDateFixed2(LocalDate date) {
        return date.format(formatter);
    }

    // ❌ 问题2：HashMap 并发修改
    private Map<String, Object> cache = new HashMap<>();

    public void putCache(String key, Object value) {
        cache.put(key, value);  // 多线程下可能死循环
    }

    // ✅ 解决方案：使用 ConcurrentHashMap
    private Map<String, Object> cacheFixed = new ConcurrentHashMap<>();

    // ❌ 问题3：ArrayList 并发修改
    private List<String> list = new ArrayList<>();

    public void addItem(String item) {
        list.add(item);  // 多线程下可能丢失数据
    }

    // ✅ 解决方案：使用 CopyOnWriteArrayList 或同步
    private List<String> listFixed = new CopyOnWriteArrayList<>();

    // ❌ 问题4：双重检查锁定（DCL）问题
    private volatile Object instance;

    public Object getInstance() {
        if (instance == null) {
            synchronized (this) {
                if (instance == null) {
                    instance = new Object();  // 需要 volatile 防止指令重排
                }
            }
        }
        return instance;
    }

    // ❌ 问题5：i++ 不是原子操作
    private int count = 0;

    public void increment() {
        count++;  // 多线程下结果不正确
    }

    // ✅ 解决方案：使用 AtomicInteger
    private AtomicInteger countFixed = new AtomicInteger(0);

    public void incrementFixed() {
        countFixed.incrementAndGet();
    }
}
```

### 15.5 MyBatis 常见问题

```java
/**
 * MyBatis 常见问题
 */
public class MyBatisPitfalls {

    // ❌ 问题1：#{}和${}混淆
    // #{} - 预编译，防止 SQL 注入
    // ${} - 字符串替换，有 SQL 注入风险

    // ✅ 正确用法
    @Select("SELECT * FROM user WHERE id = #{id}")  // 使用 #{}
    User selectById(Long id);

    // 只有在需要动态表名、列名时才用 ${}
    @Select("SELECT * FROM ${tableName} WHERE id = #{id}")
    User selectByIdDynamic(@Param("tableName") String tableName, @Param("id") Long id);

    // ❌ 问题2：返回类型不匹配
    @Select("SELECT COUNT(*) FROM user")
    int count();  // 如果结果超过 int 范围会溢出

    // ✅ 使用 Long
    @Select("SELECT COUNT(*) FROM user")
    Long countFixed();

    // ❌ 问题3：批量插入数据量过大
    void insertBatch(List<User> users);  // 一次插入太多会超时

    // ✅ 分批插入
    public void insertBatchFixed(List<User> users) {
        List<List<User>> batches = ListUtil.partition(users, 500);
        for (List<User> batch : batches) {
            userMapper.insertBatch(batch);
        }
    }

    // ❌ 问题4：like 查询没有转义
    @Select("SELECT * FROM user WHERE name LIKE '%${name}%'")  // SQL 注入风险
    List<User> searchByName(String name);

    // ✅ 正确用法
    @Select("SELECT * FROM user WHERE name LIKE CONCAT('%', #{name}, '%')")
    List<User> searchByNameFixed(String name);

    // ❌ 问题5：in 查询空集合
    @Select("<script>SELECT * FROM user WHERE id IN " +
            "<foreach collection='ids' item='id' open='(' separator=',' close=')'>" +
            "#{id}</foreach></script>")
    List<User> selectByIds(@Param("ids") List<Long> ids);  // ids 为空会报错

    // ✅ 先判断
    public List<User> selectByIdsFixed(List<Long> ids) {
        if (CollUtil.isEmpty(ids)) {
            return Collections.emptyList();
        }
        return userMapper.selectByIds(ids);
    }
}
```

### 15.6 Spring Boot 3.x 升级注意事项

```java
/**
 * Spring Boot 3.x 升级注意事项
 */
public class SpringBoot3Migration {

    /*
     * 1. Java 版本要求
     * Spring Boot 3.x 最低要求 Java 17
     * 推荐使用 Java 21 LTS
     */

    /*
     * 2. Jakarta EE 命名空间变更
     * javax.* -> jakarta.*
     * 
     * 例如：
     * javax.servlet.* -> jakarta.servlet.*
     * javax.persistence.* -> jakarta.persistence.*
     * javax.validation.* -> jakarta.validation.*
     */

    // ❌ 旧写法
    // import javax.servlet.http.HttpServletRequest;
    // import javax.validation.constraints.NotNull;

    // ✅ 新写法
    // import jakarta.servlet.http.HttpServletRequest;
    // import jakarta.validation.constraints.NotNull;

    /*
     * 3. Spring Security 变更
     * WebSecurityConfigurerAdapter 已废弃
     * 使用 SecurityFilterChain Bean 替代
     */

    // ❌ 旧写法
    // @Configuration
    // public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //     @Override
    //     protected void configure(HttpSecurity http) throws Exception {
    //         http.authorizeRequests()...
    //     }
    // }

    // ✅ 新写法
    // @Configuration
    // public class SecurityConfig {
    //     @Bean
    //     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //         http.authorizeHttpRequests()...
    //         return http.build();
    //     }
    // }

    /*
     * 4. 依赖变更
     * 
     * MyBatis-Plus:
     * mybatis-plus-boot-starter -> mybatis-plus-spring-boot3-starter
     * 
     * Druid:
     * druid-spring-boot-starter -> druid-spring-boot-3-starter
     * 
     * Swagger:
     * springfox -> springdoc-openapi-starter-webmvc-ui
     */

    /*
     * 5. 配置属性变更
     * 
     * spring.redis.* -> spring.data.redis.*
     * management.metrics.export.* -> management.*.metrics.export.*
     */
}
```

---

## 附录

### A. 常用注解速查

```java
// Spring 核心
@Component          // 通用组件
@Service            // 服务层
@Repository         // 数据访问层
@Controller         // 控制器
@RestController     // REST 控制器
@Configuration      // 配置类
@Bean               // 定义 Bean

// 依赖注入
@Autowired          // 自动注入
@Resource           // 按名称注入
@Qualifier          // 指定 Bean 名称
@Value              // 注入配置值
@RequiredArgsConstructor  // Lombok 构造器注入

// Web
@RequestMapping     // 请求映射
@GetMapping         // GET 请求
@PostMapping        // POST 请求
@PutMapping         // PUT 请求
@DeleteMapping      // DELETE 请求
@PathVariable       // 路径变量
@RequestParam       // 请求参数
@RequestBody        // 请求体
@ResponseBody       // 响应体

// 参数校验
@Valid              // 开启校验
@Validated          // 开启校验（支持分组）
@NotNull            // 非空
@NotBlank           // 非空白
@NotEmpty           // 非空集合
@Size               // 大小限制
@Min / @Max         // 数值范围
@Pattern            // 正则匹配
@Email              // 邮箱格式

// 事务
@Transactional      // 事务管理

// 缓存
@Cacheable          // 缓存查询
@CachePut           // 更新缓存
@CacheEvict         // 删除缓存

// 异步
@Async              // 异步执行
@Scheduled          // 定时任务

// MyBatis-Plus
@TableName          // 表名
@TableId            // 主键
@TableField         // 字段
@TableLogic         // 逻辑删除
```

### B. 推荐工具和资源

```
开发工具:
• IntelliJ IDEA Ultimate
• VS Code (轻量级)
• DBeaver (数据库管理)
• Redis Desktop Manager
• Postman / Apifox

代码质量:
• SonarQube
• Alibaba Java Coding Guidelines
• SpotBugs

性能测试:
• JMeter
• Gatling
• Arthas (Java 诊断)

文档:
• Spring Boot 官方文档: https://docs.spring.io/spring-boot/docs/current/reference/html/
• MyBatis-Plus 文档: https://baomidou.com/
• Hutool 文档: https://hutool.cn/docs/
```

---

> 最后更新: 2025年1月
> 
> 规范是团队协作的基础，但不是教条。根据项目实际情况灵活调整，持续改进。
