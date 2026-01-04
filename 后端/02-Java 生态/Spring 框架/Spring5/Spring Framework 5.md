
> 本笔记从零开始，循序渐进地介绍 Spring Framework 5 的核心概念和使用方法。每个知识点都配有详细的文字说明、代码示例和常见错误分析，帮助你真正理解 Spring 的设计思想。

---

## 目录

1. [Spring概述](#1. Spring 概述)
2. [IoC 容器（控制反转）](#2.IoC 容器（控制反转）)
3. [依赖注入（DI））](#3. 依赖注入（DI）)
4. [Bean 的生命周期](#4.Bean 的生命周期)
5. [Bean 的作用域](#5.Bean 的作用域)
6. [AOP（面向切面编程）](#6.AOP（面向切面编程）)
7. [事务管理](#7.事务管理)
8. [Spring JDBC](#8.Spring JDBC)
9. [SpEL（Spring 表达式语言）](#9.SpEL（Spring 表达式语言）)
10. [资源管理](#10.资源管理)
11. [国际化（i18n）](#11.国际化（i18n）)
12. [事件机制](#12.事件机制)
13. [常见错误总结](#13.常见错误总结)
14. [最佳实践](#14.最佳实践)


---

## 1. Spring 概述

### 1.1 什么是 Spring？

Spring 是一个轻量级的 Java 开发框架，它的核心思想是 **IoC（控制反转）** 和 **AOP（面向切面编程）**。

简单来说，Spring 帮你管理对象的创建和依赖关系，让你专注于业务逻辑，而不用操心"谁创建谁"、"谁依赖谁"这些繁琐的问题。

**为什么需要 Spring？**

假设没有 Spring，你的代码可能是这样的：

```java
// 传统方式：手动创建对象，耦合度高
public class UserService {
    // 直接 new 对象，UserService 和 UserDaoImpl 紧密耦合
    private UserDao userDao = new UserDaoImpl();
    
    public void saveUser(User user) {
        userDao.save(user);
    }
}
```

问题在于：如果要换一个 `UserDao` 的实现（比如从 MySQL 换成 MongoDB），你需要修改 `UserService` 的代码。这违反了"开闭原则"。

**使用 Spring 后：**

```java
// Spring 方式：依赖注入，解耦
public class UserService {
    // 不再自己 new，由 Spring 注入
    private UserDao userDao;
    
    // Spring 会自动调用这个方法注入依赖
    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }
    
    public void saveUser(User user) {
        userDao.save(user);
    }
}
```

现在，`UserService` 不关心 `UserDao` 的具体实现是什么，Spring 会帮你"注入"正确的实现。

### 1.2 Spring 的模块结构

Spring Framework 5 由多个模块组成，你可以按需引入：

```
Spring Framework
├── Core Container（核心容器）
│   ├── spring-core        # 核心工具类
│   ├── spring-beans       # Bean 工厂和配置
│   ├── spring-context     # 应用上下文
│   └── spring-expression  # SpEL 表达式
├── AOP
│   ├── spring-aop         # 面向切面编程
│   └── spring-aspects     # AspectJ 集成
├── Data Access（数据访问）
│   ├── spring-jdbc        # JDBC 封装
│   ├── spring-tx          # 事务管理
│   └── spring-orm         # ORM 框架集成
├── Web
│   ├── spring-web         # Web 基础
│   ├── spring-webmvc      # MVC 框架
│   └── spring-webflux     # 响应式 Web
└── Test
    └── spring-test        # 测试支持
```

### 1.3 Maven 依赖配置

```xml
<!-- pom.xml -->
<properties>
    <spring.version>5.3.30</spring.version>
</properties>

<dependencies>
    <!-- Spring 核心 -->
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-context</artifactId>
        <version>${spring.version}</version>
    </dependency>
    
    <!-- Spring AOP -->
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-aop</artifactId>
        <version>${spring.version}</version>
    </dependency>
    
    <!-- AspectJ（AOP 增强） -->
    <dependency>
        <groupId>org.aspectj</groupId>
        <artifactId>aspectjweaver</artifactId>
        <version>1.9.7</version>
    </dependency>
    
    <!-- Spring JDBC -->
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-jdbc</artifactId>
        <version>${spring.version}</version>
    </dependency>
    
    <!-- Spring 测试 -->
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-test</artifactId>
        <version>${spring.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

---

## 2. IoC 容器（控制反转）

### 2.1 什么是 IoC？

**IoC（Inversion of Control，控制反转）** 是一种设计思想，它把对象的创建权从程序员手中"反转"给了框架（Spring 容器）。

**传统方式 vs IoC：**

| 对比项 | 传统方式 | IoC 方式 |
|--------|----------|----------|
| 对象创建 | 程序员手动 new | Spring 容器创建 |
| 依赖关系 | 代码中硬编码 | 配置文件或注解声明 |
| 耦合度 | 高（直接依赖具体类） | 低（依赖接口） |
| 灵活性 | 差（修改需改代码） | 好（修改配置即可） |

**IoC 的好处：**
1. 解耦：类之间不直接依赖，通过接口交互
2. 易测试：可以轻松替换 Mock 对象
3. 易维护：修改依赖关系只需改配置

### 2.2 Spring 容器

Spring 提供了两种容器：

**1. BeanFactory（基础容器）**
- 最基本的容器，提供基本的 DI 功能
- 延迟加载：用到 Bean 时才创建
- 适合资源受限的环境

**2. ApplicationContext（应用上下文）**
- BeanFactory 的子接口，功能更强大
- 立即加载：容器启动时就创建所有单例 Bean
- 支持国际化、事件发布、AOP 等
- **推荐使用**

```java
// ============ 创建容器的几种方式 ============

// 1. 基于 XML 配置（传统方式）
ApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");

// 2. 基于注解配置（推荐）
ApplicationContext context = new AnnotationConfigApplicationContext(AppConfig.class);

// 3. 基于文件系统路径
ApplicationContext context = new FileSystemXmlApplicationContext("/path/to/config.xml");

// 4. Web 环境下
// 通常由 ContextLoaderListener 自动创建
```

### 2.3 XML 配置方式（了解即可）

虽然现在主流是注解配置，但了解 XML 配置有助于理解 Spring 的工作原理。

```xml
<!-- applicationContext.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
           http://www.springframework.org/schema/beans/spring-beans.xsd">
    
    <!-- 定义一个 Bean -->
    <!-- id: Bean 的唯一标识 -->
    <!-- class: Bean 的全限定类名 -->
    <bean id="userDao" class="com.example.dao.UserDaoImpl"/>
    
    <!-- 定义另一个 Bean，并注入依赖 -->
    <bean id="userService" class="com.example.service.UserServiceImpl">
        <!-- 通过 setter 方法注入 -->
        <property name="userDao" ref="userDao"/>
    </bean>
    
    <!-- 构造器注入 -->
    <bean id="orderService" class="com.example.service.OrderServiceImpl">
        <constructor-arg ref="userDao"/>
        <constructor-arg value="100"/>
    </bean>
    
</beans>
```

```java
// 使用 XML 配置的容器
public class Main {
    public static void main(String[] args) {
        // 加载配置文件，创建容器
        ApplicationContext context = new ClassPathXmlApplicationContext("applicationContext.xml");
        
        // 从容器中获取 Bean
        UserService userService = context.getBean("userService", UserService.class);
        
        // 使用 Bean
        userService.saveUser(new User());
    }
}
```

### 2.4 注解配置方式（推荐）

现代 Spring 开发主要使用注解配置，更简洁、更直观。

**核心注解：**

| 注解 | 说明 | 使用位置 |
|------|------|----------|
| `@Configuration` | 标记配置类 | 类 |
| `@Bean` | 声明一个 Bean | 方法 |
| `@Component` | 通用组件 | 类 |
| `@Service` | 服务层组件 | 类 |
| `@Repository` | 数据访问层组件 | 类 |
| `@Controller` | 控制层组件 | 类 |
| `@ComponentScan` | 组件扫描 | 配置类 |

```java
// ============ 配置类 ============
@Configuration  // 标记这是一个配置类，相当于 XML 配置文件
@ComponentScan("com.example")  // 扫描指定包下的组件
public class AppConfig {
    
    // @Bean 方法返回的对象会被注册为 Bean
    // 方法名就是 Bean 的 id
    @Bean
    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl("jdbc:mysql://localhost:3306/test");
        ds.setUsername("root");
        ds.setPassword("root");
        return ds;
    }
    
    // 可以注入其他 Bean 作为参数
    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
}

// ============ 组件类 ============
@Repository  // 标记为数据访问层组件
public class UserDaoImpl implements UserDao {
    
    @Autowired  // 自动注入
    private JdbcTemplate jdbcTemplate;
    
    @Override
    public void save(User user) {
        jdbcTemplate.update("INSERT INTO user (name) VALUES (?)", user.getName());
    }
}

@Service  // 标记为服务层组件
public class UserServiceImpl implements UserService {
    
    @Autowired
    private UserDao userDao;
    
    @Override
    public void saveUser(User user) {
        userDao.save(user);
    }
}

// ============ 启动类 ============
public class Main {
    public static void main(String[] args) {
        // 使用注解配置创建容器
        ApplicationContext context = new AnnotationConfigApplicationContext(AppConfig.class);
        
        UserService userService = context.getBean(UserService.class);
        userService.saveUser(new User("张三"));
    }
}
```


---

## 3. 依赖注入（DI）

### 3.1 什么是依赖注入？

**DI（Dependency Injection，依赖注入）** 是 IoC 的具体实现方式。简单说，就是把一个对象所依赖的其他对象"注入"进去，而不是让它自己去创建。

**举个生活中的例子：**

想象你开一家餐厅（UserService），需要食材供应商（UserDao）。

- **传统方式**：你自己去市场找供应商，谈价格，签合同（new UserDaoImpl()）
- **依赖注入**：有个中介（Spring）帮你找好供应商，直接送到你店里（@Autowired）

你只需要说"我需要一个供应商"，不用关心具体是哪家。

### 3.2 注入方式

Spring 支持三种注入方式，各有优缺点：

#### 3.2.1 构造器注入（推荐）

通过构造方法注入依赖，**Spring 官方推荐**。

```java
@Service
public class UserServiceImpl implements UserService {
    
    // 使用 final 修饰，保证依赖不可变
    private final UserDao userDao;
    private final EmailService emailService;
    
    // 构造器注入
    // 如果只有一个构造器，@Autowired 可以省略
    @Autowired
    public UserServiceImpl(UserDao userDao, EmailService emailService) {
        this.userDao = userDao;
        this.emailService = emailService;
    }
    
    @Override
    public void saveUser(User user) {
        userDao.save(user);
        emailService.sendWelcomeEmail(user.getEmail());
    }
}
```

**优点：**
- 依赖不可变（final），更安全
- 依赖不会为 null（构造时就注入了）
- 便于单元测试（可以通过构造器传入 Mock 对象）
- 能发现循环依赖问题

**缺点：**
- 依赖多时，构造器参数会很长

#### 3.2.2 Setter 注入

通过 setter 方法注入依赖。

```java
@Service
public class UserServiceImpl implements UserService {
    
    private UserDao userDao;
    private EmailService emailService;
    
    // Setter 注入
    @Autowired
    public void setUserDao(UserDao userDao) {
        this.userDao = userDao;
    }
    
    @Autowired
    public void setEmailService(EmailService emailService) {
        this.emailService = emailService;
    }
    
    // 也可以用一个方法注入多个依赖
    @Autowired
    public void setDependencies(UserDao userDao, EmailService emailService) {
        this.userDao = userDao;
        this.emailService = emailService;
    }
}
```

**优点：**
- 灵活，可以在运行时改变依赖
- 适合可选依赖

**缺点：**
- 依赖可能为 null（忘记注入）
- 依赖可变，不够安全

#### 3.2.3 字段注入（不推荐）

直接在字段上使用 @Autowired，最简洁但问题最多。

```java
@Service
public class UserServiceImpl implements UserService {
    
    // 字段注入 - 不推荐！
    @Autowired
    private UserDao userDao;
    
    @Autowired
    private EmailService emailService;
}
```

**为什么不推荐？**
- 无法使用 final，依赖可变
- 难以进行单元测试（需要反射注入）
- 隐藏了类的依赖关系
- 容易导致依赖过多而不自知

### 3.3 @Autowired 详解

`@Autowired` 是最常用的注入注解，它按照**类型（byType）**进行匹配。

```java
@Service
public class OrderService {
    
    // 基本用法：按类型注入
    @Autowired
    private UserDao userDao;
    
    // required = false：依赖可选，找不到不报错
    @Autowired(required = false)
    private CacheService cacheService;
    
    // 注入集合：注入所有实现了 PaymentStrategy 接口的 Bean
    @Autowired
    private List<PaymentStrategy> paymentStrategies;
    
    // 注入 Map：key 是 Bean 名称，value 是 Bean 实例
    @Autowired
    private Map<String, PaymentStrategy> strategyMap;
}
```

### 3.4 解决注入歧义

当一个接口有多个实现类时，Spring 不知道该注入哪个，会报错。

```java
// 接口
public interface MessageService {
    void send(String message);
}

// 实现类1
@Service
public class EmailService implements MessageService {
    @Override
    public void send(String message) {
        System.out.println("发送邮件: " + message);
    }
}

// 实现类2
@Service
public class SmsService implements MessageService {
    @Override
    public void send(String message) {
        System.out.println("发送短信: " + message);
    }
}

// 使用时会报错：找到多个 MessageService 类型的 Bean
@Service
public class NotificationService {
    @Autowired
    private MessageService messageService;  // 报错！
}
```

**解决方案：**

#### 方案1：@Qualifier 指定 Bean 名称

```java
@Service
public class NotificationService {
    
    @Autowired
    @Qualifier("emailService")  // 指定注入 emailService
    private MessageService messageService;
}
```

#### 方案2：@Primary 标记首选 Bean

```java
@Service
@Primary  // 标记为首选，当有多个候选时优先使用
public class EmailService implements MessageService {
    // ...
}
```

#### 方案3：使用 @Resource（按名称注入）

```java
@Service
public class NotificationService {
    
    @Resource(name = "smsService")  // 按名称注入
    private MessageService messageService;
}
```

**@Autowired vs @Resource：**

| 特性 | @Autowired | @Resource |
|------|------------|-----------|
| 来源 | Spring | JSR-250（Java 标准） |
| 注入方式 | 先按类型，再按名称 | 先按名称，再按类型 |
| 必需性 | required 属性 | 无（默认必需） |

### 3.5 @Value 注入配置值

`@Value` 用于注入配置文件中的值或字面量。

```properties
# application.properties
app.name=MyApplication
app.version=1.0.0
server.port=8080
```

```java
@Service
public class AppService {
    
    // 注入配置值
    @Value("${app.name}")
    private String appName;
    
    // 设置默认值（配置不存在时使用）
    @Value("${app.description:默认描述}")
    private String description;
    
    // 注入字面量
    @Value("100")
    private int maxRetry;
    
    // SpEL 表达式
    @Value("#{systemProperties['user.home']}")
    private String userHome;
    
    // 注入数组
    @Value("${app.servers:server1,server2}")
    private String[] servers;
    
    // 注入 List
    @Value("#{'${app.tags:tag1,tag2}'.split(',')}")
    private List<String> tags;
}
```

### 3.6 常见错误与解决

#### 错误1：NoSuchBeanDefinitionException

```
No qualifying bean of type 'com.example.UserDao' available
```

**原因：** Spring 容器中找不到对应类型的 Bean

**解决：**
1. 检查类是否添加了 `@Component`、`@Service` 等注解
2. 检查 `@ComponentScan` 是否扫描了该类所在的包
3. 检查是否有拼写错误

#### 错误2：NoUniqueBeanDefinitionException

```
No qualifying bean of type 'com.example.MessageService' available: 
expected single matching bean but found 2: emailService,smsService
```

**原因：** 找到多个匹配的 Bean，Spring 不知道注入哪个

**解决：**
1. 使用 `@Qualifier` 指定 Bean 名称
2. 使用 `@Primary` 标记首选 Bean
3. 使用 `@Resource` 按名称注入

#### 错误3：BeanCurrentlyInCreationException（循环依赖）

```
Requested bean is currently in creation: Is there an unresolvable circular reference?
```

**原因：** A 依赖 B，B 又依赖 A，形成循环

```java
@Service
public class ServiceA {
    @Autowired
    private ServiceB serviceB;  // A 依赖 B
}

@Service
public class ServiceB {
    @Autowired
    private ServiceA serviceA;  // B 依赖 A，循环了！
}
```

**解决：**
1. 重新设计，打破循环依赖（最佳方案）
2. 使用 `@Lazy` 延迟加载
3. 使用 Setter 注入代替构造器注入

```java
@Service
public class ServiceA {
    @Autowired
    @Lazy  // 延迟加载，打破循环
    private ServiceB serviceB;
}
```

#### 错误4：@Value 注入 null

```java
@Value("${app.name}")
private String appName;  // 值为 null
```

**原因：**
1. 配置文件没有加载
2. 在构造器中使用（此时还没注入）
3. 在静态字段上使用

**解决：**
```java
@Configuration
@PropertySource("classpath:application.properties")  // 加载配置文件
public class AppConfig {
}
```

---

## 4. Bean 的生命周期

### 4.1 生命周期概述

Spring Bean 从创建到销毁，会经历一系列的阶段。理解生命周期有助于在正确的时机执行初始化和清理操作。

**简化版生命周期：**

```
实例化 → 属性注入 → 初始化 → 使用 → 销毁
```

**详细版生命周期：**

```
1. 实例化 Bean（调用构造器）
2. 设置属性值（依赖注入）
3. 调用 BeanNameAware.setBeanName()
4. 调用 BeanFactoryAware.setBeanFactory()
5. 调用 ApplicationContextAware.setApplicationContext()
6. 调用 BeanPostProcessor.postProcessBeforeInitialization()
7. 调用 @PostConstruct 标注的方法
8. 调用 InitializingBean.afterPropertiesSet()
9. 调用 @Bean(initMethod) 指定的方法
10. 调用 BeanPostProcessor.postProcessAfterInitialization()
11. Bean 准备就绪，可以使用
12. 容器关闭时，调用 @PreDestroy 标注的方法
13. 调用 DisposableBean.destroy()
14. 调用 @Bean(destroyMethod) 指定的方法
```

### 4.2 初始化和销毁回调

有三种方式定义初始化和销毁方法：

#### 方式1：使用注解（推荐）

```java
@Component
public class DatabaseConnection {
    
    private Connection connection;
    
    // 初始化方法：在依赖注入完成后调用
    @PostConstruct
    public void init() {
        System.out.println("初始化数据库连接...");
        // 建立连接
        this.connection = DriverManager.getConnection(url, user, password);
    }
    
    // 销毁方法：在容器关闭前调用
    @PreDestroy
    public void cleanup() {
        System.out.println("关闭数据库连接...");
        if (connection != null) {
            connection.close();
        }
    }
}
```

#### 方式2：实现接口

```java
@Component
public class CacheManager implements InitializingBean, DisposableBean {
    
    // InitializingBean 接口方法
    @Override
    public void afterPropertiesSet() throws Exception {
        System.out.println("初始化缓存...");
    }
    
    // DisposableBean 接口方法
    @Override
    public void destroy() throws Exception {
        System.out.println("清理缓存...");
    }
}
```

#### 方式3：@Bean 注解指定

```java
@Configuration
public class AppConfig {
    
    @Bean(initMethod = "init", destroyMethod = "cleanup")
    public ResourceManager resourceManager() {
        return new ResourceManager();
    }
}

public class ResourceManager {
    
    public void init() {
        System.out.println("初始化资源...");
    }
    
    public void cleanup() {
        System.out.println("释放资源...");
    }
}
```

### 4.3 Aware 接口

Aware 接口让 Bean 能够感知到容器的存在，获取容器的相关信息。

```java
@Component
public class MyBean implements BeanNameAware, 
                               BeanFactoryAware, 
                               ApplicationContextAware {
    
    private String beanName;
    private BeanFactory beanFactory;
    private ApplicationContext applicationContext;
    
    @Override
    public void setBeanName(String name) {
        // 获取 Bean 在容器中的名称
        this.beanName = name;
        System.out.println("Bean 名称: " + name);
    }
    
    @Override
    public void setBeanFactory(BeanFactory beanFactory) {
        // 获取 BeanFactory 引用
        this.beanFactory = beanFactory;
    }
    
    @Override
    public void setApplicationContext(ApplicationContext ctx) {
        // 获取 ApplicationContext 引用
        this.applicationContext = ctx;
    }
    
    // 可以用 ApplicationContext 获取其他 Bean
    public void doSomething() {
        UserService userService = applicationContext.getBean(UserService.class);
    }
}
```

### 4.4 BeanPostProcessor（后置处理器）

BeanPostProcessor 可以在 Bean 初始化前后进行自定义处理，是 Spring 扩展的重要机制。

```java
@Component
public class CustomBeanPostProcessor implements BeanPostProcessor {
    
    /**
     * 在 Bean 初始化之前调用
     * 可以返回原始 Bean 或包装后的 Bean
     */
    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) {
        if (bean instanceof UserService) {
            System.out.println("UserService 初始化前处理...");
        }
        return bean;  // 返回原始 Bean
    }
    
    /**
     * 在 Bean 初始化之后调用
     * AOP 代理就是在这里创建的
     */
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof UserService) {
            System.out.println("UserService 初始化后处理...");
            // 可以返回代理对象
        }
        return bean;
    }
}
```

**实际应用：自动记录日志**

```java
// 自定义注解
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Loggable {
}

// 后置处理器：为标注了 @Loggable 的 Bean 添加日志功能
@Component
public class LoggingBeanPostProcessor implements BeanPostProcessor {
    
    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean.getClass().isAnnotationPresent(Loggable.class)) {
            // 创建代理，添加日志功能
            return createLoggingProxy(bean);
        }
        return bean;
    }
    
    private Object createLoggingProxy(Object bean) {
        // 使用 JDK 动态代理或 CGLIB 创建代理
        // ...
    }
}
```


---

## 5. Bean 的作用域

### 5.1 作用域类型

作用域决定了 Bean 的生命周期和可见范围。Spring 提供了以下作用域：

| 作用域 | 说明 | 适用场景 |
|--------|------|----------|
| singleton | 单例（默认），整个容器只有一个实例 | 无状态的 Service、Dao |
| prototype | 原型，每次获取都创建新实例 | 有状态的 Bean |
| request | 每个 HTTP 请求一个实例 | Web 应用 |
| session | 每个 HTTP Session 一个实例 | Web 应用 |
| application | 每个 ServletContext 一个实例 | Web 应用 |
| websocket | 每个 WebSocket 一个实例 | WebSocket 应用 |

### 5.2 Singleton（单例）

**默认作用域**，整个 Spring 容器中只有一个实例。

```java
@Service  // 默认就是 singleton
public class UserService {
    // 所有地方注入的都是同一个实例
}

// 显式指定
@Service
@Scope("singleton")
public class OrderService {
}
```

**特点：**
- 容器启动时创建（默认）
- 整个应用共享一个实例
- 适合无状态的 Bean（不保存请求相关的数据）

**注意事项：**
```java
@Service
public class UserService {
    // 错误！单例 Bean 中不应该有可变的实例变量
    private User currentUser;  // 多线程会出问题！
    
    // 正确：使用方法参数传递数据
    public void processUser(User user) {
        // ...
    }
}
```

### 5.3 Prototype（原型）

每次获取都创建新实例。

```java
@Component
@Scope("prototype")
public class ShoppingCart {
    private List<Item> items = new ArrayList<>();
    
    public void addItem(Item item) {
        items.add(item);
    }
}
```

**特点：**
- 每次 getBean() 或注入时都创建新实例
- Spring 不管理 prototype Bean 的完整生命周期（不会调用销毁方法）
- 适合有状态的 Bean

**常见陷阱：单例中注入原型**

```java
@Service  // 单例
public class OrderService {
    
    @Autowired
    private ShoppingCart cart;  // 原型 Bean
    
    // 问题：cart 只会在 OrderService 创建时注入一次
    // 之后每次调用都是同一个 cart 实例！
    public void createOrder() {
        cart.addItem(new Item());  // 所有订单共用一个购物车！
    }
}
```

**解决方案：**

```java
// 方案1：注入 ApplicationContext，手动获取
@Service
public class OrderService {
    
    @Autowired
    private ApplicationContext context;
    
    public void createOrder() {
        // 每次手动获取新实例
        ShoppingCart cart = context.getBean(ShoppingCart.class);
        cart.addItem(new Item());
    }
}

// 方案2：使用 @Lookup 方法注入（推荐）
@Service
public abstract class OrderService {
    
    // Spring 会重写这个方法，每次返回新的原型实例
    @Lookup
    protected abstract ShoppingCart getShoppingCart();
    
    public void createOrder() {
        ShoppingCart cart = getShoppingCart();  // 每次都是新实例
        cart.addItem(new Item());
    }
}

// 方案3：使用 ObjectFactory 或 Provider
@Service
public class OrderService {
    
    @Autowired
    private ObjectFactory<ShoppingCart> cartFactory;
    
    // 或者使用 JSR-330 的 Provider
    @Autowired
    private Provider<ShoppingCart> cartProvider;
    
    public void createOrder() {
        ShoppingCart cart = cartFactory.getObject();  // 每次都是新实例
        cart.addItem(new Item());
    }
}
```

### 5.4 Web 作用域

在 Web 应用中，还有几个特殊的作用域：

```java
// Request 作用域：每个 HTTP 请求一个实例
@Component
@Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class RequestContext {
    private String requestId = UUID.randomUUID().toString();
}

// Session 作用域：每个 HTTP Session 一个实例
@Component
@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class UserSession {
    private User currentUser;
    private LocalDateTime loginTime;
}
```

**proxyMode 的作用：**

当一个单例 Bean 需要注入 request/session 作用域的 Bean 时，需要使用代理。因为单例 Bean 只创建一次，而 request/session Bean 每次请求/会话都不同。

```java
@Service  // 单例
public class UserService {
    
    // 注入的是代理对象，每次调用时会获取当前请求/会话对应的实例
    @Autowired
    private UserSession userSession;
    
    public void doSomething() {
        // 代理会自动获取当前会话的 UserSession
        User user = userSession.getCurrentUser();
    }
}
```

---

## 6. AOP（面向切面编程）

### 6.1 什么是 AOP？

**AOP（Aspect-Oriented Programming，面向切面编程）** 是一种编程范式，用于将横切关注点（如日志、事务、安全）从业务逻辑中分离出来。

**什么是横切关注点？**

想象你有很多 Service 方法，每个方法都需要：
1. 记录日志
2. 检查权限
3. 开启事务
4. 处理异常

```java
// 没有 AOP 时，代码充满重复
public class UserService {
    
    public void createUser(User user) {
        log.info("开始创建用户");           // 日志
        checkPermission();                  // 权限
        beginTransaction();                 // 事务
        try {
            // 真正的业务逻辑
            userDao.save(user);
            commitTransaction();
        } catch (Exception e) {
            rollbackTransaction();
            log.error("创建用户失败", e);   // 日志
            throw e;
        }
        log.info("用户创建成功");           // 日志
    }
    
    public void deleteUser(Long id) {
        log.info("开始删除用户");           // 又是一样的代码...
        checkPermission();
        beginTransaction();
        // ...
    }
}
```

**使用 AOP 后：**

```java
// 业务代码干净清爽
public class UserService {
    
    public void createUser(User user) {
        userDao.save(user);  // 只关注业务逻辑
    }
    
    public void deleteUser(Long id) {
        userDao.delete(id);
    }
}

// 横切关注点统一处理
@Aspect
public class LoggingAspect {
    @Around("execution(* com.example.service.*.*(..))")
    public Object log(ProceedingJoinPoint pjp) throws Throwable {
        log.info("方法开始: {}", pjp.getSignature());
        Object result = pjp.proceed();
        log.info("方法结束: {}", pjp.getSignature());
        return result;
    }
}
```

### 6.2 AOP 核心概念

| 术语 | 英文 | 说明 | 举例 |
|------|------|------|------|
| 切面 | Aspect | 横切关注点的模块化 | 日志切面、事务切面 |
| 连接点 | Join Point | 程序执行的某个点 | 方法调用、异常抛出 |
| 切入点 | Pointcut | 匹配连接点的表达式 | execution(* com.example.*.*(..)) |
| 通知 | Advice | 在切入点执行的动作 | 前置通知、后置通知 |
| 目标对象 | Target | 被代理的原始对象 | UserService |
| 代理 | Proxy | AOP 创建的代理对象 | UserService 的代理 |
| 织入 | Weaving | 将切面应用到目标对象的过程 | 编译时、运行时 |

### 6.3 启用 AOP

```java
@Configuration
@EnableAspectJAutoProxy  // 启用 AspectJ 自动代理
public class AppConfig {
}
```

```xml
<!-- 或者在 XML 中启用 -->
<aop:aspectj-autoproxy/>
```

### 6.4 切入点表达式

切入点表达式用于匹配要拦截的方法。

**execution 表达式（最常用）：**

```
execution(修饰符? 返回类型 包名.类名.方法名(参数) 异常?)
```

```java
// 匹配 UserService 的所有方法
execution(* com.example.service.UserService.*(..))

// 匹配 service 包下所有类的所有方法
execution(* com.example.service.*.*(..))

// 匹配 service 包及子包下所有类的所有方法
execution(* com.example.service..*.*(..))

// 匹配所有 public 方法
execution(public * *(..))

// 匹配返回 String 的方法
execution(String *(..))

// 匹配方法名以 find 开头的方法
execution(* find*(..))

// 匹配只有一个 Long 参数的方法
execution(* *(Long))

// 匹配第一个参数是 Long 的方法
execution(* *(Long, ..))
```

**其他表达式：**

```java
// within：匹配指定类型内的所有方法
within(com.example.service.UserService)
within(com.example.service.*)

// @annotation：匹配带有指定注解的方法
@annotation(com.example.annotation.Loggable)

// @within：匹配带有指定注解的类的所有方法
@within(org.springframework.stereotype.Service)

// bean：匹配指定名称的 Bean 的所有方法
bean(userService)
bean(*Service)

// args：匹配参数类型的方法
args(Long, String)

// 组合表达式
execution(* com.example.service.*.*(..)) && @annotation(Loggable)
execution(* com.example.service.*.*(..)) || execution(* com.example.dao.*.*(..))
!execution(* com.example.service.*.get*(..))
```

### 6.5 通知类型

Spring AOP 支持 5 种通知类型：

```java
@Aspect
@Component
public class LoggingAspect {
    
    // 定义可重用的切入点
    @Pointcut("execution(* com.example.service.*.*(..))")
    public void serviceLayer() {}
    
    /**
     * 前置通知：方法执行前
     */
    @Before("serviceLayer()")
    public void beforeAdvice(JoinPoint jp) {
        String methodName = jp.getSignature().getName();
        Object[] args = jp.getArgs();
        System.out.println("方法 " + methodName + " 即将执行，参数: " + Arrays.toString(args));
    }
    
    /**
     * 后置通知：方法正常返回后（不管是否有返回值）
     */
    @AfterReturning(pointcut = "serviceLayer()", returning = "result")
    public void afterReturningAdvice(JoinPoint jp, Object result) {
        System.out.println("方法 " + jp.getSignature().getName() + " 返回: " + result);
    }
    
    /**
     * 异常通知：方法抛出异常后
     */
    @AfterThrowing(pointcut = "serviceLayer()", throwing = "ex")
    public void afterThrowingAdvice(JoinPoint jp, Exception ex) {
        System.out.println("方法 " + jp.getSignature().getName() + " 抛出异常: " + ex.getMessage());
    }
    
    /**
     * 最终通知：方法执行后（无论是否异常，类似 finally）
     */
    @After("serviceLayer()")
    public void afterAdvice(JoinPoint jp) {
        System.out.println("方法 " + jp.getSignature().getName() + " 执行完毕");
    }
    
    /**
     * 环绕通知：最强大的通知，可以完全控制方法执行
     */
    @Around("serviceLayer()")
    public Object aroundAdvice(ProceedingJoinPoint pjp) throws Throwable {
        String methodName = pjp.getSignature().getName();
        
        System.out.println("【环绕前】" + methodName);
        long startTime = System.currentTimeMillis();
        
        try {
            // 执行目标方法
            Object result = pjp.proceed();
            
            long duration = System.currentTimeMillis() - startTime;
            System.out.println("【环绕后】" + methodName + " 耗时: " + duration + "ms");
            
            return result;
        } catch (Throwable e) {
            System.out.println("【环绕异常】" + methodName + " 异常: " + e.getMessage());
            throw e;
        }
    }
}
```

**通知执行顺序：**

```
正常情况：
@Around（前半部分）→ @Before → 目标方法 → @AfterReturning → @After → @Around（后半部分）

异常情况：
@Around（前半部分）→ @Before → 目标方法（异常）→ @AfterThrowing → @After → @Around（catch 部分）
```

### 6.6 实战案例

#### 案例1：方法执行时间统计

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Timed {
    String value() default "";
}

// 切面
@Aspect
@Component
@Slf4j
public class TimingAspect {
    
    @Around("@annotation(timed)")
    public Object measureTime(ProceedingJoinPoint pjp, Timed timed) throws Throwable {
        String name = timed.value().isEmpty() ? pjp.getSignature().getName() : timed.value();
        
        long start = System.currentTimeMillis();
        try {
            return pjp.proceed();
        } finally {
            long duration = System.currentTimeMillis() - start;
            log.info("[{}] 执行耗时: {}ms", name, duration);
        }
    }
}

// 使用
@Service
public class UserService {
    
    @Timed("用户查询")
    public User findById(Long id) {
        return userDao.findById(id);
    }
}
```

#### 案例2：统一日志记录

```java
@Aspect
@Component
@Slf4j
public class OperationLogAspect {
    
    @Pointcut("@annotation(com.example.annotation.OperationLog)")
    public void operationLogPointcut() {}
    
    @Around("operationLogPointcut() && @annotation(operationLog)")
    public Object logOperation(ProceedingJoinPoint pjp, OperationLog operationLog) throws Throwable {
        // 获取方法信息
        String className = pjp.getTarget().getClass().getSimpleName();
        String methodName = pjp.getSignature().getName();
        String operation = operationLog.value();
        
        // 获取参数
        Object[] args = pjp.getArgs();
        String params = Arrays.toString(args);
        
        log.info("操作开始 - [{}] {}.{}, 参数: {}", operation, className, methodName, params);
        
        long startTime = System.currentTimeMillis();
        Object result = null;
        String status = "成功";
        
        try {
            result = pjp.proceed();
            return result;
        } catch (Throwable e) {
            status = "失败: " + e.getMessage();
            throw e;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            log.info("操作结束 - [{}] 状态: {}, 耗时: {}ms", operation, status, duration);
        }
    }
}
```

#### 案例3：权限校验

```java
@Aspect
@Component
public class PermissionAspect {
    
    @Autowired
    private SecurityContext securityContext;
    
    @Before("@annotation(requirePermission)")
    public void checkPermission(JoinPoint jp, RequirePermission requirePermission) {
        String[] permissions = requirePermission.value();
        User currentUser = securityContext.getCurrentUser();
        
        if (currentUser == null) {
            throw new UnauthorizedException("请先登录");
        }
        
        for (String permission : permissions) {
            if (!currentUser.hasPermission(permission)) {
                throw new ForbiddenException("缺少权限: " + permission);
            }
        }
    }
}

// 使用
@Service
public class AdminService {
    
    @RequirePermission({"admin:read", "admin:write"})
    public void deleteUser(Long id) {
        userDao.delete(id);
    }
}
```

### 6.7 AOP 常见问题

#### 问题1：自调用不生效

```java
@Service
public class UserService {
    
    @Transactional
    public void methodA() {
        // 直接调用 methodB，AOP 不生效！
        // 因为这是 this 调用，不经过代理
        this.methodB();
    }
    
    @Transactional
    public void methodB() {
        // ...
    }
}
```

**解决方案：**

```java
@Service
public class UserService {
    
    @Autowired
    private UserService self;  // 注入自己（代理对象）
    
    // 或者
    @Autowired
    private ApplicationContext context;
    
    public void methodA() {
        // 通过代理调用
        self.methodB();
        // 或
        context.getBean(UserService.class).methodB();
    }
}
```

#### 问题2：private 方法不生效

Spring AOP 基于代理，只能拦截 public 方法。private、protected、final 方法都无法被代理。

#### 问题3：代理类型选择

```java
// 强制使用 CGLIB 代理（即使实现了接口）
@EnableAspectJAutoProxy(proxyTargetClass = true)
```

| 代理类型 | 条件 | 特点 |
|----------|------|------|
| JDK 动态代理 | 目标类实现了接口 | 只能代理接口方法 |
| CGLIB 代理 | 目标类没有实现接口 | 通过继承实现，不能代理 final 方法 |


---

## 7. 事务管理

### 7.1 事务基础

**什么是事务？**

事务是一组操作的集合，要么全部成功，要么全部失败。就像银行转账：扣款和入账必须同时成功或同时失败，不能只成功一半。

**事务的 ACID 特性：**

| 特性 | 英文 | 说明 |
|------|------|------|
| 原子性 | Atomicity | 事务是不可分割的最小单位，要么全做，要么全不做 |
| 一致性 | Consistency | 事务执行前后，数据保持一致状态 |
| 隔离性 | Isolation | 多个事务并发执行时，互不干扰 |
| 持久性 | Durability | 事务提交后，数据永久保存 |

### 7.2 Spring 事务管理

Spring 提供了统一的事务管理抽象，支持编程式和声明式两种方式。

**事务管理器：**

```java
@Configuration
@EnableTransactionManagement  // 启用事务管理
public class TransactionConfig {
    
    @Bean
    public PlatformTransactionManager transactionManager(DataSource dataSource) {
        // JDBC 事务管理器
        return new DataSourceTransactionManager(dataSource);
    }
    
    // 如果使用 JPA
    @Bean
    public PlatformTransactionManager transactionManager(EntityManagerFactory emf) {
        return new JpaTransactionManager(emf);
    }
}
```

### 7.3 声明式事务（@Transactional）

声明式事务是最常用的方式，通过注解声明事务边界。

```java
@Service
public class UserService {
    
    @Autowired
    private UserDao userDao;
    
    @Autowired
    private AccountDao accountDao;
    
    /**
     * 基本用法：方法内的所有操作在一个事务中
     */
    @Transactional
    public void createUser(User user) {
        userDao.save(user);
        accountDao.createAccount(user.getId());
        // 如果这里抛出异常，上面两个操作都会回滚
    }
    
    /**
     * 只读事务：优化查询性能
     */
    @Transactional(readOnly = true)
    public User findById(Long id) {
        return userDao.findById(id);
    }
    
    /**
     * 指定回滚规则
     */
    @Transactional(
        rollbackFor = Exception.class,           // 遇到任何异常都回滚
        noRollbackFor = BusinessException.class  // 但 BusinessException 不回滚
    )
    public void updateUser(User user) {
        userDao.update(user);
    }
    
    /**
     * 设置超时时间（秒）
     */
    @Transactional(timeout = 30)
    public void longRunningOperation() {
        // 如果超过 30 秒，事务会被回滚
    }
}
```

### 7.4 事务传播行为

当一个事务方法调用另一个事务方法时，事务如何传播？

```java
@Service
public class OrderService {
    
    @Autowired
    private UserService userService;
    
    @Transactional
    public void createOrder(Order order) {
        // 这里已经有事务了
        orderDao.save(order);
        
        // 调用另一个事务方法，事务如何处理？
        userService.updateUserPoints(order.getUserId(), order.getPoints());
    }
}
```

**7 种传播行为：**

| 传播行为 | 说明 | 使用场景 |
|----------|------|----------|
| REQUIRED（默认） | 有事务就加入，没有就新建 | 大多数情况 |
| REQUIRES_NEW | 总是新建事务，挂起当前事务 | 独立的操作（如日志记录） |
| SUPPORTS | 有事务就加入，没有就非事务执行 | 查询方法 |
| NOT_SUPPORTED | 非事务执行，挂起当前事务 | 不需要事务的操作 |
| MANDATORY | 必须在事务中执行，否则抛异常 | 必须被其他事务调用的方法 |
| NEVER | 必须非事务执行，有事务就抛异常 | 不允许在事务中执行的操作 |
| NESTED | 嵌套事务，可以独立回滚 | 部分操作可以独立回滚 |

```java
@Service
public class UserService {
    
    /**
     * REQUIRED（默认）：加入当前事务，或新建事务
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void updateUser(User user) {
        userDao.update(user);
    }
    
    /**
     * REQUIRES_NEW：总是新建事务
     * 即使外层事务回滚，这里的操作也会提交
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logOperation(String operation) {
        // 记录操作日志，即使主业务失败，日志也要保存
        logDao.save(new OperationLog(operation));
    }
    
    /**
     * NESTED：嵌套事务
     * 可以独立回滚到保存点，但最终提交依赖外层事务
     */
    @Transactional(propagation = Propagation.NESTED)
    public void updatePoints(Long userId, int points) {
        // 如果这里失败，只回滚这个方法，不影响外层事务
        pointsDao.update(userId, points);
    }
}
```

**实际案例：订单创建**

```java
@Service
public class OrderService {
    
    @Autowired
    private OrderDao orderDao;
    
    @Autowired
    private InventoryService inventoryService;
    
    @Autowired
    private NotificationService notificationService;
    
    @Transactional
    public void createOrder(Order order) {
        // 1. 保存订单
        orderDao.save(order);
        
        // 2. 扣减库存（同一事务，库存不足会回滚整个订单）
        inventoryService.deductStock(order.getProductId(), order.getQuantity());
        
        // 3. 发送通知（新事务，即使通知失败，订单也要成功）
        try {
            notificationService.sendOrderNotification(order);
        } catch (Exception e) {
            // 通知失败不影响订单
            log.warn("发送通知失败", e);
        }
    }
}

@Service
public class NotificationService {
    
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void sendOrderNotification(Order order) {
        // 独立事务，失败不影响主业务
        notificationDao.save(new Notification(order));
        emailService.send(order.getUserEmail(), "订单创建成功");
    }
}
```

### 7.5 事务隔离级别

隔离级别决定了事务之间的可见性，用于解决并发问题。

**并发问题：**

| 问题 | 说明 | 示例 |
|------|------|------|
| 脏读 | 读到未提交的数据 | A 修改数据未提交，B 读到了，A 回滚，B 读到的是脏数据 |
| 不可重复读 | 同一事务内两次读取结果不同 | A 读取数据，B 修改并提交，A 再读，数据变了 |
| 幻读 | 同一事务内两次查询记录数不同 | A 查询有 10 条，B 插入 1 条，A 再查有 11 条 |

**隔离级别：**

| 隔离级别 | 脏读 | 不可重复读 | 幻读 | 性能 |
|----------|------|------------|------|------|
| READ_UNCOMMITTED | ✗ | ✗ | ✗ | 最高 |
| READ_COMMITTED | ✓ | ✗ | ✗ | 高 |
| REPEATABLE_READ | ✓ | ✓ | ✗ | 中 |
| SERIALIZABLE | ✓ | ✓ | ✓ | 最低 |

```java
@Service
public class AccountService {
    
    /**
     * 使用默认隔离级别（取决于数据库）
     */
    @Transactional
    public void transfer(Long fromId, Long toId, BigDecimal amount) {
        // ...
    }
    
    /**
     * 指定隔离级别
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public BigDecimal getBalance(Long accountId) {
        // 确保在同一事务内多次读取余额结果一致
        return accountDao.getBalance(accountId);
    }
    
    /**
     * 最高隔离级别，完全串行化
     */
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void criticalOperation() {
        // 对数据一致性要求极高的操作
    }
}
```

### 7.6 事务常见问题

#### 问题1：事务不生效

```java
@Service
public class UserService {
    
    // 问题1：方法不是 public
    @Transactional
    private void privateMethod() {  // 不生效！
        // ...
    }
    
    // 问题2：自调用
    public void methodA() {
        this.methodB();  // 不生效！直接调用不经过代理
    }
    
    @Transactional
    public void methodB() {
        // ...
    }
    
    // 问题3：异常被捕获
    @Transactional
    public void methodC() {
        try {
            userDao.save(user);
            throw new RuntimeException("error");
        } catch (Exception e) {
            // 异常被捕获，事务不会回滚！
            log.error("error", e);
        }
    }
    
    // 问题4：抛出检查异常
    @Transactional
    public void methodD() throws IOException {
        userDao.save(user);
        throw new IOException("error");  // 默认不回滚检查异常！
    }
}
```

**解决方案：**

```java
@Service
public class UserService {
    
    @Autowired
    private UserService self;  // 注入自己解决自调用问题
    
    public void methodA() {
        self.methodB();  // 通过代理调用
    }
    
    // 指定所有异常都回滚
    @Transactional(rollbackFor = Exception.class)
    public void methodD() throws IOException {
        userDao.save(user);
        throw new IOException("error");  // 现在会回滚了
    }
    
    // 需要回滚时重新抛出异常
    @Transactional
    public void methodC() {
        try {
            userDao.save(user);
            throw new RuntimeException("error");
        } catch (Exception e) {
            log.error("error", e);
            throw e;  // 重新抛出，让事务回滚
        }
    }
}
```

#### 问题2：长事务

```java
// 错误：事务范围太大
@Transactional
public void processOrder(Order order) {
    // 1. 查询用户（不需要事务）
    User user = userDao.findById(order.getUserId());
    
    // 2. 调用外部服务（可能很慢，不应该在事务中）
    PaymentResult result = paymentService.pay(order);
    
    // 3. 更新订单状态（需要事务）
    orderDao.updateStatus(order.getId(), result.getStatus());
}
```

**解决方案：缩小事务范围**

```java
@Service
public class OrderService {
    
    @Autowired
    private OrderTransactionService transactionService;
    
    // 不加事务
    public void processOrder(Order order) {
        // 1. 查询用户（不需要事务）
        User user = userDao.findById(order.getUserId());
        
        // 2. 调用外部服务（不在事务中）
        PaymentResult result = paymentService.pay(order);
        
        // 3. 只有数据库操作在事务中
        transactionService.updateOrderStatus(order.getId(), result.getStatus());
    }
}

@Service
public class OrderTransactionService {
    
    @Transactional
    public void updateOrderStatus(Long orderId, String status) {
        orderDao.updateStatus(orderId, status);
    }
}
```

### 7.7 编程式事务

有时候需要更细粒度的事务控制，可以使用编程式事务。

```java
@Service
public class UserService {
    
    @Autowired
    private TransactionTemplate transactionTemplate;
    
    @Autowired
    private PlatformTransactionManager transactionManager;
    
    /**
     * 使用 TransactionTemplate（推荐）
     */
    public void createUserWithTemplate(User user) {
        transactionTemplate.execute(status -> {
            try {
                userDao.save(user);
                accountDao.createAccount(user.getId());
                return null;
            } catch (Exception e) {
                status.setRollbackOnly();  // 标记回滚
                throw e;
            }
        });
    }
    
    /**
     * 使用 TransactionManager（更底层）
     */
    public void createUserWithManager(User user) {
        DefaultTransactionDefinition def = new DefaultTransactionDefinition();
        def.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
        
        TransactionStatus status = transactionManager.getTransaction(def);
        
        try {
            userDao.save(user);
            accountDao.createAccount(user.getId());
            transactionManager.commit(status);
        } catch (Exception e) {
            transactionManager.rollback(status);
            throw e;
        }
    }
}
```

---

## 8. Spring JDBC

### 8.1 JdbcTemplate 简介

Spring JDBC 提供了 `JdbcTemplate`，简化了 JDBC 操作，自动处理资源管理和异常转换。

**传统 JDBC vs JdbcTemplate：**

```java
// 传统 JDBC：繁琐的样板代码
public User findById(Long id) {
    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;
    try {
        conn = dataSource.getConnection();
        ps = conn.prepareStatement("SELECT * FROM user WHERE id = ?");
        ps.setLong(1, id);
        rs = ps.executeQuery();
        if (rs.next()) {
            User user = new User();
            user.setId(rs.getLong("id"));
            user.setName(rs.getString("name"));
            return user;
        }
        return null;
    } catch (SQLException e) {
        throw new RuntimeException(e);
    } finally {
        // 必须手动关闭资源
        if (rs != null) try { rs.close(); } catch (SQLException e) {}
        if (ps != null) try { ps.close(); } catch (SQLException e) {}
        if (conn != null) try { conn.close(); } catch (SQLException e) {}
    }
}

// JdbcTemplate：简洁清晰
public User findById(Long id) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM user WHERE id = ?",
        new BeanPropertyRowMapper<>(User.class),
        id
    );
}
```

### 8.2 配置 JdbcTemplate

```java
@Configuration
public class DataSourceConfig {
    
    @Bean
    public DataSource dataSource() {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl("jdbc:mysql://localhost:3306/test?useSSL=false&serverTimezone=UTC");
        ds.setUsername("root");
        ds.setPassword("root");
        ds.setMaximumPoolSize(10);
        return ds;
    }
    
    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
    
    // NamedParameterJdbcTemplate 支持命名参数
    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }
}
```

### 8.3 CRUD 操作

```java
@Repository
public class UserDao {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    // ============ 查询单个对象 ============
    
    public User findById(Long id) {
        String sql = "SELECT * FROM user WHERE id = ?";
        try {
            return jdbcTemplate.queryForObject(sql, new UserRowMapper(), id);
        } catch (EmptyResultDataAccessException e) {
            return null;  // 没有找到
        }
    }
    
    // 使用 BeanPropertyRowMapper 自动映射
    public User findByIdAuto(Long id) {
        String sql = "SELECT * FROM user WHERE id = ?";
        return jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper<>(User.class), id);
    }
    
    // 查询单个值
    public int countAll() {
        return jdbcTemplate.queryForObject("SELECT COUNT(*) FROM user", Integer.class);
    }
    
    public String findNameById(Long id) {
        return jdbcTemplate.queryForObject(
            "SELECT name FROM user WHERE id = ?", 
            String.class, 
            id
        );
    }
    
    // ============ 查询列表 ============
    
    public List<User> findAll() {
        String sql = "SELECT * FROM user";
        return jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(User.class));
    }
    
    public List<User> findByStatus(String status) {
        String sql = "SELECT * FROM user WHERE status = ?";
        return jdbcTemplate.query(sql, new BeanPropertyRowMapper<>(User.class), status);
    }
    
    // ============ 插入 ============
    
    public int insert(User user) {
        String sql = "INSERT INTO user (name, email, age) VALUES (?, ?, ?)";
        return jdbcTemplate.update(sql, user.getName(), user.getEmail(), user.getAge());
    }
    
    // 插入并获取自增 ID
    public Long insertAndGetId(User user) {
        String sql = "INSERT INTO user (name, email, age) VALUES (?, ?, ?)";
        KeyHolder keyHolder = new GeneratedKeyHolder();
        
        jdbcTemplate.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            ps.setString(1, user.getName());
            ps.setString(2, user.getEmail());
            ps.setInt(3, user.getAge());
            return ps;
        }, keyHolder);
        
        return keyHolder.getKey().longValue();
    }
    
    // ============ 更新 ============
    
    public int update(User user) {
        String sql = "UPDATE user SET name = ?, email = ?, age = ? WHERE id = ?";
        return jdbcTemplate.update(sql, user.getName(), user.getEmail(), user.getAge(), user.getId());
    }
    
    // ============ 删除 ============
    
    public int deleteById(Long id) {
        return jdbcTemplate.update("DELETE FROM user WHERE id = ?", id);
    }
    
    // ============ 批量操作 ============
    
    public int[] batchInsert(List<User> users) {
        String sql = "INSERT INTO user (name, email, age) VALUES (?, ?, ?)";
        return jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                User user = users.get(i);
                ps.setString(1, user.getName());
                ps.setString(2, user.getEmail());
                ps.setInt(3, user.getAge());
            }
            
            @Override
            public int getBatchSize() {
                return users.size();
            }
        });
    }
    
    // 更简洁的批量插入
    public int[] batchInsertSimple(List<User> users) {
        String sql = "INSERT INTO user (name, email, age) VALUES (?, ?, ?)";
        List<Object[]> batchArgs = users.stream()
            .map(u -> new Object[]{u.getName(), u.getEmail(), u.getAge()})
            .collect(Collectors.toList());
        return jdbcTemplate.batchUpdate(sql, batchArgs);
    }
}

// 自定义 RowMapper
public class UserRowMapper implements RowMapper<User> {
    @Override
    public User mapRow(ResultSet rs, int rowNum) throws SQLException {
        User user = new User();
        user.setId(rs.getLong("id"));
        user.setName(rs.getString("name"));
        user.setEmail(rs.getString("email"));
        user.setAge(rs.getInt("age"));
        user.setCreateTime(rs.getTimestamp("create_time").toLocalDateTime());
        return user;
    }
}
```

### 8.4 NamedParameterJdbcTemplate

使用命名参数代替 `?` 占位符，代码更清晰。

```java
@Repository
public class UserDao {
    
    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;
    
    public User findById(Long id) {
        String sql = "SELECT * FROM user WHERE id = :id";
        Map<String, Object> params = new HashMap<>();
        params.put("id", id);
        return namedJdbcTemplate.queryForObject(sql, params, new BeanPropertyRowMapper<>(User.class));
    }
    
    public List<User> findByCondition(String name, Integer minAge, Integer maxAge) {
        String sql = "SELECT * FROM user WHERE name LIKE :name AND age BETWEEN :minAge AND :maxAge";
        
        MapSqlParameterSource params = new MapSqlParameterSource()
            .addValue("name", "%" + name + "%")
            .addValue("minAge", minAge)
            .addValue("maxAge", maxAge);
        
        return namedJdbcTemplate.query(sql, params, new BeanPropertyRowMapper<>(User.class));
    }
    
    // 使用对象作为参数源
    public int insert(User user) {
        String sql = "INSERT INTO user (name, email, age) VALUES (:name, :email, :age)";
        SqlParameterSource params = new BeanPropertySqlParameterSource(user);
        return namedJdbcTemplate.update(sql, params);
    }
    
    // IN 查询
    public List<User> findByIds(List<Long> ids) {
        String sql = "SELECT * FROM user WHERE id IN (:ids)";
        Map<String, Object> params = Collections.singletonMap("ids", ids);
        return namedJdbcTemplate.query(sql, params, new BeanPropertyRowMapper<>(User.class));
    }
}
```


---

## 9. SpEL（Spring 表达式语言）

### 9.1 什么是 SpEL？

SpEL（Spring Expression Language）是 Spring 提供的强大表达式语言，可以在运行时查询和操作对象。

**SpEL 的用途：**
- 在注解中动态计算值
- 在配置文件中引用 Bean 属性
- 在 AOP 切入点表达式中使用
- 在 Spring Security 权限表达式中使用

### 9.2 基本语法

```java
@Component
public class SpELDemo {
    
    // ============ 字面量 ============
    
    @Value("#{100}")
    private int number;
    
    @Value("#{'Hello World'}")
    private String text;
    
    @Value("#{true}")
    private boolean flag;
    
    // ============ 引用 Bean ============
    
    @Value("#{userService}")  // 引用名为 userService 的 Bean
    private UserService userService;
    
    @Value("#{userService.findAll()}")  // 调用 Bean 的方法
    private List<User> users;
    
    @Value("#{userService.count}")  // 访问 Bean 的属性
    private int userCount;
    
    // ============ 运算符 ============
    
    @Value("#{10 + 20}")  // 算术运算
    private int sum;
    
    @Value("#{10 > 5}")  // 比较运算
    private boolean greater;
    
    @Value("#{true and false}")  // 逻辑运算
    private boolean logical;
    
    @Value("#{user.name ?: 'Unknown'}")  // Elvis 运算符（空值处理）
    private String userName;
    
    @Value("#{user?.address?.city}")  // 安全导航（避免 NPE）
    private String city;
    
    // ============ 集合操作 ============
    
    @Value("#{users[0]}")  // 访问列表元素
    private User firstUser;
    
    @Value("#{map['key']}")  // 访问 Map 元素
    private String mapValue;
    
    @Value("#{users.size()}")  // 集合大小
    private int size;
    
    // ============ 集合筛选和投影 ============
    
    @Value("#{users.?[age > 18]}")  // 筛选：年龄大于 18 的用户
    private List<User> adults;
    
    @Value("#{users.![name]}")  // 投影：提取所有用户的名字
    private List<String> names;
    
    @Value("#{users.?[status == 'ACTIVE'].![name]}")  // 组合：筛选后投影
    private List<String> activeUserNames;
    
    // ============ 类型操作 ============
    
    @Value("#{T(java.lang.Math).PI}")  // 访问静态属性
    private double pi;
    
    @Value("#{T(java.lang.Math).random()}")  // 调用静态方法
    private double random;
    
    @Value("#{T(java.time.LocalDate).now()}")  // 获取当前日期
    private LocalDate today;
    
    // ============ 条件表达式 ============
    
    @Value("#{user.age >= 18 ? '成年' : '未成年'}")
    private String ageGroup;
    
    // ============ 正则表达式 ============
    
    @Value("#{user.email matches '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'}")
    private boolean validEmail;
}
```

### 9.3 编程式使用 SpEL

```java
public class SpELProgrammatic {
    
    public void demo() {
        // 创建解析器
        ExpressionParser parser = new SpelExpressionParser();
        
        // 解析简单表达式
        Expression exp = parser.parseExpression("'Hello World'.concat('!')");
        String result = (String) exp.getValue();  // "Hello World!"
        
        // 指定返回类型
        Integer length = parser.parseExpression("'Hello'.length()").getValue(Integer.class);
        
        // 使用上下文
        User user = new User("张三", 25);
        StandardEvaluationContext context = new StandardEvaluationContext(user);
        
        String name = parser.parseExpression("name").getValue(context, String.class);  // "张三"
        Boolean adult = parser.parseExpression("age >= 18").getValue(context, Boolean.class);  // true
        
        // 设置变量
        context.setVariable("threshold", 20);
        Boolean result2 = parser.parseExpression("age > #threshold").getValue(context, Boolean.class);
        
        // 注册函数
        context.registerFunction("reverse", 
            StringUtils.class.getDeclaredMethod("reverse", String.class));
        String reversed = parser.parseExpression("#reverse('hello')").getValue(context, String.class);
    }
}
```

### 9.4 SpEL 在注解中的应用

```java
// ============ @Value 中使用 ============
@Component
public class AppConfig {
    
    @Value("#{systemProperties['user.home']}")
    private String userHome;
    
    @Value("#{systemEnvironment['JAVA_HOME']}")
    private String javaHome;
    
    @Value("#{${app.timeout} * 1000}")  // 结合 ${} 使用
    private long timeoutMs;
}

// ============ @Cacheable 中使用 ============
@Service
public class UserService {
    
    @Cacheable(value = "users", key = "#id")
    public User findById(Long id) {
        return userDao.findById(id);
    }
    
    @Cacheable(value = "users", key = "#user.id", condition = "#user.age > 18")
    public User findByUser(User user) {
        return userDao.findByUser(user);
    }
}

// ============ @PreAuthorize 中使用 ============
@RestController
public class UserController {
    
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    @PreAuthorize("#user.createdBy == authentication.name")
    @PutMapping("/users")
    public User updateUser(@RequestBody User user) {
        return userService.update(user);
    }
}

// ============ @EventListener 中使用 ============
@Component
public class EventHandler {
    
    @EventListener(condition = "#event.success")
    public void handleSuccess(OrderEvent event) {
        // 只处理成功的订单事件
    }
}
```

---

## 10. 资源管理

### 10.1 Resource 接口

Spring 提供了统一的资源访问接口 `Resource`，可以访问各种类型的资源。

```java
@Component
public class ResourceDemo {
    
    @Autowired
    private ResourceLoader resourceLoader;
    
    public void loadResources() throws IOException {
        // ============ 类路径资源 ============
        Resource classpathResource = resourceLoader.getResource("classpath:config.properties");
        
        // ============ 文件系统资源 ============
        Resource fileResource = resourceLoader.getResource("file:C:/data/config.properties");
        
        // ============ URL 资源 ============
        Resource urlResource = resourceLoader.getResource("https://example.com/config.properties");
        
        // ============ 读取资源内容 ============
        if (classpathResource.exists()) {
            // 获取输入流
            InputStream is = classpathResource.getInputStream();
            
            // 获取文件对象（如果是文件系统资源）
            File file = classpathResource.getFile();
            
            // 获取 URL
            URL url = classpathResource.getURL();
            
            // 获取文件名
            String filename = classpathResource.getFilename();
        }
    }
}
```

### 10.2 @Value 注入资源

```java
@Component
public class ConfigLoader {
    
    // 注入单个资源
    @Value("classpath:config/app.properties")
    private Resource configFile;
    
    // 注入多个资源（通配符）
    @Value("classpath:config/*.properties")
    private Resource[] configFiles;
    
    // 注入资源内容
    @Value("classpath:templates/email.html")
    private Resource emailTemplate;
    
    public String loadEmailTemplate() throws IOException {
        return StreamUtils.copyToString(
            emailTemplate.getInputStream(), 
            StandardCharsets.UTF_8
        );
    }
    
    public void loadAllConfigs() throws IOException {
        for (Resource resource : configFiles) {
            Properties props = new Properties();
            props.load(resource.getInputStream());
            // 处理配置
        }
    }
}
```

### 10.3 ResourcePatternResolver

用于加载匹配模式的多个资源。

```java
@Component
public class ResourceScanner {
    
    @Autowired
    private ResourcePatternResolver resourceResolver;
    
    public void scanResources() throws IOException {
        // 扫描所有 XML 配置文件
        Resource[] xmlResources = resourceResolver.getResources("classpath*:config/**/*.xml");
        
        // 扫描所有 JAR 包中的 META-INF/spring.factories
        Resource[] factories = resourceResolver.getResources("classpath*:META-INF/spring.factories");
        
        for (Resource resource : xmlResources) {
            System.out.println("Found: " + resource.getURL());
        }
    }
}
```

---

## 11. 国际化（i18n）

### 11.1 配置消息源

```java
@Configuration
public class I18nConfig {
    
    @Bean
    public MessageSource messageSource() {
        ReloadableResourceBundleMessageSource messageSource = new ReloadableResourceBundleMessageSource();
        messageSource.setBasename("classpath:messages");  // messages.properties
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setCacheSeconds(3600);  // 缓存时间
        return messageSource;
    }
}
```

### 11.2 消息文件

```properties
# messages.properties（默认）
greeting=Hello
user.welcome=Welcome, {0}!
error.notfound=Resource not found

# messages_zh_CN.properties（中文）
greeting=你好
user.welcome=欢迎，{0}！
error.notfound=资源未找到

# messages_ja_JP.properties（日文）
greeting=こんにちは
user.welcome=ようこそ、{0}！
error.notfound=リソースが見つかりません
```

### 11.3 使用消息

```java
@Service
public class GreetingService {
    
    @Autowired
    private MessageSource messageSource;
    
    public String getGreeting(Locale locale) {
        return messageSource.getMessage("greeting", null, locale);
    }
    
    public String getWelcome(String username, Locale locale) {
        return messageSource.getMessage("user.welcome", new Object[]{username}, locale);
    }
    
    public String getError(String code, Locale locale) {
        return messageSource.getMessage(code, null, "Unknown error", locale);
    }
}

// 使用示例
@RestController
public class GreetingController {
    
    @Autowired
    private GreetingService greetingService;
    
    @GetMapping("/greeting")
    public String greeting(@RequestHeader(value = "Accept-Language", defaultValue = "en") Locale locale) {
        return greetingService.getGreeting(locale);
    }
}
```

---

## 12. 事件机制

### 12.1 Spring 事件模型

Spring 提供了事件发布/订阅机制，实现组件间的松耦合通信。

**核心组件：**
- `ApplicationEvent`：事件基类
- `ApplicationEventPublisher`：事件发布者
- `ApplicationListener` / `@EventListener`：事件监听者

### 12.2 自定义事件

```java
// ============ 定义事件 ============
public class UserRegisteredEvent extends ApplicationEvent {
    
    private final User user;
    
    public UserRegisteredEvent(Object source, User user) {
        super(source);
        this.user = user;
    }
    
    public User getUser() {
        return user;
    }
}

// 更简洁的方式：直接使用 POJO
@Data
@AllArgsConstructor
public class OrderCreatedEvent {
    private Long orderId;
    private Long userId;
    private BigDecimal amount;
}
```

### 12.3 发布事件

```java
@Service
public class UserService {
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    public User register(UserDTO dto) {
        // 保存用户
        User user = new User();
        BeanUtils.copyProperties(dto, user);
        userDao.save(user);
        
        // 发布事件
        eventPublisher.publishEvent(new UserRegisteredEvent(this, user));
        
        // 或者发布 POJO 事件
        eventPublisher.publishEvent(new OrderCreatedEvent(1L, user.getId(), BigDecimal.ZERO));
        
        return user;
    }
}
```

### 12.4 监听事件

```java
// ============ 方式1：实现 ApplicationListener 接口 ============
@Component
public class UserRegisteredListener implements ApplicationListener<UserRegisteredEvent> {
    
    @Override
    public void onApplicationEvent(UserRegisteredEvent event) {
        User user = event.getUser();
        System.out.println("用户注册成功: " + user.getName());
        // 发送欢迎邮件等
    }
}

// ============ 方式2：使用 @EventListener 注解（推荐） ============
@Component
@Slf4j
public class EventListeners {
    
    // 基本用法
    @EventListener
    public void handleUserRegistered(UserRegisteredEvent event) {
        log.info("处理用户注册事件: {}", event.getUser().getName());
    }
    
    // 监听 POJO 事件
    @EventListener
    public void handleOrderCreated(OrderCreatedEvent event) {
        log.info("处理订单创建事件: orderId={}", event.getOrderId());
    }
    
    // 条件监听
    @EventListener(condition = "#event.amount.compareTo(new java.math.BigDecimal('1000')) > 0")
    public void handleLargeOrder(OrderCreatedEvent event) {
        log.info("处理大额订单: {}", event.getAmount());
    }
    
    // 异步监听
    @Async
    @EventListener
    public void handleUserRegisteredAsync(UserRegisteredEvent event) {
        // 异步执行，不阻塞主流程
        sendWelcomeEmail(event.getUser());
    }
    
    // 监听多个事件
    @EventListener({UserRegisteredEvent.class, UserUpdatedEvent.class})
    public void handleUserEvent(Object event) {
        log.info("用户事件: {}", event);
    }
    
    // 返回值作为新事件发布
    @EventListener
    public NotificationEvent handleAndPublish(UserRegisteredEvent event) {
        // 返回的事件会被自动发布
        return new NotificationEvent("用户 " + event.getUser().getName() + " 已注册");
    }
}
```

### 12.5 事务事件监听

在事务提交后才处理事件，避免事务回滚导致的数据不一致。

```java
@Component
public class TransactionalEventListeners {
    
    // 事务提交后执行
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void afterCommit(OrderCreatedEvent event) {
        // 发送订单确认邮件
        // 此时事务已提交，数据已持久化
    }
    
    // 事务回滚后执行
    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    public void afterRollback(OrderCreatedEvent event) {
        // 清理操作
    }
    
    // 事务完成后执行（无论提交还是回滚）
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMPLETION)
    public void afterCompletion(OrderCreatedEvent event) {
        // 释放资源
    }
    
    // 事务提交前执行
    @TransactionalEventListener(phase = TransactionPhase.BEFORE_COMMIT)
    public void beforeCommit(OrderCreatedEvent event) {
        // 在事务提交前做最后的检查
    }
}
```

---

## 13. 常见错误总结

### 13.1 Bean 相关错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| NoSuchBeanDefinitionException | 找不到 Bean | 检查 @Component 注解和 @ComponentScan 范围 |
| NoUniqueBeanDefinitionException | 找到多个 Bean | 使用 @Qualifier 或 @Primary |
| BeanCurrentlyInCreationException | 循环依赖 | 使用 @Lazy 或重构代码 |
| BeanCreationException | Bean 创建失败 | 检查构造器参数和依赖 |

### 13.2 事务相关错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| 事务不生效 | 自调用、非 public 方法 | 通过代理调用，使用 public 方法 |
| 事务不回滚 | 捕获了异常、检查异常 | 重新抛出异常，配置 rollbackFor |
| 事务超时 | 长事务 | 缩小事务范围，优化 SQL |

### 13.3 AOP 相关错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| AOP 不生效 | 自调用、final 方法 | 通过代理调用，避免 final |
| 切入点不匹配 | 表达式错误 | 检查 execution 表达式语法 |
| 代理类型错误 | 接口代理 vs 类代理 | 配置 proxyTargetClass |

### 13.4 注入相关错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| @Value 为 null | 配置未加载、静态字段 | 检查 @PropertySource，避免静态字段 |
| @Autowired 为 null | 手动 new 对象 | 让 Spring 管理对象 |
| 类型转换错误 | 配置值类型不匹配 | 检查配置值格式 |

---

## 14. 最佳实践

### 14.1 依赖注入

```java
// ✅ 推荐：构造器注入
@Service
public class UserService {
    private final UserDao userDao;
    private final EmailService emailService;
    
    public UserService(UserDao userDao, EmailService emailService) {
        this.userDao = userDao;
        this.emailService = emailService;
    }
}

// ❌ 不推荐：字段注入
@Service
public class UserService {
    @Autowired
    private UserDao userDao;
}
```

### 14.2 事务管理

```java
// ✅ 推荐：缩小事务范围
@Service
public class OrderService {
    
    public void processOrder(Order order) {
        // 非事务操作
        validateOrder(order);
        
        // 只有数据库操作在事务中
        saveOrder(order);
        
        // 非事务操作
        sendNotification(order);
    }
    
    @Transactional
    public void saveOrder(Order order) {
        orderDao.save(order);
        inventoryDao.deduct(order.getProductId(), order.getQuantity());
    }
}

// ❌ 不推荐：大事务
@Transactional
public void processOrder(Order order) {
    validateOrder(order);  // 不需要事务
    orderDao.save(order);
    inventoryDao.deduct(order.getProductId(), order.getQuantity());
    sendNotification(order);  // 不需要事务，可能很慢
}
```

### 14.3 异常处理

```java
// ✅ 推荐：让事务感知异常
@Transactional
public void createUser(User user) {
    try {
        userDao.save(user);
        externalService.notify(user);
    } catch (ExternalServiceException e) {
        log.error("外部服务调用失败", e);
        throw new BusinessException("创建用户失败", e);  // 重新抛出
    }
}

// ❌ 不推荐：吞掉异常
@Transactional
public void createUser(User user) {
    try {
        userDao.save(user);
        externalService.notify(user);
    } catch (Exception e) {
        log.error("error", e);  // 异常被吞掉，事务不会回滚
    }
}
```

### 14.4 配置管理

```java
// ✅ 推荐：使用 @ConfigurationProperties
@Configuration
@ConfigurationProperties(prefix = "app")
@Data
public class AppProperties {
    private String name;
    private int timeout;
    private List<String> servers;
}

// ❌ 不推荐：大量 @Value
@Component
public class AppConfig {
    @Value("${app.name}")
    private String name;
    
    @Value("${app.timeout}")
    private int timeout;
    
    @Value("${app.servers}")
    private List<String> servers;
}
```

---

## 15. 总结

Spring Framework 5 的核心知识点：

1. **IoC 容器**：管理 Bean 的创建和生命周期
2. **依赖注入**：解耦组件之间的依赖关系
3. **AOP**：分离横切关注点，如日志、事务、安全
4. **事务管理**：声明式事务简化数据库操作
5. **JDBC 抽象**：JdbcTemplate 简化数据访问
6. **SpEL**：强大的表达式语言
7. **事件机制**：组件间松耦合通信

掌握这些核心概念，你就能够使用 Spring 构建企业级应用了。Spring Boot 在此基础上提供了自动配置，让开发更加便捷。
