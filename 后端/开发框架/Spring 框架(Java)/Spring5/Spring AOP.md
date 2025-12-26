

> 基于 Java 8 + Spring Boot 2.7.18，从零开始系统学习 Spring AOP。本笔记包含详细的概念讲解、代码示例和常见错误分析，帮助你真正理解面向切面编程的核心思想。

---

## 目录

1. [AOP 概述](#1.AOP概述)
2. [快速入门](#2.快速入门)
3. [核心概念详解](#3.核心概念详解)
4. [切入点表达式](#4.切入点表达式)
5. [五种通知类型](#5.五种通知类型)
6. [JoinPoint 与 ProceedingJoinPoint](#6.joinpoint-与-proceedingjoinpoint)
7. [切面优先级](#7.切面优先级)
8. [AOP 代理机制](#8.aop-代理机制)
9. [实战案例](#9.实战案例)
10. [常见错误与解决](#10.常见错误与解决)
11. [最佳实践](#11.最佳实践)
12. [总结](#12.总结)

---

## 1. AOP 概述

### 1.1 什么是 AOP？

**AOP（Aspect-Oriented Programming，面向切面编程）** 是一种编程范式，它允许你将横切关注点（Cross-Cutting Concerns）从业务逻辑中分离出来。

**什么是横切关注点？**

想象你在开发一个电商系统，有很多 Service 方法：

```java
public class OrderService {
    public void createOrder(Order order) {
        // 1. 记录日志
        log.info("开始创建订单");
        // 2. 检查权限
        checkPermission();
        // 3. 开启事务
        beginTransaction();
        
        try {
            // ===== 真正的业务逻辑 =====
            orderDao.save(order);
            inventoryService.deduct(order);
            // ===========================
            
            // 4. 提交事务
            commitTransaction();
        } catch (Exception e) {
            // 5. 回滚事务
            rollbackTransaction();
            // 6. 记录错误日志
            log.error("创建订单失败", e);
            throw e;
        }
        // 7. 记录日志
        log.info("订单创建成功");
    }
}
```

你会发现：日志、权限、事务这些代码在每个方法中都要写一遍，这就是**横切关注点**——它们"横切"了多个业务模块。

**AOP 的解决方案：**

把这些横切关注点抽取出来，统一处理：

```java
// 业务代码变得干净清爽
public class OrderService {
    public void createOrder(Order order) {
        orderDao.save(order);
        inventoryService.deduct(order);
    }
}

// 日志、事务等由切面统一处理
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

### 1.2 AOP 的优势

| 优势 | 说明 |
|------|------|
| 代码复用 | 横切逻辑只需写一次 |
| 解耦 | 业务代码与横切逻辑分离 |
| 易维护 | 修改横切逻辑只需改一处 |
| 非侵入性 | 不需要修改原有代码 |

### 1.3 AOP 的应用场景

- **日志记录**：方法调用日志、操作审计
- **性能监控**：方法执行时间统计
- **事务管理**：声明式事务（@Transactional）
- **权限控制**：方法级别的权限校验
- **缓存处理**：方法结果缓存（@Cacheable）
- **异常处理**：统一异常处理
- **参数校验**：方法参数的统一校验

### 1.4 AOP 与 OOP 的关系

AOP 不是要取代 OOP（面向对象编程），而是对 OOP 的补充。

| 编程范式 | 关注点 | 解决的问题 |
|----------|--------|------------|
| OOP | 纵向（类的继承层次） | 业务逻辑的封装和复用 |
| AOP | 横向（跨越多个类） | 横切关注点的封装和复用 |

---

## 2. 快速入门

### 2.1 添加依赖

```xml
<!-- pom.xml -->
<dependencies>
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Spring AOP -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-aop</artifactId>
    </dependency>
    
    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

**说明：** `spring-boot-starter-aop` 包含了 AspectJ 的依赖，Spring Boot 会自动配置 AOP。

### 2.2 创建业务类

```java
// 用户实体
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    private Long id;
    private String username;
    private String email;
}

// 用户服务接口
public interface UserService {
    User findById(Long id);
    User create(User user);
    void delete(Long id);
}

// 用户服务实现
@Service
@Slf4j
public class UserServiceImpl implements UserService {
    
    @Override
    public User findById(Long id) {
        log.info("查询用户: id={}", id);
        // 模拟数据库查询
        return new User(id, "user" + id, "user" + id + "@example.com");
    }
    
    @Override
    public User create(User user) {
        log.info("创建用户: {}", user);
        user.setId(System.currentTimeMillis());
        return user;
    }
    
    @Override
    public void delete(Long id) {
        log.info("删除用户: id={}", id);
        if (id <= 0) {
            throw new IllegalArgumentException("ID 必须大于 0");
        }
    }
}
```

### 2.3 创建第一个切面

```java
@Aspect      // 标记为切面类
@Component   // 注册为 Spring Bean
@Slf4j
public class LoggingAspect {
    
    /**
     * 前置通知：在目标方法执行前执行
     * execution(...) 是切入点表达式，指定要拦截哪些方法
     */
    @Before("execution(* com.example.service.*.*(..))")
    public void beforeAdvice(JoinPoint joinPoint) {
        String methodName = joinPoint.getSignature().getName();
        Object[] args = joinPoint.getArgs();
        log.info("【前置通知】方法: {}, 参数: {}", methodName, Arrays.toString(args));
    }
    
    /**
     * 后置通知：在目标方法正常返回后执行
     */
    @AfterReturning(
        pointcut = "execution(* com.example.service.*.*(..))",
        returning = "result"
    )
    public void afterReturningAdvice(JoinPoint joinPoint, Object result) {
        String methodName = joinPoint.getSignature().getName();
        log.info("【后置通知】方法: {}, 返回值: {}", methodName, result);
    }
    
    /**
     * 异常通知：在目标方法抛出异常后执行
     */
    @AfterThrowing(
        pointcut = "execution(* com.example.service.*.*(..))",
        throwing = "ex"
    )
    public void afterThrowingAdvice(JoinPoint joinPoint, Exception ex) {
        String methodName = joinPoint.getSignature().getName();
        log.error("【异常通知】方法: {}, 异常: {}", methodName, ex.getMessage());
    }
}
```

### 2.4 测试

```java
@RestController
@RequestMapping("/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @GetMapping("/{id}")
    public User getById(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    @PostMapping
    public User create(@RequestBody User user) {
        return userService.create(user);
    }
    
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        userService.delete(id);
    }
}
```

访问 `GET /users/1`，控制台输出：

```
【前置通知】方法: findById, 参数: [1]
查询用户: id=1
【后置通知】方法: findById, 返回值: User(id=1, username=user1, email=user1@example.com)
```

---

## 3. 核心概念详解

### 3.1 术语表

| 术语 | 英文 | 说明 | 类比 |
|------|------|------|------|
| 切面 | Aspect | 横切关注点的模块化 | 一个"功能模块"，如日志模块 |
| 连接点 | Join Point | 程序执行的某个点 | 可以被拦截的"时机" |
| 切入点 | Pointcut | 匹配连接点的表达式 | 指定要拦截"哪些方法" |
| 通知 | Advice | 在切入点执行的动作 | 拦截后"做什么" |
| 目标对象 | Target | 被代理的原始对象 | 原始的业务类 |
| 代理 | Proxy | AOP 创建的代理对象 | 增强后的对象 |
| 织入 | Weaving | 将切面应用到目标对象的过程 | "组装"的过程 |

### 3.2 图解 AOP 执行流程

```
客户端调用
    ↓
代理对象（Proxy）
    ↓
┌─────────────────────────────────────┐
│  @Around（前半部分）                  │
│      ↓                              │
│  @Before                            │
│      ↓                              │
│  目标方法执行                         │
│      ↓                              │
│  @AfterReturning（正常）             │
│  或 @AfterThrowing（异常）           │
│      ↓                              │
│  @After                             │
│      ↓                              │
│  @Around（后半部分）                  │
└─────────────────────────────────────┘
    ↓
返回结果
```

### 3.3 切面（Aspect）

切面是 AOP 的核心，它封装了横切关注点的逻辑。

```java
@Aspect      // 声明这是一个切面
@Component   // 必须注册为 Spring Bean
public class MyAspect {
    
    // 切入点定义
    @Pointcut("execution(* com.example.service.*.*(..))")
    public void serviceLayer() {}
    
    // 通知方法
    @Before("serviceLayer()")
    public void beforeAdvice() {
        // 前置逻辑
    }
}
```

### 3.4 连接点（Join Point）

连接点是程序执行过程中的某个点，Spring AOP 只支持**方法级别**的连接点。

**Spring AOP 支持的连接点：**
- 方法执行（Method Execution）

**AspectJ 支持更多连接点：**
- 方法调用（Method Call）
- 构造器执行（Constructor Execution）
- 字段访问（Field Access）
- 异常处理（Exception Handler）
- 等等...

### 3.5 切入点（Pointcut）

切入点是一个表达式，用于匹配要拦截的连接点。

```java
@Aspect
@Component
public class MyAspect {
    
    // 定义可重用的切入点
    @Pointcut("execution(* com.example.service.*.*(..))")
    public void serviceLayer() {}
    
    @Pointcut("execution(* com.example.dao.*.*(..))")
    public void daoLayer() {}
    
    // 组合切入点
    @Pointcut("serviceLayer() || daoLayer()")
    public void businessLayer() {}
    
    // 使用切入点
    @Before("serviceLayer()")
    public void beforeService() {}
    
    @Before("businessLayer()")
    public void beforeBusiness() {}
}
```

### 3.6 通知（Advice）

通知定义了在切入点"做什么"以及"什么时候做"。

| 通知类型 | 注解 | 执行时机 |
|----------|------|----------|
| 前置通知 | @Before | 目标方法执行前 |
| 后置通知 | @AfterReturning | 目标方法正常返回后 |
| 异常通知 | @AfterThrowing | 目标方法抛出异常后 |
| 最终通知 | @After | 目标方法执行后（无论是否异常） |
| 环绕通知 | @Around | 包围目标方法，可完全控制执行 |


---

## 4. 切入点表达式

切入点表达式是 AOP 的核心，它决定了哪些方法会被拦截。

### 4.1 execution 表达式（最常用）

**语法格式：**

```
execution(修饰符? 返回类型 包名.类名.方法名(参数) 异常?)
```

**各部分说明：**

| 部分 | 是否必需 | 说明 | 示例 |
|------|----------|------|------|
| 修饰符 | 可选 | public/private 等 | public |
| 返回类型 | 必需 | 方法返回类型 | void, String, * |
| 包名.类名 | 可选 | 全限定类名 | com.example.service.UserService |
| 方法名 | 必需 | 方法名称 | findById, find*, * |
| 参数 | 必需 | 参数类型列表 | (), (Long), (..), (*) |
| 异常 | 可选 | 抛出的异常类型 | throws Exception |

**通配符说明：**

| 通配符 | 说明 | 示例 |
|--------|------|------|
| `*` | 匹配任意字符（单个部分） | `*Service` 匹配 UserService |
| `..` | 匹配任意字符（多个部分） | `com.example..` 匹配所有子包 |
| `+` | 匹配指定类及其子类 | `UserService+` |

### 4.2 execution 表达式示例

```java
@Aspect
@Component
public class PointcutExamples {
    
    // ============ 匹配方法 ============
    
    // 匹配 UserService 的所有方法
    @Pointcut("execution(* com.example.service.UserService.*(..))")
    public void userServiceMethods() {}
    
    // 匹配所有 find 开头的方法
    @Pointcut("execution(* com.example.service.*.find*(..))")
    public void findMethods() {}
    
    // 匹配所有 public 方法
    @Pointcut("execution(public * *(..))")
    public void publicMethods() {}
    
    // 匹配返回 User 类型的方法
    @Pointcut("execution(com.example.entity.User *(..))")
    public void returnUserMethods() {}
    
    // ============ 匹配包 ============
    
    // 匹配 service 包下所有类的所有方法
    @Pointcut("execution(* com.example.service.*.*(..))")
    public void servicePackage() {}
    
    // 匹配 service 包及其子包下所有类的所有方法
    @Pointcut("execution(* com.example.service..*.*(..))")
    public void servicePackageAndSubPackages() {}
    
    // ============ 匹配参数 ============
    
    // 匹配无参方法
    @Pointcut("execution(* com.example.service.*.*())")
    public void noArgMethods() {}
    
    // 匹配只有一个 Long 参数的方法
    @Pointcut("execution(* com.example.service.*.*(Long))")
    public void singleLongArgMethods() {}
    
    // 匹配第一个参数是 Long 的方法（后面可以有任意参数）
    @Pointcut("execution(* com.example.service.*.*(Long, ..))")
    public void firstArgLongMethods() {}
    
    // 匹配任意参数的方法
    @Pointcut("execution(* com.example.service.*.*(..))")
    public void anyArgMethods() {}
    
    // ============ 组合表达式 ============
    
    // 匹配 service 或 dao 包
    @Pointcut("execution(* com.example.service.*.*(..)) || execution(* com.example.dao.*.*(..))")
    public void serviceOrDao() {}
    
    // 匹配 service 包但排除 find 方法
    @Pointcut("execution(* com.example.service.*.*(..)) && !execution(* com.example.service.*.find*(..))")
    public void serviceExceptFind() {}
}
```

### 4.3 @annotation 表达式

匹配带有指定注解的方法。

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Loggable {
    String value() default "";
}

// 切面
@Aspect
@Component
public class AnnotationAspect {
    
    // 匹配带有 @Loggable 注解的方法
    @Pointcut("@annotation(com.example.annotation.Loggable)")
    public void loggableMethods() {}
    
    // 获取注解信息
    @Before("@annotation(loggable)")
    public void beforeLoggable(JoinPoint jp, Loggable loggable) {
        System.out.println("注解值: " + loggable.value());
    }
}

// 使用
@Service
public class UserService {
    
    @Loggable("查询用户")
    public User findById(Long id) {
        return userDao.findById(id);
    }
}
```

### 4.4 @within 表达式

匹配带有指定注解的类中的所有方法。

```java
// 匹配所有 @Service 注解的类的方法
@Pointcut("@within(org.springframework.stereotype.Service)")
public void serviceBeans() {}

// 匹配所有 @RestController 注解的类的方法
@Pointcut("@within(org.springframework.web.bind.annotation.RestController)")
public void controllerBeans() {}
```

### 4.5 within 表达式

匹配指定类型内的所有方法。

```java
// 匹配 UserService 类的所有方法
@Pointcut("within(com.example.service.UserService)")
public void withinUserService() {}

// 匹配 service 包下所有类的方法
@Pointcut("within(com.example.service.*)")
public void withinServicePackage() {}

// 匹配 service 包及子包下所有类的方法
@Pointcut("within(com.example.service..*)")
public void withinServiceAndSubPackages() {}
```

### 4.6 bean 表达式

匹配指定 Bean 名称的方法（Spring AOP 特有）。

```java
// 匹配名为 userService 的 Bean
@Pointcut("bean(userService)")
public void userServiceBean() {}

// 匹配所有以 Service 结尾的 Bean
@Pointcut("bean(*Service)")
public void allServiceBeans() {}

// 匹配所有以 user 开头的 Bean
@Pointcut("bean(user*)")
public void userBeans() {}
```

### 4.7 args 表达式

匹配参数类型的方法，并可以绑定参数。

```java
@Aspect
@Component
public class ArgsAspect {
    
    // 匹配第一个参数是 Long 类型的方法
    @Pointcut("args(Long, ..)")
    public void firstArgLong() {}
    
    // 绑定参数
    @Before("execution(* com.example.service.*.*(..)) && args(id, ..)")
    public void beforeWithId(Long id) {
        System.out.println("ID 参数: " + id);
    }
    
    // 绑定多个参数
    @Before("execution(* com.example.service.*.*(..)) && args(id, name)")
    public void beforeWithIdAndName(Long id, String name) {
        System.out.println("ID: " + id + ", Name: " + name);
    }
}
```

### 4.8 this 和 target 表达式

```java
// this：匹配代理对象是指定类型的方法
@Pointcut("this(com.example.service.UserService)")
public void thisUserService() {}

// target：匹配目标对象是指定类型的方法
@Pointcut("target(com.example.service.UserService)")
public void targetUserService() {}
```

**this vs target 的区别：**
- `this`：匹配的是代理对象的类型
- `target`：匹配的是被代理的目标对象的类型

在使用 JDK 动态代理时，代理对象和目标对象类型可能不同。

---

## 5. 五种通知类型

### 5.1 @Before（前置通知）

在目标方法执行**之前**执行。

```java
@Aspect
@Component
@Slf4j
public class BeforeAspect {
    
    @Before("execution(* com.example.service.*.*(..))")
    public void beforeAdvice(JoinPoint joinPoint) {
        // 获取方法签名
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String methodName = signature.getName();
        
        // 获取参数
        Object[] args = joinPoint.getArgs();
        
        // 获取目标对象
        Object target = joinPoint.getTarget();
        
        log.info("【Before】类: {}, 方法: {}, 参数: {}", 
                target.getClass().getSimpleName(), methodName, Arrays.toString(args));
    }
    
    // 带条件的前置通知
    @Before("execution(* com.example.service.*.*(..)) && args(id, ..)")
    public void beforeWithId(Long id) {
        if (id <= 0) {
            throw new IllegalArgumentException("ID 必须大于 0");
        }
        log.info("【Before】ID 参数校验通过: {}", id);
    }
}
```

**使用场景：**
- 参数校验
- 权限检查
- 日志记录

### 5.2 @AfterReturning（后置通知）

在目标方法**正常返回后**执行，可以获取返回值。

```java
@Aspect
@Component
@Slf4j
public class AfterReturningAspect {
    
    @AfterReturning(
        pointcut = "execution(* com.example.service.*.*(..))",
        returning = "result"  // 绑定返回值
    )
    public void afterReturningAdvice(JoinPoint joinPoint, Object result) {
        String methodName = joinPoint.getSignature().getName();
        log.info("【AfterReturning】方法: {}, 返回值: {}", methodName, result);
    }
    
    // 指定返回值类型
    @AfterReturning(
        pointcut = "execution(* com.example.service.*.find*(..))",
        returning = "user"
    )
    public void afterReturningUser(User user) {
        if (user != null) {
            log.info("【AfterReturning】查询到用户: {}", user.getUsername());
        }
    }
    
    // 可以修改返回值（但不推荐，应该用 @Around）
    @AfterReturning(
        pointcut = "execution(* com.example.service.*.find*(..))",
        returning = "result"
    )
    public void modifyResult(JoinPoint jp, User result) {
        if (result != null) {
            // 注意：这里修改的是对象的属性，不是替换对象
            result.setEmail(result.getEmail().toLowerCase());
        }
    }
}
```

**使用场景：**
- 记录返回结果
- 结果后处理
- 审计日志

### 5.3 @AfterThrowing（异常通知）

在目标方法**抛出异常后**执行。

```java
@Aspect
@Component
@Slf4j
public class AfterThrowingAspect {
    
    @AfterThrowing(
        pointcut = "execution(* com.example.service.*.*(..))",
        throwing = "ex"  // 绑定异常
    )
    public void afterThrowingAdvice(JoinPoint joinPoint, Exception ex) {
        String methodName = joinPoint.getSignature().getName();
        log.error("【AfterThrowing】方法: {}, 异常: {}", methodName, ex.getMessage());
    }
    
    // 只捕获特定类型的异常
    @AfterThrowing(
        pointcut = "execution(* com.example.service.*.*(..))",
        throwing = "ex"
    )
    public void afterThrowingBusinessException(BusinessException ex) {
        log.error("【AfterThrowing】业务异常: code={}, message={}", 
                ex.getCode(), ex.getMessage());
        // 可以发送告警通知
    }
    
    // 捕获所有 Throwable
    @AfterThrowing(
        pointcut = "execution(* com.example.service.*.*(..))",
        throwing = "t"
    )
    public void afterThrowingAll(Throwable t) {
        log.error("【AfterThrowing】异常类型: {}", t.getClass().getName());
    }
}
```

**注意：** 异常通知不能阻止异常传播，异常仍会向上抛出。如果需要处理异常，使用 `@Around`。

**使用场景：**
- 异常日志记录
- 异常告警通知
- 异常统计

### 5.4 @After（最终通知）

在目标方法执行**之后**执行，无论是否发生异常（类似 finally）。

```java
@Aspect
@Component
@Slf4j
public class AfterAspect {
    
    @After("execution(* com.example.service.*.*(..))")
    public void afterAdvice(JoinPoint joinPoint) {
        String methodName = joinPoint.getSignature().getName();
        log.info("【After】方法执行完毕: {}", methodName);
    }
    
    // 资源清理
    @After("execution(* com.example.service.*.*(..))")
    public void cleanupResources() {
        // 清理 ThreadLocal
        // 释放资源
        log.info("【After】资源清理完成");
    }
}
```

**使用场景：**
- 资源清理
- 释放锁
- 清理 ThreadLocal

### 5.5 @Around（环绕通知）

最强大的通知类型，可以完全控制目标方法的执行。

```java
@Aspect
@Component
@Slf4j
public class AroundAspect {
    
    @Around("execution(* com.example.service.*.*(..))")
    public Object aroundAdvice(ProceedingJoinPoint pjp) throws Throwable {
        String methodName = pjp.getSignature().getName();
        Object[] args = pjp.getArgs();
        
        log.info("【Around-前】方法: {}, 参数: {}", methodName, Arrays.toString(args));
        long startTime = System.currentTimeMillis();
        
        Object result = null;
        try {
            // ===== 执行目标方法 =====
            result = pjp.proceed();  // 必须调用，否则目标方法不会执行
            // 也可以传入修改后的参数：pjp.proceed(newArgs)
            
            long duration = System.currentTimeMillis() - startTime;
            log.info("【Around-后】方法: {}, 耗时: {}ms, 返回值: {}", 
                    methodName, duration, result);
            
            return result;  // 必须返回结果
            
        } catch (Throwable e) {
            log.error("【Around-异常】方法: {}, 异常: {}", methodName, e.getMessage());
            throw e;  // 可以选择抛出或处理异常
        }
    }
    
    // 修改参数
    @Around("execution(* com.example.service.*.create*(..))")
    public Object modifyArgs(ProceedingJoinPoint pjp) throws Throwable {
        Object[] args = pjp.getArgs();
        
        // 修改参数
        if (args.length > 0 && args[0] instanceof User) {
            User user = (User) args[0];
            user.setUsername(user.getUsername().trim());
        }
        
        return pjp.proceed(args);  // 使用修改后的参数
    }
    
    // 修改返回值
    @Around("execution(* com.example.service.*.find*(..))")
    public Object modifyResult(ProceedingJoinPoint pjp) throws Throwable {
        Object result = pjp.proceed();
        
        // 修改返回值
        if (result instanceof User) {
            User user = (User) result;
            user.setEmail("***");  // 脱敏
        }
        
        return result;
    }
    
    // 异常处理
    @Around("execution(* com.example.service.*.*(..))")
    public Object handleException(ProceedingJoinPoint pjp) throws Throwable {
        try {
            return pjp.proceed();
        } catch (BusinessException e) {
            // 业务异常，返回默认值
            log.warn("业务异常，返回默认值: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            // 其他异常，继续抛出
            throw e;
        }
    }
}
```

**@Around 的能力：**
- 控制是否执行目标方法
- 修改传入参数
- 修改返回值
- 处理异常
- 多次调用目标方法

**使用场景：**
- 性能监控
- 缓存处理
- 事务管理
- 重试机制
- 熔断降级


---

## 6. JoinPoint 与 ProceedingJoinPoint

### 6.1 JoinPoint

`JoinPoint` 是所有通知方法都可以使用的参数，提供了访问连接点信息的方法。

```java
@Aspect
@Component
@Slf4j
public class JoinPointDemo {
    
    @Before("execution(* com.example.service.*.*(..))")
    public void demonstrateJoinPoint(JoinPoint joinPoint) {
        
        // ============ 获取方法签名 ============
        Signature signature = joinPoint.getSignature();
        
        // 方法名
        String methodName = signature.getName();
        log.info("方法名: {}", methodName);
        
        // 声明类型（定义方法的类）
        String declaringTypeName = signature.getDeclaringTypeName();
        log.info("声明类型: {}", declaringTypeName);
        
        // 完整签名
        String fullSignature = signature.toLongString();
        log.info("完整签名: {}", fullSignature);
        
        // ============ 获取方法签名（更详细） ============
        if (signature instanceof MethodSignature) {
            MethodSignature methodSignature = (MethodSignature) signature;
            
            // 返回类型
            Class<?> returnType = methodSignature.getReturnType();
            log.info("返回类型: {}", returnType.getName());
            
            // 参数类型
            Class<?>[] parameterTypes = methodSignature.getParameterTypes();
            log.info("参数类型: {}", Arrays.toString(parameterTypes));
            
            // 参数名称
            String[] parameterNames = methodSignature.getParameterNames();
            log.info("参数名称: {}", Arrays.toString(parameterNames));
            
            // 获取 Method 对象
            Method method = methodSignature.getMethod();
            log.info("Method 对象: {}", method);
            
            // 获取方法上的注解
            Loggable loggable = method.getAnnotation(Loggable.class);
            if (loggable != null) {
                log.info("@Loggable 注解值: {}", loggable.value());
            }
        }
        
        // ============ 获取参数 ============
        Object[] args = joinPoint.getArgs();
        log.info("参数值: {}", Arrays.toString(args));
        
        // ============ 获取目标对象 ============
        Object target = joinPoint.getTarget();
        log.info("目标对象: {}", target.getClass().getName());
        
        // ============ 获取代理对象 ============
        Object proxy = joinPoint.getThis();
        log.info("代理对象: {}", proxy.getClass().getName());
        
        // ============ 获取连接点类型 ============
        String kind = joinPoint.getKind();
        log.info("连接点类型: {}", kind);  // method-execution
    }
}
```

### 6.2 ProceedingJoinPoint

`ProceedingJoinPoint` 是 `JoinPoint` 的子接口，只能在 `@Around` 通知中使用，提供了执行目标方法的能力。

```java
@Aspect
@Component
@Slf4j
public class ProceedingJoinPointDemo {
    
    @Around("execution(* com.example.service.*.*(..))")
    public Object demonstrateProceedingJoinPoint(ProceedingJoinPoint pjp) throws Throwable {
        
        // ProceedingJoinPoint 继承了 JoinPoint 的所有方法
        String methodName = pjp.getSignature().getName();
        Object[] args = pjp.getArgs();
        
        // ============ 执行目标方法 ============
        
        // 方式1：使用原始参数
        Object result = pjp.proceed();
        
        // 方式2：使用修改后的参数
        // Object[] newArgs = modifyArgs(args);
        // Object result = pjp.proceed(newArgs);
        
        return result;
    }
    
    // 实际应用：参数校验和修改
    @Around("execution(* com.example.service.*.create*(..))")
    public Object validateAndModifyArgs(ProceedingJoinPoint pjp) throws Throwable {
        Object[] args = pjp.getArgs();
        
        for (int i = 0; i < args.length; i++) {
            if (args[i] instanceof String) {
                // 去除字符串首尾空格
                args[i] = ((String) args[i]).trim();
            }
            if (args[i] instanceof User) {
                User user = (User) args[i];
                // 用户名转小写
                user.setUsername(user.getUsername().toLowerCase());
            }
        }
        
        // 使用修改后的参数执行
        return pjp.proceed(args);
    }
}
```

### 6.3 获取方法注解

```java
@Aspect
@Component
@Slf4j
public class AnnotationAspect {
    
    // 方式1：通过 JoinPoint 获取
    @Before("@annotation(com.example.annotation.Loggable)")
    public void getAnnotationFromJoinPoint(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        
        Loggable loggable = method.getAnnotation(Loggable.class);
        log.info("注解值: {}", loggable.value());
    }
    
    // 方式2：通过参数绑定获取（推荐）
    @Before("@annotation(loggable)")
    public void getAnnotationByBinding(JoinPoint joinPoint, Loggable loggable) {
        log.info("注解值: {}", loggable.value());
    }
    
    // 获取类上的注解
    @Before("@within(service)")
    public void getClassAnnotation(JoinPoint joinPoint, Service service) {
        log.info("Service 注解");
    }
}
```

---

## 7. 切面优先级

当多个切面作用于同一个方法时，需要控制执行顺序。

### 7.1 使用 @Order 注解

```java
@Aspect
@Component
@Order(1)  // 数字越小，优先级越高
@Slf4j
public class SecurityAspect {
    
    @Before("execution(* com.example.service.*.*(..))")
    public void checkSecurity() {
        log.info("【1】安全检查");
    }
}

@Aspect
@Component
@Order(2)
@Slf4j
public class LoggingAspect {
    
    @Before("execution(* com.example.service.*.*(..))")
    public void logBefore() {
        log.info("【2】日志记录");
    }
}

@Aspect
@Component
@Order(3)
@Slf4j
public class PerformanceAspect {
    
    @Before("execution(* com.example.service.*.*(..))")
    public void recordPerformance() {
        log.info("【3】性能监控");
    }
}
```

### 7.2 执行顺序

```
请求进入
    ↓
SecurityAspect.before()    [Order=1，最先执行]
    ↓
LoggingAspect.before()     [Order=2]
    ↓
PerformanceAspect.before() [Order=3]
    ↓
目标方法执行
    ↓
PerformanceAspect.after()  [Order=3，最先执行]
    ↓
LoggingAspect.after()      [Order=2]
    ↓
SecurityAspect.after()     [Order=1，最后执行]
    ↓
返回结果
```

**记忆口诀：** 
- Before 通知：Order 小的先执行（先进）
- After 通知：Order 大的先执行（后出）
- 类似"洋葱模型"

### 7.3 实现 Ordered 接口

```java
@Aspect
@Component
@Slf4j
public class DynamicOrderAspect implements Ordered {
    
    @Override
    public int getOrder() {
        // 可以动态计算优先级
        return 10;
    }
    
    @Before("execution(* com.example.service.*.*(..))")
    public void before() {
        log.info("动态优先级切面");
    }
}
```

---

## 8. AOP 代理机制

### 8.1 两种代理方式

Spring AOP 使用两种代理方式：

| 代理方式 | 条件 | 原理 | 特点 |
|----------|------|------|------|
| JDK 动态代理 | 目标类实现了接口 | 基于接口 | 只能代理接口方法 |
| CGLIB 代理 | 目标类没有实现接口 | 基于继承 | 可以代理类的方法 |

### 8.2 JDK 动态代理

```java
// 接口
public interface UserService {
    User findById(Long id);
}

// 实现类
@Service
public class UserServiceImpl implements UserService {
    @Override
    public User findById(Long id) {
        return new User(id, "user", "user@example.com");
    }
}

// Spring 会使用 JDK 动态代理
// 代理对象实现 UserService 接口，但不是 UserServiceImpl 的子类
```

**JDK 动态代理的限制：**
- 只能代理接口中定义的方法
- 代理对象不能转换为实现类类型

```java
@Autowired
private UserService userService;  // ✓ 正确

@Autowired
private UserServiceImpl userServiceImpl;  // ✗ 可能报错（如果使用 JDK 代理）
```

### 8.3 CGLIB 代理

```java
// 没有实现接口的类
@Service
public class OrderService {
    public Order findById(Long id) {
        return new Order(id, "order");
    }
}

// Spring 会使用 CGLIB 代理
// 代理对象是 OrderService 的子类
```

**CGLIB 代理的限制：**
- 不能代理 `final` 类
- 不能代理 `final` 方法
- 不能代理 `private` 方法

### 8.4 强制使用 CGLIB

```java
// 方式1：配置文件
// application.yml
spring:
  aop:
    proxy-target-class: true  # 强制使用 CGLIB

// 方式2：注解配置
@EnableAspectJAutoProxy(proxyTargetClass = true)
@Configuration
public class AopConfig {
}
```

### 8.5 代理对象的特点

```java
@Service
public class UserServiceImpl implements UserService {
    
    @Override
    public User findById(Long id) {
        return new User(id, "user", "user@example.com");
    }
    
    public void internalMethod() {
        // 内部方法
    }
    
    public void callInternal() {
        // 直接调用内部方法，不会触发 AOP！
        this.internalMethod();  // this 是原始对象，不是代理对象
    }
}
```

**重要：** 自调用（同一个类中方法互相调用）不会触发 AOP，因为调用的是原始对象而不是代理对象。

---

## 9. 实战案例

### 9.1 方法执行时间统计

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Timed {
    String value() default "";  // 操作名称
    boolean logArgs() default false;  // 是否记录参数
    boolean logResult() default false;  // 是否记录返回值
}

// 切面实现
@Aspect
@Component
@Slf4j
public class TimedAspect {
    
    @Around("@annotation(timed)")
    public Object measureTime(ProceedingJoinPoint pjp, Timed timed) throws Throwable {
        String operationName = timed.value().isEmpty() 
            ? pjp.getSignature().toShortString() 
            : timed.value();
        
        // 记录参数
        if (timed.logArgs()) {
            log.info("[{}] 参数: {}", operationName, Arrays.toString(pjp.getArgs()));
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            Object result = pjp.proceed();
            
            long duration = System.currentTimeMillis() - startTime;
            
            // 记录返回值
            if (timed.logResult()) {
                log.info("[{}] 耗时: {}ms, 返回值: {}", operationName, duration, result);
            } else {
                log.info("[{}] 耗时: {}ms", operationName, duration);
            }
            
            // 慢方法告警
            if (duration > 1000) {
                log.warn("[{}] 方法执行过慢: {}ms", operationName, duration);
            }
            
            return result;
            
        } catch (Throwable e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("[{}] 执行失败，耗时: {}ms, 异常: {}", operationName, duration, e.getMessage());
            throw e;
        }
    }
}

// 使用
@Service
public class UserService {
    
    @Timed(value = "查询用户", logArgs = true, logResult = true)
    public User findById(Long id) {
        // 模拟耗时操作
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return new User(id, "user", "user@example.com");
    }
}
```

### 9.2 操作日志记录

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface OperationLog {
    String module() default "";      // 模块名称
    String operation() default "";   // 操作名称
    boolean saveArgs() default true; // 是否保存参数
}

// 操作日志实体
@Data
@Entity
@Table(name = "operation_log")
public class OperationLogEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String module;
    private String operation;
    private String method;
    private String args;
    private String result;
    private String errorMsg;
    private Long duration;
    private String operator;
    private String ip;
    private LocalDateTime createTime;
}

// 切面实现
@Aspect
@Component
@Slf4j
public class OperationLogAspect {
    
    @Autowired
    private OperationLogRepository logRepository;
    
    @Autowired
    private HttpServletRequest request;
    
    @Around("@annotation(operationLog)")
    public Object logOperation(ProceedingJoinPoint pjp, OperationLog operationLog) throws Throwable {
        OperationLogEntity logEntity = new OperationLogEntity();
        logEntity.setModule(operationLog.module());
        logEntity.setOperation(operationLog.operation());
        logEntity.setMethod(pjp.getSignature().toShortString());
        logEntity.setCreateTime(LocalDateTime.now());
        
        // 获取操作人（从 SecurityContext 或 Session 获取）
        logEntity.setOperator(getCurrentUser());
        
        // 获取 IP
        logEntity.setIp(getClientIp(request));
        
        // 保存参数
        if (operationLog.saveArgs()) {
            try {
                logEntity.setArgs(new ObjectMapper().writeValueAsString(pjp.getArgs()));
            } catch (Exception e) {
                logEntity.setArgs(Arrays.toString(pjp.getArgs()));
            }
        }
        
        long startTime = System.currentTimeMillis();
        
        try {
            Object result = pjp.proceed();
            
            logEntity.setDuration(System.currentTimeMillis() - startTime);
            logEntity.setResult("SUCCESS");
            
            return result;
            
        } catch (Throwable e) {
            logEntity.setDuration(System.currentTimeMillis() - startTime);
            logEntity.setResult("FAILED");
            logEntity.setErrorMsg(e.getMessage());
            throw e;
            
        } finally {
            // 异步保存日志
            CompletableFuture.runAsync(() -> logRepository.save(logEntity));
        }
    }
    
    private String getCurrentUser() {
        // 从 SecurityContext 获取当前用户
        return "admin";
    }
    
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}

// 使用
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @OperationLog(module = "用户管理", operation = "创建用户")
    @PostMapping
    public User create(@RequestBody User user) {
        return userService.create(user);
    }
    
    @OperationLog(module = "用户管理", operation = "删除用户")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        userService.delete(id);
    }
}
```

### 9.3 方法重试机制

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Retry {
    int maxAttempts() default 3;           // 最大重试次数
    long delay() default 1000;             // 重试间隔（毫秒）
    Class<? extends Throwable>[] include() default {};  // 需要重试的异常
    Class<? extends Throwable>[] exclude() default {};  // 不重试的异常
}

// 切面实现
@Aspect
@Component
@Slf4j
public class RetryAspect {
    
    @Around("@annotation(retry)")
    public Object retry(ProceedingJoinPoint pjp, Retry retry) throws Throwable {
        int maxAttempts = retry.maxAttempts();
        long delay = retry.delay();
        Class<? extends Throwable>[] includeExceptions = retry.include();
        Class<? extends Throwable>[] excludeExceptions = retry.exclude();
        
        String methodName = pjp.getSignature().toShortString();
        Throwable lastException = null;
        
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                log.info("[{}] 第 {} 次尝试", methodName, attempt);
                return pjp.proceed();
                
            } catch (Throwable e) {
                lastException = e;
                
                // 检查是否需要重试
                if (!shouldRetry(e, includeExceptions, excludeExceptions)) {
                    log.warn("[{}] 异常不在重试范围内，直接抛出: {}", methodName, e.getClass().getName());
                    throw e;
                }
                
                if (attempt < maxAttempts) {
                    log.warn("[{}] 第 {} 次尝试失败，{}ms 后重试: {}", 
                            methodName, attempt, delay, e.getMessage());
                    Thread.sleep(delay);
                } else {
                    log.error("[{}] 重试 {} 次后仍然失败", methodName, maxAttempts);
                }
            }
        }
        
        throw lastException;
    }
    
    private boolean shouldRetry(Throwable e, 
                               Class<? extends Throwable>[] include,
                               Class<? extends Throwable>[] exclude) {
        // 检查排除列表
        for (Class<? extends Throwable> excludeClass : exclude) {
            if (excludeClass.isInstance(e)) {
                return false;
            }
        }
        
        // 如果没有指定包含列表，默认重试所有异常
        if (include.length == 0) {
            return true;
        }
        
        // 检查包含列表
        for (Class<? extends Throwable> includeClass : include) {
            if (includeClass.isInstance(e)) {
                return true;
            }
        }
        
        return false;
    }
}

// 使用
@Service
public class ExternalService {
    
    @Retry(maxAttempts = 3, delay = 2000, include = {IOException.class, TimeoutException.class})
    public String callExternalApi() throws IOException {
        // 调用外部 API，可能失败
        return restTemplate.getForObject("http://external-api/data", String.class);
    }
}
```

### 9.4 分布式锁

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface DistributedLock {
    String key();                    // 锁的 key
    long timeout() default 30000;    // 锁超时时间（毫秒）
    long waitTime() default 5000;    // 等待获取锁的时间（毫秒）
}

// 切面实现
@Aspect
@Component
@Slf4j
public class DistributedLockAspect {
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Around("@annotation(distributedLock)")
    public Object lock(ProceedingJoinPoint pjp, DistributedLock distributedLock) throws Throwable {
        String key = parseKey(distributedLock.key(), pjp);
        String lockKey = "lock:" + key;
        String lockValue = UUID.randomUUID().toString();
        
        long timeout = distributedLock.timeout();
        long waitTime = distributedLock.waitTime();
        long startTime = System.currentTimeMillis();
        
        try {
            // 尝试获取锁
            while (System.currentTimeMillis() - startTime < waitTime) {
                Boolean acquired = redisTemplate.opsForValue()
                        .setIfAbsent(lockKey, lockValue, timeout, TimeUnit.MILLISECONDS);
                
                if (Boolean.TRUE.equals(acquired)) {
                    log.info("获取分布式锁成功: {}", lockKey);
                    return pjp.proceed();
                }
                
                // 等待一段时间后重试
                Thread.sleep(100);
            }
            
            throw new RuntimeException("获取分布式锁超时: " + lockKey);
            
        } finally {
            // 释放锁（只释放自己的锁）
            String currentValue = redisTemplate.opsForValue().get(lockKey);
            if (lockValue.equals(currentValue)) {
                redisTemplate.delete(lockKey);
                log.info("释放分布式锁: {}", lockKey);
            }
        }
    }
    
    private String parseKey(String keyExpression, ProceedingJoinPoint pjp) {
        // 支持 SpEL 表达式解析
        if (keyExpression.startsWith("#")) {
            // 解析 SpEL 表达式
            MethodSignature signature = (MethodSignature) pjp.getSignature();
            String[] parameterNames = signature.getParameterNames();
            Object[] args = pjp.getArgs();
            
            StandardEvaluationContext context = new StandardEvaluationContext();
            for (int i = 0; i < parameterNames.length; i++) {
                context.setVariable(parameterNames[i], args[i]);
            }
            
            ExpressionParser parser = new SpelExpressionParser();
            return parser.parseExpression(keyExpression).getValue(context, String.class);
        }
        
        return keyExpression;
    }
}

// 使用
@Service
public class OrderService {
    
    @DistributedLock(key = "'order:' + #orderId", timeout = 10000)
    public void processOrder(Long orderId) {
        // 处理订单，同一订单同时只能有一个线程处理
    }
}
```


### 9.5 权限校验

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePermission {
    String[] value();  // 需要的权限
    Logical logical() default Logical.AND;  // 权限之间的逻辑关系
}

public enum Logical {
    AND,  // 需要所有权限
    OR    // 需要任一权限
}

// 切面实现
@Aspect
@Component
@Slf4j
public class PermissionAspect {
    
    @Before("@annotation(requirePermission)")
    public void checkPermission(JoinPoint joinPoint, RequirePermission requirePermission) {
        String[] requiredPermissions = requirePermission.value();
        Logical logical = requirePermission.logical();
        
        // 获取当前用户的权限
        Set<String> userPermissions = getCurrentUserPermissions();
        
        boolean hasPermission;
        if (logical == Logical.AND) {
            // 需要所有权限
            hasPermission = userPermissions.containsAll(Arrays.asList(requiredPermissions));
        } else {
            // 需要任一权限
            hasPermission = Arrays.stream(requiredPermissions)
                    .anyMatch(userPermissions::contains);
        }
        
        if (!hasPermission) {
            log.warn("权限不足，需要: {}, 拥有: {}", 
                    Arrays.toString(requiredPermissions), userPermissions);
            throw new AccessDeniedException("权限不足");
        }
        
        log.info("权限校验通过: {}", Arrays.toString(requiredPermissions));
    }
    
    private Set<String> getCurrentUserPermissions() {
        // 从 SecurityContext 或 Session 获取当前用户权限
        // 这里简化处理
        return Set.of("user:read", "user:write", "order:read");
    }
}

// 使用
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    @RequirePermission({"admin:read", "admin:write"})
    @GetMapping("/users")
    public List<User> listUsers() {
        return userService.findAll();
    }
    
    @RequirePermission(value = {"admin:delete", "super:admin"}, logical = Logical.OR)
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}
```

### 9.6 缓存切面

```java
// 自定义注解
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface SimpleCache {
    String key();                    // 缓存 key
    long ttl() default 300;          // 过期时间（秒）
    boolean cacheNull() default false;  // 是否缓存 null 值
}

// 切面实现
@Aspect
@Component
@Slf4j
public class SimpleCacheAspect {
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Around("@annotation(simpleCache)")
    public Object cache(ProceedingJoinPoint pjp, SimpleCache simpleCache) throws Throwable {
        String key = parseKey(simpleCache.key(), pjp);
        String cacheKey = "cache:" + key;
        
        // 尝试从缓存获取
        String cachedValue = redisTemplate.opsForValue().get(cacheKey);
        if (cachedValue != null) {
            log.info("缓存命中: {}", cacheKey);
            
            // 处理 null 值标记
            if ("__NULL__".equals(cachedValue)) {
                return null;
            }
            
            // 反序列化
            MethodSignature signature = (MethodSignature) pjp.getSignature();
            Class<?> returnType = signature.getReturnType();
            return objectMapper.readValue(cachedValue, returnType);
        }
        
        log.info("缓存未命中: {}", cacheKey);
        
        // 执行方法
        Object result = pjp.proceed();
        
        // 缓存结果
        if (result != null) {
            String value = objectMapper.writeValueAsString(result);
            redisTemplate.opsForValue().set(cacheKey, value, simpleCache.ttl(), TimeUnit.SECONDS);
            log.info("缓存写入: {}", cacheKey);
        } else if (simpleCache.cacheNull()) {
            // 缓存 null 值，防止缓存穿透
            redisTemplate.opsForValue().set(cacheKey, "__NULL__", 60, TimeUnit.SECONDS);
            log.info("缓存 null 值: {}", cacheKey);
        }
        
        return result;
    }
    
    private String parseKey(String keyExpression, ProceedingJoinPoint pjp) {
        // SpEL 表达式解析（同上）
        // ...
        return keyExpression;
    }
}

// 使用
@Service
public class UserService {
    
    @SimpleCache(key = "'user:' + #id", ttl = 600)
    public User findById(Long id) {
        log.info("从数据库查询用户: {}", id);
        return userDao.findById(id);
    }
}
```

---

## 10. 常见错误与解决

### 10.1 AOP 不生效

#### 问题1：自调用不触发 AOP

```java
@Service
public class UserService {
    
    @Transactional
    public void methodA() {
        // 直接调用 methodB，AOP 不生效！
        this.methodB();  // this 是原始对象，不是代理对象
    }
    
    @Transactional
    public void methodB() {
        // ...
    }
}
```

**解决方案：**

```java
// 方案1：注入自己
@Service
public class UserService {
    
    @Autowired
    private UserService self;  // 注入代理对象
    
    public void methodA() {
        self.methodB();  // 通过代理调用
    }
}

// 方案2：使用 AopContext
@Service
public class UserService {
    
    public void methodA() {
        ((UserService) AopContext.currentProxy()).methodB();
    }
}

// 需要开启 exposeProxy
@EnableAspectJAutoProxy(exposeProxy = true)
```

#### 问题2：private/final 方法不生效

```java
@Service
public class UserService {
    
    // private 方法无法被代理
    @Transactional
    private void privateMethod() {  // AOP 不生效！
    }
    
    // final 方法无法被 CGLIB 代理
    @Transactional
    public final void finalMethod() {  // AOP 不生效！
    }
}
```

**解决方案：** 将方法改为 public 非 final。

#### 问题3：切面类没有注册为 Bean

```java
@Aspect
// 忘记添加 @Component
public class MyAspect {
    // AOP 不生效！
}
```

**解决方案：** 添加 `@Component` 注解。

#### 问题4：切入点表达式错误

```java
@Aspect
@Component
public class MyAspect {
    
    // 包名写错
    @Before("execution(* com.exmaple.service.*.*(..))")  // exmaple 拼写错误
    public void before() {
    }
}
```

**解决方案：** 仔细检查切入点表达式，可以先用简单的表达式测试。

### 10.2 循环依赖

```java
@Aspect
@Component
public class MyAspect {
    
    @Autowired
    private UserService userService;  // 可能导致循环依赖
    
    @Before("execution(* com.example.service.*.*(..))")
    public void before() {
        userService.doSomething();  // 在切面中调用被切的服务
    }
}
```

**解决方案：**

```java
// 方案1：使用 @Lazy
@Aspect
@Component
public class MyAspect {
    
    @Autowired
    @Lazy
    private UserService userService;
}

// 方案2：使用 ObjectFactory
@Aspect
@Component
public class MyAspect {
    
    @Autowired
    private ObjectFactory<UserService> userServiceFactory;
    
    @Before("execution(* com.example.service.*.*(..))")
    public void before() {
        userServiceFactory.getObject().doSomething();
    }
}
```

### 10.3 @Around 忘记调用 proceed()

```java
@Aspect
@Component
public class MyAspect {
    
    @Around("execution(* com.example.service.*.*(..))")
    public Object around(ProceedingJoinPoint pjp) throws Throwable {
        System.out.println("before");
        // 忘记调用 pjp.proceed()，目标方法不会执行！
        System.out.println("after");
        return null;  // 返回 null，可能导致 NPE
    }
}
```

**解决方案：** 确保调用 `pjp.proceed()` 并返回结果。

### 10.4 @Around 忘记返回结果

```java
@Aspect
@Component
public class MyAspect {
    
    @Around("execution(* com.example.service.*.*(..))")
    public void around(ProceedingJoinPoint pjp) throws Throwable {  // 返回 void
        pjp.proceed();  // 结果丢失！
    }
}
```

**解决方案：** 返回类型改为 `Object`，并返回 `pjp.proceed()` 的结果。

### 10.5 异常被吞掉

```java
@Aspect
@Component
public class MyAspect {
    
    @Around("execution(* com.example.service.*.*(..))")
    public Object around(ProceedingJoinPoint pjp) {
        try {
            return pjp.proceed();
        } catch (Throwable e) {
            log.error("异常", e);
            return null;  // 异常被吞掉，调用方不知道发生了异常
        }
    }
}
```

**解决方案：** 根据业务需求决定是否重新抛出异常。

```java
@Around("execution(* com.example.service.*.*(..))")
public Object around(ProceedingJoinPoint pjp) throws Throwable {
    try {
        return pjp.proceed();
    } catch (Throwable e) {
        log.error("异常", e);
        throw e;  // 重新抛出
    }
}
```

### 10.6 通知执行顺序问题

```java
@Aspect
@Component
public class MyAspect {
    
    @Before("execution(* com.example.service.*.*(..))")
    public void before1() {
        System.out.println("before1");
    }
    
    @Before("execution(* com.example.service.*.*(..))")
    public void before2() {
        System.out.println("before2");
    }
    
    // 同一切面内的同类型通知，执行顺序不确定！
}
```

**解决方案：** 如果需要确定的执行顺序，使用多个切面配合 `@Order`。

---

## 11. 最佳实践

### 11.1 切面设计原则

```java
// ✅ 好的设计：职责单一
@Aspect
@Component
public class LoggingAspect {
    // 只负责日志
}

@Aspect
@Component
public class SecurityAspect {
    // 只负责安全
}

@Aspect
@Component
public class PerformanceAspect {
    // 只负责性能监控
}

// ❌ 不好的设计：一个切面做太多事
@Aspect
@Component
public class EverythingAspect {
    // 日志 + 安全 + 性能 + 事务 + ...
}
```

### 11.2 切入点表达式复用

```java
@Aspect
@Component
public class CommonPointcuts {
    
    // 定义可复用的切入点
    @Pointcut("execution(* com.example.service.*.*(..))")
    public void serviceLayer() {}
    
    @Pointcut("execution(* com.example.dao.*.*(..))")
    public void daoLayer() {}
    
    @Pointcut("@annotation(com.example.annotation.Loggable)")
    public void loggable() {}
    
    @Pointcut("serviceLayer() || daoLayer()")
    public void businessLayer() {}
}

// 其他切面引用
@Aspect
@Component
public class LoggingAspect {
    
    @Before("com.example.aspect.CommonPointcuts.serviceLayer()")
    public void logService() {
    }
}
```

### 11.3 避免过度使用 AOP

```java
// ❌ 不适合用 AOP 的场景
@Aspect
public class BadAspect {
    
    // 业务逻辑不应该放在切面中
    @Before("execution(* com.example.service.OrderService.create(..))")
    public void validateOrder(JoinPoint jp) {
        Order order = (Order) jp.getArgs()[0];
        if (order.getAmount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new BusinessException("订单金额必须大于0");
        }
        // 这种业务校验应该放在 Service 层
    }
}

// ✅ 适合用 AOP 的场景
// - 日志记录
// - 性能监控
// - 安全检查（通用的，如登录检查）
// - 事务管理
// - 缓存
// - 异常处理
```

### 11.4 注意性能影响

```java
@Aspect
@Component
public class PerformanceAwareAspect {
    
    // ❌ 不好：每次都创建新对象
    @Before("execution(* com.example.service.*.*(..))")
    public void before(JoinPoint jp) {
        ObjectMapper mapper = new ObjectMapper();  // 每次都创建
        // ...
    }
    
    // ✅ 好：复用对象
    private final ObjectMapper mapper = new ObjectMapper();
    
    @Before("execution(* com.example.service.*.*(..))")
    public void beforeGood(JoinPoint jp) {
        // 使用复用的 mapper
    }
}
```

### 11.5 异常处理

```java
@Aspect
@Component
@Slf4j
public class SafeAspect {
    
    @Around("execution(* com.example.service.*.*(..))")
    public Object safeAround(ProceedingJoinPoint pjp) throws Throwable {
        try {
            return pjp.proceed();
        } catch (BusinessException e) {
            // 业务异常，记录日志后重新抛出
            log.warn("业务异常: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            // 系统异常，记录详细日志后重新抛出
            log.error("系统异常: method={}, args={}", 
                    pjp.getSignature().toShortString(),
                    Arrays.toString(pjp.getArgs()), e);
            throw e;
        }
    }
}
```

---

## 12. 总结

### 12.1 核心知识点

| 知识点 | 说明 |
|--------|------|
| 切面（Aspect） | 横切关注点的模块化，使用 @Aspect 标注 |
| 切入点（Pointcut） | 定义拦截哪些方法，使用表达式 |
| 通知（Advice） | 定义拦截后做什么，5 种类型 |
| 连接点（JoinPoint） | 程序执行的某个点，Spring 只支持方法级别 |
| 代理（Proxy） | JDK 动态代理或 CGLIB 代理 |

### 12.2 通知类型对比

| 通知类型 | 执行时机 | 能否获取返回值 | 能否处理异常 | 能否阻止执行 |
|----------|----------|----------------|--------------|--------------|
| @Before | 方法前 | ✗ | ✗ | ✓（抛异常） |
| @AfterReturning | 正常返回后 | ✓ | ✗ | ✗ |
| @AfterThrowing | 异常后 | ✗ | ✓（只能获取） | ✗ |
| @After | 方法后 | ✗ | ✗ | ✗ |
| @Around | 完全控制 | ✓ | ✓ | ✓ |

### 12.3 常用切入点表达式

```java
// 匹配 service 包下所有方法
execution(* com.example.service.*.*(..))

// 匹配带有 @Transactional 注解的方法
@annotation(org.springframework.transaction.annotation.Transactional)

// 匹配 @Service 注解的类的所有方法
@within(org.springframework.stereotype.Service)

// 匹配指定 Bean
bean(userService)
```

### 12.4 使用建议

1. **优先使用注解驱动**：自定义注解 + @annotation 表达式
2. **切面职责单一**：一个切面只做一件事
3. **注意执行顺序**：使用 @Order 控制多个切面的顺序
4. **避免自调用问题**：通过代理对象调用
5. **谨慎使用 @Around**：功能强大但容易出错
6. **注意性能影响**：避免在切面中做耗时操作

Spring AOP 是一个强大的工具，合理使用可以大大提高代码的可维护性和复用性。但也要注意不要过度使用，保持代码的简洁和可读性。
