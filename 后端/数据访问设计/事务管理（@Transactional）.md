

> Spring 事务管理是企业级应用开发中最重要的技术之一
> 本笔记基于 Java 8 + Spring Boot 2.7.18 + MyBatis Plus

---

## 目录

1. [事务基础概念](#1-事务基础概念)
2. [Spring 事务管理入门](#2-spring-事务管理入门)
3. [@Transactional 注解详解](#3-transactional-注解详解)
4. [事务传播行为](#4-事务传播行为)
5. [事务隔离级别](#5-事务隔离级别)
6. [事务回滚机制](#6-事务回滚机制)
7. [编程式事务](#7-编程式事务)
8. [事务失效场景](#8-事务失效场景)
9. [分布式事务简介](#9-分布式事务简介)
10. [最佳实践](#10-最佳实践)
11. [常见错误与解决方案](#11-常见错误与解决方案)

---

## 1. 事务基础概念

### 1.1 什么是事务？

**事务（Transaction）** 是数据库操作的最小工作单元，是一组不可分割的操作序列。事务中的所有操作要么全部成功，要么全部失败回滚。

**生活中的例子**：银行转账
- 张三给李四转账 100 元
- 操作1：张三账户 -100 元
- 操作2：李四账户 +100 元
- 这两个操作必须同时成功或同时失败，不能出现张三扣了钱但李四没收到的情况

### 1.2 事务的 ACID 特性

| 特性 | 英文 | 说明 | 举例 |
|------|------|------|------|
| 原子性 | Atomicity | 事务是不可分割的最小单元，要么全部成功，要么全部失败 | 转账要么成功，要么失败，不会出现中间状态 |
| 一致性 | Consistency | 事务执行前后，数据库从一个一致状态变到另一个一致状态 | 转账前后，两人总金额不变 |
| 隔离性 | Isolation | 多个事务并发执行时，相互之间不能干扰 | A 在转账时，B 查询不会看到中间状态 |
| 持久性 | Durability | 事务一旦提交，对数据库的改变是永久的 | 转账成功后，即使系统崩溃，数据也不会丢失 |


### 1.3 并发事务带来的问题

当多个事务同时操作数据库时，如果没有适当的隔离机制，可能会出现以下问题：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        并发事务问题图解                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  【脏读 Dirty Read】                                                        │
│  事务A读取了事务B未提交的数据，如果B回滚，A读到的就是"脏数据"                  │
│                                                                             │
│  事务A:  读取余额=1000 ──────────────────────────> 读取余额=900（脏数据）    │
│  事务B:       修改余额=900 ──> 回滚 ──────────────────────────────────>     │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  【不可重复读 Non-Repeatable Read】                                         │
│  事务A两次读取同一数据，期间事务B修改并提交，导致A两次读取结果不同              │
│                                                                             │
│  事务A:  读取余额=1000 ──────────────────────────> 读取余额=900（不一致）    │
│  事务B:            修改余额=900 ──> 提交 ──────────────────────────>        │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  【幻读 Phantom Read】                                                      │
│  事务A两次查询，期间事务B插入新数据并提交，导致A第二次查询多出"幻影"行          │
│                                                                             │
│  事务A:  查询count=10 ──────────────────────────> 查询count=11（幻读）      │
│  事务B:            插入1条 ──> 提交 ──────────────────────────────>         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**三种问题的区别**：
- **脏读**：读到了别人未提交的数据（最严重）
- **不可重复读**：同一条数据，两次读取值不同（针对 UPDATE）
- **幻读**：同一个查询，两次结果行数不同（针对 INSERT/DELETE）

---

## 2. Spring 事务管理入门

### 2.1 添加依赖

```xml
<!-- pom.xml -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>

<dependencies>
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- MyBatis Plus -->
    <dependency>
        <groupId>com.baomidou</groupId>
        <artifactId>mybatis-plus-boot-starter</artifactId>
        <version>3.5.3.1</version>
    </dependency>
    
    <!-- MySQL 驱动 -->
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
    </dependency>
    
    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### 2.2 数据库配置

```yaml
# application.yml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/test?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
    username: root
    password: 123456
    driver-class-name: com.mysql.cj.jdbc.Driver

# MyBatis Plus 配置
mybatis-plus:
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl  # 打印SQL日志
```


### 2.3 实体类和 Mapper

```java
// 账户实体类
@Data
@TableName("account")
public class Account {
    
    @TableId(type = IdType.AUTO)
    private Long id;
    
    private String username;
    
    private BigDecimal balance;
    
    private LocalDateTime createTime;
    
    private LocalDateTime updateTime;
}

// Mapper 接口
@Mapper
public interface AccountMapper extends BaseMapper<Account> {
    
    /**
     * 扣减余额
     */
    @Update("UPDATE account SET balance = balance - #{amount} WHERE id = #{id} AND balance >= #{amount}")
    int decreaseBalance(@Param("id") Long id, @Param("amount") BigDecimal amount);
    
    /**
     * 增加余额
     */
    @Update("UPDATE account SET balance = balance + #{amount} WHERE id = #{id}")
    int increaseBalance(@Param("id") Long id, @Param("amount") BigDecimal amount);
}
```

### 2.4 第一个事务示例

```java
package com.example.service;

import com.example.entity.Account;
import com.example.mapper.AccountMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;

/**
 * 账户服务 - 事务入门示例
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountService {
    
    private final AccountMapper accountMapper;
    
    /**
     * 转账操作
     * 
     * @Transactional 注解表示这个方法需要事务支持
     * 方法内的所有数据库操作要么全部成功，要么全部回滚
     * 
     * @param fromId 转出账户ID
     * @param toId   转入账户ID
     * @param amount 转账金额
     */
    @Transactional
    public void transfer(Long fromId, Long toId, BigDecimal amount) {
        log.info("开始转账: {} -> {}, 金额: {}", fromId, toId, amount);
        
        // 1. 扣减转出账户余额
        int rows = accountMapper.decreaseBalance(fromId, amount);
        if (rows != 1) {
            throw new RuntimeException("余额不足或账户不存在");
        }
        
        // 2. 模拟异常（测试事务回滚）
        // if (true) {
        //     throw new RuntimeException("模拟转账异常");
        // }
        
        // 3. 增加转入账户余额
        accountMapper.increaseBalance(toId, amount);
        
        log.info("转账成功");
    }
}
```

**关键点说明**：
1. `@Transactional` 注解加在方法上，表示该方法需要事务支持
2. 方法正常执行完毕，事务自动提交
3. 方法抛出异常（默认是 RuntimeException），事务自动回滚
4. Spring Boot 默认已经配置好了事务管理器，无需额外配置

---

## 3. @Transactional 注解详解

### 3.1 注解属性一览

```java
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Transactional {
    
    // 事务管理器名称
    String value() default "";
    String transactionManager() default "";
    
    // 事务传播行为
    Propagation propagation() default Propagation.REQUIRED;
    
    // 事务隔离级别
    Isolation isolation() default Isolation.DEFAULT;
    
    // 事务超时时间（秒）
    int timeout() default -1;
    
    // 是否只读事务
    boolean readOnly() default false;
    
    // 触发回滚的异常类型
    Class<? extends Throwable>[] rollbackFor() default {};
    String[] rollbackForClassName() default {};
    
    // 不触发回滚的异常类型
    Class<? extends Throwable>[] noRollbackFor() default {};
    String[] noRollbackForClassName() default {};
}
```


### 3.2 常用属性详解

#### 3.2.1 propagation - 传播行为

```java
// 最常用：如果当前有事务就加入，没有就新建
@Transactional(propagation = Propagation.REQUIRED)

// 新建事务：不管当前有没有事务，都新建一个独立事务
@Transactional(propagation = Propagation.REQUIRES_NEW)

// 嵌套事务：在当前事务中创建一个保存点
@Transactional(propagation = Propagation.NESTED)
```

#### 3.2.2 isolation - 隔离级别

```java
// 使用数据库默认隔离级别（MySQL 默认是 REPEATABLE_READ）
@Transactional(isolation = Isolation.DEFAULT)

// 读已提交：防止脏读
@Transactional(isolation = Isolation.READ_COMMITTED)

// 可重复读：防止脏读和不可重复读
@Transactional(isolation = Isolation.REPEATABLE_READ)

// 串行化：防止所有并发问题，但性能最差
@Transactional(isolation = Isolation.SERIALIZABLE)
```

#### 3.2.3 timeout - 超时时间

```java
// 事务超时时间为 30 秒，超时自动回滚
@Transactional(timeout = 30)
```

#### 3.2.4 readOnly - 只读事务

```java
// 只读事务，用于查询操作，可以优化性能
@Transactional(readOnly = true)
public List<Account> findAll() {
    return accountMapper.selectList(null);
}
```

**只读事务的好处**：
1. 数据库可以进行优化（如 MySQL 不加锁）
2. 防止误操作修改数据
3. 某些数据库连接池可以进行优化

#### 3.2.5 rollbackFor - 回滚规则

```java
// 默认只对 RuntimeException 和 Error 回滚
// 如果需要对 checked 异常也回滚，需要指定
@Transactional(rollbackFor = Exception.class)
public void doSomething() throws Exception {
    // 即使抛出 IOException 等 checked 异常也会回滚
}

// 指定多个异常类型
@Transactional(rollbackFor = {IOException.class, SQLException.class})
```

### 3.3 注解使用位置

```java
/**
 * 方式1：加在方法上（推荐）
 * 只对该方法生效
 */
@Service
public class UserService {
    
    @Transactional
    public void createUser(User user) {
        // 有事务
    }
    
    public void findUser(Long id) {
        // 无事务
    }
}

/**
 * 方式2：加在类上
 * 对类中所有 public 方法生效
 */
@Service
@Transactional
public class OrderService {
    
    public void createOrder(Order order) {
        // 有事务
    }
    
    public void updateOrder(Order order) {
        // 有事务
    }
    
    // 方法上的注解会覆盖类上的注解
    @Transactional(readOnly = true)
    public Order findOrder(Long id) {
        // 只读事务
    }
}

/**
 * 方式3：加在接口上（不推荐）
 * 可能导致事务不生效
 */
@Transactional
public interface PayService {
    void pay(Order order);
}
```

**最佳实践**：
- 优先加在方法上，精确控制
- 查询方法使用 `@Transactional(readOnly = true)`
- 写操作方法使用 `@Transactional(rollbackFor = Exception.class)`

---

## 4. 事务传播行为

### 4.1 什么是事务传播行为？

事务传播行为定义了当一个事务方法被另一个事务方法调用时，事务应该如何传播。

**通俗理解**：方法 A 有事务，方法 A 调用方法 B，那么方法 B 是加入 A 的事务，还是自己新建一个事务？这就是传播行为要解决的问题。

### 4.2 七种传播行为

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        事务传播行为一览表                                    │
├─────────────────┬───────────────────────────────────────────────────────────┤
│     传播行为     │                        说明                               │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ REQUIRED        │ 默认值。如果当前有事务，就加入；没有就新建                   │
│ (最常用)        │ 适用场景：大多数业务方法                                    │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ REQUIRES_NEW    │ 总是新建事务。如果当前有事务，挂起当前事务                   │
│ (常用)          │ 适用场景：日志记录、独立的子操作                            │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ NESTED          │ 如果当前有事务，在嵌套事务中执行；没有就新建                 │
│ (常用)          │ 适用场景：部分回滚的场景                                    │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ SUPPORTS        │ 如果当前有事务，就加入；没有就以非事务方式执行               │
│                 │ 适用场景：查询方法                                         │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ NOT_SUPPORTED   │ 以非事务方式执行。如果当前有事务，挂起当前事务               │
│                 │ 适用场景：不需要事务的操作                                  │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ MANDATORY       │ 必须在事务中执行。如果当前没有事务，抛出异常                 │
│                 │ 适用场景：强制要求调用方有事务                              │
├─────────────────┼───────────────────────────────────────────────────────────┤
│ NEVER           │ 必须以非事务方式执行。如果当前有事务，抛出异常               │
│                 │ 适用场景：强制要求调用方没有事务                            │
└─────────────────┴───────────────────────────────────────────────────────────┘
```


### 4.3 REQUIRED（默认）

```java
/**
 * REQUIRED 传播行为示例
 * 
 * 场景：订单服务调用库存服务
 * 结果：两个方法在同一个事务中，任何一个失败都会导致整体回滚
 */
@Service
@RequiredArgsConstructor
public class OrderService {
    
    private final OrderMapper orderMapper;
    private final StockService stockService;
    
    @Transactional(propagation = Propagation.REQUIRED)
    public void createOrder(Order order) {
        // 1. 创建订单
        orderMapper.insert(order);
        
        // 2. 扣减库存（加入当前事务）
        stockService.decreaseStock(order.getProductId(), order.getQuantity());
        
        // 如果这里抛异常，订单和库存都会回滚
    }
}

@Service
@RequiredArgsConstructor
public class StockService {
    
    private final StockMapper stockMapper;
    
    @Transactional(propagation = Propagation.REQUIRED)
    public void decreaseStock(Long productId, Integer quantity) {
        // 加入 OrderService 的事务
        stockMapper.decrease(productId, quantity);
    }
}
```

**执行流程**：
```
OrderService.createOrder() 开启事务 T1
    ├── 插入订单（在 T1 中）
    ├── 调用 StockService.decreaseStock()
    │       └── 扣减库存（加入 T1）
    └── 方法结束，T1 提交
```

### 4.4 REQUIRES_NEW（新建事务）

```java
/**
 * REQUIRES_NEW 传播行为示例
 * 
 * 场景：操作日志记录
 * 需求：即使主业务失败，日志也要记录成功
 */
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserMapper userMapper;
    private final OperationLogService logService;
    
    @Transactional
    public void updateUser(User user) {
        // 1. 更新用户
        userMapper.updateById(user);
        
        // 2. 记录操作日志（独立事务）
        logService.saveLog("更新用户: " + user.getId());
        
        // 3. 模拟异常
        if (true) {
            throw new RuntimeException("模拟异常");
        }
        // 结果：用户更新回滚，但日志已经提交成功
    }
}

@Service
@RequiredArgsConstructor
public class OperationLogService {
    
    private final OperationLogMapper logMapper;
    
    /**
     * 使用 REQUIRES_NEW，不管外部有没有事务，都新建一个独立事务
     * 这样即使外部事务回滚，日志也不会丢失
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveLog(String content) {
        OperationLog log = new OperationLog();
        log.setContent(content);
        log.setCreateTime(LocalDateTime.now());
        logMapper.insert(log);
        // 这个方法结束时，日志事务就提交了
    }
}
```

**执行流程**：
```
UserService.updateUser() 开启事务 T1
    ├── 更新用户（在 T1 中）
    ├── 调用 OperationLogService.saveLog()
    │       ├── 挂起 T1
    │       ├── 开启新事务 T2
    │       ├── 插入日志（在 T2 中）
    │       ├── T2 提交 ✓
    │       └── 恢复 T1
    ├── 抛出异常
    └── T1 回滚（用户更新回滚，但日志已提交）
```

### 4.5 NESTED（嵌套事务）

```java
/**
 * NESTED 传播行为示例
 * 
 * 场景：批量处理，部分失败不影响整体
 * 特点：子事务回滚不影响父事务，但父事务回滚会导致子事务也回滚
 */
@Service
@RequiredArgsConstructor
public class BatchService {
    
    private final ItemService itemService;
    
    @Transactional
    public void batchProcess(List<Item> items) {
        int successCount = 0;
        int failCount = 0;
        
        for (Item item : items) {
            try {
                // 每个 item 在嵌套事务中处理
                itemService.processItem(item);
                successCount++;
            } catch (Exception e) {
                // 单个 item 处理失败，不影响其他 item
                failCount++;
                log.warn("处理失败: {}", item.getId(), e);
            }
        }
        
        log.info("批量处理完成，成功: {}, 失败: {}", successCount, failCount);
        
        // 如果这里抛异常，所有已处理的 item 都会回滚
    }
}

@Service
@RequiredArgsConstructor
public class ItemService {
    
    private final ItemMapper itemMapper;
    
    /**
     * NESTED：在父事务中创建一个保存点
     * 如果这个方法失败，只回滚到保存点，不影响父事务的其他操作
     */
    @Transactional(propagation = Propagation.NESTED)
    public void processItem(Item item) {
        // 处理单个 item
        itemMapper.updateById(item);
        
        if (item.getStatus() == -1) {
            throw new RuntimeException("item 状态异常");
        }
    }
}
```

**NESTED vs REQUIRES_NEW 的区别**：

| 特性 | NESTED | REQUIRES_NEW |
|------|--------|--------------|
| 父事务回滚 | 子事务也回滚 | 子事务不受影响 |
| 子事务回滚 | 父事务可以捕获异常继续 | 父事务可以捕获异常继续 |
| 实现方式 | 保存点（Savepoint） | 独立的物理事务 |
| 性能 | 较好（同一连接） | 较差（新建连接） |
| 数据库支持 | 需要支持保存点 | 所有数据库都支持 |

---

## 5. 事务隔离级别

### 5.1 四种隔离级别

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        事务隔离级别对比                                      │
├─────────────────┬─────────┬─────────────┬─────────┬─────────────────────────┤
│    隔离级别      │  脏读   │  不可重复读  │  幻读   │         说明            │
├─────────────────┼─────────┼─────────────┼─────────┼─────────────────────────┤
│ READ_UNCOMMITTED│   ✗     │      ✗      │    ✗    │ 最低级别，几乎不用       │
│ (读未提交)       │ 可能    │    可能     │  可能   │                         │
├─────────────────┼─────────┼─────────────┼─────────┼─────────────────────────┤
│ READ_COMMITTED  │   ✓     │      ✗      │    ✗    │ Oracle/SQL Server 默认  │
│ (读已提交)       │ 防止    │    可能     │  可能   │ 大多数场景够用          │
├─────────────────┼─────────┼─────────────┼─────────┼─────────────────────────┤
│ REPEATABLE_READ │   ✓     │      ✓      │    ✗    │ MySQL 默认              │
│ (可重复读)       │ 防止    │    防止     │  可能   │ MySQL 通过 MVCC 也防幻读 │
├─────────────────┼─────────┼─────────────┼─────────┼─────────────────────────┤
│ SERIALIZABLE    │   ✓     │      ✓      │    ✓    │ 最高级别，性能最差       │
│ (串行化)         │ 防止    │    防止     │  防止   │ 很少使用                │
└─────────────────┴─────────┴─────────────┴─────────┴─────────────────────────┘

✓ = 防止该问题    ✗ = 可能出现该问题
```


### 5.2 隔离级别使用示例

```java
/**
 * 隔离级别使用示例
 */
@Service
public class IsolationDemoService {
    
    /**
     * 使用数据库默认隔离级别（推荐）
     * MySQL 默认是 REPEATABLE_READ
     */
    @Transactional(isolation = Isolation.DEFAULT)
    public void defaultIsolation() {
        // ...
    }
    
    /**
     * 读已提交
     * 适用场景：对数据一致性要求不高，追求性能
     */
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public void readCommitted() {
        // 每次读取都能看到其他事务已提交的最新数据
        // 但同一事务内两次读取可能结果不同
    }
    
    /**
     * 可重复读
     * 适用场景：需要在事务内多次读取同一数据，且要求结果一致
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public void repeatableRead() {
        // 同一事务内多次读取同一数据，结果一致
        // 即使其他事务已经修改并提交
    }
    
    /**
     * 串行化
     * 适用场景：对数据一致性要求极高（如金融系统核心交易）
     * 注意：性能很差，会导致大量锁等待
     */
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void serializable() {
        // 完全串行执行，不会有任何并发问题
        // 但性能极差
    }
}
```

### 5.3 实际场景选择

```java
/**
 * 不同业务场景的隔离级别选择
 */
@Service
public class BusinessService {
    
    /**
     * 场景1：普通查询
     * 推荐：READ_COMMITTED 或 DEFAULT
     */
    @Transactional(readOnly = true, isolation = Isolation.READ_COMMITTED)
    public User getUser(Long id) {
        return userMapper.selectById(id);
    }
    
    /**
     * 场景2：报表统计（需要一致性快照）
     * 推荐：REPEATABLE_READ
     * 原因：统计过程中数据不能变化
     */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public ReportData generateReport() {
        // 多次查询，需要数据一致
        long totalUsers = userMapper.count();
        long activeUsers = userMapper.countActive();
        BigDecimal totalAmount = orderMapper.sumAmount();
        // ...
        return new ReportData(totalUsers, activeUsers, totalAmount);
    }
    
    /**
     * 场景3：库存扣减（高并发场景）
     * 推荐：DEFAULT + 乐观锁/悲观锁
     * 原因：隔离级别解决不了并发更新问题，需要配合锁机制
     */
    @Transactional
    public void decreaseStock(Long productId, Integer quantity) {
        // 使用乐观锁
        int rows = stockMapper.decreaseWithVersion(productId, quantity);
        if (rows == 0) {
            throw new RuntimeException("库存不足或版本冲突");
        }
    }
}
```

---

## 6. 事务回滚机制

### 6.1 默认回滚规则

Spring 事务默认只对 **RuntimeException** 和 **Error** 进行回滚，对 **checked 异常**（如 IOException、SQLException）不回滚。

```java
@Service
public class RollbackDemoService {
    
    /**
     * 默认回滚规则演示
     */
    @Transactional
    public void defaultRollback() {
        userMapper.insert(user);
        
        // RuntimeException - 会回滚 ✓
        throw new RuntimeException("运行时异常");
        
        // Error - 会回滚 ✓
        // throw new OutOfMemoryError();
        
        // Checked Exception - 不会回滚 ✗
        // throw new IOException("IO异常");
    }
}
```

### 6.2 自定义回滚规则

```java
@Service
public class CustomRollbackService {
    
    /**
     * 方式1：指定回滚的异常类型
     * 推荐：rollbackFor = Exception.class，对所有异常都回滚
     */
    @Transactional(rollbackFor = Exception.class)
    public void rollbackForAll() throws Exception {
        userMapper.insert(user);
        throw new IOException("IO异常");  // 现在会回滚了
    }
    
    /**
     * 方式2：指定多个回滚异常
     */
    @Transactional(rollbackFor = {IOException.class, SQLException.class})
    public void rollbackForSpecific() throws Exception {
        // ...
    }
    
    /**
     * 方式3：指定不回滚的异常
     * 场景：某些业务异常不需要回滚
     */
    @Transactional(noRollbackFor = BusinessException.class)
    public void noRollbackForBusiness() {
        userMapper.insert(user);
        // 业务异常不回滚，数据会提交
        throw new BusinessException("业务校验失败");
    }
    
    /**
     * 方式4：组合使用
     */
    @Transactional(
        rollbackFor = Exception.class,
        noRollbackFor = {BusinessException.class, ValidationException.class}
    )
    public void combinedRollback() throws Exception {
        // 除了 BusinessException 和 ValidationException，其他异常都回滚
    }
}
```

### 6.3 手动回滚

```java
@Service
public class ManualRollbackService {
    
    /**
     * 方式1：使用 TransactionAspectSupport 手动回滚
     * 适用场景：不想抛异常，但需要回滚
     */
    @Transactional
    public Result<?> createOrder(Order order) {
        try {
            orderMapper.insert(order);
            stockService.decrease(order.getProductId(), order.getQuantity());
            return Result.success();
        } catch (Exception e) {
            // 手动标记回滚
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            return Result.error("创建订单失败: " + e.getMessage());
        }
    }
    
    /**
     * 方式2：使用 TransactionStatus
     * 需要注入 PlatformTransactionManager
     */
    @Autowired
    private PlatformTransactionManager transactionManager;
    
    public void manualTransaction() {
        DefaultTransactionDefinition def = new DefaultTransactionDefinition();
        TransactionStatus status = transactionManager.getTransaction(def);
        
        try {
            // 业务操作
            userMapper.insert(user);
            orderMapper.insert(order);
            
            // 手动提交
            transactionManager.commit(status);
        } catch (Exception e) {
            // 手动回滚
            transactionManager.rollback(status);
            throw e;
        }
    }
}
```

### 6.4 回滚后的处理

```java
@Service
@Slf4j
public class RollbackHandlerService {
    
    /**
     * 事务回滚后执行某些操作
     * 使用 @TransactionalEventListener
     */
    @Transactional(rollbackFor = Exception.class)
    public void createOrder(Order order) {
        orderMapper.insert(order);
        
        // 发布事件
        applicationEventPublisher.publishEvent(new OrderCreatedEvent(order));
        
        // 如果后续抛异常，事务回滚，但事件监听器可以感知
    }
}

@Component
@Slf4j
public class OrderEventListener {
    
    /**
     * 事务提交后执行
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onOrderCreated(OrderCreatedEvent event) {
        log.info("订单创建成功，发送通知: {}", event.getOrder().getId());
    }
    
    /**
     * 事务回滚后执行
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_ROLLBACK)
    public void onOrderRollback(OrderCreatedEvent event) {
        log.warn("订单创建失败，记录日志: {}", event.getOrder().getId());
    }
}
```


---

## 7. 编程式事务

除了声明式事务（@Transactional），Spring 还支持编程式事务，提供更细粒度的控制。

### 7.1 TransactionTemplate（推荐）

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class ProgrammaticTransactionService {
    
    private final TransactionTemplate transactionTemplate;
    private final UserMapper userMapper;
    private final OrderMapper orderMapper;
    
    /**
     * 使用 TransactionTemplate 执行事务
     * 适用场景：需要在事务中返回结果
     */
    public Order createOrderWithResult(OrderDTO dto) {
        return transactionTemplate.execute(status -> {
            try {
                // 1. 创建用户
                User user = new User();
                user.setName(dto.getUserName());
                userMapper.insert(user);
                
                // 2. 创建订单
                Order order = new Order();
                order.setUserId(user.getId());
                order.setAmount(dto.getAmount());
                orderMapper.insert(order);
                
                return order;
            } catch (Exception e) {
                // 手动标记回滚
                status.setRollbackOnly();
                log.error("创建订单失败", e);
                return null;
            }
        });
    }
    
    /**
     * 无返回值的事务
     */
    public void createOrderNoResult(OrderDTO dto) {
        transactionTemplate.executeWithoutResult(status -> {
            try {
                userMapper.insert(user);
                orderMapper.insert(order);
            } catch (Exception e) {
                status.setRollbackOnly();
                throw new RuntimeException("创建失败", e);
            }
        });
    }
    
    /**
     * 自定义事务属性
     */
    public void customTransaction() {
        // 设置事务属性
        transactionTemplate.setPropagationBehavior(
            TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transactionTemplate.setIsolationLevel(
            TransactionDefinition.ISOLATION_READ_COMMITTED);
        transactionTemplate.setTimeout(30);
        
        transactionTemplate.executeWithoutResult(status -> {
            // 业务逻辑
        });
    }
}
```

### 7.2 PlatformTransactionManager

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class ManualTransactionService {
    
    private final PlatformTransactionManager transactionManager;
    private final UserMapper userMapper;
    
    /**
     * 完全手动控制事务
     * 适用场景：需要最细粒度的控制
     */
    public void manualTransaction() {
        // 1. 定义事务属性
        DefaultTransactionDefinition definition = new DefaultTransactionDefinition();
        definition.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
        definition.setIsolationLevel(TransactionDefinition.ISOLATION_DEFAULT);
        definition.setTimeout(30);
        definition.setReadOnly(false);
        
        // 2. 开启事务
        TransactionStatus status = transactionManager.getTransaction(definition);
        
        try {
            // 3. 执行业务逻辑
            userMapper.insert(user1);
            userMapper.insert(user2);
            
            // 4. 提交事务
            transactionManager.commit(status);
            log.info("事务提交成功");
            
        } catch (Exception e) {
            // 5. 回滚事务
            transactionManager.rollback(status);
            log.error("事务回滚", e);
            throw e;
        }
    }
    
    /**
     * 嵌套事务示例
     */
    public void nestedTransaction() {
        DefaultTransactionDefinition outerDef = new DefaultTransactionDefinition();
        TransactionStatus outerStatus = transactionManager.getTransaction(outerDef);
        
        try {
            userMapper.insert(user1);
            
            // 创建嵌套事务
            DefaultTransactionDefinition innerDef = new DefaultTransactionDefinition();
            innerDef.setPropagationBehavior(TransactionDefinition.PROPAGATION_NESTED);
            TransactionStatus innerStatus = transactionManager.getTransaction(innerDef);
            
            try {
                userMapper.insert(user2);
                transactionManager.commit(innerStatus);
            } catch (Exception e) {
                transactionManager.rollback(innerStatus);
                // 内部事务回滚，外部事务可以继续
            }
            
            userMapper.insert(user3);
            transactionManager.commit(outerStatus);
            
        } catch (Exception e) {
            transactionManager.rollback(outerStatus);
            throw e;
        }
    }
}
```

### 7.3 声明式 vs 编程式对比

| 特性 | 声明式（@Transactional） | 编程式（TransactionTemplate） |
|------|-------------------------|------------------------------|
| 代码侵入性 | 低，只需加注解 | 高，需要编写事务代码 |
| 灵活性 | 一般，整个方法一个事务 | 高，可以精确控制事务边界 |
| 可读性 | 好，一目了然 | 一般，代码较多 |
| 适用场景 | 大多数场景 | 需要细粒度控制的场景 |
| 事务嵌套 | 通过传播行为 | 可以手动控制 |

**选择建议**：
- 优先使用声明式事务（@Transactional）
- 需要在事务中间做判断、部分提交时，使用编程式事务
- 需要动态决定是否开启事务时，使用编程式事务

---

## 8. 事务失效场景（重点！）

这是面试高频考点，也是实际开发中最容易踩的坑。

### 8.1 失效场景汇总

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     @Transactional 失效场景汇总                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. 方法不是 public                    ──> 事务不生效                        │
│  2. 同类方法内部调用                    ──> 事务不生效                        │
│  3. 异常被 catch 吞掉                  ──> 事务不回滚                        │
│  4. 抛出 checked 异常                  ──> 事务不回滚（默认）                 │
│  5. 数据库引擎不支持事务                ──> 事务不生效（如 MyISAM）            │
│  6. 没有被 Spring 管理                 ──> 事务不生效                        │
│  7. 多线程调用                         ──> 事务不生效                        │
│  8. 错误的传播行为                      ──> 事务行为不符合预期                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```


### 8.2 场景1：方法不是 public

```java
@Service
public class TransactionFailService {
    
    /**
     * ❌ 错误：private/protected/default 方法，事务不生效
     * 原因：Spring AOP 默认使用 CGLIB 代理，只能代理 public 方法
     */
    @Transactional
    private void privateMethod() {
        // 事务不生效！
    }
    
    @Transactional
    protected void protectedMethod() {
        // 事务不生效！
    }
    
    @Transactional
    void defaultMethod() {
        // 事务不生效！
    }
    
    /**
     * ✅ 正确：public 方法
     */
    @Transactional
    public void publicMethod() {
        // 事务生效
    }
}
```

### 8.3 场景2：同类方法内部调用（最常见！）

```java
@Service
public class OrderService {
    
    @Autowired
    private OrderMapper orderMapper;
    
    /**
     * ❌ 错误示例：内部调用，事务不生效
     */
    public void createOrder(Order order) {
        // 直接调用本类的方法，不会经过代理，事务不生效！
        this.saveOrder(order);
    }
    
    @Transactional
    public void saveOrder(Order order) {
        orderMapper.insert(order);
        // 即使这里抛异常，也不会回滚，因为事务根本没开启
        throw new RuntimeException("模拟异常");
    }
}
```

**原因分析**：
```
外部调用流程（事务生效）：
调用方 ──> Spring 代理对象 ──> 目标对象.saveOrder()
                ↑
           代理拦截，开启事务

内部调用流程（事务不生效）：
目标对象.createOrder() ──> this.saveOrder()
                              ↑
                         直接调用，没有经过代理
```

**解决方案**：

```java
@Service
public class OrderService {
    
    @Autowired
    private OrderMapper orderMapper;
    
    /**
     * ✅ 方案1：注入自己（推荐）
     */
    @Autowired
    private OrderService self;
    
    public void createOrder1(Order order) {
        // 通过注入的代理对象调用
        self.saveOrder(order);
    }
    
    /**
     * ✅ 方案2：从 ApplicationContext 获取代理对象
     */
    @Autowired
    private ApplicationContext applicationContext;
    
    public void createOrder2(Order order) {
        OrderService proxy = applicationContext.getBean(OrderService.class);
        proxy.saveOrder(order);
    }
    
    /**
     * ✅ 方案3：使用 AopContext（需要开启 exposeProxy）
     */
    public void createOrder3(Order order) {
        // 需要在启动类加 @EnableAspectJAutoProxy(exposeProxy = true)
        OrderService proxy = (OrderService) AopContext.currentProxy();
        proxy.saveOrder(order);
    }
    
    /**
     * ✅ 方案4：拆分到不同的 Service（最佳实践）
     */
    @Autowired
    private OrderTransactionService transactionService;
    
    public void createOrder4(Order order) {
        transactionService.saveOrder(order);
    }
    
    @Transactional
    public void saveOrder(Order order) {
        orderMapper.insert(order);
    }
}

// 方案4：拆分出来的事务服务
@Service
public class OrderTransactionService {
    
    @Autowired
    private OrderMapper orderMapper;
    
    @Transactional
    public void saveOrder(Order order) {
        orderMapper.insert(order);
    }
}
```

### 8.4 场景3：异常被 catch 吞掉

```java
@Service
public class ExceptionSwallowService {
    
    /**
     * ❌ 错误：异常被 catch 吞掉，事务不回滚
     */
    @Transactional
    public void wrongWay() {
        try {
            userMapper.insert(user);
            int i = 1 / 0;  // 异常
        } catch (Exception e) {
            // 异常被吞掉，Spring 感知不到异常，不会回滚
            log.error("发生异常", e);
        }
        // 数据已经插入，不会回滚
    }
    
    /**
     * ✅ 正确方式1：不要 catch，让异常抛出
     */
    @Transactional
    public void correctWay1() {
        userMapper.insert(user);
        int i = 1 / 0;  // 异常抛出，事务回滚
    }
    
    /**
     * ✅ 正确方式2：catch 后重新抛出
     */
    @Transactional
    public void correctWay2() {
        try {
            userMapper.insert(user);
            int i = 1 / 0;
        } catch (Exception e) {
            log.error("发生异常", e);
            throw e;  // 重新抛出
        }
    }
    
    /**
     * ✅ 正确方式3：catch 后手动回滚
     */
    @Transactional
    public Result<?> correctWay3() {
        try {
            userMapper.insert(user);
            int i = 1 / 0;
            return Result.success();
        } catch (Exception e) {
            log.error("发生异常", e);
            // 手动标记回滚
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            return Result.error("操作失败");
        }
    }
}
```

### 8.5 场景4：抛出 checked 异常

```java
@Service
public class CheckedExceptionService {
    
    /**
     * ❌ 错误：抛出 checked 异常，默认不回滚
     */
    @Transactional
    public void wrongWay() throws IOException {
        userMapper.insert(user);
        throw new IOException("IO异常");  // checked 异常，不回滚
    }
    
    /**
     * ✅ 正确：指定 rollbackFor
     */
    @Transactional(rollbackFor = Exception.class)
    public void correctWay() throws IOException {
        userMapper.insert(user);
        throw new IOException("IO异常");  // 现在会回滚了
    }
}
```

### 8.6 场景5：数据库引擎不支持事务

```sql
-- ❌ MyISAM 引擎不支持事务
CREATE TABLE user (
    id BIGINT PRIMARY KEY
) ENGINE=MyISAM;

-- ✅ InnoDB 引擎支持事务
CREATE TABLE user (
    id BIGINT PRIMARY KEY
) ENGINE=InnoDB;
```

```java
// 检查表的引擎
@Autowired
private JdbcTemplate jdbcTemplate;

public void checkEngine() {
    String sql = "SHOW TABLE STATUS WHERE Name = 'user'";
    Map<String, Object> result = jdbcTemplate.queryForMap(sql);
    String engine = (String) result.get("Engine");
    log.info("表引擎: {}", engine);  // 应该是 InnoDB
}
```

### 8.7 场景6：没有被 Spring 管理

```java
/**
 * ❌ 错误：没有 @Service 注解，不被 Spring 管理
 */
public class NotManagedService {
    
    @Transactional
    public void doSomething() {
        // 事务不生效，因为这个类不是 Spring Bean
    }
}

/**
 * ❌ 错误：手动 new 出来的对象
 */
@Service
public class CallerService {
    
    public void call() {
        // 手动 new，不是 Spring 代理对象
        NotManagedService service = new NotManagedService();
        service.doSomething();  // 事务不生效
    }
}
```

### 8.8 场景7：多线程调用

```java
@Service
public class MultiThreadService {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * ❌ 错误：多线程中事务不生效
     * 原因：Spring 事务是基于 ThreadLocal 的，新线程获取不到事务上下文
     */
    @Transactional
    public void wrongWay() {
        userMapper.insert(user1);
        
        // 新线程中的操作不在事务中
        new Thread(() -> {
            userMapper.insert(user2);  // 不在事务中！
        }).start();
        
        throw new RuntimeException("异常");
        // user1 回滚，但 user2 不会回滚
    }
    
    /**
     * ✅ 正确：在主线程中完成所有数据库操作
     */
    @Transactional
    public void correctWay(List<User> users) {
        for (User user : users) {
            userMapper.insert(user);
        }
        // 所有操作在同一事务中
    }
    
    /**
     * ✅ 如果必须用多线程，每个线程单独管理事务
     */
    public void multiThreadWithTransaction(List<User> users) {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        
        for (User user : users) {
            executor.submit(() -> {
                // 每个线程调用有事务的方法
                userService.saveUser(user);
            });
        }
    }
}
```


### 8.9 场景8：错误的传播行为

```java
@Service
public class PropagationFailService {
    
    @Autowired
    private LogService logService;
    
    /**
     * ❌ 错误理解：以为日志会独立提交
     */
    @Transactional
    public void wrongUnderstanding() {
        userMapper.insert(user);
        
        // 如果 LogService.saveLog() 使用 REQUIRED（默认）
        // 那么日志和用户在同一个事务中
        // 主方法回滚，日志也会回滚
        logService.saveLog("创建用户");
        
        throw new RuntimeException("异常");
    }
}

@Service
public class LogService {
    
    /**
     * ❌ 使用 REQUIRED，会加入外部事务
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void saveLog(String content) {
        logMapper.insert(log);
        // 如果外部事务回滚，这里也会回滚
    }
    
    /**
     * ✅ 使用 REQUIRES_NEW，独立事务
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveLogIndependent(String content) {
        logMapper.insert(log);
        // 独立事务，外部回滚不影响这里
    }
}
```

### 8.10 事务失效排查清单

当事务不生效时，按以下清单排查：

```
□ 1. 方法是否是 public？
□ 2. 是否是同类内部调用？
□ 3. 异常是否被 catch 吞掉了？
□ 4. 抛出的是否是 checked 异常？是否配置了 rollbackFor？
□ 5. 类是否被 Spring 管理（有 @Service/@Component 等注解）？
□ 6. 是否是通过 Spring 容器获取的 Bean（不是 new 出来的）？
□ 7. 数据库表引擎是否支持事务（InnoDB）？
□ 8. 是否在多线程中调用？
□ 9. 传播行为是否正确？
□ 10. 是否配置了事务管理器？
```

---

## 9. 分布式事务简介

当系统涉及多个数据库或多个服务时，单机事务无法保证数据一致性，需要使用分布式事务。

### 9.1 分布式事务场景

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        分布式事务典型场景                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  场景1：跨数据库                                                            │
│  ┌─────────┐      ┌─────────┐      ┌─────────┐                             │
│  │ 订单服务 │ ───> │ 订单库   │      │ 库存库   │                             │
│  └─────────┘      └─────────┘      └─────────┘                             │
│       │                                 ↑                                   │
│       └─────────────────────────────────┘                                   │
│                   需要保证一致性                                             │
│                                                                             │
│  场景2：跨服务（微服务）                                                     │
│  ┌─────────┐      ┌─────────┐      ┌─────────┐                             │
│  │ 订单服务 │ ───> │ 库存服务 │ ───> │ 积分服务 │                             │
│  └─────────┘      └─────────┘      └─────────┘                             │
│       │               │                 │                                   │
│       ▼               ▼                 ▼                                   │
│   订单数据库      库存数据库        积分数据库                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 常见解决方案

| 方案 | 原理 | 优点 | 缺点 | 适用场景 |
|------|------|------|------|----------|
| 2PC/XA | 两阶段提交 | 强一致性 | 性能差，有阻塞 | 传统企业应用 |
| TCC | Try-Confirm-Cancel | 性能好 | 代码侵入大 | 高并发场景 |
| Saga | 事件驱动补偿 | 长事务友好 | 最终一致 | 长流程业务 |
| 本地消息表 | 消息+定时任务 | 简单可靠 | 有延迟 | 一般业务 |
| Seata | 阿里开源框架 | 使用简单 | 需要部署 | 微服务 |

### 9.3 Seata 简单示例

```xml
<!-- 添加 Seata 依赖 -->
<dependency>
    <groupId>io.seata</groupId>
    <artifactId>seata-spring-boot-starter</artifactId>
    <version>1.6.1</version>
</dependency>
```

```yaml
# application.yml
seata:
  enabled: true
  application-id: order-service
  tx-service-group: my_tx_group
  service:
    vgroup-mapping:
      my_tx_group: default
    grouplist:
      default: 127.0.0.1:8091
```

```java
@Service
public class OrderService {
    
    @Autowired
    private StockFeignClient stockClient;
    
    @Autowired
    private OrderMapper orderMapper;
    
    /**
     * 使用 @GlobalTransactional 开启分布式事务
     */
    @GlobalTransactional(rollbackFor = Exception.class)
    public void createOrder(OrderDTO dto) {
        // 1. 创建订单（本地数据库）
        Order order = new Order();
        order.setUserId(dto.getUserId());
        order.setProductId(dto.getProductId());
        orderMapper.insert(order);
        
        // 2. 扣减库存（远程服务）
        stockClient.decrease(dto.getProductId(), dto.getQuantity());
        
        // 3. 如果这里抛异常，订单和库存都会回滚
        if (dto.getAmount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new RuntimeException("金额不能为负");
        }
    }
}
```

---

## 10. 最佳实践

### 10.1 事务注解最佳实践

```java
@Service
@Slf4j
public class BestPracticeService {
    
    /**
     * ✅ 最佳实践1：明确指定 rollbackFor
     */
    @Transactional(rollbackFor = Exception.class)
    public void practice1() {
        // 对所有异常都回滚
    }
    
    /**
     * ✅ 最佳实践2：查询方法使用只读事务
     */
    @Transactional(readOnly = true)
    public List<User> findUsers() {
        return userMapper.selectList(null);
    }
    
    /**
     * ✅ 最佳实践3：设置合理的超时时间
     */
    @Transactional(rollbackFor = Exception.class, timeout = 30)
    public void practice3() {
        // 30秒超时
    }
    
    /**
     * ✅ 最佳实践4：事务方法尽量短小
     */
    @Transactional(rollbackFor = Exception.class)
    public void practice4(OrderDTO dto) {
        // 只包含数据库操作
        orderMapper.insert(order);
        stockMapper.decrease(productId, quantity);
    }
    
    // 非事务操作放在事务方法外面
    public void createOrder(OrderDTO dto) {
        // 1. 参数校验（非事务）
        validateParam(dto);
        
        // 2. 调用远程服务（非事务）
        UserInfo user = userClient.getUser(dto.getUserId());
        
        // 3. 数据库操作（事务）
        practice4(dto);
        
        // 4. 发送消息（非事务）
        messageService.send(new OrderCreatedMessage(dto));
    }
}
```


### 10.2 事务边界设计

```java
/**
 * ✅ 好的设计：事务边界清晰
 */
@Service
public class GoodDesignService {
    
    @Autowired
    private OrderTransactionService transactionService;
    
    /**
     * 外层方法：编排业务流程，不加事务
     */
    public OrderResult createOrder(OrderDTO dto) {
        // 1. 前置校验（无事务）
        validateOrder(dto);
        
        // 2. 查询商品信息（只读事务）
        Product product = productService.getProduct(dto.getProductId());
        
        // 3. 核心事务操作
        Order order = transactionService.doCreateOrder(dto, product);
        
        // 4. 后置处理（无事务）
        sendNotification(order);
        
        return OrderResult.success(order);
    }
}

@Service
public class OrderTransactionService {
    
    /**
     * 内层方法：只包含数据库操作，加事务
     */
    @Transactional(rollbackFor = Exception.class)
    public Order doCreateOrder(OrderDTO dto, Product product) {
        // 1. 创建订单
        Order order = new Order();
        order.setUserId(dto.getUserId());
        order.setProductId(product.getId());
        order.setAmount(product.getPrice().multiply(new BigDecimal(dto.getQuantity())));
        orderMapper.insert(order);
        
        // 2. 扣减库存
        int rows = stockMapper.decrease(product.getId(), dto.getQuantity());
        if (rows == 0) {
            throw new BusinessException("库存不足");
        }
        
        // 3. 创建支付单
        Payment payment = new Payment();
        payment.setOrderId(order.getId());
        payment.setAmount(order.getAmount());
        paymentMapper.insert(payment);
        
        return order;
    }
}
```

### 10.3 异常处理最佳实践

```java
@Service
@Slf4j
public class ExceptionHandlingService {
    
    /**
     * ✅ 最佳实践：统一异常处理
     */
    @Transactional(rollbackFor = Exception.class)
    public void bestPractice(OrderDTO dto) {
        try {
            orderMapper.insert(order);
            stockMapper.decrease(productId, quantity);
        } catch (DuplicateKeyException e) {
            // 业务异常，转换后抛出
            log.warn("订单重复: {}", dto.getOrderNo());
            throw new BusinessException("订单已存在", e);
        } catch (DataAccessException e) {
            // 数据库异常，记录日志后抛出
            log.error("数据库操作失败", e);
            throw new SystemException("系统繁忙，请稍后重试", e);
        }
        // 其他异常自动抛出，触发回滚
    }
}

/**
 * 自定义业务异常
 */
public class BusinessException extends RuntimeException {
    private String code;
    private String message;
    
    public BusinessException(String message) {
        super(message);
        this.message = message;
    }
    
    public BusinessException(String message, Throwable cause) {
        super(message, cause);
        this.message = message;
    }
}
```

### 10.4 日志记录最佳实践

```java
@Service
@Slf4j
public class LoggingService {
    
    @Transactional(rollbackFor = Exception.class)
    public void createOrder(OrderDTO dto) {
        log.info("开始创建订单, userId={}, productId={}", dto.getUserId(), dto.getProductId());
        
        try {
            Order order = new Order();
            // ... 设置属性
            orderMapper.insert(order);
            log.info("订单创建成功, orderId={}", order.getId());
            
            stockMapper.decrease(dto.getProductId(), dto.getQuantity());
            log.info("库存扣减成功, productId={}, quantity={}", dto.getProductId(), dto.getQuantity());
            
        } catch (Exception e) {
            log.error("创建订单失败, dto={}", dto, e);
            throw e;
        }
    }
}
```

### 10.5 性能优化最佳实践

```java
@Service
public class PerformanceService {
    
    /**
     * ✅ 批量操作使用批量插入
     */
    @Transactional(rollbackFor = Exception.class)
    public void batchInsert(List<User> users) {
        // 分批插入，每批 500 条
        int batchSize = 500;
        for (int i = 0; i < users.size(); i += batchSize) {
            int end = Math.min(i + batchSize, users.size());
            List<User> batch = users.subList(i, end);
            userMapper.insertBatch(batch);
        }
    }
    
    /**
     * ✅ 大事务拆分成小事务
     */
    public void processLargeData(List<Order> orders) {
        // 每 100 条一个事务
        int batchSize = 100;
        for (int i = 0; i < orders.size(); i += batchSize) {
            int end = Math.min(i + batchSize, orders.size());
            List<Order> batch = orders.subList(i, end);
            
            // 每批单独事务
            processBatch(batch);
        }
    }
    
    @Transactional(rollbackFor = Exception.class)
    public void processBatch(List<Order> orders) {
        for (Order order : orders) {
            orderMapper.updateById(order);
        }
    }
    
    /**
     * ✅ 避免在事务中进行远程调用
     */
    public void createOrderWithRemoteCall(OrderDTO dto) {
        // 1. 远程调用放在事务外
        UserInfo user = userClient.getUser(dto.getUserId());
        ProductInfo product = productClient.getProduct(dto.getProductId());
        
        // 2. 数据库操作放在事务内
        doCreateOrder(dto, user, product);
        
        // 3. 消息发送放在事务外
        messageService.sendOrderCreatedMessage(dto);
    }
    
    @Transactional(rollbackFor = Exception.class)
    public void doCreateOrder(OrderDTO dto, UserInfo user, ProductInfo product) {
        // 只有数据库操作
        orderMapper.insert(order);
        stockMapper.decrease(productId, quantity);
    }
}
```

---

## 11. 常见错误与解决方案

### 11.1 错误1：事务不回滚

**现象**：抛出异常了，但数据没有回滚

**排查步骤**：
```java
// 1. 检查异常类型
@Transactional  // 默认只对 RuntimeException 回滚
public void method() throws IOException {
    throw new IOException();  // checked 异常，不回滚
}

// 解决：添加 rollbackFor
@Transactional(rollbackFor = Exception.class)

// 2. 检查异常是否被吞掉
@Transactional
public void method() {
    try {
        // ...
    } catch (Exception e) {
        log.error("error", e);  // 异常被吞掉，不回滚
    }
}

// 解决：重新抛出或手动回滚
catch (Exception e) {
    log.error("error", e);
    throw e;  // 或 TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
}
```

### 11.2 错误2：事务不生效

**现象**：加了 @Transactional，但事务根本没开启

```java
// 1. 检查是否是内部调用
public void methodA() {
    this.methodB();  // 内部调用，事务不生效
}

@Transactional
public void methodB() { }

// 解决：注入自己或拆分 Service

// 2. 检查方法是否是 public
@Transactional
private void method() { }  // private 方法，事务不生效

// 解决：改为 public

// 3. 检查类是否被 Spring 管理
public class MyService {  // 没有 @Service，不被 Spring 管理
    @Transactional
    public void method() { }
}

// 解决：添加 @Service 注解
```


### 11.3 错误3：事务超时

**现象**：事务执行时间过长，被强制回滚

```java
// 错误日志
// org.springframework.transaction.TransactionTimedOutException: 
// Transaction timed out: deadline was ...

// 原因：事务执行时间超过了 timeout 设置

// 解决方案1：增加超时时间
@Transactional(timeout = 60)  // 60秒

// 解决方案2：优化事务内的操作
@Transactional
public void method() {
    // ❌ 不要在事务中做耗时操作
    Thread.sleep(10000);  // 睡眠
    httpClient.call();     // 远程调用
    
    // ✅ 只做数据库操作
    userMapper.insert(user);
}

// 解决方案3：拆分大事务
public void processAll(List<Data> dataList) {
    for (Data data : dataList) {
        processSingle(data);  // 每条数据单独事务
    }
}

@Transactional(timeout = 10)
public void processSingle(Data data) {
    // 处理单条数据
}
```

### 11.4 错误4：死锁

**现象**：多个事务相互等待，导致死锁

```java
// 错误日志
// com.mysql.cj.jdbc.exceptions.MySQLTransactionRollbackException: 
// Deadlock found when trying to get lock

// 场景：事务A锁定记录1，等待记录2；事务B锁定记录2，等待记录1

// 解决方案1：按固定顺序访问资源
@Transactional
public void transfer(Long fromId, Long toId, BigDecimal amount) {
    // 按 ID 大小顺序锁定，避免死锁
    Long firstId = Math.min(fromId, toId);
    Long secondId = Math.max(fromId, toId);
    
    Account first = accountMapper.selectByIdForUpdate(firstId);
    Account second = accountMapper.selectByIdForUpdate(secondId);
    
    // 执行转账
}

// 解决方案2：使用乐观锁
@Update("UPDATE account SET balance = balance - #{amount}, version = version + 1 " +
        "WHERE id = #{id} AND version = #{version} AND balance >= #{amount}")
int decreaseWithVersion(@Param("id") Long id, 
                        @Param("amount") BigDecimal amount,
                        @Param("version") Integer version);

// 解决方案3：减小事务粒度，缩短锁持有时间
```

### 11.5 错误5：连接池耗尽

**现象**：获取数据库连接超时

```java
// 错误日志
// HikariPool-1 - Connection is not available, request timed out after 30000ms

// 原因1：事务时间过长，连接被长时间占用
@Transactional
public void longTransaction() {
    userMapper.insert(user);
    Thread.sleep(60000);  // 连接被占用 60 秒
}

// 原因2：事务没有正确关闭（异常情况）

// 解决方案1：增加连接池大小
spring:
  datasource:
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000

// 解决方案2：减小事务时间
// 解决方案3：检查是否有连接泄漏
```

### 11.6 错误6：脏读/幻读

**现象**：读取到了不一致的数据

```java
// 场景：统计报表时，数据在统计过程中被修改

// 解决方案1：使用合适的隔离级别
@Transactional(isolation = Isolation.REPEATABLE_READ, readOnly = true)
public ReportData generateReport() {
    // 统计过程中数据一致
    long count1 = userMapper.count();
    // ... 其他统计
    long count2 = userMapper.count();  // 与 count1 相同
    return report;
}

// 解决方案2：使用快照查询（MySQL 特有）
@Select("SELECT * FROM user AS OF TIMESTAMP '2024-01-01 00:00:00'")
List<User> selectSnapshot();
```

### 11.7 错误7：REQUIRES_NEW 不生效

**现象**：使用了 REQUIRES_NEW，但子事务没有独立

```java
// 错误：同类内部调用
@Service
public class MyService {
    
    @Transactional
    public void outer() {
        // 内部调用，REQUIRES_NEW 不生效
        this.inner();
    }
    
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void inner() {
        // 实际上还是在 outer 的事务中
    }
}

// 解决：拆分到不同的 Service
@Service
public class OuterService {
    @Autowired
    private InnerService innerService;
    
    @Transactional
    public void outer() {
        innerService.inner();  // 通过代理调用，REQUIRES_NEW 生效
    }
}

@Service
public class InnerService {
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void inner() {
        // 独立事务
    }
}
```

### 11.8 调试技巧

```yaml
# 开启事务日志
logging:
  level:
    # 显示事务创建、提交、回滚日志
    org.springframework.transaction: DEBUG
    org.springframework.jdbc: DEBUG
    # 显示 SQL 语句
    org.mybatis: DEBUG
    com.zaxxer.hikari: DEBUG
```

```java
// 代码中打印事务状态
@Transactional
public void debugTransaction() {
    // 获取当前事务名称
    String txName = TransactionSynchronizationManager.getCurrentTransactionName();
    log.info("当前事务: {}", txName);
    
    // 是否在事务中
    boolean isActive = TransactionSynchronizationManager.isActualTransactionActive();
    log.info("事务是否激活: {}", isActive);
    
    // 是否只读
    boolean isReadOnly = TransactionSynchronizationManager.isCurrentTransactionReadOnly();
    log.info("是否只读事务: {}", isReadOnly);
}
```

---

## 附录：速查表

### A. @Transactional 常用配置

```java
// 标准写法（推荐）
@Transactional(
    rollbackFor = Exception.class,    // 所有异常都回滚
    timeout = 30,                      // 30秒超时
    propagation = Propagation.REQUIRED // 默认传播行为
)

// 只读事务
@Transactional(readOnly = true)

// 独立事务
@Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)

// 嵌套事务
@Transactional(propagation = Propagation.NESTED, rollbackFor = Exception.class)
```

### B. 传播行为速查

| 传播行为 | 当前有事务 | 当前无事务 | 使用场景 |
|----------|-----------|-----------|----------|
| REQUIRED | 加入 | 新建 | 默认，大多数场景 |
| REQUIRES_NEW | 挂起，新建 | 新建 | 日志、独立操作 |
| NESTED | 嵌套 | 新建 | 部分回滚 |
| SUPPORTS | 加入 | 非事务 | 查询 |
| NOT_SUPPORTED | 挂起 | 非事务 | 不需要事务 |
| MANDATORY | 加入 | 抛异常 | 强制要求事务 |
| NEVER | 抛异常 | 非事务 | 强制无事务 |

### C. 隔离级别速查

| 隔离级别 | 脏读 | 不可重复读 | 幻读 | 性能 |
|----------|------|-----------|------|------|
| READ_UNCOMMITTED | ✗ | ✗ | ✗ | 最好 |
| READ_COMMITTED | ✓ | ✗ | ✗ | 好 |
| REPEATABLE_READ | ✓ | ✓ | ✗ | 一般 |
| SERIALIZABLE | ✓ | ✓ | ✓ | 最差 |

---

