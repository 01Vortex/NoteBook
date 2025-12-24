> 基于 Java 8 + Spring Boot 2.7.18 环境
> Hibernate 是一个开源的对象关系映射（ORM）框架，它对 JDBC 进行了轻量级的封装，使得 Java 程序员可以使用面向对象的思维来操作数据库。

---

## 目录

1. [基础概念](#1.基础概念)
2. [环境搭建](#2.环境搭建)
3. [实体映射](#3.实体映射)
4. [基本CRUD操作](#4.基本crud操作)
5. [HQL与JPQL查询](#5.hql与jpql查询)
6. [Criteria查询](#6.criteria查询)
7. [关联映射](#7.关联映射)
8. [级联操作与延迟加载](#8.级联操作与延迟加载)
9. [缓存机制](#9.缓存机制)
10. [事务管理](#10.事务管理)
11. [性能优化](#11.性能优化)
12. [常见错误与解决方案](#12.常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Hibernate？

Hibernate 是一个强大的 ORM（Object-Relational Mapping，对象关系映射）框架。简单来说，它帮你把 Java 对象和数据库表之间建立映射关系，让你可以用操作对象的方式来操作数据库，而不用写繁琐的 SQL 语句。

**举个例子：**
- 没有 Hibernate：你需要写 `INSERT INTO user (name, age) VALUES ('张三', 18)`
- 有了 Hibernate：你只需要 `session.save(user)`，框架自动帮你生成 SQL

### 1.2 ORM 的核心思想

ORM 的核心思想是将数据库表映射为 Java 类，表中的每一行数据映射为一个 Java 对象，表中的列映射为对象的属性。

```
┌─────────────────┐         ┌─────────────────┐
│   数据库表       │         │   Java 类        │
├─────────────────┤         ├─────────────────┤
│ user 表         │  ←───→  │ User 类          │
│ - id            │         │ - Long id        │
│ - name          │         │ - String name    │
│ - age           │         │ - Integer age    │
│ - email         │         │ - String email   │
└─────────────────┘         └─────────────────┘
```

### 1.3 Hibernate 与 JPA 的关系

**JPA（Java Persistence API）** 是 Java 官方定义的 ORM 规范（接口），而 **Hibernate** 是 JPA 规范的一个实现。

```
┌─────────────────────────────────────────┐
│              JPA 规范（接口）             │
└─────────────────────────────────────────┘
                    ↑
        ┌───────────┼───────────┐
        ↑           ↑           ↑
┌───────────┐ ┌───────────┐ ┌───────────┐
│ Hibernate │ │ EclipseLink│ │ OpenJPA   │
│  （实现）   │ │  （实现）   │ │  （实现）   │
└───────────┘ └───────────┘ └───────────┘
```

在 Spring Boot 中，我们通常使用 **Spring Data JPA**，它底层默认使用 Hibernate 作为 JPA 的实现。

### 1.4 核心概念

| 概念 | 说明 |
|------|------|
| **SessionFactory** | 重量级对象，线程安全，整个应用只需要一个实例，用于创建 Session |
| **Session** | 轻量级对象，非线程安全，代表与数据库的一次会话，用于执行 CRUD 操作 |
| **Transaction** | 事务对象，用于管理数据库事务 |
| **Entity** | 实体类，与数据库表对应的 Java 类 |
| **EntityManager** | JPA 中的概念，类似于 Hibernate 的 Session |

### 1.5 Hibernate 的优缺点

**优点：**
- 提高开发效率，减少 SQL 编写
- 数据库无关性，切换数据库只需修改配置
- 提供缓存机制，提高查询性能
- 支持延迟加载，优化内存使用
- 自动生成 SQL，减少出错概率

**缺点：**
- 学习曲线较陡
- 复杂查询性能可能不如原生 SQL
- 自动生成的 SQL 可能不是最优的
- 对于简单项目可能过于重量级

---

## 2. 环境搭建

### 2.1 Maven 依赖配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.18</version>
        <relativePath/>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>hibernate-demo</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>1.8</java.version>
    </properties>
    
    <dependencies>
        <!-- Spring Boot Starter Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- Spring Data JPA（内含 Hibernate） -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        
        <!-- MySQL 驱动 -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.33</version>
        </dependency>
        
        <!-- Lombok（简化代码） -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <!-- 测试依赖 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

> **注意**：`spring-boot-starter-data-jpa` 已经包含了 Hibernate，不需要单独引入 Hibernate 依赖。

### 2.2 数据库配置

在 `application.yml` 中配置数据源和 JPA/Hibernate：

```yaml
# application.yml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/hibernate_demo?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: your_password
    
  jpa:
    # 数据库类型
    database: mysql
    # 显示 SQL 语句
    show-sql: true
    # Hibernate 配置
    hibernate:
      # DDL 策略：
      # none - 不做任何操作
      # validate - 验证表结构，不匹配则报错
      # update - 自动更新表结构（开发环境推荐）
      # create - 每次启动都重新创建表（会删除数据！）
      # create-drop - 启动时创建，关闭时删除
      ddl-auto: update
      # 命名策略：将驼峰命名转换为下划线
      naming:
        physical-strategy: org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
        implicit-strategy: org.hibernate.boot.model.naming.ImplicitNamingStrategyLegacyJpaImpl
    # JPA 属性
    properties:
      hibernate:
        # SQL 格式化
        format_sql: true
        # 方言（MySQL 8）
        dialect: org.hibernate.dialect.MySQL8Dialect
        # 批量操作大小
        jdbc:
          batch_size: 50
        # 排序插入和更新
        order_inserts: true
        order_updates: true

# 日志配置（可选，用于查看详细 SQL）
logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
```

### 2.3 创建数据库

```sql
-- 创建数据库
CREATE DATABASE IF NOT EXISTS hibernate_demo 
DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE hibernate_demo;

-- 如果使用 ddl-auto: update，表会自动创建
-- 如果想手动创建，可以使用以下 SQL：

CREATE TABLE `user` (
    `id` BIGINT(20) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
    `username` VARCHAR(50) NOT NULL COMMENT '用户名',
    `password` VARCHAR(100) NOT NULL COMMENT '密码',
    `email` VARCHAR(100) DEFAULT NULL COMMENT '邮箱',
    `age` INT(11) DEFAULT NULL COMMENT '年龄',
    `status` TINYINT(1) DEFAULT 1 COMMENT '状态(0-禁用,1-启用)',
    `create_time` DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `update_time` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_username` (`username`),
    UNIQUE KEY `uk_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';
```

### 2.4 启动类配置

```java
package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing  // 启用 JPA 审计功能（用于自动填充创建时间、更新时间）
public class HibernateDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(HibernateDemoApplication.class, args);
    }
}
```

---

## 3. 实体映射

### 3.1 基本实体类

```java
package com.example.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * 用户实体类
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity                          // 标识这是一个 JPA 实体
@Table(name = "user")            // 指定表名
@DynamicInsert                   // 动态插入：只插入非 null 字段
@DynamicUpdate                   // 动态更新：只更新变化的字段
@EntityListeners(AuditingEntityListener.class)  // 启用审计监听器
public class User {
    
    /**
     * 主键
     * @Id 标识主键字段
     * @GeneratedValue 指定主键生成策略
     *   - IDENTITY: 数据库自增（MySQL 推荐）
     *   - SEQUENCE: 序列（Oracle、PostgreSQL）
     *   - TABLE: 使用表模拟序列
     *   - AUTO: 自动选择策略
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    /**
     * 用户名
     * @Column 指定列属性
     */
    @Column(name = "username", length = 50, nullable = false, unique = true)
    private String username;
    
    /**
     * 密码
     */
    @Column(name = "password", length = 100, nullable = false)
    private String password;
    
    /**
     * 邮箱
     */
    @Column(name = "email", length = 100, unique = true)
    private String email;
    
    /**
     * 年龄
     */
    @Column(name = "age")
    private Integer age;
    
    /**
     * 状态
     */
    @Column(name = "status", columnDefinition = "TINYINT(1) DEFAULT 1")
    private Integer status;
    
    /**
     * 创建时间
     * @CreatedDate 自动填充创建时间
     */
    @CreatedDate
    @Column(name = "create_time", updatable = false)
    private LocalDateTime createTime;
    
    /**
     * 更新时间
     * @LastModifiedDate 自动填充更新时间
     */
    @LastModifiedDate
    @Column(name = "update_time")
    private LocalDateTime updateTime;
    
    /**
     * 非持久化字段（不映射到数据库）
     */
    @Transient
    private String tempField;
}
```

### 3.2 常用注解详解

| 注解 | 作用位置 | 说明 |
|------|----------|------|
| `@Entity` | 类 | 标识该类是一个 JPA 实体 |
| `@Table` | 类 | 指定实体对应的表名及其他表属性 |
| `@Id` | 字段 | 标识主键字段 |
| `@GeneratedValue` | 字段 | 指定主键生成策略 |
| `@Column` | 字段 | 指定字段与数据库列的映射关系 |
| `@Transient` | 字段 | 标识非持久化字段，不映射到数据库 |
| `@Temporal` | 字段 | 指定日期类型（DATE、TIME、TIMESTAMP） |
| `@Enumerated` | 字段 | 指定枚举类型的存储方式 |
| `@Lob` | 字段 | 标识大对象字段（BLOB、CLOB） |
| `@Basic` | 字段 | 指定字段的加载策略 |
| `@Embedded` | 字段 | 标识嵌入式对象 |
| `@Embeddable` | 类 | 标识可嵌入的类 |

### 3.3 @Column 属性详解

```java
@Column(
    name = "column_name",      // 列名
    length = 255,              // 长度（字符串类型）
    precision = 10,            // 精度（数值类型）
    scale = 2,                 // 小数位数（数值类型）
    nullable = true,           // 是否允许为空
    unique = false,            // 是否唯一
    insertable = true,         // 是否参与插入
    updatable = true,          // 是否参与更新
    columnDefinition = "..."   // 自定义列定义
)
private String fieldName;
```

### 3.4 枚举类型映射

```java
/**
 * 用户状态枚举
 */
public enum UserStatus {
    DISABLED(0, "禁用"),
    ENABLED(1, "启用"),
    LOCKED(2, "锁定");
    
    private final Integer code;
    private final String desc;
    
    UserStatus(Integer code, String desc) {
        this.code = code;
        this.desc = desc;
    }
    
    public Integer getCode() {
        return code;
    }
    
    public String getDesc() {
        return desc;
    }
}

/**
 * 在实体类中使用枚举
 */
@Entity
public class User {
    
    // 方式一：存储枚举名称（字符串）
    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 20)
    private UserStatus status;
    
    // 方式二：存储枚举序号（整数，从0开始）
    // @Enumerated(EnumType.ORDINAL)
    // private UserStatus status;
}
```

### 3.5 日期类型映射

```java
@Entity
public class User {
    
    // Java 8 日期类型（推荐）
    private LocalDate birthDate;           // 对应 DATE
    private LocalTime loginTime;           // 对应 TIME
    private LocalDateTime createTime;      // 对应 DATETIME/TIMESTAMP
    
    // 旧版日期类型（需要 @Temporal 注解）
    @Temporal(TemporalType.DATE)
    private Date birthDate2;               // 只存储日期
    
    @Temporal(TemporalType.TIME)
    private Date loginTime2;               // 只存储时间
    
    @Temporal(TemporalType.TIMESTAMP)
    private Date createTime2;              // 存储日期和时间
}
```

### 3.6 大对象映射

```java
@Entity
public class Article {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String title;
    
    /**
     * 文章内容（大文本）
     * @Lob 标识大对象
     * 对于 String 类型，映射为 CLOB（字符大对象）
     */
    @Lob
    @Basic(fetch = FetchType.LAZY)  // 延迟加载
    @Column(name = "content", columnDefinition = "LONGTEXT")
    private String content;
    
    /**
     * 图片数据（二进制）
     * 对于 byte[] 类型，映射为 BLOB（二进制大对象）
     */
    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(name = "image")
    private byte[] image;
}
```

### 3.7 嵌入式对象

当多个实体有相同的字段组合时，可以使用嵌入式对象来复用：

```java
/**
 * 地址（可嵌入类）
 */
@Embeddable
@Data
public class Address {
    
    @Column(name = "province", length = 50)
    private String province;  // 省
    
    @Column(name = "city", length = 50)
    private String city;      // 市
    
    @Column(name = "district", length = 50)
    private String district;  // 区
    
    @Column(name = "detail", length = 200)
    private String detail;    // 详细地址
}

/**
 * 用户实体
 */
@Entity
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    
    /**
     * 嵌入地址对象
     * 地址的字段会直接映射到 user 表中
     */
    @Embedded
    private Address address;
    
    /**
     * 如果有多个相同类型的嵌入对象，需要重写列名
     */
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "province", column = @Column(name = "work_province")),
        @AttributeOverride(name = "city", column = @Column(name = "work_city")),
        @AttributeOverride(name = "district", column = @Column(name = "work_district")),
        @AttributeOverride(name = "detail", column = @Column(name = "work_detail"))
    })
    private Address workAddress;
}
```

---

## 4. 基本CRUD操作

### 4.1 创建 Repository 接口

Spring Data JPA 提供了 `JpaRepository` 接口，继承它就能获得基本的 CRUD 功能：

```java
package com.example.repository;

import com.example.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * 用户 Repository
 * 
 * JpaRepository<实体类, 主键类型> 提供基本 CRUD
 * JpaSpecificationExecutor<实体类> 提供复杂查询支持
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long>, 
                                        JpaSpecificationExecutor<User> {
    
    // ============ 方法名查询（Spring Data JPA 自动实现） ============
    
    // 根据用户名查询
    Optional<User> findByUsername(String username);
    
    // 根据邮箱查询
    User findByEmail(String email);
    
    // 根据年龄范围查询
    List<User> findByAgeBetween(Integer minAge, Integer maxAge);
    
    // 根据状态查询并按创建时间降序
    List<User> findByStatusOrderByCreateTimeDesc(Integer status);
    
    // 模糊查询
    List<User> findByUsernameLike(String username);
    List<User> findByUsernameContaining(String username);
    List<User> findByUsernameStartingWith(String username);
    List<User> findByUsernameEndingWith(String username);
    
    // 多条件查询
    List<User> findByUsernameAndStatus(String username, Integer status);
    List<User> findByUsernameOrEmail(String username, String email);
    
    // 判断是否存在
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    
    // 统计数量
    long countByStatus(Integer status);
    
    // 删除
    void deleteByUsername(String username);
}
```

### 4.2 JpaRepository 提供的方法

```java
// ============ 保存 ============
<S extends T> S save(S entity);                    // 保存单个实体
<S extends T> List<S> saveAll(Iterable<S> entities);  // 批量保存
<S extends T> S saveAndFlush(S entity);            // 保存并立即刷新

// ============ 删除 ============
void deleteById(ID id);                            // 根据 ID 删除
void delete(T entity);                             // 删除实体
void deleteAll(Iterable<? extends T> entities);    // 批量删除
void deleteAll();                                  // 删除所有
void deleteAllById(Iterable<? extends ID> ids);    // 根据 ID 批量删除
void deleteAllInBatch();                           // 批量删除（一条 SQL）
void deleteAllByIdInBatch(Iterable<ID> ids);       // 根据 ID 批量删除（一条 SQL）

// ============ 查询 ============
Optional<T> findById(ID id);                       // 根据 ID 查询
List<T> findAll();                                 // 查询所有
List<T> findAllById(Iterable<ID> ids);             // 根据 ID 批量查询
List<T> findAll(Sort sort);                        // 查询所有并排序
Page<T> findAll(Pageable pageable);                // 分页查询
boolean existsById(ID id);                         // 判断是否存在
long count();                                      // 统计数量

// ============ 其他 ============
void flush();                                      // 刷新缓存到数据库
T getById(ID id);                                  // 获取引用（延迟加载）
T getReferenceById(ID id);                         // 获取引用（延迟加载，推荐）
```

### 4.3 Service 层实现

```java
package com.example.service;

import com.example.entity.User;
import java.util.List;
import java.util.Optional;

public interface UserService {
    User save(User user);
    User update(User user);
    void deleteById(Long id);
    Optional<User> findById(Long id);
    List<User> findAll();
    User findByUsername(String username);
}
```

```java
package com.example.service.impl;

import com.example.entity.User;
import com.example.repository.UserRepository;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)  // 默认只读事务
public class UserServiceImpl implements UserService {
    
    private final UserRepository userRepository;
    
    /**
     * 保存用户
     */
    @Override
    @Transactional  // 写操作需要开启事务
    public User save(User user) {
        return userRepository.save(user);
    }
    
    /**
     * 更新用户
     */
    @Override
    @Transactional
    public User update(User user) {
        // 先查询确保存在
        User existingUser = userRepository.findById(user.getId())
                .orElseThrow(() -> new RuntimeException("用户不存在"));
        
        // 更新字段
        existingUser.setUsername(user.getUsername());
        existingUser.setEmail(user.getEmail());
        existingUser.setAge(user.getAge());
        // ... 其他字段
        
        // save 方法会根据 ID 判断是插入还是更新
        return userRepository.save(existingUser);
    }
    
    /**
     * 删除用户
     */
    @Override
    @Transactional
    public void deleteById(Long id) {
        userRepository.deleteById(id);
    }
    
    /**
     * 根据 ID 查询
     */
    @Override
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
    
    /**
     * 查询所有
     */
    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    /**
     * 根据用户名查询
     */
    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }
}
```

### 4.4 方法名查询规则

Spring Data JPA 支持通过方法名自动生成查询，规则如下：

| 关键字 | 方法名示例 | 对应 SQL |
|--------|-----------|----------|
| `And` | `findByNameAndAge` | `WHERE name = ? AND age = ?` |
| `Or` | `findByNameOrAge` | `WHERE name = ? OR age = ?` |
| `Is`, `Equals` | `findByName`, `findByNameIs` | `WHERE name = ?` |
| `Between` | `findByAgeBetween` | `WHERE age BETWEEN ? AND ?` |
| `LessThan` | `findByAgeLessThan` | `WHERE age < ?` |
| `LessThanEqual` | `findByAgeLessThanEqual` | `WHERE age <= ?` |
| `GreaterThan` | `findByAgeGreaterThan` | `WHERE age > ?` |
| `GreaterThanEqual` | `findByAgeGreaterThanEqual` | `WHERE age >= ?` |
| `After` | `findByCreateTimeAfter` | `WHERE create_time > ?` |
| `Before` | `findByCreateTimeBefore` | `WHERE create_time < ?` |
| `IsNull`, `Null` | `findByEmailIsNull` | `WHERE email IS NULL` |
| `IsNotNull`, `NotNull` | `findByEmailIsNotNull` | `WHERE email IS NOT NULL` |
| `Like` | `findByNameLike` | `WHERE name LIKE ?` |
| `NotLike` | `findByNameNotLike` | `WHERE name NOT LIKE ?` |
| `StartingWith` | `findByNameStartingWith` | `WHERE name LIKE '?%'` |
| `EndingWith` | `findByNameEndingWith` | `WHERE name LIKE '%?'` |
| `Containing` | `findByNameContaining` | `WHERE name LIKE '%?%'` |
| `OrderBy` | `findByAgeOrderByNameDesc` | `ORDER BY name DESC` |
| `Not` | `findByNameNot` | `WHERE name <> ?` |
| `In` | `findByAgeIn(Collection)` | `WHERE age IN (?, ?, ...)` |
| `NotIn` | `findByAgeNotIn(Collection)` | `WHERE age NOT IN (?, ?, ...)` |
| `True` | `findByActiveTrue` | `WHERE active = true` |
| `False` | `findByActiveFalse` | `WHERE active = false` |
| `IgnoreCase` | `findByNameIgnoreCase` | `WHERE UPPER(name) = UPPER(?)` |
| `Top`, `First` | `findTop10ByAge` | `LIMIT 10` |
| `Distinct` | `findDistinctByName` | `SELECT DISTINCT ...` |

### 4.5 分页与排序

```java
@Service
public class UserServiceImpl implements UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    /**
     * 分页查询
     */
    public Page<User> findByPage(int pageNum, int pageSize) {
        // PageRequest.of(页码从0开始, 每页条数)
        Pageable pageable = PageRequest.of(pageNum - 1, pageSize);
        return userRepository.findAll(pageable);
    }
    
    /**
     * 分页 + 排序
     */
    public Page<User> findByPageWithSort(int pageNum, int pageSize) {
        // 按创建时间降序
        Sort sort = Sort.by(Sort.Direction.DESC, "createTime");
        Pageable pageable = PageRequest.of(pageNum - 1, pageSize, sort);
        return userRepository.findAll(pageable);
    }
    
    /**
     * 多字段排序
     */
    public Page<User> findByPageWithMultiSort(int pageNum, int pageSize) {
        Sort sort = Sort.by(
            Sort.Order.desc("status"),
            Sort.Order.asc("username"),
            Sort.Order.desc("createTime")
        );
        Pageable pageable = PageRequest.of(pageNum - 1, pageSize, sort);
        return userRepository.findAll(pageable);
    }
    
    /**
     * 使用 Page 对象
     */
    public void usePage() {
        Page<User> page = userRepository.findAll(PageRequest.of(0, 10));
        
        // 获取分页信息
        List<User> content = page.getContent();        // 当前页数据
        long totalElements = page.getTotalElements();  // 总记录数
        int totalPages = page.getTotalPages();         // 总页数
        int number = page.getNumber();                 // 当前页码（从0开始）
        int size = page.getSize();                     // 每页条数
        boolean hasNext = page.hasNext();              // 是否有下一页
        boolean hasPrevious = page.hasPrevious();      // 是否有上一页
        boolean isFirst = page.isFirst();              // 是否是第一页
        boolean isLast = page.isLast();                // 是否是最后一页
    }
}
```

---

## 5. HQL与JPQL查询

### 5.1 什么是 HQL 和 JPQL？

- **HQL（Hibernate Query Language）**：Hibernate 特有的查询语言
- **JPQL（Java Persistence Query Language）**：JPA 标准的查询语言

两者语法几乎相同，主要区别是 JPQL 是 JPA 标准，而 HQL 是 Hibernate 特有的。在 Spring Data JPA 中，我们通常使用 JPQL。

**与 SQL 的区别：**
- SQL 操作的是表和列
- JPQL/HQL 操作的是实体类和属性

### 5.2 使用 @Query 注解

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // ============ JPQL 查询 ============
    
    /**
     * 基本查询
     * 注意：User 是实体类名，不是表名
     */
    @Query("SELECT u FROM User u WHERE u.username = ?1")
    User findByUsernameJpql(String username);
    
    /**
     * 使用命名参数
     */
    @Query("SELECT u FROM User u WHERE u.username = :username AND u.status = :status")
    User findByUsernameAndStatusJpql(@Param("username") String username, 
                                      @Param("status") Integer status);
    
    /**
     * 模糊查询
     */
    @Query("SELECT u FROM User u WHERE u.username LIKE %:keyword%")
    List<User> searchByUsername(@Param("keyword") String keyword);
    
    /**
     * IN 查询
     */
    @Query("SELECT u FROM User u WHERE u.id IN :ids")
    List<User> findByIdIn(@Param("ids") List<Long> ids);
    
    /**
     * 排序
     */
    @Query("SELECT u FROM User u WHERE u.status = :status ORDER BY u.createTime DESC")
    List<User> findByStatusOrderByCreateTime(@Param("status") Integer status);
    
    /**
     * 分页查询
     */
    @Query("SELECT u FROM User u WHERE u.status = :status")
    Page<User> findByStatusWithPage(@Param("status") Integer status, Pageable pageable);
    
    /**
     * 统计查询
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.status = :status")
    Long countByStatusJpql(@Param("status") Integer status);
    
    /**
     * 查询部分字段（返回 Object[]）
     */
    @Query("SELECT u.id, u.username, u.email FROM User u WHERE u.status = 1")
    List<Object[]> findIdAndUsernameAndEmail();
    
    /**
     * 查询部分字段（返回 DTO，使用构造函数）
     */
    @Query("SELECT new com.example.dto.UserDTO(u.id, u.username, u.email) FROM User u WHERE u.status = 1")
    List<UserDTO> findUserDTOList();
    
    // ============ 原生 SQL 查询 ============
    
    /**
     * 使用原生 SQL
     * nativeQuery = true 表示使用原生 SQL
     */
    @Query(value = "SELECT * FROM user WHERE username = ?1", nativeQuery = true)
    User findByUsernameNative(String username);
    
    /**
     * 原生 SQL 分页
     * 需要提供 countQuery
     */
    @Query(value = "SELECT * FROM user WHERE status = :status",
           countQuery = "SELECT COUNT(*) FROM user WHERE status = :status",
           nativeQuery = true)
    Page<User> findByStatusNative(@Param("status") Integer status, Pageable pageable);
}
```

### 5.3 更新和删除操作

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * 更新操作
     * @Modifying 标识这是一个更新/删除操作
     * @Transactional 需要事务支持
     * clearAutomatically = true 执行后清除持久化上下文
     */
    @Modifying(clearAutomatically = true)
    @Transactional
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    int updateStatusById(@Param("id") Long id, @Param("status") Integer status);
    
    /**
     * 批量更新
     */
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.status = :status WHERE u.id IN :ids")
    int updateStatusByIds(@Param("ids") List<Long> ids, @Param("status") Integer status);
    
    /**
     * 删除操作
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM User u WHERE u.id = :id")
    int deleteByIdJpql(@Param("id") Long id);
    
    /**
     * 原生 SQL 更新
     */
    @Modifying
    @Transactional
    @Query(value = "UPDATE user SET status = :status WHERE id = :id", nativeQuery = true)
    int updateStatusByIdNative(@Param("id") Long id, @Param("status") Integer status);
}
```

### 5.4 动态查询（SpEL 表达式）

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * 使用 SpEL 表达式获取实体类名
     * #{#entityName} 会被替换为实体类名（User）
     */
    @Query("SELECT u FROM #{#entityName} u WHERE u.status = :status")
    List<User> findByStatusSpel(@Param("status") Integer status);
    
    /**
     * 条件判断
     */
    @Query("SELECT u FROM User u WHERE " +
           "(:username IS NULL OR u.username LIKE %:username%) AND " +
           "(:status IS NULL OR u.status = :status)")
    List<User> findByCondition(@Param("username") String username, 
                               @Param("status") Integer status);
}
```

### 5.5 DTO 投影查询

当只需要查询部分字段时，可以使用 DTO 投影：

```java
/**
 * 用户 DTO
 */
@Data
@AllArgsConstructor
public class UserDTO {
    private Long id;
    private String username;
    private String email;
}

/**
 * 接口投影（推荐）
 */
public interface UserProjection {
    Long getId();
    String getUsername();
    String getEmail();
    
    // 可以使用 @Value 进行计算
    @Value("#{target.username + ' (' + target.email + ')'}")
    String getDisplayName();
}

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * 使用接口投影
     */
    List<UserProjection> findProjectionByStatus(Integer status);
    
    /**
     * 使用 DTO 构造函数
     */
    @Query("SELECT new com.example.dto.UserDTO(u.id, u.username, u.email) " +
           "FROM User u WHERE u.status = :status")
    List<UserDTO> findDTOByStatus(@Param("status") Integer status);
}
```

---

## 6. Criteria查询

Criteria 查询是一种类型安全的查询方式，通过 Java 代码构建查询条件，避免了字符串拼接的问题。

### 6.1 JPA Criteria API

```java
@Service
public class UserServiceImpl implements UserService {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    /**
     * 基本 Criteria 查询
     */
    public List<User> findByAgeCriteria(Integer minAge, Integer maxAge) {
        // 1. 获取 CriteriaBuilder
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        
        // 2. 创建 CriteriaQuery
        CriteriaQuery<User> query = cb.createQuery(User.class);
        
        // 3. 指定根实体（FROM 子句）
        Root<User> root = query.from(User.class);
        
        // 4. 构建查询条件
        Predicate agePredicate = cb.between(root.get("age"), minAge, maxAge);
        
        // 5. 设置查询条件
        query.where(agePredicate);
        
        // 6. 执行查询
        return entityManager.createQuery(query).getResultList();
    }
    
    /**
     * 多条件查询
     */
    public List<User> findByMultiCondition(String username, Integer status, Integer minAge) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> root = query.from(User.class);
        
        // 构建条件列表
        List<Predicate> predicates = new ArrayList<>();
        
        if (username != null && !username.isEmpty()) {
            predicates.add(cb.like(root.get("username"), "%" + username + "%"));
        }
        
        if (status != null) {
            predicates.add(cb.equal(root.get("status"), status));
        }
        
        if (minAge != null) {
            predicates.add(cb.greaterThanOrEqualTo(root.get("age"), minAge));
        }
        
        // 组合条件（AND）
        query.where(cb.and(predicates.toArray(new Predicate[0])));
        
        // 排序
        query.orderBy(cb.desc(root.get("createTime")));
        
        return entityManager.createQuery(query).getResultList();
    }
    
    /**
     * 分页查询
     */
    public List<User> findByPageCriteria(int pageNum, int pageSize) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> root = query.from(User.class);
        
        query.select(root);
        
        TypedQuery<User> typedQuery = entityManager.createQuery(query);
        typedQuery.setFirstResult((pageNum - 1) * pageSize);  // 起始位置
        typedQuery.setMaxResults(pageSize);                    // 每页条数
        
        return typedQuery.getResultList();
    }
    
    /**
     * 聚合查询
     */
    public Long countByStatus(Integer status) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Long> query = cb.createQuery(Long.class);
        Root<User> root = query.from(User.class);
        
        query.select(cb.count(root));
        query.where(cb.equal(root.get("status"), status));
        
        return entityManager.createQuery(query).getSingleResult();
    }
}
```

### 6.2 JpaSpecificationExecutor

Spring Data JPA 提供了 `JpaSpecificationExecutor` 接口，简化了 Criteria 查询：

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long>, 
                                        JpaSpecificationExecutor<User> {
}
```

```java
@Service
public class UserServiceImpl implements UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    /**
     * 使用 Specification 查询
     */
    public List<User> findBySpec(String username, Integer status, Integer minAge) {
        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            
            if (username != null && !username.isEmpty()) {
                predicates.add(cb.like(root.get("username"), "%" + username + "%"));
            }
            
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            
            if (minAge != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("age"), minAge));
            }
            
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        
        return userRepository.findAll(spec);
    }
    
    /**
     * Specification + 分页 + 排序
     */
    public Page<User> findBySpecWithPage(String username, Integer status, 
                                          int pageNum, int pageSize) {
        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            
            if (username != null) {
                predicates.add(cb.like(root.get("username"), "%" + username + "%"));
            }
            
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        
        Sort sort = Sort.by(Sort.Direction.DESC, "createTime");
        Pageable pageable = PageRequest.of(pageNum - 1, pageSize, sort);
        
        return userRepository.findAll(spec, pageable);
    }
}
```

### 6.3 封装通用 Specification

```java
/**
 * 通用 Specification 构建器
 */
public class SpecificationBuilder<T> {
    
    private List<Predicate> predicates = new ArrayList<>();
    private Root<T> root;
    private CriteriaQuery<?> query;
    private CriteriaBuilder cb;
    
    public SpecificationBuilder(Root<T> root, CriteriaQuery<?> query, CriteriaBuilder cb) {
        this.root = root;
        this.query = query;
        this.cb = cb;
    }
    
    /**
     * 等于
     */
    public SpecificationBuilder<T> eq(String field, Object value) {
        if (value != null) {
            predicates.add(cb.equal(root.get(field), value));
        }
        return this;
    }
    
    /**
     * 不等于
     */
    public SpecificationBuilder<T> ne(String field, Object value) {
        if (value != null) {
            predicates.add(cb.notEqual(root.get(field), value));
        }
        return this;
    }
    
    /**
     * 模糊查询
     */
    public SpecificationBuilder<T> like(String field, String value) {
        if (value != null && !value.isEmpty()) {
            predicates.add(cb.like(root.get(field), "%" + value + "%"));
        }
        return this;
    }
    
    /**
     * 大于
     */
    public <Y extends Comparable<? super Y>> SpecificationBuilder<T> gt(String field, Y value) {
        if (value != null) {
            predicates.add(cb.greaterThan(root.get(field), value));
        }
        return this;
    }
    
    /**
     * 大于等于
     */
    public <Y extends Comparable<? super Y>> SpecificationBuilder<T> ge(String field, Y value) {
        if (value != null) {
            predicates.add(cb.greaterThanOrEqualTo(root.get(field), value));
        }
        return this;
    }
    
    /**
     * 小于
     */
    public <Y extends Comparable<? super Y>> SpecificationBuilder<T> lt(String field, Y value) {
        if (value != null) {
            predicates.add(cb.lessThan(root.get(field), value));
        }
        return this;
    }
    
    /**
     * 小于等于
     */
    public <Y extends Comparable<? super Y>> SpecificationBuilder<T> le(String field, Y value) {
        if (value != null) {
            predicates.add(cb.lessThanOrEqualTo(root.get(field), value));
        }
        return this;
    }
    
    /**
     * BETWEEN
     */
    public <Y extends Comparable<? super Y>> SpecificationBuilder<T> between(String field, Y min, Y max) {
        if (min != null && max != null) {
            predicates.add(cb.between(root.get(field), min, max));
        }
        return this;
    }
    
    /**
     * IN
     */
    public SpecificationBuilder<T> in(String field, Collection<?> values) {
        if (values != null && !values.isEmpty()) {
            predicates.add(root.get(field).in(values));
        }
        return this;
    }
    
    /**
     * IS NULL
     */
    public SpecificationBuilder<T> isNull(String field) {
        predicates.add(cb.isNull(root.get(field)));
        return this;
    }
    
    /**
     * IS NOT NULL
     */
    public SpecificationBuilder<T> isNotNull(String field) {
        predicates.add(cb.isNotNull(root.get(field)));
        return this;
    }
    
    /**
     * 构建 Predicate
     */
    public Predicate build() {
        return cb.and(predicates.toArray(new Predicate[0]));
    }
}

/**
 * 使用示例
 */
@Service
public class UserServiceImpl {
    
    public List<User> search(UserSearchDTO dto) {
        Specification<User> spec = (root, query, cb) -> {
            return new SpecificationBuilder<User>(root, query, cb)
                    .like("username", dto.getUsername())
                    .eq("status", dto.getStatus())
                    .ge("age", dto.getMinAge())
                    .le("age", dto.getMaxAge())
                    .between("createTime", dto.getStartTime(), dto.getEndTime())
                    .build();
        };
        
        return userRepository.findAll(spec);
    }
}
```

---

## 7. 关联映射

关联映射是 Hibernate 的核心功能之一，用于处理实体之间的关系。

### 7.1 一对一关系（@OneToOne）

```java
/**
 * 用户实体
 */
@Entity
@Table(name = "user")
@Data
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    
    /**
     * 一对一关系：用户 -> 用户详情
     * 
     * @OneToOne 标识一对一关系
     * cascade 级联操作
     * fetch 加载策略（EAGER-立即加载，LAZY-延迟加载）
     * mappedBy 指定关系的维护方（在对方实体中）
     */
    @OneToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "detail_id", referencedColumnName = "id")
    private UserDetail detail;
}

/**
 * 用户详情实体
 */
@Entity
@Table(name = "user_detail")
@Data
public class UserDetail {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String realName;
    
    private String phone;
    
    private String address;
    
    /**
     * 双向关联：详情 -> 用户
     * mappedBy 表示关系由 User.detail 维护
     */
    @OneToOne(mappedBy = "detail", fetch = FetchType.LAZY)
    private User user;
}
```

### 7.2 一对多关系（@OneToMany）

```java
/**
 * 部门实体
 */
@Entity
@Table(name = "department")
@Data
public class Department {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    /**
     * 一对多关系：部门 -> 员工
     * 
     * mappedBy 指定关系由 Employee.department 维护
     * cascade 级联操作
     * orphanRemoval 孤儿删除（从集合中移除时删除数据库记录）
     */
    @OneToMany(mappedBy = "department", 
               cascade = CascadeType.ALL, 
               fetch = FetchType.LAZY,
               orphanRemoval = true)
    private List<Employee> employees = new ArrayList<>();
    
    /**
     * 添加员工的便捷方法
     */
    public void addEmployee(Employee employee) {
        employees.add(employee);
        employee.setDepartment(this);
    }
    
    /**
     * 移除员工的便捷方法
     */
    public void removeEmployee(Employee employee) {
        employees.remove(employee);
        employee.setDepartment(null);
    }
}

/**
 * 员工实体
 */
@Entity
@Table(name = "employee")
@Data
public class Employee {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    private String position;
    
    /**
     * 多对一关系：员工 -> 部门
     * 
     * @ManyToOne 标识多对一关系
     * @JoinColumn 指定外键列
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "department_id")
    private Department department;
}
```

### 7.3 多对多关系（@ManyToMany）

```java
/**
 * 学生实体
 */
@Entity
@Table(name = "student")
@Data
public class Student {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    /**
     * 多对多关系：学生 <-> 课程
     * 
     * @JoinTable 指定中间表
     * joinColumns 当前实体在中间表的外键
     * inverseJoinColumns 对方实体在中间表的外键
     */
    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE}, 
                fetch = FetchType.LAZY)
    @JoinTable(
        name = "student_course",  // 中间表名
        joinColumns = @JoinColumn(name = "student_id"),
        inverseJoinColumns = @JoinColumn(name = "course_id")
    )
    private Set<Course> courses = new HashSet<>();
    
    /**
     * 添加课程
     */
    public void addCourse(Course course) {
        courses.add(course);
        course.getStudents().add(this);
    }
    
    /**
     * 移除课程
     */
    public void removeCourse(Course course) {
        courses.remove(course);
        course.getStudents().remove(this);
    }
}

/**
 * 课程实体
 */
@Entity
@Table(name = "course")
@Data
public class Course {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    private Integer credit;  // 学分
    
    /**
     * 多对多关系（被维护方）
     * mappedBy 表示关系由 Student.courses 维护
     */
    @ManyToMany(mappedBy = "courses", fetch = FetchType.LAZY)
    private Set<Student> students = new HashSet<>();
}
```

### 7.4 多对多关系（带额外字段）

当中间表需要额外字段时，需要将多对多拆分为两个一对多：

```java
/**
 * 学生实体
 */
@Entity
@Table(name = "student")
@Data
public class Student {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    @OneToMany(mappedBy = "student", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<StudentCourse> studentCourses = new ArrayList<>();
}

/**
 * 课程实体
 */
@Entity
@Table(name = "course")
@Data
public class Course {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    @OneToMany(mappedBy = "course", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<StudentCourse> studentCourses = new ArrayList<>();
}

/**
 * 学生-课程关联实体（中间表）
 */
@Entity
@Table(name = "student_course")
@Data
public class StudentCourse {
    
    @EmbeddedId
    private StudentCourseId id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("studentId")
    @JoinColumn(name = "student_id")
    private Student student;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("courseId")
    @JoinColumn(name = "course_id")
    private Course course;
    
    // 额外字段
    private Double score;        // 成绩
    private LocalDate enrollDate; // 选课日期
}

/**
 * 复合主键
 */
@Embeddable
@Data
public class StudentCourseId implements Serializable {
    
    private Long studentId;
    private Long courseId;
}
```

### 7.5 关联映射注解总结

| 注解 | 说明 | 常用属性 |
|------|------|----------|
| `@OneToOne` | 一对一关系 | cascade, fetch, mappedBy, orphanRemoval |
| `@OneToMany` | 一对多关系 | cascade, fetch, mappedBy, orphanRemoval |
| `@ManyToOne` | 多对一关系 | cascade, fetch, optional |
| `@ManyToMany` | 多对多关系 | cascade, fetch, mappedBy |
| `@JoinColumn` | 指定外键列 | name, referencedColumnName, nullable |
| `@JoinTable` | 指定中间表 | name, joinColumns, inverseJoinColumns |

### 7.6 关联查询示例

```java
@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long> {
    
    /**
     * 使用 JOIN FETCH 避免 N+1 问题
     */
    @Query("SELECT d FROM Department d LEFT JOIN FETCH d.employees WHERE d.id = :id")
    Optional<Department> findByIdWithEmployees(@Param("id") Long id);
    
    /**
     * 查询部门及其员工数量
     */
    @Query("SELECT d, COUNT(e) FROM Department d LEFT JOIN d.employees e GROUP BY d")
    List<Object[]> findDepartmentWithEmployeeCount();
}

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {
    
    /**
     * 根据部门名称查询员工
     */
    @Query("SELECT e FROM Employee e JOIN e.department d WHERE d.name = :deptName")
    List<Employee> findByDepartmentName(@Param("deptName") String deptName);
    
    /**
     * 使用 EntityGraph 指定加载策略
     */
    @EntityGraph(attributePaths = {"department"})
    List<Employee> findByNameContaining(String name);
}
```

---

## 8. 级联操作与延迟加载

### 8.1 级联操作（Cascade）

级联操作指的是对一个实体的操作会自动传播到关联的实体。

```java
/**
 * CascadeType 枚举值说明
 */
public enum CascadeType {
    ALL,      // 所有操作都级联
    PERSIST,  // 保存时级联
    MERGE,    // 更新时级联
    REMOVE,   // 删除时级联
    REFRESH,  // 刷新时级联
    DETACH    // 分离时级联
}

/**
 * 使用示例
 */
@Entity
public class Department {
    
    // 所有操作都级联
    @OneToMany(mappedBy = "department", cascade = CascadeType.ALL)
    private List<Employee> employees;
    
    // 只在保存和更新时级联
    // @OneToMany(mappedBy = "department", cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    // private List<Employee> employees;
}
```

**级联操作示例：**

```java
@Service
@Transactional
public class DepartmentServiceImpl {
    
    @Autowired
    private DepartmentRepository departmentRepository;
    
    /**
     * 级联保存
     * 保存部门时，会自动保存关联的员工
     */
    public void saveDepartmentWithEmployees() {
        Department dept = new Department();
        dept.setName("技术部");
        
        Employee emp1 = new Employee();
        emp1.setName("张三");
        emp1.setDepartment(dept);
        
        Employee emp2 = new Employee();
        emp2.setName("李四");
        emp2.setDepartment(dept);
        
        dept.setEmployees(Arrays.asList(emp1, emp2));
        
        // 只需要保存部门，员工会自动保存
        departmentRepository.save(dept);
    }
    
    /**
     * 级联删除
     * 删除部门时，会自动删除关联的员工
     */
    public void deleteDepartment(Long id) {
        departmentRepository.deleteById(id);
    }
}
```

### 8.2 孤儿删除（orphanRemoval）

当从集合中移除关联对象时，自动删除数据库中的记录：

```java
@Entity
public class Department {
    
    @OneToMany(mappedBy = "department", 
               cascade = CascadeType.ALL, 
               orphanRemoval = true)  // 启用孤儿删除
    private List<Employee> employees = new ArrayList<>();
}

@Service
@Transactional
public class DepartmentServiceImpl {
    
    /**
     * 孤儿删除示例
     */
    public void removeEmployee(Long deptId, Long empId) {
        Department dept = departmentRepository.findById(deptId).orElseThrow();
        
        // 从集合中移除员工
        dept.getEmployees().removeIf(e -> e.getId().equals(empId));
        
        // 保存部门，被移除的员工会自动从数据库删除
        departmentRepository.save(dept);
    }
}
```

### 8.3 延迟加载（Lazy Loading）

延迟加载是指在真正需要数据时才去查询数据库，可以提高性能。

```java
@Entity
public class Department {
    
    /**
     * FetchType.LAZY - 延迟加载（推荐）
     * FetchType.EAGER - 立即加载
     */
    @OneToMany(mappedBy = "department", fetch = FetchType.LAZY)
    private List<Employee> employees;
}
```

**默认加载策略：**
- `@OneToOne`: EAGER
- `@ManyToOne`: EAGER
- `@OneToMany`: LAZY
- `@ManyToMany`: LAZY

### 8.4 解决延迟加载问题

**问题：LazyInitializationException**

当 Session 关闭后访问延迟加载的属性，会抛出此异常。

**解决方案：**

```java
// 方案一：使用 @Transactional 保持 Session 打开
@Service
@Transactional(readOnly = true)
public class DepartmentServiceImpl {
    
    public Department getDepartmentWithEmployees(Long id) {
        Department dept = departmentRepository.findById(id).orElseThrow();
        // 在事务内访问延迟加载的属性
        dept.getEmployees().size();  // 触发加载
        return dept;
    }
}

// 方案二：使用 JOIN FETCH
@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long> {
    
    @Query("SELECT d FROM Department d LEFT JOIN FETCH d.employees WHERE d.id = :id")
    Optional<Department> findByIdWithEmployees(@Param("id") Long id);
}

// 方案三：使用 @EntityGraph
@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long> {
    
    @EntityGraph(attributePaths = {"employees"})
    Optional<Department> findWithEmployeesById(Long id);
}

// 方案四：使用 Hibernate.initialize()
@Service
@Transactional(readOnly = true)
public class DepartmentServiceImpl {
    
    public Department getDepartmentWithEmployees(Long id) {
        Department dept = departmentRepository.findById(id).orElseThrow();
        Hibernate.initialize(dept.getEmployees());  // 强制初始化
        return dept;
    }
}

// 方案五：配置 Open Session In View（不推荐，有性能问题）
// application.yml
// spring.jpa.open-in-view: true  # 默认为 true
```

---

## 9. 缓存机制

Hibernate 提供了两级缓存机制来提高查询性能。

### 9.1 一级缓存（Session 缓存）

一级缓存是 Session 级别的缓存，默认开启，无需配置。

```java
@Service
@Transactional
public class UserServiceImpl {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    /**
     * 一级缓存示例
     */
    public void firstLevelCacheDemo() {
        // 第一次查询，从数据库加载
        User user1 = entityManager.find(User.class, 1L);
        System.out.println("第一次查询：" + user1.getUsername());
        
        // 第二次查询，从一级缓存获取（不会发送 SQL）
        User user2 = entityManager.find(User.class, 1L);
        System.out.println("第二次查询：" + user2.getUsername());
        
        // user1 和 user2 是同一个对象
        System.out.println("是否同一对象：" + (user1 == user2));  // true
    }
    
    /**
     * 清除一级缓存
     */
    public void clearFirstLevelCache() {
        User user1 = entityManager.find(User.class, 1L);
        
        // 清除一级缓存
        entityManager.clear();
        
        // 再次查询，会重新从数据库加载
        User user2 = entityManager.find(User.class, 1L);
        
        System.out.println("是否同一对象：" + (user1 == user2));  // false
    }
}
```

### 9.2 二级缓存（SessionFactory 缓存）

二级缓存是 SessionFactory 级别的缓存，可以跨 Session 共享，需要手动配置。

**添加依赖：**

```xml
<!-- Ehcache 缓存 -->
<dependency>
    <groupId>org.hibernate</groupId>
    <artifactId>hibernate-ehcache</artifactId>
    <version>5.6.15.Final</version>
</dependency>

<!-- 或者使用 Caffeine -->
<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>
<dependency>
    <groupId>org.hibernate</groupId>
    <artifactId>hibernate-jcache</artifactId>
</dependency>
```

**配置二级缓存：**

```yaml
# application.yml
spring:
  jpa:
    properties:
      hibernate:
        # 开启二级缓存
        cache:
          use_second_level_cache: true
          use_query_cache: true  # 开启查询缓存
          region:
            factory_class: org.hibernate.cache.ehcache.EhCacheRegionFactory
        # 生成缓存统计信息
        generate_statistics: true
```

**创建 ehcache.xml：**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ehcache xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="http://ehcache.org/ehcache.xsd">
    
    <!-- 磁盘缓存路径 -->
    <diskStore path="java.io.tmpdir"/>
    
    <!-- 默认缓存配置 -->
    <defaultCache
        maxElementsInMemory="10000"
        eternal="false"
        timeToIdleSeconds="120"
        timeToLiveSeconds="120"
        overflowToDisk="true"
        diskPersistent="false"
        diskExpiryThreadIntervalSeconds="120"/>
    
    <!-- 实体类缓存配置 -->
    <cache name="com.example.entity.User"
           maxElementsInMemory="1000"
           eternal="false"
           timeToIdleSeconds="300"
           timeToLiveSeconds="600"
           overflowToDisk="false"/>
    
    <!-- 查询缓存配置 -->
    <cache name="org.hibernate.cache.internal.StandardQueryCache"
           maxElementsInMemory="500"
           eternal="false"
           timeToIdleSeconds="300"
           timeToLiveSeconds="600"/>
</ehcache>
```

**在实体类上启用缓存：**

```java
@Entity
@Table(name = "user")
@Data
@Cacheable                                    // JPA 标准注解
@org.hibernate.annotations.Cache(            // Hibernate 注解
    usage = CacheConcurrencyStrategy.READ_WRITE,
    region = "com.example.entity.User"
)
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    
    // 关联集合也可以缓存
    @OneToMany(mappedBy = "user")
    @org.hibernate.annotations.Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
    private List<Order> orders;
}
```

### 9.3 缓存并发策略

| 策略 | 说明 | 适用场景 |
|------|------|----------|
| `READ_ONLY` | 只读缓存，数据不会被修改 | 静态数据、字典表 |
| `NONSTRICT_READ_WRITE` | 非严格读写，不保证缓存与数据库一致 | 偶尔修改的数据 |
| `READ_WRITE` | 读写缓存，使用软锁保证一致性 | 经常读取、偶尔修改 |
| `TRANSACTIONAL` | 事务缓存，完全事务隔离 | 需要强一致性的场景 |

### 9.4 查询缓存

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * 启用查询缓存
     */
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    List<User> findByStatus(Integer status);
    
    /**
     * JPQL 查询缓存
     */
    @Query("SELECT u FROM User u WHERE u.status = :status")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    List<User> findByStatusCached(@Param("status") Integer status);
}
```

---

## 10. 事务管理

### 10.1 Spring 事务基础

```java
@Service
public class UserServiceImpl implements UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    /**
     * @Transactional 注解属性说明
     * 
     * propagation: 传播行为
     * isolation: 隔离级别
     * timeout: 超时时间（秒）
     * readOnly: 是否只读
     * rollbackFor: 指定回滚的异常类型
     * noRollbackFor: 指定不回滚的异常类型
     */
    @Transactional(
        propagation = Propagation.REQUIRED,
        isolation = Isolation.DEFAULT,
        timeout = 30,
        readOnly = false,
        rollbackFor = Exception.class
    )
    public void saveUser(User user) {
        userRepository.save(user);
    }
}
```

### 10.2 事务传播行为

| 传播行为 | 说明 |
|----------|------|
| `REQUIRED`（默认） | 如果当前有事务，加入该事务；如果没有，创建新事务 |
| `REQUIRES_NEW` | 总是创建新事务，如果当前有事务，挂起当前事务 |
| `SUPPORTS` | 如果当前有事务，加入该事务；如果没有，以非事务方式执行 |
| `NOT_SUPPORTED` | 以非事务方式执行，如果当前有事务，挂起当前事务 |
| `MANDATORY` | 必须在事务中执行，如果当前没有事务，抛出异常 |
| `NEVER` | 必须以非事务方式执行，如果当前有事务，抛出异常 |
| `NESTED` | 如果当前有事务，在嵌套事务中执行；如果没有，创建新事务 |

```java
@Service
public class OrderServiceImpl {
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Autowired
    private LogService logService;
    
    /**
     * REQUIRED：默认传播行为
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void createOrder(Order order) {
        orderRepository.save(order);
        // 如果这里抛出异常，整个事务回滚
    }
    
    /**
     * REQUIRES_NEW：独立事务
     * 即使外层事务回滚，日志也会保存
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveLog(String message) {
        // 这是一个独立的事务
        logService.save(message);
    }
    
    /**
     * 组合使用
     */
    @Transactional
    public void createOrderWithLog(Order order) {
        try {
            orderRepository.save(order);
            // 即使订单保存失败，日志也会保存
            saveLog("创建订单：" + order.getOrderNo());
        } catch (Exception e) {
            saveLog("创建订单失败：" + e.getMessage());
            throw e;
        }
    }
}
```

### 10.3 事务隔离级别

| 隔离级别 | 脏读 | 不可重复读 | 幻读 | 说明 |
|----------|------|------------|------|------|
| `READ_UNCOMMITTED` | ✓ | ✓ | ✓ | 最低级别，可能读取未提交的数据 |
| `READ_COMMITTED` | ✗ | ✓ | ✓ | 只能读取已提交的数据（Oracle 默认） |
| `REPEATABLE_READ` | ✗ | ✗ | ✓ | 同一事务内多次读取结果一致（MySQL 默认） |
| `SERIALIZABLE` | ✗ | ✗ | ✗ | 最高级别，完全串行化执行 |

```java
@Service
public class AccountServiceImpl {
    
    /**
     * 转账操作，使用可重复读隔离级别
     */
    @Transactional(isolation = Isolation.REPEATABLE_READ)
    public void transfer(Long fromId, Long toId, BigDecimal amount) {
        Account from = accountRepository.findById(fromId).orElseThrow();
        Account to = accountRepository.findById(toId).orElseThrow();
        
        if (from.getBalance().compareTo(amount) < 0) {
            throw new RuntimeException("余额不足");
        }
        
        from.setBalance(from.getBalance().subtract(amount));
        to.setBalance(to.getBalance().add(amount));
        
        accountRepository.save(from);
        accountRepository.save(to);
    }
}
```

### 10.4 事务回滚规则

```java
@Service
public class UserServiceImpl {
    
    /**
     * 默认情况下，只有 RuntimeException 和 Error 会触发回滚
     * 检查型异常（Exception）不会触发回滚
     */
    @Transactional
    public void defaultRollback() throws Exception {
        // RuntimeException 会回滚
        // throw new RuntimeException("运行时异常");
        
        // 检查型异常不会回滚
        // throw new Exception("检查型异常");
    }
    
    /**
     * 指定所有异常都回滚
     */
    @Transactional(rollbackFor = Exception.class)
    public void rollbackForAll() throws Exception {
        throw new Exception("这个异常也会触发回滚");
    }
    
    /**
     * 指定某些异常不回滚
     */
    @Transactional(noRollbackFor = BusinessException.class)
    public void noRollbackForBusiness() {
        throw new BusinessException("业务异常，不回滚");
    }
    
    /**
     * 手动回滚
     */
    @Transactional
    public void manualRollback() {
        try {
            // 业务逻辑
        } catch (Exception e) {
            // 手动标记回滚
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        }
    }
}
```

### 10.5 事务失效场景

```java
@Service
public class UserServiceImpl {
    
    /**
     * 场景1：方法不是 public
     * 事务不生效！
     */
    @Transactional
    private void privateMethod() {
        // 事务不生效
    }
    
    /**
     * 场景2：同一个类内部调用
     * 事务不生效！
     */
    public void methodA() {
        methodB();  // 内部调用，事务不生效
    }
    
    @Transactional
    public void methodB() {
        // 事务不生效
    }
    
    /**
     * 场景3：异常被捕获
     * 事务不回滚！
     */
    @Transactional
    public void catchException() {
        try {
            // 业务逻辑
            throw new RuntimeException("异常");
        } catch (Exception e) {
            // 异常被捕获，事务不回滚
            log.error("发生异常", e);
        }
    }
    
    /**
     * 场景4：抛出检查型异常
     * 事务不回滚！
     */
    @Transactional
    public void checkedException() throws Exception {
        throw new Exception("检查型异常");  // 不回滚
    }
    
    // ============ 解决方案 ============
    
    @Autowired
    private UserServiceImpl self;  // 注入自己
    
    /**
     * 解决内部调用问题
     */
    public void methodAFixed() {
        self.methodB();  // 通过代理调用，事务生效
    }
    
    /**
     * 解决异常捕获问题
     */
    @Transactional
    public void catchExceptionFixed() {
        try {
            // 业务逻辑
        } catch (Exception e) {
            log.error("发生异常", e);
            throw e;  // 重新抛出异常
            // 或者手动回滚
            // TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        }
    }
}
```

---

## 11. 性能优化

### 11.1 N+1 查询问题

N+1 问题是 ORM 框架最常见的性能问题之一。

**问题描述：**
```java
// 查询所有部门（1 条 SQL）
List<Department> departments = departmentRepository.findAll();

// 遍历部门，访问员工（N 条 SQL）
for (Department dept : departments) {
    // 每次访问 employees 都会发送一条 SQL
    System.out.println(dept.getEmployees().size());
}
// 总共执行了 1 + N 条 SQL
```

**解决方案：**

```java
// 方案一：使用 JOIN FETCH
@Query("SELECT d FROM Department d LEFT JOIN FETCH d.employees")
List<Department> findAllWithEmployees();

// 方案二：使用 @EntityGraph
@EntityGraph(attributePaths = {"employees"})
List<Department> findAll();

// 方案三：使用 @BatchSize（批量加载）
@Entity
public class Department {
    
    @OneToMany(mappedBy = "department")
    @BatchSize(size = 20)  // 每次加载 20 个部门的员工
    private List<Employee> employees;
}

// 方案四：全局配置批量加载
// application.yml
spring:
  jpa:
    properties:
      hibernate:
        default_batch_fetch_size: 20
```

### 11.2 批量操作优化

```java
@Service
public class UserServiceImpl {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    /**
     * 批量插入优化
     */
    @Transactional
    public void batchInsert(List<User> users) {
        int batchSize = 50;
        
        for (int i = 0; i < users.size(); i++) {
            entityManager.persist(users.get(i));
            
            // 每 50 条刷新一次
            if (i > 0 && i % batchSize == 0) {
                entityManager.flush();
                entityManager.clear();
            }
        }
        
        // 处理剩余的
        entityManager.flush();
        entityManager.clear();
    }
    
    /**
     * 批量更新（使用 JPQL）
     */
    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.status = :status WHERE u.id IN :ids")
    int batchUpdateStatus(@Param("ids") List<Long> ids, @Param("status") Integer status);
    
    /**
     * 批量删除（使用 JPQL）
     */
    @Transactional
    @Modifying
    @Query("DELETE FROM User u WHERE u.id IN :ids")
    int batchDelete(@Param("ids") List<Long> ids);
}
```

**配置批量操作：**

```yaml
spring:
  jpa:
    properties:
      hibernate:
        jdbc:
          batch_size: 50           # 批量大小
          batch_versioned_data: true
        order_inserts: true        # 排序插入
        order_updates: true        # 排序更新
  datasource:
    url: jdbc:mysql://localhost:3306/db?rewriteBatchedStatements=true
```

### 11.3 只读查询优化

```java
@Service
public class UserServiceImpl {
    
    /**
     * 只读事务优化
     * readOnly = true 会：
     * 1. 告诉 Hibernate 不需要脏检查
     * 2. 某些数据库会优化只读事务
     */
    @Transactional(readOnly = true)
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    /**
     * 使用 StatelessSession（无状态会话）
     * 不使用一级缓存，适合大批量只读操作
     */
    public List<User> findAllStateless() {
        Session session = entityManager.unwrap(Session.class);
        StatelessSession statelessSession = session.getSessionFactory().openStatelessSession();
        
        try {
            return statelessSession.createQuery("FROM User", User.class).list();
        } finally {
            statelessSession.close();
        }
    }
}
```

### 11.4 投影查询优化

```java
/**
 * 只查询需要的字段，减少数据传输
 */
public interface UserProjection {
    Long getId();
    String getUsername();
    String getEmail();
}

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    // 使用接口投影
    List<UserProjection> findProjectionByStatus(Integer status);
    
    // 使用 DTO
    @Query("SELECT new com.example.dto.UserDTO(u.id, u.username, u.email) " +
           "FROM User u WHERE u.status = :status")
    List<UserDTO> findDTOByStatus(@Param("status") Integer status);
}
```

### 11.5 索引优化

```java
@Entity
@Table(name = "user", indexes = {
    @Index(name = "idx_username", columnList = "username"),
    @Index(name = "idx_email", columnList = "email"),
    @Index(name = "idx_status_create_time", columnList = "status, create_time")
})
public class User {
    // ...
}
```

### 11.6 SQL 日志与分析

```yaml
# 开发环境配置
spring:
  jpa:
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        use_sql_comments: true
        generate_statistics: true

logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    org.hibernate.stat: DEBUG
```

```java
/**
 * 获取 Hibernate 统计信息
 */
@Service
public class HibernateStatsService {
    
    @PersistenceContext
    private EntityManager entityManager;
    
    public void printStats() {
        Session session = entityManager.unwrap(Session.class);
        Statistics stats = session.getSessionFactory().getStatistics();
        
        System.out.println("查询执行次数: " + stats.getQueryExecutionCount());
        System.out.println("二级缓存命中次数: " + stats.getSecondLevelCacheHitCount());
        System.out.println("二级缓存未命中次数: " + stats.getSecondLevelCacheMissCount());
        System.out.println("实体加载次数: " + stats.getEntityLoadCount());
        System.out.println("实体插入次数: " + stats.getEntityInsertCount());
        System.out.println("实体更新次数: " + stats.getEntityUpdateCount());
        System.out.println("实体删除次数: " + stats.getEntityDeleteCount());
    }
}
```

---

## 12. 常见错误与解决方案

### 12.1 LazyInitializationException

**错误信息：**
```
org.hibernate.LazyInitializationException: could not initialize proxy - no Session
```

**原因：** 在 Session 关闭后访问延迟加载的属性

**解决方案：**
```java
// 方案一：使用 @Transactional 保持 Session
@Service
@Transactional(readOnly = true)
public class UserServiceImpl {
    public User getUser(Long id) {
        User user = userRepository.findById(id).orElseThrow();
        user.getOrders().size();  // 在事务内访问
        return user;
    }
}

// 方案二：使用 JOIN FETCH
@Query("SELECT u FROM User u LEFT JOIN FETCH u.orders WHERE u.id = :id")
Optional<User> findByIdWithOrders(@Param("id") Long id);

// 方案三：使用 @EntityGraph
@EntityGraph(attributePaths = {"orders"})
Optional<User> findWithOrdersById(Long id);

// 方案四：使用 Hibernate.initialize()
@Transactional(readOnly = true)
public User getUser(Long id) {
    User user = userRepository.findById(id).orElseThrow();
    Hibernate.initialize(user.getOrders());
    return user;
}
```

### 12.2 MultipleBagFetchException

**错误信息：**
```
org.hibernate.loader.MultipleBagFetchException: cannot simultaneously fetch multiple bags
```

**原因：** 同时 FETCH 多个 List 类型的集合

**解决方案：**
```java
// 方案一：将 List 改为 Set
@Entity
public class User {
    @OneToMany(mappedBy = "user")
    private Set<Order> orders = new HashSet<>();  // 使用 Set
    
    @OneToMany(mappedBy = "user")
    private Set<Address> addresses = new HashSet<>();  // 使用 Set
}

// 方案二：分开查询
@Query("SELECT u FROM User u LEFT JOIN FETCH u.orders WHERE u.id = :id")
Optional<User> findByIdWithOrders(@Param("id") Long id);

@Query("SELECT u FROM User u LEFT JOIN FETCH u.addresses WHERE u.id = :id")
Optional<User> findByIdWithAddresses(@Param("id") Long id);

// 方案三：使用 @BatchSize
@OneToMany(mappedBy = "user")
@BatchSize(size = 20)
private List<Order> orders;
```

### 12.3 StackOverflowError（循环引用）

**错误信息：**
```
java.lang.StackOverflowError
```

**原因：** 双向关联导致 toString()、equals()、hashCode() 或 JSON 序列化时无限循环

**解决方案：**
```java
// 方案一：使用 @ToString.Exclude 和 @EqualsAndHashCode.Exclude
@Entity
@Data
public class User {
    @Id
    private Long id;
    
    @OneToMany(mappedBy = "user")
    @ToString.Exclude           // 排除 toString
    @EqualsAndHashCode.Exclude  // 排除 equals 和 hashCode
    private List<Order> orders;
}

// 方案二：JSON 序列化时使用 @JsonIgnore 或 @JsonManagedReference/@JsonBackReference
@Entity
public class User {
    @OneToMany(mappedBy = "user")
    @JsonManagedReference  // 主控方
    private List<Order> orders;
}

@Entity
public class Order {
    @ManyToOne
    @JsonBackReference  // 被控方（不序列化）
    private User user;
}

// 方案三：使用 DTO 返回数据
public class UserDTO {
    private Long id;
    private String username;
    // 不包含关联对象
}
```

### 12.4 TransientPropertyValueException

**错误信息：**
```
org.hibernate.TransientPropertyValueException: object references an unsaved transient instance
```

**原因：** 保存实体时，关联的对象还没有被持久化

**解决方案：**
```java
// 方案一：先保存关联对象
@Transactional
public void saveOrder(Order order) {
    // 先保存用户
    userRepository.save(order.getUser());
    // 再保存订单
    orderRepository.save(order);
}

// 方案二：使用级联保存
@Entity
public class Order {
    @ManyToOne(cascade = CascadeType.PERSIST)  // 级联保存
    private User user;
}

// 方案三：关联已存在的对象
@Transactional
public void saveOrder(Order order, Long userId) {
    User user = userRepository.findById(userId).orElseThrow();
    order.setUser(user);
    orderRepository.save(order);
}
```

### 12.5 DetachedEntityPassedToPersistException

**错误信息：**
```
org.hibernate.PersistentObjectException: detached entity passed to persist
```

**原因：** 尝试 persist 一个已分离的实体（有 ID 的实体）

**解决方案：**
```java
// 方案一：使用 merge 代替 persist
@Transactional
public User updateUser(User user) {
    return entityManager.merge(user);  // 使用 merge
}

// 方案二：使用 save（Spring Data JPA 会自动判断）
@Transactional
public User updateUser(User user) {
    return userRepository.save(user);  // save 会自动判断是 insert 还是 update
}

// 方案三：先查询再更新
@Transactional
public User updateUser(User user) {
    User existingUser = userRepository.findById(user.getId()).orElseThrow();
    existingUser.setUsername(user.getUsername());
    // ... 更新其他字段
    return userRepository.save(existingUser);
}
```

### 12.6 DataIntegrityViolationException

**错误信息：**
```
org.springframework.dao.DataIntegrityViolationException: could not execute statement
Caused by: java.sql.SQLIntegrityConstraintViolationException: Duplicate entry
```

**原因：** 违反数据库约束（唯一约束、外键约束等）

**解决方案：**
```java
// 方案一：保存前检查
@Transactional
public User saveUser(User user) {
    if (userRepository.existsByUsername(user.getUsername())) {
        throw new BusinessException("用户名已存在");
    }
    if (userRepository.existsByEmail(user.getEmail())) {
        throw new BusinessException("邮箱已存在");
    }
    return userRepository.save(user);
}

// 方案二：捕获异常处理
@Transactional
public User saveUser(User user) {
    try {
        return userRepository.save(user);
    } catch (DataIntegrityViolationException e) {
        if (e.getMessage().contains("uk_username")) {
            throw new BusinessException("用户名已存在");
        }
        if (e.getMessage().contains("uk_email")) {
            throw new BusinessException("邮箱已存在");
        }
        throw e;
    }
}
```

### 12.7 OptimisticLockException

**错误信息：**
```
org.hibernate.StaleObjectStateException: Row was updated or deleted by another transaction
```

**原因：** 乐观锁冲突，数据已被其他事务修改

**解决方案：**
```java
// 方案一：重试机制
@Transactional
public User updateUserWithRetry(User user, int maxRetry) {
    int retryCount = 0;
    while (retryCount < maxRetry) {
        try {
            User existingUser = userRepository.findById(user.getId()).orElseThrow();
            existingUser.setUsername(user.getUsername());
            return userRepository.save(existingUser);
        } catch (OptimisticLockException e) {
            retryCount++;
            if (retryCount >= maxRetry) {
                throw new BusinessException("数据已被修改，请刷新后重试");
            }
        }
    }
    throw new BusinessException("更新失败");
}

// 方案二：使用悲观锁
@Lock(LockModeType.PESSIMISTIC_WRITE)
@Query("SELECT u FROM User u WHERE u.id = :id")
Optional<User> findByIdForUpdate(@Param("id") Long id);
```

### 12.8 QuerySyntaxException

**错误信息：**
```
org.hibernate.hql.internal.ast.QuerySyntaxException: User is not mapped
```

**原因：** JPQL 语法错误或实体类未被扫描到

**解决方案：**
```java
// 1. 检查实体类是否有 @Entity 注解
@Entity
public class User {
    // ...
}

// 2. 检查 JPQL 中使用的是实体类名，不是表名
// 错误：SELECT * FROM user
// 正确：SELECT u FROM User u

// 3. 检查实体类是否在扫描路径下
@SpringBootApplication
@EntityScan("com.example.entity")  // 指定实体类扫描路径
public class Application {
}

// 4. 检查字段名是否正确（使用 Java 属性名，不是数据库列名）
// 错误：WHERE u.user_name = :name
// 正确：WHERE u.username = :name
```

### 12.9 No EntityManager with actual transaction available

**错误信息：**
```
javax.persistence.TransactionRequiredException: No EntityManager with actual transaction available for current thread
```

**原因：** 执行写操作时没有事务

**解决方案：**
```java
// 方案一：添加 @Transactional 注解
@Service
public class UserServiceImpl {
    
    @Transactional  // 添加事务注解
    public void saveUser(User user) {
        userRepository.save(user);
    }
}

// 方案二：在 Repository 方法上添加 @Transactional
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") Integer status);
}
```

### 12.10 PropertyAccessException

**错误信息：**
```
org.hibernate.PropertyAccessException: Could not set field value by reflection
```

**原因：** Hibernate 无法访问实体类的属性

**解决方案：**
```java
// 1. 确保有无参构造函数
@Entity
@NoArgsConstructor  // Lombok 生成无参构造函数
public class User {
    // ...
}

// 2. 确保字段有 getter/setter
@Entity
@Data  // Lombok 生成 getter/setter
public class User {
    // ...
}

// 3. 检查字段类型是否匹配
// 数据库 INT -> Java Integer（不是 int）
// 数据库 BIGINT -> Java Long（不是 long）
```

### 12.11 性能问题排查清单

```java
/**
 * 性能问题排查清单
 */
public class PerformanceChecklist {
    
    // 1. 检查是否有 N+1 问题
    // - 开启 SQL 日志查看执行的 SQL 数量
    // - 使用 JOIN FETCH 或 @EntityGraph
    
    // 2. 检查是否查询了不必要的字段
    // - 使用投影查询只查询需要的字段
    
    // 3. 检查是否有不必要的延迟加载
    // - 合理设置 fetch 策略
    
    // 4. 检查批量操作是否优化
    // - 配置 batch_size
    // - 使用 JPQL 批量更新/删除
    
    // 5. 检查是否使用了缓存
    // - 配置二级缓存
    // - 配置查询缓存
    
    // 6. 检查数据库索引
    // - 为常用查询字段添加索引
    
    // 7. 检查事务范围
    // - 避免长事务
    // - 只读操作使用 readOnly = true
}
```

---

## 总结

Hibernate 是一个功能强大的 ORM 框架，通过本笔记的学习，你应该掌握了：

1. **基础概念**：ORM 思想、Hibernate 与 JPA 的关系
2. **环境搭建**：Spring Boot 集成配置
3. **实体映射**：各种注解的使用、枚举、日期、大对象映射
4. **CRUD 操作**：JpaRepository 的使用、方法名查询、分页排序
5. **HQL/JPQL 查询**：@Query 注解、原生 SQL、DTO 投影
6. **Criteria 查询**：类型安全的动态查询
7. **关联映射**：一对一、一对多、多对多关系
8. **级联与延迟加载**：级联操作、延迟加载问题解决
9. **缓存机制**：一级缓存、二级缓存配置
10. **事务管理**：传播行为、隔离级别、事务失效场景
11. **性能优化**：N+1 问题、批量操作、索引优化
12. **常见错误**：各种异常的原因和解决方案

记住，Hibernate 虽然强大，但也需要合理使用。在实际项目中，要根据具体场景选择合适的查询方式和优化策略。

---

## 参考资料

- [Hibernate 官方文档](https://hibernate.org/orm/documentation/)
- [Spring Data JPA 官方文档](https://spring.io/projects/spring-data-jpa)
- [JPA 规范](https://jakarta.ee/specifications/persistence/)
