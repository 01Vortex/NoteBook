> 基于 Java 8 + Spring Boot 2.7.18 环境
> MyBatis-Plus 是 MyBatis 的增强工具，在 MyBatis 的基础上只做增强不做改变，为简化开发、提高效率而生。

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [基本CRUD操作](#3-基本crud操作)
4. [条件构造器](#4-条件构造器)
5. [分页查询](#5-分页查询)
6. [自动填充](#6-自动填充)
7. [逻辑删除](#7-逻辑删除)
8. [乐观锁](#8-乐观锁)
9. [代码生成器](#9-代码生成器)
10. [多数据源](#10-多数据源)
11. [性能优化](#11-性能优化)
12. [常见错误与解决方案](#12-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 MyBatis-Plus？

MyBatis-Plus（简称 MP）是一个 MyBatis 的增强工具，就像它的口号所说的那样："为简化开发、提高效率而生"。

简单来说，如果你用过 MyBatis，你就知道写一个简单的增删改查需要：
- 写 Mapper 接口
- 写对应的 XML 文件
- 在 XML 里写 SQL 语句

而 MyBatis-Plus 帮你把这些重复性的工作都做了！你只需要继承一个 `BaseMapper` 接口，就能直接使用十几个现成的 CRUD 方法，完全不用写 SQL。

### 1.2 核心特性

| 特性 | 说明 |
|------|------|
| **无侵入** | 只做增强不做改变，引入它不会对现有工程产生影响 |
| **损耗小** | 启动即会自动注入基本 CRUD，性能基本无损耗 |
| **强大的 CRUD** | 内置通用 Mapper、通用 Service，少量配置即可实现单表大部分 CRUD |
| **Lambda 表达式** | 通过 Lambda 表达式，方便地编写各类查询条件 |
| **主键自动生成** | 支持多达 4 种主键策略，可自由配置 |
| **ActiveRecord 模式** | 支持 AR 模式，实体类只需继承 Model 类即可进行 CRUD |
| **内置分页插件** | 基于 MyBatis 物理分页，配置好插件后，分页等同于普通查询 |
| **内置代码生成器** | 采用代码或者 Maven 插件可快速生成各层代码 |

### 1.3 与 MyBatis 的关系

```
┌─────────────────────────────────────────┐
│           MyBatis-Plus                   │
│  ┌─────────────────────────────────┐    │
│  │         MyBatis                  │    │
│  │  ┌─────────────────────────┐    │    │
│  │  │        JDBC              │    │    │
│  │  └─────────────────────────┘    │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

MyBatis-Plus 是在 MyBatis 之上的一层封装，它并没有改变 MyBatis 的任何东西，你仍然可以在 MP 项目中使用原生 MyBatis 的所有功能。

---

## 2. 环境搭建

### 2.1 Maven 依赖配置

在 `pom.xml` 中添加以下依赖：

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
    <artifactId>mybatis-plus-demo</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>1.8</java.version>
    </properties>
    
    <dependencies>
        <!-- Spring Boot Starter -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- MyBatis-Plus Starter（核心依赖） -->
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.5.3.1</version>
        </dependency>
        
        <!-- MySQL 驱动 -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.33</version>
        </dependency>
        
        <!-- Lombok（简化代码，可选但强烈推荐） -->
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

> **注意**：引入 `mybatis-plus-boot-starter` 后，不需要再单独引入 `mybatis-spring-boot-starter`，否则可能会产生版本冲突！

### 2.2 数据库配置

在 `application.yml` 中配置数据源：

```yaml
# application.yml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/mybatis_plus_demo?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: your_password

# MyBatis-Plus 配置
mybatis-plus:
  # mapper.xml 文件位置（如果有自定义 SQL）
  mapper-locations: classpath*:/mapper/**/*.xml
  # 实体类包路径（用于别名）
  type-aliases-package: com.example.entity
  configuration:
    # 开启驼峰命名转换（数据库下划线 -> Java驼峰）
    map-underscore-to-camel-case: true
    # 开启 SQL 日志打印（开发环境建议开启）
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
  global-config:
    db-config:
      # 主键生成策略：AUTO-数据库自增, ASSIGN_ID-雪花算法, ASSIGN_UUID-UUID
      id-type: ASSIGN_ID
      # 表名前缀（如果表名都有统一前缀）
      # table-prefix: t_
      # 逻辑删除配置
      logic-delete-field: deleted
      logic-delete-value: 1
      logic-not-delete-value: 0
```

### 2.3 创建数据库表

```sql
-- 创建数据库
CREATE DATABASE IF NOT EXISTS mybatis_plus_demo 
DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE mybatis_plus_demo;

-- 创建用户表
CREATE TABLE `user` (
    `id` BIGINT(20) NOT NULL COMMENT '主键ID',
    `name` VARCHAR(30) DEFAULT NULL COMMENT '姓名',
    `age` INT(11) DEFAULT NULL COMMENT '年龄',
    `email` VARCHAR(50) DEFAULT NULL COMMENT '邮箱',
    `create_time` DATETIME DEFAULT NULL COMMENT '创建时间',
    `update_time` DATETIME DEFAULT NULL COMMENT '更新时间',
    `deleted` INT(1) DEFAULT 0 COMMENT '逻辑删除标识(0-未删除,1-已删除)',
    `version` INT(11) DEFAULT 1 COMMENT '乐观锁版本号',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

-- 插入测试数据
INSERT INTO `user` (id, name, age, email, create_time, update_time) VALUES
(1, '张三', 18, 'zhangsan@example.com', NOW(), NOW()),
(2, '李四', 20, 'lisi@example.com', NOW(), NOW()),
(3, '王五', 28, 'wangwu@example.com', NOW(), NOW()),
(4, '赵六', 21, 'zhaoliu@example.com', NOW(), NOW()),
(5, '孙七', 24, 'sunqi@example.com', NOW(), NOW());
```

### 2.4 创建实体类

```java
package com.example.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * 用户实体类
 * 
 * @TableName 指定表名（如果类名和表名一致可以省略）
 */
@Data
@TableName("user")
public class User {
    
    /**
     * 主键
     * @TableId 标识主键字段
     * IdType.ASSIGN_ID: 使用雪花算法生成ID（推荐）
     * IdType.AUTO: 使用数据库自增
     * IdType.INPUT: 手动输入
     */
    @TableId(type = IdType.ASSIGN_ID)
    private Long id;
    
    /**
     * 姓名
     * 如果字段名和数据库列名一致，可以不加 @TableField
     */
    private String name;
    
    /**
     * 年龄
     */
    private Integer age;
    
    /**
     * 邮箱
     */
    private String email;
    
    /**
     * 创建时间
     * @TableField(fill = FieldFill.INSERT) 表示插入时自动填充
     */
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createTime;
    
    /**
     * 更新时间
     * @TableField(fill = FieldFill.INSERT_UPDATE) 表示插入和更新时都自动填充
     */
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;
    
    /**
     * 逻辑删除标识
     * @TableLogic 标识逻辑删除字段
     */
    @TableLogic
    private Integer deleted;
    
    /**
     * 乐观锁版本号
     * @Version 标识乐观锁字段
     */
    @Version
    private Integer version;
}
```

### 2.5 常用注解详解

| 注解 | 作用位置 | 说明 |
|------|----------|------|
| `@TableName` | 类 | 指定实体类对应的表名 |
| `@TableId` | 字段 | 标识主键字段 |
| `@TableField` | 字段 | 指定字段与数据库列的映射关系 |
| `@TableLogic` | 字段 | 标识逻辑删除字段 |
| `@Version` | 字段 | 标识乐观锁版本字段 |
| `@EnumValue` | 枚举字段 | 标识枚举类中存入数据库的字段 |
| `@OrderBy` | 字段 | 指定默认排序字段 |

**@TableField 常用属性：**

```java
// 指定数据库列名（当字段名与列名不一致时）
@TableField("user_name")
private String name;

// 标识非数据库字段（不参与 SQL 操作）
@TableField(exist = false)
private String remark;

// 指定查询时的条件策略
@TableField(condition = SqlCondition.LIKE)
private String name;

// 指定更新时的策略
@TableField(update = "%s+1")  // 更新时 age = age + 1
private Integer age;

// 指定插入时的策略
@TableField(insertStrategy = FieldStrategy.NOT_NULL)
private String email;
```

### 2.6 创建 Mapper 接口

```java
package com.example.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.entity.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * 用户 Mapper 接口
 * 
 * 继承 BaseMapper<T> 后，就拥有了基本的 CRUD 功能
 * 泛型 T 指定实体类类型
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {
    // 这里可以定义自定义的查询方法
    // 简单的 CRUD 不需要写任何代码！
}
```

### 2.7 启动类配置

```java
package com.example;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.example.mapper")  // 扫描 Mapper 接口所在的包
public class MybatisPlusDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(MybatisPlusDemoApplication.class, args);
    }
}
```

> **提示**：`@MapperScan` 和 `@Mapper` 二选一即可。推荐在启动类使用 `@MapperScan`，这样就不用在每个 Mapper 接口上加 `@Mapper` 注解了。

---

## 3. 基本CRUD操作

### 3.1 BaseMapper 提供的方法

继承 `BaseMapper<T>` 后，你将自动获得以下方法：

```java
// ============ 插入操作 ============
int insert(T entity);                              // 插入一条记录

// ============ 删除操作 ============
int deleteById(Serializable id);                   // 根据 ID 删除
int deleteById(T entity);                          // 根据实体 ID 删除
int deleteByMap(Map<String, Object> columnMap);    // 根据 Map 条件删除
int delete(Wrapper<T> queryWrapper);               // 根据条件删除
int deleteBatchIds(Collection<?> idList);          // 批量删除

// ============ 更新操作 ============
int updateById(T entity);                          // 根据 ID 更新
int update(T entity, Wrapper<T> updateWrapper);    // 根据条件更新

// ============ 查询操作 ============
T selectById(Serializable id);                     // 根据 ID 查询
List<T> selectBatchIds(Collection<?> idList);      // 批量查询
List<T> selectByMap(Map<String, Object> columnMap);// 根据 Map 条件查询
T selectOne(Wrapper<T> queryWrapper);              // 查询一条记录
Long selectCount(Wrapper<T> queryWrapper);         // 查询总记录数
List<T> selectList(Wrapper<T> queryWrapper);       // 查询列表
List<Map<String, Object>> selectMaps(Wrapper<T> queryWrapper);  // 查询并返回 Map
List<Object> selectObjs(Wrapper<T> queryWrapper);  // 查询并返回第一列
IPage<T> selectPage(IPage<T> page, Wrapper<T> queryWrapper);    // 分页查询
```

### 3.2 插入操作示例

```java
@SpringBootTest
public class InsertTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 插入单条记录
     */
    @Test
    public void testInsert() {
        User user = new User();
        user.setName("测试用户");
        user.setAge(25);
        user.setEmail("test@example.com");
        
        // 执行插入，返回受影响的行数
        int result = userMapper.insert(user);
        System.out.println("插入结果：" + result);
        
        // 插入后，主键会自动回填到实体对象中
        System.out.println("生成的ID：" + user.getId());
    }
    
    /**
     * 批量插入（需要使用 Service 层的 saveBatch 方法）
     * BaseMapper 没有提供批量插入方法
     */
}
```

### 3.3 删除操作示例

```java
@SpringBootTest
public class DeleteTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 根据 ID 删除
     */
    @Test
    public void testDeleteById() {
        int result = userMapper.deleteById(1L);
        System.out.println("删除结果：" + result);
    }
    
    /**
     * 批量删除
     */
    @Test
    public void testDeleteBatchIds() {
        List<Long> ids = Arrays.asList(1L, 2L, 3L);
        int result = userMapper.deleteBatchIds(ids);
        System.out.println("批量删除结果：" + result);
    }
    
    /**
     * 根据 Map 条件删除
     */
    @Test
    public void testDeleteByMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("name", "张三");
        map.put("age", 18);
        
        // 删除 name='张三' AND age=18 的记录
        int result = userMapper.deleteByMap(map);
        System.out.println("条件删除结果：" + result);
    }
    
    /**
     * 根据条件构造器删除
     */
    @Test
    public void testDeleteByWrapper() {
        // 删除年龄大于 30 的用户
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.gt("age", 30);
        
        int result = userMapper.delete(wrapper);
        System.out.println("条件删除结果：" + result);
    }
}
```

### 3.4 更新操作示例

```java
@SpringBootTest
public class UpdateTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 根据 ID 更新
     * 注意：只会更新非 null 的字段
     */
    @Test
    public void testUpdateById() {
        User user = new User();
        user.setId(1L);
        user.setName("张三改名了");
        user.setAge(20);
        // email 为 null，不会被更新
        
        int result = userMapper.updateById(user);
        System.out.println("更新结果：" + result);
    }
    
    /**
     * 根据条件更新
     */
    @Test
    public void testUpdateByWrapper() {
        // 方式一：使用 UpdateWrapper
        UpdateWrapper<User> wrapper = new UpdateWrapper<>();
        wrapper.set("name", "新名字")
               .set("email", "new@example.com")
               .eq("id", 1L);
        
        int result = userMapper.update(null, wrapper);
        System.out.println("更新结果：" + result);
        
        // 方式二：实体 + UpdateWrapper
        User user = new User();
        user.setName("另一个名字");
        
        UpdateWrapper<User> wrapper2 = new UpdateWrapper<>();
        wrapper2.eq("age", 20);
        
        // 将所有 age=20 的用户名字改为 "另一个名字"
        userMapper.update(user, wrapper2);
    }
    
    /**
     * 使用 LambdaUpdateWrapper（推荐，避免字段名写错）
     */
    @Test
    public void testLambdaUpdate() {
        LambdaUpdateWrapper<User> wrapper = new LambdaUpdateWrapper<>();
        wrapper.set(User::getName, "Lambda更新")
               .set(User::getEmail, "lambda@example.com")
               .eq(User::getId, 1L);
        
        userMapper.update(null, wrapper);
    }
}
```

### 3.5 查询操作示例

```java
@SpringBootTest
public class SelectTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 根据 ID 查询
     */
    @Test
    public void testSelectById() {
        User user = userMapper.selectById(1L);
        System.out.println(user);
    }
    
    /**
     * 批量查询
     */
    @Test
    public void testSelectBatchIds() {
        List<Long> ids = Arrays.asList(1L, 2L, 3L);
        List<User> users = userMapper.selectBatchIds(ids);
        users.forEach(System.out::println);
    }
    
    /**
     * 根据 Map 条件查询
     */
    @Test
    public void testSelectByMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("name", "张三");
        
        List<User> users = userMapper.selectByMap(map);
        users.forEach(System.out::println);
    }
    
    /**
     * 查询所有
     */
    @Test
    public void testSelectAll() {
        // 传入 null 表示无条件查询
        List<User> users = userMapper.selectList(null);
        users.forEach(System.out::println);
    }
    
    /**
     * 查询总记录数
     */
    @Test
    public void testSelectCount() {
        // 查询所有记录数
        Long count = userMapper.selectCount(null);
        System.out.println("总记录数：" + count);
        
        // 查询满足条件的记录数
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.gt("age", 20);
        Long count2 = userMapper.selectCount(wrapper);
        System.out.println("年龄大于20的记录数：" + count2);
    }
    
    /**
     * 查询单条记录
     * 注意：如果查询结果有多条，会抛出异常！
     */
    @Test
    public void testSelectOne() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("name", "张三");
        
        User user = userMapper.selectOne(wrapper);
        System.out.println(user);
    }
}
```

### 3.6 Service 层封装

MyBatis-Plus 还提供了 `IService` 接口和 `ServiceImpl` 实现类，封装了更多便捷的方法：

```java
// Service 接口
package com.example.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.entity.User;

public interface UserService extends IService<User> {
    // 可以定义自己的业务方法
}
```

```java
// Service 实现类
package com.example.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.entity.User;
import com.example.mapper.UserMapper;
import com.example.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    // ServiceImpl 已经注入了 baseMapper，可以直接使用
}
```

**IService 提供的常用方法：**

```java
// ============ 保存 ============
boolean save(T entity);                            // 保存单条
boolean saveBatch(Collection<T> entityList);       // 批量保存
boolean saveBatch(Collection<T> entityList, int batchSize);  // 批量保存（指定批次大小）
boolean saveOrUpdate(T entity);                    // 存在则更新，不存在则插入
boolean saveOrUpdateBatch(Collection<T> entityList);  // 批量存在则更新

// ============ 删除 ============
boolean removeById(Serializable id);
boolean removeByMap(Map<String, Object> columnMap);
boolean remove(Wrapper<T> queryWrapper);
boolean removeByIds(Collection<?> idList);

// ============ 更新 ============
boolean updateById(T entity);
boolean update(Wrapper<T> updateWrapper);
boolean update(T entity, Wrapper<T> updateWrapper);
boolean updateBatchById(Collection<T> entityList);

// ============ 查询 ============
T getById(Serializable id);
List<T> listByIds(Collection<?> idList);
List<T> listByMap(Map<String, Object> columnMap);
T getOne(Wrapper<T> queryWrapper);
T getOne(Wrapper<T> queryWrapper, boolean throwEx);  // throwEx=false 时多条不抛异常
long count();
long count(Wrapper<T> queryWrapper);
List<T> list();
List<T> list(Wrapper<T> queryWrapper);
IPage<T> page(IPage<T> page);
IPage<T> page(IPage<T> page, Wrapper<T> queryWrapper);
```

---

## 4. 条件构造器

条件构造器是 MyBatis-Plus 的核心功能之一，它允许你用 Java 代码的方式构建 SQL 的 WHERE 条件，避免了手写 SQL 字符串的繁琐和出错风险。

### 4.1 条件构造器类型

```
Wrapper (抽象类)
├── AbstractWrapper (抽象类)
│   ├── QueryWrapper<T>      // 查询条件构造器
│   ├── UpdateWrapper<T>     // 更新条件构造器
│   ├── LambdaQueryWrapper<T>  // Lambda 查询条件构造器（推荐）
│   └── LambdaUpdateWrapper<T> // Lambda 更新条件构造器（推荐）
```

### 4.2 QueryWrapper 基本使用

```java
@SpringBootTest
public class QueryWrapperTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 等于 eq
     * SQL: SELECT * FROM user WHERE name = '张三'
     */
    @Test
    public void testEq() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("name", "张三");
        
        List<User> users = userMapper.selectList(wrapper);
        users.forEach(System.out::println);
    }
    
    /**
     * 不等于 ne
     * SQL: SELECT * FROM user WHERE name <> '张三'
     */
    @Test
    public void testNe() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.ne("name", "张三");
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 大于 gt / 大于等于 ge / 小于 lt / 小于等于 le
     * SQL: SELECT * FROM user WHERE age > 20 AND age <= 30
     */
    @Test
    public void testCompare() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.gt("age", 20)
               .le("age", 30);
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * BETWEEN
     * SQL: SELECT * FROM user WHERE age BETWEEN 18 AND 30
     */
    @Test
    public void testBetween() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.between("age", 18, 30);
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * LIKE 模糊查询
     * like: %值%
     * likeLeft: %值
     * likeRight: 值%
     */
    @Test
    public void testLike() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        
        // SQL: SELECT * FROM user WHERE name LIKE '%张%'
        wrapper.like("name", "张");
        
        // SQL: SELECT * FROM user WHERE name LIKE '%三'
        // wrapper.likeLeft("name", "三");
        
        // SQL: SELECT * FROM user WHERE name LIKE '张%'
        // wrapper.likeRight("name", "张");
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * IS NULL / IS NOT NULL
     */
    @Test
    public void testNull() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.isNull("email");
        // wrapper.isNotNull("email");
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * IN / NOT IN
     * SQL: SELECT * FROM user WHERE age IN (18, 20, 22)
     */
    @Test
    public void testIn() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.in("age", 18, 20, 22);
        // 或者传入集合
        // wrapper.in("age", Arrays.asList(18, 20, 22));
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * OR 条件
     * 默认是 AND 连接，使用 or() 切换为 OR
     * SQL: SELECT * FROM user WHERE name = '张三' OR age = 20
     */
    @Test
    public void testOr() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("name", "张三")
               .or()
               .eq("age", 20);
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 嵌套 OR
     * SQL: SELECT * FROM user WHERE name = '张三' AND (age = 20 OR email IS NOT NULL)
     */
    @Test
    public void testNestedOr() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.eq("name", "张三")
               .and(w -> w.eq("age", 20).or().isNotNull("email"));
        
        List<User> users = userMapper.selectList(wrapper);
    }
}
```

### 4.3 排序与分组

```java
@SpringBootTest
public class OrderGroupTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 排序
     * SQL: SELECT * FROM user ORDER BY age DESC, id ASC
     */
    @Test
    public void testOrderBy() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.orderByDesc("age")
               .orderByAsc("id");
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 分组
     * SQL: SELECT age, COUNT(*) as count FROM user GROUP BY age HAVING count > 1
     */
    @Test
    public void testGroupBy() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.select("age", "COUNT(*) as count")
               .groupBy("age")
               .having("COUNT(*) > 1");
        
        List<Map<String, Object>> result = userMapper.selectMaps(wrapper);
        result.forEach(System.out::println);
    }
    
    /**
     * 指定查询字段
     * SQL: SELECT id, name FROM user
     */
    @Test
    public void testSelect() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.select("id", "name");
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 排除某些字段
     */
    @Test
    public void testSelectExclude() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        // 排除 create_time 和 update_time 字段
        wrapper.select(User.class, info -> 
            !info.getColumn().equals("create_time") && 
            !info.getColumn().equals("update_time"));
        
        List<User> users = userMapper.selectList(wrapper);
    }
}
```

### 4.4 LambdaQueryWrapper（强烈推荐）

使用 Lambda 表达式可以避免字段名写错的问题，IDE 也能提供更好的代码提示：

```java
@SpringBootTest
public class LambdaQueryWrapperTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 基本使用
     * 使用方法引用代替字符串字段名
     */
    @Test
    public void testLambda() {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getName, "张三")
               .gt(User::getAge, 18)
               .like(User::getEmail, "example");
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 链式调用
     */
    @Test
    public void testChain() {
        List<User> users = new LambdaQueryChainWrapper<>(userMapper)
                .eq(User::getName, "张三")
                .gt(User::getAge, 18)
                .list();
    }
    
    /**
     * 条件判断（动态 SQL）
     * 只有当条件为 true 时，才会拼接该条件
     */
    @Test
    public void testCondition() {
        String name = "张三";  // 可能为 null
        Integer minAge = null; // 可能为 null
        
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        // 第一个参数为 boolean，为 true 时才拼接条件
        wrapper.eq(name != null, User::getName, name)
               .ge(minAge != null, User::getAge, minAge);
        
        // 如果 name="张三", minAge=null
        // 生成的 SQL: SELECT * FROM user WHERE name = '张三'
        // minAge 条件不会被拼接
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 复杂条件组合
     * SQL: SELECT * FROM user 
     *      WHERE (name = '张三' OR name = '李四') 
     *      AND age >= 18
     */
    @Test
    public void testComplex() {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.and(w -> w.eq(User::getName, "张三")
                         .or()
                         .eq(User::getName, "李四"))
               .ge(User::getAge, 18);
        
        List<User> users = userMapper.selectList(wrapper);
    }
    
    /**
     * 子查询
     * SQL: SELECT * FROM user WHERE id IN (SELECT user_id FROM order WHERE amount > 100)
     */
    @Test
    public void testSubQuery() {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        wrapper.inSql("id", "SELECT user_id FROM `order` WHERE amount > 100");
        
        List<User> users = userMapper.selectList(wrapper);
    }
}
```

### 4.5 条件构造器方法速查表

| 方法 | 说明 | SQL 示例 |
|------|------|----------|
| `eq` | 等于 | `WHERE name = '张三'` |
| `ne` | 不等于 | `WHERE name <> '张三'` |
| `gt` | 大于 | `WHERE age > 18` |
| `ge` | 大于等于 | `WHERE age >= 18` |
| `lt` | 小于 | `WHERE age < 18` |
| `le` | 小于等于 | `WHERE age <= 18` |
| `between` | BETWEEN | `WHERE age BETWEEN 18 AND 30` |
| `notBetween` | NOT BETWEEN | `WHERE age NOT BETWEEN 18 AND 30` |
| `like` | LIKE '%值%' | `WHERE name LIKE '%张%'` |
| `notLike` | NOT LIKE | `WHERE name NOT LIKE '%张%'` |
| `likeLeft` | LIKE '%值' | `WHERE name LIKE '%三'` |
| `likeRight` | LIKE '值%' | `WHERE name LIKE '张%'` |
| `isNull` | IS NULL | `WHERE email IS NULL` |
| `isNotNull` | IS NOT NULL | `WHERE email IS NOT NULL` |
| `in` | IN | `WHERE age IN (18, 20, 22)` |
| `notIn` | NOT IN | `WHERE age NOT IN (18, 20, 22)` |
| `inSql` | IN 子查询 | `WHERE id IN (SELECT ...)` |
| `groupBy` | GROUP BY | `GROUP BY age` |
| `having` | HAVING | `HAVING COUNT(*) > 1` |
| `orderByAsc` | 升序排序 | `ORDER BY age ASC` |
| `orderByDesc` | 降序排序 | `ORDER BY age DESC` |
| `or` | OR 连接 | `WHERE ... OR ...` |
| `and` | AND 嵌套 | `WHERE ... AND (...)` |
| `apply` | 拼接 SQL | 自定义 SQL 片段 |
| `last` | 拼接到最后 | 在 SQL 最后追加内容 |
| `exists` | EXISTS | `WHERE EXISTS (SELECT ...)` |

---

## 5. 分页查询

MyBatis-Plus 内置了强大的分页插件，使用起来非常简单。

### 5.1 配置分页插件

```java
package com.example.config;

import com.baomidou.mybatisplus.annotation.DbType;
import com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor;
import com.baomidou.mybatisplus.extension.plugins.inner.PaginationInnerInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * MyBatis-Plus 配置类
 */
@Configuration
public class MybatisPlusConfig {
    
    /**
     * 配置 MyBatis-Plus 插件
     */
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        
        // 添加分页插件
        PaginationInnerInterceptor paginationInterceptor = new PaginationInnerInterceptor();
        // 设置数据库类型（用于生成正确的分页 SQL）
        paginationInterceptor.setDbType(DbType.MYSQL);
        // 设置单页最大条数限制（-1 表示不限制）
        paginationInterceptor.setMaxLimit(500L);
        // 溢出总页数后是否进行处理（true 表示回到第一页）
        paginationInterceptor.setOverflow(false);
        
        interceptor.addInnerInterceptor(paginationInterceptor);
        
        return interceptor;
    }
}
```

### 5.2 基本分页查询

```java
@SpringBootTest
public class PageTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 基本分页查询
     */
    @Test
    public void testPage() {
        // 创建分页对象：第1页，每页5条
        Page<User> page = new Page<>(1, 5);
        
        // 执行分页查询
        Page<User> result = userMapper.selectPage(page, null);
        
        // 获取分页信息
        System.out.println("当前页：" + result.getCurrent());
        System.out.println("每页条数：" + result.getSize());
        System.out.println("总记录数：" + result.getTotal());
        System.out.println("总页数：" + result.getPages());
        System.out.println("是否有上一页：" + result.hasPrevious());
        System.out.println("是否有下一页：" + result.hasNext());
        
        // 获取数据列表
        List<User> records = result.getRecords();
        records.forEach(System.out::println);
    }
    
    /**
     * 带条件的分页查询
     */
    @Test
    public void testPageWithCondition() {
        Page<User> page = new Page<>(1, 5);
        
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.gt(User::getAge, 18)
               .orderByDesc(User::getCreateTime);
        
        Page<User> result = userMapper.selectPage(page, wrapper);
        result.getRecords().forEach(System.out::println);
    }
    
    /**
     * 不查询总记录数（提高性能）
     * 适用于只需要数据，不需要显示总页数的场景
     */
    @Test
    public void testPageWithoutCount() {
        // 第三个参数 false 表示不查询总记录数
        Page<User> page = new Page<>(1, 5, false);
        
        Page<User> result = userMapper.selectPage(page, null);
        // result.getTotal() 将返回 0
    }
}
```

### 5.3 自定义分页查询

有时候内置的方法不能满足需求，需要自定义 SQL 进行分页：

```java
// UserMapper.java
public interface UserMapper extends BaseMapper<User> {
    
    /**
     * 自定义分页查询
     * 第一个参数必须是 Page 对象
     */
    IPage<User> selectUserPage(IPage<User> page, @Param("minAge") Integer minAge);
    
    /**
     * 多表联查分页
     */
    IPage<UserVO> selectUserWithOrderPage(IPage<UserVO> page, @Param("status") Integer status);
}
```

```xml
<!-- UserMapper.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" 
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mapper.UserMapper">
    
    <!-- 自定义分页查询 -->
    <select id="selectUserPage" resultType="com.example.entity.User">
        SELECT * FROM user 
        WHERE age >= #{minAge}
        ORDER BY create_time DESC
    </select>
    
    <!-- 多表联查分页 -->
    <select id="selectUserWithOrderPage" resultType="com.example.vo.UserVO">
        SELECT u.id, u.name, u.age, o.order_no, o.amount
        FROM user u
        LEFT JOIN `order` o ON u.id = o.user_id
        WHERE o.status = #{status}
    </select>
    
</mapper>
```

```java
// 使用自定义分页
@Test
public void testCustomPage() {
    Page<User> page = new Page<>(1, 10);
    IPage<User> result = userMapper.selectUserPage(page, 18);
    result.getRecords().forEach(System.out::println);
}
```

### 5.4 Service 层分页

```java
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    /**
     * 分页查询用户
     */
    public IPage<User> getUserPage(int pageNum, int pageSize, String name) {
        Page<User> page = new Page<>(pageNum, pageSize);
        
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.like(StringUtils.isNotBlank(name), User::getName, name)
               .orderByDesc(User::getCreateTime);
        
        return this.page(page, wrapper);
    }
}
```

---

## 6. 自动填充

自动填充功能可以在插入或更新数据时，自动为某些字段赋值，比如创建时间、更新时间、创建人等。

### 6.1 配置自动填充处理器

```java
package com.example.handler;

import com.baomidou.mybatisplus.core.handlers.MetaObjectHandler;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.reflection.MetaObject;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * 自动填充处理器
 * 实现 MetaObjectHandler 接口
 */
@Slf4j
@Component
public class MyMetaObjectHandler implements MetaObjectHandler {
    
    /**
     * 插入时自动填充
     */
    @Override
    public void insertFill(MetaObject metaObject) {
        log.info("开始插入填充...");
        
        // 方式一：使用 strictInsertFill（推荐）
        // 只有当字段值为 null 时才会填充
        this.strictInsertFill(metaObject, "createTime", LocalDateTime.class, LocalDateTime.now());
        this.strictInsertFill(metaObject, "updateTime", LocalDateTime.class, LocalDateTime.now());
        
        // 方式二：使用 setFieldValByName
        // 无论字段是否有值都会填充（会覆盖原有值）
        // this.setFieldValByName("createTime", LocalDateTime.now(), metaObject);
        
        // 填充创建人（假设从上下文获取当前用户）
        // this.strictInsertFill(metaObject, "createBy", String.class, getCurrentUser());
        
        // 填充默认值
        this.strictInsertFill(metaObject, "deleted", Integer.class, 0);
        this.strictInsertFill(metaObject, "version", Integer.class, 1);
    }
    
    /**
     * 更新时自动填充
     */
    @Override
    public void updateFill(MetaObject metaObject) {
        log.info("开始更新填充...");
        
        // 更新时间
        this.strictUpdateFill(metaObject, "updateTime", LocalDateTime.class, LocalDateTime.now());
        
        // 更新人
        // this.strictUpdateFill(metaObject, "updateBy", String.class, getCurrentUser());
    }
    
    /**
     * 获取当前登录用户（示例）
     */
    private String getCurrentUser() {
        // 实际项目中从 SecurityContext 或 ThreadLocal 获取
        return "admin";
    }
}
```

### 6.2 实体类配置

```java
@Data
@TableName("user")
public class User {
    
    @TableId(type = IdType.ASSIGN_ID)
    private Long id;
    
    private String name;
    
    private Integer age;
    
    private String email;
    
    /**
     * 创建时间 - 插入时自动填充
     */
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createTime;
    
    /**
     * 更新时间 - 插入和更新时都自动填充
     */
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;
    
    /**
     * 创建人 - 插入时自动填充
     */
    @TableField(fill = FieldFill.INSERT)
    private String createBy;
    
    /**
     * 更新人 - 更新时自动填充
     */
    @TableField(fill = FieldFill.UPDATE)
    private String updateBy;
    
    @TableLogic
    @TableField(fill = FieldFill.INSERT)
    private Integer deleted;
    
    @Version
    @TableField(fill = FieldFill.INSERT)
    private Integer version;
}
```

### 6.3 FieldFill 枚举说明

| 枚举值 | 说明 |
|--------|------|
| `DEFAULT` | 默认不处理 |
| `INSERT` | 插入时填充 |
| `UPDATE` | 更新时填充 |
| `INSERT_UPDATE` | 插入和更新时都填充 |

### 6.4 注意事项

```java
/**
 * 自动填充的注意事项
 */
public class AutoFillNotes {
    
    // 1. 自动填充只在使用 MyBatis-Plus 提供的方法时生效
    // 如果使用自定义 SQL，需要手动处理
    
    // 2. strictInsertFill 和 strictUpdateFill 只有在字段值为 null 时才会填充
    // 如果想强制覆盖，使用 setFieldValByName
    
    // 3. 更新操作时，如果使用 UpdateWrapper 且没有传入实体对象，自动填充不会生效
    // 错误示例：
    // userMapper.update(null, updateWrapper);  // 自动填充不生效
    
    // 正确示例：
    // User user = new User();
    // userMapper.update(user, updateWrapper);  // 自动填充生效
    
    // 4. 字段类型必须匹配
    // 如果数据库是 datetime，Java 字段应该是 LocalDateTime 或 Date
}
```

---

## 7. 逻辑删除

逻辑删除是指不真正从数据库中删除数据，而是通过一个标识字段来标记数据是否被删除。这样可以保留数据的历史记录，也便于数据恢复。

### 7.1 配置逻辑删除

**方式一：全局配置（application.yml）**

```yaml
mybatis-plus:
  global-config:
    db-config:
      # 逻辑删除字段名
      logic-delete-field: deleted
      # 逻辑已删除值
      logic-delete-value: 1
      # 逻辑未删除值
      logic-not-delete-value: 0
```

**方式二：注解配置（实体类）**

```java
@Data
@TableName("user")
public class User {
    
    @TableId(type = IdType.ASSIGN_ID)
    private Long id;
    
    private String name;
    
    /**
     * 逻辑删除字段
     * @TableLogic 标识该字段为逻辑删除字段
     * value: 未删除的值
     * delval: 已删除的值
     */
    @TableLogic(value = "0", delval = "1")
    private Integer deleted;
}
```

### 7.2 逻辑删除的效果

配置逻辑删除后，MyBatis-Plus 会自动修改 SQL：

```java
@SpringBootTest
public class LogicDeleteTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 删除操作
     * 实际执行的 SQL: UPDATE user SET deleted = 1 WHERE id = 1 AND deleted = 0
     */
    @Test
    public void testDelete() {
        userMapper.deleteById(1L);
    }
    
    /**
     * 查询操作
     * 实际执行的 SQL: SELECT * FROM user WHERE deleted = 0
     * 自动过滤已删除的数据
     */
    @Test
    public void testSelect() {
        List<User> users = userMapper.selectList(null);
        users.forEach(System.out::println);
    }
    
    /**
     * 更新操作
     * 实际执行的 SQL: UPDATE user SET name = '新名字' WHERE id = 1 AND deleted = 0
     */
    @Test
    public void testUpdate() {
        User user = new User();
        user.setId(1L);
        user.setName("新名字");
        userMapper.updateById(user);
    }
}
```

### 7.3 查询已删除的数据

有时候需要查询已删除的数据（比如数据恢复），可以使用自定义 SQL：

```java
// UserMapper.java
public interface UserMapper extends BaseMapper<User> {
    
    /**
     * 查询所有数据（包括已删除的）
     */
    @Select("SELECT * FROM user")
    List<User> selectAllIncludeDeleted();
    
    /**
     * 查询已删除的数据
     */
    @Select("SELECT * FROM user WHERE deleted = 1")
    List<User> selectDeleted();
    
    /**
     * 恢复已删除的数据
     */
    @Update("UPDATE user SET deleted = 0 WHERE id = #{id}")
    int restoreById(@Param("id") Long id);
    
    /**
     * 物理删除（真正删除数据）
     */
    @Delete("DELETE FROM user WHERE id = #{id}")
    int physicalDeleteById(@Param("id") Long id);
}
```

### 7.4 逻辑删除的注意事项

```java
/**
 * 逻辑删除注意事项
 */
public class LogicDeleteNotes {
    
    // 1. 逻辑删除只对 MyBatis-Plus 自动生成的 SQL 有效
    // 自定义 SQL 需要手动处理 deleted 条件
    
    // 2. 逻辑删除字段的类型支持：
    // - Integer, int
    // - Boolean, boolean
    // - LocalDateTime (删除时间)
    
    // 3. 使用 LocalDateTime 作为逻辑删除字段
    // @TableLogic(value = "null", delval = "now()")
    // private LocalDateTime deleteTime;
    
    // 4. 逻辑删除会影响唯一索引
    // 如果 name 字段有唯一索引，逻辑删除后再插入相同 name 会报错
    // 解决方案：唯一索引改为 (name, deleted) 联合索引
    
    // 5. 关联查询时需要注意
    // 如果主表和关联表都有逻辑删除，需要在 SQL 中都加上条件
}
```

---

## 8. 乐观锁

乐观锁是一种并发控制机制，用于防止多个用户同时修改同一条数据时产生的数据覆盖问题。

### 8.1 乐观锁原理

```
场景：用户A和用户B同时读取了同一条数据（version=1）

没有乐观锁：
1. 用户A修改数据，保存成功
2. 用户B修改数据，保存成功（覆盖了用户A的修改）

有乐观锁：
1. 用户A修改数据，UPDATE ... WHERE version = 1，成功，version 变为 2
2. 用户B修改数据，UPDATE ... WHERE version = 1，失败（因为 version 已经是 2 了）
```

### 8.2 配置乐观锁插件

```java
@Configuration
public class MybatisPlusConfig {
    
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        
        // 添加乐观锁插件
        interceptor.addInnerInterceptor(new OptimisticLockerInnerInterceptor());
        
        // 添加分页插件
        interceptor.addInnerInterceptor(new PaginationInnerInterceptor(DbType.MYSQL));
        
        return interceptor;
    }
}
```

### 8.3 实体类配置

```java
@Data
@TableName("user")
public class User {
    
    @TableId(type = IdType.ASSIGN_ID)
    private Long id;
    
    private String name;
    
    private Integer age;
    
    /**
     * 版本号字段
     * @Version 标识乐观锁版本字段
     */
    @Version
    private Integer version;
}
```

### 8.4 使用乐观锁

```java
@SpringBootTest
public class OptimisticLockTest {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 乐观锁测试
     */
    @Test
    public void testOptimisticLock() {
        // 1. 查询用户（获取当前版本号）
        User user = userMapper.selectById(1L);
        System.out.println("当前版本号：" + user.getVersion());  // version = 1
        
        // 2. 修改用户信息
        user.setName("新名字");
        
        // 3. 执行更新
        // 实际 SQL: UPDATE user SET name='新名字', version=2 WHERE id=1 AND version=1
        int result = userMapper.updateById(user);
        
        if (result > 0) {
            System.out.println("更新成功，新版本号：" + user.getVersion());  // version = 2
        } else {
            System.out.println("更新失败，数据已被其他人修改");
        }
    }
    
    /**
     * 模拟并发冲突
     */
    @Test
    public void testConcurrentUpdate() {
        // 模拟用户A和用户B同时读取数据
        User userA = userMapper.selectById(1L);
        User userB = userMapper.selectById(1L);
        
        // 用户A先更新
        userA.setName("用户A修改");
        int resultA = userMapper.updateById(userA);
        System.out.println("用户A更新结果：" + (resultA > 0 ? "成功" : "失败"));
        
        // 用户B后更新（会失败，因为版本号已经变了）
        userB.setName("用户B修改");
        int resultB = userMapper.updateById(userB);
        System.out.println("用户B更新结果：" + (resultB > 0 ? "成功" : "失败"));
    }
}
```

### 8.5 乐观锁的注意事项

```java
/**
 * 乐观锁注意事项
 */
public class OptimisticLockNotes {
    
    // 1. 乐观锁只在 updateById(entity) 和 update(entity, wrapper) 方法中生效
    // 使用 UpdateWrapper 直接更新不会触发乐观锁
    
    // 2. 更新时必须先查询获取 version 值
    // 错误示例：
    // User user = new User();
    // user.setId(1L);
    // user.setName("新名字");
    // userMapper.updateById(user);  // version 为 null，乐观锁不生效
    
    // 正确示例：
    // User user = userMapper.selectById(1L);  // 先查询
    // user.setName("新名字");
    // userMapper.updateById(user);  // 乐观锁生效
    
    // 3. 支持的版本字段类型：
    // - int, Integer
    // - long, Long
    // - Date, Timestamp, LocalDateTime
    
    // 4. 更新失败后的处理
    // 可以选择重试或提示用户
}
```

### 8.6 乐观锁重试机制

```java
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    /**
     * 带重试的更新方法
     * @param user 用户对象
     * @param maxRetry 最大重试次数
     * @return 是否更新成功
     */
    public boolean updateWithRetry(User user, int maxRetry) {
        int retryCount = 0;
        
        while (retryCount < maxRetry) {
            // 重新查询最新数据
            User latestUser = this.getById(user.getId());
            if (latestUser == null) {
                return false;
            }
            
            // 更新字段
            latestUser.setName(user.getName());
            latestUser.setAge(user.getAge());
            // ... 其他字段
            
            // 尝试更新
            boolean success = this.updateById(latestUser);
            if (success) {
                return true;
            }
            
            retryCount++;
            log.warn("乐观锁冲突，第 {} 次重试", retryCount);
        }
        
        log.error("更新失败，已达到最大重试次数");
        return false;
    }
}
```

---

## 9. 代码生成器

MyBatis-Plus 提供了代码生成器，可以根据数据库表自动生成 Entity、Mapper、Service、Controller 等代码。

### 9.1 添加依赖

```xml
<!-- 代码生成器 -->
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-generator</artifactId>
    <version>3.5.3.1</version>
</dependency>

<!-- 模板引擎（二选一） -->
<!-- Freemarker -->
<dependency>
    <groupId>org.freemarker</groupId>
    <artifactId>freemarker</artifactId>
    <version>2.3.31</version>
</dependency>

<!-- 或者 Velocity -->
<!--
<dependency>
    <groupId>org.apache.velocity</groupId>
    <artifactId>velocity-engine-core</artifactId>
    <version>2.3</version>
</dependency>
-->
```

### 9.2 代码生成器配置

```java
package com.example.generator;

import com.baomidou.mybatisplus.generator.FastAutoGenerator;
import com.baomidou.mybatisplus.generator.config.OutputFile;
import com.baomidou.mybatisplus.generator.config.rules.DbColumnType;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;

import java.sql.Types;
import java.util.Collections;

/**
 * MyBatis-Plus 代码生成器
 */
public class CodeGenerator {
    
    public static void main(String[] args) {
        // 数据库连接配置
        String url = "jdbc:mysql://localhost:3306/mybatis_plus_demo?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai";
        String username = "root";
        String password = "your_password";
        
        FastAutoGenerator.create(url, username, password)
            // 全局配置
            .globalConfig(builder -> {
                builder.author("YourName")           // 作者
                       .outputDir("D://code//output") // 输出目录
                       .commentDate("yyyy-MM-dd")    // 注释日期格式
                       .disableOpenDir();            // 生成后不打开目录
            })
            // 数据源配置
            .dataSourceConfig(builder -> builder.typeConvertHandler((globalConfig, typeRegistry, metaInfo) -> {
                int typeCode = metaInfo.getJdbcType().TYPE_CODE;
                if (typeCode == Types.SMALLINT) {
                    return DbColumnType.INTEGER;
                }
                return typeRegistry.getColumnType(metaInfo);
            }))
            // 包配置
            .packageConfig(builder -> {
                builder.parent("com.example")        // 父包名
                       .moduleName("system")         // 模块名
                       .entity("entity")             // Entity 包名
                       .mapper("mapper")             // Mapper 包名
                       .service("service")           // Service 包名
                       .serviceImpl("service.impl")  // ServiceImpl 包名
                       .controller("controller")     // Controller 包名
                       .xml("mapper.xml")            // Mapper XML 包名
                       .pathInfo(Collections.singletonMap(
                           OutputFile.xml, "D://code//output//mapper"  // XML 文件输出路径
                       ));
            })
            // 策略配置
            .strategyConfig(builder -> {
                builder.addInclude("user", "order", "product")  // 要生成的表名
                       .addTablePrefix("t_", "sys_")            // 过滤表前缀
                       
                       // Entity 策略
                       .entityBuilder()
                       .enableLombok()                          // 启用 Lombok
                       .enableTableFieldAnnotation()            // 生成字段注解
                       .logicDeleteColumnName("deleted")        // 逻辑删除字段
                       .versionColumnName("version")            // 乐观锁字段
                       
                       // Mapper 策略
                       .mapperBuilder()
                       .enableMapperAnnotation()                // 添加 @Mapper 注解
                       .enableBaseResultMap()                   // 生成 BaseResultMap
                       .enableBaseColumnList()                  // 生成 BaseColumnList
                       
                       // Service 策略
                       .serviceBuilder()
                       .formatServiceFileName("%sService")      // Service 命名格式
                       .formatServiceImplFileName("%sServiceImpl")
                       
                       // Controller 策略
                       .controllerBuilder()
                       .enableRestStyle();                      // 生成 @RestController
            })
            // 使用 Freemarker 模板引擎
            .templateEngine(new FreemarkerTemplateEngine())
            .execute();
    }
}
```

### 9.3 生成的代码示例

**Entity:**
```java
@Data
@TableName("user")
public class User implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @TableId(value = "id", type = IdType.ASSIGN_ID)
    private Long id;
    
    @TableField("name")
    private String name;
    
    @TableField("age")
    private Integer age;
    
    @TableField("email")
    private String email;
    
    @TableField(value = "create_time", fill = FieldFill.INSERT)
    private LocalDateTime createTime;
    
    @TableField(value = "update_time", fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updateTime;
    
    @TableLogic
    @TableField("deleted")
    private Integer deleted;
    
    @Version
    @TableField("version")
    private Integer version;
}
```

**Mapper:**
```java
@Mapper
public interface UserMapper extends BaseMapper<User> {

}
```

**Service:**
```java
public interface UserService extends IService<User> {

}
```

**ServiceImpl:**
```java
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

}
```

**Controller:**
```java
@RestController
@RequestMapping("/system/user")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    // 可以在这里添加 CRUD 接口
}
```

---

## 10. 多数据源

在实际项目中，经常需要连接多个数据库。MyBatis-Plus 提供了 `dynamic-datasource` 来支持多数据源。

### 10.1 添加依赖

```xml
<!-- 多数据源 -->
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>dynamic-datasource-spring-boot-starter</artifactId>
    <version>3.6.1</version>
</dependency>
```

### 10.2 配置多数据源

```yaml
# application.yml
spring:
  datasource:
    dynamic:
      # 设置默认数据源
      primary: master
      # 严格匹配数据源，未匹配到则抛出异常
      strict: false
      datasource:
        # 主库
        master:
          driver-class-name: com.mysql.cj.jdbc.Driver
          url: jdbc:mysql://localhost:3306/master_db?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
          username: root
          password: password
        # 从库
        slave:
          driver-class-name: com.mysql.cj.jdbc.Driver
          url: jdbc:mysql://localhost:3306/slave_db?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
          username: root
          password: password
        # 其他数据源
        other:
          driver-class-name: com.mysql.cj.jdbc.Driver
          url: jdbc:mysql://localhost:3306/other_db?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
          username: root
          password: password
```

### 10.3 使用 @DS 注解切换数据源

```java
/**
 * @DS 注解可以加在类或方法上
 * 方法上的注解优先级高于类上的注解
 */
@Service
@DS("master")  // 类级别指定默认数据源
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    /**
     * 使用主库（默认）
     */
    public User getFromMaster(Long id) {
        return this.getById(id);
    }
    
    /**
     * 使用从库
     */
    @DS("slave")
    public User getFromSlave(Long id) {
        return this.getById(id);
    }
    
    /**
     * 使用其他数据源
     */
    @DS("other")
    public List<User> listFromOther() {
        return this.list();
    }
}
```

### 10.4 在 Mapper 层切换数据源

```java
@Mapper
@DS("slave")  // 整个 Mapper 使用从库
public interface SlaveUserMapper extends BaseMapper<User> {
    
}
```

### 10.5 动态切换数据源

```java
@Service
public class DynamicDataSourceService {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 手动切换数据源
     */
    public void manualSwitch() {
        // 切换到从库
        DynamicDataSourceContextHolder.push("slave");
        try {
            List<User> users = userMapper.selectList(null);
            // 处理数据...
        } finally {
            // 清除数据源，恢复默认
            DynamicDataSourceContextHolder.poll();
        }
    }
}
```

### 10.6 读写分离示例

```java
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    /**
     * 写操作 - 使用主库
     */
    @DS("master")
    @Transactional
    public boolean saveUser(User user) {
        return this.save(user);
    }
    
    /**
     * 读操作 - 使用从库
     */
    @DS("slave")
    public User getUser(Long id) {
        return this.getById(id);
    }
    
    /**
     * 读操作 - 使用从库
     */
    @DS("slave")
    public List<User> listUsers() {
        return this.list();
    }
}
```

---

## 11. 性能优化

### 11.1 SQL 性能分析插件

在开发环境中，可以使用性能分析插件来监控 SQL 执行情况：

```java
@Configuration
public class MybatisPlusConfig {
    
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        
        // 添加分页插件
        interceptor.addInnerInterceptor(new PaginationInnerInterceptor(DbType.MYSQL));
        
        // 添加乐观锁插件
        interceptor.addInnerInterceptor(new OptimisticLockerInnerInterceptor());
        
        // 添加防止全表更新与删除插件（生产环境建议开启）
        interceptor.addInnerInterceptor(new BlockAttackInnerInterceptor());
        
        return interceptor;
    }
    
    /**
     * SQL 执行效率插件（仅开发环境使用）
     * 3.5.x 版本已移除，可以使用 p6spy 替代
     */
}
```

### 11.2 使用 p6spy 监控 SQL

**添加依赖：**
```xml
<dependency>
    <groupId>p6spy</groupId>
    <artifactId>p6spy</artifactId>
    <version>3.9.1</version>
</dependency>
```

**修改数据源配置：**
```yaml
spring:
  datasource:
    driver-class-name: com.p6spy.engine.spy.P6SpyDriver
    url: jdbc:p6spy:mysql://localhost:3306/mybatis_plus_demo?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
```

**创建 spy.properties：**
```properties
# spy.properties
modulelist=com.baomidou.mybatisplus.extension.p6spy.MybatisPlusLogFactory,com.p6spy.engine.outage.P6OutageFactory
# 自定义日志打印
logMessageFormat=com.baomidou.mybatisplus.extension.p6spy.P6SpyLogger
# 日志输出到控制台
appender=com.baomidou.mybatisplus.extension.p6spy.StdoutLogger
# 设置 p6spy driver 代理
deregisterdrivers=true
# 取消JDBC URL前缀
useprefix=true
# 日期格式
dateformat=yyyy-MM-dd HH:mm:ss
# 实际驱动
driverlist=com.mysql.cj.jdbc.Driver
# 是否开启慢SQL记录
outagedetection=true
# 慢SQL记录标准 2 秒
outagedetectioninterval=2
```

### 11.3 批量操作优化

```java
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    /**
     * 批量插入优化
     * 默认批次大小为 1000
     */
    public void batchInsert(List<User> users) {
        // 方式一：使用 saveBatch（推荐）
        this.saveBatch(users, 500);  // 每批 500 条
        
        // 方式二：使用 saveOrUpdateBatch
        this.saveOrUpdateBatch(users, 500);
    }
    
    /**
     * 批量更新优化
     */
    public void batchUpdate(List<User> users) {
        this.updateBatchById(users, 500);
    }
}
```

**开启批量插入的 rewriteBatchedStatements：**
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mybatis_plus_demo?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai&rewriteBatchedStatements=true
```

### 11.4 查询优化

```java
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    /**
     * 只查询需要的字段
     */
    public List<User> selectOnlyNameAndAge() {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.select(User::getId, User::getName, User::getAge);
        return this.list(wrapper);
    }
    
    /**
     * 使用流式查询处理大数据量
     */
    public void processLargeData() {
        // 分批处理，避免一次性加载过多数据到内存
        int pageSize = 1000;
        int pageNum = 1;
        
        while (true) {
            Page<User> page = new Page<>(pageNum, pageSize);
            Page<User> result = this.page(page);
            
            if (result.getRecords().isEmpty()) {
                break;
            }
            
            // 处理当前批次数据
            result.getRecords().forEach(user -> {
                // 处理逻辑...
            });
            
            pageNum++;
        }
    }
    
    /**
     * 避免 N+1 查询问题
     * 使用 IN 查询代替循环查询
     */
    public Map<Long, User> getUserMap(List<Long> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return Collections.emptyMap();
        }
        
        // 批量查询
        List<User> users = this.listByIds(userIds);
        
        // 转换为 Map
        return users.stream()
                .collect(Collectors.toMap(User::getId, Function.identity()));
    }
}
```

### 11.5 索引优化建议

```sql
-- 为常用查询字段添加索引
CREATE INDEX idx_user_name ON user(name);
CREATE INDEX idx_user_age ON user(age);
CREATE INDEX idx_user_email ON user(email);

-- 联合索引（注意字段顺序）
CREATE INDEX idx_user_name_age ON user(name, age);

-- 唯一索引
CREATE UNIQUE INDEX uk_user_email ON user(email);
```

---

## 12. 常见错误与解决方案

### 12.1 表名/字段名映射错误

**错误信息：**
```
Table 'database.User' doesn't exist
Unknown column 'createTime' in 'field list'
```

**原因：** 表名或字段名与数据库不匹配

**解决方案：**
```java
// 1. 使用 @TableName 指定表名
@TableName("t_user")
public class User {
    
    // 2. 使用 @TableField 指定字段名
    @TableField("create_time")
    private LocalDateTime createTime;
}

// 3. 或者开启驼峰命名转换（推荐）
// application.yml
mybatis-plus:
  configuration:
    map-underscore-to-camel-case: true
```

### 12.2 主键生成问题

**错误信息：**
```
Cannot add or update a child row: a foreign key constraint fails
Duplicate entry '0' for key 'PRIMARY'
```

**原因：** 主键生成策略配置不正确

**解决方案：**
```java
// 1. 使用雪花算法（推荐）
@TableId(type = IdType.ASSIGN_ID)
private Long id;

// 2. 使用数据库自增
@TableId(type = IdType.AUTO)
private Long id;

// 3. 全局配置
// application.yml
mybatis-plus:
  global-config:
    db-config:
      id-type: ASSIGN_ID
```

### 12.3 分页不生效

**现象：** 分页查询返回全部数据，没有分页效果

**原因：** 没有配置分页插件

**解决方案：**
```java
@Configuration
public class MybatisPlusConfig {
    
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        // 必须添加分页插件！
        interceptor.addInnerInterceptor(new PaginationInnerInterceptor(DbType.MYSQL));
        return interceptor;
    }
}
```

### 12.4 自动填充不生效

**现象：** createTime、updateTime 等字段没有自动填充

**原因及解决方案：**
```java
// 1. 检查是否实现了 MetaObjectHandler
@Component  // 必须加 @Component 注解！
public class MyMetaObjectHandler implements MetaObjectHandler {
    // ...
}

// 2. 检查实体类字段是否添加了 @TableField(fill = ...)
@TableField(fill = FieldFill.INSERT)
private LocalDateTime createTime;

// 3. 检查字段类型是否匹配
// 如果数据库是 datetime，Java 应该用 LocalDateTime 或 Date

// 4. 使用 UpdateWrapper 时，需要传入实体对象
// 错误：
userMapper.update(null, updateWrapper);  // 自动填充不生效

// 正确：
User user = new User();
userMapper.update(user, updateWrapper);  // 自动填充生效
```

### 12.5 逻辑删除不生效

**现象：** 删除后数据真的被删除了，或者查询时没有过滤已删除数据

**原因及解决方案：**
```java
// 1. 检查是否配置了逻辑删除
// application.yml
mybatis-plus:
  global-config:
    db-config:
      logic-delete-field: deleted
      logic-delete-value: 1
      logic-not-delete-value: 0

// 2. 或者在实体类使用 @TableLogic
@TableLogic
private Integer deleted;

// 3. 检查数据库字段是否存在且有默认值
// ALTER TABLE user ADD COLUMN deleted INT DEFAULT 0;

// 4. 自定义 SQL 不会自动添加逻辑删除条件
// 需要手动添加 WHERE deleted = 0
```

### 12.6 乐观锁不生效

**现象：** 并发更新时没有版本控制

**原因及解决方案：**
```java
// 1. 检查是否配置了乐观锁插件
@Bean
public MybatisPlusInterceptor mybatisPlusInterceptor() {
    MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
    interceptor.addInnerInterceptor(new OptimisticLockerInnerInterceptor());
    return interceptor;
}

// 2. 检查实体类是否添加了 @Version
@Version
private Integer version;

// 3. 更新时必须先查询获取 version
// 错误：
User user = new User();
user.setId(1L);
user.setName("新名字");
userMapper.updateById(user);  // version 为 null，乐观锁不生效

// 正确：
User user = userMapper.selectById(1L);  // 先查询
user.setName("新名字");
userMapper.updateById(user);  // 乐观锁生效
```

### 12.7 Mapper 注入失败

**错误信息：**
```
No qualifying bean of type 'com.example.mapper.UserMapper' available
```

**原因及解决方案：**
```java
// 1. 检查启动类是否添加了 @MapperScan
@SpringBootApplication
@MapperScan("com.example.mapper")  // 扫描 Mapper 包
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

// 2. 或者在每个 Mapper 接口上添加 @Mapper
@Mapper
public interface UserMapper extends BaseMapper<User> {
}

// 3. 检查 Mapper 接口是否在正确的包路径下
```

### 12.8 SQL 注入风险

**问题：** 使用字符串拼接 SQL 可能导致 SQL 注入

**解决方案：**
```java
// 错误示例（有 SQL 注入风险）：
String name = request.getParameter("name");
wrapper.apply("name = '" + name + "'");  // 危险！

// 正确示例（使用占位符）：
String name = request.getParameter("name");
wrapper.apply("name = {0}", name);  // 安全

// 或者使用 eq 方法：
wrapper.eq("name", name);  // 安全

// 使用 Lambda 表达式更安全：
wrapper.eq(User::getName, name);  // 最安全
```

### 12.9 事务不生效

**现象：** 数据操作失败后没有回滚

**原因及解决方案：**
```java
// 1. 检查是否添加了 @Transactional 注解
@Service
public class UserServiceImpl {
    
    @Transactional(rollbackFor = Exception.class)  // 指定回滚异常
    public void saveUser(User user) {
        // ...
    }
}

// 2. 检查是否是同一个类内部调用（事务不生效）
// 错误：
public void methodA() {
    methodB();  // 内部调用，事务不生效
}

@Transactional
public void methodB() {
    // ...
}

// 正确：通过代理对象调用
@Autowired
private UserService self;

public void methodA() {
    self.methodB();  // 通过代理调用，事务生效
}

// 3. 检查异常是否被捕获
@Transactional
public void saveUser(User user) {
    try {
        // ...
    } catch (Exception e) {
        // 异常被捕获，事务不会回滚
        // 需要手动抛出或使用 TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
    }
}
```

### 12.10 多数据源事务问题

**问题：** 多数据源下事务不生效或数据源切换失败

**解决方案：**
```java
// 1. @DS 注解和 @Transactional 一起使用时，@DS 要放在外层
@DS("slave")
@Transactional
public void method() {
    // ...
}

// 2. 跨数据源事务需要使用分布式事务
// 可以使用 Seata 等分布式事务框架

// 3. 如果不需要跨数据源事务，可以分开处理
@DS("master")
@Transactional
public void saveMaster(User user) {
    // 主库操作
}

@DS("slave")
public User getSlave(Long id) {
    // 从库操作（只读，不需要事务）
    return userMapper.selectById(id);
}
```

### 12.11 类型转换错误

**错误信息：**
```
Cannot convert value of type 'java.lang.String' to required type 'java.time.LocalDateTime'
```

**解决方案：**
```java
// 1. 检查数据库字段类型和 Java 字段类型是否匹配
// MySQL datetime -> Java LocalDateTime
// MySQL date -> Java LocalDate
// MySQL timestamp -> Java LocalDateTime

// 2. 添加 Jackson 配置（用于 JSON 序列化）
@Configuration
public class JacksonConfig {
    
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }
}

// 3. 在实体类字段上添加格式化注解
@JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
private LocalDateTime createTime;
```

### 12.12 性能问题排查

**问题：** 查询速度慢

**排查步骤：**
```java
// 1. 开启 SQL 日志，查看执行的 SQL
// application.yml
mybatis-plus:
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl

// 2. 检查是否有 N+1 查询问题
// 使用 IN 查询代替循环查询

// 3. 检查是否查询了不必要的字段
// 使用 select() 指定需要的字段
wrapper.select(User::getId, User::getName);

// 4. 检查是否缺少索引
// 使用 EXPLAIN 分析 SQL

// 5. 检查分页是否合理
// 避免深分页（offset 过大）

// 6. 检查是否有全表扫描
// 避免使用 LIKE '%xxx' 开头的模糊查询
```

---

## 总结

MyBatis-Plus 是一个非常强大的 MyBatis 增强工具，它极大地简化了数据库操作的代码量。通过本笔记的学习，你应该掌握了：

1. **基础配置**：如何在 Spring Boot 项目中集成 MyBatis-Plus
2. **CRUD 操作**：使用 BaseMapper 和 IService 进行增删改查
3. **条件构造器**：使用 QueryWrapper 和 LambdaQueryWrapper 构建复杂查询
4. **分页查询**：配置和使用分页插件
5. **自动填充**：自动填充创建时间、更新时间等字段
6. **逻辑删除**：实现软删除功能
7. **乐观锁**：处理并发更新问题
8. **代码生成器**：快速生成 Entity、Mapper、Service、Controller 代码
9. **多数据源**：配置和使用多个数据库
10. **性能优化**：SQL 监控、批量操作、查询优化
11. **常见错误**：各种常见问题的排查和解决方案

记住，MyBatis-Plus 只是工具，真正重要的是理解其背后的原理和最佳实践。在实际项目中，要根据具体需求选择合适的功能，避免过度使用或滥用。

---

## 参考资料

- [MyBatis-Plus 官方文档](https://baomidou.com/)
- [MyBatis-Plus GitHub](https://github.com/baomidou/mybatis-plus)
- [Spring Boot 官方文档](https://spring.io/projects/spring-boot)
