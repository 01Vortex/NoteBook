
> MyBatis 是一款优秀的持久层框架，支持自定义 SQL、存储过程以及高级映射
> 本笔记基于 Java 8 + Spring Boot 2.7.18 + MyBatis 3.5.x

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [基础 CRUD](#3-基础-crud)
4. [参数处理](#4-参数处理)
5. [结果映射](#5-结果映射)
6. [动态 SQL](#6-动态-sql)
7. [关联查询](#7-关联查询)
8. [注解开发](#8-注解开发)
9. [缓存机制](#9-缓存机制)
10. [分页查询](#10-分页查询)
11. [批量操作](#11-批量操作)
12. [插件机制](#12-插件机制)
13. [代码生成器](#13-代码生成器)
14. [常见错误与解决方案](#14-常见错误与解决方案)
15. [最佳实践](#15-最佳实践)

---

## 1. 基础概念

### 1.1 什么是 MyBatis？

MyBatis 是一款优秀的**持久层框架**，它消除了几乎所有的 JDBC 代码和手动设置参数以及获取结果集的工作。MyBatis 可以使用简单的 XML 或注解来配置和映射原生类型、接口和 Java POJO（Plain Old Java Objects，普通老式 Java 对象）为数据库中的记录。

**MyBatis 的特点：**
- **简单易学**：相比 Hibernate，MyBatis 更加轻量级，学习成本低
- **灵活**：SQL 写在 XML 里，便于统一管理和优化
- **解除 SQL 与程序代码的耦合**：SQL 和代码分离，提高可维护性
- **支持动态 SQL**：可以根据条件动态生成 SQL
- **支持对象关系映射**：支持一对一、一对多等关联映射

### 1.2 MyBatis vs Hibernate vs JPA

| 特性 | MyBatis | Hibernate | JPA |
|------|---------|-----------|-----|
| 学习曲线 | 低 | 高 | 中 |
| SQL 控制 | 完全控制 | 自动生成 | 自动生成 |
| 性能优化 | 容易 | 较难 | 较难 |
| 移植性 | 较差（SQL 依赖数据库） | 好 | 好 |
| 适用场景 | 复杂查询、性能要求高 | 简单 CRUD、快速开发 | 标准化项目 |

### 1.3 核心组件

```
SqlSessionFactoryBuilder  -->  SqlSessionFactory  -->  SqlSession  -->  Mapper
       (构建器)                    (工厂)              (会话)         (映射器)
```

**核心组件说明：**

| 组件 | 说明 | 生命周期 |
|------|------|----------|
| SqlSessionFactoryBuilder | 用于创建 SqlSessionFactory | 用完即丢 |
| SqlSessionFactory | 用于创建 SqlSession | 应用级别（单例） |
| SqlSession | 执行 SQL 的会话 | 请求/方法级别 |
| Mapper | 映射器接口 | 方法级别 |

### 1.4 工作原理

```
1. 读取 MyBatis 配置文件（mybatis-config.xml）
2. 加载映射文件（Mapper.xml）
3. 构建 SqlSessionFactory
4. 创建 SqlSession
5. 通过 SqlSession 获取 Mapper 接口的代理对象
6. 执行 Mapper 接口方法，代理对象调用对应的 SQL
7. 返回结果
```

---

## 2. 环境搭建

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
    
    <!-- MyBatis Spring Boot Starter -->
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
    
    <!-- Druid 连接池（可选） -->
    <dependency>
        <groupId>com.alibaba</groupId>
        <artifactId>druid-spring-boot-starter</artifactId>
        <version>1.2.18</version>
    </dependency>
    
    <!-- Lombok（可选） -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### 2.2 配置文件

```yaml
# application.yml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql://localhost:3306/mydb?useUnicode=true&characterEncoding=utf-8&useSSL=false&serverTimezone=Asia/Shanghai
    username: root
    password: root
    # Druid 连接池配置
    type: com.alibaba.druid.pool.DruidDataSource
    druid:
      initial-size: 5
      min-idle: 5
      max-active: 20
      max-wait: 60000
      time-between-eviction-runs-millis: 60000
      min-evictable-idle-time-millis: 300000

# MyBatis 配置
mybatis:
  # Mapper XML 文件位置
  mapper-locations: classpath:mapper/*.xml
  # 实体类包路径（用于类型别名）
  type-aliases-package: com.example.entity
  configuration:
    # 开启驼峰命名转换（数据库下划线 -> Java驼峰）
    map-underscore-to-camel-case: true
    # 开启延迟加载
    lazy-loading-enabled: true
    # 开启二级缓存
    cache-enabled: true
    # 打印 SQL 日志
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl

# 日志配置
logging:
  level:
    com.example.mapper: debug
```


### 2.3 启动类配置

```java
package com.example;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.example.mapper")  // 扫描 Mapper 接口
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 2.4 项目结构

```
src/main/java/com/example/
├── Application.java              # 启动类
├── entity/                       # 实体类
│   └── User.java
├── mapper/                       # Mapper 接口
│   └── UserMapper.java
├── service/                      # 服务层
│   ├── UserService.java
│   └── impl/
│       └── UserServiceImpl.java
└── controller/                   # 控制器
    └── UserController.java

src/main/resources/
├── application.yml               # 配置文件
└── mapper/                       # Mapper XML 文件
    └── UserMapper.xml
```

### 2.5 数据库准备

```sql
-- 创建数据库
CREATE DATABASE IF NOT EXISTS mydb DEFAULT CHARACTER SET utf8mb4;

USE mydb;

-- 创建用户表
CREATE TABLE `user` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT '主键ID',
    `username` VARCHAR(50) NOT NULL COMMENT '用户名',
    `password` VARCHAR(100) NOT NULL COMMENT '密码',
    `email` VARCHAR(100) COMMENT '邮箱',
    `phone` VARCHAR(20) COMMENT '手机号',
    `status` TINYINT DEFAULT 1 COMMENT '状态：0-禁用，1-启用',
    `create_time` DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `update_time` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    `deleted` TINYINT DEFAULT 0 COMMENT '是否删除：0-否，1-是',
    UNIQUE KEY `uk_username` (`username`),
    KEY `idx_email` (`email`),
    KEY `idx_create_time` (`create_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

-- 插入测试数据
INSERT INTO `user` (`username`, `password`, `email`, `phone`) VALUES
('zhangsan', '123456', 'zhangsan@example.com', '13800138001'),
('lisi', '123456', 'lisi@example.com', '13800138002'),
('wangwu', '123456', 'wangwu@example.com', '13800138003');
```

---

## 3. 基础 CRUD

### 3.1 实体类

```java
package com.example.entity;

import lombok.Data;
import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * 用户实体类
 */
@Data
public class User implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 主键ID
     */
    private Long id;
    
    /**
     * 用户名
     */
    private String username;
    
    /**
     * 密码
     */
    private String password;
    
    /**
     * 邮箱
     */
    private String email;
    
    /**
     * 手机号
     */
    private String phone;
    
    /**
     * 状态：0-禁用，1-启用
     */
    private Integer status;
    
    /**
     * 创建时间
     */
    private LocalDateTime createTime;
    
    /**
     * 更新时间
     */
    private LocalDateTime updateTime;
    
    /**
     * 是否删除
     */
    private Integer deleted;
}
```

### 3.2 Mapper 接口

```java
package com.example.mapper;

import com.example.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 用户 Mapper 接口
 */
@Mapper
public interface UserMapper {
    
    /**
     * 根据ID查询用户
     */
    User selectById(Long id);
    
    /**
     * 查询所有用户
     */
    List<User> selectAll();
    
    /**
     * 根据用户名查询
     */
    User selectByUsername(String username);
    
    /**
     * 插入用户
     */
    int insert(User user);
    
    /**
     * 更新用户
     */
    int update(User user);
    
    /**
     * 根据ID删除用户
     */
    int deleteById(Long id);
    
    /**
     * 批量删除
     */
    int deleteBatch(@Param("ids") List<Long> ids);
}
```

### 3.3 Mapper XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" 
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="com.example.mapper.UserMapper">
    
    <!-- 结果映射 -->
    <resultMap id="BaseResultMap" type="User">
        <id column="id" property="id"/>
        <result column="username" property="username"/>
        <result column="password" property="password"/>
        <result column="email" property="email"/>
        <result column="phone" property="phone"/>
        <result column="status" property="status"/>
        <result column="create_time" property="createTime"/>
        <result column="update_time" property="updateTime"/>
        <result column="deleted" property="deleted"/>
    </resultMap>
    
    <!-- 基础列 -->
    <sql id="Base_Column_List">
        id, username, password, email, phone, status, create_time, update_time, deleted
    </sql>
    
    <!-- 根据ID查询 -->
    <select id="selectById" resultMap="BaseResultMap">
        SELECT <include refid="Base_Column_List"/>
        FROM user
        WHERE id = #{id} AND deleted = 0
    </select>
    
    <!-- 查询所有 -->
    <select id="selectAll" resultMap="BaseResultMap">
        SELECT <include refid="Base_Column_List"/>
        FROM user
        WHERE deleted = 0
        ORDER BY create_time DESC
    </select>
    
    <!-- 根据用户名查询 -->
    <select id="selectByUsername" resultMap="BaseResultMap">
        SELECT <include refid="Base_Column_List"/>
        FROM user
        WHERE username = #{username} AND deleted = 0
    </select>
    
    <!-- 插入 -->
    <insert id="insert" useGeneratedKeys="true" keyProperty="id">
        INSERT INTO user (username, password, email, phone, status)
        VALUES (#{username}, #{password}, #{email}, #{phone}, #{status})
    </insert>
    
    <!-- 更新 -->
    <update id="update">
        UPDATE user
        SET username = #{username},
            password = #{password},
            email = #{email},
            phone = #{phone},
            status = #{status}
        WHERE id = #{id}
    </update>
    
    <!-- 删除（逻辑删除） -->
    <update id="deleteById">
        UPDATE user SET deleted = 1 WHERE id = #{id}
    </update>
    
    <!-- 批量删除 -->
    <update id="deleteBatch">
        UPDATE user SET deleted = 1
        WHERE id IN
        <foreach collection="ids" item="id" open="(" separator="," close=")">
            #{id}
        </foreach>
    </update>
    
</mapper>
```

### 3.4 Service 层

```java
package com.example.service;

import com.example.entity.User;
import java.util.List;

public interface UserService {
    User getById(Long id);
    List<User> getAll();
    User getByUsername(String username);
    boolean save(User user);
    boolean update(User user);
    boolean deleteById(Long id);
    boolean deleteBatch(List<Long> ids);
}
```

```java
package com.example.service.impl;

import com.example.entity.User;
import com.example.mapper.UserMapper;
import com.example.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    
    private final UserMapper userMapper;
    
    @Override
    public User getById(Long id) {
        return userMapper.selectById(id);
    }
    
    @Override
    public List<User> getAll() {
        return userMapper.selectAll();
    }
    
    @Override
    public User getByUsername(String username) {
        return userMapper.selectByUsername(username);
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean save(User user) {
        return userMapper.insert(user) > 0;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean update(User user) {
        return userMapper.update(user) > 0;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean deleteById(Long id) {
        return userMapper.deleteById(id) > 0;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean deleteBatch(List<Long> ids) {
        return userMapper.deleteBatch(ids) > 0;
    }
}
```


---

## 4. 参数处理

MyBatis 支持多种参数传递方式，理解参数处理机制对于编写正确的 SQL 非常重要。

### 4.1 单个参数

```java
// Mapper 接口
User selectById(Long id);
User selectByUsername(String username);
```

```xml
<!-- 单个参数可以使用任意名称 -->
<select id="selectById" resultType="User">
    SELECT * FROM user WHERE id = #{id}
</select>

<select id="selectByUsername" resultType="User">
    SELECT * FROM user WHERE username = #{username}
</select>
```

### 4.2 多个参数

当有多个参数时，MyBatis 默认使用 `arg0, arg1...` 或 `param1, param2...` 作为参数名。推荐使用 `@Param` 注解指定参数名。

```java
// 方式一：使用 @Param 注解（推荐）
User selectByUsernameAndPassword(@Param("username") String username, 
                                  @Param("password") String password);

// 方式二：使用 Map
User selectByMap(Map<String, Object> params);

// 方式三：使用实体类
User selectByCondition(User user);
```

```xml
<!-- 使用 @Param 注解 -->
<select id="selectByUsernameAndPassword" resultType="User">
    SELECT * FROM user 
    WHERE username = #{username} AND password = #{password}
</select>

<!-- 使用 Map -->
<select id="selectByMap" resultType="User">
    SELECT * FROM user 
    WHERE username = #{username} AND status = #{status}
</select>

<!-- 使用实体类 -->
<select id="selectByCondition" resultType="User">
    SELECT * FROM user 
    WHERE username = #{username} AND email = #{email}
</select>
```

### 4.3 集合参数

```java
// List 参数
List<User> selectByIds(@Param("ids") List<Long> ids);

// 数组参数
List<User> selectByIdArray(@Param("ids") Long[] ids);
```

```xml
<!-- List 参数 -->
<select id="selectByIds" resultType="User">
    SELECT * FROM user WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</select>

<!-- 数组参数 -->
<select id="selectByIdArray" resultType="User">
    SELECT * FROM user WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</select>
```

### 4.4 #{} 和 ${} 的区别

这是 MyBatis 中非常重要的概念，理解它们的区别可以避免 SQL 注入问题。

| 特性 | #{} | ${} |
|------|-----|-----|
| 处理方式 | 预编译（PreparedStatement） | 字符串替换 |
| SQL 注入 | 安全 | 不安全 |
| 使用场景 | 参数值 | 表名、列名、排序字段 |

```xml
<!-- #{} 预编译，安全 -->
<select id="selectByUsername" resultType="User">
    SELECT * FROM user WHERE username = #{username}
    <!-- 实际执行：SELECT * FROM user WHERE username = ? -->
</select>

<!-- ${} 字符串替换，有 SQL 注入风险 -->
<select id="selectByTableName" resultType="User">
    SELECT * FROM ${tableName} WHERE id = #{id}
    <!-- 实际执行：SELECT * FROM user WHERE id = ? -->
</select>

<!-- ${} 用于动态表名、列名、排序 -->
<select id="selectWithOrder" resultType="User">
    SELECT * FROM user ORDER BY ${orderColumn} ${orderType}
</select>
```

**注意：** 使用 `${}` 时，必须对参数进行校验，防止 SQL 注入！

```java
// 安全的做法：白名单校验
public List<User> selectWithOrder(String orderColumn, String orderType) {
    // 校验排序字段
    List<String> allowedColumns = Arrays.asList("id", "username", "create_time");
    if (!allowedColumns.contains(orderColumn)) {
        throw new IllegalArgumentException("非法的排序字段");
    }
    
    // 校验排序方式
    if (!"ASC".equalsIgnoreCase(orderType) && !"DESC".equalsIgnoreCase(orderType)) {
        throw new IllegalArgumentException("非法的排序方式");
    }
    
    return userMapper.selectWithOrder(orderColumn, orderType);
}
```

### 4.5 参数类型处理器

MyBatis 内置了常用的类型处理器，也可以自定义类型处理器。

```java
/**
 * 自定义类型处理器：JSON 字符串 <-> List
 */
@MappedTypes(List.class)
@MappedJdbcTypes(JdbcType.VARCHAR)
public class JsonListTypeHandler extends BaseTypeHandler<List<String>> {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, 
                                    List<String> parameter, JdbcType jdbcType) throws SQLException {
        try {
            ps.setString(i, objectMapper.writeValueAsString(parameter));
        } catch (JsonProcessingException e) {
            throw new SQLException("JSON 序列化失败", e);
        }
    }
    
    @Override
    public List<String> getNullableResult(ResultSet rs, String columnName) throws SQLException {
        return parseJson(rs.getString(columnName));
    }
    
    @Override
    public List<String> getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        return parseJson(rs.getString(columnIndex));
    }
    
    @Override
    public List<String> getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        return parseJson(cs.getString(columnIndex));
    }
    
    private List<String> parseJson(String json) {
        if (json == null || json.isEmpty()) {
            return new ArrayList<>();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException e) {
            return new ArrayList<>();
        }
    }
}
```

```yaml
# 注册类型处理器
mybatis:
  type-handlers-package: com.example.handler
```

---

## 5. 结果映射

### 5.1 自动映射

当数据库列名和实体类属性名一致时，MyBatis 可以自动映射。

```xml
<!-- 自动映射 -->
<select id="selectById" resultType="User">
    SELECT id, username, password, email FROM user WHERE id = #{id}
</select>
```

开启驼峰命名转换后，`create_time` 会自动映射到 `createTime`：

```yaml
mybatis:
  configuration:
    map-underscore-to-camel-case: true
```

### 5.2 resultMap 映射

当列名和属性名不一致，或需要复杂映射时，使用 resultMap。

```xml
<resultMap id="UserResultMap" type="User">
    <!-- id 标签用于主键，可以提高性能 -->
    <id column="id" property="id"/>
    <!-- result 标签用于普通字段 -->
    <result column="user_name" property="username"/>
    <result column="pass_word" property="password"/>
    <result column="e_mail" property="email"/>
    <result column="create_time" property="createTime"/>
</resultMap>

<select id="selectById" resultMap="UserResultMap">
    SELECT id, user_name, pass_word, e_mail, create_time 
    FROM user WHERE id = #{id}
</select>
```

### 5.3 返回 Map

```java
// 返回单个 Map
Map<String, Object> selectByIdReturnMap(Long id);

// 返回 Map 列表
List<Map<String, Object>> selectAllReturnMap();

// 返回以某个字段为 key 的 Map
@MapKey("id")
Map<Long, User> selectAllAsMap();
```

```xml
<select id="selectByIdReturnMap" resultType="map">
    SELECT * FROM user WHERE id = #{id}
</select>

<select id="selectAllReturnMap" resultType="map">
    SELECT * FROM user
</select>

<select id="selectAllAsMap" resultType="User">
    SELECT * FROM user
</select>
```

### 5.4 构造器映射

```xml
<resultMap id="UserConstructorMap" type="User">
    <constructor>
        <idArg column="id" javaType="Long"/>
        <arg column="username" javaType="String"/>
        <arg column="email" javaType="String"/>
    </constructor>
</resultMap>
```

```java
@Data
public class User {
    private Long id;
    private String username;
    private String email;
    
    // 需要对应的构造函数
    public User(Long id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }
}
```


---

## 6. 动态 SQL

动态 SQL 是 MyBatis 的强大特性之一，可以根据条件动态生成 SQL 语句。

### 6.1 if 标签

根据条件判断是否包含某段 SQL。

```xml
<select id="selectByCondition" resultType="User">
    SELECT * FROM user
    WHERE deleted = 0
    <if test="username != null and username != ''">
        AND username LIKE CONCAT('%', #{username}, '%')
    </if>
    <if test="email != null and email != ''">
        AND email = #{email}
    </if>
    <if test="status != null">
        AND status = #{status}
    </if>
</select>
```

### 6.2 where 标签

自动处理 WHERE 关键字和多余的 AND/OR。

```xml
<select id="selectByCondition" resultType="User">
    SELECT * FROM user
    <where>
        <if test="username != null and username != ''">
            AND username LIKE CONCAT('%', #{username}, '%')
        </if>
        <if test="email != null and email != ''">
            AND email = #{email}
        </if>
        <if test="status != null">
            AND status = #{status}
        </if>
        AND deleted = 0
    </where>
</select>
```

**where 标签的作用：**
- 如果内部有条件成立，自动添加 WHERE 关键字
- 自动去除开头多余的 AND 或 OR
- 如果内部没有条件成立，不会添加 WHERE

### 6.3 set 标签

用于 UPDATE 语句，自动处理多余的逗号。

```xml
<update id="updateSelective">
    UPDATE user
    <set>
        <if test="username != null and username != ''">
            username = #{username},
        </if>
        <if test="password != null and password != ''">
            password = #{password},
        </if>
        <if test="email != null and email != ''">
            email = #{email},
        </if>
        <if test="phone != null and phone != ''">
            phone = #{phone},
        </if>
        <if test="status != null">
            status = #{status},
        </if>
        update_time = NOW()
    </set>
    WHERE id = #{id}
</update>
```

### 6.4 choose/when/otherwise 标签

类似于 Java 的 switch-case 语句，只会选择一个分支。

```xml
<select id="selectByCondition" resultType="User">
    SELECT * FROM user
    WHERE deleted = 0
    <choose>
        <when test="id != null">
            AND id = #{id}
        </when>
        <when test="username != null and username != ''">
            AND username = #{username}
        </when>
        <when test="email != null and email != ''">
            AND email = #{email}
        </when>
        <otherwise>
            AND status = 1
        </otherwise>
    </choose>
</select>
```

### 6.5 trim 标签

更灵活的标签，可以自定义前缀、后缀以及要去除的内容。

```xml
<!-- 等价于 where 标签 -->
<trim prefix="WHERE" prefixOverrides="AND |OR ">
    <if test="username != null">
        AND username = #{username}
    </if>
    <if test="email != null">
        AND email = #{email}
    </if>
</trim>

<!-- 等价于 set 标签 -->
<trim prefix="SET" suffixOverrides=",">
    <if test="username != null">
        username = #{username},
    </if>
    <if test="email != null">
        email = #{email},
    </if>
</trim>
```

**trim 标签属性：**
- `prefix`：在内容前添加的前缀
- `suffix`：在内容后添加的后缀
- `prefixOverrides`：去除内容开头的指定字符
- `suffixOverrides`：去除内容结尾的指定字符

### 6.6 foreach 标签

用于遍历集合，常用于 IN 查询和批量操作。

```xml
<!-- IN 查询 -->
<select id="selectByIds" resultType="User">
    SELECT * FROM user
    WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</select>

<!-- 批量插入 -->
<insert id="insertBatch">
    INSERT INTO user (username, password, email, phone)
    VALUES
    <foreach collection="users" item="user" separator=",">
        (#{user.username}, #{user.password}, #{user.email}, #{user.phone})
    </foreach>
</insert>

<!-- 批量更新 -->
<update id="updateBatch">
    <foreach collection="users" item="user" separator=";">
        UPDATE user
        SET username = #{user.username},
            email = #{user.email}
        WHERE id = #{user.id}
    </foreach>
</update>
```

**foreach 标签属性：**
- `collection`：要遍历的集合（list、array、map 的 key）
- `item`：当前元素的变量名
- `index`：当前元素的索引（List）或 key（Map）
- `open`：开始符号
- `close`：结束符号
- `separator`：元素之间的分隔符

### 6.7 sql 和 include 标签

用于定义可重用的 SQL 片段。

```xml
<!-- 定义 SQL 片段 -->
<sql id="Base_Column_List">
    id, username, password, email, phone, status, create_time, update_time, deleted
</sql>

<sql id="Where_Condition">
    <where>
        <if test="username != null and username != ''">
            AND username LIKE CONCAT('%', #{username}, '%')
        </if>
        <if test="email != null and email != ''">
            AND email = #{email}
        </if>
        <if test="status != null">
            AND status = #{status}
        </if>
        AND deleted = 0
    </where>
</sql>

<!-- 引用 SQL 片段 -->
<select id="selectByCondition" resultType="User">
    SELECT <include refid="Base_Column_List"/>
    FROM user
    <include refid="Where_Condition"/>
</select>

<!-- 带参数的 SQL 片段 -->
<sql id="Table_Name">
    ${tableName}
</sql>

<select id="selectFromTable" resultType="User">
    SELECT * FROM <include refid="Table_Name">
        <property name="tableName" value="user"/>
    </include>
</select>
```

### 6.8 bind 标签

用于创建变量并绑定到上下文。

```xml
<select id="selectByUsername" resultType="User">
    <!-- 创建模糊查询的变量 -->
    <bind name="pattern" value="'%' + username + '%'"/>
    SELECT * FROM user
    WHERE username LIKE #{pattern}
</select>
```


---

## 7. 关联查询

MyBatis 支持一对一、一对多、多对多等关联查询。

### 7.1 准备工作

```sql
-- 部门表
CREATE TABLE `department` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `name` VARCHAR(50) NOT NULL COMMENT '部门名称',
    `parent_id` BIGINT DEFAULT 0 COMMENT '父部门ID',
    `create_time` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户表添加部门ID
ALTER TABLE `user` ADD COLUMN `dept_id` BIGINT COMMENT '部门ID';

-- 角色表
CREATE TABLE `role` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `name` VARCHAR(50) NOT NULL COMMENT '角色名称',
    `code` VARCHAR(50) NOT NULL COMMENT '角色编码'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户角色关联表
CREATE TABLE `user_role` (
    `user_id` BIGINT NOT NULL,
    `role_id` BIGINT NOT NULL,
    PRIMARY KEY (`user_id`, `role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

```java
// 部门实体
@Data
public class Department {
    private Long id;
    private String name;
    private Long parentId;
    private LocalDateTime createTime;
    private List<User> users;  // 一对多：部门下的用户
}

// 角色实体
@Data
public class Role {
    private Long id;
    private String name;
    private String code;
}

// 用户实体（扩展）
@Data
public class User {
    private Long id;
    private String username;
    private String password;
    private String email;
    private Long deptId;
    private Department department;  // 一对一：所属部门
    private List<Role> roles;       // 多对多：拥有的角色
}
```

### 7.2 一对一关联（association）

#### 方式一：嵌套结果映射（推荐）

一次查询，通过 JOIN 获取所有数据。

```xml
<resultMap id="UserWithDeptMap" type="User">
    <id column="id" property="id"/>
    <result column="username" property="username"/>
    <result column="email" property="email"/>
    <result column="dept_id" property="deptId"/>
    <!-- 一对一关联 -->
    <association property="department" javaType="Department">
        <id column="dept_id" property="id"/>
        <result column="dept_name" property="name"/>
    </association>
</resultMap>

<select id="selectUserWithDept" resultMap="UserWithDeptMap">
    SELECT 
        u.id, u.username, u.email, u.dept_id,
        d.name AS dept_name
    FROM user u
    LEFT JOIN department d ON u.dept_id = d.id
    WHERE u.id = #{id}
</select>
```

#### 方式二：嵌套查询（N+1 问题）

先查询主表，再根据外键查询关联表。

```xml
<resultMap id="UserWithDeptMap2" type="User">
    <id column="id" property="id"/>
    <result column="username" property="username"/>
    <result column="dept_id" property="deptId"/>
    <!-- 嵌套查询 -->
    <association property="department" 
                 column="dept_id" 
                 select="com.example.mapper.DepartmentMapper.selectById"/>
</resultMap>

<select id="selectUserWithDept2" resultMap="UserWithDeptMap2">
    SELECT id, username, dept_id FROM user WHERE id = #{id}
</select>
```

```xml
<!-- DepartmentMapper.xml -->
<select id="selectById" resultType="Department">
    SELECT * FROM department WHERE id = #{id}
</select>
```

### 7.3 一对多关联（collection）

#### 方式一：嵌套结果映射

```xml
<resultMap id="DeptWithUsersMap" type="Department">
    <id column="id" property="id"/>
    <result column="name" property="name"/>
    <!-- 一对多关联 -->
    <collection property="users" ofType="User">
        <id column="user_id" property="id"/>
        <result column="username" property="username"/>
        <result column="email" property="email"/>
    </collection>
</resultMap>

<select id="selectDeptWithUsers" resultMap="DeptWithUsersMap">
    SELECT 
        d.id, d.name,
        u.id AS user_id, u.username, u.email
    FROM department d
    LEFT JOIN user u ON d.id = u.dept_id
    WHERE d.id = #{id}
</select>
```

#### 方式二：嵌套查询

```xml
<resultMap id="DeptWithUsersMap2" type="Department">
    <id column="id" property="id"/>
    <result column="name" property="name"/>
    <collection property="users" 
                column="id" 
                select="com.example.mapper.UserMapper.selectByDeptId"/>
</resultMap>

<select id="selectDeptWithUsers2" resultMap="DeptWithUsersMap2">
    SELECT * FROM department WHERE id = #{id}
</select>
```

```xml
<!-- UserMapper.xml -->
<select id="selectByDeptId" resultType="User">
    SELECT * FROM user WHERE dept_id = #{deptId} AND deleted = 0
</select>
```

### 7.4 多对多关联

```xml
<resultMap id="UserWithRolesMap" type="User">
    <id column="id" property="id"/>
    <result column="username" property="username"/>
    <result column="email" property="email"/>
    <!-- 多对多关联 -->
    <collection property="roles" ofType="Role">
        <id column="role_id" property="id"/>
        <result column="role_name" property="name"/>
        <result column="role_code" property="code"/>
    </collection>
</resultMap>

<select id="selectUserWithRoles" resultMap="UserWithRolesMap">
    SELECT 
        u.id, u.username, u.email,
        r.id AS role_id, r.name AS role_name, r.code AS role_code
    FROM user u
    LEFT JOIN user_role ur ON u.id = ur.user_id
    LEFT JOIN role r ON ur.role_id = r.id
    WHERE u.id = #{id}
</select>
```

### 7.5 延迟加载

延迟加载可以在需要时才加载关联数据，减少不必要的查询。

```yaml
# 全局配置
mybatis:
  configuration:
    lazy-loading-enabled: true
    aggressive-lazy-loading: false
```

```xml
<!-- 单独配置 -->
<association property="department" 
             column="dept_id" 
             select="selectDeptById"
             fetchType="lazy"/>

<collection property="roles" 
            column="id" 
            select="selectRolesByUserId"
            fetchType="lazy"/>
```

**fetchType 取值：**
- `lazy`：延迟加载
- `eager`：立即加载

### 7.6 关联查询最佳实践

```java
/**
 * 复杂查询 DTO
 */
@Data
public class UserDetailDTO {
    private Long id;
    private String username;
    private String email;
    private String deptName;
    private List<String> roleNames;
}
```

```xml
<!-- 使用 DTO 接收复杂查询结果 -->
<resultMap id="UserDetailMap" type="UserDetailDTO">
    <id column="id" property="id"/>
    <result column="username" property="username"/>
    <result column="email" property="email"/>
    <result column="dept_name" property="deptName"/>
    <collection property="roleNames" ofType="String">
        <result column="role_name"/>
    </collection>
</resultMap>

<select id="selectUserDetail" resultMap="UserDetailMap">
    SELECT 
        u.id, u.username, u.email,
        d.name AS dept_name,
        r.name AS role_name
    FROM user u
    LEFT JOIN department d ON u.dept_id = d.id
    LEFT JOIN user_role ur ON u.id = ur.user_id
    LEFT JOIN role r ON ur.role_id = r.id
    WHERE u.id = #{id} AND u.deleted = 0
</select>
```


---

## 8. 注解开发

MyBatis 支持使用注解代替 XML 配置，适合简单的 CRUD 操作。

### 8.1 基础注解

```java
@Mapper
public interface UserMapper {
    
    // 查询
    @Select("SELECT * FROM user WHERE id = #{id}")
    User selectById(Long id);
    
    @Select("SELECT * FROM user WHERE deleted = 0")
    List<User> selectAll();
    
    // 插入
    @Insert("INSERT INTO user (username, password, email) VALUES (#{username}, #{password}, #{email})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(User user);
    
    // 更新
    @Update("UPDATE user SET username = #{username}, email = #{email} WHERE id = #{id}")
    int update(User user);
    
    // 删除
    @Delete("DELETE FROM user WHERE id = #{id}")
    int deleteById(Long id);
}
```

### 8.2 结果映射注解

```java
@Mapper
public interface UserMapper {
    
    // 使用 @Results 定义结果映射
    @Select("SELECT * FROM user WHERE id = #{id}")
    @Results(id = "userResultMap", value = {
        @Result(id = true, column = "id", property = "id"),
        @Result(column = "username", property = "username"),
        @Result(column = "create_time", property = "createTime")
    })
    User selectById(Long id);
    
    // 复用结果映射
    @Select("SELECT * FROM user WHERE username = #{username}")
    @ResultMap("userResultMap")
    User selectByUsername(String username);
}
```

### 8.3 动态 SQL 注解

```java
@Mapper
public interface UserMapper {
    
    // 使用 @SelectProvider 实现动态 SQL
    @SelectProvider(type = UserSqlProvider.class, method = "selectByCondition")
    List<User> selectByCondition(User user);
    
    @InsertProvider(type = UserSqlProvider.class, method = "insertSelective")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insertSelective(User user);
    
    @UpdateProvider(type = UserSqlProvider.class, method = "updateSelective")
    int updateSelective(User user);
}

/**
 * SQL 提供者类
 */
public class UserSqlProvider {
    
    public String selectByCondition(User user) {
        return new SQL() {{
            SELECT("*");
            FROM("user");
            WHERE("deleted = 0");
            if (user.getUsername() != null) {
                WHERE("username LIKE CONCAT('%', #{username}, '%')");
            }
            if (user.getEmail() != null) {
                WHERE("email = #{email}");
            }
            if (user.getStatus() != null) {
                WHERE("status = #{status}");
            }
        }}.toString();
    }
    
    public String insertSelective(User user) {
        return new SQL() {{
            INSERT_INTO("user");
            if (user.getUsername() != null) {
                VALUES("username", "#{username}");
            }
            if (user.getPassword() != null) {
                VALUES("password", "#{password}");
            }
            if (user.getEmail() != null) {
                VALUES("email", "#{email}");
            }
            if (user.getPhone() != null) {
                VALUES("phone", "#{phone}");
            }
        }}.toString();
    }
    
    public String updateSelective(User user) {
        return new SQL() {{
            UPDATE("user");
            if (user.getUsername() != null) {
                SET("username = #{username}");
            }
            if (user.getPassword() != null) {
                SET("password = #{password}");
            }
            if (user.getEmail() != null) {
                SET("email = #{email}");
            }
            WHERE("id = #{id}");
        }}.toString();
    }
}
```

### 8.4 关联查询注解

```java
@Mapper
public interface UserMapper {
    
    // 一对一关联
    @Select("SELECT * FROM user WHERE id = #{id}")
    @Results({
        @Result(id = true, column = "id", property = "id"),
        @Result(column = "username", property = "username"),
        @Result(column = "dept_id", property = "deptId"),
        @Result(column = "dept_id", property = "department",
                one = @One(select = "com.example.mapper.DepartmentMapper.selectById"))
    })
    User selectWithDept(Long id);
    
    // 一对多关联
    @Select("SELECT * FROM department WHERE id = #{id}")
    @Results({
        @Result(id = true, column = "id", property = "id"),
        @Result(column = "name", property = "name"),
        @Result(column = "id", property = "users",
                many = @Many(select = "com.example.mapper.UserMapper.selectByDeptId"))
    })
    Department selectDeptWithUsers(Long id);
}
```

### 8.5 注解 vs XML

| 特性 | 注解 | XML |
|------|------|-----|
| 简单 SQL | 推荐 | 可以 |
| 复杂 SQL | 不推荐 | 推荐 |
| 动态 SQL | 较复杂 | 简单 |
| 可维护性 | 一般 | 好 |
| 重构支持 | 好 | 一般 |

**建议：** 简单的 CRUD 使用注解，复杂的查询使用 XML。

---

## 9. 缓存机制

MyBatis 提供了两级缓存机制，可以有效减少数据库访问次数。

### 9.1 一级缓存（本地缓存）

一级缓存是 SqlSession 级别的缓存，默认开启。

**特点：**
- 同一个 SqlSession 中，相同的查询会使用缓存
- 执行增删改操作后，缓存会被清空
- SqlSession 关闭后，缓存失效

```java
@Test
public void testFirstLevelCache() {
    SqlSession sqlSession = sqlSessionFactory.openSession();
    UserMapper mapper = sqlSession.getMapper(UserMapper.class);
    
    // 第一次查询，访问数据库
    User user1 = mapper.selectById(1L);
    
    // 第二次查询，使用缓存
    User user2 = mapper.selectById(1L);
    
    System.out.println(user1 == user2);  // true
    
    sqlSession.close();
}
```

**一级缓存失效的情况：**
1. 不同的 SqlSession
2. 查询条件不同
3. 两次查询之间执行了增删改操作
4. 手动清空缓存：`sqlSession.clearCache()`

### 9.2 二级缓存（全局缓存）

二级缓存是 Mapper 级别的缓存，需要手动开启。

**开启二级缓存：**

```yaml
# 全局开启
mybatis:
  configuration:
    cache-enabled: true
```

```xml
<!-- Mapper.xml 中开启 -->
<mapper namespace="com.example.mapper.UserMapper">
    <!-- 开启二级缓存 -->
    <cache/>
    
    <!-- 或自定义配置 -->
    <cache
        eviction="LRU"
        flushInterval="60000"
        size="512"
        readOnly="true"/>
</mapper>
```

**cache 标签属性：**
- `eviction`：缓存回收策略（LRU、FIFO、SOFT、WEAK）
- `flushInterval`：刷新间隔（毫秒）
- `size`：缓存数量
- `readOnly`：是否只读

**注意：** 使用二级缓存的实体类必须实现 Serializable 接口。

```java
@Data
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    // ...
}
```

### 9.3 自定义缓存

可以使用第三方缓存（如 Redis）作为二级缓存。

```xml
<dependency>
    <groupId>org.mybatis.caches</groupId>
    <artifactId>mybatis-redis</artifactId>
    <version>1.0.0-beta2</version>
</dependency>
```

```xml
<cache type="org.mybatis.caches.redis.RedisCache"/>
```

### 9.4 缓存使用建议

1. **一级缓存**：默认开启，一般不需要配置
2. **二级缓存**：
   - 适合读多写少的场景
   - 不适合频繁更新的数据
   - 分布式环境下建议使用 Redis 等分布式缓存
3. **查询缓存**：可以在 select 标签上配置 `useCache="false"` 禁用缓存
4. **刷新缓存**：可以在增删改标签上配置 `flushCache="true"` 刷新缓存

```xml
<!-- 禁用缓存 -->
<select id="selectById" resultType="User" useCache="false">
    SELECT * FROM user WHERE id = #{id}
</select>

<!-- 刷新缓存 -->
<update id="update" flushCache="true">
    UPDATE user SET username = #{username} WHERE id = #{id}
</update>
```


---

## 10. 分页查询

### 10.1 手动分页

```java
// Mapper 接口
List<User> selectPage(@Param("offset") int offset, @Param("limit") int limit);
```

```xml
<select id="selectPage" resultType="User">
    SELECT * FROM user WHERE deleted = 0
    ORDER BY create_time DESC
    LIMIT #{offset}, #{limit}
</select>
```

### 10.2 PageHelper 分页插件（推荐）

PageHelper 是 MyBatis 最常用的分页插件。

**添加依赖：**

```xml
<dependency>
    <groupId>com.github.pagehelper</groupId>
    <artifactId>pagehelper-spring-boot-starter</artifactId>
    <version>1.4.6</version>
</dependency>
```

**配置：**

```yaml
pagehelper:
  helper-dialect: mysql
  reasonable: true
  support-methods-arguments: true
  params: count=countSql
```

**使用方式：**

```java
@Service
public class UserServiceImpl implements UserService {
    
    @Autowired
    private UserMapper userMapper;
    
    /**
     * 分页查询
     */
    public PageInfo<User> getPage(int pageNum, int pageSize) {
        // 开启分页（必须紧跟查询语句）
        PageHelper.startPage(pageNum, pageSize);
        
        // 执行查询
        List<User> users = userMapper.selectAll();
        
        // 封装分页结果
        return new PageInfo<>(users);
    }
    
    /**
     * 带条件的分页查询
     */
    public PageInfo<User> getPageByCondition(int pageNum, int pageSize, User condition) {
        PageHelper.startPage(pageNum, pageSize);
        List<User> users = userMapper.selectByCondition(condition);
        return new PageInfo<>(users);
    }
    
    /**
     * 分页并排序
     */
    public PageInfo<User> getPageWithSort(int pageNum, int pageSize, String orderBy) {
        PageHelper.startPage(pageNum, pageSize, orderBy);
        List<User> users = userMapper.selectAll();
        return new PageInfo<>(users);
    }
}
```

**PageInfo 常用属性：**

```java
PageInfo<User> pageInfo = new PageInfo<>(users);

pageInfo.getPageNum();      // 当前页码
pageInfo.getPageSize();     // 每页数量
pageInfo.getTotal();        // 总记录数
pageInfo.getPages();        // 总页数
pageInfo.getList();         // 当前页数据
pageInfo.isHasNextPage();   // 是否有下一页
pageInfo.isHasPreviousPage(); // 是否有上一页
pageInfo.getPrePage();      // 上一页页码
pageInfo.getNextPage();     // 下一页页码
```

**Controller 示例：**

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @GetMapping("/page")
    public Result<PageInfo<User>> getPage(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize) {
        PageInfo<User> pageInfo = userService.getPage(pageNum, pageSize);
        return Result.success(pageInfo);
    }
}
```

### 10.3 分页注意事项

```java
// ❌ 错误：PageHelper.startPage 和查询之间有其他操作
PageHelper.startPage(1, 10);
User user = userMapper.selectById(1L);  // 这个查询会被分页
List<User> users = userMapper.selectAll();  // 这个查询不会被分页

// ✅ 正确：PageHelper.startPage 紧跟查询语句
PageHelper.startPage(1, 10);
List<User> users = userMapper.selectAll();

// ✅ 使用 try-finally 确保分页被清理
try {
    PageHelper.startPage(1, 10);
    return userMapper.selectAll();
} finally {
    PageHelper.clearPage();
}
```

---

## 11. 批量操作

### 11.1 批量插入

```xml
<!-- 方式一：foreach -->
<insert id="insertBatch">
    INSERT INTO user (username, password, email, phone)
    VALUES
    <foreach collection="users" item="user" separator=",">
        (#{user.username}, #{user.password}, #{user.email}, #{user.phone})
    </foreach>
</insert>
```

```java
// 方式二：使用 SqlSession 的 BATCH 模式
@Service
public class UserServiceImpl {
    
    @Autowired
    private SqlSessionFactory sqlSessionFactory;
    
    public void batchInsert(List<User> users) {
        try (SqlSession sqlSession = sqlSessionFactory.openSession(ExecutorType.BATCH)) {
            UserMapper mapper = sqlSession.getMapper(UserMapper.class);
            
            for (int i = 0; i < users.size(); i++) {
                mapper.insert(users.get(i));
                
                // 每 500 条提交一次
                if ((i + 1) % 500 == 0) {
                    sqlSession.flushStatements();
                }
            }
            
            sqlSession.flushStatements();
            sqlSession.commit();
        }
    }
}
```

### 11.2 批量更新

```xml
<!-- 方式一：foreach + CASE WHEN -->
<update id="updateBatch">
    UPDATE user
    SET 
        username = CASE id
            <foreach collection="users" item="user">
                WHEN #{user.id} THEN #{user.username}
            </foreach>
        END,
        email = CASE id
            <foreach collection="users" item="user">
                WHEN #{user.id} THEN #{user.email}
            </foreach>
        END
    WHERE id IN
    <foreach collection="users" item="user" open="(" separator="," close=")">
        #{user.id}
    </foreach>
</update>

<!-- 方式二：多条 UPDATE 语句（需要开启 allowMultiQueries） -->
<update id="updateBatch2">
    <foreach collection="users" item="user" separator=";">
        UPDATE user
        SET username = #{user.username},
            email = #{user.email}
        WHERE id = #{user.id}
    </foreach>
</update>
```

```yaml
# 开启多语句执行
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mydb?allowMultiQueries=true
```

### 11.3 批量删除

```xml
<delete id="deleteBatch">
    DELETE FROM user WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</delete>

<!-- 逻辑删除 -->
<update id="deleteBatchLogic">
    UPDATE user SET deleted = 1 WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</update>
```

### 11.4 批量操作性能对比

| 方式 | 性能 | 适用场景 |
|------|------|----------|
| foreach 拼接 | 中等 | 数据量小（< 1000） |
| BATCH 模式 | 高 | 数据量大 |
| 多条语句 | 低 | 不推荐 |

---

## 12. 插件机制

MyBatis 允许在执行过程中拦截某些方法调用，实现自定义功能。

### 12.1 插件原理

MyBatis 允许拦截的方法：
- `Executor`：执行器（update、query、commit、rollback）
- `StatementHandler`：SQL 语句处理器
- `ParameterHandler`：参数处理器
- `ResultSetHandler`：结果集处理器

### 12.2 自定义插件

```java
/**
 * SQL 执行时间统计插件
 */
@Intercepts({
    @Signature(type = StatementHandler.class, method = "query", args = {Statement.class, ResultHandler.class}),
    @Signature(type = StatementHandler.class, method = "update", args = {Statement.class})
})
@Component
@Slf4j
public class SqlExecuteTimePlugin implements Interceptor {
    
    /**
     * 慢 SQL 阈值（毫秒）
     */
    private static final long SLOW_SQL_THRESHOLD = 1000;
    
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        long startTime = System.currentTimeMillis();
        
        try {
            return invocation.proceed();
        } finally {
            long endTime = System.currentTimeMillis();
            long executeTime = endTime - startTime;
            
            if (executeTime > SLOW_SQL_THRESHOLD) {
                StatementHandler handler = (StatementHandler) invocation.getTarget();
                BoundSql boundSql = handler.getBoundSql();
                String sql = boundSql.getSql().replaceAll("\\s+", " ");
                
                log.warn("慢 SQL 警告！执行时间: {}ms, SQL: {}", executeTime, sql);
            }
        }
    }
    
    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }
    
    @Override
    public void setProperties(Properties properties) {
        // 可以从配置中读取属性
    }
}
```

### 12.3 数据权限插件

```java
/**
 * 数据权限插件
 * 自动在查询语句中添加数据权限条件
 */
@Intercepts({
    @Signature(type = StatementHandler.class, method = "prepare", args = {Connection.class, Integer.class})
})
@Component
@Slf4j
public class DataPermissionPlugin implements Interceptor {
    
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        StatementHandler handler = (StatementHandler) invocation.getTarget();
        
        // 获取原始 SQL
        MetaObject metaObject = SystemMetaObject.forObject(handler);
        MappedStatement mappedStatement = (MappedStatement) metaObject.getValue("delegate.mappedStatement");
        
        // 只处理 SELECT 语句
        if (mappedStatement.getSqlCommandType() != SqlCommandType.SELECT) {
            return invocation.proceed();
        }
        
        BoundSql boundSql = handler.getBoundSql();
        String originalSql = boundSql.getSql();
        
        // 获取当前用户的数据权限
        Long deptId = getCurrentUserDeptId();
        if (deptId != null) {
            // 添加数据权限条件
            String newSql = addDataPermission(originalSql, deptId);
            metaObject.setValue("delegate.boundSql.sql", newSql);
        }
        
        return invocation.proceed();
    }
    
    private Long getCurrentUserDeptId() {
        // 从 SecurityContext 获取当前用户的部门ID
        return 1L;
    }
    
    private String addDataPermission(String sql, Long deptId) {
        // 简单实现：在 WHERE 后添加条件
        // 实际项目中需要更复杂的 SQL 解析
        if (sql.toLowerCase().contains("where")) {
            return sql + " AND dept_id = " + deptId;
        } else {
            return sql + " WHERE dept_id = " + deptId;
        }
    }
    
    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }
    
    @Override
    public void setProperties(Properties properties) {
    }
}
```

### 12.4 自动填充插件

```java
/**
 * 自动填充创建时间和更新时间
 */
@Intercepts({
    @Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class})
})
@Component
public class AutoFillPlugin implements Interceptor {
    
    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        MappedStatement ms = (MappedStatement) invocation.getArgs()[0];
        Object parameter = invocation.getArgs()[1];
        
        if (parameter == null) {
            return invocation.proceed();
        }
        
        SqlCommandType sqlCommandType = ms.getSqlCommandType();
        
        if (sqlCommandType == SqlCommandType.INSERT) {
            // 插入时填充创建时间和更新时间
            setFieldValue(parameter, "createTime", LocalDateTime.now());
            setFieldValue(parameter, "updateTime", LocalDateTime.now());
        } else if (sqlCommandType == SqlCommandType.UPDATE) {
            // 更新时填充更新时间
            setFieldValue(parameter, "updateTime", LocalDateTime.now());
        }
        
        return invocation.proceed();
    }
    
    private void setFieldValue(Object obj, String fieldName, Object value) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            if (field.get(obj) == null) {
                field.set(obj, value);
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            // 字段不存在，忽略
        }
    }
    
    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }
    
    @Override
    public void setProperties(Properties properties) {
    }
}
```


---

## 13. 代码生成器

### 13.1 MyBatis Generator

MyBatis Generator（MBG）是 MyBatis 官方的代码生成工具。

**添加依赖：**

```xml
<plugin>
    <groupId>org.mybatis.generator</groupId>
    <artifactId>mybatis-generator-maven-plugin</artifactId>
    <version>1.4.1</version>
    <configuration>
        <configurationFile>src/main/resources/generatorConfig.xml</configurationFile>
        <overwrite>true</overwrite>
        <verbose>true</verbose>
    </configuration>
    <dependencies>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.33</version>
        </dependency>
    </dependencies>
</plugin>
```

**配置文件 generatorConfig.xml：**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE generatorConfiguration
        PUBLIC "-//mybatis.org//DTD MyBatis Generator Configuration 1.0//EN"
        "http://mybatis.org/dtd/mybatis-generator-config_1_0.dtd">

<generatorConfiguration>
    <context id="MySqlContext" targetRuntime="MyBatis3" defaultModelType="flat">
        
        <!-- 生成的代码不带注释 -->
        <commentGenerator>
            <property name="suppressAllComments" value="true"/>
            <property name="suppressDate" value="true"/>
        </commentGenerator>
        
        <!-- 数据库连接 -->
        <jdbcConnection driverClass="com.mysql.cj.jdbc.Driver"
                        connectionURL="jdbc:mysql://localhost:3306/mydb?useSSL=false&amp;serverTimezone=Asia/Shanghai"
                        userId="root"
                        password="root"/>
        
        <!-- 类型转换 -->
        <javaTypeResolver>
            <property name="forceBigDecimals" value="false"/>
        </javaTypeResolver>
        
        <!-- 实体类生成配置 -->
        <javaModelGenerator targetPackage="com.example.entity" targetProject="src/main/java">
            <property name="enableSubPackages" value="true"/>
            <property name="trimStrings" value="true"/>
        </javaModelGenerator>
        
        <!-- Mapper XML 生成配置 -->
        <sqlMapGenerator targetPackage="mapper" targetProject="src/main/resources">
            <property name="enableSubPackages" value="true"/>
        </sqlMapGenerator>
        
        <!-- Mapper 接口生成配置 -->
        <javaClientGenerator type="XMLMAPPER" targetPackage="com.example.mapper" targetProject="src/main/java">
            <property name="enableSubPackages" value="true"/>
        </javaClientGenerator>
        
        <!-- 表配置 -->
        <table tableName="user" domainObjectName="User">
            <generatedKey column="id" sqlStatement="MySql" identity="true"/>
        </table>
        
        <table tableName="department" domainObjectName="Department">
            <generatedKey column="id" sqlStatement="MySql" identity="true"/>
        </table>
        
    </context>
</generatorConfiguration>
```

**执行生成：**

```bash
mvn mybatis-generator:generate
```

### 13.2 MyBatis-Plus Generator

MyBatis-Plus 提供了更强大的代码生成器。

```xml
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-generator</artifactId>
    <version>3.5.3.1</version>
</dependency>
<dependency>
    <groupId>org.freemarker</groupId>
    <artifactId>freemarker</artifactId>
    <version>2.3.31</version>
</dependency>
```

```java
public class CodeGenerator {
    
    public static void main(String[] args) {
        FastAutoGenerator.create("jdbc:mysql://localhost:3306/mydb", "root", "root")
                .globalConfig(builder -> {
                    builder.author("Your Name")
                            .outputDir(System.getProperty("user.dir") + "/src/main/java")
                            .commentDate("yyyy-MM-dd");
                })
                .packageConfig(builder -> {
                    builder.parent("com.example")
                            .entity("entity")
                            .mapper("mapper")
                            .service("service")
                            .serviceImpl("service.impl")
                            .controller("controller")
                            .xml("mapper");
                })
                .strategyConfig(builder -> {
                    builder.addInclude("user", "department", "role")
                            .entityBuilder()
                            .enableLombok()
                            .enableTableFieldAnnotation()
                            .logicDeleteColumnName("deleted")
                            .mapperBuilder()
                            .enableBaseResultMap()
                            .enableBaseColumnList();
                })
                .templateEngine(new FreemarkerTemplateEngine())
                .execute();
    }
}
```

---

## 14. 常见错误与解决方案

### 14.1 Mapper 接口找不到

**错误信息：**
```
org.apache.ibatis.binding.BindingException: Invalid bound statement (not found)
```

**原因：**
1. Mapper XML 文件位置不正确
2. namespace 与 Mapper 接口不匹配
3. 方法名不匹配

**解决方案：**

```yaml
# 检查 mapper-locations 配置
mybatis:
  mapper-locations: classpath:mapper/*.xml
```

```xml
<!-- 检查 namespace -->
<mapper namespace="com.example.mapper.UserMapper">
    <!-- 方法名必须与接口方法名一致 -->
    <select id="selectById" resultType="User">
        SELECT * FROM user WHERE id = #{id}
    </select>
</mapper>
```

### 14.2 参数绑定错误

**错误信息：**
```
org.apache.ibatis.binding.BindingException: Parameter 'xxx' not found
```

**原因：** 多个参数时没有使用 @Param 注解

**解决方案：**

```java
// ❌ 错误
User selectByUsernameAndPassword(String username, String password);

// ✅ 正确
User selectByUsernameAndPassword(@Param("username") String username, 
                                  @Param("password") String password);
```

### 14.3 类型转换错误

**错误信息：**
```
org.apache.ibatis.type.TypeException: Could not set parameters for mapping
```

**原因：** Java 类型与数据库类型不匹配

**解决方案：**

```xml
<!-- 指定 jdbcType -->
<insert id="insert">
    INSERT INTO user (username, email, create_time)
    VALUES (#{username}, #{email, jdbcType=VARCHAR}, #{createTime, jdbcType=TIMESTAMP})
</insert>
```

### 14.4 结果映射错误

**错误信息：**
```
org.apache.ibatis.executor.result.ResultMapException: Error attempting to get column 'xxx'
```

**原因：** 列名与属性名不匹配

**解决方案：**

```yaml
# 开启驼峰命名转换
mybatis:
  configuration:
    map-underscore-to-camel-case: true
```

```xml
<!-- 或使用 resultMap -->
<resultMap id="UserMap" type="User">
    <result column="create_time" property="createTime"/>
</resultMap>
```

### 14.5 空指针异常

**错误信息：**
```
java.lang.NullPointerException
```

**原因：** 查询结果为 null，但代码没有处理

**解决方案：**

```java
// 使用 Optional
Optional<User> selectById(Long id);

// 或在代码中判断
User user = userMapper.selectById(id);
if (user == null) {
    throw new BusinessException("用户不存在");
}
```

### 14.6 SQL 注入

**错误示例：**

```xml
<!-- ❌ 危险：使用 ${} 拼接用户输入 -->
<select id="selectByUsername" resultType="User">
    SELECT * FROM user WHERE username = '${username}'
</select>
```

**解决方案：**

```xml
<!-- ✅ 安全：使用 #{} -->
<select id="selectByUsername" resultType="User">
    SELECT * FROM user WHERE username = #{username}
</select>
```

### 14.7 事务不生效

**原因：**
1. 方法不是 public
2. 同类方法调用
3. 异常被捕获

**解决方案：**

```java
@Service
public class UserServiceImpl {
    
    // ✅ 方法必须是 public
    @Transactional(rollbackFor = Exception.class)
    public void createUser(User user) {
        userMapper.insert(user);
        // 不要捕获异常，让事务回滚
    }
    
    // ❌ 同类方法调用，事务不生效
    public void batchCreate(List<User> users) {
        for (User user : users) {
            createUser(user);  // 事务不生效
        }
    }
    
    // ✅ 正确做法：注入自己或使用 AopContext
    @Autowired
    private UserServiceImpl self;
    
    public void batchCreate2(List<User> users) {
        for (User user : users) {
            self.createUser(user);  // 事务生效
        }
    }
}
```

### 14.8 N+1 查询问题

**问题：** 关联查询时，每条主记录都会触发一次关联查询

**解决方案：**

```xml
<!-- ❌ N+1 问题 -->
<resultMap id="UserMap" type="User">
    <association property="department" column="dept_id" 
                 select="selectDeptById"/>
</resultMap>

<!-- ✅ 使用 JOIN 一次查询 -->
<resultMap id="UserMap" type="User">
    <association property="department" javaType="Department">
        <id column="dept_id" property="id"/>
        <result column="dept_name" property="name"/>
    </association>
</resultMap>

<select id="selectWithDept" resultMap="UserMap">
    SELECT u.*, d.name AS dept_name
    FROM user u
    LEFT JOIN department d ON u.dept_id = d.id
</select>
```

### 14.9 批量操作超时

**原因：** 批量数据量过大

**解决方案：**

```java
// 分批处理
public void batchInsert(List<User> users) {
    int batchSize = 500;
    for (int i = 0; i < users.size(); i += batchSize) {
        int end = Math.min(i + batchSize, users.size());
        List<User> batch = users.subList(i, end);
        userMapper.insertBatch(batch);
    }
}
```

### 14.10 缓存脏数据

**原因：** 多个应用共享数据库，但缓存不同步

**解决方案：**

```xml
<!-- 禁用二级缓存 -->
<select id="selectById" resultType="User" useCache="false">
    SELECT * FROM user WHERE id = #{id}
</select>

<!-- 或使用分布式缓存 -->
<cache type="org.mybatis.caches.redis.RedisCache"/>
```


---

## 15. 最佳实践

### 15.1 项目结构规范

```
src/main/java/com/example/
├── config/
│   └── MyBatisConfig.java        # MyBatis 配置
├── entity/
│   ├── User.java                 # 实体类
│   └── dto/
│       └── UserDTO.java          # 数据传输对象
├── mapper/
│   └── UserMapper.java           # Mapper 接口
├── service/
│   ├── UserService.java          # 服务接口
│   └── impl/
│       └── UserServiceImpl.java  # 服务实现
└── controller/
    └── UserController.java       # 控制器

src/main/resources/
├── application.yml               # 配置文件
└── mapper/
    └── UserMapper.xml            # Mapper XML
```

### 15.2 命名规范

```java
// 实体类：与表名对应，使用大驼峰
public class User {}
public class UserRole {}

// Mapper 接口：实体类名 + Mapper
public interface UserMapper {}

// Mapper XML：与 Mapper 接口同名
// UserMapper.xml

// 方法命名规范
selectById()           // 根据ID查询
selectByUsername()     // 根据条件查询
selectList()           // 查询列表
selectPage()           // 分页查询
selectCount()          // 查询数量
insert()               // 插入
insertBatch()          // 批量插入
update()               // 更新
updateSelective()      // 选择性更新
deleteById()           // 根据ID删除
deleteBatch()          // 批量删除
```

### 15.3 通用 Mapper 基类

```java
/**
 * 通用 Mapper 基类
 */
public interface BaseMapper<T> {
    
    /**
     * 根据ID查询
     */
    T selectById(Long id);
    
    /**
     * 查询所有
     */
    List<T> selectAll();
    
    /**
     * 根据条件查询
     */
    List<T> selectByCondition(T condition);
    
    /**
     * 插入
     */
    int insert(T entity);
    
    /**
     * 选择性插入
     */
    int insertSelective(T entity);
    
    /**
     * 更新
     */
    int update(T entity);
    
    /**
     * 选择性更新
     */
    int updateSelective(T entity);
    
    /**
     * 根据ID删除
     */
    int deleteById(Long id);
    
    /**
     * 批量删除
     */
    int deleteBatch(@Param("ids") List<Long> ids);
}

/**
 * 用户 Mapper
 */
@Mapper
public interface UserMapper extends BaseMapper<User> {
    
    /**
     * 根据用户名查询
     */
    User selectByUsername(String username);
    
    /**
     * 其他自定义方法...
     */
}
```

### 15.4 通用 Service 基类

```java
/**
 * 通用 Service 接口
 */
public interface BaseService<T> {
    
    T getById(Long id);
    
    List<T> getAll();
    
    List<T> getByCondition(T condition);
    
    boolean save(T entity);
    
    boolean update(T entity);
    
    boolean deleteById(Long id);
    
    boolean deleteBatch(List<Long> ids);
}

/**
 * 通用 Service 实现
 */
public abstract class BaseServiceImpl<M extends BaseMapper<T>, T> implements BaseService<T> {
    
    @Autowired
    protected M baseMapper;
    
    @Override
    public T getById(Long id) {
        return baseMapper.selectById(id);
    }
    
    @Override
    public List<T> getAll() {
        return baseMapper.selectAll();
    }
    
    @Override
    public List<T> getByCondition(T condition) {
        return baseMapper.selectByCondition(condition);
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean save(T entity) {
        return baseMapper.insert(entity) > 0;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean update(T entity) {
        return baseMapper.updateSelective(entity) > 0;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean deleteById(Long id) {
        return baseMapper.deleteById(id) > 0;
    }
    
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean deleteBatch(List<Long> ids) {
        return baseMapper.deleteBatch(ids) > 0;
    }
}

/**
 * 用户 Service 实现
 */
@Service
public class UserServiceImpl extends BaseServiceImpl<UserMapper, User> implements UserService {
    
    @Override
    public User getByUsername(String username) {
        return baseMapper.selectByUsername(username);
    }
}
```

### 15.5 SQL 编写规范

```xml
<!-- 1. 使用 sql 片段复用代码 -->
<sql id="Base_Column_List">
    id, username, password, email, phone, status, create_time, update_time, deleted
</sql>

<!-- 2. 查询时指定需要的列，避免 SELECT * -->
<select id="selectById" resultMap="BaseResultMap">
    SELECT <include refid="Base_Column_List"/>
    FROM user
    WHERE id = #{id} AND deleted = 0
</select>

<!-- 3. 使用 WHERE 1=1 或 <where> 标签处理动态条件 -->
<select id="selectByCondition" resultMap="BaseResultMap">
    SELECT <include refid="Base_Column_List"/>
    FROM user
    <where>
        <if test="username != null and username != ''">
            AND username LIKE CONCAT('%', #{username}, '%')
        </if>
        <if test="status != null">
            AND status = #{status}
        </if>
        AND deleted = 0
    </where>
    ORDER BY create_time DESC
</select>

<!-- 4. 更新时使用 <set> 标签 -->
<update id="updateSelective">
    UPDATE user
    <set>
        <if test="username != null">username = #{username},</if>
        <if test="email != null">email = #{email},</if>
        update_time = NOW()
    </set>
    WHERE id = #{id}
</update>

<!-- 5. 批量操作使用 foreach -->
<insert id="insertBatch">
    INSERT INTO user (username, password, email)
    VALUES
    <foreach collection="list" item="item" separator=",">
        (#{item.username}, #{item.password}, #{item.email})
    </foreach>
</insert>
```

### 15.6 性能优化建议

```java
/**
 * 1. 使用分页查询，避免一次查询大量数据
 */
public PageInfo<User> getPage(int pageNum, int pageSize) {
    PageHelper.startPage(pageNum, pageSize);
    return new PageInfo<>(userMapper.selectAll());
}

/**
 * 2. 批量操作分批处理
 */
public void batchInsert(List<User> users) {
    int batchSize = 500;
    for (int i = 0; i < users.size(); i += batchSize) {
        int end = Math.min(i + batchSize, users.size());
        userMapper.insertBatch(users.subList(i, end));
    }
}

/**
 * 3. 使用索引优化查询
 */
// 确保 WHERE 条件中的字段有索引

/**
 * 4. 避免 N+1 查询
 */
// 使用 JOIN 代替嵌套查询

/**
 * 5. 合理使用缓存
 */
// 读多写少的数据使用二级缓存
```

### 15.7 安全建议

```java
/**
 * 1. 使用 #{} 而不是 ${}
 */
// #{} 会进行预编译，防止 SQL 注入

/**
 * 2. 对动态表名、列名进行白名单校验
 */
public List<User> selectWithOrder(String orderColumn) {
    List<String> allowedColumns = Arrays.asList("id", "username", "create_time");
    if (!allowedColumns.contains(orderColumn)) {
        throw new IllegalArgumentException("非法的排序字段");
    }
    return userMapper.selectWithOrder(orderColumn);
}

/**
 * 3. 敏感数据加密存储
 */
// 密码使用 BCrypt 加密
// 手机号、身份证等使用 AES 加密

/**
 * 4. 日志脱敏
 */
// 不要在日志中打印敏感信息
```

---

## 总结

MyBatis 是一款优秀的持久层框架，通过本笔记的学习，你应该能够：

1. **掌握基础**：理解 MyBatis 的核心概念和工作原理
2. **熟练配置**：能够在 Spring Boot 项目中正确配置 MyBatis
3. **CRUD 操作**：熟练编写增删改查的 Mapper 和 XML
4. **参数处理**：理解 #{} 和 ${} 的区别，正确处理各种参数
5. **结果映射**：掌握 resultMap 的使用，处理复杂的结果映射
6. **动态 SQL**：熟练使用 if、where、set、foreach 等标签
7. **关联查询**：掌握一对一、一对多、多对多的关联映射
8. **缓存机制**：理解一级缓存和二级缓存的原理和使用
9. **分页查询**：使用 PageHelper 实现分页
10. **批量操作**：掌握批量插入、更新、删除的最佳实践
11. **插件开发**：了解 MyBatis 插件机制，能够开发自定义插件
12. **问题排查**：能够识别和解决常见的 MyBatis 问题

**推荐资源：**
- [MyBatis 官方文档](https://mybatis.org/mybatis-3/zh/index.html)
- [MyBatis-Spring 文档](https://mybatis.org/spring/zh/index.html)
- [MyBatis-Plus 文档](https://baomidou.com/)
- [PageHelper 文档](https://pagehelper.github.io/)