## 1. 简介

本博客将详细介绍在IDEA中，如何整合SpringBoot与SpringData JPA，以实现数据库的增删改查操作。我将逐步从环境搭建到实际代码实现的完整流程，帮助读者更好地理解并掌握这一技术栈。

JPA是Java Persistence API的缩写，它定义了Java对象如何映射到关系型数据库中的表，以及如何使用面向对象的方式来查询这些表。JPA是Java EE 5规范的一部分，并由EJB 3.0（Enterprise JavaBeans）实现。

## 2. 创建SpringBoot项目

首先，我们需要创建SpringBoot项目。在创建SpringBoot项目时，可以选择使用Spring Initializr来快速生成项目结构。
### [[SpringBoot2]]

## 3. [Maven依赖](https://so.csdn.net/so/search?q=Maven%E4%BE%9D%E8%B5%96&spm=1001.2101.3001.7020 "Maven依赖")引入

首先，你需要在你的`pom.xml`文件中添加Spring Boot和SpringData JPA的依赖，对于Maven，添加以下依赖：

![](https://i-blog.csdnimg.cn/blog_migrate/86a9a468805a46e2721d7ea00eeaaab4.png)

```XML
        <!-- jpa 依赖-->        <dependency>            <groupId>org.springframework.boot</groupId>            <artifactId>spring-boot-starter-data-jpa</artifactId>        </dependency>         <!-- lombok依赖 为了简化实体类的编写代码量 -->        <dependency>            <groupId>org.projectlombok</groupId>            <artifactId>lombok</artifactId>            <optional>true</optional>        </dependency>        <!-- 数据库连接驱动，这里以MySQL为例 -->        <dependency>            <groupId>mysql</groupId>            <artifactId>mysql-connector-java</artifactId>        </dependency>
```

## 4. 修改application.properties配置文件

在resources目录下新建application.properties文件，用于存放[数据库连接](https://so.csdn.net/so/search?q=%E6%95%B0%E6%8D%AE%E5%BA%93%E8%BF%9E%E6%8E%A5&spm=1001.2101.3001.7020 "数据库连接")需要的一些配置数据（一般在新建Springboot项目都会自动生成该文件），也可以新建application.yml文件，不过格式得转换，配置文件如下：

![](https://i-blog.csdnimg.cn/blog_migrate/f4c56d96157151d25782da3589b90b6b.png)

```java
# 应用服务 WEB 访问端口server.port=8080 # MySQLspring.datasource.url=jdbc:mysql://localhost:3306/tic?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=truespring.datasource.username=rootspring.datasource.password=123456spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver # JPAspring.jpa.show-sql=truespring.jpa.database-platform=org.hibernate.dialect.MySQL5InnoDBDialectspring.jpa.hibernate.ddl-auto=create
```

此处作者以properties文件进行讲解：

- **spring.datasource.url：**这是Spring Boot中配置数据源URL的属性。

> **jdbc：**mysql: 表示使用的是MySQL数据库的JDBC连接。
> 
> **localhost：**数据库服务器的主机名，这里表示数据库服务器运行在本机上。
> 
> **3306：**MySQL数据库的默认端口号。
> 
> **/tic：**连接的数据库名，为了演示，我本地创建了个叫tic的数据库，可自行建库进行配置。
> 
> **?useSSL=false&serverTimezone=UTC：**这部分是连接参数的附加设置。

- **spring.datasource.username：**这是Spring Boot中配置数据库连接的用户名的属性，根据个人创建的用户设置。
- **spring.datasource.password：**这是Spring Boot中配置数据库连接密码的属性，根据个人创建的用户设置。
- **spring.datasource.driver-class-name：**这是Spring Boot中配置数据库驱动类名的属性。

> **com.mysql.cj.jdbc.Driver：**是MySQL Connector/J 8.0及以上版本的JDBC驱动类名。使用这个驱动类，可以确保你的Spring Boot应用程序能够连接到MySQL数据库。
> 
> 如果你选择的是 MySQL Connector/J 8.0 以下版本中（如：MySQL Connector/J 5.7），JDBC 驱动类名通常是 com.mysql.jdbc.Driver

- **spring.jpa.show-sql：**用于在控制台输出由 JPA（Java Persistence API）生成的 SQL 语句。这在你需要调试或查看实际执行的 SQL 语句时非常有用，默认false。 
- **spring.jpa.database-platform：**用于配置数据库平台的具体名称，它告诉Spring Boot如何将JPA映射语言（如Hibernate）与特定的数据库系统相匹配。

> 本文使用MySQL，因此设置为org.hibernate.dialect.MySQL5InnoDBDialect，如你正在使用PostgreSQL数据库，则设置为org.hibernate.dialect.PostgreSQLDialect，或者使用Oracle，则设置为org.hibernate.dialect.Oracle10gDialect等。

- **spring.jpa.hibernate.ddl-auto：**是 Spring Boot 中用于配置 Hibernate 自动处理数据库模式（DDL，即数据定义语言）的一个属性。这个属性决定了 Hibernate 是否以及如何自动更新数据库模式以匹配实体类。

> 具体来说，ddl-auto 属性可以有以下几个值：
> 
> **none：**Hibernate 不会做任何数据库模式的更新或验证。  
> **validate：**Hibernate 会在启动时验证数据库模式是否与实体类匹配，但不会进行任何更新。  
> **update：**Hibernate 会在启动时检查数据库模式是否与实体类匹配，如果不匹配，它会更新数据库模式。请注意，这通常只适用于开发环境，因为更新模式可能会导致数据丢失。  
> **create：**Hibernate 会在启动时创建数据库模式，如果模式已经存在，它会被删除并重新创建。这同样只适用于开发环境。  
> **create-drop：**Hibernate 会在启动时创建数据库模式，并在应用程序关闭时删除它。这通常用于集成测试。
> 
> **注意：**
> 
> - update 模式不会自动创建数据库或模式（schema）。它只会更新现有的模式以匹配实体类。
> - 使用 update 或 create 模式在生产环境中是非常危险的，因为它可能会导致数据丢失或不一致。在生产环境中，你应该使用如 Liquibase 或 Flyway 这样的迁移工具来管理数据库模式的变更。
> - 在开发环境中，update 模式可以加快开发速度，因为它允许你在不手动修改数据库模式的情况下修改实体类。但是，你应该始终确保你的数据库备份是最新的，并准备在需要时恢复数据。

上述为本次集成JPA的配置参数，实际的配置还需结合自己的开发环境进行配置。

此处仅简单使用了JPA几个配置， 实际JPA还提供了很多的可配参数，可自行百度，当然关注作者后续也会持续更新相关的博文...

## 5. Entity实体类编写

在JPA中，有自己独立风格的实体，一般来讲就是有一些独特的注解来定义实体。 JPA是一个比较完全式的ORM框架，就是可以完全通过实体映射数据库，甚至我们可以根据实体去生成数据库。

我们先来看实体的案例，本次集成以User为例，具体实现如下：

![](https://i-blog.csdnimg.cn/blog_migrate/e1be7ae00a801be11978f45c15d57c79.png)

```java
package com.tic.jpa.entity; import lombok.Data; import javax.persistence.*;import java.io.Serializable;import java.util.Date; /** * @Author: Michael Lee * @CreateTime: 2024-06-28 * @Description: 用户实体类 */@Data@Entity@Table(name = "t_user") // 映射表名public class User implements Serializable {    /**     * 主键生成策略： 自增     */    @Id    @GeneratedValue(strategy = GenerationType.IDENTITY)    private Integer id;    /**     * 用户名称     */    @Column(name = "username", nullable = false, length = 50)    private String name;    /**     * 年龄     */    @Column(name = "age")    private Integer age;    /**     * 性别     */    @Column(name = "gender")    private String gender;    /**     * 创建时间     */    @Column(name = "create_time")    private Date createTime;    /**     * 更新时间     */    @Column(name = "update_time")    private Date updateTime;}
```

此处讲解作者实体类使用的注解： 

- **@Data：**是 Lombok 库提供的一个注解，它会自动为类生成常用的方法，如 getter、setter、equals(), hashCode(), toString() 等，而无需显式编写这些方法。使用 Lombok 可以大大减少样板代码的数量，使代码更加简洁和易读。
- **@Entity：**是 JPA（Java Persistence API）中的一个核心注解，它用于将一个普通的 Java 类声明为一个实体类，从而可以映射到数据库中的表。当一个类被标记为 @Entity 时，JPA 提供商（如 Hibernate）将负责处理这个类与数据库表之间的映射和交互。
- **@Table：**是 JPA (Java Persistence API) 中的一个注解，用于指定实体类与数据库表之间的映射关系。当你想要明确指定一个实体类应该映射到哪个数据库表，或者想要为表指定一个不同的名称（而不是默认的类名作为表名），或者想要为表指定一个特定的 schema 时，你可以使用 @Table 注解。
- **@Id：**是 JPA (Java Persistence API) 中的一个注解，用于标识实体类中的一个字段作为主键。在 JPA 中，每个实体类都需要有一个主键字段，这个字段在数据库中通常是一个具有唯一性的列。使用 @Id 注解可以明确指定哪个字段是主键字段。
- **@GeneratedValue：**是 JPA (Java Persistence API) 中的一个注解，用于指定主键的生成策略。当我们在一个实体类中使用 @Id 注解来标记一个字段作为主键时，通常需要指定主键的生成方式，因为数据库中的主键通常是唯一的，并且需要由某种机制来自动生成。本文使用GenerationType.IDENTITY（id自增策略）。
- **@Column：**是 JPA (Java Persistence API) 中的一个注解，用于指定实体类中的一个字段与数据库表中的列之间的映射关系。当你想要明确指定一个字段应该映射到哪个数据库列，或者想要为列指定一个不同的名称（而不是默认的字段名作为列名），或者想要为列指定一些额外的属性（如长度、是否可为空等）时，你可以使用 @Column 注解。

上述为本次集成JPA的注解，实际的注解配置还需结合自己的需求进行配置。

## 6. Dao层接口开发

Dao层主要处理和数据库的交互，这里我们可以使用JPA为我们提供的基类：JpaRepository，里面包含了大部分常用操作，只需集成即可。

![](https://i-blog.csdnimg.cn/blog_migrate/a53b9bc58e794861bb793a42d2472da5.png)

```java
package com.tic.jpa.dao; import com.tic.jpa.entity.User;import org.springframework.data.jpa.repository.JpaRepository;import org.springframework.stereotype.Repository; import java.io.Serializable; /** * @Author: Michael Lee * @CreateTime: 2024-06-28 * @Description: 用户Dao层接口 */@Repositorypublic interface UserRepository extends JpaRepository<User,Integer>, Serializable {    }
```

## 7. 测试接口开发

完成上述步骤后，您的项目已经顺利集成了JPA，那么我们现在可以对集成的结果进行一个测试，看看还有没有问题，是不是可以投入使用。

我写了两个测试接口分别用来插入user数据和查询表中所有user数据，接口实现如下：

![](https://i-blog.csdnimg.cn/blog_migrate/fc49e810deb5d482037c29c0601c3b60.png)

```java
package com.tic.jpa.controller; import com.tic.jpa.dao.UserRepository;import com.tic.jpa.entity.User;import org.springframework.web.bind.annotation.*; import javax.annotation.Resource;import java.util.Date;import java.util.List; /** * @Author: Michael Lee * @CreateTime: 2024-06-28 * @Description: 测试接口 */@RestController@RequestMapping("/test")public class TestController {    @Resource    private UserRepository userRepository;     @PostMapping("/insert")    public String insert(@RequestBody User user) {        user.setCreateTime(new Date());        userRepository.save(user);        return "接口调用成功！";    }     @GetMapping("/select")    public List<User> findAll() {        return userRepository.findAll();    }}
```

## 8. 程序测试

上述所有步骤都完成后，启动一下工程，从启动日志可以看到Jpa直接通过User实体类创建了t_user表。

![](https://i-blog.csdnimg.cn/blog_migrate/1988e81f6a127a7065f4838344cfffa9.png)

打开数据库管理工具可以看到t_user表已经创建在tic库下。

> **在此插个很好用的数据库管理工具的安装教程~**
> 
> [【JAVA开发笔记】DBeaver 数据库管理工具的安装与使用（超级详细）](http://t.csdnimg.cn/UEyGO "【JAVA开发笔记】DBeaver 数据库管理工具的安装与使用（超级详细）")

![](https://i-blog.csdnimg.cn/blog_migrate/7b8430c37a90151ac80426b77ae10f19.png)

程序启动成功并且表建好后，通过Postman调用新增用户的测试接口。

![](https://i-blog.csdnimg.cn/blog_migrate/ea3751549f0ea17479a97ad43b8fd59a.png)

接口调用成功后，可以看到t_user表中成功插入了一条数据。

ps：可以多插入几条~

![](https://i-blog.csdnimg.cn/blog_migrate/49f641188b21d5e476651861dc9c8cd3.png)

接着再通过Postman调用查询的测试接口，接口响应所有用户信息即为成功。

![](https://i-blog.csdnimg.cn/blog_migrate/2bc7f1cd8188b162ed8ef7c752216dfd.png)

因为前面设置了JPA打印SQL相关配置，可以在控制台看到详细的SQL日志，此功能在研测阶段很有用，但是上线后为了日志的简洁可以关闭改功能~

![](https://i-blog.csdnimg.cn/blog_migrate/e00f89ec8e5e9666fe33103dbb02c2bc.png)
