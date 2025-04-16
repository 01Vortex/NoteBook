
# entity
## Lombok
Lombok 是一个非常有用的 Java 库，可以通过注解自动生成样板代码，从而减少冗余的代码编写工作。以下是 Lombok 提供的主要注解及其详细解释：

### 常用注解

1. **@Data**
   - 自动生成 getter、setter、toString、equals 和 hashCode 方法。
   - 结合了 `@ToString`, `@EqualsAndHashCode`, `@Getter`, `@Setter`, 和 `@RequiredArgsConstructor` 的功能。

2. **@Getter** 和 **@Setter**
   - 分别用于生成所有字段的 getter 和 setter 方法。
   - 可以在类级别或字段级别使用。

3. **@ToString**
   - 生成 `toString` 方法，默认包含所有非静态字段。
   - 可以通过 `exclude` 参数排除某些字段，通过 `of` 参数指定包含哪些字段。

4. **@EqualsAndHashCode**
   - 生成 `equals` 和 `hashCode` 方法，默认包含所有非静态和非 transient 字段。
   - 可以通过 `exclude` 参数排除某些字段，通过 `of` 参数指定包含哪些字段。

5. **@NoArgsConstructor**, **@RequiredArgsConstructor**, 和 **@AllArgsConstructor**
   - `@NoArgsConstructor`: 生成一个无参构造函数。
   - `@RequiredArgsConstructor`: 生成一个包含所有 final 字段和带有 `@NonNull` 注解的字段的构造函数。
   - `@AllArgsConstructor`: 生成一个包含所有字段的全参构造函数。

6. **@Builder**
   - 为类提供构建器模式的支持。
   - 可以通过 `toBuilder = true` 允许从现有实例创建构建器。

7. **@Value**
   - 类似于 `@Data`，但生成的类是不可变的（final 字段），并且没有 setter 方法。
   - 默认包含 `@ToString`, `@EqualsAndHashCode`, `@Getter`, 和 `@FieldDefaults(makeFinal = true)`。

8. **@NonFinal**
   - 与 `@Value` 结合使用时，允许某个字段不是 final 的。

9. **@SneakyThrows**
   - 允许方法抛出受检异常而不显式声明。
   - 示例：`@SneakyThrows IOException.class`

10. **@Cleanup**
    - 确保资源在作用域结束时自动关闭。
    - 示例：
      ```java
      try (@Cleanup InputStream in = new FileInputStream("file.txt")) {
          // 使用 in
      }
      ```

11. **@Log**
    - 生成不同日志框架的日志记录器。
    - 支持多种日志框架，如 SLF4J, Log4j, Log4j2, JDK Logger 等。
    - 示例：
      ```java
      @Slf4j
      public class Example {
          public void exampleMethod() {
              log.info("This is an info message");
          }
      }
      ```

12. **@UtilityClass**
    - 将类标记为工具类，确保它是不可实例化的，并且私有化构造函数。
    - 示例：
      ```java
      @UtilityClass
      public class StringUtils {
          public static String capitalize(String str) {
              return Character.toUpperCase(str.charAt(0)) + str.substring(1);
          }
      }
      ```

13. **@Accessors**
    - 配置 getter 和 setter 方法的行为。
    - 示例：
      ```java
      @Accessors(chain = true)
      public class Person {
          private String name;
          private int age;
      }
      ```
      这样可以链式调用 setter 方法：
      ```java
      person.setName("John").setAge(30);
      ```

14. **@FieldNameConstants**
    - 生成常量字段，对应类中的字段名。
    - 示例：
      ```java
      @FieldNameConstants
      public class User {
          private String username;
          private String password;
      }
      ```
      生成的常量：
      ```java
      public static final String USERNAME = "username";
      public static final String PASSWORD = "password";
      ```

15. **@Wither**
    - 为每个字段生成一个返回新对象的方法，该对象具有该字段的不同值。
    - 示例：
      ```java
      @Value
      public class Point {
          int x;
          int y;

          @Wither(AccessLevel.PROTECTED)
          int z;
      }
      ```
      生成的方法：
      ```java
      protected Point withZ(int z) {
          return this.z == z ? this : new Point(this.x, this.y, z);
      }
      ```

### 示例代码

以下是一个综合示例，展示了如何使用上述部分 Lombok 注解：

```java
package com.example.demo.entity;

import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class User {
    private String username;
    private String email;
    private int age;
    private List<String> roles;

    @SneakyThrows
    public void readFile(String filePath) {
        try (var reader = new java.io.FileReader(filePath)) {
            // 读取文件内容
        }
    }

    @Log
    public void logExample() {
        log.info("Logging an info message");
    }
}
```

在这个示例中：
- `@Data` 自动生成 getter、setter、toString、equals 和 hashCode 方法。
- `@NoArgsConstructor` 生成一个无参构造函数。
- `@AllArgsConstructor` 生成一个包含所有字段的全参构造函数。
- `@Builder` 提供构建器模式的支持。
- `@SneakyThrows` 允许 `readFile` 方法抛出 `IOException` 而不显式声明。
- `@Log` 生成一个日志记录器。

通过使用这些注解，可以显著减少样板代码，提高开发效率。

### 完整示例

以下是一个完整的示例，展示了如何在 Spring Boot 项目中使用 Lombok 来定义 `Login` 类，并在控制器中使用它。

#### 依赖配置

首先，确保在 `pom.xml` 文件中添加 Lombok 依赖：

```xml
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.26</version> <!-- 确保使用最新版本 -->
    <scope>provided</scope>
</dependency>
```

#### Login 类

```java
package com.exam.entity;

import lombok.Data;

@Data
public class Login {
    private String username;
    private String password;
}
```

#### 控制器示例

```java
package com.exam.controller;

import com.exam.entity.Login;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @PostMapping("/login")
    public String login(@RequestBody Login login) {
        // 这里可以添加登录验证逻辑
        return "Logged in successfully with username: " + login.getUsername();
    }
}
```

在这个示例中：
- `AuthController` 提供了一个 `/api/auth/login` 接口，用于处理登录请求。
- `Login` 类通过 Lombok 的 `@Data` 注解自动生成了所需的 getter 和 setter 方法。

通过这种方式，代码变得更加简洁和易于维护。
## Admin.java
该代码定义了一个名为`Admin`的Java类，用于表示管理员实体。类中包含以下功能：
1. 定义了管理员的相关属性：`adminId`, `adminName`, `sex`, `tel`, `email`, `pwd`, `cardId`, `role`。
2. 提供了每个属性的getter和setter方法，用于访问和修改属性值。
3. 在setter方法中对字符串类型的属性进行了非空判断和trim处理，避免存储多余的空格。



## ApiResult.java
`ApiResult<T>` 类是一个通用的响应封装类，用于在API调用中返回统一格式的数据。这种设计有助于客户端更好地理解和处理服务器端返回的结果。下面是对这个类的详细解释：

### 类定义
```java
public class ApiResult<T> {
```
- `ApiResult<T>` 是一个泛型类，其中 `T` 是一个类型参数，表示返回的数据类型可以是任意类型。

### 字段
```java
private int code;
```
- `code` 是一个整数类型的字段，用于表示请求的状态码。通常情况下：
  - `200` 表示请求成功。
  - 其他值（如 `400`, `401`, `403`, `404`, `500` 等）表示不同的错误类型。

```java
private String message;
```
- `message` 是一个字符串类型的字段，用于提供对状态码的详细描述或错误信息。例如，当 `code` 为 `404` 时，`message` 可能会是 `"Resource not found"`。

```java
private T data;
```
- `data` 是一个泛型类型的字段，用于存储实际的业务数据。它可以是任何类型的对象，具体取决于API调用的上下文。

### 构造函数
```java
public ApiResult() {
}
```
- 这是一个无参构造函数，允许创建一个没有任何初始值的 `ApiResult` 对象。

```java
public ApiResult(int code, String message, T data) {
    this.code = code;
    this.message = message;
    this.data = data;
}
```
- 这是一个带参构造函数，允许在创建对象时初始化 `code`, `message`, 和 `data` 字段。

### Getter 和 Setter 方法
```java
public int getCode() {
    return code;
}

public void setCode(int code) {
    this.code = code;
}

public String getMessage() {
    return message;
}

public void setMessage(String message) {
    this.message = message;
}

public T getData() {
    return data;
}

public void setData(T data) {
    this.data = data;
}
```
- 这些方法用于获取和设置 `ApiResult` 对象的各个字段值。

### 使用场景
假设我们有一个API接口用于获取用户信息，我们可以使用 `ApiResult<User>` 来封装返回结果：

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public ApiResult<User> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        if (user != null) {
            return new ApiResult<>(200, "User found", user);
        } else {
            return new ApiResult<>(404, "User not found", null);
        }
    }
}
```

在这个例子中：
- 如果找到了用户，则返回状态码 `200` 和用户对象。
- 如果没有找到用户，则返回状态码 `404` 并附带相应的消息。

通过这种方式，客户端可以根据 `code` 和 `message` 字段来判断请求是否成功，并根据 `data` 字段来获取具体的业务数据。




## Message.java
`Message` 类是一个用于表示消息或帖子的实体类，包含了消息的详细信息以及相关的评论。通过使用 Lombok 的 `@Data` 注解，这个类自动生成了 getter、setter、toString、equals 和 hashCode 方法。下面是对这个类的详细解释：

### 类定义
```java
package com.exam.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class Message {
```
- `Message` 类位于 `com.exam.entity` 包中。
- 使用了 Lombok 的 `@Data` 注解，这会自动生成常用的 boilerplate 代码，如 getter、setter、toString、equals 和 hashCode 方法。

### 字段

```java
private Integer id;
```
- `id` 是一个整数类型的字段，表示消息的唯一标识码。

```java
private Integer temp_id; // 解决id为null创建的一个临时id
```
- `temp_id` 是一个整数类型的字段，用于在 `id` 为 `null` 时提供一个临时的标识符。

```java
private String title;
```
- `title` 是一个字符串类型的字段，表示消息的标题。

```java
private String content;
```
- `content` 是一个字符串类型的字段，表示消息的内容。

```java
@JsonFormat(pattern = "yyyy-MM-dd", timezone="GMT+8")
private Date time;
```
- `time` 是一个日期类型的字段，表示消息的时间戳。
- `@JsonFormat` 注解用于指定日期的格式和时区。这里设置的格式为 `yyyy-MM-dd`，时区为 `GMT+8`。

```java
List<Replay> replays;   // 一对多关系，评论信息
```
- `replays` 是一个 `List<Replay>` 类型的字段，表示与该消息相关的所有评论。
- 这里假设 `Replay` 是一个表示评论的实体类。

### 使用场景
假设我们有一个论坛系统，需要管理和存储帖子及其评论信息，可以使用 `Message` 类来表示这些信息。以下是一个简单的示例，展示如何在控制器中使用 `Message` 类：

#### Replay 类

首先，我们需要一个 `Replay` 类来表示评论信息：

```java
package com.exam.entity;

import lombok.Data;

@Data
public class Replay {
    private Integer id;
    private Integer messageId; // 关联的消息ID
    private String content;
    private String author;
}
```

#### 控制器示例

```java
package com.exam.controller;

import com.exam.entity.Message;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private List<Message> messages = new ArrayList<>();

    @PostMapping
    public Message createMessage(@RequestBody Message message) {
        messages.add(message);
        return message;
    }

    @GetMapping("/{id}")
    public Message getMessageById(@PathVariable Integer id) {
        return messages.stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    @GetMapping
    public List<Message> getAllMessages() {
        return messages;
    }
}
```

在这个例子中：
- `createMessage` 方法用于创建一个新的消息记录，并将其添加到 `messages` 列表中。
- `getMessageById` 方法根据 `id` 查找并返回相应的消息记录。
- `getAllMessages` 方法返回所有的消息记录。

### 完整示例

以下是完整的 `Message` 类和 `Replay` 类，以及一个简单的控制器示例。

#### Message 类

```java
package com.exam.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.util.Date;
import java.util.List;

@Data
public class Message {
    private Integer id;
    private Integer temp_id; // 解决id为null创建的一个临时id

    private String title;

    private String content;

    @JsonFormat(pattern = "yyyy-MM-dd", timezone="GMT+8")
    private Date time;

    private List<Replay> replays;   // 一对多关系，评论信息
}
```

#### Replay 类

```java
package com.exam.entity;

import lombok.Data;

@Data
public class Replay {
    private Integer id;
    private Integer messageId; // 关联的消息ID
    private String content;
    private String author;
}
```

#### 控制器示例

```java
package com.exam.controller;

import com.exam.entity.Message;
import com.exam.entity.Replay;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private List<Message> messages = new ArrayList<>();

    @PostMapping
    public Message createMessage(@RequestBody Message message) {
        messages.add(message);
        return message;
    }

    @GetMapping("/{id}")
    public Message getMessageById(@PathVariable Integer id) {
        return messages.stream()
                .filter(m -> m.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    @GetMapping
    public List<Message> getAllMessages() {
        return messages;
    }

    @PostMapping("/{messageId}/replies")
    public Message addReply(@PathVariable Integer messageId, @RequestBody Replay reply) {
        Message message = messages.stream()
                .filter(m -> m.getId().equals(messageId))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Message not found"));

        if (message.getReplays() == null) {
            message.setReplays(new ArrayList<>());
        }
        message.getReplays().add(reply);
        return message;
    }
}
```

在这个示例中：
- `createMessage` 方法用于创建一个新的消息记录，并将其添加到 `messages` 列表中。
- `getMessageById` 方法根据 `id` 查找并返回相应的消息记录。
- `getAllMessages` 方法返回所有的消息记录。
- `addReply` 方法用于向特定消息添加新的评论。

通过这种方式，我们可以方便地管理和操作消息及其评论信息。



# mapper
## Mybatis
使用 MyBatis 和 MyBatis Plus 可以简化数据库操作，提高开发效率。下面详细介绍如何在 Spring Boot 项目中集成和使用这两个框架。

### 1. 添加依赖

首先，在 `pom.xml` 文件中添加 MyBatis 和 MyBatis Plus 的依赖。

```xml
<dependencies>
    <!-- Spring Boot Starter Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <!-- MySQL Connector -->
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <scope>runtime</scope>
    </dependency>

    <!-- MyBatis Plus -->
    <dependency>
        <groupId>com.baomidou</groupId>
        <artifactId>mybatis-plus-boot-starter</artifactId>
        <version>3.5.2</version>
    </dependency>

    <!-- Lombok (optional) -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <version>1.18.26</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```

### 2. 配置数据源

在 `application.yml` 或 `application.properties` 文件中配置数据库连接信息。

#### application.yml
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/your_database?useSSL=false&serverTimezone=UTC
    username: your_username
    password: your_password
    driver-class-name: com.mysql.cj.jdbc.Driver

mybatis-plus:
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
```

#### application.properties
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/your_database?useSSL=false&serverTimezone=UTC
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

mybatis-plus.configuration.log-impl=org.apache.ibatis.logging.stdout.StdOutImpl
```

### 3. 创建实体类

假设我们有一个 `User` 实体类，对应数据库中的 `users` 表。

```java
package com.example.demo.entity;

import lombok.Data;
import java.util.Date;

@Data
public class User {
    private Long id;
    private String name;
    private Integer age;
    private String email;
    private Date createTime;
    private Date updateTime;
}
```

### 4. 创建 Mapper 接口

MyBatis Plus 提供了 `BaseMapper` 接口，可以简化 CRUD 操作。

```java
package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
    // 可以在这里定义自定义的 SQL 方法
}
```

### 5. 配置扫描 Mapper 接口

确保 Spring Boot 能够扫描到 Mapper 接口。可以在主类上使用 `@MapperScan` 注解，或者在配置文件中进行配置。

#### 主类上的注解
```java
package com.example.demo;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.example.demo.mapper")
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

#### 配置文件中的配置
```yaml
mybatis-plus:
  mapper-locations: classpath*:mapper/*.xml
  type-aliases-package: com.example.demo.entity
```

### 6. 使用 Service 层

创建一个服务层来处理业务逻辑。

```java
package com.example.demo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.demo.entity.User;
import com.example.demo.mapper.UserMapper;
import com.example.demo.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    // 可以在这里实现自定义的业务逻辑
}
```

#### 定义 Service 接口
```java
package com.example.demo.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.demo.entity.User;

public interface UserService extends IService<User> {
    // 可以在这里定义自定义的服务方法
}
```

### 7. 创建 Controller

最后，创建一个控制器来处理 HTTP 请求。

```java
package com.example.demo.controller;

import com.example.demo.entity.User;
import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping
    public boolean createUser(@RequestBody User user) {
        return userService.save(user);
    }

    @GetMapping("/{id}")
    public User getUserById(@PathVariable Long id) {
        return userService.getById(id);
    }

    @GetMapping
    public List<User> getAllUsers() {
        return userService.list();
    }

    @PutMapping("/{id}")
    public boolean updateUser(@PathVariable Long id, @RequestBody User user) {
        user.setId(id);
        return userService.updateById(user);
    }

    @DeleteMapping("/{id}")
    public boolean deleteUser(@PathVariable Long id) {
        return userService.removeById(id);
    }
}
```

### 8. 自定义 SQL 查询

如果需要自定义 SQL 查询，可以在 Mapper 接口中定义方法，并在 XML 文件中编写对应的 SQL 语句。

#### UserMapper.java
```java
package com.example.demo.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.demo.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface UserMapper extends BaseMapper<User> {
    List<User> getUsersByName(@Param("name") String name);
}
```

#### UserMapper.xml
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="com.example.demo.mapper.UserMapper">
    <select id="getUsersByName" resultType="com.example.demo.entity.User">
        SELECT * FROM users WHERE name = #{name}
    </select>
</mapper>
```

### 总结

通过以上步骤，你可以在 Spring Boot 项目中成功集成和使用 MyBatis Plus。MyBatis Plus 提供了许多便捷的功能，如代码生成器、分页插件、条件构造器等，可以帮助开发者更高效地进行数据库操作。希望这个示例对你有所帮助！


## AdminMapper.java
你已经定义了一个 `AdminMapper` 接口，其中包含了基本的 CRUD 操作。为了确保这个接口能够正常工作，并且符合 MyBatis 和 MyBatis Plus 的最佳实践，我们可以进行一些调整和完善。以下是一些建议和完整的示例代码：

### 1. 确保实体类字段与数据库列名一致

为了简化映射，建议实体类的字段名与数据库表的列名保持一致。如果需要不同的命名规则，可以使用注解来映射。

#### Admin 实体类

```java
package com.exam.entity;

import lombok.Data;
import java.util.Date;

@Data
public class Admin {
    private Integer adminId;   // 对应数据库中的 adminId
    private String adminName;  // 对应数据库中的 adminName
    private String sex;        // 对应数据库中的 sex
    private String tel;        // 对应数据库中的 tel
    private String email;      // 对应数据库中的 email
    private String pwd;        // 对应数据库中的 pwd
    private String cardId;     // 对应数据库中的 cardId
    private String role;       // 对应数据库中的 role
}
```

### 2. 完善 Mapper 接口

确保所有方法都有适当的注解，并且 SQL 语句正确无误。

```java
package com.exam.mapper;

import com.exam.entity.Admin;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface AdminMapper {

    @Select("SELECT adminId, adminName, sex, tel, email, pwd, cardId, role FROM admin")
    public List<Admin> findAll();

    @Select("SELECT adminId, adminName, sex, tel, email, pwd, cardId, role FROM admin WHERE adminId = #{adminId}")
    public Admin findById(Integer adminId);

    @Delete("DELETE FROM admin WHERE adminId = #{adminId}")
    public int deleteById(int adminId);

    @Update("UPDATE admin SET adminName = #{adminName}, sex = #{sex}, " +
            "tel = #{tel}, email = #{email}, pwd = #{pwd}, cardId = #{cardId}, role = #{role} " +
            "WHERE adminId = #{adminId}")
    public int update(Admin admin);

    @Options(useGeneratedKeys = true, keyProperty = "adminId")
    @Insert("INSERT INTO admin(adminName, sex, tel, email, pwd, cardId, role) " +
            "VALUES(#{adminName}, #{sex}, #{tel}, #{email}, #{pwd}, #{cardId}, #{role})")
    public int add(Admin admin);
}
```

### 3. 配置扫描 Mapper 接口

确保 Spring Boot 能够扫描到 `AdminMapper` 接口。可以在主类上使用 `@MapperScan` 注解，或者在配置文件中进行配置。

#### 主类上的注解
```java
package com.exam;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.exam.mapper")
public class ExamApplication {
    public static void main(String[] args) {
        SpringApplication.run(ExamApplication.class, args);
    }
}
```

### 4. 创建 Service 层

创建一个服务层来处理业务逻辑。

#### AdminService 接口
```java
package com.exam.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.exam.entity.Admin;

public interface AdminService extends IService<Admin> {
    // 可以在这里定义自定义的服务方法
}
```

#### AdminServiceImpl 类
```java
package com.exam.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.exam.entity.Admin;
import com.exam.mapper.AdminMapper;
import com.exam.service.AdminService;
import org.springframework.stereotype.Service;

@Service
public class AdminServiceImpl extends ServiceImpl<AdminMapper, Admin> implements AdminService {
    // 可以在这里实现自定义的业务逻辑
}
```

### 5. 创建 Controller

最后，创建一个控制器来处理 HTTP 请求。

```java
package com.exam.controller;

import com.exam.entity.Admin;
import com.exam.service.AdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admins")
public class AdminController {

    @Autowired
    private AdminService adminService;

    @PostMapping
    public boolean createAdmin(@RequestBody Admin admin) {
        return adminService.save(admin);
    }

    @GetMapping("/{adminId}")
    public Admin getAdminById(@PathVariable Integer adminId) {
        return adminService.getById(adminId);
    }

    @GetMapping
    public List<Admin> getAllAdmins() {
        return adminService.list();
    }

    @PutMapping("/{adminId}")
    public boolean updateAdmin(@PathVariable Integer adminId, @RequestBody Admin admin) {
        admin.setAdminId(adminId);
        return adminService.updateById(admin);
    }

    @DeleteMapping("/{adminId}")
    public boolean deleteAdmin(@PathVariable Integer adminId) {
        return adminService.removeById(adminId);
    }
}
```

### 6. 数据库配置

确保在 `application.yml` 或 `application.properties` 文件中配置了正确的数据库连接信息。

#### application.yml
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/your_database?useSSL=false&serverTimezone=UTC
    username: your_username
    password: your_password
    driver-class-name: com.mysql.cj.jdbc.Driver

mybatis-plus:
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
```

### 总结

通过以上步骤，你可以在 Spring Boot 项目中成功集成和使用 MyBatis Plus，并定义了一个完整的 `AdminMapper` 接口来进行 CRUD 操作。以下是完整的代码结构：

#### 目录结构
```
src
├── main
│   ├── java
│   │   └── com
│   │       └── exam
│   │           ├── ExamApplication.java
│   │           ├── controller
│   │           │   └── AdminController.java
│   │           ├── entity
│   │           │   └── Admin.java
│   │           ├── mapper
│   │           │   └── AdminMapper.java
│   │           ├── service
│   │           │   ├── AdminService.java
│   │           │   └── impl
│   │           │       └── AdminServiceImpl.java
│   │           └── ExamApplication.java
│   └── resources
│       └── application.yml
```

这样配置后，你的 `AdminMapper` 接口将能够正常工作，并且你可以通过 RESTful API 进行管理员的增删改查操作。希望这些信息对你有所帮助！



