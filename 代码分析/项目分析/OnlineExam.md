
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


## Mybatis的分页
MyBatis 是一个优秀的持久层框架，它简化了数据库操作的复杂性。分页是数据库查询中常见的需求，特别是在处理大量数据时，分页可以显著提高用户体验和系统性能。MyBatis 提供了多种方式来实现分页功能，其中最常用的是使用 MyBatis Plus 插件。

### MyBatis Plus 分页插件

MyBatis Plus 是 MyBatis 的增强工具，旨在简化开发、提高效率。它内置了一个强大的分页插件，可以非常方便地实现分页查询。

#### 主要特点

1. **自动处理分页逻辑**:
   - 自动计算 SQL 中的 `LIMIT` 和 `OFFSET` 参数。
   - 支持多种数据库（如 MySQL、PostgreSQL、Oracle 等）的分页语法。

2. **简洁的 API**:
   - 使用简单的 Java 对象来表示分页信息。
   - 通过注解或 XML 配置轻松启用分页功能。

3. **高效的性能**:
   - 减少不必要的查询次数，提高查询效率。
   - 支持物理分页和逻辑分页。

4. **易于集成**:
   - 可以与 Spring Boot 等框架无缝集成。
   - 支持自定义分页逻辑和扩展。

#### 实现步骤

1. **添加依赖**:
   首先，在项目的 `pom.xml` 文件中添加 MyBatis Plus 的依赖：

   ```xml
   <dependency>
       <groupId>com.baomidou</groupId>
       <artifactId>mybatis-plus-boot-starter</artifactId>
       <version>最新版本号</version>
   </dependency>
   ```

2. **配置分页插件**:
   在 Spring Boot 应用中配置 MyBatis Plus 的分页插件。通常在配置类中进行配置：

   ```java
   package com.exam.config;

   import com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor;
   import com.baomidou.mybatisplus.extension.plugins.inner.PaginationInnerInterceptor;
   import org.mybatis.spring.annotation.MapperScan;
   import org.springframework.context.annotation.Bean;
   import org.springframework.context.annotation.Configuration;

   @Configuration
   @MapperScan("com.exam.mapper") // 扫描 Mapper 接口所在包
   public class MyBatisPlusConfig {

       @Bean
       public MybatisPlusInterceptor mybatisPlusInterceptor() {
           MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
           interceptor.addInnerInterceptor(new PaginationInnerInterceptor());
           return interceptor;
       }
   }
   ```

3. **编写 Mapper 接口**:
   在 Mapper 接口中使用 `IPage` 和 `Page` 类来进行分页查询。例如：

   ```java
   package com.exam.mapper;

   import com.baomidou.mybatisplus.core.metadata.IPage;
   import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
   import com.exam.vo.AnswerVO;
   import org.apache.ibatis.annotations.Mapper;
   import org.apache.ibatis.annotations.Select;

   @Mapper
   public interface AnswerMapper {

       @Select("select question, subject, score, section, level, \"选择题\" as type from multi_question " +
               "union select question, subject, score, section, level, \"判断题\" as type from judge_question " +
               "union select question, subject, score, section, level, \"填空题\" as type from fill_question")
       IPage<AnswerVO> findAll(Page page);
   }
   ```

4. **使用 Mapper 进行分页查询**:
   在 Service 层或 Controller 层中使用 Mapper 接口进行分页查询。例如：

   ```java
   package com.exam.service;

   import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
   import com.exam.mapper.AnswerMapper;
   import com.exam.vo.AnswerVO;
   import org.springframework.beans.factory.annotation.Autowired;
   import org.springframework.stereotype.Service;

   @Service
   public class AnswerService {

       @Autowired
       private AnswerMapper answerMapper;

       public IPage<AnswerVO> getPaginatedAnswers(int currentPage, int pageSize) {
           Page<AnswerVO> page = new Page<>(currentPage, pageSize);
           return answerMapper.findAll(page);
       }
   }
   ```

5. **控制器示例**:
   创建一个 Controller 来处理 HTTP 请求并返回分页后的题目信息。例如：

   ```java
   package com.exam.controller;

   import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
   import com.exam.service.AnswerService;
   import com.exam.vo.AnswerVO;
   import org.springframework.beans.factory.annotation.Autowired;
   import org.springframework.web.bind.annotation.GetMapping;
   import org.springframework.web.bind.annotation.RequestParam;
   import org.springframework.web.bind.annotation.RestController;

   @RestController
   public class AnswerController {

       @Autowired
       private AnswerService answerService;

       @GetMapping("/answers")
       public Page<AnswerVO> getAnswers(@RequestParam int page, @RequestParam int size) {
           return answerService.getPaginatedAnswers(page, size);
       }
   }
   ```

### 示例代码解析

#### 1. 添加依赖

确保项目中包含了 MyBatis Plus 的依赖：

```xml
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-boot-starter</artifactId>
    <version>3.5.2</version> <!-- 请使用最新版本 -->
</dependency>
```

#### 2. 配置分页插件

在配置类中启用分页插件：

```java
package com.exam.config;

import com.baomidou.mybatisplus.extension.plugins.MybatisPlusInterceptor;
import com.baomidou.mybatisplus.extension.plugins.inner.PaginationInnerInterceptor;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@MapperScan("com.exam.mapper") // 扫描 Mapper 接口所在包
public class MyBatisPlusConfig {

    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        MybatisPlusInterceptor interceptor = new MybatisPlusInterceptor();
        interceptor.addInnerInterceptor(new PaginationInnerInterceptor());
        return interceptor;
    }
}
```

#### 3. 编写 Mapper 接口

定义一个 Mapper 接口，并使用 `IPage` 和 `Page` 进行分页查询：

```java
package com.exam.mapper;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.exam.vo.AnswerVO;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface AnswerMapper {

    @Select("select question, subject, score, section, level, \"选择题\" as type from multi_question " +
            "union select question, subject, score, section, level, \"判断题\" as type from judge_question " +
            "union select question, subject, score, section, level, \"填空题\" as type from fill_question")
    IPage<AnswerVO> findAll(Page page);
}
```

#### 4. 使用 Mapper 进行分页查询

在 Service 层中调用 Mapper 接口进行分页查询：

```java
package com.exam.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.exam.mapper.AnswerMapper;
import com.exam.vo.AnswerVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AnswerService {

    @Autowired
    private AnswerMapper answerMapper;

    public IPage<AnswerVO> getPaginatedAnswers(int currentPage, int pageSize) {
        Page<AnswerVO> page = new Page<>(currentPage, pageSize);
        return answerMapper.findAll(page);
    }
}
```

#### 5. 控制器示例

创建一个 Controller 来处理 HTTP 请求并返回分页后的题目信息：

```java
package com.exam.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.exam.service.AnswerService;
import com.exam.vo.AnswerVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AnswerController {

    @Autowired
    private AnswerService answerService;

    @GetMapping("/answers")
    public Page<AnswerVO> getAnswers(@RequestParam int page, @RequestParam int size) {
        return answerService.getPaginatedAnswers(page, size);
    }
}
```

### 总结

MyBatis Plus 的分页插件提供了一种简单而高效的方式来实现分页功能。通过配置分页插件并在 Mapper 接口中使用 `IPage` 和 `Page` 类，可以轻松地实现复杂的分页查询。这种方式不仅减少了手动编写分页逻辑的工作量，还提高了代码的可维护性和性能。


## 什么时候使用List<>
在Java中，`List<Admin>`通常用于存储和操作一组`Admin`对象。具体来说，在以下几种情况下会使用`List<Admin>`：

1. **查询所有记录**:
   当你需要从数据库中获取所有管理员的信息时，可以使用`List<Admin>`来存储这些信息。例如：
   ```java
   @Select("select adminName, sex, tel, email, cardId, role from admin")
   public List<Admin> findAll();
   ```
   这个方法会返回一个包含所有管理员信息的列表。

2. **批量处理数据**:
   在某些业务场景中，你可能需要对多个管理员进行批量处理。例如，统计所有管理员的数量、筛选出特定条件的管理员等。使用`List<Admin>`可以方便地进行这些操作。
   ```java
   List<Admin> admins = adminMapper.findAll();
   for (Admin admin : admins) {
       // 对每个admin对象进行处理
   }
   ```

3. **传递和返回多条记录**:
   在服务层或控制器层，你可能会将查询到的多个管理员信息传递给其他层或返回给客户端。使用`List<Admin>`可以方便地进行这种传递和返回。
   ```java
   public List<Admin> getAllAdmins() {
       return adminMapper.findAll();
   }
   ```

4. **缓存数据**:
   有时候为了提高性能，你会将一些频繁访问的数据缓存起来。使用`List<Admin>`可以方便地存储这些缓存数据。
   ```java
   private List<Admin> cachedAdmins;

   public void loadAdmins() {
       cachedAdmins = adminMapper.findAll();
   }

   public List<Admin> getCachedAdmins() {
       return cachedAdmins;
   }
   ```

5. **聚合和分析数据**:
   在数据分析或报表生成的场景中，你可能需要对多条记录进行聚合和分析。使用`List<Admin>`可以方便地进行这些操作。
   ```java
   List<Admin> admins = adminMapper.findAll();
   long numberOfAdmins = admins.stream().count();
   ```

总结来说，`List<Admin>`主要用于存储和操作一组`Admin`对象，特别是在需要处理多条记录的情况下。它提供了丰富的集合操作方法，使得数据的增删改查和业务逻辑处理变得更加方便。

## 什么是值对象
值对象（Value Object）是一种设计模式，常用于领域驱动设计（Domain-Driven Design, DDD）中。值对象的主要特点是其身份由其属性决定，而不是一个唯一的标识符。这意味着两个值对象只要它们的属性相同，就被认为是相等的。以下是对值对象的详细解释：

### 主要特点

1. **不可变性**:
   - 值对象通常是不可变的（immutable），即一旦创建就不能修改其状态。
   - 不可变性有助于确保对象的一致性和线程安全性。

2. **无唯一标识符**:
   - 值对象没有唯一的标识符（如主键），它们的身份完全由其属性决定。
   - 例如，货币金额是一个典型的值对象，因为它是由数值和货币类型（如美元、欧元）组成的，而不需要一个唯一的ID。

3. **相等性比较**:
   - 值对象通过比较所有属性来判断是否相等。
   - 例如，两个表示同一种货币金额的对象只有在数值和货币类型都相同时才被认为是相等的。

4. **轻量级**:
   - 值对象通常比实体对象（Entity）更轻量级，因为它们不需要持久化标识符或复杂的业务逻辑。
   - 它们主要用于数据传输和封装简单的数据结构。

5. **复用性**:
   - 值对象可以在不同的上下文中复用，因为它们的行为和状态是独立的。
   - 例如，同一个货币金额对象可以在多个订单中使用。

### 示例

假设我们正在开发一个考试管理系统，其中需要处理各种类型的题目信息。我们可以定义一个值对象 `AnswerVO` 来封装题目信息。

#### 定义值对象 `AnswerVO`

```java
package com.exam.vo;

public class AnswerVO {

    private String question;
    private String subject;
    private Integer score;
    private String section;
    private String level;
    private String type;

    // 构造函数
    public AnswerVO() {
    }

    public AnswerVO(String question, String subject, Integer score, String section, String level, String type) {
        this.question = question;
        this.subject = subject;
        this.score = score;
        this.section = section;
        this.level = level;
        this.type = type;
    }

    // Getter 和 Setter 方法
    public String getQuestion() {
        return question;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Integer getScore() {
        return score;
    }

    public void setScore(Integer score) {
        this.score = score;
    }

    public String getSection() {
        return section;
    }

    public void setSection(String section) {
        this.section = section;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    // equals 和 hashCode 方法
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AnswerVO answerVO = (AnswerVO) o;
        return question.equals(answerVO.question) &&
                subject.equals(answerVO.subject) &&
                score.equals(answerVO.score) &&
                section.equals(answerVO.section) &&
                level.equals(answerVO.level) &&
                type.equals(answerVO.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(question, subject, score, section, level, type);
    }

    // toString 方法
    @Override
    public String toString() {
        return "AnswerVO{" +
                "question='" + question + '\'' +
                ", subject='" + subject + '\'' +
                ", score=" + score +
                ", section='" + section + '\'' +
                ", level='" + level + '\'' +
                ", type='" + type + '\'' +
                '}';
    }
}
```

#### 解释

1. **属性**:
   - `question`: 题目内容。
   - `subject`: 科目名称。
   - `score`: 分数。
   - `section`: 部分或章节。
   - `level`: 难度级别。
   - `type`: 题目类型（选择题、判断题、填空题等）。

2. **构造函数**:
   - 默认构造函数。
   - 带参数的构造函数，方便初始化对象。

3. **Getter 和 Setter 方法**:
   - 提供对各个属性的访问和修改方法。

4. **equals 和 hashCode 方法**:
   - 重写这两个方法以确保根据属性值进行相等性比较。
   - `equals` 方法比较所有属性是否相等。
   - `hashCode` 方法生成基于属性的哈希码。

5. **toString 方法**:
   - 提供一个字符串表示形式，便于调试和日志记录。

### 使用场景

1. **数据传输对象 (DTO)**:
   - 在不同层之间传递数据时使用值对象。
   - 例如，在服务层和控制器层之间传递题目信息。

2. **领域模型中的简单数据结构**:
   - 封装一些简单的数据结构，如地址、货币金额等。
   - 这些数据结构不需要唯一的标识符，只需根据属性值进行比较。

3. **避免重复代码**:
   - 通过定义值对象，可以减少重复的代码和数据结构。
   - 例如，多个地方需要使用相同的题目信息时，可以共享同一个值对象。

### 与实体对象的区别

| 特征          | 值对象 (Value Object)                           | 实体对象 (Entity)                                       |
|---------------|---------------------------------------------------|---------------------------------------------------------|
| 标识符        | 没有唯一的标识符                                | 有唯一的标识符（如数据库中的主键）                      |
| 相等性比较    | 根据属性值比较                                  | 根据唯一标识符比较                                      |
| 生命周期      | 通常较短，随操作结束而销毁                      | 生命周期较长，可能在整个应用程序中存在                    |
| 可变性        | 通常是不可变的                                  | 通常是可变的                                            |
| 复用性        | 可以在不同的上下文中复用                        | 每个实例都是独立的，不能复用                            |

### 总结

值对象是一种轻量级的数据结构，主要用于封装简单的数据，并且通过其属性值来确定相等性。它们在领域驱动设计中扮演着重要角色，帮助开发者更好地组织和管理数据。通过定义和使用值对象，可以提高代码的可维护性和复用性。

如果你有任何具体的问题或需要进一步的帮助，请随时提问！
## AdminMapper.java
这个代码片段是一个MyBatis的Mapper接口定义，用于对`admin`表进行基本的CRUD（创建、读取、更新、删除）操作。下面是对代码的详细解释：

1. **包声明**:
   ```java
   package com.exam.mapper;
   ```
   这行代码指定了这个类所在的包路径为`com.exam.mapper`。

2. **导入必要的类**:
   ```java
   import com.exam.entity.Admin;
   import org.apache.ibatis.annotations.*;
   import java.util.List;
   ```
   - `Admin`是自定义的一个实体类，表示管理员的信息。
   - MyBatis的相关注解：`@Mapper`, `@Select`, `@Delete`, `@Update`, `@Insert`, `@Options`。
   - `List`是Java集合框架中的一个接口，用于存储多个对象。

3. **Mapper接口定义**:
   ```java
   @Mapper
   public interface AdminMapper {
       ...
   }
   ```
   使用`@Mapper`注解标识这是一个MyBatis Mapper接口，这样MyBatis会在启动时自动扫描并注册这些接口。

4. **方法定义及SQL查询**:

   - **查询所有管理员信息**:
     ```java
     @Select("select adminName,sex,tel,email,cardId,role from admin")
     public List<Admin> findAll();
     ```
     - `findAll`方法用于查询所有的管理员信息。
     - `@Select`注解中的SQL语句从`admin`表中选择指定的字段，并将结果封装到`Admin`对象中。
     - 返回的是一个包含所有管理员信息的`List<Admin>`对象。

   - **根据ID查询管理员信息**:
     ```java
     @Select("select adminName,sex,tel,email,cardId,role from admin where adminId = #{adminId}")
     public Admin findById(Integer adminId);
     ```
     - `findById`方法用于根据管理员ID查询具体的管理员信息。
     - `@Select`注解中的SQL语句从`admin`表中选择指定的字段，并通过`where`子句过滤出特定ID的记录。
     - 返回的是一个`Admin`对象，表示查询到的管理员信息。

   - **根据ID删除管理员信息**:
     ```java
     @Delete("delete from admin where adminId = #{adminId}")
     public int deleteById(int adminId);
     ```
     - `deleteById`方法用于根据管理员ID删除对应的记录。
     - `@Delete`注解中的SQL语句通过`where`子句删除特定ID的记录。
     - 返回的是受影响的行数（即删除的记录数量），类型为`int`。

   - **更新管理员信息**:
     ```java
     @Update("update admin set adminName = #{adminName},sex = #{sex}," +
             "tel = #{tel}, email = #{email},pwd = #{pwd},cardId = #{cardId},role = #{role} where adminId = #{adminId}")
     public int update(Admin admin);
     ```
     - `update`方法用于更新管理员的信息。
     - `@Update`注解中的SQL语句通过`set`子句设置新的字段值，并通过`where`子句过滤出特定ID的记录进行更新。
     - 参数是一个`Admin`对象，包含了要更新的所有字段。
     - 返回的是受影响的行数（即成功更新的数量），类型为`int`。

   - **插入新管理员信息**:
     ```java
     @Options(useGeneratedKeys = true,keyProperty = "adminId")
     @Insert("insert into admin(adminName,sex,tel,email,pwd,cardId,role) " +
             "values(#{adminName},#{sex},#{tel},#{email},#{pwd},#{cardId},#{role})")
     public int add(Admin admin);
     ```
     - `add`方法用于插入一个新的管理员记录。
     - `@Insert`注解中的SQL语句插入一条新的记录到`admin`表中。
     - `@Options`注解配置了使用数据库生成的主键，并将其赋值给传入的`Admin`对象的`adminId`属性。
     - 参数是一个`Admin`对象，包含了要插入的所有字段。
     - 返回的是受影响的行数（即插入的记录数量），类型为`int`。

总结来说，这段代码的作用是提供了一系列的方法来操作`admin`表中的数据，包括查询所有管理员信息、根据ID查询单个管理员信息、根据ID删除管理员信息、更新管理员信息以及插入新的管理员信息。





## AnswerMapper.java
这个代码片段是一个MyBatis的Mapper接口定义，用于从数据库中查询不同类型的题目信息，并将结果封装到`AnswerVO`对象中。下面是对代码的详细解释：

1. **包声明**:
   ```java
   package com.exam.mapper;
   ```
   这行代码指定了这个类所在的包路径为`com.exam.mapper`。

2. **导入必要的类**:
   ```java
   import com.baomidou.mybatisplus.core.metadata.IPage;
   import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
   import com.exam.vo.AnswerVO;
   import org.apache.ibatis.annotations.Mapper;
   import org.apache.ibatis.annotations.Select;
   ```
   - `IPage`和`Page`是MyBatis Plus提供的分页工具类。
   - `AnswerVO`是自定义的一个值对象（Value Object），用于封装查询结果。
   - `@Mapper`注解标识这是一个MyBatis Mapper接口。
   - `@Select`注解用于指定SQL查询语句。

3. **Mapper接口定义**:
   ```java
   @Mapper
   public interface AnswerMapper {
       ...
   }
   ```
   使用`@Mapper`注解标识这是一个MyBatis Mapper接口，这样MyBatis会在启动时自动扫描并注册这些接口。

4. **方法定义及SQL查询**:
   ```java
   @Select("select question, subject, score, section, level, \"选择题\" as type from multi_question " +
           "union select question, subject, score, section, level, \"判断题\" as type from judge_question " +
           "union select question, subject, score, section, level, \"填空题\" as type from fill_question")
   IPage<AnswerVO> findAll(Page page);
   ```
   - `findAll`方法用于查询所有类型的题目信息，并进行分页。
   - `@Select`注解中的SQL语句使用了`UNION`操作符来合并三个子查询的结果：
     - 第一个子查询从`multi_question`表中选择数据，并将题目类型设置为“选择题”。
     - 第二个子查询从`judge_question`表中选择数据，并将题目类型设置为“判断题”。
     - 第三个子查询从`fill_question`表中选择数据，并将题目类型设置为“填空题”。
   - 每个子查询都选择了相同的字段：`question`, `subject`, `score`, `section`, `level`，并在每个子查询中添加了一个额外的字段`type`来表示题目类型。
   - 方法接收一个`Page`对象作为参数，该对象包含了分页信息（如当前页码、每页大小等）。
   - 方法返回的是一个`IPage<AnswerVO>`对象，其中包含了分页后的查询结果以及相关的分页信息。

总结来说，这段代码的作用是从多个不同的题目表中查询出题目信息，并通过`UNION`操作符将它们合并成一个结果集，最后将结果封装到`AnswerVO`对象中并通过分页的方式返回给调用者。具体功能如下：

- **查询所有题目信息**:
  - SQL语句通过`UNION`操作符合并了来自`multi_question`、`judge_question`和`fill_question`表的数据。
  - 每个子查询都选择了相同的字段，并添加了一个额外的字段`type`来区分题目类型。
  
- **分页处理**:
  - 方法接收一个`Page`对象作为参数，该对象包含了分页信息。
  - 返回的是一个`IPage<AnswerVO>`对象，其中包含了分页后的查询结果以及相关的分页信息，便于前端展示分页数据。

### 示例使用

假设有一个`AnswerService`类，它使用`AnswerMapper`来获取题目信息并进行分页处理：

```java
package com.exam.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.exam.mapper.AnswerMapper;
import com.exam.vo.AnswerVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AnswerService {

    @Autowired
    private AnswerMapper answerMapper;

    public IPage<AnswerVO> getPaginatedAnswers(int currentPage, int pageSize) {
        Page<AnswerVO> page = new Page<>(currentPage, pageSize);
        return answerMapper.findAll(page);
    }
}
```

在这个示例中，`getPaginatedAnswers`方法接收当前页码和每页大小作为参数，并使用`AnswerMapper`的`findAll`方法获取分页后的题目信息。

### 控制器示例

假设有一个`AnswerController`类，它通过`AnswerService`来处理HTTP请求并返回分页后的题目信息：

```java
package com.exam.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.exam.service.AnswerService;
import com.exam.vo.AnswerVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AnswerController {

    @Autowired
    private AnswerService answerService;

    @GetMapping("/answers")
    public Page<AnswerVO> getAnswers(@RequestParam int page, @RequestParam int size) {
        return answerService.getPaginatedAnswers(page, size);
    }
}
```

在这个示例中，`getAnswers`方法通过HTTP GET请求接收当前页码和每页大小作为参数，并调用`AnswerService`的`getPaginatedAnswers`方法获取分页后的题目信息，然后将其返回给客户端。

通过这种方式，你可以方便地实现对不同题目类型的查询和分页显示。