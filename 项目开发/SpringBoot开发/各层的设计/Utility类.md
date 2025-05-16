
# 数据校验
## 自定义类
在Spring Boot项目中，为了确保数据的有效性，通常会对输入的数据进行校验。对于邮箱、非空以及手机号的校验，可以通过创建一个工具类来集中处理这些验证逻辑。以下是如何实现这样一个工具类的示例：

### 创建验证工具类

首先，我们需要创建一个Java类，比如叫做`DataValidationUtil`，在这个类里定义静态方法来进行各种校验。

```java
import java.util.regex.Pattern;

public class DataValidationUtil {

    // 校验邮箱格式
    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern pattern = Pattern.compile(emailRegex);
        return pattern.matcher(email).matches();
    }

    // 校验是否为空或仅包含空白字符
    public static boolean isNotEmpty(String input) {
        return input != null && !input.trim().isEmpty();
    }

    // 校验手机号格式（这里以中国大陆手机号为例）
    public static boolean isValidPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isEmpty()) {
            return false;
        }
        String phoneRegex = "^1[3-9]\\d{9}$"; // 中国大陆手机号正则表达式
        Pattern pattern = Pattern.compile(phoneRegex);
        return pattern.matcher(phoneNumber).matches();
    }
}
```

### 使用示例

接下来，在需要的地方调用`ValidationUtil`中的方法来进行校验。例如，在Controller层使用它来验证用户提交的数据：

```java
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/validation")
public class ValidationController {

    @GetMapping("/check-email")
    @ResponseBody
    public String checkEmail(@RequestParam String email) {
        if (ValidationUtil.isValidEmail(email)) {
            return "邮箱格式正确";
        } else {
            return "邮箱格式不正确";
        }
    }

    @GetMapping("/check-phone")
    @ResponseBody
    public String checkPhone(@RequestParam String phone) {
        if (ValidationUtil.isValidPhoneNumber(phone)) {
            return "手机号格式正确";
        } else {
            return "手机号格式不正确";
        }
    }

    @GetMapping("/check-not-empty")
    @ResponseBody
    public String checkNotEmpty(@RequestParam String input) {
        if (ValidationUtil.isNotEmpty(input)) {
            return "输入有效";
        } else {
            return "输入不能为空";
        }
    }
}
```

这种方式将所有的校验逻辑封装在一个工具类中，不仅使得代码更加整洁和易于维护，同时也方便了复用。此外，还可以根据实际需求对`ValidationUtil`进行扩展，添加更多的校验规则。如果想要更进一步提高灵活性和可维护性，可以考虑使用注解的方式结合Hibernate Validator来完成字段级别的校验。不过，上述方式已经足够应对大多数基本的数据校验场景。


## 使用工具包
在Spring Boot项目中，确实有专门的工具包用于数据校验，最常用的就是Hibernate Validator，它是Bean Validation规范（JSR 303/JSR 380）的一个实现。通过使用这些工具包，你可以轻松地为你的Java Bean添加各种约束注解来完成数据校验。

### Hibernate Validator 常用注解

以下是一些常用的校验注解：

- `@NotNull`: 验证字段不为null。
- `@NotEmpty`: 验证字符串、集合等不为null且长度大于0。
- `@NotBlank`: 验证字符串不为null且去掉空白字符后的长度大于0。
- `@Email`: 验证是否是合法的电子邮件地址。
- `@Pattern`: 使用正则表达式进行验证。
- `@Size`: 检查字符串或集合的大小是否在给定范围内。
- `@Min`, `@Max`: 对数值类型的最小值和最大值进行限制。
- `@Digits`: 确保数字具有指定精度。
- `@AssertTrue`, `@AssertFalse`: 确保布尔值符合预期。

### 如何集成到Spring Boot项目中

首先，在`pom.xml`文件中添加依赖项：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

如果你使用的Spring Boot版本低于2.3.x，则需要引入`spring-boot-starter-web`依赖，因为那时校验功能包含在web启动器中：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

### 实际应用例子

定义一个带有校验注解的DTO类：

```java
import javax.validation.constraints.*;

public class UserDTO {

    @NotBlank(message = "姓名不能为空")
    private String name;

    @Email(message = "邮箱格式不正确")
    @NotBlank(message = "邮箱不能为空")
    private String email;

    @Pattern(regexp="^1[3-9]\\d{9}$", message="手机号码格式不正确")
    @NotBlank(message = "手机号码不能为空")
    private String phone;

    // Getters and setters...
}
```

然后，在Controller层使用`@Valid`或`@Validated`注解触发校验：

```java
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Validated
public class UserController {

    @PostMapping("/create")
    public ResponseEntity<String> createUser(@Valid @RequestBody UserDTO userDTO) {
        // 如果校验失败，会抛出MethodArgumentNotValidException异常
        return ResponseEntity.ok("用户创建成功");
    }
}
```

最后，为了处理校验失败的情况，可以使用全局异常处理器捕获`MethodArgumentNotValidException`并返回适当的错误信息给客户端。
