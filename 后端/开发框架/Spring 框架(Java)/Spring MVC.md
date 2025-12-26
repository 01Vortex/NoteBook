

> 基于 Java 8 + Spring Boot 2.7.18，从零开始系统学习 Spring MVC。本笔记包含详细的概念讲解、代码示例和常见错误分析，帮助你真正掌握 Web 开发的核心技术。

---

## 目录

1. [Spring MVC 概述](#1.spring-mvc-概述)
2. [快速入门](#2.快速入门)
3. [控制器（Controller）](#3.控制器controller)
4. [请求映射](#4.请求映射)
5. [参数绑定](#5.参数绑定)
6. [数据校验](#6.数据校验)
7. [响应处理](#7.响应处理)
8. [异常处理](#8.异常处理)
9. [拦截器](#9.拦截器)
10. [过滤器](#10.过滤器)
11. [文件上传下载](#11.文件上传下载)
12. [跨域处理](#12.跨域处理)
13. [RESTful API 设计](#13.restful-api-设计)
14. [统一响应封装](#14.统一响应封装)
15. [常见错误与解决](#15.常见错误与解决)
16. [最佳实践](#16.最佳实践)

---

## 1. Spring MVC 概述

### 1.1 什么是 Spring MVC？

Spring MVC 是 Spring Framework 中的 Web 模块，是一个基于 **MVC（Model-View-Controller）** 设计模式的 Web 框架。

**MVC 模式解释：**

想象你去餐厅吃饭：
- **Controller（控制器）**：服务员，接收你的点单请求，协调厨房和上菜
- **Model（模型）**：厨房，处理业务逻辑，准备菜品（数据）
- **View（视图）**：餐盘和摆盘，把菜品呈现给你

```
用户请求 → Controller（接收请求）→ Model（处理业务）→ View（渲染响应）→ 返回用户
```

### 1.2 Spring MVC 的核心组件

| 组件 | 说明 | 作用 |
|------|------|------|
| DispatcherServlet | 前端控制器 | 接收所有请求，统一分发 |
| HandlerMapping | 处理器映射器 | 根据 URL 找到对应的 Controller |
| HandlerAdapter | 处理器适配器 | 调用 Controller 方法 |
| Controller | 控制器 | 处理请求，返回数据或视图 |
| ViewResolver | 视图解析器 | 解析视图名称，渲染页面 |
| HandlerInterceptor | 拦截器 | 请求前后的拦截处理 |

### 1.3 请求处理流程

```
1. 用户发送请求到 DispatcherServlet
2. DispatcherServlet 调用 HandlerMapping 查找 Handler
3. HandlerMapping 返回 HandlerExecutionChain（Handler + 拦截器）
4. DispatcherServlet 调用 HandlerAdapter 执行 Handler
5. Handler（Controller）执行业务逻辑，返回 ModelAndView
6. DispatcherServlet 调用 ViewResolver 解析视图
7. ViewResolver 返回 View 对象
8. DispatcherServlet 渲染视图，返回响应
```

**简化理解：**
```
请求 → DispatcherServlet → 找 Controller → 执行方法 → 返回结果 → 响应
```

### 1.4 Spring MVC vs Spring Boot

| 对比项 | 传统 Spring MVC | Spring Boot |
|--------|----------------|-------------|
| 配置方式 | XML + 注解 | 自动配置 + 注解 |
| 服务器 | 需要外部 Tomcat | 内嵌 Tomcat |
| 依赖管理 | 手动管理版本 | starter 自动管理 |
| 启动方式 | 部署 WAR 包 | 直接运行 JAR |

Spring Boot 本质上是对 Spring MVC 的封装和简化，底层原理是一样的。

---

## 2. 快速入门

### 2.1 创建项目

**Maven 依赖（pom.xml）：**

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
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>springmvc-demo</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>1.8</java.version>
    </properties>
    
    <dependencies>
        <!-- Spring Boot Web Starter（包含 Spring MVC） -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- 参数校验 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <!-- Lombok（简化代码） -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <!-- 测试 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

### 2.2 启动类

```java
package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 2.3 第一个 Controller

```java
package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController  // 标记为 REST 控制器，返回 JSON 数据
public class HelloController {
    
    @GetMapping("/hello")  // 处理 GET /hello 请求
    public String hello() {
        return "Hello, Spring MVC!";
    }
}
```

### 2.4 配置文件

```yaml
# application.ym
server:
  port: 8080                    # 服务端口
  servlet:
    context-path: /api          # 上下文路径，所有请求都要加 /api 前缀

spring:
  application:
    name: springmvc-demo
  mvc:
    throw-exception-if-no-handler-found: true  # 找不到处理器时抛异常
  web:
    resources:
      add-mappings: false       # 不处理静态资源（纯 API 项目）
```

### 2.5 运行测试

启动应用后，访问：`http://localhost:8080/api/hello`

返回：`Hello, Spring MVC!`

---

## 3. 控制器（Controller）

### 3.1 @Controller vs @RestController

```java
// ============ @Controller：返回视图 ============
@Controller
public class PageController {
    
    @GetMapping("/home")
    public String home(Model model) {
        model.addAttribute("message", "欢迎");
        return "home";  // 返回视图名称，由视图解析器解析为 home.html
    }
    
    // 如果要返回 JSON，需要加 @ResponseBody
    @GetMapping("/data")
    @ResponseBody
    public User getData() {
        return new User("张三", 25);
    }
}

// ============ @RestController：返回 JSON ============
// @RestController = @Controller + @ResponseBody
@RestController
public class ApiController {
    
    @GetMapping("/user")
    public User getUser() {
        return new User("张三", 25);  // 自动转为 JSON
    }
}
```

**选择建议：**
- 前后端分离项目：使用 `@RestController`
- 传统 MVC 项目（返回页面）：使用 `@Controller`

### 3.2 @RequestMapping

`@RequestMapping` 是最基础的请求映射注解，可以用在类和方法上。

```java
@RestController
@RequestMapping("/users")  // 类级别：所有方法的 URL 都以 /users 开头
public class UserController {
    
    // 完整路径：GET /users
    @RequestMapping(method = RequestMethod.GET)
    public List<User> list() {
        return userService.findAll();
    }
    
    // 完整路径：POST /users
    @RequestMapping(method = RequestMethod.POST)
    public User create(@RequestBody User user) {
        return userService.save(user);
    }
    
    // 完整路径：GET /users/123
    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public User getById(@PathVariable Long id) {
        return userService.findById(id);
    }
}
```

### 3.3 快捷注解

Spring 4.3 引入了更简洁的快捷注解：

| 注解 | 等价于 |
|------|--------|
| `@GetMapping` | `@RequestMapping(method = GET)` |
| `@PostMapping` | `@RequestMapping(method = POST)` |
| `@PutMapping` | `@RequestMapping(method = PUT)` |
| `@DeleteMapping` | `@RequestMapping(method = DELETE)` |
| `@PatchMapping` | `@RequestMapping(method = PATCH)` |

```java
@RestController
@RequestMapping("/users")
public class UserController {
    
    @GetMapping                    // GET /users
    public List<User> list() { }
    
    @GetMapping("/{id}")           // GET /users/123
    public User getById(@PathVariable Long id) { }
    
    @PostMapping                   // POST /users
    public User create(@RequestBody User user) { }
    
    @PutMapping("/{id}")           // PUT /users/123
    public User update(@PathVariable Long id, @RequestBody User user) { }
    
    @DeleteMapping("/{id}")        // DELETE /users/123
    public void delete(@PathVariable Long id) { }
}
```

---

## 4. 请求映射

### 4.1 URL 路径映射

```java
@RestController
public class MappingController {
    
    // ============ 精确匹配 ============
    @GetMapping("/users")
    public String exactMatch() {
        return "精确匹配 /users";
    }
    
    // ============ 路径变量 ============
    @GetMapping("/users/{id}")
    public String pathVariable(@PathVariable Long id) {
        return "用户ID: " + id;
    }
    
    // 多个路径变量
    @GetMapping("/users/{userId}/orders/{orderId}")
    public String multiPathVariable(
            @PathVariable Long userId,
            @PathVariable Long orderId) {
        return "用户: " + userId + ", 订单: " + orderId;
    }
    
    // 路径变量使用正则表达式
    @GetMapping("/files/{filename:.+}")  // 匹配带扩展名的文件
    public String fileWithExtension(@PathVariable String filename) {
        return "文件: " + filename;  // 如 report.pdf
    }
    
    // ============ 通配符匹配 ============
    @GetMapping("/docs/*")      // 匹配 /docs/xxx（单层）
    public String singleWildcard() {
        return "单层通配符";
    }
    
    @GetMapping("/files/**")    // 匹配 /files/xxx/yyy（多层）
    public String multiWildcard() {
        return "多层通配符";
    }
    
    // ============ 多路径映射 ============
    @GetMapping({"/home", "/index", "/"})
    public String multiPath() {
        return "首页";
    }
}
```

### 4.2 请求参数条件

```java
@RestController
@RequestMapping("/api")
public class ConditionController {
    
    // ============ 必须包含某参数 ============
    @GetMapping(value = "/search", params = "keyword")
    public String searchWithKeyword(@RequestParam String keyword) {
        return "搜索: " + keyword;
    }
    
    // 参数必须等于某值
    @GetMapping(value = "/search", params = "type=advanced")
    public String advancedSearch() {
        return "高级搜索";
    }
    
    // 参数不能存在
    @GetMapping(value = "/search", params = "!debug")
    public String searchWithoutDebug() {
        return "非调试模式搜索";
    }
    
    // ============ 请求头条件 ============
    @GetMapping(value = "/data", headers = "X-API-Version=1")
    public String apiV1() {
        return "API V1";
    }
    
    @GetMapping(value = "/data", headers = "X-API-Version=2")
    public String apiV2() {
        return "API V2";
    }
    
    // ============ Content-Type 条件 ============
    @PostMapping(value = "/upload", consumes = "multipart/form-data")
    public String uploadFile() {
        return "文件上传";
    }
    
    @PostMapping(value = "/data", consumes = "application/json")
    public String jsonData(@RequestBody Map<String, Object> data) {
        return "JSON 数据";
    }
    
    // ============ Accept 条件 ============
    @GetMapping(value = "/report", produces = "application/json")
    public Map<String, Object> jsonReport() {
        return Map.of("type", "json");
    }
    
    @GetMapping(value = "/report", produces = "application/xml")
    public String xmlReport() {
        return "<report><type>xml</type></report>";
    }
}
```


---

## 5. 参数绑定

### 5.1 参数绑定概述

Spring MVC 可以自动将请求中的数据绑定到方法参数上，这是最常用的功能之一。

**支持的参数来源：**
- URL 路径参数（`/users/{id}`）
- 查询参数（`?name=张三&age=25`）
- 请求体（JSON、表单）
- 请求头
- Cookie

### 5.2 @PathVariable（路径参数）

从 URL 路径中提取参数。

```java
@RestController
@RequestMapping("/users")
public class UserController {
    
    // 基本用法
    @GetMapping("/{id}")
    public User getById(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    // 参数名不一致时，指定名称
    @GetMapping("/{userId}/orders/{orderId}")
    public Order getOrder(
            @PathVariable("userId") Long uid,
            @PathVariable("orderId") Long oid) {
        return orderService.findByUserAndId(uid, oid);
    }
    
    // 可选路径参数（Spring 4.3.3+）
    @GetMapping({"/profile", "/profile/{section}"})
    public String profile(@PathVariable(required = false) String section) {
        return section != null ? "查看: " + section : "查看全部";
    }
    
    // 获取所有路径变量
    @GetMapping("/{type}/{id}")
    public String allPathVars(@PathVariable Map<String, String> pathVars) {
        return "type=" + pathVars.get("type") + ", id=" + pathVars.get("id");
    }
}
```

### 5.3 @RequestParam（查询参数）

从 URL 查询字符串或表单数据中获取参数。

```java
@RestController
@RequestMapping("/api")
public class SearchController {
    
    // 基本用法：GET /api/search?keyword=spring
    @GetMapping("/search")
    public List<Article> search(@RequestParam String keyword) {
        return articleService.search(keyword);
    }
    
    // 可选参数 + 默认值
    @GetMapping("/users")
    public Page<User> listUsers(
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(required = false) String keyword) {
        return userService.findPage(page, size, keyword);
    }
    
    // 参数名不一致
    @GetMapping("/products")
    public List<Product> listProducts(
            @RequestParam("category_id") Long categoryId) {
        return productService.findByCategory(categoryId);
    }
    
    // 接收数组：GET /api/items?ids=1&ids=2&ids=3
    @GetMapping("/items")
    public List<Item> getItems(@RequestParam List<Long> ids) {
        return itemService.findByIds(ids);
    }
    
    // 接收所有参数
    @GetMapping("/filter")
    public List<Product> filter(@RequestParam Map<String, String> params) {
        return productService.filter(params);
    }
    
    // 接收多值参数
    @GetMapping("/multi")
    public String multi(@RequestParam MultiValueMap<String, String> params) {
        // MultiValueMap 可以处理同名多值参数
        List<String> tags = params.get("tag");  // tag=a&tag=b&tag=c
        return "tags: " + tags;
    }
}
```

### 5.4 @RequestBody（请求体）

接收 JSON 或 XML 格式的请求体，自动反序列化为对象。

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // 接收 JSON 对象
    @PostMapping
    public User create(@RequestBody UserDTO userDTO) {
        return userService.create(userDTO);
    }
    
    // 接收 JSON 数组
    @PostMapping("/batch")
    public List<User> batchCreate(@RequestBody List<UserDTO> userDTOs) {
        return userService.batchCreate(userDTOs);
    }
    
    // 接收为 Map（不确定结构时）
    @PostMapping("/dynamic")
    public String dynamic(@RequestBody Map<String, Object> data) {
        String name = (String) data.get("name");
        Integer age = (Integer) data.get("age");
        return "name=" + name + ", age=" + age;
    }
    
    // 接收原始 JSON 字符串
    @PostMapping("/raw")
    public String raw(@RequestBody String json) {
        return "收到: " + json;
    }
}

// DTO 类
@Data
public class UserDTO {
    private String username;
    private String email;
    private Integer age;
    private List<String> roles;
}
```

**注意：** `@RequestBody` 只能用一次，因为请求体只能读取一次。

### 5.5 @RequestHeader（请求头）

```java
@RestController
public class HeaderController {
    
    // 获取单个请求头
    @GetMapping("/info")
    public String info(
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("Accept-Language") String language) {
        return "UA: " + userAgent + ", Lang: " + language;
    }
    
    // 可选请求头
    @GetMapping("/auth")
    public String auth(
            @RequestHeader(value = "Authorization", required = false) String token) {
        return token != null ? "已认证" : "未认证";
    }
    
    // 获取所有请求头
    @GetMapping("/headers")
    public Map<String, String> allHeaders(@RequestHeader Map<String, String> headers) {
        return headers;
    }
    
    // 使用 HttpHeaders 对象
    @GetMapping("/http-headers")
    public String httpHeaders(@RequestHeader HttpHeaders headers) {
        return "Content-Type: " + headers.getContentType();
    }
}
```

### 5.6 @CookieValue（Cookie）

```java
@RestController
public class CookieController {
    
    // 获取 Cookie
    @GetMapping("/session")
    public String session(@CookieValue("JSESSIONID") String sessionId) {
        return "Session: " + sessionId;
    }
    
    // 可选 Cookie
    @GetMapping("/theme")
    public String theme(
            @CookieValue(value = "theme", defaultValue = "light") String theme) {
        return "主题: " + theme;
    }
    
    // 获取完整 Cookie 对象
    @GetMapping("/cookie-detail")
    public String cookieDetail(@CookieValue("token") Cookie cookie) {
        return "name=" + cookie.getName() + 
               ", value=" + cookie.getValue() + 
               ", maxAge=" + cookie.getMaxAge();
    }
}
```

### 5.7 @ModelAttribute（表单/对象绑定）

将请求参数绑定到对象，常用于表单提交。

```java
@RestController
@RequestMapping("/api")
public class FormController {
    
    // 自动绑定查询参数到对象
    // GET /api/search?keyword=spring&page=1&size=10
    @GetMapping("/search")
    public Page<Article> search(@ModelAttribute SearchQuery query) {
        return articleService.search(query);
    }
    
    // 表单提交（application/x-www-form-urlencoded）
    @PostMapping("/login")
    public String login(@ModelAttribute LoginForm form) {
        return "用户: " + form.getUsername();
    }
    
    // @ModelAttribute 可以省略
    @GetMapping("/users")
    public List<User> listUsers(UserQuery query) {  // 自动绑定
        return userService.findByQuery(query);
    }
}

@Data
public class SearchQuery {
    private String keyword;
    private Integer page = 1;
    private Integer size = 10;
    private String sortBy;
    private String sortOrder;
}

@Data
public class LoginForm {
    private String username;
    private String password;
    private Boolean rememberMe;
}
```

### 5.8 Servlet API 参数

可以直接注入 Servlet API 对象。

```java
@RestController
public class ServletApiController {
    
    @GetMapping("/servlet")
    public String servlet(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpSession session) {
        
        // 获取请求信息
        String ip = request.getRemoteAddr();
        String method = request.getMethod();
        
        // 设置响应头
        response.setHeader("X-Custom-Header", "value");
        
        // 操作 Session
        session.setAttribute("user", "张三");
        
        return "IP: " + ip + ", Method: " + method;
    }
    
    // 获取请求 URI 信息
    @GetMapping("/uri-info")
    public Map<String, String> uriInfo(HttpServletRequest request) {
        Map<String, String> info = new HashMap<>();
        info.put("requestURI", request.getRequestURI());
        info.put("requestURL", request.getRequestURL().toString());
        info.put("contextPath", request.getContextPath());
        info.put("servletPath", request.getServletPath());
        info.put("queryString", request.getQueryString());
        return info;
    }
}
```

### 5.9 日期参数处理

日期参数需要特殊处理，否则会报错。

```java
@RestController
@RequestMapping("/api")
public class DateController {
    
    // 方式1：使用 @DateTimeFormat
    @GetMapping("/events")
    public List<Event> getEvents(
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd") LocalDate date,
            @RequestParam @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss") LocalDateTime dateTime) {
        return eventService.findByDate(date);
    }
    
    // 方式2：使用 ISO 标准格式
    @GetMapping("/events-iso")
    public List<Event> getEventsIso(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime dateTime) {
        return eventService.findByDate(date);
    }
}

// 方式3：全局配置（推荐）
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addFormatters(FormatterRegistry registry) {
        DateTimeFormatterRegistrar registrar = new DateTimeFormatterRegistrar();
        registrar.setDateFormatter(DateTimeFormatter.ofPattern("yyyy-MM-dd"));
        registrar.setDateTimeFormatter(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        registrar.registerFormatters(registry);
    }
}

// 方式4：JSON 日期格式（application.yml）
// spring:
//   jackson:
//     date-format: yyyy-MM-dd HH:mm:ss
//     time-zone: GMT+8
```

### 5.10 参数绑定常见错误

#### 错误1：参数类型不匹配

```
Failed to convert value of type 'java.lang.String' to required type 'java.lang.Long'
```

**原因：** 传入的参数无法转换为目标类型

**解决：** 检查参数值是否正确，或添加异常处理

```java
@ExceptionHandler(MethodArgumentTypeMismatchException.class)
public Result<?> handleTypeMismatch(MethodArgumentTypeMismatchException e) {
    return Result.error("参数类型错误: " + e.getName());
}
```

#### 错误2：必需参数缺失

```
Required request parameter 'id' is not present
```

**解决：** 设置 `required = false` 或提供默认值

```java
@GetMapping("/user")
public User getUser(@RequestParam(required = false, defaultValue = "0") Long id) {
    return userService.findById(id);
}
```

#### 错误3：JSON 反序列化失败

```
JSON parse error: Cannot deserialize value of type `java.time.LocalDateTime`
```

**解决：** 配置 Jackson 日期格式

```java
@Data
public class EventDTO {
    private String name;
    
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime startTime;
}
```

---

## 6. 数据校验

### 6.1 校验注解

Spring Boot 2.3+ 需要单独引入 validation starter：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

**常用校验注解：**

| 注解 | 说明 | 示例 |
|------|------|------|
| `@NotNull` | 不能为 null | `@NotNull Long id` |
| `@NotEmpty` | 不能为 null 且不能为空（字符串、集合） | `@NotEmpty String name` |
| `@NotBlank` | 不能为 null 且去空格后长度 > 0 | `@NotBlank String name` |
| `@Size` | 长度/大小范围 | `@Size(min=2, max=20)` |
| `@Min` / `@Max` | 数值范围 | `@Min(0) @Max(100)` |
| `@Email` | 邮箱格式 | `@Email String email` |
| `@Pattern` | 正则匹配 | `@Pattern(regexp="^1[3-9]\\d{9}$")` |
| `@Past` / `@Future` | 过去/未来的日期 | `@Past LocalDate birthday` |
| `@Positive` | 正数 | `@Positive Integer count` |
| `@Valid` | 嵌套校验 | `@Valid Address address` |

### 6.2 基本使用

```java
// ============ DTO 类 ============
@Data
public class UserDTO {
    
    @NotBlank(message = "用户名不能为空")
    @Size(min = 2, max = 20, message = "用户名长度必须在2-20之间")
    private String username;
    
    @NotBlank(message = "密码不能为空")
    @Size(min = 6, max = 20, message = "密码长度必须在6-20之间")
    private String password;
    
    @NotBlank(message = "邮箱不能为空")
    @Email(message = "邮箱格式不正确")
    private String email;
    
    @NotNull(message = "年龄不能为空")
    @Min(value = 0, message = "年龄不能小于0")
    @Max(value = 150, message = "年龄不能大于150")
    private Integer age;
    
    @Pattern(regexp = "^1[3-9]\\d{9}$", message = "手机号格式不正确")
    private String phone;
    
    @Past(message = "生日必须是过去的日期")
    private LocalDate birthday;
    
    // 嵌套校验
    @Valid
    @NotNull(message = "地址不能为空")
    private AddressDTO address;
}

@Data
public class AddressDTO {
    @NotBlank(message = "省份不能为空")
    private String province;
    
    @NotBlank(message = "城市不能为空")
    private String city;
    
    @NotBlank(message = "详细地址不能为空")
    private String detail;
}

// ============ Controller ============
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // 使用 @Valid 或 @Validated 触发校验
    @PostMapping
    public Result<User> create(@Valid @RequestBody UserDTO userDTO) {
        User user = userService.create(userDTO);
        return Result.success(user);
    }
    
    // 校验路径参数
    @GetMapping("/{id}")
    public Result<User> getById(
            @PathVariable @Min(value = 1, message = "ID必须大于0") Long id) {
        return Result.success(userService.findById(id));
    }
    
    // 校验查询参数
    @GetMapping
    public Result<Page<User>> list(
            @RequestParam @Min(1) Integer page,
            @RequestParam @Min(1) @Max(100) Integer size) {
        return Result.success(userService.findPage(page, size));
    }
}
```

**注意：** 校验路径参数和查询参数时，需要在 Controller 类上添加 `@Validated`：

```java
@RestController
@RequestMapping("/api/users")
@Validated  // 必须添加这个注解
public class UserController {
    // ...
}
```

### 6.3 分组校验

不同场景使用不同的校验规则。

```java
// ============ 定义分组接口 ============
public interface ValidationGroups {
    interface Create {}
    interface Update {}
}

// ============ DTO 使用分组 ============
@Data
public class UserDTO {
    
    @Null(groups = Create.class, message = "创建时不能指定ID")
    @NotNull(groups = Update.class, message = "更新时必须指定ID")
    private Long id;
    
    @NotBlank(groups = {Create.class, Update.class}, message = "用户名不能为空")
    private String username;
    
    @NotBlank(groups = Create.class, message = "创建时密码不能为空")
    private String password;
}

// ============ Controller 指定分组 ============
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @PostMapping
    public Result<User> create(
            @Validated(Create.class) @RequestBody UserDTO userDTO) {
        return Result.success(userService.create(userDTO));
    }
    
    @PutMapping("/{id}")
    public Result<User> update(
            @PathVariable Long id,
            @Validated(Update.class) @RequestBody UserDTO userDTO) {
        return Result.success(userService.update(id, userDTO));
    }
}
```

### 6.4 自定义校验注解

```java
// ============ 自定义注解 ============
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PhoneValidator.class)
public @interface Phone {
    String message() default "手机号格式不正确";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

// ============ 校验器实现 ============
public class PhoneValidator implements ConstraintValidator<Phone, String> {
    
    private static final Pattern PHONE_PATTERN = Pattern.compile("^1[3-9]\\d{9}$");
    
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isEmpty()) {
            return true;  // 空值由 @NotBlank 处理
        }
        return PHONE_PATTERN.matcher(value).matches();
    }
}

// ============ 使用 ============
@Data
public class UserDTO {
    @Phone
    private String phone;
}
```

### 6.5 校验异常处理

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    
    /**
     * 处理 @RequestBody 参数校验异常
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<?> handleValidException(MethodArgumentNotValidException e) {
        List<String> errors = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.toList());
        return Result.error(400, "参数校验失败", errors);
    }
    
    /**
     * 处理 @PathVariable 和 @RequestParam 参数校验异常
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public Result<?> handleConstraintViolation(ConstraintViolationException e) {
        List<String> errors = e.getConstraintViolations().stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .collect(Collectors.toList());
        return Result.error(400, "参数校验失败", errors);
    }
    
    /**
     * 处理参数绑定异常
     */
    @ExceptionHandler(BindException.class)
    public Result<?> handleBindException(BindException e) {
        List<String> errors = e.getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.toList());
        return Result.error(400, "参数绑定失败", errors);
    }
}
```


---

## 7. 响应处理

### 7.1 返回 JSON

Spring MVC 默认使用 Jackson 进行 JSON 序列化。

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // 返回对象，自动转为 JSON
    @GetMapping("/{id}")
    public User getById(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    // 返回集合
    @GetMapping
    public List<User> list() {
        return userService.findAll();
    }
    
    // 返回 Map
    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total", userService.count());
        stats.put("active", userService.countActive());
        return stats;
    }
}
```

### 7.2 Jackson 序列化配置

```java
// ============ 实体类注解配置 ============
@Data
public class User {
    
    private Long id;
    
    private String username;
    
    @JsonIgnore  // 不序列化此字段
    private String password;
    
    @JsonProperty("mail")  // 序列化时使用别名
    private String email;
    
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "GMT+8")
    private LocalDateTime createTime;
    
    @JsonInclude(JsonInclude.Include.NON_NULL)  // 为 null 时不序列化
    private String remark;
}

// ============ 全局配置（application.yml） ============
// spring:
//   jackson:
//     date-format: yyyy-MM-dd HH:mm:ss
//     time-zone: GMT+8
//     default-property-inclusion: non_null  # 全局忽略 null 值
//     serialization:
//       write-dates-as-timestamps: false    # 日期不转时间戳

// ============ Java 配置类 ============
@Configuration
public class JacksonConfig {
    
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        
        // 日期格式
        mapper.setDateFormat(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"));
        mapper.setTimeZone(TimeZone.getTimeZone("GMT+8"));
        
        // 忽略 null 值
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        // 忽略未知属性
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        
        // 支持 Java 8 日期
        mapper.registerModule(new JavaTimeModule());
        
        return mapper;
    }
}
```

### 7.3 ResponseEntity

`ResponseEntity` 可以完全控制 HTTP 响应，包括状态码、响应头和响应体。

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // 返回指定状态码
    @PostMapping
    public ResponseEntity<User> create(@RequestBody UserDTO dto) {
        User user = userService.create(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
    
    // 简写方式
    @PostMapping("/v2")
    public ResponseEntity<User> createV2(@RequestBody UserDTO dto) {
        User user = userService.create(dto);
        return ResponseEntity.created(URI.create("/api/users/" + user.getId()))
                            .body(user);
    }
    
    // 返回 404
    @GetMapping("/{id}")
    public ResponseEntity<User> getById(@PathVariable Long id) {
        User user = userService.findById(id);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(user);
    }
    
    // 设置响应头
    @GetMapping("/export")
    public ResponseEntity<byte[]> export() {
        byte[] data = userService.exportExcel();
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", "users.xlsx");
        
        return new ResponseEntity<>(data, headers, HttpStatus.OK);
    }
    
    // 无内容响应
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

### 7.4 设置响应头和 Cookie

```java
@RestController
public class ResponseController {
    
    // 通过 HttpServletResponse 设置
    @GetMapping("/custom-header")
    public String customHeader(HttpServletResponse response) {
        response.setHeader("X-Custom-Header", "custom-value");
        response.setHeader("Cache-Control", "no-cache");
        return "success";
    }
    
    // 设置 Cookie
    @GetMapping("/set-cookie")
    public String setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("token", "abc123");
        cookie.setMaxAge(3600);      // 1小时
        cookie.setPath("/");
        cookie.setHttpOnly(true);    // 防止 XSS
        cookie.setSecure(false);     // 生产环境设为 true
        response.addCookie(cookie);
        return "Cookie 已设置";
    }
    
    // 删除 Cookie
    @GetMapping("/delete-cookie")
    public String deleteCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("token", null);
        cookie.setMaxAge(0);  // 立即过期
        cookie.setPath("/");
        response.addCookie(cookie);
        return "Cookie 已删除";
    }
}
```

---

## 8. 异常处理

### 8.1 全局异常处理

使用 `@RestControllerAdvice` 统一处理所有 Controller 的异常。

```java
// ============ 自定义业务异常 ============
@Getter
public class BusinessException extends RuntimeException {
    
    private final Integer code;
    
    public BusinessException(String message) {
        super(message);
        this.code = 500;
    }
    
    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
    }
}

// ============ 全局异常处理器 ============
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    /**
     * 处理业务异常
     */
    @ExceptionHandler(BusinessException.class)
    public Result<?> handleBusinessException(BusinessException e) {
        log.warn("业务异常: {}", e.getMessage());
        return Result.error(e.getCode(), e.getMessage());
    }
    
    /**
     * 处理参数校验异常（@RequestBody）
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<?> handleValidException(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        log.warn("参数校验失败: {}", message);
        return Result.error(400, message);
    }
    
    /**
     * 处理参数校验异常（@PathVariable, @RequestParam）
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public Result<?> handleConstraintViolation(ConstraintViolationException e) {
        String message = e.getConstraintViolations().stream()
                .map(ConstraintViolation::getMessage)
                .collect(Collectors.joining("; "));
        return Result.error(400, message);
    }
    
    /**
     * 处理参数类型不匹配
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public Result<?> handleTypeMismatch(MethodArgumentTypeMismatchException e) {
        return Result.error(400, "参数类型错误: " + e.getName());
    }
    
    /**
     * 处理请求方法不支持
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public Result<?> handleMethodNotSupported(HttpRequestMethodNotSupportedException e) {
        return Result.error(405, "不支持的请求方法: " + e.getMethod());
    }
    
    /**
     * 处理请求体缺失
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public Result<?> handleMessageNotReadable(HttpMessageNotReadableException e) {
        return Result.error(400, "请求体格式错误");
    }
    
    /**
     * 处理资源不存在
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public Result<?> handleNoHandlerFound(NoHandlerFoundException e) {
        return Result.error(404, "接口不存在: " + e.getRequestURL());
    }
    
    /**
     * 处理所有其他异常
     */
    @ExceptionHandler(Exception.class)
    public Result<?> handleException(Exception e) {
        log.error("系统异常", e);
        return Result.error(500, "系统繁忙，请稍后重试");
    }
}
```

### 8.2 针对特定 Controller 的异常处理

```java
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    
    // 只处理当前 Controller 的异常
    @ExceptionHandler(OrderNotFoundException.class)
    public Result<?> handleOrderNotFound(OrderNotFoundException e) {
        return Result.error(404, "订单不存在: " + e.getOrderId());
    }
    
    @GetMapping("/{id}")
    public Order getById(@PathVariable Long id) {
        Order order = orderService.findById(id);
        if (order == null) {
            throw new OrderNotFoundException(id);
        }
        return order;
    }
}
```

### 8.3 异常处理最佳实践

```java
// ============ 统一异常码枚举 ============
@Getter
@AllArgsConstructor
public enum ErrorCode {
    
    SUCCESS(200, "成功"),
    BAD_REQUEST(400, "请求参数错误"),
    UNAUTHORIZED(401, "未登录"),
    FORBIDDEN(403, "无权限"),
    NOT_FOUND(404, "资源不存在"),
    INTERNAL_ERROR(500, "系统内部错误"),
    
    // 业务错误码（1000+）
    USER_NOT_FOUND(1001, "用户不存在"),
    USER_ALREADY_EXISTS(1002, "用户已存在"),
    PASSWORD_ERROR(1003, "密码错误"),
    ORDER_NOT_FOUND(2001, "订单不存在"),
    STOCK_NOT_ENOUGH(2002, "库存不足");
    
    private final Integer code;
    private final String message;
}

// ============ 业务异常使用枚举 ============
public class BusinessException extends RuntimeException {
    
    private final ErrorCode errorCode;
    
    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
    
    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public Integer getCode() {
        return errorCode.getCode();
    }
}

// ============ 使用示例 ============
@Service
public class UserService {
    
    public User findById(Long id) {
        User user = userDao.findById(id);
        if (user == null) {
            throw new BusinessException(ErrorCode.USER_NOT_FOUND);
        }
        return user;
    }
}
```


---

## 9. 拦截器

### 9.1 拦截器概述

拦截器（Interceptor）是 Spring MVC 提供的机制，可以在请求处理的不同阶段进行拦截处理。

**拦截器 vs 过滤器：**

| 对比项 | 拦截器（Interceptor） | 过滤器（Filter） |
|--------|----------------------|------------------|
| 规范 | Spring MVC | Servlet |
| 作用范围 | Controller 方法 | 所有请求 |
| 获取信息 | 可以获取 Handler 信息 | 只能获取请求/响应 |
| 依赖注入 | 支持 | 需要特殊处理 |
| 执行顺序 | 在 DispatcherServlet 之后 | 在 DispatcherServlet 之前 |

### 9.2 创建拦截器

```java
@Component
@Slf4j
public class LoggingInterceptor implements HandlerInterceptor {
    
    /**
     * 请求处理前调用
     * 返回 true 继续执行，返回 false 中断请求
     */
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        // 记录请求开始时间
        request.setAttribute("startTime", System.currentTimeMillis());
        
        log.info("请求开始: {} {}", request.getMethod(), request.getRequestURI());
        
        // 可以在这里做权限校验
        // if (!checkAuth(request)) {
        //     response.sendError(401, "未授权");
        //     return false;
        // }
        
        return true;  // 继续执行
    }
    
    /**
     * 请求处理后、视图渲染前调用
     * 只有 preHandle 返回 true 才会执行
     */
    @Override
    public void postHandle(HttpServletRequest request, 
                          HttpServletResponse response, 
                          Object handler, 
                          ModelAndView modelAndView) throws Exception {
        log.info("请求处理完成，准备渲染视图");
    }
    
    /**
     * 请求完成后调用（包括异常情况）
     * 类似 finally，用于资源清理
     */
    @Override
    public void afterCompletion(HttpServletRequest request, 
                               HttpServletResponse response, 
                               Object handler, 
                               Exception ex) throws Exception {
        long startTime = (Long) request.getAttribute("startTime");
        long duration = System.currentTimeMillis() - startTime;
        
        log.info("请求结束: {} {} 耗时: {}ms", 
                request.getMethod(), request.getRequestURI(), duration);
        
        if (ex != null) {
            log.error("请求异常", ex);
        }
    }
}
```

### 9.3 注册拦截器

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Autowired
    private LoggingInterceptor loggingInterceptor;
    
    @Autowired
    private AuthInterceptor authInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 日志拦截器：拦截所有请求
        registry.addInterceptor(loggingInterceptor)
                .addPathPatterns("/**");
        
        // 认证拦截器：拦截需要登录的接口
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/**")           // 拦截的路径
                .excludePathPatterns(                  // 排除的路径
                    "/api/auth/login",
                    "/api/auth/register",
                    "/api/public/**"
                )
                .order(1);  // 执行顺序，数字越小越先执行
    }
}
```

### 9.4 认证拦截器示例

```java
@Component
@Slf4j
public class AuthInterceptor implements HandlerInterceptor {
    
    @Autowired
    private JwtUtils jwtUtils;
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        // 放行 OPTIONS 请求（跨域预检）
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        
        // 检查是否需要认证
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            
            // 检查方法或类上是否有 @NoAuth 注解
            if (handlerMethod.hasMethodAnnotation(NoAuth.class) ||
                handlerMethod.getBeanType().isAnnotationPresent(NoAuth.class)) {
                return true;  // 不需要认证
            }
        }
        
        // 获取 Token
        String token = request.getHeader("Authorization");
        if (token == null || !token.startsWith("Bearer ")) {
            sendError(response, 401, "请先登录");
            return false;
        }
        
        token = token.substring(7);
        
        // 验证 Token
        try {
            String userId = jwtUtils.parseToken(token);
            request.setAttribute("userId", userId);
            return true;
        } catch (Exception e) {
            log.warn("Token 验证失败: {}", e.getMessage());
            sendError(response, 401, "登录已过期，请重新登录");
            return false;
        }
    }
    
    private void sendError(HttpServletResponse response, int code, String message) 
            throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(code);
        response.getWriter().write(
            "{\"code\":" + code + ",\"message\":\"" + message + "\"}"
        );
    }
}

// 自定义注解：标记不需要认证的接口
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface NoAuth {
}

// 使用示例
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @NoAuth  // 不需要登录
    @GetMapping("/public")
    public String publicApi() {
        return "公开接口";
    }
    
    @GetMapping("/profile")  // 需要登录
    public User profile(HttpServletRequest request) {
        String userId = (String) request.getAttribute("userId");
        return userService.findById(Long.parseLong(userId));
    }
}
```

### 9.5 拦截器执行顺序

多个拦截器的执行顺序：

```
请求进入
    ↓
Interceptor1.preHandle()
    ↓
Interceptor2.preHandle()
    ↓
Controller 方法执行
    ↓
Interceptor2.postHandle()
    ↓
Interceptor1.postHandle()
    ↓
视图渲染
    ↓
Interceptor2.afterCompletion()
    ↓
Interceptor1.afterCompletion()
    ↓
响应返回
```

**注意：** 如果某个拦截器的 `preHandle` 返回 `false`，后续拦截器不会执行，但已执行的拦截器的 `afterCompletion` 会被调用。

---

## 10. 过滤器

### 10.1 创建过滤器

```java
// ============ 方式1：实现 Filter 接口 ============
@Component
@Slf4j
public class RequestLogFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, 
                        ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        String requestId = UUID.randomUUID().toString().substring(0, 8);
        long startTime = System.currentTimeMillis();
        
        log.info("[{}] 请求开始: {} {}", 
                requestId, httpRequest.getMethod(), httpRequest.getRequestURI());
        
        try {
            chain.doFilter(request, response);  // 继续执行
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            log.info("[{}] 请求结束，耗时: {}ms", requestId, duration);
        }
    }
}

// ============ 方式2：使用 @WebFilter 注解 ============
@WebFilter(urlPatterns = "/*", filterName = "encodingFilter")
@Order(1)
public class EncodingFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, 
                        ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        request.setCharacterEncoding("UTF-8");
        response.setCharacterEncoding("UTF-8");
        chain.doFilter(request, response);
    }
}

// 需要在启动类添加 @ServletComponentScan
@SpringBootApplication
@ServletComponentScan
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 10.2 使用 FilterRegistrationBean 注册

```java
@Configuration
public class FilterConfig {
    
    @Bean
    public FilterRegistrationBean<RequestLogFilter> requestLogFilter() {
        FilterRegistrationBean<RequestLogFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RequestLogFilter());
        registration.addUrlPatterns("/*");
        registration.setName("requestLogFilter");
        registration.setOrder(1);  // 执行顺序
        return registration;
    }
    
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>();
        
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOriginPattern("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        
        registration.setFilter(new CorsFilter(source));
        registration.setOrder(0);  // 最先执行
        return registration;
    }
}
```

### 10.3 请求包装器

有时需要多次读取请求体，但 `InputStream` 只能读取一次。可以使用包装器解决。

```java
// ============ 可重复读取的请求包装器 ============
public class RepeatableReadRequestWrapper extends HttpServletRequestWrapper {
    
    private final byte[] body;
    
    public RepeatableReadRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        this.body = StreamUtils.copyToByteArray(request.getInputStream());
    }
    
    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream bais = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public int read() {
                return bais.read();
            }
            
            @Override
            public boolean isFinished() {
                return bais.available() == 0;
            }
            
            @Override
            public boolean isReady() {
                return true;
            }
            
            @Override
            public void setReadListener(ReadListener listener) {
            }
        };
    }
    
    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }
    
    public String getBody() {
        return new String(body, StandardCharsets.UTF_8);
    }
}

// ============ 使用包装器的过滤器 ============
@Component
public class RequestBodyLogFilter implements Filter {
    
    @Override
    public void doFilter(ServletRequest request, 
                        ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // 只处理 JSON 请求
        if (httpRequest.getContentType() != null && 
            httpRequest.getContentType().contains("application/json")) {
            
            RepeatableReadRequestWrapper wrapper = new RepeatableReadRequestWrapper(httpRequest);
            log.info("请求体: {}", wrapper.getBody());
            chain.doFilter(wrapper, response);  // 使用包装后的请求
        } else {
            chain.doFilter(request, response);
        }
    }
}
```

---

## 11. 文件上传下载

### 11.1 文件上传配置

```yaml
# application.yml
spring:
  servlet:
    multipart:
      enabled: true
      max-file-size: 10MB          # 单个文件最大大小
      max-request-size: 100MB      # 请求最大大小
      file-size-threshold: 2KB     # 超过此大小写入临时文件
      location: /tmp               # 临时文件目录
```

### 11.2 单文件上传

```java
@RestController
@RequestMapping("/api/files")
@Slf4j
public class FileController {
    
    @Value("${file.upload-dir:./uploads}")
    private String uploadDir;
    
    /**
     * 单文件上传
     */
    @PostMapping("/upload")
    public Result<String> upload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return Result.error("请选择文件");
        }
        
        try {
            // 生成唯一文件名
            String originalName = file.getOriginalFilename();
            String extension = originalName.substring(originalName.lastIndexOf("."));
            String newName = UUID.randomUUID().toString() + extension;
            
            // 创建目录
            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }
            
            // 保存文件
            Path filePath = uploadPath.resolve(newName);
            file.transferTo(filePath.toFile());
            
            log.info("文件上传成功: {} -> {}", originalName, newName);
            return Result.success("/files/" + newName);
            
        } catch (IOException e) {
            log.error("文件上传失败", e);
            return Result.error("文件上传失败");
        }
    }
    
    /**
     * 带参数的文件上传
     */
    @PostMapping("/upload-with-info")
    public Result<String> uploadWithInfo(
            @RequestParam("file") MultipartFile file,
            @RequestParam("description") String description,
            @RequestParam(value = "category", defaultValue = "default") String category) {
        
        log.info("上传文件: {}, 描述: {}, 分类: {}", 
                file.getOriginalFilename(), description, category);
        
        // 保存文件逻辑...
        return Result.success("上传成功");
    }
}
```

### 11.3 多文件上传

```java
@RestController
@RequestMapping("/api/files")
public class FileController {
    
    /**
     * 多文件上传
     */
    @PostMapping("/upload-multiple")
    public Result<List<String>> uploadMultiple(
            @RequestParam("files") MultipartFile[] files) {
        
        List<String> urls = new ArrayList<>();
        
        for (MultipartFile file : files) {
            if (!file.isEmpty()) {
                String url = saveFile(file);
                urls.add(url);
            }
        }
        
        return Result.success(urls);
    }
    
    /**
     * 使用 List 接收
     */
    @PostMapping("/upload-list")
    public Result<List<String>> uploadList(
            @RequestParam("files") List<MultipartFile> files) {
        
        List<String> urls = files.stream()
                .filter(f -> !f.isEmpty())
                .map(this::saveFile)
                .collect(Collectors.toList());
        
        return Result.success(urls);
    }
    
    private String saveFile(MultipartFile file) {
        // 保存文件逻辑
        return "/files/" + file.getOriginalFilename();
    }
}
```

### 11.4 文件下载

```java
@RestController
@RequestMapping("/api/files")
public class FileController {
    
    @Value("${file.upload-dir:./uploads}")
    private String uploadDir;
    
    /**
     * 文件下载
     */
    @GetMapping("/download/{filename}")
    public ResponseEntity<Resource> download(@PathVariable String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename);
            Resource resource = new UrlResource(filePath.toUri());
            
            if (!resource.exists()) {
                return ResponseEntity.notFound().build();
            }
            
            // 获取文件类型
            String contentType = Files.probeContentType(filePath);
            if (contentType == null) {
                contentType = "application/octet-stream";
            }
            
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(contentType))
                    .header(HttpHeaders.CONTENT_DISPOSITION, 
                            "attachment; filename=\"" + filename + "\"")
                    .body(resource);
                    
        } catch (IOException e) {
            return ResponseEntity.internalServerError().build();
        }
    }
    
    /**
     * 图片预览（不下载）
     */
    @GetMapping("/preview/{filename}")
    public ResponseEntity<Resource> preview(@PathVariable String filename) {
        try {
            Path filePath = Paths.get(uploadDir).resolve(filename);
            Resource resource = new UrlResource(filePath.toUri());
            
            if (!resource.exists()) {
                return ResponseEntity.notFound().build();
            }
            
            String contentType = Files.probeContentType(filePath);
            
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(contentType))
                    .header(HttpHeaders.CONTENT_DISPOSITION, 
                            "inline; filename=\"" + filename + "\"")  // inline 表示预览
                    .body(resource);
                    
        } catch (IOException e) {
            return ResponseEntity.internalServerError().build();
        }
    }
    
    /**
     * 导出 Excel
     */
    @GetMapping("/export/users")
    public void exportUsers(HttpServletResponse response) throws IOException {
        // 设置响应头
        response.setContentType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        response.setHeader("Content-Disposition", "attachment; filename=users.xlsx");
        
        // 生成 Excel（使用 POI 或 EasyExcel）
        // Workbook workbook = ...
        // workbook.write(response.getOutputStream());
    }
}
```


---

## 12. 跨域处理

### 12.1 什么是跨域？

当浏览器从一个域名的网页去请求另一个域名的资源时，就会发生跨域。浏览器出于安全考虑，会阻止这种请求。

**跨域的条件（满足任一即跨域）：**
- 协议不同：http vs https
- 域名不同：a.com vs b.com
- 端口不同：localhost:3000 vs localhost:8080

### 12.2 @CrossOrigin 注解

```java
@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "http://localhost:3000")  // 类级别
public class UserController {
    
    @GetMapping
    public List<User> list() {
        return userService.findAll();
    }
    
    // 方法级别，覆盖类级别配置
    @CrossOrigin(origins = "*", maxAge = 3600)
    @GetMapping("/{id}")
    public User getById(@PathVariable Long id) {
        return userService.findById(id);
    }
}
```

### 12.3 全局跨域配置（推荐）

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")                    // 所有路径
                .allowedOriginPatterns("*")           // 允许的源
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")                  // 允许的请求头
                .exposedHeaders("Authorization")      // 暴露的响应头
                .allowCredentials(true)               // 允许携带 Cookie
                .maxAge(3600);                        // 预检请求缓存时间
    }
}
```

### 12.4 使用 CorsFilter

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOriginPattern("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        
        return new CorsFilter(source);
    }
}
```

### 12.5 跨域常见问题

#### 问题1：预检请求失败

```
Access to XMLHttpRequest has been blocked by CORS policy: 
Response to preflight request doesn't pass access control check
```

**原因：** OPTIONS 预检请求被拦截器拦截

**解决：** 在拦截器中放行 OPTIONS 请求

```java
@Override
public boolean preHandle(HttpServletRequest request, 
                        HttpServletResponse response, 
                        Object handler) {
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
        return true;  // 放行预检请求
    }
    // 其他逻辑...
}
```

#### 问题2：携带 Cookie 时跨域失败

**原因：** `allowCredentials(true)` 时不能使用 `allowedOrigins("*")`

**解决：** 使用 `allowedOriginPatterns("*")` 代替

---

## 13. RESTful API 设计

### 13.1 RESTful 设计原则

REST（Representational State Transfer）是一种 API 设计风格。

**核心原则：**
1. 使用 HTTP 方法表示操作
2. 使用 URL 表示资源
3. 使用 HTTP 状态码表示结果
4. 无状态

**HTTP 方法与 CRUD 对应：**

| HTTP 方法 | 操作 | 示例 |
|-----------|------|------|
| GET | 查询 | GET /users |
| POST | 创建 | POST /users |
| PUT | 全量更新 | PUT /users/1 |
| PATCH | 部分更新 | PATCH /users/1 |
| DELETE | 删除 | DELETE /users/1 |

### 13.2 URL 设计规范

```
# 好的设计
GET    /users              # 获取用户列表
GET    /users/1            # 获取单个用户
POST   /users              # 创建用户
PUT    /users/1            # 更新用户
DELETE /users/1            # 删除用户
GET    /users/1/orders     # 获取用户的订单
POST   /users/1/orders     # 为用户创建订单

# 不好的设计
GET    /getUsers           # 动词不应该出现在 URL 中
POST   /createUser
GET    /getUserById?id=1
POST   /deleteUser
```

### 13.3 完整的 RESTful Controller

```java
@RestController
@RequestMapping("/api/v1/users")
@Validated
@Slf4j
public class UserController {
    
    @Autowired
    private UserService userService;
    
    /**
     * 获取用户列表（分页）
     * GET /api/v1/users?page=1&size=10&keyword=张
     */
    @GetMapping
    public Result<PageResult<UserVO>> list(
            @RequestParam(defaultValue = "1") @Min(1) Integer page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) Integer size,
            @RequestParam(required = false) String keyword) {
        
        PageResult<UserVO> result = userService.findPage(page, size, keyword);
        return Result.success(result);
    }
    
    /**
     * 获取单个用户
     * GET /api/v1/users/1
     */
    @GetMapping("/{id}")
    public Result<UserVO> getById(@PathVariable @Min(1) Long id) {
        UserVO user = userService.findById(id);
        return Result.success(user);
    }
    
    /**
     * 创建用户
     * POST /api/v1/users
     */
    @PostMapping
    public Result<UserVO> create(@Valid @RequestBody CreateUserDTO dto) {
        UserVO user = userService.create(dto);
        return Result.success(user);
    }
    
    /**
     * 更新用户
     * PUT /api/v1/users/1
     */
    @PutMapping("/{id}")
    public Result<UserVO> update(
            @PathVariable @Min(1) Long id,
            @Valid @RequestBody UpdateUserDTO dto) {
        UserVO user = userService.update(id, dto);
        return Result.success(user);
    }
    
    /**
     * 部分更新用户
     * PATCH /api/v1/users/1
     */
    @PatchMapping("/{id}")
    public Result<UserVO> patch(
            @PathVariable @Min(1) Long id,
            @RequestBody Map<String, Object> updates) {
        UserVO user = userService.patch(id, updates);
        return Result.success(user);
    }
    
    /**
     * 删除用户
     * DELETE /api/v1/users/1
     */
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable @Min(1) Long id) {
        userService.delete(id);
        return Result.success();
    }
    
    /**
     * 批量删除
     * DELETE /api/v1/users?ids=1,2,3
     */
    @DeleteMapping
    public Result<Void> batchDelete(@RequestParam List<Long> ids) {
        userService.batchDelete(ids);
        return Result.success();
    }
    
    /**
     * 获取用户的订单
     * GET /api/v1/users/1/orders
     */
    @GetMapping("/{id}/orders")
    public Result<List<OrderVO>> getUserOrders(@PathVariable Long id) {
        List<OrderVO> orders = orderService.findByUserId(id);
        return Result.success(orders);
    }
}
```

### 13.4 HTTP 状态码使用

| 状态码 | 含义 | 使用场景 |
|--------|------|----------|
| 200 OK | 成功 | GET、PUT、PATCH 成功 |
| 201 Created | 已创建 | POST 创建成功 |
| 204 No Content | 无内容 | DELETE 成功 |
| 400 Bad Request | 请求错误 | 参数校验失败 |
| 401 Unauthorized | 未认证 | 未登录 |
| 403 Forbidden | 禁止访问 | 无权限 |
| 404 Not Found | 未找到 | 资源不存在 |
| 500 Internal Server Error | 服务器错误 | 系统异常 |

---

## 14. 统一响应封装

### 14.1 统一响应类

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Result<T> {
    
    private Integer code;
    private String message;
    private T data;
    private Long timestamp;
    
    public Result(Integer code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
        this.timestamp = System.currentTimeMillis();
    }
    
    // 成功响应
    public static <T> Result<T> success() {
        return new Result<>(200, "success", null);
    }
    
    public static <T> Result<T> success(T data) {
        return new Result<>(200, "success", data);
    }
    
    public static <T> Result<T> success(String message, T data) {
        return new Result<>(200, message, data);
    }
    
    // 失败响应
    public static <T> Result<T> error(String message) {
        return new Result<>(500, message, null);
    }
    
    public static <T> Result<T> error(Integer code, String message) {
        return new Result<>(code, message, null);
    }
    
    public static <T> Result<T> error(Integer code, String message, T data) {
        return new Result<>(code, message, data);
    }
}
```

### 14.2 分页响应类

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageResult<T> {
    
    private List<T> list;        // 数据列表
    private Long total;          // 总记录数
    private Integer page;        // 当前页码
    private Integer size;        // 每页大小
    private Integer totalPages;  // 总页数
    
    public PageResult(List<T> list, Long total, Integer page, Integer size) {
        this.list = list;
        this.total = total;
        this.page = page;
        this.size = size;
        this.totalPages = (int) Math.ceil((double) total / size);
    }
    
    // 从 Spring Data Page 转换
    public static <T> PageResult<T> of(Page<T> page) {
        return new PageResult<>(
            page.getContent(),
            page.getTotalElements(),
            page.getNumber() + 1,
            page.getSize()
        );
    }
}
```

### 14.3 全局响应包装（可选）

自动将 Controller 返回值包装为统一响应格式。

```java
@RestControllerAdvice
public class ResponseAdvice implements ResponseBodyAdvice<Object> {
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Override
    public boolean supports(MethodParameter returnType, 
                           Class<? extends HttpMessageConverter<?>> converterType) {
        // 已经是 Result 类型的不处理
        return !returnType.getParameterType().equals(Result.class);
    }
    
    @Override
    public Object beforeBodyWrite(Object body, 
                                  MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        // 处理 String 类型（需要特殊处理）
        if (body instanceof String) {
            try {
                return objectMapper.writeValueAsString(Result.success(body));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
        
        // 其他类型直接包装
        return Result.success(body);
    }
}
```

**注意：** 全局响应包装可能会影响 Swagger 等工具，需要排除特定路径。

---

## 15. 常见错误与解决

### 15.1 404 错误

**错误信息：**
```
Whitelabel Error Page - 404 Not Found
```

**可能原因：**
1. Controller 没有被扫描到
2. URL 路径不匹配
3. 请求方法不匹配

**解决方案：**
```java
// 1. 确保 Controller 在启动类的包或子包下
@SpringBootApplication  // 会扫描当前包及子包
public class Application { }

// 2. 或者指定扫描路径
@SpringBootApplication
@ComponentScan("com.example")
public class Application { }

// 3. 检查 URL 是否正确
// 注意 context-path 配置
// server.servlet.context-path=/api
```

### 15.2 405 Method Not Allowed

**错误信息：**
```
Request method 'POST' not supported
```

**原因：** 请求方法与 Controller 方法不匹配

**解决：** 检查 HTTP 方法是否正确

```java
@GetMapping("/users")     // 只接受 GET
@PostMapping("/users")    // 只接受 POST
@RequestMapping("/users") // 接受所有方法
```

### 15.3 415 Unsupported Media Type

**错误信息：**
```
Content type 'application/x-www-form-urlencoded' not supported
```

**原因：** 请求的 Content-Type 与 Controller 期望的不匹配

**解决：**
```java
// @RequestBody 需要 application/json
@PostMapping("/users")
public User create(@RequestBody UserDTO dto) { }

// 表单数据使用 @ModelAttribute 或 @RequestParam
@PostMapping("/login")
public String login(@RequestParam String username, @RequestParam String password) { }
```

### 15.4 400 Bad Request

**错误信息：**
```
JSON parse error: Cannot deserialize value
```

**原因：** JSON 格式错误或类型不匹配

**解决：**
1. 检查 JSON 格式是否正确
2. 检查字段类型是否匹配
3. 配置 Jackson 忽略未知属性

```java
// application.yml
spring:
  jackson:
    deserialization:
      fail-on-unknown-properties: false
```

### 15.5 循环引用导致 JSON 序列化失败

**错误信息：**
```
Could not write JSON: Infinite recursion
```

**原因：** 实体类之间存在双向关联

**解决：**
```java
@Entity
public class User {
    @OneToMany(mappedBy = "user")
    @JsonIgnore  // 忽略此字段
    private List<Order> orders;
}

// 或者使用 @JsonManagedReference 和 @JsonBackReference
@Entity
public class User {
    @OneToMany(mappedBy = "user")
    @JsonManagedReference
    private List<Order> orders;
}

@Entity
public class Order {
    @ManyToOne
    @JsonBackReference
    private User user;
}
```

---

## 16. 最佳实践

### 16.1 Controller 层规范

```java
@RestController
@RequestMapping("/api/v1/users")
@Validated
@Slf4j
public class UserController {
    
    // 1. 使用构造器注入
    private final UserService userService;
    
    public UserController(UserService userService) {
        this.userService = userService;
    }
    
    // 2. 方法职责单一
    @GetMapping("/{id}")
    public Result<UserVO> getById(@PathVariable Long id) {
        return Result.success(userService.findById(id));
    }
    
    // 3. 使用 DTO 接收参数，VO 返回数据
    @PostMapping
    public Result<UserVO> create(@Valid @RequestBody CreateUserDTO dto) {
        return Result.success(userService.create(dto));
    }
    
    // 4. 不要在 Controller 中写业务逻辑
    // 错误示例：
    // @PostMapping
    // public Result<User> create(@RequestBody UserDTO dto) {
    //     if (userDao.existsByUsername(dto.getUsername())) {
    //         return Result.error("用户名已存在");
    //     }
    //     User user = new User();
    //     BeanUtils.copyProperties(dto, user);
    //     userDao.save(user);
    //     return Result.success(user);
    // }
}
```

### 16.2 DTO/VO 设计

```java
// ============ 创建用户 DTO ============
@Data
public class CreateUserDTO {
    @NotBlank(message = "用户名不能为空")
    private String username;
    
    @NotBlank(message = "密码不能为空")
    private String password;
    
    @Email(message = "邮箱格式不正确")
    private String email;
}

// ============ 更新用户 DTO ============
@Data
public class UpdateUserDTO {
    @Size(min = 2, max = 20)
    private String username;
    
    @Email
    private String email;
    
    private Integer age;
}

// ============ 用户 VO（返回给前端） ============
@Data
public class UserVO {
    private Long id;
    private String username;
    private String email;
    private Integer age;
    private String status;
    
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createTime;
    
    // 不包含敏感信息如 password
}
```

### 16.3 异常处理规范

```java
// 1. 定义业务异常
public class BusinessException extends RuntimeException {
    private final ErrorCode errorCode;
    
    public BusinessException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}

// 2. 在 Service 层抛出异常
@Service
public class UserService {
    public UserVO findById(Long id) {
        User user = userDao.findById(id)
            .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        return convertToVO(user);
    }
}

// 3. 全局异常处理器统一处理
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(BusinessException.class)
    public Result<?> handleBusinessException(BusinessException e) {
        return Result.error(e.getErrorCode().getCode(), e.getMessage());
    }
}
```

### 16.4 日志规范

```java
@RestController
@Slf4j
public class UserController {
    
    @PostMapping("/users")
    public Result<UserVO> create(@RequestBody CreateUserDTO dto) {
        log.info("创建用户请求: username={}", dto.getUsername());
        
        try {
            UserVO user = userService.create(dto);
            log.info("用户创建成功: id={}", user.getId());
            return Result.success(user);
        } catch (Exception e) {
            log.error("用户创建失败: username={}", dto.getUsername(), e);
            throw e;
        }
    }
}
```

---

## 17. 总结

Spring MVC 核心知识点：

1. **请求映射**：@RequestMapping、@GetMapping 等注解
2. **参数绑定**：@PathVariable、@RequestParam、@RequestBody 等
3. **数据校验**：@Valid、@Validated 配合校验注解
4. **响应处理**：JSON 序列化、ResponseEntity
5. **异常处理**：@RestControllerAdvice + @ExceptionHandler
6. **拦截器**：HandlerInterceptor 实现请求拦截
7. **文件处理**：MultipartFile 上传、Resource 下载
8. **跨域处理**：@CrossOrigin、CorsFilter

掌握这些核心概念，你就能够使用 Spring MVC 构建完整的 Web 应用了。
