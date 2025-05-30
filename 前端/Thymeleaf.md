Thymeleaf 是一个用于 Java 的现代服务器端模板引擎，广泛应用于 Spring Boot 项目中。它支持 HTML、XML、JavaScript、CSS 等格式的模板渲染，并与 Spring MVC 深度集成。

以下是 **Thymeleaf 常用语法大全**，适用于 Thymeleaf 3.x 版本（Spring Boot 默认使用）。

---

## 基础语法

| 语法 | 描述 |
|------|------|
| `${...}` | 变量表达式，用于输出变量值，如：`${user.name}` |
| `*{...}` | 选择表达式，用于在选定对象上操作，常用于表单绑定，如：`*{name}` |
| `#{...}` | 消息表达式，用于国际化消息，如：`#{home.title}` |
| `@{...}` | 链接 URL 表达式，用于生成 URL，如：`@{/login}` |
| `~{...}` | 片段表达式，用于引入模板片段，如：`~{fragments/header :: header}` |

---

## 常用属性指令（HTML 属性）

| 属性 | 示例 | 说明 |
|------|------|------|
| `th:text` | `<p th:text="${name}">` | 文本内容替换（自动转义） |
| `th:utext` | `<p th:utext="${htmlContent}">` | 不转义文本内容（输出原始 HTML） |
| `th:value` | `<input th:value="${user.name}" />` | 设置 input 的 value 值 |
| `th:each` | `<div th:each="user : ${users}">` | 循环遍历集合 |
| `th:href` | `<a th:href="@{/user/{id}(id=${user.id})}">` | 动态生成链接 |
| `th:src` | `<img th:src="@{/images/logo.png}" />` | 动态设置图片路径 |
| `th:if` / `th:unless` | `<div th:if="${user.isAdmin}">` | 条件判断显示/隐藏元素 |
| `th:switch` / `th:case` | 多条件分支判断 |
| `th:field` | `<input type="text" th:field="*{name}" />` | 表单字段绑定（需配合 form 使用） |
| `th:error` | `<span th:if="${#fields.hasErrors('name')}" th:errors="*{name}">` | 显示表单校验错误信息 |
| `th:fragment` | `<div th:fragment="header">` | 定义可复用的模板片段 |
| `th:replace` / `th:insert` | `<div th:replace="~{fragments/header :: header}">` | 引入模板片段（替换或插入） |
| `th:attr` | `<div th:attr="data-id=${user.id}">` | 动态添加任意属性 |
| `th:class` / `th:classappend` | `<div th:class="${user.isAdmin} ? admin : user">` | 动态设置 class 样式 |
| `th:inline` | `<script th:inline="javascript">` | 内联脚本支持（JS 中嵌入变量） |

---

## 控制结构

### 条件判断

```html
<div th:if="${user.age >= 18}">
    成年人
</div>
<div th:unless="${user.age < 18}">
    成年人
</div>
```


### 分支判断

```html
<div th:switch="${user.role}">
    <p th:case="'admin'">管理员</p>
    <p th:case="'user'">普通用户</p>
    <p th:case="*">未知角色</p>
</div>
```


### 循环遍历

```html
<ul>
    <li th:each="user, stat : ${users}"
        th:text="${stat.index + 1 + '. ' + user.name}">
    </li>
</ul>
```


- `stat.index`: 从 0 开始索引
- `stat.count`: 从 1 开始索引
- `stat.size`: 总数量
- `stat.first`, `stat.last`: 是否为第一个/最后一个

---

##  模板布局（Fragment）

### 定义片段

```html
<!-- fragments/header.html -->
<div th:fragment="header">
    <h1>网站头部</h1>
</div>
```


### 引用片段

```html
<!-- home.html -->
<div th:replace="~{fragments/header :: header}"></div>
```


- `th:replace`: 替换当前标签为片段内容
- `th:insert`: 插入片段作为子节点
- `th:include`: 插入片段的内容部分

---

## 表达式基本对象

| 对象 | 说明 |
|------|------|
| `#ctx` | 上下文对象 |
| `#locale` | 当前区域信息 |
| `#request` | HTTP 请求对象（仅在 Web 环境下可用） |
| `#response` | HTTP 响应对象 |
| `#session` | Session 对象 |
| `#servletContext` | Servlet 上下文对象 |
| `#dates` | 日期工具类（如 `#dates.format(date, 'yyyy-MM-dd')`） |
| `#calendars` | 日历工具类 |
| `#numbers` | 数字工具类 |
| `#strings` | 字符串工具类（如 `#strings.isEmpty(name)`） |
| `#objects` | 对象工具类 |
| `#bools` | 布尔工具类 |
| `#arrays`, `#lists`, `#sets`, `#maps` | 集合工具类 |

---

## 国际化（i18n）

### 消息文件结构：

```
messages.properties
messages_en.properties
messages_zh.properties
```


### 页面中使用：

```html
<h1 th:text="#{welcome.message}">Welcome</h1>
```


---

## 其他实用技巧

### 内联 JS

```html
<script th:inline="javascript">
    /*<![CDATA[*/
    var username = /*[(${user.name})]*/ 'default';
    alert(username);
    /*]]>*/
</script>
```


### 注释

```html
<!--/* This code is commented out. */-->
<div th:if="false">不会显示</div>
<!--/*/ This comment will not appear in the output. /*/-->
```


---

## 示例：登录页面（login.html）

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title th:text="#{login.title}">登录</title>
</head>
<body>
    <h1 th:text="#{login.heading}">请登录</h1>

    <form th:action="@{/login}" method="post">
        <label for="username">用户名：</label>
        <input type="text" id="username" name="username" th:placeholder="#{login.username}" />

        <label for="password">密码：</label>
        <input type="password" id="password" name="password" th:placeholder="#{login.password}" />

        <button type="submit" th:text="#{login.submit}">登录</button>
    </form>
</body>
</html>
```

