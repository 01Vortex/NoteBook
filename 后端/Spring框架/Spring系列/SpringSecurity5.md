# Spring Security所有接口
Spring Security 是一个功能强大且高度可定制的安全框架，它包含了许多接口来支持各种安全相关的操作和需求。以下是 Spring Security 中一些核心的接口分类及部分重要接口的列表：

### 核心认证与授权接口

1. **`Authentication`**
   - 表示用户或实体的身份验证信息。

2. **`AuthenticationManager`**
   - 负责处理 `Authentication` 对象的管理，通常用于执行身份验证。

3. **`AuthenticationProvider`**
   - 为 `AuthenticationManager` 提供具体的身份验证逻辑。

4. **`UserDetailsService`**
   - 通过用户名加载用户详细信息（如权限、角色等）的服务接口。

5. **`GrantedAuthority`**
   - 代表分配给用户的权限或角色。

6. **`AccessDecisionManager`**
   - 决定是否授予对特定资源的访问权限。

7. **`AccessDecisionVoter`**
   - 投票决定是否允许访问特定资源。

8. **`FilterInvocationSecurityMetadataSource`**
   - 确定请求所需的权限。


### 安全响应接口

1. **`AuthenticationSuccessHandler`**
   - 认证成功后的处理器。

2. **`AuthenticationFailureHandler`**
   - 认证失败后的处理器。

3. **`LogoutSuccessHandler`**
   - 登出成功后的处理器。

### HttpSecurity 相关接口

1. **`HttpSecurity`**
   - 用于构建Web安全配置的核心类，虽然不是接口，但它是通过DSL风格进行安全设置的重要方式。

2. **`SecurityFilterChain`**  不直接实现,只当一个函数类型
   - 定义了一个过滤器链，用于处理HTTP请求的安全性。

### 其他重要接口

1. **`PasswordEncoder`**
   - 密码加密接口，提供密码编码和匹配方法。

2. **`CsrfTokenRepository`**
   - 处理CSRF令牌的存储和检索。

3. **`RememberMeServices`**
   - 提供“记住我”功能的服务接口。



# 核心类和方法
Spring Security 是一个功能强大且高度可定制的身份验证和访问控制框架，用于保护基于 Spring 的 Java 应用程序。它提供了多种核心类和方法来帮助开发者实现安全功能。以下是 Spring Security 中一些关键的核心类及其主要职责和常用方法的概述：

### 注解标记
@Configuration：表明这是一个配置类，Spring会根据这个类来创建相应的Bean。
@EnableWebSecurity：启用Spring Security的Web安全支持，并允许自定义配置。

### 核心类

1. **`AuthenticationManager`**
   - **职责**：负责认证用户身份。
   - **常用方法**：
     - `authenticate(Authentication authentication)`：尝试认证提供的 `Authentication` 对象，并返回完全填充（包括授予的权限）的 `Authentication` 对象，如果认证失败，则抛出异常。

2. **`UserDetailsService`**
   - **职责**：根据用户名加载用户特定数据。
   - **常用方法**：
     - `loadUserByUsername(String username)`：根据用户名加载用户详情信息，通常包含用户的权限等信息。

3. **`PasswordEncoder`**
   - **职责**：用于加密密码和匹配加密后的密码与明文密码是否一致。
   - **常用方法**：
     - `encode(CharSequence rawPassword)`：对原始密码进行编码。
     - `matches(CharSequence rawPassword, String encodedPassword)`：判断原始密码与已编码的密码是否匹配。

4. **`HttpSecurity`**
   - **职责**：配置应用程序的安全选项，如 HTTP 请求的安全约束。
   - **常用方法**：
     - `authorizeRequests()`：定义哪些 URL 需要什么样的权限才能访问。
     - `formLogin()`：启用基于表单的登录。
     - `logout()`：配置注销处理。
     - `csrf().disable()` 或 `cors()`：配置跨站请求伪造保护或跨域资源共享支持。

5. ~~**`WebSecurityConfigurerAdapter` (Deprecated in newer versions)**~~
   - **职责**：提供了一种便捷的方式来配置 Web 安全性，不过在最新的 Spring Security 版本中已经被标记为过时，推荐直接使用 ==`SecurityFilterChain` Bean== 的来配置。
   - **常用方法**：
     - `configure(HttpSecurity http)`：配置 HttpSecurity。
     - `configure(AuthenticationManagerBuilder auth)`：配置认证管理器。


6. **SecurityFilterChain接口**
- **作用**：代表了一组用于保护应用的过滤器。每个 `SecurityFilterChain` 可以包含多个过滤器，并且可以根据特定条件（如URL模式）决定是否应用于某个请求。
- **匹配逻辑**：通过实现 `matches(HttpServletRequest request)` 方法来确定是否将此过滤器链应用于传入的请求。

创建 `SecurityFilterChain` Bean

当你使用Spring Security进行配置时，通常==不会直接实现 `SecurityFilterChain` 接口==，而是通过配置 ==`HttpSecurity` 对象并调用其 `.build()` 方法来创建一个 `SecurityFilterChain` 的实例==。这个过程通常是隐式的，在Spring Boot环境中，你可以通过以下方式注册一个 `SecurityFilterChain` Bean：

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests(authorize -> authorize
        // 配置哪些请求需要认证等
    )
    // 其他配置...
    ;
    return http.build(); // 返回一个SecurityFilterChain实例
}
```

这里，`http.build()` 会根据你对 `HttpSecurity` 对象的配置生成一个实现了 `SecurityFilterChain` 接口的具体实例。具体实现细节由Spring Security框架内部管理。

虽然 `SecurityFilterChain` 是作为一个接口存在的，但通过Spring Security提供的DSL风格的API和配置机制，你可以非常方便地定义和注册符合你应用需求的安全过滤器链，而无需直接操作或实现该接口本身。这种设计使得开发者可以专注于声明式地描述安全需求，而不必深入到具体的过滤器链实现细节中。


7. **`SecurityContextHolder`**
   - **职责**：持有当前线程的安全上下文。
   - **常用方法**：
     - `getContext()`：获取当前的安全上下文。
     - `setContext(SecurityContext context)`：设置当前的安全上下文。

8. **`UsernamePasswordAuthenticationToken`**
   - **职责**：表示一个由用户名和密码组成的认证令牌。
   - **常用构造函数/方法**：
     - 构造函数：创建一个新的实例。
     - `getAuthorities()`：获取此 Authentication 对象中的权限列表。

9. **`JwtUtils` (非标准，自定义类)**
   - **职责**：虽然不是 Spring Security 的一部分，但在使用 JWT 时经常会有一个类似的工具类来帮助生成、解析和验证 JWT。
   - **常用方法**（假设实现）：
     - `generateToken(UserDetails userDetails)`：生成 JWT。
     - `validateToken(String token)`：验证 JWT 是否有效。
     - `getUsernameFromToken(String token)`：从 JWT 中提取用户名。

### 核心概念

- **Authentication**：代表当前用户的身份认证状态。
- **Authorization**：授权过程，决定用户是否有权执行特定操作。
- **Security Context**：存储当前认证信息的地方，默认情况下通过 `ThreadLocal` 实现，使得每个请求都可以独立地拥有自己的安全上下文。

这些核心类和概念共同构成了 Spring Security 的基础，帮助开发者轻松实现复杂的安全需求。随着 Spring Security 的版本更新，某些API可能会有所变化，因此建议查阅最新文档以获取最准确的信息。



# 参考
[SpringSecurity（看这一篇就够了）-CSDN博客](https://blog.csdn.net/m0_74436895/article/details/140998480)






# 自创问题
## 使用.build()有哪些潜在风险
在Spring Security配置中使用 `.build()` 方法本身是一个标准且推荐的做法，用于根据你提供的配置来构建 `SecurityFilterChain` 实例。然而，尽管它是一个必要的步骤，不当的使用或配置可能带来一些潜在风险或问题。以下是一些需要注意的方面：

1. **不完整的安全配置**：
   - 如果在调用 `.build()` 之前没有正确设置所有必要的安全配置（如认证、授权规则等），可能会导致应用程序的安全性降低。例如，忘记为敏感资源添加访问控制规则，使得这些资源无需认证即可访问。

2. **错误的顺序配置**：
   - Spring Security中的某些配置项是依赖于特定顺序的。如果配置项的顺序不正确，可能会导致意想不到的行为。例如，如果你先定义了需要身份验证的请求规则，然后才定义了允许匿名访问的路径，这可能导致期望匿名访问的路径也需要身份验证。

3. **禁用重要的安全特性**：
   - 如示例中所示，通过 `.csrf().disable()` 来禁用CSRF保护。虽然在某些场景下这样做可能是必要的（比如开发REST API时），但在大多数情况下，特别是对于Web应用，保持这些默认安全措施开启是非常重要的。随意关闭这些保护机制可能会使你的应用暴露于跨站请求伪造攻击之下。

4. **硬编码的安全配置**：
   - 直接在代码中硬编码安全相关的配置（如用户名、密码、URL等）会减少灵活性，并可能造成安全隐患。理想的做法是将这些配置外部化，例如使用环境变量或属性文件。

5. **忽略默认行为**：
   - 忽略或覆盖Spring Security提供的默认安全行为而不完全理解其含义和影响也可能导致安全漏洞。了解并合理利用框架提供的默认安全策略有助于提高应用的整体安全性。

为了避免这些问题，重要的是要全面理解和测试你的安全配置，确保它们符合你的应用需求同时不会引入不必要的风险。此外，保持对Spring Security最新版本和最佳实践的关注，可以帮助你更好地保护你的应用程序。



## HttpSecurity 和 SecurityFilterChain
`HttpSecurity` 和 `SecurityFilterChain` 在Spring Security中扮演着不同的角色，但它们之间有紧密的联系。理解它们的关系有助于更好地配置和使用Spring Security来保护你的应用程序。

### HttpSecurity

- **作用**：`HttpSecurity` 是用于构建安全配置的核心类之一。它提供了一种DSL（领域特定语言）风格的方式来配置基于HTTP的安全性设置，包括但不限于认证、授权、CSRF保护、CORS配置等。
- **使用场景**：当你需要为你的应用定制安全策略时，你会通过配置 `HttpSecurity` 来实现这一点。例如，你可以指定哪些URL路径需要身份验证，如何处理登录和登出流程，是否启用或禁用某些安全特性等。

### SecurityFilterChain

- **作用**：`SecurityFilterChain` 表示一个过滤器链，它是实际应用于处理请求的一系列过滤器的集合。这些过滤器根据你对 `HttpSecurity` 的配置来决定如何处理到来的HTTP请求。
- **Bean形式**：在现代Spring Security版本中（特别是从5.7.0-M2开始），推荐的方式是通过创建一个或多个 `SecurityFilterChain` Bean来定义你的安全配置，而不是直接实现`WebSecurityConfigurerAdapter`（该方法已经被标记为过时）。

### 关系

1. **配置到实现**：你通过配置 `HttpSecurity` 对象来描述你希望应用的安全策略。一旦配置完成，调用 `HttpSecurity.build()` 方法将基于这些配置创建一个 `SecurityFilterChain` 实例。
   
2. **Bean注册**：在Spring Boot环境中，通常会通过方法标注`@Bean`来注册一个或多个 `SecurityFilterChain` Bean。这意味着你可以根据不同的URL模式或其他条件定义多个安全配置，并将它们作为独立的Bean注册到Spring应用上下文中。

3. **请求处理**：当一个HTTP请求到达服务器时，Spring Security会根据请求的内容（如URL路径）选择合适的 `SecurityFilterChain` 来处理这个请求。每个 `SecurityFilterChain` 包含了一系列过滤器，这些过滤器按照预定顺序执行，以确保请求符合安全要求。

简而言之，`HttpSecurity` 是你用来配置安全策略的对象，而 `SecurityFilterChain` 则是基于这些配置创建出来的实际执行安全检查的组件。通过将 `HttpSecurity` 配置转化为 `SecurityFilterChain` Bean，你可以灵活地为不同的应用场景制定相应的安全措施。