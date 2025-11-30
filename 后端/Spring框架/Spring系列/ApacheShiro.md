# 基本概念
## 什么是Apache Shiro?
**Apache Shiro** 是一个功能强大且灵活的开源安全框架，旨在为Java应用程序提供身份验证、授权、加密和会话管理等功能。与Spring Security类似，Shiro的目标是简化应用程序的安全性实现，但它在设计上更加轻量级和易于使用，适用于各种类型的Java应用程序，包括Web应用、移动应用和企业级应用。

### Apache Shiro的核心概念

Shiro的核心概念围绕着**主体（Subject）**、**安全管理器（SecurityManager）**和**领域（Realm）**展开：

1. **主体（Subject）**：
   - 主体代表当前用户或应用程序的“用户”概念。它是Shiro的核心接口，封装了当前用户的安全状态（如身份验证状态、角色和权限）。
   - 开发者可以通过`Subject`接口来执行身份验证、授权、会话访问等操作。

2. **安全管理器（SecurityManager）**：
   - `SecurityManager`是Shiro的核心组件，负责管理所有与安全相关的操作，包括身份验证、授权、会话管理和加密。
   - 在Shiro中，`SecurityManager`是单例的，负责协调所有安全操作。

3. **领域（Realm）**：
   - 领域是Shiro中的一个概念，用于从特定的数据源（如数据库、LDAP、文件系统等）中获取安全数据（如用户、角色和权限）。
   - Shiro支持多个领域，可以配置多个领域来从不同的数据源获取安全信息。

### Apache Shiro的主要功能

1. **身份验证（Authentication）**：
   - 验证用户的身份，即确认用户是否是他们声称的那个人。
   - Shiro提供了多种身份验证机制，包括用户名/密码认证、令牌认证等。

2. **授权（Authorization）**：
   - 控制用户对应用程序资源的访问权限。
   - Shiro支持基于角色的访问控制（RBAC）和基于权限的访问控制（PBAC）。

3. **会话管理（Session Management）**：
   - 管理用户会话，支持Web应用程序和非Web应用程序。
   - Shiro提供了会话持久化、会话集群等功能。

4. **加密（Cryptography）**：
   - 提供加密和解密功能，支持多种加密算法。
   - Shiro可以用于密码哈希、加密数据等。

5. **缓存（Caching）**：
   - 提供缓存机制，支持多种缓存实现（如Ehcache, Redis等）。
   - 缓存可以提高身份验证和授权的性能。

6. **Web支持**：
   - 提供与Web框架（如Spring MVC, Struts等）的集成，支持Web应用程序的安全性需求。

### Apache Shiro的优势

- **简单易用**：Shiro的API设计简洁，易于理解和上手。
- **灵活性**：Shiro可以用于各种类型的Java应用程序，包括Web应用、移动应用和企业级应用。
- **可扩展性**：Shiro支持自定义领域、缓存、会话管理等，可以根据需要进行扩展。
- **独立于容器**：Shiro不依赖于特定的Web容器或应用服务器，可以在任何Java环境中使用。

### Apache Shiro的基本使用

以下是一个简单的Shiro使用示例：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.config.IniSecurityManagerFactory;

public class ShiroExample {
    public static void main(String[] args) {
        // 加载Shiro配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        // 获取当前主体
        Subject currentUser = SecurityUtils.getSubject();

        // 登录
        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken("user", "password");
            try {
                currentUser.login(token);
            } catch (UnknownAccountException e) {
                System.out.println("账户不存在");
            } catch (IncorrectCredentialsException e) {
                System.out.println("密码错误");
            } catch (LockedAccountException e) {
                System.out.println("账户被锁定");
            }
        }

        // 授权
        if (currentUser.hasRole("admin")) {
            System.out.println("用户具有admin角色");
        }

        // 登出
        currentUser.logout();
    }
}
```

在这个例子中，Shiro从`shiro.ini`配置文件中加载安全配置，并执行身份验证和授权操作。

### 总结

Apache Shiro是一个功能强大且灵活的安全框架，适用于各种类型的Java应用程序。它提供了身份验证、授权、会话管理、加密等功能，并且易于集成和使用。通过使用Shiro，开发者可以简化应用程序的安全性实现，提高代码的可维护性和安全性。

## Shiro与Spring Security有什么区别
**Apache Shiro** 和 **Spring Security** 都是用于Java应用程序的安全框架，但它们在设计理念、功能集、易用性以及与Spring框架的集成程度等方面存在显著区别。以下是Shiro和Spring Security的主要区别：

### 1. 设计理念

- **Apache Shiro**：
  - **轻量级和简单易用**：Shiro的设计目标是简单易用，适用于各种类型的Java应用程序，包括Web应用、移动应用和企业级应用。
  - **独立于容器**：Shiro不依赖于特定的Web容器或应用服务器，可以在任何Java环境中使用。

- **Spring Security**：
  - **与Spring框架紧密集成**：Spring Security是Spring生态系统的一部分，与Spring框架的其他组件（如Spring MVC, Spring Boot等）无缝集成。
  - **功能全面**：Spring Security提供了全面的安全功能，包括身份验证、授权、会话管理、CSRF保护等。

### 2. 功能集

- **Apache Shiro**：
  - **身份验证和授权**：支持多种身份验证机制和授权策略。
  - **会话管理**：支持Web和非Web应用程序的会话管理。
  - **加密**：提供加密和解密功能，支持多种加密算法。
  - **缓存**：支持缓存机制，可以提高身份验证和授权的性能。
  - **Web支持**：提供与Web框架的集成，但不如Spring Security深入。

- **Spring Security**：
  - **身份验证和授权**：支持多种身份验证机制和授权策略，包括基于角色的访问控制（RBAC）和基于权限的访问控制（PBAC）。
  - **会话管理**：提供强大的会话管理功能，包括会话固定保护、会话超时等。
  - **CSRF保护**：内置CSRF保护机制。
  - **OAuth2和OpenID**：支持OAuth2和OpenID等现代身份验证协议。
  - **Web支持**：与Spring MVC无缝集成，提供全面的Web安全功能。
  - **方法级安全**：支持方法级别的安全控制，可以通过注解（如`@PreAuthorize`, `@PostAuthorize`等）来控制方法访问权限。

### 3. 易用性

- **Apache Shiro**：
  - **简单易用**：Shiro的API设计简洁，易于理解和上手。
  - **配置简单**：Shiro的配置相对简单，可以通过INI文件或Java代码进行配置。

- **Spring Security**：
  - **配置复杂**：Spring Security的配置相对复杂，尤其是对于初学者来说。
  - **灵活性高**：Spring Security提供了高度的灵活性，可以根据需要进行高度定制。

### 4. 与Spring框架的集成

- **Apache Shiro**：
  - **独立于Spring**：Shiro可以与Spring框架集成，但集成程度不如Spring Security深入。
  - **需要额外配置**：需要手动配置Shiro与Spring的集成，如配置Shiro的过滤器链等。

- **Spring Security**：
  - **与Spring无缝集成**：Spring Security是Spring生态系统的一部分，与Spring框架的其他组件无缝集成。
  - **自动配置**：Spring Boot提供了自动配置功能，可以简化Spring Security的配置。

### 5. 社区和支持

- **Apache Shiro**：
  - **社区较小**：Shiro的社区相对较小，但仍然活跃。
  - **文档和资源**：Shiro的文档和资源相对较少，但基本功能都有详细的文档。

- **Spring Security**：
  - **社区庞大**：Spring Security是Spring生态系统的一部分，拥有庞大的社区和丰富的资源。
  - **文档和资源**：Spring Security的文档和资源非常丰富，包括官方文档、教程、示例等。

### 6. 适用场景

- **Apache Shiro**：
  - 适用于需要简单易用的安全解决方案的应用程序。
  - 适用于非Spring应用程序或需要与多种框架集成的应用程序。

- **Spring Security**：
  - 适用于基于Spring框架的应用程序，尤其是Spring Boot应用程序。
  - 适用于需要全面安全功能和高定制性的应用程序。

### 总结

- **Apache Shiro**：
  - 轻量级、简单易用，适用于各种类型的Java应用程序。
  - 独立于Spring框架，集成程度不如Spring Security深入。

- **Spring Security**：
  - 与Spring框架紧密集成，功能全面，适用于基于Spring的应用程序。
  - 配置复杂，但提供了高度的灵活性和强大的功能。

选择哪种框架取决于具体的应用需求和项目背景。如果你的应用程序基于Spring框架，并且需要全面和深入的安全功能，Spring Security是更好的选择。如果你的应用程序需要简单易用的安全解决方案，或者需要与多种框架集成，Apache Shiro可能更适合。



## Shiro接口
Apache Shiro是一个功能强大的安全框架，它提供了多个接口用于处理认证、授权、加密和会话管理等功能。下面是一些关键的Apache Shiro接口及其主要方法概览：

1. **Subject** 接口：
   - `getSession()`：获取当前Subject的会话。
   - `isAuthenticated()`：检查Subject是否已经通过认证。
   - `authenticate(AuthenticationToken token)`：执行登录操作。
   - `logout()`：登出当前Subject。
   - `isPermitted(String permission)`：检查Subject是否被允许执行特定的操作。
   - `hasRole(String roleIdentifier)`：检查Subject是否拥有某个角色。

2. **SecurityManager** 接口：
   - 作为Shiro的核心组件，它负责协调所有内部的安全操作。虽然它是核心，但它的接口相对简单，因为大多数安全性操作是通过`Subject`进行的。
   
3. **Realm** 接口：
   - `String getName()`：返回Realm的名字。
   - `boolean supports(AuthenticationToken token)`：检查此Realm是否支持指定类型的`AuthenticationToken`。
   - `AuthenticationInfo getAuthenticationInfo(AuthenticationToken token)`：根据提供的`AuthenticationToken`获取认证信息。
   - `AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals)`：根据主体信息获取授权信息。

4. **AuthenticationToken** 接口：
   - 代表传递给`Subject.login`方法的令牌，包含用户身份验证所需的信息。
   - 不同实现（如`UsernamePasswordToken`）可能提供额外的方法来设置用户名、密码等。

5. **AuthenticationInfo** 接口：
   - 包含成功认证后的相关信息，通常由Realm提供。
   
6. **AuthorizationInfo** 接口：
   - 包含角色和权限信息，通常也是由Realm提供。

7. **Session** 接口：
   - 提供了对会话的基本操作，比如`getId()`、`getAttribute(Object key)`、`setAttribute(Object key, Object value)`等。

8. **CacheManager** 接口：
   - 负责管理缓存实例，可以用于存储认证和授权信息以提高性能。

9. **RememberMeManager** 接口：
   - 管理“记住我”功能相关的逻辑。

注意，上述列出的是Shiro中一些主要接口及其部分方法。实际上，Apache Shiro还包含了更多的接口和类，以及这些接口的具体实现，它们共同协作完成复杂的安全需求。此外，由于Shiro的设计非常灵活，很多接口都有多种实现，可以根据具体的应用场景选择合适的实现或自定义实现。
## Shiro的核心组件有哪些?
**Apache Shiro** 是一个功能强大的安全框架，旨在为Java应用程序提供身份验证、授权、会话管理和加密等功能。Shiro的核心设计围绕着几个关键组件，这些组件协同工作以实现全面的安全性。以下是Shiro的核心组件及其功能：

### 1. 主体（Subject）

- **定义**：`Subject`是Shiro的核心接口，代表当前用户或应用程序的“用户”概念。它封装了当前用户的安全状态，包括身份验证状态、角色和权限。
- **功能**：
  - **身份验证（Authentication）**：验证用户的身份。
  - **授权（Authorization）**：检查用户是否具有特定的角色或权限。
  - **会话管理（Session Management）**：管理用户会话。
  - **退出（Logout）**：处理用户退出操作。

- **示例**：
  ```java
  Subject currentUser = SecurityUtils.getSubject();
  if (!currentUser.isAuthenticated()) {
      UsernamePasswordToken token = new UsernamePasswordToken("username", "password");
      currentUser.login(token);
  }
  ```

### 2. 安全管理器（SecurityManager）

- **定义**：`SecurityManager`是Shiro的核心组件，负责管理所有与安全相关的操作，包括身份验证、授权、会话管理和加密。它是Shiro架构中的单例，负责协调所有安全操作。
- **功能**：
  - 管理`Subject`实例。
  - 协调身份验证、授权、会话管理和加密等操作。
  - 维护应用程序的安全上下文。

- **配置示例**：
  ```java
  Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
  SecurityManager securityManager = factory.getInstance();
  SecurityUtils.setSecurityManager(securityManager);
  ```

### 3. 领域（Realm）

- **定义**：`Realm`是Shiro中的一个概念，用于从特定的数据源（如数据库、LDAP、文件系统等）中获取安全数据（如用户、角色和权限）。Shiro支持多个领域，可以配置多个领域来从不同的数据源获取安全信息。
- **功能**：
  - **身份验证**：验证用户的身份。
  - **授权**：提供用户的角色和权限信息。
  - **数据源访问**：从数据源（如数据库、LDAP等）中获取安全数据。

- **示例**：
  ```java
  public class MyRealm extends AuthorizingRealm {
      @Override
      protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
          // 获取授权信息
      }

      @Override
      protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
          // 获取身份验证信息
      }
  }
  ```

### 4. 会话（Session）

- **定义**：`Session`是Shiro提供的会话管理功能，用于管理用户会话。会话可以用于存储用户状态信息，支持Web和非Web应用程序。
- **功能**：
  - **会话创建和管理**：创建、更新和销毁会话。
  - **会话属性**：存储和检索会话属性。
  - **会话持久化**：支持会话持久化，可以将会话数据存储到数据库或缓存中。

- **示例**：
  ```java
  Session session = currentUser.getSession();
  session.setAttribute("key", "value");
  String value = (String) session.getAttribute("key");
  ```

### 5. 凭证匹配器（CredentialsMatcher）

- **定义**：`CredentialsMatcher`用于验证用户提供的凭证（如密码）与存储在数据源中的凭证是否匹配。Shiro提供了多种凭证匹配器实现，如`HashedCredentialsMatcher`用于密码哈希匹配。
- **功能**：
  - **凭证验证**：验证用户提供的凭证是否正确。
  - **凭证哈希**：支持密码哈希和匹配。

- **示例**：
  ```java
  HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
  matcher.setHashAlgorithmName("SHA-256");
  matcher.setHashIterations(1024);
  matcher.setStoredCredentialsHexEncoded(true);
  ```

### 6. 过滤器（Filter）

- **定义**：`Filter`是Shiro提供的过滤器机制，用于在Web应用程序中拦截HTTP请求，并执行安全检查。Shiro提供了多种内置过滤器，如`authc`（身份验证过滤器）、`roles`（角色过滤器）、`perms`（权限过滤器）等。
- **功能**：
  - **请求拦截**：拦截HTTP请求，执行安全检查。
  - **过滤器链配置**：配置过滤器链，控制请求的访问权限。

- **示例**：
  ```xml
  <filter>
      <filter-name>shiroFilter</filter-name>
      <filter-class>org.apache.shiro.web.servlet.IniShiroFilter</filter-class>
      <init-param>
          <param-name>configPath</param-name>
          <param-value>classpath:shiro.ini</param-value>
      </init-param>
  </filter>
  <filter-mapping>
      <filter-name>shiroFilter</filter-name>
      <url-pattern>/*</url-pattern>
  </filter-mapping>
  ```

### 7. 加密（Cryptography）

- **定义**：Shiro提供了加密和解密功能，支持多种加密算法。Shiro可以用于密码哈希、数据加密等。
- **功能**：
  - **密码哈希**：支持多种哈希算法，如SHA-256, bcrypt等。
  - **数据加密**：支持数据加密和解密。

- **示例**：
  ```java
  String hashedPassword = new Sha256Hash("password").toHex();
  ```

### 总结

Shiro的核心组件包括`Subject`, `SecurityManager`, `Realm`, `Session`, `CredentialsMatcher`, `Filter`和`Cryptography`。这些组件协同工作，提供了全面的安全性功能，使得开发者可以轻松地在Java应用程序中实现身份验证、授权、会话管理和加密等安全功能。





## Shiro如何处理认证和授权?
**Apache Shiro** 是一个功能强大的安全框架，提供了全面的身份验证（Authentication）和授权（Authorization）功能。以下是Shiro如何处理认证和授权的详细说明：

### 1. 认证（Authentication）

**认证**是验证用户身份的过程。Shiro通过`Subject`接口和`Realm`组件来实现认证。

#### 认证流程

1. **获取当前用户**：
   - 使用`SecurityUtils.getSubject()`方法获取当前用户（`Subject`）。

2. **创建认证令牌**：
   - 创建一个`AuthenticationToken`对象，通常使用`UsernamePasswordToken`，它封装了用户的用户名和密码。

3. **执行登录**：
   - 调用`subject.login(token)`方法执行登录操作。Shiro会调用配置的`Realm`来验证用户的身份。

4. **处理认证结果**：
   - 如果认证成功，用户将被标记为已认证。
   - 如果认证失败，Shiro会抛出相应的异常，如`UnknownAccountException`（未知账户）或`IncorrectCredentialsException`（密码错误）。

#### 示例代码

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;

public void authenticateUser(String username, String password) {
    Subject currentUser = SecurityUtils.getSubject();
    if (!currentUser.isAuthenticated()) {
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try {
            currentUser.login(token);
            System.out.println("用户认证成功");
        } catch (UnknownAccountException e) {
            System.out.println("账户不存在");
        } catch (IncorrectCredentialsException e) {
            System.out.println("密码错误");
        } catch (LockedAccountException e) {
            System.out.println("账户被锁定");
        } catch (AuthenticationException e) {
            System.out.println("认证失败: " + e.getMessage());
        }
    }
}
```

#### 认证过程

- **Realm**：
  - Shiro通过配置的`Realm`来获取用户的身份验证信息。`Realm`负责从数据源（如数据库、LDAP等）中获取用户信息，并验证用户提供的凭证。
  - `Realm`实现了`doGetAuthenticationInfo`方法，该方法返回一个`AuthenticationInfo`对象，包含用户的凭证信息。

- **凭证匹配**：
  - Shiro使用`CredentialsMatcher`来验证用户提供的凭证（如密码）与存储在`Realm`中的凭证是否匹配。

### 2. 授权（Authorization）

**授权**是控制用户对应用程序资源的访问权限的过程。Shiro通过`Subject`接口和`Realm`组件来实现授权。

#### 授权流程

1. **获取当前用户**：
   - 使用`SecurityUtils.getSubject()`方法获取当前用户（`Subject`）。

2. **检查角色或权限**：
   - 使用`subject.hasRole("roleName")`或`subject.isPermitted("permission")`方法检查用户是否具有特定的角色或权限。

3. **执行授权逻辑**：
   - 根据授权结果执行相应的逻辑，如允许访问资源或拒绝访问。

#### 示例代码

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

public void checkAuthorization() {
    Subject currentUser = SecurityUtils.getSubject();
    if (currentUser.hasRole("admin")) {
        System.out.println("用户具有admin角色");
    } else {
        System.out.println("用户没有admin角色");
    }

    if (currentUser.isPermitted("user:create")) {
        System.out.println("用户具有创建用户的权限");
    } else {
        System.out.println("用户没有创建用户的权限");
    }
}
```

#### 授权过程

- **Realm**：
  - Shiro通过配置的`Realm`来获取用户的角色和权限信息。`Realm`实现了`doGetAuthorizationInfo`方法，该方法返回一个`AuthorizationInfo`对象，包含用户的角色和权限信息。

- **角色和权限**：
  - Shiro支持基于角色的访问控制（RBAC）和基于权限的访问控制（PBAC）。
  - `hasRole("roleName")`方法用于检查用户是否具有特定的角色。
  - `isPermitted("permission")`方法用于检查用户是否具有特定的权限。

### 3. 权限表达式

Shiro支持使用权限表达式来定义复杂的权限逻辑。权限表达式可以使用通配符和逻辑运算符来匹配权限。

**示例**：

```java
if (currentUser.isPermitted("user:edit:*")) {
    // 用户具有编辑任何用户的权限
}

if (currentUser.isPermitted("user:edit:123")) {
    // 用户具有编辑ID为123的用户的权限
}
```

### 4. 总结

- **认证**：
  - 通过`Subject.login(token)`方法执行认证。
  - 使用`Realm`获取用户信息并验证凭证。
  - 使用`CredentialsMatcher`验证凭证。

- **授权**：
  - 通过`Subject.hasRole("roleName")`或`subject.isPermitted("permission")`方法检查角色和权限。
  - 使用`Realm`获取用户的角色和权限信息。
  - 支持权限表达式进行复杂的权限匹配。

通过以上机制，Shiro提供了灵活且强大的认证和授权功能，使得开发者可以轻松地在Java应用程序中实现全面的安全性。



## Shiro支持哪些认证方式?
**Apache Shiro** 是一个灵活且功能强大的安全框架，支持多种认证方式，以满足不同应用程序的需求。以下是Shiro支持的主要认证方式：

### 1. 基于用户名和密码的认证

这是最常见的认证方式，用户通过提供用户名和密码来进行身份验证。

**示例**：

```java
UsernamePasswordToken token = new UsernamePasswordToken("username", "password");
Subject currentUser = SecurityUtils.getSubject();
try {
    currentUser.login(token);
    System.out.println("用户认证成功");
} catch (AuthenticationException e) {
    System.out.println("认证失败: " + e.getMessage());
}
```

### 2. 基于令牌的认证

Shiro支持基于令牌的认证，例如使用JWT（JSON Web Token）或其他自定义令牌进行身份验证。

**示例**：

```java
AuthenticationToken token = new JwtToken(jwtTokenString);
Subject currentUser = SecurityUtils.getSubject();
try {
    currentUser.login(token);
    System.out.println("用户认证成功");
} catch (AuthenticationException e) {
    System.out.println("认证失败: " + e.getMessage());
}
```

### 3. 基于LDAP的认证

Shiro支持通过LDAP（轻量级目录访问协议）进行身份验证，适用于企业级应用。

**配置示例**：

```ini
[main]
ldapRealm = org.apache.shiro.realm.ldap.JndiLdapRealm
ldapRealm.contextFactory.url = ldap://ldap.example.com:389
ldapRealm.contextFactory.systemUsername = cn=admin,dc=example,dc=com
ldapRealm.contextFactory.systemPassword = secret
ldapRealm.userDnTemplate = uid={0},ou=users,dc=example,dc=com
```

### 4. 基于数据库的认证

Shiro可以从数据库中获取用户信息进行身份验证。开发者可以自定义`Realm`来实现数据库认证。

**示例**：

```java
public class DatabaseRealm extends AuthorizingRealm {
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        // 从数据库中获取用户信息
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }
}
```

### 5. 基于OAuth的认证

Shiro支持OAuth 1.0和OAuth 2.0协议，适用于需要与第三方身份提供者集成的应用。

**示例**：

```java
OAuthToken token = new OAuthToken(oauthTokenString, oauthTokenSecret);
Subject currentUser = SecurityUtils.getSubject();
try {
    currentUser.login(token);
    System.out.println("用户认证成功");
} catch (AuthenticationException e) {
    System.out.println("认证失败: " + e.getMessage());
}
```

### 6. 基于OpenID的认证

Shiro支持OpenID协议，适用于需要使用OpenID进行身份验证的应用。

**示例**：

```java
OpenIdToken token = new OpenIdToken(openIdUrl);
Subject currentUser = SecurityUtils.getSubject();
try {
    currentUser.login(token);
    System.out.println("用户认证成功");
} catch (AuthenticationException e) {
    System.out.println("认证失败: " + e.getMessage());
}
```

### 7. 基于多因素认证（MFA）

Shiro支持多因素认证（MFA），可以通过自定义`Realm`或使用第三方库来实现。

**示例**：

```java
UsernamePasswordToken token = new UsernamePasswordToken("username", "password");
token.setRememberMe(true);
Subject currentUser = SecurityUtils.getSubject();
try {
    currentUser.login(token);
    System.out.println("用户认证成功");
} catch (AuthenticationException e) {
    System.out.println("认证失败: " + e.getMessage());
}
```

### 8. 基于自定义认证

开发者可以自定义认证逻辑，通过实现`Realm`接口来实现自定义的认证机制。

**示例**：

```java
public class CustomRealm extends AuthorizingRealm {
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 自定义认证逻辑
        String username = (String) token.getPrincipal();
        // 从自定义数据源获取用户信息
        User user = customUserService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }
}
```

### 总结

Shiro支持多种认证方式，包括：

- 基于用户名和密码的认证
- 基于令牌的认证（如JWT）
- 基于LDAP的认证
- 基于数据库的认证
- 基于OAuth和OpenID的认证
- 基于多因素认证（MFA）
- 基于自定义认证

通过这些认证方式，Shiro能够满足各种应用程序的安全需求，开发者可以根据具体需求选择合适的认证方式。

## Shiro如何处理密码加密?
在**Apache Shiro**中，密码加密是保护用户密码安全的重要环节。Shiro提供了灵活的密码加密和匹配机制，支持多种加密算法和哈希函数。以下是Shiro如何处理密码加密的详细说明：

### 1. 密码加密的基本概念

- **加密（Encryption）**：将明文密码转换为不可读的密文，通常使用对称加密算法（如AES）或非对称加密算法（如RSA）。
- **哈希（Hashing）**：将明文密码转换为固定长度的哈希值，通常使用单向哈希函数（如SHA-256, bcrypt等）。哈希是不可逆的，无法从哈希值还原出原始密码。

在大多数情况下，密码存储使用哈希而不是加密，因为哈希更安全且不需要存储密钥。

### 2. Shiro的密码加密机制

Shiro通过`CredentialsMatcher`接口来处理密码加密和匹配。`CredentialsMatcher`负责将用户输入的密码与存储在数据库或其他数据源中的密码进行匹配。

#### 主要的`CredentialsMatcher`实现：

1. **`HashedCredentialsMatcher`**：
   - 支持多种哈希算法，如SHA-256, bcrypt, MD5等。
   - 可以配置哈希迭代次数、盐值等参数。

2. **`SimpleCredentialsMatcher`**：
   - 直接比较用户输入的密码和存储的密码，不进行加密或哈希。

3. **`PasswordMatcher`**：
   - 用于自定义密码匹配逻辑。

### 3. 使用`HashedCredentialsMatcher`进行密码哈希

`HashedCredentialsMatcher`是Shiro中常用的密码匹配器，支持多种哈希算法。以下是配置和使用`HashedCredentialsMatcher`的步骤：

#### 配置`HashedCredentialsMatcher`

```java
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("SHA-256"); // 设置哈希算法
        matcher.setHashIterations(1024); // 设置哈希迭代次数
        matcher.setStoredCredentialsHexEncoded(true); // 设置是否以十六进制存储
        return matcher;
    }

    @Bean
    public AuthorizingRealm myRealm(HashedCredentialsMatcher matcher) {
        MyRealm realm = new MyRealm();
        realm.setCredentialsMatcher(matcher);
        return realm;
    }

    @Bean
    public SecurityManager securityManager(AuthorizingRealm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        return securityManager;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        // 配置URL权限
        chainDefinition.addPathDefinition("/login", "anon");
        chainDefinition.addPathDefinition("/**", "authc");
        return chainDefinition;
    }
}
```

#### 自定义`Realm`

```java
import org.apache.shiro.authc.*;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class MyRealm extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取授权信息
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取用户输入的用户名
        String username = (String) token.getPrincipal();
        // 从数据库中获取用户信息
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        // 返回认证信息
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }
}
```

#### 密码存储

在用户注册或密码更改时，需要对密码进行哈希处理并存储。

```java
import org.apache.shiro.crypto.hash.Sha256Hash;

public void registerUser(String username, String password) {
    // 生成盐值
    String salt = new SecureRandomNumberGenerator().nextBytes().toHex();
    // 对密码进行哈希处理
    String hashedPassword = new Sha256Hash(password, salt, 1024).toHex();
    // 存储用户信息，包括用户名、哈希后的密码和盐值
    userService.saveUser(username, hashedPassword, salt);
}
```

### 4. 使用盐值（Salt）

为了防止彩虹表攻击，Shiro支持使用盐值（Salt）来增强密码哈希的安全性。盐值是随机生成的字符串，与密码一起进行哈希处理。

**示例**：

```java
String salt = new SecureRandomNumberGenerator().nextBytes().toHex();
String hashedPassword = new Sha256Hash(password, salt, 1024).toHex();
```

在`HashedCredentialsMatcher`中，Shiro会自动使用存储的盐值进行密码匹配。

### 5. 总结

Shiro通过`CredentialsMatcher`接口和`HashedCredentialsMatcher`实现来处理密码加密和匹配，支持多种哈希算法和盐值的使用。开发者可以根据具体需求选择合适的哈希算法和配置参数，以增强应用程序的安全性。

### 常用哈希算法

- **SHA-256**：常用的安全哈希算法。
- **bcrypt**：一种自适应哈希函数，具有较高的安全性。
- **scrypt**：一种内存密集型哈希函数，适用于需要更高安全性的场景。

通过合理配置和使用Shiro的密码加密机制，开发者可以有效地保护用户密码的安全。




# 架构与组件
## Shiro的架构是怎样的?
### Apache Shiro的整体架构


Shiro的架构设计简洁且模块化，主要由以下几个核心部分组成：

1. **Subject（主体）**
2. **SecurityManager（安全管理器）**
3. **Realms（领域）**
4. **Session Management（会话管理）**
5. **Cache Management（缓存管理）**
6. **Cryptography（加密）**
7. **Authorization（授权）**
8. **Authentication（认证）**

这些组件共同构成了Shiro的安全框架，提供了身份验证、授权、会话管理、加密等功能。以下是Shiro架构的详细说明：

### 1. Subject（主体）

- **位置**：Shiro架构的最上层。
- **功能**：
  - **代表当前用户**：`Subject`是Shiro的核心接口，代表当前用户或应用程序的“用户”概念。
  - **封装安全操作**：`Subject`封装了所有与安全相关的操作，包括身份验证、授权、会话管理和退出。
  - **与SecurityManager交互**：`Subject`通过`SecurityManager`执行安全操作。

- **使用场景**：
  - 开发者通过`Subject`接口与Shiro进行交互，执行身份验证、授权、会话管理等操作。

- **示例**：
  ```java
  Subject currentUser = SecurityUtils.getSubject();
  if (!currentUser.isAuthenticated()) {
      UsernamePasswordToken token = new UsernamePasswordToken("username", "password");
      currentUser.login(token);
  }
  ```

### 2. SecurityManager（安全管理器）

- **位置**：Shiro架构的核心，负责协调所有安全操作。
- **功能**：
  - **管理Subject实例**：`SecurityManager`负责管理所有`Subject`实例。
  - **协调安全操作**：`SecurityManager`协调身份验证、授权、会话管理和加密等操作。
  - **维护安全上下文**：`SecurityManager`维护应用程序的安全上下文。

- **使用场景**：
  - `SecurityManager`是Shiro的核心管理器，所有安全操作都通过它来协调。

- **配置示例**：
  ```java
  Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
  SecurityManager securityManager = factory.getInstance();
  SecurityUtils.setSecurityManager(securityManager);
  ```

### 3. Realms（领域）

- **位置**：Shiro架构的底层，负责与数据源交互。
- **功能**：
  - **身份验证（Authentication）**：验证用户的身份。
  - **授权（Authorization）**：提供用户的角色和权限信息。
  - **数据源访问**：`Realm`从数据源（如数据库、LDAP等）中获取安全数据。

- **使用场景**：
  - `Realm`是Shiro与实际数据源交互的桥梁，开发者可以通过实现`Realm`接口来自定义数据源访问逻辑。

- **示例**：
  ```java
  public class MyRealm extends AuthorizingRealm {
      @Override
      protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
          // 获取授权信息
      }

      @Override
      protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
          // 获取身份验证信息
      }
  }
  ```

### 4. Session Management（会话管理）

- **位置**：Shiro架构的一部分，负责管理用户会话。
- **功能**：
  - **会话创建和管理**：创建、更新和销毁会话。
  - **会话属性**：存储和检索会话属性。
  - **会话持久化**：支持会话持久化，可以将会话数据存储到数据库或缓存中。

- **使用场景**：
  - 管理用户会话，支持会话持久化和集群。

### 5. Cache Management（缓存管理）

- **位置**：Shiro架构的一部分，负责管理缓存。
- **功能**：
  - **缓存身份验证和授权信息**：提高身份验证和授权的性能。
  - **缓存会话数据**：提高会话管理的性能。

- **使用场景**：
  - 提高Shiro的性能，减少对数据源的访问次数。

### 6. Cryptography（加密）

- **位置**：Shiro架构的一部分，负责加密和解密。
- **功能**：
  - **密码哈希**：支持多种哈希算法，如SHA-256, bcrypt等。
  - **数据加密**：支持数据加密和解密。

- **使用场景**：
  - 保护用户密码安全，加密敏感数据。

### 7. Authorization（授权）

- **位置**：Shiro架构的一部分，负责授权。
- **功能**：
  - **角色和权限管理**：管理用户的角色和权限。
  - **访问控制**：控制用户对应用程序资源的访问权限。

- **使用场景**：
  - 实现基于角色的访问控制（RBAC）和基于权限的访问控制（PBAC）。

### 8. Authentication（认证）

- **位置**：Shiro架构的一部分，负责认证。
- **功能**：
  - **身份验证**：验证用户的身份。
  - **凭证匹配**：验证用户提供的凭证（如密码）与存储在数据源中的凭证是否匹配。

- **使用场景**：
  - 实现用户身份验证，确保用户身份的真实性和安全性。

### 总结

Shiro的架构设计简洁且模块化，核心组件包括`Subject`, `SecurityManager`, `Realm`, `SessionManager`, `CacheManager`, `Cryptography`, `Authorization`和`Authentication`。这些组件协同工作，提供了全面的安全性功能，使得开发者可以轻松地在Java应用程序中实现身份验证、授权、会话管理和加密等安全功能。

通过这种架构，Shiro能够灵活地适应各种应用场景，并提供高度可定制和可扩展的安全解决方案。




## Subject在Shiro架构中扮演什么角色
在**Apache Shiro**的架构中，**Subject**是一个核心概念和接口，代表了应用程序的“当前用户”或“主体”。Subject在Shiro中扮演着至关重要的角色，负责封装与用户相关的所有安全操作和状态。以下是Subject在Shiro架构中的详细角色和功能：

### 1. Subject的定义

- **Subject**是Shiro的核心接口，代表当前用户或应用程序的“用户”概念。它封装了当前用户的安全状态，包括身份验证状态、角色和权限。
- Subject是一个抽象概念，可以代表任何与安全相关的实体，如用户、应用程序、服务等。

### 2. Subject的主要功能

Subject在Shiro中负责执行与用户相关的所有安全操作，主要功能包括：

#### a. 身份验证（Authentication）

- **功能**：验证用户的身份，确认用户是否是他们声称的那个人。
- **方法**：
  - `login(AuthenticationToken token)`: 执行登录操作，验证用户身份。
  - `logout()`: 执行登出操作，结束用户会话。

- **示例**：
  ```java
  Subject currentUser = SecurityUtils.getSubject();
  if (!currentUser.isAuthenticated()) {
      UsernamePasswordToken token = new UsernamePasswordToken("username", "password");
      currentUser.login(token);
  }
  ```

#### b. 授权（Authorization）

- **功能**：控制用户对应用程序资源的访问权限，检查用户是否具有特定的角色或权限。
- **方法**：
  - `hasRole(String roleName)`: 检查用户是否具有特定的角色。
  - `isPermitted(String permission)`: 检查用户是否具有特定的权限。

- **示例**：
  ```java
  if (currentUser.hasRole("admin")) {
      System.out.println("用户具有admin角色");
  }

  if (currentUser.isPermitted("user:create")) {
      System.out.println("用户具有创建用户的权限");
  }
  ```

#### c. 会话管理（Session Management）

- **功能**：管理用户会话，支持Web和非Web应用程序。
- **方法**：
  - `getSession()`: 获取当前用户的会话对象。
  - `getSession(boolean create)`: 获取当前用户的会话对象，如果不存在则根据参数决定是否创建新的会话。

- **示例**：
  ```java
  Session session = currentUser.getSession();
  session.setAttribute("key", "value");
  String value = (String) session.getAttribute("key");
  ```

#### d. 其他功能

- **获取用户信息**：
  - `getPrincipal()`: 获取当前用户的主体信息，通常是用户名或用户对象。
  - `getPrincipals()`: 获取当前用户的主体集合。

- **检查认证状态**：
  - `isAuthenticated()`: 检查用户是否已认证。
  - `isRemembered()`: 检查用户是否通过“记住我”功能认证。

### 3. Subject在Shiro架构中的位置

- **位置**：Subject位于Shiro架构的最上层，直接与应用程序代码交互。
- **与SecurityManager的关系**：
  - Subject通过`SecurityManager`执行所有安全操作。`SecurityManager`是Shiro的核心管理器，负责协调所有安全操作。
  - 当应用程序调用Subject的方法时，Subject会将请求委托给`SecurityManager`，由`SecurityManager`执行具体的操作。

- **图示**：

  ```
  +-----------------+
  |    Application  |
  +-----------------+
          |
          | Subject API
          v
  +-----------------+
  |    SecurityManager   |
  +-----------------+
          |
          | Realm
          v
  +-----------------+
  |      Realm      |
  +-----------------+
  ```

### 4. Subject的使用场景

- **Web应用程序**：在Web应用程序中，Shiro会自动为每个HTTP请求创建一个Subject实例，代表当前请求的用户。
- **非Web应用程序**：在非Web应用程序中，开发者可以手动创建和管理Subject实例。

### 5. 总结

Subject在Shiro架构中扮演着至关重要的角色，它是Shiro与应用程序代码交互的桥梁，封装了所有与用户相关的安全操作和状态。通过Subject，开发者可以轻松地执行身份验证、授权、会话管理和其他安全操作，而无需关心底层的安全实现细节。

### 关键点

- **Subject是Shiro的核心接口**，代表当前用户。
- **封装了所有与用户相关的安全操作**，包括身份验证、授权、会话管理等。
- **通过SecurityManager执行安全操作**，与Shiro的其他组件协同工作。
- **适用于Web和非Web应用程序**，提供了灵活的安全管理机制。

通过理解Subject的角色和功能，开发者可以更好地应用Shiro框架，构建安全可靠的Java应用程序。




## SecurityManager的作用是什么?
在**Apache Shiro**架构中，**SecurityManager**是一个核心组件，负责管理和协调应用程序的所有安全操作。它充当了Shiro框架的“大脑”，负责处理身份验证、授权、会话管理、缓存管理、加密等安全相关的功能。以下是**SecurityManager**在Shiro架构中的详细作用和功能：

### 1. SecurityManager的定义

- **SecurityManager**是Shiro的核心管理器，负责协调和管理所有与安全相关的操作。它是Shiro架构中的核心组件，所有安全操作都通过它来执行。
- SecurityManager是一个单例对象，负责维护应用程序的安全上下文，并协调各个安全组件（如Realm、SessionManager、CacheManager等）的工作。

### 2. SecurityManager的主要功能

#### a. 身份验证（Authentication）

- **功能**：验证用户的身份，确认用户是否是他们声称的那个人。
- **实现**：
  - SecurityManager通过配置的Realm获取用户的身份验证信息，并使用CredentialsMatcher验证用户提供的凭证（如密码）。
  - 当用户调用`Subject.login(token)`时，SecurityManager会处理身份验证逻辑。

#### b. 授权（Authorization）

- **功能**：控制用户对应用程序资源的访问权限，检查用户是否具有特定的角色或权限。
- **实现**：
  - SecurityManager通过Realm获取用户的角色和权限信息，并使用这些信息来执行授权检查。
  - 当用户调用`Subject.hasRole(roleName)`或`Subject.isPermitted(permission)`时，SecurityManager会处理授权逻辑。

#### c. 会话管理（Session Management）

- **功能**：管理用户会话，支持Web和非Web应用程序。
- **实现**：
  - SecurityManager通过SessionManager创建、更新和销毁用户会话。
  - 当用户调用`Subject.getSession()`时，SecurityManager会处理会话管理逻辑。

#### d. 缓存管理（Cache Management）

- **功能**：管理Shiro的缓存机制，提高身份验证和授权的性能。
- **实现**：
  - SecurityManager通过CacheManager缓存身份验证和授权信息，减少对数据源的访问次数。
  - 当用户进行身份验证或授权操作时，SecurityManager会使用缓存来提高性能。

#### e. 加密（Cryptography）

- **功能**：提供加密和解密功能，支持多种加密算法。
- **实现**：
  - SecurityManager通过Cryptography模块处理密码哈希、数据加密等操作。
  - 当用户进行密码验证或数据加密操作时，SecurityManager会使用Cryptography模块。

#### f. 安全管理上下文（Security Context）

- **功能**：维护应用程序的安全上下文，管理当前用户的安全状态。
- **实现**：
  - SecurityManager维护当前用户的安全上下文，包括身份验证状态、角色和权限信息。
  - 当用户进行安全操作时，SecurityManager会更新和查询安全上下文。

### 3. SecurityManager在Shiro架构中的位置

- **位置**：SecurityManager位于Shiro架构的核心，负责协调和管理所有安全操作。
- **与Subject的关系**：
  - Subject是Shiro与应用程序代码交互的桥梁，而SecurityManager是Subject的后台管理器。
  - 当应用程序调用Subject的方法时，Subject会将请求委托给SecurityManager，由SecurityManager执行具体的操作。

- **图示**：

  ```
  +-----------------+
  |    Application  |
  +-----------------+
          |
          | Subject API
          v
  +-----------------+
  |    SecurityManager   |
  +-----------------+
          |
          | Realm, SessionManager, CacheManager, Cryptography, etc.
          v
  +-----------------+
  |      Realm      |
  +-----------------+
  ```

### 4. SecurityManager的配置

- **配置方式**：
  - 可以通过Java配置或XML配置来配置SecurityManager。
  - 通常需要配置Realm、SessionManager、CacheManager等组件。

- **示例**（Java配置）：

  ```java
  @Configuration
  public class ShiroConfig {

      @Bean
      public SecurityManager securityManager() {
          DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
          securityManager.setRealm(myRealm());
          securityManager.setSessionManager(sessionManager());
          securityManager.setCacheManager(cacheManager());
          return securityManager;
      }

      @Bean
      public Realm myRealm() {
          // 配置Realm
      }

      @Bean
      public SessionManager sessionManager() {
          // 配置SessionManager
      }

      @Bean
      public CacheManager cacheManager() {
          // 配置CacheManager
      }
  }
  ```

### 5. 总结

**SecurityManager**在Shiro架构中扮演着至关重要的角色，负责管理和协调所有与安全相关的操作。它是Shiro框架的核心管理器，充当了Shiro的“大脑”，通过与Realm、SessionManager、CacheManager等组件协同工作，提供了全面的安全性功能。

### SecurityManager的关键功能

- **身份验证和授权**：处理用户身份验证和授权逻辑。
- **会话管理**：管理用户会话，支持Web和非Web应用程序。
- **缓存管理**：缓存身份验证和授权信息，提高性能。
- **加密**：处理密码哈希和数据加密。
- **安全管理上下文**：维护当前用户的安全状态。

通过理解SecurityManager的作用和功能，开发者可以更好地配置和使用Shiro框架，构建安全可靠的Java应用程序。



## Realm在Shiro中是如何工作的?
在**Apache Shiro**中，**Realm**是一个非常重要的组件，负责从特定的数据源（如数据库、LDAP、文件系统等）中获取安全数据（如用户信息、角色和权限）。Realm充当了Shiro与实际数据源之间的桥梁，使得Shiro能够获取必要的信息来进行身份验证和授权。以下是Realm在Shiro中的工作原理和详细功能：

### 1. Realm的定义

- **Realm**是Shiro中的一个概念，用于从特定的数据源中获取安全数据。它是Shiro与实际数据源（如数据库、LDAP等）交互的桥梁。
- Realm负责提供用户的身份验证信息和授权信息，包括用户的角色和权限。

### 2. Realm的主要功能

Realm在Shiro中主要负责以下两个功能：

#### a. 身份验证（Authentication）

- **功能**：提供用户的身份验证信息，验证用户的身份。
- **实现**：
  - Realm实现了`doGetAuthenticationInfo`方法，该方法接收一个`AuthenticationToken`对象，并返回一个`AuthenticationInfo`对象。
  - `AuthenticationInfo`对象包含了用户的身份验证信息，如用户名和密码（通常是加密后的密码）。

- **示例**：
  ```java
  public class MyRealm extends AuthorizingRealm {
      @Override
      protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
          String username = (String) token.getPrincipal();
          User user = userService.findByUsername(username);
          if (user == null) {
              throw new UnknownAccountException("账户不存在");
          }
          return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
      }
  }
  ```

#### b. 授权（Authorization）

- **功能**：提供用户的角色和权限信息，控制用户对应用程序资源的访问权限。
- **实现**：
  - Realm实现了`doGetAuthorizationInfo`方法，该方法接收一个`PrincipalCollection`对象，并返回一个`AuthorizationInfo`对象。
  - `AuthorizationInfo`对象包含了用户的角色和权限信息。

- **示例**：
  ```java
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
      String username = (String) principals.getPrimaryPrincipal();
      User user = userService.findByUsername(username);
      if (user == null) {
          throw new UnknownAccountException("账户不存在");
      }
      SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
      info.setRoles(user.getRoles());
      info.setStringPermissions(user.getPermissions());
      return info;
  }
  ```

### 3. Realm的工作流程

1. **身份验证**：
   - 当用户尝试登录时，Shiro会调用Realm的`doGetAuthenticationInfo`方法。
   - Realm从数据源中获取用户的身份验证信息（如用户名和密码）。
   - Shiro使用`CredentialsMatcher`验证用户提供的凭证（如密码）与Realm返回的凭证是否匹配。

2. **授权**：
   - 当用户尝试访问受保护的资源时，Shiro会调用Realm的`doGetAuthorizationInfo`方法。
   - Realm从数据源中获取用户的角色和权限信息。
   - Shiro使用这些信息来执行授权检查，控制用户对资源的访问权限。

### 4. Realm的类型

Shiro支持多种类型的Realm，可以根据不同的数据源和需求选择合适的Realm类型：

1. **JdbcRealm**：
   - 从关系型数据库中获取安全数据。
   - 需要配置数据源和SQL语句。

2. **LdapRealm**：
   - 从LDAP服务器中获取安全数据。
   - 适用于企业级应用。

3. **IniRealm**：
   - 从INI文件中获取安全数据。
   - 适用于简单的应用场景。

4. **PropertiesRealm**：
   - 从属性文件中获取安全数据。
   - 适用于简单的应用场景。

5. **CustomRealm**：
   - 开发者可以自定义Realm，实现自定义的数据源访问逻辑。
   - 适用于复杂或特定的数据源需求。

### 5. 配置Realm

可以通过Java配置或XML配置来配置Realm。以下是使用Java配置配置Realm的示例：

```java
@Configuration
public class ShiroConfig {

    @Bean
    public Realm myRealm() {
        MyRealm realm = new MyRealm();
        realm.setCredentialsMatcher(hashedCredentialsMatcher());
        return realm;
    }

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("SHA-256");
        matcher.setHashIterations(1024);
        matcher.setStoredCredentialsHexEncoded(true);
        return matcher;
    }

    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(myRealm());
        return securityManager;
    }
}
```

### 6. 总结

Realm在Shiro中扮演着至关重要的角色，负责从数据源中获取安全数据，并提供身份验证和授权信息。通过实现Realm接口，开发者可以自定义数据源访问逻辑，灵活地集成Shiro与各种数据源。Realm的工作流程包括身份验证和授权两个主要步骤，Shiro通过Realm获取必要的信息来执行安全操作。

### Realm的关键点

- **Realm是Shiro与数据源之间的桥梁**。
- **负责提供身份验证和授权信息**。
- **支持多种数据源**，包括数据库、LDAP、文件系统等。
- **可以通过自定义Realm实现特定的数据源访问逻辑**。

通过理解Realm的工作原理和功能，开发者可以更好地配置和使用Shiro框架，构建安全可靠的Java应用程序。





## Shiro如何与不同的数据源（如数据库、LDAP等) 集成?
**Apache Shiro** 是一个灵活的安全框架，支持与多种数据源集成，如数据库、LDAP（轻量级目录访问协议）、文件系统等。通过使用不同的**Realm**实现，Shiro可以与各种数据源进行交互，从而实现身份验证和授权。以下是Shiro如何与不同数据源集成的详细说明：

### 1. 集成数据库

Shiro可以通过**JdbcRealm**或自定义Realm与关系型数据库（如MySQL, PostgreSQL等）集成。

#### a. 使用JdbcRealm

**JdbcRealm**是Shiro提供的一个内置Realm实现，可以直接从数据库中获取用户信息、角色和权限。

**配置示例**：

```java
@Bean
public Realm jdbcRealm() {
    JdbcRealm realm = new JdbcRealm();
    realm.setDataSource(dataSource());
    realm.setAuthenticationQuery("SELECT password FROM users WHERE username = ?");
    realm.setUserRolesQuery("SELECT role_name FROM user_roles WHERE username = ?");
    realm.setPermissionsQuery("SELECT permission FROM roles_permissions WHERE role_name = ?");
    realm.setCredentialsMatcher(hashedCredentialsMatcher());
    return realm;
}
```

**说明**：
- `setAuthenticationQuery`：设置用于身份验证的SQL查询。
- `setUserRolesQuery`：设置用于获取用户角色的SQL查询。
- `setPermissionsQuery`：设置用于获取用户权限的SQL查询。
- `setCredentialsMatcher`：设置密码匹配器。

#### b. 使用自定义Realm

如果需要更复杂的数据库访问逻辑，可以实现自定义Realm。

**示例**：

```java
public class DatabaseRealm extends AuthorizingRealm {

    @Autowired
    private UserRepository userRepository;

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(user.getRoles());
        info.setStringPermissions(user.getPermissions());
        return info;
    }
}
```

**说明**：
- 通过依赖注入（`@Autowired`）使用Spring Data JPA或其他ORM框架访问数据库。
- 实现`doGetAuthenticationInfo`和`doGetAuthorizationInfo`方法，从数据库中获取用户信息、角色和权限。

### 2. 集成LDAP

Shiro可以通过**LdapRealm**与LDAP服务器（如Active Directory, OpenLDAP等）集成，适用于企业级应用。

#### a. 配置LdapRealm

**示例**：

```java
@Bean
public Realm ldapRealm() {
    LdapRealm realm = new LdapRealm();
    realm.setContextFactory(contextFactory());
    realm.setUserDnTemplate("uid={0},ou=users,dc=example,dc=com");
    realm.setGroupSearchBase("ou=groups,dc=example,dc=com");
    realm.setGroupObjectClass("groupOfNames");
    realm.setGroupIdAttribute("cn");
    return realm;
}

@Bean
public LdapContextFactory contextFactory() {
    DefaultLdapContextFactory factory = new DefaultLdapContextFactory();
    factory.setUrl("ldap://ldap.example.com:389");
    factory.setSystemUsername("cn=admin,dc=example,dc=com");
    factory.setSystemPassword("password");
    return factory;
}
```

**说明**：
- `setUserDnTemplate`：设置用户DN模板，用于查找用户。
- `setGroupSearchBase`和`setGroupObjectClass`：设置组搜索基础和组对象类。
- `setGroupIdAttribute`：设置组ID属性。

### 3. 集成文件系统

Shiro可以通过**PropertiesRealm**或自定义Realm与文件系统集成，适用于简单的应用场景。

#### a. 使用PropertiesRealm

**PropertiesRealm**可以从属性文件中加载用户信息、角色和权限。

**配置示例**：

```java
@Bean
public Realm propertiesRealm() {
    PropertiesRealm realm = new PropertiesRealm();
    realm.setResourcePath("classpath:shiro-users.properties");
    realm.setCredentialsMatcher(hashedCredentialsMatcher());
    return realm;
}
```

**说明**：
- `setResourcePath`：设置属性文件的路径。
- 属性文件示例（shiro-users.properties）：
  ```
  username=password,role1,role2
  ```

### 4. 集成自定义数据源

如果需要集成其他类型的数据源（如NoSQL数据库、REST服务等），可以创建自定义Realm。

**示例**：

```java
public class CustomRealm extends AuthorizingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 自定义身份验证逻辑
        String username = (String) token.getPrincipal();
        // 从自定义数据源获取用户信息
        User user = customUserService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 自定义授权逻辑
        String username = (String) principals.getPrimaryPrincipal();
        User user = customUserService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(user.getRoles());
        info.setStringPermissions(user.getPermissions());
        return info;
    }
}
```

### 5. 总结

Shiro通过不同的Realm实现与各种数据源集成，包括数据库、LDAP、文件系统等。开发者可以根据具体需求选择合适的Realm类型，并配置相应的数据源访问逻辑。通过这种方式，Shiro可以灵活地与不同的数据源协同工作，实现全面的身份验证和授权功能。

### 关键点

- **JdbcRealm**：用于从关系型数据库中获取安全数据。
- **LdapRealm**：用于从LDAP服务器中获取安全数据。
- **PropertiesRealm**：用于从属性文件中获取安全数据。
- **自定义Realm**：用于集成其他类型的数据源，如NoSQL数据库、REST服务等。

通过合理配置和使用不同的Realm，Shiro可以与各种数据源无缝集成，满足不同应用程序的安全需求。



## Shiro的Session管理是如何实现的?
**Apache Shiro** 提供了强大的**Session管理**功能，支持Web和非Web应用程序。Shiro的Session管理机制允许开发者轻松地管理用户会话，包括会话创建、更新、销毁、会话属性管理、会话持久化等。以下是Shiro的Session管理的详细实现机制：

### 1. Session的概念

- **Session** 是用户与应用程序交互期间的状态管理单元。它通常用于存储用户的状态信息，如用户身份、权限、会话属性等。
- Shiro的Session接口类似于Java Servlet的`HttpSession`，但Shiro的Session管理不依赖于Web容器，可以在Web和非Web应用程序中使用。

### 2. SessionManager

**SessionManager** 是Shiro中负责管理Session的核心组件。它负责创建、更新、销毁Session，并维护Session的生命周期。

#### 主要功能：

- **创建Session**：当用户首次与应用程序交互时，SessionManager会创建一个新的Session。
- **获取Session**：通过`Subject.getSession()`方法获取当前用户的Session。
- **更新Session**：在用户与应用程序交互期间，SessionManager会定期更新Session的状态。
- **销毁Session**：当用户退出或Session超时，SessionManager会销毁Session。

#### SessionManager的类型：

- **DefaultWebSessionManager**：用于Web应用程序，基于Servlet容器的Session管理。
- **DefaultSessionManager**：用于非Web应用程序，独立于Web容器。

### 3. Session的创建和获取

#### 创建Session

当用户首次与应用程序交互时，Shiro会自动创建一个新的Session。例如，在Web应用程序中，当用户发送第一个请求时，Shiro会创建一个Session。

#### 获取Session

开发者可以通过`Subject.getSession()`方法获取当前用户的Session。

**示例**：

```java
Subject currentUser = SecurityUtils.getSession();
Session session = currentUser.getSession();
if (session == null) {
    session = currentUser.startSession();
}
session.setAttribute("key", "value");
```

### 4. Session的属性管理

Session可以存储任意类型的属性，类似于`HttpSession`。开发者可以通过Session对象设置和获取属性。

**示例**：

```java
Session session = currentUser.getSession();
session.setAttribute("user", user);
User user = (User) session.getAttribute("user");
```

### 5. Session的生命周期

#### a. 会话超时

SessionManager可以配置会话超时时间。当会话超过指定时间没有活动时，SessionManager会自动销毁该会话。

**配置示例**：

```java
@Bean
public SessionManager sessionManager() {
    DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
    sessionManager.setGlobalSessionTimeout(1800000); // 设置会话超时时间为30分钟
    return sessionManager;
}
```

#### b. 会话持久化

Shiro支持会话持久化，可以将会话数据存储到数据库或缓存中，以便在应用程序重启后恢复会话。

**配置示例**：

```java
@Bean
public SessionDAO sessionDAO() {
    EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
    sessionDAO.setActiveSessionsCache(cacheManager().getCache("shiro-activeSessionCache"));
    return sessionDAO;
}

@Bean
public SessionManager sessionManager() {
    DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
    sessionManager.setSessionDAO(sessionDAO());
    return sessionManager;
}
```

### 6. Session的持久化

Shiro支持多种Session持久化机制，可以通过配置不同的SessionDAO来实现。

#### a. EnterpriseCacheSessionDAO

- **功能**：将会话数据存储到缓存中。
- **优点**：高性能，适用于分布式缓存（如Ehcache, Redis等）。

**配置示例**：

```java
@Bean
public CacheManager cacheManager() {
    return new EhCacheManager();
}

@Bean
public SessionDAO sessionDAO() {
    EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
    sessionDAO.setActiveSessionsCache(cacheManager().getCache("shiro-activeSessionCache"));
    return sessionDAO;
}
```

#### b. JDBCSessionDAO

- **功能**：将会话数据存储到关系型数据库中。
- **优点**：适用于需要持久化会话数据的场景。

**配置示例**：

```java
@Bean
public SessionDAO sessionDAO() {
    JdbcSessionDAO sessionDAO = new JdbcSessionDAO();
    sessionDAO.setDataSource(dataSource());
    sessionDAO.setDeleteExpiredSessions(true);
    return sessionDAO;
}
```

### 7. Session的集群

Shiro支持Session集群，可以通过配置不同的SessionDAO和缓存实现来实现。例如，使用Redis作为缓存，可以实现分布式Session管理。

**配置示例**：

```java
@Bean
public CacheManager cacheManager() {
    RedisCacheManager cacheManager = new RedisCacheManager();
    cacheManager.setRedisManager(redisManager());
    return cacheManager;
}

@Bean
public SessionDAO sessionDAO() {
    EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
    sessionDAO.setActiveSessionsCache(cacheManager().getCache("shiro-activeSessionCache"));
    return sessionDAO;
}
```

### 8. 总结

Shiro的Session管理功能强大且灵活，支持Web和非Web应用程序。通过SessionManager和SessionDAO，Shiro可以轻松地管理会话的生命周期、会话属性、会话持久化和集群。开发者可以根据具体需求配置不同的SessionManager和SessionDAO，实现高效的Session管理。

### 关键点

- **SessionManager**：负责管理Session的生命周期。
- **SessionDAO**：负责Session的持久化和集群。
- **Session属性管理**：Session可以存储任意类型的属性。
- **会话超时和持久化**：支持会话超时和持久化到数据库或缓存。
- **Session集群**：支持分布式Session管理。

通过合理配置和使用Shiro的Session管理功能，开发者可以构建安全可靠的应用程序，提供良好的用户体验。




## Shiro如何处理缓存?
**Apache Shiro** 提供了灵活的缓存机制，用于提高身份验证、授权、会话管理等操作的性能。Shiro的缓存机制通过**CacheManager**接口实现，支持多种缓存实现（如Ehcache、Redis等）。以下是Shiro如何处理缓存的详细说明：

### 1. CacheManager

**CacheManager** 是Shiro中负责管理缓存的核心组件。它负责创建、获取和销毁缓存实例。Shiro提供了多种CacheManager实现，可以根据不同的需求选择合适的缓存实现。

#### 主要功能：

- **创建缓存实例**：根据缓存名称创建缓存实例。
- **获取缓存实例**：获取指定名称的缓存实例。
- **销毁缓存实例**：销毁缓存实例，释放资源。

#### 常见的CacheManager实现：

- **MemoryConstrainedCacheManager**：基于内存的缓存实现，适用于简单的应用场景。
- **EhCacheManager**：基于Ehcache的缓存实现，适用于需要高性能缓存的应用。
- **RedisCacheManager**：基于Redis的缓存实现，适用于分布式缓存场景。
- **CachingShiroSessionDAO**：用于缓存Session数据的SessionDAO实现。

### 2. 缓存的应用场景

Shiro的缓存机制主要用于以下场景：

#### a. 身份验证缓存

- **功能**：缓存用户的身份验证信息，避免频繁访问数据源（如数据库、LDAP等）。
- **实现**：
  - Shiro在用户登录时，会将用户的身份验证信息缓存起来。
  - 下次用户登录时，Shiro会先从缓存中获取身份验证信息，如果缓存命中，则无需访问数据源。

#### b. 授权缓存

- **功能**：缓存用户的角色和权限信息，避免频繁访问数据源。
- **实现**：
  - Shiro在用户进行授权检查时，会将用户的角色和权限信息缓存起来。
  - 下次进行授权检查时，Shiro会先从缓存中获取角色和权限信息，如果缓存命中，则无需访问数据源。

#### c. Session缓存

- **功能**：缓存Session数据，提高Session管理的性能。
- **实现**：
  - Shiro可以通过SessionDAO将Session数据缓存起来。
  - 例如，使用Ehcache或Redis作为Session缓存，可以提高Session管理的性能。

### 3. 配置CacheManager

可以通过Java配置或XML配置来配置CacheManager。以下是使用Java配置配置EhCacheManager的示例：

```java
@Configuration
public class ShiroConfig {

    @Bean
    public CacheManager cacheManager() {
        EhCacheManager cacheManager = new EhCacheManager();
        cacheManager.setCacheManagerConfigFile("classpath:ehcache.xml");
        return cacheManager;
    }

    @Bean
    public Realm myRealm(CacheManager cacheManager) {
        MyRealm realm = new MyRealm();
        realm.setCacheManager(cacheManager);
        realm.setCachingEnabled(true); // 启用缓存
        realm.setAuthenticationCachingEnabled(true); // 启用身份验证缓存
        realm.setAuthorizationCachingEnabled(true); // 启用授权缓存
        return realm;
    }

    @Bean
    public SecurityManager securityManager(Realm realm, CacheManager cacheManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        securityManager.setCacheManager(cacheManager);
        return securityManager;
    }
}
```

**说明**：
- `EhCacheManager`是Shiro提供的基于Ehcache的CacheManager实现。
- `setCacheManagerConfigFile`方法用于指定Ehcache的配置文件。
- 在Realm中启用缓存，并配置身份验证和授权缓存。

### 4. 配置Realm的缓存

在Realm中，可以通过以下方法启用和配置缓存：

- **setCachingEnabled(true)**：启用缓存。
- **setAuthenticationCachingEnabled(true)**：启用身份验证缓存。
- **setAuthorizationCachingEnabled(true)**：启用授权缓存。
- **setCacheManager(cacheManager)**：设置CacheManager。

**示例**：

```java
public class MyRealm extends AuthorizingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 身份验证逻辑
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 授权逻辑
    }

    @Override
    public void setCacheManager(CacheManager cacheManager) {
        super.setCacheManager(cacheManager);
    }
}
```

### 5. 缓存策略

Shiro支持多种缓存策略，可以通过CacheManager和Cache实现来配置。例如，使用Ehcache时，可以在`ehcache.xml`中配置缓存策略：

```xml
<ehcache>
    <cache name="shiro-activeSessionCache"
           maxEntriesLocalHeap="1000"
           timeToLiveSeconds="1800">
    </cache>
    <cache name="shiro-authenticationCache"
           maxEntriesLocalHeap="1000"
           timeToLiveSeconds="1800">
    </cache>
    <cache name="shiro-authorizationCache"
           maxEntriesLocalHeap="1000"
           timeToLiveSeconds="1800">
    </cache>
</ehcache>
```

### 6. 总结

Shiro的缓存机制通过CacheManager和Cache实现，提供了灵活且高效的缓存解决方案。主要功能包括：

- **身份验证缓存**：缓存用户的身份验证信息。
- **授权缓存**：缓存用户的角色和权限信息。
- **Session缓存**：缓存Session数据。

通过合理配置和使用Shiro的缓存机制，开发者可以显著提高应用程序的性能，减少对数据源的访问次数。




## Shiro的过滤器链是如何工作的?
**Apache Shiro** 的**过滤器链（Filter Chain）** 是其Web安全机制的核心组件之一。过滤器链负责拦截HTTP请求，并根据配置的规则执行相应的安全逻辑，如身份验证、授权、会话管理等。Shiro的过滤器链类似于Java Servlet过滤器链，但Shiro的过滤器链更专注于安全相关的功能。以下是Shiro过滤器链的工作原理和详细说明：

### 1. 过滤器链的概念

- **过滤器链** 是由一组Shiro过滤器（Filter）组成的链，每个过滤器负责处理特定的HTTP请求，并根据配置的安全规则决定是否允许请求通过。
- 过滤器链按照配置的顺序依次执行，每个过滤器可以决定是否继续执行下一个过滤器，或者中断请求处理。

### 2. 过滤器链的工作流程

1. **请求到达Web容器**：
   - 当一个HTTP请求到达Web容器（如Tomcat）时，Shiro的过滤器链会拦截该请求。

2. **执行过滤器链**：
   - 过滤器链中的每个过滤器按照配置的顺序依次执行。
   - 每个过滤器可以执行以下操作：
     - **检查请求**：检查请求是否符合特定的安全规则（如是否已认证、是否具有特定角色或权限）。
     - **执行安全逻辑**：如果请求符合安全规则，则执行相应的安全逻辑（如登录、授权检查）。
     - **中断请求**：如果请求不符合安全规则，则中断请求处理，返回相应的错误响应（如401 Unauthorized, 403 Forbidden等）。

3. **请求通过过滤器链**：
   - 如果请求通过了所有过滤器的检查，则请求会被转发到目标资源（如JSP页面、Servlet等）。
   - 如果请求被过滤器链中断，则不会到达目标资源，Shiro会返回相应的错误响应。

### 3. 常见的Shiro过滤器

Shiro提供了多种内置过滤器，每个过滤器负责不同的安全功能。以下是一些常见的Shiro过滤器：

- **authc**（Authentication Filter）：用于拦截需要身份验证的请求。如果用户未认证，则重定向到登录页面。
- **anon**（Anonymous Filter）：用于拦截匿名请求，不需要身份验证。
- **authcBasic**（Basic Authentication Filter）：用于拦截需要基本身份验证的请求。
- **roles**（Roles Filter）：用于拦截需要特定角色的请求。
- **perms**（Permissions Filter）：用于拦截需要特定权限的请求。
- **logout**（Logout Filter）：用于处理用户登出操作。
- **user**（User Filter）：用于拦截已认证的用户请求。

### 4. 配置过滤器链

可以通过Java配置或XML配置来配置Shiro的过滤器链。以下是使用Java配置配置过滤器链的示例：

```java
@Configuration
public class ShiroConfig {

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        
        // 配置URL权限
        chainDefinition.addPathDefinition("/login", "anon"); // 匿名访问
        chainDefinition.addPathDefinition("/logout", "logout"); // 登出
        chainDefinition.addPathDefinition("/admin/**", "authc, roles[admin]"); // 需要认证并具有admin角色
        chainDefinition.addPathDefinition("/user/**", "authc, roles[user]"); // 需要认证并具有user角色
        chainDefinition.addPathDefinition("/**", "authc"); // 其他所有请求都需要认证
        
        return chainDefinition;
    }

    @Bean
    public SecurityManager securityManager(Realm realm, CacheManager cacheManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        securityManager.setCacheManager(cacheManager);
        return securityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager, ShiroFilterChainDefinition chainDefinition) {
        ShiroFilterFactoryBean shiroFilter = new ShiroFilterFactoryBean();
        shiroFilter.setSecurityManager(securityManager);
        shiroFilter.setFilterChainDefinitionMap(chainDefinition.getFilterChainMap());
        return shiroFilter;
    }
}
```

**说明**：
- `addPathDefinition`方法用于配置URL路径和对应的过滤器链。
- 例如，`/admin/**`路径下的请求需要认证并具有`admin`角色，`/user/**`路径下的请求需要认证并具有`user`角色，`/**`路径下的其他所有请求都需要认证。

### 5. 过滤器链的执行顺序

过滤器链中的过滤器按照配置的顺序依次执行。每个过滤器可以决定是否继续执行下一个过滤器，或者中断请求处理。

**示例**：

```java
chainDefinition.addPathDefinition("/admin/**", "authc, roles[admin]");
```

在这个例子中，`/admin/**`路径下的请求会依次执行以下过滤器：

1. **authc**（Authentication Filter）：检查用户是否已认证。
2. **roles[admin]**（Roles Filter）：检查用户是否具有`admin`角色。

如果用户未认证，则`authc`过滤器会中断请求处理，重定向到登录页面。如果用户已认证但没有`admin`角色，则`roles`过滤器会中断请求处理，返回403 Forbidden响应。

### 6. 总结

Shiro的过滤器链是实现Web安全机制的关键组件，通过配置过滤器链，开发者可以灵活地控制HTTP请求的安全逻辑。过滤器链的工作流程如下：

1. **请求到达Web容器**。
2. **执行过滤器链**。
3. **每个过滤器执行安全检查**。
4. **请求通过或被中断**。

通过合理配置和使用Shiro的过滤器链，开发者可以构建安全可靠的Web应用程序，控制用户对资源的访问权限。




# 配置与使用
## 如何在Java SE应用程序中配置Shiro?
在**Java SE应用程序**（即非Web应用程序）中配置**Apache Shiro**与在Web应用程序中有所不同，因为Shiro的Web支持依赖于Servlet容器。在Java SE应用程序中，Shiro主要通过**SecurityManager**和**Subject**来管理安全逻辑。以下是如何在Java SE应用程序中配置Shiro的详细步骤：

### 1. 添加Shiro依赖

首先，确保你的项目中包含了Shiro的核心依赖。如果你使用Maven，可以在`pom.xml`中添加以下依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.10.1</version>
</dependency>
```

### 2. 创建Shiro配置文件（INI文件）

在Java SE应用程序中，通常使用INI文件来配置Shiro。INI文件用于定义用户、角色、权限以及Realm等配置。

**示例：`shiro.ini`**

```ini
[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin

[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*

[main]
# 配置自定义Realm（可选）
myRealm = com.example.security.DatabaseRealm
securityManager.realms = $myRealm

# 配置Session管理器（可选）
sessionManager = org.apache.shiro.session.mgt.DefaultSessionManager
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
```

**说明**：
- `[users]`部分定义了用户及其密码和角色。
- `[roles]`部分定义了角色及其权限。
- `[main]`部分用于配置自定义Realm、SessionManager、CacheManager等。

### 3. 编写自定义Realm（可选）

如果需要从数据库或其他数据源加载用户信息，可以编写自定义Realm。

**示例：**

```java
package com.example.security;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class RealmRealm extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取授权信息
        String username = (String) principals.getPrimaryPrincipal();
        // 从数据库或其他数据源获取用户角色和权限
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRole("user");
        info.addStringPermission("user:read");
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取身份验证信息
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        // 从数据库或其他数据源获取用户信息
        if ("user".equals(username)) {
            return new SimpleAuthenticationInfo(username, "password", getName());
        }
        throw new UnknownAccountException("账户不存在");
    }
}
```

### 4. 配置SecurityManager

在Java SE应用程序中，可以通过以下方式配置Shiro的`SecurityManager`：

**示例：**

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Factory;
import org.apache.shiro.config.IniSecurityManagerFactory;

public class ShiroConfig {

    public static SecurityManager getSecurityManager() {
        // 加载INI配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        // 获取SecurityManager实例
        SecurityManager securityManager = factory.getInstance();
        // 设置SecurityManager到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }
}
```

### 5. 使用Subject进行身份验证和授权

在Java SE应用程序中，可以通过`Subject`接口进行身份验证和授权。

**示例：**

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.authc.*;

public class ShiroExample {

    public static void main(String[] args) {
        // 获取SecurityManager
        SecurityManager securityManager = ShiroConfig.getSecurityManager();

        // 获取当前用户
        Subject currentUser = SecurityUtils.getSubject();

        // 执行登录
        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken("user", "password");
            try {
                currentUser.login(token);
                System.out.println("用户认证成功");
            } catch (UnknownAccountException e) {
                System.out.println("账户不存在");
            } catch (IncorrectCredentialsException e) {
                System.out.println("密码错误");
            } catch (AuthenticationException e) {
                System.out.println("认证失败: " + e.getMessage());
            }
        }

        // 执行授权检查
        if (currentUser.hasRole("user")) {
            System.out.println("用户具有user角色");
        }

        if (currentUser.isPermitted("user:read")) {
            System.out.println("用户具有读取权限");
        }

        // 执行登出
        currentUser.logout();
    }
}
```

### 6. 总结

在Java SE应用程序中配置Shiro主要包括以下几个步骤：

1. **添加Shiro依赖**。
2. **创建Shiro配置文件（INI文件）**，定义用户、角色、权限以及Realm等配置。
3. **编写自定义Realm**（如果需要从数据库或其他数据源加载用户信息）。
4. **配置SecurityManager**，并将其设置到`SecurityUtils`。
5. **使用Subject进行身份验证和授权**。

通过以上步骤，开发者可以在Java SE应用程序中轻松地集成Shiro，实现身份验证、授权、会话管理等功能。



## 如何在Web应用程序中配置Shiro?
在**Web应用程序**中配置**Apache Shiro** 主要涉及以下几个步骤：添加依赖、配置Shiro过滤器链、定义安全策略以及集成到Web框架（如Spring MVC）中。以下是详细的配置步骤和示例：

### 1. 添加Shiro依赖

首先，确保你的项目中包含了Shiro的核心依赖以及Web相关的依赖。如果你使用Maven，可以在`pom.xml`中添加以下依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-web</artifactId>
    <version>1.10.1</version>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.10.1</version>
</dependency>
```

### 2. 配置Shiro过滤器链

Shiro通过**过滤器链（Filter Chain）**来拦截HTTP请求，并根据配置的安全规则执行相应的安全逻辑。在Web应用程序中，通常使用`ShiroFilter`来配置过滤器链。

#### a. 使用Spring配置Shiro过滤器

如果你的Web应用程序使用Spring框架，可以通过Spring配置Shiro过滤器。

**示例：**

```java
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {

    @Bean
    public DefaultWebSecurityManager securityManager(Realm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        return securityManager;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilter = new ShiroFilterFactoryBean();
        shiroFilter.setSecurityManager(securityManager);

        // 配置URL权限
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        filterChainDefinitionMap.put("/login", "anon"); // 匿名访问
        filterChainDefinitionMap.put("/logout", "logout"); // 登出
        filterChainDefinitionMap.put("/admin/**", "authc, roles[admin]"); // 需要认证并具有admin角色
        filterChainDefinitionMap.put("/user/**", "authc, roles[user]"); // 需要认证并具有user角色
        filterChainDefinitionMap.put("/**", "authc"); // 其他所有请求都需要认证

        shiroFilter.setFilterChainDefinitionMap(filterChainDefinitionMap);

        // 设置登录页面
        shiroFilter.setLoginUrl("/login");
        // 设置未授权页面
        shiroFilter.setUnauthorizedUrl("/unauthorized");

        return shiroFilter;
    }
}
```

**说明**：
- `ShiroFilterFactoryBean`用于配置Shiro过滤器链。
- `filterChainDefinitionMap`定义了URL路径和对应的过滤器链。
  - `/login`路径下的请求不需要认证（`anon`）。
  - `/admin/**`路径下的请求需要认证并具有`admin`角色（`authc, roles[admin]`）。
  - `/user/**`路径下的请求需要认证并具有`user`角色（`authc, roles[user]`）。
  - 其他所有请求都需要认证（`authc`）。
- `setLoginUrl`方法用于设置登录页面。
- `setUnauthorizedUrl`方法用于设置未授权页面。

#### b. 配置Web.xml（如果不使用Spring）

如果不使用Spring，可以通过`web.xml`配置Shiro过滤器。

**示例：**

```xml
<filter>
    <filter-name>ShiroFilter</filter-name>
    <filter-class>org.apache.shiro.web.servlet.IniShiroFilter</filter-class>
    <init-param>
        <param-name>configPath</param-name>
        <param-value>classpath:shiro.ini</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>ShiroFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

### 3. 配置Realm

在Web应用程序中，Realm的配置与Java SE应用程序类似，可以通过INI文件或Java代码配置。

**示例：使用INI文件配置Realm**

```ini
[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin

[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*

[main]
# 配置自定义Realm（可选）
myRealm = com.example.security.DatabaseRealm
securityManager.realms = $myRealm

# 配置Session管理器（可选）
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
```

### 4. 编写自定义Realm（可选）

如果需要从数据库或其他数据源加载用户信息，可以编写自定义Realm。

**示例：**

```java
package com.example.security;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class DatabaseRealm extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取授权信息
        String username = (String) principals.getPrimaryPrincipal();
        // 从数据库或其他数据源获取用户角色和权限
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRole("user");
        info.addStringPermission("user:read");
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取身份验证信息
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        // 从数据库或其他数据源获取用户信息
        if ("user".equals(username)) {
            return new SimpleAuthenticationInfo(username, "password", getName());
        }
        throw new UnknownAccountException("账户不存在");
    }
}
```

### 5. 总结

在Web应用程序中配置Shiro主要包括以下几个步骤：

1. **添加Shiro依赖**。
2. **配置Shiro过滤器链**，定义URL路径和对应的安全规则。
3. **配置Realm**，定义用户、角色、权限以及数据源访问逻辑。
4. **集成到Web框架**（如Spring MVC），通过Spring配置或`web.xml`配置Shiro过滤器。

通过以上步骤，开发者可以在Web应用程序中轻松地集成Shiro，实现身份验证、授权、会话管理等功能。




## 如何使用Shiro进行用户认证?
在**Apache Shiro**中，**用户认证**是验证用户身份的过程。Shiro提供了简单而强大的API来进行身份验证，无论是在Web应用程序还是Java SE应用程序中。以下是如何使用Shiro进行用户认证的详细步骤和示例：

### 1. 添加Shiro依赖

首先，确保你的项目中包含了Shiro的核心依赖。如果你使用Maven，可以在`pom.xml`中添加以下依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.10.1</version>
</dependency>
```

如果是在Web应用程序中，还需要添加Shiro的Web依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-web</artifactId>
    <version>1.10.1</version>
</dependency>
```

### 2. 配置Shiro

#### a. 使用INI文件配置（适用于Java SE和Web应用）

创建一个`shiro.ini`文件，用于定义用户、角色、权限以及Realm。

**示例：`shiro.ini`**

```
[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin

[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*

[main]
# 配置自定义Realm（可选）
myRealm = com.example.security.DatabaseRealm
securityManager.realms = $myRealm

# 配置Session管理器（可选）
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
```

#### b. 配置SecurityManager

在Java SE应用程序中，可以通过以下方式配置Shiro的`SecurityManager`：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Factory;
import org.apache.shiro.config.IniSecurityManagerFactory;

public class ShiroConfig {

    public static SecurityManager getSecurityManager() {
        // 加载INI配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        // 获取SecurityManager实例
        SecurityManager securityManager = factory.getInstance();
        // 设置SecurityManager到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }
}
```

### 3. 执行用户认证

在应用程序中，可以通过`Subject`接口进行用户认证。以下是认证的步骤：

1. **获取当前用户（Subject）**：
   - 使用`SecurityUtils.getSubject()`方法获取当前用户。

2. **创建认证令牌（AuthenticationToken）**：
   - 创建一个`UsernamePasswordToken`对象，封装用户的用户名和密码。

3. **执行登录（login）**：
   - 调用`subject.login(token)`方法执行登录操作。

4. **处理认证结果**：
   - 如果认证成功，用户将被标记为已认证。
   - 如果认证失败，Shiro会抛出相应的异常，如`UnknownAccountException`（未知账户）或`IncorrectCredentialsException`（密码错误）。

**示例：**

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;

public class AuthenticationExample {

    public static void main(String[] args) {
        // 获取SecurityManager
        SecurityManager securityManager = ShiroConfig.getSecurityManager();

        // 获取当前用户
        Subject currentUser = SecurityUtils.getSubject();

        // 执行登录
        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken("user", "password");
            try {
                currentUser.login(token);
                System.out.println("用户认证成功");
            } catch (UnknownAccountException e) {
                System.out.println("账户不存在");
            } catch (IncorrectCredentialsException e) {
                System.out.println("密码错误");
            } catch (LockedAccountException e) {
                System.out.println("账户被锁定");
            } catch (AuthenticationException e) {
                System.out.println("认证失败: " + e.getMessage());
            }
        }

        // 执行授权检查（可选）
        if (currentUser.hasRole("user")) {
            System.out.println("用户具有user角色");
        }

        // 执行登出
        currentUser.logout();
    }
}
```

### 4. 认证流程

1. **获取当前用户**：
   - `Subject currentUser = SecurityUtils.getSubject();`

2. **创建认证令牌**：
   - `UsernamePasswordToken token = new UsernamePasswordToken("user", "password");`

3. **执行登录**：
   - `currentUser.login(token);`

4. **处理认证结果**：
   - 如果认证成功，用户将被标记为已认证。
   - 如果认证失败，Shiro会抛出相应的异常。

### 5. 认证结果处理

在认证过程中，Shiro可能会抛出以下异常：

- **UnknownAccountException**：账户不存在。
- **IncorrectCredentialsException**：密码错误。
- **LockedAccountException**：账户被锁定。
- **AuthenticationException**：认证失败。

开发者可以根据不同的异常类型进行相应的处理，如提示用户错误信息或记录日志。

### 6. 总结

通过以下步骤，开发者可以使用Shiro进行用户认证：

1. **添加Shiro依赖**。
2. **配置Shiro**，包括SecurityManager和Realm。
3. **获取当前用户（Subject）**。
4. **创建认证令牌**。
5. **执行登录操作**。
6. **处理认证结果**。

通过使用Shiro的认证机制，开发者可以轻松地在应用程序中实现用户身份验证，并结合授权、会话管理等功能，构建安全可靠的应用程序。



## 如何使用Shiro进行用户授权?
在**Apache Shiro**中，**用户授权**是控制用户对应用程序资源的访问权限的过程。Shiro提供了灵活且强大的授权机制，支持基于角色的访问控制（RBAC）和基于权限的访问控制（PBAC）。以下是使用Shiro进行用户授权的详细步骤和示例：

### 1. 添加Shiro依赖

首先，确保你的项目中包含了Shiro的核心依赖。如果你使用Maven，可以在`pom.xml`中添加以下依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.10.1</version>
</dependency>
```

如果是在Web应用程序中，还需要添加Shiro的Web依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-web</artifactId>
    <version>1.10.1</version>
</dependency>
```

### 2. 配置Shiro

#### a. 使用INI文件配置（适用于Java SE和Web应用）

创建一个`shiro.ini`文件，用于定义用户、角色、权限以及Realm。

**示例：`shiro.ini`**

```ini
[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin

[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*

[main]
# 配置自定义Realm（可选）
myRealm = com.example.security.DatabaseRealm
securityManager.realms = $myRealm

# 配置Session管理器（可选）
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
```

#### b. 配置SecurityManager

在Java SE应用程序中，可以通过以下方式配置Shiro的`SecurityManager`：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Factory;
import org.apache.shiro.config.IniSecurityManagerFactory;

public class ShiroConfig {

    public static SecurityManager getSecurityManager() {
        // 加载INI配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        // 获取SecurityManager实例
        SecurityManager securityManager = factory.getInstance();
        // 设置SecurityManager到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }
}
```

### 3. 执行用户授权

在应用程序中，可以通过`Subject`接口进行用户授权。以下是授权的步骤：

1. **获取当前用户（Subject）**：
   - 使用`SecurityUtils.getSubject()`方法获取当前用户。

2. **检查角色（hasRole）**：
   - 使用`subject.hasRole("roleName")`方法检查用户是否具有特定的角色。

3. **检查权限（isPermitted）**：
   - 使用`subject.isPermitted("permission")`方法检查用户是否具有特定的权限。

4. **执行授权逻辑**：
   - 根据授权结果执行相应的逻辑，如允许访问资源或拒绝访问。

**示例：**

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

public class AuthorizationExample {

    public static void main(String[] args) {
        // 获取SecurityManager
        SecurityManager securityManager = ShiroConfig.getSecurityManager();

        // 获取当前用户
        Subject currentUser = SecurityUtils.getSubject();

        // 执行授权检查
        if (currentUser.hasRole("admin")) {
            System.out.println("用户具有admin角色");
            // 执行admin角色的逻辑
        } else if (currentUser.hasRole("user")) {
            System.out.println("用户具有user角色");
            // 执行user角色的逻辑
        } else {
            System.out.println("用户没有有效的角色");
        }

        if (currentUser.isPermitted("user:read")) {
            System.out.println("用户具有读取权限");
            // 执行读取权限的逻辑
        }

        if (currentUser.isPermitted("user:write")) {
            System.out.println("用户具有写入权限");
            // 执行写入权限的逻辑
        }

        // 执行登出
        currentUser.logout();
    }
}
```

### 4. 授权流程

1. **获取当前用户**：
   - `Subject currentUser = SecurityUtils.getSubject();`

2. **检查角色**：
   - `currentUser.hasRole("admin")`：检查用户是否具有`admin`角色。
   - `currentUser.hasRole("user")`：检查用户是否具有`user`角色。

3. **检查权限**：
   - `currentUser.isPermitted("user:read")`：检查用户是否具有读取权限。
   - `currentUser.isPermitted("user:write")`：检查用户是否具有写入权限。

4. **执行授权逻辑**：
   - 根据授权结果执行相应的逻辑。

### 5. 基于注解的授权

Shiro支持基于注解的授权，可以在方法上使用`@RequiresRoles`和`@RequiresPermissions`注解来控制方法访问权限。

**示例：**

```java
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresPermissions;

public class UserService {

    @RequiresRoles("admin")
    public void adminMethod() {
        // admin角色的逻辑
    }

    @RequiresPermissions("user:read")
    public void readUser() {
        // 读取用户的逻辑
    }

    @RequiresPermissions("user:write")
    public void writeUser() {
        // 写入用户的逻辑
    }
}
```

### 6. 总结

通过以下步骤，开发者可以使用Shiro进行用户授权：

1. **添加Shiro依赖**。
2. **配置Shiro**，包括SecurityManager和Realm。
3. **获取当前用户（Subject）**。
4. **检查角色和权限**：
   - 使用`hasRole`和`isPermitted`方法。
   - 或者使用`@RequiresRoles`和`@RequiresPermissions`注解。
5. **执行授权逻辑**。

通过使用Shiro的授权机制，开发者可以轻松地在应用程序中实现基于角色和权限的访问控制，从而构建安全可靠的应用程序。





## 如何使用Shiro进行角色和权限管理?
在**Apache Shiro**中，**角色和权限管理**是实现细粒度访问控制的核心功能。通过角色和权限，开发者可以控制用户对应用程序资源的访问权限。以下是如何使用Shiro进行角色和权限管理的详细步骤和示例：

### 1. 理解角色和权限

- **角色（Role）**：
  - 角色是一组权限的集合，用于简化权限管理。例如，`admin`角色可以包含多个权限，如`user:read`、`user:write`、`admin:*`等。
  - 角色可以分配给用户，用户通过角色获得相应的权限。

- **权限（Permission）**：
  - 权限是具体的操作权限，用于控制用户对资源的访问。例如，`user:read`表示读取用户信息的权限，`user:write`表示写入用户信息的权限。
  - 权限可以分配给角色，也可以直接分配给用户。

### 2. 配置Shiro

#### a. 使用INI文件配置（适用于Java SE和Web应用）

创建一个`shiro.ini`文件，用于定义用户、角色、权限以及Realm。

**示例：`shiro.ini`**

```
[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin

[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*

[main]
# 配置自定义Realm（可选）
myRealm = com.example.security.DatabaseRealm
securityManager.realms = $myRealm

# 配置Session管理器（可选）
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
```

#### b. 配置SecurityManager

在Java SE应用程序中，可以通过以下方式配置Shiro的`SecurityManager`：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Factory;
import org.apache.shiro.config.IniSecurityManagerFactory;

public class ShiroConfig {

    public static SecurityManager getSecurityManager() {
        // 加载INI配置文件
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        // 获取SecurityManager实例
        SecurityManager securityManager = factory.getInstance();
        // 设置SecurityManager到SecurityUtils
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }
}
```

### 3. 定义角色和权限

在`shiro.ini`文件中，通过`[roles]`部分定义角色和权限。

**示例：**

```
[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*
```

- `user`角色拥有`user:read`权限。
- `admin`角色拥有`user:read`、`user:write`和`admin:*`权限。

### 4. 分配角色和权限给用户

在`[users]`部分，通过逗号分隔的角色列表将角色分配给用户。

**示例：**

```
[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin
```

- 用户`user`拥有`user`角色。
- 用户`admin`拥有`admin`角色。

### 5. 执行角色和权限检查

在应用程序中，可以通过`Subject`接口进行角色和权限检查。

#### a. 检查角色

使用`hasRole`方法检查用户是否具有特定的角色。

**示例：**

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

public void checkRoles() {
    Subject currentUser = SecurityUtils.getSubject();
    if (currentUser.hasRole("admin")) {
        System.out.println("用户具有admin角色");
    } else if (currentUser.hasRole("user")) {
        System.out.println("用户具有user角色");
    } else {
        System.out.println("用户没有有效的角色");
    }
}
```

#### b. 检查权限

使用`isPermitted`方法检查用户是否具有特定的权限。

**示例：**

```java
public void checkPermissions() {
    Subject currentUser = SecurityUtils.getSubject();
    if (currentUser.isPermitted("user:read")) {
        System.out.println("用户具有读取权限");
    }
    if (currentUser.isPermitted("user:write")) {
        System.out.println("用户具有写入权限");
    }
    if (currentUser.isPermitted("admin:*")) {
        System.out.println("用户具有admin权限");
    }
}
```

### 6. 基于注解的授权

Shiro支持基于注解的授权，可以在方法上使用`@RequiresRoles`和`@RequiresPermissions`注解来控制方法访问权限。

**示例：**

```java
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresPermissions;

public class UserService {

    @RequiresRoles("admin")
    public void adminMethod() {
        // admin角色的逻辑
    }

    @RequiresPermissions("user:read")
    public void readUser() {
        // 读取用户的逻辑
    }

    @RequiresPermissions("user:write")
    public void writeUser() {
        // 写入用户的逻辑
    }
}
```

### 7. 总结

通过以下步骤，开发者可以使用Shiro进行角色和权限管理：

1. **添加Shiro依赖**。
2. **配置Shiro**，包括SecurityManager和Realm。
3. **定义角色和权限**，并在`shiro.ini`文件中分配给用户。
4. **执行角色和权限检查**：
   - 使用`hasRole`和`isPermitted`方法。
   - 或者使用`@RequiresRoles`和`@RequiresPermissions`注解。
5. **执行授权逻辑**。

通过使用Shiro的角色和权限管理机制，开发者可以轻松地实现细粒度的访问控制，构建安全可靠的应用程序。


## 如何使用Shiro进行密码加密和验证?
在**Apache Shiro**中，**密码加密和验证**是保护用户密码安全的重要环节。Shiro提供了灵活的密码加密和匹配机制，支持多种加密算法和哈希函数（如SHA-256、bcrypt等）。以下是使用Shiro进行密码加密和验证的详细步骤和示例：

### 1. 密码加密的基本概念

- **加密（Encryption）**：将明文密码转换为不可读的密文，通常使用对称加密算法（如AES）或非对称加密算法（如RSA）。
- **哈希（Hashing）**：将明文密码转换为固定长度的哈希值，通常使用单向哈希函数（如SHA-256, bcrypt等）。哈希是不可逆的，无法从哈希值还原出原始密码。

在大多数情况下，密码存储使用哈希而不是加密，因为哈希更安全且不需要存储密钥。

### 2. Shiro的密码加密机制

Shiro通过`CredentialsMatcher`接口来处理密码加密和匹配。`CredentialsMatcher`负责将用户输入的密码与存储在数据库或其他数据源中的密码进行匹配。

#### 主要的`CredentialsMatcher`实现：

1. **`HashedCredentialsMatcher`**：
   - 支持多种哈希算法，如SHA-256, bcrypt, MD5等。
   - 可以配置哈希迭代次数、盐值等参数。

2. **`SimpleCredentialsMatcher`**：
   - 直接比较用户输入的密码和存储的密码，不进行加密或哈希。

3. **`PasswordMatcher`**：
   - 用于自定义密码匹配逻辑。

### 3. 使用`HashedCredentialsMatcher`进行密码哈希

`HashedCredentialsMatcher`是Shiro中常用的密码匹配器，支持多种哈希算法。以下是配置和使用`HashedCredentialsMatcher`的步骤：

#### a. 配置`HashedCredentialsMatcher`

```java
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("SHA-256"); // 设置哈希算法
        matcher.setHashIterations(1024); // 设置哈希迭代次数
        matcher.setStoredCredentialsHexEncoded(true); // 设置是否以十六进制存储
        return matcher;
    }

    @Bean
    public AuthorizingRealm myRealm(HashedCredentialsMatcher matcher) {
        MyRealm realm = new MyRealm();
        realm.setCredentialsMatcher(matcher);
        return realm;
    }

    @Bean
    public SecurityManager securityManager(AuthorizingRealm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        return securityManager;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        // 配置URL权限
        chainDefinition.addPathDefinition("/login", "anon");
        chainDefinition.addPathDefinition("/**", "authc");
        return chainDefinition;
    }
}
```

#### b. 自定义`Realm`

```java
import org.apache.shiro.authc.*;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class MyRealm extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取授权信息
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取用户输入的用户名
        String username = (String) token.getPrincipal();
        // 从数据库中获取用户信息
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        // 返回认证信息
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }
}
```

#### c. 密码存储

在用户注册或密码更改时，需要对密码进行哈希处理并存储。

```java
import org.apache.shiro.crypto.hash.Sha256Hash;

public void registerUser(String username, String password) {
    // 生成盐值
    String salt = new SecureRandomNumberGenerator().nextBytes().toHex();
    // 对密码进行哈希处理
    String hashedPassword = new Sha256Hash(password, salt, 1024).toHex();
    // 存储用户信息，包括用户名、哈希后的密码和盐值
    userService.saveUser(username, hashedPassword, salt);
}
```

### 4. 使用盐值（Salt）

为了防止彩虹表攻击，Shiro支持使用盐值（Salt）来增强密码哈希的安全性。盐值是随机生成的字符串，与密码一起进行哈希处理。

**示例**：

```java
String salt = new SecureRandomNumberGenerator().nextBytes().toHex();
String hashedPassword = new Sha256Hash(password, salt, 1024).toHex();
```

在`HashedCredentialsMatcher`中，Shiro会自动使用存储的盐值进行密码匹配。

### 5. 总结

Shiro通过`CredentialsMatcher`接口和`HashedCredentialsMatcher`实现来处理密码加密和匹配，支持多种哈希算法和盐值的使用。开发者可以根据具体需求选择合适的哈希算法和配置参数，以增强应用程序的安全性。

### 常用哈希算法

- **SHA-256**：常用的安全哈希算法。
- **bcrypt**：一种自适应哈希函数，具有较高的安全性。
- **scrypt**：一种内存密集型哈希函数，适用于需要更高安全性的场景。

通过合理配置和使用Shiro的密码加密机制，开发者可以有效地保护用户密码的安全。



## 如何使用Shiro进行Session管理?
**Apache Shiro** 提供了强大的**Session管理**功能，适用于Web和非Web应用程序。Shiro的Session管理机制允许开发者轻松地管理用户会话，包括会话创建、更新、销毁、会话属性管理、会话持久化等。以下是如何在Shiro中进行Session管理的详细说明：

### 1. Session的概念

- **Session** 是用户与应用程序交互期间的状态管理单元。它通常用于存储用户的状态信息，如用户身份、权限、会话属性等。
- Shiro的Session接口类似于Java Servlet的`HttpSession`，但Shiro的Session管理不依赖于Web容器，可以在Web和非Web应用程序中使用。

### 2. SessionManager

**SessionManager** 是Shiro中负责管理Session的核心组件。它负责创建、更新、销毁Session，并维护Session的生命周期。

#### 主要功能：

- **创建Session**：当用户首次与应用程序交互时，SessionManager会创建一个新的Session。
- **获取Session**：通过`Subject.getSession()`方法获取当前用户的Session。
- **更新Session**：在用户与应用程序交互期间，SessionManager会定期更新Session的状态。
- **销毁Session**：当用户退出或Session超时，SessionManager会销毁Session。

#### SessionManager的类型：

- **DefaultWebSessionManager**：用于Web应用程序，基于Servlet容器的Session管理。
- **DefaultSessionManager**：用于非Web应用程序，独立于Web容器。

### 3. 配置SessionManager

#### a. 使用Java配置

在Java SE或Web应用程序中，可以通过Java配置来配置SessionManager。

**示例：**

```java
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {

    @Bean
    public SessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setGlobalSessionTimeout(1800000); // 设置会话超时时间为30分钟
        sessionManager.setSessionValidationSchedulerEnabled(true);
        sessionManager.setSessionIdCookieEnabled(true);
        return sessionManager;
    }

    @Bean
    public SecurityManager securityManager(Realm realm, SessionManager sessionManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        securityManager.setSessionManager(sessionManager);
        return securityManager;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        // 配置URL权限
        chainDefinition.addPathDefinition("/login", "anon"); // 匿名访问
        chainDefinition.addPathDefinition("/logout", "logout"); // 登出
        chainDefinition.addPathDefinition("/**", "authc"); // 其他所有请求都需要认证
        return chainDefinition;
    }
}
```

**说明**：
- `DefaultWebSessionManager`用于Web应用程序。
- `setGlobalSessionTimeout`方法设置会话超时时间。
- `setSessionValidationSchedulerEnabled`方法启用会话验证调度器。
- `setSessionIdCookieEnabled`方法启用会话ID Cookie。

#### b. 使用INI文件配置

在`shiro.ini`文件中，可以通过以下方式配置SessionManager：

```ini
[main]
# 配置Session管理器
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
sessionManager.globalSessionTimeout = 1800000 # 设置会话超时时间为30分钟
sessionManager.sessionValidationSchedulerEnabled = true
sessionManager.sessionIdCookieEnabled = true
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager
```

### 4. Session的属性管理

Session可以存储任意类型的属性，类似于`HttpSession`。开发者可以通过Session对象设置和获取属性。

**示例**：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.session.Session;

public void setSessionAttribute(String key, Object value) {
    Subject currentUser = SecurityUtils.getSubject();
    Session session = currentUser.getSession();
    session.setAttribute(key, value);
}

public Object getSessionAttribute(String key) {
    Subject currentUser = SecurityUtils.getSubject();
    Session session = currentUser.getSession();
    return session.getAttribute(key);
}
```

### 5. Session的持久化

Shiro支持会话持久化，可以将会话数据存储到数据库或缓存中，以便在应用程序重启后恢复会话。

#### a. 使用EnterpriseCacheSessionDAO

**EnterpriseCacheSessionDAO**将会话数据存储到缓存中。

**配置示例**：

```java
@Bean
public SessionDAO sessionDAO() {
    EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
    sessionDAO.setActiveSessionsCache(cacheManager().getCache("shiro-activeSessionCache"));
    return sessionDAO;
}

@Bean
public SessionManager sessionManager() {
    DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
    sessionManager.setSessionDAO(sessionDAO());
    return sessionManager;
}
```

#### b. 使用JDBCSessionDAO

**JDBCSessionDAO**将会话数据存储到关系型数据库中。

**配置示例**：

```java
@Bean
public SessionDAO sessionDAO() {
    JdbcSessionDAO sessionDAO = new JdbcSessionDAO();
    sessionDAO.setDataSource(dataSource());
    sessionDAO.setDeleteExpiredSessions(true);
    return sessionDAO;
}
```

### 6. Session的集群

Shiro支持Session集群，可以通过配置不同的SessionDAO和缓存实现来实现。例如，使用Redis作为缓存，可以实现分布式Session管理。

**配置示例**：

```java
@Bean
public CacheManager cacheManager() {
    RedisCacheManager cacheManager = new RedisCacheManager();
    cacheManager.setRedisManager(redisManager());
    return cacheManager;
}

@Bean
public SessionDAO sessionDAO() {
    EnterpriseCacheSessionDAO sessionDAO = new EnterpriseCacheSessionDAO();
    sessionDAO.setActiveSessionsCache(cacheManager().getCache("shiro-activeSessionCache"));
    return sessionDAO;
}
```

### 7. 总结

Shiro的Session管理功能强大且灵活，支持Web和非Web应用程序。通过SessionManager和SessionDAO，Shiro可以轻松地管理会话的生命周期、会话属性、会话持久化和集群。开发者可以根据具体需求配置不同的SessionManager和SessionDAO，实现高效的Session管理。

### 关键点

- **SessionManager**：负责管理Session的生命周期。
- **SessionDAO**：负责Session的持久化和集群。
- **Session属性管理**：Session可以存储任意类型的属性。
- **会话超时和持久化**：支持会话超时和持久化到数据库或缓存。
- **Session集群**：支持分布式Session管理。

通过合理配置和使用Shiro的Session管理功能，开发者可以构建安全可靠的应用程序，提供良好的用户体验。





## 如何使用Shiro进行Remember Me功能
在**Apache Shiro**中，**Remember Me**功能允许用户在关闭浏览器或会话过期后仍然保持登录状态，而无需每次都重新输入用户名和密码。Shiro提供了内置的Remember Me功能，支持基于Cookie的持久化机制。以下是如何在Shiro中实现Remember Me功能的详细步骤和示例：

### 1. 添加Shiro依赖

确保你的项目中包含了Shiro的核心依赖。如果你使用Maven，可以在`pom.xml`中添加以下依赖：

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.10.1</version>
</dependency>
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-web</artifactId>
    <version>1.10.1</version>
</dependency>
```

### 2. 配置Shiro以支持Remember Me

#### a. 使用INI文件配置

在`shiro.ini`文件中，可以配置Remember Me功能。以下是一个示例配置：

```
[main]
# 配置Remember Me Cookie
rememberMeManager = org.apache.shiro.web.mgt.CookieRememberMeManager
# 设置Cookie名称
rememberMeManager.cookie.name = rememberMe
# 设置Cookie过期时间（秒）
rememberMeManager.cookie.maxAge = 2592000 # 30天
# 设置Cookie路径
rememberMeManager.cookie.path = /
# 设置Cookie是否只读
rememberMeManager.cookie.httpOnly = true

# 配置SecurityManager
securityManager.rememberMeManager = $rememberMeManager

# 配置Session管理器（可选）
sessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager
securityManager.sessionManager = $sessionManager

# 配置CacheManager（可选）
cacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager
securityManager.cacheManager = $cacheManager

# 配置Realm
myRealm = com.example.security.DatabaseRealm
securityManager.realms = $myRealm

[users]
# 用户名 = 密码, 角色1, 角色2, ...
user = password, user
admin = admin, admin

[roles]
# 角色 = 权限1, 权限2, ...
user = user:read
admin = user:read, user:write, admin:*
```

**说明**：
- `rememberMeManager`配置了Remember Me的Cookie管理器。
- `cookie.maxAge`设置Cookie的过期时间，这里设置为30天。
- `cookie.path`和`cookie.httpOnly`用于配置Cookie的属性。

#### b. 配置SecurityManager

在Java SE或Web应用程序中，可以通过Java配置来配置Shiro的`SecurityManager`，并启用Remember Me。

**示例：**

```java
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {

    @Bean
    public CookieRememberMeManager rememberMeManager() {
        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
        SimpleCookie cookie = new SimpleCookie("rememberMe");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(2592000); // 30天
        rememberMeManager.setCookie(cookie);
        return rememberMeManager;
    }

    @Bean
    public DefaultWebSecurityManager securityManager(AuthorizingRealm realm, CookieRememberMeManager rememberMeManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        securityManager.setRememberMeManager(rememberMeManager);
        return securityManager;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        // 配置URL权限
        chainDefinition.addPathDefinition("/login", "anon"); // 匿名访问
        chainDefinition.addPathDefinition("/logout", "logout"); // 登出
        chainDefinition.addPathDefinition("/**", "authc"); // 其他所有请求都需要认证
        return chainDefinition;
    }
}
```

### 3. 在登录时启用Remember Me

在用户登录时，可以通过`UsernamePasswordToken`对象的`setRememberMe(true)`方法启用Remember Me功能。

**示例：**

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;

public void login(String username, String password, boolean rememberMe) {
    Subject currentUser = SecurityUtils.getSubject();
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    token.setRememberMe(rememberMe);
    try {
        currentUser.login(token);
        System.out.println("用户认证成功");
    } catch (UnknownAccountException e) {
        System.out.println("账户不存在");
    } catch (IncorrectCredentialsException e) {
        System.out.println("密码错误");
    } catch (LockedAccountException e) {
        System.out.println("账户被锁定");
    } catch (AuthenticationException e) {
        System.out.println("认证失败: " + e.getMessage());
    }
}
```

**说明**：
- `token.setRememberMe(true)`方法启用Remember Me功能。
- 用户登录后，Shiro会将用户的身份信息存储在Cookie中，并在下次访问时自动恢复会话。

### 4. 处理Remember Me登录

Shiro会自动处理Remember Me登录。如果用户通过Remember Me登录，Shiro会创建一个新的会话，并恢复用户身份信息。

**示例**：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

public boolean isRemembered() {
    Subject currentUser = SecurityUtils.getSubject();
    return currentUser.isRemembered();
}
```

**说明**：
- `currentUser.isRemembered()`方法可以检查用户是否通过Remember Me登录。

### 5. 登出时清除Remember Me

在用户登出时，Shiro会自动清除Remember Me的Cookie。

**示例**：

```java
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

public void logout() {
    Subject currentUser = SecurityUtils.getSubject();
    currentUser.logout();
}
```

### 6. 总结

通过以下步骤，开发者可以使用Shiro实现Remember Me功能：

1. **添加Shiro依赖**。
2. **配置Shiro**，包括Remember Me Manager和SecurityManager。
3. **在登录时启用Remember Me**，通过`UsernamePasswordToken.setRememberMe(true)`。
4. **处理Remember Me登录**，Shiro会自动恢复用户会话。
5. **登出时清除Remember Me**，Shiro会自动清除Remember Me的Cookie。

通过使用Shiro的Remember Me功能，开发者可以提供更好的用户体验，使用户在关闭浏览器或会话过期后仍然保持登录状态。


## 如何使用Shiro进行多租户支持?
在**Apache Shiro**中，**多租户支持**（Multi-tenancy）是指在同一个应用程序中为多个租户（用户或组织）提供隔离和安全性的能力。多租户架构通常用于SaaS（软件即服务）应用，其中多个客户共享相同的应用程序实例，但每个客户的数据和访问权限是隔离的。以下是如何使用Shiro实现多租户支持的详细步骤和示例：

### 1. 多租户的基本概念

- **租户（Tenant）**：在多租户架构中，租户是指使用应用程序的独立实体，如公司、组织或用户组。每个租户的数据和访问权限是隔离的。
- **隔离级别**：
  - **数据库级别隔离**：每个租户使用独立的数据库或数据库模式（schema）。
  - **表级别隔离**：所有租户共享同一个数据库，但使用不同的表或表前缀。
  - **行级别隔离**：所有租户共享同一个数据库和表，通过行数据中的租户标识进行隔离。

### 2. 实现多租户支持的步骤

#### a. 确定隔离级别

首先，确定应用程序的隔离级别。常见的隔离级别包括数据库级别、表级别和行级别。

- **数据库级别隔离**：适用于每个租户需要完全隔离的场景。
- **表级别隔离**：适用于租户数量较少且数据量不大的场景。
- **行级别隔离**：适用于租户数量较多且数据量较大的场景。

#### b. 配置Shiro Realm

Shiro的Realm负责从数据源中获取用户信息、角色和权限。在多租户架构中，Realm需要根据当前租户的信息来获取相应的数据。

**示例：实现多租户Realm**

```java
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class MultiTenantRealm extends AuthorizingRealm {

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取当前租户信息
        String tenantId = getCurrentTenantId();
        // 获取用户输入的用户名
        String username = (String) token.getPrincipal();
        // 从数据库中获取用户信息，根据租户ID进行过滤
        User user = userService.findByUsernameAndTenantId(username, tenantId);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取当前租户信息
        String tenantId = getCurrentTenantId();
        // 获取用户输入的用户名
        String username = (String) principals.getPrimaryPrincipal();
        // 从数据库中获取用户角色和权限，根据租户ID进行过滤
        User user = userService.findByUsernameAndTenantId(username, tenantId);
        if (user == null) {
            throw new UnknownAccountException("账户不存在");
        }
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(user.getRoles());
        info.setStringPermissions(user.getPermissions());
        return info;
    }

    private String getCurrentTenantId() {
        // 获取当前租户ID的逻辑，例如从线程本地变量或当前HTTP请求中获取
        return TenantContextHolder.getCurrentTenantId();
    }
}
```

**说明**：
- `getCurrentTenantId`方法用于获取当前租户ID，可以根据具体需求从线程本地变量、HTTP请求头或会话中获取。
- `userService.findByUsernameAndTenantId`方法根据用户名和租户ID从数据库中获取用户信息。

#### c. 配置Shiro SecurityManager

在配置Shiro的`SecurityManager`时，使用自定义的多租户Realm。

**示例**：

```java
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ShiroConfig {

    @Bean
    public MultiTenantRealm multiTenantRealm() {
        return new MultiTenantRealm();
    }

    @Bean
    public SecurityManager securityManager(MultiTenantRealm realm) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(realm);
        return securityManager;
    }

    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
        // 配置URL权限
        chainDefinition.addPathDefinition("/login", "anon"); // 匿名访问
        chainDefinition.addPathDefinition("/logout", "logout"); // 登出
        chainDefinition.addPathDefinition("/**", "authc"); // 其他所有请求都需要认证
        return chainDefinition;
    }
}
```

#### d. 获取当前租户ID

在多租户架构中，需要在每个请求中确定当前租户ID。可以通过以下几种方式获取：

- **HTTP请求头**：在每个HTTP请求中包含租户ID。
- **URL参数**：在URL中包含租户ID。
- **会话**：将租户ID存储在用户会话中。
- **线程本地变量**：使用`ThreadLocal`存储当前租户ID。

**示例**：

```java
public class TenantContextHolder {
    private static final ThreadLocal<String> tenantIdHolder = new ThreadLocal<>();

    public static void setCurrentTenantId(String tenantId) {
        tenantIdHolder.set(tenantId);
    }

    public static String getCurrentTenantId() {
        return tenantIdHolder.get();
    }

    public static void clear() {
        tenantIdHolder.remove();
    }
}
```

在每个HTTP请求中，可以通过过滤器或拦截器设置当前租户ID。

**示例**：

```java
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

public class TenantFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 从请求中获取租户ID，例如从请求头或URL参数中获取
        String tenantId = request.getParameter("tenantId");
        TenantContextHolder.setCurrentTenantId(tenantId);
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContextHolder.clear();
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // 初始化逻辑
    }

    @Override
    public void destroy() {
        // 销毁逻辑
    }
}
```

### 3. 总结

通过以下步骤，开发者可以使用Shiro实现多租户支持：

1. **确定隔离级别**，选择数据库级别、表级别或行级别隔离。
2. **配置Shiro Realm**，根据当前租户ID获取相应的用户信息、角色和权限。
3. **配置Shiro SecurityManager**，使用自定义的多租户Realm。
4. **获取当前租户ID**，可以通过HTTP请求头、URL参数、会话或线程本地变量获取。
5. **实现租户过滤器**，在每个请求中设置当前租户ID。

通过合理配置和使用Shiro的多租户支持机制，开发者可以构建安全可靠的多租户应用程序，满足不同租户的安全和隔离需求。


# 高级功能
## Shiro如何支持OAuth2?
[案例一](https://blog.csdn.net/qq_34021712/article/details/80510774)


## Shiro如何支持JWT?
[案例一](https://developer.aliyun.com/article/1296302)
