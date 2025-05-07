# 核心类和方法
Spring Security 是一个功能强大且高度可定制的身份验证和访问控制框架，用于保护基于 Spring 的 Java 应用程序。它提供了多种核心类和方法来帮助开发者实现安全功能。以下是 Spring Security 中一些关键的核心类及其主要职责和常用方法的概述：

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

5. **`WebSecurityConfigurerAdapter` (Deprecated in newer versions)**
   - **职责**：提供了一种便捷的方式来配置 Web 安全性，不过在最新的 Spring Security 版本中已经被标记为过时，推荐直接使用 `SecurityFilterChain` Bean 来配置。
   - **常用方法**：
     - `configure(HttpSecurity http)`：配置 HttpSecurity。
     - `configure(AuthenticationManagerBuilder auth)`：配置认证管理器。

6. **`SecurityContextHolder`**
   - **职责**：持有当前线程的安全上下文。
   - **常用方法**：
     - `getContext()`：获取当前的安全上下文。
     - `setContext(SecurityContext context)`：设置当前的安全上下文。

7. **`UsernamePasswordAuthenticationToken`**
   - **职责**：表示一个由用户名和密码组成的认证令牌。
   - **常用构造函数/方法**：
     - 构造函数：创建一个新的实例。
     - `getAuthorities()`：获取此 Authentication 对象中的权限列表。

8. **`JwtUtils` (非标准，自定义类)**
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
# Spring Security介绍

## Spring Security简介

Spring 是非常流行和成功的 Java 应用开发框架，Spring Security 正是 Spring 家族中的成员。Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方案。

正如你可能知道的关于安全方面的两个核心功能是**认证**和**授权**，一般来说，Web 应用的安全性包括**用户认证（Authentication）和用户授权（Authorization）**两个部分，这两点也是 SpringSecurity 重要核心功能。

（1）用户认证指的是：验证某个用户是否为系统中的合法主体，也就是说用户能否访问该系统。用户认证一般要求用户提供用户名和密码，系统通过校验用户名和密码来完成认证过程。

**通俗点说就是系统认为用户是否能登录**

（2）用户授权指的是验证某个用户是否有权限执行某个操作。在一个系统中，不同用户所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的权限。

**通俗点讲就是系统判断用户是否有权限去做某些事情。**

## 历史

“Spring Security 开始于 2003 年年底,““Spring 的 acegi 安全系统”。 起因是 Spring开发者邮件列表中的一个问题,有人提问是否考虑提供一个基于 Spring 的安全实现。

Spring Security 以“The Acegi Secutity System for Spring” 的名字始于 2013 年晚些时候。一个问题提交到 Spring 开发者的邮件列表，询问是否已经有考虑一个机遇 Spring 的安全性社区实现。那时候 Spring 的社区相对较小（相对现在）。实际上 Spring 自己在2013 年只是一个存在于 ScourseForge 的项目，这个问题的回答是一个值得研究的领域，虽然目前时间的缺乏组织了我们对它的探索。

考虑到这一点，一个简单的安全实现建成但是并没有发布。几周后，Spring 社区的其他成员询问了安全性，这次这个代码被发送给他们。其他几个请求也跟随而来。到 2014 年一月大约有 20 万人使用了这个代码。这些创业者的人提出一个 SourceForge 项目加入是为了，这是在 2004 三月正式成立。

在早些时候，这个项目没有任何自己的验证模块，身份验证过程依赖于容器管理的安全性和 Acegi 安全性。而不是专注于授权。开始的时候这很适合，但是越来越多的用户请求额外的容器支持。容器特定的认证领域接口的基本限制变得清晰。还有一个相关的问题增加新的容器的路径，这是最终用户的困惑和错误配置的常见问题。

Acegi 安全特定的认证服务介绍。大约一年后，Acegi 安全正式成为了 Spring 框架的子项目。1.0.0 最终版本是出版于 2006 -在超过两年半的大量生产的软件项目和数以百计的改进和积极利用社区的贡献。

Acegi 安全 2007 年底正式成为了 Spring 组合项目，更名为"Spring Security"。

## 同款产品对比

#### 3.1、Spring Security

Spring 技术栈的组成部分。  
链接: [SpringSecurity官网](https://spring.io/projects/spring-security)

通过提供完整可扩展的认证和授权支持保护你的应用程序。

**SpringSecurity 特点：**

⚫ 和 Spring 无缝整合。

⚫ 全面的[权限控制](https://so.csdn.net/so/search?q=%E6%9D%83%E9%99%90%E6%8E%A7%E5%88%B6&spm=1001.2101.3001.7020)。

⚫ 专门为 Web 开发而设计。

​ ◼旧版本不能脱离 Web 环境使用。

​ ◼新版本对整个框架进行了分层抽取，分成了核心模块和 Web 模块。单独引入核心模块就可以脱离 Web 环境。

⚫ 重量级。

#### 3.2、 [Shiro](https://so.csdn.net/so/search?q=Shiro&spm=1001.2101.3001.7020)

Apache 旗下的轻量级权限控制框架。

**特点：**

⚫ 轻量级。Shiro 主张的理念是把复杂的事情变简单。针对对性能有更高要求

的互联网应用有更好表现。

⚫ 通用性。

​ ◼好处：不局限于 Web 环境，可以脱离 Web 环境使用。

​ ◼缺陷：在 Web 环境下一些特定的需求需要手动编写代码定制。

Spring Security 是 Spring 家族中的一个安全管理框架，实际上，在 Spring Boot 出现之前，Spring Security 就已经发展了多年了，但是使用的并不多，安全管理这个领域，一直是 Shiro 的天下。

相对于 Shiro，在 SSM 中整合 Spring Security 都是比较麻烦的操作，所以，Spring Security 虽然功能比 Shiro 强大，但是使用反而没有 Shiro 多（Shiro 虽然功能没有Spring Security 多，但是对于大部分项目而言，Shiro 也够用了）。

自从有了 Spring Boot 之后，Spring Boot 对于 Spring Security 提供了自动化配置方案，可以使用更少的配置来使用 Spring Security。

因此，一般来说，常见的安全管理技术栈的组合是这样的：

• SSM + Shiro

• Spring Boot/Spring Cloud + Spring Security

**以上只是一个推荐的组合而已，如果单纯从技术上来说，无论怎么组合，都是可以运行的**

# Spring Security实现权限

要对Web资源进行保护，最好的办法莫过于Filter  
要想对方法调用进行保护，最好的办法莫过于[AOP]

Spring Security进行认证和鉴权的时候,就是利用的一系列的Filter来进行拦截的。  
![SpringSecurtiy过滤器链](https://i-blog.csdnimg.cn/blog_migrate/06baa2fe1001978350645fd0d799eb81.png)

如图所示，一个请求想要访问到API就会从左到右经过蓝线框里的过滤器，其中**绿色部分是负责认证的过滤器，蓝色部分是负责异常处理，橙色部分则是负责授权**。进过一系列拦截最终访问到我们的API。

这里面我们只需要重点关注两个过滤器即可：`UsernamePasswordAuthenticationFilter`负责登录认证，`FilterSecurityInterceptor`负责权限授权。

说明：**Spring Security的核心逻辑全在这一套过滤器中，过滤器里会调用各种组件完成功能，掌握了这些过滤器和组件你就掌握了Spring Security**！这个框架的使用方式就是对这些过滤器和组件进行扩展。

## SpringSecurity入门

#### 1.1 添加依赖

```xml
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>
```

说明：依赖包（spring-boot-starter-security）导入后，Spring Security就默认提供了许多功能将整个应用给保护了起来：

​ 1、要求经过身份验证的用户才能与应用程序进行交互

​ 2、创建好了默认登录表单

​ 3、生成用户名为`user`的随机密码并打印在控制台上

​ 4、`CSRF`攻击防护、`Session Fixation`攻击防护

​ 5、等等等等…

#### 1.2、启动项目测试

在浏览器访问：http://localhost:8800/doc.html

自动跳转到了登录页面

![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/8ce3b2281cf0ebc853f4ca8068362442.png)

默认的用户名：user

密码在项目启动的时候在控制台会打印，**注意每次启动的时候密码都会发生变化！**  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/ad924519b91ab5d7818535620a91b833.png)

输入用户名，密码，成功访问到controller方法并返回数据，说明Spring Security默认安全保护生效。

在实际开发中，这些默认的配置是不能满足我们需要的，我们需要扩展Spring Security组件，完成自定义配置，实现我们的项目需求。

## 用户认证

用户认证流程：  
![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/53cd6192c1c7c434145f2c1a3b64109a.png)  
概念速查:

**`Authentication`**接口: 它的实现类，表示当前访问系统的用户，封装了用户相关信息。

**`AuthenticationManager`**接口：定义了认证Authentication的方法

**`UserDetailsService`**接口：加载用户特定数据的核心接口。里面定义了一个根据用户名查询用户信息的方法。

**`UserDetails`**接口：提供核心用户信息。通过UserDetailsService根据用户名获取处理的用户信息要封装成UserDetails对象返回。然后将这些信息封装到Authentication对象中。

#### 2.1、用户认证核心组件

我们系统中会有许多用户，确认当前是哪个用户正在使用我们系统就是登录认证的最终目的。这里我们就提取出了一个核心概念：**当前登录用户/当前认证用户**。整个系统安全都是围绕当前登录用户展开的，这个不难理解，要是当前登录用户都不能确认了，那A下了一个订单，下到了B的账户上这不就乱套了。这一概念在Spring Security中的体现就是 **`Authentication`**，它存储了认证信息，代表当前登录用户。

我们在程序中如何获取并使用它呢？我们需要通过 **`SecurityContext`** 来获取`Authentication`，`SecurityContext`就是我们的上下文对象！这个上下文对象则是交由 **`SecurityContextHolder`** 进行管理，你可以在程序**任何地方**使用它：

```java
Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
```

`SecurityContextHolder`原理非常简单，就是使用`ThreadLocal`来保证一个线程中传递同一个对象！

**现在我们已经知道了Spring Security中三个核心组件：**

​ 1、`Authentication`：存储了认证信息，代表当前登录用户

​ 2、`SeucirtyContext`：上下文对象，用来获取`Authentication`

​ 3、`SecurityContextHolder`：上下文管理对象，用来在程序任何地方获取`SecurityContext`

**`Authentication`中是什么信息呢：**

​ 1、`Principal`：用户信息，没有认证时一般是用户名，认证后一般是用户对象

​ 2、`Credentials`：用户凭证，一般是密码

​ 3、`Authorities`：用户权限

#### 2.2、用户认证

Spring Security是怎么进行用户认证的呢？

**`AuthenticationManager`** 就是Spring Security用于执行身份验证的组件，只需要调用它的`authenticate`方法即可完成认证。Spring Security默认的认证方式就是在`UsernamePasswordAuthenticationFilter`这个过滤器中进行认证的，该过滤器负责认证逻辑。

Spring Security用户认证关键代码如下：

```java
// 生成一个包含账号密码的认证信息
Authentication authenticationToken = new UsernamePasswordAuthenticationToken(username, passwrod);
// AuthenticationManager校验这个认证信息，返回一个已认证的Authentication
Authentication authentication = authenticationManager.authenticate(authenticationToken);
// 将返回的Authentication存到上下文中
SecurityContextHolder.getContext().setAuthentication(authentication);
```

下面我们来分析一下。

###### 2.2.1、认证接口分析

`AuthenticationManager`的校验逻辑非常简单：

根据用户名先查询出用户对象(没有查到则抛出异常)将用户对象的密码和传递过来的密码进行校验，密码不匹配则抛出异常。

这个逻辑没啥好说的，再简单不过了。重点是这里每一个步骤Spring Security都提供了组件：

​ 1、是谁执行 **根据用户名查询出用户对象** 逻辑的呢？用户对象数据可以存在内存中、文件中、数据库中，你得确定好怎么查才行。这一部分就是交由**`UserDetialsService`** 处理，该接口只有一个方法`loadUserByUsername(String username)`，通过用户名查询用户对象，默认实现是在内存中查询。

​ 2、那查询出来的 **用户对象** 又是什么呢？每个系统中的用户对象数据都不尽相同，咱们需要确认我们的用户数据是啥样的才行。Spring Security中的用户数据则是由**`UserDetails`** 来体现，该接口中提供了账号、密码等通用属性。

​ 3、**对密码进行校验**大家可能会觉得比较简单，`if、else`搞定，就没必要用什么组件了吧？但框架毕竟是框架考虑的比较周全，除了`if、else`外还解决了密码加密的问题，这个组件就是**`PasswordEncoder`**，负责密码加密与校验。

我们可以看下`AuthenticationManager`校验逻辑的大概源码：

我们可以看下`AuthenticationManager`校验逻辑的大概源码：

```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
...省略其他代码

    // 传递过来的用户名
    String username = authentication.getName();
    // 调用UserDetailService的方法，通过用户名查询出用户对象UserDetail（查询不出来UserDetailService则会抛出异常）
    UserDetails userDetails = this.getUserDetailsService().loadUserByUsername(username);
    String presentedPassword = authentication.getCredentials().toString();

    // 传递过来的密码
    String password = authentication.getCredentials().toString();
    // 使用密码解析器PasswordEncoder传递过来的密码是否和真实的用户密码匹配
    if (!passwordEncoder.matches(password, userDetails.getPassword())) {
        // 密码错误则抛出异常
        throw new BadCredentialsException("错误信息...");
    }

    // 注意哦，这里返回的已认证Authentication，是将整个UserDetails放进去充当Principal
    UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(userDetails,
            authentication.getCredentials(), userDetails.getAuthorities());
    return result;

...省略其他代码
}
```

`UserDetialsService`、`UserDetails`、`PasswordEncoder`，这三个组件Spring Security都有默认实现，这一般是满足不了我们的实际需求的，所以这里我们自己来实现这些组件！

###### 2.2.2、加密器PasswordEncoder

采取MD5加密  
自定义加密处理组件：CustomMd5PasswordEncoder

```java
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;

import java.util.Arrays;

/**
 * 自定义security密码校验
 * @author 尹稳健~
 * @version 1.0
 * @time 2023/1/31
 */
public class CustomMd5PasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence rawPassword) {
        // 进行一个md5加密
        return Arrays.toString(DigestUtils.md5Digest(rawPassword.toString().getBytes()));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 通过md5校验
        return encodedPassword.equals(Arrays.toString(DigestUtils.md5Digest(rawPassword.toString().getBytes())));
    }
}

```

###### 2.2.3、用户对象UserDetails

该接口就是我们所说的用户对象，它提供了用户的一些通用属性，源码如下：

```java
public interface UserDetails extends Serializable {
	/**
     * 用户权限集合（这个权限对象现在不管它，到权限时我会讲解）
     */
    Collection<? extends GrantedAuthority> getAuthorities();
    /**
     * 用户密码
     */
    String getPassword();
    /**
     * 用户名
     */
    String getUsername();
    /**
     * 用户没过期返回true，反之则false
     */
    boolean isAccountNonExpired();
    /**
     * 用户没锁定返回true，反之则false
     */
    boolean isAccountNonLocked();
    /**
     * 用户凭据(通常为密码)没过期返回true，反之则false
     */
    boolean isCredentialsNonExpired();
    /**
     * 用户是启用状态返回true，反之则false
     */
    boolean isEnabled();
}
```

实际开发中我们的用户属性各种各样，这些默认属性可能是满足不了，所以我们一般会自己实现该接口，然后设置好我们实际的用户实体对象。实现此接口要重写很多方法比较麻烦，我们可以继承Spring Security提供的`org.springframework.security.core.userdetails.User`类，该类实现了`UserDetails`接口帮我们省去了重写方法的工作：

```java
import com.sky.model.system.SysUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * 自定义对象
 * @author 尹稳健~
 * @version 1.0
 * @time 2023/1/31
 */
public class CustomUser extends User {
    private SysUser sysUser;

    public CustomUser(SysUser sysUser, Collection<? extends GrantedAuthority> authorities) {
        super(sysUser.getUsername(), sysUser.getPassword(), authorities);
        this.sysUser = sysUser;
    }

    public SysUser getSysUser() {
        return sysUser;
    }

    public void setSysUser(SysUser sysUser) {
        this.sysUser = sysUser;
    }
}

```

###### 2.2.4、 业务对象UserDetailsService

该接口很简单只有一个方法：

```java
public interface UserDetailsService {
    /**
     * 根据用户名获取用户对象（获取不到直接抛异常）
     */
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

我们实现该接口，就完成了自己的业务

```java
import com.sky.model.system.SysUser;
import com.sky.system.custom.CustomUser;
import com.sky.system.service.SysUserService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Collections;
import java.util.Objects;

/**
 * 实现UserDetailsService接口，重写方法
 * @author 尹稳健~
 * @version 1.0
 * @time 2023/1/31
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private SysUserService sysUserService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = sysUserService.queryByUsername(username);
        if (Objects.isNull(sysUser)){
            throw new UsernameNotFoundException("用户名不存在！");
        }

        if(sysUser.getStatus() == 0) {
            throw new RuntimeException("账号已停用");
        }
        return new CustomUser(sysUser, Collections.emptyList());
    }
}

```

###### 2.2.5、登录接口

接下我们需要自定义登陆接口，然后让SpringSecurity对这个接口放行,让用户访问这个接口的时候不用登录也能访问。

​ 在接口中我们通过AuthenticationManager的authenticate方法来进行用户认证,所以需要在SecurityConfig中配置把AuthenticationManager注入容器。

​ 认证成功的话要生成一个jwt，放入响应中返回。

```java
@Slf4j
@Api(tags = "系统管理-登录管理")
@RequestMapping("/admin/system/index")
@RestController
public class IndexController {

    @Resource
    private SysUserService sysUserService;
    
    @ApiOperation("登录接口")
    @PostMapping("/login")
    public Result<Map<String,Object>> login(@RequestBody LoginVo loginVo){
    return sysUserService.login(loginVo);
	}
}
```

###### 2.2.6、 `SecurityConfig配置`

```java
package com.sky.system.config;

import com.sky.system.custom.CustomMd5PasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

/**
 * Security配置类
 * @author 尹稳健~
 * @version 1.0
 * @time 2023/1/31
 */
@Configuration
/**
 * @EnableWebSecurity是开启SpringSecurity的默认行为
 */
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 密码明文加密方式配置
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new CustomMd5PasswordEncoder();
    }

    /**
     * 获取AuthenticationManager（认证管理器），登录时认证使用
     * @param authenticationConfiguration
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return  http
                // 基于 token，不需要 csrf
                .csrf().disable()
                // 开启跨域以便前端调用接口
                .cors().and()
                .authorizeRequests()
                // 指定某些接口不需要通过验证即可访问。登录接口肯定是不需要认证的
                .antMatchers("/admin/system/index/login").permitAll()
                // 静态资源，可匿名访问
                .antMatchers(HttpMethod.GET, "/", "/*.html", "/**/*.html", "/**/*.css", "/**/*.js", "/profile/**").permitAll()
                .antMatchers("/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/*/api-docs", "/druid/**","/doc.html").permitAll()
                // 这里意思是其它所有接口需要认证才能访问
                .anyRequest().authenticated()
                .and()
                // 基于 token，不需要 session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // cors security 解决方案
                .cors().configurationSource(corsConfigurationSource())
                .and()
                .build();
    }

    /**
     * 配置跨源访问(CORS)
     * @return
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedHeaders(Collections.singletonList("*"));
        configuration.setAllowedMethods(Collections.singletonList("*"));
        configuration.setAllowedOrigins(Collections.singletonList("*"));
        configuration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
```

controller通过login方法调用实际业务

```java
@Service
public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, SysUser> implements SysUserService {


    @Resource
    private SysMenuService sysMenuService;

    /**
     * 通过AuthenticationManager的authenticate方法来进行用户认证,
     */
    @Resource
    private AuthenticationManager authenticationManager;
    
	@Override
    public Result<Map<String, Object>> login(LoginVo loginVo) {
        // 将表单数据封装到 UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginVo.getUsername(), loginVo.getPassword());
        // authenticate方法会调用loadUserByUsername
        Authentication authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        if(Objects.isNull(authenticate)){
            throw new RuntimeException("用户名或密码错误");
        }
        // 校验成功，强转对象
        CustomUser customUser = (CustomUser) authenticate.getPrincipal();
        SysUser sysUser = customUser.getSysUser();
        // 校验通过返回token
        String token = JwtUtil.createToken(sysUser.getId(), sysUser.getUsername());
        Map<String, Object> map = new HashMap<>();
        map.put("token",token);
        return Result.ok(map);
    }
}
```

###### 2.2.7、认证过滤器

我们需要自定义一个过滤器，这个过滤器会去获取请求头中的token，对token进行解析取出其中的信息，获取对应的LoginUser对象。然后封装Authentication对象存入SecurityContextHolder。

```java
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            //放行
            filterChain.doFilter(request, response);
            return;
        }
        //解析token
        String userid;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userid = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }
        //从redis中获取用户信息
        String redisKey = "login:" + userid;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if(Objects.isNull(loginUser)){
            throw new RuntimeException("用户未登录");
        }
        //存入SecurityContextHolder
        //TODO 获取权限信息封装到Authentication中
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginUser,null,null);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request, response);
    }
}

```

#### 3、用户授权

在SpringSecurity中，会使用默认的FilterSecurityInterceptor来进行权限校验。在FilterSecurityInterceptor中会从SecurityContextHolder获取其中的**Authentication**，然后获取其中的权限信息。判断当前用户是否拥有访问当前资源所需的权限。

**SpringSecurity中的Authentication类：**

```java
public interface Authentication extends Principal, Serializable {
	//权限数据列表
    Collection<? extends GrantedAuthority> getAuthorities();

    Object getCredentials();

    Object getDetails();

    Object getPrincipal();

    boolean isAuthenticated();

    void setAuthenticated(boolean var1) throws IllegalArgumentException;
}
```

前面登录时执行loadUserByUsername方法时，return new CustomUser(sysUser, Collections.emptyList());后面的空数据对接就是返回给Spring Security的权限数据。

在TokenAuthenticationFilter中怎么获取权限数据呢？登录时我们把权限数据保存到redis中（用户名为key，权限数据为value即可），这样通过token获取用户名即可拿到权限数据，这样就可构成出完整的Authentication对象。

##### 3.1、修改loadUserByUsername接口方法

```java
@Autowired
private SysMenuService sysMenuService;
```

```java
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    SysUser sysUser = sysUserService.getByUsername(username);
    if(null == sysUser) {
        throw new UsernameNotFoundException("用户名不存在！");
    }

    if(sysUser.getStatus().intValue() == 0) {
        throw new RuntimeException("账号已停用");
    }
    List<String> userPermsList = sysMenuService.findUserPermsList(sysUser.getId());
    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
    for (String perm : userPermsList) {
        authorities.add(new SimpleGrantedAuthority(perm.trim()));
    }
    return new CustomUser(sysUser, authorities);
}
```

##### 3.2、修改配置类

修改WebSecurityConfig类

配置类添加注解：

开启基于方法的安全认证机制，也就是说在web层的controller启用注解机制的安全确认

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
```

##### 3.3、控制controller层接口权限

**Spring Security默认是禁用注解的，要想开启注解，需要在继承WebSecurityConfigurerAdapter的类上加@EnableGlobalMethodSecurity注解，来判断用户对某个控制层的方法是否具有访问权限**

通过@PreAuthorize标签控制controller层接口权限

```java
public class SysRoleController {

    @Autowired
    private SysRoleService sysRoleService;

    @PreAuthorize("hasAuthority('bnt.sysRole.list')")
    @ApiOperation(value = "获取分页列表")
    @GetMapping("/{page}/{limit}")
    public Result index(
            @ApiParam(name = "page", value = "当前页码", required = true)
            @PathVariable Long page,

            @ApiParam(name = "limit", value = "每页记录数", required = true)
            @PathVariable Long limit,

            @ApiParam(name = "roleQueryVo", value = "查询对象", required = false)
                    SysRoleQueryVo roleQueryVo) {
        Page<SysRole> pageParam = new Page<>(page, limit);
        IPage<SysRole> pageModel = sysRoleService.selectPage(pageParam, roleQueryVo);
        return Result.ok(pageModel);
    }


    ...
}
```

##### 3.4、测试服务器端权限

登录后台，分配权限进行测试，页面如果添加了按钮权限控制，可临时去除方便测试

测试结论：

​ 1、分配了权限的能够成功返回接口数据

​ 2、没有分配权限的会抛出异常：org.springframework.security.access.AccessDeniedException: 不允许访问

#### 4、异常处理

我们还希望在认证失败或者是授权失败的情况下也能和我们的接口一样返回相同结构的json，这样可以让前端能对响应进行统一的处理。要实现这个功能我们需要知道SpringSecurity的异常处理机制。

​ 在SpringSecurity中，如果我们在认证或者授权的过程中出现了异常会被ExceptionTranslationFilter捕获到。在ExceptionTranslationFilter中会去判断是认证失败还是授权失败出现的异常。

​ 如果是认证过程中出现的异常会被封装成AuthenticationException然后调用**AuthenticationEntryPoint**对象的方法去进行异常处理。

​ 如果是授权过程中出现的异常会被封装成AccessDeniedException然后调用**AccessDeniedHandler**对象的方法去进行异常处理。

​ 所以如果我们需要自定义异常处理，我们只需要自定义AuthenticationEntryPoint和AccessDeniedHandler然后配置给SpringSecurity即可。

==异常处理有2种方式：==

​ 1、扩展Spring Security异常处理类：AccessDeniedHandler、AuthenticationEntryPoint

​ 2、在spring boot全局异常统一处理

**第一种方案说明：如果系统实现了全局异常处理，那么全局异常首先会获取AccessDeniedException异常，要想Spring Security扩展异常生效，必须在全局异常再次抛出该异常。**

①自定义实现类

```java
import com.alibaba.fastjson2.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sky.common.result.ResultCodeEnum;
import com.sky.common.util.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 认证失败处理
 * @author 尹稳健~
 * @version 1.0
 * @time 2023/2/1
 */
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(200);
        int code = ResultCodeEnum.LOGIN_AUTH.getCode();
        String msg = "认证失败，无法访问系统资源";
        response.setContentType("application/json;charset=UTF-8");
        Map<String, Object> result = new HashMap<>();
        result.put("msg", msg);
        result.put("code", code);
        String s = new ObjectMapper().writeValueAsString(result);
        response.getWriter().println(s);
    }
}
```

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sky.common.result.ResultCodeEnum;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author 尹稳健~
 * @version 1.0
 * @time 2023/2/1
 */
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        int code = ResultCodeEnum.PERMISSION.getCode();
        response.setStatus(200);
        response.setContentType("application/json;charset=UTF-8");
        String msg = "权限不足，无法访问系统资源";
        Map<String, Object> result = new HashMap<>();
        result.put("msg", msg);
        result.put("code", code);
        String s = new ObjectMapper().writeValueAsString(result);
        response.getWriter().println(s);
    }
}


```

②配置给SpringSecurity

​

​ 先注入对应的处理器

```java
    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
```

​ 然后我们可以使用HttpSecurity对象的方法去配置。

```java
        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint).
                accessDeniedHandler(accessDeniedHandler);
```