# Spring Security 完整学习笔记

> Spring Security 是一个功能强大且高度可定制的身份验证和访问控制框架
> 本笔记基于 Java 8 + Spring Boot 2.7.18

---

## 目录

1. [基础概念](#1-基础概念)
2. [快速入门](#2-快速入门)
3. [认证机制](#3-认证机制)
4. [授权机制](#4-授权机制)
5. [JWT 认证](#5-jwt-认证)
6. [OAuth2 认证](#6-oauth2-认证)
7. [方法级安全](#7-方法级安全)
8. [CORS 跨域](#8-cors-跨域)
9. [CSRF 防护](#9-csrf-防护)
10. [记住我功能](#10-记住我功能)
11. [会话管理](#11-会话管理)
12. [密码加密](#12-密码加密)
13. [常见错误与解决方案](#13-常见错误与解决方案)
14. [最佳实践](#14-最佳实践)

---

## 1. 基础概念

### 1.1 什么是 Spring Security？

Spring Security 是 Spring 家族中的安全框架，提供了全面的安全解决方案，包括认证（Authentication）和授权（Authorization）两个核心功能。

**核心功能：**
- **认证（Authentication）**：验证用户身份，确认"你是谁"
- **授权（Authorization）**：验证用户权限，确认"你能做什么"
- **防护攻击**：防止 CSRF、XSS、会话固定等攻击

### 1.2 核心概念

| 概念 | 说明 |
|------|------|
| Principal | 当前用户，通常是 UserDetails 对象 |
| Authentication | 认证信息，包含用户身份和权限 |
| SecurityContext | 安全上下文，存储当前用户的认证信息 |
| SecurityContextHolder | 安全上下文持有者，用于获取当前用户信息 |
| UserDetails | 用户详情接口，包含用户名、密码、权限等 |
| UserDetailsService | 用户详情服务，用于加载用户信息 |
| GrantedAuthority | 授予的权限 |
| AuthenticationManager | 认证管理器，处理认证请求 |
| AuthenticationProvider | 认证提供者，实际执行认证逻辑 |
| FilterChain | 过滤器链，处理安全相关的请求 |

### 1.3 认证流程

```
用户请求 -> UsernamePasswordAuthenticationFilter
                    |
                    v
           AuthenticationManager
                    |
                    v
           AuthenticationProvider
                    |
                    v
           UserDetailsService.loadUserByUsername()
                    |
                    v
           PasswordEncoder.matches()
                    |
                    v
           认证成功 -> SecurityContextHolder 存储认证信息
           认证失败 -> 抛出 AuthenticationException
```

### 1.4 过滤器链

Spring Security 通过一系列过滤器来处理安全相关的请求：

```
SecurityContextPersistenceFilter    # 安全上下文持久化
        ↓
LogoutFilter                        # 处理登出
        ↓
UsernamePasswordAuthenticationFilter # 处理表单登录
        ↓
BasicAuthenticationFilter           # 处理 HTTP Basic 认证
        ↓
RequestCacheAwareFilter             # 请求缓存
        ↓
SecurityContextHolderAwareRequestFilter
        ↓
AnonymousAuthenticationFilter       # 匿名认证
        ↓
SessionManagementFilter             # 会话管理
        ↓
ExceptionTranslationFilter          # 异常转换
        ↓
FilterSecurityInterceptor           # 授权过滤器
```

---

## 2. 快速入门

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
    
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    
    <!-- MySQL -->
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
    </dependency>
    
    <!-- MyBatis Plus -->
    <dependency>
        <groupId>com.baomidou</groupId>
        <artifactId>mybatis-plus-boot-starter</artifactId>
        <version>3.5.3.1</version>
    </dependency>
</dependencies>
```

### 2.2 默认配置

添加 Spring Security 依赖后，所有接口都会被保护。默认用户名是 `user`，密码在启动日志中打印。

```
Using generated security password: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 2.3 基本配置

```java
package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    /**
     * 安全过滤器链配置
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 授权配置
            .authorizeRequests()
                // 允许匿名访问的路径
                .antMatchers("/", "/login", "/register", "/public/**").permitAll()
                // 需要特定角色的路径
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                // 其他请求需要认证
                .anyRequest().authenticated()
            .and()
            // 表单登录配置
            .formLogin()
                .loginPage("/login")           // 自定义登录页面
                .loginProcessingUrl("/doLogin") // 登录处理 URL
                .usernameParameter("username")  // 用户名参数名
                .passwordParameter("password")  // 密码参数名
                .defaultSuccessUrl("/home")     // 登录成功跳转
                .failureUrl("/login?error")     // 登录失败跳转
                .permitAll()
            .and()
            // 登出配置
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .deleteCookies("JSESSIONID")
                .permitAll()
            .and()
            // CSRF 配置（前后端分离项目通常禁用）
            .csrf().disable();
        
        return http.build();
    }
    
    /**
     * 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 2.4 内存用户配置

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    /**
     * 内存用户配置（仅用于测试）
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password(passwordEncoder().encode("123456"))
            .roles("USER")
            .build();
        
        UserDetails admin = User.builder()
            .username("admin")
            .password(passwordEncoder().encode("admin123"))
            .roles("ADMIN", "USER")
            .build();
        
        return new InMemoryUserDetailsManager(user, admin);
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```


---

## 3. 认证机制

### 3.1 数据库用户认证

#### 数据库表设计

```sql
-- 用户表
CREATE TABLE `sys_user` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `username` VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名',
    `password` VARCHAR(100) NOT NULL COMMENT '密码',
    `nickname` VARCHAR(50) COMMENT '昵称',
    `email` VARCHAR(100) COMMENT '邮箱',
    `phone` VARCHAR(20) COMMENT '手机号',
    `avatar` VARCHAR(200) COMMENT '头像',
    `status` TINYINT DEFAULT 1 COMMENT '状态：0-禁用，1-启用',
    `create_time` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `update_time` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 角色表
CREATE TABLE `sys_role` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `name` VARCHAR(50) NOT NULL COMMENT '角色名称',
    `code` VARCHAR(50) NOT NULL UNIQUE COMMENT '角色编码',
    `description` VARCHAR(200) COMMENT '描述',
    `create_time` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 权限表
CREATE TABLE `sys_permission` (
    `id` BIGINT PRIMARY KEY AUTO_INCREMENT,
    `name` VARCHAR(50) NOT NULL COMMENT '权限名称',
    `code` VARCHAR(100) NOT NULL UNIQUE COMMENT '权限编码',
    `type` TINYINT COMMENT '类型：1-菜单，2-按钮',
    `parent_id` BIGINT DEFAULT 0 COMMENT '父级ID',
    `path` VARCHAR(200) COMMENT '路由路径',
    `icon` VARCHAR(50) COMMENT '图标',
    `sort` INT DEFAULT 0 COMMENT '排序',
    `create_time` DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 用户角色关联表
CREATE TABLE `sys_user_role` (
    `user_id` BIGINT NOT NULL,
    `role_id` BIGINT NOT NULL,
    PRIMARY KEY (`user_id`, `role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 角色权限关联表
CREATE TABLE `sys_role_permission` (
    `role_id` BIGINT NOT NULL,
    `permission_id` BIGINT NOT NULL,
    PRIMARY KEY (`role_id`, `permission_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### 实体类

```java
// 用户实体
@Data
@TableName("sys_user")
public class SysUser implements Serializable {
    
    @TableId(type = IdType.AUTO)
    private Long id;
    
    private String username;
    
    private String password;
    
    private String nickname;
    
    private String email;
    
    private String phone;
    
    private String avatar;
    
    private Integer status;
    
    private LocalDateTime createTime;
    
    private LocalDateTime updateTime;
    
    // 非数据库字段
    @TableField(exist = false)
    private List<SysRole> roles;
    
    @TableField(exist = false)
    private List<SysPermission> permissions;
}

// 角色实体
@Data
@TableName("sys_role")
public class SysRole implements Serializable {
    
    @TableId(type = IdType.AUTO)
    private Long id;
    
    private String name;
    
    private String code;
    
    private String description;
    
    private LocalDateTime createTime;
}

// 权限实体
@Data
@TableName("sys_permission")
public class SysPermission implements Serializable {
    
    @TableId(type = IdType.AUTO)
    private Long id;
    
    private String name;
    
    private String code;
    
    private Integer type;
    
    private Long parentId;
    
    private String path;
    
    private String icon;
    
    private Integer sort;
    
    private LocalDateTime createTime;
}
```

#### 自定义 UserDetails

```java
package com.example.security;

import com.example.entity.SysUser;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class LoginUser implements UserDetails {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 用户信息
     */
    private SysUser user;
    
    /**
     * 权限列表
     */
    private List<String> permissions;
    
    /**
     * 角色列表
     */
    private List<String> roles;
    
    /**
     * Spring Security 权限集合
     */
    private List<SimpleGrantedAuthority> authorities;
    
    public LoginUser(SysUser user, List<String> permissions, List<String> roles) {
        this.user = user;
        this.permissions = permissions;
        this.roles = roles;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities != null) {
            return authorities;
        }
        
        // 将权限和角色转换为 GrantedAuthority
        authorities = permissions.stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
        
        // 添加角色（角色需要加 ROLE_ 前缀）
        roles.forEach(role -> 
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        
        return authorities;
    }
    
    @Override
    public String getPassword() {
        return user.getPassword();
    }
    
    @Override
    public String getUsername() {
        return user.getUsername();
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return user.getStatus() == 1;
    }
}
```

#### 自定义 UserDetailsService

```java
package com.example.security;

import com.example.entity.SysUser;
import com.example.mapper.SysUserMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    
    private final SysUserMapper userMapper;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. 查询用户
        SysUser user = userMapper.selectByUsername(username);
        if (user == null) {
            log.warn("用户不存在: {}", username);
            throw new UsernameNotFoundException("用户不存在");
        }
        
        // 2. 检查用户状态
        if (user.getStatus() == 0) {
            log.warn("用户已被禁用: {}", username);
            throw new UsernameNotFoundException("用户已被禁用");
        }
        
        // 3. 查询用户权限
        List<String> permissions = userMapper.selectPermissionsByUserId(user.getId());
        
        // 4. 查询用户角色
        List<String> roles = userMapper.selectRolesByUserId(user.getId());
        
        log.info("用户登录: {}, 角色: {}, 权限: {}", username, roles, permissions);
        
        // 5. 返回 UserDetails
        return new LoginUser(user, permissions, roles);
    }
}
```

#### Mapper

```java
@Mapper
public interface SysUserMapper extends BaseMapper<SysUser> {
    
    /**
     * 根据用户名查询用户
     */
    @Select("SELECT * FROM sys_user WHERE username = #{username}")
    SysUser selectByUsername(String username);
    
    /**
     * 查询用户权限
     */
    @Select("SELECT DISTINCT p.code FROM sys_permission p " +
            "INNER JOIN sys_role_permission rp ON p.id = rp.permission_id " +
            "INNER JOIN sys_user_role ur ON rp.role_id = ur.role_id " +
            "WHERE ur.user_id = #{userId}")
    List<String> selectPermissionsByUserId(Long userId);
    
    /**
     * 查询用户角色
     */
    @Select("SELECT r.code FROM sys_role r " +
            "INNER JOIN sys_user_role ur ON r.id = ur.role_id " +
            "WHERE ur.user_id = #{userId}")
    List<String> selectRolesByUserId(Long userId);
}
```

### 3.2 自定义认证成功/失败处理

```java
// 认证成功处理器
@Component
@Slf4j
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("用户登录成功: {}", authentication.getName());
        
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(JSON.toJSONString(Result.success("登录成功")));
    }
}

// 认证失败处理器
@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        log.warn("用户登录失败: {}", exception.getMessage());
        
        String message = "登录失败";
        if (exception instanceof BadCredentialsException) {
            message = "用户名或密码错误";
        } else if (exception instanceof DisabledException) {
            message = "账号已被禁用";
        } else if (exception instanceof LockedException) {
            message = "账号已被锁定";
        } else if (exception instanceof AccountExpiredException) {
            message = "账号已过期";
        }
        
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(JSON.toJSONString(Result.error(401, message)));
    }
}

// 未认证处理器
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(JSON.toJSONString(Result.error(401, "请先登录")));
    }
}

// 无权限处理器
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write(JSON.toJSONString(Result.error(403, "没有访问权限")));
    }
}
```

### 3.3 配置自定义处理器

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final CustomAuthenticationSuccessHandler successHandler;
    private final CustomAuthenticationFailureHandler failureHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/login", "/register", "/captcha").permitAll()
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginProcessingUrl("/login")
                .successHandler(successHandler)
                .failureHandler(failureHandler)
            .and()
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            .and()
            .csrf().disable();
        
        return http.build();
    }
}
```


---

## 4. 授权机制

### 4.1 URL 级别授权

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            // 允许所有人访问
            .antMatchers("/public/**", "/login", "/register").permitAll()
            
            // 需要认证
            .antMatchers("/api/**").authenticated()
            
            // 需要特定角色（自动添加 ROLE_ 前缀）
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/user/**").hasAnyRole("USER", "ADMIN")
            
            // 需要特定权限
            .antMatchers("/system/user/add").hasAuthority("system:user:add")
            .antMatchers("/system/user/delete").hasAuthority("system:user:delete")
            .antMatchers("/system/user/**").hasAnyAuthority("system:user:list", "system:user:view")
            
            // IP 限制
            .antMatchers("/internal/**").hasIpAddress("192.168.1.0/24")
            
            // 自定义表达式
            .antMatchers("/order/**").access("hasRole('USER') and hasAuthority('order:view')")
            
            // 其他请求需要认证
            .anyRequest().authenticated();
    
    return http.build();
}
```

### 4.2 方法级别授权

```java
// 启用方法级安全
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,   // 启用 @PreAuthorize 和 @PostAuthorize
    securedEnabled = true,   // 启用 @Secured
    jsr250Enabled = true     // 启用 @RolesAllowed
)
public class MethodSecurityConfig {
}
```

```java
@RestController
@RequestMapping("/user")
public class UserController {
    
    /**
     * @PreAuthorize - 方法执行前检查权限
     */
    @PreAuthorize("hasAuthority('system:user:list')")
    @GetMapping("/list")
    public Result<List<User>> list() {
        return Result.success(userService.list());
    }
    
    /**
     * 检查角色
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/add")
    public Result<Void> add(@RequestBody User user) {
        userService.save(user);
        return Result.success();
    }
    
    /**
     * 多个条件
     */
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('system:user:edit')")
    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody User user) {
        userService.updateById(user);
        return Result.success();
    }
    
    /**
     * 使用参数
     */
    @PreAuthorize("#id == authentication.principal.user.id or hasRole('ADMIN')")
    @GetMapping("/{id}")
    public Result<User> getById(@PathVariable Long id) {
        return Result.success(userService.getById(id));
    }
    
    /**
     * @PostAuthorize - 方法执行后检查权限
     */
    @PostAuthorize("returnObject.data.username == authentication.name or hasRole('ADMIN')")
    @GetMapping("/info/{id}")
    public Result<User> getInfo(@PathVariable Long id) {
        return Result.success(userService.getById(id));
    }
    
    /**
     * @Secured - 检查角色（需要 ROLE_ 前缀）
     */
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        userService.removeById(id);
        return Result.success();
    }
    
    /**
     * @RolesAllowed - JSR-250 标准注解
     */
    @RolesAllowed({"ADMIN", "MANAGER"})
    @PostMapping("/batch")
    public Result<Void> batchAdd(@RequestBody List<User> users) {
        userService.saveBatch(users);
        return Result.success();
    }
}
```

### 4.3 自定义权限表达式

```java
// 自定义权限评估器
@Component("perm")
public class CustomPermissionEvaluator {
    
    /**
     * 检查是否有权限
     */
    public boolean hasPermission(String permission) {
        LoginUser loginUser = SecurityUtils.getLoginUser();
        if (loginUser == null) {
            return false;
        }
        
        // 超级管理员拥有所有权限
        if (loginUser.getRoles().contains("SUPER_ADMIN")) {
            return true;
        }
        
        return loginUser.getPermissions().contains(permission);
    }
    
    /**
     * 检查是否是资源所有者
     */
    public boolean isOwner(Long resourceUserId) {
        LoginUser loginUser = SecurityUtils.getLoginUser();
        if (loginUser == null) {
            return false;
        }
        return loginUser.getUser().getId().equals(resourceUserId);
    }
}
```

```java
// 使用自定义权限表达式
@RestController
@RequestMapping("/article")
public class ArticleController {
    
    @PreAuthorize("@perm.hasPermission('article:add')")
    @PostMapping
    public Result<Void> add(@RequestBody Article article) {
        articleService.save(article);
        return Result.success();
    }
    
    @PreAuthorize("@perm.isOwner(#article.userId) or hasRole('ADMIN')")
    @PutMapping
    public Result<Void> update(@RequestBody Article article) {
        articleService.updateById(article);
        return Result.success();
    }
}
```

### 4.4 动态权限配置

```java
// 动态权限数据源
@Component
public class DynamicSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    
    @Autowired
    private SysPermissionMapper permissionMapper;
    
    /**
     * 获取访问该 URL 所需的权限
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation fi = (FilterInvocation) object;
        String url = fi.getRequestUrl();
        String method = fi.getRequest().getMethod();
        
        // 从数据库查询该 URL 需要的权限
        List<String> permissions = permissionMapper.selectPermissionsByUrl(url, method);
        
        if (permissions.isEmpty()) {
            return null;  // 返回 null 表示不需要权限
        }
        
        String[] attributes = permissions.toArray(new String[0]);
        return SecurityConfig.createList(attributes);
    }
    
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}

// 动态权限决策管理器
@Component
public class DynamicAccessDecisionManager implements AccessDecisionManager {
    
    @Override
    public void decide(Authentication authentication, Object object,
                       Collection<ConfigAttribute> configAttributes) 
            throws AccessDeniedException, InsufficientAuthenticationException {
        
        if (configAttributes == null || configAttributes.isEmpty()) {
            return;  // 没有配置权限要求，直接放行
        }
        
        // 获取用户权限
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        
        for (ConfigAttribute configAttribute : configAttributes) {
            String needPermission = configAttribute.getAttribute();
            
            for (GrantedAuthority authority : authorities) {
                if (needPermission.equals(authority.getAuthority())) {
                    return;  // 有权限，放行
                }
            }
        }
        
        throw new AccessDeniedException("没有访问权限");
    }
    
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }
    
    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
```

---

## 5. JWT 认证

### 5.1 添加依赖

```xml
<!-- JWT -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<!-- Redis -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

### 5.2 JWT 工具类

```java
package com.example.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class JwtUtils {
    
    @Value("${jwt.secret:your-256-bit-secret-key-here-must-be-at-least-32-characters}")
    private String secret;
    
    @Value("${jwt.expiration:86400000}")  // 默认 24 小时
    private Long expiration;
    
    @Value("${jwt.header:Authorization}")
    private String header;
    
    @Value("${jwt.prefix:Bearer }")
    private String prefix;
    
    /**
     * 生成 JWT Token
     */
    public String generateToken(String username, Map<String, Object> claims) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        
        if (claims == null) {
            claims = new HashMap<>();
        }
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSecretKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    /**
     * 生成 JWT Token（简化版）
     */
    public String generateToken(String username) {
        return generateToken(username, null);
    }
    
    /**
     * 从 Token 中获取用户名
     */
    public String getUsernameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims != null ? claims.getSubject() : null;
    }
    
    /**
     * 从 Token 中获取 Claims
     */
    public Claims getClaimsFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSecretKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("Token 已过期: {}", e.getMessage());
            return e.getClaims();
        } catch (JwtException e) {
            log.error("Token 解析失败: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 验证 Token 是否有效
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSecretKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            log.error("Token 验证失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 判断 Token 是否过期
     */
    public boolean isTokenExpired(String token) {
        Claims claims = getClaimsFromToken(token);
        if (claims == null) {
            return true;
        }
        Date expiration = claims.getExpiration();
        return expiration.before(new Date());
    }
    
    /**
     * 获取密钥
     */
    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String getHeader() {
        return header;
    }
    
    public String getPrefix() {
        return prefix;
    }
}
```

### 5.3 JWT 认证过滤器

```java
package com.example.security.filter;

import com.example.security.LoginUser;
import com.example.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtUtils jwtUtils;
    private final RedisTemplate<String, Object> redisTemplate;
    
    private static final String TOKEN_PREFIX = "login:token:";
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 1. 获取 Token
        String token = getTokenFromRequest(request);
        
        if (!StringUtils.hasText(token)) {
            // 没有 Token，继续执行过滤器链
            filterChain.doFilter(request, response);
            return;
        }
        
        // 2. 验证 Token
        if (!jwtUtils.validateToken(token)) {
            log.warn("Token 无效");
            filterChain.doFilter(request, response);
            return;
        }
        
        // 3. 从 Token 中获取用户名
        String username = jwtUtils.getUsernameFromToken(token);
        if (!StringUtils.hasText(username)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // 4. 从 Redis 中获取用户信息
        String redisKey = TOKEN_PREFIX + username;
        LoginUser loginUser = (LoginUser) redisTemplate.opsForValue().get(redisKey);
        
        if (loginUser == null) {
            log.warn("用户信息不存在或已过期: {}", username);
            filterChain.doFilter(request, response);
            return;
        }
        
        // 5. 将用户信息存入 SecurityContext
        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // 6. 继续执行过滤器链
        filterChain.doFilter(request, response);
    }
    
    /**
     * 从请求中获取 Token
     */
    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(jwtUtils.getHeader());
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtUtils.getPrefix())) {
            return bearerToken.substring(jwtUtils.getPrefix().length());
        }
        return null;
    }
}
```


### 5.4 登录服务

```java
package com.example.service;

import com.example.dto.LoginRequest;
import com.example.dto.LoginResponse;
import com.example.security.LoginUser;
import com.example.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService {
    
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final RedisTemplate<String, Object> redisTemplate;
    
    private static final String TOKEN_PREFIX = "login:token:";
    private static final long TOKEN_EXPIRE_TIME = 24 * 60 * 60;  // 24 小时
    
    /**
     * 用户登录
     */
    public LoginResponse login(LoginRequest request) {
        // 1. 认证
        UsernamePasswordAuthenticationToken authenticationToken = 
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        
        // 2. 获取用户信息
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        
        // 3. 生成 Token
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", loginUser.getUser().getId());
        String token = jwtUtils.generateToken(loginUser.getUsername(), claims);
        
        // 4. 将用户信息存入 Redis
        String redisKey = TOKEN_PREFIX + loginUser.getUsername();
        redisTemplate.opsForValue().set(redisKey, loginUser, TOKEN_EXPIRE_TIME, TimeUnit.SECONDS);
        
        log.info("用户登录成功: {}", loginUser.getUsername());
        
        // 5. 返回登录结果
        return LoginResponse.builder()
                .token(token)
                .username(loginUser.getUsername())
                .nickname(loginUser.getUser().getNickname())
                .avatar(loginUser.getUser().getAvatar())
                .roles(loginUser.getRoles())
                .permissions(loginUser.getPermissions())
                .build();
    }
    
    /**
     * 用户登出
     */
    public void logout() {
        // 获取当前用户
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return;
        }
        
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        
        // 删除 Redis 中的用户信息
        String redisKey = TOKEN_PREFIX + loginUser.getUsername();
        redisTemplate.delete(redisKey);
        
        // 清除 SecurityContext
        SecurityContextHolder.clearContext();
        
        log.info("用户登出成功: {}", loginUser.getUsername());
    }
    
    /**
     * 刷新 Token
     */
    public String refreshToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new RuntimeException("用户未登录");
        }
        
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        
        // 生成新 Token
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", loginUser.getUser().getId());
        String newToken = jwtUtils.generateToken(loginUser.getUsername(), claims);
        
        // 更新 Redis 过期时间
        String redisKey = TOKEN_PREFIX + loginUser.getUsername();
        redisTemplate.expire(redisKey, TOKEN_EXPIRE_TIME, TimeUnit.SECONDS);
        
        return newToken;
    }
}
```

### 5.5 Security 配置（JWT 版本）

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final UserDetailsServiceImpl userDetailsService;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 关闭 CSRF
            .csrf().disable()
            // 关闭 Session
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // 授权配置
            .authorizeRequests()
                .antMatchers("/login", "/register", "/captcha").permitAll()
                .antMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .anyRequest().authenticated()
            .and()
            // 异常处理
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            .and()
            // 添加 JWT 过滤器
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            // 允许跨域
            .cors();
        
        return http.build();
    }
    
    /**
     * 认证管理器
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    
    /**
     * 密码编码器
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 5.6 登录控制器

```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final LoginService loginService;
    
    /**
     * 登录
     */
    @PostMapping("/login")
    public Result<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        LoginResponse response = loginService.login(request);
        return Result.success(response);
    }
    
    /**
     * 登出
     */
    @PostMapping("/logout")
    public Result<Void> logout() {
        loginService.logout();
        return Result.success();
    }
    
    /**
     * 刷新 Token
     */
    @PostMapping("/refresh")
    public Result<String> refreshToken() {
        String token = loginService.refreshToken();
        return Result.success(token);
    }
    
    /**
     * 获取当前用户信息
     */
    @GetMapping("/info")
    public Result<LoginUser> getUserInfo() {
        LoginUser loginUser = SecurityUtils.getLoginUser();
        return Result.success(loginUser);
    }
}
```

### 5.7 安全工具类

```java
package com.example.util;

import com.example.security.LoginUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {
    
    /**
     * 获取当前登录用户
     */
    public static LoginUser getLoginUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof LoginUser) {
            return (LoginUser) principal;
        }
        return null;
    }
    
    /**
     * 获取当前用户ID
     */
    public static Long getUserId() {
        LoginUser loginUser = getLoginUser();
        return loginUser != null ? loginUser.getUser().getId() : null;
    }
    
    /**
     * 获取当前用户名
     */
    public static String getUsername() {
        LoginUser loginUser = getLoginUser();
        return loginUser != null ? loginUser.getUsername() : null;
    }
    
    /**
     * 判断是否有某个权限
     */
    public static boolean hasPermission(String permission) {
        LoginUser loginUser = getLoginUser();
        if (loginUser == null) {
            return false;
        }
        return loginUser.getPermissions().contains(permission);
    }
    
    /**
     * 判断是否有某个角色
     */
    public static boolean hasRole(String role) {
        LoginUser loginUser = getLoginUser();
        if (loginUser == null) {
            return false;
        }
        return loginUser.getRoles().contains(role);
    }
    
    /**
     * 判断是否是管理员
     */
    public static boolean isAdmin() {
        return hasRole("ADMIN") || hasRole("SUPER_ADMIN");
    }
}
```

---

## 6. OAuth2 认证

### 6.1 OAuth2 简介

OAuth2 是一个授权框架，允许第三方应用获取有限的访问权限。

**四种授权模式：**
- **授权码模式（Authorization Code）**：最安全，适用于有后端的应用
- **简化模式（Implicit）**：适用于纯前端应用（已不推荐）
- **密码模式（Password）**：适用于受信任的应用
- **客户端凭证模式（Client Credentials）**：适用于服务间调用

### 6.2 添加依赖

```xml
<!-- OAuth2 资源服务器 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<!-- OAuth2 客户端 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

### 6.3 OAuth2 登录（第三方登录）

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: your-github-client-id
            client-secret: your-github-client-secret
            scope: read:user,user:email
          google:
            client-id: your-google-client-id
            client-secret: your-google-client-secret
            scope: openid,profile,email
          gitee:
            client-id: your-gitee-client-id
            client-secret: your-gitee-client-secret
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: user_info
        provider:
          gitee:
            authorization-uri: https://gitee.com/oauth/authorize
            token-uri: https://gitee.com/oauth/token
            user-info-uri: https://gitee.com/api/v5/user
            user-name-attribute: login
```

```java
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/login", "/error").permitAll()
                .anyRequest().authenticated()
            .and()
            .oauth2Login()
                .loginPage("/login")
                .defaultSuccessUrl("/home")
                .failureUrl("/login?error")
                .userInfoEndpoint()
                    .userService(customOAuth2UserService());
        
        return http.build();
    }
    
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
        return new CustomOAuth2UserService();
    }
}

// 自定义 OAuth2 用户服务
@Service
@Slf4j
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    @Autowired
    private SysUserMapper userMapper;
    
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = delegate.loadUser(userRequest);
        
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration()
            .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        
        // 获取用户信息
        Map<String, Object> attributes = oauth2User.getAttributes();
        String username = (String) attributes.get(userNameAttributeName);
        String email = (String) attributes.get("email");
        String avatar = (String) attributes.get("avatar_url");
        
        log.info("OAuth2 登录: provider={}, username={}", registrationId, username);
        
        // 查询或创建用户
        SysUser user = userMapper.selectByOAuth2(registrationId, username);
        if (user == null) {
            user = new SysUser();
            user.setUsername(registrationId + "_" + username);
            user.setNickname(username);
            user.setEmail(email);
            user.setAvatar(avatar);
            user.setStatus(1);
            userMapper.insert(user);
        }
        
        return new DefaultOAuth2User(
            oauth2User.getAuthorities(),
            attributes,
            userNameAttributeName
        );
    }
}
```


---

## 7. 方法级安全

### 7.1 启用方法级安全

```java
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,   // 启用 @PreAuthorize 和 @PostAuthorize
    securedEnabled = true,   // 启用 @Secured
    jsr250Enabled = true     // 启用 @RolesAllowed
)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    
    /**
     * 自定义权限评估器
     */
    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(new CustomPermissionEvaluator());
        return handler;
    }
}
```

### 7.2 常用注解

```java
@Service
public class UserService {
    
    /**
     * @PreAuthorize - 方法执行前检查
     */
    @PreAuthorize("hasRole('ADMIN')")
    public void adminOnly() {
        // 只有 ADMIN 角色可以访问
    }
    
    @PreAuthorize("hasAuthority('user:delete')")
    public void deleteUser(Long id) {
        // 需要 user:delete 权限
    }
    
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public void managerOrAdmin() {
        // ADMIN 或 MANAGER 角色可以访问
    }
    
    @PreAuthorize("#userId == authentication.principal.user.id")
    public User getUser(Long userId) {
        // 只能查看自己的信息
        return userMapper.selectById(userId);
    }
    
    @PreAuthorize("@perm.hasPermission('user:edit')")
    public void editUser(User user) {
        // 使用自定义权限检查
    }
    
    /**
     * @PostAuthorize - 方法执行后检查
     */
    @PostAuthorize("returnObject.username == authentication.name")
    public User getUserInfo(Long id) {
        // 只能返回自己的信息
        return userMapper.selectById(id);
    }
    
    /**
     * @PreFilter - 过滤输入集合
     */
    @PreFilter("filterObject.createdBy == authentication.name")
    public void batchDelete(List<Article> articles) {
        // 只删除自己创建的文章
    }
    
    /**
     * @PostFilter - 过滤输出集合
     */
    @PostFilter("filterObject.status == 1 or hasRole('ADMIN')")
    public List<Article> getArticles() {
        // 普通用户只能看到已发布的文章，管理员可以看到所有
        return articleMapper.selectList(null);
    }
    
    /**
     * @Secured - 检查角色
     */
    @Secured({"ROLE_ADMIN", "ROLE_MANAGER"})
    public void securedMethod() {
        // 需要 ROLE_ADMIN 或 ROLE_MANAGER
    }
    
    /**
     * @RolesAllowed - JSR-250 标准
     */
    @RolesAllowed({"ADMIN", "MANAGER"})
    public void rolesAllowedMethod() {
        // 需要 ADMIN 或 MANAGER 角色
    }
}
```

### 7.3 SpEL 表达式

```java
// 常用 SpEL 表达式
@PreAuthorize("hasRole('ADMIN')")                    // 有 ADMIN 角色
@PreAuthorize("hasAnyRole('ADMIN', 'USER')")         // 有任一角色
@PreAuthorize("hasAuthority('user:read')")           // 有指定权限
@PreAuthorize("hasAnyAuthority('user:read', 'user:write')")  // 有任一权限
@PreAuthorize("isAuthenticated()")                   // 已认证
@PreAuthorize("isAnonymous()")                       // 匿名用户
@PreAuthorize("isFullyAuthenticated()")              // 完全认证（非记住我）
@PreAuthorize("permitAll()")                         // 允许所有
@PreAuthorize("denyAll()")                           // 拒绝所有

// 使用参数
@PreAuthorize("#id == authentication.principal.user.id")
public User getById(Long id) { }

// 使用对象属性
@PreAuthorize("#user.username == authentication.name")
public void update(User user) { }

// 组合条件
@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.user.id")
public User getUser(Long id) { }

// 使用自定义 Bean
@PreAuthorize("@permissionService.hasPermission(authentication, #id, 'user')")
public void delete(Long id) { }
```

---

## 8. CORS 跨域

### 8.1 全局 CORS 配置

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 允许的源
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:8080"));
        // 或允许所有源（不推荐生产环境使用）
        // configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        
        // 允许的方法
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // 允许的请求头
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        // 暴露的响应头
        configuration.setExposedHeaders(Arrays.asList("Authorization", "X-Total-Count"));
        
        // 是否允许携带凭证
        configuration.setAllowCredentials(true);
        
        // 预检请求缓存时间
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}
```

### 8.2 Security 中配置 CORS

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // 启用 CORS
        .cors().configurationSource(corsConfigurationSource())
        .and()
        // 其他配置...
        .csrf().disable();
    
    return http.build();
}
```

### 8.3 Controller 级别 CORS

```java
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600)
public class ApiController {
    
    @CrossOrigin(origins = "*")  // 方法级别覆盖
    @GetMapping("/public")
    public String publicApi() {
        return "public";
    }
}
```

---

## 9. CSRF 防护

### 9.1 CSRF 简介

CSRF（Cross-Site Request Forgery，跨站请求伪造）是一种攻击方式，攻击者诱导用户在已登录的网站上执行非预期的操作。

### 9.2 CSRF 配置

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // 启用 CSRF（默认启用）
        .csrf()
            // 忽略某些路径
            .ignoringAntMatchers("/api/**", "/webhook/**")
            // 自定义 CSRF Token 仓库
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    
    return http.build();
}
```

### 9.3 前端处理 CSRF Token

```html
<!-- Thymeleaf 模板 -->
<form th:action="@{/login}" method="post">
    <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
    <!-- 其他表单字段 -->
</form>
```

```javascript
// JavaScript 获取 CSRF Token
const csrfToken = document.querySelector('meta[name="_csrf"]').content;
const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

// 发送请求时携带 CSRF Token
fetch('/api/data', {
    method: 'POST',
    headers: {
        [csrfHeader]: csrfToken,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
});
```

### 9.4 前后端分离项目

前后端分离项目通常使用 JWT Token，可以禁用 CSRF：

```java
http.csrf().disable();
```

---

## 10. 记住我功能

### 10.1 基本配置

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .rememberMe()
            .key("uniqueAndSecret")           // 加密密钥
            .tokenValiditySeconds(604800)     // Token 有效期（7天）
            .rememberMeParameter("remember")  // 表单参数名
            .userDetailsService(userDetailsService);
    
    return http.build();
}
```

### 10.2 持久化 Token

```java
@Bean
public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
    JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
    tokenRepository.setDataSource(dataSource);
    // 启动时创建表（仅首次）
    // tokenRepository.setCreateTableOnStartup(true);
    return tokenRepository;
}

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .rememberMe()
            .tokenRepository(persistentTokenRepository(dataSource))
            .tokenValiditySeconds(604800)
            .userDetailsService(userDetailsService);
    
    return http.build();
}
```

```sql
-- 记住我 Token 表
CREATE TABLE `persistent_logins` (
    `username` VARCHAR(64) NOT NULL,
    `series` VARCHAR(64) PRIMARY KEY,
    `token` VARCHAR(64) NOT NULL,
    `last_used` TIMESTAMP NOT NULL
);
```

---

## 11. 会话管理

### 11.1 会话配置

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement()
            // 会话创建策略
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            // 会话固定攻击防护
            .sessionFixation().migrateSession()
            // 最大会话数
            .maximumSessions(1)
            // 达到最大会话数时的策略
            .maxSessionsPreventsLogin(false)  // false: 踢掉旧会话，true: 阻止新登录
            // 会话过期跳转
            .expiredUrl("/login?expired");
    
    return http.build();
}
```

### 11.2 会话创建策略

| 策略 | 说明 |
|------|------|
| ALWAYS | 总是创建会话 |
| IF_REQUIRED | 需要时创建（默认） |
| NEVER | 不创建，但会使用已存在的会话 |
| STATELESS | 不创建也不使用会话（适用于 JWT） |

### 11.3 并发会话控制

```java
@Bean
public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
}

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement()
            .maximumSessions(1)
            .sessionRegistry(sessionRegistry());
    
    return http.build();
}

@Bean
public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl();
}
```

### 11.4 获取在线用户

```java
@Service
@RequiredArgsConstructor
public class SessionService {
    
    private final SessionRegistry sessionRegistry;
    
    /**
     * 获取所有在线用户
     */
    public List<String> getOnlineUsers() {
        return sessionRegistry.getAllPrincipals().stream()
            .filter(principal -> !sessionRegistry.getAllSessions(principal, false).isEmpty())
            .map(principal -> ((UserDetails) principal).getUsername())
            .collect(Collectors.toList());
    }
    
    /**
     * 强制用户下线
     */
    public void forceLogout(String username) {
        sessionRegistry.getAllPrincipals().stream()
            .filter(principal -> ((UserDetails) principal).getUsername().equals(username))
            .flatMap(principal -> sessionRegistry.getAllSessions(principal, false).stream())
            .forEach(SessionInformation::expireNow);
    }
}
```

---

# 第五部分：OAuth2 与 OpenID Connect

## 5.1 OAuth2 基础概念

### 5.1.1 什么是 OAuth2？

OAuth2（Open Authorization 2.0）是一个开放标准的授权协议，允许用户授权第三方应用访问其在某一服务提供商上存储的私密资源（如照片、视频、联系人列表等），而无需将用户名和密码提供给第三方应用。

**通俗理解**：想象你住在一个高档小区，有一天你网购了一个大件商品，快递员需要进入小区送货。传统方式是你把小区门禁卡给快递员（相当于给出密码），但这样很不安全。OAuth2 就像是物业给快递员发放一张临时通行证，这张通行证：
- 只能在特定时间段内使用（有效期）
- 只能进入特定区域（权限范围）
- 随时可以被撤销（令牌撤销）
- 不会暴露你的门禁卡信息（不暴露密码）

### 5.1.2 OAuth2 的四种授权模式

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        OAuth2 四种授权模式对比                                │
├─────────────────┬───────────────────┬───────────────────┬───────────────────┤
│     模式        │     适用场景       │      安全性       │      复杂度       │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ 授权码模式      │ 有后端的Web应用    │       最高        │        高         │
│ (Authorization  │ 第三方登录         │                   │                   │
│  Code)          │                   │                   │                   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ 简化模式        │ 纯前端应用(SPA)    │       较低        │        低         │
│ (Implicit)      │ 移动端应用         │   (已不推荐)      │                   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ 密码模式        │ 高度信任的应用     │       中等        │        低         │
│ (Password)      │ 自家应用           │   (已不推荐)      │                   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ 客户端凭证模式  │ 服务间通信         │       高          │       最低        │
│ (Client         │ 无用户参与的场景   │                   │                   │
│  Credentials)   │                   │                   │                   │
└─────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

### 5.1.3 OAuth2 核心角色

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OAuth2 核心角色                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                          ┌─────────────────┐          │
│  │  Resource Owner │                          │ Authorization   │          │
│  │    (资源所有者)  │                          │    Server       │          │
│  │                 │                          │  (授权服务器)    │          │
│  │  就是用户本人    │                          │                 │          │
│  │  拥有受保护资源  │                          │ 负责认证用户身份 │          │
│  └────────┬────────┘                          │ 颁发访问令牌     │          │
│           │                                   └────────┬────────┘          │
│           │ 授权                                       │                   │
│           ▼                                           │ 颁发令牌          │
│  ┌─────────────────┐                                  │                   │
│  │     Client      │◄─────────────────────────────────┘                   │
│  │    (客户端)     │                                                       │
│  │                 │                                                       │
│  │ 第三方应用程序   │                                                       │
│  │ 想要访问用户资源 │                                                       │
│  └────────┬────────┘                                                       │
│           │                                                                │
│           │ 携带令牌请求                                                    │
│           ▼                                                                │
│  ┌─────────────────┐                                                       │
│  │ Resource Server │                                                       │
│  │   (资源服务器)   │                                                       │
│  │                 │                                                       │
│  │ 存储受保护资源   │                                                       │
│  │ 验证令牌有效性   │                                                       │
│  └─────────────────┘                                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**生活化例子**：
- **Resource Owner（资源所有者）**：你本人，微信账号的主人
- **Client（客户端）**：某个想用微信登录的第三方App
- **Authorization Server（授权服务器）**：微信的登录授权页面
- **Resource Server（资源服务器）**：存储你微信头像、昵称的微信服务器

### 5.1.4 授权码模式详解（最重要）

授权码模式是最安全、最常用的OAuth2授权方式，适用于有后端服务器的Web应用。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        授权码模式完整流程                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│     用户                客户端               授权服务器           资源服务器  │
│      │                   │                     │                    │       │
│      │  1.点击登录        │                     │                    │       │
│      │──────────────────>│                     │                    │       │
│      │                   │                     │                    │       │
│      │  2.重定向到授权页面 │                     │                    │       │
│      │<──────────────────│                     │                    │       │
│      │                   │                     │                    │       │
│      │  3.用户登录并授权  │                     │                    │       │
│      │─────────────────────────────────────────>│                    │       │
│      │                   │                     │                    │       │
│      │  4.返回授权码(code)│                     │                    │       │
│      │<─────────────────────────────────────────│                    │       │
│      │                   │                     │                    │       │
│      │  5.携带code重定向  │                     │                    │       │
│      │──────────────────>│                     │                    │       │
│      │                   │                     │                    │       │
│      │                   │  6.用code换token     │                    │       │
│      │                   │────────────────────>│                    │       │
│      │                   │                     │                    │       │
│      │                   │  7.返回access_token  │                    │       │
│      │                   │<────────────────────│                    │       │
│      │                   │                     │                    │       │
│      │                   │  8.携带token请求资源 │                    │       │
│      │                   │─────────────────────────────────────────>│       │
│      │                   │                     │                    │       │
│      │                   │  9.返回受保护资源    │                    │       │
│      │                   │<─────────────────────────────────────────│       │
│      │                   │                     │                    │       │
│      │  10.展示数据       │                     │                    │       │
│      │<──────────────────│                     │                    │       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**为什么需要授权码这个中间步骤？**

这是一个很好的问题！为什么不直接返回 access_token，而要先返回一个 code？

1. **安全性**：code 通过浏览器重定向传递（前端），可能被截获；但 code 换 token 是服务器间通信（后端），更安全
2. **code 是一次性的**：使用后立即失效，即使被截获也无法重复使用
3. **code 有效期很短**：通常只有几分钟
4. **换取 token 需要 client_secret**：这个密钥只有后端知道，前端无法获取

## 5.2 Spring Security OAuth2 客户端配置

### 5.2.1 添加依赖

```xml
<!-- pom.xml -->
<dependencies>
    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- OAuth2 客户端 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
    </dependency>
    
    <!-- Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Thymeleaf（可选，用于页面展示） -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <dependency>
        <groupId>org.thymeleaf.extras</groupId>
        <artifactId>thymeleaf-extras-springsecurity5</artifactId>
    </dependency>
</dependencies>
```

### 5.2.2 配置第三方登录（以 GitHub 为例）

**第一步：在 GitHub 注册 OAuth 应用**

1. 登录 GitHub → Settings → Developer settings → OAuth Apps → New OAuth App
2. 填写信息：
   - Application name: 你的应用名称
   - Homepage URL: http://localhost:8080
   - Authorization callback URL: http://localhost:8080/login/oauth2/code/github

**第二步：配置 application.yml**

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          # github 是注册ID，可以自定义，但要与后面的provider对应
          github:
            client-id: 你的GitHub-Client-ID
            client-secret: 你的GitHub-Client-Secret
            # 授权范围：读取用户信息
            scope:
              - user:email
              - read:user
            # 重定向URI，Spring Security 会自动处理
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            # 客户端认证方式
            client-authentication-method: client_secret_basic
            # 授权模式
            authorization-grant-type: authorization_code
        provider:
          github:
            # GitHub 的授权端点
            authorization-uri: https://github.com/login/oauth/authorize
            # GitHub 的令牌端点
            token-uri: https://github.com/login/oauth/access_token
            # GitHub 的用户信息端点
            user-info-uri: https://api.github.com/user
            # 用户名属性
            user-name-attribute: login
```

**第三步：Security 配置类**

```java
package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * OAuth2 登录安全配置
 * 
 * 这个配置类启用了 OAuth2 登录功能，用户可以通过 GitHub 账号登录系统
 */
@Configuration
@EnableWebSecurity
public class OAuth2LoginSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 授权配置
            .authorizeHttpRequests(authorize -> authorize
                // 首页和静态资源允许匿名访问
                .antMatchers("/", "/index", "/css/**", "/js/**", "/images/**").permitAll()
                // 登录相关页面允许匿名访问
                .antMatchers("/login/**", "/oauth2/**").permitAll()
                // 其他所有请求需要认证
                .anyRequest().authenticated()
            )
            // 启用 OAuth2 登录
            .oauth2Login(oauth2 -> oauth2
                // 自定义登录页面（可选）
                .loginPage("/login")
                // 登录成功后的默认跳转页面
                .defaultSuccessUrl("/home", true)
                // 登录失败后的跳转页面
                .failureUrl("/login?error=true")
                // 用户信息端点配置
                .userInfoEndpoint(userInfo -> userInfo
                    // 自定义用户服务（后面会详细讲）
                    .userService(customOAuth2UserService())
                )
            )
            // 登出配置
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
            );
        
        return http.build();
    }
    
    @Bean
    public CustomOAuth2UserService customOAuth2UserService() {
        return new CustomOAuth2UserService();
    }
}
```

### 5.2.3 自定义 OAuth2 用户服务

当用户通过第三方登录后，我们通常需要：
1. 获取第三方返回的用户信息
2. 检查本地数据库是否已有该用户
3. 如果没有，创建新用户；如果有，更新用户信息
4. 返回本地用户对象

```java
package com.example.security.service;

import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * 自定义 OAuth2 用户服务
 * 
 * 这个服务在用户通过 OAuth2 登录成功后被调用，
 * 负责处理从第三方获取的用户信息，并与本地用户系统对接
 */
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. 调用父类方法，从第三方获取用户信息
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        // 2. 获取第三方平台标识（如 github、google 等）
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        
        // 3. 获取用户属性
        Map<String, Object> attributes = oauth2User.getAttributes();
        
        // 4. 根据不同平台处理用户信息
        User user = processOAuth2User(registrationId, attributes);
        
        // 5. 返回包装后的 OAuth2User
        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority("ROLE_" + user.getRole())),
            attributes,
            // 指定哪个属性作为用户名
            userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName()
        );
    }
    
    /**
     * 处理 OAuth2 用户信息
     * 根据不同的第三方平台，提取用户信息并保存到本地数据库
     */
    private User processOAuth2User(String registrationId, Map<String, Object> attributes) {
        String email;
        String name;
        String avatarUrl;
        String providerId;
        
        // 根据不同平台提取用户信息
        switch (registrationId.toLowerCase()) {
            case "github":
                providerId = String.valueOf(attributes.get("id"));
                email = (String) attributes.get("email");
                name = (String) attributes.get("login");
                avatarUrl = (String) attributes.get("avatar_url");
                break;
            case "google":
                providerId = (String) attributes.get("sub");
                email = (String) attributes.get("email");
                name = (String) attributes.get("name");
                avatarUrl = (String) attributes.get("picture");
                break;
            default:
                throw new OAuth2AuthenticationException("不支持的登录方式: " + registrationId);
        }
        
        // 查找或创建用户
        return findOrCreateUser(registrationId, providerId, email, name, avatarUrl);
    }

    /**
     * 查找或创建用户
     * 
     * 业务逻辑：
     * 1. 首先通过第三方平台ID查找用户
     * 2. 如果找到，更新用户信息
     * 3. 如果没找到，创建新用户
     */
    private User findOrCreateUser(String provider, String providerId, 
                                   String email, String name, String avatarUrl) {
        // 尝试通过第三方ID查找用户
        Optional<User> existingUser = userRepository
            .findByProviderAndProviderId(provider, providerId);
        
        if (existingUser.isPresent()) {
            // 用户已存在，更新信息
            User user = existingUser.get();
            user.setName(name);
            user.setAvatarUrl(avatarUrl);
            user.setLastLoginTime(LocalDateTime.now());
            return userRepository.save(user);
        } else {
            // 用户不存在，创建新用户
            User newUser = new User();
            newUser.setProvider(provider);
            newUser.setProviderId(providerId);
            newUser.setEmail(email);
            newUser.setName(name);
            newUser.setAvatarUrl(avatarUrl);
            newUser.setRole("USER");  // 默认角色
            newUser.setEnabled(true);
            newUser.setCreateTime(LocalDateTime.now());
            newUser.setLastLoginTime(LocalDateTime.now());
            return userRepository.save(newUser);
        }
    }
}
```

### 5.2.4 用户实体类

```java
package com.example.security.entity;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * 用户实体类
 * 支持本地注册和第三方登录两种方式
 */
@Entity
@Table(name = "sys_user", 
       uniqueConstraints = {
           @UniqueConstraint(columnNames = {"provider", "provider_id"})
       })
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    /**
     * 用户名（本地注册用户使用）
     */
    @Column(length = 50)
    private String username;
    
    /**
     * 密码（本地注册用户使用，第三方登录用户为空）
     */
    @Column(length = 100)
    private String password;
    
    /**
     * 邮箱
     */
    @Column(length = 100)
    private String email;
    
    /**
     * 显示名称
     */
    @Column(length = 50)
    private String name;
    
    /**
     * 头像URL
     */
    @Column(length = 500)
    private String avatarUrl;
    
    /**
     * 第三方登录提供商（github、google、wechat等）
     */
    @Column(length = 20)
    private String provider;
    
    /**
     * 第三方平台的用户ID
     */
    @Column(name = "provider_id", length = 100)
    private String providerId;
    
    /**
     * 用户角色
     */
    @Column(length = 20)
    private String role;
    
    /**
     * 是否启用
     */
    private Boolean enabled = true;
    
    /**
     * 创建时间
     */
    @Column(name = "create_time")
    private LocalDateTime createTime;
    
    /**
     * 最后登录时间
     */
    @Column(name = "last_login_time")
    private LocalDateTime lastLoginTime;
    
    // Getters and Setters 省略...
}
```

### 5.2.5 配置多个第三方登录

实际项目中，我们通常需要支持多个第三方登录（GitHub、Google、微信等）。

```yaml
# application.yml - 多平台 OAuth2 配置
spring:
  security:
    oauth2:
      client:
        registration:
          # GitHub 登录
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: user:email,read:user
            
          # Google 登录
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid,profile,email
            
          # 微信登录（需要自定义配置）
          wechat:
            client-id: ${WECHAT_APP_ID}
            client-secret: ${WECHAT_APP_SECRET}
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: snsapi_login
            client-name: 微信
            
        provider:
          # 微信需要自定义 provider（因为不是标准 OAuth2）
          wechat:
            authorization-uri: https://open.weixin.qq.com/connect/qrconnect
            token-uri: https://api.weixin.qq.com/sns/oauth2/access_token
            user-info-uri: https://api.weixin.qq.com/sns/userinfo
            user-name-attribute: openid
```

### 5.2.6 自定义登录页面

```java
package com.example.security.controller;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;

/**
 * 登录控制器
 */
@Controller
public class LoginController {

    private final ClientRegistrationRepository clientRegistrationRepository;
    
    // OAuth2 登录链接的固定前缀
    private static final String OAUTH2_AUTHORIZATION_BASE_URI = "/oauth2/authorization";

    public LoginController(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    /**
     * 自定义登录页面
     * 展示所有可用的 OAuth2 登录选项
     */
    @GetMapping("/login")
    public String login(Model model) {
        // 获取所有已配置的 OAuth2 客户端
        Map<String, String> oauth2LoginUrls = new HashMap<>();
        
        // 遍历所有注册的客户端
        Iterable<ClientRegistration> registrations = 
            (Iterable<ClientRegistration>) clientRegistrationRepository;
            
        registrations.forEach(registration -> {
            // 构建登录URL：/oauth2/authorization/{registrationId}
            String loginUrl = OAUTH2_AUTHORIZATION_BASE_URI + "/" + registration.getRegistrationId();
            // 获取客户端名称（如 GitHub、Google）
            String clientName = registration.getClientName();
            oauth2LoginUrls.put(clientName, loginUrl);
        });
        
        model.addAttribute("oauth2LoginUrls", oauth2LoginUrls);
        return "login";
    }
}
```

**登录页面模板（Thymeleaf）**

```html
<!-- templates/login.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
    <style>
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            padding: 30px;
            border: 1px solid #ddd;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .login-title {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
        }
        .oauth2-btn {
            display: block;
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            text-decoration: none;
            text-align: center;
            color: white;
        }
        .github-btn { background-color: #333; }
        .google-btn { background-color: #4285f4; }
        .wechat-btn { background-color: #07c160; }
        .divider {
            text-align: center;
            margin: 20px 0;
            color: #999;
        }
        .error-msg {
            color: #dc3545;
            text-align: center;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 class="login-title">欢迎登录</h2>
        
        <!-- 错误提示 -->
        <div th:if="${param.error}" class="error-msg">
            登录失败，请重试
        </div>
        
        <!-- 本地登录表单 -->
        <form th:action="@{/login}" method="post">
            <input type="text" name="username" placeholder="用户名" 
                   style="width:100%;padding:10px;margin:5px 0;box-sizing:border-box;">
            <input type="password" name="password" placeholder="密码" 
                   style="width:100%;padding:10px;margin:5px 0;box-sizing:border-box;">
            <button type="submit" 
                    style="width:100%;padding:12px;background:#007bff;color:white;border:none;cursor:pointer;">
                登录
            </button>
        </form>
        
        <div class="divider">—— 或使用第三方账号登录 ——</div>
        
        <!-- OAuth2 登录按钮 -->
        <th:block th:each="entry : ${oauth2LoginUrls}">
            <a th:href="${entry.value}" 
               th:class="'oauth2-btn ' + ${entry.key.toLowerCase()} + '-btn'"
               th:text="'使用 ' + ${entry.key} + ' 登录'">
            </a>
        </th:block>
    </div>
</body>
</html>
```

## 5.3 OAuth2 资源服务器配置

资源服务器是存储受保护资源的服务器，它需要验证访问令牌的有效性。

### 5.3.1 添加依赖

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

### 5.3.2 JWT 令牌验证配置

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # 方式1：指定 JWK Set URI（推荐）
          # 资源服务器会从这个地址获取公钥来验证 JWT
          jwk-set-uri: http://auth-server:8080/.well-known/jwks.json
          
          # 方式2：指定 issuer URI
          # Spring Security 会自动发现 JWK Set URI
          # issuer-uri: http://auth-server:8080
          
          # 方式3：直接指定公钥（不推荐，密钥轮换困难）
          # public-key-location: classpath:public.pem
```

### 5.3.3 资源服务器安全配置

```java
package com.example.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 资源服务器安全配置
 * 
 * 资源服务器的职责：
 * 1. 验证请求中携带的访问令牌
 * 2. 根据令牌中的权限信息进行访问控制
 * 3. 不负责用户认证（认证由授权服务器完成）
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)  // 启用方法级安全
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 禁用 CSRF（因为使用 JWT，不需要 CSRF 保护）
            .csrf().disable()
            
            // 禁用 Session（JWT 是无状态的）
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            
            // 授权配置
            .authorizeHttpRequests(authorize -> authorize
                // 公开接口
                .antMatchers("/api/public/**").permitAll()
                // 健康检查
                .antMatchers("/actuator/health").permitAll()
                // 需要特定权限的接口
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .antMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                // 其他接口需要认证
                .anyRequest().authenticated()
            )
            
            // 配置为 OAuth2 资源服务器，使用 JWT 验证
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    // 自定义 JWT 转换器（将 JWT 中的信息转换为 Spring Security 的权限）
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
                // 自定义认证失败处理
                .authenticationEntryPoint(customAuthenticationEntryPoint())
                // 自定义访问拒绝处理
                .accessDeniedHandler(customAccessDeniedHandler())
            );
        
        return http.build();
    }

    /**
     * JWT 认证转换器
     * 
     * 作用：将 JWT 中的 claims 转换为 Spring Security 的 GrantedAuthority
     * 
     * 为什么需要这个？
     * 不同的授权服务器可能使用不同的 claim 名称来存储权限信息，
     * 比如有的用 "scope"，有的用 "authorities"，有的用 "roles"。
     * 这个转换器让我们可以自定义如何提取权限信息。
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = 
            new JwtGrantedAuthoritiesConverter();
        
        // 设置权限信息在 JWT 中的 claim 名称
        // 默认是 "scope" 或 "scp"
        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
        
        // 设置权限前缀
        // 默认是 "SCOPE_"，这里改为 "ROLE_" 以匹配 hasRole() 的检查
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        
        JwtAuthenticationConverter jwtAuthenticationConverter = 
            new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
            grantedAuthoritiesConverter
        );
        
        return jwtAuthenticationConverter;
    }
    
    /**
     * 自定义认证失败处理器
     * 当 JWT 无效或过期时返回友好的错误信息
     */
    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            
            Map<String, Object> body = new HashMap<>();
            body.put("code", 401);
            body.put("message", "访问令牌无效或已过期");
            body.put("timestamp", LocalDateTime.now().toString());
            body.put("path", request.getRequestURI());
            
            response.getWriter().write(
                new ObjectMapper().writeValueAsString(body)
            );
        };
    }
    
    /**
     * 自定义访问拒绝处理器
     * 当用户权限不足时返回友好的错误信息
     */
    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            
            Map<String, Object> body = new HashMap<>();
            body.put("code", 403);
            body.put("message", "权限不足，无法访问该资源");
            body.put("timestamp", LocalDateTime.now().toString());
            body.put("path", request.getRequestURI());
            
            response.getWriter().write(
                new ObjectMapper().writeValueAsString(body)
            );
        };
    }
}
```

### 5.3.4 在控制器中使用 JWT 信息

```java
package com.example.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/**
 * 资源控制器示例
 * 展示如何在资源服务器中获取和使用 JWT 中的信息
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    /**
     * 公开接口，无需认证
     */
    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello, this is a public endpoint!";
    }
    
    /**
     * 需要认证的接口
     * 使用 @AuthenticationPrincipal 注解获取 JWT 对象
     */
    @GetMapping("/user/profile")
    public Map<String, Object> getUserProfile(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> profile = new HashMap<>();
        
        // 从 JWT 中获取用户信息
        profile.put("userId", jwt.getSubject());  // sub claim
        profile.put("username", jwt.getClaimAsString("preferred_username"));
        profile.put("email", jwt.getClaimAsString("email"));
        profile.put("roles", jwt.getClaimAsStringList("authorities"));
        
        // JWT 的签发时间和过期时间
        profile.put("issuedAt", jwt.getIssuedAt());
        profile.put("expiresAt", jwt.getExpiresAt());
        
        return profile;
    }
    
    /**
     * 需要 ADMIN 角色的接口
     * 使用 @PreAuthorize 进行方法级权限控制
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public List<String> getAllUsers() {
        // 只有管理员才能访问
        return Arrays.asList("user1", "user2", "user3");
    }
    
    /**
     * 使用 SpEL 表达式进行复杂权限判断
     * 只有用户本人或管理员才能访问
     */
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.subject")
    @GetMapping("/user/{userId}/details")
    public Map<String, Object> getUserDetails(@PathVariable String userId) {
        Map<String, Object> details = new HashMap<>();
        details.put("userId", userId);
        details.put("message", "User details retrieved successfully");
        return details;
    }
    
    /**
     * 检查特定权限（scope）
     */
    @PreAuthorize("hasAuthority('SCOPE_read:users')")
    @GetMapping("/users")
    public List<String> listUsers() {
        return Arrays.asList("user1", "user2");
    }
}
```

## 5.4 OAuth2 授权服务器配置

授权服务器是 OAuth2 架构中最核心的组件，负责：
1. 认证用户身份
2. 管理客户端注册
3. 颁发访问令牌
4. 管理令牌生命周期

> **注意**：Spring Security OAuth2 Authorization Server 是一个独立项目，
> 在 Spring Boot 2.7.x 中需要单独引入依赖。

### 5.4.1 添加依赖

```xml
<!-- pom.xml -->
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <!-- Spring Authorization Server -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-authorization-server</artifactId>
        <version>0.4.5</version>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- 数据库支持（用于持久化客户端和令牌） -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

### 5.4.2 授权服务器核心配置

```java
package com.example.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

/**
 * OAuth2 授权服务器配置
 * 
 * 这是整个 OAuth2 系统的核心，负责：
 * 1. 用户认证
 * 2. 客户端管理
 * 3. 令牌颁发
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    /**
     * 授权服务器安全过滤器链
     * 处理 OAuth2 相关的端点请求
     */
    @Bean
    @Order(1)  // 优先级最高
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) 
            throws Exception {
        // 应用默认的授权服务器安全配置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        // 启用 OpenID Connect 1.0
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());
        
        // 未认证时重定向到登录页面
        http.exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")
            )
        );
        
        // 接受访问令牌用于用户信息端点
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        
        return http.build();
    }
    
    /**
     * 默认安全过滤器链
     * 处理登录等常规请求
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            // 表单登录
            .formLogin(Customizer.withDefaults());
        
        return http.build();
    }
    
    /**
     * 注册客户端仓库
     * 
     * 客户端就是想要访问用户资源的第三方应用
     * 每个客户端都需要在授权服务器注册，获得 client_id 和 client_secret
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // 注册一个客户端（实际项目中应该从数据库读取）
        RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
            // 客户端ID（相当于用户名）
            .clientId("web-client")
            // 客户端密钥（相当于密码），需要加密存储
            .clientSecret("{noop}web-client-secret")  // {noop}表示明文，生产环境要用BCrypt
            // 客户端名称
            .clientName("Web Application")
            // 客户端认证方式
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            // 支持的授权模式
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            // 授权成功后的回调地址
            .redirectUri("http://localhost:8080/login/oauth2/code/web-client")
            .redirectUri("http://localhost:8080/authorized")
            // 授权范围
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("read")
            .scope("write")
            // 客户端设置
            .clientSettings(ClientSettings.builder()
                // 是否需要用户确认授权
                .requireAuthorizationConsent(true)
                .build())
            // 令牌设置
            .tokenSettings(TokenSettings.builder()
                // 访问令牌有效期
                .accessTokenTimeToLive(Duration.ofHours(1))
                // 刷新令牌有效期
                .refreshTokenTimeToLive(Duration.ofDays(7))
                // 是否重用刷新令牌
                .reuseRefreshTokens(false)
                .build())
            .build();

        // 注册一个移动端客户端
        RegisteredClient mobileClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("mobile-client")
            .clientSecret("{noop}mobile-client-secret")
            .clientName("Mobile Application")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("myapp://callback")  // 移动端使用自定义 scheme
            .scope(OidcScopes.OPENID)
            .scope("read")
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)  // 移动端通常不需要确认
                .requireProofKey(true)  // 启用 PKCE（移动端必须）
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .build())
            .build();
        
        // 注册一个服务间通信的客户端
        RegisteredClient serviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("service-client")
            .clientSecret("{noop}service-client-secret")
            .clientName("Backend Service")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            // 只支持客户端凭证模式（无用户参与）
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("internal:read")
            .scope("internal:write")
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(10))
                .build())
            .build();
        
        return new InMemoryRegisteredClientRepository(webClient, mobileClient, serviceClient);
    }
    
    /**
     * JWK 源配置
     * 
     * JWK（JSON Web Key）是用于签名和验证 JWT 的密钥
     * 授权服务器使用私钥签名 JWT，资源服务器使用公钥验证 JWT
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
    
    /**
     * 生成 RSA 密钥对
     * 
     * 注意：生产环境中应该使用固定的密钥对，而不是每次启动都生成新的
     * 否则服务重启后，之前颁发的令牌都会失效
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
    
    /**
     * JWT 解码器
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
    
    /**
     * 授权服务器设置
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            // 授权服务器的 issuer（签发者）
            .issuer("http://localhost:9000")
            // 各端点路径（使用默认值）
            // .authorizationEndpoint("/oauth2/authorize")
            // .tokenEndpoint("/oauth2/token")
            // .jwkSetEndpoint("/oauth2/jwks")
            // .tokenRevocationEndpoint("/oauth2/revoke")
            // .tokenIntrospectionEndpoint("/oauth2/introspect")
            // .oidcUserInfoEndpoint("/userinfo")
            .build();
    }
}
```

### 5.4.3 自定义 JWT 令牌内容

默认的 JWT 只包含基本信息，我们通常需要添加自定义信息（如用户角色、部门等）。

```java
package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.stream.Collectors;

/**
 * JWT 令牌自定义配置
 * 
 * 通过 OAuth2TokenCustomizer 可以在 JWT 中添加自定义的 claims
 */
@Configuration
public class JwtTokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            // 只处理访问令牌
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                
                // 添加用户权限/角色
                context.getClaims().claim("authorities",
                    principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
                );
                
                // 如果是用户认证（不是客户端凭证模式）
                if (principal.getPrincipal() instanceof CustomUserDetails) {
                    CustomUserDetails userDetails = 
                        (CustomUserDetails) principal.getPrincipal();
                    
                    // 添加用户ID
                    context.getClaims().claim("user_id", userDetails.getUserId());
                    // 添加用户名
                    context.getClaims().claim("username", userDetails.getUsername());
                    // 添加邮箱
                    context.getClaims().claim("email", userDetails.getEmail());
                    // 添加部门
                    context.getClaims().claim("department", userDetails.getDepartment());
                }
            }
            
            // 处理 ID Token（OpenID Connect）
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                Authentication principal = context.getPrincipal();
                
                if (principal.getPrincipal() instanceof CustomUserDetails) {
                    CustomUserDetails userDetails = 
                        (CustomUserDetails) principal.getPrincipal();
                    
                    // ID Token 中添加用户信息
                    context.getClaims().claim("name", userDetails.getName());
                    context.getClaims().claim("email", userDetails.getEmail());
                    context.getClaims().claim("picture", userDetails.getAvatarUrl());
                }
            }
        };
    }
}
```


---

## 12. 密码加密

### 12.1 PasswordEncoder 接口

Spring Security 提供了 `PasswordEncoder` 接口用于密码加密和验证。

```java
public interface PasswordEncoder {
    // 加密密码
    String encode(CharSequence rawPassword);
    
    // 验证密码
    boolean matches(CharSequence rawPassword, String encodedPassword);
    
    // 是否需要重新加密（用于升级加密算法）
    default boolean upgradeEncoding(String encodedPassword) {
        return false;
    }
}
```

### 12.2 常用加密器

| 加密器 | 说明 | 推荐度 |
|--------|------|--------|
| BCryptPasswordEncoder | BCrypt 算法，自带盐值 | ⭐⭐⭐⭐⭐ 推荐 |
| Argon2PasswordEncoder | Argon2 算法，更安全但更慢 | ⭐⭐⭐⭐ |
| SCryptPasswordEncoder | SCrypt 算法 | ⭐⭐⭐ |
| Pbkdf2PasswordEncoder | PBKDF2 算法 | ⭐⭐⭐ |
| NoOpPasswordEncoder | 不加密（仅测试用） | ❌ 禁止生产使用 |

### 12.3 BCryptPasswordEncoder 使用

```java
@Configuration
public class SecurityConfig {
    
    /**
     * 配置密码编码器
     * BCrypt 是目前最推荐的密码加密算法
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 默认强度为 10，范围 4-31，数值越大越安全但越慢
        return new BCryptPasswordEncoder();
        
        // 自定义强度
        // return new BCryptPasswordEncoder(12);
    }
}
```

```java
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final PasswordEncoder passwordEncoder;
    private final SysUserMapper userMapper;
    
    /**
     * 用户注册
     */
    public void register(RegisterRequest request) {
        SysUser user = new SysUser();
        user.setUsername(request.getUsername());
        // 加密密码
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setStatus(1);
        userMapper.insert(user);
    }
    
    /**
     * 修改密码
     */
    public void changePassword(Long userId, String oldPassword, String newPassword) {
        SysUser user = userMapper.selectById(userId);
        
        // 验证旧密码
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new RuntimeException("原密码错误");
        }
        
        // 设置新密码
        user.setPassword(passwordEncoder.encode(newPassword));
        userMapper.updateById(user);
    }
}
```

### 12.4 DelegatingPasswordEncoder（多算法支持）

当系统需要升级加密算法时，可以使用 `DelegatingPasswordEncoder` 支持多种算法。

```java
@Bean
public PasswordEncoder passwordEncoder() {
    // 默认使用 BCrypt
    String defaultEncoder = "bcrypt";
    
    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put("bcrypt", new BCryptPasswordEncoder());
    encoders.put("noop", NoOpPasswordEncoder.getInstance());
    encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
    encoders.put("scrypt", new SCryptPasswordEncoder());
    encoders.put("sha256", new StandardPasswordEncoder());
    
    DelegatingPasswordEncoder delegating = 
        new DelegatingPasswordEncoder(defaultEncoder, encoders);
    
    // 设置默认匹配器（用于没有前缀的旧密码）
    delegating.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
    
    return delegating;
}
```

密码存储格式：`{算法标识}加密后的密码`

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
{noop}password
{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc
```

### 12.5 密码强度验证

```java
@Component
public class PasswordValidator {
    
    /**
     * 验证密码强度
     * 要求：8-20位，包含大小写字母、数字、特殊字符
     */
    public void validate(String password) {
        if (password == null || password.length() < 8 || password.length() > 20) {
            throw new IllegalArgumentException("密码长度必须在8-20位之间");
        }
        
        if (!password.matches(".*[A-Z].*")) {
            throw new IllegalArgumentException("密码必须包含大写字母");
        }
        
        if (!password.matches(".*[a-z].*")) {
            throw new IllegalArgumentException("密码必须包含小写字母");
        }
        
        if (!password.matches(".*\\d.*")) {
            throw new IllegalArgumentException("密码必须包含数字");
        }
        
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            throw new IllegalArgumentException("密码必须包含特殊字符");
        }
    }
}
```

---

## 13. 常见错误与解决方案

### 13.1 认证相关错误

#### 错误1：There is no PasswordEncoder mapped for the id "null"

**原因**：密码没有加密前缀，且没有配置 PasswordEncoder

**解决方案**：
```java
// 方案1：配置 PasswordEncoder Bean
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

// 方案2：使用 DelegatingPasswordEncoder
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}

// 方案3：密码加上前缀（不推荐）
// 数据库中存储：{noop}123456 或 {bcrypt}$2a$10$...
```

#### 错误2：Bad credentials

**原因**：用户名或密码错误

**排查步骤**：
```java
// 1. 检查用户是否存在
@Override
public UserDetails loadUserByUsername(String username) {
    SysUser user = userMapper.selectByUsername(username);
    if (user == null) {
        log.error("用户不存在: {}", username);  // 添加日志
        throw new UsernameNotFoundException("用户不存在");
    }
    // ...
}

// 2. 检查密码是否正确加密
log.info("数据库密码: {}", user.getPassword());
log.info("输入密码加密后: {}", passwordEncoder.encode(inputPassword));
log.info("密码匹配结果: {}", passwordEncoder.matches(inputPassword, user.getPassword()));
```

#### 错误3：Access is denied

**原因**：用户没有访问权限

**解决方案**：
```java
// 1. 检查用户角色/权限
LoginUser loginUser = SecurityUtils.getLoginUser();
log.info("用户角色: {}", loginUser.getRoles());
log.info("用户权限: {}", loginUser.getPermissions());

// 2. 检查权限配置
// 注意：hasRole("ADMIN") 会自动添加 ROLE_ 前缀
// 所以数据库中应该存储 ADMIN，而不是 ROLE_ADMIN
.antMatchers("/admin/**").hasRole("ADMIN")  // 检查 ROLE_ADMIN
.antMatchers("/admin/**").hasAuthority("ROLE_ADMIN")  // 等价写法
```

### 13.2 CORS 相关错误

#### 错误：CORS policy: No 'Access-Control-Allow-Origin' header

**解决方案**：
```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}

// Security 配置中启用
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .cors().configurationSource(corsConfigurationSource())
        // ...
}
```

### 13.3 JWT 相关错误

#### 错误1：JWT signature does not match

**原因**：JWT 签名验证失败，密钥不匹配

**解决方案**：
```java
// 确保生成和验证使用相同的密钥
@Value("${jwt.secret}")
private String secret;

// 密钥长度至少 256 位（32 字符）
// application.yml
jwt:
  secret: your-256-bit-secret-key-here-must-be-at-least-32-characters
```

#### 错误2：JWT expired

**原因**：Token 已过期

**解决方案**：
```java
// 1. 前端拦截 401 错误，自动刷新 Token
// 2. 后端提供刷新 Token 接口
@PostMapping("/refresh")
public Result<String> refreshToken(@RequestHeader("Refresh-Token") String refreshToken) {
    // 验证 refreshToken 并生成新的 accessToken
}

// 3. 适当延长 Token 有效期
jwt:
  expiration: 86400000  # 24小时
```

### 13.4 Session 相关错误

#### 错误：Maximum sessions exceeded

**原因**：超过最大会话数限制

**解决方案**：
```java
http
    .sessionManagement()
        .maximumSessions(1)
        // false: 踢掉旧会话（默认）
        // true: 阻止新登录
        .maxSessionsPreventsLogin(false)
        .expiredUrl("/login?expired");
```

### 13.5 循环依赖错误

#### 错误：The dependencies of some of the beans in the application context form a cycle

**原因**：SecurityConfig 和 UserDetailsService 循环依赖

**解决方案**：
```java
// 方案1：使用 @Lazy 注解
@Configuration
public class SecurityConfig {
    
    @Autowired
    @Lazy
    private UserDetailsService userDetailsService;
}

// 方案2：使用 setter 注入
@Configuration
public class SecurityConfig {
    
    private UserDetailsService userDetailsService;
    
    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}

// 方案3：通过 AuthenticationConfiguration 获取
@Bean
public AuthenticationManager authenticationManager(
        AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
}
```

---

## 14. 最佳实践

### 14.1 安全配置最佳实践

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 1. CSRF 配置
            // 前后端分离项目禁用，传统项目启用
            .csrf().disable()
            
            // 2. Session 配置
            // JWT 项目使用 STATELESS
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            
            // 3. 授权配置
            .authorizeRequests()
                // 白名单
                .antMatchers(
                    "/login", "/register", "/captcha",
                    "/swagger-ui/**", "/v3/api-docs/**",
                    "/actuator/health"
                ).permitAll()
                // 其他需要认证
                .anyRequest().authenticated()
            .and()
            
            // 4. 异常处理
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            .and()
            
            // 5. 跨域配置
            .cors().configurationSource(corsConfigurationSource())
            .and()
            
            // 6. 添加自定义过滤器
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            
            // 7. 禁用默认登录页
            .formLogin().disable()
            .httpBasic().disable();
        
        return http.build();
    }
}
```

### 14.2 密码安全最佳实践

```java
/**
 * 密码安全规范
 */
public class PasswordSecurityBestPractices {
    
    // 1. 使用 BCrypt 加密，强度至少 10
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
    
    // 2. 密码强度要求
    public void validatePassword(String password) {
        // 长度 8-20
        // 包含大小写字母、数字、特殊字符
        // 不能包含用户名
        // 不能是常见弱密码
    }
    
    // 3. 密码传输加密
    // 使用 HTTPS
    // 前端可以先做一次哈希（可选）
    
    // 4. 登录失败限制
    // 连续失败 5 次锁定账号 30 分钟
    
    // 5. 密码定期更换
    // 90 天强制更换
    // 不能使用最近 5 次的密码
}
```

### 14.3 JWT 最佳实践

```java
/**
 * JWT 安全规范
 */
public class JwtSecurityBestPractices {
    
    // 1. 密钥管理
    // - 使用足够长的密钥（至少 256 位）
    // - 密钥存储在配置中心或环境变量
    // - 定期轮换密钥
    
    // 2. Token 有效期
    // - Access Token: 15分钟 - 2小时
    // - Refresh Token: 7天 - 30天
    
    // 3. Token 存储
    // - 前端：httpOnly Cookie 或 内存
    // - 避免存储在 localStorage（XSS 风险）
    
    // 4. Token 刷新机制
    public String refreshToken(String refreshToken) {
        // 验证 refreshToken
        // 检查是否在黑名单
        // 生成新的 accessToken
        // 可选：生成新的 refreshToken（滑动过期）
        return newAccessToken;
    }
    
    // 5. Token 撤销
    // - 使用 Redis 黑名单
    // - 或使用短有效期 + 刷新机制
    
    // 6. 敏感操作二次验证
    // - 修改密码、绑定手机等操作需要重新输入密码
}
```

### 14.4 接口安全最佳实践

```java
/**
 * 接口安全规范
 */
@RestController
@RequestMapping("/api")
public class SecureApiController {
    
    // 1. 使用方法级权限控制
    @PreAuthorize("hasAuthority('user:delete')")
    @DeleteMapping("/users/{id}")
    public Result<Void> deleteUser(@PathVariable Long id) {
        // ...
    }
    
    // 2. 数据权限控制（只能操作自己的数据）
    @PreAuthorize("#userId == authentication.principal.user.id or hasRole('ADMIN')")
    @GetMapping("/users/{userId}/orders")
    public Result<List<Order>> getUserOrders(@PathVariable Long userId) {
        // ...
    }
    
    // 3. 参数校验
    @PostMapping("/users")
    public Result<Void> createUser(@RequestBody @Valid UserDTO user) {
        // @Valid 触发参数校验
    }
    
    // 4. 敏感数据脱敏
    @GetMapping("/users/{id}")
    public Result<UserVO> getUser(@PathVariable Long id) {
        User user = userService.getById(id);
        UserVO vo = new UserVO();
        vo.setPhone(desensitize(user.getPhone()));  // 手机号脱敏
        vo.setIdCard(desensitize(user.getIdCard())); // 身份证脱敏
        return Result.success(vo);
    }
    
    // 5. 日志记录
    @PostMapping("/login")
    public Result<LoginResponse> login(@RequestBody LoginRequest request) {
        // 记录登录日志：IP、时间、结果
        log.info("用户登录: username={}, ip={}", request.getUsername(), getClientIp());
        // ...
    }
}
```

### 14.5 防护攻击最佳实践

```java
/**
 * 安全防护配置
 */
@Configuration
public class SecurityProtectionConfig {
    
    /**
     * 1. 防止暴力破解
     */
    @Bean
    public LoginAttemptService loginAttemptService() {
        return new LoginAttemptService();
    }
    
    /**
     * 2. 防止 XSS 攻击
     */
    @Bean
    public FilterRegistrationBean<XssFilter> xssFilter() {
        FilterRegistrationBean<XssFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new XssFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }
    
    /**
     * 3. 防止 SQL 注入
     * - 使用参数化查询（MyBatis 的 #{} 而不是 ${}）
     * - 使用 ORM 框架
     */
    
    /**
     * 4. 安全响应头
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .headers()
                // 防止点击劫持
                .frameOptions().deny()
                // 启用 XSS 过滤
                .xssProtection().block(true)
                // 禁止内容类型嗅探
                .contentTypeOptions()
                // HSTS（强制 HTTPS）
                .httpStrictTransportSecurity()
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000);
        
        return http.build();
    }
    
    /**
     * 5. 接口限流
     */
    @Bean
    public RateLimiter rateLimiter() {
        // 使用 Guava RateLimiter 或 Redis 实现
        return RateLimiter.create(100);  // 每秒 100 个请求
    }
}
```

### 14.6 审计日志最佳实践

```java
/**
 * 安全审计日志
 */
@Aspect
@Component
@Slf4j
public class SecurityAuditAspect {
    
    @Autowired
    private AuditLogService auditLogService;
    
    /**
     * 记录敏感操作
     */
    @Around("@annotation(auditLog)")
    public Object audit(ProceedingJoinPoint joinPoint, AuditLog auditLog) throws Throwable {
        // 获取当前用户
        String username = SecurityUtils.getUsername();
        String ip = getClientIp();
        String operation = auditLog.value();
        String method = joinPoint.getSignature().getName();
        String params = Arrays.toString(joinPoint.getArgs());
        
        long startTime = System.currentTimeMillis();
        Object result = null;
        String status = "SUCCESS";
        String errorMsg = null;
        
        try {
            result = joinPoint.proceed();
            return result;
        } catch (Exception e) {
            status = "FAILED";
            errorMsg = e.getMessage();
            throw e;
        } finally {
            long costTime = System.currentTimeMillis() - startTime;
            
            // 保存审计日志
            AuditLogEntity logEntity = new AuditLogEntity();
            logEntity.setUsername(username);
            logEntity.setIp(ip);
            logEntity.setOperation(operation);
            logEntity.setMethod(method);
            logEntity.setParams(params);
            logEntity.setStatus(status);
            logEntity.setErrorMsg(errorMsg);
            logEntity.setCostTime(costTime);
            logEntity.setCreateTime(LocalDateTime.now());
            
            auditLogService.save(logEntity);
            
            log.info("审计日志: user={}, operation={}, status={}, cost={}ms",
                username, operation, status, costTime);
        }
    }
}

/**
 * 审计日志注解
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AuditLog {
    String value() default "";
}

/**
 * 使用示例
 */
@RestController
public class UserController {
    
    @AuditLog("删除用户")
    @DeleteMapping("/users/{id}")
    public Result<Void> deleteUser(@PathVariable Long id) {
        // ...
    }
    
    @AuditLog("修改用户密码")
    @PutMapping("/users/{id}/password")
    public Result<Void> changePassword(@PathVariable Long id) {
        // ...
    }
}
```

---

## 附录：常用配置模板

### A. 前后端分离项目配置模板

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtFilter;
    private final CustomAuthenticationEntryPoint authEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
                .antMatchers("/auth/**", "/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .exceptionHandling()
                .authenticationEntryPoint(authEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            .and()
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
            .cors();
        
        return http.build();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### B. application.yml 安全配置模板

```yaml
# JWT 配置
jwt:
  secret: your-256-bit-secret-key-here-must-be-at-least-32-characters-long
  expiration: 86400000  # 24小时
  refresh-expiration: 604800000  # 7天
  header: Authorization
  prefix: "Bearer "

# Spring Security 配置
spring:
  security:
    # 忽略静态资源
    ignored: /static/**,/favicon.ico

# 日志配置（调试用）
logging:
  level:
    org.springframework.security: DEBUG
```

---


> 
> 本笔记涵盖了 Spring Security 的核心概念和实战应用，包括：
> - 认证与授权机制
> - JWT 无状态认证
> - OAuth2 第三方登录
> - 方法级安全控制
> - 常见问题解决方案
> - 安全最佳实践
> 
> 建议结合实际项目练习，加深理解。
