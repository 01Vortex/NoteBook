

> Spring Security 6 是 Spring 安全框架的重大升级，配合 Spring Boot 3.x 使用
> 本笔记基于 Java 17 + Spring Boot 3.2.12，着重对比 Spring Security 5 的变化

---

## 目录

1. [重大变化概览](#1-重大变化概览)
2. [项目配置](#2-项目配置)
3. [配置方式迁移](#3-配置方式迁移)
4. [认证配置](#4-认证配置)
5. [授权配置](#5-授权配置)
6. [密码编码](#6-密码编码)
7. [CSRF 防护](#7-csrf-防护)
8. [CORS 配置](#8-cors-配置)
9. [Session 管理](#9-session-管理)
10. [Remember-Me](#10-remember-me)
11. [JWT 认证](#11-jwt-认证)
12. [OAuth2 集成](#12-oauth2-集成)
13. [方法级安全](#13-方法级安全)
14. [自定义认证](#14-自定义认证)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 重大变化概览

### 1.1 Spring Security 6 vs 5 核心差异

Spring Security 6 是一次"断代式"升级，很多 API 都发生了变化。如果你熟悉 Spring Security 5，需要重新学习配置方式。

| 特性 | Spring Security 5 | Spring Security 6 |
|------|-------------------|-------------------|
| Java 版本 | Java 8+ | **Java 17+** |
| Servlet API | javax.servlet | **jakarta.servlet** |
| 配置方式 | 继承 WebSecurityConfigurerAdapter | **SecurityFilterChain Bean** |
| 路径匹配 | antMatchers/mvcMatchers | **requestMatchers** |
| 授权 API | authorizeRequests | **authorizeHttpRequests** |
| Lambda DSL | 可选 | **推荐（部分必须）** |
| 默认行为 | 较宽松 | **更严格安全** |

### 1.2 为什么要升级？

**安全性提升：**
- 默认配置更安全
- 修复了多个安全漏洞
- 更好的密码存储策略

**现代化：**
- 拥抱 Jakarta EE 9+
- 更清晰的 API 设计
- 更好的函数式编程支持

**维护性：**
- Spring Security 5.x 将逐步停止维护
- 新功能只在 6.x 中添加

### 1.3 主要 API 变化速查

```java
// ==================== 配置类 ====================
// Security 5: 继承适配器
public class Config extends WebSecurityConfigurerAdapter { }

// Security 6: 使用 Bean
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) { }

// ==================== 路径匹配 ====================
// Security 5
.antMatchers("/api/**")
.mvcMatchers("/users")
.regexMatchers("/admin/.*")

// Security 6
.requestMatchers("/api/**")
.requestMatchers("/users")
.requestMatchers(new RegexRequestMatcher("/admin/.*", null))

// ==================== 授权 ====================
// Security 5
.authorizeRequests()

// Security 6
.authorizeHttpRequests()

// ==================== Lambda DSL ====================
// Security 5: 链式调用
http.csrf().disable().cors().and().authorizeRequests()...

// Security 6: Lambda 风格
http.csrf(csrf -> csrf.disable())
    .cors(cors -> cors.configurationSource(...))
    .authorizeHttpRequests(auth -> auth...)
```

---

## 2. 项目配置

### 2.1 Maven 依赖

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
        <version>3.2.12</version>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>security-demo</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>17</java.version>
    </properties>
    
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
        
        <!-- 数据库（可选） -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        
        <!-- OAuth2 Resource Server（JWT 支持） -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
        </dependency>
        
        <!-- OAuth2 Client（第三方登录） -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-client</artifactId>
        </dependency>
        
        <!-- 测试 -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### 2.2 Gradle 依赖

```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.12'
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    sourceCompatibility = '17'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
    
    testImplementation 'org.springframework.security:spring-security-test'
}
```

### 2.3 默认安全行为

添加 Spring Security 依赖后，默认行为：

```yaml
# 默认生成的用户
# 用户名: user
# 密码: 控制台输出的 UUID

# 自定义默认用户（application.yml）
spring:
  security:
    user:
      name: admin
      password: admin123
      roles: ADMIN
```

**默认安全规则：**
- 所有端点都需要认证
- 提供表单登录页面 `/login`
- 提供登出端点 `/logout`
- 启用 CSRF 防护
- 启用安全响应头

---

## 3. 配置方式迁移

### 3.1 最重要的变化：告别 WebSecurityConfigurerAdapter

这是 Spring Security 6 最大的变化！`WebSecurityConfigurerAdapter` 已被完全移除。

**Spring Security 5（旧方式）：**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login")
                .permitAll()
            .and()
            .logout()
                .permitAll();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("user")
            .password("{noop}password")
            .roles("USER");
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }
}
```

**Spring Security 6（新方式）：**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout
                .permitAll()
            );
        
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
    
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers("/css/**", "/js/**", "/images/**");
    }
}
```

### 3.2 方法对照表

| Spring Security 5 | Spring Security 6 | 说明 |
|-------------------|-------------------|------|
| `configure(HttpSecurity)` | `SecurityFilterChain` Bean | HTTP 安全配置 |
| `configure(AuthenticationManagerBuilder)` | `UserDetailsService` Bean | 用户认证配置 |
| `configure(WebSecurity)` | `WebSecurityCustomizer` Bean | 忽略路径配置 |
| `authorizeRequests()` | `authorizeHttpRequests()` | 授权配置 |
| `antMatchers()` | `requestMatchers()` | 路径匹配 |
| `mvcMatchers()` | `requestMatchers()` | 路径匹配 |
| `and()` | Lambda 表达式 | 链式调用 |

### 3.3 Lambda DSL 详解

Spring Security 6 强制使用 Lambda DSL，这让配置更清晰：

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        // CSRF 配置
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        )
        
        // CORS 配置
        .cors(cors -> cors
            .configurationSource(corsConfigurationSource())
        )
        
        // 授权配置
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers(HttpMethod.GET, "/api/users/**").hasAnyRole("USER", "ADMIN")
            .requestMatchers(HttpMethod.POST, "/api/users/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        
        // 表单登录
        .formLogin(form -> form
            .loginPage("/login")
            .loginProcessingUrl("/doLogin")
            .defaultSuccessUrl("/home", true)
            .failureUrl("/login?error=true")
            .usernameParameter("username")
            .passwordParameter("password")
            .permitAll()
        )
        
        // 登出配置
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/login?logout=true")
            .deleteCookies("JSESSIONID")
            .invalidateHttpSession(true)
            .clearAuthentication(true)
        )
        
        // 异常处理
        .exceptionHandling(ex -> ex
            .authenticationEntryPoint(customAuthenticationEntryPoint())
            .accessDeniedHandler(customAccessDeniedHandler())
        )
        
        // Session 管理
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .maximumSessions(1)
            .expiredUrl("/login?expired=true")
        );
    
    return http.build();
}
```

### 3.4 使用 Customizer.withDefaults()

当使用默认配置时，可以使用 `Customizer.withDefaults()`：

```java
import org.springframework.security.config.Customizer;

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        )
        .formLogin(Customizer.withDefaults())  // 使用默认表单登录
        .httpBasic(Customizer.withDefaults()); // 使用默认 HTTP Basic
    
    return http.build();
}
```

---

## 4. 认证配置

### 4.1 内存用户认证

**Spring Security 5：**
```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("user").password("{noop}password").roles("USER")
        .and()
        .withUser("admin").password("{noop}admin").roles("ADMIN");
}
```

**Spring Security 6：**
```java
@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10$...")  // BCrypt 加密
            .roles("USER")
            .build();
    
    UserDetails admin = User.builder()
            .username("admin")
            .password("{bcrypt}$2a$10$...")
            .roles("ADMIN", "USER")
            .build();
    
    return new InMemoryUserDetailsManager(user, admin);
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

### 4.2 数据库用户认证

```java
// 用户实体
@Entity
@Table(name = "users")
public class User implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private String password;
    
    @Column(nullable = false)
    private boolean enabled = true;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toSet());
    }
    
    @Override
    public boolean isAccountNonExpired() { return true; }
    
    @Override
    public boolean isAccountNonLocked() { return true; }
    
    @Override
    public boolean isCredentialsNonExpired() { return true; }
    
    @Override
    public boolean isEnabled() { return enabled; }
    
    // getters and setters
}

// 角色实体
@Entity
@Table(name = "roles")
public class Role {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String name;
    
    // getters and setters
}
```

```java
// UserDetailsService 实现
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    private final UserRepository userRepository;
    
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));
    }
}

// Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}

// 安全配置
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    // AuthenticationManager Bean（如果需要手动认证）
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

### 4.3 多 UserDetailsService 配置

```java
@Configuration
@EnableWebSecurity
public class MultiUserSourceConfig {
    
    @Bean
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/admin/**")
            .authorizeHttpRequests(auth -> auth
                .anyRequest().hasRole("ADMIN")
            )
            .formLogin(form -> form
                .loginPage("/admin/login")
            )
            .userDetailsService(adminUserDetailsService());
        
        return http.build();
    }
    
    @Bean
    public SecurityFilterChain userFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/user/**")
            .authorizeHttpRequests(auth -> auth
                .anyRequest().hasRole("USER")
            )
            .formLogin(form -> form
                .loginPage("/user/login")
            )
            .userDetailsService(regularUserDetailsService());
        
        return http.build();
    }
    
    @Bean
    public UserDetailsService adminUserDetailsService() {
        // 管理员用户源
        return new AdminUserDetailsService();
    }
    
    @Bean
    public UserDetailsService regularUserDetailsService() {
        // 普通用户源
        return new RegularUserDetailsService();
    }
}
```

---

## 5. 授权配置

### 5.1 requestMatchers 详解

**Spring Security 5 的多种匹配器：**
```java
// Security 5 有多种匹配器
.antMatchers("/api/**")      // Ant 风格
.mvcMatchers("/users")       // MVC 风格（推荐）
.regexMatchers("/admin/.*")  // 正则表达式
```

**Spring Security 6 统一使用 requestMatchers：**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        // 基本路径匹配
        .requestMatchers("/public/**").permitAll()
        .requestMatchers("/api/v1/**").authenticated()
        
        // HTTP 方法 + 路径
        .requestMatchers(HttpMethod.GET, "/api/users/**").hasAnyRole("USER", "ADMIN")
        .requestMatchers(HttpMethod.POST, "/api/users/**").hasRole("ADMIN")
        .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN")
        
        // 多路径匹配
        .requestMatchers("/login", "/register", "/forgot-password").permitAll()
        
        // 正则表达式匹配
        .requestMatchers(new RegexRequestMatcher("/api/v[0-9]+/.*", null)).authenticated()
        
        // 自定义 RequestMatcher
        .requestMatchers(request -> request.getHeader("X-API-KEY") != null).permitAll()
        
        // 默认规则
        .anyRequest().authenticated()
    );
    
    return http.build();
}
```

### 5.2 授权表达式对比

**Spring Security 5：**
```java
.authorizeRequests()
    .antMatchers("/admin/**").access("hasRole('ADMIN') and hasIpAddress('192.168.1.0/24')")
    .antMatchers("/api/**").access("@customSecurity.check(authentication, request)")
```

**Spring Security 6：**
```java
.authorizeHttpRequests(auth -> auth
    // 简单角色检查
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
    
    // 权限检查
    .requestMatchers("/api/write/**").hasAuthority("WRITE_PRIVILEGE")
    .requestMatchers("/api/read/**").hasAnyAuthority("READ_PRIVILEGE", "WRITE_PRIVILEGE")
    
    // 使用 AuthorizationManager（新方式）
    .requestMatchers("/api/special/**").access(customAuthorizationManager())
    
    // 认证状态
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/private/**").authenticated()
    .requestMatchers("/anonymous/**").anonymous()
    .anyRequest().denyAll()
)
```

### 5.3 自定义 AuthorizationManager

```java
// 自定义授权管理器
@Component
public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, 
                                       RequestAuthorizationContext context) {
        Authentication auth = authentication.get();
        HttpServletRequest request = context.getRequest();
        
        // 自定义授权逻辑
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }
        
        // 检查 IP 地址
        String remoteAddr = request.getRemoteAddr();
        if (remoteAddr.startsWith("192.168.")) {
            return new AuthorizationDecision(true);
        }
        
        // 检查角色
        boolean hasAdminRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        
        return new AuthorizationDecision(hasAdminRole);
    }
}

// 使用
@Bean
public SecurityFilterChain filterChain(HttpSecurity http, 
        CustomAuthorizationManager customAuthManager) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/special/**").access(customAuthManager)
        .anyRequest().authenticated()
    );
    return http.build();
}
```

### 5.4 基于 SpEL 的授权（Security 6 方式）

```java
// 配置
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/**").access(
            AuthorizationManagers.allOf(
                AuthorityAuthorizationManager.hasRole("USER"),
                (authentication, context) -> {
                    // 自定义检查
                    String apiKey = context.getRequest().getHeader("X-API-KEY");
                    return new AuthorizationDecision(apiKey != null);
                }
            )
        )
    );
    return http.build();
}
```

---

## 6. 密码编码

### 6.1 PasswordEncoder 配置

```java
@Configuration
public class PasswordConfig {
    
    // 推荐：BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    // 或者：使用委托编码器（支持多种格式）
    @Bean
    public PasswordEncoder delegatingPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

### 6.2 密码格式对比

```java
// 委托编码器支持的格式
{bcrypt}$2a$10$...     // BCrypt（推荐）
{pbkdf2}...            // PBKDF2
{scrypt}...            // SCrypt
{argon2}...            // Argon2（最安全）
{sha256}...            // SHA-256（不推荐）
{noop}plaintext        // 明文（仅测试用）

// 示例
@Bean
public UserDetailsService users() {
    UserDetails user = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
            .roles("USER")
            .build();
    return new InMemoryUserDetailsManager(user);
}
```

### 6.3 密码升级策略

```java
@Service
public class UserService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    // 注册时加密密码
    public User register(String username, String rawPassword) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(rawPassword));
        return userRepository.save(user);
    }
    
    // 登录时检查是否需要升级密码
    public void upgradePasswordIfNeeded(User user, String rawPassword) {
        if (passwordEncoder.upgradeEncoding(user.getPassword())) {
            user.setPassword(passwordEncoder.encode(rawPassword));
            userRepository.save(user);
        }
    }
}
```

---

## 7. CSRF 防护

### 7.1 CSRF 配置变化

**Spring Security 5：**
```java
http.csrf().disable();
http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
http.csrf().ignoringAntMatchers("/api/**");
```

**Spring Security 6：**
```java
http
    // 禁用 CSRF
    .csrf(csrf -> csrf.disable())
    
    // 使用 Cookie 存储 Token
    .csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    )
    
    // 忽略特定路径
    .csrf(csrf -> csrf
        .ignoringRequestMatchers("/api/**")
        .ignoringRequestMatchers("/webhook/**")
    )
    
    // 自定义 Token 处理（Security 6 新增）
    .csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
    );
```

### 7.2 CSRF Token 处理器（Security 6 新特性）

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
    );
    return http.build();
}

// SPA 应用的 CSRF 处理器
public class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
    
    private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();
    
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, 
                       Supplier<CsrfToken> csrfToken) {
        this.delegate.handle(request, response, csrfToken);
    }
    
    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        // 优先从 Header 获取
        String headerValue = request.getHeader(csrfToken.getHeaderName());
        if (StringUtils.hasText(headerValue)) {
            return super.resolveCsrfTokenValue(request, csrfToken);
        }
        // 否则从参数获取
        return this.delegate.resolveCsrfTokenValue(request, csrfToken);
    }
}
```

### 7.3 前端获取 CSRF Token

```javascript
// 从 Cookie 获取 CSRF Token
function getCsrfToken() {
    const cookie = document.cookie
        .split('; ')
        .find(row => row.startsWith('XSRF-TOKEN='));
    return cookie ? cookie.split('=')[1] : null;
}

// 发送请求时携带 Token
fetch('/api/data', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-XSRF-TOKEN': getCsrfToken()
    },
    body: JSON.stringify(data)
});
```

---

## 8. CORS 配置

### 8.1 CORS 配置变化

**Spring Security 5：**
```java
http.cors().and()...
http.cors().configurationSource(corsConfigurationSource());
```

**Spring Security 6：**
```java
http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

// 或使用默认配置
http.cors(Customizer.withDefaults());
```

### 8.2 完整 CORS 配置

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            );
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 允许的源
        configuration.setAllowedOrigins(List.of(
            "http://localhost:3000",
            "https://example.com"
        ));
        // 或使用模式匹配
        configuration.setAllowedOriginPatterns(List.of("https://*.example.com"));
        
        // 允许的方法
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        
        // 允许的请求头
        configuration.setAllowedHeaders(List.of("*"));
        
        // 暴露的响应头
        configuration.setExposedHeaders(List.of("Authorization", "X-Custom-Header"));
        
        // 允许携带凭证
        configuration.setAllowCredentials(true);
        
        // 预检请求缓存时间
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 8.3 不同路径不同 CORS 策略

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    
    // API 路径配置
    CorsConfiguration apiConfig = new CorsConfiguration();
    apiConfig.setAllowedOrigins(List.of("https://api-client.com"));
    apiConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    source.registerCorsConfiguration("/api/**", apiConfig);
    
    // 公开路径配置
    CorsConfiguration publicConfig = new CorsConfiguration();
    publicConfig.setAllowedOrigins(List.of("*"));
    publicConfig.setAllowedMethods(List.of("GET"));
    source.registerCorsConfiguration("/public/**", publicConfig);
    
    return source;
}
```

---

## 9. Session 管理

### 9.1 Session 配置变化

**Spring Security 5：**
```java
http.sessionManagement()
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true);
```

**Spring Security 6：**
```java
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true)
);
```

### 9.2 完整 Session 配置

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.sessionManagement(session -> session
        // Session 创建策略
        // ALWAYS: 总是创建
        // IF_REQUIRED: 需要时创建（默认）
        // NEVER: 不创建，但会使用已存在的
        // STATELESS: 不创建也不使用（适合 REST API）
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        
        // 并发控制
        .maximumSessions(1)                    // 最大会话数
        .maxSessionsPreventsLogin(false)       // false: 踢掉旧会话; true: 阻止新登录
        .expiredUrl("/login?expired=true")     // 会话过期跳转
        .expiredSessionStrategy(event -> {     // 自定义过期处理
            HttpServletResponse response = event.getResponse();
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Session expired\"}");
        })
        
        // Session 固定攻击防护
        .sessionFixation(fixation -> fixation
            .newSession()  // 创建新 Session，不复制属性
            // .migrateSession()  // 创建新 Session，复制属性（默认）
            // .changeSessionId() // 只改变 Session ID
            // .none()            // 不防护（不推荐）
        )
        
        // 无效 Session 处理
        .invalidSessionUrl("/login?invalid=true")
        .invalidSessionStrategy((request, response) -> {
            response.sendRedirect("/login?invalid=true");
        })
    );
    
    return http.build();
}
```

### 9.3 分布式 Session（Redis）

```xml
<!-- 依赖 -->
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

```yaml
# application.yml
spring:
  data:
    redis:
      host: localhost
      port: 6379
  session:
    store-type: redis
    timeout: 30m
    redis:
      namespace: spring:session
```

```java
@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800)
public class SessionConfig {
    
    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return new GenericJackson2JsonRedisSerializer();
    }
}
```

---

## 10. Remember-Me

### 10.1 Remember-Me 配置变化

**Spring Security 5：**
```java
http.rememberMe()
    .key("uniqueAndSecret")
    .tokenValiditySeconds(86400);
```

**Spring Security 6：**
```java
http.rememberMe(remember -> remember
    .key("uniqueAndSecret")
    .tokenValiditySeconds(86400)
);
```

### 10.2 完整 Remember-Me 配置

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.rememberMe(remember -> remember
        // 密钥（用于生成 Token）
        .key("mySecretKey")
        
        // Token 有效期（秒）
        .tokenValiditySeconds(7 * 24 * 60 * 60)  // 7天
        
        // Cookie 名称
        .rememberMeCookieName("remember-me")
        
        // 参数名称
        .rememberMeParameter("remember-me")
        
        // 使用安全 Cookie
        .useSecureCookie(true)
        
        // 自定义 UserDetailsService
        .userDetailsService(userDetailsService)
        
        // 持久化 Token（数据库存储）
        .tokenRepository(persistentTokenRepository())
    );
    
    return http.build();
}

// 持久化 Token 存储
@Bean
public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
    JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
    repository.setDataSource(dataSource);
    // 首次运行时创建表
    // repository.setCreateTableOnStartup(true);
    return repository;
}
```

**数据库表结构：**
```sql
CREATE TABLE persistent_logins (
    username VARCHAR(64) NOT NULL,
    series VARCHAR(64) PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    last_used TIMESTAMP NOT NULL
);
```

---

## 11. JWT 认证

### 11.1 JWT 配置（Resource Server）

```xml
<!-- 依赖 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # 方式一：使用 JWK Set URI
          jwk-set-uri: https://auth-server.com/.well-known/jwks.json
          
          # 方式二：使用公钥
          # public-key-location: classpath:public.pem
          
          # 方式三：使用 Issuer URI（自动发现）
          # issuer-uri: https://auth-server.com
```

### 11.2 JWT 安全配置

**Spring Security 5：**
```java
http.oauth2ResourceServer()
    .jwt()
    .jwtAuthenticationConverter(jwtAuthenticationConverter());
```

**Spring Security 6：**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
            )
        );
    
    return http.build();
}

// JWT 转换器：将 JWT Claims 转换为 Spring Security 权限
@Bean
public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    // 从 JWT 的哪个字段读取权限
    grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
    // 权限前缀
    grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
    
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
    return converter;
}
```

### 11.3 自定义 JWT 解码器

```java
@Bean
public JwtDecoder jwtDecoder() {
    // 使用对称密钥
    SecretKey secretKey = new SecretKeySpec(
        "your-256-bit-secret-key-here!!".getBytes(), 
        "HmacSHA256"
    );
    return NimbusJwtDecoder.withSecretKey(secretKey).build();
}

// 或使用 RSA 公钥
@Bean
public JwtDecoder jwtDecoder(@Value("${jwt.public-key}") RSAPublicKey publicKey) {
    return NimbusJwtDecoder.withPublicKey(publicKey).build();
}

// 添加自定义验证
@Bean
public JwtDecoder jwtDecoderWithValidation() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
        .withJwkSetUri("https://auth-server.com/.well-known/jwks.json")
        .build();
    
    // 添加自定义验证器
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer("https://auth-server.com");
    OAuth2TokenValidator<Jwt> withAudience = new JwtClaimValidator<List<String>>(
        "aud", 
        aud -> aud.contains("my-api")
    );
    
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, withAudience));
    return decoder;
}
```

### 11.4 自签名 JWT 实现

```java
@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.expiration:86400000}")
    private long expiration;
    
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    // 生成 Token
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    // 验证 Token
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    
    // 提取用户名
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }
    
    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}
```

### 11.5 JWT 过滤器

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String jwt = authHeader.substring(7);
        String username = jwtService.extractUsername(jwt);
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            if (jwtService.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        filterChain.doFilter(request, response);
    }
}

// 配置
@Bean
public SecurityFilterChain filterChain(HttpSecurity http, 
        JwtAuthenticationFilter jwtFilter) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/auth/**").permitAll()
            .anyRequest().authenticated()
        )
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    
    return http.build();
}
```

---

## 12. OAuth2 集成

### 12.1 OAuth2 登录配置

**Spring Security 5：**
```java
http.oauth2Login()
    .loginPage("/login")
    .defaultSuccessUrl("/home");
```

**Spring Security 6：**
```java
http.oauth2Login(oauth2 -> oauth2
    .loginPage("/login")
    .defaultSuccessUrl("/home")
);
```

### 12.2 完整 OAuth2 配置

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope: read:user,user:email
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: openid,profile,email
        provider:
          github:
            authorization-uri: https://github.com/login/oauth/authorize
            token-uri: https://github.com/login/oauth/access_token
            user-info-uri: https://api.github.com/user
            user-name-attribute: login
```

```java
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login/**", "/error").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/home", true)
                .failureUrl("/login?error=true")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService())
                )
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/")
            );
        
        return http.build();
    }
    
    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> customOAuth2UserService() {
        return new CustomOAuth2UserService();
    }
}
```

### 12.3 自定义 OAuth2 用户服务

```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    
    private final UserRepository userRepository;
    
    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        
        // 查找或创建用户
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> createUser(email, name, registrationId));
        
        // 更新最后登录时间
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);
        
        // 返回自定义的 OAuth2User
        return new CustomOAuth2User(oauth2User, user);
    }
    
    private User createUser(String email, String name, String provider) {
        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setProvider(provider);
        user.setEnabled(true);
        return userRepository.save(user);
    }
}

// 自定义 OAuth2User
public class CustomOAuth2User implements OAuth2User {
    
    private final OAuth2User oauth2User;
    private final User user;
    
    public CustomOAuth2User(OAuth2User oauth2User, User user) {
        this.oauth2User = oauth2User;
        this.user = user;
    }
    
    @Override
    public Map<String, Object> getAttributes() {
        return oauth2User.getAttributes();
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());
    }
    
    @Override
    public String getName() {
        return user.getEmail();
    }
    
    public User getUser() {
        return user;
    }
}
```

---

## 13. 方法级安全

### 13.1 启用方法级安全

**Spring Security 5：**
```java
@EnableGlobalMethodSecurity(
    prePostEnabled = true,
    securedEnabled = true,
    jsr250Enabled = true
)
```

**Spring Security 6：**
```java
@EnableMethodSecurity(
    prePostEnabled = true,   // 启用 @PreAuthorize, @PostAuthorize
    securedEnabled = true,   // 启用 @Secured
    jsr250Enabled = true     // 启用 @RolesAllowed
)
```

### 13.2 方法级安全注解

```java
@Service
public class UserService {
    
    // @PreAuthorize - 方法执行前检查
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(Long id) {
        // 只有 ADMIN 角色可以执行
    }
    
    // 使用 SpEL 表达式
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public User getUser(String username) {
        // ADMIN 或用户本人可以访问
        return userRepository.findByUsername(username);
    }
    
    // @PostAuthorize - 方法执行后检查
    @PostAuthorize("returnObject.username == authentication.name or hasRole('ADMIN')")
    public User getUserById(Long id) {
        // 返回结果后检查权限
        return userRepository.findById(id).orElseThrow();
    }
    
    // @PreFilter - 过滤输入集合
    @PreFilter("filterObject.owner == authentication.name")
    public void deleteDocuments(List<Document> documents) {
        // 只处理属于当前用户的文档
    }
    
    // @PostFilter - 过滤输出集合
    @PostFilter("filterObject.owner == authentication.name or hasRole('ADMIN')")
    public List<Document> getAllDocuments() {
        // 只返回用户有权限查看的文档
        return documentRepository.findAll();
    }
    
    // @Secured - 简单角色检查
    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    public void securedMethod() {
        // USER 或 ADMIN 角色可以执行
    }
    
    // @RolesAllowed (JSR-250)
    @RolesAllowed({"USER", "ADMIN"})
    public void rolesAllowedMethod() {
        // 与 @Secured 类似
    }
}
```

### 13.3 自定义权限评估器

```java
// 自定义权限评估器
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    
    private final DocumentRepository documentRepository;
    
    public CustomPermissionEvaluator(DocumentRepository documentRepository) {
        this.documentRepository = documentRepository;
    }
    
    @Override
    public boolean hasPermission(Authentication authentication, 
                                  Object targetDomainObject, 
                                  Object permission) {
        if (authentication == null || targetDomainObject == null) {
            return false;
        }
        
        String username = authentication.getName();
        String perm = permission.toString();
        
        if (targetDomainObject instanceof Document doc) {
            return hasDocumentPermission(username, doc, perm);
        }
        
        return false;
    }
    
    @Override
    public boolean hasPermission(Authentication authentication, 
                                  Serializable targetId, 
                                  String targetType, 
                                  Object permission) {
        if (authentication == null || targetId == null) {
            return false;
        }
        
        if ("Document".equals(targetType)) {
            Document doc = documentRepository.findById((Long) targetId).orElse(null);
            if (doc != null) {
                return hasDocumentPermission(authentication.getName(), doc, permission.toString());
            }
        }
        
        return false;
    }
    
    private boolean hasDocumentPermission(String username, Document doc, String permission) {
        return switch (permission) {
            case "READ" -> doc.getOwner().equals(username) || doc.isPublic();
            case "WRITE" -> doc.getOwner().equals(username);
            case "DELETE" -> doc.getOwner().equals(username);
            default -> false;
        };
    }
}

// 配置
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
    
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            CustomPermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}

// 使用
@Service
public class DocumentService {
    
    @PreAuthorize("hasPermission(#id, 'Document', 'READ')")
    public Document getDocument(Long id) {
        return documentRepository.findById(id).orElseThrow();
    }
    
    @PreAuthorize("hasPermission(#document, 'WRITE')")
    public Document updateDocument(Document document) {
        return documentRepository.save(document);
    }
}
```

---

## 14. 自定义认证

### 14.1 自定义认证过滤器

```java
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {
    
    private final String headerName = "X-API-KEY";
    private final ApiKeyService apiKeyService;
    
    public ApiKeyAuthenticationFilter(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String apiKey = request.getHeader(headerName);
        
        if (apiKey != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            ApiKeyDetails details = apiKeyService.validateApiKey(apiKey);
            
            if (details != null) {
                ApiKeyAuthenticationToken authentication = new ApiKeyAuthenticationToken(
                        details,
                        details.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 只对 /api/** 路径生效
        return !request.getRequestURI().startsWith("/api/");
    }
}

// 自定义 Authentication Token
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {
    
    private final ApiKeyDetails principal;
    
    public ApiKeyAuthenticationToken(ApiKeyDetails principal, 
                                     Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        setAuthenticated(true);
    }
    
    @Override
    public Object getCredentials() {
        return null;
    }
    
    @Override
    public Object getPrincipal() {
        return principal;
    }
}
```

### 14.2 自定义 AuthenticationProvider

```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    
    public CustomAuthenticationProvider(UserDetailsService userDetailsService, 
                                        PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        
        UserDetails user = userDetailsService.loadUserByUsername(username);
        
        // 自定义验证逻辑
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("密码错误");
        }
        
        if (!user.isEnabled()) {
            throw new DisabledException("账户已禁用");
        }
        
        if (!user.isAccountNonLocked()) {
            throw new LockedException("账户已锁定");
        }
        
        // 可以添加更多验证：IP 白名单、登录时间限制等
        
        return new UsernamePasswordAuthenticationToken(
                user, 
                password, 
                user.getAuthorities()
        );
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

// 配置
@Bean
public AuthenticationManager authenticationManager(
        CustomAuthenticationProvider customProvider) {
    return new ProviderManager(customProvider);
}
```

### 14.3 多因素认证（MFA）

```java
@Service
public class MfaService {
    
    private final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
    
    // 生成密钥
    public String generateSecretKey() {
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        return key.getKey();
    }
    
    // 生成二维码 URL
    public String getQrCodeUrl(String username, String secretKey) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(
                "MyApp",
                username,
                new GoogleAuthenticatorKey.Builder(secretKey).build()
        );
    }
    
    // 验证 TOTP 码
    public boolean verifyCode(String secretKey, int code) {
        return googleAuthenticator.authorize(secretKey, code);
    }
}

// MFA 过滤器
public class MfaAuthenticationFilter extends OncePerRequestFilter {
    
    private final MfaService mfaService;
    private final UserRepository userRepository;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth != null && auth.isAuthenticated() && requiresMfa(auth)) {
            String totpCode = request.getHeader("X-TOTP-CODE");
            
            if (totpCode == null) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("{\"error\": \"MFA required\"}");
                return;
            }
            
            User user = userRepository.findByUsername(auth.getName()).orElseThrow();
            
            if (!mfaService.verifyCode(user.getMfaSecret(), Integer.parseInt(totpCode))) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Invalid TOTP code\"}");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean requiresMfa(Authentication auth) {
        // 检查用户是否启用了 MFA
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("MFA_REQUIRED"));
    }
}
```

---

## 15. 常见错误与解决方案

### 15.1 配置类错误

**错误：cannot find symbol WebSecurityConfigurerAdapter**
```java
// 原因：Spring Security 6 已移除该类
// 解决：使用 SecurityFilterChain Bean

// ❌ 旧方式
public class SecurityConfig extends WebSecurityConfigurerAdapter { }

// ✅ 新方式
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 配置
        return http.build();
    }
}
```

**错误：cannot find symbol antMatchers**
```java
// 原因：方法已重命名
// 解决：使用 requestMatchers

// ❌ 旧方式
.antMatchers("/api/**").permitAll()

// ✅ 新方式
.requestMatchers("/api/**").permitAll()
```

**错误：cannot find symbol authorizeRequests**
```java
// 原因：方法已重命名
// 解决：使用 authorizeHttpRequests

// ❌ 旧方式
http.authorizeRequests()
    .antMatchers("/public/**").permitAll()

// ✅ 新方式
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
)
```

### 15.2 Lambda DSL 错误

**错误：and() method not found**
```java
// 原因：Security 6 使用 Lambda DSL，不再需要 and()
// 解决：使用 Lambda 表达式

// ❌ 旧方式
http.csrf().disable()
    .and()
    .authorizeRequests()
    .and()
    .formLogin();

// ✅ 新方式
http
    .csrf(csrf -> csrf.disable())
    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
    .formLogin(Customizer.withDefaults());
```

**错误：配置不生效**
```java
// 原因：忘记调用 http.build()
// 解决：确保返回 http.build()

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();  // ← 不要忘记这行！
}
```

### 15.3 认证错误

**错误：No AuthenticationProvider found**
```java
// 原因：没有配置 UserDetailsService 或 AuthenticationProvider
// 解决：配置用户服务

@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();
    return new InMemoryUserDetailsManager(user);
}
```

**错误：Bad credentials**
```java
// 原因：密码编码不匹配
// 解决：确保密码编码一致

// 存储时加密
String encoded = passwordEncoder.encode("rawPassword");

// 配置密码编码器
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

**错误：There is no PasswordEncoder mapped for the id "null"**
```java
// 原因：密码没有编码前缀
// 解决：添加编码前缀或配置 PasswordEncoder

// 方式一：添加前缀
.password("{bcrypt}$2a$10$...")
.password("{noop}plaintext")

// 方式二：配置默认编码器
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

### 15.4 授权错误

**错误：Access Denied 403**
```java
// 可能原因：
// 1. 角色名称不匹配
// 2. 权限配置顺序错误
// 3. CSRF 问题

// 检查角色名称
.hasRole("ADMIN")      // 自动添加 ROLE_ 前缀
.hasAuthority("ROLE_ADMIN")  // 需要完整名称

// 检查配置顺序（具体规则在前）
.requestMatchers("/admin/**").hasRole("ADMIN")
.requestMatchers("/api/**").authenticated()
.anyRequest().permitAll()  // 最后

// 检查 CSRF（REST API 通常禁用）
.csrf(csrf -> csrf.disable())
```

**错误：路径匹配不生效**
```java
// 原因：Spring Security 6 路径匹配更严格
// 解决：检查路径格式

// 注意尾部斜杠
.requestMatchers("/api/users")   // 只匹配 /api/users
.requestMatchers("/api/users/")  // 只匹配 /api/users/
.requestMatchers("/api/users", "/api/users/")  // 同时匹配

// 注意通配符
.requestMatchers("/api/**")  // 匹配 /api/ 下所有路径
.requestMatchers("/api/*")   // 只匹配一级路径
```

### 15.5 CSRF 错误

**错误：403 Forbidden - Invalid CSRF Token**
```java
// 原因：CSRF Token 缺失或无效
// 解决方案：

// 方案一：REST API 禁用 CSRF
http.csrf(csrf -> csrf.disable());

// 方案二：正确配置 CSRF
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
);

// 方案三：忽略特定路径
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/**")
);
```

**错误：CSRF Token 在 SPA 中不工作**
```java
// 原因：Security 6 默认使用 XorCsrfTokenRequestAttributeHandler
// 解决：使用自定义处理器

http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
);

// 前端需要从 Cookie 读取并在 Header 中发送
// Cookie 名: XSRF-TOKEN
// Header 名: X-XSRF-TOKEN
```

### 15.6 CORS 错误

**错误：CORS policy blocked**
```java
// 原因：CORS 配置缺失或不正确
// 解决：配置 CORS

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
    return http.build();
}

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("http://localhost:3000"));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("*"));
    config.setAllowCredentials(true);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}
```

**错误：Preflight request 失败**
```java
// 原因：OPTIONS 请求被拦截
// 解决：允许 OPTIONS 请求

http.authorizeHttpRequests(auth -> auth
    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
    .anyRequest().authenticated()
);
```

### 15.7 Session 错误

**错误：Session 创建失败**
```java
// 原因：STATELESS 模式下尝试使用 Session
// 解决：检查 Session 策略

// 如果使用 JWT，应该是 STATELESS
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
);

// 如果需要 Session，使用 IF_REQUIRED
http.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
);
```

### 15.8 测试错误

**错误：测试中认证不生效**
```java
// 解决：使用 @WithMockUser 或 SecurityMockMvcRequestPostProcessors

@Test
@WithMockUser(username = "admin", roles = {"ADMIN"})
void adminEndpoint_shouldSucceed() throws Exception {
    mockMvc.perform(get("/admin/dashboard"))
            .andExpect(status().isOk());
}

// 或使用 with(user(...))
@Test
void adminEndpoint_withUser() throws Exception {
    mockMvc.perform(get("/admin/dashboard")
            .with(user("admin").roles("ADMIN")))
            .andExpect(status().isOk());
}

// 测试 CSRF
@Test
void postEndpoint_withCsrf() throws Exception {
    mockMvc.perform(post("/api/data")
            .with(csrf())
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}"))
            .andExpect(status().isOk());
}
```

---

## 附录：快速参考

### 方法对照表

| Spring Security 5 | Spring Security 6 |
|-------------------|-------------------|
| `extends WebSecurityConfigurerAdapter` | `@Bean SecurityFilterChain` |
| `configure(HttpSecurity)` | `SecurityFilterChain` Bean |
| `configure(AuthenticationManagerBuilder)` | `UserDetailsService` Bean |
| `configure(WebSecurity)` | `WebSecurityCustomizer` Bean |
| `authorizeRequests()` | `authorizeHttpRequests()` |
| `antMatchers()` | `requestMatchers()` |
| `mvcMatchers()` | `requestMatchers()` |
| `.and()` | Lambda 表达式 |
| `@EnableGlobalMethodSecurity` | `@EnableMethodSecurity` |

### 常用配置模板

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

---

> 💡 **迁移建议**：
> 1. 先升级到 Spring Security 5.8，解决废弃警告
> 2. 使用 IDE 的全局替换功能批量修改方法名
> 3. 逐步将链式调用改为 Lambda DSL
> 4. 充分测试所有安全相关功能
> 5. 关注官方迁移指南获取最新信息
