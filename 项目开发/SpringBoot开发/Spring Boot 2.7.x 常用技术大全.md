> 基于 Java 8 + Spring Boot 2.7.18 最佳实践
> 
> 版本说明：本文档所有示例均基于 Spring Boot 2.7.18 (最后一个支持 Java 8 的 LTS 版本)

---

## 目录

1. [数据库集成](#1-数据库集成)
2. [消息队列集成](#2-消息队列集成)
3. [安全集成](#3-安全集成)
4. [缓存集成](#4-缓存集成)
5. [任务调度集成](#5-任务调度集成)
6. [监控与日志集成](#6-监控与日志集成)
7. [API文档集成](#7-api文档集成)
8. [模板引擎集成](#8-模板引擎集成)
9. [分布式系统集成](#9-分布式系统集成)
10. [测试集成](#10-测试集成)
11. [配置管理集成](#11-配置管理集成)
12. [容器化与部署](#12-容器化与部署)
13. [开发工具集成](#13-开发工具集成)

---

## 1. 数据库集成

### 1.1 关系型数据库

#### Spring Data JPA (Hibernate)

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <scope>runtime</scope>
</dependency>
<!-- HikariCP 连接池 (Spring Boot 2.x 默认) -->
<dependency>
    <groupId>com.zaxxer</groupId>
    <artifactId>HikariCP</artifactId>
</dependency>
```

**配置 (application.yml)：**
```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mydb?useUnicode=true&characterEncoding=utf8&useSSL=false&serverTimezone=Asia/Shanghai
    username: ${DB_USERNAME:root}
    password: ${DB_PASSWORD:password}
    driver-class-name: com.mysql.cj.jdbc.Driver
    # HikariCP 连接池配置
    hikari:
      minimum-idle: 5
      maximum-pool-size: 20
      idle-timeout: 30000
      pool-name: SpringBootHikariCP
      max-lifetime: 1800000
      connection-timeout: 30000
      connection-test-query: SELECT 1
  jpa:
    hibernate:
      ddl-auto: validate  # 生产环境推荐 validate 或 none
    show-sql: false       # 生产环境关闭
    open-in-view: false   # 推荐关闭，避免懒加载问题
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.MySQL8Dialect
        jdbc:
          batch_size: 50
        order_inserts: true
        order_updates: true
```

**实体类最佳实践：**
```java
@Entity
@Table(name = "t_user", indexes = {
    @Index(name = "idx_email", columnList = "email", unique = true)
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 50)
    private String username;
    
    @Column(nullable = false, unique = true, length = 100)
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private UserStatus status;
    
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    
    @Version
    private Integer version;  // 乐观锁
}

public enum UserStatus {
    ACTIVE, INACTIVE, LOCKED
}
```

**Repository 最佳实践：**
```java
@Repository
public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
    
    Optional<User> findByEmail(String email);
    
    @Query("SELECT u FROM User u WHERE u.status = :status")
    List<User> findByStatus(@Param("status") UserStatus status);
    
    @Modifying
    @Query("UPDATE User u SET u.status = :status WHERE u.id = :id")
    int updateStatus(@Param("id") Long id, @Param("status") UserStatus status);
    
    // 分页查询
    Page<User> findByStatusOrderByCreatedAtDesc(UserStatus status, Pageable pageable);
    
    // 使用 Specification 动态查询
    default Page<User> findByCondition(UserQueryDTO query, Pageable pageable) {
        return findAll((root, criteriaQuery, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (StringUtils.hasText(query.getUsername())) {
                predicates.add(cb.like(root.get("username"), "%" + query.getUsername() + "%"));
            }
            if (query.getStatus() != null) {
                predicates.add(cb.equal(root.get("status"), query.getStatus()));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        }, pageable);
    }
}
```


#### MyBatis-Plus (推荐)

**Maven 依赖：**
```xml
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-boot-starter</artifactId>
    <version>3.5.3.1</version>
</dependency>
```

**配置：**
```yaml
mybatis-plus:
  mapper-locations: classpath*:mapper/**/*.xml
  type-aliases-package: com.example.entity
  global-config:
    db-config:
      id-type: auto
      logic-delete-field: deleted
      logic-delete-value: 1
      logic-not-delete-value: 0
  configuration:
    map-underscore-to-camel-case: true
    cache-enabled: false
    log-impl: org.apache.ibatis.logging.slf4j.Slf4jImpl
```

**实体类：**
```java
@Data
@TableName("t_user")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements Serializable {
    
    @TableId(type = IdType.AUTO)
    private Long id;
    
    private String username;
    
    private String email;
    
    @TableField(fill = FieldFill.INSERT)
    private LocalDateTime createdAt;
    
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private LocalDateTime updatedAt;
    
    @TableLogic
    private Integer deleted;
    
    @Version
    private Integer version;
}
```

**Mapper：**
```java
@Mapper
public interface UserMapper extends BaseMapper<User> {
    
    // 自定义复杂查询
    @Select("SELECT * FROM t_user WHERE email = #{email}")
    User selectByEmail(@Param("email") String email);
}
```

**Service 层：**
```java
public interface UserService extends IService<User> {
    User getByEmail(String email);
    Page<User> pageByCondition(UserQueryDTO query);
}

@Service
@RequiredArgsConstructor
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    
    @Override
    public User getByEmail(String email) {
        return lambdaQuery()
            .eq(User::getEmail, email)
            .one();
    }
    
    @Override
    public Page<User> pageByCondition(UserQueryDTO query) {
        return lambdaQuery()
            .like(StringUtils.hasText(query.getUsername()), User::getUsername, query.getUsername())
            .eq(query.getStatus() != null, User::getStatus, query.getStatus())
            .orderByDesc(User::getCreatedAt)
            .page(new Page<>(query.getPageNum(), query.getPageSize()));
    }
}
```

**自动填充配置：**
```java
@Component
public class MyMetaObjectHandler implements MetaObjectHandler {
    
    @Override
    public void insertFill(MetaObject metaObject) {
        this.strictInsertFill(metaObject, "createdAt", LocalDateTime::now, LocalDateTime.class);
        this.strictInsertFill(metaObject, "updatedAt", LocalDateTime::now, LocalDateTime.class);
    }
    
    @Override
    public void updateFill(MetaObject metaObject) {
        this.strictUpdateFill(metaObject, "updatedAt", LocalDateTime::now, LocalDateTime.class);
    }
}
```


### 1.2 NoSQL 数据库

#### MongoDB

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-mongodb</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  data:
    mongodb:
      uri: mongodb://${MONGO_USER:admin}:${MONGO_PASSWORD:password}@localhost:27017/mydb?authSource=admin
      auto-index-creation: true
```

**文档实体：**
```java
@Document(collection = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDocument {
    
    @Id
    private String id;
    
    @Indexed(unique = true)
    private String email;
    
    private String username;
    
    @CreatedDate
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
}
```

**Repository：**
```java
@Repository
public interface UserDocumentRepository extends MongoRepository<UserDocument, String> {
    
    Optional<UserDocument> findByEmail(String email);
    
    @Query("{ 'username': { $regex: ?0, $options: 'i' } }")
    List<UserDocument> findByUsernameContaining(String username);
}
```

#### Redis

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-pool2</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  redis:
    host: ${REDIS_HOST:localhost}
    port: ${REDIS_PORT:6379}
    password: ${REDIS_PASSWORD:}
    database: 0
    timeout: 3000ms
    lettuce:
      pool:
        max-active: 20
        max-idle: 10
        min-idle: 5
        max-wait: -1ms
```

**Redis 配置类：**
```java
@Configuration
@EnableCaching
public class RedisConfig {
    
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // JSON 序列化
        Jackson2JsonRedisSerializer<Object> jsonSerializer = new Jackson2JsonRedisSerializer<>(Object.class);
        ObjectMapper om = new ObjectMapper();
        om.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        om.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
        om.registerModule(new JavaTimeModule());
        jsonSerializer.setObjectMapper(om);
        
        // Key 使用 String 序列化
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        // Value 使用 JSON 序列化
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);
        
        template.afterPropertiesSet();
        return template;
    }
    
    @Bean
    public CacheManager cacheManager(RedisConnectionFactory factory) {
        RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
            .entryTtl(Duration.ofHours(1))
            .serializeKeysWith(RedisSerializationContext.SerializationPair.fromSerializer(new StringRedisSerializer()))
            .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer()))
            .disableCachingNullValues();
        
        return RedisCacheManager.builder(factory)
            .cacheDefaults(config)
            .withCacheConfiguration("users", config.entryTtl(Duration.ofMinutes(30)))
            .build();
    }
}
```

**Redis 工具类：**
```java
@Component
@RequiredArgsConstructor
public class RedisUtil {
    
    private final RedisTemplate<String, Object> redisTemplate;
    
    public void set(String key, Object value, long timeout, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, timeout, unit);
    }
    
    public <T> T get(String key, Class<T> clazz) {
        Object value = redisTemplate.opsForValue().get(key);
        return clazz.cast(value);
    }
    
    public Boolean delete(String key) {
        return redisTemplate.delete(key);
    }
    
    public Boolean hasKey(String key) {
        return redisTemplate.hasKey(key);
    }
    
    public Boolean expire(String key, long timeout, TimeUnit unit) {
        return redisTemplate.expire(key, timeout, unit);
    }
    
    // 分布式锁
    public boolean tryLock(String key, String value, long timeout, TimeUnit unit) {
        return Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(key, value, timeout, unit));
    }
    
    public void unlock(String key, String value) {
        String script = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
        redisTemplate.execute(new DefaultRedisScript<>(script, Long.class), Collections.singletonList(key), value);
    }
}
```

--
-

## 2. 消息队列集成

### 2.1 RabbitMQ

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-amqp</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  rabbitmq:
    host: ${RABBITMQ_HOST:localhost}
    port: ${RABBITMQ_PORT:5672}
    username: ${RABBITMQ_USER:guest}
    password: ${RABBITMQ_PASSWORD:guest}
    virtual-host: /
    publisher-confirm-type: correlated  # 发布确认
    publisher-returns: true              # 发布返回
    listener:
      simple:
        acknowledge-mode: manual         # 手动确认
        prefetch: 10                     # 预取数量
        retry:
          enabled: true
          max-attempts: 3
          initial-interval: 1000ms
```

**配置类：**
```java
@Configuration
public class RabbitMQConfig {
    
    public static final String EXCHANGE_NAME = "app.exchange";
    public static final String QUEUE_NAME = "app.queue";
    public static final String ROUTING_KEY = "app.routing.key";
    public static final String DLX_EXCHANGE = "app.dlx.exchange";
    public static final String DLX_QUEUE = "app.dlx.queue";
    
    // 死信交换机
    @Bean
    public DirectExchange dlxExchange() {
        return new DirectExchange(DLX_EXCHANGE);
    }
    
    @Bean
    public Queue dlxQueue() {
        return QueueBuilder.durable(DLX_QUEUE).build();
    }
    
    @Bean
    public Binding dlxBinding() {
        return BindingBuilder.bind(dlxQueue()).to(dlxExchange()).with("dlx");
    }
    
    // 业务交换机和队列
    @Bean
    public DirectExchange exchange() {
        return new DirectExchange(EXCHANGE_NAME);
    }
    
    @Bean
    public Queue queue() {
        return QueueBuilder.durable(QUEUE_NAME)
            .withArgument("x-dead-letter-exchange", DLX_EXCHANGE)
            .withArgument("x-dead-letter-routing-key", "dlx")
            .withArgument("x-message-ttl", 60000)  // 消息过期时间
            .build();
    }
    
    @Bean
    public Binding binding() {
        return BindingBuilder.bind(queue()).to(exchange()).with(ROUTING_KEY);
    }
    
    @Bean
    public MessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }
    
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(messageConverter());
        template.setConfirmCallback((data, ack, cause) -> {
            if (!ack) {
                log.error("消息发送失败: {}", cause);
            }
        });
        template.setReturnsCallback(returned -> {
            log.error("消息被退回: {}", returned.getMessage());
        });
        return template;
    }
}
```

**生产者：**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class MessageProducer {
    
    private final RabbitTemplate rabbitTemplate;
    
    public void send(Object message) {
        String msgId = UUID.randomUUID().toString();
        rabbitTemplate.convertAndSend(
            RabbitMQConfig.EXCHANGE_NAME,
            RabbitMQConfig.ROUTING_KEY,
            message,
            msg -> {
                msg.getMessageProperties().setMessageId(msgId);
                msg.getMessageProperties().setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                return msg;
            }
        );
        log.info("消息发送成功, msgId: {}", msgId);
    }
}
```

**消费者：**
```java
@Component
@Slf4j
public class MessageConsumer {
    
    @RabbitListener(queues = RabbitMQConfig.QUEUE_NAME)
    public void receive(Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        String msgId = message.getMessageProperties().getMessageId();
        try {
            String body = new String(message.getBody());
            log.info("收到消息: {}, msgId: {}", body, msgId);
            
            // 业务处理...
            
            channel.basicAck(deliveryTag, false);  // 确认消息
        } catch (Exception e) {
            log.error("消息处理失败", e);
            channel.basicNack(deliveryTag, false, false);  // 拒绝消息，进入死信队列
        }
    }
}
```

##
# 2.2 Kafka

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.kafka</groupId>
    <artifactId>spring-kafka</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  kafka:
    bootstrap-servers: ${KAFKA_SERVERS:localhost:9092}
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer
      acks: all
      retries: 3
      batch-size: 16384
      buffer-memory: 33554432
    consumer:
      group-id: ${spring.application.name}
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      auto-offset-reset: earliest
      enable-auto-commit: false
      properties:
        spring.json.trusted.packages: "*"
    listener:
      ack-mode: manual_immediate
      concurrency: 3
```

**生产者：**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class KafkaProducer {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    
    public void send(String topic, String key, Object message) {
        kafkaTemplate.send(topic, key, message)
            .addCallback(
                result -> log.info("消息发送成功: topic={}, partition={}, offset={}",
                    result.getRecordMetadata().topic(),
                    result.getRecordMetadata().partition(),
                    result.getRecordMetadata().offset()),
                ex -> log.error("消息发送失败", ex)
            );
    }
}
```

**消费者：**
```java
@Component
@Slf4j
public class KafkaConsumer {
    
    @KafkaListener(topics = "my-topic", groupId = "my-group")
    public void consume(ConsumerRecord<String, Object> record, Acknowledgment ack) {
        try {
            log.info("收到消息: topic={}, partition={}, offset={}, key={}, value={}",
                record.topic(), record.partition(), record.offset(), record.key(), record.value());
            
            // 业务处理...
            
            ack.acknowledge();  // 手动提交
        } catch (Exception e) {
            log.error("消息处理失败", e);
            // 可以选择不提交，让消息重新消费
        }
    }
}
```

---

## 3. 安全集成

### 3.1 Spring Security (推荐配置)

> 注意：Spring Boot 2.7.x 中 `WebSecurityConfigurerAdapter` 已废弃，推荐使用组件化配置

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
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
```

**Security 配置 (Spring Boot 2.7+ 新方式)：**
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .cors().and()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeHttpRequests(auth -> auth
                .antMatchers("/api/auth/**", "/api/public/**").permitAll()
                .antMatchers("/actuator/health").permitAll()
                .antMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated()
            )
            .exceptionHandling()
                .authenticationEntryPoint((request, response, ex) -> {
                    response.setContentType("application/json;charset=UTF-8");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"code\":401,\"message\":\"未授权\"}");
                })
                .accessDeniedHandler((request, response, ex) -> {
                    response.setContentType("application/json;charset=UTF-8");
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("{\"code\":403,\"message\":\"禁止访问\"}");
                })
            .and()
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```


**JWT 工具类：**
```java
@Component
public class JwtUtil {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.expiration:86400000}")  // 默认24小时
    private long expiration;
    
    private Key key;
    
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
        return claimsResolver.apply(claims);
    }
    
    public boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    
    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}
```

**JWT 过滤器：**
```java
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String token = authHeader.substring(7);
        try {
            String username = jwtUtil.extractUsername(token);
            
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                if (jwtUtil.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            log.error("JWT 验证失败", e);
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### 3.2 CORS 配置

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

---

## 4. 缓存集成

### 4.1 Spring Cache + Redis

**使用示例：**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    
    private final UserRepository userRepository;
    
    @Cacheable(value = "users", key = "#id", unless = "#result == null")
    public User getById(Long id) {
        log.info("从数据库查询用户: {}", id);
        return userRepository.findById(id).orElse(null);
    }
    
    @CachePut(value = "users", key = "#user.id")
    public User update(User user) {
        return userRepository.save(user);
    }
    
    @CacheEvict(value = "users", key = "#id")
    public void delete(Long id) {
        userRepository.deleteById(id);
    }
    
    @CacheEvict(value = "users", allEntries = true)
    public void clearCache() {
        log.info("清除所有用户缓存");
    }
}
```

### 4.2 Caffeine 本地缓存

**Maven 依赖：**
```xml
<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>
```

**配置：**
```java
@Configuration
@EnableCaching
public class CaffeineCacheConfig {
    
    @Bean
    public CacheManager caffeineCacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(Caffeine.newBuilder()
            .initialCapacity(100)
            .maximumSize(1000)
            .expireAfterWrite(Duration.ofMinutes(10))
            .recordStats());
        return cacheManager;
    }
}
```


---

## 5. 任务调度集成

### 5.1 Spring Task

**启用配置：**
```java
@Configuration
@EnableScheduling
@EnableAsync
public class ScheduleConfig implements SchedulingConfigurer, AsyncConfigurer {
    
    @Override
    public void configureTasks(ScheduledTaskRegistrar taskRegistrar) {
        taskRegistrar.setScheduler(taskScheduler());
    }
    
    @Bean
    public ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(10);
        scheduler.setThreadNamePrefix("scheduled-");
        scheduler.setAwaitTerminationSeconds(60);
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        return scheduler;
    }
    
    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("async-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }
}
```

**定时任务：**
```java
@Component
@Slf4j
public class ScheduledTasks {
    
    // 固定频率执行 (上次开始后5秒)
    @Scheduled(fixedRate = 5000)
    public void fixedRateTask() {
        log.info("Fixed rate task - {}", LocalDateTime.now());
    }
    
    // 固定延迟执行 (上次结束后5秒)
    @Scheduled(fixedDelay = 5000)
    public void fixedDelayTask() {
        log.info("Fixed delay task - {}", LocalDateTime.now());
    }
    
    // Cron 表达式 (每天凌晨2点)
    @Scheduled(cron = "0 0 2 * * ?")
    public void cronTask() {
        log.info("Cron task - {}", LocalDateTime.now());
    }
    
    // 异步任务
    @Async
    @Scheduled(fixedRate = 10000)
    public void asyncTask() {
        log.info("Async task running in thread: {}", Thread.currentThread().getName());
    }
}
```

### 5.2 Quartz

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-quartz</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  quartz:
    job-store-type: jdbc  # 持久化到数据库
    jdbc:
      initialize-schema: always
    properties:
      org.quartz:
        scheduler:
          instanceName: MyScheduler
          instanceId: AUTO
        jobStore:
          class: org.quartz.impl.jdbcjobstore.JobStoreTX
          driverDelegateClass: org.quartz.impl.jdbcjobstore.StdJDBCDelegate
          tablePrefix: QRTZ_
          isClustered: true
          clusterCheckinInterval: 10000
        threadPool:
          class: org.quartz.simpl.SimpleThreadPool
          threadCount: 10
```

**Job 定义：**
```java
@Slf4j
public class SampleJob extends QuartzJobBean {
    
    @Autowired
    private SomeService someService;
    
    @Override
    protected void executeInternal(JobExecutionContext context) throws JobExecutionException {
        JobDataMap dataMap = context.getMergedJobDataMap();
        String param = dataMap.getString("param");
        log.info("执行任务, 参数: {}", param);
        someService.doSomething();
    }
}
```

**动态任务管理：**
```java
@Service
@RequiredArgsConstructor
public class QuartzService {
    
    private final Scheduler scheduler;
    
    public void addJob(String jobName, String groupName, String cron, Map<String, Object> params) 
            throws SchedulerException {
        JobDetail jobDetail = JobBuilder.newJob(SampleJob.class)
            .withIdentity(jobName, groupName)
            .usingJobData(new JobDataMap(params))
            .storeDurably()
            .build();
        
        CronTrigger trigger = TriggerBuilder.newTrigger()
            .withIdentity(jobName + "_trigger", groupName)
            .withSchedule(CronScheduleBuilder.cronSchedule(cron))
            .build();
        
        scheduler.scheduleJob(jobDetail, trigger);
    }
    
    public void pauseJob(String jobName, String groupName) throws SchedulerException {
        scheduler.pauseJob(JobKey.jobKey(jobName, groupName));
    }
    
    public void resumeJob(String jobName, String groupName) throws SchedulerException {
        scheduler.resumeJob(JobKey.jobKey(jobName, groupName));
    }
    
    public void deleteJob(String jobName, String groupName) throws SchedulerException {
        scheduler.deleteJob(JobKey.jobKey(jobName, groupName));
    }
}
```


---

## 6. 监控与日志集成

### 6.1 Spring Boot Actuator

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

**配置：**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus,loggers,env
      base-path: /actuator
  endpoint:
    health:
      show-details: when_authorized
      show-components: when_authorized
  info:
    env:
      enabled: true

info:
  app:
    name: ${spring.application.name}
    version: '@project.version@'
    java-version: ${java.version}
```

### 6.2 Prometheus + Grafana

**Maven 依赖：**
```xml
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>
```

**自定义指标：**
```java
@Component
@RequiredArgsConstructor
public class CustomMetrics {
    
    private final MeterRegistry meterRegistry;
    
    private Counter requestCounter;
    private Timer requestTimer;
    
    @PostConstruct
    public void init() {
        requestCounter = Counter.builder("app.requests.total")
            .description("Total requests")
            .tag("application", "my-app")
            .register(meterRegistry);
        
        requestTimer = Timer.builder("app.requests.duration")
            .description("Request duration")
            .tag("application", "my-app")
            .register(meterRegistry);
    }
    
    public void incrementRequestCount() {
        requestCounter.increment();
    }
    
    public void recordRequestDuration(long durationMs) {
        requestTimer.record(Duration.ofMillis(durationMs));
    }
}
```

### 6.3 Logback 配置

**logback-spring.xml：**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration scan="true" scanPeriod="30 seconds">
    
    <springProperty scope="context" name="APP_NAME" source="spring.application.name" defaultValue="app"/>
    
    <!-- 控制台输出 -->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
        </encoder>
    </appender>
    
    <!-- 文件输出 -->
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/${APP_NAME}.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <fileNamePattern>logs/${APP_NAME}.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
            <maxFileSize>100MB</maxFileSize>
            <maxHistory>30</maxHistory>
            <totalSizeCap>3GB</totalSizeCap>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
        </encoder>
    </appender>
    
    <!-- 异步输出 -->
    <appender name="ASYNC_FILE" class="ch.qos.logback.classic.AsyncAppender">
        <discardingThreshold>0</discardingThreshold>
        <queueSize>512</queueSize>
        <appender-ref ref="FILE"/>
    </appender>
    
    <!-- JSON 格式 (用于 ELK) -->
    <appender name="JSON_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/${APP_NAME}-json.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
            <fileNamePattern>logs/${APP_NAME}-json.%d{yyyy-MM-dd}.%i.log.gz</fileNamePattern>
            <maxFileSize>100MB</maxFileSize>
            <maxHistory>7</maxHistory>
        </rollingPolicy>
        <encoder class="net.logstash.logback.encoder.LogstashEncoder">
            <customFields>{"app":"${APP_NAME}"}</customFields>
        </encoder>
    </appender>
    
    <springProfile name="dev">
        <root level="DEBUG">
            <appender-ref ref="CONSOLE"/>
        </root>
    </springProfile>
    
    <springProfile name="prod">
        <root level="INFO">
            <appender-ref ref="CONSOLE"/>
            <appender-ref ref="ASYNC_FILE"/>
        </root>
    </springProfile>
</configuration>
```


---

## 7. API文档集成

### 7.1 SpringDoc OpenAPI (推荐)

> Spring Boot 2.7.x 推荐使用 springdoc-openapi 替代 springfox

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-ui</artifactId>
    <version>1.7.0</version>
</dependency>
```

**配置：**
```yaml
springdoc:
  api-docs:
    path: /v3/api-docs
    enabled: true
  swagger-ui:
    path: /swagger-ui.html
    enabled: true
    operations-sorter: method
    tags-sorter: alpha
  packages-to-scan: com.example.controller
  paths-to-match: /api/**
```

**配置类：**
```java
@Configuration
public class OpenApiConfig {
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("API 文档")
                .version("1.0.0")
                .description("Spring Boot 2.7.x API 文档")
                .contact(new Contact()
                    .name("开发团队")
                    .email("dev@example.com")))
            .addSecurityItem(new SecurityRequirement().addList("Bearer"))
            .components(new Components()
                .addSecuritySchemes("Bearer", new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")));
    }
}
```

**Controller 示例：**
```java
@RestController
@RequestMapping("/api/users")
@Tag(name = "用户管理", description = "用户相关接口")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    @Operation(summary = "获取用户列表", description = "分页获取用户列表")
    @Parameters({
        @Parameter(name = "page", description = "页码", example = "1"),
        @Parameter(name = "size", description = "每页数量", example = "10")
    })
    @GetMapping
    public Result<Page<UserVO>> list(
            @RequestParam(defaultValue = "1") Integer page,
            @RequestParam(defaultValue = "10") Integer size) {
        return Result.success(userService.page(page, size));
    }
    
    @Operation(summary = "获取用户详情")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "成功"),
        @ApiResponse(responseCode = "404", description = "用户不存在")
    })
    @GetMapping("/{id}")
    public Result<UserVO> getById(@PathVariable Long id) {
        return Result.success(userService.getById(id));
    }
    
    @Operation(summary = "创建用户")
    @PostMapping
    public Result<UserVO> create(@Valid @RequestBody UserCreateDTO dto) {
        return Result.success(userService.create(dto));
    }
}
```

---

## 8. 模板引擎集成

### 8.1 Thymeleaf

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  thymeleaf:
    cache: false  # 开发环境关闭缓存
    prefix: classpath:/templates/
    suffix: .html
    mode: HTML
    encoding: UTF-8
```

**模板示例：**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title th:text="${title}">默认标题</title>
</head>
<body>
    <div th:fragment="header">
        <nav>
            <a th:href="@{/}">首页</a>
            <span th:if="${user != null}" th:text="${user.name}"></span>
        </nav>
    </div>
    
    <main>
        <table>
            <tr th:each="item : ${items}">
                <td th:text="${item.name}"></td>
                <td th:text="${#dates.format(item.createdAt, 'yyyy-MM-dd HH:mm')}"></td>
            </tr>
        </table>
    </main>
</body>
</html>
```

-
--

## 9. 分布式系统集成

### 9.1 Spring Cloud (2021.0.x 兼容 Spring Boot 2.7.x)

**版本对应：**
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>2021.0.8</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### 9.2 Nacos (服务发现 + 配置中心)

**Maven 依赖：**
```xml
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
</dependency>
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
</dependency>
```

**配置 (bootstrap.yml)：**
```yaml
spring:
  application:
    name: my-service
  cloud:
    nacos:
      discovery:
        server-addr: ${NACOS_SERVER:localhost:8848}
        namespace: ${NACOS_NAMESPACE:}
      config:
        server-addr: ${NACOS_SERVER:localhost:8848}
        namespace: ${NACOS_NAMESPACE:}
        file-extension: yaml
        refresh-enabled: true
```

### 9.3 OpenFeign (服务调用)

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```

**启用：**
```java
@SpringBootApplication
@EnableFeignClients
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

**Feign Client：**
```java
@FeignClient(name = "user-service", fallbackFactory = UserClientFallbackFactory.class)
public interface UserClient {
    
    @GetMapping("/api/users/{id}")
    Result<UserVO> getById(@PathVariable("id") Long id);
    
    @PostMapping("/api/users")
    Result<UserVO> create(@RequestBody UserCreateDTO dto);
}

@Component
@Slf4j
public class UserClientFallbackFactory implements FallbackFactory<UserClient> {
    
    @Override
    public UserClient create(Throwable cause) {
        log.error("调用 user-service 失败", cause);
        return new UserClient() {
            @Override
            public Result<UserVO> getById(Long id) {
                return Result.fail("服务暂不可用");
            }
            
            @Override
            public Result<UserVO> create(UserCreateDTO dto) {
                return Result.fail("服务暂不可用");
            }
        };
    }
}
```

### 9.4 Sentinel (流量控制)

**Maven 依赖：**
```xml
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-sentinel</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  cloud:
    sentinel:
      transport:
        dashboard: localhost:8080
        port: 8719
      eager: true
```

**使用示例：**
```java
@RestController
@RequestMapping("/api")
public class ApiController {
    
    @GetMapping("/resource")
    @SentinelResource(value = "resource", 
        blockHandler = "handleBlock", 
        fallback = "handleFallback")
    public Result<String> resource() {
        return Result.success("OK");
    }
    
    public Result<String> handleBlock(BlockException ex) {
        return Result.fail("请求被限流");
    }
    
    public Result<String> handleFallback(Throwable ex) {
        return Result.fail("服务降级");
    }
}
```

---

#
# 10. 测试集成

### 10.1 单元测试 (JUnit 5 + Mockito)

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

**Service 层测试：**
```java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @InjectMocks
    private UserServiceImpl userService;
    
    @Test
    @DisplayName("根据ID查询用户 - 用户存在")
    void getById_WhenUserExists_ReturnsUser() {
        // Given
        User user = User.builder().id(1L).username("test").build();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        
        // When
        User result = userService.getById(1L);
        
        // Then
        assertNotNull(result);
        assertEquals("test", result.getUsername());
        verify(userRepository, times(1)).findById(1L);
    }
    
    @Test
    @DisplayName("根据ID查询用户 - 用户不存在")
    void getById_WhenUserNotExists_ThrowsException() {
        // Given
        when(userRepository.findById(anyLong())).thenReturn(Optional.empty());
        
        // When & Then
        assertThrows(ResourceNotFoundException.class, () -> userService.getById(999L));
    }
}
```

### 10.2 集成测试

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Transactional
class UserControllerIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    @DisplayName("创建用户 - 成功")
    void createUser_Success() throws Exception {
        UserCreateDTO dto = new UserCreateDTO();
        dto.setUsername("newuser");
        dto.setEmail("new@example.com");
        dto.setPassword("password123");
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(dto)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").value(200))
            .andExpect(jsonPath("$.data.username").value("newuser"));
    }
    
    @Test
    @DisplayName("获取用户列表 - 分页")
    void listUsers_WithPagination() throws Exception {
        mockMvc.perform(get("/api/users")
                .param("page", "1")
                .param("size", "10"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").value(200))
            .andExpect(jsonPath("$.data.content").isArray());
    }
}
```

### 10.3 TestContainers (数据库集成测试)

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>testcontainers</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>mysql</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>junit-jupiter</artifactId>
    <scope>test</scope>
</dependency>
```

**测试配置：**
```java
@SpringBootTest
@Testcontainers
class UserRepositoryTest {
    
    @Container
    static MySQLContainer<?> mysql = new MySQLContainer<>("mysql:8.0")
        .withDatabaseName("testdb")
        .withUsername("test")
        .withPassword("test");
    
    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", mysql::getJdbcUrl);
        registry.add("spring.datasource.username", mysql::getUsername);
        registry.add("spring.datasource.password", mysql::getPassword);
    }
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    void testSaveAndFind() {
        User user = User.builder().username("test").email("test@example.com").build();
        User saved = userRepository.save(user);
        
        Optional<User> found = userRepository.findById(saved.getId());
        assertTrue(found.isPresent());
        assertEquals("test", found.get().getUsername());
    }
}
```

---


## 11. 配置管理集成

### 11.1 多环境配置

**目录结构：**
```
src/main/resources/
├── application.yml           # 公共配置
├── application-dev.yml       # 开发环境
├── application-test.yml      # 测试环境
└── application-prod.yml      # 生产环境
```

**application.yml：**
```yaml
spring:
  application:
    name: my-app
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}

server:
  port: ${SERVER_PORT:8080}
  servlet:
    context-path: /

# 公共配置
app:
  name: ${spring.application.name}
  version: '@project.version@'
```

**配置属性类：**
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "app")
@Validated
public class AppProperties {
    
    @NotBlank
    private String name;
    
    private String version;
    
    @Valid
    private Security security = new Security();
    
    @Data
    public static class Security {
        private String jwtSecret = "defaultSecret";
        private long jwtExpiration = 86400000;
    }
}
```

### 11.2 配置加密 (Jasypt)

**Maven 依赖：**
```xml
<dependency>
    <groupId>com.github.ulisesbocchio</groupId>
    <artifactId>jasypt-spring-boot-starter</artifactId>
    <version>3.0.5</version>
</dependency>
```

**配置：**
```yaml
jasypt:
  encryptor:
    password: ${JASYPT_PASSWORD:mySecretKey}
    algorithm: PBEWithMD5AndDES

spring:
  datasource:
    password: ENC(加密后的密码)
```

---

## 12. 容器化与部署

### 12.1 Dockerfile (多阶段构建)

```dockerfile
# 构建阶段
FROM maven:3.8-openjdk-8-slim AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn package -DskipTests -B

# 运行阶段
FROM openjdk:8-jre-slim
WORKDIR /app

# 创建非 root 用户
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# 复制 jar 文件
COPY --from=builder /app/target/*.jar app.jar

# 设置权限
RUN chown -R appuser:appgroup /app
USER appuser

# JVM 参数
ENV JAVA_OPTS="-Xms512m -Xmx512m -XX:+UseG1GC -XX:+HeapDumpOnOutOfMemoryError"

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

### 12.2 Docker Compose

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - DB_HOST=mysql
      - REDIS_HOST=redis
    depends_on:
      - mysql
      - redis
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: mydb
      MYSQL_USER: appuser
      MYSQL_PASSWORD: apppassword
    volumes:
      - mysql-data:/var/lib/mysql
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - app-network

volumes:
  mysql-data:
  redis-data:

networks:
  app-network:
    driver: bridge
```

### 12.3 Kubernetes 部署

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    app: my-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
        - name: my-app
          image: my-app:latest
          ports:
            - containerPort: 8080
          env:
            - name: SPRING_PROFILES_ACTIVE
              value: "prod"
            - name: JAVA_OPTS
              value: "-Xms512m -Xmx512m"
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: my-app-service
spec:
  selector:
    app: my-app
  ports:
    - port: 80
      targetPort: 8080
  type: ClusterIP
```

-
--

## 13. 开发工具集成

### 13.1 Lombok

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
```

**常用注解：**
```java
@Data                    // @Getter + @Setter + @ToString + @EqualsAndHashCode + @RequiredArgsConstructor
@Builder                 // 构建者模式
@NoArgsConstructor       // 无参构造
@AllArgsConstructor      // 全参构造
@RequiredArgsConstructor // final 字段构造
@Slf4j                   // 日志
@Value                   // 不可变类
@Accessors(chain = true) // 链式调用
```

### 13.2 MapStruct (对象映射)

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.mapstruct</groupId>
    <artifactId>mapstruct</artifactId>
    <version>1.5.5.Final</version>
</dependency>

<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <configuration>
        <annotationProcessorPaths>
            <path>
                <groupId>org.mapstruct</groupId>
                <artifactId>mapstruct-processor</artifactId>
                <version>1.5.5.Final</version>
            </path>
            <path>
                <groupId>org.projectlombok</groupId>
                <artifactId>lombok</artifactId>
                <version>${lombok.version}</version>
            </path>
            <path>
                <groupId>org.projectlombok</groupId>
                <artifactId>lombok-mapstruct-binding</artifactId>
                <version>0.2.0</version>
            </path>
        </annotationProcessorPaths>
    </configuration>
</plugin>
```

**Mapper 定义：**
```java
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {
    
    UserVO toVO(User user);
    
    List<UserVO> toVOList(List<User> users);
    
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    User toEntity(UserCreateDTO dto);
    
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateEntity(UserUpdateDTO dto, @MappingTarget User user);
}
```

### 13.3 数据库迁移 (Flyway)

**Maven 依赖：**
```xml
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-core</artifactId>
</dependency>
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-mysql</artifactId>
</dependency>
```

**配置：**
```yaml
spring:
  flyway:
    enabled: true
    locations: classpath:db/migration
    baseline-on-migrate: true
    validate-on-migrate: true
```

**迁移脚本 (V1__init.sql)：**
```sql
-- V1__init.sql
CREATE TABLE IF NOT EXISTS t_user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    version INT DEFAULT 0,
    INDEX idx_email (email),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 13.4 统一响应封装

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Result<T> implements Serializable {
    
    private Integer code;
    private String message;
    private T data;
    private Long timestamp;
    
    public static <T> Result<T> success() {
        return success(null);
    }
    
    public static <T> Result<T> success(T data) {
        return Result.<T>builder()
            .code(200)
            .message("success")
            .data(data)
            .timestamp(System.currentTimeMillis())
            .build();
    }
    
    public static <T> Result<T> fail(String message) {
        return fail(500, message);
    }
    
    public static <T> Result<T> fail(Integer code, String message) {
        return Result.<T>builder()
            .code(code)
            .message(message)
            .timestamp(System.currentTimeMillis())
            .build();
    }
}
```

### 13.5 全局异常处理

```java
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Result<Void> handleValidationException(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
            .map(error -> error.getField() + ": " + error.getDefaultMessage())
            .collect(Collectors.joining(", "));
        return Result.fail(400, message);
    }
    
    @ExceptionHandler(ConstraintViolationException.class)
    public Result<Void> handleConstraintViolation(ConstraintViolationException e) {
        String message = e.getConstraintViolations().stream()
            .map(ConstraintViolation::getMessage)
            .collect(Collectors.joining(", "));
        return Result.fail(400, message);
    }
    
    @ExceptionHandler(BusinessException.class)
    public Result<Void> handleBusinessException(BusinessException e) {
        log.warn("业务异常: {}", e.getMessage());
        return Result.fail(e.getCode(), e.getMessage());
    }
    
    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("系统异常", e);
        return Result.fail(500, "系统繁忙，请稍后重试");
    }
}

@Getter
public class BusinessException extends RuntimeException {
    private final Integer code;
    
    public BusinessException(String message) {
        this(500, message);
    }
    
    public BusinessException(Integer code, String message) {
        super(message);
        this.code = code;
    }
}
```


---

## 附录

### A. 推荐 Maven 依赖版本 (Spring Boot 2.7.18)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.18</version>
    </parent>
    
    <properties>
        <java.version>1.8</java.version>
        <mybatis-plus.version>3.5.3.1</mybatis-plus.version>
        <springdoc.version>1.7.0</springdoc.version>
        <mapstruct.version>1.5.5.Final</mapstruct.version>
        <jjwt.version>0.11.5</jjwt.version>
    </properties>
    
    <dependencies>
        <!-- Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- Validation -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        
        <!-- AOP -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-aop</artifactId>
        </dependency>
        
        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        
        <!-- DevTools -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>
        
        <!-- Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

### B. 常用配置模板

**application.yml 完整模板：**
```yaml
server:
  port: ${SERVER_PORT:8080}
  servlet:
    context-path: /
  tomcat:
    max-threads: 200
    min-spare-threads: 10
    accept-count: 100
    connection-timeout: 10000

spring:
  application:
    name: my-app
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}
  
  # Jackson
  jackson:
    date-format: yyyy-MM-dd HH:mm:ss
    time-zone: Asia/Shanghai
    default-property-inclusion: non_null
    serialization:
      write-dates-as-timestamps: false
  
  # 文件上传
  servlet:
    multipart:
      max-file-size: 10MB
      max-request-size: 50MB

# 日志
logging:
  level:
    root: INFO
    com.example: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{50} - %msg%n"
```

### C. 项目结构推荐

```
src/main/java/com/example/
├── Application.java              # 启动类
├── config/                       # 配置类
│   ├── SecurityConfig.java
│   ├── RedisConfig.java
│   └── WebMvcConfig.java
├── controller/                   # 控制器
│   └── UserController.java
├── service/                      # 服务层
│   ├── UserService.java
│   └── impl/
│       └── UserServiceImpl.java
├── repository/                   # 数据访问层
│   └── UserRepository.java
├── entity/                       # 实体类
│   └── User.java
├── dto/                          # 数据传输对象
│   ├── UserCreateDTO.java
│   └── UserQueryDTO.java
├── vo/                           # 视图对象
│   └── UserVO.java
├── mapper/                       # 对象映射
│   └── UserMapper.java
├── common/                       # 公共模块
│   ├── Result.java
│   ├── PageResult.java
│   └── Constants.java
├── exception/                    # 异常处理
│   ├── BusinessException.java
│   └── GlobalExceptionHandler.java
└── util/                         # 工具类
    ├── JwtUtil.java
    └── RedisUtil.java
```

---

> 最后更新：2024年
> 
> 适用版本：Java 8 + Spring Boot 2.7.18
