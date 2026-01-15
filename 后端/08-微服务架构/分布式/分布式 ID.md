

> 分布式 ID 是分布式系统中用于唯一标识数据的关键技术
> 本笔记涵盖主流分布式 ID 生成方案，从原理到实战

---

## 目录

1. [基础概念](#1-基础概念)
2. [UUID 方案](#2-uuid-方案)
3. [数据库自增方案](#3-数据库自增方案)
4. [数据库号段模式](#4-数据库号段模式)
5. [Redis 方案](#5-redis-方案)
6. [雪花算法](#6-雪花算法)
7. [Leaf 方案](#7-leaf-方案)
8. [UidGenerator 方案](#8-uidgenerator-方案)
9. [Tinyid 方案](#9-tinyid-方案)
10. [MongoDB ObjectId](#10-mongodb-objectid)
11. [方案对比与选型](#11-方案对比与选型)
12. [生产环境最佳实践](#12-生产环境最佳实践)
13. [常见错误与解决方案](#13-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 为什么需要分布式 ID？

在单机系统中，我们通常使用数据库自增 ID 来标识数据。但在分布式系统中，这种方式会遇到问题：

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   服务 A    │     │   服务 B    │     │   服务 C    │
│   ID: 1     │     │   ID: 1     │     │   ID: 1     │
│   ID: 2     │     │   ID: 2     │     │   ID: 2     │
└─────────────┘     └─────────────┘     └─────────────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                    ┌─────────────┐
                    │  数据合并   │
                    │  ID 冲突！  │
                    └─────────────┘
```

**典型场景：**
- 分库分表后，各表的自增 ID 会重复
- 微服务架构中，多个服务需要生成唯一订单号
- 数据迁移、合并时需要保证 ID 不冲突
- 消息队列中的消息需要唯一标识

### 1.2 分布式 ID 的核心要求

| 要求 | 说明 | 重要程度 |
|-----|------|---------|
| **全局唯一** | 不同节点生成的 ID 不能重复 | ⭐⭐⭐⭐⭐ |
| **趋势递增** | ID 大致按时间递增，利于数据库索引 | ⭐⭐⭐⭐ |
| **高可用** | 服务不能成为单点故障 | ⭐⭐⭐⭐⭐ |
| **高性能** | 生成速度快，延迟低 | ⭐⭐⭐⭐ |
| **信息安全** | 不暴露业务信息（如订单量） | ⭐⭐⭐ |


### 1.3 ID 类型分类

```
分布式 ID
├── 字符串类型
│   ├── UUID（36位）
│   ├── MongoDB ObjectId（24位）
│   └── 自定义编码（如订单号）
│
└── 数字类型
    ├── 64位 Long（雪花算法）
    ├── 数据库自增
    └── Redis 自增
```

**数字 ID vs 字符串 ID：**

| 特性 | 数字 ID | 字符串 ID |
|-----|--------|----------|
| 存储空间 | 8 字节 | 16-36 字节 |
| 索引效率 | 高 | 较低 |
| 可读性 | 差 | 较好 |
| 排序性能 | 高 | 较低 |
| 信息隐藏 | 差 | 好 |

> 💡 **建议**：数据库主键优先使用数字类型，对外暴露的业务 ID 可以使用字符串类型。

---

## 2. UUID 方案

### 2.1 什么是 UUID？

UUID（Universally Unique Identifier）是一种 128 位的标识符，通常表示为 36 个字符的字符串。

```
550e8400-e29b-41d4-a716-446655440000
    │       │    │    │       │
    │       │    │    │       └── 随机数
    │       │    │    └── 节点标识
    │       │    └── 版本号（第13位）
    │       └── 时间戳
    └── 时间戳
```

### 2.2 UUID 版本

| 版本 | 生成方式 | 特点 |
|-----|---------|------|
| v1 | 时间戳 + MAC 地址 | 可能暴露 MAC 地址 |
| v2 | DCE 安全 | 很少使用 |
| v3 | MD5 哈希 | 基于命名空间 |
| v4 | 随机数 | **最常用** |
| v5 | SHA-1 哈希 | 基于命名空间 |

### 2.3 Java 实现

```java
import java.util.UUID;

public class UUIDGenerator {
    
    /**
     * 生成标准 UUID（v4）
     * 示例：550e8400-e29b-41d4-a716-446655440000
     */
    public static String generateUUID() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * 生成不带横线的 UUID
     * 示例：550e8400e29b41d4a716446655440000
     */
    public static String generateSimpleUUID() {
        return UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * 基于名称生成 UUID（v3/v5）
     * 相同的名称会生成相同的 UUID
     */
    public static String generateNameBasedUUID(String name) {
        return UUID.nameUUIDFromBytes(name.getBytes()).toString();
    }
    
    public static void main(String[] args) {
        // 生成 10 个 UUID
        for (int i = 0; i < 10; i++) {
            System.out.println(generateUUID());
        }
    }
}
```


### 2.4 其他语言实现

```python
# Python
import uuid

# v4 随机 UUID
print(uuid.uuid4())  # 550e8400-e29b-41d4-a716-446655440000

# v1 时间戳 UUID
print(uuid.uuid1())

# v5 基于名称
print(uuid.uuid5(uuid.NAMESPACE_DNS, 'example.com'))
```

```javascript
// Node.js
const { v4: uuidv4, v1: uuidv1 } = require('uuid');

console.log(uuidv4());  // 随机 UUID
console.log(uuidv1());  // 时间戳 UUID

// 浏览器原生支持（现代浏览器）
console.log(crypto.randomUUID());
```

```go
// Go
package main

import (
    "fmt"
    "github.com/google/uuid"
)

func main() {
    id := uuid.New()
    fmt.Println(id.String())
}
```

### 2.5 UUID 优缺点

**优点：**
- ✅ 本地生成，无网络开销
- ✅ 性能极高，无并发问题
- ✅ 全球唯一，无需协调

**缺点：**
- ❌ 36 字符太长，占用存储空间
- ❌ 无序，作为主键会导致 B+ 树频繁分裂
- ❌ 不可读，不便于调试
- ❌ 无法排序，无法体现生成顺序

> ⚠️ **重要**：UUID 作为 MySQL 主键会严重影响性能！InnoDB 使用聚簇索引，无序的 UUID 会导致频繁的页分裂。

### 2.6 UUID 性能问题演示

```sql
-- 创建测试表
CREATE TABLE test_uuid (
    id VARCHAR(36) PRIMARY KEY,
    data VARCHAR(100)
);

CREATE TABLE test_bigint (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    data VARCHAR(100)
);

-- 插入 100 万条数据后对比
-- UUID 表：插入慢 3-5 倍，查询慢 2-3 倍
-- 原因：UUID 无序导致随机 IO，B+ 树频繁分裂重组
```

---

## 3. 数据库自增方案

### 3.1 单机自增

最简单的方案，利用数据库的 AUTO_INCREMENT 特性：

```sql
CREATE TABLE id_generator (
    id BIGINT NOT NULL AUTO_INCREMENT,
    stub CHAR(1) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY stub (stub)
) ENGINE=InnoDB;

-- 获取 ID
REPLACE INTO id_generator (stub) VALUES ('a');
SELECT LAST_INSERT_ID();
```

**为什么用 REPLACE INTO？**
- `REPLACE INTO` 会先删除再插入，触发自增
- `stub` 字段保证表中只有一行数据，避免表无限增长


### 3.2 多主集群方案

单机存在单点故障，可以使用多个数据库实例，通过设置不同的起始值和步长来避免冲突：

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   MySQL 1   │     │   MySQL 2   │     │   MySQL 3   │
│  起始值: 1  │     │  起始值: 2  │     │  起始值: 3  │
│  步长: 3    │     │  步长: 3    │     │  步长: 3    │
│             │     │             │     │             │
│  1, 4, 7... │     │  2, 5, 8... │     │  3, 6, 9... │
└─────────────┘     └─────────────┘     └─────────────┘
```

```sql
-- MySQL 1 配置
SET @@auto_increment_offset = 1;
SET @@auto_increment_increment = 3;

-- MySQL 2 配置
SET @@auto_increment_offset = 2;
SET @@auto_increment_increment = 3;

-- MySQL 3 配置
SET @@auto_increment_offset = 3;
SET @@auto_increment_increment = 3;
```

### 3.3 Java 实现

```java
import java.sql.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DatabaseIdGenerator {
    
    private static final String[] DB_URLS = {
        "jdbc:mysql://db1:3306/id_db",
        "jdbc:mysql://db2:3306/id_db",
        "jdbc:mysql://db3:3306/id_db"
    };
    
    private static final AtomicInteger counter = new AtomicInteger(0);
    
    /**
     * 轮询获取 ID（简单负载均衡）
     */
    public static long generateId() throws SQLException {
        int index = counter.getAndIncrement() % DB_URLS.length;
        return getIdFromDatabase(DB_URLS[index]);
    }
    
    private static long getIdFromDatabase(String url) throws SQLException {
        try (Connection conn = DriverManager.getConnection(url, "user", "password");
             Statement stmt = conn.createStatement()) {
            
            stmt.executeUpdate("REPLACE INTO id_generator (stub) VALUES ('a')");
            
            try (ResultSet rs = stmt.executeQuery("SELECT LAST_INSERT_ID()")) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        }
        throw new SQLException("Failed to generate ID");
    }
}
```

### 3.4 优缺点分析

**优点：**
- ✅ 实现简单，易于理解
- ✅ ID 有序递增
- ✅ 数字类型，存储和索引效率高

**缺点：**
- ❌ 依赖数据库，存在单点风险
- ❌ 每次获取 ID 都需要访问数据库，性能瓶颈
- ❌ 扩展困难，增加节点需要重新配置步长
- ❌ 数据库压力大，高并发场景不适用

> 💡 **适用场景**：并发量不高（QPS < 1000）的中小型系统。

---

## 4. 数据库号段模式

### 4.1 核心思想

号段模式是对数据库自增方案的优化。不再每次都访问数据库，而是一次性获取一批 ID（号段），在内存中分配：

```
┌─────────────────────────────────────────────────────────┐
│                      应用服务器                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │              内存号段缓存                         │   │
│  │  当前号段: [1001, 2000]  下一个: 1500            │   │
│  │  下一号段: [2001, 3000]  (预加载)                │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                           │
                           │ 号段用完时批量获取
                           ▼
                    ┌─────────────┐
                    │   数据库    │
                    │  max_id     │
                    └─────────────┘
```


### 4.2 数据库表设计

```sql
CREATE TABLE id_segment (
    biz_tag VARCHAR(128) NOT NULL COMMENT '业务标识',
    max_id BIGINT NOT NULL DEFAULT 1 COMMENT '当前最大ID',
    step INT NOT NULL DEFAULT 1000 COMMENT '号段步长',
    description VARCHAR(256) COMMENT '描述',
    update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (biz_tag)
) ENGINE=InnoDB;

-- 初始化业务号段
INSERT INTO id_segment (biz_tag, max_id, step, description) VALUES
('order', 1, 1000, '订单ID'),
('user', 1, 500, '用户ID'),
('product', 1, 2000, '商品ID');
```

### 4.3 获取号段的 SQL

```sql
-- 使用乐观锁获取号段
UPDATE id_segment 
SET max_id = max_id + step 
WHERE biz_tag = 'order';

SELECT max_id, step 
FROM id_segment 
WHERE biz_tag = 'order';

-- 返回的 max_id 就是新号段的结束值
-- 新号段范围: [max_id - step + 1, max_id]
```

### 4.4 Java 完整实现

```java
import java.sql.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

public class SegmentIdGenerator {
    
    private final String bizTag;
    private final String jdbcUrl;
    private final ReentrantLock lock = new ReentrantLock();
    
    // 当前号段
    private volatile AtomicLong currentId;
    private volatile long currentMaxId;
    
    // 下一个号段（双缓冲）
    private volatile AtomicLong nextId;
    private volatile long nextMaxId;
    private volatile boolean nextReady = false;
    
    // 当号段使用到 50% 时，异步加载下一个号段
    private static final double LOAD_FACTOR = 0.5;
    
    public SegmentIdGenerator(String bizTag, String jdbcUrl) {
        this.bizTag = bizTag;
        this.jdbcUrl = jdbcUrl;
        loadSegment();
    }
    
    /**
     * 获取下一个 ID
     */
    public long nextId() {
        while (true) {
            long id = currentId.getAndIncrement();
            
            if (id <= currentMaxId) {
                // 检查是否需要预加载下一个号段
                checkAndLoadNext(id);
                return id;
            }
            
            // 当前号段用完，切换到下一个号段
            switchToNextSegment();
        }
    }
    
    /**
     * 检查并异步加载下一个号段
     */
    private void checkAndLoadNext(long currentValue) {
        if (!nextReady) {
            long threshold = (long) ((currentMaxId - currentId.get()) * LOAD_FACTOR);
            if (currentValue >= currentMaxId - threshold) {
                // 异步加载
                new Thread(this::loadNextSegment).start();
            }
        }
    }
    
    /**
     * 切换到下一个号段
     */
    private void switchToNextSegment() {
        lock.lock();
        try {
            // 双重检查
            if (currentId.get() > currentMaxId) {
                if (nextReady) {
                    currentId = nextId;
                    currentMaxId = nextMaxId;
                    nextReady = false;
                } else {
                    // 下一个号段还没准备好，同步加载
                    loadSegment();
                }
            }
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * 从数据库加载号段
     */
    private void loadSegment() {
        lock.lock();
        try {
            long[] segment = fetchSegmentFromDB();
            currentId = new AtomicLong(segment[0]);
            currentMaxId = segment[1];
        } finally {
            lock.unlock();
        }
    }
    
    private void loadNextSegment() {
        if (nextReady) return;
        
        lock.lock();
        try {
            if (!nextReady) {
                long[] segment = fetchSegmentFromDB();
                nextId = new AtomicLong(segment[0]);
                nextMaxId = segment[1];
                nextReady = true;
            }
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * 从数据库获取号段
     * @return [起始ID, 结束ID]
     */
    private long[] fetchSegmentFromDB() {
        try (Connection conn = DriverManager.getConnection(jdbcUrl, "user", "password")) {
            conn.setAutoCommit(false);
            
            // 更新并获取新号段
            try (PreparedStatement updateStmt = conn.prepareStatement(
                    "UPDATE id_segment SET max_id = max_id + step WHERE biz_tag = ?")) {
                updateStmt.setString(1, bizTag);
                updateStmt.executeUpdate();
            }
            
            try (PreparedStatement selectStmt = conn.prepareStatement(
                    "SELECT max_id, step FROM id_segment WHERE biz_tag = ?")) {
                selectStmt.setString(1, bizTag);
                try (ResultSet rs = selectStmt.executeQuery()) {
                    if (rs.next()) {
                        long maxId = rs.getLong("max_id");
                        int step = rs.getInt("step");
                        conn.commit();
                        return new long[]{maxId - step + 1, maxId};
                    }
                }
            }
            
            conn.rollback();
            throw new RuntimeException("Failed to fetch segment for: " + bizTag);
        } catch (SQLException e) {
            throw new RuntimeException("Database error", e);
        }
    }
}
```


### 4.5 双缓冲优化

双缓冲是号段模式的关键优化，避免号段用完时的等待：

```
时间线 ─────────────────────────────────────────────────────►

号段1: [1, 1000]
████████████████████████████████████████
                    │
                    │ 使用到 50%，异步加载号段2
                    ▼
号段2: [1001, 2000]
                    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
                                        │
                                        │ 号段1用完，无缝切换
                                        ▼
                    ████████████████████████████████████████
```

### 4.6 优缺点分析

**优点：**
- ✅ 大幅减少数据库访问（1000 次 ID 只需 1 次 DB 访问）
- ✅ ID 有序递增
- ✅ 双缓冲保证高可用

**缺点：**
- ❌ 服务重启会浪费号段
- ❌ 仍依赖数据库
- ❌ 实现相对复杂

---

## 5. Redis 方案

### 5.1 基本原理

利用 Redis 的 INCR 命令原子性递增：

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   服务 A    │     │   服务 B    │     │   服务 C    │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │    INCR id:order  │                   │
       └───────────────────┼───────────────────┘
                           ▼
                    ┌─────────────┐
                    │    Redis    │
                    │  id:order   │
                    │    = 1001   │
                    └─────────────┘
```

### 5.2 基础实现

```java
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

public class RedisIdGenerator {
    
    private final JedisPool jedisPool;
    private final String keyPrefix;
    
    public RedisIdGenerator(JedisPool jedisPool, String keyPrefix) {
        this.jedisPool = jedisPool;
        this.keyPrefix = keyPrefix;
    }
    
    /**
     * 获取下一个 ID
     */
    public long nextId(String bizTag) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = keyPrefix + ":" + bizTag;
            return jedis.incr(key);
        }
    }
    
    /**
     * 批量获取 ID（减少网络开销）
     */
    public long[] nextIds(String bizTag, int count) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = keyPrefix + ":" + bizTag;
            long endId = jedis.incrBy(key, count);
            long startId = endId - count + 1;
            
            long[] ids = new long[count];
            for (int i = 0; i < count; i++) {
                ids[i] = startId + i;
            }
            return ids;
        }
    }
    
    /**
     * 设置初始值
     */
    public void setInitialValue(String bizTag, long value) {
        try (Jedis jedis = jedisPool.getResource()) {
            String key = keyPrefix + ":" + bizTag;
            jedis.set(key, String.valueOf(value));
        }
    }
}
```


### 5.3 带时间前缀的 ID

```java
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class RedisTimeIdGenerator {
    
    private final JedisPool jedisPool;
    private static final DateTimeFormatter FORMATTER = 
        DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
    
    /**
     * 生成带时间前缀的 ID
     * 格式：20240115143052000001
     */
    public String nextId(String bizTag) {
        String timePrefix = LocalDateTime.now().format(FORMATTER);
        String key = "id:" + bizTag + ":" + timePrefix;
        
        try (Jedis jedis = jedisPool.getResource()) {
            // 设置过期时间，避免 key 无限增长
            long seq = jedis.incr(key);
            if (seq == 1) {
                jedis.expire(key, 60); // 60秒后过期
            }
            
            // 序列号补零到 6 位
            return timePrefix + String.format("%06d", seq);
        }
    }
}
```

### 5.4 Redis Cluster 方案

```java
import redis.clients.jedis.JedisCluster;

public class RedisClusterIdGenerator {
    
    private final JedisCluster jedisCluster;
    
    /**
     * 使用 Lua 脚本保证原子性
     */
    private static final String LUA_SCRIPT = 
        "local key = KEYS[1] " +
        "local step = tonumber(ARGV[1]) " +
        "local current = redis.call('INCRBY', key, step) " +
        "return current";
    
    public long[] nextIds(String bizTag, int count) {
        String key = "id:" + bizTag;
        
        // 使用 Lua 脚本批量获取
        Object result = jedisCluster.eval(
            LUA_SCRIPT, 
            1, 
            key, 
            String.valueOf(count)
        );
        
        long endId = (Long) result;
        long startId = endId - count + 1;
        
        long[] ids = new long[count];
        for (int i = 0; i < count; i++) {
            ids[i] = startId + i;
        }
        return ids;
    }
}
```

### 5.5 Spring Boot 集成

```java
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public class SpringRedisIdGenerator {
    
    private final StringRedisTemplate redisTemplate;
    
    public SpringRedisIdGenerator(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    
    public Long nextId(String bizTag) {
        String key = "id:" + bizTag;
        return redisTemplate.opsForValue().increment(key);
    }
    
    public Long nextId(String bizTag, long delta) {
        String key = "id:" + bizTag;
        return redisTemplate.opsForValue().increment(key, delta);
    }
}
```

### 5.6 优缺点分析

**优点：**
- ✅ 性能极高（10万+ QPS）
- ✅ 实现简单
- ✅ ID 有序递增

**缺点：**
- ❌ 依赖 Redis，需要保证 Redis 高可用
- ❌ Redis 宕机可能导致 ID 重复（RDB 持久化有数据丢失风险）
- ❌ 网络开销（每次都需要访问 Redis）

> ⚠️ **注意**：生产环境必须使用 Redis Cluster 或 Sentinel 保证高可用！

---

## 6. 雪花算法

### 6.1 什么是雪花算法？

雪花算法（Snowflake）是 Twitter 开源的分布式 ID 生成算法，生成 64 位的 Long 类型 ID。

```
 0 | 0000000000 0000000000 0000000000 0000000000 0 | 00000 | 00000 | 000000000000
 │ │                                             │ │     │ │     │ │
 │ │                41位时间戳                    │ │ 5位 │ │ 5位 │ │  12位序列号
 │ │            (毫秒级，可用69年)                │ │数据 │ │机器 │ │ (每毫秒4096个)
 │ │                                             │ │中心 │ │  ID │ │
 │ └─────────────────────────────────────────────┘ └─────┘ └─────┘ └────────────┘
 │
 └── 符号位（始终为0，表示正数）
```


### 6.2 位分配详解

| 部分 | 位数 | 说明 | 范围 |
|-----|-----|------|------|
| 符号位 | 1 | 始终为 0 | - |
| 时间戳 | 41 | 毫秒级时间戳 | 约 69 年 |
| 数据中心 | 5 | 数据中心 ID | 0-31 |
| 机器 ID | 5 | 机器 ID | 0-31 |
| 序列号 | 12 | 毫秒内序列 | 0-4095 |

**理论性能：**
- 单机每毫秒可生成 4096 个 ID
- 单机每秒可生成 409.6 万个 ID
- 支持 32 个数据中心 × 32 台机器 = 1024 个节点

### 6.3 Java 标准实现

```java
public class SnowflakeIdGenerator {
    
    // 起始时间戳（2024-01-01 00:00:00）
    private static final long EPOCH = 1704067200000L;
    
    // 各部分位数
    private static final long DATACENTER_ID_BITS = 5L;
    private static final long WORKER_ID_BITS = 5L;
    private static final long SEQUENCE_BITS = 12L;
    
    // 最大值
    private static final long MAX_DATACENTER_ID = ~(-1L << DATACENTER_ID_BITS); // 31
    private static final long MAX_WORKER_ID = ~(-1L << WORKER_ID_BITS);         // 31
    private static final long MAX_SEQUENCE = ~(-1L << SEQUENCE_BITS);           // 4095
    
    // 位移量
    private static final long WORKER_ID_SHIFT = SEQUENCE_BITS;                           // 12
    private static final long DATACENTER_ID_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS;      // 17
    private static final long TIMESTAMP_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS + DATACENTER_ID_BITS; // 22
    
    private final long datacenterId;
    private final long workerId;
    
    private long sequence = 0L;
    private long lastTimestamp = -1L;
    
    public SnowflakeIdGenerator(long datacenterId, long workerId) {
        if (datacenterId > MAX_DATACENTER_ID || datacenterId < 0) {
            throw new IllegalArgumentException(
                "Datacenter ID must be between 0 and " + MAX_DATACENTER_ID);
        }
        if (workerId > MAX_WORKER_ID || workerId < 0) {
            throw new IllegalArgumentException(
                "Worker ID must be between 0 and " + MAX_WORKER_ID);
        }
        this.datacenterId = datacenterId;
        this.workerId = workerId;
    }
    
    /**
     * 生成下一个 ID（线程安全）
     */
    public synchronized long nextId() {
        long currentTimestamp = System.currentTimeMillis();
        
        // 时钟回拨检测
        if (currentTimestamp < lastTimestamp) {
            long offset = lastTimestamp - currentTimestamp;
            if (offset <= 5) {
                // 回拨时间小于5ms，等待
                try {
                    Thread.sleep(offset << 1);
                    currentTimestamp = System.currentTimeMillis();
                    if (currentTimestamp < lastTimestamp) {
                        throw new RuntimeException("Clock moved backwards after waiting");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Thread interrupted", e);
                }
            } else {
                throw new RuntimeException(
                    "Clock moved backwards. Refusing to generate ID for " + offset + " ms");
            }
        }
        
        // 同一毫秒内
        if (currentTimestamp == lastTimestamp) {
            sequence = (sequence + 1) & MAX_SEQUENCE;
            // 序列号溢出，等待下一毫秒
            if (sequence == 0) {
                currentTimestamp = waitNextMillis(lastTimestamp);
            }
        } else {
            // 新的毫秒，序列号重置
            sequence = 0L;
        }
        
        lastTimestamp = currentTimestamp;
        
        // 组装 ID
        return ((currentTimestamp - EPOCH) << TIMESTAMP_SHIFT)
                | (datacenterId << DATACENTER_ID_SHIFT)
                | (workerId << WORKER_ID_SHIFT)
                | sequence;
    }
    
    /**
     * 等待下一毫秒
     */
    private long waitNextMillis(long lastTimestamp) {
        long timestamp = System.currentTimeMillis();
        while (timestamp <= lastTimestamp) {
            timestamp = System.currentTimeMillis();
        }
        return timestamp;
    }
    
    /**
     * 解析 ID 中的信息
     */
    public static long[] parseId(long id) {
        long[] result = new long[4];
        result[0] = (id >> TIMESTAMP_SHIFT) + EPOCH;  // 时间戳
        result[1] = (id >> DATACENTER_ID_SHIFT) & MAX_DATACENTER_ID;  // 数据中心ID
        result[2] = (id >> WORKER_ID_SHIFT) & MAX_WORKER_ID;  // 机器ID
        result[3] = id & MAX_SEQUENCE;  // 序列号
        return result;
    }
    
    public static void main(String[] args) {
        SnowflakeIdGenerator generator = new SnowflakeIdGenerator(1, 1);
        
        for (int i = 0; i < 10; i++) {
            long id = generator.nextId();
            long[] parsed = parseId(id);
            System.out.printf("ID: %d, Time: %d, DC: %d, Worker: %d, Seq: %d%n",
                id, parsed[0], parsed[1], parsed[2], parsed[3]);
        }
    }
}
```


### 6.4 时钟回拨问题

时钟回拨是雪花算法最大的问题。当系统时间被调整（NTP 同步、手动调整）时，可能导致 ID 重复。

**解决方案：**

```java
/**
 * 方案1：等待时钟追上
 */
if (currentTimestamp < lastTimestamp) {
    long offset = lastTimestamp - currentTimestamp;
    if (offset <= 5) {
        Thread.sleep(offset << 1);
    }
}

/**
 * 方案2：使用扩展位
 * 预留几位作为时钟回拨计数器
 */
public class SnowflakeWithBackup {
    private int clockBackwardCount = 0;
    
    public synchronized long nextId() {
        long currentTimestamp = System.currentTimeMillis();
        
        if (currentTimestamp < lastTimestamp) {
            clockBackwardCount++;
            if (clockBackwardCount > 3) {
                throw new RuntimeException("Clock moved backwards too many times");
            }
            // 使用回拨计数器作为 workerId 的一部分
        }
        // ...
    }
}

/**
 * 方案3：使用备用 workerId
 */
public class SnowflakeWithBackupWorker {
    private final long[] workerIds = {1, 2, 3}; // 预分配多个 workerId
    private int currentWorkerIndex = 0;
    
    public synchronized long nextId() {
        long currentTimestamp = System.currentTimeMillis();
        
        if (currentTimestamp < lastTimestamp) {
            // 切换到备用 workerId
            currentWorkerIndex = (currentWorkerIndex + 1) % workerIds.length;
            sequence = 0;
        }
        // ...
    }
}
```

### 6.5 WorkerId 分配策略

在分布式环境中，如何保证每个节点的 workerId 唯一是个挑战：

```java
/**
 * 方案1：配置文件指定
 * 简单但不灵活，适合节点固定的场景
 */
@Value("${snowflake.worker-id}")
private long workerId;

/**
 * 方案2：基于 IP 地址
 */
public static long getWorkerIdByIP() {
    try {
        InetAddress address = InetAddress.getLocalHost();
        byte[] ipBytes = address.getAddress();
        // 取 IP 最后两段作为 workerId
        return ((ipBytes[2] & 0xFF) << 8) | (ipBytes[3] & 0xFF) % 32;
    } catch (UnknownHostException e) {
        return new Random().nextInt(32);
    }
}

/**
 * 方案3：基于 Zookeeper
 */
public class ZkWorkerIdAllocator {
    private final CuratorFramework client;
    private final String basePath = "/snowflake/worker";
    
    public long allocateWorkerId() throws Exception {
        // 创建临时顺序节点
        String path = client.create()
            .creatingParentsIfNeeded()
            .withMode(CreateMode.EPHEMERAL_SEQUENTIAL)
            .forPath(basePath + "/worker-");
        
        // 从路径中提取序号作为 workerId
        String sequenceStr = path.substring(path.lastIndexOf("-") + 1);
        return Long.parseLong(sequenceStr) % 1024;
    }
}

/**
 * 方案4：基于 Redis
 */
public class RedisWorkerIdAllocator {
    private final StringRedisTemplate redisTemplate;
    
    public long allocateWorkerId(String serviceName) {
        String key = "snowflake:worker:" + serviceName;
        Long workerId = redisTemplate.opsForValue().increment(key);
        return workerId % 1024;
    }
}
```

### 6.6 优缺点分析

**优点：**
- ✅ 本地生成，性能极高
- ✅ 趋势递增，利于数据库索引
- ✅ 64 位 Long 类型，存储高效
- ✅ 可从 ID 中解析出时间信息

**缺点：**
- ❌ 依赖系统时钟，时钟回拨会导致问题
- ❌ workerId 分配需要额外机制
- ❌ 不同机器生成的 ID 不是严格递增的


---

## 7. Leaf 方案

### 7.1 什么是 Leaf？

Leaf 是美团开源的分布式 ID 生成系统，提供两种模式：
- **Leaf-Segment**：号段模式（数据库）
- **Leaf-Snowflake**：雪花算法模式

### 7.2 Leaf-Segment 模式

Leaf 对号段模式做了优化，引入了双缓冲和动态步长：

```
┌─────────────────────────────────────────────────────────────┐
│                        Leaf Server                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    SegmentBuffer                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐           │   │
│  │  │   Segment 0     │  │   Segment 1     │           │   │
│  │  │  [1001, 2000]   │  │  [2001, 3000]   │           │   │
│  │  │  当前使用        │  │  预加载完成      │           │   │
│  │  └─────────────────┘  └─────────────────┘           │   │
│  │                                                      │   │
│  │  当 Segment 0 使用到 10% 时，异步加载 Segment 1      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Leaf 数据库表

```sql
CREATE TABLE leaf_alloc (
    biz_tag VARCHAR(128) NOT NULL DEFAULT '' COMMENT '业务标识',
    max_id BIGINT NOT NULL DEFAULT 1 COMMENT '当前已分配的最大ID',
    step INT NOT NULL COMMENT '步长',
    description VARCHAR(256) DEFAULT NULL COMMENT '描述',
    update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (biz_tag)
) ENGINE=InnoDB;

-- 初始化
INSERT INTO leaf_alloc (biz_tag, max_id, step, description) VALUES
('order', 1, 2000, '订单ID'),
('user', 1, 1000, '用户ID');
```

### 7.4 Spring Boot 集成 Leaf

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.sankuai.inf.leaf</groupId>
    <artifactId>leaf-boot-starter</artifactId>
    <version>1.0.1</version>
</dependency>
```

```yaml
# application.yml
leaf:
  name: leaf-service
  segment:
    enable: true
    jdbc-url: jdbc:mysql://localhost:3306/leaf?useSSL=false
    jdbc-username: root
    jdbc-password: password
  snowflake:
    enable: true
    zk-address: localhost:2181
    port: 8080
```

```java
import com.sankuai.inf.leaf.common.Result;
import com.sankuai.inf.leaf.service.SegmentService;
import com.sankuai.inf.leaf.service.SnowflakeService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/id")
public class LeafIdController {
    
    private final SegmentService segmentService;
    private final SnowflakeService snowflakeService;
    
    public LeafIdController(SegmentService segmentService, 
                           SnowflakeService snowflakeService) {
        this.segmentService = segmentService;
        this.snowflakeService = snowflakeService;
    }
    
    /**
     * 号段模式获取 ID
     */
    @GetMapping("/segment/{bizTag}")
    public Result getSegmentId(@PathVariable String bizTag) {
        return segmentService.getId(bizTag);
    }
    
    /**
     * 雪花算法获取 ID
     */
    @GetMapping("/snowflake/{bizTag}")
    public Result getSnowflakeId(@PathVariable String bizTag) {
        return snowflakeService.getId(bizTag);
    }
}
```


### 7.5 Leaf-Snowflake 模式

Leaf 使用 Zookeeper 解决 workerId 分配问题：

```
┌─────────────────────────────────────────────────────────────┐
│                       Zookeeper                              │
│  /leaf/snowflake/                                           │
│  ├── leaf-service-1  (workerId: 0)                          │
│  ├── leaf-service-2  (workerId: 1)                          │
│  └── leaf-service-3  (workerId: 2)                          │
└─────────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │ Leaf Node 1 │ │ Leaf Node 2 │ │ Leaf Node 3 │
    │ workerId: 0 │ │ workerId: 1 │ │ workerId: 2 │
    └─────────────┘ └─────────────┘ └─────────────┘
```

### 7.6 Leaf 的优化点

1. **双缓冲**：提前加载下一个号段，避免等待
2. **动态步长**：根据 ID 消耗速度动态调整步长
3. **Zookeeper 持久化 workerId**：解决雪花算法的 workerId 分配问题
4. **监控告警**：提供监控接口，号段不足时告警

---

## 8. UidGenerator 方案

### 8.1 什么是 UidGenerator？

UidGenerator 是百度开源的分布式 ID 生成器，基于雪花算法优化，解决了时钟回拨问题。

### 8.2 位分配

UidGenerator 采用不同的位分配策略：

```
 0 | 0000000000 0000000000 0000000 | 0000000000 0000000000 00 | 0000000000 000
 │ │                              │ │                        │ │
 │ │         28位时间戳            │ │      22位 workerId     │ │  13位序列号
 │ │       (秒级，约8.5年)         │ │    (约420万个节点)      │ │ (每秒8192个)
 │ │                              │ │                        │ │
 │ └──────────────────────────────┘ └────────────────────────┘ └─────────────┘
 │
 └── 符号位
```

### 8.3 核心特性

**1. CachedUidGenerator（推荐）**

使用 RingBuffer 预生成 ID，大幅提升性能：

```
┌─────────────────────────────────────────────────────────────┐
│                      RingBuffer                              │
│  ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐ │
│  │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │   │   │   │   │   │   │ │
│  └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘ │
│        ▲                       ▲                             │
│        │                       │                             │
│      Tail                    Cursor                          │
│   (生产者位置)              (消费者位置)                       │
└─────────────────────────────────────────────────────────────┘
```

**2. 时钟回拨处理**

UidGenerator 使用"借用未来时间"的方式处理时钟回拨：

```java
// 当检测到时钟回拨时，不是抛出异常，而是使用上次的时间戳继续生成
// 通过增加序列号来保证唯一性
```


### 8.4 Spring Boot 集成

```xml
<!-- pom.xml -->
<dependency>
    <groupId>com.baidu.fsg</groupId>
    <artifactId>uid-generator</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

```sql
-- 创建 worker_node 表
CREATE TABLE worker_node (
    id BIGINT NOT NULL AUTO_INCREMENT COMMENT 'auto increment id',
    host_name VARCHAR(64) NOT NULL COMMENT 'host name',
    port VARCHAR(64) NOT NULL COMMENT 'port',
    type INT NOT NULL COMMENT 'node type: ACTUAL or CONTAINER',
    launch_date DATE NOT NULL COMMENT 'launch date',
    modified TIMESTAMP NOT NULL COMMENT 'modified time',
    created TIMESTAMP NOT NULL COMMENT 'created time',
    PRIMARY KEY(id)
) ENGINE=InnoDB;
```

```java
import com.baidu.fsg.uid.UidGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UidGeneratorConfig {
    
    @Bean
    public UidGenerator cachedUidGenerator() {
        CachedUidGenerator generator = new CachedUidGenerator();
        generator.setWorkerIdAssigner(workerIdAssigner());
        generator.setTimeBits(28);
        generator.setWorkerBits(22);
        generator.setSeqBits(13);
        generator.setEpochStr("2024-01-01");
        
        // RingBuffer 配置
        generator.setBoostPower(3);  // RingBuffer 大小 = 2^13 * 2^3 = 65536
        generator.setPaddingFactor(50);  // 填充因子 50%
        
        return generator;
    }
    
    @Bean
    public WorkerIdAssigner workerIdAssigner() {
        return new DisposableWorkerIdAssigner();
    }
}
```

```java
import com.baidu.fsg.uid.UidGenerator;
import org.springframework.stereotype.Service;

@Service
public class IdService {
    
    private final UidGenerator uidGenerator;
    
    public IdService(UidGenerator uidGenerator) {
        this.uidGenerator = uidGenerator;
    }
    
    public long generateId() {
        return uidGenerator.getUID();
    }
    
    public String parseId(long uid) {
        return uidGenerator.parseUID(uid);
    }
}
```

---

## 9. Tinyid 方案

### 9.1 什么是 Tinyid？

Tinyid 是滴滴开源的分布式 ID 生成系统，基于号段模式，支持 HTTP 和 SDK 两种接入方式。

### 9.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                        客户端                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Tinyid Client                      │   │
│  │  ┌─────────────────┐  ┌─────────────────┐           │   │
│  │  │   本地号段缓存   │  │   下一号段缓存   │           │   │
│  │  │  [1001, 2000]   │  │  [2001, 3000]   │           │   │
│  │  └─────────────────┘  └─────────────────┘           │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ 号段用完时获取
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     Tinyid Server                            │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │   Server 1      │  │   Server 2      │                   │
│  └────────┬────────┘  └────────┬────────┘                   │
│           │                    │                             │
│           └────────┬───────────┘                             │
│                    ▼                                         │
│             ┌─────────────┐                                  │
│             │   MySQL     │                                  │
│             └─────────────┘                                  │
└─────────────────────────────────────────────────────────────┘
```


### 9.3 数据库表设计

```sql
-- 号段表
CREATE TABLE tiny_id_info (
    id BIGINT NOT NULL AUTO_INCREMENT,
    biz_type VARCHAR(63) NOT NULL COMMENT '业务类型',
    begin_id BIGINT NOT NULL COMMENT '开始ID',
    max_id BIGINT NOT NULL COMMENT '当前最大ID',
    step INT NOT NULL COMMENT '步长',
    delta INT NOT NULL DEFAULT 1 COMMENT '每次增量',
    remainder INT NOT NULL DEFAULT 0 COMMENT '余数',
    create_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    version BIGINT NOT NULL DEFAULT 0 COMMENT '乐观锁版本号',
    PRIMARY KEY (id),
    UNIQUE KEY uk_biz_type (biz_type)
) ENGINE=InnoDB;

-- Token 表（用于认证）
CREATE TABLE tiny_id_token (
    id INT NOT NULL AUTO_INCREMENT,
    token VARCHAR(255) NOT NULL COMMENT '令牌',
    biz_type VARCHAR(63) NOT NULL COMMENT '业务类型',
    remark VARCHAR(255) COMMENT '备注',
    create_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

-- 初始化数据
INSERT INTO tiny_id_info (biz_type, begin_id, max_id, step, delta, remainder)
VALUES ('order', 1, 1, 2000, 1, 0);

INSERT INTO tiny_id_token (token, biz_type, remark)
VALUES ('your_token', 'order', '订单ID');
```

### 9.4 客户端使用

```java
// 方式1：HTTP 接口
// GET http://tinyid-server/tinyid/id/nextId?bizType=order&token=xxx

// 方式2：SDK
import com.xiaoju.uemc.tinyid.client.TinyId;

public class TinyIdDemo {
    
    public static void main(String[] args) {
        // 获取单个 ID
        Long id = TinyId.nextId("order");
        System.out.println("ID: " + id);
        
        // 批量获取 ID
        List<Long> ids = TinyId.nextId("order", 100);
        System.out.println("IDs: " + ids);
    }
}
```

```properties
# tinyid_client.properties
tinyid.server=localhost:9999
tinyid.token=your_token
```

---

## 10. MongoDB ObjectId

### 10.1 ObjectId 结构

MongoDB 的 ObjectId 是一个 12 字节（24 个十六进制字符）的唯一标识符：

```
507f1f77bcf86cd799439011
│       │     │   │
│       │     │   └── 3字节：自增计数器
│       │     └── 2字节：进程ID
│       └── 5字节：机器标识（随机值）
└── 4字节：时间戳（秒级）
```

### 10.2 Java 实现

```java
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicInteger;

public class ObjectIdGenerator {
    
    private static final int MACHINE_IDENTIFIER;
    private static final short PROCESS_IDENTIFIER;
    private static final AtomicInteger COUNTER = new AtomicInteger(new SecureRandom().nextInt());
    
    static {
        MACHINE_IDENTIFIER = createMachineIdentifier();
        PROCESS_IDENTIFIER = createProcessIdentifier();
    }
    
    /**
     * 生成 ObjectId
     */
    public static String generate() {
        int timestamp = (int) (System.currentTimeMillis() / 1000);
        int counter = COUNTER.getAndIncrement() & 0x00FFFFFF;
        
        ByteBuffer buffer = ByteBuffer.allocate(12);
        buffer.putInt(timestamp);
        buffer.put((byte) (MACHINE_IDENTIFIER >> 16));
        buffer.put((byte) (MACHINE_IDENTIFIER >> 8));
        buffer.put((byte) MACHINE_IDENTIFIER);
        buffer.putShort(PROCESS_IDENTIFIER);
        buffer.put((byte) (counter >> 16));
        buffer.put((byte) (counter >> 8));
        buffer.put((byte) counter);
        
        return bytesToHex(buffer.array());
    }
    
    private static int createMachineIdentifier() {
        try {
            StringBuilder sb = new StringBuilder();
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                sb.append(ni.toString());
                byte[] mac = ni.getHardwareAddress();
                if (mac != null) {
                    for (byte b : mac) {
                        sb.append(String.format("%02X", b));
                    }
                }
            }
            return sb.toString().hashCode() & 0x00FFFFFF;
        } catch (Exception e) {
            return new SecureRandom().nextInt() & 0x00FFFFFF;
        }
    }
    
    private static short createProcessIdentifier() {
        try {
            String processName = java.lang.management.ManagementFactory
                .getRuntimeMXBean().getName();
            return (short) Integer.parseInt(processName.split("@")[0]);
        } catch (Exception e) {
            return (short) new SecureRandom().nextInt();
        }
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    public static void main(String[] args) {
        for (int i = 0; i < 5; i++) {
            System.out.println(generate());
        }
    }
}
```


### 10.3 使用 MongoDB 驱动

```java
import org.bson.types.ObjectId;

public class MongoObjectIdDemo {
    
    public static void main(String[] args) {
        // 生成 ObjectId
        ObjectId id = new ObjectId();
        System.out.println("ObjectId: " + id.toHexString());
        
        // 解析 ObjectId
        System.out.println("Timestamp: " + id.getTimestamp());
        System.out.println("Date: " + id.getDate());
        
        // 从字符串创建
        ObjectId parsed = new ObjectId("507f1f77bcf86cd799439011");
        System.out.println("Parsed: " + parsed);
    }
}
```

---

## 11. 方案对比与选型

### 11.1 综合对比

| 方案 | 性能 | 有序性 | 可用性 | 实现复杂度 | 适用场景 |
|-----|------|-------|-------|-----------|---------|
| UUID | ⭐⭐⭐⭐⭐ | ❌ | ⭐⭐⭐⭐⭐ | ⭐ | 不需要有序的场景 |
| 数据库自增 | ⭐⭐ | ✅ | ⭐⭐ | ⭐ | 低并发场景 |
| 号段模式 | ⭐⭐⭐⭐ | ✅ | ⭐⭐⭐⭐ | ⭐⭐⭐ | 中高并发场景 |
| Redis | ⭐⭐⭐⭐⭐ | ✅ | ⭐⭐⭐ | ⭐⭐ | 高并发场景 |
| 雪花算法 | ⭐⭐⭐⭐⭐ | ✅ | ⭐⭐⭐⭐ | ⭐⭐⭐ | 高并发场景 |
| Leaf | ⭐⭐⭐⭐⭐ | ✅ | ⭐⭐⭐⭐⭐ | ⭐⭐ | 企业级应用 |
| UidGenerator | ⭐⭐⭐⭐⭐ | ✅ | ⭐⭐⭐⭐ | ⭐⭐⭐ | 高性能场景 |

### 11.2 选型建议

```
                    ┌─────────────────────────────────────┐
                    │           需要分布式 ID？            │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────┴───────────────────┐
                    │           并发量多大？               │
                    └─────────────────┬───────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
            ▼                         ▼                         ▼
    ┌───────────────┐         ┌───────────────┐         ┌───────────────┐
    │  QPS < 1000   │         │ 1000 < QPS    │         │  QPS > 10万   │
    │               │         │    < 10万     │         │               │
    │  数据库自增    │         │  号段模式     │         │  雪花算法     │
    │  或 Redis     │         │  或 Leaf      │         │  或 Leaf      │
    └───────────────┘         └───────────────┘         └───────────────┘
```

**具体建议：**

1. **小型项目**：数据库自增或 Redis 即可
2. **中型项目**：号段模式（Leaf-Segment）
3. **大型项目**：雪花算法（Leaf-Snowflake）或 UidGenerator
4. **不需要有序**：UUID
5. **需要时间信息**：雪花算法或 ObjectId

### 11.3 性能测试参考

```java
public class IdGeneratorBenchmark {
    
    public static void main(String[] args) {
        int count = 1000000;
        
        // UUID
        long start = System.currentTimeMillis();
        for (int i = 0; i < count; i++) {
            UUID.randomUUID().toString();
        }
        System.out.println("UUID: " + (System.currentTimeMillis() - start) + "ms");
        
        // Snowflake
        SnowflakeIdGenerator snowflake = new SnowflakeIdGenerator(1, 1);
        start = System.currentTimeMillis();
        for (int i = 0; i < count; i++) {
            snowflake.nextId();
        }
        System.out.println("Snowflake: " + (System.currentTimeMillis() - start) + "ms");
    }
}

// 典型结果（100万次）：
// UUID: ~800ms
// Snowflake: ~50ms
// Redis INCR: ~3000ms（网络开销）
// 号段模式: ~30ms（本地分配）
```


---

## 12. 生产环境最佳实践

### 12.1 ID 设计原则

```java
/**
 * 1. 使用 Long 类型而非 String
 * - 存储空间小（8字节 vs 36字节）
 * - 索引效率高
 * - 比较速度快
 */
@Id
private Long id;  // ✅ 推荐
// private String id;  // ❌ 不推荐作为主键

/**
 * 2. 业务 ID 与数据库 ID 分离
 * - 数据库主键使用自增或雪花 ID
 * - 对外暴露使用业务 ID（可加密）
 */
@Entity
public class Order {
    @Id
    private Long id;           // 内部主键
    private String orderNo;    // 对外业务号
}

/**
 * 3. ID 不要暴露业务信息
 * - 避免使用连续自增（暴露订单量）
 * - 可以对 ID 进行混淆
 */
public class IdObfuscator {
    private static final long XOR_KEY = 0x5DEECE66DL;
    
    public static long obfuscate(long id) {
        return id ^ XOR_KEY;
    }
    
    public static long deobfuscate(long obfuscatedId) {
        return obfuscatedId ^ XOR_KEY;
    }
}
```

### 12.2 高可用部署

```yaml
# Leaf 高可用部署示例
# docker-compose.yml
version: '3'
services:
  leaf-1:
    image: leaf:latest
    ports:
      - "8081:8080"
    environment:
      - LEAF_SEGMENT_ENABLE=true
      - LEAF_SNOWFLAKE_ENABLE=true
      - MYSQL_URL=jdbc:mysql://mysql:3306/leaf
      - ZK_ADDRESS=zk1:2181,zk2:2181,zk3:2181
    depends_on:
      - mysql
      - zk1
      
  leaf-2:
    image: leaf:latest
    ports:
      - "8082:8080"
    environment:
      - LEAF_SEGMENT_ENABLE=true
      - LEAF_SNOWFLAKE_ENABLE=true
      - MYSQL_URL=jdbc:mysql://mysql:3306/leaf
      - ZK_ADDRESS=zk1:2181,zk2:2181,zk3:2181
    depends_on:
      - mysql
      - zk1

  nginx:
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - leaf-1
      - leaf-2
```

```nginx
# nginx.conf - 负载均衡
upstream leaf_servers {
    server leaf-1:8080 weight=1;
    server leaf-2:8080 weight=1;
    keepalive 32;
}

server {
    listen 80;
    
    location /api/id {
        proxy_pass http://leaf_servers;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

### 12.3 监控告警

```java
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

@Component
public class IdGeneratorMetrics {
    
    private final Counter idGeneratedCounter;
    private final Timer idGenerationTimer;
    private final AtomicLong segmentRemaining;
    
    public IdGeneratorMetrics(MeterRegistry registry) {
        this.idGeneratedCounter = Counter.builder("id.generated.total")
            .description("Total number of IDs generated")
            .register(registry);
            
        this.idGenerationTimer = Timer.builder("id.generation.time")
            .description("Time to generate an ID")
            .register(registry);
            
        this.segmentRemaining = registry.gauge("id.segment.remaining", 
            new AtomicLong(0));
    }
    
    public long generateIdWithMetrics(IdGenerator generator) {
        return idGenerationTimer.record(() -> {
            long id = generator.nextId();
            idGeneratedCounter.increment();
            return id;
        });
    }
    
    public void updateSegmentRemaining(long remaining) {
        segmentRemaining.set(remaining);
    }
}
```

```yaml
# Prometheus 告警规则
groups:
  - name: id-generator
    rules:
      - alert: IdSegmentLow
        expr: id_segment_remaining < 1000
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "ID segment is running low"
          
      - alert: IdGenerationSlow
        expr: histogram_quantile(0.99, id_generation_time_seconds_bucket) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "ID generation is slow"
```


### 12.4 容灾方案

```java
/**
 * 多级容灾 ID 生成器
 * 主：Leaf-Snowflake
 * 备：本地雪花算法
 * 兜底：UUID
 */
@Component
public class FallbackIdGenerator {
    
    private final LeafSnowflakeService leafService;
    private final SnowflakeIdGenerator localSnowflake;
    
    @Value("${id.generator.fallback.enabled:true}")
    private boolean fallbackEnabled;
    
    public long nextId() {
        // 1. 尝试使用 Leaf
        try {
            Result result = leafService.getId("default");
            if (result.getStatus() == Status.SUCCESS) {
                return result.getId();
            }
        } catch (Exception e) {
            log.warn("Leaf service failed, falling back to local", e);
        }
        
        // 2. 降级到本地雪花算法
        if (fallbackEnabled) {
            try {
                return localSnowflake.nextId();
            } catch (Exception e) {
                log.error("Local snowflake failed, falling back to UUID", e);
            }
        }
        
        // 3. 最后兜底：UUID 转 Long
        return Math.abs(UUID.randomUUID().getMostSignificantBits());
    }
}
```

---

## 13. 常见错误与解决方案

### 13.1 时钟回拨导致 ID 重复

**错误现象：**
```
RuntimeException: Clock moved backwards. Refusing to generate id for 5 milliseconds
```

**原因分析：**
- NTP 时间同步导致系统时间回退
- 虚拟机快照恢复
- 手动调整系统时间

**解决方案：**

```java
// 方案1：等待时钟追上
if (currentTimestamp < lastTimestamp) {
    long offset = lastTimestamp - currentTimestamp;
    if (offset <= 5) {
        Thread.sleep(offset << 1);
    } else {
        throw new RuntimeException("Clock moved backwards");
    }
}

// 方案2：使用 NTP 平滑调整
# /etc/ntp.conf
tinker panic 0  # 禁止大幅度时间跳变

// 方案3：使用 UidGenerator 的借用未来时间策略
```

### 13.2 WorkerId 冲突

**错误现象：**
```
生成的 ID 出现重复
```

**原因分析：**
- 多个实例使用了相同的 workerId
- 容器重启后 workerId 分配不一致

**解决方案：**

```java
// 方案1：使用 Zookeeper 分配
public class ZkWorkerIdAssigner implements WorkerIdAssigner {
    
    @Override
    public long assignWorkerId() {
        String path = zkClient.create()
            .creatingParentsIfNeeded()
            .withMode(CreateMode.EPHEMERAL_SEQUENTIAL)
            .forPath("/snowflake/worker-");
        
        return extractWorkerId(path);
    }
}

// 方案2：使用数据库分配
@Transactional
public long assignWorkerId(String hostInfo) {
    // 先查询是否已分配
    WorkerNode existing = workerNodeMapper.selectByHost(hostInfo);
    if (existing != null) {
        return existing.getId();
    }
    
    // 新分配
    WorkerNode node = new WorkerNode();
    node.setHostName(hostInfo);
    node.setLaunchDate(new Date());
    workerNodeMapper.insert(node);
    
    return node.getId();
}

// 方案3：基于 IP + 端口
public long getWorkerIdByIpPort() {
    String ip = getLocalIp();
    int port = getServerPort();
    return (ip.hashCode() ^ port) & 0x3FF;  // 10位
}
```


### 13.3 号段用尽

**错误现象：**
```
获取 ID 超时或失败
```

**原因分析：**
- 数据库连接失败
- 号段消耗过快，双缓冲来不及加载
- 步长设置过小

**解决方案：**

```java
// 方案1：动态调整步长
public int calculateStep(long consumeSpeed) {
    // 根据消耗速度动态调整步长
    // 目标：一个号段至少能用 15 分钟
    int targetMinutes = 15;
    int step = (int) (consumeSpeed * 60 * targetMinutes);
    
    // 限制范围
    return Math.max(1000, Math.min(step, 1000000));
}

// 方案2：提前加载阈值调整
// 当号段使用到 20% 时就开始加载下一个（而不是 50%）
private static final double LOAD_FACTOR = 0.2;

// 方案3：增加本地缓存层
@Component
public class CachedIdGenerator {
    
    private final BlockingQueue<Long> idCache = new LinkedBlockingQueue<>(10000);
    
    @Scheduled(fixedRate = 1000)
    public void fillCache() {
        while (idCache.size() < 5000) {
            try {
                long id = remoteIdService.nextId();
                idCache.offer(id);
            } catch (Exception e) {
                break;
            }
        }
    }
    
    public long nextId() {
        Long id = idCache.poll();
        if (id != null) {
            return id;
        }
        // 缓存为空，直接调用远程服务
        return remoteIdService.nextId();
    }
}
```

### 13.4 UUID 作为主键性能差

**错误现象：**
```
插入速度慢，查询性能下降
```

**原因分析：**
- UUID 无序，导致 B+ 树频繁分裂
- UUID 占用空间大（36字节）
- 索引效率低

**解决方案：**

```java
// 方案1：使用有序 UUID（UUID v1 或 ULID）
// ULID: 26 字符，时间有序
import de.huxhorn.sulky.ulid.ULID;

ULID ulid = new ULID();
String id = ulid.nextULID();  // 01ARZ3NDEKTSV4RRFFQ69G5FAV

// 方案2：UUID 转二进制存储
@Column(columnDefinition = "BINARY(16)")
private byte[] id;

public void setId(UUID uuid) {
    ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
    bb.putLong(uuid.getMostSignificantBits());
    bb.putLong(uuid.getLeastSignificantBits());
    this.id = bb.array();
}

// 方案3：改用雪花算法
// 64位 Long 类型，有序且高效
```

### 13.5 Redis 宕机导致 ID 不连续

**错误现象：**
```
Redis 重启后 ID 从 0 开始
```

**原因分析：**
- Redis 使用 RDB 持久化，有数据丢失风险
- 未配置持久化

**解决方案：**

```bash
# 方案1：使用 AOF 持久化
# redis.conf
appendonly yes
appendfsync everysec

# 方案2：使用 Redis Cluster
# 多副本保证数据不丢失

# 方案3：定期同步到数据库
```

```java
// 方案4：启动时从数据库恢复
@PostConstruct
public void init() {
    // 从数据库获取最大 ID
    Long maxId = orderMapper.selectMaxId();
    if (maxId != null) {
        redisTemplate.opsForValue().set("id:order", String.valueOf(maxId));
    }
}
```

### 13.6 ID 溢出

**错误现象：**
```
ID 变成负数或归零
```

**原因分析：**
- Long 类型最大值约 922 亿亿
- 雪花算法 41 位时间戳约 69 年
- 序列号溢出

**解决方案：**

```java
// 方案1：监控 ID 使用情况
@Scheduled(cron = "0 0 * * * ?")
public void checkIdUsage() {
    long currentId = idGenerator.getCurrentId();
    long maxId = Long.MAX_VALUE;
    double usage = (double) currentId / maxId * 100;
    
    if (usage > 80) {
        alertService.send("ID usage is " + usage + "%");
    }
}

// 方案2：调整位分配
// 减少 workerId 位数，增加时间戳位数

// 方案3：更换起始时间戳
// 将 EPOCH 设置为更近的时间
private static final long EPOCH = 1704067200000L; // 2024-01-01
```


### 13.7 分库分表后 ID 不均匀

**错误现象：**
```
某些分片数据量远大于其他分片
```

**原因分析：**
- 使用时间戳作为分片键
- ID 生成不均匀

**解决方案：**

```java
// 方案1：使用 ID 取模分片
int shardIndex = (int) (id % shardCount);

// 方案2：使用一致性哈希
int shardIndex = consistentHash.getNode(id);

// 方案3：在 ID 中嵌入分片信息
public long generateShardedId(int shardId) {
    long baseId = snowflake.nextId();
    // 将分片 ID 嵌入到 ID 的低位
    return (baseId << 4) | (shardId & 0xF);
}
```

### 13.8 并发获取 ID 性能瓶颈

**错误现象：**
```
高并发下获取 ID 延迟增加
```

**原因分析：**
- synchronized 锁竞争
- 网络延迟（Redis/数据库）

**解决方案：**

```java
// 方案1：使用 ThreadLocal 缓存
public class ThreadLocalIdGenerator {
    
    private static final ThreadLocal<long[]> LOCAL_IDS = 
        ThreadLocal.withInitial(() -> new long[0]);
    private static final ThreadLocal<Integer> LOCAL_INDEX = 
        ThreadLocal.withInitial(() -> 0);
    
    public long nextId() {
        long[] ids = LOCAL_IDS.get();
        int index = LOCAL_INDEX.get();
        
        if (index >= ids.length) {
            // 批量获取
            ids = batchFetch(100);
            LOCAL_IDS.set(ids);
            index = 0;
        }
        
        LOCAL_INDEX.set(index + 1);
        return ids[index];
    }
}

// 方案2：使用 Disruptor 无锁队列
// 参考 UidGenerator 的 RingBuffer 实现

// 方案3：分段锁
public class SegmentedIdGenerator {
    
    private final SnowflakeIdGenerator[] generators;
    private final AtomicInteger counter = new AtomicInteger(0);
    
    public SegmentedIdGenerator(int segments) {
        generators = new SnowflakeIdGenerator[segments];
        for (int i = 0; i < segments; i++) {
            generators[i] = new SnowflakeIdGenerator(1, i);
        }
    }
    
    public long nextId() {
        int index = counter.getAndIncrement() % generators.length;
        return generators[index].nextId();
    }
}
```

---

## 附录：快速参考

### 常用工具类

```java
/**
 * ID 工具类
 */
public class IdUtils {
    
    private static final SnowflakeIdGenerator SNOWFLAKE = 
        new SnowflakeIdGenerator(1, 1);
    
    /**
     * 生成雪花 ID
     */
    public static long snowflakeId() {
        return SNOWFLAKE.nextId();
    }
    
    /**
     * 生成 UUID
     */
    public static String uuid() {
        return UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * 生成短 ID（8位）
     */
    public static String shortId() {
        return Long.toString(snowflakeId(), 36);
    }
    
    /**
     * 生成订单号
     * 格式：yyyyMMddHHmmss + 6位序列号
     */
    public static String orderNo() {
        String time = LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        String seq = String.format("%06d", snowflakeId() % 1000000);
        return time + seq;
    }
}
```

### 方案速查表

| 场景 | 推荐方案 | 备选方案 |
|-----|---------|---------|
| 数据库主键 | 雪花算法 | 号段模式 |
| 订单号 | 时间戳 + 序列号 | 雪花算法 |
| 短链接 | 雪花算法 + Base62 | 自增 + Base62 |
| 分布式追踪 | UUID | 雪花算法 |
| 消息 ID | 雪花算法 | UUID |
| 文件名 | UUID | ObjectId |

---

> 📝 **笔记更新日期**：2024年
> 
> 💡 **建议**：根据实际业务场景选择合适的方案，不要过度设计。大多数场景下，雪花算法或号段模式就能满足需求。
