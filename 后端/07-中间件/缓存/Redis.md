

> 基于 Redis 6.2.x 版本，从零开始系统学习 Redis。本笔记包含详细的概念讲解、命令示例和常见错误分析，帮助你真正掌握这个高性能的内存数据库。

---

## 目录

1. [Redis 概述](#1-redis-概述)
2. [安装与配置](#2-安装与配置)
3. [数据类型 - String](#3-数据类型---string)
4. [数据类型 - List](#4-数据类型---list)
5. [数据类型 - Set](#5-数据类型---set)
6. [数据类型 - Hash](#6-数据类型---hash)
7. [数据类型 - Sorted Set](#7-数据类型---sorted-set)
8. [特殊数据类型](#8-特殊数据类型)
9. [Key 操作](#9-key-操作)
10. [事务](#10-事务)
11. [发布订阅](#11-发布订阅)
12. [持久化](#12-持久化)
13. [主从复制](#13-主从复制)
14. [哨兵模式](#14-哨兵模式)
15. [集群模式](#15-集群模式)
16. [Java 客户端](#16-java-客户端)
17. [应用场景](#17-应用场景)
18. [性能优化](#18-性能优化)
19. [常见错误与解决](#19-常见错误与解决)
20. [总结](#20-总结)

---

## 1. Redis 概述

### 1.1 什么是 Redis？

**Redis（Remote Dictionary Server）** 是一个开源的、基于内存的高性能键值对数据库。

**特点：** 高性能（10万+ QPS）、丰富数据类型、持久化、高可用

### 1.2 应用场景

- 缓存、会话存储、排行榜、计数器、消息队列、分布式锁、限流

---

## 2. 安装与配置

### 2.1 Docker 安装

```bash
docker run -d --name redis6 -p 6379:6379 redis:6.2
docker exec -it redis6 redis-cli
```

### 2.2 核心配置

```bash
bind 0.0.0.0
port 6379
requirepass yourpassword
maxmemory 2gb
maxmemory-policy allkeys-lru
appendonly yes
```


---

## 3. 数据类型 - String

### 3.1 概述

String 是最基本的数据类型，二进制安全，最大 512MB。

### 3.2 基本操作

```bash
# 设置/获取
SET name "张三"
GET name

# 带过期时间
SET token "abc" EX 3600          # 秒
SET token "abc" PX 60000         # 毫秒

# 条件设置
SET lock "1" NX EX 10            # 不存在才设置（分布式锁）
SET key value XX                 # 存在才设置

# 批量操作
MSET k1 v1 k2 v2
MGET k1 k2

# 追加/长度
APPEND key value
STRLEN key
```

### 3.3 数值操作

```bash
SET counter 100
INCR counter                     # +1 → 101
DECR counter                     # -1 → 100
INCRBY counter 10                # +10 → 110
DECRBY counter 5                 # -5 → 105
INCRBYFLOAT price 0.5            # 浮点数加法
```

### 3.4 应用场景

```bash
# 缓存
SET user:1 '{"id":1,"name":"张三"}'

# 计数器
INCR article:1:views

# 分布式锁
SET lock:order:123 "uuid" NX EX 30

# 限流
INCR rate:user:1
EXPIRE rate:user:1 60
```

---

## 4. 数据类型 - List

### 4.1 概述

双向链表，有序可重复，适合队列/栈。

### 4.2 基本操作

```bash
# 插入
LPUSH list a b c                 # 左插入 → [c,b,a]
RPUSH list d e                   # 右插入 → [c,b,a,d,e]

# 弹出
LPOP list                        # 左弹出
RPOP list                        # 右弹出

# 获取
LINDEX list 0                    # 获取索引0的元素
LRANGE list 0 -1                 # 获取所有元素
LLEN list                        # 长度

# 阻塞弹出（消息队列）
BLPOP queue 30                   # 阻塞等待30秒
BRPOP queue 0                    # 无限等待
```

### 4.3 应用场景

```bash
# 消息队列
LPUSH queue:orders '{"orderId":1}'
BRPOP queue:orders 0

# 最新动态（保留最新100条）
LPUSH timeline:user:1 '{"content":"..."}'
LTRIM timeline:user:1 0 99
```

---

## 5. 数据类型 - Set

### 5.1 概述

无序集合，元素唯一，支持集合运算。

### 5.2 基本操作

```bash
# 添加/删除
SADD tags "java" "redis" "mysql"
SREM tags "mysql"

# 查询
SMEMBERS tags                    # 所有成员
SISMEMBER tags "java"            # 是否存在
SCARD tags                       # 数量
SRANDMEMBER tags 2               # 随机获取2个
SPOP tags                        # 随机弹出1个
```

### 5.3 集合运算

```bash
SADD set1 a b c
SADD set2 b c d

SINTER set1 set2                 # 交集 → [b,c]
SUNION set1 set2                 # 并集 → [a,b,c,d]
SDIFF set1 set2                  # 差集 → [a]

# 存储结果
SINTERSTORE dest set1 set2
```

### 5.4 应用场景

```bash
# 标签系统
SADD article:1:tags "java" "redis"

# 共同关注
SINTER user:1:following user:2:following

# 抽奖
SADD lottery user1 user2 user3
SRANDMEMBER lottery 1            # 抽1人
SPOP lottery 1                   # 抽1人并移除
```

---

## 6. 数据类型 - Hash

### 6.1 概述

键值对集合，适合存储对象。

### 6.2 基本操作

```bash
# 设置/获取
HSET user:1 name "张三" age 25
HGET user:1 name
HMGET user:1 name age
HGETALL user:1

# 判断/删除
HEXISTS user:1 name
HDEL user:1 age
HLEN user:1

# 获取所有键/值
HKEYS user:1
HVALS user:1

# 数值操作
HINCRBY user:1 age 1
HINCRBYFLOAT user:1 score 0.5
```

### 6.3 应用场景

```bash
# 存储对象
HSET user:1 name "张三" age 25 email "test@example.com"

# 购物车
HSET cart:user:1 product:1 2    # 商品1数量2
HINCRBY cart:user:1 product:1 1 # 加1
HDEL cart:user:1 product:1      # 删除
HGETALL cart:user:1             # 获取购物车
```

---

## 7. 数据类型 - Sorted Set

### 7.1 概述

有序集合，每个元素关联一个分数（score），按分数排序。

### 7.2 基本操作

```bash
# 添加
ZADD rank 100 "张三" 90 "李四" 80 "王五"

# 查询
ZSCORE rank "张三"               # 获取分数 → 100
ZRANK rank "张三"                # 获取排名（从0开始，升序）
ZREVRANK rank "张三"             # 获取排名（降序）
ZCARD rank                       # 数量

# 范围查询
ZRANGE rank 0 -1                 # 升序获取所有
ZRANGE rank 0 -1 WITHSCORES      # 带分数
ZREVRANGE rank 0 2               # 降序前3名
ZRANGEBYSCORE rank 80 100        # 分数范围

# 修改
ZINCRBY rank 10 "张三"           # 加分

# 删除
ZREM rank "王五"
ZREMRANGEBYRANK rank 0 1         # 删除排名范围
ZREMRANGEBYSCORE rank 0 60       # 删除分数范围
```

### 7.3 应用场景

```bash
# 排行榜
ZADD leaderboard 1000 "player1" 900 "player2"
ZINCRBY leaderboard 100 "player1"
ZREVRANGE leaderboard 0 9 WITHSCORES  # Top 10

# 延迟队列
ZADD delay:queue 1735100000 "task1"   # 时间戳作为分数
ZRANGEBYSCORE delay:queue 0 <current_timestamp>

# 热搜
ZINCRBY hot:search 1 "关键词"
ZREVRANGE hot:search 0 9
```


---

## 8. 特殊数据类型

### 8.1 Bitmaps（位图）

用于存储位信息，适合统计场景。

```bash
# 设置位
SETBIT sign:user:1:202412 0 1    # 12月1日签到
SETBIT sign:user:1:202412 1 1    # 12月2日签到

# 获取位
GETBIT sign:user:1:202412 0      # 1

# 统计
BITCOUNT sign:user:1:202412      # 签到天数

# 位运算
BITOP AND result key1 key2       # 与
BITOP OR result key1 key2        # 或
```

**应用：** 用户签到、在线状态、布隆过滤器

### 8.2 HyperLogLog

基数统计，用于统计不重复元素数量，误差约 0.81%。

```bash
PFADD visitors "user1" "user2" "user3"
PFADD visitors "user1" "user4"   # user1 重复不计
PFCOUNT visitors                 # 4

# 合并
PFMERGE result hll1 hll2
```

**应用：** UV 统计、独立访客数

### 8.3 Geospatial（地理位置）

存储地理位置信息。

```bash
# 添加位置
GEOADD locations 116.40 39.90 "北京" 121.47 31.23 "上海"

# 获取位置
GEOPOS locations "北京"

# 计算距离
GEODIST locations "北京" "上海" km    # 约 1068 km

# 范围查询
GEORADIUS locations 116.40 39.90 500 km  # 500km 内的城市
GEOSEARCH locations FROMMEMBER "北京" BYRADIUS 500 km
```

**应用：** 附近的人、门店搜索

### 8.4 Stream（消息流，Redis 5.0+）

类似 Kafka 的消息队列。

```bash
# 添加消息
XADD stream:orders * orderId 1 amount 100
# 返回消息ID：1735100000000-0

# 读取消息
XREAD COUNT 10 STREAMS stream:orders 0  # 从头读
XREAD BLOCK 5000 STREAMS stream:orders $  # 阻塞读取新消息

# 消费者组
XGROUP CREATE stream:orders group1 0
XREADGROUP GROUP group1 consumer1 COUNT 1 STREAMS stream:orders >
XACK stream:orders group1 <message-id>

# 查看信息
XLEN stream:orders
XINFO STREAM stream:orders
```

---

## 9. Key 操作

### 9.1 基本操作

```bash
# 查看
KEYS pattern                     # 查找匹配的 key（生产慎用）
KEYS user:*
SCAN cursor [MATCH pattern] [COUNT count]  # 渐进式遍历（推荐）
SCAN 0 MATCH user:* COUNT 100

EXISTS key [key ...]             # 是否存在
TYPE key                         # 类型
OBJECT ENCODING key              # 编码方式

# 删除
DEL key [key ...]                # 同步删除
UNLINK key [key ...]             # 异步删除（推荐）

# 重命名
RENAME key newkey
RENAMENX key newkey              # 新名不存在才重命名
```

### 9.2 过期时间

```bash
# 设置过期
EXPIRE key seconds               # 秒
PEXPIRE key milliseconds         # 毫秒
EXPIREAT key timestamp           # Unix 时间戳
PEXPIREAT key milliseconds-timestamp

# 查看剩余时间
TTL key                          # 秒（-1 永不过期，-2 不存在）
PTTL key                         # 毫秒

# 移除过期
PERSIST key
```

### 9.3 内存淘汰策略

```bash
# 配置
maxmemory 2gb
maxmemory-policy allkeys-lru
```

| 策略 | 说明 |
|------|------|
| noeviction | 不淘汰，内存满时报错 |
| allkeys-lru | 所有 key 中 LRU 淘汰 |
| allkeys-lfu | 所有 key 中 LFU 淘汰 |
| allkeys-random | 所有 key 随机淘汰 |
| volatile-lru | 有过期时间的 key 中 LRU 淘汰 |
| volatile-lfu | 有过期时间的 key 中 LFU 淘汰 |
| volatile-random | 有过期时间的 key 随机淘汰 |
| volatile-ttl | 淘汰 TTL 最小的 key |

---

## 10. 事务

### 10.1 基本事务

```bash
MULTI                            # 开启事务
SET name "张三"
INCR counter
EXEC                             # 执行事务

DISCARD                          # 取消事务
```

### 10.2 WATCH 乐观锁

```bash
WATCH key                        # 监视 key
MULTI
SET key newvalue
EXEC                             # 如果 key 被修改，返回 nil

UNWATCH                          # 取消监视
```

### 10.3 注意事项

- Redis 事务不支持回滚
- 命令入队时语法错误，整个事务不执行
- 执行时错误，其他命令继续执行

---

## 11. 发布订阅

```bash
# 订阅频道
SUBSCRIBE channel1 channel2
PSUBSCRIBE news:*                # 模式订阅

# 发布消息
PUBLISH channel1 "Hello"

# 查看
PUBSUB CHANNELS                  # 活跃频道
PUBSUB NUMSUB channel1           # 订阅数
```

**注意：** 消息不持久化，订阅者离线会丢失消息。生产环境建议用 Stream。

---

## 12. 持久化

### 12.1 RDB（快照）

```bash
# 配置
save 900 1                       # 900秒内1次修改
save 300 10
save 60 10000
dbfilename dump.rdb
dir /data

# 手动触发
SAVE                             # 同步（阻塞）
BGSAVE                           # 异步（推荐）
```

**优点：** 文件小、恢复快
**缺点：** 可能丢失最后一次快照后的数据

### 12.2 AOF（追加日志）

```bash
# 配置
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec             # always/everysec/no

# AOF 重写
BGREWRITEAOF
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
```

**优点：** 数据安全性高
**缺点：** 文件大、恢复慢

### 12.3 混合持久化（Redis 4.0+）

```bash
aof-use-rdb-preamble yes
```

AOF 文件前半部分是 RDB 格式，后半部分是 AOF 格式。


---

## 13. 主从复制

### 13.1 配置

```bash
# 从节点配置
replicaof 192.168.1.100 6379
masterauth yourpassword

# 或命令行
REPLICAOF 192.168.1.100 6379
REPLICAOF NO ONE                 # 取消复制
```

### 13.2 复制原理

```
1. 从节点发送 PSYNC 命令
2. 主节点执行 BGSAVE 生成 RDB
3. 主节点发送 RDB 给从节点
4. 从节点加载 RDB
5. 主节点发送缓冲区命令
6. 持续同步增量数据
```

### 13.3 查看状态

```bash
INFO replication
```

---

## 14. 哨兵模式

### 14.1 概述

哨兵（Sentinel）用于监控主从节点，实现自动故障转移。

### 14.2 配置（sentinel.conf）

```bash
sentinel monitor mymaster 192.168.1.100 6379 2
sentinel auth-pass mymaster yourpassword
sentinel down-after-milliseconds mymaster 30000
sentinel failover-timeout mymaster 180000
sentinel parallel-syncs mymaster 1
```

### 14.3 启动

```bash
redis-sentinel /path/to/sentinel.conf
# 或
redis-server /path/to/sentinel.conf --sentinel
```

### 14.4 工作原理

```
1. 哨兵定期 PING 主从节点
2. 主节点无响应，标记为主观下线
3. 多数哨兵确认，标记为客观下线
4. 选举领导者哨兵
5. 领导者选择新主节点
6. 通知其他从节点复制新主节点
7. 通知客户端新主节点地址
```

---

## 15. 集群模式

### 15.1 概述

Redis Cluster 是官方的分布式方案，数据分片存储在多个节点。

**特点：**
- 数据分片（16384 个槽）
- 主从复制
- 自动故障转移
- 无中心架构

### 15.2 创建集群

```bash
# 启动多个节点
redis-server --port 7001 --cluster-enabled yes --cluster-config-file nodes-7001.conf

# 创建集群
redis-cli --cluster create \
  192.168.1.101:7001 192.168.1.101:7002 \
  192.168.1.102:7001 192.168.1.102:7002 \
  192.168.1.103:7001 192.168.1.103:7002 \
  --cluster-replicas 1
```

### 15.3 集群操作

```bash
# 连接集群
redis-cli -c -h 192.168.1.101 -p 7001

# 查看集群信息
CLUSTER INFO
CLUSTER NODES
CLUSTER SLOTS

# 添加节点
redis-cli --cluster add-node new_host:port existing_host:port

# 重新分片
redis-cli --cluster reshard host:port
```

### 15.4 注意事项

- 不支持多 key 操作（除非在同一槽）
- 使用 Hash Tag 强制 key 在同一槽：`{user}:1:name`

---

## 16. Java 客户端

### 16.1 Jedis

```xml
<dependency>
    <groupId>redis.clients</groupId>
    <artifactId>jedis</artifactId>
    <version>4.3.1</version>
</dependency>
```

```java
// 单机
Jedis jedis = new Jedis("localhost", 6379);
jedis.auth("password");
jedis.set("name", "张三");
String name = jedis.get("name");
jedis.close();

// 连接池
JedisPoolConfig config = new JedisPoolConfig();
config.setMaxTotal(100);
config.setMaxIdle(10);
JedisPool pool = new JedisPool(config, "localhost", 6379);

try (Jedis jedis = pool.getResource()) {
    jedis.set("key", "value");
}
```

### 16.2 Lettuce（推荐）

```xml
<dependency>
    <groupId>io.lettuce</groupId>
    <artifactId>lettuce-core</artifactId>
    <version>6.2.6.RELEASE</version>
</dependency>
```

```java
RedisClient client = RedisClient.create("redis://password@localhost:6379");
StatefulRedisConnection<String, String> connection = client.connect();
RedisCommands<String, String> commands = connection.sync();

commands.set("name", "张三");
String name = commands.get("name");

connection.close();
client.shutdown();
```

### 16.3 Spring Boot 集成

```yaml
# application.yml
spring:
  redis:
    host: localhost
    port: 6379
    password: yourpassword
    lettuce:
      pool:
        max-active: 100
        max-idle: 10
        min-idle: 5
```

```java
@Autowired
private StringRedisTemplate redisTemplate;

// String
redisTemplate.opsForValue().set("name", "张三");
redisTemplate.opsForValue().set("token", "abc", 1, TimeUnit.HOURS);
String name = redisTemplate.opsForValue().get("name");

// Hash
redisTemplate.opsForHash().put("user:1", "name", "张三");
redisTemplate.opsForHash().putAll("user:1", map);
Object name = redisTemplate.opsForHash().get("user:1", "name");

// List
redisTemplate.opsForList().leftPush("list", "a");
redisTemplate.opsForList().range("list", 0, -1);

// Set
redisTemplate.opsForSet().add("set", "a", "b", "c");
redisTemplate.opsForSet().members("set");

// ZSet
redisTemplate.opsForZSet().add("rank", "张三", 100);
redisTemplate.opsForZSet().reverseRange("rank", 0, 9);

// 过期
redisTemplate.expire("key", 1, TimeUnit.HOURS);
redisTemplate.delete("key");
```

---

## 17. 应用场景

### 17.1 分布式锁

```java
// 加锁
Boolean locked = redisTemplate.opsForValue()
    .setIfAbsent("lock:order:" + orderId, uuid, 30, TimeUnit.SECONDS);

// 解锁（Lua 脚本保证原子性）
String script = 
    "if redis.call('get', KEYS[1]) == ARGV[1] then " +
    "   return redis.call('del', KEYS[1]) " +
    "else " +
    "   return 0 " +
    "end";
redisTemplate.execute(new DefaultRedisScript<>(script, Long.class),
    Collections.singletonList("lock:order:" + orderId), uuid);
```

### 17.2 限流

```java
// 滑动窗口限流
String key = "rate:" + userId;
long now = System.currentTimeMillis();
long windowStart = now - 60000; // 1分钟窗口

redisTemplate.opsForZSet().removeRangeByScore(key, 0, windowStart);
Long count = redisTemplate.opsForZSet().zCard(key);

if (count < 100) { // 每分钟100次
    redisTemplate.opsForZSet().add(key, String.valueOf(now), now);
    redisTemplate.expire(key, 1, TimeUnit.MINUTES);
    return true; // 允许
}
return false; // 拒绝
```

### 17.3 排行榜

```java
// 增加分数
redisTemplate.opsForZSet().incrementScore("leaderboard", "player1", 100);

// 获取排名
Long rank = redisTemplate.opsForZSet().reverseRank("leaderboard", "player1");

// Top 10
Set<ZSetOperations.TypedTuple<String>> top10 = 
    redisTemplate.opsForZSet().reverseRangeWithScores("leaderboard", 0, 9);
```

### 17.4 缓存

```java
public User getUser(Long id) {
    String key = "user:" + id;
    String json = redisTemplate.opsForValue().get(key);
    
    if (json != null) {
        return JSON.parseObject(json, User.class);
    }
    
    User user = userMapper.selectById(id);
    if (user != null) {
        redisTemplate.opsForValue().set(key, JSON.toJSONString(user), 1, TimeUnit.HOURS);
    } else {
        // 缓存空值防止穿透
        redisTemplate.opsForValue().set(key, "", 5, TimeUnit.MINUTES);
    }
    return user;
}
```


---

## 18. 性能优化

### 18.1 命令优化

```bash
# 避免使用 KEYS（生产环境）
KEYS user:*                      # ❌ 阻塞
SCAN 0 MATCH user:* COUNT 100    # ✓ 渐进式

# 批量操作
MSET k1 v1 k2 v2                 # ✓ 一次网络往返
SET k1 v1; SET k2 v2             # ❌ 多次网络往返

# Pipeline
Pipeline pipeline = jedis.pipelined();
for (int i = 0; i < 1000; i++) {
    pipeline.set("key" + i, "value" + i);
}
pipeline.sync();

# 避免大 Key
# String < 10KB
# List/Set/Hash/ZSet 元素 < 5000
```

### 18.2 内存优化

```bash
# 使用合适的数据结构
# 小数据量用 ziplist 编码更省内存

# 设置过期时间
EXPIRE key 3600

# 使用 Hash 代替多个 String
# ❌ user:1:name, user:1:age, user:1:email
# ✓ HSET user:1 name "张三" age 25 email "test@example.com"

# 查看内存使用
MEMORY USAGE key
INFO memory
```

### 18.3 配置优化

```bash
# 连接数
maxclients 10000

# 内存
maxmemory 4gb
maxmemory-policy allkeys-lru

# 持久化
# 根据业务选择 RDB/AOF/混合

# 慢查询
slowlog-log-slower-than 10000    # 10ms
slowlog-max-len 128
SLOWLOG GET 10                   # 查看慢查询
```

---

## 19. 常见错误与解决

### 19.1 连接错误

```
DENIED Redis is running in protected mode
```
**解决：** 设置密码或关闭保护模式
```bash
requirepass yourpassword
# 或
protected-mode no
```

```
Connection refused
```
**解决：** 检查 Redis 是否启动，bind 配置是否正确

### 19.2 内存错误

```
OOM command not allowed when used memory > 'maxmemory'
```
**解决：** 增加 maxmemory 或设置淘汰策略
```bash
maxmemory 4gb
maxmemory-policy allkeys-lru
```

### 19.3 持久化错误

```
MISCONF Redis is configured to save RDB snapshots
```
**解决：** 检查磁盘空间，或临时关闭
```bash
CONFIG SET stop-writes-on-bgsave-error no
```

### 19.4 集群错误

```
CLUSTERDOWN The cluster is down
```
**解决：** 检查集群节点状态，确保槽位分配完整

```
MOVED 3999 192.168.1.102:7002
```
**解决：** 使用 `-c` 参数连接集群
```bash
redis-cli -c -h host -p port
```

### 19.5 缓存问题

**缓存穿透：** 查询不存在的数据
```java
// 解决：缓存空值
if (data == null) {
    redisTemplate.opsForValue().set(key, "", 5, TimeUnit.MINUTES);
}
// 或使用布隆过滤器
```

**缓存击穿：** 热点 key 过期
```java
// 解决：互斥锁
String lockKey = "lock:" + key;
if (redisTemplate.opsForValue().setIfAbsent(lockKey, "1", 10, TimeUnit.SECONDS)) {
    try {
        // 查询数据库并缓存
    } finally {
        redisTemplate.delete(lockKey);
    }
}
```

**缓存雪崩：** 大量 key 同时过期
```java
// 解决：过期时间加随机值
int randomSeconds = new Random().nextInt(300);
redisTemplate.opsForValue().set(key, value, 3600 + randomSeconds, TimeUnit.SECONDS);
```

---

## 20. 总结

### 20.1 数据类型选择

| 场景 | 数据类型 |
|------|----------|
| 缓存对象 | String（JSON）或 Hash |
| 计数器 | String（INCR） |
| 队列 | List 或 Stream |
| 去重 | Set |
| 排行榜 | Sorted Set |
| 签到/统计 | Bitmap |
| UV 统计 | HyperLogLog |
| 地理位置 | Geospatial |

### 20.2 常用命令速查

```bash
# 通用
KEYS pattern / SCAN cursor
EXISTS key / TYPE key / DEL key
EXPIRE key seconds / TTL key

# String
SET key value [EX seconds] [NX|XX]
GET key / MGET key1 key2
INCR key / INCRBY key increment

# Hash
HSET key field value / HGET key field
HMSET key f1 v1 f2 v2 / HGETALL key

# List
LPUSH key value / RPUSH key value
LPOP key / RPOP key / LRANGE key start stop

# Set
SADD key member / SREM key member
SMEMBERS key / SINTER key1 key2

# Sorted Set
ZADD key score member
ZRANGE key start stop [WITHSCORES]
ZREVRANGE key start stop
ZINCRBY key increment member
```

### 20.3 最佳实践

1. **Key 命名规范**：`业务:对象:id:属性`，如 `user:1:name`
2. **避免大 Key**：String < 10KB，集合元素 < 5000
3. **设置过期时间**：避免内存无限增长
4. **使用连接池**：避免频繁创建连接
5. **批量操作**：使用 MSET/MGET/Pipeline
6. **生产禁用危险命令**：KEYS、FLUSHALL、FLUSHDB
7. **监控**：INFO、SLOWLOG、MEMORY
