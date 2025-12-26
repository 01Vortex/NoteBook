
> 基于 MongoDB 5.0.x 版本，从零开始系统学习 MongoDB。本笔记包含详细的概念讲解、命令示例和常见错误分析，帮助你真正掌握这个流行的文档型数据库。

---

## 目录

1. [MongoDB 概述](#1.MongoDB概述)
2. [安装与配置](#2.安装与配置)
3. [基本概念](#3.基本概念)
4. [数据库操作](#4.数据库操作)
5. [文档操作 - 增删改](#5.文档操作---增删改)
6. [文档操作 - 查询](#6.文档操作---查询)
7. [聚合操作](#7.聚合操作)
8. [索引](#8.索引)
9. [数据建模](#9.数据建模)
10. [事务](#10.事务)
11. [复制集](#11.复制集)
12. [分片集群](#12.分片集群)
13. [Java 客户端](#13.java-客户端)
14. [性能优化](#14.性能优化)
15. [常见错误与解决](#15.常见错误与解决)
16. [总结](#16.总结)

---

## 1. MongoDB概述

### 1.1 什么是 MongoDB？

**MongoDB** 是一个基于分布式文件存储的开源 **NoSQL 数据库**，由 C++ 编写。它使用类似 JSON 的 **BSON**（Binary JSON）格式存储数据，具有高性能、高可用、易扩展的特点。

**为什么叫"文档数据库"？**

在 MongoDB 中，数据以"文档"（Document）的形式存储，类似于 JSON 对象。你可以把它想象成一个超级灵活的"记事本"，每条记录可以有不同的字段结构。

```javascript
// 一个用户文档
{
    "_id": ObjectId("507f1f77bcf86cd799439011"),
    "name": "张三",
    "age": 25,
    "email": "zhangsan@example.com",
    "hobbies": ["篮球", "游戏", "编程"],
    "address": {
        "city": "北京",
        "district": "朝阳区"
    }
}
```

### 1.2 MongoDB vs 关系型数据库

| 对比项 | MongoDB | MySQL |
|--------|---------|-------|
| 数据模型 | 文档（BSON） | 表（行和列） |
| 模式 | 灵活（Schema-less） | 固定（Schema） |
| 关联 | 嵌入文档或引用 | 外键关联 |
| 事务 | 支持（4.0+） | 完整支持 |
| 扩展方式 | 水平扩展（分片） | 垂直扩展为主 |
| 查询语言 | MongoDB Query Language | SQL |
| 适用场景 | 大数据、灵活结构、高并发 | 复杂关联、强一致性 |

### 1.3 核心特性

| 特性 | 说明 |
|------|------|
| 文档模型 | 灵活的 JSON 风格文档 |
| 高性能 | 支持嵌入式文档减少 I/O |
| 高可用 | 复制集自动故障转移 |
| 水平扩展 | 分片集群支持海量数据 |
| 丰富的查询 | 支持动态查询、全文搜索、地理空间查询 |
| 聚合框架 | 强大的数据处理管道 |

### 1.4 应用场景

- **内容管理**：博客、CMS（文档结构灵活）
- **电商系统**：商品信息（属性多变）
- **社交应用**：用户动态、评论
- **物联网**：设备数据、日志
- **实时分析**：大数据聚合分析
- **游戏**：用户数据、排行榜

### 1.5 MongoDB 5.0 新特性

| 特性 | 说明 |
|------|------|
| 时序集合 | 原生支持时序数据 |
| 实时重新分片 | 在线调整分片 |
| 长时间运行快照查询 | 一致性读取 |
| 版本化 API | API 版本控制 |

---

## 2. 安装与配置

### 2.1 Docker 安装（推荐）

```
# 拉取镜像
docker pull mongo:5.0

# 运行容器
docker run -d \
  --name mongo5 \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=admin123 \
  -v mongo_data:/data/db \
  mongo:5.0

# 进入容器
docker exec -it mongo5 mongosh -u admin -p admin123

# 或使用 MongoDB Compass 图形化工具连接
# mongodb://admin:admin123@localhost:27017
```

### 2.2 Linux 安装

```bash
# Ubuntu
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# 启动
sudo systemctl start mongod
sudo systemctl enable mongod

# 连接
mongosh
```

### 2.3 配置文件（mongod.conf）

```yaml
# 存储配置
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true

# 网络配置
net:
  port: 27017
  bindIp: 0.0.0.0

# 安全配置
security:
  authorization: enabled

# 日志配置
systemLog:
  destination: file
  path: /var/log/mongodb/mongod.log
  logAppend: true

# 复制集配置
replication:
  replSetName: rs0
```

### 2.4 连接方式

```bash
# 本地连接
mongosh

# 指定主机和端口
mongosh --host localhost --port 27017

# 带认证
mongosh -u admin -p admin123 --authenticationDatabase admin

# 连接字符串
mongosh "mongodb://admin:admin123@localhost:27017/mydb?authSource=admin"
```

---

## 3. 基本概念

### 3.1 术语对照

| MongoDB | 关系型数据库 | 说明 |
|---------|-------------|------|
| Database | Database | 数据库 |
| Collection | Table | 集合（表） |
| Document | Row | 文档（行） |
| Field | Column | 字段（列） |
| Index | Index | 索引 |
| _id | Primary Key | 主键 |
| Embedded Document | Join | 嵌入文档 |
| Reference | Foreign Key | 引用 |

### 3.2 数据类型

| 类型 | 说明 | 示例 |
|------|------|------|
| String | 字符串 | `"Hello"` |
| Integer | 整数 | `123` |
| Double | 浮点数 | `3.14` |
| Boolean | 布尔值 | `true` |
| ObjectId | 文档 ID | `ObjectId("...")` |
| Date | 日期 | `ISODate("2024-01-01")` |
| Array | 数组 | `[1, 2, 3]` |
| Object | 嵌入文档 | `{name: "张三"}` |
| Null | 空值 | `null` |
| Binary | 二进制 | `BinData(...)` |
| Decimal128 | 高精度小数 | `NumberDecimal("9.99")` |

### 3.3 ObjectId

ObjectId 是 MongoDB 默认的主键类型，12 字节，由以下部分组成：

```
|  4字节   |  5字节  | 3字节 |
| 时间戳  | 随机值  | 计数器 |
```

```javascript
// 创建 ObjectId
ObjectId()                              // 自动生成
ObjectId("507f1f77bcf86cd799439011")   // 指定值

// 获取时间戳
ObjectId("507f1f77bcf86cd799439011").getTimestamp()
```

---

## 4. 数据库操作

### 4.1 数据库管理

```javascript
// 查看所有数据库
show dbs

// 切换/创建数据库（使用时自动创建）
use mydb

// 查看当前数据库
db

// 删除当前数据库
db.dropDatabase()

// 查看数据库状态
db.stats()
```

### 4.2 集合管理

```javascript
// 查看所有集合
show collections

// 创建集合
db.createCollection("users")

// 创建带选项的集合
db.createCollection("logs", {
    capped: true,           // 固定大小集合
    size: 10485760,         // 最大 10MB
    max: 5000               // 最多 5000 条文档
})

// 删除集合
db.users.drop()

// 重命名集合
db.users.renameCollection("members")

// 查看集合状态
db.users.stats()
```


---

## 5. 文档操作 - 增删改

### 5.1 插入文档

```javascript
// ============ 插入单个文档 ============
db.users.insertOne({
    name: "张三",
    age: 25,
    email: "zhangsan@example.com",
    hobbies: ["篮球", "游戏"],
    address: {
        city: "北京",
        district: "朝阳区"
    },
    createTime: new Date()
})

// ============ 插入多个文档 ============
db.users.insertMany([
    { name: "李四", age: 30, email: "lisi@example.com" },
    { name: "王五", age: 28, email: "wangwu@example.com" },
    { name: "赵六", age: 35, email: "zhaoliu@example.com" }
])

// ============ 插入选项 ============
db.users.insertMany(
    [{ name: "test1" }, { name: "test2" }],
    { ordered: false }  // 无序插入，一条失败不影响其他
)
```

### 5.2 更新文档

```javascript
// ============ 更新单个文档 ============
db.users.updateOne(
    { name: "张三" },                    // 查询条件
    { $set: { age: 26, email: "new@example.com" } }  // 更新操作
)

// ============ 更新多个文档 ============
db.users.updateMany(
    { age: { $lt: 30 } },               // 年龄小于 30
    { $set: { status: "young" } }
)

// ============ 替换文档 ============
db.users.replaceOne(
    { name: "张三" },
    { name: "张三", age: 27, email: "zhangsan@new.com" }  // 完全替换
)

// ============ 更新或插入（upsert） ============
db.users.updateOne(
    { name: "新用户" },
    { $set: { age: 20 } },
    { upsert: true }                    // 不存在则插入
)
```

### 5.3 更新操作符

```javascript
// ============ 字段操作 ============
// $set: 设置字段值
db.users.updateOne({ name: "张三" }, { $set: { age: 26 } })

// $unset: 删除字段
db.users.updateOne({ name: "张三" }, { $unset: { email: "" } })

// $rename: 重命名字段
db.users.updateOne({ name: "张三" }, { $rename: { "email": "mail" } })

// $inc: 数值增加
db.users.updateOne({ name: "张三" }, { $inc: { age: 1 } })      // +1
db.users.updateOne({ name: "张三" }, { $inc: { age: -1 } })     // -1

// $mul: 数值乘法
db.users.updateOne({ name: "张三" }, { $mul: { score: 1.1 } })  // *1.1

// $min/$max: 取最小/最大值
db.users.updateOne({ name: "张三" }, { $min: { age: 20 } })     // 如果 age > 20，则设为 20
db.users.updateOne({ name: "张三" }, { $max: { age: 30 } })     // 如果 age < 30，则设为 30

// $currentDate: 设置为当前日期
db.users.updateOne({ name: "张三" }, { $currentDate: { updateTime: true } })

// ============ 数组操作 ============
// $push: 添加元素
db.users.updateOne({ name: "张三" }, { $push: { hobbies: "游泳" } })

// $push + $each: 添加多个元素
db.users.updateOne({ name: "张三" }, { 
    $push: { hobbies: { $each: ["跑步", "健身"] } } 
})

// $addToSet: 添加元素（去重）
db.users.updateOne({ name: "张三" }, { $addToSet: { hobbies: "篮球" } })

// $pop: 删除第一个(-1)或最后一个(1)元素
db.users.updateOne({ name: "张三" }, { $pop: { hobbies: 1 } })

// $pull: 删除指定元素
db.users.updateOne({ name: "张三" }, { $pull: { hobbies: "游戏" } })

// $pullAll: 删除多个指定元素
db.users.updateOne({ name: "张三" }, { $pullAll: { hobbies: ["游戏", "篮球"] } })

// $: 更新数组中匹配的第一个元素
db.users.updateOne(
    { name: "张三", "scores.subject": "数学" },
    { $set: { "scores.$.score": 95 } }
)

// $[]: 更新数组中所有元素
db.users.updateOne(
    { name: "张三" },
    { $inc: { "scores.$[].score": 5 } }
)
```

### 5.4 删除文档

```javascript
// 删除单个文档
db.users.deleteOne({ name: "张三" })

// 删除多个文档
db.users.deleteMany({ age: { $lt: 18 } })

// 删除所有文档
db.users.deleteMany({})

// 查找并删除（返回被删除的文档）
db.users.findOneAndDelete({ name: "张三" })
```

---

## 6. 文档操作 - 查询

### 6.1 基本查询

```javascript
// 查询所有文档
db.users.find()

// 格式化输出
db.users.find().pretty()

// 查询单个文档
db.users.findOne({ name: "张三" })

// 指定返回字段（投影）
db.users.find({}, { name: 1, age: 1, _id: 0 })  // 1 包含，0 排除

// 统计数量
db.users.countDocuments({ age: { $gt: 20 } })
db.users.estimatedDocumentCount()  // 估算总数（更快）
```

### 6.2 比较操作符

```javascript
// $eq: 等于
db.users.find({ age: { $eq: 25 } })
db.users.find({ age: 25 })  // 简写

// $ne: 不等于
db.users.find({ age: { $ne: 25 } })

// $gt: 大于
db.users.find({ age: { $gt: 25 } })

// $gte: 大于等于
db.users.find({ age: { $gte: 25 } })

// $lt: 小于
db.users.find({ age: { $lt: 25 } })

// $lte: 小于等于
db.users.find({ age: { $lte: 25 } })

// $in: 在数组中
db.users.find({ age: { $in: [20, 25, 30] } })

// $nin: 不在数组中
db.users.find({ age: { $nin: [20, 25, 30] } })
```

### 6.3 逻辑操作符

```javascript
// $and: 与（默认多条件就是 AND）
db.users.find({ $and: [{ age: { $gt: 20 } }, { age: { $lt: 30 } }] })
db.users.find({ age: { $gt: 20, $lt: 30 } })  // 简写

// $or: 或
db.users.find({ $or: [{ age: { $lt: 20 } }, { age: { $gt: 30 } }] })

// $not: 非
db.users.find({ age: { $not: { $gt: 25 } } })

// $nor: 都不满足
db.users.find({ $nor: [{ age: 20 }, { age: 25 }] })
```

### 6.4 元素操作符

```javascript
// $exists: 字段是否存在
db.users.find({ email: { $exists: true } })
db.users.find({ email: { $exists: false } })

// $type: 字段类型
db.users.find({ age: { $type: "int" } })
db.users.find({ age: { $type: "number" } })
```

### 6.5 数组操作符

```javascript
// 数组包含某元素
db.users.find({ hobbies: "篮球" })

// $all: 包含所有指定元素
db.users.find({ hobbies: { $all: ["篮球", "游戏"] } })

// $size: 数组长度
db.users.find({ hobbies: { $size: 3 } })

// $elemMatch: 数组元素匹配多个条件
db.users.find({
    scores: { $elemMatch: { subject: "数学", score: { $gt: 90 } } }
})
```

### 6.6 正则表达式

```javascript
// 基本正则
db.users.find({ name: /^张/ })           // 以"张"开头
db.users.find({ name: /三$/ })           // 以"三"结尾
db.users.find({ email: /@example\.com$/ })

// $regex 操作符
db.users.find({ name: { $regex: "^张", $options: "i" } })  // i: 忽略大小写
```

### 6.7 排序、分页、限制

```javascript
// 排序
db.users.find().sort({ age: 1 })         // 升序
db.users.find().sort({ age: -1 })        // 降序
db.users.find().sort({ age: -1, name: 1 })  // 多字段排序

// 限制数量
db.users.find().limit(10)

// 跳过
db.users.find().skip(20)

// 分页（第 3 页，每页 10 条）
db.users.find().skip(20).limit(10).sort({ createTime: -1 })

// 去重
db.users.distinct("city")
db.users.distinct("city", { age: { $gt: 20 } })
```

### 6.8 嵌入文档查询

```javascript
// 精确匹配嵌入文档
db.users.find({ address: { city: "北京", district: "朝阳区" } })

// 点号表示法查询嵌入文档字段
db.users.find({ "address.city": "北京" })
db.users.find({ "address.city": "北京", "address.district": "朝阳区" })
```

---

## 7. 聚合操作

### 7.1 聚合管道概述

聚合管道（Aggregation Pipeline）是 MongoDB 强大的数据处理框架，数据通过多个阶段（Stage）依次处理。

```javascript
db.collection.aggregate([
    { $stage1: { ... } },
    { $stage2: { ... } },
    { $stage3: { ... } }
])
```

### 7.2 常用聚合阶段

```javascript
// ============ $match: 过滤 ============
db.orders.aggregate([
    { $match: { status: "completed", amount: { $gt: 100 } } }
])

// ============ $project: 投影 ============
db.users.aggregate([
    { $project: { 
        name: 1, 
        age: 1,
        email: 1,
        _id: 0,
        ageGroup: { $cond: { if: { $gte: ["$age", 18] }, then: "成年", else: "未成年" } }
    }}
])

// ============ $group: 分组 ============
db.orders.aggregate([
    { $group: {
        _id: "$userId",                    // 分组字段
        totalAmount: { $sum: "$amount" },  // 求和
        avgAmount: { $avg: "$amount" },    // 平均
        count: { $sum: 1 },                // 计数
        maxAmount: { $max: "$amount" },    // 最大
        minAmount: { $min: "$amount" },    // 最小
        orders: { $push: "$orderId" }      // 收集到数组
    }}
])

// ============ $sort: 排序 ============
db.users.aggregate([
    { $sort: { age: -1, name: 1 } }
])

// ============ $limit / $skip: 分页 ============
db.users.aggregate([
    { $skip: 10 },
    { $limit: 10 }
])

// ============ $unwind: 展开数组 ============
db.users.aggregate([
    { $unwind: "$hobbies" }  // 每个数组元素生成一个文档
])

// ============ $lookup: 关联查询（类似 JOIN） ============
db.orders.aggregate([
    { $lookup: {
        from: "users",           // 关联的集合
        localField: "userId",    // 本集合的字段
        foreignField: "_id",     // 关联集合的字段
        as: "userInfo"           // 输出字段名
    }}
])

// ============ $addFields: 添加字段 ============
db.users.aggregate([
    { $addFields: {
        fullName: { $concat: ["$firstName", " ", "$lastName"] },
        ageNextYear: { $add: ["$age", 1] }
    }}
])

// ============ $count: 计数 ============
db.users.aggregate([
    { $match: { age: { $gt: 20 } } },
    { $count: "adultCount" }
])
```

### 7.3 聚合表达式

```javascript
// 算术表达式
{ $add: ["$price", "$tax"] }           // 加法
{ $subtract: ["$price", "$discount"] } // 减法
{ $multiply: ["$price", "$quantity"] } // 乘法
{ $divide: ["$total", "$count"] }      // 除法
{ $mod: ["$num", 2] }                  // 取模

// 字符串表达式
{ $concat: ["$firstName", " ", "$lastName"] }  // 拼接
{ $substr: ["$name", 0, 3] }                   // 截取
{ $toUpper: "$name" }                          // 大写
{ $toLower: "$name" }                          // 小写

// 日期表达式
{ $year: "$createTime" }
{ $month: "$createTime" }
{ $dayOfMonth: "$createTime" }
{ $dateToString: { format: "%Y-%m-%d", date: "$createTime" } }

// 条件表达式
{ $cond: { if: { $gte: ["$age", 18] }, then: "成年", else: "未成年" } }
{ $ifNull: ["$email", "未设置"] }
{ $switch: {
    branches: [
        { case: { $gte: ["$score", 90] }, then: "A" },
        { case: { $gte: ["$score", 80] }, then: "B" },
        { case: { $gte: ["$score", 60] }, then: "C" }
    ],
    default: "D"
}}
```

### 7.4 实际案例

```javascript
// 案例1：统计每个城市的用户数和平均年龄
db.users.aggregate([
    { $group: {
        _id: "$address.city",
        userCount: { $sum: 1 },
        avgAge: { $avg: "$age" }
    }},
    { $sort: { userCount: -1 } },
    { $limit: 10 }
])

// 案例2：订单统计（按月份）
db.orders.aggregate([
    { $match: { status: "completed" } },
    { $group: {
        _id: { 
            year: { $year: "$createTime" },
            month: { $month: "$createTime" }
        },
        totalAmount: { $sum: "$amount" },
        orderCount: { $sum: 1 }
    }},
    { $sort: { "_id.year": -1, "_id.month": -1 } }
])

// 案例3：用户订单详情（关联查询）
db.users.aggregate([
    { $lookup: {
        from: "orders",
        localField: "_id",
        foreignField: "userId",
        as: "orders"
    }},
    { $addFields: {
        orderCount: { $size: "$orders" },
        totalSpent: { $sum: "$orders.amount" }
    }},
    { $project: { orders: 0 } }
])
```


---

## 8. 索引

### 8.1 索引概述

索引是提高查询性能的关键。MongoDB 支持多种索引类型。

### 8.2 索引操作

```javascript
// ============ 创建索引 ============
// 单字段索引
db.users.createIndex({ name: 1 })        // 升序
db.users.createIndex({ age: -1 })        // 降序

// 复合索引
db.users.createIndex({ name: 1, age: -1 })

// 唯一索引
db.users.createIndex({ email: 1 }, { unique: true })

// 稀疏索引（只索引存在该字段的文档）
db.users.createIndex({ phone: 1 }, { sparse: true })

// TTL 索引（自动过期删除）
db.logs.createIndex({ createTime: 1 }, { expireAfterSeconds: 86400 })  // 1天后删除

// 文本索引
db.articles.createIndex({ title: "text", content: "text" })

// 地理空间索引
db.places.createIndex({ location: "2dsphere" })

// 哈希索引（用于分片）
db.users.createIndex({ _id: "hashed" })

// ============ 查看索引 ============
db.users.getIndexes()

// ============ 删除索引 ============
db.users.dropIndex("name_1")
db.users.dropIndex({ name: 1 })
db.users.dropIndexes()  // 删除所有索引（除 _id）

// ============ 索引选项 ============
db.users.createIndex(
    { email: 1 },
    {
        unique: true,           // 唯一
        sparse: true,           // 稀疏
        background: true,       // 后台创建
        name: "idx_email",      // 索引名称
        partialFilterExpression: { status: "active" }  // 部分索引
    }
)
```

### 8.3 执行计划

```javascript
// 查看执行计划
db.users.find({ name: "张三" }).explain()
db.users.find({ name: "张三" }).explain("executionStats")

// 重要字段
// - winningPlan.stage: 执行阶段
//   - COLLSCAN: 全集合扫描（无索引）
//   - IXSCAN: 索引扫描
//   - FETCH: 根据索引获取文档
// - executionStats.totalDocsExamined: 扫描文档数
// - executionStats.totalKeysExamined: 扫描索引数
// - executionStats.executionTimeMillis: 执行时间
```

### 8.4 索引最佳实践

```javascript
// 1. 为常用查询字段创建索引
db.orders.createIndex({ userId: 1, createTime: -1 })

// 2. 复合索引遵循 ESR 原则
// E: Equality（等值查询字段放前面）
// S: Sort（排序字段）
// R: Range（范围查询字段放后面）
db.orders.createIndex({ status: 1, createTime: -1, amount: 1 })

// 3. 覆盖查询（只返回索引字段，不需要回表）
db.users.createIndex({ name: 1, email: 1 })
db.users.find({ name: "张三" }, { name: 1, email: 1, _id: 0 })

// 4. 避免创建过多索引（影响写入性能）

// 5. 定期分析慢查询
db.setProfilingLevel(1, { slowms: 100 })  // 记录超过 100ms 的查询
db.system.profile.find().sort({ ts: -1 }).limit(10)
```

---

## 9. 数据建模

### 9.1 嵌入式文档 vs 引用

**嵌入式文档（Embedded）：**

```javascript
// 用户和地址嵌入在一起
{
    _id: ObjectId("..."),
    name: "张三",
    addresses: [
        { type: "home", city: "北京", street: "朝阳路" },
        { type: "work", city: "北京", street: "中关村" }
    ]
}
```

**引用（Reference）：**

```javascript
// 用户文档
{ _id: ObjectId("user1"), name: "张三" }

// 地址文档（引用用户）
{ _id: ObjectId("addr1"), userId: ObjectId("user1"), city: "北京" }
```

### 9.2 选择建议

| 场景 | 推荐方式 | 原因 |
|------|----------|------|
| 一对一 | 嵌入 | 简单，一次查询 |
| 一对少（<100） | 嵌入 | 性能好 |
| 一对多（100-1000） | 引用或混合 | 避免文档过大 |
| 一对非常多（>1000） | 引用 | 文档大小限制 16MB |
| 多对多 | 引用 | 灵活 |
| 数据频繁更新 | 引用 | 避免重复更新 |
| 数据一起查询 | 嵌入 | 减少查询次数 |

### 9.3 设计模式

```javascript
// ============ 模式1：属性模式 ============
// 适合：属性不固定的商品
{
    _id: ObjectId("..."),
    name: "iPhone 15",
    attributes: [
        { key: "颜色", value: "黑色" },
        { key: "存储", value: "256GB" },
        { key: "屏幕", value: "6.1英寸" }
    ]
}

// ============ 模式2：桶模式 ============
// 适合：时序数据
{
    _id: ObjectId("..."),
    sensorId: "sensor001",
    date: ISODate("2024-01-01"),
    readings: [
        { time: ISODate("2024-01-01T00:00:00"), value: 25.5 },
        { time: ISODate("2024-01-01T00:01:00"), value: 25.6 },
        // ... 一天的数据
    ]
}

// ============ 模式3：预计算模式 ============
// 适合：统计数据
{
    _id: ObjectId("..."),
    articleId: ObjectId("article1"),
    views: 1000,
    likes: 50,
    comments: 20,
    lastUpdated: ISODate("2024-01-01")
}

// ============ 模式4：多态模式 ============
// 适合：不同类型的文档存在同一集合
{
    _id: ObjectId("..."),
    type: "book",
    title: "MongoDB 指南",
    author: "张三",
    pages: 500
}
{
    _id: ObjectId("..."),
    type: "video",
    title: "MongoDB 教程",
    duration: 3600,
    resolution: "1080p"
}
```

---

## 10. 事务

### 10.1 事务概述

MongoDB 4.0+ 支持多文档事务，4.2+ 支持分片集群事务。

### 10.2 事务操作

```javascript
// 开启会话
const session = db.getMongo().startSession()

// 开始事务
session.startTransaction({
    readConcern: { level: "snapshot" },
    writeConcern: { w: "majority" }
})

try {
    const users = session.getDatabase("mydb").users
    const accounts = session.getDatabase("mydb").accounts
    
    // 转账操作
    users.updateOne(
        { _id: "user1" },
        { $inc: { balance: -100 } },
        { session }
    )
    
    users.updateOne(
        { _id: "user2" },
        { $inc: { balance: 100 } },
        { session }
    )
    
    // 提交事务
    session.commitTransaction()
} catch (error) {
    // 回滚事务
    session.abortTransaction()
    throw error
} finally {
    session.endSession()
}
```

### 10.3 注意事项

- 事务有时间限制（默认 60 秒）
- 事务会影响性能，尽量保持简短
- 单文档操作本身就是原子的，不需要事务

---

## 11. 复制集

### 11.1 复制集概述

复制集（Replica Set）是 MongoDB 的高可用方案，由多个节点组成：
- **Primary**：主节点，处理写操作
- **Secondary**：从节点，复制主节点数据
- **Arbiter**：仲裁节点，只参与选举

### 11.2 配置复制集

```javascript
// 初始化复制集
rs.initiate({
    _id: "rs0",
    members: [
        { _id: 0, host: "mongo1:27017", priority: 2 },
        { _id: 1, host: "mongo2:27017", priority: 1 },
        { _id: 2, host: "mongo3:27017", priority: 1 }
    ]
})

// 查看状态
rs.status()
rs.conf()

// 添加节点
rs.add("mongo4:27017")
rs.addArb("mongo5:27017")  // 添加仲裁节点

// 移除节点
rs.remove("mongo4:27017")
```

### 11.3 读写分离

```javascript
// 连接字符串指定读偏好
"mongodb://mongo1:27017,mongo2:27017,mongo3:27017/mydb?replicaSet=rs0&readPreference=secondaryPreferred"

// 读偏好选项
// primary: 只从主节点读（默认）
// primaryPreferred: 优先主节点
// secondary: 只从从节点读
// secondaryPreferred: 优先从节点
// nearest: 最近的节点
```

---

## 12. 分片集群

### 12.1 分片概述

分片（Sharding）是 MongoDB 的水平扩展方案，将数据分布到多个分片上。

**组件：**
- **Shard**：存储数据的分片
- **Config Server**：存储集群元数据
- **Mongos**：路由，客户端连接入口

### 12.2 分片策略

```javascript
// 范围分片
sh.shardCollection("mydb.users", { age: 1 })

// 哈希分片（数据分布更均匀）
sh.shardCollection("mydb.orders", { _id: "hashed" })

// 区域分片
sh.addShardTag("shard1", "CN")
sh.addTagRange("mydb.users", { region: "CN" }, { region: "CN\uffff" }, "CN")
```

### 12.3 分片操作

```javascript
// 启用数据库分片
sh.enableSharding("mydb")

// 分片集合
sh.shardCollection("mydb.orders", { userId: "hashed" })

// 查看状态
sh.status()

// 查看分片分布
db.orders.getShardDistribution()
```

---

## 13. Java 客户端

### 13.1 MongoDB Driver

```xml
<dependency>
    <groupId>org.mongodb</groupId>
    <artifactId>mongodb-driver-sync</artifactId>
    <version>4.9.1</version>
</dependency>
```

```java
// 连接
MongoClient client = MongoClients.create("mongodb://localhost:27017");
MongoDatabase database = client.getDatabase("mydb");
MongoCollection<Document> collection = database.getCollection("users");

// 插入
Document doc = new Document("name", "张三")
    .append("age", 25)
    .append("email", "zhangsan@example.com");
collection.insertOne(doc);

// 查询
Document user = collection.find(eq("name", "张三")).first();
FindIterable<Document> users = collection.find(gt("age", 20));

// 更新
collection.updateOne(eq("name", "张三"), set("age", 26));

// 删除
collection.deleteOne(eq("name", "张三"));

// 关闭
client.close();
```

### 13.2 Spring Data MongoDB

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-mongodb</artifactId>
</dependency>
```

```yaml
# application.yml
spring:
  data:
    mongodb:
      uri: mongodb://admin:admin123@localhost:27017/mydb?authSource=admin
```

```java
// 实体类
@Document(collection = "users")
@Data
public class User {
    @Id
    private String id;
    private String name;
    private Integer age;
    private String email;
    @Indexed(unique = true)
    private String phone;
    private Address address;
    private List<String> hobbies;
    @CreatedDate
    private LocalDateTime createTime;
}

// Repository
public interface UserRepository extends MongoRepository<User, String> {
    List<User> findByName(String name);
    List<User> findByAgeGreaterThan(Integer age);
    List<User> findByAddressCity(String city);
    
    @Query("{ 'age': { $gt: ?0, $lt: ?1 } }")
    List<User> findByAgeRange(Integer min, Integer max);
}

// Service
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private MongoTemplate mongoTemplate;
    
    // 使用 Repository
    public User save(User user) {
        return userRepository.save(user);
    }
    
    // 使用 MongoTemplate（复杂查询）
    public List<User> findByCondition(String city, Integer minAge) {
        Query query = new Query();
        query.addCriteria(Criteria.where("address.city").is(city)
            .and("age").gte(minAge));
        query.with(Sort.by(Sort.Direction.DESC, "createTime"));
        query.limit(10);
        return mongoTemplate.find(query, User.class);
    }
    
    // 聚合查询
    public List<Document> aggregateByCity() {
        Aggregation agg = Aggregation.newAggregation(
            Aggregation.group("address.city")
                .count().as("count")
                .avg("age").as("avgAge"),
            Aggregation.sort(Sort.Direction.DESC, "count")
        );
        return mongoTemplate.aggregate(agg, "users", Document.class)
            .getMappedResults();
    }
}
```


---

## 14. 性能优化

### 14.1 查询优化

```javascript
// 1. 使用索引
db.users.createIndex({ name: 1, age: -1 })

// 2. 只返回需要的字段
db.users.find({ name: "张三" }, { name: 1, email: 1, _id: 0 })

// 3. 使用 limit 限制结果
db.users.find().limit(100)

// 4. 避免使用 $where（JavaScript 执行慢）
// ❌ db.users.find({ $where: "this.age > 20" })
// ✓ db.users.find({ age: { $gt: 20 } })

// 5. 使用 hint 强制使用索引
db.users.find({ name: "张三" }).hint({ name: 1 })

// 6. 分析慢查询
db.setProfilingLevel(1, { slowms: 100 })
db.system.profile.find().sort({ ts: -1 }).limit(10)
```

### 14.2 写入优化

```javascript
// 1. 批量插入
db.users.insertMany([...], { ordered: false })

// 2. 使用 bulkWrite
db.users.bulkWrite([
    { insertOne: { document: { name: "张三" } } },
    { updateOne: { filter: { name: "李四" }, update: { $set: { age: 30 } } } },
    { deleteOne: { filter: { name: "王五" } } }
], { ordered: false })

// 3. 合理设置 writeConcern
db.users.insertOne({ name: "张三" }, { writeConcern: { w: 1 } })
// w: 0 - 不等待确认
// w: 1 - 等待主节点确认（默认）
// w: "majority" - 等待多数节点确认
```

### 14.3 配置优化

```yaml
# mongod.conf
storage:
  wiredTiger:
    engineConfig:
      cacheSizeGB: 4  # 缓存大小（建议为内存的 50%）
    collectionConfig:
      blockCompressor: snappy  # 压缩算法

operationProfiling:
  slowOpThresholdMs: 100
  mode: slowOp
```

### 14.4 监控命令

```javascript
// 服务器状态
db.serverStatus()

// 当前操作
db.currentOp()

// 集合统计
db.users.stats()

// 索引使用情况
db.users.aggregate([{ $indexStats: {} }])

// 慢查询日志
db.system.profile.find().sort({ ts: -1 }).limit(10)
```

---

## 15. 常见错误与解决

### 15.1 连接错误

```
MongoNetworkError: connect ECONNREFUSED
```
**原因：** MongoDB 服务未启动或网络不通
**解决：** 检查服务状态，检查防火墙

```
Authentication failed
```
**原因：** 用户名密码错误或权限不足
**解决：** 检查认证信息，确认 authSource

### 15.2 写入错误

```
E11000 duplicate key error
```
**原因：** 唯一索引冲突
**解决：** 检查数据是否重复，或使用 upsert

```
document is larger than the maximum size 16777216
```
**原因：** 文档超过 16MB 限制
**解决：** 拆分文档，使用 GridFS 存储大文件

### 15.3 查询错误

```
Sort operation used more than the maximum 33554432 bytes of RAM
```
**原因：** 排序数据超过 32MB 内存限制
**解决：** 创建索引支持排序，或使用 allowDiskUse

```javascript
db.users.find().sort({ age: 1 }).allowDiskUse()
```

### 15.4 索引错误

```
Index build failed
```
**原因：** 创建唯一索引时存在重复数据
**解决：** 先清理重复数据，再创建索引

### 15.5 复制集错误

```
not master and slaveOk=false
```
**原因：** 从节点默认不允许读取
**解决：** 设置读偏好或在从节点执行 `rs.secondaryOk()`

---

## 16. 总结

### 16.1 CRUD 命令速查

```javascript
// 插入
db.collection.insertOne({ ... })
db.collection.insertMany([{ ... }, { ... }])

// 查询
db.collection.find({ ... })
db.collection.findOne({ ... })

// 更新
db.collection.updateOne({ filter }, { $set: { ... } })
db.collection.updateMany({ filter }, { $set: { ... } })
db.collection.replaceOne({ filter }, { ... })

// 删除
db.collection.deleteOne({ filter })
db.collection.deleteMany({ filter })

// 聚合
db.collection.aggregate([{ $match }, { $group }, { $sort }])
```

### 16.2 常用操作符

| 类型 | 操作符 |
|------|--------|
| 比较 | $eq, $ne, $gt, $gte, $lt, $lte, $in, $nin |
| 逻辑 | $and, $or, $not, $nor |
| 元素 | $exists, $type |
| 数组 | $all, $size, $elemMatch |
| 更新 | $set, $unset, $inc, $push, $pull, $addToSet |
| 聚合 | $match, $group, $project, $sort, $limit, $lookup |

### 16.3 最佳实践

1. **数据建模**：根据查询模式设计，优先嵌入
2. **索引策略**：为常用查询创建索引，遵循 ESR 原则
3. **文档大小**：控制在合理范围，避免超大文档
4. **批量操作**：使用 insertMany、bulkWrite
5. **读写分离**：复制集配置读偏好
6. **监控**：定期分析慢查询，优化性能
7. **备份**：定期备份，测试恢复流程

### 16.4 与 MySQL 对比选择

| 场景 | 推荐 |
|------|------|
| 复杂关联查询 | MySQL |
| 强事务要求 | MySQL |
| 灵活数据结构 | MongoDB |
| 大数据量、高并发 | MongoDB |
| 地理位置查询 | MongoDB |
| 日志、物联网数据 | MongoDB |
