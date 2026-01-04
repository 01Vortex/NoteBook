

> 基于 MySQL 8.0.x 版本，从零开始系统学习 MySQL 数据库。本笔记包含详细的概念讲解、SQL 语句示例和常见错误分析，帮助你真正掌握关系型数据库的核心技术。

---

## 目录

1. [MySQL 概述](#1.mysql-概述)
2. [安装与配置](#2.安装与配置)
3. [数据库基础操作](#3.数据库基础操作)
4. [数据类型](#4.数据类型)
5. [表操作（DDL）](#5.表操作ddl)
6. [数据操作（DML）](#6.数据操作dml)
7. [查询语句（DQL）](#7.查询语句dql)
8. [函数](#8.函数)
9. [约束](#9.约束)
10. [多表查询](#10.多表查询)
11. [子查询](#11.子查询)
12. [事务](#12.事务)
13. [索引](#13.索引)
14. [视图](#14.视图)
15. [存储过程与函数](#15.存储过程与函数)
16. [触发器](#16.触发器)
17. [用户与权限](#17.用户与权限)
18. [备份与恢复](#18.备份与恢复)
19. [性能优化](#19.性能优化)
20. [常见错误与解决](#20.常见错误与解决)

---

## 1. MySQL 概述

### 1.1 什么是 MySQL？

MySQL 是一个开源的**关系型数据库管理系统（RDBMS）**，由瑞典 MySQL AB 公司开发，现属于 Oracle 公司。它使用 SQL（结构化查询语言）进行数据管理。

**关系型数据库的特点：**
- 数据以**表（Table）**的形式存储
- 表由**行（Row）**和**列（Column）**组成
- 表与表之间可以建立**关系（Relationship）**
- 支持**事务（Transaction）**，保证数据一致性

**MySQL 的优势：**
- 开源免费（社区版）
- 性能优秀，适合高并发场景
- 跨平台，支持 Windows、Linux、macOS
- 生态丰富，社区活跃
- 支持多种存储引擎

### 1.2 MySQL 8.0 新特性

| 特性 | 说明 |
|------|------|
| 窗口函数 | ROW_NUMBER()、RANK()、DENSE_RANK() 等 |
| CTE | 公共表表达式（WITH 子句） |
| 原子 DDL | DDL 操作支持事务 |
| JSON 增强 | 更多 JSON 函数和索引支持 |
| 默认字符集 | 默认 utf8mb4，支持 emoji |
| 角色管理 | 支持角色（Role）简化权限管理 |
| 不可见索引 | 可以将索引设为不可见进行测试 |
| 降序索引 | 支持真正的降序索引 |
| 密码策略 | 更强的密码安全策略 |

### 1.3 MySQL 架构

```
┌─────────────────────────────────────────────────────────┐
│                    客户端连接层                           │
│  (MySQL Client, JDBC, ODBC, PHP, Python...)             │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                      服务层                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  │连接管理  │ │查询缓存  │ │ SQL解析  │ │查询优化  │        │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘        │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                    存储引擎层                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│  │ InnoDB  │ │ MyISAM  │ │ Memory  │ │  其他   │         │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘        │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                      文件系统                            │
│  (数据文件、日志文件、配置文件)                             │
└─────────────────────────────────────────────────────────┘
```

### 1.4 存储引擎对比

| 特性 | InnoDB | MyISAM | Memory |
|------|--------|--------|--------|
| 事务支持 | ✓ | ✗ | ✗ |
| 外键支持 | ✓ | ✗ | ✗ |
| 行级锁 | ✓ | ✗（表锁） | ✗（表锁） |
| 崩溃恢复 | ✓ | ✗ | ✗ |
| 全文索引 | ✓（5.6+） | ✓ | ✗ |
| 存储位置 | 磁盘 | 磁盘 | 内存 |
| 适用场景 | OLTP | 读多写少 | 临时数据 |

**MySQL 8.0 默认使用 InnoDB 存储引擎。**

---

## 2. 安装与配置

### 2.1 Linux 安装（CentOS/RHEL）

```bash
# 下载 MySQL Yum 仓库
wget https://dev.mysql.com/get/mysql80-community-release-el7-3.noarch.rpm

# 安装仓库
sudo rpm -ivh mysql80-community-release-el7-3.noarch.rpm

# 安装 MySQL
sudo yum install mysql-server

# 启动服务
sudo systemctl start mysqld
sudo systemctl enable mysqld

# 获取临时密码
sudo grep 'temporary password' /var/log/mysqld.log

# 安全初始化
sudo mysql_secure_installation
```

### 2.2 Docker 安装（推荐）

```bash
# 拉取镜像
docker pull mysql:8.0

# 运行容器
docker run -d \
  --name mysql8 \
  -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=root123 \
  -e MYSQL_DATABASE=testdb \
  -v mysql_data:/var/lib/mysql \
  mysql:8.0

# 进入容器
docker exec -it mysql8 mysql -uroot -p
```

### 2.3 配置文件（my.cnf）

```ini
[mysqld]
# 基础配置
port = 3306
datadir = /var/lib/mysql
socket = /var/lib/mysql/mysql.sock

# 字符集
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# 连接配置
max_connections = 500
max_connect_errors = 100

# 缓冲区配置
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_log_buffer_size = 16M

# 日志配置
log_error = /var/log/mysql/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

# 二进制日志（主从复制需要）
log_bin = mysql-bin
binlog_format = ROW
expire_logs_days = 7

# 时区
default-time-zone = '+08:00'

[client]
default-character-set = utf8mb4
```

### 2.4 连接 MySQL

```bash
# 命令行连接
mysql -h localhost -P 3306 -u root -p

# 常用参数
# -h: 主机地址
# -P: 端口号
# -u: 用户名
# -p: 密码（不要直接写在命令中）
# -D: 指定数据库
```

---

## 3. 数据库基础操作

### 3.1 数据库操作

```sql
-- ============ 查看数据库 ============
-- 查看所有数据库
SHOW DATABASES;

-- 查看当前数据库
SELECT DATABASE();

-- 查看数据库创建语句
SHOW CREATE DATABASE db_name;

-- ============ 创建数据库 ============
-- 基本创建
CREATE DATABASE mydb;

-- 指定字符集（推荐）
CREATE DATABASE mydb
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

-- 如果不存在则创建
CREATE DATABASE IF NOT EXISTS mydb;

-- ============ 使用数据库 ============
USE mydb;

-- ============ 修改数据库 ============
-- 修改字符集
ALTER DATABASE mydb CHARACTER SET utf8mb4;

-- ============ 删除数据库 ============
DROP DATABASE mydb;

-- 如果存在则删除
DROP DATABASE IF EXISTS mydb;
```

### 3.2 查看系统信息

```sql
-- 查看 MySQL 版本
SELECT VERSION();

-- 查看当前用户
SELECT USER();

-- 查看当前日期时间
SELECT NOW();

-- 查看系统变量
SHOW VARIABLES LIKE 'character%';
SHOW VARIABLES LIKE 'max_connections';

-- 查看状态
SHOW STATUS LIKE 'Threads%';

-- 查看进程列表
SHOW PROCESSLIST;

-- 查看存储引擎
SHOW ENGINES;
```


---

## 4. 数据类型

### 4.1 数值类型

| 类型 | 大小 | 范围（有符号） | 范围（无符号） | 用途 |
|------|------|----------------|----------------|------|
| TINYINT | 1 字节 | -128 ~ 127 | 0 ~ 255 | 小整数 |
| SMALLINT | 2 字节 | -32768 ~ 32767 | 0 ~ 65535 | 小整数 |
| MEDIUMINT | 3 字节 | -8388608 ~ 8388607 | 0 ~ 16777215 | 中等整数 |
| INT | 4 字节 | -2^31 ~ 2^31-1 | 0 ~ 2^32-1 | 标准整数 |
| BIGINT | 8 字节 | -2^63 ~ 2^63-1 | 0 ~ 2^64-1 | 大整数 |
| FLOAT | 4 字节 | | | 单精度浮点 |
| DOUBLE | 8 字节 | | | 双精度浮点 |
| DECIMAL(M,D) | 变长 | | | 精确小数 |

```sql
-- 整数类型
age TINYINT UNSIGNED,           -- 年龄（0-255）
status TINYINT DEFAULT 0,       -- 状态
user_id INT UNSIGNED,           -- 用户ID
order_id BIGINT UNSIGNED,       -- 订单ID（雪花算法）

-- 浮点类型（不精确，不推荐用于金额）
score FLOAT,
rate DOUBLE,

-- 精确小数（推荐用于金额）
price DECIMAL(10, 2),           -- 最大 99999999.99
amount DECIMAL(18, 4),          -- 高精度金额
```

**注意：** 金额等需要精确计算的字段，一定要用 `DECIMAL`，不要用 `FLOAT` 或 `DOUBLE`。

### 4.2 字符串类型

| 类型 | 大小 | 说明 |
|------|------|------|
| CHAR(N) | 0-255 字符 | 定长字符串，不足补空格 |
| VARCHAR(N) | 0-65535 字符 | 变长字符串 |
| TINYTEXT | 255 字节 | 短文本 |
| TEXT | 65535 字节 | 文本 |
| MEDIUMTEXT | 16MB | 中等文本 |
| LONGTEXT | 4GB | 长文本 |
| BINARY(N) | 0-255 字节 | 定长二进制 |
| VARBINARY(N) | 0-65535 字节 | 变长二进制 |
| BLOB | 65535 字节 | 二进制大对象 |

```sql
-- 定长字符串（适合固定长度的数据）
gender CHAR(1),                 -- 性别：M/F
country_code CHAR(2),           -- 国家代码：CN/US
uuid CHAR(36),                  -- UUID

-- 变长字符串（最常用）
username VARCHAR(50),           -- 用户名
email VARCHAR(100),             -- 邮箱
phone VARCHAR(20),              -- 手机号
title VARCHAR(200),             -- 标题

-- 文本类型（大段文字）
content TEXT,                   -- 文章内容
description MEDIUMTEXT,         -- 详细描述
```

**CHAR vs VARCHAR：**
- `CHAR(10)` 存储 "abc" 占用 10 个字符空间
- `VARCHAR(10)` 存储 "abc" 占用 3+1 个字符空间（+1 是长度标记）
- 固定长度用 CHAR，可变长度用 VARCHAR

### 4.3 日期时间类型

| 类型 | 大小 | 格式 | 范围 |
|------|------|------|------|
| DATE | 3 字节 | YYYY-MM-DD | 1000-01-01 ~ 9999-12-31 |
| TIME | 3 字节 | HH:MM:SS | -838:59:59 ~ 838:59:59 |
| DATETIME | 8 字节 | YYYY-MM-DD HH:MM:SS | 1000-01-01 ~ 9999-12-31 |
| TIMESTAMP | 4 字节 | YYYY-MM-DD HH:MM:SS | 1970-01-01 ~ 2038-01-19 |
| YEAR | 1 字节 | YYYY | 1901 ~ 2155 |

```sql
-- 日期
birthday DATE,                  -- 生日
start_date DATE,                -- 开始日期

-- 时间
duration TIME,                  -- 时长

-- 日期时间
create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
update_time DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

-- 时间戳（自动转换时区）
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
```

**DATETIME vs TIMESTAMP：**
- `DATETIME`：存储的是字面值，不受时区影响
- `TIMESTAMP`：存储的是 UTC 时间戳，会根据时区自动转换
- `TIMESTAMP` 有 2038 年问题，新项目建议用 `DATETIME`

### 4.4 JSON 类型（MySQL 5.7+）

```sql
-- 创建包含 JSON 字段的表
CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100),
    attributes JSON,
    tags JSON
);

-- 插入 JSON 数据
INSERT INTO products (name, attributes, tags) VALUES
('iPhone 15', '{"color": "black", "storage": "256GB", "price": 7999}', '["手机", "苹果", "5G"]');

-- 查询 JSON 字段
SELECT 
    name,
    attributes->>'$.color' AS color,           -- 提取值（去引号）
    attributes->'$.price' AS price,            -- 提取值（保留类型）
    JSON_EXTRACT(attributes, '$.storage') AS storage
FROM products;

-- JSON 函数
SELECT 
    JSON_KEYS(attributes) AS keys,             -- 获取所有键
    JSON_LENGTH(tags) AS tag_count,            -- 数组长度
    JSON_CONTAINS(tags, '"手机"') AS has_phone -- 是否包含
FROM products;

-- 修改 JSON
UPDATE products 
SET attributes = JSON_SET(attributes, '$.price', 6999)
WHERE id = 1;

-- JSON 数组操作
UPDATE products 
SET tags = JSON_ARRAY_APPEND(tags, '$', '新品')
WHERE id = 1;
```

### 4.5 枚举和集合

```sql
-- ENUM：只能选择一个值
CREATE TABLE users (
    id INT PRIMARY KEY,
    gender ENUM('male', 'female', 'other') DEFAULT 'other',
    status ENUM('active', 'inactive', 'banned') DEFAULT 'active'
);

-- SET：可以选择多个值
CREATE TABLE articles (
    id INT PRIMARY KEY,
    tags SET('tech', 'life', 'travel', 'food')
);

INSERT INTO articles VALUES (1, 'tech,life');
```

**注意：** 实际开发中，建议用 TINYINT + 代码中的枚举类，而不是数据库的 ENUM，因为 ENUM 修改不方便。

---

## 5. 表操作（DDL）

### 5.1 创建表

```sql
-- 基本语法
CREATE TABLE table_name (
    column1 datatype constraints,
    column2 datatype constraints,
    ...
    table_constraints
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 完整示例
CREATE TABLE users (
    -- 主键，自增
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT COMMENT '用户ID',
    
    -- 基本信息
    username VARCHAR(50) NOT NULL UNIQUE COMMENT '用户名',
    password VARCHAR(100) NOT NULL COMMENT '密码（加密）',
    email VARCHAR(100) COMMENT '邮箱',
    phone VARCHAR(20) COMMENT '手机号',
    
    -- 状态字段
    status TINYINT UNSIGNED DEFAULT 1 COMMENT '状态：0-禁用，1-正常',
    is_deleted TINYINT UNSIGNED DEFAULT 0 COMMENT '是否删除：0-否，1-是',
    
    -- 时间字段
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    update_time DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    
    -- 索引
    INDEX idx_email (email),
    INDEX idx_phone (phone),
    INDEX idx_create_time (create_time)
    
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

-- 复制表结构
CREATE TABLE users_backup LIKE users;

-- 复制表结构和数据
CREATE TABLE users_backup AS SELECT * FROM users;
```

### 5.2 查看表

```sql
-- 查看所有表
SHOW TABLES;

-- 查看表结构
DESC users;
DESCRIBE users;
SHOW COLUMNS FROM users;

-- 查看建表语句
SHOW CREATE TABLE users;

-- 查看表状态
SHOW TABLE STATUS LIKE 'users';
```

### 5.3 修改表

```sql
-- ============ 修改表名 ============
ALTER TABLE users RENAME TO t_users;
RENAME TABLE users TO t_users;

-- ============ 添加列 ============
-- 添加到末尾
ALTER TABLE users ADD COLUMN age TINYINT UNSIGNED COMMENT '年龄';

-- 添加到开头
ALTER TABLE users ADD COLUMN id2 INT FIRST;

-- 添加到指定列后面
ALTER TABLE users ADD COLUMN nickname VARCHAR(50) AFTER username;

-- 同时添加多列
ALTER TABLE users 
    ADD COLUMN avatar VARCHAR(200) COMMENT '头像',
    ADD COLUMN bio TEXT COMMENT '简介';

-- ============ 修改列 ============
-- 修改列类型和约束（MODIFY）
ALTER TABLE users MODIFY COLUMN email VARCHAR(150) NOT NULL;

-- 修改列名和类型（CHANGE）
ALTER TABLE users CHANGE COLUMN phone mobile VARCHAR(20);

-- 修改列默认值
ALTER TABLE users ALTER COLUMN status SET DEFAULT 0;

-- 删除列默认值
ALTER TABLE users ALTER COLUMN status DROP DEFAULT;

-- ============ 删除列 ============
ALTER TABLE users DROP COLUMN age;

-- ============ 修改表选项 ============
-- 修改存储引擎
ALTER TABLE users ENGINE = InnoDB;

-- 修改字符集
ALTER TABLE users CONVERT TO CHARACTER SET utf8mb4;

-- 修改注释
ALTER TABLE users COMMENT = '用户信息表';
```

### 5.4 删除表

```sql
-- 删除表
DROP TABLE users;

-- 如果存在则删除
DROP TABLE IF EXISTS users;

-- 删除多个表
DROP TABLE IF EXISTS users, orders, products;

-- 清空表数据（保留结构）
TRUNCATE TABLE users;

-- DELETE vs TRUNCATE
-- DELETE: 逐行删除，可以带条件，可以回滚，不重置自增
-- TRUNCATE: 删除并重建表，不能带条件，不能回滚，重置自增
```

---

## 6. 数据操作（DML）

### 6.1 插入数据（INSERT）

```sql
-- ============ 基本插入 ============
-- 指定列名插入
INSERT INTO users (username, password, email) 
VALUES ('zhangsan', '123456', 'zhangsan@example.com');

-- 插入所有列（不推荐，列顺序可能变化）
INSERT INTO users 
VALUES (NULL, 'lisi', '123456', 'lisi@example.com', NULL, 1, 0, NOW(), NOW());

-- ============ 批量插入 ============
INSERT INTO users (username, password, email) VALUES
    ('user1', 'pwd1', 'user1@example.com'),
    ('user2', 'pwd2', 'user2@example.com'),
    ('user3', 'pwd3', 'user3@example.com');

-- ============ 插入或更新 ============
-- 主键或唯一键冲突时更新
INSERT INTO users (id, username, email) 
VALUES (1, 'zhangsan', 'new@example.com')
ON DUPLICATE KEY UPDATE 
    email = VALUES(email),
    update_time = NOW();

-- ============ 插入或忽略 ============
-- 主键或唯一键冲突时忽略
INSERT IGNORE INTO users (username, password) 
VALUES ('zhangsan', '123456');

-- ============ 替换插入 ============
-- 主键或唯一键冲突时先删除再插入
REPLACE INTO users (id, username, password) 
VALUES (1, 'zhangsan', 'newpwd');

-- ============ 从查询结果插入 ============
INSERT INTO users_backup (username, email)
SELECT username, email FROM users WHERE status = 1;
```

### 6.2 更新数据（UPDATE）

```sql
-- ============ 基本更新 ============
UPDATE users SET email = 'new@example.com' WHERE id = 1;

-- 更新多个字段
UPDATE users 
SET 
    email = 'new@example.com',
    phone = '13800138000',
    update_time = NOW()
WHERE id = 1;

-- ============ 条件更新 ============
-- 更新所有符合条件的记录
UPDATE users SET status = 0 WHERE create_time < '2024-01-01';

-- 使用表达式
UPDATE products SET price = price * 0.9 WHERE category = 'electronics';

-- 使用 CASE WHEN
UPDATE users 
SET level = CASE 
    WHEN points >= 1000 THEN 'gold'
    WHEN points >= 500 THEN 'silver'
    ELSE 'bronze'
END;

-- ============ 关联更新 ============
-- 根据另一个表更新
UPDATE users u
INNER JOIN orders o ON u.id = o.user_id
SET u.last_order_time = o.create_time
WHERE o.status = 'completed';

-- ============ 限制更新数量 ============
UPDATE users SET status = 0 WHERE status = 1 LIMIT 10;

-- ============ 安全更新模式 ============
-- MySQL 默认开启安全更新模式，不允许没有 WHERE 或 LIMIT 的 UPDATE
-- 临时关闭
SET SQL_SAFE_UPDATES = 0;
UPDATE users SET status = 1;
SET SQL_SAFE_UPDATES = 1;
```

### 6.3 删除数据（DELETE）

```sql
-- ============ 基本删除 ============
DELETE FROM users WHERE id = 1;

-- 删除多条记录
DELETE FROM users WHERE status = 0;

-- ============ 关联删除 ============
-- 删除没有订单的用户
DELETE u FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE o.id IS NULL;

-- ============ 限制删除数量 ============
DELETE FROM logs WHERE create_time < '2024-01-01' LIMIT 1000;

-- ============ 清空表 ============
-- 方式1：DELETE（可回滚，不重置自增）
DELETE FROM users;

-- 方式2：TRUNCATE（不可回滚，重置自增，更快）
TRUNCATE TABLE users;
```

**软删除 vs 硬删除：**

```sql
-- 软删除（推荐）：只标记删除状态，数据还在
UPDATE users SET is_deleted = 1, delete_time = NOW() WHERE id = 1;

-- 硬删除：真正删除数据
DELETE FROM users WHERE id = 1;
```


---

## 7. 查询语句（DQL）

### 7.1 基本查询

```sql
-- ============ SELECT 基础 ============
-- 查询所有列
SELECT * FROM users;

-- 查询指定列
SELECT id, username, email FROM users;

-- 使用别名
SELECT 
    id AS user_id,
    username AS name,
    email AS '邮箱'
FROM users;

-- 去重
SELECT DISTINCT status FROM users;
SELECT DISTINCT city, province FROM users;  -- 组合去重

-- 常量和表达式
SELECT 
    username,
    price,
    price * 0.9 AS discount_price,
    'VIP' AS user_type
FROM products;
```

### 7.2 条件查询（WHERE）

```sql
-- ============ 比较运算符 ============
SELECT * FROM users WHERE age = 18;
SELECT * FROM users WHERE age != 18;
SELECT * FROM users WHERE age <> 18;
SELECT * FROM users WHERE age > 18;
SELECT * FROM users WHERE age >= 18;
SELECT * FROM users WHERE age < 18;
SELECT * FROM users WHERE age <= 18;

-- ============ 逻辑运算符 ============
SELECT * FROM users WHERE age >= 18 AND status = 1;
SELECT * FROM users WHERE age < 18 OR status = 0;
SELECT * FROM users WHERE NOT status = 0;
SELECT * FROM users WHERE NOT (age < 18);

-- ============ 范围查询 ============
-- BETWEEN（包含边界）
SELECT * FROM users WHERE age BETWEEN 18 AND 30;
-- 等价于
SELECT * FROM users WHERE age >= 18 AND age <= 30;

-- IN
SELECT * FROM users WHERE status IN (1, 2, 3);
SELECT * FROM users WHERE city IN ('北京', '上海', '广州');

-- NOT IN
SELECT * FROM users WHERE status NOT IN (0, -1);

-- ============ 空值判断 ============
SELECT * FROM users WHERE email IS NULL;
SELECT * FROM users WHERE email IS NOT NULL;

-- 注意：不能用 = NULL，要用 IS NULL
SELECT * FROM users WHERE email = NULL;  -- 错误！永远返回空

-- ============ 模糊查询 ============
-- % 匹配任意多个字符
SELECT * FROM users WHERE username LIKE '张%';      -- 以"张"开头
SELECT * FROM users WHERE username LIKE '%三';      -- 以"三"结尾
SELECT * FROM users WHERE username LIKE '%小%';     -- 包含"小"

-- _ 匹配单个字符
SELECT * FROM users WHERE username LIKE '张_';      -- "张"后面一个字符
SELECT * FROM users WHERE username LIKE '张__';     -- "张"后面两个字符

-- 转义特殊字符
SELECT * FROM products WHERE name LIKE '%\%%';      -- 包含 %
SELECT * FROM products WHERE name LIKE '%\_%';      -- 包含 _
SELECT * FROM products WHERE name LIKE '%10\%%' ESCAPE '\\';
```

### 7.3 排序（ORDER BY）

```sql
-- 升序（默认）
SELECT * FROM users ORDER BY create_time;
SELECT * FROM users ORDER BY create_time ASC;

-- 降序
SELECT * FROM users ORDER BY create_time DESC;

-- 多字段排序
SELECT * FROM users ORDER BY status DESC, create_time DESC;

-- 按表达式排序
SELECT * FROM products ORDER BY price * discount;

-- 按别名排序
SELECT *, price * 0.9 AS discount_price 
FROM products 
ORDER BY discount_price;

-- 按字段位置排序（不推荐）
SELECT id, username, age FROM users ORDER BY 3;  -- 按第3列（age）排序

-- NULL 值排序
-- MySQL 中 NULL 被视为最小值
SELECT * FROM users ORDER BY email;              -- NULL 在最前面
SELECT * FROM users ORDER BY email DESC;         -- NULL 在最后面

-- 自定义排序
SELECT * FROM users 
ORDER BY FIELD(status, 1, 2, 0, -1);  -- 按指定顺序排序
```

### 7.4 分页（LIMIT）

```sql
-- 基本分页
SELECT * FROM users LIMIT 10;           -- 前 10 条
SELECT * FROM users LIMIT 10 OFFSET 20; -- 跳过 20 条，取 10 条
SELECT * FROM users LIMIT 20, 10;       -- 同上，从第 21 条开始取 10 条

-- 分页公式：LIMIT (page - 1) * pageSize, pageSize
-- 第 1 页：LIMIT 0, 10
-- 第 2 页：LIMIT 10, 10
-- 第 3 页：LIMIT 20, 10

-- 分页查询示例
SELECT * FROM users 
WHERE status = 1 
ORDER BY create_time DESC 
LIMIT 0, 10;

-- 大数据量分页优化
-- 问题：LIMIT 1000000, 10 会扫描 1000010 行
-- 优化方案1：使用主键范围
SELECT * FROM users WHERE id > 1000000 ORDER BY id LIMIT 10;

-- 优化方案2：子查询
SELECT * FROM users 
WHERE id >= (SELECT id FROM users ORDER BY id LIMIT 1000000, 1)
LIMIT 10;
```

### 7.5 分组（GROUP BY）

```sql
-- ============ 基本分组 ============
-- 按状态分组统计
SELECT status, COUNT(*) AS count FROM users GROUP BY status;

-- 按城市分组统计
SELECT city, COUNT(*) AS user_count, AVG(age) AS avg_age
FROM users 
GROUP BY city;

-- 多字段分组
SELECT city, gender, COUNT(*) AS count
FROM users
GROUP BY city, gender;

-- ============ 分组过滤（HAVING） ============
-- WHERE 在分组前过滤，HAVING 在分组后过滤
SELECT city, COUNT(*) AS count
FROM users
WHERE status = 1           -- 先过滤状态为 1 的用户
GROUP BY city
HAVING count > 100;        -- 再过滤数量大于 100 的城市

-- HAVING 可以使用聚合函数
SELECT user_id, SUM(amount) AS total
FROM orders
GROUP BY user_id
HAVING SUM(amount) > 10000;

-- ============ WITH ROLLUP（汇总） ============
SELECT city, COUNT(*) AS count
FROM users
GROUP BY city WITH ROLLUP;
-- 结果会多一行 NULL，表示所有城市的总计
```

### 7.6 聚合函数

```sql
-- ============ 常用聚合函数 ============
SELECT 
    COUNT(*) AS total,              -- 总行数
    COUNT(email) AS email_count,    -- 非 NULL 的 email 数量
    COUNT(DISTINCT city) AS cities, -- 不同城市数量
    SUM(amount) AS total_amount,    -- 总金额
    AVG(amount) AS avg_amount,      -- 平均金额
    MAX(amount) AS max_amount,      -- 最大金额
    MIN(amount) AS min_amount,      -- 最小金额
    GROUP_CONCAT(username) AS names -- 拼接字符串
FROM orders;

-- ============ GROUP_CONCAT 详解 ============
-- 基本用法
SELECT user_id, GROUP_CONCAT(product_name) AS products
FROM orders
GROUP BY user_id;

-- 指定分隔符
SELECT user_id, GROUP_CONCAT(product_name SEPARATOR ', ') AS products
FROM orders
GROUP BY user_id;

-- 去重
SELECT user_id, GROUP_CONCAT(DISTINCT product_name) AS products
FROM orders
GROUP BY user_id;

-- 排序
SELECT user_id, GROUP_CONCAT(product_name ORDER BY create_time DESC) AS products
FROM orders
GROUP BY user_id;
```

### 7.7 SQL 执行顺序

```sql
SELECT DISTINCT column, AGG_FUNC(column)  -- 5. 选择列
FROM table                                 -- 1. 确定数据源
JOIN another_table ON condition            -- 2. 连接表
WHERE condition                            -- 3. 过滤行
GROUP BY column                            -- 4. 分组
HAVING condition                           -- 6. 过滤分组
ORDER BY column                            -- 7. 排序
LIMIT offset, count;                       -- 8. 分页

-- 执行顺序：FROM → JOIN → WHERE → GROUP BY → HAVING → SELECT → DISTINCT → ORDER BY → LIMIT
```

---

## 8. 函数

### 8.1 字符串函数

```sql
-- ============ 常用字符串函数 ============
SELECT 
    CONCAT('Hello', ' ', 'World'),          -- 'Hello World'
    CONCAT_WS('-', '2024', '01', '01'),     -- '2024-01-01'
    LENGTH('Hello'),                         -- 5（字节数）
    CHAR_LENGTH('你好'),                     -- 2（字符数）
    UPPER('hello'),                          -- 'HELLO'
    LOWER('HELLO'),                          -- 'hello'
    TRIM('  hello  '),                       -- 'hello'
    LTRIM('  hello'),                        -- 'hello'
    RTRIM('hello  '),                        -- 'hello'
    LEFT('hello', 3),                        -- 'hel'
    RIGHT('hello', 3),                       -- 'llo'
    SUBSTRING('hello', 2, 3),                -- 'ell'（从第2个字符开始取3个）
    SUBSTR('hello', 2),                      -- 'ello'（从第2个字符到末尾）
    REPLACE('hello', 'l', 'L'),              -- 'heLLo'
    REVERSE('hello'),                        -- 'olleh'
    REPEAT('ab', 3),                         -- 'ababab'
    LPAD('123', 5, '0'),                     -- '00123'（左填充）
    RPAD('123', 5, '0'),                     -- '12300'（右填充）
    INSTR('hello', 'l'),                     -- 3（第一次出现的位置）
    LOCATE('l', 'hello'),                    -- 3（同上）
    FIELD('b', 'a', 'b', 'c'),              -- 2（在列表中的位置）
    FORMAT(1234567.89, 2);                   -- '1,234,567.89'

-- ============ 实际应用 ============
-- 手机号脱敏
SELECT CONCAT(LEFT(phone, 3), '****', RIGHT(phone, 4)) AS masked_phone
FROM users;

-- 邮箱脱敏
SELECT CONCAT(LEFT(email, 3), '***', SUBSTRING(email, INSTR(email, '@'))) AS masked_email
FROM users;

-- 生成订单号
SELECT CONCAT('ORD', DATE_FORMAT(NOW(), '%Y%m%d'), LPAD(id, 6, '0')) AS order_no
FROM orders;
```

### 8.2 数值函数

```sql
SELECT 
    ABS(-10),                    -- 10（绝对值）
    CEIL(3.14),                  -- 4（向上取整）
    CEILING(3.14),               -- 4（同上）
    FLOOR(3.94),                 -- 3（向下取整）
    ROUND(3.567, 2),             -- 3.57（四舍五入）
    TRUNCATE(3.567, 2),          -- 3.56（截断）
    MOD(10, 3),                  -- 1（取模）
    10 % 3,                      -- 1（同上）
    POW(2, 10),                  -- 1024（幂运算）
    POWER(2, 10),                -- 1024（同上）
    SQRT(16),                    -- 4（平方根）
    RAND(),                      -- 0-1 之间的随机数
    RAND(1),                     -- 带种子的随机数（可重复）
    SIGN(-10),                   -- -1（符号：-1/0/1）
    GREATEST(1, 5, 3),           -- 5（最大值）
    LEAST(1, 5, 3);              -- 1（最小值）

-- 生成随机整数（1-100）
SELECT FLOOR(RAND() * 100) + 1;

-- 保留两位小数
SELECT ROUND(price * 0.9, 2) AS discount_price FROM products;
```

### 8.3 日期时间函数

```sql
-- ============ 获取当前时间 ============
SELECT 
    NOW(),                       -- 2024-12-25 10:30:00
    CURRENT_TIMESTAMP(),         -- 同上
    CURDATE(),                   -- 2024-12-25
    CURRENT_DATE(),              -- 同上
    CURTIME(),                   -- 10:30:00
    CURRENT_TIME();              -- 同上

-- ============ 提取日期部分 ============
SELECT 
    YEAR('2024-12-25'),          -- 2024
    MONTH('2024-12-25'),         -- 12
    DAY('2024-12-25'),           -- 25
    HOUR('10:30:45'),            -- 10
    MINUTE('10:30:45'),          -- 30
    SECOND('10:30:45'),          -- 45
    DAYOFWEEK('2024-12-25'),     -- 4（周三，1=周日）
    WEEKDAY('2024-12-25'),       -- 2（周三，0=周一）
    DAYOFYEAR('2024-12-25'),     -- 360
    WEEK('2024-12-25'),          -- 52（第几周）
    QUARTER('2024-12-25');       -- 4（第几季度）

-- ============ 日期格式化 ============
SELECT DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s');  -- 2024-12-25 10:30:00
SELECT DATE_FORMAT(NOW(), '%Y年%m月%d日');        -- 2024年12月25日
SELECT TIME_FORMAT(NOW(), '%H:%i');              -- 10:30

-- 格式化符号
-- %Y: 4位年份    %y: 2位年份
-- %m: 月份(01-12) %c: 月份(1-12)
-- %d: 日(01-31)   %e: 日(1-31)
-- %H: 小时(00-23) %h: 小时(01-12)
-- %i: 分钟(00-59)
-- %s: 秒(00-59)
-- %W: 星期名     %w: 星期(0-6)

-- ============ 日期计算 ============
SELECT 
    DATE_ADD(NOW(), INTERVAL 7 DAY),      -- 7天后
    DATE_ADD(NOW(), INTERVAL 1 MONTH),    -- 1个月后
    DATE_ADD(NOW(), INTERVAL 1 YEAR),     -- 1年后
    DATE_SUB(NOW(), INTERVAL 7 DAY),      -- 7天前
    DATEDIFF('2024-12-31', '2024-01-01'), -- 365（相差天数）
    TIMESTAMPDIFF(MONTH, '2024-01-01', '2024-12-31'),  -- 11（相差月数）
    TIMESTAMPDIFF(YEAR, '2000-01-01', NOW());         -- 年龄

-- ============ 日期转换 ============
SELECT 
    STR_TO_DATE('2024-12-25', '%Y-%m-%d'),  -- 字符串转日期
    UNIX_TIMESTAMP(),                        -- 当前时间戳
    UNIX_TIMESTAMP('2024-12-25 10:30:00'),  -- 指定时间的时间戳
    FROM_UNIXTIME(1735100000);              -- 时间戳转日期

-- ============ 实际应用 ============
-- 查询今天的订单
SELECT * FROM orders WHERE DATE(create_time) = CURDATE();

-- 查询本月的订单
SELECT * FROM orders 
WHERE YEAR(create_time) = YEAR(NOW()) 
  AND MONTH(create_time) = MONTH(NOW());

-- 查询最近7天的订单
SELECT * FROM orders WHERE create_time >= DATE_SUB(NOW(), INTERVAL 7 DAY);

-- 计算年龄
SELECT username, TIMESTAMPDIFF(YEAR, birthday, CURDATE()) AS age FROM users;
```

### 8.4 条件函数

```sql
-- ============ IF 函数 ============
SELECT 
    username,
    IF(status = 1, '正常', '禁用') AS status_text
FROM users;

-- ============ IFNULL / COALESCE ============
SELECT 
    IFNULL(email, '未设置') AS email,           -- 如果为 NULL 返回默认值
    COALESCE(email, phone, '无联系方式') AS contact;  -- 返回第一个非 NULL 值

-- ============ NULLIF ============
SELECT NULLIF(10, 10);  -- NULL（两个值相等返回 NULL）
SELECT NULLIF(10, 20);  -- 10（两个值不等返回第一个值）

-- ============ CASE WHEN ============
-- 简单 CASE
SELECT 
    username,
    CASE status
        WHEN 0 THEN '禁用'
        WHEN 1 THEN '正常'
        WHEN 2 THEN 'VIP'
        ELSE '未知'
    END AS status_text
FROM users;

-- 搜索 CASE
SELECT 
    username,
    CASE 
        WHEN age < 18 THEN '未成年'
        WHEN age < 30 THEN '青年'
        WHEN age < 50 THEN '中年'
        ELSE '老年'
    END AS age_group
FROM users;

-- 用于统计
SELECT 
    SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) AS active_count,
    SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) AS inactive_count,
    SUM(CASE WHEN gender = 'male' THEN 1 ELSE 0 END) AS male_count,
    SUM(CASE WHEN gender = 'female' THEN 1 ELSE 0 END) AS female_count
FROM users;
```

### 8.5 窗口函数（MySQL 8.0+）

```sql
-- ============ 排名函数 ============
SELECT 
    username,
    score,
    ROW_NUMBER() OVER (ORDER BY score DESC) AS row_num,    -- 行号（1,2,3,4,5）
    RANK() OVER (ORDER BY score DESC) AS rank_num,         -- 排名（1,2,2,4,5）
    DENSE_RANK() OVER (ORDER BY score DESC) AS dense_rank  -- 密集排名（1,2,2,3,4）
FROM students;

-- 分组排名
SELECT 
    class,
    username,
    score,
    ROW_NUMBER() OVER (PARTITION BY class ORDER BY score DESC) AS class_rank
FROM students;

-- ============ 聚合窗口函数 ============
SELECT 
    username,
    amount,
    SUM(amount) OVER () AS total,                          -- 总计
    SUM(amount) OVER (ORDER BY create_time) AS running_total,  -- 累计
    AVG(amount) OVER () AS avg_amount,                     -- 平均
    COUNT(*) OVER () AS total_count                        -- 总数
FROM orders;

-- 分组聚合
SELECT 
    user_id,
    amount,
    SUM(amount) OVER (PARTITION BY user_id) AS user_total,
    SUM(amount) OVER (PARTITION BY user_id ORDER BY create_time) AS user_running_total
FROM orders;

-- ============ 偏移函数 ============
SELECT 
    username,
    amount,
    LAG(amount, 1) OVER (ORDER BY create_time) AS prev_amount,   -- 上一行
    LEAD(amount, 1) OVER (ORDER BY create_time) AS next_amount,  -- 下一行
    FIRST_VALUE(amount) OVER (ORDER BY create_time) AS first_amount,  -- 第一行
    LAST_VALUE(amount) OVER (ORDER BY create_time) AS last_amount     -- 最后一行
FROM orders;

-- ============ 实际应用 ============
-- 计算环比增长
SELECT 
    month,
    amount,
    LAG(amount, 1) OVER (ORDER BY month) AS prev_amount,
    ROUND((amount - LAG(amount, 1) OVER (ORDER BY month)) / 
          LAG(amount, 1) OVER (ORDER BY month) * 100, 2) AS growth_rate
FROM monthly_sales;

-- 取每组前 N 名
SELECT * FROM (
    SELECT 
        class,
        username,
        score,
        ROW_NUMBER() OVER (PARTITION BY class ORDER BY score DESC) AS rn
    FROM students
) t WHERE rn <= 3;
```


---

## 9. 约束

### 9.1 约束类型

| 约束 | 关键字 | 说明 |
|------|--------|------|
| 主键 | PRIMARY KEY | 唯一标识，非空且唯一 |
| 唯一 | UNIQUE | 值唯一，允许 NULL |
| 非空 | NOT NULL | 不允许 NULL |
| 默认值 | DEFAULT | 默认值 |
| 检查 | CHECK | 检查条件（MySQL 8.0.16+） |
| 外键 | FOREIGN KEY | 关联其他表 |
| 自增 | AUTO_INCREMENT | 自动递增 |

### 9.2 主键约束

```sql
-- ============ 创建主键 ============
-- 方式1：列级约束
CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50)
);

-- 方式2：表级约束
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT,
    username VARCHAR(50),
    PRIMARY KEY (id)
);

-- 复合主键
CREATE TABLE order_items (
    order_id BIGINT,
    product_id BIGINT,
    quantity INT,
    PRIMARY KEY (order_id, product_id)
);

-- ============ 添加主键 ============
ALTER TABLE users ADD PRIMARY KEY (id);

-- ============ 删除主键 ============
ALTER TABLE users DROP PRIMARY KEY;

-- ============ 自增相关 ============
-- 查看自增值
SHOW CREATE TABLE users;
SELECT AUTO_INCREMENT FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'mydb' AND TABLE_NAME = 'users';

-- 设置自增起始值
ALTER TABLE users AUTO_INCREMENT = 1000;

-- 插入时指定 ID
INSERT INTO users (id, username) VALUES (100, 'test');
-- 下一个自增值会从 101 开始
```

### 9.3 唯一约束

```sql
-- ============ 创建唯一约束 ============
-- 方式1：列级约束
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(100) UNIQUE
);

-- 方式2：表级约束（可以命名）
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    UNIQUE KEY uk_username (username),
    UNIQUE KEY uk_email (email)
);

-- 复合唯一约束
CREATE TABLE user_roles (
    user_id BIGINT,
    role_id BIGINT,
    UNIQUE KEY uk_user_role (user_id, role_id)
);

-- ============ 添加唯一约束 ============
ALTER TABLE users ADD UNIQUE KEY uk_phone (phone);

-- ============ 删除唯一约束 ============
ALTER TABLE users DROP INDEX uk_phone;
```

### 9.4 非空和默认值约束

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,                    -- 非空
    status TINYINT NOT NULL DEFAULT 1,                -- 非空 + 默认值
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP,   -- 默认当前时间
    update_time DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 修改非空约束
ALTER TABLE users MODIFY COLUMN email VARCHAR(100) NOT NULL;
ALTER TABLE users MODIFY COLUMN email VARCHAR(100) NULL;

-- 修改默认值
ALTER TABLE users ALTER COLUMN status SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN status DROP DEFAULT;
```

### 9.5 检查约束（MySQL 8.0.16+）

```sql
-- ============ 创建检查约束 ============
CREATE TABLE products (
    id BIGINT PRIMARY KEY,
    name VARCHAR(100),
    price DECIMAL(10, 2),
    stock INT,
    CONSTRAINT chk_price CHECK (price > 0),
    CONSTRAINT chk_stock CHECK (stock >= 0)
);

-- 多条件检查
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    age TINYINT,
    gender CHAR(1),
    CONSTRAINT chk_age CHECK (age >= 0 AND age <= 150),
    CONSTRAINT chk_gender CHECK (gender IN ('M', 'F'))
);

-- ============ 添加检查约束 ============
ALTER TABLE products ADD CONSTRAINT chk_price CHECK (price > 0);

-- ============ 删除检查约束 ============
ALTER TABLE products DROP CHECK chk_price;
```

### 9.6 外键约束

```sql
-- ============ 创建外键 ============
-- 先创建主表
CREATE TABLE departments (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL
);

-- 再创建从表
CREATE TABLE employees (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL,
    dept_id BIGINT,
    CONSTRAINT fk_dept FOREIGN KEY (dept_id) REFERENCES departments(id)
);

-- ============ 外键行为 ============
-- ON DELETE / ON UPDATE 可选值：
-- RESTRICT: 拒绝操作（默认）
-- CASCADE: 级联操作
-- SET NULL: 设为 NULL
-- NO ACTION: 同 RESTRICT

CREATE TABLE employees (
    id BIGINT PRIMARY KEY,
    name VARCHAR(50),
    dept_id BIGINT,
    CONSTRAINT fk_dept FOREIGN KEY (dept_id) 
        REFERENCES departments(id)
        ON DELETE SET NULL      -- 删除部门时，员工的 dept_id 设为 NULL
        ON UPDATE CASCADE       -- 更新部门 ID 时，员工的 dept_id 同步更新
);

-- ============ 添加外键 ============
ALTER TABLE employees 
ADD CONSTRAINT fk_dept FOREIGN KEY (dept_id) REFERENCES departments(id);

-- ============ 删除外键 ============
ALTER TABLE employees DROP FOREIGN KEY fk_dept;

-- ============ 查看外键 ============
SELECT * FROM information_schema.KEY_COLUMN_USAGE 
WHERE TABLE_SCHEMA = 'mydb' AND TABLE_NAME = 'employees';
```

**外键的优缺点：**

| 优点 | 缺点 |
|------|------|
| 保证数据完整性 | 影响性能（插入/更新/删除都要检查） |
| 级联操作方便 | 不利于分库分表 |
| 数据库层面约束 | 增加维护复杂度 |

**实际开发建议：** 互联网项目通常不使用外键，而是在应用层保证数据一致性。

---

## 10. 多表查询

### 10.1 表关系

```
一对一（1:1）：用户 - 用户详情
一对多（1:N）：部门 - 员工
多对多（M:N）：学生 - 课程（需要中间表）
```

### 10.2 内连接（INNER JOIN）

返回两个表中匹配的记录。

```sql
-- 隐式内连接
SELECT e.name, d.name AS dept_name
FROM employees e, departments d
WHERE e.dept_id = d.id;

-- 显式内连接（推荐）
SELECT e.name, d.name AS dept_name
FROM employees e
INNER JOIN departments d ON e.dept_id = d.id;

-- 多表连接
SELECT 
    e.name AS employee,
    d.name AS department,
    p.name AS project
FROM employees e
INNER JOIN departments d ON e.dept_id = d.id
INNER JOIN projects p ON e.project_id = p.id;
```

### 10.3 外连接（OUTER JOIN）

```sql
-- ============ 左外连接 ============
-- 返回左表所有记录，右表没有匹配的显示 NULL
SELECT e.name, d.name AS dept_name
FROM employees e
LEFT JOIN departments d ON e.dept_id = d.id;

-- 查询没有部门的员工
SELECT e.name
FROM employees e
LEFT JOIN departments d ON e.dept_id = d.id
WHERE d.id IS NULL;

-- ============ 右外连接 ============
-- 返回右表所有记录，左表没有匹配的显示 NULL
SELECT e.name, d.name AS dept_name
FROM employees e
RIGHT JOIN departments d ON e.dept_id = d.id;

-- 查询没有员工的部门
SELECT d.name
FROM employees e
RIGHT JOIN departments d ON e.dept_id = d.id
WHERE e.id IS NULL;

-- ============ 全外连接 ============
-- MySQL 不支持 FULL OUTER JOIN，用 UNION 模拟
SELECT e.name, d.name AS dept_name
FROM employees e
LEFT JOIN departments d ON e.dept_id = d.id
UNION
SELECT e.name, d.name AS dept_name
FROM employees e
RIGHT JOIN departments d ON e.dept_id = d.id;
```

### 10.4 自连接

```sql
-- 查询员工及其上级
SELECT 
    e.name AS employee,
    m.name AS manager
FROM employees e
LEFT JOIN employees m ON e.manager_id = m.id;

-- 查询同一部门的员工对
SELECT 
    e1.name AS employee1,
    e2.name AS employee2
FROM employees e1
INNER JOIN employees e2 ON e1.dept_id = e2.dept_id AND e1.id < e2.id;
```

### 10.5 交叉连接（笛卡尔积）

```sql
-- 返回两个表的所有组合
SELECT * FROM employees CROSS JOIN departments;

-- 等价于
SELECT * FROM employees, departments;

-- 实际应用：生成日期表
SELECT * FROM 
    (SELECT 0 AS n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3) a
CROSS JOIN 
    (SELECT 0 AS m UNION SELECT 1 UNION SELECT 2 UNION SELECT 3) b;
```

### 10.6 UNION 合并查询

```sql
-- UNION：合并并去重
SELECT name FROM employees
UNION
SELECT name FROM managers;

-- UNION ALL：合并不去重（更快）
SELECT name FROM employees
UNION ALL
SELECT name FROM managers;

-- 注意：列数和类型必须一致
SELECT id, name, 'employee' AS type FROM employees
UNION ALL
SELECT id, name, 'manager' AS type FROM managers;
```

---

## 11. 子查询

### 11.1 标量子查询

返回单个值。

```sql
-- 查询工资高于平均工资的员工
SELECT * FROM employees 
WHERE salary > (SELECT AVG(salary) FROM employees);

-- 查询最新订单
SELECT * FROM orders 
WHERE create_time = (SELECT MAX(create_time) FROM orders);
```

### 11.2 列子查询

返回一列多行。

```sql
-- 查询有订单的用户
SELECT * FROM users 
WHERE id IN (SELECT DISTINCT user_id FROM orders);

-- 查询没有订单的用户
SELECT * FROM users 
WHERE id NOT IN (SELECT DISTINCT user_id FROM orders WHERE user_id IS NOT NULL);

-- 使用 ANY/SOME
SELECT * FROM employees 
WHERE salary > ANY (SELECT salary FROM employees WHERE dept_id = 1);

-- 使用 ALL
SELECT * FROM employees 
WHERE salary > ALL (SELECT salary FROM employees WHERE dept_id = 1);
```

### 11.3 行子查询

返回一行多列。

```sql
-- 查询与张三同部门同职位的员工
SELECT * FROM employees 
WHERE (dept_id, position) = (
    SELECT dept_id, position FROM employees WHERE name = '张三'
);
```

### 11.4 表子查询

返回多行多列，作为临时表使用。

```sql
-- 查询每个部门工资最高的员工
SELECT e.* FROM employees e
INNER JOIN (
    SELECT dept_id, MAX(salary) AS max_salary
    FROM employees
    GROUP BY dept_id
) t ON e.dept_id = t.dept_id AND e.salary = t.max_salary;

-- 分页优化
SELECT * FROM users
WHERE id >= (SELECT id FROM users ORDER BY id LIMIT 100000, 1)
LIMIT 10;
```

### 11.5 EXISTS 子查询

```sql
-- 查询有订单的用户
SELECT * FROM users u
WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id);

-- 查询没有订单的用户
SELECT * FROM users u
WHERE NOT EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id);

-- EXISTS vs IN
-- EXISTS 适合外表小、内表大的情况
-- IN 适合外表大、内表小的情况
```

### 11.6 CTE 公共表表达式（MySQL 8.0+）

```sql
-- ============ 基本 CTE ============
WITH dept_stats AS (
    SELECT dept_id, COUNT(*) AS emp_count, AVG(salary) AS avg_salary
    FROM employees
    GROUP BY dept_id
)
SELECT d.name, s.emp_count, s.avg_salary
FROM departments d
INNER JOIN dept_stats s ON d.id = s.dept_id;

-- ============ 多个 CTE ============
WITH 
dept_stats AS (
    SELECT dept_id, COUNT(*) AS emp_count
    FROM employees
    GROUP BY dept_id
),
high_salary AS (
    SELECT * FROM employees WHERE salary > 10000
)
SELECT * FROM dept_stats
UNION ALL
SELECT dept_id, COUNT(*) FROM high_salary GROUP BY dept_id;

-- ============ 递归 CTE ============
-- 查询组织架构树
WITH RECURSIVE org_tree AS (
    -- 基础查询：顶级部门
    SELECT id, name, parent_id, 1 AS level
    FROM departments
    WHERE parent_id IS NULL
    
    UNION ALL
    
    -- 递归查询：子部门
    SELECT d.id, d.name, d.parent_id, t.level + 1
    FROM departments d
    INNER JOIN org_tree t ON d.parent_id = t.id
)
SELECT * FROM org_tree ORDER BY level, id;

-- 生成数字序列
WITH RECURSIVE numbers AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM numbers WHERE n < 100
)
SELECT * FROM numbers;
```


---

## 12. 事务

### 12.1 事务概述

**事务（Transaction）** 是一组操作的集合，要么全部成功，要么全部失败。

**ACID 特性：**

| 特性 | 英文 | 说明 |
|------|------|------|
| 原子性 | Atomicity | 事务是不可分割的最小单位 |
| 一致性 | Consistency | 事务前后数据保持一致 |
| 隔离性 | Isolation | 多个事务互不干扰 |
| 持久性 | Durability | 事务提交后永久保存 |

### 12.2 事务操作

```sql
-- ============ 基本事务 ============
-- 开启事务
START TRANSACTION;
-- 或
BEGIN;

-- 执行操作
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;

-- 提交事务
COMMIT;

-- 或回滚事务
ROLLBACK;

-- ============ 自动提交 ============
-- 查看自动提交状态
SELECT @@autocommit;

-- 关闭自动提交
SET autocommit = 0;

-- 开启自动提交
SET autocommit = 1;

-- ============ 保存点 ============
START TRANSACTION;

UPDATE accounts SET balance = balance - 100 WHERE id = 1;
SAVEPOINT sp1;  -- 创建保存点

UPDATE accounts SET balance = balance + 100 WHERE id = 2;
SAVEPOINT sp2;

-- 回滚到保存点
ROLLBACK TO sp1;

COMMIT;
```

### 12.3 隔离级别

**并发问题：**

| 问题 | 说明 |
|------|------|
| 脏读 | 读到其他事务未提交的数据 |
| 不可重复读 | 同一事务内两次读取结果不同（数据被修改） |
| 幻读 | 同一事务内两次读取记录数不同（数据被插入/删除） |

**隔离级别：**

| 隔离级别 | 脏读 | 不可重复读 | 幻读 |
|----------|------|------------|------|
| READ UNCOMMITTED | ✗ | ✗ | ✗ |
| READ COMMITTED | ✓ | ✗ | ✗ |
| REPEATABLE READ（默认） | ✓ | ✓ | ✗ |
| SERIALIZABLE | ✓ | ✓ | ✓ |

```sql
-- 查看隔离级别
SELECT @@transaction_isolation;
SELECT @@global.transaction_isolation;

-- 设置隔离级别
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET GLOBAL TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- 或在配置文件中设置
-- transaction-isolation = READ-COMMITTED
```

### 12.4 锁机制

```sql
-- ============ 共享锁（读锁） ============
-- 其他事务可以读，但不能写
SELECT * FROM users WHERE id = 1 LOCK IN SHARE MODE;
-- MySQL 8.0+ 推荐写法
SELECT * FROM users WHERE id = 1 FOR SHARE;

-- ============ 排他锁（写锁） ============
-- 其他事务不能读也不能写
SELECT * FROM users WHERE id = 1 FOR UPDATE;

-- ============ 锁的范围 ============
-- 行锁：锁定特定行（需要索引）
SELECT * FROM users WHERE id = 1 FOR UPDATE;

-- 间隙锁：锁定范围（防止幻读）
SELECT * FROM users WHERE id BETWEEN 1 AND 10 FOR UPDATE;

-- 表锁
LOCK TABLES users READ;   -- 读锁
LOCK TABLES users WRITE;  -- 写锁
UNLOCK TABLES;            -- 解锁

-- ============ 死锁 ============
-- 事务1
START TRANSACTION;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;  -- 等待事务2

-- 事务2
START TRANSACTION;
UPDATE accounts SET balance = balance - 100 WHERE id = 2;
UPDATE accounts SET balance = balance + 100 WHERE id = 1;  -- 等待事务1，死锁！

-- 查看死锁日志
SHOW ENGINE INNODB STATUS;

-- 避免死锁的方法：
-- 1. 按固定顺序访问表和行
-- 2. 大事务拆分成小事务
-- 3. 使用较低的隔离级别
-- 4. 为表添加合适的索引
```

---

## 13. 索引

### 13.1 索引概述

**索引** 是帮助 MySQL 高效获取数据的数据结构，类似于书的目录。

**索引的优缺点：**

| 优点 | 缺点 |
|------|------|
| 提高查询速度 | 占用磁盘空间 |
| 加速排序和分组 | 降低增删改速度 |
| 保证数据唯一性 | 需要维护 |

### 13.2 索引类型

| 类型 | 说明 | 关键字 |
|------|------|--------|
| 主键索引 | 唯一且非空 | PRIMARY KEY |
| 唯一索引 | 唯一，允许 NULL | UNIQUE |
| 普通索引 | 最基本的索引 | INDEX / KEY |
| 全文索引 | 用于全文搜索 | FULLTEXT |
| 空间索引 | 用于地理数据 | SPATIAL |

### 13.3 索引操作

```sql
-- ============ 创建索引 ============
-- 方式1：创建表时
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    INDEX idx_username (username),
    UNIQUE INDEX idx_email (email)
);

-- 方式2：ALTER TABLE
ALTER TABLE users ADD INDEX idx_phone (phone);
ALTER TABLE users ADD UNIQUE INDEX idx_email (email);

-- 方式3：CREATE INDEX
CREATE INDEX idx_create_time ON users (create_time);
CREATE UNIQUE INDEX idx_email ON users (email);

-- ============ 复合索引 ============
CREATE INDEX idx_name_age ON users (name, age);

-- ============ 前缀索引 ============
-- 对长字符串只索引前 N 个字符
CREATE INDEX idx_email ON users (email(20));

-- ============ 查看索引 ============
SHOW INDEX FROM users;
SHOW KEYS FROM users;

-- ============ 删除索引 ============
DROP INDEX idx_phone ON users;
ALTER TABLE users DROP INDEX idx_phone;

-- ============ 不可见索引（MySQL 8.0+） ============
-- 将索引设为不可见，测试删除索引的影响
ALTER TABLE users ALTER INDEX idx_phone INVISIBLE;
ALTER TABLE users ALTER INDEX idx_phone VISIBLE;
```

### 13.4 索引设计原则

```sql
-- ============ 适合创建索引的情况 ============
-- 1. 主键自动创建索引
-- 2. 频繁作为查询条件的字段
-- 3. 外键字段
-- 4. 排序字段
-- 5. 分组字段
-- 6. 统计字段

-- ============ 不适合创建索引的情况 ============
-- 1. 数据量小的表
-- 2. 频繁更新的字段
-- 3. 很少用于查询的字段
-- 4. 区分度低的字段（如性别）

-- ============ 复合索引设计 ============
-- 最左前缀原则
CREATE INDEX idx_a_b_c ON t (a, b, c);

-- 以下查询可以使用索引：
WHERE a = 1
WHERE a = 1 AND b = 2
WHERE a = 1 AND b = 2 AND c = 3
WHERE a = 1 AND c = 3  -- 只用到 a

-- 以下查询不能使用索引：
WHERE b = 2
WHERE c = 3
WHERE b = 2 AND c = 3

-- ============ 索引失效的情况 ============
-- 1. 使用函数
WHERE YEAR(create_time) = 2024  -- 不走索引
WHERE create_time >= '2024-01-01' AND create_time < '2025-01-01'  -- 走索引

-- 2. 隐式类型转换
WHERE phone = 13800138000  -- phone 是 VARCHAR，不走索引
WHERE phone = '13800138000'  -- 走索引

-- 3. LIKE 以 % 开头
WHERE name LIKE '%张'  -- 不走索引
WHERE name LIKE '张%'  -- 走索引

-- 4. OR 条件（除非所有条件都有索引）
WHERE a = 1 OR b = 2  -- 如果 b 没有索引，整个查询不走索引

-- 5. NOT IN / NOT EXISTS / !=
WHERE status != 1  -- 可能不走索引

-- 6. IS NULL / IS NOT NULL（取决于数据分布）
```

### 13.5 EXPLAIN 执行计划

```sql
EXPLAIN SELECT * FROM users WHERE username = 'zhangsan';

-- 重要字段说明：
-- type: 访问类型（从好到差）
--   system > const > eq_ref > ref > range > index > ALL
-- possible_keys: 可能使用的索引
-- key: 实际使用的索引
-- key_len: 索引长度
-- rows: 预估扫描行数
-- Extra: 额外信息
--   Using index: 覆盖索引
--   Using where: 使用 WHERE 过滤
--   Using filesort: 需要额外排序
--   Using temporary: 使用临时表

-- ============ type 详解 ============
-- const: 主键或唯一索引等值查询
EXPLAIN SELECT * FROM users WHERE id = 1;

-- eq_ref: 连接查询使用主键或唯一索引
EXPLAIN SELECT * FROM orders o JOIN users u ON o.user_id = u.id;

-- ref: 非唯一索引等值查询
EXPLAIN SELECT * FROM users WHERE status = 1;

-- range: 范围查询
EXPLAIN SELECT * FROM users WHERE id > 100;

-- index: 全索引扫描
EXPLAIN SELECT id FROM users;

-- ALL: 全表扫描（最差）
EXPLAIN SELECT * FROM users WHERE name LIKE '%张%';
```

---

## 14. 视图

### 14.1 视图概述

**视图（View）** 是一个虚拟表，它的内容由查询定义。视图不存储数据，只存储 SQL 语句。

**视图的优点：**
- 简化复杂查询
- 提供数据安全性（隐藏敏感列）
- 提供逻辑数据独立性

### 14.2 视图操作

```sql
-- ============ 创建视图 ============
CREATE VIEW v_user_info AS
SELECT id, username, email, create_time
FROM users
WHERE status = 1;

-- 带检查选项
CREATE VIEW v_active_users AS
SELECT * FROM users WHERE status = 1
WITH CHECK OPTION;  -- 插入/更新时检查是否满足条件

-- ============ 查看视图 ============
SHOW TABLES;  -- 视图也会显示
SHOW CREATE VIEW v_user_info;
DESC v_user_info;

-- ============ 使用视图 ============
SELECT * FROM v_user_info WHERE id = 1;

-- ============ 修改视图 ============
ALTER VIEW v_user_info AS
SELECT id, username, email, phone, create_time
FROM users
WHERE status = 1;

-- 或
CREATE OR REPLACE VIEW v_user_info AS
SELECT id, username, email
FROM users;

-- ============ 删除视图 ============
DROP VIEW v_user_info;
DROP VIEW IF EXISTS v_user_info;

-- ============ 通过视图更新数据 ============
-- 简单视图可以更新
UPDATE v_user_info SET email = 'new@example.com' WHERE id = 1;

-- 以下情况不能更新：
-- 1. 包含聚合函数
-- 2. 包含 DISTINCT
-- 3. 包含 GROUP BY
-- 4. 包含 UNION
-- 5. 包含子查询
-- 6. 包含 JOIN（某些情况）
```

### 14.3 视图应用场景

```sql
-- ============ 简化复杂查询 ============
CREATE VIEW v_order_detail AS
SELECT 
    o.id AS order_id,
    o.order_no,
    u.username,
    p.name AS product_name,
    oi.quantity,
    oi.price,
    o.create_time
FROM orders o
JOIN users u ON o.user_id = u.id
JOIN order_items oi ON o.id = oi.order_id
JOIN products p ON oi.product_id = p.id;

-- 使用时只需
SELECT * FROM v_order_detail WHERE username = 'zhangsan';

-- ============ 数据安全 ============
-- 隐藏敏感信息
CREATE VIEW v_user_public AS
SELECT id, username, 
    CONCAT(LEFT(email, 3), '***', SUBSTRING(email, INSTR(email, '@'))) AS email
FROM users;

-- ============ 统计视图 ============
CREATE VIEW v_daily_sales AS
SELECT 
    DATE(create_time) AS date,
    COUNT(*) AS order_count,
    SUM(amount) AS total_amount
FROM orders
GROUP BY DATE(create_time);
```

---

## 15. 存储过程与函数

### 15.1 存储过程

```sql
-- ============ 创建存储过程 ============
DELIMITER //

CREATE PROCEDURE sp_get_user(IN p_id BIGINT)
BEGIN
    SELECT * FROM users WHERE id = p_id;
END //

DELIMITER ;

-- ============ 调用存储过程 ============
CALL sp_get_user(1);

-- ============ 带输出参数 ============
DELIMITER //

CREATE PROCEDURE sp_get_user_count(OUT p_count INT)
BEGIN
    SELECT COUNT(*) INTO p_count FROM users;
END //

DELIMITER ;

-- 调用
CALL sp_get_user_count(@count);
SELECT @count;

-- ============ 带输入输出参数 ============
DELIMITER //

CREATE PROCEDURE sp_increase_salary(INOUT p_salary DECIMAL(10,2), IN p_rate DECIMAL(5,2))
BEGIN
    SET p_salary = p_salary * (1 + p_rate);
END //

DELIMITER ;

-- 调用
SET @salary = 10000;
CALL sp_increase_salary(@salary, 0.1);
SELECT @salary;  -- 11000

-- ============ 复杂存储过程 ============
DELIMITER //

CREATE PROCEDURE sp_transfer(
    IN p_from_id BIGINT,
    IN p_to_id BIGINT,
    IN p_amount DECIMAL(10,2),
    OUT p_result VARCHAR(50)
)
BEGIN
    DECLARE v_balance DECIMAL(10,2);
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        SET p_result = '转账失败';
    END;
    
    START TRANSACTION;
    
    -- 检查余额
    SELECT balance INTO v_balance FROM accounts WHERE id = p_from_id FOR UPDATE;
    
    IF v_balance < p_amount THEN
        SET p_result = '余额不足';
        ROLLBACK;
    ELSE
        -- 扣款
        UPDATE accounts SET balance = balance - p_amount WHERE id = p_from_id;
        -- 入账
        UPDATE accounts SET balance = balance + p_amount WHERE id = p_to_id;
        
        COMMIT;
        SET p_result = '转账成功';
    END IF;
END //

DELIMITER ;

-- ============ 查看存储过程 ============
SHOW PROCEDURE STATUS WHERE Db = 'mydb';
SHOW CREATE PROCEDURE sp_get_user;

-- ============ 删除存储过程 ============
DROP PROCEDURE IF EXISTS sp_get_user;
```

### 15.2 存储函数

```sql
-- ============ 创建函数 ============
DELIMITER //

CREATE FUNCTION fn_get_age(p_birthday DATE)
RETURNS INT
DETERMINISTIC
BEGIN
    RETURN TIMESTAMPDIFF(YEAR, p_birthday, CURDATE());
END //

DELIMITER ;

-- ============ 调用函数 ============
SELECT fn_get_age('1990-01-01');
SELECT username, fn_get_age(birthday) AS age FROM users;

-- ============ 复杂函数 ============
DELIMITER //

CREATE FUNCTION fn_get_level(p_points INT)
RETURNS VARCHAR(20)
DETERMINISTIC
BEGIN
    DECLARE v_level VARCHAR(20);
    
    IF p_points >= 10000 THEN
        SET v_level = '钻石会员';
    ELSEIF p_points >= 5000 THEN
        SET v_level = '金牌会员';
    ELSEIF p_points >= 1000 THEN
        SET v_level = '银牌会员';
    ELSE
        SET v_level = '普通会员';
    END IF;
    
    RETURN v_level;
END //

DELIMITER ;

-- ============ 删除函数 ============
DROP FUNCTION IF EXISTS fn_get_age;
```

### 15.3 流程控制

```sql
-- ============ IF 语句 ============
IF condition THEN
    statements;
ELSEIF condition THEN
    statements;
ELSE
    statements;
END IF;

-- ============ CASE 语句 ============
CASE value
    WHEN value1 THEN statements;
    WHEN value2 THEN statements;
    ELSE statements;
END CASE;

-- ============ WHILE 循环 ============
WHILE condition DO
    statements;
END WHILE;

-- ============ REPEAT 循环 ============
REPEAT
    statements;
UNTIL condition
END REPEAT;

-- ============ LOOP 循环 ============
label: LOOP
    statements;
    IF condition THEN
        LEAVE label;  -- 退出循环
    END IF;
    ITERATE label;    -- 继续下一次循环
END LOOP;

-- ============ 游标 ============
DELIMITER //

CREATE PROCEDURE sp_process_users()
BEGIN
    DECLARE v_id BIGINT;
    DECLARE v_name VARCHAR(50);
    DECLARE v_done INT DEFAULT FALSE;
    
    -- 声明游标
    DECLARE cur CURSOR FOR SELECT id, username FROM users;
    -- 声明结束处理器
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;
    
    OPEN cur;
    
    read_loop: LOOP
        FETCH cur INTO v_id, v_name;
        IF v_done THEN
            LEAVE read_loop;
        END IF;
        
        -- 处理每一行
        SELECT v_id, v_name;
    END LOOP;
    
    CLOSE cur;
END //

DELIMITER ;
```


---

## 16. 触发器

### 16.1 触发器概述

**触发器（Trigger）** 是与表相关联的数据库对象，在特定事件（INSERT/UPDATE/DELETE）发生时自动执行。

### 16.2 触发器操作

```sql
-- ============ 创建触发器 ============
-- 语法
CREATE TRIGGER trigger_name
{BEFORE | AFTER} {INSERT | UPDATE | DELETE}
ON table_name
FOR EACH ROW
BEGIN
    -- 触发器逻辑
END;

-- ============ INSERT 触发器 ============
DELIMITER //

CREATE TRIGGER tr_user_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    -- NEW 表示新插入的行
    INSERT INTO user_logs (user_id, action, create_time)
    VALUES (NEW.id, 'INSERT', NOW());
END //

DELIMITER ;

-- ============ UPDATE 触发器 ============
DELIMITER //

CREATE TRIGGER tr_user_update
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    -- OLD 表示更新前的行，NEW 表示更新后的行
    IF OLD.email != NEW.email THEN
        INSERT INTO user_logs (user_id, action, old_value, new_value, create_time)
        VALUES (NEW.id, 'UPDATE_EMAIL', OLD.email, NEW.email, NOW());
    END IF;
END //

DELIMITER ;

-- ============ DELETE 触发器 ============
DELIMITER //

CREATE TRIGGER tr_user_delete
BEFORE DELETE ON users
FOR EACH ROW
BEGIN
    -- OLD 表示被删除的行
    INSERT INTO user_archives (id, username, email, deleted_at)
    VALUES (OLD.id, OLD.username, OLD.email, NOW());
END //

DELIMITER ;

-- ============ 查看触发器 ============
SHOW TRIGGERS;
SHOW TRIGGERS FROM mydb;
SELECT * FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = 'mydb';

-- ============ 删除触发器 ============
DROP TRIGGER IF EXISTS tr_user_insert;
```

### 16.3 触发器应用场景

```sql
-- ============ 自动更新统计表 ============
DELIMITER //

CREATE TRIGGER tr_order_insert
AFTER INSERT ON orders
FOR EACH ROW
BEGIN
    -- 更新用户订单统计
    UPDATE user_stats 
    SET order_count = order_count + 1,
        total_amount = total_amount + NEW.amount
    WHERE user_id = NEW.user_id;
END //

DELIMITER ;

-- ============ 数据校验 ============
DELIMITER //

CREATE TRIGGER tr_product_check
BEFORE INSERT ON products
FOR EACH ROW
BEGIN
    IF NEW.price <= 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '价格必须大于0';
    END IF;
    IF NEW.stock < 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '库存不能为负';
    END IF;
END //

DELIMITER ;

-- ============ 级联更新 ============
DELIMITER //

CREATE TRIGGER tr_category_update
AFTER UPDATE ON categories
FOR EACH ROW
BEGIN
    IF OLD.name != NEW.name THEN
        UPDATE products SET category_name = NEW.name WHERE category_id = NEW.id;
    END IF;
END //

DELIMITER ;
```

---

## 17. 用户与权限

### 17.1 用户管理

```sql
-- ============ 查看用户 ============
SELECT user, host FROM mysql.user;

-- ============ 创建用户 ============
-- 基本创建
CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';

-- 允许远程连接
CREATE USER 'username'@'%' IDENTIFIED BY 'password';

-- 指定 IP
CREATE USER 'username'@'192.168.1.%' IDENTIFIED BY 'password';

-- MySQL 8.0 密码策略
CREATE USER 'username'@'%' IDENTIFIED WITH mysql_native_password BY 'password';

-- ============ 修改用户 ============
-- 修改密码
ALTER USER 'username'@'localhost' IDENTIFIED BY 'newpassword';

-- 修改当前用户密码
ALTER USER USER() IDENTIFIED BY 'newpassword';

-- 重命名用户
RENAME USER 'oldname'@'localhost' TO 'newname'@'localhost';

-- ============ 删除用户 ============
DROP USER 'username'@'localhost';

-- ============ 密码过期 ============
ALTER USER 'username'@'localhost' PASSWORD EXPIRE;
ALTER USER 'username'@'localhost' PASSWORD EXPIRE INTERVAL 90 DAY;
ALTER USER 'username'@'localhost' PASSWORD EXPIRE NEVER;
```

### 17.2 权限管理

```sql
-- ============ 查看权限 ============
SHOW GRANTS FOR 'username'@'localhost';
SHOW GRANTS FOR CURRENT_USER;

-- ============ 授予权限 ============
-- 授予所有权限
GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost';

-- 授予特定数据库权限
GRANT ALL PRIVILEGES ON mydb.* TO 'username'@'localhost';

-- 授予特定表权限
GRANT SELECT, INSERT, UPDATE ON mydb.users TO 'username'@'localhost';

-- 授予特定列权限
GRANT SELECT (id, username), UPDATE (email) ON mydb.users TO 'username'@'localhost';

-- 授予存储过程权限
GRANT EXECUTE ON PROCEDURE mydb.sp_get_user TO 'username'@'localhost';

-- 授予授权权限
GRANT ALL PRIVILEGES ON mydb.* TO 'username'@'localhost' WITH GRANT OPTION;

-- ============ 撤销权限 ============
REVOKE INSERT ON mydb.* FROM 'username'@'localhost';
REVOKE ALL PRIVILEGES ON mydb.* FROM 'username'@'localhost';

-- ============ 刷新权限 ============
FLUSH PRIVILEGES;
```

### 17.3 角色管理（MySQL 8.0+）

```sql
-- ============ 创建角色 ============
CREATE ROLE 'app_read', 'app_write', 'app_admin';

-- ============ 授予角色权限 ============
GRANT SELECT ON mydb.* TO 'app_read';
GRANT INSERT, UPDATE, DELETE ON mydb.* TO 'app_write';
GRANT ALL PRIVILEGES ON mydb.* TO 'app_admin';

-- ============ 将角色授予用户 ============
GRANT 'app_read' TO 'user1'@'localhost';
GRANT 'app_read', 'app_write' TO 'user2'@'localhost';

-- ============ 激活角色 ============
SET DEFAULT ROLE 'app_read' TO 'user1'@'localhost';
SET DEFAULT ROLE ALL TO 'user2'@'localhost';

-- ============ 查看角色 ============
SELECT * FROM mysql.role_edges;
SHOW GRANTS FOR 'app_read';

-- ============ 删除角色 ============
DROP ROLE 'app_read';
```

---

## 18. 备份与恢复

### 18.1 mysqldump 备份

```bash
# ============ 备份单个数据库 ============
mysqldump -u root -p mydb > mydb_backup.sql

# ============ 备份多个数据库 ============
mysqldump -u root -p --databases mydb1 mydb2 > backup.sql

# ============ 备份所有数据库 ============
mysqldump -u root -p --all-databases > all_backup.sql

# ============ 只备份表结构 ============
mysqldump -u root -p --no-data mydb > mydb_structure.sql

# ============ 只备份数据 ============
mysqldump -u root -p --no-create-info mydb > mydb_data.sql

# ============ 备份特定表 ============
mysqldump -u root -p mydb users orders > tables_backup.sql

# ============ 压缩备份 ============
mysqldump -u root -p mydb | gzip > mydb_backup.sql.gz

# ============ 常用选项 ============
mysqldump -u root -p \
  --single-transaction \    # InnoDB 一致性备份
  --quick \                 # 大表优化
  --lock-tables=false \     # 不锁表
  --routines \              # 包含存储过程和函数
  --triggers \              # 包含触发器
  --events \                # 包含事件
  mydb > mydb_backup.sql
```

### 18.2 恢复数据

```bash
# ============ 恢复数据库 ============
mysql -u root -p mydb < mydb_backup.sql

# ============ 恢复压缩文件 ============
gunzip < mydb_backup.sql.gz | mysql -u root -p mydb

# ============ 在 MySQL 中恢复 ============
mysql> source /path/to/backup.sql;
```

### 18.3 二进制日志备份

```sql
-- 查看二进制日志
SHOW BINARY LOGS;
SHOW MASTER STATUS;

-- 查看日志内容
SHOW BINLOG EVENTS IN 'mysql-bin.000001';
```

```bash
# 使用 mysqlbinlog 恢复
mysqlbinlog mysql-bin.000001 | mysql -u root -p

# 指定时间范围
mysqlbinlog --start-datetime="2024-01-01 00:00:00" \
            --stop-datetime="2024-01-01 12:00:00" \
            mysql-bin.000001 | mysql -u root -p

# 指定位置范围
mysqlbinlog --start-position=100 --stop-position=500 \
            mysql-bin.000001 | mysql -u root -p
```

---

## 19. 性能优化

### 19.1 查询优化

```sql
-- ============ 使用 EXPLAIN 分析 ============
EXPLAIN SELECT * FROM users WHERE username = 'zhangsan';

-- ============ 优化建议 ============

-- 1. 避免 SELECT *
-- 不好
SELECT * FROM users;
-- 好
SELECT id, username, email FROM users;

-- 2. 使用索引
-- 确保 WHERE、ORDER BY、GROUP BY 的字段有索引

-- 3. 避免在索引列上使用函数
-- 不好
SELECT * FROM users WHERE YEAR(create_time) = 2024;
-- 好
SELECT * FROM users WHERE create_time >= '2024-01-01' AND create_time < '2025-01-01';

-- 4. 避免隐式类型转换
-- 不好（phone 是 VARCHAR）
SELECT * FROM users WHERE phone = 13800138000;
-- 好
SELECT * FROM users WHERE phone = '13800138000';

-- 5. 使用 LIMIT 限制结果
SELECT * FROM users ORDER BY create_time DESC LIMIT 10;

-- 6. 使用 EXISTS 代替 IN（大数据量时）
-- 不好
SELECT * FROM users WHERE id IN (SELECT user_id FROM orders);
-- 好
SELECT * FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id);

-- 7. 避免使用 OR，改用 UNION
-- 不好
SELECT * FROM users WHERE status = 1 OR status = 2;
-- 好
SELECT * FROM users WHERE status = 1
UNION ALL
SELECT * FROM users WHERE status = 2;

-- 8. 批量操作
-- 不好：多次单条插入
INSERT INTO users (name) VALUES ('a');
INSERT INTO users (name) VALUES ('b');
-- 好：批量插入
INSERT INTO users (name) VALUES ('a'), ('b'), ('c');
```

### 19.2 配置优化

```ini
[mysqld]
# 连接数
max_connections = 500

# InnoDB 缓冲池（建议设为物理内存的 50-70%）
innodb_buffer_pool_size = 4G

# InnoDB 日志文件大小
innodb_log_file_size = 256M

# 查询缓存（MySQL 8.0 已移除）
# query_cache_size = 0

# 排序缓冲区
sort_buffer_size = 4M

# 连接缓冲区
join_buffer_size = 4M

# 临时表大小
tmp_table_size = 64M
max_heap_table_size = 64M

# 慢查询日志
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
```

### 19.3 慢查询分析

```bash
# 查看慢查询日志
cat /var/log/mysql/slow.log

# 使用 mysqldumpslow 分析
mysqldumpslow -s t -t 10 /var/log/mysql/slow.log  # 按时间排序，前10条
mysqldumpslow -s c -t 10 /var/log/mysql/slow.log  # 按次数排序，前10条
```

```sql
-- 开启慢查询日志
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 2;

-- 查看慢查询状态
SHOW VARIABLES LIKE 'slow_query%';
SHOW VARIABLES LIKE 'long_query_time';
```

---

## 20. 常见错误与解决

### 20.1 连接错误

```
ERROR 1045 (28000): Access denied for user 'root'@'localhost'
```
**原因：** 密码错误或用户不存在
**解决：** 检查用户名密码，或重置密码

```
ERROR 2002 (HY000): Can't connect to local MySQL server through socket
```
**原因：** MySQL 服务未启动
**解决：** 启动 MySQL 服务

```
ERROR 1130 (HY000): Host 'xxx' is not allowed to connect
```
**原因：** 用户没有远程连接权限
**解决：** 
```sql
CREATE USER 'user'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';
FLUSH PRIVILEGES;
```

### 20.2 语法错误

```
ERROR 1064 (42000): You have an error in your SQL syntax
```
**原因：** SQL 语法错误
**解决：** 检查 SQL 语句，注意关键字、引号、括号

```
ERROR 1054 (42S22): Unknown column 'xxx' in 'field list'
```
**原因：** 列名不存在
**解决：** 检查列名拼写，确认表结构

### 20.3 数据错误

```
ERROR 1062 (23000): Duplicate entry 'xxx' for key 'PRIMARY'
```
**原因：** 主键或唯一键重复
**解决：** 使用 INSERT IGNORE 或 ON DUPLICATE KEY UPDATE

```
ERROR 1452 (23000): Cannot add or update a child row: a foreign key constraint fails
```
**原因：** 外键约束失败，引用的记录不存在
**解决：** 先插入主表记录，或检查外键值

```
ERROR 1406 (22001): Data too long for column 'xxx'
```
**原因：** 数据超过列定义的长度
**解决：** 增加列长度或截断数据

### 20.4 锁和事务错误

```
ERROR 1205 (HY000): Lock wait timeout exceeded
```
**原因：** 等待锁超时
**解决：** 
```sql
-- 查看锁等待
SHOW ENGINE INNODB STATUS;
-- 查看进程
SHOW PROCESSLIST;
-- 杀死阻塞进程
KILL process_id;
```

```
ERROR 1213 (40001): Deadlock found when trying to get lock
```
**原因：** 死锁
**解决：** 重试事务，优化事务顺序

### 20.5 字符集错误

```
ERROR 1366 (HY000): Incorrect string value: '\xE4\xB8\xAD...' for column 'xxx'
```
**原因：** 字符集不支持中文
**解决：** 
```sql
ALTER TABLE table_name CONVERT TO CHARACTER SET utf8mb4;
```

---

## 21. 总结

### 21.1 SQL 语句分类

| 类型 | 全称 | 关键字 |
|------|------|--------|
| DDL | 数据定义语言 | CREATE, ALTER, DROP, TRUNCATE |
| DML | 数据操作语言 | INSERT, UPDATE, DELETE |
| DQL | 数据查询语言 | SELECT |
| DCL | 数据控制语言 | GRANT, REVOKE |
| TCL | 事务控制语言 | COMMIT, ROLLBACK, SAVEPOINT |

### 21.2 常用命令速查

```sql
-- 数据库
SHOW DATABASES;
CREATE DATABASE db_name;
USE db_name;
DROP DATABASE db_name;

-- 表
SHOW TABLES;
DESC table_name;
CREATE TABLE ...;
ALTER TABLE ...;
DROP TABLE table_name;

-- 数据
INSERT INTO ... VALUES ...;
UPDATE ... SET ... WHERE ...;
DELETE FROM ... WHERE ...;
SELECT ... FROM ... WHERE ... ORDER BY ... LIMIT ...;

-- 索引
CREATE INDEX idx_name ON table_name (column);
DROP INDEX idx_name ON table_name;

-- 用户
CREATE USER 'user'@'host' IDENTIFIED BY 'password';
GRANT ... ON ... TO ...;
REVOKE ... ON ... FROM ...;

-- 事务
START TRANSACTION;
COMMIT;
ROLLBACK;
```

### 21.3 最佳实践

1. **表设计**：使用合适的数据类型，添加必要的索引
2. **查询优化**：避免 SELECT *，使用 EXPLAIN 分析
3. **事务管理**：保持事务简短，避免长事务
4. **安全性**：使用参数化查询，避免 SQL 注入
5. **备份**：定期备份，测试恢复流程
6. **监控**：开启慢查询日志，定期分析优化
