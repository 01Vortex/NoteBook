

> Prometheus 是一个开源的系统监控和告警工具包，Grafana 是一个开源的数据可视化平台
> 本笔记基于 Prometheus 2.x + Grafana 10.x + Node Exporter + Alertmanager

---

## 目录

1. [基础概念](#1-基础概念)
2. [Prometheus 安装与配置](#2-prometheus-安装与配置)
3. [PromQL 查询语言](#3-promql-查询语言)
4. [数据采集与 Exporter](#4-数据采集与-exporter)
5. [服务发现](#5-服务发现)
6. [Grafana 安装与配置](#6-grafana-安装与配置)
7. [Dashboard 设计](#7-dashboard-设计)
8. [告警配置](#8-告警配置)
9. [应用程序集成](#9-应用程序集成)
10. [高可用与扩展](#10-高可用与扩展)
11. [存储与性能优化](#11-存储与性能优化)
12. [安全配置](#12-安全配置)
13. [Kubernetes 监控](#13-kubernetes-监控)
14. [最佳实践](#14-最佳实践)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Prometheus？

Prometheus 是由 SoundCloud 开发的开源监控系统，现已成为云原生计算基金会（CNCF）的毕业项目。它专为可靠性和可扩展性设计，是现代云原生监控的事实标准。

**Prometheus 的核心特点**：
- **多维数据模型**：使用指标名称和键值对（标签）标识时间序列数据
- **PromQL**：强大灵活的查询语言，支持复杂的数据聚合和计算
- **Pull 模式**：主动从目标拉取指标，而非被动接收推送
- **服务发现**：支持多种服务发现机制，自动发现监控目标
- **独立部署**：不依赖分布式存储，单节点即可运行
- **告警支持**：内置告警规则引擎，配合 Alertmanager 实现告警通知

### 1.2 什么是 Grafana？

Grafana 是一个开源的数据可视化和监控平台，支持多种数据源，提供丰富的图表类型和强大的仪表板功能。

**Grafana 的核心特点**：
- **多数据源支持**：Prometheus、InfluxDB、Elasticsearch、MySQL 等
- **丰富的可视化**：折线图、柱状图、仪表盘、热力图、表格等
- **告警功能**：支持基于查询结果的告警
- **模板变量**：动态仪表板，支持下拉选择和变量替换
- **插件生态**：丰富的社区插件扩展功能


### 1.3 监控架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         监控系统架构                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│   │ 应用服务  │    │ 数据库    │    │ 中间件   │    │ 主机     │      │
│   │ /metrics │    │ Exporter │    │ Exporter │    │ Exporter │      │
│   └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘     │
│        │               │               │               │            │
│        └───────────────┴───────────────┴───────────────┘            │
│                              │                                       │
│                              ▼                                       │
│                    ┌─────────────────┐                              │
│                    │   Prometheus    │                              │
│                    │   (数据采集)     │                              │
│                    └────────┬────────┘                              │
│                             │                                        │
│              ┌──────────────┼──────────────┐                        │
│              ▼              ▼              ▼                         │
│     ┌────────────┐  ┌────────────┐  ┌────────────┐                 │
│     │  Grafana   │  │Alertmanager│  │   API      │                 │
│     │  (可视化)   │  │  (告警)    │  │  (查询)    │                 │
│     └────────────┘  └────────────┘  └────────────┘                 │
│                            │                                         │
│                            ▼                                         │
│              ┌─────────────────────────┐                            │
│              │ 邮件 / Slack / 钉钉 / 微信 │                          │
│              └─────────────────────────┘                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.4 核心概念

| 概念 | 说明 | 示例 |
|------|------|------|
| Metric（指标） | 被监控的数值数据 | `http_requests_total` |
| Label（标签） | 指标的维度标识 | `method="GET"`, `status="200"` |
| Time Series（时间序列） | 指标 + 标签的唯一组合 | `http_requests_total{method="GET"}` |
| Sample（样本） | 时间序列在某一时刻的值 | `(timestamp, value)` |
| Target（目标） | 被监控的端点 | `localhost:9090/metrics` |
| Job（作业） | 相同目的的目标集合 | `prometheus`, `node` |
| Instance（实例） | 单个目标的标识 | `192.168.1.1:9100` |

### 1.5 指标类型

Prometheus 支持四种指标类型，理解它们对于正确使用监控至关重要：

```
┌─────────────────────────────────────────────────────────────────┐
│                        指标类型对比                              │
├─────────────┬───────────────────────────────────────────────────┤
│ Counter     │ 只增不减的计数器，重启后归零                        │
│ (计数器)    │ 适用于：请求数、错误数、任务完成数                   │
│             │ 示例：http_requests_total                          │
├─────────────┼───────────────────────────────────────────────────┤
│ Gauge       │ 可增可减的仪表盘，表示瞬时值                        │
│ (仪表盘)    │ 适用于：温度、内存使用、并发连接数                   │
│             │ 示例：node_memory_available_bytes                  │
├─────────────┼───────────────────────────────────────────────────┤
│ Histogram   │ 直方图，统计数据分布                                │
│ (直方图)    │ 适用于：请求延迟、响应大小                          │
│             │ 示例：http_request_duration_seconds                │
├─────────────┼───────────────────────────────────────────────────┤
│ Summary     │ 摘要，类似直方图但计算分位数                        │
│ (摘要)      │ 适用于：需要精确分位数的场景                        │
│             │ 示例：go_gc_duration_seconds                       │
└─────────────┴───────────────────────────────────────────────────┘
```


---

## 2. Prometheus 安装与配置

### 2.1 安装方式

#### 二进制安装

```bash
# 下载 Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.47.0/prometheus-2.47.0.linux-amd64.tar.gz

# 解压
tar xvfz prometheus-2.47.0.linux-amd64.tar.gz
cd prometheus-2.47.0.linux-amd64

# 启动
./prometheus --config.file=prometheus.yml

# 访问 Web UI
# http://localhost:9090
```

#### Docker 安装

```bash
# 单独运行
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v /path/to/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v prometheus_data:/prometheus \
  prom/prometheus

# 查看日志
docker logs -f prometheus
```

#### Docker Compose 完整部署

```yaml
# docker-compose.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:v2.47.0
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus/rules:/etc/prometheus/rules
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=15d'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:10.1.0
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    restart: unless-stopped
    networks:
      - monitoring

  alertmanager:
    image: prom/alertmanager:v0.26.0
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager_data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    restart: unless-stopped
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:v1.6.1
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped
    networks:
      - monitoring

volumes:
  prometheus_data:
  grafana_data:
  alertmanager_data:

networks:
  monitoring:
    driver: bridge
```


### 2.2 Prometheus 配置文件

```yaml
# prometheus/prometheus.yml
global:
  scrape_interval: 15s          # 默认采集间隔
  evaluation_interval: 15s       # 规则评估间隔
  scrape_timeout: 10s           # 采集超时时间
  
  # 外部标签，用于联邦集群和远程存储
  external_labels:
    cluster: 'production'
    region: 'cn-east-1'

# 告警管理器配置
alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093
      # 发送告警的超时时间
      timeout: 10s

# 规则文件
rule_files:
  - /etc/prometheus/rules/*.yml

# 采集配置
scrape_configs:
  # Prometheus 自身监控
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    # 可以覆盖全局配置
    scrape_interval: 5s
    metrics_path: /metrics
    scheme: http

  # Node Exporter - 主机监控
  - job_name: 'node'
    static_configs:
      - targets: 
          - 'node-exporter:9100'
          - '192.168.1.10:9100'
          - '192.168.1.11:9100'
        labels:
          env: 'production'
    # 重新标记配置
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '([^:]+):\d+'
        replacement: '${1}'

  # 应用服务监控
  - job_name: 'spring-boot'
    metrics_path: /actuator/prometheus
    static_configs:
      - targets: ['app1:8080', 'app2:8080']
        labels:
          application: 'user-service'

  # 带认证的目标
  - job_name: 'authenticated-target'
    basic_auth:
      username: prometheus
      password: secret
    static_configs:
      - targets: ['secure-app:8080']

  # HTTPS 目标
  - job_name: 'https-target'
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/ca.crt
      cert_file: /etc/prometheus/client.crt
      key_file: /etc/prometheus/client.key
      insecure_skip_verify: false
    static_configs:
      - targets: ['secure-server:443']

# 远程写入（可选）
remote_write:
  - url: "http://remote-storage:9201/write"
    queue_config:
      max_samples_per_send: 1000
      batch_send_deadline: 5s

# 远程读取（可选）
remote_read:
  - url: "http://remote-storage:9201/read"
    read_recent: true
```

### 2.3 启动参数说明

```bash
# 常用启动参数
./prometheus \
  --config.file=prometheus.yml \           # 配置文件路径
  --storage.tsdb.path=/prometheus \        # 数据存储路径
  --storage.tsdb.retention.time=15d \      # 数据保留时间
  --storage.tsdb.retention.size=50GB \     # 数据保留大小
  --web.listen-address=0.0.0.0:9090 \      # 监听地址
  --web.enable-lifecycle \                 # 启用生命周期 API（热重载）
  --web.enable-admin-api \                 # 启用管理 API
  --web.external-url=http://prometheus.example.com \  # 外部访问 URL
  --log.level=info                         # 日志级别

# 热重载配置（需要 --web.enable-lifecycle）
curl -X POST http://localhost:9090/-/reload

# 检查配置文件语法
./promtool check config prometheus.yml

# 检查规则文件语法
./promtool check rules rules/*.yml
```


---

## 3. PromQL 查询语言

PromQL（Prometheus Query Language）是 Prometheus 的查询语言，功能强大且灵活。掌握 PromQL 是使用 Prometheus 的关键。

### 3.1 基础查询

```promql
# ========== 选择器 ==========

# 选择指标
http_requests_total

# 精确匹配标签
http_requests_total{method="GET"}

# 多标签匹配
http_requests_total{method="GET", status="200"}

# 正则匹配（=~）
http_requests_total{method=~"GET|POST"}

# 正则不匹配（!~）
http_requests_total{method!~"DELETE|PUT"}

# 不等于（!=）
http_requests_total{status!="500"}

# 匹配所有包含某标签的时间序列
{__name__=~"http_.*"}


# ========== 时间范围 ==========

# 过去 5 分钟的数据（范围向量）
http_requests_total[5m]

# 过去 1 小时的数据
http_requests_total[1h]

# 时间单位：s(秒) m(分) h(时) d(天) w(周) y(年)

# 偏移量 - 1 小时前的数据
http_requests_total offset 1h

# 偏移量 - 1 小时前的 5 分钟范围数据
http_requests_total[5m] offset 1h

# @ 修饰符 - 指定时间点的数据（Unix 时间戳）
http_requests_total @ 1609459200
```

### 3.2 运算符

```promql
# ========== 算术运算符 ==========
# + - * / % ^（幂运算）

# 计算请求错误率
http_requests_total{status="500"} / http_requests_total * 100

# 内存使用百分比
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100


# ========== 比较运算符 ==========
# == != > < >= <=

# 过滤 CPU 使用率大于 80% 的实例
node_cpu_seconds_total > 0.8

# 使用 bool 修饰符返回 0/1
http_requests_total > bool 100


# ========== 逻辑运算符 ==========
# and or unless

# 同时满足两个条件
http_requests_total{method="GET"} and http_requests_total{status="200"}

# 满足任一条件
http_requests_total{status="500"} or http_requests_total{status="502"}

# 排除某些结果
http_requests_total unless http_requests_total{status="200"}


# ========== 向量匹配 ==========

# 一对一匹配
method_code:http_errors:rate5m{method="get"} / method:http_requests:rate5m

# 使用 on 指定匹配标签
method_code:http_errors:rate5m / on(method) method:http_requests:rate5m

# 使用 ignoring 忽略某些标签
method_code:http_errors:rate5m / ignoring(code) method:http_requests:rate5m

# 一对多匹配（group_left/group_right）
method_code:http_errors:rate5m / on(method) group_left method:http_requests:rate5m
```


### 3.3 聚合函数

```promql
# ========== 基础聚合 ==========

# 求和
sum(http_requests_total)

# 按标签分组求和
sum by (method) (http_requests_total)
sum(http_requests_total) by (method)  # 等价写法

# 排除某些标签后求和
sum without (instance) (http_requests_total)

# 计数
count(http_requests_total)

# 平均值
avg(node_cpu_seconds_total)

# 最大/最小值
max(node_memory_MemAvailable_bytes)
min(node_memory_MemAvailable_bytes)

# 标准差和方差
stddev(http_request_duration_seconds)
stdvar(http_request_duration_seconds)

# 取前 N 个最大/最小值
topk(5, http_requests_total)
bottomk(5, http_requests_total)

# 分位数（0-1）
quantile(0.95, http_request_duration_seconds)


# ========== 实用聚合示例 ==========

# 每个服务的总请求数
sum by (service) (http_requests_total)

# 每个实例的平均 CPU 使用率
avg by (instance) (rate(node_cpu_seconds_total{mode!="idle"}[5m]))

# 集群总内存使用量
sum(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes)

# 每个状态码的请求占比
sum by (status) (http_requests_total) / sum(http_requests_total) * 100
```

### 3.4 常用函数

```promql
# ========== 速率函数（用于 Counter） ==========

# rate - 计算每秒平均增长率（推荐用于告警和图表）
rate(http_requests_total[5m])

# irate - 计算瞬时增长率（基于最后两个数据点）
irate(http_requests_total[5m])

# increase - 计算时间范围内的增长量
increase(http_requests_total[1h])

# 注意：rate/irate/increase 只能用于 Counter 类型


# ========== 变化函数 ==========

# changes - 值变化的次数
changes(node_load1[1h])

# delta - 范围向量第一个和最后一个值的差（用于 Gauge）
delta(node_memory_MemAvailable_bytes[1h])

# deriv - 线性回归计算导数
deriv(node_memory_MemAvailable_bytes[1h])

# predict_linear - 线性预测
predict_linear(node_filesystem_free_bytes[1h], 4*3600)  # 预测 4 小时后的值


# ========== 时间函数 ==========

# time - 当前 Unix 时间戳
time()

# timestamp - 样本的时间戳
timestamp(http_requests_total)

# day_of_week - 星期几（0=周日）
day_of_week()

# hour - 小时（0-23）
hour()


# ========== 标签函数 ==========

# label_replace - 替换/添加标签
label_replace(http_requests_total, "host", "$1", "instance", "([^:]+):\\d+")

# label_join - 连接多个标签值
label_join(http_requests_total, "new_label", "-", "method", "status")


# ========== 其他常用函数 ==========

# abs - 绝对值
abs(delta(temperature[1h]))

# ceil/floor - 向上/向下取整
ceil(http_request_duration_seconds)

# round - 四舍五入
round(http_request_duration_seconds, 0.1)

# clamp - 限制值范围
clamp(cpu_usage, 0, 100)

# clamp_min/clamp_max - 限制最小/最大值
clamp_min(temperature, 0)

# absent - 如果向量为空返回 1
absent(up{job="myapp"})

# sort/sort_desc - 排序
sort(http_requests_total)
sort_desc(http_requests_total)

# histogram_quantile - 从直方图计算分位数
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
```


### 3.5 实战查询示例

```promql
# ========== 系统监控 ==========

# CPU 使用率（排除 idle）
100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# 内存使用率
(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100

# 磁盘使用率
(1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes) * 100

# 磁盘 IO 使用率
rate(node_disk_io_time_seconds_total[5m]) * 100

# 网络接收速率（MB/s）
rate(node_network_receive_bytes_total{device!~"lo|veth.*"}[5m]) / 1024 / 1024

# 系统负载（1分钟）与 CPU 核心数比较
node_load1 / count without (cpu, mode) (node_cpu_seconds_total{mode="idle"})


# ========== 应用监控 ==========

# QPS（每秒请求数）
sum(rate(http_requests_total[5m]))

# 按服务分组的 QPS
sum by (service) (rate(http_requests_total[5m]))

# 错误率
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100

# P99 延迟
histogram_quantile(0.99, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))

# P95 延迟（按服务分组）
histogram_quantile(0.95, sum by (le, service) (rate(http_request_duration_seconds_bucket[5m])))

# 平均响应时间
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])

# 慢请求数（响应时间 > 1s）
sum(rate(http_request_duration_seconds_bucket{le="1"}[5m])) 
- sum(rate(http_request_duration_seconds_bucket{le="+Inf"}[5m]))


# ========== 数据库监控 ==========

# MySQL QPS
rate(mysql_global_status_queries[5m])

# MySQL 连接数使用率
mysql_global_status_threads_connected / mysql_global_variables_max_connections * 100

# Redis 命令执行速率
rate(redis_commands_total[5m])

# Redis 内存使用率
redis_memory_used_bytes / redis_memory_max_bytes * 100


# ========== 容器监控 ==========

# 容器 CPU 使用率
sum by (container) (rate(container_cpu_usage_seconds_total[5m])) * 100

# 容器内存使用率
container_memory_usage_bytes / container_spec_memory_limit_bytes * 100

# 容器网络流量
sum by (container) (rate(container_network_receive_bytes_total[5m]))


# ========== 告警相关 ==========

# 服务是否存活
up == 0

# 预测磁盘 4 小时后是否会满
predict_linear(node_filesystem_free_bytes[1h], 4*3600) < 0

# 最近 5 分钟没有请求
absent(rate(http_requests_total[5m]) > 0)

# 错误率突增（与 1 小时前比较）
rate(http_requests_total{status=~"5.."}[5m]) 
> 2 * rate(http_requests_total{status=~"5.."}[5m] offset 1h)
```


---

## 4. 数据采集与 Exporter

Exporter 是 Prometheus 生态中的数据采集器，负责将各种系统和应用的指标转换为 Prometheus 格式。

### 4.1 常用 Exporter

| Exporter | 用途 | 默认端口 |
|----------|------|----------|
| Node Exporter | Linux 主机监控 | 9100 |
| Windows Exporter | Windows 主机监控 | 9182 |
| MySQL Exporter | MySQL 数据库监控 | 9104 |
| PostgreSQL Exporter | PostgreSQL 监控 | 9187 |
| Redis Exporter | Redis 监控 | 9121 |
| MongoDB Exporter | MongoDB 监控 | 9216 |
| Nginx Exporter | Nginx 监控 | 9113 |
| Blackbox Exporter | 黑盒探测（HTTP/TCP/ICMP） | 9115 |
| cAdvisor | 容器监控 | 8080 |
| kube-state-metrics | Kubernetes 状态监控 | 8080 |

### 4.2 Node Exporter 配置

```bash
# 下载安装
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
tar xvfz node_exporter-1.6.1.linux-amd64.tar.gz
cd node_exporter-1.6.1.linux-amd64

# 启动（启用/禁用特定收集器）
./node_exporter \
  --collector.systemd \
  --collector.processes \
  --no-collector.wifi \
  --web.listen-address=:9100

# 创建 systemd 服务
cat > /etc/systemd/system/node_exporter.service << EOF
[Unit]
Description=Node Exporter
After=network.target

[Service]
Type=simple
User=node_exporter
ExecStart=/usr/local/bin/node_exporter \
  --collector.systemd \
  --collector.processes
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable node_exporter
systemctl start node_exporter
```

### 4.3 MySQL Exporter 配置

```bash
# 创建监控用户
mysql -u root -p << EOF
CREATE USER 'exporter'@'localhost' IDENTIFIED BY 'password';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';
FLUSH PRIVILEGES;
EOF

# 配置文件
cat > /etc/.mysqld_exporter.cnf << EOF
[client]
user=exporter
password=password
host=localhost
port=3306
EOF

# 启动
./mysqld_exporter --config.my-cnf=/etc/.mysqld_exporter.cnf

# Prometheus 配置
# prometheus.yml
scrape_configs:
  - job_name: 'mysql'
    static_configs:
      - targets: ['mysql-server:9104']
```

### 4.4 Blackbox Exporter（黑盒监控）

Blackbox Exporter 用于探测外部服务的可用性，支持 HTTP、HTTPS、TCP、ICMP、DNS 等协议。

```yaml
# blackbox.yml
modules:
  http_2xx:
    prober: http
    timeout: 5s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: [200, 201, 204]
      method: GET
      follow_redirects: true
      fail_if_ssl: false
      fail_if_not_ssl: false
      tls_config:
        insecure_skip_verify: false

  http_post_2xx:
    prober: http
    timeout: 5s
    http:
      method: POST
      headers:
        Content-Type: application/json
      body: '{"test": "data"}'

  tcp_connect:
    prober: tcp
    timeout: 5s

  icmp:
    prober: icmp
    timeout: 5s
    icmp:
      preferred_ip_protocol: ip4

  dns:
    prober: dns
    timeout: 5s
    dns:
      query_name: "example.com"
      query_type: "A"
```

```yaml
# prometheus.yml - Blackbox 配置
scrape_configs:
  - job_name: 'blackbox-http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - https://www.google.com
          - https://www.github.com
          - http://myapp.example.com/health
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

  - job_name: 'blackbox-tcp'
    metrics_path: /probe
    params:
      module: [tcp_connect]
    static_configs:
      - targets:
          - mysql-server:3306
          - redis-server:6379
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```


---

## 5. 服务发现

在动态环境中（如 Kubernetes、云平台），手动配置监控目标不现实。Prometheus 支持多种服务发现机制。

### 5.1 文件服务发现

最简单的动态配置方式，Prometheus 会自动监控文件变化。

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'file-sd'
    file_sd_configs:
      - files:
          - /etc/prometheus/targets/*.json
          - /etc/prometheus/targets/*.yml
        refresh_interval: 30s
```

```json
// /etc/prometheus/targets/apps.json
[
  {
    "targets": ["app1:8080", "app2:8080"],
    "labels": {
      "env": "production",
      "team": "backend"
    }
  },
  {
    "targets": ["app3:8080"],
    "labels": {
      "env": "staging",
      "team": "frontend"
    }
  }
]
```

```yaml
# /etc/prometheus/targets/databases.yml
- targets:
    - mysql1:9104
    - mysql2:9104
  labels:
    type: mysql
    env: production
```

### 5.2 Consul 服务发现

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'consul-services'
    consul_sd_configs:
      - server: 'consul:8500'
        services: []  # 空表示所有服务
        tags:
          - prometheus  # 只发现带此标签的服务
    relabel_configs:
      # 保留带 prometheus 标签的服务
      - source_labels: [__meta_consul_tags]
        regex: .*,prometheus,.*
        action: keep
      # 设置 job 名称为服务名
      - source_labels: [__meta_consul_service]
        target_label: job
      # 设置实例标签
      - source_labels: [__meta_consul_service_address, __meta_consul_service_port]
        separator: ':'
        target_label: instance
```

### 5.3 Kubernetes 服务发现

```yaml
# prometheus.yml
scrape_configs:
  # 发现 Kubernetes 节点
  - job_name: 'kubernetes-nodes'
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)

  # 发现 Pod
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      # 只保留带有 prometheus.io/scrape: "true" 注解的 Pod
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      # 使用注解中的路径
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      # 使用注解中的端口
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      # 添加 Pod 标签
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      # 添加命名空间标签
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      # 添加 Pod 名称标签
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name

  # 发现 Service
  - job_name: 'kubernetes-services'
    kubernetes_sd_configs:
      - role: service
    metrics_path: /probe
    params:
      module: [http_2xx]
    relabel_configs:
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_probe]
        action: keep
        regex: true
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

### 5.4 Relabel 配置详解

Relabel 是 Prometheus 中非常强大的功能，用于在采集前修改目标的标签。

```yaml
relabel_configs:
  # keep - 保留匹配的目标
  - source_labels: [__meta_kubernetes_pod_label_app]
    regex: myapp
    action: keep

  # drop - 丢弃匹配的目标
  - source_labels: [__meta_kubernetes_namespace]
    regex: kube-system
    action: drop

  # replace - 替换标签值
  - source_labels: [__address__]
    regex: '([^:]+):\d+'
    replacement: '${1}'
    target_label: instance

  # labelmap - 批量映射标签
  - action: labelmap
    regex: __meta_kubernetes_pod_label_(.+)

  # labeldrop - 删除匹配的标签
  - action: labeldrop
    regex: __meta_.*

  # labelkeep - 只保留匹配的标签
  - action: labelkeep
    regex: (job|instance|__address__)

  # hashmod - 用于分片
  - source_labels: [__address__]
    modulus: 4
    target_label: __tmp_hash
    action: hashmod
  - source_labels: [__tmp_hash]
    regex: 0
    action: keep
```


---

## 6. Grafana 安装与配置

### 6.1 安装 Grafana

```bash
# Docker 安装
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -v grafana_data:/var/lib/grafana \
  -e GF_SECURITY_ADMIN_PASSWORD=admin123 \
  grafana/grafana:10.1.0

# 二进制安装（Ubuntu/Debian）
sudo apt-get install -y apt-transport-https software-properties-common
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update
sudo apt-get install grafana

sudo systemctl enable grafana-server
sudo systemctl start grafana-server

# 访问 http://localhost:3000
# 默认用户名/密码: admin/admin
```

### 6.2 配置文件

```ini
# /etc/grafana/grafana.ini

[server]
http_port = 3000
domain = grafana.example.com
root_url = %(protocol)s://%(domain)s:%(http_port)s/

[database]
type = postgres
host = localhost:5432
name = grafana
user = grafana
password = password

[session]
provider = redis
provider_config = addr=localhost:6379,pool_size=100,db=grafana

[security]
admin_user = admin
admin_password = secure_password
secret_key = your_secret_key
disable_gravatar = true

[users]
allow_sign_up = false
allow_org_create = false
auto_assign_org = true
auto_assign_org_role = Viewer

[auth.anonymous]
enabled = false

[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml

[smtp]
enabled = true
host = smtp.example.com:587
user = grafana@example.com
password = smtp_password
from_address = grafana@example.com
from_name = Grafana

[alerting]
enabled = true
execute_alerts = true

[log]
mode = console file
level = info

[metrics]
enabled = true
```

### 6.3 数据源配置

```yaml
# grafana/provisioning/datasources/datasources.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
      httpMethod: POST

  - name: Prometheus-Remote
    type: prometheus
    access: proxy
    url: http://remote-prometheus:9090
    editable: false

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: false

  - name: InfluxDB
    type: influxdb
    access: proxy
    url: http://influxdb:8086
    database: metrics
    user: admin
    secureJsonData:
      password: password
```

### 6.4 Dashboard 自动配置

```yaml
# grafana/provisioning/dashboards/dashboards.yml
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    folderUid: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards/json
```


---

## 7. Dashboard 设计

### 7.1 Dashboard JSON 结构

```json
{
  "dashboard": {
    "id": null,
    "uid": "system-overview",
    "title": "系统概览",
    "tags": ["system", "overview"],
    "timezone": "browser",
    "schemaVersion": 38,
    "version": 1,
    "refresh": "30s",
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "templating": {
      "list": [
        {
          "name": "instance",
          "type": "query",
          "datasource": "Prometheus",
          "query": "label_values(up, instance)",
          "refresh": 1,
          "multi": true,
          "includeAll": true
        }
      ]
    },
    "panels": []
  }
}
```

### 7.2 常用面板配置

```json
// Stat 面板 - 显示单个数值
{
  "type": "stat",
  "title": "CPU 使用率",
  "gridPos": { "x": 0, "y": 0, "w": 6, "h": 4 },
  "targets": [
    {
      "expr": "100 - (avg(rate(node_cpu_seconds_total{mode=\"idle\",instance=~\"$instance\"}[5m])) * 100)",
      "legendFormat": "CPU"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "percent",
      "min": 0,
      "max": 100,
      "thresholds": {
        "mode": "absolute",
        "steps": [
          { "color": "green", "value": null },
          { "color": "yellow", "value": 70 },
          { "color": "red", "value": 90 }
        ]
      }
    }
  },
  "options": {
    "colorMode": "background",
    "graphMode": "area",
    "justifyMode": "auto"
  }
}
```

```json
// Time Series 面板 - 时间序列图
{
  "type": "timeseries",
  "title": "请求速率",
  "gridPos": { "x": 0, "y": 4, "w": 12, "h": 8 },
  "targets": [
    {
      "expr": "sum(rate(http_requests_total{instance=~\"$instance\"}[5m])) by (method)",
      "legendFormat": "{{method}}"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "reqps",
      "custom": {
        "drawStyle": "line",
        "lineInterpolation": "smooth",
        "fillOpacity": 10,
        "pointSize": 5,
        "showPoints": "auto"
      }
    }
  },
  "options": {
    "legend": {
      "displayMode": "table",
      "placement": "bottom",
      "calcs": ["mean", "max", "last"]
    },
    "tooltip": {
      "mode": "multi",
      "sort": "desc"
    }
  }
}
```

```json
// Gauge 面板 - 仪表盘
{
  "type": "gauge",
  "title": "内存使用率",
  "gridPos": { "x": 6, "y": 0, "w": 6, "h": 4 },
  "targets": [
    {
      "expr": "(1 - node_memory_MemAvailable_bytes{instance=~\"$instance\"} / node_memory_MemTotal_bytes{instance=~\"$instance\"}) * 100"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "percent",
      "min": 0,
      "max": 100,
      "thresholds": {
        "steps": [
          { "color": "green", "value": null },
          { "color": "yellow", "value": 70 },
          { "color": "red", "value": 85 }
        ]
      }
    }
  }
}
```

```json
// Table 面板 - 表格
{
  "type": "table",
  "title": "Top 10 请求路径",
  "gridPos": { "x": 12, "y": 4, "w": 12, "h": 8 },
  "targets": [
    {
      "expr": "topk(10, sum by (path) (rate(http_requests_total[5m])))",
      "format": "table",
      "instant": true
    }
  ],
  "transformations": [
    {
      "id": "organize",
      "options": {
        "renameByName": {
          "path": "路径",
          "Value": "QPS"
        }
      }
    }
  ],
  "fieldConfig": {
    "overrides": [
      {
        "matcher": { "id": "byName", "options": "QPS" },
        "properties": [
          { "id": "unit", "value": "reqps" },
          { "id": "decimals", "value": 2 }
        ]
      }
    ]
  }
}
```

### 7.3 模板变量

```yaml
# 查询变量 - 从 Prometheus 获取标签值
- name: instance
  type: query
  query: label_values(up{job="node"}, instance)
  refresh: 1  # 1=加载时刷新, 2=时间范围变化时刷新
  multi: true
  includeAll: true
  allValue: ".*"

# 自定义变量
- name: interval
  type: custom
  options:
    - text: "1m"
      value: "1m"
    - text: "5m"
      value: "5m"
    - text: "15m"
      value: "15m"
  current:
    text: "5m"
    value: "5m"

# 间隔变量（自动计算）
- name: __interval
  type: interval
  auto: true
  auto_min: "10s"
  auto_count: 100

# 数据源变量
- name: datasource
  type: datasource
  query: prometheus
```

```promql
# 在查询中使用变量
rate(http_requests_total{instance=~"$instance"}[$interval])

# 使用 __interval 自动间隔
rate(http_requests_total[$__interval])

# 使用 __range 时间范围
increase(http_requests_total[$__range])
```


---

## 8. 告警配置

### 8.1 Prometheus 告警规则

```yaml
# prometheus/rules/alerts.yml
groups:
  - name: 系统告警
    interval: 30s
    rules:
      # 实例宕机
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "实例 {{ $labels.instance }} 宕机"
          description: "{{ $labels.job }} 的实例 {{ $labels.instance }} 已经宕机超过 1 分钟"

      # CPU 使用率过高
      - alert: HighCpuUsage
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "CPU 使用率过高"
          description: "实例 {{ $labels.instance }} CPU 使用率超过 80%，当前值: {{ $value | printf \"%.2f\" }}%"

      # 内存使用率过高
      - alert: HighMemoryUsage
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "内存使用率过高"
          description: "实例 {{ $labels.instance }} 内存使用率超过 85%，当前值: {{ $value | printf \"%.2f\" }}%"

      # 磁盘空间不足
      - alert: DiskSpaceLow
        expr: (1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "磁盘空间不足"
          description: "实例 {{ $labels.instance }} 磁盘 {{ $labels.mountpoint }} 使用率超过 85%"

      # 磁盘即将写满（预测）
      - alert: DiskWillFillIn4Hours
        expr: predict_linear(node_filesystem_free_bytes{fstype!~"tmpfs|overlay"}[1h], 4*3600) < 0
        for: 30m
        labels:
          severity: critical
        annotations:
          summary: "磁盘预计 4 小时内写满"
          description: "实例 {{ $labels.instance }} 磁盘 {{ $labels.mountpoint }} 预计 4 小时内写满"

  - name: 应用告警
    rules:
      # 错误率过高
      - alert: HighErrorRate
        expr: sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100 > 5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "HTTP 错误率过高"
          description: "错误率超过 5%，当前值: {{ $value | printf \"%.2f\" }}%"

      # 响应时间过长
      - alert: HighLatency
        expr: histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "P95 响应时间过长"
          description: "P95 响应时间超过 1 秒，当前值: {{ $value | printf \"%.2f\" }}s"

      # 服务无请求
      - alert: NoRequests
        expr: sum(rate(http_requests_total[5m])) == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "服务无请求"
          description: "服务在过去 10 分钟内没有收到任何请求"

  - name: 数据库告警
    rules:
      # MySQL 连接数过高
      - alert: MysqlTooManyConnections
        expr: mysql_global_status_threads_connected / mysql_global_variables_max_connections * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "MySQL 连接数过高"
          description: "MySQL 连接数使用率超过 80%"

      # Redis 内存使用过高
      - alert: RedisHighMemoryUsage
        expr: redis_memory_used_bytes / redis_memory_max_bytes * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Redis 内存使用过高"
          description: "Redis 内存使用率超过 80%"
```


### 8.2 Alertmanager 配置

```yaml
# alertmanager/alertmanager.yml
global:
  # 全局配置
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alertmanager@example.com'
  smtp_auth_username: 'alertmanager@example.com'
  smtp_auth_password: 'password'
  smtp_require_tls: true

# 告警模板
templates:
  - '/etc/alertmanager/templates/*.tmpl'

# 路由配置
route:
  # 默认接收者
  receiver: 'default-receiver'
  # 分组等待时间
  group_wait: 30s
  # 分组间隔
  group_interval: 5m
  # 重复发送间隔
  repeat_interval: 4h
  # 分组标签
  group_by: ['alertname', 'severity']
  
  # 子路由
  routes:
    # 严重告警发送到 PagerDuty
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      continue: true  # 继续匹配后续路由
    
    # 数据库告警发送给 DBA
    - match_re:
        alertname: ^(Mysql|Redis|Postgres).*
      receiver: 'dba-team'
    
    # 按服务分组
    - match:
        team: backend
      receiver: 'backend-team'
      group_by: ['alertname', 'service']

# 接收者配置
receivers:
  - name: 'default-receiver'
    email_configs:
      - to: 'ops@example.com'
        send_resolved: true

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'your-pagerduty-service-key'
        severity: critical

  - name: 'dba-team'
    email_configs:
      - to: 'dba@example.com'
    webhook_configs:
      - url: 'http://dingtalk-webhook/send'

  - name: 'backend-team'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/xxx/xxx/xxx'
        channel: '#alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'

  # 钉钉告警
  - name: 'dingtalk'
    webhook_configs:
      - url: 'http://dingtalk-webhook:8060/dingtalk/webhook/send'
        send_resolved: true

  # 企业微信告警
  - name: 'wechat'
    wechat_configs:
      - corp_id: 'your-corp-id'
        to_user: '@all'
        agent_id: 'your-agent-id'
        api_secret: 'your-api-secret'

# 抑制规则
inhibit_rules:
  # 当 critical 告警触发时，抑制同实例的 warning 告警
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']
  
  # 当实例宕机时，抑制该实例的所有其他告警
  - source_match:
      alertname: 'InstanceDown'
    target_match_re:
      alertname: '.+'
    equal: ['instance']
```

### 8.3 告警模板

```go
{{/* alertmanager/templates/default.tmpl */}}

{{ define "email.default.subject" }}
[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .GroupLabels.alertname }}
{{ end }}

{{ define "email.default.html" }}
<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: Arial, sans-serif; }
  .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
  .critical { background-color: #f8d7da; border: 1px solid #f5c6cb; }
  .warning { background-color: #fff3cd; border: 1px solid #ffeeba; }
  .resolved { background-color: #d4edda; border: 1px solid #c3e6cb; }
</style>
</head>
<body>
<h2>告警通知</h2>
<p>告警组: {{ .GroupLabels.alertname }}</p>
<p>状态: {{ .Status }}</p>

{{ range .Alerts }}
<div class="alert {{ .Labels.severity }}">
  <h3>{{ .Labels.alertname }}</h3>
  <p><strong>严重级别:</strong> {{ .Labels.severity }}</p>
  <p><strong>实例:</strong> {{ .Labels.instance }}</p>
  <p><strong>摘要:</strong> {{ .Annotations.summary }}</p>
  <p><strong>详情:</strong> {{ .Annotations.description }}</p>
  <p><strong>开始时间:</strong> {{ .StartsAt.Format "2006-01-02 15:04:05" }}</p>
  {{ if .EndsAt }}
  <p><strong>结束时间:</strong> {{ .EndsAt.Format "2006-01-02 15:04:05" }}</p>
  {{ end }}
</div>
{{ end }}

<p>
  <a href="{{ .ExternalURL }}">查看 Alertmanager</a>
</p>
</body>
</html>
{{ end }}
```


---

## 9. 应用程序集成

### 9.1 Java/Spring Boot 集成

```xml
<!-- pom.xml -->
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
    <dependency>
        <groupId>io.micrometer</groupId>
        <artifactId>micrometer-registry-prometheus</artifactId>
    </dependency>
</dependencies>
```

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus,metrics
  endpoint:
    prometheus:
      enabled: true
    health:
      show-details: always
  metrics:
    tags:
      application: ${spring.application.name}
      env: ${spring.profiles.active:default}
```

```java
// 自定义指标
import io.micrometer.core.instrument.*;
import org.springframework.stereotype.Component;

@Component
public class CustomMetrics {
    
    private final Counter orderCounter;
    private final Timer orderTimer;
    private final Gauge activeUsers;
    private final DistributionSummary orderAmount;
    
    public CustomMetrics(MeterRegistry registry) {
        // Counter - 计数器
        this.orderCounter = Counter.builder("orders_total")
            .description("订单总数")
            .tag("type", "created")
            .register(registry);
        
        // Timer - 计时器
        this.orderTimer = Timer.builder("order_processing_duration")
            .description("订单处理时间")
            .publishPercentiles(0.5, 0.95, 0.99)
            .publishPercentileHistogram()
            .register(registry);
        
        // Gauge - 仪表盘
        AtomicInteger activeUserCount = new AtomicInteger(0);
        this.activeUsers = Gauge.builder("active_users", activeUserCount, AtomicInteger::get)
            .description("当前活跃用户数")
            .register(registry);
        
        // Distribution Summary - 分布摘要
        this.orderAmount = DistributionSummary.builder("order_amount")
            .description("订单金额分布")
            .baseUnit("yuan")
            .publishPercentiles(0.5, 0.95, 0.99)
            .register(registry);
    }
    
    public void recordOrder(double amount) {
        orderCounter.increment();
        orderAmount.record(amount);
    }
    
    public void timeOrderProcessing(Runnable task) {
        orderTimer.record(task);
    }
}
```

### 9.2 Python 集成

```python
# pip install prometheus-client

from prometheus_client import Counter, Gauge, Histogram, Summary
from prometheus_client import start_http_server, generate_latest
from flask import Flask, Response
import time

app = Flask(__name__)

# 定义指标
REQUEST_COUNT = Counter(
    'http_requests_total',
    '请求总数',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    '请求延迟',
    ['method', 'endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1, 5, 10]
)

ACTIVE_REQUESTS = Gauge(
    'http_requests_active',
    '当前活跃请求数'
)

# 装饰器 - 自动记录指标
def track_metrics(func):
    def wrapper(*args, **kwargs):
        ACTIVE_REQUESTS.inc()
        start_time = time.time()
        
        try:
            response = func(*args, **kwargs)
            status = '200'
        except Exception as e:
            status = '500'
            raise
        finally:
            ACTIVE_REQUESTS.dec()
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.path,
                status=status
            ).inc()
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.path
            ).observe(time.time() - start_time)
        
        return response
    return wrapper

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype='text/plain')

@app.route('/api/users')
@track_metrics
def get_users():
    # 业务逻辑
    return {'users': []}

if __name__ == '__main__':
    app.run(port=8080)
```

### 9.3 Go 集成

```go
package main

import (
    "net/http"
    "time"
    
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    httpRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "HTTP 请求总数",
        },
        []string{"method", "path", "status"},
    )
    
    httpRequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "http_request_duration_seconds",
            Help:    "HTTP 请求延迟",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "path"},
    )
    
    activeConnections = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "active_connections",
            Help: "当前活跃连接数",
        },
    )
)

func init() {
    prometheus.MustRegister(httpRequestsTotal)
    prometheus.MustRegister(httpRequestDuration)
    prometheus.MustRegister(activeConnections)
}

// 中间件
func metricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        activeConnections.Inc()
        defer activeConnections.Dec()
        
        // 包装 ResponseWriter 以获取状态码
        wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
        next.ServeHTTP(wrapped, r)
        
        duration := time.Since(start).Seconds()
        httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, string(wrapped.statusCode)).Inc()
        httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
    })
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}

func main() {
    http.Handle("/metrics", promhttp.Handler())
    http.Handle("/api/", metricsMiddleware(http.HandlerFunc(apiHandler)))
    http.ListenAndServe(":8080", nil)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
}
```

### 9.4 Node.js 集成

```javascript
// npm install prom-client express

const express = require('express');
const client = require('prom-client');

const app = express();

// 启用默认指标收集
client.collectDefaultMetrics({ prefix: 'nodejs_' });

// 自定义指标
const httpRequestsTotal = new client.Counter({
    name: 'http_requests_total',
    help: 'HTTP 请求总数',
    labelNames: ['method', 'path', 'status']
});

const httpRequestDuration = new client.Histogram({
    name: 'http_request_duration_seconds',
    help: 'HTTP 请求延迟',
    labelNames: ['method', 'path'],
    buckets: [0.01, 0.05, 0.1, 0.5, 1, 5, 10]
});

const activeRequests = new client.Gauge({
    name: 'http_requests_active',
    help: '当前活跃请求数'
});

// 中间件
app.use((req, res, next) => {
    const start = Date.now();
    activeRequests.inc();
    
    res.on('finish', () => {
        const duration = (Date.now() - start) / 1000;
        activeRequests.dec();
        
        httpRequestsTotal.labels(req.method, req.path, res.statusCode).inc();
        httpRequestDuration.labels(req.method, req.path).observe(duration);
    });
    
    next();
});

// 指标端点
app.get('/metrics', async (req, res) => {
    res.set('Content-Type', client.register.contentType);
    res.end(await client.register.metrics());
});

app.get('/api/users', (req, res) => {
    res.json({ users: [] });
});

app.listen(8080, () => {
    console.log('Server running on port 8080');
});
```


---

## 10. 高可用与扩展

### 10.1 Prometheus 高可用

Prometheus 本身不支持原生集群，但可以通过以下方式实现高可用：

```
┌─────────────────────────────────────────────────────────────────┐
│                    Prometheus 高可用架构                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    ┌──────────────┐         ┌──────────────┐                   │
│    │ Prometheus 1 │         │ Prometheus 2 │                   │
│    │   (主节点)    │         │   (副本)     │                   │
│    └──────┬───────┘         └──────┬───────┘                   │
│           │                        │                            │
│           └────────────┬───────────┘                            │
│                        │                                         │
│                        ▼                                         │
│              ┌─────────────────┐                                │
│              │   Thanos/VictoriaMetrics                         │
│              │   (长期存储 + 去重)                               │
│              └────────┬────────┘                                │
│                       │                                          │
│                       ▼                                          │
│              ┌─────────────────┐                                │
│              │     Grafana     │                                │
│              └─────────────────┘                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### 方案一：双副本 + 负载均衡

```yaml
# docker-compose-ha.yml
version: '3.8'

services:
  prometheus-1:
    image: prom/prometheus:v2.47.0
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data_1:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
    networks:
      - monitoring

  prometheus-2:
    image: prom/prometheus:v2.47.0
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data_2:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
    networks:
      - monitoring

  nginx:
    image: nginx:alpine
    ports:
      - "9090:9090"
    volumes:
      - ./nginx-prometheus.conf:/etc/nginx/nginx.conf
    depends_on:
      - prometheus-1
      - prometheus-2
    networks:
      - monitoring

volumes:
  prometheus_data_1:
  prometheus_data_2:

networks:
  monitoring:
```

```nginx
# nginx-prometheus.conf
upstream prometheus {
    server prometheus-1:9090;
    server prometheus-2:9090 backup;
}

server {
    listen 9090;
    
    location / {
        proxy_pass http://prometheus;
        proxy_set_header Host $host;
    }
}
```

### 10.2 Thanos 架构

Thanos 是 Prometheus 的高可用和长期存储解决方案。

```yaml
# docker-compose-thanos.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:v2.47.0
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.min-block-duration=2h'
      - '--storage.tsdb.max-block-duration=2h'
    networks:
      - monitoring

  thanos-sidecar:
    image: quay.io/thanos/thanos:v0.32.0
    volumes:
      - prometheus_data:/prometheus
      - ./thanos-bucket.yml:/etc/thanos/bucket.yml
    command:
      - sidecar
      - --tsdb.path=/prometheus
      - --prometheus.url=http://prometheus:9090
      - --objstore.config-file=/etc/thanos/bucket.yml
    depends_on:
      - prometheus
    networks:
      - monitoring

  thanos-query:
    image: quay.io/thanos/thanos:v0.32.0
    ports:
      - "19090:9090"
    command:
      - query
      - --http-address=0.0.0.0:9090
      - --store=thanos-sidecar:10901
      - --store=thanos-store:10901
    networks:
      - monitoring

  thanos-store:
    image: quay.io/thanos/thanos:v0.32.0
    volumes:
      - ./thanos-bucket.yml:/etc/thanos/bucket.yml
    command:
      - store
      - --data-dir=/var/thanos/store
      - --objstore.config-file=/etc/thanos/bucket.yml
    networks:
      - monitoring

  thanos-compactor:
    image: quay.io/thanos/thanos:v0.32.0
    volumes:
      - ./thanos-bucket.yml:/etc/thanos/bucket.yml
    command:
      - compact
      - --data-dir=/var/thanos/compact
      - --objstore.config-file=/etc/thanos/bucket.yml
      - --wait
    networks:
      - monitoring

volumes:
  prometheus_data:

networks:
  monitoring:
```

```yaml
# thanos-bucket.yml (S3 配置)
type: S3
config:
  bucket: "thanos-metrics"
  endpoint: "s3.amazonaws.com"
  access_key: "your-access-key"
  secret_key: "your-secret-key"
  region: "us-east-1"
```

### 10.3 联邦集群

联邦集群允许一个 Prometheus 从其他 Prometheus 实例拉取数据。

```yaml
# 全局 Prometheus 配置
scrape_configs:
  - job_name: 'federate'
    scrape_interval: 15s
    honor_labels: true
    metrics_path: '/federate'
    params:
      'match[]':
        - '{job="prometheus"}'
        - '{__name__=~"job:.*"}'
        - 'up'
    static_configs:
      - targets:
          - 'prometheus-dc1:9090'
          - 'prometheus-dc2:9090'
          - 'prometheus-dc3:9090'
```


---

## 11. 存储与性能优化

### 11.1 存储配置

```bash
# Prometheus 存储参数
./prometheus \
  --storage.tsdb.path=/prometheus \           # 数据存储路径
  --storage.tsdb.retention.time=15d \         # 数据保留时间
  --storage.tsdb.retention.size=50GB \        # 数据保留大小（先达到的生效）
  --storage.tsdb.min-block-duration=2h \      # 最小块持续时间
  --storage.tsdb.max-block-duration=2h \      # 最大块持续时间（用于 Thanos）
  --storage.tsdb.wal-compression              # 启用 WAL 压缩
```

### 11.2 性能优化

```yaml
# prometheus.yml 优化配置
global:
  scrape_interval: 30s      # 增加采集间隔减少负载
  scrape_timeout: 25s       # 采集超时略小于间隔
  evaluation_interval: 30s  # 规则评估间隔

scrape_configs:
  - job_name: 'high-cardinality-app'
    scrape_interval: 60s    # 高基数指标使用更长间隔
    sample_limit: 10000     # 限制每次采集的样本数
    static_configs:
      - targets: ['app:8080']
    metric_relabel_configs:
      # 删除不需要的指标
      - source_labels: [__name__]
        regex: 'go_.*'
        action: drop
      # 删除高基数标签
      - regex: 'id|uuid'
        action: labeldrop
```

### 11.3 记录规则（Recording Rules）

记录规则可以预计算常用查询，提高查询性能。

```yaml
# prometheus/rules/recording_rules.yml
groups:
  - name: 预计算规则
    interval: 30s
    rules:
      # 预计算 CPU 使用率
      - record: instance:node_cpu_utilization:rate5m
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

      # 预计算内存使用率
      - record: instance:node_memory_utilization:ratio
        expr: 1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes

      # 预计算 QPS
      - record: job:http_requests:rate5m
        expr: sum by (job) (rate(http_requests_total[5m]))

      # 预计算错误率
      - record: job:http_errors:rate5m
        expr: sum by (job) (rate(http_requests_total{status=~"5.."}[5m]))

      - record: job:http_error_rate:ratio5m
        expr: job:http_errors:rate5m / job:http_requests:rate5m

      # 预计算 P99 延迟
      - record: job:http_request_duration_seconds:p99
        expr: histogram_quantile(0.99, sum by (job, le) (rate(http_request_duration_seconds_bucket[5m])))

      # 预计算磁盘使用率
      - record: instance:node_filesystem_utilization:ratio
        expr: 1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes
```

### 11.4 远程存储

```yaml
# prometheus.yml - 远程写入配置
remote_write:
  - url: "http://victoriametrics:8428/api/v1/write"
    queue_config:
      capacity: 10000
      max_shards: 30
      max_samples_per_send: 5000
      batch_send_deadline: 10s
      min_backoff: 30ms
      max_backoff: 5s
    write_relabel_configs:
      # 只写入特定指标
      - source_labels: [__name__]
        regex: 'job:.*|instance:.*'
        action: keep

remote_read:
  - url: "http://victoriametrics:8428/api/v1/read"
    read_recent: true
```

### 11.5 存储容量规划

```
存储计算公式：
存储大小 = 采集间隔 × 时间序列数 × 每个样本大小 × 保留时间

示例：
- 采集间隔：15s
- 时间序列数：100,000
- 每个样本大小：约 1-2 bytes（压缩后）
- 保留时间：15 天

每天数据量 = (86400 / 15) × 100,000 × 2 = 约 1.15 GB/天
15 天数据量 = 1.15 × 15 = 约 17.25 GB

建议预留 2-3 倍空间用于压缩和临时文件
```


---

## 12. 安全配置

### 12.1 Prometheus 认证

```yaml
# prometheus.yml - 基本认证
scrape_configs:
  - job_name: 'secure-target'
    basic_auth:
      username: prometheus
      password_file: /etc/prometheus/password

  # Bearer Token 认证
  - job_name: 'kubernetes-api'
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    
  # TLS 配置
  - job_name: 'tls-target'
    scheme: https
    tls_config:
      ca_file: /etc/prometheus/ca.crt
      cert_file: /etc/prometheus/client.crt
      key_file: /etc/prometheus/client.key
      insecure_skip_verify: false
```

```yaml
# web-config.yml - Prometheus Web 认证
basic_auth_users:
  admin: $2y$10$xxx...  # bcrypt 加密的密码

tls_server_config:
  cert_file: /etc/prometheus/server.crt
  key_file: /etc/prometheus/server.key
  client_auth_type: RequireAndVerifyClientCert
  client_ca_file: /etc/prometheus/ca.crt
```

```bash
# 生成 bcrypt 密码
htpasswd -nBC 10 "" | tr -d ':\n'

# 启动时指定 web 配置
./prometheus --web.config.file=web-config.yml
```

### 12.2 Grafana 安全配置

```ini
# grafana.ini
[security]
admin_user = admin
admin_password = secure_password
secret_key = your_secret_key_here
disable_gravatar = true
cookie_secure = true
cookie_samesite = strict
strict_transport_security = true
strict_transport_security_max_age_seconds = 86400
x_content_type_options = true
x_xss_protection = true

[auth]
disable_login_form = false
disable_signout_menu = false

[auth.anonymous]
enabled = false

[auth.basic]
enabled = true

[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml
allow_sign_up = true

[auth.google]
enabled = true
client_id = your-client-id
client_secret = your-client-secret
scopes = openid email profile
auth_url = https://accounts.google.com/o/oauth2/auth
token_url = https://oauth2.googleapis.com/token
allowed_domains = example.com
allow_sign_up = true
```

### 12.3 网络安全

```yaml
# docker-compose.yml - 网络隔离
version: '3.8'

services:
  prometheus:
    networks:
      - monitoring-internal
      - monitoring-external
    # 只暴露给内部网络

  grafana:
    networks:
      - monitoring-internal
      - frontend
    ports:
      - "3000:3000"

  node-exporter:
    networks:
      - monitoring-internal
    # 不暴露端口到外部

networks:
  monitoring-internal:
    internal: true  # 内部网络，不能访问外部
  monitoring-external:
  frontend:
```

```nginx
# Nginx 反向代理 + 认证
server {
    listen 443 ssl;
    server_name prometheus.example.com;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    # 基本认证
    auth_basic "Prometheus";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # IP 白名单
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;

    location / {
        proxy_pass http://prometheus:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```


---

## 13. Kubernetes 监控

### 13.1 kube-prometheus-stack

kube-prometheus-stack 是在 Kubernetes 中部署完整监控栈的最佳方式。

```bash
# 使用 Helm 安装
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# 安装
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.retention=30d \
  --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
  --set grafana.adminPassword=admin123

# 查看安装的组件
kubectl get pods -n monitoring
```

```yaml
# values.yaml - 自定义配置
prometheus:
  prometheusSpec:
    retention: 30d
    retentionSize: 50GB
    resources:
      requests:
        memory: 2Gi
        cpu: 500m
      limits:
        memory: 4Gi
        cpu: 2000m
    storageSpec:
      volumeClaimTemplate:
        spec:
          storageClassName: standard
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
    additionalScrapeConfigs:
      - job_name: 'custom-app'
        kubernetes_sd_configs:
          - role: pod
        relabel_configs:
          - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
            action: keep
            regex: true

grafana:
  adminPassword: secure_password
  persistence:
    enabled: true
    size: 10Gi
  dashboardProviders:
    dashboardproviders.yaml:
      apiVersion: 1
      providers:
        - name: 'custom'
          folder: 'Custom'
          type: file
          options:
            path: /var/lib/grafana/dashboards/custom

alertmanager:
  config:
    global:
      resolve_timeout: 5m
    route:
      receiver: 'slack'
    receivers:
      - name: 'slack'
        slack_configs:
          - api_url: 'https://hooks.slack.com/services/xxx'
            channel: '#alerts'
```

### 13.2 ServiceMonitor 和 PodMonitor

```yaml
# ServiceMonitor - 监控 Service
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: my-app
  namespace: monitoring
  labels:
    release: prometheus  # 必须匹配 Prometheus 的 serviceMonitorSelector
spec:
  selector:
    matchLabels:
      app: my-app
  namespaceSelector:
    matchNames:
      - default
      - production
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
      scrapeTimeout: 10s
      honorLabels: true
```

```yaml
# PodMonitor - 直接监控 Pod
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: my-app-pods
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: my-app
  namespaceSelector:
    any: true
  podMetricsEndpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

### 13.3 PrometheusRule

```yaml
# PrometheusRule - 告警规则
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: my-app-rules
  namespace: monitoring
  labels:
    release: prometheus
spec:
  groups:
    - name: my-app
      rules:
        - alert: MyAppDown
          expr: up{job="my-app"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "MyApp is down"
            description: "MyApp instance {{ $labels.instance }} is down"

        - alert: MyAppHighErrorRate
          expr: |
            sum(rate(http_requests_total{job="my-app",status=~"5.."}[5m])) 
            / sum(rate(http_requests_total{job="my-app"}[5m])) > 0.05
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High error rate"
            description: "Error rate is {{ $value | humanizePercentage }}"
```

### 13.4 应用监控配置

```yaml
# Deployment 配置
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  template:
    metadata:
      labels:
        app: my-app
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      containers:
        - name: my-app
          image: my-app:latest
          ports:
            - name: http
              containerPort: 8080
            - name: metrics
              containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: my-app
  labels:
    app: my-app
spec:
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: metrics
      port: 8080
      targetPort: 8080
  selector:
    app: my-app
```


---

## 14. 最佳实践

### 14.1 指标命名规范

```
指标命名规则：
1. 使用小写字母和下划线
2. 以应用或库名称为前缀
3. 使用基本单位（秒、字节）
4. 以单位为后缀

格式：<namespace>_<name>_<unit>

✅ 正确示例：
http_requests_total                    # Counter
http_request_duration_seconds          # Histogram
node_memory_available_bytes            # Gauge
process_cpu_seconds_total              # Counter

❌ 错误示例：
HttpRequests                           # 不要用驼峰
http_requests_milliseconds             # 应该用秒
requests                               # 缺少前缀
http_request_duration                  # 缺少单位
```

### 14.2 标签使用规范

```yaml
# ✅ 好的标签使用
http_requests_total{method="GET", status="200", handler="/api/users"}

# ❌ 避免高基数标签
http_requests_total{user_id="12345", request_id="abc-123"}  # 会产生大量时间序列

# 标签最佳实践：
# 1. 标签值应该是有限的、可枚举的
# 2. 避免使用 ID、时间戳等高基数值
# 3. 标签数量不宜过多（建议 < 10 个）
# 4. 使用有意义的标签名

# 常用标签：
# - env: production, staging, development
# - region: us-east-1, eu-west-1
# - service: user-service, order-service
# - instance: 实例标识
# - method: GET, POST, PUT, DELETE
# - status: 200, 400, 500
# - handler/path: API 路径
```

### 14.3 告警规则最佳实践

```yaml
groups:
  - name: 告警最佳实践
    rules:
      # 1. 使用 for 子句避免瞬时抖动
      - alert: HighCpuUsage
        expr: cpu_usage > 80
        for: 5m  # 持续 5 分钟才告警
        labels:
          severity: warning

      # 2. 使用预计算规则提高性能
      - alert: HighErrorRate
        expr: job:http_error_rate:ratio5m > 0.05  # 使用预计算指标
        for: 5m

      # 3. 提供有意义的注解
      - alert: DiskSpaceLow
        expr: disk_usage > 85
        for: 10m
        annotations:
          summary: "磁盘空间不足 ({{ $labels.instance }})"
          description: "磁盘 {{ $labels.mountpoint }} 使用率 {{ $value | printf \"%.1f\" }}%"
          runbook_url: "https://wiki.example.com/runbooks/disk-space"

      # 4. 分级告警
      - alert: ServiceLatencyWarning
        expr: http_request_duration_seconds_p99 > 1
        for: 5m
        labels:
          severity: warning

      - alert: ServiceLatencyCritical
        expr: http_request_duration_seconds_p99 > 5
        for: 5m
        labels:
          severity: critical

      # 5. 使用 absent() 检测指标缺失
      - alert: PrometheusTargetMissing
        expr: absent(up{job="my-app"})
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "监控目标丢失"
```

### 14.4 Dashboard 设计原则

```
1. 层次结构
   - 概览 Dashboard：关键指标一目了然
   - 详情 Dashboard：深入分析特定服务
   - 调试 Dashboard：问题排查用

2. 布局建议
   - 最重要的指标放在左上角
   - 相关指标放在一起
   - 使用行（Row）分组
   - 保持一致的面板大小

3. 颜色使用
   - 绿色：正常
   - 黄色：警告
   - 红色：严重
   - 保持颜色一致性

4. 时间范围
   - 默认显示最近 1 小时
   - 提供快速时间选择
   - 考虑数据刷新频率

5. 变量使用
   - 使用变量实现动态筛选
   - 提供 "All" 选项
   - 变量之间可以级联
```

### 14.5 监控覆盖清单

```
基础设施监控：
□ CPU 使用率
□ 内存使用率
□ 磁盘使用率和 IO
□ 网络流量和错误
□ 系统负载
□ 进程数

应用监控：
□ 请求速率（QPS）
□ 错误率
□ 响应时间（P50/P95/P99）
□ 并发连接数
□ 队列长度

数据库监控：
□ 连接数
□ 查询速率
□ 慢查询数
□ 复制延迟
□ 缓存命中率

中间件监控：
□ Redis：内存、命中率、连接数
□ Kafka：消费延迟、分区状态
□ Nginx：请求数、连接数、错误数

业务监控：
□ 用户注册/登录数
□ 订单数量
□ 支付成功率
□ 关键业务流程耗时
```


---

## 15. 常见错误与解决方案

### 15.1 Prometheus 常见问题

```bash
# ❌ 错误：TSDB 锁定
# Error opening TSDB: lock file exists

# 原因：Prometheus 异常退出，锁文件未清理
# ✅ 解决：
rm /prometheus/lock
# 或者等待旧进程完全退出


# ❌ 错误：内存不足 OOM
# out of memory

# 原因：时间序列过多或查询过于复杂
# ✅ 解决：
# 1. 增加内存
# 2. 减少采集的指标数量
# 3. 使用 metric_relabel_configs 删除不需要的指标
# 4. 减少标签基数
# 5. 使用记录规则预计算


# ❌ 错误：采集超时
# context deadline exceeded

# 原因：目标响应太慢
# ✅ 解决：
scrape_configs:
  - job_name: 'slow-target'
    scrape_timeout: 30s  # 增加超时时间
    scrape_interval: 60s  # 增加采集间隔


# ❌ 错误：目标不可达
# Get "http://target:9090/metrics": dial tcp: connection refused

# 原因：网络问题或服务未启动
# ✅ 解决：
# 1. 检查目标服务是否运行
# 2. 检查网络连通性
# 3. 检查防火墙规则
# 4. 检查 DNS 解析


# ❌ 错误：配置文件语法错误
# error loading config file

# ✅ 解决：使用 promtool 检查配置
./promtool check config prometheus.yml
./promtool check rules rules/*.yml


# ❌ 错误：高基数导致性能问题
# 查询缓慢，内存占用高

# ✅ 解决：
# 1. 检查高基数指标
# 查询：topk(10, count by (__name__)({__name__=~".+"}))
# 2. 删除高基数标签
metric_relabel_configs:
  - regex: 'request_id|trace_id|user_id'
    action: labeldrop
```

### 15.2 PromQL 常见错误

```promql
# ❌ 错误：对 Counter 直接求和
sum(http_requests_total)  # 结果会越来越大

# ✅ 正确：使用 rate() 或 increase()
sum(rate(http_requests_total[5m]))


# ❌ 错误：rate() 时间范围太短
rate(http_requests_total[30s])  # 可能没有足够的数据点

# ✅ 正确：时间范围至少是采集间隔的 4 倍
rate(http_requests_total[5m])  # 采集间隔 15s，5m 有约 20 个数据点


# ❌ 错误：histogram_quantile 分组错误
histogram_quantile(0.95, http_request_duration_seconds_bucket)

# ✅ 正确：必须按 le 标签分组
histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket[5m])))


# ❌ 错误：向量匹配失败
http_requests_total / http_errors_total  # 标签不匹配

# ✅ 正确：使用 on() 或 ignoring() 指定匹配标签
http_requests_total / on(instance, job) http_errors_total


# ❌ 错误：absent() 使用不当
absent(up{job="myapp"} == 1)  # 语法错误

# ✅ 正确：
absent(up{job="myapp"})  # 检查指标是否存在
up{job="myapp"} == 0     # 检查值是否为 0


# ❌ 错误：offset 位置错误
rate(http_requests_total offset 1h[5m])  # 语法错误

# ✅ 正确：
rate(http_requests_total[5m] offset 1h)
```

### 15.3 Grafana 常见问题

```bash
# ❌ 错误：数据源连接失败
# Post "http://prometheus:9090/api/v1/query": dial tcp: connection refused

# ✅ 解决：
# 1. 检查 Prometheus 是否运行
# 2. 检查 URL 是否正确（注意容器网络）
# 3. 在 Docker 中使用服务名而非 localhost


# ❌ 错误：Dashboard 加载缓慢
# 原因：查询过于复杂或数据量太大

# ✅ 解决：
# 1. 使用记录规则预计算
# 2. 减少时间范围
# 3. 增加查询间隔
# 4. 使用 $__interval 自动调整


# ❌ 错误：变量查询返回空
# 原因：查询语法错误或数据源问题

# ✅ 解决：
# 1. 在 Prometheus 中测试查询
# 2. 检查 label_values() 语法
# 正确：label_values(up, instance)
# 错误：label_values(instance)  # 缺少指标名


# ❌ 错误：图表显示 No Data
# 原因：查询无结果或时间范围不对

# ✅ 解决：
# 1. 在 Query Inspector 中查看原始查询
# 2. 检查时间范围是否有数据
# 3. 检查变量值是否正确
# 4. 检查指标名和标签是否正确


# ❌ 错误：告警不触发
# 原因：配置问题或条件不满足

# ✅ 解决：
# 1. 检查告警规则语法
# 2. 在 Prometheus 中测试表达式
# 3. 检查 for 持续时间
# 4. 检查 Alertmanager 配置
```

### 15.4 Alertmanager 常见问题

```yaml
# ❌ 错误：告警未发送
# 原因：路由配置错误

# ✅ 解决：检查路由匹配
# 使用 amtool 测试路由
amtool config routes test --config.file=alertmanager.yml severity=critical

# ❌ 错误：重复告警
# 原因：group_by 配置不当

# ✅ 解决：正确配置分组
route:
  group_by: ['alertname', 'severity', 'instance']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h


# ❌ 错误：告警风暴
# 原因：缺少抑制规则

# ✅ 解决：配置抑制规则
inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']


# ❌ 错误：邮件发送失败
# dial tcp: connection refused

# ✅ 解决：
# 1. 检查 SMTP 配置
# 2. 检查网络连通性
# 3. 检查认证信息
# 4. 检查是否需要 TLS
global:
  smtp_smarthost: 'smtp.example.com:587'
  smtp_require_tls: true
  smtp_auth_username: 'user'
  smtp_auth_password: 'password'
```

### 15.5 性能问题排查

```bash
# 1. 检查 Prometheus 状态
curl http://localhost:9090/api/v1/status/runtimeinfo

# 2. 检查 TSDB 状态
curl http://localhost:9090/api/v1/status/tsdb

# 3. 查看高基数指标
curl 'http://localhost:9090/api/v1/query?query=topk(10,count by (__name__)({__name__=~".+"}))'

# 4. 查看采集目标状态
curl http://localhost:9090/api/v1/targets

# 5. 检查内存使用
curl http://localhost:9090/metrics | grep process_resident_memory_bytes

# 6. 检查查询性能
# 在 Prometheus UI 中启用 Query Stats
# 或查看 prometheus_engine_query_duration_seconds
```

---

## 附录：常用命令速查

```bash
# Prometheus
./promtool check config prometheus.yml          # 检查配置
./promtool check rules rules/*.yml              # 检查规则
./promtool query instant http://localhost:9090 'up'  # 即时查询
./promtool query range http://localhost:9090 --start=1h --end=now 'up'  # 范围查询
curl -X POST http://localhost:9090/-/reload    # 热重载配置

# Alertmanager
./amtool check-config alertmanager.yml          # 检查配置
./amtool alert query                            # 查看告警
./amtool silence add alertname=Test             # 添加静默
./amtool silence query                          # 查看静默
./amtool silence expire <silence-id>            # 取消静默

# Grafana
grafana-cli plugins install <plugin-name>       # 安装插件
grafana-cli admin reset-admin-password <new-password>  # 重置密码

# Docker Compose
docker-compose up -d                            # 启动服务
docker-compose logs -f prometheus               # 查看日志
docker-compose restart prometheus               # 重启服务
docker-compose down                             # 停止服务
```

---

> 本笔记涵盖了 Prometheus + Grafana 监控系统从入门到进阶的核心知识点。
> 官方文档：
> - Prometheus: https://prometheus.io/docs/
> - Grafana: https://grafana.com/docs/
> - Alertmanager: https://prometheus.io/docs/alerting/latest/alertmanager/
