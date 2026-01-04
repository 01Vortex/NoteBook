# RocketMQ 完整学习笔记

> RocketMQ 是阿里巴巴开源的分布式消息中间件，具有高吞吐、低延迟、高可用的特点
> 本笔记基于 Java 17 + Spring Boot 3.2.12 + RocketMQ 5.x
> 涵盖从入门到生产实践的完整内容

---

## 目录

1. [RocketMQ 简介](#1-rocketmq-简介)
2. [安装部署](#2-安装部署)
3. [核心概念](#3-核心概念)
4. [Spring Boot 集成](#4-spring-boot-集成)
5. [消息发送](#5-消息发送)
6. [消息消费](#6-消息消费)
7. [顺序消息](#7-顺序消息)
8. [延迟消息](#8-延迟消息)
9. [事务消息](#9-事务消息)
10. [消息过滤](#10-消息过滤)
11. [消息重试与死信队列](#11-消息重试与死信队列)
12. [集群消费与广播消费](#12-集群消费与广播消费)
13. [消息轨迹](#13-消息轨迹)
14. [生产环境配置](#14-生产环境配置)
15. [常见错误与解决方案](#15-常见错误与解决方案)
16. [最佳实践](#16-最佳实践)

---

## 1. RocketMQ 简介

### 1.1 什么是 RocketMQ？

RocketMQ 是一款低延迟、高可靠、可伸缩、易于使用的消息中间件。它诞生于阿里巴巴，经历了双十一等大促的考验，2017 年成为 Apache 顶级项目。

**核心特点**：
- **高吞吐**：单机支持 10 万级 TPS
- **低延迟**：毫秒级消息投递
- **高可用**：支持主从同步、多副本
- **丰富的消息类型**：普通消息、顺序消息、延迟消息、事务消息
- **海量消息堆积**：支持亿级消息堆积，不影响性能

### 1.2 RocketMQ vs 其他 MQ

| 特性 | RocketMQ | Kafka | RabbitMQ |
|------|----------|-------|----------|
| 开发语言 | Java | Scala | Erlang |
| 单机吞吐 | 10万级 | 100万级 | 万级 |
| 消息延迟 | 毫秒级 | 毫秒级 | 微秒级 |
| 消息可靠性 | 高 | 高 | 高 |
| 事务消息 | 支持 | 不支持 | 不支持 |
| 延迟消息 | 支持 | 不支持 | 支持（插件） |
| 顺序消息 | 支持 | 支持 | 支持 |
| 消息回溯 | 支持 | 支持 | 不支持 |
| 适用场景 | 电商、金融 | 日志、大数据 | 企业应用 |

### 1.3 应用场景

- **异步解耦**：订单创建后异步发送短信、邮件
- **流量削峰**：秒杀场景，用 MQ 缓冲请求
- **数据同步**：数据库变更同步到缓存、ES
- **分布式事务**：使用事务消息保证最终一致性
- **延迟任务**：订单超时取消、定时提醒


---

## 2. 安装部署

### 2.1 Docker 单机部署（开发环境）

```bash
# 创建网络
docker network create rocketmq

# 启动 NameServer
docker run -d \
  --name rmqnamesrv \
  --network rocketmq \
  -p 9876:9876 \
  apache/rocketmq:5.1.4 \
  sh mqnamesrv

# 启动 Broker
docker run -d \
  --name rmqbroker \
  --network rocketmq \
  -p 10911:10911 \
  -p 10909:10909 \
  -e "NAMESRV_ADDR=rmqnamesrv:9876" \
  apache/rocketmq:5.1.4 \
  sh mqbroker -n rmqnamesrv:9876

# 启动控制台（可选）
docker run -d \
  --name rmqconsole \
  --network rocketmq \
  -p 8080:8080 \
  -e "JAVA_OPTS=-Drocketmq.namesrv.addr=rmqnamesrv:9876" \
  apacherocketmq/rocketmq-dashboard:latest
```

### 2.2 Docker Compose 部署

```yaml
# docker-compose.yml
version: '3.8'

services:
  namesrv:
    image: apache/rocketmq:5.1.4
    container_name: rmqnamesrv
    ports:
      - "9876:9876"
    command: sh mqnamesrv
    networks:
      - rocketmq

  broker:
    image: apache/rocketmq:5.1.4
    container_name: rmqbroker
    ports:
      - "10911:10911"
      - "10909:10909"
    environment:
      NAMESRV_ADDR: namesrv:9876
    command: sh mqbroker -n namesrv:9876
    depends_on:
      - namesrv
    networks:
      - rocketmq

  dashboard:
    image: apacherocketmq/rocketmq-dashboard:latest
    container_name: rmqdashboard
    ports:
      - "8080:8080"
    environment:
      JAVA_OPTS: -Drocketmq.namesrv.addr=namesrv:9876
    depends_on:
      - namesrv
      - broker
    networks:
      - rocketmq

networks:
  rocketmq:
    driver: bridge
```

```bash
# 启动
docker-compose up -d

# 查看日志
docker-compose logs -f
```

### 2.3 访问控制台

启动后访问：http://localhost:8080

可以查看：
- 集群状态
- Topic 列表
- 消费者组
- 消息查询

---

## 3. 核心概念

### 3.1 架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          RocketMQ 架构                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐                           │
│   │ Producer │     │ Producer │     │ Producer │                           │
│   └────┬─────┘     └────┬─────┘     └────┬─────┘                           │
│        │                │                │                                  │
│        └────────────────┼────────────────┘                                  │
│                         │                                                   │
│                         ▼                                                   │
│              ┌─────────────────────┐                                        │
│              │     NameServer      │  ← 路由注册中心                         │
│              │  (可部署多个，无状态) │                                        │
│              └─────────────────────┘                                        │
│                         │                                                   │
│        ┌────────────────┼────────────────┐                                  │
│        ▼                ▼                ▼                                  │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐                              │
│   │ Broker  │     │ Broker  │     │ Broker  │  ← 消息存储                   │
│   │ Master  │     │ Master  │     │ Master  │                              │
│   └────┬────┘     └────┬────┘     └────┬────┘                              │
│        │               │               │                                    │
│   ┌────┴────┐     ┌────┴────┐     ┌────┴────┐                              │
│   │ Broker  │     │ Broker  │     │ Broker  │  ← 从节点                     │
│   │  Slave  │     │  Slave  │     │  Slave  │                              │
│   └─────────┘     └─────────┘     └─────────┘                              │
│                         │                                                   │
│        ┌────────────────┼────────────────┐                                  │
│        ▼                ▼                ▼                                  │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐                           │
│   │ Consumer │     │ Consumer │     │ Consumer │                           │
│   └──────────┘     └──────────┘     └──────────┘                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 核心概念

| 概念 | 说明 |
|------|------|
| **NameServer** | 路由注册中心，Broker 向其注册，Producer/Consumer 从其获取路由信息 |
| **Broker** | 消息存储服务器，负责消息的存储、投递、查询 |
| **Producer** | 消息生产者，负责发送消息 |
| **Consumer** | 消息消费者，负责消费消息 |
| **Topic** | 消息主题，一类消息的集合，是逻辑概念 |
| **MessageQueue** | 消息队列，Topic 的物理分区，一个 Topic 有多个 Queue |
| **Tag** | 消息标签，用于消息过滤 |
| **ConsumerGroup** | 消费者组，同一组内的消费者共同消费消息 |
| **Offset** | 消费位点，记录消费进度 |

### 3.3 消息模型

```
Topic: OrderTopic
├── MessageQueue-0  ──> Consumer-1 (ConsumerGroup-A)
├── MessageQueue-1  ──> Consumer-2 (ConsumerGroup-A)
├── MessageQueue-2  ──> Consumer-3 (ConsumerGroup-A)
└── MessageQueue-3  ──> Consumer-1 (ConsumerGroup-A)  // 消费者不够时，一个消费者消费多个队列

同时：
├── MessageQueue-0  ──> Consumer-X (ConsumerGroup-B)  // 不同消费组独立消费
├── MessageQueue-1  ──> Consumer-X (ConsumerGroup-B)
...
```


---

## 4. Spring Boot 集成

### 4.1 添加依赖

```xml
<!-- pom.xml -->
<dependencies>
    <!-- RocketMQ Spring Boot Starter -->
    <dependency>
        <groupId>org.apache.rocketmq</groupId>
        <artifactId>rocketmq-spring-boot-starter</artifactId>
        <version>2.2.3</version>
    </dependency>
    
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    
    <!-- JSON -->
    <dependency>
        <groupId>com.alibaba.fastjson2</groupId>
        <artifactId>fastjson2</artifactId>
        <version>2.0.43</version>
    </dependency>
</dependencies>
```

### 4.2 配置文件

```yaml
# application.yml
rocketmq:
  name-server: localhost:9876
  producer:
    group: my-producer-group
    send-message-timeout: 3000
    retry-times-when-send-failed: 2
    retry-times-when-send-async-failed: 2
  consumer:
    group: my-consumer-group
    
# 日志配置
logging:
  level:
    org.apache.rocketmq: INFO
```

### 4.3 配置类

```java
package com.example.config;

import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Resource;

@Configuration
public class RocketMQConfig {
    
    @Resource
    private RocketMQTemplate rocketMQTemplate;
    
    @PostConstruct
    public void init() {
        // 设置消息发送超时时间
        rocketMQTemplate.getProducer().setSendMsgTimeout(3000);
        // 设置最大消息大小（默认 4MB）
        rocketMQTemplate.getProducer().setMaxMessageSize(4 * 1024 * 1024);
    }
}
```

### 4.4 消息实体

```java
package com.example.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * 订单消息
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderMessage implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 订单ID
     */
    private Long orderId;
    
    /**
     * 用户ID
     */
    private Long userId;
    
    /**
     * 订单金额
     */
    private BigDecimal amount;
    
    /**
     * 订单状态
     */
    private String status;
    
    /**
     * 创建时间
     */
    private LocalDateTime createTime;
}
```

---

## 5. 消息发送

### 5.1 发送方式概览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        RocketMQ 消息发送方式                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. 同步发送（Sync）                                                        │
│     - 发送后等待 Broker 响应                                                │
│     - 可靠性最高，性能较低                                                  │
│     - 适用场景：重要通知、订单创建                                          │
│                                                                             │
│  2. 异步发送（Async）                                                       │
│     - 发送后立即返回，通过回调处理结果                                      │
│     - 可靠性高，性能好                                                      │
│     - 适用场景：响应时间敏感的场景                                          │
│                                                                             │
│  3. 单向发送（OneWay）                                                      │
│     - 发送后不等待响应                                                      │
│     - 性能最高，可靠性最低                                                  │
│     - 适用场景：日志收集、不重要的通知                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 消息发送服务

```java
package com.example.service;

import com.alibaba.fastjson2.JSON;
import com.example.dto.OrderMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.client.producer.SendCallback;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class MessageProducerService {
    
    private final RocketMQTemplate rocketMQTemplate;
    
    // Topic 常量
    private static final String ORDER_TOPIC = "ORDER_TOPIC";
    
    // ==================== 同步发送 ====================
    
    /**
     * 同步发送消息（推荐用于重要消息）
     */
    public SendResult syncSend(OrderMessage orderMessage) {
        String destination = ORDER_TOPIC;
        SendResult result = rocketMQTemplate.syncSend(destination, orderMessage);
        log.info("同步发送成功, msgId: {}, status: {}", 
            result.getMsgId(), result.getSendStatus());
        return result;
    }
    
    /**
     * 同步发送带 Tag 的消息
     */
    public SendResult syncSendWithTag(OrderMessage orderMessage, String tag) {
        String destination = ORDER_TOPIC + ":" + tag;
        SendResult result = rocketMQTemplate.syncSend(destination, orderMessage);
        log.info("同步发送成功, tag: {}, msgId: {}", tag, result.getMsgId());
        return result;
    }
    
    /**
     * 同步发送带超时的消息
     */
    public SendResult syncSendWithTimeout(OrderMessage orderMessage, long timeout) {
        String destination = ORDER_TOPIC;
        SendResult result = rocketMQTemplate.syncSend(destination, orderMessage, timeout);
        return result;
    }
    
    // ==================== 异步发送 ====================
    
    /**
     * 异步发送消息
     */
    public void asyncSend(OrderMessage orderMessage) {
        String destination = ORDER_TOPIC;
        
        rocketMQTemplate.asyncSend(destination, orderMessage, new SendCallback() {
            @Override
            public void onSuccess(SendResult sendResult) {
                log.info("异步发送成功, msgId: {}", sendResult.getMsgId());
            }
            
            @Override
            public void onException(Throwable e) {
                log.error("异步发送失败, order: {}", orderMessage.getOrderId(), e);
                // 可以在这里做重试或告警
            }
        });
    }
    
    /**
     * 异步发送带超时的消息
     */
    public void asyncSendWithTimeout(OrderMessage orderMessage, long timeout) {
        String destination = ORDER_TOPIC;
        
        rocketMQTemplate.asyncSend(destination, orderMessage, new SendCallback() {
            @Override
            public void onSuccess(SendResult sendResult) {
                log.info("异步发送成功, msgId: {}", sendResult.getMsgId());
            }
            
            @Override
            public void onException(Throwable e) {
                log.error("异步发送失败", e);
            }
        }, timeout);
    }
    
    // ==================== 单向发送 ====================
    
    /**
     * 单向发送（不关心结果）
     */
    public void sendOneWay(OrderMessage orderMessage) {
        String destination = ORDER_TOPIC;
        rocketMQTemplate.sendOneWay(destination, orderMessage);
        log.info("单向发送完成, orderId: {}", orderMessage.getOrderId());
    }
    
    // ==================== 发送原生消息 ====================
    
    /**
     * 发送带自定义属性的消息
     */
    public SendResult sendWithProperties(OrderMessage orderMessage) {
        Message<OrderMessage> message = MessageBuilder
            .withPayload(orderMessage)
            .setHeader("orderId", orderMessage.getOrderId())
            .setHeader("userId", orderMessage.getUserId())
            .setHeader("KEYS", orderMessage.getOrderId().toString())  // 消息 Key，用于查询
            .build();
        
        return rocketMQTemplate.syncSend(ORDER_TOPIC, message);
    }
    
    /**
     * 发送 JSON 字符串消息
     */
    public SendResult sendJsonMessage(OrderMessage orderMessage) {
        String json = JSON.toJSONString(orderMessage);
        return rocketMQTemplate.syncSend(ORDER_TOPIC, json);
    }
}
```

### 5.3 发送 Controller

```java
package com.example.controller;

import com.example.dto.OrderMessage;
import com.example.service.MessageProducerService;
import lombok.RequiredArgsConstructor;
import org.apache.rocketmq.client.producer.SendResult;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/mq")
@RequiredArgsConstructor
public class MessageController {
    
    private final MessageProducerService producerService;
    
    /**
     * 同步发送测试
     */
    @PostMapping("/sync")
    public SendResult syncSend(@RequestParam Long orderId) {
        OrderMessage message = OrderMessage.builder()
            .orderId(orderId)
            .userId(1001L)
            .amount(new BigDecimal("99.99"))
            .status("CREATED")
            .createTime(LocalDateTime.now())
            .build();
        
        return producerService.syncSend(message);
    }
    
    /**
     * 异步发送测试
     */
    @PostMapping("/async")
    public String asyncSend(@RequestParam Long orderId) {
        OrderMessage message = OrderMessage.builder()
            .orderId(orderId)
            .userId(1001L)
            .amount(new BigDecimal("99.99"))
            .status("CREATED")
            .createTime(LocalDateTime.now())
            .build();
        
        producerService.asyncSend(message);
        return "消息已提交";
    }
    
    /**
     * 单向发送测试
     */
    @PostMapping("/oneway")
    public String oneWaySend(@RequestParam Long orderId) {
        OrderMessage message = OrderMessage.builder()
            .orderId(orderId)
            .userId(1001L)
            .amount(new BigDecimal("99.99"))
            .status("CREATED")
            .createTime(LocalDateTime.now())
            .build();
        
        producerService.sendOneWay(message);
        return "消息已发送";
    }
}
```


---

## 6. 消息消费

### 6.1 消费者监听器

```java
package com.example.consumer;

import com.example.dto.OrderMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 订单消息消费者
 * 
 * @RocketMQMessageListener 注解参数说明：
 * - topic: 订阅的主题
 * - consumerGroup: 消费者组名称
 * - selectorType: 过滤类型（TAG/SQL92）
 * - selectorExpression: 过滤表达式
 * - consumeMode: 消费模式（CONCURRENTLY/ORDERLY）
 * - messageModel: 消息模型（CLUSTERING/BROADCASTING）
 * - consumeThreadNumber: 消费线程数
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-consumer-group"
)
public class OrderMessageConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到订单消息: orderId={}, status={}", 
            message.getOrderId(), message.getStatus());
        
        try {
            // 处理业务逻辑
            processOrder(message);
            log.info("订单处理成功: {}", message.getOrderId());
            
        } catch (Exception e) {
            log.error("订单处理失败: {}", message.getOrderId(), e);
            // 抛出异常会触发重试
            throw new RuntimeException("订单处理失败", e);
        }
    }
    
    private void processOrder(OrderMessage message) {
        // 模拟业务处理
        // 1. 更新订单状态
        // 2. 发送通知
        // 3. 记录日志
    }
}
```

### 6.2 消费带 Tag 的消息

```java
package com.example.consumer;

import com.example.dto.OrderMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.annotation.SelectorType;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 只消费特定 Tag 的消息
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-pay-consumer-group",
    selectorType = SelectorType.TAG,
    selectorExpression = "PAY || REFUND"  // 只消费 PAY 和 REFUND 标签的消息
)
public class OrderPayConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到支付相关消息: orderId={}, status={}", 
            message.getOrderId(), message.getStatus());
        // 处理支付相关逻辑
    }
}
```

### 6.3 消费原生消息

```java
package com.example.consumer;

import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.common.message.MessageExt;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 消费原生消息（可以获取更多消息属性）
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-raw-consumer-group"
)
public class OrderRawConsumer implements RocketMQListener<MessageExt> {
    
    @Override
    public void onMessage(MessageExt messageExt) {
        // 获取消息属性
        String msgId = messageExt.getMsgId();
        String topic = messageExt.getTopic();
        String tags = messageExt.getTags();
        String keys = messageExt.getKeys();
        int reconsumeTimes = messageExt.getReconsumeTimes();  // 重试次数
        long bornTimestamp = messageExt.getBornTimestamp();   // 消息产生时间
        
        // 获取消息体
        String body = new String(messageExt.getBody());
        
        log.info("收到原生消息: msgId={}, topic={}, tags={}, keys={}, 重试次数={}", 
            msgId, topic, tags, keys, reconsumeTimes);
        log.info("消息内容: {}", body);
        
        // 根据重试次数做不同处理
        if (reconsumeTimes > 3) {
            log.warn("消息重试次数过多，进入人工处理: {}", msgId);
            // 保存到数据库，人工处理
            return;
        }
        
        // 处理业务逻辑
    }
}
```

### 6.4 批量消费

```java
package com.example.consumer;

import com.example.dto.OrderMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 批量消费消息
 * 注意：需要配置 consumeMessageBatchMaxSize
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "BATCH_TOPIC",
    consumerGroup = "batch-consumer-group",
    consumeMessageBatchMaxSize = 10  // 每次最多消费 10 条
)
public class BatchMessageConsumer implements RocketMQListener<List<OrderMessage>> {
    
    @Override
    public void onMessage(List<OrderMessage> messages) {
        log.info("批量收到 {} 条消息", messages.size());
        
        for (OrderMessage message : messages) {
            try {
                processMessage(message);
            } catch (Exception e) {
                log.error("处理消息失败: {}", message.getOrderId(), e);
            }
        }
    }
    
    private void processMessage(OrderMessage message) {
        // 处理单条消息
    }
}
```

---

## 7. 顺序消息

### 7.1 顺序消息概念

顺序消息保证同一业务的消息按发送顺序消费。例如：订单的创建、支付、发货消息必须按顺序处理。

```
普通消息：
Producer ──> Queue-0 ──> Consumer-1
         ──> Queue-1 ──> Consumer-2
         ──> Queue-2 ──> Consumer-3
（消息可能被不同消费者并行消费，顺序无法保证）

顺序消息：
Producer ──> Queue-0 ──> Consumer-1  （同一订单的消息发到同一队列）
         ──> Queue-1 ──> Consumer-2
         ──> Queue-2 ──> Consumer-3
（同一队列的消息由同一消费者顺序消费）
```

### 7.2 发送顺序消息

```java
package com.example.service;

import com.example.dto.OrderMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrderlyMessageService {
    
    private final RocketMQTemplate rocketMQTemplate;
    
    private static final String ORDERLY_TOPIC = "ORDERLY_ORDER_TOPIC";
    
    /**
     * 发送顺序消息
     * 
     * @param orderMessage 订单消息
     * @param hashKey 用于选择队列的 key（通常是订单ID）
     */
    public SendResult sendOrderlyMessage(OrderMessage orderMessage, String hashKey) {
        Message<OrderMessage> message = MessageBuilder
            .withPayload(orderMessage)
            .build();
        
        // syncSendOrderly 会根据 hashKey 选择队列
        // 相同 hashKey 的消息会发送到同一个队列
        SendResult result = rocketMQTemplate.syncSendOrderly(
            ORDERLY_TOPIC, 
            message, 
            hashKey  // 通常使用订单ID
        );
        
        log.info("顺序消息发送成功, orderId: {}, queue: {}", 
            orderMessage.getOrderId(), result.getMessageQueue().getQueueId());
        
        return result;
    }
    
    /**
     * 模拟订单流程：创建 -> 支付 -> 发货
     */
    public void sendOrderFlow(Long orderId) {
        String hashKey = orderId.toString();
        
        // 1. 订单创建
        OrderMessage createMsg = OrderMessage.builder()
            .orderId(orderId)
            .status("CREATED")
            .build();
        sendOrderlyMessage(createMsg, hashKey);
        
        // 2. 订单支付
        OrderMessage payMsg = OrderMessage.builder()
            .orderId(orderId)
            .status("PAID")
            .build();
        sendOrderlyMessage(payMsg, hashKey);
        
        // 3. 订单发货
        OrderMessage shipMsg = OrderMessage.builder()
            .orderId(orderId)
            .status("SHIPPED")
            .build();
        sendOrderlyMessage(shipMsg, hashKey);
        
        log.info("订单流程消息发送完成: {}", orderId);
    }
}
```

### 7.3 消费顺序消息

```java
package com.example.consumer;

import com.example.dto.OrderMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.ConsumeMode;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 顺序消息消费者
 * 
 * consumeMode = ConsumeMode.ORDERLY 表示顺序消费
 * 同一队列的消息会被同一个线程顺序消费
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDERLY_ORDER_TOPIC",
    consumerGroup = "orderly-consumer-group",
    consumeMode = ConsumeMode.ORDERLY  // 关键：顺序消费模式
)
public class OrderlyMessageConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("顺序消费: orderId={}, status={}, thread={}", 
            message.getOrderId(), 
            message.getStatus(),
            Thread.currentThread().getName());
        
        // 模拟处理时间
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // 处理业务逻辑
        switch (message.getStatus()) {
            case "CREATED":
                handleOrderCreated(message);
                break;
            case "PAID":
                handleOrderPaid(message);
                break;
            case "SHIPPED":
                handleOrderShipped(message);
                break;
            default:
                log.warn("未知状态: {}", message.getStatus());
        }
    }
    
    private void handleOrderCreated(OrderMessage message) {
        log.info("处理订单创建: {}", message.getOrderId());
    }
    
    private void handleOrderPaid(OrderMessage message) {
        log.info("处理订单支付: {}", message.getOrderId());
    }
    
    private void handleOrderShipped(OrderMessage message) {
        log.info("处理订单发货: {}", message.getOrderId());
    }
}
```


---

## 8. 延迟消息

### 8.1 延迟消息概念

延迟消息是指消息发送后，不会立即被消费，而是等待指定时间后才能被消费。

**应用场景**：
- 订单超时取消（30分钟未支付自动取消）
- 定时提醒（会议开始前15分钟提醒）
- 延迟重试（失败后延迟重试）

### 8.2 RocketMQ 延迟级别

RocketMQ 开源版本支持 18 个延迟级别：

```
延迟级别对照表：
Level 1  = 1s      Level 7  = 3m      Level 13 = 9m
Level 2  = 5s      Level 8  = 4m      Level 14 = 10m
Level 3  = 10s     Level 9  = 5m      Level 15 = 20m
Level 4  = 30s     Level 10 = 6m      Level 16 = 30m
Level 5  = 1m      Level 11 = 7m      Level 17 = 1h
Level 6  = 2m      Level 12 = 8m      Level 18 = 2h
```

### 8.3 发送延迟消息

```java
package com.example.service;

import com.example.dto.OrderMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class DelayMessageService {
    
    private final RocketMQTemplate rocketMQTemplate;
    
    private static final String DELAY_TOPIC = "DELAY_ORDER_TOPIC";
    
    /**
     * 发送延迟消息
     * 
     * @param orderMessage 消息内容
     * @param delayLevel 延迟级别（1-18）
     */
    public SendResult sendDelayMessage(OrderMessage orderMessage, int delayLevel) {
        Message<OrderMessage> message = MessageBuilder
            .withPayload(orderMessage)
            .build();
        
        // 第三个参数是超时时间，第四个参数是延迟级别
        SendResult result = rocketMQTemplate.syncSend(
            DELAY_TOPIC, 
            message, 
            3000,       // 发送超时时间
            delayLevel  // 延迟级别
        );
        
        log.info("延迟消息发送成功, orderId: {}, delayLevel: {}, msgId: {}", 
            orderMessage.getOrderId(), delayLevel, result.getMsgId());
        
        return result;
    }
    
    /**
     * 发送订单超时取消消息（30分钟后）
     * 延迟级别 16 = 30分钟
     */
    public SendResult sendOrderTimeoutMessage(Long orderId) {
        OrderMessage message = OrderMessage.builder()
            .orderId(orderId)
            .status("TIMEOUT_CHECK")
            .build();
        
        return sendDelayMessage(message, 16);  // 30分钟后消费
    }
    
    /**
     * 发送支付提醒消息（5分钟后）
     * 延迟级别 9 = 5分钟
     */
    public SendResult sendPaymentReminder(Long orderId) {
        OrderMessage message = OrderMessage.builder()
            .orderId(orderId)
            .status("PAYMENT_REMINDER")
            .build();
        
        return sendDelayMessage(message, 9);  // 5分钟后消费
    }
    
    /**
     * 发送延迟重试消息
     */
    public SendResult sendDelayRetry(OrderMessage orderMessage, int retryCount) {
        // 根据重试次数选择延迟级别
        int delayLevel = Math.min(retryCount + 3, 18);  // 从 10s 开始，逐渐增加
        return sendDelayMessage(orderMessage, delayLevel);
    }
}
```

### 8.4 消费延迟消息

```java
package com.example.consumer;

import com.example.dto.OrderMessage;
import com.example.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 延迟消息消费者
 */
@Slf4j
@Component
@RequiredArgsConstructor
@RocketMQMessageListener(
    topic = "DELAY_ORDER_TOPIC",
    consumerGroup = "delay-order-consumer-group"
)
public class DelayOrderConsumer implements RocketMQListener<OrderMessage> {
    
    private final OrderService orderService;
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到延迟消息: orderId={}, status={}", 
            message.getOrderId(), message.getStatus());
        
        switch (message.getStatus()) {
            case "TIMEOUT_CHECK":
                handleTimeoutCheck(message);
                break;
            case "PAYMENT_REMINDER":
                handlePaymentReminder(message);
                break;
            default:
                log.warn("未知的延迟消息类型: {}", message.getStatus());
        }
    }
    
    /**
     * 处理订单超时检查
     */
    private void handleTimeoutCheck(OrderMessage message) {
        Long orderId = message.getOrderId();
        
        // 查询订单当前状态
        String currentStatus = orderService.getOrderStatus(orderId);
        
        if ("CREATED".equals(currentStatus)) {
            // 订单仍未支付，执行取消
            log.info("订单超时未支付，自动取消: {}", orderId);
            orderService.cancelOrder(orderId, "超时未支付");
        } else {
            log.info("订单已支付或已取消，无需处理: {}, status: {}", orderId, currentStatus);
        }
    }
    
    /**
     * 处理支付提醒
     */
    private void handlePaymentReminder(OrderMessage message) {
        Long orderId = message.getOrderId();
        
        String currentStatus = orderService.getOrderStatus(orderId);
        
        if ("CREATED".equals(currentStatus)) {
            // 订单仍未支付，发送提醒
            log.info("发送支付提醒: {}", orderId);
            // notificationService.sendPaymentReminder(orderId);
        }
    }
}
```

### 8.5 任意延迟时间（RocketMQ 5.x）

RocketMQ 5.x 支持任意延迟时间：

```java
/**
 * 发送任意延迟时间的消息（RocketMQ 5.x）
 */
public SendResult sendDelayMessageWithTime(OrderMessage orderMessage, long delayMs) {
    Message<OrderMessage> message = MessageBuilder
        .withPayload(orderMessage)
        // 设置延迟时间（毫秒）
        .setHeader("TIMER_DELAY_MS", delayMs)
        .build();
    
    return rocketMQTemplate.syncSend(DELAY_TOPIC, message);
}

// 使用示例：延迟 45 分钟
sendDelayMessageWithTime(orderMessage, 45 * 60 * 1000);
```

---

## 9. 事务消息

### 9.1 事务消息概念

事务消息用于解决分布式事务问题，保证本地事务和消息发送的原子性。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        事务消息流程                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Producer                    Broker                    Consumer             │
│     │                          │                          │                 │
│     │  1. 发送半消息(Half)      │                          │                 │
│     │ ─────────────────────>   │                          │                 │
│     │                          │                          │                 │
│     │  2. 返回发送结果          │                          │                 │
│     │ <─────────────────────   │                          │                 │
│     │                          │                          │                 │
│     │  3. 执行本地事务          │                          │                 │
│     │  ┌─────────────┐         │                          │                 │
│     │  │ 本地事务    │         │                          │                 │
│     │  └─────────────┘         │                          │                 │
│     │                          │                          │                 │
│     │  4. 提交/回滚             │                          │                 │
│     │ ─────────────────────>   │                          │                 │
│     │                          │                          │                 │
│     │                          │  5. 投递消息（如果提交）   │                 │
│     │                          │ ─────────────────────>   │                 │
│     │                          │                          │                 │
│     │  6. 回查（如果未收到确认）│                          │                 │
│     │ <─────────────────────   │                          │                 │
│     │                          │                          │                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.2 事务消息生产者

```java
package com.example.service;

import com.alibaba.fastjson2.JSON;
import com.example.dto.OrderMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.client.producer.TransactionSendResult;
import org.apache.rocketmq.spring.core.RocketMQTemplate;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class TransactionMessageService {
    
    private final RocketMQTemplate rocketMQTemplate;
    
    private static final String TX_TOPIC = "TX_ORDER_TOPIC";
    
    /**
     * 发送事务消息
     */
    public TransactionSendResult sendTransactionMessage(OrderMessage orderMessage) {
        Message<OrderMessage> message = MessageBuilder
            .withPayload(orderMessage)
            .setHeader("orderId", orderMessage.getOrderId())
            .build();
        
        // 发送事务消息
        // 第三个参数是传递给本地事务执行器的参数
        TransactionSendResult result = rocketMQTemplate.sendMessageInTransaction(
            TX_TOPIC,
            message,
            orderMessage  // 传递给事务监听器
        );
        
        log.info("事务消息发送结果: orderId={}, state={}", 
            orderMessage.getOrderId(), result.getLocalTransactionState());
        
        return result;
    }
}
```

### 9.3 事务监听器

```java
package com.example.listener;

import com.example.dto.OrderMessage;
import com.example.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.RocketMQTransactionListener;
import org.apache.rocketmq.spring.core.RocketMQLocalTransactionListener;
import org.apache.rocketmq.spring.core.RocketMQLocalTransactionState;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Component;

/**
 * 事务消息监听器
 * 
 * 负责执行本地事务和事务回查
 */
@Slf4j
@Component
@RequiredArgsConstructor
@RocketMQTransactionListener
public class OrderTransactionListener implements RocketMQLocalTransactionListener {
    
    private final OrderService orderService;
    
    /**
     * 执行本地事务
     * 
     * 在发送半消息成功后调用
     * 
     * @return COMMIT - 提交事务，消息可被消费
     *         ROLLBACK - 回滚事务，消息被删除
     *         UNKNOWN - 未知状态，等待回查
     */
    @Override
    public RocketMQLocalTransactionState executeLocalTransaction(Message msg, Object arg) {
        OrderMessage orderMessage = (OrderMessage) arg;
        Long orderId = orderMessage.getOrderId();
        
        log.info("执行本地事务: orderId={}", orderId);
        
        try {
            // 执行本地事务（如：创建订单、扣减库存等）
            boolean success = orderService.createOrderWithTransaction(orderMessage);
            
            if (success) {
                log.info("本地事务执行成功，提交消息: {}", orderId);
                return RocketMQLocalTransactionState.COMMIT;
            } else {
                log.warn("本地事务执行失败，回滚消息: {}", orderId);
                return RocketMQLocalTransactionState.ROLLBACK;
            }
            
        } catch (Exception e) {
            log.error("本地事务执行异常: {}", orderId, e);
            // 返回 UNKNOWN，等待回查
            return RocketMQLocalTransactionState.UNKNOWN;
        }
    }
    
    /**
     * 事务回查
     * 
     * 当 Broker 长时间未收到事务确认时调用
     * 需要检查本地事务的执行结果
     */
    @Override
    public RocketMQLocalTransactionState checkLocalTransaction(Message msg) {
        // 从消息头获取订单ID
        String orderIdStr = (String) msg.getHeaders().get("orderId");
        Long orderId = Long.parseLong(orderIdStr);
        
        log.info("事务回查: orderId={}", orderId);
        
        try {
            // 查询本地事务执行结果
            boolean exists = orderService.checkOrderExists(orderId);
            
            if (exists) {
                log.info("事务回查：订单存在，提交消息: {}", orderId);
                return RocketMQLocalTransactionState.COMMIT;
            } else {
                log.info("事务回查：订单不存在，回滚消息: {}", orderId);
                return RocketMQLocalTransactionState.ROLLBACK;
            }
            
        } catch (Exception e) {
            log.error("事务回查异常: {}", orderId, e);
            return RocketMQLocalTransactionState.UNKNOWN;
        }
    }
}
```

### 9.4 事务消息消费者

```java
package com.example.consumer;

import com.example.dto.OrderMessage;
import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 事务消息消费者
 * 
 * 只有事务提交后，消息才会被投递到这里
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "TX_ORDER_TOPIC",
    consumerGroup = "tx-order-consumer-group"
)
public class TransactionOrderConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到事务消息: orderId={}, status={}", 
            message.getOrderId(), message.getStatus());
        
        // 处理后续业务
        // 例如：发送通知、同步数据等
    }
}
```


---

## 10. 消息过滤

### 10.1 Tag 过滤

```java
// 生产者：发送带 Tag 的消息
public SendResult sendWithTag(OrderMessage message, String tag) {
    String destination = "ORDER_TOPIC:" + tag;  // Topic:Tag 格式
    return rocketMQTemplate.syncSend(destination, message);
}

// 发送不同 Tag 的消息
sendWithTag(message, "CREATE");   // 创建订单
sendWithTag(message, "PAY");      // 支付订单
sendWithTag(message, "CANCEL");   // 取消订单
```

```java
// 消费者：只消费特定 Tag
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-pay-group",
    selectorType = SelectorType.TAG,
    selectorExpression = "PAY || REFUND"  // 只消费 PAY 和 REFUND
)
public class PayOrderConsumer implements RocketMQListener<OrderMessage> {
    // ...
}

// 消费所有 Tag
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-all-group",
    selectorExpression = "*"  // 消费所有 Tag
)
public class AllOrderConsumer implements RocketMQListener<OrderMessage> {
    // ...
}
```

### 10.2 SQL92 过滤

SQL92 过滤支持更复杂的过滤条件，需要在 Broker 配置中开启：

```properties
# broker.conf
enablePropertyFilter=true
```

```java
// 生产者：发送带属性的消息
public SendResult sendWithProperties(OrderMessage message) {
    Message<OrderMessage> msg = MessageBuilder
        .withPayload(message)
        .setHeader("amount", message.getAmount().doubleValue())
        .setHeader("status", message.getStatus())
        .setHeader("userId", message.getUserId())
        .build();
    
    return rocketMQTemplate.syncSend("ORDER_TOPIC", msg);
}
```

```java
// 消费者：使用 SQL92 过滤
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-vip-group",
    selectorType = SelectorType.SQL92,
    selectorExpression = "amount > 1000 AND status = 'PAID'"  // SQL 表达式
)
public class VipOrderConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("收到大额已支付订单: orderId={}, amount={}", 
            message.getOrderId(), message.getAmount());
    }
}

// 更复杂的 SQL 过滤
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-filter-group",
    selectorType = SelectorType.SQL92,
    selectorExpression = "(status = 'PAID' OR status = 'SHIPPED') AND userId BETWEEN 1000 AND 2000"
)
public class FilteredOrderConsumer implements RocketMQListener<OrderMessage> {
    // ...
}
```

---

## 11. 消息重试与死信队列

### 11.1 消费重试机制

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        消费重试机制                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  消费失败后，RocketMQ 会自动重试，重试间隔逐渐增加：                          │
│                                                                             │
│  第 1 次重试：10s 后                                                        │
│  第 2 次重试：30s 后                                                        │
│  第 3 次重试：1m 后                                                         │
│  第 4 次重试：2m 后                                                         │
│  第 5 次重试：3m 后                                                         │
│  ...                                                                        │
│  第 16 次重试：2h 后                                                        │
│                                                                             │
│  默认最多重试 16 次，超过后进入死信队列                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 自定义重试次数

```java
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-consumer-group",
    maxReconsumeTimes = 5  // 最大重试 5 次
)
public class OrderConsumerWithRetry implements RocketMQListener<MessageExt> {
    
    @Override
    public void onMessage(MessageExt messageExt) {
        int reconsumeTimes = messageExt.getReconsumeTimes();
        String msgId = messageExt.getMsgId();
        
        log.info("消费消息: msgId={}, 重试次数={}", msgId, reconsumeTimes);
        
        try {
            // 处理业务逻辑
            processMessage(messageExt);
            
        } catch (Exception e) {
            log.error("消息处理失败: msgId={}, 重试次数={}", msgId, reconsumeTimes, e);
            
            // 根据重试次数决定处理方式
            if (reconsumeTimes >= 3) {
                // 重试多次仍失败，保存到数据库人工处理
                saveToFailedTable(messageExt, e);
                return;  // 不再抛异常，避免继续重试
            }
            
            // 抛出异常触发重试
            throw new RuntimeException("消息处理失败，等待重试", e);
        }
    }
    
    private void processMessage(MessageExt messageExt) {
        // 业务处理
    }
    
    private void saveToFailedTable(MessageExt messageExt, Exception e) {
        // 保存失败消息到数据库
        log.warn("消息多次重试失败，保存到失败表: {}", messageExt.getMsgId());
    }
}
```

### 11.3 死信队列处理

```java
package com.example.consumer;

import lombok.extern.slf4j.Slf4j;
import org.apache.rocketmq.common.message.MessageExt;
import org.apache.rocketmq.spring.annotation.RocketMQMessageListener;
import org.apache.rocketmq.spring.core.RocketMQListener;
import org.springframework.stereotype.Component;

/**
 * 死信队列消费者
 * 
 * 死信队列 Topic 格式：%DLQ%ConsumerGroup
 */
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "%DLQ%order-consumer-group",  // 死信队列 Topic
    consumerGroup = "dlq-consumer-group"
)
public class DeadLetterConsumer implements RocketMQListener<MessageExt> {
    
    @Override
    public void onMessage(MessageExt messageExt) {
        log.warn("收到死信消息: msgId={}, topic={}, reconsumeTimes={}", 
            messageExt.getMsgId(),
            messageExt.getTopic(),
            messageExt.getReconsumeTimes());
        
        String body = new String(messageExt.getBody());
        log.warn("死信消息内容: {}", body);
        
        // 处理死信消息
        // 1. 保存到数据库
        // 2. 发送告警通知
        // 3. 人工处理
        handleDeadLetter(messageExt);
    }
    
    private void handleDeadLetter(MessageExt messageExt) {
        // 保存到数据库
        // deadLetterRepository.save(...)
        
        // 发送告警
        // alertService.sendAlert("死信消息告警", messageExt.getMsgId());
        
        log.info("死信消息已处理: {}", messageExt.getMsgId());
    }
}
```

---

## 12. 集群消费与广播消费

### 12.1 消费模式对比

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        消费模式对比                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  集群消费（CLUSTERING）- 默认模式                                            │
│  ┌─────────┐                                                                │
│  │ Message │ ──> Consumer-1 ✓                                               │
│  └─────────┘     Consumer-2 ✗  （同一消息只被一个消费者消费）                 │
│                  Consumer-3 ✗                                               │
│                                                                             │
│  适用场景：订单处理、业务逻辑处理                                            │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  广播消费（BROADCASTING）                                                    │
│  ┌─────────┐                                                                │
│  │ Message │ ──> Consumer-1 ✓                                               │
│  └─────────┘     Consumer-2 ✓  （同一消息被所有消费者消费）                   │
│                  Consumer-3 ✓                                               │
│                                                                             │
│  适用场景：缓存刷新、配置更新                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.2 集群消费

```java
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-cluster-group",
    messageModel = MessageModel.CLUSTERING  // 集群消费（默认）
)
public class ClusterConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("集群消费: orderId={}, consumer={}", 
            message.getOrderId(), 
            System.getProperty("server.port"));
    }
}
```

### 12.3 广播消费

```java
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "CACHE_REFRESH_TOPIC",
    consumerGroup = "cache-broadcast-group",
    messageModel = MessageModel.BROADCASTING  // 广播消费
)
public class BroadcastConsumer implements RocketMQListener<String> {
    
    @Autowired
    private CacheManager cacheManager;
    
    @Override
    public void onMessage(String cacheKey) {
        log.info("收到缓存刷新广播: key={}", cacheKey);
        
        // 所有实例都会收到这条消息，刷新本地缓存
        cacheManager.evict(cacheKey);
        
        log.info("本地缓存已刷新: {}", cacheKey);
    }
}
```

### 12.4 广播消息发送

```java
@Service
@RequiredArgsConstructor
public class CacheRefreshService {
    
    private final RocketMQTemplate rocketMQTemplate;
    
    /**
     * 发送缓存刷新广播
     */
    public void broadcastCacheRefresh(String cacheKey) {
        rocketMQTemplate.syncSend("CACHE_REFRESH_TOPIC", cacheKey);
        log.info("缓存刷新广播已发送: {}", cacheKey);
    }
    
    /**
     * 发送配置更新广播
     */
    public void broadcastConfigUpdate(String configKey, String configValue) {
        Map<String, String> config = Map.of("key", configKey, "value", configValue);
        rocketMQTemplate.syncSend("CONFIG_UPDATE_TOPIC", config);
        log.info("配置更新广播已发送: {}={}", configKey, configValue);
    }
}
```


---

## 13. 消息轨迹

### 13.1 开启消息轨迹

```yaml
# application.yml
rocketmq:
  name-server: localhost:9876
  producer:
    group: my-producer-group
    enable-msg-trace: true  # 开启生产者消息轨迹
    customized-trace-topic: RMQ_SYS_TRACE_TOPIC  # 轨迹 Topic
  consumer:
    group: my-consumer-group
    enable-msg-trace: true  # 开启消费者消息轨迹
```

### 13.2 消费者开启轨迹

```java
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-trace-group",
    enableMsgTrace = true,  // 开启消息轨迹
    customizedTraceTopic = "RMQ_SYS_TRACE_TOPIC"
)
public class TraceOrderConsumer implements RocketMQListener<OrderMessage> {
    
    @Override
    public void onMessage(OrderMessage message) {
        log.info("消费消息: {}", message.getOrderId());
    }
}
```

### 13.3 查询消息轨迹

通过 RocketMQ Dashboard 可以查询消息轨迹：
1. 访问控制台
2. 进入"消息"页面
3. 输入 Message ID 或 Message Key 查询
4. 查看消息的发送、存储、消费轨迹

---

## 14. 生产环境配置

### 14.1 生产者配置

```yaml
# application-prod.yml
rocketmq:
  name-server: ${ROCKETMQ_NAMESRV:rocketmq-namesrv:9876}
  producer:
    group: ${spring.application.name}-producer
    # 发送超时时间
    send-message-timeout: 3000
    # 消息体最大值（默认 4MB）
    max-message-size: 4194304
    # 同步发送失败重试次数
    retry-times-when-send-failed: 2
    # 异步发送失败重试次数
    retry-times-when-send-async-failed: 2
    # 发送失败时是否重试其他 Broker
    retry-next-server: true
    # 开启消息轨迹
    enable-msg-trace: true
```

### 14.2 消费者配置

```yaml
rocketmq:
  consumer:
    group: ${spring.application.name}-consumer
    # 消费线程数
    consume-thread-min: 20
    consume-thread-max: 64
    # 每次拉取消息数量
    pull-batch-size: 32
    # 消费超时时间（分钟）
    consume-timeout: 15
```

### 14.3 高可用配置

```java
@Configuration
public class RocketMQProducerConfig {
    
    @Bean
    public RocketMQTemplate rocketMQTemplate(
            RocketMQProperties properties,
            ObjectMapper objectMapper) {
        
        RocketMQTemplate template = new RocketMQTemplate();
        
        // 配置生产者
        DefaultMQProducer producer = new DefaultMQProducer(properties.getProducer().getGroup());
        producer.setNamesrvAddr(properties.getNameServer());
        producer.setSendMsgTimeout(properties.getProducer().getSendMessageTimeout());
        producer.setRetryTimesWhenSendFailed(properties.getProducer().getRetryTimesWhenSendFailed());
        producer.setRetryTimesWhenSendAsyncFailed(properties.getProducer().getRetryTimesWhenSendAsyncFailed());
        
        // 设置 VIP 通道（生产环境建议关闭）
        producer.setVipChannelEnabled(false);
        
        template.setProducer(producer);
        template.setObjectMapper(objectMapper);
        
        return template;
    }
}
```

### 14.4 监控告警

```java
@Component
@Slf4j
public class RocketMQHealthIndicator implements HealthIndicator {
    
    @Autowired
    private RocketMQTemplate rocketMQTemplate;
    
    @Override
    public Health health() {
        try {
            // 检查生产者状态
            DefaultMQProducer producer = rocketMQTemplate.getProducer();
            if (producer == null) {
                return Health.down().withDetail("error", "Producer is null").build();
            }
            
            // 尝试发送测试消息
            SendResult result = rocketMQTemplate.syncSend(
                "HEALTH_CHECK_TOPIC", 
                "health-check-" + System.currentTimeMillis(),
                1000
            );
            
            if (result.getSendStatus() == SendStatus.SEND_OK) {
                return Health.up()
                    .withDetail("nameServer", producer.getNamesrvAddr())
                    .withDetail("producerGroup", producer.getProducerGroup())
                    .build();
            } else {
                return Health.down()
                    .withDetail("sendStatus", result.getSendStatus())
                    .build();
            }
            
        } catch (Exception e) {
            log.error("RocketMQ health check failed", e);
            return Health.down()
                .withDetail("error", e.getMessage())
                .build();
        }
    }
}
```

---

## 15. 常见错误与解决方案

### 15.1 连接错误

#### 错误1：No route info of this topic

```
MQClientException: No route info of this topic: ORDER_TOPIC
```

**原因**：Topic 不存在或 NameServer 连接失败

**解决方案**：
```bash
# 1. 检查 NameServer 是否启动
docker ps | grep namesrv

# 2. 检查 Broker 是否注册到 NameServer
docker logs rmqbroker

# 3. 手动创建 Topic
docker exec -it rmqbroker sh mqadmin updateTopic -n namesrv:9876 -b broker:10911 -t ORDER_TOPIC

# 4. 或者开启自动创建 Topic（不推荐生产环境）
# broker.conf
autoCreateTopicEnable=true
```

#### 错误2：connect to broker failed

```
RemotingConnectException: connect to <broker:10911> failed
```

**原因**：Broker 地址不可达

**解决方案**：
```bash
# 1. 检查网络连通性
telnet broker-ip 10911

# 2. 检查 Broker 配置
# broker.conf
brokerIP1=实际IP地址  # 不要用 localhost

# 3. Docker 环境需要配置正确的 IP
docker run -e "BROKER_IP=宿主机IP" ...
```

### 15.2 发送错误

#### 错误3：Message body size over max value

```
MQClientException: Message body size over max value, MAX: 4194304
```

**原因**：消息体超过 4MB 限制

**解决方案**：
```java
// 1. 增加消息大小限制
producer.setMaxMessageSize(10 * 1024 * 1024);  // 10MB

// 2. 或者压缩消息
String compressed = compress(largeMessage);
rocketMQTemplate.syncSend(topic, compressed);

// 3. 或者分片发送
List<String> chunks = splitMessage(largeMessage);
for (String chunk : chunks) {
    rocketMQTemplate.syncSend(topic, chunk);
}
```

#### 错误4：SLAVE_NOT_AVAILABLE

```
SendResult: SLAVE_NOT_AVAILABLE
```

**原因**：同步刷盘模式下从节点不可用

**解决方案**：
```properties
# broker.conf
# 改为异步刷盘（性能更好，但可能丢消息）
flushDiskType=ASYNC_FLUSH

# 或者确保从节点正常运行
```

### 15.3 消费错误

#### 错误5：消费者启动失败

```
The consumer group has been created before, specify another name please
```

**原因**：消费者组已存在且配置不同

**解决方案**：
```java
// 1. 使用不同的消费者组名
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-consumer-group-v2"  // 修改组名
)

// 2. 或者删除旧的消费者组
// 通过控制台删除
```

#### 错误6：消息堆积

**原因**：消费速度跟不上生产速度

**解决方案**：
```java
// 1. 增加消费线程数
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-consumer-group",
    consumeThreadNumber = 64  // 增加线程数
)

// 2. 增加消费者实例数量

// 3. 优化消费逻辑，减少处理时间

// 4. 批量消费
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-consumer-group",
    consumeMessageBatchMaxSize = 10  // 批量消费
)
```

### 15.4 事务消息错误

#### 错误7：事务回查失败

**原因**：回查逻辑异常或数据库查询失败

**解决方案**：
```java
@Override
public RocketMQLocalTransactionState checkLocalTransaction(Message msg) {
    try {
        // 确保回查逻辑健壮
        String orderId = (String) msg.getHeaders().get("orderId");
        if (orderId == null) {
            log.error("回查失败：orderId 为空");
            return RocketMQLocalTransactionState.ROLLBACK;
        }
        
        boolean exists = orderService.checkOrderExists(Long.parseLong(orderId));
        return exists ? 
            RocketMQLocalTransactionState.COMMIT : 
            RocketMQLocalTransactionState.ROLLBACK;
            
    } catch (Exception e) {
        log.error("事务回查异常", e);
        // 返回 UNKNOWN，等待下次回查
        return RocketMQLocalTransactionState.UNKNOWN;
    }
}
```


---

## 16. 最佳实践

### 16.1 消息设计最佳实践

```java
/**
 * 消息设计最佳实践
 */
public class MessageDesignBestPractice {
    
    // 1. Topic 命名规范
    // 格式：{业务域}_{消息类型}_{环境}
    // 例如：ORDER_CREATE_PROD, USER_REGISTER_DEV
    
    // 2. Tag 命名规范
    // 格式：{操作类型}
    // 例如：CREATE, UPDATE, DELETE, PAY, REFUND
    
    // 3. Key 设置（用于消息查询）
    public SendResult sendWithKey(OrderMessage message) {
        Message<OrderMessage> msg = MessageBuilder
            .withPayload(message)
            .setHeader("KEYS", message.getOrderId().toString())  // 设置 Key
            .build();
        return rocketMQTemplate.syncSend("ORDER_TOPIC", msg);
    }
    
    // 4. 消息体设计
    @Data
    public class StandardMessage<T> {
        private String messageId;      // 消息唯一ID
        private String traceId;        // 链路追踪ID
        private Long timestamp;        // 消息时间戳
        private String source;         // 消息来源
        private T data;                // 业务数据
    }
}
```

### 16.2 生产者最佳实践

```java
@Service
@Slf4j
public class ProducerBestPractice {
    
    @Autowired
    private RocketMQTemplate rocketMQTemplate;
    
    /**
     * 1. 同步发送 + 结果检查
     */
    public void sendWithCheck(OrderMessage message) {
        SendResult result = rocketMQTemplate.syncSend("ORDER_TOPIC", message);
        
        // 检查发送结果
        if (result.getSendStatus() != SendStatus.SEND_OK) {
            log.error("消息发送失败: status={}, msgId={}", 
                result.getSendStatus(), result.getMsgId());
            // 可以保存到数据库，后续重试
            throw new RuntimeException("消息发送失败");
        }
        
        log.info("消息发送成功: msgId={}", result.getMsgId());
    }
    
    /**
     * 2. 异步发送 + 回调处理
     */
    public void sendAsync(OrderMessage message) {
        rocketMQTemplate.asyncSend("ORDER_TOPIC", message, new SendCallback() {
            @Override
            public void onSuccess(SendResult sendResult) {
                log.info("异步发送成功: {}", sendResult.getMsgId());
            }
            
            @Override
            public void onException(Throwable e) {
                log.error("异步发送失败", e);
                // 保存失败消息，后续重试
                saveFailedMessage(message, e);
            }
        });
    }
    
    /**
     * 3. 发送前校验
     */
    public void sendWithValidation(OrderMessage message) {
        // 参数校验
        if (message == null || message.getOrderId() == null) {
            throw new IllegalArgumentException("消息不能为空");
        }
        
        // 幂等性检查（可选）
        if (isDuplicate(message)) {
            log.warn("重复消息，跳过发送: {}", message.getOrderId());
            return;
        }
        
        rocketMQTemplate.syncSend("ORDER_TOPIC", message);
    }
    
    private void saveFailedMessage(OrderMessage message, Throwable e) {
        // 保存到数据库
    }
    
    private boolean isDuplicate(OrderMessage message) {
        // 检查是否重复
        return false;
    }
}
```

### 16.3 消费者最佳实践

```java
@Slf4j
@Component
@RocketMQMessageListener(
    topic = "ORDER_TOPIC",
    consumerGroup = "order-consumer-group",
    consumeThreadNumber = 20,
    maxReconsumeTimes = 3
)
public class ConsumerBestPractice implements RocketMQListener<MessageExt> {
    
    @Autowired
    private OrderService orderService;
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    @Override
    public void onMessage(MessageExt messageExt) {
        String msgId = messageExt.getMsgId();
        String body = new String(messageExt.getBody());
        
        log.info("收到消息: msgId={}, reconsumeTimes={}", 
            msgId, messageExt.getReconsumeTimes());
        
        // 1. 幂等性检查
        if (isProcessed(msgId)) {
            log.info("消息已处理，跳过: {}", msgId);
            return;
        }
        
        try {
            // 2. 解析消息
            OrderMessage message = JSON.parseObject(body, OrderMessage.class);
            
            // 3. 处理业务
            processMessage(message);
            
            // 4. 标记已处理
            markProcessed(msgId);
            
            log.info("消息处理成功: {}", msgId);
            
        } catch (Exception e) {
            log.error("消息处理失败: {}", msgId, e);
            
            // 5. 根据重试次数决定处理方式
            if (messageExt.getReconsumeTimes() >= 3) {
                // 保存到失败表，人工处理
                saveToFailedTable(messageExt, e);
                return;  // 不再重试
            }
            
            // 抛出异常，触发重试
            throw new RuntimeException("消息处理失败", e);
        }
    }
    
    /**
     * 幂等性检查（使用 Redis）
     */
    private boolean isProcessed(String msgId) {
        String key = "mq:processed:" + msgId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
    
    /**
     * 标记消息已处理
     */
    private void markProcessed(String msgId) {
        String key = "mq:processed:" + msgId;
        redisTemplate.opsForValue().set(key, "1", 7, TimeUnit.DAYS);
    }
    
    private void processMessage(OrderMessage message) {
        // 业务处理
        orderService.processOrder(message);
    }
    
    private void saveToFailedTable(MessageExt messageExt, Exception e) {
        // 保存失败消息
        log.warn("消息多次重试失败，保存到失败表: {}", messageExt.getMsgId());
    }
}
```

### 16.4 Topic 和消费者组规划

```
推荐的 Topic 规划：

1. 按业务域划分
   - ORDER_TOPIC      # 订单相关
   - USER_TOPIC       # 用户相关
   - PAYMENT_TOPIC    # 支付相关
   - INVENTORY_TOPIC  # 库存相关

2. 按消息类型划分
   - SYNC_TOPIC       # 同步消息
   - ASYNC_TOPIC      # 异步消息
   - DELAY_TOPIC      # 延迟消息
   - TX_TOPIC         # 事务消息

3. 消费者组命名
   - {服务名}-{topic}-consumer
   - order-service-order-consumer
   - inventory-service-order-consumer
```

### 16.5 监控指标

```java
@Component
@Slf4j
public class RocketMQMetrics {
    
    @Autowired
    private MeterRegistry meterRegistry;
    
    private Counter sendSuccessCounter;
    private Counter sendFailCounter;
    private Counter consumeSuccessCounter;
    private Counter consumeFailCounter;
    private Timer sendTimer;
    
    @PostConstruct
    public void init() {
        sendSuccessCounter = Counter.builder("rocketmq.send.success")
            .description("发送成功数")
            .register(meterRegistry);
            
        sendFailCounter = Counter.builder("rocketmq.send.fail")
            .description("发送失败数")
            .register(meterRegistry);
            
        consumeSuccessCounter = Counter.builder("rocketmq.consume.success")
            .description("消费成功数")
            .register(meterRegistry);
            
        consumeFailCounter = Counter.builder("rocketmq.consume.fail")
            .description("消费失败数")
            .register(meterRegistry);
            
        sendTimer = Timer.builder("rocketmq.send.time")
            .description("发送耗时")
            .register(meterRegistry);
    }
    
    public void recordSendSuccess() {
        sendSuccessCounter.increment();
    }
    
    public void recordSendFail() {
        sendFailCounter.increment();
    }
    
    public void recordConsumeSuccess() {
        consumeSuccessCounter.increment();
    }
    
    public void recordConsumeFail() {
        consumeFailCounter.increment();
    }
    
    public void recordSendTime(long timeMs) {
        sendTimer.record(timeMs, TimeUnit.MILLISECONDS);
    }
}
```

---

## 附录：速查表

### A. 常用注解

| 注解 | 说明 |
|------|------|
| @RocketMQMessageListener | 消息监听器 |
| @RocketMQTransactionListener | 事务监听器 |

### B. 消息发送方式

| 方法 | 说明 |
|------|------|
| syncSend | 同步发送 |
| asyncSend | 异步发送 |
| sendOneWay | 单向发送 |
| syncSendOrderly | 顺序发送 |
| sendMessageInTransaction | 事务发送 |

### C. 延迟级别

| 级别 | 延迟时间 | 级别 | 延迟时间 |
|------|---------|------|---------|
| 1 | 1s | 10 | 6m |
| 2 | 5s | 11 | 7m |
| 3 | 10s | 12 | 8m |
| 4 | 30s | 13 | 9m |
| 5 | 1m | 14 | 10m |
| 6 | 2m | 15 | 20m |
| 7 | 3m | 16 | 30m |
| 8 | 4m | 17 | 1h |
| 9 | 5m | 18 | 2h |

---

> 
> 本笔记涵盖了 RocketMQ 与 Spring Boot 3 集成的完整内容：
> - 基础概念和架构
> - 各种消息类型（普通、顺序、延迟、事务）
> - 消息过滤和重试机制
> - 集群消费和广播消费
> - 生产环境配置和监控
> - 常见错误解决方案
> - 最佳实践
> 
> RocketMQ 是阿里双十一验证过的消息中间件，适合电商、金融等对可靠性要求高的场景。
