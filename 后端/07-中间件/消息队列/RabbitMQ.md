# RabbitMQ 完整学习笔记

> RabbitMQ 是一个开源的消息代理软件，实现了高级消息队列协议（AMQP）
> 本笔记基于 Java 8 + Spring Boot 2.7.18 + RabbitMQ 3.x

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [Spring Boot 集成](#3-spring-boot-集成)
4. [消息模型](#4-消息模型)
5. [交换机类型](#5-交换机类型)
6. [消息确认机制](#6-消息确认机制)
7. [消息持久化](#7-消息持久化)
8. [死信队列](#8-死信队列)
9. [延迟队列](#9-延迟队列)
10. [消息幂等性](#10-消息幂等性)
11. [集群与高可用](#11-集群与高可用)
12. [性能优化](#12-性能优化)
13. [监控与管理](#13-监控与管理)
14. [常见错误与解决方案](#14-常见错误与解决方案)
15. [最佳实践](#15-最佳实践)

---

## 1. 基础概念

### 1.1 什么是消息队列？

消息队列（Message Queue，MQ）是一种应用程序之间的通信方式。它允许应用程序通过发送和接收消息来进行异步通信，而不需要直接连接。

**消息队列的核心价值：**
- **解耦**：生产者和消费者不需要知道对方的存在
- **异步**：发送方不需要等待接收方处理完成
- **削峰**：在高并发场景下，消息队列可以缓冲请求
- **可靠性**：消息持久化确保消息不丢失

### 1.2 什么是 RabbitMQ？

RabbitMQ 是由 Erlang 语言开发的开源消息代理软件，实现了 AMQP（Advanced Message Queuing Protocol，高级消息队列协议）。它是目前最流行的消息队列之一。

**RabbitMQ 的特点：**
- **可靠性**：支持消息持久化、传输确认、发布确认
- **灵活的路由**：通过交换机（Exchange）实现灵活的消息路由
- **集群**：支持集群部署，提高可用性和吞吐量
- **高可用**：支持镜像队列，确保消息不丢失
- **多协议支持**：支持 AMQP、STOMP、MQTT 等协议
- **管理界面**：提供 Web 管理界面，方便监控和管理

### 1.3 核心概念

理解 RabbitMQ 的核心概念是使用它的基础：

```
生产者 (Producer)
    |
    v
交换机 (Exchange) --绑定(Binding)--> 队列 (Queue)
                                        |
                                        v
                                   消费者 (Consumer)
```

**核心组件说明：**

| 组件 | 说明 |
|------|------|
| Producer（生产者） | 发送消息的应用程序 |
| Consumer（消费者） | 接收消息的应用程序 |
| Queue（队列） | 存储消息的缓冲区，消息最终存储在队列中 |
| Exchange（交换机） | 接收生产者发送的消息，并根据路由规则将消息路由到队列 |
| Binding（绑定） | 交换机和队列之间的关联关系 |
| Routing Key（路由键） | 生产者发送消息时指定的路由键，用于交换机路由消息 |
| Virtual Host（虚拟主机） | 类似于命名空间，用于隔离不同的应用 |
| Connection（连接） | 应用程序与 RabbitMQ 之间的 TCP 连接 |
| Channel（信道） | 连接中的虚拟连接，减少 TCP 连接开销 |

### 1.4 AMQP 协议

AMQP（Advanced Message Queuing Protocol）是一个开放标准的应用层协议，为面向消息的中间件设计。

**AMQP 的核心概念：**
- **Message（消息）**：由消息头和消息体组成
- **Publisher（发布者）**：发送消息的客户端
- **Subscriber（订阅者）**：接收消息的客户端
- **Broker（代理）**：消息中间件服务器

---

## 2. 环境搭建

### 2.1 Docker 安装（推荐）

使用 Docker 是最简单的安装方式：

```bash
# 拉取带管理界面的镜像
docker pull rabbitmq:3.11-management

# 运行容器
docker run -d \
  --name rabbitmq \
  -p 5672:5672 \
  -p 15672:15672 \
  -e RABBITMQ_DEFAULT_USER=admin \
  -e RABBITMQ_DEFAULT_PASS=admin123 \
  rabbitmq:3.11-management
```

**端口说明：**
- `5672`：AMQP 协议端口，应用程序连接使用
- `15672`：Web 管理界面端口

访问 `http://localhost:15672`，使用 admin/admin123 登录管理界面。


### 2.2 Windows 安装

1. **安装 Erlang**
   - 下载地址：https://www.erlang.org/downloads
   - 安装后配置环境变量 `ERLANG_HOME`

2. **安装 RabbitMQ**
   - 下载地址：https://www.rabbitmq.com/download.html
   - 安装后启用管理插件：
   ```bash
   rabbitmq-plugins enable rabbitmq_management
   ```

3. **启动服务**
   ```bash
   # 启动
   rabbitmq-server start
   
   # 或作为服务启动
   rabbitmq-service start
   ```

### 2.3 Linux 安装

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install rabbitmq-server

# CentOS/RHEL
sudo yum install rabbitmq-server

# 启动服务
sudo systemctl start rabbitmq-server
sudo systemctl enable rabbitmq-server

# 启用管理插件
sudo rabbitmq-plugins enable rabbitmq_management

# 添加用户
sudo rabbitmqctl add_user admin admin123
sudo rabbitmqctl set_user_tags admin administrator
sudo rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"
```

### 2.4 常用管理命令

```bash
# 查看状态
rabbitmqctl status

# 用户管理
rabbitmqctl list_users                    # 列出用户
rabbitmqctl add_user username password    # 添加用户
rabbitmqctl delete_user username          # 删除用户
rabbitmqctl change_password user newpass  # 修改密码
rabbitmqctl set_user_tags user admin      # 设置用户角色

# 权限管理
rabbitmqctl set_permissions -p / user ".*" ".*" ".*"
rabbitmqctl list_permissions

# 队列管理
rabbitmqctl list_queues                   # 列出队列
rabbitmqctl list_queues name messages     # 列出队列和消息数
rabbitmqctl purge_queue queue_name        # 清空队列
rabbitmqctl delete_queue queue_name       # 删除队列

# 交换机管理
rabbitmqctl list_exchanges                # 列出交换机
rabbitmqctl list_bindings                 # 列出绑定关系

# 连接管理
rabbitmqctl list_connections              # 列出连接
rabbitmqctl list_channels                 # 列出信道
```

---

## 3. Spring Boot 集成

### 3.1 添加依赖

```xml
<!-- pom.xml -->
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.18</version>
</parent>

<dependencies>
    <!-- Spring Boot Starter -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- RabbitMQ -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-amqp</artifactId>
    </dependency>
    
    <!-- JSON 序列化 -->
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
    </dependency>
    
    <!-- Lombok（可选） -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### 3.2 配置文件

```yaml
# application.yml
spring:
  rabbitmq:
    host: localhost
    port: 5672
    username: admin
    password: admin123
    virtual-host: /
    # 发布确认类型：none（禁用）、correlated（异步确认）、simple（同步确认）
    publisher-confirm-type: correlated
    # 发布返回（消息无法路由时返回）
    publisher-returns: true
    # 消费者配置
    listener:
      simple:
        # 确认模式：none（自动确认）、manual（手动确认）、auto（根据异常自动确认）
        acknowledge-mode: manual
        # 预取数量（每次从队列获取的消息数）
        prefetch: 1
        # 并发消费者数量
        concurrency: 1
        max-concurrency: 10
        # 消费失败重试
        retry:
          enabled: true
          initial-interval: 1000
          max-attempts: 3
          max-interval: 10000
          multiplier: 2
    # 连接超时
    connection-timeout: 10000
    # 模板配置
    template:
      # 强制消息返回
      mandatory: true
```

### 3.3 基础配置类

```java
package com.example.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMQConfig {
    
    // 队列名称常量
    public static final String QUEUE_NAME = "test.queue";
    public static final String EXCHANGE_NAME = "test.exchange";
    public static final String ROUTING_KEY = "test.routing.key";
    
    /**
     * 声明队列
     * durable: 是否持久化
     * exclusive: 是否排他（仅创建者可用，连接关闭后删除）
     * autoDelete: 是否自动删除（无消费者时删除）
     */
    @Bean
    public Queue testQueue() {
        return QueueBuilder
                .durable(QUEUE_NAME)
                .build();
    }
    
    /**
     * 声明交换机
     */
    @Bean
    public DirectExchange testExchange() {
        return ExchangeBuilder
                .directExchange(EXCHANGE_NAME)
                .durable(true)
                .build();
    }
    
    /**
     * 绑定队列到交换机
     */
    @Bean
    public Binding testBinding(Queue testQueue, DirectExchange testExchange) {
        return BindingBuilder
                .bind(testQueue)
                .to(testExchange)
                .with(ROUTING_KEY);
    }
    
    /**
     * 消息转换器（使用 JSON 序列化）
     */
    @Bean
    public MessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }
    
    /**
     * 配置 RabbitTemplate
     */
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory,
                                         MessageConverter messageConverter) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(messageConverter);
        
        // 消息发送到交换机确认回调
        rabbitTemplate.setConfirmCallback((correlationData, ack, cause) -> {
            if (ack) {
                System.out.println("消息发送到交换机成功: " + correlationData);
            } else {
                System.err.println("消息发送到交换机失败: " + cause);
            }
        });
        
        // 消息从交换机路由到队列失败回调
        rabbitTemplate.setReturnsCallback(returned -> {
            System.err.println("消息路由失败: " + returned.getMessage());
            System.err.println("回复码: " + returned.getReplyCode());
            System.err.println("回复信息: " + returned.getReplyText());
            System.err.println("交换机: " + returned.getExchange());
            System.err.println("路由键: " + returned.getRoutingKey());
        });
        
        // 设置强制标志，消息不可路由时返回给生产者
        rabbitTemplate.setMandatory(true);
        
        return rabbitTemplate;
    }
}
```


### 3.4 消息实体类

```java
package com.example.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrderMessage implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    /**
     * 消息ID（用于幂等性判断）
     */
    private String messageId;
    
    /**
     * 订单ID
     */
    private Long orderId;
    
    /**
     * 订单金额
     */
    private Double amount;
    
    /**
     * 用户ID
     */
    private Long userId;
    
    /**
     * 创建时间
     */
    private LocalDateTime createTime;
}
```

### 3.5 生产者

```java
package com.example.producer;

import com.example.config.RabbitMQConfig;
import com.example.entity.OrderMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class OrderProducer {
    
    private final RabbitTemplate rabbitTemplate;
    
    /**
     * 发送订单消息
     */
    public void sendOrderMessage(OrderMessage message) {
        // 生成消息ID
        String messageId = UUID.randomUUID().toString();
        message.setMessageId(messageId);
        message.setCreateTime(LocalDateTime.now());
        
        // 创建关联数据（用于确认回调）
        CorrelationData correlationData = new CorrelationData(messageId);
        
        log.info("发送订单消息: {}", message);
        
        // 发送消息
        rabbitTemplate.convertAndSend(
                RabbitMQConfig.EXCHANGE_NAME,
                RabbitMQConfig.ROUTING_KEY,
                message,
                correlationData
        );
    }
    
    /**
     * 发送消息并设置消息属性
     */
    public void sendWithProperties(OrderMessage message) {
        String messageId = UUID.randomUUID().toString();
        message.setMessageId(messageId);
        
        rabbitTemplate.convertAndSend(
                RabbitMQConfig.EXCHANGE_NAME,
                RabbitMQConfig.ROUTING_KEY,
                message,
                msg -> {
                    // 设置消息属性
                    msg.getMessageProperties().setMessageId(messageId);
                    msg.getMessageProperties().setContentType("application/json");
                    msg.getMessageProperties().setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                    // 设置过期时间（毫秒）
                    msg.getMessageProperties().setExpiration("60000");
                    return msg;
                },
                new CorrelationData(messageId)
        );
    }
}
```

### 3.6 消费者

```java
package com.example.consumer;

import com.example.entity.OrderMessage;
import com.rabbitmq.client.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class OrderConsumer {
    
    /**
     * 监听订单队列
     * 手动确认模式
     */
    @RabbitListener(queues = "test.queue")
    public void handleOrderMessage(OrderMessage message, 
                                   Message amqpMessage, 
                                   Channel channel) throws IOException {
        // 获取消息的投递标签
        long deliveryTag = amqpMessage.getMessageProperties().getDeliveryTag();
        
        try {
            log.info("收到订单消息: {}", message);
            
            // 业务处理
            processOrder(message);
            
            // 手动确认消息
            // deliveryTag: 消息的投递标签
            // multiple: 是否批量确认（true 表示确认所有小于等于 deliveryTag 的消息）
            channel.basicAck(deliveryTag, false);
            log.info("消息确认成功: {}", message.getMessageId());
            
        } catch (Exception e) {
            log.error("处理订单消息失败: {}", e.getMessage(), e);
            
            // 判断是否已经重试过
            Boolean redelivered = amqpMessage.getMessageProperties().getRedelivered();
            
            if (redelivered) {
                // 已经重试过，拒绝消息并不再重新入队（可以进入死信队列）
                // deliveryTag: 消息的投递标签
                // requeue: 是否重新入队
                channel.basicReject(deliveryTag, false);
                log.warn("消息已重试，拒绝处理: {}", message.getMessageId());
            } else {
                // 第一次失败，拒绝消息并重新入队
                // deliveryTag: 消息的投递标签
                // multiple: 是否批量拒绝
                // requeue: 是否重新入队
                channel.basicNack(deliveryTag, false, true);
                log.warn("消息处理失败，重新入队: {}", message.getMessageId());
            }
        }
    }
    
    /**
     * 业务处理方法
     */
    private void processOrder(OrderMessage message) {
        // 模拟业务处理
        log.info("处理订单: orderId={}, amount={}", 
                message.getOrderId(), message.getAmount());
        
        // 模拟处理耗时
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
```

### 3.7 测试接口

```java
package com.example.controller;

import com.example.entity.OrderMessage;
import com.example.producer.OrderProducer;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/order")
@RequiredArgsConstructor
public class OrderController {
    
    private final OrderProducer orderProducer;
    
    /**
     * 发送订单消息
     */
    @PostMapping("/send")
    public String sendOrder(@RequestBody OrderMessage message) {
        orderProducer.sendOrderMessage(message);
        return "消息发送成功";
    }
    
    /**
     * 批量发送测试
     */
    @GetMapping("/batch/{count}")
    public String batchSend(@PathVariable int count) {
        for (int i = 0; i < count; i++) {
            OrderMessage message = new OrderMessage();
            message.setOrderId((long) i);
            message.setAmount(100.0 + i);
            message.setUserId(1L);
            orderProducer.sendOrderMessage(message);
        }
        return "批量发送 " + count + " 条消息成功";
    }
}
```

---

## 4. 消息模型

RabbitMQ 支持多种消息模型，适用于不同的业务场景。

### 4.1 简单模式（Simple）

最简单的模式，一个生产者对应一个消费者。

```
Producer --> Queue --> Consumer
```

```java
// 配置
@Configuration
public class SimpleConfig {
    
    public static final String SIMPLE_QUEUE = "simple.queue";
    
    @Bean
    public Queue simpleQueue() {
        return new Queue(SIMPLE_QUEUE, true);
    }
}

// 生产者
@Component
public class SimpleProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void send(String message) {
        // 直接发送到队列（使用默认交换机）
        rabbitTemplate.convertAndSend(SimpleConfig.SIMPLE_QUEUE, message);
    }
}

// 消费者
@Component
public class SimpleConsumer {
    
    @RabbitListener(queues = "simple.queue")
    public void receive(String message) {
        System.out.println("收到消息: " + message);
    }
}
```


### 4.2 工作队列模式（Work Queue）

一个生产者对应多个消费者，消息会被轮询分发给消费者。适用于任务分发场景。

```
              /--> Consumer1
Producer --> Queue
              \--> Consumer2
```

```java
// 配置
@Configuration
public class WorkQueueConfig {
    
    public static final String WORK_QUEUE = "work.queue";
    
    @Bean
    public Queue workQueue() {
        return new Queue(WORK_QUEUE, true);
    }
}

// 生产者
@Component
public class WorkProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void send(String message) {
        rabbitTemplate.convertAndSend(WorkQueueConfig.WORK_QUEUE, message);
    }
}

// 消费者1
@Component
public class WorkConsumer1 {
    
    @RabbitListener(queues = "work.queue")
    public void receive(String message, Channel channel, 
                        @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        try {
            System.out.println("消费者1收到: " + message);
            // 模拟处理耗时
            Thread.sleep(1000);
            channel.basicAck(tag, false);
        } catch (Exception e) {
            channel.basicNack(tag, false, true);
        }
    }
}

// 消费者2
@Component
public class WorkConsumer2 {
    
    @RabbitListener(queues = "work.queue")
    public void receive(String message, Channel channel,
                        @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        try {
            System.out.println("消费者2收到: " + message);
            Thread.sleep(500);
            channel.basicAck(tag, false);
        } catch (Exception e) {
            channel.basicNack(tag, false, true);
        }
    }
}
```

**注意：** 默认情况下，RabbitMQ 使用轮询分发。设置 `prefetch=1` 可以实现能者多劳（处理快的消费者获取更多消息）。

### 4.3 发布/订阅模式（Publish/Subscribe）

使用 Fanout 交换机，消息会被广播到所有绑定的队列。

```
              /--> Queue1 --> Consumer1
Producer --> Exchange(fanout)
              \--> Queue2 --> Consumer2
```

```java
@Configuration
public class FanoutConfig {
    
    public static final String FANOUT_EXCHANGE = "fanout.exchange";
    public static final String FANOUT_QUEUE_1 = "fanout.queue.1";
    public static final String FANOUT_QUEUE_2 = "fanout.queue.2";
    
    @Bean
    public FanoutExchange fanoutExchange() {
        return new FanoutExchange(FANOUT_EXCHANGE);
    }
    
    @Bean
    public Queue fanoutQueue1() {
        return new Queue(FANOUT_QUEUE_1);
    }
    
    @Bean
    public Queue fanoutQueue2() {
        return new Queue(FANOUT_QUEUE_2);
    }
    
    @Bean
    public Binding fanoutBinding1(Queue fanoutQueue1, FanoutExchange fanoutExchange) {
        return BindingBuilder.bind(fanoutQueue1).to(fanoutExchange);
    }
    
    @Bean
    public Binding fanoutBinding2(Queue fanoutQueue2, FanoutExchange fanoutExchange) {
        return BindingBuilder.bind(fanoutQueue2).to(fanoutExchange);
    }
}

// 生产者
@Component
public class FanoutProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void send(String message) {
        // Fanout 交换机忽略 routingKey
        rabbitTemplate.convertAndSend(FanoutConfig.FANOUT_EXCHANGE, "", message);
    }
}

// 消费者
@Component
public class FanoutConsumer {
    
    @RabbitListener(queues = "fanout.queue.1")
    public void receive1(String message) {
        System.out.println("队列1收到: " + message);
    }
    
    @RabbitListener(queues = "fanout.queue.2")
    public void receive2(String message) {
        System.out.println("队列2收到: " + message);
    }
}
```

### 4.4 路由模式（Routing）

使用 Direct 交换机，根据路由键精确匹配队列。

```
                    routing_key=error
              /-------------------------> Queue1 --> Consumer1
Producer --> Exchange(direct)
              \-------------------------> Queue2 --> Consumer2
                    routing_key=info
```

```java
@Configuration
public class DirectConfig {
    
    public static final String DIRECT_EXCHANGE = "direct.exchange";
    public static final String ERROR_QUEUE = "error.queue";
    public static final String INFO_QUEUE = "info.queue";
    
    @Bean
    public DirectExchange directExchange() {
        return new DirectExchange(DIRECT_EXCHANGE);
    }
    
    @Bean
    public Queue errorQueue() {
        return new Queue(ERROR_QUEUE);
    }
    
    @Bean
    public Queue infoQueue() {
        return new Queue(INFO_QUEUE);
    }
    
    @Bean
    public Binding errorBinding(Queue errorQueue, DirectExchange directExchange) {
        return BindingBuilder.bind(errorQueue).to(directExchange).with("error");
    }
    
    @Bean
    public Binding infoBinding(Queue infoQueue, DirectExchange directExchange) {
        return BindingBuilder.bind(infoQueue).to(directExchange).with("info");
    }
}

// 生产者
@Component
public class DirectProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void sendError(String message) {
        rabbitTemplate.convertAndSend(DirectConfig.DIRECT_EXCHANGE, "error", message);
    }
    
    public void sendInfo(String message) {
        rabbitTemplate.convertAndSend(DirectConfig.DIRECT_EXCHANGE, "info", message);
    }
}

// 消费者
@Component
public class DirectConsumer {
    
    @RabbitListener(queues = "error.queue")
    public void receiveError(String message) {
        System.out.println("错误日志: " + message);
    }
    
    @RabbitListener(queues = "info.queue")
    public void receiveInfo(String message) {
        System.out.println("信息日志: " + message);
    }
}
```

### 4.5 主题模式（Topic）

使用 Topic 交换机，支持通配符匹配路由键。

**通配符规则：**
- `*`：匹配一个单词
- `#`：匹配零个或多个单词

```
                    routing_key=order.create
              /---------------------------------> Queue1 (order.*) --> Consumer1
Producer --> Exchange(topic)
              \---------------------------------> Queue2 (order.#) --> Consumer2
                    routing_key=order.pay.success
```

```java
@Configuration
public class TopicConfig {
    
    public static final String TOPIC_EXCHANGE = "topic.exchange";
    public static final String ORDER_QUEUE = "order.queue";
    public static final String ALL_ORDER_QUEUE = "all.order.queue";
    
    @Bean
    public TopicExchange topicExchange() {
        return new TopicExchange(TOPIC_EXCHANGE);
    }
    
    @Bean
    public Queue orderQueue() {
        return new Queue(ORDER_QUEUE);
    }
    
    @Bean
    public Queue allOrderQueue() {
        return new Queue(ALL_ORDER_QUEUE);
    }
    
    // order.* 匹配 order.create, order.cancel 等
    @Bean
    public Binding orderBinding(Queue orderQueue, TopicExchange topicExchange) {
        return BindingBuilder.bind(orderQueue).to(topicExchange).with("order.*");
    }
    
    // order.# 匹配 order.create, order.pay.success, order.pay.fail 等
    @Bean
    public Binding allOrderBinding(Queue allOrderQueue, TopicExchange topicExchange) {
        return BindingBuilder.bind(allOrderQueue).to(topicExchange).with("order.#");
    }
}

// 生产者
@Component
public class TopicProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void sendOrderCreate(String message) {
        // 匹配 order.* 和 order.#
        rabbitTemplate.convertAndSend(TopicConfig.TOPIC_EXCHANGE, "order.create", message);
    }
    
    public void sendOrderPaySuccess(String message) {
        // 只匹配 order.#
        rabbitTemplate.convertAndSend(TopicConfig.TOPIC_EXCHANGE, "order.pay.success", message);
    }
}

// 消费者
@Component
public class TopicConsumer {
    
    @RabbitListener(queues = "order.queue")
    public void receiveOrder(String message) {
        System.out.println("订单队列收到: " + message);
    }
    
    @RabbitListener(queues = "all.order.queue")
    public void receiveAllOrder(String message) {
        System.out.println("全部订单队列收到: " + message);
    }
}
```


---

## 5. 交换机类型

### 5.1 交换机类型对比

| 类型 | 路由规则 | 使用场景 |
|------|----------|----------|
| Direct | 精确匹配路由键 | 点对点通信、日志分级 |
| Fanout | 广播到所有绑定队列 | 广播通知、群发消息 |
| Topic | 通配符匹配路由键 | 灵活的消息路由 |
| Headers | 根据消息头匹配 | 复杂的路由规则 |

### 5.2 Headers 交换机

根据消息头属性进行匹配，而不是路由键。

```java
@Configuration
public class HeadersConfig {
    
    public static final String HEADERS_EXCHANGE = "headers.exchange";
    public static final String HEADERS_QUEUE = "headers.queue";
    
    @Bean
    public HeadersExchange headersExchange() {
        return new HeadersExchange(HEADERS_EXCHANGE);
    }
    
    @Bean
    public Queue headersQueue() {
        return new Queue(HEADERS_QUEUE);
    }
    
    @Bean
    public Binding headersBinding(Queue headersQueue, HeadersExchange headersExchange) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("type", "order");
        headers.put("status", "new");
        
        // whereAll: 所有头都匹配
        // whereAny: 任意一个头匹配
        return BindingBuilder
                .bind(headersQueue)
                .to(headersExchange)
                .whereAll(headers)
                .match();
    }
}

// 生产者
@Component
public class HeadersProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void send(String message) {
        rabbitTemplate.convertAndSend(
                HeadersConfig.HEADERS_EXCHANGE,
                "",  // Headers 交换机忽略路由键
                message,
                msg -> {
                    msg.getMessageProperties().setHeader("type", "order");
                    msg.getMessageProperties().setHeader("status", "new");
                    return msg;
                }
        );
    }
}
```

### 5.3 使用注解声明交换机和队列

Spring AMQP 支持使用 `@RabbitListener` 注解直接声明交换机、队列和绑定关系：

```java
@Component
public class AnnotationConsumer {
    
    /**
     * 使用注解声明队列、交换机和绑定
     */
    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(value = "annotation.queue", durable = "true"),
            exchange = @Exchange(value = "annotation.exchange", type = ExchangeTypes.DIRECT),
            key = "annotation.key"
    ))
    public void receive(String message) {
        System.out.println("收到消息: " + message);
    }
    
    /**
     * Topic 交换机示例
     */
    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(value = "topic.annotation.queue", durable = "true"),
            exchange = @Exchange(value = "topic.annotation.exchange", type = ExchangeTypes.TOPIC),
            key = "order.#"
    ))
    public void receiveTopicMessage(String message) {
        System.out.println("Topic 消息: " + message);
    }
    
    /**
     * 声明带参数的队列
     */
    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "args.queue",
                    durable = "true",
                    arguments = {
                            @Argument(name = "x-message-ttl", value = "60000", type = "java.lang.Integer"),
                            @Argument(name = "x-max-length", value = "1000", type = "java.lang.Integer")
                    }
            ),
            exchange = @Exchange(value = "args.exchange", type = ExchangeTypes.DIRECT),
            key = "args.key"
    ))
    public void receiveWithArgs(String message) {
        System.out.println("带参数队列消息: " + message);
    }
}
```

---

## 6. 消息确认机制

消息确认是保证消息可靠性的关键机制。

### 6.1 生产者确认

确保消息成功发送到 RabbitMQ。

```java
@Configuration
public class ConfirmConfig {
    
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(new Jackson2JsonMessageConverter());
        
        // 1. 确认回调：消息到达交换机时触发
        rabbitTemplate.setConfirmCallback((correlationData, ack, cause) -> {
            String id = correlationData != null ? correlationData.getId() : "";
            if (ack) {
                log.info("消息发送到交换机成功，ID: {}", id);
            } else {
                log.error("消息发送到交换机失败，ID: {}, 原因: {}", id, cause);
                // 可以在这里进行重试或记录到数据库
            }
        });
        
        // 2. 返回回调：消息无法路由到队列时触发
        rabbitTemplate.setReturnsCallback(returned -> {
            log.error("消息路由失败: exchange={}, routingKey={}, replyCode={}, replyText={}, message={}",
                    returned.getExchange(),
                    returned.getRoutingKey(),
                    returned.getReplyCode(),
                    returned.getReplyText(),
                    returned.getMessage());
            // 可以在这里进行重试或记录
        });
        
        rabbitTemplate.setMandatory(true);
        
        return rabbitTemplate;
    }
}
```

### 6.2 消费者确认

确保消息被正确处理。

**确认模式：**
- `NONE`：自动确认，消息发送给消费者后立即确认
- `AUTO`：根据方法执行结果自动确认（无异常确认，有异常拒绝）
- `MANUAL`：手动确认，需要在代码中显式调用确认方法

```java
@Component
@Slf4j
public class ManualAckConsumer {
    
    @RabbitListener(queues = "manual.ack.queue")
    public void receive(Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        
        try {
            // 获取消息内容
            String content = new String(message.getBody());
            log.info("收到消息: {}", content);
            
            // 业务处理
            processMessage(content);
            
            // 确认消息
            // basicAck(deliveryTag, multiple)
            // deliveryTag: 消息的投递标签
            // multiple: false-只确认当前消息，true-确认所有小于等于deliveryTag的消息
            channel.basicAck(deliveryTag, false);
            
        } catch (BusinessException e) {
            // 业务异常，不重试，直接拒绝
            log.error("业务处理失败: {}", e.getMessage());
            // basicReject(deliveryTag, requeue)
            // requeue: false-丢弃或进入死信队列，true-重新入队
            channel.basicReject(deliveryTag, false);
            
        } catch (Exception e) {
            // 其他异常，可以重试
            log.error("处理消息异常: {}", e.getMessage());
            // basicNack(deliveryTag, multiple, requeue)
            channel.basicNack(deliveryTag, false, true);
        }
    }
    
    private void processMessage(String content) throws BusinessException {
        // 业务处理逻辑
    }
}
```

### 6.3 确认方法对比

| 方法 | 说明 | 参数 |
|------|------|------|
| basicAck | 确认消息 | deliveryTag, multiple |
| basicNack | 拒绝消息（可批量） | deliveryTag, multiple, requeue |
| basicReject | 拒绝消息（单条） | deliveryTag, requeue |

```java
// 确认单条消息
channel.basicAck(deliveryTag, false);

// 批量确认（确认所有 deliveryTag <= 当前值的消息）
channel.basicAck(deliveryTag, true);

// 拒绝并重新入队
channel.basicNack(deliveryTag, false, true);

// 拒绝并丢弃（或进入死信队列）
channel.basicNack(deliveryTag, false, false);

// 拒绝单条消息
channel.basicReject(deliveryTag, false);
```


---

## 7. 消息持久化

消息持久化确保 RabbitMQ 重启后消息不丢失。

### 7.1 持久化的三个层面

要实现完整的消息持久化，需要同时满足三个条件：

1. **交换机持久化**
2. **队列持久化**
3. **消息持久化**

```java
@Configuration
public class PersistenceConfig {
    
    // 1. 持久化交换机
    @Bean
    public DirectExchange persistentExchange() {
        // durable=true 表示持久化
        return new DirectExchange("persistent.exchange", true, false);
    }
    
    // 2. 持久化队列
    @Bean
    public Queue persistentQueue() {
        // durable=true 表示持久化
        return QueueBuilder
                .durable("persistent.queue")
                .build();
    }
    
    @Bean
    public Binding persistentBinding() {
        return BindingBuilder
                .bind(persistentQueue())
                .to(persistentExchange())
                .with("persistent.key");
    }
}

// 3. 发送持久化消息
@Component
public class PersistentProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void send(String message) {
        rabbitTemplate.convertAndSend(
                "persistent.exchange",
                "persistent.key",
                message,
                msg -> {
                    // 设置消息持久化
                    msg.getMessageProperties().setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                    return msg;
                }
        );
    }
}
```

### 7.2 持久化的性能影响

持久化会影响性能，因为需要写入磁盘。可以通过以下方式优化：

```java
// 1. 使用 lazy queue（惰性队列）
@Bean
public Queue lazyQueue() {
    return QueueBuilder
            .durable("lazy.queue")
            .lazy()  // 消息直接写入磁盘，减少内存使用
            .build();
}

// 2. 批量确认
@Bean
public RabbitTemplate batchRabbitTemplate(ConnectionFactory connectionFactory) {
    RabbitTemplate template = new RabbitTemplate(connectionFactory);
    // 使用批量确认可以提高性能
    return template;
}
```

---

## 8. 死信队列

死信队列（Dead Letter Queue，DLQ）用于存储无法被正常消费的消息。

### 8.1 消息成为死信的条件

1. **消息被拒绝**（basicReject/basicNack）且 requeue=false
2. **消息过期**（TTL 到期）
3. **队列达到最大长度**

### 8.2 死信队列配置

```java
@Configuration
public class DeadLetterConfig {
    
    // 死信交换机
    public static final String DLX_EXCHANGE = "dlx.exchange";
    // 死信队列
    public static final String DLX_QUEUE = "dlx.queue";
    // 死信路由键
    public static final String DLX_ROUTING_KEY = "dlx.routing.key";
    
    // 正常交换机
    public static final String NORMAL_EXCHANGE = "normal.exchange";
    // 正常队列
    public static final String NORMAL_QUEUE = "normal.queue";
    // 正常路由键
    public static final String NORMAL_ROUTING_KEY = "normal.routing.key";
    
    // ========== 死信交换机和队列 ==========
    
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
        return BindingBuilder
                .bind(dlxQueue())
                .to(dlxExchange())
                .with(DLX_ROUTING_KEY);
    }
    
    // ========== 正常交换机和队列（绑定死信交换机） ==========
    
    @Bean
    public DirectExchange normalExchange() {
        return new DirectExchange(NORMAL_EXCHANGE);
    }
    
    @Bean
    public Queue normalQueue() {
        return QueueBuilder
                .durable(NORMAL_QUEUE)
                // 绑定死信交换机
                .deadLetterExchange(DLX_EXCHANGE)
                // 绑定死信路由键
                .deadLetterRoutingKey(DLX_ROUTING_KEY)
                // 设置消息过期时间（可选）
                .ttl(10000)
                // 设置队列最大长度（可选）
                .maxLength(100)
                .build();
    }
    
    @Bean
    public Binding normalBinding() {
        return BindingBuilder
                .bind(normalQueue())
                .to(normalExchange())
                .with(NORMAL_ROUTING_KEY);
    }
}
```

### 8.3 死信队列消费者

```java
@Component
@Slf4j
public class DeadLetterConsumer {
    
    /**
     * 正常队列消费者
     */
    @RabbitListener(queues = "normal.queue")
    public void receiveNormal(Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        String content = new String(message.getBody());
        
        try {
            log.info("正常队列收到消息: {}", content);
            
            // 模拟业务处理失败
            if (content.contains("error")) {
                throw new RuntimeException("业务处理失败");
            }
            
            channel.basicAck(deliveryTag, false);
            
        } catch (Exception e) {
            log.error("处理失败，消息将进入死信队列: {}", e.getMessage());
            // 拒绝消息，不重新入队，消息将进入死信队列
            channel.basicReject(deliveryTag, false);
        }
    }
    
    /**
     * 死信队列消费者
     */
    @RabbitListener(queues = "dlx.queue")
    public void receiveDeadLetter(Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        String content = new String(message.getBody());
        
        log.warn("死信队列收到消息: {}", content);
        
        // 获取死信信息
        Map<String, Object> headers = message.getMessageProperties().getHeaders();
        List<Map<String, Object>> xDeath = (List<Map<String, Object>>) headers.get("x-death");
        if (xDeath != null && !xDeath.isEmpty()) {
            Map<String, Object> death = xDeath.get(0);
            log.info("死信原因: {}", death.get("reason"));
            log.info("原队列: {}", death.get("queue"));
            log.info("原交换机: {}", death.get("exchange"));
            log.info("死亡次数: {}", death.get("count"));
        }
        
        // 处理死信消息（如：记录日志、发送告警、人工处理等）
        handleDeadLetter(content);
        
        channel.basicAck(deliveryTag, false);
    }
    
    private void handleDeadLetter(String content) {
        // 记录到数据库或发送告警
        log.info("处理死信消息: {}", content);
    }
}
```

### 8.4 使用注解配置死信队列

```java
@Component
public class AnnotationDeadLetterConsumer {
    
    @RabbitListener(bindings = @QueueBinding(
            value = @Queue(
                    value = "order.queue",
                    durable = "true",
                    arguments = {
                            @Argument(name = "x-dead-letter-exchange", value = "order.dlx.exchange"),
                            @Argument(name = "x-dead-letter-routing-key", value = "order.dlx.key"),
                            @Argument(name = "x-message-ttl", value = "60000", type = "java.lang.Integer")
                    }
            ),
            exchange = @Exchange(value = "order.exchange", type = ExchangeTypes.DIRECT),
            key = "order.key"
    ))
    public void receiveOrder(String message, Channel channel,
                             @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        try {
            // 业务处理
            channel.basicAck(tag, false);
        } catch (Exception e) {
            channel.basicReject(tag, false);
        }
    }
}
```


---

## 9. 延迟队列

延迟队列用于实现消息的延迟投递，常用于订单超时取消、定时任务等场景。

### 9.1 基于死信队列实现延迟队列

利用消息 TTL + 死信队列实现延迟效果。

```java
@Configuration
public class DelayQueueConfig {
    
    // 延迟交换机（实际是死信交换机）
    public static final String DELAY_EXCHANGE = "delay.exchange";
    // 延迟队列（实际是死信队列，消费者监听这个队列）
    public static final String DELAY_QUEUE = "delay.queue";
    // 延迟路由键
    public static final String DELAY_ROUTING_KEY = "delay.routing.key";
    
    // 等待交换机
    public static final String WAIT_EXCHANGE = "wait.exchange";
    // 等待队列（消息在这里等待过期）
    public static final String WAIT_QUEUE = "wait.queue";
    // 等待路由键
    public static final String WAIT_ROUTING_KEY = "wait.routing.key";
    
    // ========== 延迟交换机和队列（消费者监听） ==========
    
    @Bean
    public DirectExchange delayExchange() {
        return new DirectExchange(DELAY_EXCHANGE);
    }
    
    @Bean
    public Queue delayQueue() {
        return QueueBuilder.durable(DELAY_QUEUE).build();
    }
    
    @Bean
    public Binding delayBinding() {
        return BindingBuilder
                .bind(delayQueue())
                .to(delayExchange())
                .with(DELAY_ROUTING_KEY);
    }
    
    // ========== 等待交换机和队列（消息在这里等待） ==========
    
    @Bean
    public DirectExchange waitExchange() {
        return new DirectExchange(WAIT_EXCHANGE);
    }
    
    @Bean
    public Queue waitQueue() {
        return QueueBuilder
                .durable(WAIT_QUEUE)
                // 绑定死信交换机
                .deadLetterExchange(DELAY_EXCHANGE)
                .deadLetterRoutingKey(DELAY_ROUTING_KEY)
                // 不设置队列级别的 TTL，使用消息级别的 TTL
                .build();
    }
    
    @Bean
    public Binding waitBinding() {
        return BindingBuilder
                .bind(waitQueue())
                .to(waitExchange())
                .with(WAIT_ROUTING_KEY);
    }
}
```

### 9.2 延迟消息生产者

```java
@Component
@Slf4j
public class DelayProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * 发送延迟消息
     * @param message 消息内容
     * @param delayTime 延迟时间（毫秒）
     */
    public void sendDelayMessage(String message, long delayTime) {
        log.info("发送延迟消息: {}, 延迟时间: {}ms", message, delayTime);
        
        rabbitTemplate.convertAndSend(
                DelayQueueConfig.WAIT_EXCHANGE,
                DelayQueueConfig.WAIT_ROUTING_KEY,
                message,
                msg -> {
                    // 设置消息过期时间
                    msg.getMessageProperties().setExpiration(String.valueOf(delayTime));
                    return msg;
                }
        );
    }
    
    /**
     * 发送订单超时取消消息
     */
    public void sendOrderTimeoutMessage(Long orderId, long timeoutMinutes) {
        String message = String.valueOf(orderId);
        long delayTime = timeoutMinutes * 60 * 1000;
        sendDelayMessage(message, delayTime);
    }
}
```

### 9.3 延迟消息消费者

```java
@Component
@Slf4j
public class DelayConsumer {
    
    @RabbitListener(queues = "delay.queue")
    public void receiveDelayMessage(String message, Channel channel,
                                    @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        try {
            log.info("收到延迟消息: {}", message);
            
            // 处理延迟消息（如：检查订单状态，取消超时订单）
            processDelayMessage(message);
            
            channel.basicAck(tag, false);
        } catch (Exception e) {
            log.error("处理延迟消息失败: {}", e.getMessage());
            channel.basicReject(tag, false);
        }
    }
    
    private void processDelayMessage(String message) {
        // 业务处理逻辑
        log.info("处理延迟消息: {}", message);
    }
}
```

### 9.4 基于插件实现延迟队列（推荐）

RabbitMQ 提供了 `rabbitmq_delayed_message_exchange` 插件，可以更优雅地实现延迟队列。

**安装插件：**

```bash
# 下载插件
wget https://github.com/rabbitmq/rabbitmq-delayed-message-exchange/releases/download/v3.11.1/rabbitmq_delayed_message_exchange-3.11.1.ez

# 复制到插件目录
cp rabbitmq_delayed_message_exchange-3.11.1.ez /usr/lib/rabbitmq/lib/rabbitmq_server-3.11/plugins/

# 启用插件
rabbitmq-plugins enable rabbitmq_delayed_message_exchange
```

**配置：**

```java
@Configuration
public class DelayedPluginConfig {
    
    public static final String DELAYED_EXCHANGE = "delayed.exchange";
    public static final String DELAYED_QUEUE = "delayed.queue";
    public static final String DELAYED_ROUTING_KEY = "delayed.routing.key";
    
    /**
     * 声明延迟交换机
     */
    @Bean
    public CustomExchange delayedExchange() {
        Map<String, Object> args = new HashMap<>();
        // 设置交换机类型
        args.put("x-delayed-type", "direct");
        
        return new CustomExchange(
                DELAYED_EXCHANGE,
                "x-delayed-message",  // 交换机类型
                true,                  // 持久化
                false,                 // 自动删除
                args
        );
    }
    
    @Bean
    public Queue delayedQueue() {
        return QueueBuilder.durable(DELAYED_QUEUE).build();
    }
    
    @Bean
    public Binding delayedBinding() {
        return BindingBuilder
                .bind(delayedQueue())
                .to(delayedExchange())
                .with(DELAYED_ROUTING_KEY)
                .noargs();
    }
}
```

**生产者：**

```java
@Component
@Slf4j
public class DelayedPluginProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * 发送延迟消息
     */
    public void sendDelayedMessage(String message, long delayTime) {
        log.info("发送延迟消息: {}, 延迟: {}ms", message, delayTime);
        
        rabbitTemplate.convertAndSend(
                DelayedPluginConfig.DELAYED_EXCHANGE,
                DelayedPluginConfig.DELAYED_ROUTING_KEY,
                message,
                msg -> {
                    // 设置延迟时间（毫秒）
                    msg.getMessageProperties().setDelay((int) delayTime);
                    return msg;
                }
        );
    }
}
```

### 9.5 两种延迟队列方案对比

| 特性 | 死信队列方案 | 插件方案 |
|------|-------------|----------|
| 实现复杂度 | 较复杂 | 简单 |
| 消息顺序 | 可能乱序（先入队的长延迟消息会阻塞后入队的短延迟消息） | 保证顺序 |
| 性能 | 一般 | 较好 |
| 依赖 | 无 | 需要安装插件 |
| 适用场景 | 固定延迟时间 | 任意延迟时间 |

---

## 10. 消息幂等性

幂等性是指同一操作执行多次的效果与执行一次相同。在消息队列中，由于网络问题或重试机制，消息可能被重复消费，因此需要保证消费的幂等性。

### 10.1 幂等性问题场景

1. **生产者重复发送**：网络超时导致生产者重试
2. **消费者重复消费**：消费者处理成功但确认失败，消息重新入队
3. **消息重新入队**：消费者处理失败，消息重新入队后再次消费

### 10.2 基于数据库实现幂等性

```java
@Service
@Slf4j
public class IdempotentService {
    
    @Autowired
    private MessageLogMapper messageLogMapper;
    
    /**
     * 检查消息是否已处理
     */
    public boolean isProcessed(String messageId) {
        MessageLog log = messageLogMapper.selectByMessageId(messageId);
        return log != null && "SUCCESS".equals(log.getStatus());
    }
    
    /**
     * 记录消息处理开始
     */
    @Transactional
    public boolean startProcess(String messageId) {
        try {
            MessageLog log = new MessageLog();
            log.setMessageId(messageId);
            log.setStatus("PROCESSING");
            log.setCreateTime(LocalDateTime.now());
            messageLogMapper.insert(log);
            return true;
        } catch (DuplicateKeyException e) {
            // 消息已存在，说明正在处理或已处理
            return false;
        }
    }
    
    /**
     * 记录消息处理成功
     */
    @Transactional
    public void markSuccess(String messageId) {
        messageLogMapper.updateStatus(messageId, "SUCCESS", LocalDateTime.now());
    }
    
    /**
     * 记录消息处理失败
     */
    @Transactional
    public void markFailed(String messageId, String errorMsg) {
        messageLogMapper.updateStatusWithError(messageId, "FAILED", errorMsg, LocalDateTime.now());
    }
}

// 消息日志表
@Data
public class MessageLog {
    private Long id;
    private String messageId;
    private String status;  // PROCESSING, SUCCESS, FAILED
    private String errorMsg;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;
}
```

```sql
-- 消息日志表
CREATE TABLE message_log (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    message_id VARCHAR(64) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL,
    error_msg VARCHAR(500),
    create_time DATETIME NOT NULL,
    update_time DATETIME,
    INDEX idx_message_id (message_id)
);
```

### 10.3 幂等消费者实现

```java
@Component
@Slf4j
public class IdempotentConsumer {
    
    @Autowired
    private IdempotentService idempotentService;
    
    @Autowired
    private OrderService orderService;
    
    @RabbitListener(queues = "order.queue")
    public void handleOrder(OrderMessage message, Channel channel,
                           @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        String messageId = message.getMessageId();
        
        try {
            // 1. 检查是否已处理
            if (idempotentService.isProcessed(messageId)) {
                log.info("消息已处理，跳过: {}", messageId);
                channel.basicAck(tag, false);
                return;
            }
            
            // 2. 尝试开始处理（利用数据库唯一索引保证幂等）
            if (!idempotentService.startProcess(messageId)) {
                log.info("消息正在处理中，跳过: {}", messageId);
                channel.basicAck(tag, false);
                return;
            }
            
            // 3. 业务处理
            orderService.processOrder(message);
            
            // 4. 标记处理成功
            idempotentService.markSuccess(messageId);
            
            // 5. 确认消息
            channel.basicAck(tag, false);
            log.info("消息处理成功: {}", messageId);
            
        } catch (Exception e) {
            log.error("消息处理失败: {}", e.getMessage(), e);
            
            // 标记处理失败
            idempotentService.markFailed(messageId, e.getMessage());
            
            // 拒绝消息，不重新入队（进入死信队列）
            channel.basicReject(tag, false);
        }
    }
}
```


### 10.4 基于 Redis 实现幂等性

使用 Redis 的 SETNX 命令实现分布式锁，性能更好。

```java
@Service
@Slf4j
public class RedisIdempotentService {
    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    private static final String KEY_PREFIX = "mq:idempotent:";
    private static final long EXPIRE_TIME = 24 * 60 * 60; // 24小时
    
    /**
     * 尝试获取处理权
     * @return true-获取成功，可以处理；false-已被处理或正在处理
     */
    public boolean tryAcquire(String messageId) {
        String key = KEY_PREFIX + messageId;
        Boolean success = redisTemplate.opsForValue()
                .setIfAbsent(key, "PROCESSING", EXPIRE_TIME, TimeUnit.SECONDS);
        return Boolean.TRUE.equals(success);
    }
    
    /**
     * 标记处理成功
     */
    public void markSuccess(String messageId) {
        String key = KEY_PREFIX + messageId;
        redisTemplate.opsForValue().set(key, "SUCCESS", EXPIRE_TIME, TimeUnit.SECONDS);
    }
    
    /**
     * 标记处理失败（删除 key，允许重试）
     */
    public void markFailed(String messageId) {
        String key = KEY_PREFIX + messageId;
        redisTemplate.delete(key);
    }
    
    /**
     * 检查是否已处理成功
     */
    public boolean isSuccess(String messageId) {
        String key = KEY_PREFIX + messageId;
        String value = redisTemplate.opsForValue().get(key);
        return "SUCCESS".equals(value);
    }
}
```

```java
@Component
@Slf4j
public class RedisIdempotentConsumer {
    
    @Autowired
    private RedisIdempotentService idempotentService;
    
    @RabbitListener(queues = "order.queue")
    public void handleOrder(OrderMessage message, Channel channel,
                           @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        String messageId = message.getMessageId();
        
        try {
            // 尝试获取处理权
            if (!idempotentService.tryAcquire(messageId)) {
                log.info("消息已处理或正在处理，跳过: {}", messageId);
                channel.basicAck(tag, false);
                return;
            }
            
            // 业务处理
            processOrder(message);
            
            // 标记成功
            idempotentService.markSuccess(messageId);
            channel.basicAck(tag, false);
            
        } catch (Exception e) {
            log.error("处理失败: {}", e.getMessage());
            // 标记失败，允许重试
            idempotentService.markFailed(messageId);
            channel.basicNack(tag, false, true);
        }
    }
    
    private void processOrder(OrderMessage message) {
        // 业务逻辑
    }
}
```

---

## 11. 集群与高可用

### 11.1 集群模式

RabbitMQ 支持集群部署，提高可用性和吞吐量。

**集群特点：**
- 所有节点共享元数据（交换机、队列定义、绑定关系等）
- 队列数据默认只存在于创建它的节点上
- 客户端可以连接任意节点

**搭建集群（Docker Compose）：**

```yaml
# docker-compose.yml
version: '3.8'

services:
  rabbitmq1:
    image: rabbitmq:3.11-management
    hostname: rabbitmq1
    environment:
      - RABBITMQ_ERLANG_COOKIE=secret_cookie
      - RABBITMQ_DEFAULT_USER=admin
      - RABBITMQ_DEFAULT_PASS=admin123
    ports:
      - "5672:5672"
      - "15672:15672"
    networks:
      - rabbitmq-cluster

  rabbitmq2:
    image: rabbitmq:3.11-management
    hostname: rabbitmq2
    environment:
      - RABBITMQ_ERLANG_COOKIE=secret_cookie
      - RABBITMQ_DEFAULT_USER=admin
      - RABBITMQ_DEFAULT_PASS=admin123
    ports:
      - "5673:5672"
      - "15673:15672"
    depends_on:
      - rabbitmq1
    networks:
      - rabbitmq-cluster

  rabbitmq3:
    image: rabbitmq:3.11-management
    hostname: rabbitmq3
    environment:
      - RABBITMQ_ERLANG_COOKIE=secret_cookie
      - RABBITMQ_DEFAULT_USER=admin
      - RABBITMQ_DEFAULT_PASS=admin123
    ports:
      - "5674:5672"
      - "15674:15672"
    depends_on:
      - rabbitmq1
    networks:
      - rabbitmq-cluster

networks:
  rabbitmq-cluster:
    driver: bridge
```

**加入集群：**

```bash
# 在 rabbitmq2 上执行
docker exec -it rabbitmq2 bash
rabbitmqctl stop_app
rabbitmqctl reset
rabbitmqctl join_cluster rabbit@rabbitmq1
rabbitmqctl start_app

# 在 rabbitmq3 上执行
docker exec -it rabbitmq3 bash
rabbitmqctl stop_app
rabbitmqctl reset
rabbitmqctl join_cluster rabbit@rabbitmq1
rabbitmqctl start_app

# 查看集群状态
rabbitmqctl cluster_status
```

### 11.2 镜像队列（经典镜像）

镜像队列将队列数据复制到多个节点，提高可用性。

```bash
# 设置镜像策略
# ha-mode: all（所有节点）、exactly（指定数量）、nodes（指定节点）
rabbitmqctl set_policy ha-all "^ha\." '{"ha-mode":"all","ha-sync-mode":"automatic"}'

# 指定数量的镜像
rabbitmqctl set_policy ha-two "^two\." '{"ha-mode":"exactly","ha-params":2,"ha-sync-mode":"automatic"}'
```

### 11.3 仲裁队列（Quorum Queue，推荐）

RabbitMQ 3.8+ 引入的新队列类型，基于 Raft 协议，提供更好的数据安全性。

```java
@Configuration
public class QuorumQueueConfig {
    
    @Bean
    public Queue quorumQueue() {
        return QueueBuilder
                .durable("quorum.queue")
                .quorum()  // 声明为仲裁队列
                .build();
    }
    
    // 或使用 arguments
    @Bean
    public Queue quorumQueue2() {
        Map<String, Object> args = new HashMap<>();
        args.put("x-queue-type", "quorum");
        return new Queue("quorum.queue.2", true, false, false, args);
    }
}
```

**仲裁队列 vs 镜像队列：**

| 特性 | 仲裁队列 | 镜像队列 |
|------|----------|----------|
| 数据安全 | 更高（Raft 协议） | 一般 |
| 性能 | 较好 | 一般 |
| 配置复杂度 | 简单 | 复杂 |
| 消息顺序 | 保证 | 可能乱序 |
| 推荐程度 | 推荐 | 不推荐（已弃用） |

### 11.4 Spring Boot 集群配置

```yaml
spring:
  rabbitmq:
    # 多节点配置
    addresses: rabbitmq1:5672,rabbitmq2:5672,rabbitmq3:5672
    username: admin
    password: admin123
    virtual-host: /
    # 连接超时
    connection-timeout: 10000
    # 请求心跳
    requested-heartbeat: 30
```

```java
@Configuration
public class ClusterConfig {
    
    @Bean
    public ConnectionFactory connectionFactory() {
        CachingConnectionFactory factory = new CachingConnectionFactory();
        
        // 设置多个地址
        factory.setAddresses("rabbitmq1:5672,rabbitmq2:5672,rabbitmq3:5672");
        factory.setUsername("admin");
        factory.setPassword("admin123");
        factory.setVirtualHost("/");
        
        // 连接恢复
        factory.getRabbitConnectionFactory().setAutomaticRecoveryEnabled(true);
        factory.getRabbitConnectionFactory().setNetworkRecoveryInterval(5000);
        
        return factory;
    }
}
```


---

## 12. 性能优化

### 12.1 生产者优化

```java
@Configuration
public class ProducerOptimizationConfig {
    
    @Bean
    public RabbitTemplate optimizedRabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        
        // 1. 使用 JSON 序列化（比 Java 序列化更高效）
        template.setMessageConverter(new Jackson2JsonMessageConverter());
        
        // 2. 设置通道缓存大小
        if (connectionFactory instanceof CachingConnectionFactory) {
            CachingConnectionFactory cachingFactory = (CachingConnectionFactory) connectionFactory;
            cachingFactory.setChannelCacheSize(25);
        }
        
        return template;
    }
}

// 批量发送
@Component
public class BatchProducer {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * 批量发送消息
     */
    public void batchSend(List<String> messages, String exchange, String routingKey) {
        rabbitTemplate.execute(channel -> {
            for (String message : messages) {
                channel.basicPublish(
                        exchange,
                        routingKey,
                        MessageProperties.PERSISTENT_TEXT_PLAIN,
                        message.getBytes()
                );
            }
            return null;
        });
    }
}
```

### 12.2 消费者优化

```yaml
spring:
  rabbitmq:
    listener:
      simple:
        # 预取数量：根据消息处理速度调整
        # 处理快的消息可以设置大一些，处理慢的设置小一些
        prefetch: 10
        # 并发消费者数量
        concurrency: 5
        max-concurrency: 20
        # 批量确认
        batch-size: 10
```

```java
@Component
public class OptimizedConsumer {
    
    /**
     * 批量消费
     */
    @RabbitListener(queues = "batch.queue", containerFactory = "batchContainerFactory")
    public void batchReceive(List<Message> messages, Channel channel) throws IOException {
        try {
            // 批量处理
            for (Message message : messages) {
                processMessage(message);
            }
            
            // 批量确认（确认最后一条消息，multiple=true）
            long lastTag = messages.get(messages.size() - 1)
                    .getMessageProperties().getDeliveryTag();
            channel.basicAck(lastTag, true);
            
        } catch (Exception e) {
            // 批量拒绝
            long lastTag = messages.get(messages.size() - 1)
                    .getMessageProperties().getDeliveryTag();
            channel.basicNack(lastTag, true, true);
        }
    }
    
    private void processMessage(Message message) {
        // 处理逻辑
    }
}

@Configuration
public class BatchConsumerConfig {
    
    @Bean
    public SimpleRabbitListenerContainerFactory batchContainerFactory(
            ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setBatchListener(true);
        factory.setBatchSize(10);
        factory.setConsumerBatchEnabled(true);
        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        return factory;
    }
}
```

### 12.3 连接池优化

```java
@Configuration
public class ConnectionPoolConfig {
    
    @Bean
    public ConnectionFactory connectionFactory() {
        CachingConnectionFactory factory = new CachingConnectionFactory();
        factory.setHost("localhost");
        factory.setPort(5672);
        factory.setUsername("admin");
        factory.setPassword("admin123");
        
        // 连接缓存模式
        factory.setCacheMode(CachingConnectionFactory.CacheMode.CHANNEL);
        
        // 通道缓存大小
        factory.setChannelCacheSize(50);
        
        // 连接缓存大小（CONNECTION 模式下有效）
        // factory.setConnectionCacheSize(10);
        
        // 通道检查间隔
        factory.setChannelCheckoutTimeout(10000);
        
        return factory;
    }
}
```

### 12.4 队列优化

```java
@Configuration
public class QueueOptimizationConfig {
    
    /**
     * 惰性队列：消息直接写入磁盘，减少内存使用
     * 适用于消息量大、消费速度慢的场景
     */
    @Bean
    public Queue lazyQueue() {
        return QueueBuilder
                .durable("lazy.queue")
                .lazy()
                .build();
    }
    
    /**
     * 设置队列最大长度
     */
    @Bean
    public Queue limitedQueue() {
        return QueueBuilder
                .durable("limited.queue")
                .maxLength(10000)           // 最大消息数
                .maxLengthBytes(104857600)  // 最大字节数（100MB）
                .overflow(QueueBuilder.Overflow.rejectPublish) // 溢出策略
                .build();
    }
    
    /**
     * 设置消息 TTL
     */
    @Bean
    public Queue ttlQueue() {
        return QueueBuilder
                .durable("ttl.queue")
                .ttl(60000)  // 消息过期时间（毫秒）
                .build();
    }
}
```

### 12.5 性能监控

```java
@Component
@Slf4j
public class RabbitMQMetrics {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    /**
     * 获取队列消息数量
     */
    public long getQueueMessageCount(String queueName) {
        return rabbitTemplate.execute(channel -> {
            AMQP.Queue.DeclareOk declareOk = channel.queueDeclarePassive(queueName);
            return (long) declareOk.getMessageCount();
        });
    }
    
    /**
     * 获取队列消费者数量
     */
    public long getQueueConsumerCount(String queueName) {
        return rabbitTemplate.execute(channel -> {
            AMQP.Queue.DeclareOk declareOk = channel.queueDeclarePassive(queueName);
            return (long) declareOk.getConsumerCount();
        });
    }
    
    /**
     * 定时监控
     */
    @Scheduled(fixedRate = 60000)
    public void monitorQueues() {
        List<String> queues = Arrays.asList("order.queue", "payment.queue", "notification.queue");
        
        for (String queue : queues) {
            try {
                long messageCount = getQueueMessageCount(queue);
                long consumerCount = getQueueConsumerCount(queue);
                
                log.info("队列监控 - {}: 消息数={}, 消费者数={}", 
                        queue, messageCount, consumerCount);
                
                // 告警逻辑
                if (messageCount > 10000) {
                    log.warn("队列 {} 消息积压: {}", queue, messageCount);
                }
            } catch (Exception e) {
                log.error("监控队列 {} 失败: {}", queue, e.getMessage());
            }
        }
    }
}
```

---

## 13. 监控与管理

### 13.1 管理界面

RabbitMQ 提供了 Web 管理界面，访问 `http://localhost:15672`。

**主要功能：**
- 查看队列、交换机、绑定关系
- 查看连接、通道
- 查看消息速率
- 手动发送/接收消息
- 用户和权限管理

### 13.2 HTTP API

RabbitMQ 提供了 HTTP API，可以通过编程方式管理。

```java
@Service
public class RabbitMQAdminService {
    
    private final RestTemplate restTemplate;
    private final String baseUrl = "http://localhost:15672/api";
    private final String username = "admin";
    private final String password = "admin123";
    
    public RabbitMQAdminService() {
        this.restTemplate = new RestTemplate();
    }
    
    /**
     * 获取所有队列信息
     */
    public List<Map> getQueues() {
        String url = baseUrl + "/queues";
        HttpHeaders headers = createAuthHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<List> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, List.class);
        return response.getBody();
    }
    
    /**
     * 获取队列详情
     */
    public Map getQueueInfo(String vhost, String queueName) {
        String url = baseUrl + "/queues/" + encodeVhost(vhost) + "/" + queueName;
        HttpHeaders headers = createAuthHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<Map> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, Map.class);
        return response.getBody();
    }
    
    /**
     * 删除队列
     */
    public void deleteQueue(String vhost, String queueName) {
        String url = baseUrl + "/queues/" + encodeVhost(vhost) + "/" + queueName;
        HttpHeaders headers = createAuthHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        restTemplate.exchange(url, HttpMethod.DELETE, entity, Void.class);
    }
    
    /**
     * 清空队列
     */
    public void purgeQueue(String vhost, String queueName) {
        String url = baseUrl + "/queues/" + encodeVhost(vhost) + "/" + queueName + "/contents";
        HttpHeaders headers = createAuthHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        restTemplate.exchange(url, HttpMethod.DELETE, entity, Void.class);
    }
    
    private HttpHeaders createAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        String auth = username + ":" + password;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        headers.set("Authorization", "Basic " + encodedAuth);
        return headers;
    }
    
    private String encodeVhost(String vhost) {
        return "/".equals(vhost) ? "%2F" : vhost;
    }
}
```

### 13.3 Prometheus + Grafana 监控

```yaml
# docker-compose.yml 添加监控组件
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
```

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rabbitmq'
    static_configs:
      - targets: ['rabbitmq:15692']
    metrics_path: /metrics
```

启用 RabbitMQ Prometheus 插件：

```bash
rabbitmq-plugins enable rabbitmq_prometheus
```


---

## 14. 常见错误与解决方案

### 14.1 连接失败

**错误信息：**
```
org.springframework.amqp.AmqpConnectException: java.net.ConnectException: Connection refused
```

**原因：**
1. RabbitMQ 服务未启动
2. 连接地址或端口错误
3. 防火墙阻止连接

**解决方案：**
```bash
# 检查服务状态
rabbitmqctl status

# 检查端口
netstat -tlnp | grep 5672

# 检查防火墙
firewall-cmd --list-ports
firewall-cmd --add-port=5672/tcp --permanent
firewall-cmd --reload
```

### 14.2 认证失败

**错误信息：**
```
com.rabbitmq.client.AuthenticationFailureException: ACCESS_REFUSED
```

**原因：**
1. 用户名或密码错误
2. 用户没有访问虚拟主机的权限

**解决方案：**
```bash
# 检查用户
rabbitmqctl list_users

# 添加用户
rabbitmqctl add_user admin admin123
rabbitmqctl set_user_tags admin administrator

# 设置权限
rabbitmqctl set_permissions -p / admin ".*" ".*" ".*"
```

### 14.3 队列不存在

**错误信息：**
```
com.rabbitmq.client.ShutdownSignalException: channel error; 
protocol method: #method<channel.close>(reply-code=404, reply-text=NOT_FOUND - no queue 'xxx')
```

**原因：**
1. 队列未声明
2. 队列名称拼写错误
3. 队列被删除

**解决方案：**
```java
// 确保队列在配置类中声明
@Bean
public Queue myQueue() {
    return new Queue("my.queue", true);
}

// 或使用注解声明
@RabbitListener(queuesToDeclare = @Queue("my.queue"))
public void receive(String message) {
    // ...
}
```

### 14.4 消息序列化失败

**错误信息：**
```
org.springframework.amqp.support.converter.MessageConversionException: 
failed to convert Message content
```

**原因：**
1. 消息格式与转换器不匹配
2. 消息类缺少无参构造函数
3. 消息类未实现 Serializable

**解决方案：**
```java
// 1. 配置 JSON 消息转换器
@Bean
public MessageConverter messageConverter() {
    return new Jackson2JsonMessageConverter();
}

// 2. 确保消息类有无参构造函数
@Data
@NoArgsConstructor
@AllArgsConstructor
public class OrderMessage implements Serializable {
    private Long orderId;
    private String orderNo;
}

// 3. 手动处理消息
@RabbitListener(queues = "my.queue")
public void receive(Message message) {
    String content = new String(message.getBody());
    OrderMessage order = JSON.parseObject(content, OrderMessage.class);
}
```

### 14.5 消息确认超时

**错误信息：**
```
org.springframework.amqp.rabbit.listener.exception.ListenerExecutionFailedException: 
Listener threw exception
```

**原因：**
1. 消费者处理时间过长
2. 未正确确认消息
3. 连接断开

**解决方案：**
```yaml
spring:
  rabbitmq:
    listener:
      simple:
        # 增加预取数量
        prefetch: 1
        # 设置确认超时
        default-requeue-rejected: false
    # 增加连接超时
    connection-timeout: 60000
    # 心跳检测
    requested-heartbeat: 30
```

```java
// 确保正确确认消息
@RabbitListener(queues = "my.queue")
public void receive(Message message, Channel channel) throws IOException {
    long tag = message.getMessageProperties().getDeliveryTag();
    try {
        // 业务处理
        processMessage(message);
        // 必须确认
        channel.basicAck(tag, false);
    } catch (Exception e) {
        // 异常时也要处理
        channel.basicNack(tag, false, false);
    }
}
```

### 14.6 消息积压

**现象：** 队列中消息数量持续增长，消费速度跟不上生产速度。

**原因：**
1. 消费者处理速度慢
2. 消费者数量不足
3. 消费者异常导致消息重复入队

**解决方案：**
```yaml
spring:
  rabbitmq:
    listener:
      simple:
        # 增加并发消费者
        concurrency: 10
        max-concurrency: 50
        # 增加预取数量
        prefetch: 10
```

```java
// 优化消费者处理逻辑
@RabbitListener(queues = "my.queue", concurrency = "5-20")
public void receive(String message) {
    // 异步处理
    CompletableFuture.runAsync(() -> processMessage(message));
}

// 或使用批量消费
@RabbitListener(queues = "my.queue", containerFactory = "batchContainerFactory")
public void batchReceive(List<String> messages) {
    // 批量处理
    messages.parallelStream().forEach(this::processMessage);
}
```

### 14.7 消息丢失

**原因：**
1. 消息未持久化
2. 消费者自动确认但处理失败
3. RabbitMQ 宕机

**解决方案：**
```java
// 1. 消息持久化
@Bean
public Queue durableQueue() {
    return QueueBuilder.durable("durable.queue").build();
}

// 2. 手动确认
@RabbitListener(queues = "my.queue", ackMode = "MANUAL")
public void receive(Message message, Channel channel) throws IOException {
    long tag = message.getMessageProperties().getDeliveryTag();
    try {
        processMessage(message);
        channel.basicAck(tag, false);
    } catch (Exception e) {
        channel.basicNack(tag, false, true);
    }
}

// 3. 发布确认
@Bean
public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
    RabbitTemplate template = new RabbitTemplate(connectionFactory);
    template.setConfirmCallback((data, ack, cause) -> {
        if (!ack) {
            // 记录失败消息，重试
            log.error("消息发送失败: {}", cause);
        }
    });
    return template;
}
```

### 14.8 重复消费

**原因：**
1. 消费者处理成功但确认失败
2. 网络问题导致消息重新入队
3. 消费者重启

**解决方案：**
```java
// 实现幂等性
@RabbitListener(queues = "my.queue")
public void receive(OrderMessage message, Channel channel,
                   @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
    String messageId = message.getMessageId();
    
    // 检查是否已处理
    if (idempotentService.isProcessed(messageId)) {
        channel.basicAck(tag, false);
        return;
    }
    
    try {
        // 业务处理
        processOrder(message);
        // 标记已处理
        idempotentService.markProcessed(messageId);
        channel.basicAck(tag, false);
    } catch (Exception e) {
        channel.basicNack(tag, false, false);
    }
}
```

### 14.9 内存溢出

**错误信息：**
```
{resource_limit_exceeded, memory}
```

**原因：**
1. 消息积压过多
2. 消息体过大
3. 内存配置不足

**解决方案：**
```bash
# 调整内存阈值
rabbitmqctl set_vm_memory_high_watermark 0.6

# 或在配置文件中设置
# rabbitmq.conf
vm_memory_high_watermark.relative = 0.6
vm_memory_high_watermark_paging_ratio = 0.75
```

```java
// 使用惰性队列
@Bean
public Queue lazyQueue() {
    return QueueBuilder
            .durable("lazy.queue")
            .lazy()  // 消息直接写入磁盘
            .maxLength(100000)
            .build();
}
```

### 14.10 通道关闭异常

**错误信息：**
```
com.rabbitmq.client.ShutdownSignalException: channel error
```

**原因：**
1. 操作了不存在的队列/交换机
2. 权限不足
3. 参数不匹配

**解决方案：**
```java
// 使用 passive 声明检查队列是否存在
public boolean queueExists(String queueName) {
    try {
        rabbitTemplate.execute(channel -> {
            channel.queueDeclarePassive(queueName);
            return true;
        });
        return true;
    } catch (Exception e) {
        return false;
    }
}

// 捕获异常
@RabbitListener(queues = "my.queue")
public void receive(Message message, Channel channel) {
    try {
        // 业务处理
    } catch (ShutdownSignalException e) {
        log.error("通道关闭: {}", e.getMessage());
        // 重新建立连接
    }
}
```


---

## 15. 最佳实践

### 15.1 消息设计

```java
/**
 * 消息基类
 */
@Data
public abstract class BaseMessage implements Serializable {
    
    /**
     * 消息ID（用于幂等性判断）
     */
    private String messageId;
    
    /**
     * 消息类型
     */
    private String messageType;
    
    /**
     * 创建时间
     */
    private LocalDateTime createTime;
    
    /**
     * 业务ID（用于追踪）
     */
    private String businessId;
    
    /**
     * 来源系统
     */
    private String source;
    
    public BaseMessage() {
        this.messageId = UUID.randomUUID().toString();
        this.createTime = LocalDateTime.now();
    }
}

/**
 * 订单消息
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class OrderMessage extends BaseMessage {
    
    private Long orderId;
    private String orderNo;
    private BigDecimal amount;
    private Integer status;
    private Long userId;
    
    public OrderMessage() {
        super();
        this.setMessageType("ORDER");
    }
}
```

### 15.2 统一消息发送服务

```java
@Service
@Slf4j
public class MessageSendService {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    @Autowired
    private MessageLogService messageLogService;
    
    /**
     * 发送消息（带重试和日志）
     */
    public <T extends BaseMessage> boolean send(String exchange, String routingKey, T message) {
        String messageId = message.getMessageId();
        
        try {
            // 1. 记录消息日志
            messageLogService.saveLog(messageId, exchange, routingKey, message, "SENDING");
            
            // 2. 发送消息
            CorrelationData correlationData = new CorrelationData(messageId);
            
            rabbitTemplate.convertAndSend(exchange, routingKey, message, msg -> {
                msg.getMessageProperties().setMessageId(messageId);
                msg.getMessageProperties().setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                return msg;
            }, correlationData);
            
            // 3. 更新日志状态
            messageLogService.updateStatus(messageId, "SENT");
            
            log.info("消息发送成功: messageId={}, exchange={}, routingKey={}", 
                    messageId, exchange, routingKey);
            return true;
            
        } catch (Exception e) {
            log.error("消息发送失败: messageId={}, error={}", messageId, e.getMessage(), e);
            messageLogService.updateStatus(messageId, "FAILED", e.getMessage());
            return false;
        }
    }
    
    /**
     * 发送延迟消息
     */
    public <T extends BaseMessage> boolean sendDelay(String exchange, String routingKey, 
                                                      T message, long delayMs) {
        String messageId = message.getMessageId();
        
        try {
            rabbitTemplate.convertAndSend(exchange, routingKey, message, msg -> {
                msg.getMessageProperties().setMessageId(messageId);
                msg.getMessageProperties().setDelay((int) delayMs);
                return msg;
            });
            
            log.info("延迟消息发送成功: messageId={}, delay={}ms", messageId, delayMs);
            return true;
            
        } catch (Exception e) {
            log.error("延迟消息发送失败: {}", e.getMessage(), e);
            return false;
        }
    }
}
```

### 15.3 统一消息消费基类

```java
/**
 * 消息消费基类
 */
@Slf4j
public abstract class BaseMessageConsumer<T extends BaseMessage> {
    
    @Autowired
    protected IdempotentService idempotentService;
    
    /**
     * 处理消息
     */
    protected void handleMessage(T message, Channel channel, long deliveryTag) throws IOException {
        String messageId = message.getMessageId();
        
        try {
            // 1. 幂等性检查
            if (!idempotentService.tryAcquire(messageId)) {
                log.info("消息已处理，跳过: {}", messageId);
                channel.basicAck(deliveryTag, false);
                return;
            }
            
            // 2. 业务处理
            doHandle(message);
            
            // 3. 标记成功
            idempotentService.markSuccess(messageId);
            channel.basicAck(deliveryTag, false);
            
            log.info("消息处理成功: {}", messageId);
            
        } catch (BusinessException e) {
            // 业务异常，不重试
            log.error("业务处理失败: {}", e.getMessage());
            idempotentService.markFailed(messageId);
            channel.basicReject(deliveryTag, false);
            
        } catch (Exception e) {
            // 其他异常，可重试
            log.error("消息处理异常: {}", e.getMessage(), e);
            idempotentService.markFailed(messageId);
            
            // 判断重试次数
            if (getRetryCount(message) < getMaxRetryCount()) {
                channel.basicNack(deliveryTag, false, true);
            } else {
                channel.basicReject(deliveryTag, false);
            }
        }
    }
    
    /**
     * 具体业务处理（子类实现）
     */
    protected abstract void doHandle(T message) throws Exception;
    
    /**
     * 获取最大重试次数
     */
    protected int getMaxRetryCount() {
        return 3;
    }
    
    /**
     * 获取当前重试次数
     */
    protected int getRetryCount(T message) {
        // 可以从消息头中获取
        return 0;
    }
}

/**
 * 订单消息消费者
 */
@Component
@Slf4j
public class OrderMessageConsumer extends BaseMessageConsumer<OrderMessage> {
    
    @Autowired
    private OrderService orderService;
    
    @RabbitListener(queues = "order.queue")
    public void receive(OrderMessage message, Channel channel,
                       @Header(AmqpHeaders.DELIVERY_TAG) long tag) throws IOException {
        handleMessage(message, channel, tag);
    }
    
    @Override
    protected void doHandle(OrderMessage message) throws Exception {
        orderService.processOrder(message);
    }
}
```

### 15.4 配置规范

```yaml
# application.yml
spring:
  rabbitmq:
    host: ${RABBITMQ_HOST:localhost}
    port: ${RABBITMQ_PORT:5672}
    username: ${RABBITMQ_USERNAME:admin}
    password: ${RABBITMQ_PASSWORD:admin123}
    virtual-host: ${RABBITMQ_VHOST:/}
    
    # 发布确认
    publisher-confirm-type: correlated
    publisher-returns: true
    
    # 消费者配置
    listener:
      simple:
        acknowledge-mode: manual
        prefetch: 10
        concurrency: 5
        max-concurrency: 20
        retry:
          enabled: true
          initial-interval: 1000
          max-attempts: 3
          max-interval: 10000
          multiplier: 2
    
    # 模板配置
    template:
      mandatory: true
      retry:
        enabled: true
        initial-interval: 1000
        max-attempts: 3
        max-interval: 10000
        multiplier: 2

# 自定义配置
rabbitmq:
  exchange:
    order: order.exchange
    payment: payment.exchange
    notification: notification.exchange
  queue:
    order: order.queue
    payment: payment.queue
    notification: notification.queue
  routing-key:
    order-create: order.create
    order-cancel: order.cancel
    payment-success: payment.success
```

### 15.5 异常处理

```java
@Configuration
public class RabbitMQErrorConfig {
    
    /**
     * 全局错误处理器
     */
    @Bean
    public RabbitListenerErrorHandler rabbitListenerErrorHandler() {
        return (message, channel, exception) -> {
            log.error("消息处理异常: {}", exception.getMessage(), exception);
            
            // 可以在这里发送告警
            // alertService.sendAlert("RabbitMQ消息处理异常", exception.getMessage());
            
            throw exception;
        };
    }
    
    /**
     * 自定义错误处理器
     */
    @Bean
    public ErrorHandler errorHandler() {
        return new ConditionalRejectingErrorHandler(new CustomFatalExceptionStrategy());
    }
    
    /**
     * 自定义致命异常策略
     */
    public static class CustomFatalExceptionStrategy extends ConditionalRejectingErrorHandler.DefaultExceptionStrategy {
        
        @Override
        public boolean isFatal(Throwable t) {
            // 业务异常不重试
            if (t.getCause() instanceof BusinessException) {
                return true;
            }
            // 消息格式错误不重试
            if (t.getCause() instanceof MessageConversionException) {
                return true;
            }
            return super.isFatal(t);
        }
    }
}
```

### 15.6 命名规范

```
交换机命名：{业务}.exchange 或 {业务}.{类型}.exchange
  例：order.exchange, order.direct.exchange, order.topic.exchange

队列命名：{业务}.queue 或 {业务}.{功能}.queue
  例：order.queue, order.create.queue, order.cancel.queue

路由键命名：{业务}.{动作} 或 {业务}.{子业务}.{动作}
  例：order.create, order.pay.success, order.pay.fail

死信交换机：{业务}.dlx.exchange
死信队列：{业务}.dlx.queue
延迟交换机：{业务}.delay.exchange
延迟队列：{业务}.delay.queue
```

### 15.7 项目结构

```
src/main/java/com/example/
├── config/
│   ├── RabbitMQConfig.java          # 基础配置
│   ├── OrderQueueConfig.java        # 订单队列配置
│   ├── PaymentQueueConfig.java      # 支付队列配置
│   └── DeadLetterConfig.java        # 死信队列配置
├── message/
│   ├── BaseMessage.java             # 消息基类
│   ├── OrderMessage.java            # 订单消息
│   └── PaymentMessage.java          # 支付消息
├── producer/
│   ├── MessageSendService.java      # 统一发送服务
│   ├── OrderProducer.java           # 订单生产者
│   └── PaymentProducer.java         # 支付生产者
├── consumer/
│   ├── BaseMessageConsumer.java     # 消费者基类
│   ├── OrderConsumer.java           # 订单消费者
│   └── PaymentConsumer.java         # 支付消费者
└── service/
    ├── IdempotentService.java       # 幂等性服务
    └── MessageLogService.java       # 消息日志服务
```

---

## 总结

RabbitMQ 是一个功能强大的消息队列中间件，通过本笔记的学习，你应该能够：

1. **理解核心概念**：掌握 Exchange、Queue、Binding、Routing Key 等核心概念
2. **熟练使用**：能够在 Spring Boot 项目中集成和使用 RabbitMQ
3. **掌握消息模型**：了解简单模式、工作队列、发布订阅、路由、主题等模式
4. **保证可靠性**：通过消息确认、持久化、死信队列等机制保证消息不丢失
5. **实现延迟队列**：使用死信队列或插件实现延迟消息
6. **保证幂等性**：通过数据库或 Redis 实现消息消费的幂等性
7. **高可用部署**：了解集群、镜像队列、仲裁队列等高可用方案
8. **性能优化**：掌握生产者、消费者、队列的优化技巧
9. **问题排查**：能够识别和解决常见的 RabbitMQ 问题

**推荐资源：**
- [RabbitMQ 官方文档](https://www.rabbitmq.com/documentation.html)
- [Spring AMQP 文档](https://docs.spring.io/spring-amqp/docs/current/reference/html/)
- [RabbitMQ 中文社区](https://rabbitmq.mr-ping.com/)