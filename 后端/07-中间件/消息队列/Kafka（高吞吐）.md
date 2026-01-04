

> Apache Kafka 是一个分布式流处理平台，以高吞吐、低延迟著称
> 本笔记基于 Java 17 + Spring Boot 3.2.12 + Kafka 3.x

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与部署](#2-安装与部署)
3. [Spring Boot 集成](#3-spring-boot-集成)
4. [生产者](#4-生产者)
5. [消费者](#5-消费者)
6. [消息序列化](#6-消息序列化)
7. [分区与副本](#7-分区与副本)
8. [消费者组](#8-消费者组)
9. [事务消息](#9-事务消息)
10. [消息可靠性](#10-消息可靠性)
11. [性能优化](#11-性能优化)
12. [监控与运维](#12-监控与运维)
13. [Kafka Streams](#13-kafka-streams)
14. [最佳实践](#14-最佳实践)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Kafka？

Kafka 最初由 LinkedIn 开发，后成为 Apache 顶级项目。它是一个分布式的、基于发布/订阅模式的消息系统，主要用于：

- **消息队列**：解耦系统、异步处理、削峰填谷
- **日志收集**：收集各服务日志，统一处理
- **流处理**：实时数据处理和分析
- **事件溯源**：记录状态变化的完整历史

**Kafka 的特点：**
- **高吞吐**：单机可达百万级 TPS
- **低延迟**：毫秒级延迟
- **高可用**：分布式架构，支持副本
- **持久化**：消息持久化到磁盘
- **可扩展**：水平扩展能力强

### 1.2 核心概念

```
┌─────────────────────────────────────────────────────────────┐
│                      Kafka Cluster                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Topic: orders                     │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐         │   │
│  │  │Partition 0│ │Partition 1│ │Partition 2│         │   │
│  │  │ [0,1,2,3] │ │ [0,1,2]   │ │ [0,1,2,3,4]│        │   │
│  │  └───────────┘ └───────────┘ └───────────┘         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Broker 0          Broker 1          Broker 2              │
└─────────────────────────────────────────────────────────────┘
        ↑                                    ↓
   ┌─────────┐                        ┌─────────────┐
   │Producer │                        │Consumer Group│
   └─────────┘                        │ Consumer 1  │
                                      │ Consumer 2  │
                                      └─────────────┘
```

**核心术语：**

| 术语 | 说明 |
|------|------|
| Broker | Kafka 服务器节点 |
| Topic | 消息主题，逻辑分类 |
| Partition | 分区，Topic 的物理分片 |
| Replica | 副本，分区的备份 |
| Producer | 生产者，发送消息 |
| Consumer | 消费者，接收消息 |
| Consumer Group | 消费者组，多个消费者协同消费 |
| Offset | 偏移量，消息在分区中的位置 |
| Leader | 主副本，处理读写请求 |
| Follower | 从副本，同步数据 |

### 1.3 Kafka vs 其他 MQ

| 特性 | Kafka | RabbitMQ | RocketMQ |
|------|-------|----------|----------|
| 吞吐量 | 百万级 | 万级 | 十万级 |
| 延迟 | 毫秒 | 微秒 | 毫秒 |
| 可用性 | 高 | 高 | 非常高 |
| 消息可靠性 | 高 | 高 | 非常高 |
| 功能丰富度 | 中 | 高 | 高 |
| 适用场景 | 日志、大数据 | 业务消息 | 电商、金融 |

---

## 2. 安装与部署

### 2.1 Docker 部署（推荐开发环境）

```yaml
# docker-compose.yml
version: '3.8'

services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - "2181:2181"

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    depends_on:
      - zookeeper
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"

  # 可选：Kafka UI
  kafka-ui:
    image: provectuslabs/kafka-ui:latest
    ports:
      - "8080:8080"
    environment:
      KAFKA_CLUSTERS_0_NAME: local
      KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS: kafka:9092
      KAFKA_CLUSTERS_0_ZOOKEEPER: zookeeper:2181
```

```bash
# 启动
docker-compose up -d

# 查看日志
docker-compose logs -f kafka
```

### 2.2 KRaft 模式（无 Zookeeper）

Kafka 3.x 支持 KRaft 模式，不再依赖 Zookeeper。

```yaml
# docker-compose-kraft.yml
version: '3.8'

services:
  kafka:
    image: confluentinc/cp-kafka:7.5.0
    ports:
      - "9092:9092"
    environment:
      KAFKA_NODE_ID: 1
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_LISTENERS: PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      CLUSTER_ID: MkU3OEVBNTcwNTJENDM2Qk
```

### 2.3 常用命令

```bash
# 进入 Kafka 容器
docker exec -it kafka bash

# 创建 Topic
kafka-topics --create --topic my-topic \
  --bootstrap-server localhost:9092 \
  --partitions 3 \
  --replication-factor 1

# 查看 Topic 列表
kafka-topics --list --bootstrap-server localhost:9092

# 查看 Topic 详情
kafka-topics --describe --topic my-topic \
  --bootstrap-server localhost:9092

# 删除 Topic
kafka-topics --delete --topic my-topic \
  --bootstrap-server localhost:9092

# 发送消息
kafka-console-producer --topic my-topic \
  --bootstrap-server localhost:9092

# 消费消息
kafka-console-consumer --topic my-topic \
  --bootstrap-server localhost:9092 \
  --from-beginning

# 查看消费者组
kafka-consumer-groups --list \
  --bootstrap-server localhost:9092

# 查看消费者组详情
kafka-consumer-groups --describe --group my-group \
  --bootstrap-server localhost:9092
```

---

## 3. Spring Boot 集成

### 3.1 Maven 依赖

```xml
<dependencies>
    <!-- Spring Kafka -->
    <dependency>
        <groupId>org.springframework.kafka</groupId>
        <artifactId>spring-kafka</artifactId>
    </dependency>
    
    <!-- JSON 序列化 -->
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
    </dependency>
    
    <!-- 测试 -->
    <dependency>
        <groupId>org.springframework.kafka</groupId>
        <artifactId>spring-kafka-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

### 3.2 基础配置

```yaml
# application.yml
spring:
  kafka:
    bootstrap-servers: localhost:9092
    
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer
      acks: all
      retries: 3
      batch-size: 16384
      buffer-memory: 33554432
      properties:
        linger.ms: 10
    
    consumer:
      group-id: my-group
      auto-offset-reset: earliest
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      enable-auto-commit: false
      properties:
        spring.json.trusted.packages: "*"
    
    listener:
      ack-mode: manual
      concurrency: 3
```

### 3.3 快速开始示例

```java
// 消息实体
public record OrderMessage(
    String orderId,
    String userId,
    BigDecimal amount,
    LocalDateTime createTime
) {}

// 生产者
@Service
@RequiredArgsConstructor
public class OrderProducer {
    
    private final KafkaTemplate<String, OrderMessage> kafkaTemplate;
    
    public void sendOrder(OrderMessage order) {
        kafkaTemplate.send("orders", order.orderId(), order);
    }
}

// 消费者
@Service
@Slf4j
public class OrderConsumer {
    
    @KafkaListener(topics = "orders", groupId = "order-service")
    public void consume(OrderMessage order, Acknowledgment ack) {
        log.info("Received order: {}", order);
        // 处理订单
        ack.acknowledge();
    }
}

// 启动类
@SpringBootApplication
public class KafkaApplication {
    public static void main(String[] args) {
        SpringApplication.run(KafkaApplication.class, args);
    }
}
```

---

## 4. 生产者

### 4.1 KafkaTemplate 详解

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class MessageProducer {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    
    // 基本发送
    public void send(String topic, Object message) {
        kafkaTemplate.send(topic, message);
    }
    
    // 指定 Key
    public void sendWithKey(String topic, String key, Object message) {
        kafkaTemplate.send(topic, key, message);
    }
    
    // 指定分区
    public void sendToPartition(String topic, int partition, String key, Object message) {
        kafkaTemplate.send(topic, partition, key, message);
    }
    
    // 同步发送（等待结果）
    public void sendSync(String topic, Object message) {
        try {
            SendResult<String, Object> result = kafkaTemplate.send(topic, message).get();
            RecordMetadata metadata = result.getRecordMetadata();
            log.info("Sent to partition {} with offset {}", 
                    metadata.partition(), metadata.offset());
        } catch (Exception e) {
            log.error("Send failed", e);
            throw new RuntimeException(e);
        }
    }
    
    // 异步发送（带回调）
    public void sendAsync(String topic, Object message) {
        CompletableFuture<SendResult<String, Object>> future = 
            kafkaTemplate.send(topic, message);
        
        future.whenComplete((result, ex) -> {
            if (ex == null) {
                RecordMetadata metadata = result.getRecordMetadata();
                log.info("Sent successfully to {}:{}", 
                        metadata.topic(), metadata.partition());
            } else {
                log.error("Send failed", ex);
            }
        });
    }
    
    // 发送到指定时间戳
    public void sendWithTimestamp(String topic, Object message, long timestamp) {
        ProducerRecord<String, Object> record = new ProducerRecord<>(
            topic, null, timestamp, null, message
        );
        kafkaTemplate.send(record);
    }
    
    // 发送带 Header 的消息
    public void sendWithHeaders(String topic, Object message, Map<String, String> headers) {
        ProducerRecord<String, Object> record = new ProducerRecord<>(topic, message);
        headers.forEach((key, value) -> 
            record.headers().add(key, value.getBytes(StandardCharsets.UTF_8))
        );
        kafkaTemplate.send(record);
    }
}
```

### 4.2 生产者配置详解

```java
@Configuration
public class KafkaProducerConfig {
    
    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;
    
    @Bean
    public ProducerFactory<String, Object> producerFactory() {
        Map<String, Object> props = new HashMap<>();
        
        // 基础配置
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        
        // 可靠性配置
        props.put(ProducerConfig.ACKS_CONFIG, "all");  // 所有副本确认
        props.put(ProducerConfig.RETRIES_CONFIG, 3);   // 重试次数
        props.put(ProducerConfig.RETRY_BACKOFF_MS_CONFIG, 1000);  // 重试间隔
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);  // 幂等性
        
        // 性能配置
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, 16384);  // 批量大小
        props.put(ProducerConfig.LINGER_MS_CONFIG, 10);  // 等待时间
        props.put(ProducerConfig.BUFFER_MEMORY_CONFIG, 33554432);  // 缓冲区大小
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, "snappy");  // 压缩
        
        // 超时配置
        props.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 30000);
        props.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 120000);
        
        return new DefaultKafkaProducerFactory<>(props);
    }
    
    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}
```

### 4.3 自定义分区策略

```java
// 自定义分区器
public class OrderPartitioner implements Partitioner {
    
    @Override
    public int partition(String topic, Object key, byte[] keyBytes, 
                         Object value, byte[] valueBytes, Cluster cluster) {
        List<PartitionInfo> partitions = cluster.partitionsForTopic(topic);
        int numPartitions = partitions.size();
        
        if (key == null) {
            // 无 Key 时轮询
            return ThreadLocalRandom.current().nextInt(numPartitions);
        }
        
        // 根据 Key 哈希分区
        return Math.abs(key.hashCode()) % numPartitions;
    }
    
    @Override
    public void close() {}
    
    @Override
    public void configure(Map<String, ?> configs) {}
}

// 配置使用
props.put(ProducerConfig.PARTITIONER_CLASS_CONFIG, OrderPartitioner.class);
```

---

## 5. 消费者

### 5.1 @KafkaListener 详解

```java
@Service
@Slf4j
public class MessageConsumer {
    
    // 基本消费
    @KafkaListener(topics = "my-topic", groupId = "my-group")
    public void consume(String message) {
        log.info("Received: {}", message);
    }
    
    // 消费对象
    @KafkaListener(topics = "orders", groupId = "order-group")
    public void consumeOrder(OrderMessage order) {
        log.info("Received order: {}", order);
    }
    
    // 手动确认
    @KafkaListener(topics = "orders", groupId = "order-group")
    public void consumeWithAck(OrderMessage order, Acknowledgment ack) {
        try {
            processOrder(order);
            ack.acknowledge();  // 手动确认
        } catch (Exception e) {
            log.error("Process failed", e);
            // 不确认，消息会重新投递
        }
    }
    
    // 获取完整消息信息
    @KafkaListener(topics = "orders", groupId = "order-group")
    public void consumeWithMetadata(
            @Payload OrderMessage order,
            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic,
            @Header(KafkaHeaders.RECEIVED_PARTITION) int partition,
            @Header(KafkaHeaders.OFFSET) long offset,
            @Header(KafkaHeaders.RECEIVED_TIMESTAMP) long timestamp) {
        
        log.info("Received from {}:{} at offset {}", topic, partition, offset);
        log.info("Order: {}", order);
    }
    
    // 使用 ConsumerRecord
    @KafkaListener(topics = "orders", groupId = "order-group")
    public void consumeRecord(ConsumerRecord<String, OrderMessage> record) {
        log.info("Key: {}, Value: {}", record.key(), record.value());
        log.info("Partition: {}, Offset: {}", record.partition(), record.offset());
    }
    
    // 批量消费
    @KafkaListener(topics = "orders", groupId = "order-group", 
                   containerFactory = "batchFactory")
    public void consumeBatch(List<OrderMessage> orders, Acknowledgment ack) {
        log.info("Received {} orders", orders.size());
        orders.forEach(this::processOrder);
        ack.acknowledge();
    }
    
    // 消费多个 Topic
    @KafkaListener(topics = {"topic1", "topic2"}, groupId = "multi-group")
    public void consumeMultiTopics(String message, 
            @Header(KafkaHeaders.RECEIVED_TOPIC) String topic) {
        log.info("Received from {}: {}", topic, message);
    }
    
    // 使用 Topic 模式
    @KafkaListener(topicPattern = "order-.*", groupId = "pattern-group")
    public void consumePattern(String message) {
        log.info("Received: {}", message);
    }
    
    // 指定分区
    @KafkaListener(
        groupId = "partition-group",
        topicPartitions = @TopicPartition(
            topic = "orders",
            partitions = {"0", "1"}
        )
    )
    public void consumePartitions(OrderMessage order) {
        log.info("Received: {}", order);
    }
    
    // 指定初始偏移量
    @KafkaListener(
        groupId = "offset-group",
        topicPartitions = @TopicPartition(
            topic = "orders",
            partitionOffsets = {
                @PartitionOffset(partition = "0", initialOffset = "0"),
                @PartitionOffset(partition = "1", initialOffset = "100")
            }
        )
    )
    public void consumeFromOffset(OrderMessage order) {
        log.info("Received: {}", order);
    }
    
    private void processOrder(OrderMessage order) {
        // 处理订单逻辑
    }
}
```

### 5.2 消费者配置详解

```java
@Configuration
@EnableKafka
public class KafkaConsumerConfig {
    
    @Value("${spring.kafka.bootstrap-servers}")
    private String bootstrapServers;
    
    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        
        // 基础配置
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "my-group");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        
        // 偏移量配置
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        
        // 拉取配置
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 500);
        props.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 300000);
        props.put(ConsumerConfig.FETCH_MIN_BYTES_CONFIG, 1);
        props.put(ConsumerConfig.FETCH_MAX_WAIT_MS_CONFIG, 500);
        
        // 会话配置
        props.put(ConsumerConfig.SESSION_TIMEOUT_MS_CONFIG, 30000);
        props.put(ConsumerConfig.HEARTBEAT_INTERVAL_MS_CONFIG, 10000);
        
        // JSON 反序列化配置
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "*");
        
        return new DefaultKafkaConsumerFactory<>(props);
    }
    
    // 单条消息监听容器
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        factory.setConcurrency(3);  // 并发消费者数量
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL);
        return factory;
    }
    
    // 批量消息监听容器
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> batchFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        factory.setBatchListener(true);  // 启用批量消费
        factory.setConcurrency(3);
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL);
        return factory;
    }
}
```

### 5.3 消费者错误处理

```java
@Configuration
public class KafkaErrorHandlerConfig {
    
    // 错误处理器
    @Bean
    public DefaultErrorHandler errorHandler(KafkaTemplate<String, Object> kafkaTemplate) {
        // 死信队列处理
        DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(
            kafkaTemplate,
            (record, ex) -> new TopicPartition(record.topic() + ".DLT", record.partition())
        );
        
        // 重试配置：最多重试 3 次，间隔 1 秒
        FixedBackOff backOff = new FixedBackOff(1000L, 3L);
        
        DefaultErrorHandler errorHandler = new DefaultErrorHandler(recoverer, backOff);
        
        // 不重试的异常
        errorHandler.addNotRetryableExceptions(
            IllegalArgumentException.class,
            JsonParseException.class
        );
        
        return errorHandler;
    }
    
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory(
            ConsumerFactory<String, Object> consumerFactory,
            DefaultErrorHandler errorHandler) {
        
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory);
        factory.setCommonErrorHandler(errorHandler);
        return factory;
    }
}

// 自定义错误处理
@Service
@Slf4j
public class OrderConsumer {
    
    @KafkaListener(topics = "orders", groupId = "order-group")
    public void consume(OrderMessage order, Acknowledgment ack) {
        try {
            processOrder(order);
            ack.acknowledge();
        } catch (RetryableException e) {
            log.warn("Retryable error, will retry", e);
            throw e;  // 抛出异常触发重试
        } catch (Exception e) {
            log.error("Non-retryable error", e);
            ack.acknowledge();  // 确认消息，避免无限重试
            // 发送到死信队列或记录日志
        }
    }
}
```

---

## 6. 消息序列化

### 6.1 JSON 序列化

```java
// 配置 JSON 序列化
@Configuration
public class KafkaSerializerConfig {
    
    @Bean
    public ProducerFactory<String, Object> producerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        
        // 添加类型信息到 Header
        props.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, true);
        
        return new DefaultKafkaProducerFactory<>(props);
    }
    
    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, JsonDeserializer.class);
        
        // 信任的包
        props.put(JsonDeserializer.TRUSTED_PACKAGES, "com.example.model");
        // 使用 Header 中的类型信息
        props.put(JsonDeserializer.USE_TYPE_INFO_HEADERS, true);
        
        return new DefaultKafkaConsumerFactory<>(props);
    }
}
```

### 6.2 Avro 序列化

```xml
<!-- 依赖 -->
<dependency>
    <groupId>io.confluent</groupId>
    <artifactId>kafka-avro-serializer</artifactId>
    <version>7.5.0</version>
</dependency>
```

```java
// Avro 配置
@Configuration
public class KafkaAvroConfig {
    
    @Bean
    public ProducerFactory<String, GenericRecord> avroProducerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, KafkaAvroSerializer.class);
        props.put("schema.registry.url", "http://localhost:8081");
        
        return new DefaultKafkaProducerFactory<>(props);
    }
}
```

### 6.3 自定义序列化器

```java
// 自定义序列化器
public class OrderSerializer implements Serializer<OrderMessage> {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    public byte[] serialize(String topic, OrderMessage data) {
        if (data == null) return null;
        try {
            return objectMapper.writeValueAsBytes(data);
        } catch (JsonProcessingException e) {
            throw new SerializationException("Error serializing", e);
        }
    }
}

// 自定义反序列化器
public class OrderDeserializer implements Deserializer<OrderMessage> {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    public OrderMessage deserialize(String topic, byte[] data) {
        if (data == null) return null;
        try {
            return objectMapper.readValue(data, OrderMessage.class);
        } catch (IOException e) {
            throw new SerializationException("Error deserializing", e);
        }
    }
}
```

---

## 7. 分区与副本

### 7.1 分区策略

分区是 Kafka 实现高吞吐和并行处理的关键。

```java
// 分区数量建议
// - 分区数 >= 消费者数量
// - 分区数不宜过多（增加管理开销）
// - 一般建议：分区数 = 预期吞吐量 / 单分区吞吐量

// 创建 Topic 时指定分区
@Bean
public NewTopic orderTopic() {
    return TopicBuilder.name("orders")
            .partitions(6)
            .replicas(3)
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000")  // 7天
            .build();
}

// 消息分区规则
// 1. 指定分区：直接发送到指定分区
// 2. 指定 Key：根据 Key 哈希分配分区（相同 Key 总是到同一分区）
// 3. 无 Key：轮询或粘性分区
```

### 7.2 副本机制

```
Topic: orders (3 partitions, 3 replicas)

Broker 0          Broker 1          Broker 2
┌─────────┐      ┌─────────┐      ┌─────────┐
│ P0(L)   │      │ P0(F)   │      │ P0(F)   │
│ P1(F)   │      │ P1(L)   │      │ P1(F)   │
│ P2(F)   │      │ P2(F)   │      │ P2(L)   │
└─────────┘      └─────────┘      └─────────┘

L = Leader（处理读写）
F = Follower（同步数据）
```

```yaml
# 副本配置
spring:
  kafka:
    producer:
      acks: all  # 等待所有副本确认
      properties:
        min.insync.replicas: 2  # 最小同步副本数
```

---

## 8. 消费者组

### 8.1 消费者组机制

消费者组是 Kafka 实现消息广播和负载均衡的核心机制。

```
Topic: orders (3 partitions)

Consumer Group A (3 consumers)
┌─────────────────────────────────────┐
│ Consumer 1 ← Partition 0            │
│ Consumer 2 ← Partition 1            │
│ Consumer 3 ← Partition 2            │
└─────────────────────────────────────┘

Consumer Group B (2 consumers)
┌─────────────────────────────────────┐
│ Consumer 1 ← Partition 0, 1         │
│ Consumer 2 ← Partition 2            │
└─────────────────────────────────────┘

规则：
- 同一消费者组内，一个分区只能被一个消费者消费
- 不同消费者组可以独立消费同一消息
- 消费者数量 > 分区数时，多余消费者空闲
```

### 8.2 再平衡（Rebalance）

```java
// 再平衡监听器
@Component
@Slf4j
public class RebalanceListener implements ConsumerAwareRebalanceListener {
    
    @Override
    public void onPartitionsAssigned(Consumer<?, ?> consumer, 
                                     Collection<TopicPartition> partitions) {
        log.info("Partitions assigned: {}", partitions);
        // 可以在这里恢复消费位置
    }
    
    @Override
    public void onPartitionsRevoked(Consumer<?, ?> consumer, 
                                    Collection<TopicPartition> partitions) {
        log.info("Partitions revoked: {}", partitions);
        // 可以在这里提交偏移量
    }
}

// 配置监听器
@Bean
public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory(
        ConsumerFactory<String, Object> consumerFactory,
        RebalanceListener rebalanceListener) {
    
    ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
        new ConcurrentKafkaListenerContainerFactory<>();
    factory.setConsumerFactory(consumerFactory);
    factory.getContainerProperties().setConsumerRebalanceListener(rebalanceListener);
    return factory;
}
```

---

## 9. 事务消息

### 9.1 生产者事务

```java
@Configuration
public class KafkaTransactionConfig {
    
    @Bean
    public ProducerFactory<String, Object> producerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);
        
        // 事务配置
        props.put(ProducerConfig.TRANSACTIONAL_ID_CONFIG, "tx-");
        props.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);
        props.put(ProducerConfig.ACKS_CONFIG, "all");
        
        return new DefaultKafkaProducerFactory<>(props);
    }
    
    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
    
    @Bean
    public KafkaTransactionManager<String, Object> kafkaTransactionManager() {
        return new KafkaTransactionManager<>(producerFactory());
    }
}
```

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class TransactionalProducer {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    
    // 使用 executeInTransaction
    public void sendInTransaction(List<OrderMessage> orders) {
        kafkaTemplate.executeInTransaction(operations -> {
            for (OrderMessage order : orders) {
                operations.send("orders", order.orderId(), order);
            }
            return true;
        });
    }
    
    // 使用 @Transactional
    @Transactional("kafkaTransactionManager")
    public void sendWithAnnotation(List<OrderMessage> orders) {
        for (OrderMessage order : orders) {
            kafkaTemplate.send("orders", order.orderId(), order);
        }
        // 如果抛出异常，所有消息都会回滚
    }
}
```

### 9.2 消费者事务（Exactly-Once）

```java
@Configuration
public class ExactlyOnceConfig {
    
    @Bean
    public ConsumerFactory<String, Object> consumerFactory() {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(ConsumerConfig.ISOLATION_LEVEL_CONFIG, "read_committed");  // 只读已提交
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        return new DefaultKafkaConsumerFactory<>(props);
    }
    
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, Object> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, Object> factory = 
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL);
        return factory;
    }
}
```

---

## 10. 消息可靠性

### 10.1 生产者可靠性

```yaml
spring:
  kafka:
    producer:
      # acks 配置
      # 0: 不等待确认（可能丢失）
      # 1: Leader 确认（Leader 故障可能丢失）
      # all/-1: 所有 ISR 副本确认（最可靠）
      acks: all
      
      # 重试配置
      retries: 3
      properties:
        retry.backoff.ms: 1000
        delivery.timeout.ms: 120000
        
      # 幂等性（防止重复）
      properties:
        enable.idempotence: true
```

### 10.2 消费者可靠性

```java
@Service
@Slf4j
public class ReliableConsumer {
    
    @KafkaListener(topics = "orders", groupId = "reliable-group")
    public void consume(ConsumerRecord<String, OrderMessage> record, 
                        Acknowledgment ack) {
        try {
            // 1. 处理消息
            processOrder(record.value());
            
            // 2. 处理成功后手动确认
            ack.acknowledge();
            
        } catch (Exception e) {
            log.error("Process failed for offset {}", record.offset(), e);
            // 不确认，消息会重新投递
            // 或者发送到死信队列后确认
        }
    }
    
    // 幂等处理（防止重复消费）
    @KafkaListener(topics = "orders", groupId = "idempotent-group")
    public void consumeIdempotent(ConsumerRecord<String, OrderMessage> record, 
                                   Acknowledgment ack) {
        String messageId = record.key();
        
        // 检查是否已处理
        if (isProcessed(messageId)) {
            log.info("Message {} already processed, skip", messageId);
            ack.acknowledge();
            return;
        }
        
        try {
            processOrder(record.value());
            markAsProcessed(messageId);
            ack.acknowledge();
        } catch (Exception e) {
            log.error("Process failed", e);
        }
    }
}
```

### 10.3 消息不丢失配置总结

```yaml
# 生产者配置
spring:
  kafka:
    producer:
      acks: all
      retries: 3
      properties:
        enable.idempotence: true
        max.in.flight.requests.per.connection: 5

# 消费者配置
    consumer:
      enable-auto-commit: false
      auto-offset-reset: earliest
      properties:
        isolation.level: read_committed

# Broker 配置（server.properties）
# min.insync.replicas=2
# unclean.leader.election.enable=false
```

---

## 11. 性能优化

### 11.1 生产者优化

```yaml
spring:
  kafka:
    producer:
      # 批量发送
      batch-size: 32768          # 32KB
      buffer-memory: 67108864    # 64MB
      properties:
        linger.ms: 20            # 等待时间
        
      # 压缩
      compression-type: lz4      # none, gzip, snappy, lz4, zstd
      
      # 并发
      properties:
        max.in.flight.requests.per.connection: 5
```

```java
// 异步批量发送
@Service
public class BatchProducer {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final List<CompletableFuture<SendResult<String, Object>>> futures = 
        new ArrayList<>();
    
    public void sendBatch(List<OrderMessage> orders) {
        for (OrderMessage order : orders) {
            CompletableFuture<SendResult<String, Object>> future = 
                kafkaTemplate.send("orders", order.orderId(), order);
            futures.add(future);
        }
        
        // 等待所有发送完成
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        futures.clear();
    }
}
```

### 11.2 消费者优化

```yaml
spring:
  kafka:
    consumer:
      # 批量拉取
      max-poll-records: 500
      properties:
        fetch.min.bytes: 1048576     # 1MB
        fetch.max.wait.ms: 500
        
    listener:
      # 并发消费
      concurrency: 6
      type: batch
```

```java
// 批量消费
@KafkaListener(topics = "orders", groupId = "batch-group",
               containerFactory = "batchFactory")
public void consumeBatch(List<ConsumerRecord<String, OrderMessage>> records,
                         Acknowledgment ack) {
    // 批量处理
    List<OrderMessage> orders = records.stream()
            .map(ConsumerRecord::value)
            .toList();
    
    batchProcess(orders);
    ack.acknowledge();
}

// 并行处理
@KafkaListener(topics = "orders", groupId = "parallel-group",
               concurrency = "6")
public void consumeParallel(OrderMessage order, Acknowledgment ack) {
    processOrder(order);
    ack.acknowledge();
}
```

### 11.3 Topic 优化

```java
@Bean
public NewTopic optimizedTopic() {
    return TopicBuilder.name("high-throughput-topic")
            .partitions(12)  // 根据消费者数量设置
            .replicas(3)
            .config(TopicConfig.COMPRESSION_TYPE_CONFIG, "lz4")
            .config(TopicConfig.RETENTION_MS_CONFIG, "86400000")  // 1天
            .config(TopicConfig.SEGMENT_BYTES_CONFIG, "1073741824")  // 1GB
            .config(TopicConfig.MIN_IN_SYNC_REPLICAS_CONFIG, "2")
            .build();
}
```

---

## 12. 监控与运维

### 12.1 JMX 监控指标

```java
// 生产者关键指标
// kafka.producer:type=producer-metrics,client-id=*
// - record-send-rate: 发送速率
// - record-error-rate: 错误率
// - request-latency-avg: 平均延迟

// 消费者关键指标
// kafka.consumer:type=consumer-fetch-manager-metrics,client-id=*
// - records-consumed-rate: 消费速率
// - records-lag-max: 最大延迟
// - fetch-latency-avg: 拉取延迟
```

### 12.2 Spring Boot Actuator 集成

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,metrics,kafka
  health:
    kafka:
      enabled: true
```

```java
// 自定义健康检查
@Component
public class KafkaHealthIndicator implements HealthIndicator {
    
    private final KafkaTemplate<String, Object> kafkaTemplate;
    
    @Override
    public Health health() {
        try {
            kafkaTemplate.send("health-check", "ping").get(5, TimeUnit.SECONDS);
            return Health.up().build();
        } catch (Exception e) {
            return Health.down().withException(e).build();
        }
    }
}
```

### 12.3 消费延迟监控

```java
@Service
@Slf4j
public class LagMonitor {
    
    private final ConsumerFactory<String, Object> consumerFactory;
    
    public Map<TopicPartition, Long> getConsumerLag(String groupId, String topic) {
        try (Consumer<String, Object> consumer = consumerFactory.createConsumer(groupId, "")) {
            List<TopicPartition> partitions = consumer.partitionsFor(topic).stream()
                    .map(info -> new TopicPartition(topic, info.partition()))
                    .toList();
            
            Map<TopicPartition, Long> endOffsets = consumer.endOffsets(partitions);
            Map<TopicPartition, OffsetAndMetadata> committed = 
                consumer.committed(new HashSet<>(partitions));
            
            Map<TopicPartition, Long> lag = new HashMap<>();
            for (TopicPartition tp : partitions) {
                long end = endOffsets.get(tp);
                long current = committed.get(tp) != null ? committed.get(tp).offset() : 0;
                lag.put(tp, end - current);
            }
            
            return lag;
        }
    }
}
```

---

## 13. Kafka Streams

### 13.1 基础配置

```xml
<dependency>
    <groupId>org.apache.kafka</groupId>
    <artifactId>kafka-streams</artifactId>
</dependency>
```

```java
@Configuration
@EnableKafkaStreams
public class KafkaStreamsConfig {
    
    @Bean(name = KafkaStreamsDefaultConfiguration.DEFAULT_STREAMS_CONFIG_BEAN_NAME)
    public KafkaStreamsConfiguration kafkaStreamsConfig() {
        Map<String, Object> props = new HashMap<>();
        props.put(StreamsConfig.APPLICATION_ID_CONFIG, "streams-app");
        props.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        props.put(StreamsConfig.DEFAULT_KEY_SERDE_CLASS_CONFIG, Serdes.String().getClass());
        props.put(StreamsConfig.DEFAULT_VALUE_SERDE_CLASS_CONFIG, Serdes.String().getClass());
        props.put(StreamsConfig.PROCESSING_GUARANTEE_CONFIG, StreamsConfig.EXACTLY_ONCE_V2);
        return new KafkaStreamsConfiguration(props);
    }
}
```

### 13.2 流处理示例

```java
@Component
public class OrderStreamProcessor {
    
    @Autowired
    public void buildPipeline(StreamsBuilder streamsBuilder) {
        // 读取订单流
        KStream<String, String> orders = streamsBuilder.stream("orders");
        
        // 过滤大额订单
        KStream<String, String> largeOrders = orders.filter((key, value) -> {
            OrderMessage order = parseOrder(value);
            return order.amount().compareTo(new BigDecimal("1000")) > 0;
        });
        
        // 输出到新 Topic
        largeOrders.to("large-orders");
        
        // 统计每个用户的订单数
        KTable<String, Long> orderCounts = orders
                .map((key, value) -> {
                    OrderMessage order = parseOrder(value);
                    return KeyValue.pair(order.userId(), value);
                })
                .groupByKey()
                .count();
        
        // 输出统计结果
        orderCounts.toStream().to("order-counts");
    }
    
    // 窗口聚合
    @Autowired
    public void buildWindowedPipeline(StreamsBuilder streamsBuilder) {
        KStream<String, String> orders = streamsBuilder.stream("orders");
        
        // 5分钟滚动窗口统计
        KTable<Windowed<String>, Long> windowedCounts = orders
                .groupByKey()
                .windowedBy(TimeWindows.ofSizeWithNoGrace(Duration.ofMinutes(5)))
                .count();
        
        windowedCounts.toStream()
                .map((windowedKey, count) -> KeyValue.pair(
                        windowedKey.key() + "@" + windowedKey.window().start(),
                        count.toString()
                ))
                .to("windowed-counts");
    }
}
```

---

## 14. 最佳实践

### 14.1 Topic 设计

```java
// Topic 命名规范
// <环境>.<领域>.<事件类型>
// prod.order.created
// dev.user.registered

// Topic 配置建议
@Bean
public NewTopic orderTopic() {
    return TopicBuilder.name("prod.order.created")
            .partitions(6)           // 分区数 = 预期消费者数量
            .replicas(3)             // 副本数 >= 3
            .config(TopicConfig.RETENTION_MS_CONFIG, "604800000")  // 7天
            .config(TopicConfig.MIN_IN_SYNC_REPLICAS_CONFIG, "2")
            .config(TopicConfig.CLEANUP_POLICY_CONFIG, "delete")
            .build();
}
```

### 14.2 消息设计

```java
// 消息结构建议
public record KafkaMessage<T>(
    String messageId,      // 唯一标识，用于幂等
    String type,           // 消息类型
    T payload,             // 业务数据
    LocalDateTime timestamp,
    Map<String, String> metadata
) {}

// 使用示例
KafkaMessage<OrderMessage> message = new KafkaMessage<>(
    UUID.randomUUID().toString(),
    "ORDER_CREATED",
    order,
    LocalDateTime.now(),
    Map.of("source", "order-service", "version", "1.0")
);
```

### 14.3 消费者设计

```java
// 幂等消费
@Service
@RequiredArgsConstructor
public class IdempotentConsumer {
    
    private final RedisTemplate<String, String> redisTemplate;
    
    @KafkaListener(topics = "orders", groupId = "idempotent-group")
    public void consume(KafkaMessage<OrderMessage> message, Acknowledgment ack) {
        String messageId = message.messageId();
        String key = "kafka:processed:" + messageId;
        
        // 使用 Redis 实现幂等
        Boolean isNew = redisTemplate.opsForValue()
                .setIfAbsent(key, "1", Duration.ofDays(7));
        
        if (Boolean.FALSE.equals(isNew)) {
            log.info("Message {} already processed", messageId);
            ack.acknowledge();
            return;
        }
        
        try {
            processOrder(message.payload());
            ack.acknowledge();
        } catch (Exception e) {
            redisTemplate.delete(key);  // 处理失败，删除标记
            throw e;
        }
    }
}
```

### 14.4 错误处理策略

```java
@Configuration
public class KafkaErrorConfig {
    
    @Bean
    public DefaultErrorHandler errorHandler(KafkaTemplate<String, Object> kafkaTemplate) {
        // 死信队列
        DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(
            kafkaTemplate,
            (record, ex) -> {
                // 自定义死信 Topic 名称
                return new TopicPartition(record.topic() + ".DLT", -1);
            }
        );
        
        // 指数退避重试
        ExponentialBackOff backOff = new ExponentialBackOff(1000L, 2.0);
        backOff.setMaxElapsedTime(60000L);  // 最大重试时间 60 秒
        
        DefaultErrorHandler handler = new DefaultErrorHandler(recoverer, backOff);
        
        // 不重试的异常
        handler.addNotRetryableExceptions(
            DeserializationException.class,
            IllegalArgumentException.class
        );
        
        return handler;
    }
}
```

---

## 15. 常见错误与解决方案

### 15.1 连接错误

**错误：Connection to node -1 could not be established**
```java
// 原因：无法连接到 Kafka Broker
// 解决方案：

// 1. 检查 Kafka 是否启动
docker ps | grep kafka

// 2. 检查配置
spring:
  kafka:
    bootstrap-servers: localhost:9092  # 确保地址正确

// 3. 检查网络
telnet localhost 9092

// 4. Docker 环境检查 advertised.listeners
KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
```

**错误：Broker may not be available**
```java
// 原因：Broker 不可用或配置错误
// 解决方案：

// 1. 检查 Zookeeper 连接
docker logs zookeeper

// 2. 检查 Kafka 日志
docker logs kafka

// 3. 确保 advertised.listeners 配置正确
```

### 15.2 序列化错误

**错误：Deserializer class not found**
```java
// 原因：反序列化器配置错误
// 解决方案：
spring:
  kafka:
    consumer:
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      properties:
        spring.json.trusted.packages: "*"
```

**错误：JsonParseException / DeserializationException**
```java
// 原因：消息格式与预期不符
// 解决方案：

// 1. 检查消息格式
// 2. 配置错误处理
@Bean
public DefaultErrorHandler errorHandler() {
    return new DefaultErrorHandler((record, ex) -> {
        log.error("Failed to deserialize: {}", record.value(), ex);
    }, new FixedBackOff(0L, 0L));  // 不重试
}

// 3. 使用 ErrorHandlingDeserializer
props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, 
    ErrorHandlingDeserializer.class);
props.put(ErrorHandlingDeserializer.VALUE_DESERIALIZER_CLASS, 
    JsonDeserializer.class);
```

### 15.3 消费者错误

**错误：Consumer group is rebalancing**
```java
// 原因：消费者组正在重新平衡
// 解决方案：

// 1. 增加 session.timeout.ms
spring:
  kafka:
    consumer:
      properties:
        session.timeout.ms: 30000
        heartbeat.interval.ms: 10000

// 2. 减少处理时间或增加 max.poll.interval.ms
        max.poll.interval.ms: 300000
        max.poll.records: 100
```

**错误：CommitFailedException**
```java
// 原因：消费者被踢出组后尝试提交偏移量
// 解决方案：

// 1. 增加 max.poll.interval.ms
// 2. 减少单次处理的消息数量
// 3. 优化消息处理逻辑

spring:
  kafka:
    consumer:
      properties:
        max.poll.interval.ms: 600000
        max.poll.records: 50
```

**错误：No current assignment for partition**
```java
// 原因：分区未分配给当前消费者
// 解决方案：

// 1. 检查消费者组配置
// 2. 确保分区数 >= 消费者数
// 3. 等待再平衡完成
```

### 15.4 生产者错误

**错误：RecordTooLargeException**
```java
// 原因：消息超过大小限制
// 解决方案：

// 1. 增加消息大小限制
spring:
  kafka:
    producer:
      properties:
        max.request.size: 10485760  # 10MB

// 2. Broker 端配置
// message.max.bytes=10485760

// 3. 压缩消息
spring:
  kafka:
    producer:
      compression-type: lz4
```

**错误：TimeoutException on send**
```java
// 原因：发送超时
// 解决方案：

spring:
  kafka:
    producer:
      properties:
        request.timeout.ms: 30000
        delivery.timeout.ms: 120000
        retries: 3
        retry.backoff.ms: 1000
```

### 15.5 偏移量错误

**错误：OffsetOutOfRangeException**
```java
// 原因：请求的偏移量不存在
// 解决方案：

spring:
  kafka:
    consumer:
      auto-offset-reset: earliest  # 或 latest
```

**错误：消息重复消费**
```java
// 原因：偏移量提交失败或消费者重启
// 解决方案：

// 1. 实现幂等消费
// 2. 使用手动提交
@KafkaListener(topics = "orders")
public void consume(OrderMessage order, Acknowledgment ack) {
    if (isProcessed(order.orderId())) {
        ack.acknowledge();
        return;
    }
    
    processOrder(order);
    markAsProcessed(order.orderId());
    ack.acknowledge();
}
```

### 15.6 性能问题

**问题：消费延迟过高**
```java
// 解决方案：

// 1. 增加消费者数量（不超过分区数）
spring:
  kafka:
    listener:
      concurrency: 6

// 2. 批量消费
    listener:
      type: batch
    consumer:
      max-poll-records: 500

// 3. 优化处理逻辑
// 4. 增加分区数
```

**问题：生产者吞吐量低**
```java
// 解决方案：

spring:
  kafka:
    producer:
      batch-size: 32768
      properties:
        linger.ms: 20
      compression-type: lz4
      buffer-memory: 67108864
```

---

## 附录：配置速查表

```yaml
# 完整配置示例
spring:
  kafka:
    bootstrap-servers: localhost:9092
    
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer
      acks: all
      retries: 3
      batch-size: 16384
      buffer-memory: 33554432
      compression-type: lz4
      properties:
        linger.ms: 10
        enable.idempotence: true
        max.in.flight.requests.per.connection: 5
    
    consumer:
      group-id: my-group
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      auto-offset-reset: earliest
      enable-auto-commit: false
      max-poll-records: 500
      properties:
        spring.json.trusted.packages: "*"
        session.timeout.ms: 30000
        heartbeat.interval.ms: 10000
        max.poll.interval.ms: 300000
    
    listener:
      ack-mode: manual
      concurrency: 3
      type: single
```

---

> 💡 **学习建议**：
> 1. 先掌握基本的生产者和消费者使用
> 2. 理解分区和消费者组的概念
> 3. 学会处理消息可靠性问题
> 4. 根据业务场景选择合适的配置
> 5. 监控是关键，及时发现问题
