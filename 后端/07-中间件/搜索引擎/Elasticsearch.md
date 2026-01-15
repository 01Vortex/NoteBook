> Elasticsearch 是一个基于 Lucene 的分布式搜索和分析引擎
> 本笔记基于 Elasticsearch 7.x + Java 8 + Spring Boot 2.7.18

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [核心概念详解](#3-核心概念详解)
4. [Spring Boot 集成](#4-spring-boot-集成)
5. [索引操作](#5-索引操作)
6. [文档 CRUD](#6-文档-crud)
7. [查询 DSL](#7-查询-dsl)
8. [聚合分析](#8-聚合分析)
9. [分词与分析器](#9-分词与分析器)
10. [高亮搜索](#10-高亮搜索)
11. [分页与排序](#11-分页与排序)
12. [批量操作](#12-批量操作)
13. [索引别名与重建](#13-索引别名与重建)
14. [性能优化](#14-性能优化)
15. [集群与分片](#15-集群与分片)
16. [常见错误与解决方案](#16-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Elasticsearch？

Elasticsearch（简称 ES）是一个开源的分布式搜索和分析引擎，基于 Apache Lucene 构建。它能够快速地存储、搜索和分析海量数据，常用于：

- **全文搜索**：电商商品搜索、站内搜索、日志搜索
- **日志分析**：ELK Stack（Elasticsearch + Logstash + Kibana）
- **数据分析**：实时数据统计、聚合分析
- **应用监控**：APM（应用性能监控）

**为什么选择 Elasticsearch？**
- 近实时搜索（Near Real-Time），数据写入后约 1 秒即可被搜索到
- 分布式架构，天然支持水平扩展
- RESTful API，使用简单
- 强大的全文搜索能力
- 丰富的聚合分析功能

### 1.2 与关系型数据库对比

理解 ES 最好的方式是与我们熟悉的 MySQL 进行类比：

| MySQL | Elasticsearch | 说明 |
|-------|---------------|------|
| Database（数据库） | Index（索引） | 数据的逻辑容器 |
| Table（表） | Type（类型）* | ES 7.x 已废弃，一个索引只有一个类型 `_doc` |
| Row（行） | Document（文档） | 一条数据记录，JSON 格式 |
| Column（列） | Field（字段） | 文档中的属性 |
| Schema（表结构） | Mapping（映射） | 定义字段类型和属性 |
| SQL | DSL | 查询语言 |

> **注意**：ES 7.x 版本开始，Type 概念被废弃，一个 Index 只能有一个 Type（默认 `_doc`）。ES 8.x 完全移除了 Type。

### 1.3 核心术语

**文档（Document）**
- ES 中的最小数据单元，相当于数据库中的一行记录
- 以 JSON 格式存储
- 每个文档都有一个唯一的 `_id`

```json
{
  "_index": "products",
  "_type": "_doc",
  "_id": "1",
  "_source": {
    "name": "iPhone 15",
    "price": 5999,
    "brand": "Apple"
  }
}
```

**索引（Index）**
- 文档的集合，相当于数据库中的表
- 索引名必须小写，不能以 `_`、`-`、`+` 开头

**映射（Mapping）**
- 定义文档中字段的类型、分词器等属性
- 类似于数据库的表结构定义

**分片（Shard）**
- 索引可以被分成多个分片，分布在不同节点上
- 主分片（Primary Shard）：数据的原始分片
- 副本分片（Replica Shard）：主分片的复制，提供高可用和读取负载均衡

**节点（Node）与集群（Cluster）**
- 节点：一个 ES 实例
- 集群：多个节点组成的集合，共同存储数据

### 1.4 数据类型

ES 支持多种数据类型，常用的有：

| 类型 | 说明 | 示例 |
|------|------|------|
| text | 全文搜索字段，会被分词 | 商品描述、文章内容 |
| keyword | 精确匹配，不分词 | 状态、标签、ID |
| long/integer/short/byte | 整数类型 | 数量、年龄 |
| double/float | 浮点数类型 | 价格、评分 |
| boolean | 布尔类型 | 是否上架 |
| date | 日期类型 | 创建时间 |
| object | 对象类型 | 嵌套的 JSON 对象 |
| nested | 嵌套类型 | 数组中的对象需要独立查询时使用 |

**text vs keyword 的区别**：
```json
// text 类型会被分词
"title": "iPhone 15 Pro Max"
// 分词后：["iphone", "15", "pro", "max"]
// 可以搜索 "iphone" 或 "pro" 找到这条数据

// keyword 类型不分词
"status": "published"
// 必须精确匹配 "published" 才能找到
```

---

## 2. 环境搭建

### 2.1 Docker 安装 Elasticsearch

推荐使用 Docker 快速搭建开发环境：

```bash
# 创建网络
docker network create elastic

# 启动 Elasticsearch
docker run -d \
  --name elasticsearch \
  --net elastic \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
  -e "xpack.security.enabled=false" \
  elasticsearch:7.17.9

# 启动 Kibana（可视化工具）
docker run -d \
  --name kibana \
  --net elastic \
  -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
  kibana:7.17.9
```

**验证安装**：
```bash
curl http://localhost:9200

# 返回类似以下内容表示成功
{
  "name" : "xxx",
  "cluster_name" : "docker-cluster",
  "cluster_uuid" : "xxx",
  "version" : {
    "number" : "7.17.9",
    ...
  },
  "tagline" : "You Know, for Search"
}
```

### 2.2 Docker Compose 方式

创建 `docker-compose.yml`：

```yaml
version: '3.8'
services:
  elasticsearch:
    image: elasticsearch:7.17.9
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
      - "9300:9300"
    volumes:
      - es-data:/usr/share/elasticsearch/data
    networks:
      - elastic

  kibana:
    image: kibana:7.17.9
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - elastic

volumes:
  es-data:

networks:
  elastic:
    driver: bridge
```

```bash
# 启动
docker-compose up -d

# 查看日志
docker-compose logs -f elasticsearch

# 停止
docker-compose down
```

### 2.3 安装 IK 分词器

ES 默认的分词器对中文支持不好，需要安装 IK 分词器：

```bash
# 进入容器
docker exec -it elasticsearch bash

# 安装 IK 分词器（版本需与 ES 版本一致）
./bin/elasticsearch-plugin install https://github.com/medcl/elasticsearch-analysis-ik/releases/download/v7.17.9/elasticsearch-analysis-ik-7.17.9.zip

# 退出并重启容器
exit
docker restart elasticsearch
```

**IK 分词器提供两种分词模式**：
- `ik_smart`：智能分词，粗粒度
- `ik_max_word`：最细粒度分词

```json
// 测试分词效果
POST /_analyze
{
  "analyzer": "ik_smart",
  "text": "中华人民共和国国歌"
}
// 结果：["中华人民共和国", "国歌"]

POST /_analyze
{
  "analyzer": "ik_max_word",
  "text": "中华人民共和国国歌"
}
// 结果：["中华人民共和国", "中华人民", "中华", "华人", "人民共和国", "人民", "共和国", "共和", "国歌"]
```

---

## 3. 核心概念详解

### 3.1 倒排索引

倒排索引是 ES 实现快速全文搜索的核心数据结构。

**正排索引**（传统数据库）：
```
文档ID -> 文档内容
1 -> "Java 编程入门"
2 -> "Python 编程实战"
3 -> "Java 高级编程"
```

**倒排索引**：
```
词项 -> 文档ID列表
Java -> [1, 3]
编程 -> [1, 2, 3]
入门 -> [1]
Python -> [2]
实战 -> [2]
高级 -> [3]
```

当搜索 "Java" 时，直接从倒排索引中找到包含该词的文档列表 [1, 3]，无需遍历所有文档。

### 3.2 分词过程

文档写入 ES 时，会经过以下处理：

```
原始文本 -> 字符过滤器 -> 分词器 -> 词项过滤器 -> 倒排索引
```

1. **字符过滤器（Character Filter）**：处理原始文本，如去除 HTML 标签
2. **分词器（Tokenizer）**：将文本切分成词项
3. **词项过滤器（Token Filter）**：对词项进行处理，如转小写、去停用词、同义词处理

### 3.3 文档写入流程

```
1. 客户端发送写入请求到协调节点
2. 协调节点根据文档 ID 计算路由，确定目标分片
   shard = hash(_routing) % number_of_primary_shards
3. 请求转发到主分片所在节点
4. 主分片写入成功后，并行复制到副本分片
5. 所有副本写入成功后，返回客户端
```

### 3.4 近实时搜索原理

ES 的"近实时"是通过 Refresh 机制实现的：

```
写入请求 -> Index Buffer（内存）-> Refresh（默认1秒）-> Segment（可搜索）
                                                           |
                                                           v
                                                    Translog（持久化）
                                                           |
                                                           v
                                                    Flush -> 磁盘
```

- **Index Buffer**：文档先写入内存缓冲区
- **Refresh**：每秒将 Buffer 中的数据写入新的 Segment，此时数据可被搜索
- **Translog**：事务日志，保证数据不丢失
- **Flush**：将 Segment 持久化到磁盘，清空 Translog

---

## 4. Spring Boot 集成

### 4.1 添加依赖

Spring Boot 2.7.18 推荐使用 Spring Data Elasticsearch：

```xml
<dependencies>
    <!-- Spring Data Elasticsearch -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-elasticsearch</artifactId>
    </dependency>
    
    <!-- 如果需要使用 RestHighLevelClient（更灵活） -->
    <dependency>
        <groupId>org.elasticsearch.client</groupId>
        <artifactId>elasticsearch-rest-high-level-client</artifactId>
        <version>7.17.9</version>
    </dependency>
    
    <!-- Lombok（可选） -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### 4.2 配置文件

```yaml
# application.yml
spring:
  elasticsearch:
    uris: http://localhost:9200
    # 如果有认证
    # username: elastic
    # password: your_password
    connection-timeout: 5s
    socket-timeout: 30s

# 日志配置（调试时开启）
logging:
  level:
    org.springframework.data.elasticsearch: DEBUG
    org.elasticsearch.client: DEBUG
```

### 4.3 配置类

```java
import org.elasticsearch.client.RestHighLevelClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.elasticsearch.client.ClientConfiguration;
import org.springframework.data.elasticsearch.client.RestClients;
import org.springframework.data.elasticsearch.config.AbstractElasticsearchConfiguration;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;

@Configuration
@EnableElasticsearchRepositories(basePackages = "com.example.repository")
public class ElasticsearchConfig extends AbstractElasticsearchConfiguration {

    @Override
    @Bean
    public RestHighLevelClient elasticsearchClient() {
        ClientConfiguration configuration = ClientConfiguration.builder()
                .connectedTo("localhost:9200")
                // .usingSsl()  // 如果使用 HTTPS
                // .withBasicAuth("elastic", "password")  // 如果有认证
                .withConnectTimeout(5000)
                .withSocketTimeout(30000)
                .build();
        
        return RestClients.create(configuration).rest();
    }
}
```

### 4.4 实体类定义

```java
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Document(indexName = "products")  // 索引名
@Setting(shards = 3, replicas = 1)  // 分片和副本配置
public class Product {

    @Id
    private String id;

    /**
     * text 类型：会被分词，用于全文搜索
     * analyzer：写入时使用的分词器
     * searchAnalyzer：搜索时使用的分词器
     */
    @Field(type = FieldType.Text, analyzer = "ik_max_word", searchAnalyzer = "ik_smart")
    private String name;

    @Field(type = FieldType.Text, analyzer = "ik_max_word", searchAnalyzer = "ik_smart")
    private String description;

    /**
     * keyword 类型：不分词，用于精确匹配、聚合、排序
     */
    @Field(type = FieldType.Keyword)
    private String brand;

    @Field(type = FieldType.Keyword)
    private String category;

    @Field(type = FieldType.Double)
    private BigDecimal price;

    @Field(type = FieldType.Integer)
    private Integer stock;

    @Field(type = FieldType.Integer)
    private Integer sales;

    /**
     * 多字段类型：同时支持全文搜索和精确匹配
     */
    @MultiField(
        mainField = @Field(type = FieldType.Text, analyzer = "ik_max_word"),
        otherFields = {
            @InnerField(suffix = "keyword", type = FieldType.Keyword)
        }
    )
    private String tags;

    @Field(type = FieldType.Boolean)
    private Boolean onSale;

    @Field(type = FieldType.Date, format = DateFormat.date_hour_minute_second)
    private LocalDateTime createTime;

    @Field(type = FieldType.Date, format = DateFormat.date_hour_minute_second)
    private LocalDateTime updateTime;

    /**
     * 嵌套对象
     */
    @Field(type = FieldType.Nested)
    private List<ProductAttribute> attributes;
}

@Data
public class ProductAttribute {
    @Field(type = FieldType.Keyword)
    private String name;
    
    @Field(type = FieldType.Keyword)
    private String value;
}
```

### 4.5 Repository 接口

Spring Data Elasticsearch 提供了类似 JPA 的 Repository 模式：

```java
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.elasticsearch.annotations.Query;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

import java.math.BigDecimal;
import java.util.List;

public interface ProductRepository extends ElasticsearchRepository<Product, String> {

    // 方法名查询（自动生成查询语句）
    List<Product> findByName(String name);
    
    List<Product> findByBrand(String brand);
    
    List<Product> findByPriceBetween(BigDecimal minPrice, BigDecimal maxPrice);
    
    List<Product> findByNameContaining(String keyword);
    
    List<Product> findByBrandAndOnSaleTrue(String brand);
    
    Page<Product> findByCategory(String category, Pageable pageable);
    
    List<Product> findByNameOrDescription(String name, String description);
    
    // 自定义查询（使用 ES 查询 DSL）
    @Query("{\"match\": {\"name\": \"?0\"}}")
    List<Product> searchByName(String name);
    
    @Query("{\"bool\": {\"must\": [{\"match\": {\"name\": \"?0\"}}, {\"range\": {\"price\": {\"lte\": ?1}}}]}}")
    List<Product> searchByNameAndMaxPrice(String name, BigDecimal maxPrice);
    
    // 统计
    long countByBrand(String brand);
    
    boolean existsByName(String name);
    
    // 删除
    void deleteByBrand(String brand);
}
```

### 4.6 Service 层

```java
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ProductService {

    private final ProductRepository productRepository;

    // 保存单个文档
    public Product save(Product product) {
        return productRepository.save(product);
    }

    // 批量保存
    public Iterable<Product> saveAll(List<Product> products) {
        return productRepository.saveAll(products);
    }

    // 根据 ID 查询
    public Optional<Product> findById(String id) {
        return productRepository.findById(id);
    }

    // 查询所有
    public Iterable<Product> findAll() {
        return productRepository.findAll();
    }

    // 分页查询
    public Page<Product> findByCategory(String category, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "sales"));
        return productRepository.findByCategory(category, pageRequest);
    }

    // 删除
    public void deleteById(String id) {
        productRepository.deleteById(id);
    }

    // 判断是否存在
    public boolean existsById(String id) {
        return productRepository.existsById(id);
    }
}
```

---

## 5. 索引操作

### 5.1 使用 ElasticsearchRestTemplate

对于更复杂的索引操作，可以使用 `ElasticsearchRestTemplate`：

```java
import lombok.RequiredArgsConstructor;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentType;
import org.springframework.data.elasticsearch.core.ElasticsearchRestTemplate;
import org.springframework.data.elasticsearch.core.IndexOperations;
import org.springframework.data.elasticsearch.core.document.Document;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class IndexService {

    private final ElasticsearchRestTemplate elasticsearchRestTemplate;
    private final RestHighLevelClient restHighLevelClient;

    /**
     * 创建索引（使用 Spring Data）
     */
    public boolean createIndex(Class<?> clazz) {
        IndexOperations indexOps = elasticsearchRestTemplate.indexOps(clazz);
        if (!indexOps.exists()) {
            indexOps.create();
            indexOps.putMapping(indexOps.createMapping());
            return true;
        }
        return false;
    }

    /**
     * 删除索引
     */
    public boolean deleteIndex(Class<?> clazz) {
        IndexOperations indexOps = elasticsearchRestTemplate.indexOps(clazz);
        return indexOps.delete();
    }

    /**
     * 判断索引是否存在
     */
    public boolean indexExists(Class<?> clazz) {
        return elasticsearchRestTemplate.indexOps(clazz).exists();
    }

    /**
     * 使用 RestHighLevelClient 创建索引（更灵活）
     */
    public boolean createIndexWithSettings(String indexName) throws Exception {
        // 检查索引是否存在
        GetIndexRequest getRequest = new GetIndexRequest(indexName);
        if (restHighLevelClient.indices().exists(getRequest, RequestOptions.DEFAULT)) {
            return false;
        }

        // 创建索引请求
        CreateIndexRequest request = new CreateIndexRequest(indexName);
        
        // 设置分片和副本
        request.settings(Settings.builder()
                .put("index.number_of_shards", 3)
                .put("index.number_of_replicas", 1)
                .put("index.refresh_interval", "1s")
        );

        // 设置映射
        String mapping = """
            {
              "properties": {
                "name": {
                  "type": "text",
                  "analyzer": "ik_max_word",
                  "search_analyzer": "ik_smart"
                },
                "brand": {
                  "type": "keyword"
                },
                "price": {
                  "type": "double"
                },
                "createTime": {
                  "type": "date",
                  "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                }
              }
            }
            """;
        request.mapping(mapping, XContentType.JSON);

        restHighLevelClient.indices().create(request, RequestOptions.DEFAULT);
        return true;
    }
}
```

### 5.2 Kibana 中的索引操作

```json
// 创建索引
PUT /products
{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1,
    "analysis": {
      "analyzer": {
        "my_analyzer": {
          "type": "custom",
          "tokenizer": "ik_max_word",
          "filter": ["lowercase"]
        }
      }
    }
  },
  "mappings": {
    "properties": {
      "name": {
        "type": "text",
        "analyzer": "ik_max_word",
        "search_analyzer": "ik_smart"
      },
      "brand": {
        "type": "keyword"
      },
      "price": {
        "type": "double"
      },
      "description": {
        "type": "text",
        "analyzer": "ik_max_word"
      },
      "tags": {
        "type": "keyword"
      },
      "createTime": {
        "type": "date",
        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
      }
    }
  }
}

// 查看索引信息
GET /products

// 查看索引映射
GET /products/_mapping

// 查看索引设置
GET /products/_settings

// 删除索引
DELETE /products

// 关闭索引（暂停读写）
POST /products/_close

// 打开索引
POST /products/_open
```

### 5.3 修改映射

**注意**：ES 中已存在的字段映射无法修改，只能新增字段。如需修改，必须重建索引。

```json
// 新增字段
PUT /products/_mapping
{
  "properties": {
    "newField": {
      "type": "keyword"
    }
  }
}
```

---

## 6. 文档 CRUD

### 6.1 使用 ElasticsearchRestTemplate

```java
import lombok.RequiredArgsConstructor;
import org.elasticsearch.index.query.QueryBuilders;
import org.springframework.data.elasticsearch.core.ElasticsearchRestTemplate;
import org.springframework.data.elasticsearch.core.SearchHit;
import org.springframework.data.elasticsearch.core.SearchHits;
import org.springframework.data.elasticsearch.core.document.Document;
import org.springframework.data.elasticsearch.core.query.*;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProductDocumentService {

    private final ElasticsearchRestTemplate elasticsearchRestTemplate;

    /**
     * 新增/更新文档
     */
    public Product save(Product product) {
        return elasticsearchRestTemplate.save(product);
    }

    /**
     * 根据 ID 查询
     */
    public Product findById(String id) {
        return elasticsearchRestTemplate.get(id, Product.class);
    }

    /**
     * 根据 ID 删除
     */
    public String deleteById(String id) {
        return elasticsearchRestTemplate.delete(id, Product.class);
    }

    /**
     * 根据条件删除
     */
    public void deleteByQuery(String brand) {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.termQuery("brand", brand))
                .build();
        elasticsearchRestTemplate.delete(query, Product.class);
    }

    /**
     * 更新文档（部分更新）
     */
    public void updateById(String id, Product product) {
        Document document = Document.create();
        if (product.getName() != null) {
            document.put("name", product.getName());
        }
        if (product.getPrice() != null) {
            document.put("price", product.getPrice());
        }
        
        UpdateQuery updateQuery = UpdateQuery.builder(id)
                .withDocument(document)
                .build();
        
        elasticsearchRestTemplate.update(updateQuery, 
                elasticsearchRestTemplate.getIndexCoordinatesFor(Product.class));
    }

    /**
     * 使用脚本更新
     */
    public void updateByScript(String id, int increment) {
        UpdateQuery updateQuery = UpdateQuery.builder(id)
                .withScript("ctx._source.sales += params.increment")
                .withParams(java.util.Map.of("increment", increment))
                .build();
        
        elasticsearchRestTemplate.update(updateQuery,
                elasticsearchRestTemplate.getIndexCoordinatesFor(Product.class));
    }

    /**
     * 判断文档是否存在
     */
    public boolean exists(String id) {
        return elasticsearchRestTemplate.exists(id, Product.class);
    }
}
```

### 6.2 使用 RestHighLevelClient

```java
import lombok.RequiredArgsConstructor;
import org.elasticsearch.action.delete.DeleteRequest;
import org.elasticsearch.action.delete.DeleteResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptType;
import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ProductRestService {

    private final RestHighLevelClient client;
    private final ObjectMapper objectMapper;

    /**
     * 新增文档
     */
    public String createDocument(String indexName, String id, Product product) throws Exception {
        IndexRequest request = new IndexRequest(indexName)
                .id(id)
                .source(objectMapper.writeValueAsString(product), XContentType.JSON);
        
        IndexResponse response = client.index(request, RequestOptions.DEFAULT);
        return response.getId();
    }

    /**
     * 查询文档
     */
    public Product getDocument(String indexName, String id) throws Exception {
        GetRequest request = new GetRequest(indexName, id);
        GetResponse response = client.get(request, RequestOptions.DEFAULT);
        
        if (response.isExists()) {
            return objectMapper.readValue(response.getSourceAsString(), Product.class);
        }
        return null;
    }

    /**
     * 更新文档
     */
    public void updateDocument(String indexName, String id, Map<String, Object> updates) throws Exception {
        UpdateRequest request = new UpdateRequest(indexName, id)
                .doc(updates);
        
        client.update(request, RequestOptions.DEFAULT);
    }

    /**
     * 使用脚本更新（如增加销量）
     */
    public void updateByScript(String indexName, String id, String field, int increment) throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("increment", increment);
        
        Script script = new Script(
                ScriptType.INLINE,
                "painless",
                "ctx._source." + field + " += params.increment",
                params
        );
        
        UpdateRequest request = new UpdateRequest(indexName, id)
                .script(script);
        
        client.update(request, RequestOptions.DEFAULT);
    }

    /**
     * 删除文档
     */
    public void deleteDocument(String indexName, String id) throws Exception {
        DeleteRequest request = new DeleteRequest(indexName, id);
        client.delete(request, RequestOptions.DEFAULT);
    }

    /**
     * Upsert（存在则更新，不存在则插入）
     */
    public void upsertDocument(String indexName, String id, Product product) throws Exception {
        String json = objectMapper.writeValueAsString(product);
        
        UpdateRequest request = new UpdateRequest(indexName, id)
                .doc(json, XContentType.JSON)
                .upsert(json, XContentType.JSON);
        
        client.update(request, RequestOptions.DEFAULT);
    }
}
```

### 6.3 Kibana 中的文档操作

```json
// 新增文档（指定 ID）
PUT /products/_doc/1
{
  "name": "iPhone 15 Pro",
  "brand": "Apple",
  "price": 7999,
  "description": "Apple 最新旗舰手机",
  "category": "手机",
  "stock": 100,
  "sales": 500,
  "onSale": true,
  "createTime": "2024-01-15 10:30:00"
}

// 新增文档（自动生成 ID）
POST /products/_doc
{
  "name": "华为 Mate 60",
  "brand": "Huawei",
  "price": 5999
}

// 查询文档
GET /products/_doc/1

// 更新文档（全量替换）
PUT /products/_doc/1
{
  "name": "iPhone 15 Pro Max",
  "brand": "Apple",
  "price": 9999
}

// 更新文档（部分更新）
POST /products/_update/1
{
  "doc": {
    "price": 7499,
    "stock": 80
  }
}

// 使用脚本更新
POST /products/_update/1
{
  "script": {
    "source": "ctx._source.sales += params.count",
    "params": {
      "count": 10
    }
  }
}

// 删除文档
DELETE /products/_doc/1

// 根据条件删除
POST /products/_delete_by_query
{
  "query": {
    "term": {
      "brand": "Apple"
    }
  }
}
```

---

## 7. 查询 DSL

### 7.1 查询类型概述

ES 查询分为两大类：

| 类型 | 说明 | 特点 |
|------|------|------|
| Query Context | 查询上下文 | 计算相关性评分（_score），用于全文搜索 |
| Filter Context | 过滤上下文 | 不计算评分，只判断是否匹配，可缓存，性能更好 |

**最佳实践**：精确匹配用 filter，全文搜索用 query。

### 7.2 全文搜索查询

```java
import org.elasticsearch.index.query.QueryBuilders;
import org.springframework.data.elasticsearch.core.query.NativeSearchQuery;
import org.springframework.data.elasticsearch.core.query.NativeSearchQueryBuilder;

@Service
@RequiredArgsConstructor
public class ProductSearchService {

    private final ElasticsearchRestTemplate elasticsearchRestTemplate;

    /**
     * match 查询：分词后匹配
     */
    public List<Product> matchQuery(String keyword) {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.matchQuery("name", keyword))
                .build();
        
        SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
        return hits.stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());
    }

    /**
     * multi_match 查询：多字段匹配
     */
    public List<Product> multiMatchQuery(String keyword) {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.multiMatchQuery(keyword, "name", "description", "brand")
                        .field("name", 3.0f)  // name 字段权重提升 3 倍
                        .field("description", 1.0f))
                .build();
        
        return executeSearch(query);
    }

    /**
     * match_phrase 查询：短语匹配（词序必须一致）
     */
    public List<Product> matchPhraseQuery(String phrase) {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.matchPhraseQuery("name", phrase)
                        .slop(2))  // 允许词之间有 2 个词的间隔
                .build();
        
        return executeSearch(query);
    }

    /**
     * query_string 查询：支持 Lucene 查询语法
     */
    public List<Product> queryStringQuery(String queryString) {
        // 支持语法：AND, OR, NOT, +, -, *, ?, ~
        // 例如："iPhone AND (Pro OR Max)"
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.queryStringQuery(queryString)
                        .defaultField("name")
                        .analyzeWildcard(true))
                .build();
        
        return executeSearch(query);
    }

    private List<Product> executeSearch(NativeSearchQuery query) {
        SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
        return hits.stream()
                .map(SearchHit::getContent)
                .collect(Collectors.toList());
    }
}
```

### 7.3 精确查询

```java
/**
 * term 查询：精确匹配（不分词）
 */
public List<Product> termQuery(String brand) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.termQuery("brand", brand))
            .build();
    
    return executeSearch(query);
}

/**
 * terms 查询：多值精确匹配（IN 查询）
 */
public List<Product> termsQuery(List<String> brands) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.termsQuery("brand", brands))
            .build();
    
    return executeSearch(query);
}

/**
 * range 查询：范围查询
 */
public List<Product> rangeQuery(BigDecimal minPrice, BigDecimal maxPrice) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.rangeQuery("price")
                    .gte(minPrice)   // 大于等于
                    .lte(maxPrice)   // 小于等于
                    // .gt()  大于
                    // .lt()  小于
            )
            .build();
    
    return executeSearch(query);
}

/**
 * exists 查询：字段是否存在
 */
public List<Product> existsQuery(String field) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.existsQuery(field))
            .build();
    
    return executeSearch(query);
}

/**
 * prefix 查询：前缀匹配
 */
public List<Product> prefixQuery(String prefix) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.prefixQuery("brand", prefix))
            .build();
    
    return executeSearch(query);
}

/**
 * wildcard 查询：通配符匹配
 * * 匹配任意字符
 * ? 匹配单个字符
 */
public List<Product> wildcardQuery(String pattern) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.wildcardQuery("name.keyword", "*Phone*"))
            .build();
    
    return executeSearch(query);
}

/**
 * ids 查询：根据 ID 列表查询
 */
public List<Product> idsQuery(List<String> ids) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.idsQuery().addIds(ids.toArray(new String[0])))
            .build();
    
    return executeSearch(query);
}
```

### 7.4 复合查询

```java
/**
 * bool 查询：组合多个查询条件
 * - must：必须匹配，计算评分（AND）
 * - should：可选匹配，计算评分（OR）
 * - must_not：必须不匹配，不计算评分（NOT）
 * - filter：必须匹配，不计算评分，可缓存
 */
public List<Product> boolQuery(ProductSearchDTO dto) {
    BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
    
    // 关键词搜索（must，计算评分）
    if (StringUtils.hasText(dto.getKeyword())) {
        boolQuery.must(QueryBuilders.multiMatchQuery(dto.getKeyword(), "name", "description"));
    }
    
    // 品牌过滤（filter，不计算评分，可缓存）
    if (StringUtils.hasText(dto.getBrand())) {
        boolQuery.filter(QueryBuilders.termQuery("brand", dto.getBrand()));
    }
    
    // 价格范围（filter）
    if (dto.getMinPrice() != null || dto.getMaxPrice() != null) {
        RangeQueryBuilder rangeQuery = QueryBuilders.rangeQuery("price");
        if (dto.getMinPrice() != null) {
            rangeQuery.gte(dto.getMinPrice());
        }
        if (dto.getMaxPrice() != null) {
            rangeQuery.lte(dto.getMaxPrice());
        }
        boolQuery.filter(rangeQuery);
    }
    
    // 必须在售（filter）
    boolQuery.filter(QueryBuilders.termQuery("onSale", true));
    
    // 排除某些品牌（must_not）
    if (dto.getExcludeBrands() != null && !dto.getExcludeBrands().isEmpty()) {
        boolQuery.mustNot(QueryBuilders.termsQuery("brand", dto.getExcludeBrands()));
    }
    
    // 可选条件：有库存或高销量（should）
    if (dto.isPreferInStock()) {
        boolQuery.should(QueryBuilders.rangeQuery("stock").gt(0));
        boolQuery.should(QueryBuilders.rangeQuery("sales").gt(100));
        boolQuery.minimumShouldMatch(1);  // 至少满足一个 should 条件
    }
    
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(boolQuery)
            .build();
    
    return executeSearch(query);
}

/**
 * constant_score 查询：将查询转为 filter，不计算评分
 */
public List<Product> constantScoreQuery(String brand) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.constantScoreQuery(
                    QueryBuilders.termQuery("brand", brand)
            ).boost(1.0f))
            .build();
    
    return executeSearch(query);
}

/**
 * boosting 查询：提升或降低某些文档的评分
 */
public List<Product> boostingQuery(String keyword, String negativeBrand) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.boostingQuery(
                    QueryBuilders.matchQuery("name", keyword),  // positive
                    QueryBuilders.termQuery("brand", negativeBrand)  // negative
            ).negativeBoost(0.5f))  // 匹配 negative 的文档评分降低 50%
            .build();
    
    return executeSearch(query);
}
```

### 7.5 嵌套查询

当文档中包含嵌套对象（nested 类型）时，需要使用嵌套查询：

```java
/**
 * nested 查询：查询嵌套对象
 */
public List<Product> nestedQuery(String attrName, String attrValue) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.nestedQuery(
                    "attributes",  // 嵌套字段路径
                    QueryBuilders.boolQuery()
                            .must(QueryBuilders.termQuery("attributes.name", attrName))
                            .must(QueryBuilders.termQuery("attributes.value", attrValue)),
                    ScoreMode.Avg  // 评分模式
            ))
            .build();
    
    return executeSearch(query);
}
```

### 7.6 Kibana 中的查询示例

```json
// match 查询
GET /products/_search
{
  "query": {
    "match": {
      "name": "iPhone 手机"
    }
  }
}

// multi_match 查询
GET /products/_search
{
  "query": {
    "multi_match": {
      "query": "苹果手机",
      "fields": ["name^3", "description", "brand"],
      "type": "best_fields"
    }
  }
}

// bool 复合查询
GET /products/_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "name": "手机" } }
      ],
      "filter": [
        { "term": { "brand": "Apple" } },
        { "range": { "price": { "gte": 5000, "lte": 10000 } } },
        { "term": { "onSale": true } }
      ],
      "must_not": [
        { "term": { "category": "配件" } }
      ],
      "should": [
        { "range": { "sales": { "gte": 100 } } }
      ]
    }
  }
}

// 嵌套查询
GET /products/_search
{
  "query": {
    "nested": {
      "path": "attributes",
      "query": {
        "bool": {
          "must": [
            { "term": { "attributes.name": "颜色" } },
            { "term": { "attributes.value": "黑色" } }
          ]
        }
      }
    }
  }
}
```

---

## 8. 聚合分析

聚合（Aggregation）是 ES 强大的数据分析功能，类似于 SQL 中的 GROUP BY。

### 8.1 聚合类型

| 类型 | 说明 | 示例 |
|------|------|------|
| Bucket | 桶聚合，分组 | terms、range、date_histogram |
| Metric | 指标聚合，计算 | sum、avg、max、min、count |
| Pipeline | 管道聚合，基于其他聚合结果 | avg_bucket、max_bucket |

### 8.2 指标聚合

```java
import org.elasticsearch.search.aggregations.AggregationBuilders;
import org.elasticsearch.search.aggregations.metrics.*;

@Service
@RequiredArgsConstructor
public class ProductAggregationService {

    private final ElasticsearchRestTemplate elasticsearchRestTemplate;

    /**
     * 基础指标聚合：统计价格
     */
    public Map<String, Object> priceStats() {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .withQuery(QueryBuilders.matchAllQuery())
                .addAggregation(AggregationBuilders.avg("avg_price").field("price"))
                .addAggregation(AggregationBuilders.max("max_price").field("price"))
                .addAggregation(AggregationBuilders.min("min_price").field("price"))
                .addAggregation(AggregationBuilders.sum("total_price").field("price"))
                .addAggregation(AggregationBuilders.count("count").field("price"))
                .withMaxResults(0)  // 不返回文档，只返回聚合结果
                .build();

        SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
        
        Map<String, Object> result = new HashMap<>();
        
        Avg avgPrice = hits.getAggregations().get("avg_price");
        result.put("avgPrice", avgPrice.getValue());
        
        Max maxPrice = hits.getAggregations().get("max_price");
        result.put("maxPrice", maxPrice.getValue());
        
        Min minPrice = hits.getAggregations().get("min_price");
        result.put("minPrice", minPrice.getValue());
        
        Sum totalPrice = hits.getAggregations().get("total_price");
        result.put("totalPrice", totalPrice.getValue());
        
        ValueCount count = hits.getAggregations().get("count");
        result.put("count", count.getValue());
        
        return result;
    }

    /**
     * stats 聚合：一次性获取多个统计值
     */
    public Map<String, Object> statsAggregation() {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .addAggregation(AggregationBuilders.stats("price_stats").field("price"))
                .withMaxResults(0)
                .build();

        SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
        Stats stats = hits.getAggregations().get("price_stats");
        
        Map<String, Object> result = new HashMap<>();
        result.put("count", stats.getCount());
        result.put("min", stats.getMin());
        result.put("max", stats.getMax());
        result.put("avg", stats.getAvg());
        result.put("sum", stats.getSum());
        
        return result;
    }

    /**
     * cardinality 聚合：去重计数（类似 COUNT(DISTINCT)）
     */
    public long countDistinctBrands() {
        NativeSearchQuery query = new NativeSearchQueryBuilder()
                .addAggregation(AggregationBuilders.cardinality("brand_count").field("brand"))
                .withMaxResults(0)
                .build();

        SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
        Cardinality cardinality = hits.getAggregations().get("brand_count");
        
        return cardinality.getValue();
    }
}
```

### 8.3 桶聚合

```java
/**
 * terms 聚合：按字段值分组
 */
public List<Map<String, Object>> brandAggregation() {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .addAggregation(AggregationBuilders.terms("brand_agg")
                    .field("brand")
                    .size(10)  // 返回前 10 个桶
                    .order(BucketOrder.count(false)))  // 按数量降序
            .withMaxResults(0)
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    Terms terms = hits.getAggregations().get("brand_agg");
    
    List<Map<String, Object>> result = new ArrayList<>();
    for (Terms.Bucket bucket : terms.getBuckets()) {
        Map<String, Object> item = new HashMap<>();
        item.put("brand", bucket.getKeyAsString());
        item.put("count", bucket.getDocCount());
        result.add(item);
    }
    
    return result;
}

/**
 * range 聚合：按范围分组
 */
public List<Map<String, Object>> priceRangeAggregation() {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .addAggregation(AggregationBuilders.range("price_range")
                    .field("price")
                    .addUnboundedTo("便宜", 1000)           // < 1000
                    .addRange("中等", 1000, 5000)           // 1000 - 5000
                    .addRange("较贵", 5000, 10000)          // 5000 - 10000
                    .addUnboundedFrom("昂贵", 10000))       // >= 10000
            .withMaxResults(0)
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    Range range = hits.getAggregations().get("price_range");
    
    List<Map<String, Object>> result = new ArrayList<>();
    for (Range.Bucket bucket : range.getBuckets()) {
        Map<String, Object> item = new HashMap<>();
        item.put("key", bucket.getKeyAsString());
        item.put("from", bucket.getFrom());
        item.put("to", bucket.getTo());
        item.put("count", bucket.getDocCount());
        result.add(item);
    }
    
    return result;
}

/**
 * date_histogram 聚合：按日期分组
 */
public List<Map<String, Object>> salesByMonth() {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .addAggregation(AggregationBuilders.dateHistogram("sales_by_month")
                    .field("createTime")
                    .calendarInterval(DateHistogramInterval.MONTH)
                    .format("yyyy-MM")
                    .minDocCount(0))  // 即使没有数据也显示
            .withMaxResults(0)
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    Histogram histogram = hits.getAggregations().get("sales_by_month");
    
    List<Map<String, Object>> result = new ArrayList<>();
    for (Histogram.Bucket bucket : histogram.getBuckets()) {
        Map<String, Object> item = new HashMap<>();
        item.put("month", bucket.getKeyAsString());
        item.put("count", bucket.getDocCount());
        result.add(item);
    }
    
    return result;
}
```

### 8.4 嵌套聚合

```java
/**
 * 嵌套聚合：先按品牌分组，再计算每个品牌的平均价格
 */
public List<Map<String, Object>> brandWithAvgPrice() {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .addAggregation(AggregationBuilders.terms("brand_agg")
                    .field("brand")
                    .size(10)
                    .subAggregation(AggregationBuilders.avg("avg_price").field("price"))
                    .subAggregation(AggregationBuilders.max("max_price").field("price"))
                    .subAggregation(AggregationBuilders.sum("total_sales").field("sales")))
            .withMaxResults(0)
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    Terms terms = hits.getAggregations().get("brand_agg");
    
    List<Map<String, Object>> result = new ArrayList<>();
    for (Terms.Bucket bucket : terms.getBuckets()) {
        Map<String, Object> item = new HashMap<>();
        item.put("brand", bucket.getKeyAsString());
        item.put("count", bucket.getDocCount());
        
        Avg avgPrice = bucket.getAggregations().get("avg_price");
        item.put("avgPrice", avgPrice.getValue());
        
        Max maxPrice = bucket.getAggregations().get("max_price");
        item.put("maxPrice", maxPrice.getValue());
        
        Sum totalSales = bucket.getAggregations().get("total_sales");
        item.put("totalSales", totalSales.getValue());
        
        result.add(item);
    }
    
    return result;
}

/**
 * 多层嵌套聚合：品牌 -> 分类 -> 统计
 */
public List<Map<String, Object>> brandCategoryStats() {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .addAggregation(AggregationBuilders.terms("brand_agg")
                    .field("brand")
                    .size(10)
                    .subAggregation(AggregationBuilders.terms("category_agg")
                            .field("category")
                            .size(5)
                            .subAggregation(AggregationBuilders.avg("avg_price").field("price"))))
            .withMaxResults(0)
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    Terms brandTerms = hits.getAggregations().get("brand_agg");
    
    List<Map<String, Object>> result = new ArrayList<>();
    for (Terms.Bucket brandBucket : brandTerms.getBuckets()) {
        Map<String, Object> brandItem = new HashMap<>();
        brandItem.put("brand", brandBucket.getKeyAsString());
        
        Terms categoryTerms = brandBucket.getAggregations().get("category_agg");
        List<Map<String, Object>> categories = new ArrayList<>();
        
        for (Terms.Bucket categoryBucket : categoryTerms.getBuckets()) {
            Map<String, Object> categoryItem = new HashMap<>();
            categoryItem.put("category", categoryBucket.getKeyAsString());
            categoryItem.put("count", categoryBucket.getDocCount());
            
            Avg avgPrice = categoryBucket.getAggregations().get("avg_price");
            categoryItem.put("avgPrice", avgPrice.getValue());
            
            categories.add(categoryItem);
        }
        
        brandItem.put("categories", categories);
        result.add(brandItem);
    }
    
    return result;
}
```

### 8.5 Kibana 中的聚合示例

```json
// 基础指标聚合
GET /products/_search
{
  "size": 0,
  "aggs": {
    "avg_price": { "avg": { "field": "price" } },
    "max_price": { "max": { "field": "price" } },
    "min_price": { "min": { "field": "price" } },
    "total_sales": { "sum": { "field": "sales" } },
    "brand_count": { "cardinality": { "field": "brand" } }
  }
}

// terms 聚合
GET /products/_search
{
  "size": 0,
  "aggs": {
    "brand_agg": {
      "terms": {
        "field": "brand",
        "size": 10,
        "order": { "_count": "desc" }
      }
    }
  }
}

// 嵌套聚合
GET /products/_search
{
  "size": 0,
  "aggs": {
    "brand_agg": {
      "terms": {
        "field": "brand",
        "size": 10
      },
      "aggs": {
        "avg_price": { "avg": { "field": "price" } },
        "category_agg": {
          "terms": {
            "field": "category",
            "size": 5
          }
        }
      }
    }
  }
}

// 带查询条件的聚合
GET /products/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "onSale": true } },
        { "range": { "price": { "gte": 1000 } } }
      ]
    }
  },
  "aggs": {
    "brand_stats": {
      "terms": {
        "field": "brand"
      },
      "aggs": {
        "price_stats": {
          "stats": { "field": "price" }
        }
      }
    }
  }
}
```

---

## 9. 分词与分析器

### 9.1 分析器组成

分析器（Analyzer）由三部分组成：

```
原始文本 -> Character Filters -> Tokenizer -> Token Filters -> 词项
```

1. **Character Filters**：字符过滤器，预处理文本
2. **Tokenizer**：分词器，将文本切分成词项
3. **Token Filters**：词项过滤器，对词项进行处理

### 9.2 内置分析器

| 分析器 | 说明 | 示例 |
|--------|------|------|
| standard | 标准分析器（默认） | "Hello World" → ["hello", "world"] |
| simple | 简单分析器，按非字母分割 | "Hello-World" → ["hello", "world"] |
| whitespace | 空格分析器 | "Hello World" → ["Hello", "World"] |
| keyword | 不分词 | "Hello World" → ["Hello World"] |
| ik_smart | IK 智能分词 | "中华人民共和国" → ["中华人民共和国"] |
| ik_max_word | IK 最细粒度分词 | "中华人民共和国" → ["中华人民共和国", "中华人民", ...] |

### 9.3 测试分析器

```json
// 测试标准分析器
POST /_analyze
{
  "analyzer": "standard",
  "text": "Hello World, This is Elasticsearch!"
}

// 测试 IK 分词器
POST /_analyze
{
  "analyzer": "ik_smart",
  "text": "中华人民共和国国歌"
}

// 测试指定索引的字段分析器
POST /products/_analyze
{
  "field": "name",
  "text": "iPhone 15 Pro Max 苹果手机"
}
```

### 9.4 自定义分析器

```json
// 创建索引时定义自定义分析器
PUT /my_index
{
  "settings": {
    "analysis": {
      "char_filter": {
        "my_char_filter": {
          "type": "mapping",
          "mappings": ["& => and", "| => or"]
        }
      },
      "tokenizer": {
        "my_tokenizer": {
          "type": "pattern",
          "pattern": "[\\W_]+"
        }
      },
      "filter": {
        "my_stopwords": {
          "type": "stop",
          "stopwords": ["the", "a", "an", "is", "are"]
        }
      },
      "analyzer": {
        "my_analyzer": {
          "type": "custom",
          "char_filter": ["my_char_filter"],
          "tokenizer": "my_tokenizer",
          "filter": ["lowercase", "my_stopwords"]
        }
      }
    }
  },
  "mappings": {
    "properties": {
      "content": {
        "type": "text",
        "analyzer": "my_analyzer"
      }
    }
  }
}
```

### 9.5 IK 分词器自定义词典

IK 分词器支持自定义词典，用于添加新词或停用词：

```bash
# 进入 ES 容器
docker exec -it elasticsearch bash

# 编辑 IK 配置文件
cd /usr/share/elasticsearch/config/analysis-ik/

# 创建自定义词典
echo "苹果手机" >> custom.dic
echo "华为手机" >> custom.dic

# 创建停用词词典
echo "的" >> stopword.dic
echo "了" >> stopword.dic

# 编辑 IKAnalyzer.cfg.xml
vim IKAnalyzer.cfg.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE properties SYSTEM "http://java.sun.com/dtd/properties.dtd">
<properties>
    <comment>IK Analyzer 扩展配置</comment>
    <!-- 自定义词典 -->
    <entry key="ext_dict">custom.dic</entry>
    <!-- 自定义停用词词典 -->
    <entry key="ext_stopwords">stopword.dic</entry>
    <!-- 远程词典（支持热更新） -->
    <entry key="remote_ext_dict">http://your-server/dict.txt</entry>
</properties>
```

```bash
# 重启 ES 使配置生效
docker restart elasticsearch
```

---

## 10. 高亮搜索

高亮搜索可以在搜索结果中标记匹配的关键词，常用于搜索结果展示。

### 10.1 基础高亮

```java
import org.elasticsearch.search.fetch.subphase.highlight.HighlightBuilder;

/**
 * 高亮搜索
 */
public SearchResult<Product> searchWithHighlight(String keyword, int page, int size) {
    // 构建高亮
    HighlightBuilder highlightBuilder = new HighlightBuilder()
            .field("name")
            .field("description")
            .preTags("<em class='highlight'>")  // 高亮前缀
            .postTags("</em>")                   // 高亮后缀
            .fragmentSize(100)                   // 片段大小
            .numOfFragments(3);                  // 片段数量

    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.multiMatchQuery(keyword, "name", "description"))
            .withHighlightBuilder(highlightBuilder)
            .withPageable(PageRequest.of(page, size))
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    
    List<Product> products = new ArrayList<>();
    for (SearchHit<Product> hit : hits) {
        Product product = hit.getContent();
        
        // 获取高亮结果
        Map<String, List<String>> highlightFields = hit.getHighlightFields();
        
        // 用高亮内容替换原内容
        if (highlightFields.containsKey("name")) {
            product.setName(highlightFields.get("name").get(0));
        }
        if (highlightFields.containsKey("description")) {
            product.setDescription(String.join("...", highlightFields.get("description")));
        }
        
        products.add(product);
    }
    
    return new SearchResult<>(products, hits.getTotalHits());
}
```

### 10.2 高亮配置选项

```java
HighlightBuilder highlightBuilder = new HighlightBuilder()
        // 指定高亮字段
        .field(new HighlightBuilder.Field("name")
                .preTags("<strong>")
                .postTags("</strong>"))
        .field(new HighlightBuilder.Field("description")
                .preTags("<em>")
                .postTags("</em>")
                .fragmentSize(150)
                .numOfFragments(3))
        
        // 全局设置
        .requireFieldMatch(false)  // 是否只高亮匹配的字段
        .encoder("html")           // HTML 编码，防止 XSS
        
        // 高亮类型
        .highlighterType("unified");  // unified（默认）、plain、fvh
```

### 10.3 Kibana 中的高亮查询

```json
GET /products/_search
{
  "query": {
    "multi_match": {
      "query": "苹果手机",
      "fields": ["name", "description"]
    }
  },
  "highlight": {
    "pre_tags": ["<em class='highlight'>"],
    "post_tags": ["</em>"],
    "fields": {
      "name": {
        "fragment_size": 100,
        "number_of_fragments": 1
      },
      "description": {
        "fragment_size": 150,
        "number_of_fragments": 3
      }
    }
  }
}
```

---

## 11. 分页与排序

### 11.1 基础分页

```java
/**
 * 基础分页查询
 */
public Page<Product> searchWithPagination(String keyword, int page, int size) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.matchQuery("name", keyword))
            .withPageable(PageRequest.of(page, size))
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    
    List<Product> products = hits.stream()
            .map(SearchHit::getContent)
            .collect(Collectors.toList());
    
    return new PageImpl<>(products, PageRequest.of(page, size), hits.getTotalHits());
}
```

### 11.2 深度分页问题

ES 默认限制 `from + size <= 10000`，超过会报错。这是因为深度分页性能很差。

**解决方案**：

```java
/**
 * 方案一：search_after（推荐）
 * 适用于实时滚动翻页
 */
public List<Product> searchAfter(String keyword, Object[] searchAfter, int size) {
    NativeSearchQueryBuilder builder = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.matchQuery("name", keyword))
            .withSort(SortBuilders.fieldSort("_score").order(SortOrder.DESC))
            .withSort(SortBuilders.fieldSort("id").order(SortOrder.ASC))  // 必须有唯一排序字段
            .withPageable(PageRequest.of(0, size));
    
    if (searchAfter != null && searchAfter.length > 0) {
        builder.withSearchAfter(Arrays.asList(searchAfter));
    }
    
    NativeSearchQuery query = builder.build();
    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    
    return hits.stream()
            .map(SearchHit::getContent)
            .collect(Collectors.toList());
}

/**
 * 方案二：Scroll API
 * 适用于导出大量数据
 */
public List<Product> scrollSearch(String keyword) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.matchQuery("name", keyword))
            .withPageable(PageRequest.of(0, 1000))
            .build();

    List<Product> allProducts = new ArrayList<>();
    
    // 开始滚动
    SearchScrollHits<Product> scroll = elasticsearchRestTemplate.searchScrollStart(
            60000,  // scroll 上下文保持时间（毫秒）
            query,
            Product.class,
            elasticsearchRestTemplate.getIndexCoordinatesFor(Product.class)
    );
    
    String scrollId = scroll.getScrollId();
    
    while (scroll.hasSearchHits()) {
        scroll.getSearchHits().forEach(hit -> allProducts.add(hit.getContent()));
        
        // 继续滚动
        scroll = elasticsearchRestTemplate.searchScrollContinue(
                scrollId,
                60000,
                Product.class,
                elasticsearchRestTemplate.getIndexCoordinatesFor(Product.class)
        );
    }
    
    // 清除 scroll 上下文
    elasticsearchRestTemplate.searchScrollClear(Collections.singletonList(scrollId));
    
    return allProducts;
}
```

### 11.3 排序

```java
/**
 * 多字段排序
 */
public List<Product> searchWithSort(String keyword) {
    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(QueryBuilders.matchQuery("name", keyword))
            .withSort(SortBuilders.scoreSort().order(SortOrder.DESC))  // 按评分降序
            .withSort(SortBuilders.fieldSort("sales").order(SortOrder.DESC))  // 按销量降序
            .withSort(SortBuilders.fieldSort("price").order(SortOrder.ASC))   // 按价格升序
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    return hits.stream().map(SearchHit::getContent).collect(Collectors.toList());
}

/**
 * 自定义评分排序
 */
public List<Product> searchWithFunctionScore(String keyword) {
    FunctionScoreQueryBuilder functionScoreQuery = QueryBuilders.functionScoreQuery(
            QueryBuilders.matchQuery("name", keyword),
            new FunctionScoreQueryBuilder.FilterFunctionBuilder[]{
                    // 销量高的加分
                    new FunctionScoreQueryBuilder.FilterFunctionBuilder(
                            ScoreFunctionBuilders.fieldValueFactorFunction("sales")
                                    .factor(0.1f)
                                    .modifier(FieldValueFactorFunction.Modifier.LOG1P)
                                    .missing(1)
                    ),
                    // 新品加分
                    new FunctionScoreQueryBuilder.FilterFunctionBuilder(
                            QueryBuilders.rangeQuery("createTime").gte("now-7d"),
                            ScoreFunctionBuilders.weightFactorFunction(2)
                    )
            }
    ).scoreMode(FunctionScoreQuery.ScoreMode.SUM)
     .boostMode(CombineFunction.MULTIPLY);

    NativeSearchQuery query = new NativeSearchQueryBuilder()
            .withQuery(functionScoreQuery)
            .build();

    SearchHits<Product> hits = elasticsearchRestTemplate.search(query, Product.class);
    return hits.stream().map(SearchHit::getContent).collect(Collectors.toList());
}
```

### 11.4 Kibana 中的分页排序

```json
// 基础分页
GET /products/_search
{
  "from": 0,
  "size": 10,
  "query": {
    "match": { "name": "手机" }
  },
  "sort": [
    { "_score": "desc" },
    { "sales": "desc" },
    { "price": "asc" }
  ]
}

// search_after 分页
GET /products/_search
{
  "size": 10,
  "query": {
    "match": { "name": "手机" }
  },
  "sort": [
    { "_score": "desc" },
    { "_id": "asc" }
  ],
  "search_after": [0.8, "product_100"]
}
```

---

## 12. 批量操作

### 12.1 批量写入

```java
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.common.xcontent.XContentType;

/**
 * 批量写入文档
 */
public void bulkInsert(List<Product> products) throws Exception {
    BulkRequest bulkRequest = new BulkRequest();
    
    for (Product product : products) {
        IndexRequest indexRequest = new IndexRequest("products")
                .id(product.getId())
                .source(objectMapper.writeValueAsString(product), XContentType.JSON);
        bulkRequest.add(indexRequest);
    }
    
    // 设置刷新策略
    bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);
    
    BulkResponse response = restHighLevelClient.bulk(bulkRequest, RequestOptions.DEFAULT);
    
    if (response.hasFailures()) {
        // 处理失败
        for (BulkItemResponse item : response.getItems()) {
            if (item.isFailed()) {
                log.error("批量写入失败: {}, 原因: {}", 
                        item.getId(), item.getFailureMessage());
            }
        }
    }
}

/**
 * 使用 Spring Data 批量保存
 */
public void bulkSaveWithSpringData(List<Product> products) {
    // 分批处理，避免内存溢出
    int batchSize = 1000;
    for (int i = 0; i < products.size(); i += batchSize) {
        int end = Math.min(i + batchSize, products.size());
        List<Product> batch = products.subList(i, end);
        productRepository.saveAll(batch);
    }
}
```

### 12.2 批量更新和删除

```java
/**
 * 批量更新
 */
public void bulkUpdate(Map<String, Map<String, Object>> updates) throws Exception {
    BulkRequest bulkRequest = new BulkRequest();
    
    for (Map.Entry<String, Map<String, Object>> entry : updates.entrySet()) {
        UpdateRequest updateRequest = new UpdateRequest("products", entry.getKey())
                .doc(entry.getValue());
        bulkRequest.add(updateRequest);
    }
    
    restHighLevelClient.bulk(bulkRequest, RequestOptions.DEFAULT);
}

/**
 * 批量删除
 */
public void bulkDelete(List<String> ids) throws Exception {
    BulkRequest bulkRequest = new BulkRequest();
    
    for (String id : ids) {
        DeleteRequest deleteRequest = new DeleteRequest("products", id);
        bulkRequest.add(deleteRequest);
    }
    
    restHighLevelClient.bulk(bulkRequest, RequestOptions.DEFAULT);
}

/**
 * 根据查询条件批量更新
 */
public void updateByQuery(String brand, BigDecimal discount) throws Exception {
    UpdateByQueryRequest request = new UpdateByQueryRequest("products");
    request.setQuery(QueryBuilders.termQuery("brand", brand));
    request.setScript(new Script(
            ScriptType.INLINE,
            "painless",
            "ctx._source.price = ctx._source.price * params.discount",
            Collections.singletonMap("discount", discount)
    ));
    request.setRefresh(true);
    
    restHighLevelClient.updateByQuery(request, RequestOptions.DEFAULT);
}
```

### 12.3 Kibana 中的批量操作

```json
// 批量操作（_bulk API）
POST /_bulk
{"index": {"_index": "products", "_id": "1"}}
{"name": "iPhone 15", "brand": "Apple", "price": 5999}
{"index": {"_index": "products", "_id": "2"}}
{"name": "华为 Mate 60", "brand": "Huawei", "price": 5499}
{"update": {"_index": "products", "_id": "1"}}
{"doc": {"price": 5799}}
{"delete": {"_index": "products", "_id": "3"}}

// 根据查询条件更新
POST /products/_update_by_query
{
  "query": {
    "term": { "brand": "Apple" }
  },
  "script": {
    "source": "ctx._source.price = ctx._source.price * 0.9",
    "lang": "painless"
  }
}

// 根据查询条件删除
POST /products/_delete_by_query
{
  "query": {
    "range": {
      "stock": { "lte": 0 }
    }
  }
}
```

---

## 13. 索引别名与重建

### 13.1 索引别名

索引别名是指向一个或多个索引的虚拟名称，可以实现：
- 零停机时间重建索引
- 多索引查询
- 索引版本管理

```json
// 创建别名
POST /_aliases
{
  "actions": [
    { "add": { "index": "products_v1", "alias": "products" } }
  ]
}

// 切换别名（原子操作）
POST /_aliases
{
  "actions": [
    { "remove": { "index": "products_v1", "alias": "products" } },
    { "add": { "index": "products_v2", "alias": "products" } }
  ]
}

// 查看别名
GET /_alias/products

// 删除别名
POST /_aliases
{
  "actions": [
    { "remove": { "index": "products_v1", "alias": "products" } }
  ]
}
```

### 13.2 零停机重建索引

当需要修改映射或分片数时，必须重建索引。以下是零停机重建的步骤：

```java
@Service
@RequiredArgsConstructor
public class IndexRebuilder {

    private final RestHighLevelClient client;

    /**
     * 零停机重建索引
     */
    public void reindex(String aliasName, String newIndexName, String mapping) throws Exception {
        // 1. 获取当前别名指向的索引
        GetAliasesRequest getAliasRequest = new GetAliasesRequest(aliasName);
        GetAliasesResponse aliasResponse = client.indices()
                .getAlias(getAliasRequest, RequestOptions.DEFAULT);
        String oldIndexName = aliasResponse.getAliases().keySet().iterator().next();

        // 2. 创建新索引
        CreateIndexRequest createRequest = new CreateIndexRequest(newIndexName);
        createRequest.mapping(mapping, XContentType.JSON);
        createRequest.settings(Settings.builder()
                .put("index.number_of_shards", 3)
                .put("index.number_of_replicas", 1)
        );
        client.indices().create(createRequest, RequestOptions.DEFAULT);

        // 3. 数据迁移（reindex）
        ReindexRequest reindexRequest = new ReindexRequest();
        reindexRequest.setSourceIndices(oldIndexName);
        reindexRequest.setDestIndex(newIndexName);
        reindexRequest.setRefresh(true);
        
        // 可选：添加查询条件，只迁移部分数据
        // reindexRequest.setSourceQuery(QueryBuilders.termQuery("status", "active"));
        
        client.reindex(reindexRequest, RequestOptions.DEFAULT);

        // 4. 原子切换别名
        IndicesAliasesRequest aliasRequest = new IndicesAliasesRequest();
        aliasRequest.addAliasAction(
                IndicesAliasesRequest.AliasActions.remove()
                        .index(oldIndexName)
                        .alias(aliasName)
        );
        aliasRequest.addAliasAction(
                IndicesAliasesRequest.AliasActions.add()
                        .index(newIndexName)
                        .alias(aliasName)
        );
        client.indices().updateAliases(aliasRequest, RequestOptions.DEFAULT);

        // 5. 删除旧索引（可选，建议保留一段时间）
        // DeleteIndexRequest deleteRequest = new DeleteIndexRequest(oldIndexName);
        // client.indices().delete(deleteRequest, RequestOptions.DEFAULT);
    }
}
```

### 13.3 Kibana 中的 Reindex

```json
// 基础 reindex
POST /_reindex
{
  "source": {
    "index": "products_v1"
  },
  "dest": {
    "index": "products_v2"
  }
}

// 带条件的 reindex
POST /_reindex
{
  "source": {
    "index": "products_v1",
    "query": {
      "term": { "onSale": true }
    }
  },
  "dest": {
    "index": "products_v2"
  }
}

// 修改字段的 reindex
POST /_reindex
{
  "source": {
    "index": "products_v1"
  },
  "dest": {
    "index": "products_v2"
  },
  "script": {
    "source": "ctx._source.newField = ctx._source.remove('oldField')"
  }
}
```

---

## 14. 性能优化

### 14.1 写入优化

```java
// 1. 批量写入，减少网络开销
BulkRequest bulkRequest = new BulkRequest();
// 添加多个请求...
bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.NONE);  // 不立即刷新

// 2. 调整刷新间隔（写入密集时）
PUT /products/_settings
{
  "index.refresh_interval": "30s"  // 默认 1s，写入密集时可调大
}

// 3. 关闭副本（大量导入数据时）
PUT /products/_settings
{
  "index.number_of_replicas": 0
}
// 导入完成后恢复
PUT /products/_settings
{
  "index.number_of_replicas": 1
}

// 4. 使用自动生成 ID（比指定 ID 快）
POST /products/_doc
{
  "name": "Product"
}
```

### 14.2 查询优化

```java
// 1. 使用 filter 代替 query（不需要评分时）
BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
        .filter(QueryBuilders.termQuery("brand", "Apple"))  // 使用 filter
        .filter(QueryBuilders.rangeQuery("price").lte(10000));

// 2. 只返回需要的字段
NativeSearchQuery query = new NativeSearchQueryBuilder()
        .withQuery(boolQuery)
        .withSourceFilter(new FetchSourceFilter(
                new String[]{"name", "price"},  // 包含的字段
                new String[]{}                   // 排除的字段
        ))
        .build();

// 3. 使用 routing 减少分片扫描
IndexRequest request = new IndexRequest("products")
        .id("1")
        .routing("Apple")  // 相同 routing 的文档在同一分片
        .source(json, XContentType.JSON);

// 查询时指定 routing
NativeSearchQuery query = new NativeSearchQueryBuilder()
        .withQuery(QueryBuilders.termQuery("brand", "Apple"))
        .withRoute("Apple")
        .build();

// 4. 避免深度分页，使用 search_after
// 见第 11 节

// 5. 使用 preference 保证查询一致性
SearchRequest searchRequest = new SearchRequest("products");
searchRequest.preference("_local");  // 优先本地分片
// 或使用自定义值保证同一用户查询同一分片
searchRequest.preference("user_123");
```

### 14.3 映射优化

```json
// 1. 禁用不需要的功能
PUT /products
{
  "mappings": {
    "properties": {
      "description": {
        "type": "text",
        "norms": false,      // 不需要评分时禁用
        "index_options": "freqs"  // 减少索引信息
      },
      "internal_id": {
        "type": "keyword",
        "doc_values": false,  // 不需要排序/聚合时禁用
        "index": false        // 不需要搜索时禁用
      }
    }
  }
}

// 2. 使用合适的数据类型
// - 整数优先使用 integer 而非 long
// - 精确匹配使用 keyword 而非 text
// - 不需要范围查询的数字可以用 keyword

// 3. 避免使用动态映射
PUT /products
{
  "mappings": {
    "dynamic": "strict"  // 禁止自动创建字段
  }
}
```

### 14.4 集群优化

```yaml
# elasticsearch.yml

# 内存设置（建议不超过 32GB）
# -Xms16g -Xmx16g

# 线程池设置
thread_pool:
  write:
    size: 8
    queue_size: 1000
  search:
    size: 12
    queue_size: 1000

# 断路器设置
indices.breaker.total.limit: 70%
indices.breaker.fielddata.limit: 40%
indices.breaker.request.limit: 40%

# 缓存设置
indices.queries.cache.size: 10%
indices.fielddata.cache.size: 20%
```

### 14.5 监控与诊断

```json
// 查看集群健康状态
GET /_cluster/health

// 查看节点状态
GET /_nodes/stats

// 查看索引状态
GET /products/_stats

// 查看慢查询日志
PUT /products/_settings
{
  "index.search.slowlog.threshold.query.warn": "10s",
  "index.search.slowlog.threshold.query.info": "5s",
  "index.search.slowlog.threshold.fetch.warn": "1s"
}

// 分析查询性能
GET /products/_search
{
  "profile": true,
  "query": {
    "match": { "name": "手机" }
  }
}

// 查看分片分配
GET /_cat/shards/products?v
```


---

## 15. 集群与分片

### 15.1 集群架构

ES 集群由多个节点组成，每个节点可以承担不同的角色：

| 节点角色 | 配置 | 说明 |
|----------|------|------|
| Master | `node.master: true` | 管理集群状态、索引创建删除、分片分配 |
| Data | `node.data: true` | 存储数据、执行 CRUD、搜索、聚合 |
| Ingest | `node.ingest: true` | 数据预处理（类似 Logstash） |
| Coordinating | 所有角色为 false | 路由请求、合并结果、负载均衡 |
| ML | `node.ml: true` | 机器学习任务 |

**生产环境推荐配置**：
```yaml
# 专用 Master 节点（至少 3 个，保证高可用）
node.master: true
node.data: false
node.ingest: false

# 专用 Data 节点
node.master: false
node.data: true
node.ingest: false

# 专用协调节点（可选）
node.master: false
node.data: false
node.ingest: false
```

### 15.2 分片策略

**主分片（Primary Shard）**：
- 数据的原始存储位置
- 创建索引时确定，之后不可更改
- 每个文档只属于一个主分片

**副本分片（Replica Shard）**：
- 主分片的完整复制
- 提供高可用和读取负载均衡
- 可以动态调整数量

```json
// 创建索引时设置分片
PUT /products
{
  "settings": {
    "number_of_shards": 3,      // 主分片数（不可更改）
    "number_of_replicas": 1     // 每个主分片的副本数
  }
}

// 动态调整副本数
PUT /products/_settings
{
  "number_of_replicas": 2
}
```

**分片数量规划**：
- 单个分片建议 10GB - 50GB
- 分片数 = 数据量 / 单分片大小
- 考虑未来数据增长
- 分片过多会增加协调开销
- 分片过少会限制扩展能力

### 15.3 路由机制

ES 使用路由算法决定文档存储在哪个分片：

```
shard = hash(_routing) % number_of_primary_shards
```

默认 `_routing` 等于文档 `_id`，可以自定义：

```json
// 写入时指定 routing
PUT /products/_doc/1?routing=Apple
{
  "name": "iPhone 15",
  "brand": "Apple"
}

// 查询时指定 routing（只查询特定分片，提高性能）
GET /products/_search?routing=Apple
{
  "query": {
    "match": { "name": "iPhone" }
  }
}
```

**自定义路由的应用场景**：
- 多租户系统：按租户 ID 路由
- 时序数据：按日期路由
- 地理数据：按区域路由

### 15.4 集群健康状态

```json
// 查看集群健康
GET /_cluster/health

// 返回示例
{
  "cluster_name": "my-cluster",
  "status": "green",           // green/yellow/red
  "number_of_nodes": 3,
  "number_of_data_nodes": 3,
  "active_primary_shards": 10,
  "active_shards": 20,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 0
}
```

| 状态 | 含义 | 处理方式 |
|------|------|----------|
| Green | 所有分片正常 | 无需处理 |
| Yellow | 主分片正常，部分副本未分配 | 检查节点数量、磁盘空间 |
| Red | 部分主分片不可用 | 紧急处理，检查节点状态 |

### 15.5 分片分配与恢复

```json
// 查看分片分配情况
GET /_cat/shards/products?v

// 查看未分配分片的原因
GET /_cluster/allocation/explain
{
  "index": "products",
  "shard": 0,
  "primary": true
}

// 手动移动分片
POST /_cluster/reroute
{
  "commands": [
    {
      "move": {
        "index": "products",
        "shard": 0,
        "from_node": "node1",
        "to_node": "node2"
      }
    }
  ]
}

// 强制分配未分配的分片（谨慎使用）
POST /_cluster/reroute
{
  "commands": [
    {
      "allocate_stale_primary": {
        "index": "products",
        "shard": 0,
        "node": "node1",
        "accept_data_loss": true
      }
    }
  ]
}
```

### 15.6 跨集群搜索

```json
// 配置远程集群
PUT /_cluster/settings
{
  "persistent": {
    "cluster.remote.cluster_two.seeds": ["192.168.1.100:9300"]
  }
}

// 跨集群搜索
GET /cluster_two:products,products/_search
{
  "query": {
    "match": { "name": "手机" }
  }
}
```

### 15.7 Docker Compose 集群部署

```yaml
version: '3.8'
services:
  es01:
    image: elasticsearch:7.17.9
    container_name: es01
    environment:
      - node.name=es01
      - cluster.name=es-cluster
      - discovery.seed_hosts=es02,es03
      - cluster.initial_master_nodes=es01,es02,es03
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - es01-data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - elastic

  es02:
    image: elasticsearch:7.17.9
    container_name: es02
    environment:
      - node.name=es02
      - cluster.name=es-cluster
      - discovery.seed_hosts=es01,es03
      - cluster.initial_master_nodes=es01,es02,es03
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - es02-data:/usr/share/elasticsearch/data
    networks:
      - elastic

  es03:
    image: elasticsearch:7.17.9
    container_name: es03
    environment:
      - node.name=es03
      - cluster.name=es-cluster
      - discovery.seed_hosts=es01,es02
      - cluster.initial_master_nodes=es01,es02,es03
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - es03-data:/usr/share/elasticsearch/data
    networks:
      - elastic

volumes:
  es01-data:
  es02-data:
  es03-data:

networks:
  elastic:
    driver: bridge
```

---

## 16. 常见错误与解决方案

### 16.1 集群状态异常

#### Red 状态：主分片不可用

**错误现象**：
```json
{
  "status": "red",
  "unassigned_shards": 5
}
```

**排查步骤**：
```json
// 1. 查看未分配分片
GET /_cat/shards?v&h=index,shard,prirep,state,unassigned.reason

// 2. 查看分配失败原因
GET /_cluster/allocation/explain

// 3. 查看节点状态
GET /_cat/nodes?v
```

**常见原因与解决方案**：

| 原因 | 解决方案 |
|------|----------|
| 节点宕机 | 重启节点或等待副本提升为主分片 |
| 磁盘空间不足 | 清理磁盘或扩容 |
| 分片数据损坏 | 从副本恢复或接受数据丢失 |

```json
// 磁盘空间不足时，调整水位线
PUT /_cluster/settings
{
  "persistent": {
    "cluster.routing.allocation.disk.watermark.low": "85%",
    "cluster.routing.allocation.disk.watermark.high": "90%",
    "cluster.routing.allocation.disk.watermark.flood_stage": "95%"
  }
}
```

#### Yellow 状态：副本未分配

**常见原因**：
- 单节点集群（副本无法分配到同一节点）
- 节点数少于副本数 + 1

**解决方案**：
```json
// 单节点开发环境，设置副本为 0
PUT /products/_settings
{
  "number_of_replicas": 0
}

// 或添加更多节点
```

### 16.2 查询相关错误

#### Result window is too large

**错误信息**：
```
Result window is too large, from + size must be less than or equal to: [10000]
```

**原因**：深度分页超过限制

**解决方案**：
```json
// 方案一：调整限制（不推荐）
PUT /products/_settings
{
  "max_result_window": 50000
}

// 方案二：使用 search_after（推荐）
GET /products/_search
{
  "size": 10,
  "sort": [{ "_id": "asc" }],
  "search_after": ["last_sort_value"]
}

// 方案三：使用 Scroll API（导出数据）
POST /products/_search?scroll=1m
{
  "size": 1000,
  "query": { "match_all": {} }
}
```

#### circuit_breaking_exception

**错误信息**：
```
[parent] Data too large, data for [<http_request>] would be [xxx/xxxgb]
```

**原因**：查询消耗内存超过断路器限制

**解决方案**：
```json
// 1. 优化查询，减少返回数据量
GET /products/_search
{
  "size": 100,
  "_source": ["name", "price"],  // 只返回需要的字段
  "query": { ... }
}

// 2. 调整断路器设置（临时方案）
PUT /_cluster/settings
{
  "persistent": {
    "indices.breaker.total.limit": "80%"
  }
}

// 3. 增加节点内存
```

#### query_shard_exception

**错误信息**：
```
failed to create query: For input string: "xxx"
```

**原因**：查询语法错误或字段类型不匹配

**解决方案**：
```json
// 检查字段类型
GET /products/_mapping

// 确保查询值类型正确
// 错误：对 integer 字段使用字符串
{ "term": { "price": "abc" } }

// 正确
{ "term": { "price": 100 } }
```

### 16.3 写入相关错误

#### version_conflict_engine_exception

**错误信息**：
```
version conflict, current version [2] is different than the one provided [1]
```

**原因**：并发更新导致版本冲突

**解决方案**：
```json
// 方案一：使用 retry_on_conflict
POST /products/_update/1?retry_on_conflict=3
{
  "doc": { "price": 100 }
}

// 方案二：使用乐观锁
PUT /products/_doc/1?if_seq_no=10&if_primary_term=1
{
  "name": "iPhone 15",
  "price": 5999
}

// 方案三：使用脚本更新（原子操作）
POST /products/_update/1
{
  "script": {
    "source": "ctx._source.stock -= params.count",
    "params": { "count": 1 }
  }
}
```

#### mapper_parsing_exception

**错误信息**：
```
failed to parse field [price] of type [long]
```

**原因**：写入数据类型与映射不匹配

**解决方案**：
```java
// 1. 检查数据类型
// 错误：price 字段定义为 long，但写入了字符串
{ "price": "5999" }

// 正确
{ "price": 5999 }

// 2. 如果需要修改映射，必须重建索引
// 见第 13 节
```

#### rejected execution

**错误信息**：
```
rejected execution of ... on EsThreadPoolExecutor
```

**原因**：线程池队列已满

**解决方案**：
```yaml
# 1. 调整线程池配置
thread_pool:
  write:
    size: 8
    queue_size: 2000

# 2. 减少并发写入量

# 3. 增加节点
```

### 16.4 索引相关错误

#### index_not_found_exception

**错误信息**：
```
no such index [products]
```

**解决方案**：
```json
// 检查索引是否存在
HEAD /products

// 创建索引
PUT /products
{
  "mappings": { ... }
}

// 或检查别名
GET /_alias/products
```

#### illegal_argument_exception: mapper cannot be changed

**错误信息**：
```
mapper [price] cannot be changed from type [long] to [text]
```

**原因**：尝试修改已存在字段的类型

**解决方案**：
```json
// ES 不支持修改字段类型，必须重建索引
// 1. 创建新索引
PUT /products_v2
{
  "mappings": {
    "properties": {
      "price": { "type": "text" }
    }
  }
}

// 2. 迁移数据
POST /_reindex
{
  "source": { "index": "products_v1" },
  "dest": { "index": "products_v2" }
}

// 3. 切换别名
POST /_aliases
{
  "actions": [
    { "remove": { "index": "products_v1", "alias": "products" } },
    { "add": { "index": "products_v2", "alias": "products" } }
  ]
}
```

### 16.5 连接相关错误

#### Connection refused

**错误信息**：
```
Connection refused: localhost:9200
```

**排查步骤**：
```bash
# 1. 检查 ES 是否运行
docker ps | grep elasticsearch
curl http://localhost:9200

# 2. 检查端口绑定
netstat -tlnp | grep 9200

# 3. 检查防火墙
iptables -L -n

# 4. 检查 ES 日志
docker logs elasticsearch
```

#### NoNodeAvailableException

**错误信息**：
```
NoNodeAvailableException[None of the configured nodes are available]
```

**Java 客户端排查**：
```java
// 检查配置
ClientConfiguration configuration = ClientConfiguration.builder()
        .connectedTo("localhost:9200")  // 确保地址正确
        .withConnectTimeout(Duration.ofSeconds(5))
        .withSocketTimeout(Duration.ofSeconds(30))
        .build();

// 检查网络连通性
// 确保应用能访问 ES 节点
```

### 16.6 性能相关问题

#### 查询慢

**排查步骤**：
```json
// 1. 开启慢查询日志
PUT /products/_settings
{
  "index.search.slowlog.threshold.query.warn": "5s",
  "index.search.slowlog.threshold.query.info": "2s"
}

// 2. 使用 Profile API 分析
GET /products/_search
{
  "profile": true,
  "query": { ... }
}

// 3. 检查分片大小
GET /_cat/shards/products?v&h=index,shard,prirep,docs,store

// 4. 检查是否使用了昂贵的查询
// - wildcard 前缀通配符
// - script 查询
// - 深度分页
```

#### 写入慢

**优化建议**：
```json
// 1. 使用批量写入
POST /_bulk
{ ... }

// 2. 调整刷新间隔
PUT /products/_settings
{
  "refresh_interval": "30s"
}

// 3. 临时关闭副本（大量导入时）
PUT /products/_settings
{
  "number_of_replicas": 0
}

// 4. 使用自动生成 ID
POST /products/_doc
{ ... }
```

### 16.7 Java 客户端常见问题

#### Spring Data Elasticsearch 版本兼容

| Spring Boot | Spring Data ES | Elasticsearch |
|-------------|----------------|---------------|
| 2.7.x | 4.4.x | 7.17.x |
| 3.0.x | 5.0.x | 8.5.x |
| 3.1.x | 5.1.x | 8.7.x |

**版本不兼容错误**：
```
java.lang.NoSuchMethodError: org.elasticsearch.client.RestHighLevelClient
```

**解决方案**：
```xml
<!-- 确保版本匹配 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-elasticsearch</artifactId>
</dependency>
<dependency>
    <groupId>org.elasticsearch.client</groupId>
    <artifactId>elasticsearch-rest-high-level-client</artifactId>
    <version>7.17.9</version>  <!-- 与 ES 服务器版本一致 -->
</dependency>
```

#### 序列化问题

**错误信息**：
```
Cannot deserialize value of type `java.time.LocalDateTime`
```

**解决方案**：
```java
@Configuration
public class ElasticsearchConfig {
    
    @Bean
    public ElasticsearchCustomConversions elasticsearchCustomConversions() {
        return new ElasticsearchCustomConversions(Arrays.asList(
                new LocalDateTimeToStringConverter(),
                new StringToLocalDateTimeConverter()
        ));
    }
}

@WritingConverter
public class LocalDateTimeToStringConverter implements Converter<LocalDateTime, String> {
    @Override
    public String convert(LocalDateTime source) {
        return source.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}

@ReadingConverter
public class StringToLocalDateTimeConverter implements Converter<String, LocalDateTime> {
    @Override
    public LocalDateTime convert(String source) {
        return LocalDateTime.parse(source, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}
```

---

## 快速参考

### 常用 REST API

| 操作 | API |
|------|-----|
| 集群健康 | `GET /_cluster/health` |
| 节点信息 | `GET /_cat/nodes?v` |
| 索引列表 | `GET /_cat/indices?v` |
| 分片信息 | `GET /_cat/shards?v` |
| 创建索引 | `PUT /index_name` |
| 删除索引 | `DELETE /index_name` |
| 查看映射 | `GET /index_name/_mapping` |
| 添加文档 | `POST /index_name/_doc` |
| 查询文档 | `GET /index_name/_search` |
| 批量操作 | `POST /_bulk` |

### 查询类型速查

| 查询类型 | 用途 | 示例 |
|----------|------|------|
| match | 全文搜索 | `{"match": {"name": "手机"}}` |
| term | 精确匹配 | `{"term": {"brand": "Apple"}}` |
| range | 范围查询 | `{"range": {"price": {"gte": 100}}}` |
| bool | 组合查询 | `{"bool": {"must": [...], "filter": [...]}}` |
| nested | 嵌套查询 | `{"nested": {"path": "attrs", "query": {...}}}` |

---

> 💡 **小贴士**：ES 是一个功能强大但也相对复杂的系统，建议在生产环境使用前充分测试，并建立完善的监控和告警机制。遇到问题时，ES 的官方文档和社区都是很好的资源。
