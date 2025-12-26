# MinIO 完整学习笔记

> MinIO 是一个高性能、兼容 S3 API 的对象存储服务
> 本笔记基于 Java 8 + Spring Boot 2.7.18
> 着重介绍与 Spring Boot 的各种集成方式

---

## 目录

1. [MinIO 简介](#1-minio-简介)
2. [安装部署](#2-安装部署)
3. [基础概念](#3-基础概念)
4. [Spring Boot 集成](#4-spring-boot-集成)
5. [基本操作](#5-基本操作)
6. [文件上传](#6-文件上传)
7. [文件下载](#7-文件下载)
8. [文件管理](#8-文件管理)
9. [预签名 URL](#9-预签名-url)
10. [存储桶策略](#10-存储桶策略)
11. [事件通知](#11-事件通知)
12. [高级特性](#12-高级特性)
13. [生产环境配置](#13-生产环境配置)
14. [常见错误与解决方案](#14-常见错误与解决方案)
15. [最佳实践](#15-最佳实践)

---

## 1. MinIO 简介

### 1.1 什么是 MinIO？

MinIO 是一个开源的高性能对象存储服务，完全兼容 Amazon S3 API。

**核心特点**：
- **S3 兼容**：100% 兼容 Amazon S3 API
- **高性能**：单节点读写速度可达 GB/s 级别
- **轻量级**：单个二进制文件，部署简单
- **云原生**：支持 Kubernetes、Docker 部署

### 1.2 应用场景

- 图片/视频存储、文档管理、日志存储、数据备份、静态资源托管


---

## 2. 安装部署

### 2.1 Docker 单机部署

```bash
# 启动 MinIO
docker run -d \
  --name minio \
  -p 9000:9000 \
  -p 9001:9001 \
  -e "MINIO_ROOT_USER=admin" \
  -e "MINIO_ROOT_PASSWORD=admin123456" \
  -v ~/minio/data:/data \
  minio/minio server /data --console-address ":9001"
```

**端口说明**：
- `9000`：API 端口（程序访问）
- `9001`：控制台端口（浏览器访问）

### 2.2 Docker Compose 部署

```yaml
# docker-compose.yml
version: '3.8'
services:
  minio:
    image: minio/minio:latest
    container_name: minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: admin
      MINIO_ROOT_PASSWORD: admin123456
    volumes:
      - ./data:/data
    command: server /data --console-address ":9001"
    restart: always
```

### 2.3 访问控制台

访问 http://localhost:9001，使用 admin/admin123456 登录

---

## 3. 基础概念

### 3.1 核心概念

```
┌─────────────────────────────────────────────────────────────────┐
│                        MinIO 核心概念                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Bucket（存储桶）                                                │
│  ├── 类似于文件系统的"根目录"                                    │
│  ├── 名称全局唯一                                               │
│  └── 可以设置访问策略                                           │
│                                                                 │
│  Object（对象）                                                  │
│  ├── 存储的基本单元（文件）                                      │
│  ├── 由 Key（路径）+ Value（内容）+ Metadata（元数据）组成       │
│  └── 最大支持 5TB 单文件                                        │
│                                                                 │
│  Key（键/路径）                                                  │
│  ├── 对象的唯一标识                                             │
│  ├── 可以包含 "/"，模拟目录结构                                 │
│  └── 例如：images/2024/01/avatar.jpg                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 存储结构示例

```
minio-server/
├── bucket-images/              # 图片存储桶
│   ├── avatar/
│   │   ├── user1.jpg
│   │   └── user2.jpg
│   └── product/
│       ├── p001.jpg
│       └── p002.jpg
├── bucket-documents/           # 文档存储桶
│   ├── contracts/
│   │   └── contract001.pdf
│   └── reports/
│       └── report2024.xlsx
└── bucket-backups/             # 备份存储桶
    └── db/
        └── backup-20240115.sql
```

---

## 4. Spring Boot 集成

### 4.1 添加依赖

```xml
<!-- pom.xml -->
<dependencies>
    <!-- MinIO Java SDK -->
    <dependency>
        <groupId>io.minio</groupId>
        <artifactId>minio</artifactId>
        <version>8.5.7</version>
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
    
    <!-- 配置处理器 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-configuration-processor</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>
```

### 4.2 配置文件

```yaml
# application.yml
minio:
  endpoint: http://localhost:9000
  access-key: admin
  secret-key: admin123456
  bucket-name: default-bucket
  
# 文件上传配置
spring:
  servlet:
    multipart:
      max-file-size: 100MB
      max-request-size: 100MB
```

### 4.3 配置属性类

```java
package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "minio")
public class MinioProperties {
    
    /**
     * MinIO 服务地址
     */
    private String endpoint;
    
    /**
     * 访问密钥
     */
    private String accessKey;
    
    /**
     * 秘密密钥
     */
    private String secretKey;
    
    /**
     * 默认存储桶名称
     */
    private String bucketName;
}
```

### 4.4 MinIO 客户端配置

```java
package com.example.config;

import io.minio.MinioClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class MinioConfig {
    
    private final MinioProperties properties;
    
    @Bean
    public MinioClient minioClient() {
        log.info("初始化 MinIO 客户端, endpoint: {}", properties.getEndpoint());
        
        return MinioClient.builder()
                .endpoint(properties.getEndpoint())
                .credentials(properties.getAccessKey(), properties.getSecretKey())
                .build();
    }
}
```


### 4.5 MinIO 工具类（核心封装）

```java
package com.example.util;

import com.example.config.MinioProperties;
import io.minio.*;
import io.minio.http.Method;
import io.minio.messages.Bucket;
import io.minio.messages.DeleteError;
import io.minio.messages.DeleteObject;
import io.minio.messages.Item;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class MinioUtil {
    
    private final MinioClient minioClient;
    private final MinioProperties properties;
    
    /**
     * 初始化：确保默认存储桶存在
     */
    @PostConstruct
    public void init() {
        try {
            String bucketName = properties.getBucketName();
            if (!bucketExists(bucketName)) {
                createBucket(bucketName);
                log.info("创建默认存储桶: {}", bucketName);
            }
        } catch (Exception e) {
            log.error("初始化 MinIO 失败", e);
        }
    }
    
    // ==================== 存储桶操作 ====================
    
    /**
     * 检查存储桶是否存在
     */
    public boolean bucketExists(String bucketName) {
        try {
            return minioClient.bucketExists(
                BucketExistsArgs.builder()
                    .bucket(bucketName)
                    .build()
            );
        } catch (Exception e) {
            log.error("检查存储桶失败: {}", bucketName, e);
            return false;
        }
    }
    
    /**
     * 创建存储桶
     */
    public void createBucket(String bucketName) {
        try {
            if (!bucketExists(bucketName)) {
                minioClient.makeBucket(
                    MakeBucketArgs.builder()
                        .bucket(bucketName)
                        .build()
                );
                log.info("存储桶创建成功: {}", bucketName);
            }
        } catch (Exception e) {
            log.error("创建存储桶失败: {}", bucketName, e);
            throw new RuntimeException("创建存储桶失败", e);
        }
    }
    
    /**
     * 获取所有存储桶
     */
    public List<String> listBuckets() {
        try {
            return minioClient.listBuckets().stream()
                .map(Bucket::name)
                .collect(Collectors.toList());
        } catch (Exception e) {
            log.error("获取存储桶列表失败", e);
            return Collections.emptyList();
        }
    }
    
    /**
     * 删除存储桶
     */
    public void removeBucket(String bucketName) {
        try {
            minioClient.removeBucket(
                RemoveBucketArgs.builder()
                    .bucket(bucketName)
                    .build()
            );
            log.info("存储桶删除成功: {}", bucketName);
        } catch (Exception e) {
            log.error("删除存储桶失败: {}", bucketName, e);
            throw new RuntimeException("删除存储桶失败", e);
        }
    }
    
    // ==================== 文件上传 ====================
    
    /**
     * 上传文件（MultipartFile）
     */
    public String uploadFile(MultipartFile file) {
        return uploadFile(properties.getBucketName(), file);
    }
    
    /**
     * 上传文件到指定存储桶
     */
    public String uploadFile(String bucketName, MultipartFile file) {
        String objectName = generateObjectName(file.getOriginalFilename());
        return uploadFile(bucketName, objectName, file);
    }
    
    /**
     * 上传文件（指定路径）
     */
    public String uploadFile(String bucketName, String objectName, MultipartFile file) {
        try {
            // 确保存储桶存在
            createBucket(bucketName);
            
            minioClient.putObject(
                PutObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .stream(file.getInputStream(), file.getSize(), -1)
                    .contentType(file.getContentType())
                    .build()
            );
            
            log.info("文件上传成功: {}/{}", bucketName, objectName);
            return objectName;
            
        } catch (Exception e) {
            log.error("文件上传失败: {}", file.getOriginalFilename(), e);
            throw new RuntimeException("文件上传失败", e);
        }
    }
    
    /**
     * 上传文件（InputStream）
     */
    public String uploadFile(String bucketName, String objectName, 
                             InputStream inputStream, String contentType) {
        try {
            createBucket(bucketName);
            
            minioClient.putObject(
                PutObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .stream(inputStream, -1, 10485760)  // 10MB 分片
                    .contentType(contentType)
                    .build()
            );
            
            return objectName;
            
        } catch (Exception e) {
            log.error("文件上传失败: {}", objectName, e);
            throw new RuntimeException("文件上传失败", e);
        }
    }
    
    /**
     * 生成对象名称（按日期分目录 + UUID）
     */
    private String generateObjectName(String originalFilename) {
        String date = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd"));
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String extension = getFileExtension(originalFilename);
        return date + "/" + uuid + extension;
    }
    
    /**
     * 获取文件扩展名
     */
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "";
        }
        return filename.substring(filename.lastIndexOf("."));
    }
    
    // ==================== 文件下载 ====================
    
    /**
     * 下载文件
     */
    public InputStream downloadFile(String objectName) {
        return downloadFile(properties.getBucketName(), objectName);
    }
    
    /**
     * 下载文件（指定存储桶）
     */
    public InputStream downloadFile(String bucketName, String objectName) {
        try {
            return minioClient.getObject(
                GetObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .build()
            );
        } catch (Exception e) {
            log.error("文件下载失败: {}/{}", bucketName, objectName, e);
            throw new RuntimeException("文件下载失败", e);
        }
    }
    
    // ==================== 文件删除 ====================
    
    /**
     * 删除文件
     */
    public void deleteFile(String objectName) {
        deleteFile(properties.getBucketName(), objectName);
    }
    
    /**
     * 删除文件（指定存储桶）
     */
    public void deleteFile(String bucketName, String objectName) {
        try {
            minioClient.removeObject(
                RemoveObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .build()
            );
            log.info("文件删除成功: {}/{}", bucketName, objectName);
        } catch (Exception e) {
            log.error("文件删除失败: {}/{}", bucketName, objectName, e);
            throw new RuntimeException("文件删除失败", e);
        }
    }
    
    /**
     * 批量删除文件
     */
    public void deleteFiles(String bucketName, List<String> objectNames) {
        try {
            List<DeleteObject> objects = objectNames.stream()
                .map(DeleteObject::new)
                .collect(Collectors.toList());
            
            Iterable<Result<DeleteError>> results = minioClient.removeObjects(
                RemoveObjectsArgs.builder()
                    .bucket(bucketName)
                    .objects(objects)
                    .build()
            );
            
            for (Result<DeleteError> result : results) {
                DeleteError error = result.get();
                log.error("删除失败: {}", error.objectName());
            }
            
        } catch (Exception e) {
            log.error("批量删除失败", e);
            throw new RuntimeException("批量删除失败", e);
        }
    }
    
    // ==================== 预签名 URL ====================
    
    /**
     * 获取预签名下载 URL（默认7天有效）
     */
    public String getPresignedUrl(String objectName) {
        return getPresignedUrl(properties.getBucketName(), objectName, 7, TimeUnit.DAYS);
    }
    
    /**
     * 获取预签名下载 URL（自定义有效期）
     */
    public String getPresignedUrl(String bucketName, String objectName, 
                                   int duration, TimeUnit unit) {
        try {
            return minioClient.getPresignedObjectUrl(
                GetPresignedObjectUrlArgs.builder()
                    .method(Method.GET)
                    .bucket(bucketName)
                    .object(objectName)
                    .expiry(duration, unit)
                    .build()
            );
        } catch (Exception e) {
            log.error("获取预签名URL失败: {}/{}", bucketName, objectName, e);
            throw new RuntimeException("获取预签名URL失败", e);
        }
    }
    
    /**
     * 获取预签名上传 URL
     */
    public String getPresignedUploadUrl(String bucketName, String objectName,
                                         int duration, TimeUnit unit) {
        try {
            return minioClient.getPresignedObjectUrl(
                GetPresignedObjectUrlArgs.builder()
                    .method(Method.PUT)
                    .bucket(bucketName)
                    .object(objectName)
                    .expiry(duration, unit)
                    .build()
            );
        } catch (Exception e) {
            log.error("获取预签名上传URL失败", e);
            throw new RuntimeException("获取预签名上传URL失败", e);
        }
    }
    
    // ==================== 文件信息 ====================
    
    /**
     * 获取文件信息
     */
    public StatObjectResponse getFileInfo(String bucketName, String objectName) {
        try {
            return minioClient.statObject(
                StatObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .build()
            );
        } catch (Exception e) {
            log.error("获取文件信息失败: {}/{}", bucketName, objectName, e);
            throw new RuntimeException("获取文件信息失败", e);
        }
    }
    
    /**
     * 检查文件是否存在
     */
    public boolean fileExists(String bucketName, String objectName) {
        try {
            minioClient.statObject(
                StatObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .build()
            );
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * 列出存储桶中的文件
     */
    public List<String> listFiles(String bucketName, String prefix) {
        List<String> files = new ArrayList<>();
        try {
            Iterable<Result<Item>> results = minioClient.listObjects(
                ListObjectsArgs.builder()
                    .bucket(bucketName)
                    .prefix(prefix)
                    .recursive(true)
                    .build()
            );
            
            for (Result<Item> result : results) {
                files.add(result.get().objectName());
            }
        } catch (Exception e) {
            log.error("列出文件失败: {}", bucketName, e);
        }
        return files;
    }
    
    /**
     * 获取文件访问 URL（需要存储桶设置为公开）
     */
    public String getFileUrl(String objectName) {
        return properties.getEndpoint() + "/" + properties.getBucketName() + "/" + objectName;
    }
}
```


---

## 5. 基本操作

### 5.1 文件上传 Controller

```java
package com.example.controller;

import com.example.util.MinioUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {
    
    private final MinioUtil minioUtil;
    
    /**
     * 单文件上传
     */
    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> upload(@RequestParam("file") MultipartFile file) {
        String objectName = minioUtil.uploadFile(file);
        String url = minioUtil.getPresignedUrl(objectName);
        
        Map<String, Object> result = new HashMap<>();
        result.put("objectName", objectName);
        result.put("url", url);
        result.put("size", file.getSize());
        result.put("contentType", file.getContentType());
        
        return ResponseEntity.ok(result);
    }
    
    /**
     * 多文件上传
     */
    @PostMapping("/upload/batch")
    public ResponseEntity<List<Map<String, Object>>> uploadBatch(
            @RequestParam("files") MultipartFile[] files) {
        
        List<Map<String, Object>> results = new java.util.ArrayList<>();
        
        for (MultipartFile file : files) {
            String objectName = minioUtil.uploadFile(file);
            String url = minioUtil.getPresignedUrl(objectName);
            
            Map<String, Object> result = new HashMap<>();
            result.put("originalName", file.getOriginalFilename());
            result.put("objectName", objectName);
            result.put("url", url);
            results.add(result);
        }
        
        return ResponseEntity.ok(results);
    }
    
    /**
     * 上传到指定目录
     */
    @PostMapping("/upload/{folder}")
    public ResponseEntity<Map<String, Object>> uploadToFolder(
            @PathVariable String folder,
            @RequestParam("file") MultipartFile file) {
        
        String objectName = folder + "/" + file.getOriginalFilename();
        minioUtil.uploadFile(minioUtil.getProperties().getBucketName(), objectName, file);
        
        Map<String, Object> result = new HashMap<>();
        result.put("objectName", objectName);
        result.put("url", minioUtil.getPresignedUrl(objectName));
        
        return ResponseEntity.ok(result);
    }
    
    /**
     * 删除文件
     */
    @DeleteMapping("/{objectName}")
    public ResponseEntity<Void> delete(@PathVariable String objectName) {
        minioUtil.deleteFile(objectName);
        return ResponseEntity.ok().build();
    }
    
    /**
     * 获取文件列表
     */
    @GetMapping("/list")
    public ResponseEntity<List<String>> list(
            @RequestParam(defaultValue = "") String prefix) {
        List<String> files = minioUtil.listFiles(
            minioUtil.getProperties().getBucketName(), prefix);
        return ResponseEntity.ok(files);
    }
    
    /**
     * 获取预签名下载 URL
     */
    @GetMapping("/url/{objectName}")
    public ResponseEntity<String> getUrl(@PathVariable String objectName) {
        String url = minioUtil.getPresignedUrl(objectName);
        return ResponseEntity.ok(url);
    }
}
```

### 5.2 文件下载 Controller

```java
package com.example.controller;

import com.example.util.MinioUtil;
import io.minio.StatObjectResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileDownloadController {
    
    private final MinioUtil minioUtil;
    
    /**
     * 文件下载（流式）
     */
    @GetMapping("/download/{objectName}")
    public void download(@PathVariable String objectName, 
                         HttpServletResponse response) {
        try {
            // 获取文件信息
            StatObjectResponse stat = minioUtil.getFileInfo(
                minioUtil.getProperties().getBucketName(), objectName);
            
            // 设置响应头
            response.setContentType(stat.contentType());
            response.setContentLengthLong(stat.size());
            response.setHeader(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=" + URLEncoder.encode(
                    getFileName(objectName), StandardCharsets.UTF_8.name()));
            
            // 写入响应流
            try (InputStream is = minioUtil.downloadFile(objectName);
                 OutputStream os = response.getOutputStream()) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
            }
            
        } catch (Exception e) {
            throw new RuntimeException("文件下载失败", e);
        }
    }
    
    /**
     * 文件预览（图片、PDF等）
     */
    @GetMapping("/preview/{objectName}")
    public ResponseEntity<byte[]> preview(@PathVariable String objectName) {
        try {
            StatObjectResponse stat = minioUtil.getFileInfo(
                minioUtil.getProperties().getBucketName(), objectName);
            
            try (InputStream is = minioUtil.downloadFile(objectName)) {
                byte[] bytes = is.readAllBytes();
                
                return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(stat.contentType()))
                    .header(HttpHeaders.CONTENT_DISPOSITION, 
                        "inline; filename=" + getFileName(objectName))
                    .body(bytes);
            }
            
        } catch (Exception e) {
            throw new RuntimeException("文件预览失败", e);
        }
    }
    
    /**
     * 从路径中提取文件名
     */
    private String getFileName(String objectName) {
        if (objectName.contains("/")) {
            return objectName.substring(objectName.lastIndexOf("/") + 1);
        }
        return objectName;
    }
}
```

---

## 6. 文件上传

### 6.1 分片上传

```java
package com.example.service;

import io.minio.*;
import io.minio.messages.Part;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
@Service
@RequiredArgsConstructor
public class MultipartUploadService {
    
    private final MinioClient minioClient;
    
    // 分片大小：5MB
    private static final long PART_SIZE = 5 * 1024 * 1024;
    
    /**
     * 分片上传大文件
     */
    public String uploadLargeFile(String bucketName, String objectName, 
                                   MultipartFile file) {
        try {
            long fileSize = file.getSize();
            
            // 小文件直接上传
            if (fileSize <= PART_SIZE) {
                minioClient.putObject(
                    PutObjectArgs.builder()
                        .bucket(bucketName)
                        .object(objectName)
                        .stream(file.getInputStream(), fileSize, -1)
                        .contentType(file.getContentType())
                        .build()
                );
                return objectName;
            }
            
            // 大文件分片上传
            try (InputStream is = file.getInputStream()) {
                minioClient.putObject(
                    PutObjectArgs.builder()
                        .bucket(bucketName)
                        .object(objectName)
                        .stream(is, fileSize, PART_SIZE)
                        .contentType(file.getContentType())
                        .build()
                );
            }
            
            log.info("大文件上传成功: {}, 大小: {} MB", objectName, fileSize / 1024 / 1024);
            return objectName;
            
        } catch (Exception e) {
            log.error("分片上传失败", e);
            throw new RuntimeException("分片上传失败", e);
        }
    }
}
```

### 6.2 断点续传

```java
package com.example.service;

import com.example.dto.ChunkUploadDTO;
import io.minio.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class ChunkUploadService {
    
    private final MinioClient minioClient;
    private final RedisTemplate<String, Object> redisTemplate;
    
    private static final String UPLOAD_PREFIX = "minio:upload:";
    
    /**
     * 初始化分片上传
     */
    public Map<String, Object> initUpload(String bucketName, String fileName, 
                                           int totalChunks, String fileMd5) {
        String uploadId = UUID.randomUUID().toString();
        String objectName = generateObjectName(fileName);
        
        // 保存上传信息到 Redis
        Map<String, Object> uploadInfo = new HashMap<>();
        uploadInfo.put("uploadId", uploadId);
        uploadInfo.put("objectName", objectName);
        uploadInfo.put("bucketName", bucketName);
        uploadInfo.put("totalChunks", totalChunks);
        uploadInfo.put("uploadedChunks", new HashSet<Integer>());
        uploadInfo.put("fileMd5", fileMd5);
        
        String key = UPLOAD_PREFIX + fileMd5;
        redisTemplate.opsForValue().set(key, uploadInfo, 24, TimeUnit.HOURS);
        
        return uploadInfo;
    }
    
    /**
     * 上传分片
     */
    public boolean uploadChunk(String fileMd5, int chunkIndex, MultipartFile chunk) {
        try {
            String key = UPLOAD_PREFIX + fileMd5;
            Map<String, Object> uploadInfo = (Map<String, Object>) 
                redisTemplate.opsForValue().get(key);
            
            if (uploadInfo == null) {
                throw new RuntimeException("上传任务不存在");
            }
            
            String bucketName = (String) uploadInfo.get("bucketName");
            String objectName = (String) uploadInfo.get("objectName");
            String chunkObjectName = objectName + ".chunk." + chunkIndex;
            
            // 上传分片
            minioClient.putObject(
                PutObjectArgs.builder()
                    .bucket(bucketName)
                    .object(chunkObjectName)
                    .stream(chunk.getInputStream(), chunk.getSize(), -1)
                    .build()
            );
            
            // 更新已上传分片
            Set<Integer> uploadedChunks = (Set<Integer>) uploadInfo.get("uploadedChunks");
            uploadedChunks.add(chunkIndex);
            redisTemplate.opsForValue().set(key, uploadInfo, 24, TimeUnit.HOURS);
            
            log.info("分片上传成功: {}, chunk: {}", objectName, chunkIndex);
            return true;
            
        } catch (Exception e) {
            log.error("分片上传失败", e);
            return false;
        }
    }
    
    /**
     * 合并分片
     */
    public String mergeChunks(String fileMd5) {
        try {
            String key = UPLOAD_PREFIX + fileMd5;
            Map<String, Object> uploadInfo = (Map<String, Object>) 
                redisTemplate.opsForValue().get(key);
            
            if (uploadInfo == null) {
                throw new RuntimeException("上传任务不存在");
            }
            
            String bucketName = (String) uploadInfo.get("bucketName");
            String objectName = (String) uploadInfo.get("objectName");
            int totalChunks = (int) uploadInfo.get("totalChunks");
            
            // 构建分片源列表
            List<ComposeSource> sources = new ArrayList<>();
            for (int i = 0; i < totalChunks; i++) {
                sources.add(
                    ComposeSource.builder()
                        .bucket(bucketName)
                        .object(objectName + ".chunk." + i)
                        .build()
                );
            }
            
            // 合并分片
            minioClient.composeObject(
                ComposeObjectArgs.builder()
                    .bucket(bucketName)
                    .object(objectName)
                    .sources(sources)
                    .build()
            );
            
            // 删除分片文件
            for (int i = 0; i < totalChunks; i++) {
                minioClient.removeObject(
                    RemoveObjectArgs.builder()
                        .bucket(bucketName)
                        .object(objectName + ".chunk." + i)
                        .build()
                );
            }
            
            // 清理 Redis
            redisTemplate.delete(key);
            
            log.info("分片合并成功: {}", objectName);
            return objectName;
            
        } catch (Exception e) {
            log.error("分片合并失败", e);
            throw new RuntimeException("分片合并失败", e);
        }
    }
    
    /**
     * 检查已上传的分片
     */
    public Set<Integer> getUploadedChunks(String fileMd5) {
        String key = UPLOAD_PREFIX + fileMd5;
        Map<String, Object> uploadInfo = (Map<String, Object>) 
            redisTemplate.opsForValue().get(key);
        
        if (uploadInfo == null) {
            return Collections.emptySet();
        }
        
        return (Set<Integer>) uploadInfo.get("uploadedChunks");
    }
    
    private String generateObjectName(String fileName) {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String ext = fileName.substring(fileName.lastIndexOf("."));
        return uuid + ext;
    }
}
```


### 6.3 前端分片上传示例

```javascript
// 前端分片上传示例（Vue + axios）
async function uploadLargeFile(file) {
    const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const fileMd5 = await calculateMd5(file);
    
    // 1. 初始化上传
    const { data: uploadInfo } = await axios.post('/api/files/init-upload', {
        fileName: file.name,
        totalChunks,
        fileMd5
    });
    
    // 2. 检查已上传的分片（断点续传）
    const { data: uploadedChunks } = await axios.get(
        `/api/files/uploaded-chunks/${fileMd5}`
    );
    
    // 3. 上传分片
    for (let i = 0; i < totalChunks; i++) {
        if (uploadedChunks.includes(i)) {
            console.log(`分片 ${i} 已上传，跳过`);
            continue;
        }
        
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);
        
        const formData = new FormData();
        formData.append('chunk', chunk);
        formData.append('chunkIndex', i);
        formData.append('fileMd5', fileMd5);
        
        await axios.post('/api/files/upload-chunk', formData);
        console.log(`分片 ${i + 1}/${totalChunks} 上传完成`);
    }
    
    // 4. 合并分片
    const { data: result } = await axios.post(
        `/api/files/merge-chunks/${fileMd5}`
    );
    
    return result;
}
```

---

## 7. 文件下载

### 7.1 范围下载（支持断点续传）

```java
package com.example.controller;

import com.example.util.MinioUtil;
import io.minio.StatObjectResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.io.OutputStream;

@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class RangeDownloadController {
    
    private final MinioUtil minioUtil;
    
    /**
     * 支持范围请求的下载（断点续传、视频拖动）
     */
    @GetMapping("/range-download/{objectName}")
    public void rangeDownload(@PathVariable String objectName,
                              HttpServletRequest request,
                              HttpServletResponse response) {
        try {
            String bucketName = minioUtil.getProperties().getBucketName();
            StatObjectResponse stat = minioUtil.getFileInfo(bucketName, objectName);
            long fileSize = stat.size();
            
            // 解析 Range 请求头
            String rangeHeader = request.getHeader("Range");
            long start = 0;
            long end = fileSize - 1;
            
            if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
                String[] ranges = rangeHeader.substring(6).split("-");
                start = Long.parseLong(ranges[0]);
                if (ranges.length > 1 && !ranges[1].isEmpty()) {
                    end = Long.parseLong(ranges[1]);
                }
            }
            
            long contentLength = end - start + 1;
            
            // 设置响应头
            response.setContentType(stat.contentType());
            response.setHeader("Accept-Ranges", "bytes");
            response.setHeader("Content-Length", String.valueOf(contentLength));
            response.setHeader("Content-Range", 
                String.format("bytes %d-%d/%d", start, end, fileSize));
            
            // 部分内容返回 206
            if (rangeHeader != null) {
                response.setStatus(HttpServletResponse.SC_PARTIAL_CONTENT);
            }
            
            // 获取指定范围的数据
            try (InputStream is = minioUtil.downloadFileRange(bucketName, objectName, start, end);
                 OutputStream os = response.getOutputStream()) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
                os.flush();
            }
            
        } catch (Exception e) {
            throw new RuntimeException("范围下载失败", e);
        }
    }
}
```

```java
// MinioUtil 中添加范围下载方法
public InputStream downloadFileRange(String bucketName, String objectName, 
                                      long offset, long length) {
    try {
        return minioClient.getObject(
            GetObjectArgs.builder()
                .bucket(bucketName)
                .object(objectName)
                .offset(offset)
                .length(length - offset + 1)
                .build()
        );
    } catch (Exception e) {
        throw new RuntimeException("范围下载失败", e);
    }
}
```

---

## 8. 文件管理

### 8.1 文件信息服务

```java
package com.example.service;

import com.example.dto.FileInfoDTO;
import com.example.util.MinioUtil;
import io.minio.StatObjectResponse;
import io.minio.messages.Item;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class FileManageService {
    
    private final MinioUtil minioUtil;
    
    /**
     * 获取文件详细信息
     */
    public FileInfoDTO getFileInfo(String objectName) {
        String bucketName = minioUtil.getProperties().getBucketName();
        StatObjectResponse stat = minioUtil.getFileInfo(bucketName, objectName);
        
        FileInfoDTO dto = new FileInfoDTO();
        dto.setObjectName(objectName);
        dto.setSize(stat.size());
        dto.setContentType(stat.contentType());
        dto.setLastModified(stat.lastModified().toLocalDateTime());
        dto.setEtag(stat.etag());
        dto.setUserMetadata(stat.userMetadata());
        
        return dto;
    }
    
    /**
     * 复制文件
     */
    public void copyFile(String sourceObject, String targetObject) {
        minioUtil.copyFile(
            minioUtil.getProperties().getBucketName(),
            sourceObject,
            minioUtil.getProperties().getBucketName(),
            targetObject
        );
    }
    
    /**
     * 移动文件（复制后删除源文件）
     */
    public void moveFile(String sourceObject, String targetObject) {
        copyFile(sourceObject, targetObject);
        minioUtil.deleteFile(sourceObject);
    }
    
    /**
     * 获取目录下的文件列表
     */
    public List<FileInfoDTO> listDirectory(String prefix) {
        List<FileInfoDTO> files = new ArrayList<>();
        String bucketName = minioUtil.getProperties().getBucketName();
        
        for (String objectName : minioUtil.listFiles(bucketName, prefix)) {
            try {
                StatObjectResponse stat = minioUtil.getFileInfo(bucketName, objectName);
                
                FileInfoDTO dto = new FileInfoDTO();
                dto.setObjectName(objectName);
                dto.setSize(stat.size());
                dto.setContentType(stat.contentType());
                dto.setLastModified(stat.lastModified().toLocalDateTime());
                
                files.add(dto);
            } catch (Exception e) {
                // 忽略获取失败的文件
            }
        }
        
        return files;
    }
}
```

### 8.2 文件复制方法

```java
// MinioUtil 中添加复制方法
public void copyFile(String sourceBucket, String sourceObject,
                     String targetBucket, String targetObject) {
    try {
        minioClient.copyObject(
            CopyObjectArgs.builder()
                .bucket(targetBucket)
                .object(targetObject)
                .source(
                    CopySource.builder()
                        .bucket(sourceBucket)
                        .object(sourceObject)
                        .build()
                )
                .build()
        );
        log.info("文件复制成功: {}/{} -> {}/{}", 
            sourceBucket, sourceObject, targetBucket, targetObject);
    } catch (Exception e) {
        log.error("文件复制失败", e);
        throw new RuntimeException("文件复制失败", e);
    }
}
```

---

## 9. 预签名 URL

### 9.1 预签名 URL 详解

预签名 URL 允许在不暴露凭证的情况下，临时授权访问私有文件。

```java
package com.example.service;

import com.example.config.MinioProperties;
import io.minio.GetPresignedObjectUrlArgs;
import io.minio.MinioClient;
import io.minio.PostPolicy;
import io.minio.http.Method;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class PresignedUrlService {
    
    private final MinioClient minioClient;
    private final MinioProperties properties;
    
    /**
     * 获取预签名下载 URL
     */
    public String getDownloadUrl(String objectName, int expireMinutes) {
        try {
            return minioClient.getPresignedObjectUrl(
                GetPresignedObjectUrlArgs.builder()
                    .method(Method.GET)
                    .bucket(properties.getBucketName())
                    .object(objectName)
                    .expiry(expireMinutes, TimeUnit.MINUTES)
                    .build()
            );
        } catch (Exception e) {
            throw new RuntimeException("获取下载URL失败", e);
        }
    }
    
    /**
     * 获取预签名上传 URL（PUT 方式）
     */
    public String getUploadUrl(String objectName, int expireMinutes) {
        try {
            return minioClient.getPresignedObjectUrl(
                GetPresignedObjectUrlArgs.builder()
                    .method(Method.PUT)
                    .bucket(properties.getBucketName())
                    .object(objectName)
                    .expiry(expireMinutes, TimeUnit.MINUTES)
                    .build()
            );
        } catch (Exception e) {
            throw new RuntimeException("获取上传URL失败", e);
        }
    }
    
    /**
     * 获取 POST 表单上传策略
     * 适用于浏览器直接上传
     */
    public Map<String, String> getPostPolicy(String objectName, int expireMinutes) {
        try {
            PostPolicy policy = new PostPolicy(
                properties.getBucketName(),
                ZonedDateTime.now().plusMinutes(expireMinutes)
            );
            
            // 设置上传条件
            policy.addEqualsCondition("key", objectName);
            policy.addStartsWithCondition("Content-Type", "");
            policy.addContentLengthRangeCondition(0, 100 * 1024 * 1024); // 最大 100MB
            
            Map<String, String> formData = minioClient.getPresignedPostFormData(policy);
            formData.put("url", properties.getEndpoint() + "/" + properties.getBucketName());
            formData.put("key", objectName);
            
            return formData;
            
        } catch (Exception e) {
            throw new RuntimeException("获取上传策略失败", e);
        }
    }
}
```

### 9.2 前端直传示例

```javascript
// 使用预签名 URL 直接上传到 MinIO
async function directUpload(file) {
    // 1. 获取预签名上传 URL
    const { data: uploadUrl } = await axios.get('/api/files/presigned-upload', {
        params: { fileName: file.name }
    });
    
    // 2. 直接上传到 MinIO（不经过后端）
    await axios.put(uploadUrl, file, {
        headers: {
            'Content-Type': file.type
        }
    });
    
    console.log('上传成功');
}

// 使用 POST 表单策略上传
async function formUpload(file) {
    // 1. 获取上传策略
    const { data: policy } = await axios.get('/api/files/post-policy', {
        params: { fileName: file.name }
    });
    
    // 2. 构建表单数据
    const formData = new FormData();
    Object.keys(policy).forEach(key => {
        if (key !== 'url') {
            formData.append(key, policy[key]);
        }
    });
    formData.append('file', file);
    
    // 3. 上传
    await axios.post(policy.url, formData);
    
    console.log('上传成功');
}
```


---

## 10. 存储桶策略

### 10.1 设置存储桶策略

```java
package com.example.service;

import io.minio.MinioClient;
import io.minio.SetBucketPolicyArgs;
import io.minio.GetBucketPolicyArgs;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class BucketPolicyService {
    
    private final MinioClient minioClient;
    
    /**
     * 设置存储桶为公开读
     */
    public void setPublicReadPolicy(String bucketName) {
        String policy = """
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": ["*"]},
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::%s/*"]
                    }
                ]
            }
            """.formatted(bucketName);
        
        setBucketPolicy(bucketName, policy);
    }
    
    /**
     * 设置存储桶为公开读写
     */
    public void setPublicReadWritePolicy(String bucketName) {
        String policy = """
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": ["*"]},
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": ["arn:aws:s3:::%s/*"]
                    }
                ]
            }
            """.formatted(bucketName);
        
        setBucketPolicy(bucketName, policy);
    }
    
    /**
     * 设置指定目录公开读
     */
    public void setDirectoryPublicRead(String bucketName, String prefix) {
        String policy = """
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": ["*"]},
                        "Action": ["s3:GetObject"],
                        "Resource": ["arn:aws:s3:::%s/%s*"]
                    }
                ]
            }
            """.formatted(bucketName, prefix);
        
        setBucketPolicy(bucketName, policy);
    }
    
    /**
     * 设置存储桶策略
     */
    public void setBucketPolicy(String bucketName, String policy) {
        try {
            minioClient.setBucketPolicy(
                SetBucketPolicyArgs.builder()
                    .bucket(bucketName)
                    .config(policy)
                    .build()
            );
            log.info("存储桶策略设置成功: {}", bucketName);
        } catch (Exception e) {
            log.error("设置存储桶策略失败", e);
            throw new RuntimeException("设置存储桶策略失败", e);
        }
    }
    
    /**
     * 获取存储桶策略
     */
    public String getBucketPolicy(String bucketName) {
        try {
            return minioClient.getBucketPolicy(
                GetBucketPolicyArgs.builder()
                    .bucket(bucketName)
                    .build()
            );
        } catch (Exception e) {
            log.error("获取存储桶策略失败", e);
            return null;
        }
    }
}
```

### 10.2 常用策略模板

```json
// 1. 完全公开（不推荐）
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:*"],
            "Resource": ["arn:aws:s3:::bucket-name/*"]
        }
    ]
}

// 2. 只读公开
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::bucket-name/*"]
        }
    ]
}

// 3. 指定 IP 访问
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::bucket-name/*"],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": ["192.168.1.0/24", "10.0.0.0/8"]
                }
            }
        }
    ]
}

// 4. 指定目录公开
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["*"]},
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::bucket-name/public/*"]
        }
    ]
}
```

---

## 11. 事件通知

### 11.1 配置事件通知

MinIO 支持将存储桶事件发送到 Webhook、Kafka、RabbitMQ 等。

```java
package com.example.service;

import io.minio.*;
import io.minio.messages.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.LinkedList;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class BucketNotificationService {
    
    private final MinioClient minioClient;
    
    /**
     * 配置 Webhook 通知
     */
    public void configureWebhookNotification(String bucketName, String webhookUrl) {
        try {
            // 创建队列配置
            QueueConfiguration queueConfig = new QueueConfiguration();
            queueConfig.setQueue("arn:minio:sqs::webhook:webhook");
            
            // 设置触发事件
            List<EventType> events = new LinkedList<>();
            events.add(EventType.OBJECT_CREATED_ANY);  // 对象创建
            events.add(EventType.OBJECT_REMOVED_ANY);  // 对象删除
            queueConfig.setEvents(events);
            
            // 设置过滤规则（可选）
            // queueConfig.setPrefixRule("images/");
            // queueConfig.setSuffixRule(".jpg");
            
            List<QueueConfiguration> queueConfigs = new LinkedList<>();
            queueConfigs.add(queueConfig);
            
            NotificationConfiguration config = new NotificationConfiguration();
            config.setQueueConfigurationList(queueConfigs);
            
            minioClient.setBucketNotification(
                SetBucketNotificationArgs.builder()
                    .bucket(bucketName)
                    .config(config)
                    .build()
            );
            
            log.info("事件通知配置成功: {}", bucketName);
            
        } catch (Exception e) {
            log.error("配置事件通知失败", e);
            throw new RuntimeException("配置事件通知失败", e);
        }
    }
    
    /**
     * 监听存储桶事件
     */
    public void listenBucketEvents(String bucketName) {
        try {
            String[] events = {"s3:ObjectCreated:*", "s3:ObjectRemoved:*"};
            
            try (CloseableIterator<Result<NotificationRecords>> iterator = 
                    minioClient.listenBucketNotification(
                        ListenBucketNotificationArgs.builder()
                            .bucket(bucketName)
                            .events(events)
                            .build()
                    )) {
                
                while (iterator.hasNext()) {
                    NotificationRecords records = iterator.next().get();
                    for (Event event : records.events()) {
                        log.info("收到事件: {} - {}", 
                            event.eventType(), 
                            event.objectName());
                        
                        // 处理事件
                        handleEvent(event);
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("监听事件失败", e);
        }
    }
    
    private void handleEvent(Event event) {
        switch (event.eventType()) {
            case OBJECT_CREATED_PUT:
            case OBJECT_CREATED_POST:
                log.info("文件上传: {}", event.objectName());
                // 处理文件上传事件
                break;
            case OBJECT_REMOVED_DELETE:
                log.info("文件删除: {}", event.objectName());
                // 处理文件删除事件
                break;
            default:
                log.info("其他事件: {}", event.eventType());
        }
    }
}
```

### 11.2 Webhook 接收端

```java
package com.example.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/webhook/minio")
public class MinioWebhookController {
    
    /**
     * 接收 MinIO 事件通知
     */
    @PostMapping("/events")
    public void handleEvent(@RequestBody Map<String, Object> event) {
        log.info("收到 MinIO 事件: {}", event);
        
        // 解析事件
        String eventName = (String) event.get("EventName");
        Map<String, Object> records = (Map<String, Object>) event.get("Records");
        
        // 根据事件类型处理
        if (eventName != null && eventName.startsWith("s3:ObjectCreated")) {
            handleObjectCreated(event);
        } else if (eventName != null && eventName.startsWith("s3:ObjectRemoved")) {
            handleObjectRemoved(event);
        }
    }
    
    private void handleObjectCreated(Map<String, Object> event) {
        log.info("处理文件创建事件");
        // 例如：生成缩略图、更新数据库等
    }
    
    private void handleObjectRemoved(Map<String, Object> event) {
        log.info("处理文件删除事件");
        // 例如：清理缓存、更新数据库等
    }
}
```


---

## 12. 高级特性

### 12.1 图片处理（缩略图生成）

```java
package com.example.service;

import com.example.util.MinioUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.coobird.thumbnailator.Thumbnails;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

@Slf4j
@Service
@RequiredArgsConstructor
public class ImageService {
    
    private final MinioUtil minioUtil;
    
    /**
     * 上传图片并生成缩略图
     */
    public String uploadImageWithThumbnail(MultipartFile file) {
        try {
            // 1. 上传原图
            String originalName = minioUtil.uploadFile(file);
            
            // 2. 生成缩略图
            ByteArrayOutputStream thumbnailOs = new ByteArrayOutputStream();
            Thumbnails.of(file.getInputStream())
                .size(200, 200)
                .keepAspectRatio(true)
                .outputFormat("jpg")
                .toOutputStream(thumbnailOs);
            
            // 3. 上传缩略图
            String thumbnailName = originalName.replace(".", "_thumb.");
            ByteArrayInputStream thumbnailIs = new ByteArrayInputStream(thumbnailOs.toByteArray());
            minioUtil.uploadFile(
                minioUtil.getProperties().getBucketName(),
                thumbnailName,
                thumbnailIs,
                "image/jpeg"
            );
            
            log.info("图片上传成功，原图: {}, 缩略图: {}", originalName, thumbnailName);
            return originalName;
            
        } catch (Exception e) {
            log.error("图片上传失败", e);
            throw new RuntimeException("图片上传失败", e);
        }
    }
    
    /**
     * 压缩图片
     */
    public String compressImage(MultipartFile file, double quality) {
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            Thumbnails.of(file.getInputStream())
                .scale(1.0)
                .outputQuality(quality)
                .toOutputStream(os);
            
            ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
            return minioUtil.uploadFile(
                minioUtil.getProperties().getBucketName(),
                minioUtil.generateObjectName(file.getOriginalFilename()),
                is,
                file.getContentType()
            );
            
        } catch (Exception e) {
            throw new RuntimeException("图片压缩失败", e);
        }
    }
}
```

### 12.2 文件类型校验

```java
package com.example.util;

import org.apache.tika.Tika;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class FileValidator {
    
    private final Tika tika = new Tika();
    
    // 允许的图片类型
    private static final List<String> ALLOWED_IMAGE_TYPES = Arrays.asList(
        "image/jpeg", "image/png", "image/gif", "image/webp"
    );
    
    // 允许的文档类型
    private static final List<String> ALLOWED_DOC_TYPES = Arrays.asList(
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    
    /**
     * 验证文件类型（基于文件内容，而非扩展名）
     */
    public String detectMimeType(MultipartFile file) throws IOException {
        return tika.detect(file.getInputStream());
    }
    
    /**
     * 验证是否为图片
     */
    public boolean isImage(MultipartFile file) {
        try {
            String mimeType = detectMimeType(file);
            return ALLOWED_IMAGE_TYPES.contains(mimeType);
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * 验证是否为文档
     */
    public boolean isDocument(MultipartFile file) {
        try {
            String mimeType = detectMimeType(file);
            return ALLOWED_DOC_TYPES.contains(mimeType);
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * 验证文件大小
     */
    public boolean validateSize(MultipartFile file, long maxSizeBytes) {
        return file.getSize() <= maxSizeBytes;
    }
    
    /**
     * 综合验证
     */
    public void validate(MultipartFile file, List<String> allowedTypes, long maxSize) {
        // 检查文件是否为空
        if (file.isEmpty()) {
            throw new IllegalArgumentException("文件不能为空");
        }
        
        // 检查文件大小
        if (file.getSize() > maxSize) {
            throw new IllegalArgumentException("文件大小超过限制");
        }
        
        // 检查文件类型
        try {
            String mimeType = detectMimeType(file);
            if (!allowedTypes.contains(mimeType)) {
                throw new IllegalArgumentException("不支持的文件类型: " + mimeType);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("无法识别文件类型");
        }
    }
}
```

### 12.3 文件去重（基于 MD5）

```java
package com.example.service;

import com.example.util.MinioUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class FileDeduplicationService {
    
    private final MinioUtil minioUtil;
    private final RedisTemplate<String, String> redisTemplate;
    
    private static final String FILE_MD5_PREFIX = "file:md5:";
    
    /**
     * 上传文件（去重）
     */
    public String uploadWithDeduplication(MultipartFile file) throws IOException {
        // 1. 计算文件 MD5
        String md5 = DigestUtils.md5DigestAsHex(file.getInputStream());
        String redisKey = FILE_MD5_PREFIX + md5;
        
        // 2. 检查是否已存在
        String existingObjectName = redisTemplate.opsForValue().get(redisKey);
        if (existingObjectName != null) {
            // 文件已存在，检查 MinIO 中是否真的存在
            if (minioUtil.fileExists(minioUtil.getProperties().getBucketName(), existingObjectName)) {
                log.info("文件已存在，复用: {}", existingObjectName);
                return existingObjectName;
            }
        }
        
        // 3. 上传新文件
        String objectName = minioUtil.uploadFile(file);
        
        // 4. 保存 MD5 映射
        redisTemplate.opsForValue().set(redisKey, objectName, 365, TimeUnit.DAYS);
        
        log.info("新文件上传: {}, MD5: {}", objectName, md5);
        return objectName;
    }
    
    /**
     * 秒传检查
     */
    public String checkInstantUpload(String md5) {
        String redisKey = FILE_MD5_PREFIX + md5;
        String objectName = redisTemplate.opsForValue().get(redisKey);
        
        if (objectName != null && 
            minioUtil.fileExists(minioUtil.getProperties().getBucketName(), objectName)) {
            return objectName;
        }
        
        return null;
    }
}
```

---

## 13. 生产环境配置

### 13.1 高可用配置

```yaml
# application-prod.yml
minio:
  endpoint: http://minio-cluster.example.com:9000
  access-key: ${MINIO_ACCESS_KEY}
  secret-key: ${MINIO_SECRET_KEY}
  bucket-name: production-bucket
  
  # 连接池配置
  pool:
    max-connections: 100
    connection-timeout: 10000
    read-timeout: 30000
    write-timeout: 30000

spring:
  servlet:
    multipart:
      max-file-size: 500MB
      max-request-size: 500MB
```

### 13.2 连接池配置

```java
package com.example.config;

import io.minio.MinioClient;
import okhttp3.OkHttpClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class MinioConfig {
    
    @Bean
    public MinioClient minioClient(MinioProperties properties) {
        // 自定义 OkHttpClient
        OkHttpClient httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build();
        
        return MinioClient.builder()
            .endpoint(properties.getEndpoint())
            .credentials(properties.getAccessKey(), properties.getSecretKey())
            .httpClient(httpClient)
            .build();
    }
}
```

### 13.3 Nginx 反向代理配置

```nginx
# nginx.conf
upstream minio_servers {
    server minio1:9000 weight=1;
    server minio2:9000 weight=1;
    server minio3:9000 weight=1;
    server minio4:9000 weight=1;
}

server {
    listen 9000;
    server_name minio.example.com;
    
    # 允许大文件上传
    client_max_body_size 1000M;
    
    location / {
        proxy_pass http://minio_servers;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # 超时设置
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
        proxy_read_timeout 300;
    }
}
```


---

## 14. 常见错误与解决方案

### 14.1 连接错误

#### 错误1：Connection refused

```
io.minio.errors.MinioException: Connection refused
```

**原因**：MinIO 服务未启动或端口不正确

**解决方案**：
```bash
# 检查 MinIO 是否运行
docker ps | grep minio

# 检查端口
netstat -tlnp | grep 9000

# 查看日志
docker logs minio
```

#### 错误2：Access Denied

```
io.minio.errors.ErrorResponseException: Access Denied
```

**原因**：访问密钥错误或权限不足

**解决方案**：
```yaml
# 检查配置
minio:
  access-key: admin          # 确保与 MinIO 配置一致
  secret-key: admin123456    # 密码至少 8 位
```

### 14.2 上传错误

#### 错误3：EntityTooLarge

```
io.minio.errors.ErrorResponseException: Your proposed upload exceeds the maximum allowed size
```

**原因**：文件大小超过限制

**解决方案**：
```yaml
# Spring Boot 配置
spring:
  servlet:
    multipart:
      max-file-size: 100MB
      max-request-size: 100MB

# Nginx 配置（如果有）
client_max_body_size 100M;
```

#### 错误4：NoSuchBucket

```
io.minio.errors.ErrorResponseException: The specified bucket does not exist
```

**原因**：存储桶不存在

**解决方案**：
```java
// 上传前检查并创建存储桶
if (!minioClient.bucketExists(BucketExistsArgs.builder().bucket(bucketName).build())) {
    minioClient.makeBucket(MakeBucketArgs.builder().bucket(bucketName).build());
}
```

### 14.3 下载错误

#### 错误5：NoSuchKey

```
io.minio.errors.ErrorResponseException: The specified key does not exist
```

**原因**：文件不存在

**解决方案**：
```java
// 下载前检查文件是否存在
public boolean fileExists(String bucketName, String objectName) {
    try {
        minioClient.statObject(
            StatObjectArgs.builder()
                .bucket(bucketName)
                .object(objectName)
                .build()
        );
        return true;
    } catch (Exception e) {
        return false;
    }
}
```

### 14.4 预签名 URL 错误

#### 错误6：SignatureDoesNotMatch

```
The request signature we calculated does not match the signature you provided
```

**原因**：URL 被修改或过期

**解决方案**：
```java
// 1. 检查时间同步
// 确保服务器时间与 MinIO 服务器时间同步

// 2. 不要修改预签名 URL
// 预签名 URL 包含签名，任何修改都会导致签名失效

// 3. 检查有效期
String url = minioClient.getPresignedObjectUrl(
    GetPresignedObjectUrlArgs.builder()
        .method(Method.GET)
        .bucket(bucketName)
        .object(objectName)
        .expiry(7, TimeUnit.DAYS)  // 设置合理的有效期
        .build()
);
```

### 14.5 性能问题

#### 问题7：上传速度慢

**解决方案**：
```java
// 1. 使用分片上传
minioClient.putObject(
    PutObjectArgs.builder()
        .bucket(bucketName)
        .object(objectName)
        .stream(inputStream, fileSize, 10 * 1024 * 1024)  // 10MB 分片
        .build()
);

// 2. 使用连接池
OkHttpClient httpClient = new OkHttpClient.Builder()
    .connectionPool(new ConnectionPool(10, 5, TimeUnit.MINUTES))
    .build();

// 3. 并行上传多个文件
ExecutorService executor = Executors.newFixedThreadPool(4);
files.forEach(file -> executor.submit(() -> uploadFile(file)));
```

### 14.6 内存问题

#### 问题8：OutOfMemoryError

**原因**：大文件加载到内存

**解决方案**：
```java
// ❌ 错误：将整个文件加载到内存
byte[] bytes = file.getBytes();

// ✓ 正确：使用流式处理
try (InputStream is = file.getInputStream()) {
    minioClient.putObject(
        PutObjectArgs.builder()
            .bucket(bucketName)
            .object(objectName)
            .stream(is, file.getSize(), -1)
            .build()
    );
}
```

---

## 15. 最佳实践

### 15.1 文件命名规范

```java
/**
 * 文件命名最佳实践
 */
public class FileNamingStrategy {
    
    /**
     * 按日期 + UUID 命名（推荐）
     * 格式：2024/01/15/uuid.ext
     */
    public String generateByDateUuid(String originalFilename) {
        String date = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd"));
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String ext = getExtension(originalFilename);
        return date + "/" + uuid + ext;
    }
    
    /**
     * 按业务分类命名
     * 格式：{业务类型}/{日期}/{uuid}.ext
     */
    public String generateByBusiness(String business, String originalFilename) {
        String date = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String ext = getExtension(originalFilename);
        return business + "/" + date + "/" + uuid + ext;
    }
    
    /**
     * 按用户分类命名
     * 格式：users/{userId}/{类型}/{uuid}.ext
     */
    public String generateByUser(Long userId, String type, String originalFilename) {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String ext = getExtension(originalFilename);
        return "users/" + userId + "/" + type + "/" + uuid + ext;
    }
}
```

### 15.2 存储桶设计

```
推荐的存储桶设计：

1. 按环境分离
   - dev-bucket      # 开发环境
   - test-bucket     # 测试环境
   - prod-bucket     # 生产环境

2. 按业务分离
   - user-avatars    # 用户头像
   - product-images  # 商品图片
   - documents       # 文档
   - backups         # 备份

3. 按访问权限分离
   - public-assets   # 公开资源（设置公开读）
   - private-files   # 私有文件（需要签名访问）
```

### 15.3 安全最佳实践

```java
/**
 * 安全最佳实践
 */
@Service
public class SecureFileService {
    
    // 1. 文件类型白名单
    private static final Set<String> ALLOWED_TYPES = Set.of(
        "image/jpeg", "image/png", "image/gif",
        "application/pdf", "application/msword"
    );
    
    // 2. 文件大小限制
    private static final long MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    
    // 3. 文件名清理
    public String sanitizeFilename(String filename) {
        // 移除路径遍历字符
        return filename.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
    
    // 4. 验证文件
    public void validateFile(MultipartFile file) {
        // 检查空文件
        if (file.isEmpty()) {
            throw new IllegalArgumentException("文件不能为空");
        }
        
        // 检查大小
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("文件大小超过限制");
        }
        
        // 检查类型（基于内容，而非扩展名）
        String mimeType = detectMimeType(file);
        if (!ALLOWED_TYPES.contains(mimeType)) {
            throw new IllegalArgumentException("不支持的文件类型");
        }
    }
    
    // 5. 使用预签名 URL 而非直接暴露文件
    public String getSecureUrl(String objectName) {
        return minioUtil.getPresignedUrl(objectName, 30, TimeUnit.MINUTES);
    }
}
```

### 15.4 性能优化

```java
/**
 * 性能优化最佳实践
 */
@Configuration
public class MinioOptimizationConfig {
    
    /**
     * 1. 使用连接池
     */
    @Bean
    public MinioClient minioClient(MinioProperties props) {
        OkHttpClient httpClient = new OkHttpClient.Builder()
            .connectionPool(new ConnectionPool(20, 5, TimeUnit.MINUTES))
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
        
        return MinioClient.builder()
            .endpoint(props.getEndpoint())
            .credentials(props.getAccessKey(), props.getSecretKey())
            .httpClient(httpClient)
            .build();
    }
    
    /**
     * 2. 异步上传线程池
     */
    @Bean
    public ExecutorService uploadExecutor() {
        return new ThreadPoolExecutor(
            4, 8, 60, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(100),
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }
}

/**
 * 3. 批量操作
 */
@Service
public class BatchUploadService {
    
    @Async("uploadExecutor")
    public CompletableFuture<String> uploadAsync(MultipartFile file) {
        String objectName = minioUtil.uploadFile(file);
        return CompletableFuture.completedFuture(objectName);
    }
    
    public List<String> uploadBatch(List<MultipartFile> files) {
        List<CompletableFuture<String>> futures = files.stream()
            .map(this::uploadAsync)
            .collect(Collectors.toList());
        
        return futures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
    }
}
```

---

## 附录：速查表

### A. 常用 API

| 操作 | 方法 |
|------|------|
| 创建存储桶 | `makeBucket()` |
| 检查存储桶 | `bucketExists()` |
| 列出存储桶 | `listBuckets()` |
| 删除存储桶 | `removeBucket()` |
| 上传文件 | `putObject()` |
| 下载文件 | `getObject()` |
| 删除文件 | `removeObject()` |
| 批量删除 | `removeObjects()` |
| 复制文件 | `copyObject()` |
| 文件信息 | `statObject()` |
| 列出文件 | `listObjects()` |
| 预签名 URL | `getPresignedObjectUrl()` |

### B. 常用配置

```yaml
minio:
  endpoint: http://localhost:9000
  access-key: admin
  secret-key: admin123456
  bucket-name: default-bucket

spring:
  servlet:
    multipart:
      max-file-size: 100MB
      max-request-size: 100MB
```

---

> 📝 **笔记完成**
> 
> 本笔记涵盖了 MinIO 与 Spring Boot 集成的方方面面：
> - 基础安装部署和配置
> - 完整的工具类封装
> - 文件上传下载（包括分片、断点续传）
> - 预签名 URL 和存储桶策略
> - 事件通知和高级特性
> - 生产环境配置和性能优化
> - 常见错误解决方案
> 
> 建议在开发环境使用 Docker 部署，生产环境使用分布式集群。
