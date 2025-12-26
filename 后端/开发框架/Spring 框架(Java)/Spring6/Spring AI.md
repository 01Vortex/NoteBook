

> Spring AI 是 Spring 生态系统中用于构建 AI 应用的框架，简化了与各种 AI 模型的集成
> 本笔记基于 Java 17+ Spring Boot 3.2.12 + Spring AI 1.0.0

---

## 目录

1. [基础概念](#1-基础概念)
2. [项目搭建](#2-项目搭建)
3. [Chat 模型](#3-chat-模型)
4. [Prompt 工程](#4-prompt-工程)
5. [输出解析](#5-输出解析)
6. [Embedding 嵌入](#6-embedding-嵌入)
7. [向量数据库](#7-向量数据库)
8. [RAG 检索增强生成](#8-rag-检索增强生成)
9. [Function Calling](#9-function-calling)
10. [Image 图像模型](#10-image-图像模型)
11. [Audio 音频模型](#11-audio-音频模型)
12. [Advisors 增强器](#12-advisors-增强器)
13. [对话记忆](#13-对话记忆)
14. [多模态](#14-多模态)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Spring AI？

Spring AI 是 Spring 官方推出的 AI 应用开发框架，它的目标是让 Java 开发者能够像使用 Spring Data、Spring Security 一样简单地集成 AI 能力。

简单来说，Spring AI 就是一个"翻译官"，它帮你把复杂的 AI 模型 API 调用封装成简洁的 Java 接口，让你专注于业务逻辑而非底层细节。

**核心优势：**
- **统一抽象**：一套代码适配多种 AI 提供商（OpenAI、Azure、Ollama 等）
- **Spring 原生**：完美融入 Spring 生态，支持依赖注入、自动配置
- **开箱即用**：丰富的 Starter，快速集成各种 AI 能力
- **可移植性**：轻松切换不同的 AI 模型提供商

### 1.2 核心概念

**Model（模型）**
模型是 AI 能力的核心，Spring AI 支持多种类型：
- ChatModel：对话模型，用于文本生成
- EmbeddingModel：嵌入模型，将文本转为向量
- ImageModel：图像生成模型
- AudioModel：语音识别/合成模型

**Prompt（提示词）**
Prompt 是发送给 AI 模型的输入，包含用户消息和系统指令。好的 Prompt 设计是获得高质量输出的关键。

**Message（消息）**
消息是对话的基本单元，分为：
- SystemMessage：系统指令，定义 AI 的角色和行为
- UserMessage：用户输入
- AssistantMessage：AI 的回复
- ToolResponseMessage：工具调用的返回结果

**Advisor（增强器）**
Advisor 是一种拦截器模式，可以在请求发送前和响应返回后进行处理，用于实现日志、缓存、RAG 等功能。

### 1.3 支持的 AI 提供商

| 提供商 | Chat | Embedding | Image | Audio |
|--------|------|-----------|-------|-------|
| OpenAI | ✅ | ✅ | ✅ | ✅ |
| Azure OpenAI | ✅ | ✅ | ✅ | ✅ |
| Ollama | ✅ | ✅ | ❌ | ❌ |
| Anthropic Claude | ✅ | ❌ | ❌ | ❌ |
| Google Vertex AI | ✅ | ✅ | ✅ | ❌ |
| Amazon Bedrock | ✅ | ✅ | ✅ | ❌ |
| Mistral AI | ✅ | ✅ | ❌ | ❌ |
| 智谱 AI | ✅ | ✅ | ✅ | ❌ |
| 阿里通义千问 | ✅ | ✅ | ✅ | ✅ |

### 1.4 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                      Spring AI 架构                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Application Layer                  │   │
│  │    (Your Business Logic / Controllers / Services)    │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Spring AI Core                    │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │ChatModel│ │Embedding│ │  Image  │ │  Audio  │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────────────────┐   │   │
│  │  │ Prompt  │ │ Advisor │ │   Vector Store      │   │   │
│  │  └─────────┘ └─────────┘ └─────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Model Providers                    │   │
│  │  OpenAI │ Azure │ Ollama │ Claude │ Bedrock │ ...   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 项目搭建

### 2.1 Maven 依赖配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.12</version>
        <relativePath/>
    </parent>

    <groupId>com.example</groupId>
    <artifactId>spring-ai-demo</artifactId>
    <version>1.0.0</version>

    <properties>
        <java.version>17</java.version>
        <spring-ai.version>1.0.0</spring-ai.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.ai</groupId>
                <artifactId>spring-ai-bom</artifactId>
                <version>${spring-ai.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <!-- Spring Boot Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!-- OpenAI Starter -->
        <dependency>
            <groupId>org.springframework.ai</groupId>
            <artifactId>spring-ai-openai-spring-boot-starter</artifactId>
        </dependency>

        <!-- Lombok（可选） -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
    </dependencies>
</project>
```


**Prompt（提示词）**
Prompt 是发送给 AI 模型的输入，包含用户消息和系统指令。好的 Prompt 设计是获得高质量输出的关键。

**Message（消息）**
消息是对话的基本单位，分为：
- SystemMessage：系统指令，定义 AI 的角色和行为
- UserMessage：用户输入
- AssistantMessage：AI 的回复
- ToolResponseMessage：工具调用的返回结果

**Advisor（增强器）**
Advisor 是 Spring AI 的拦截器机制，可以在请求前后进行处理，实现日志记录、RAG 增强等功能。

### 1.3 支持的 AI 提供商

| 提供商 | Chat | Embedding | Image | Audio |
|--------|------|-----------|-------|-------|
| OpenAI | ✅ | ✅ | ✅ | ✅ |
| Azure OpenAI | ✅ | ✅ | ✅ | ✅ |
| Ollama | ✅ | ✅ | ❌ | ❌ |
| Anthropic Claude | ✅ | ❌ | ❌ | ❌ |
| Google Vertex AI | ✅ | ✅ | ✅ | ❌ |
| Amazon Bedrock | ✅ | ✅ | ✅ | ❌ |
| Mistral AI | ✅ | ✅ | ❌ | ❌ |
| 智谱 AI | ✅ | ✅ | ✅ | ❌ |
| 阿里通义千问 | ✅ | ✅ | ✅ | ✅ |

### 1.4 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层 (Your Application)               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  ChatClient │  │ Advisors    │  │ Output Parsers      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Spring AI Core                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ChatModel │ │Embedding │ │ImageModel│ │AudioModel│       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│                    Model Providers                           │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐    │
│  │ OpenAI │ │ Azure  │ │ Ollama │ │Claude  │ │通义千问│    │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 项目搭建

### 2.1 Maven 依赖配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.12</version>
        <relativePath/>
    </parent>
    
    <groupId>com.example</groupId>
    <artifactId>spring-ai-demo</artifactId>
    <version>1.0.0</version>
    
    <properties>
        <java.version>17</java.version>
        <spring-ai.version>1.0.0</spring-ai.version>
    </properties>
    
    <!-- Spring AI BOM 依赖管理 -->
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.ai</groupId>
                <artifactId>spring-ai-bom</artifactId>
                <version>${spring-ai.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <!-- Spring Boot Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        
        <!-- OpenAI Starter -->
        <dependency>
            <groupId>org.springframework.ai</groupId>
            <artifactId>spring-ai-openai-spring-boot-starter</artifactId>
        </dependency>
        
        <!-- 或者使用 Ollama（本地部署） -->
        <!--
        <dependency>
            <groupId>org.springframework.ai</groupId>
            <artifactId>spring-ai-ollama-spring-boot-starter</artifactId>
        </dependency>
        -->
        
        <!-- 向量数据库（可选） -->
        <dependency>
            <groupId>org.springframework.ai</groupId>
            <artifactId>spring-ai-pgvector-store-spring-boot-starter</artifactId>
        </dependency>
    </dependencies>
    
    <!-- Spring AI 仓库 -->
    <repositories>
        <repository>
            <id>spring-milestones</id>
            <name>Spring Milestones</name>
            <url>https://repo.spring.io/milestone</url>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </repository>
        <repository>
            <id>spring-snapshots</id>
            <name>Spring Snapshots</name>
            <url>https://repo.spring.io/snapshot</url>
            <releases>
                <enabled>false</enabled>
            </releases>
        </repository>
    </repositories>
</project>
```

### 2.2 Gradle 依赖配置

```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.12'
    id 'io.spring.dependency-management' version '1.1.4'
}

group = 'com.example'
version = '1.0.0'

java {
    sourceCompatibility = '17'
}

repositories {
    mavenCentral()
    maven { url 'https://repo.spring.io/milestone' }
    maven { url 'https://repo.spring.io/snapshot' }
}

ext {
    set('springAiVersion', "1.0.0")
}

dependencyManagement {
    imports {
        mavenBom "org.springframework.ai:spring-ai-bom:${springAiVersion}"
    }
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.ai:spring-ai-openai-spring-boot-starter'
}
```

### 2.3 配置文件

```yaml
# application.yml
spring:
  ai:
    # OpenAI 配置
    openai:
      api-key: ${OPENAI_API_KEY}
      base-url: https://api.openai.com  # 可配置代理地址
      chat:
        options:
          model: gpt-4o
          temperature: 0.7
          max-tokens: 2000
      embedding:
        options:
          model: text-embedding-3-small
    
    # Ollama 配置（本地部署）
    ollama:
      base-url: http://localhost:11434
      chat:
        options:
          model: llama3
          temperature: 0.7
      embedding:
        options:
          model: nomic-embed-text
```

### 2.4 快速开始示例

```java
package com.example.springai;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class SpringAiDemoApplication {

    private final ChatClient chatClient;

    // 通过构造器注入 ChatClient.Builder
    public SpringAiDemoApplication(ChatClient.Builder chatClientBuilder) {
        this.chatClient = chatClientBuilder.build();
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringAiDemoApplication.class, args);
    }

    @GetMapping("/chat")
    public String chat(@RequestParam String message) {
        return chatClient.prompt()
                .user(message)
                .call()
                .content();
    }
}
```

启动应用后访问：`http://localhost:8080/chat?message=你好`

---

## 3. Chat 模型

### 3.1 ChatClient 基础用法

ChatClient 是 Spring AI 中最核心的组件，提供了流畅的 API 来与 AI 模型交互。

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.stereotype.Service;

@Service
public class ChatService {

    private final ChatClient chatClient;

    public ChatService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 最简单的调用方式
    public String simpleChat(String userMessage) {
        return chatClient.prompt()
                .user(userMessage)
                .call()
                .content();  // 直接返回文本内容
    }

    // 获取完整响应（包含元数据）
    public ChatResponse fullResponse(String userMessage) {
        return chatClient.prompt()
                .user(userMessage)
                .call()
                .chatResponse();
    }

    // 带系统提示词
    public String chatWithSystem(String userMessage) {
        return chatClient.prompt()
                .system("你是一个专业的 Java 开发助手，回答要简洁专业。")
                .user(userMessage)
                .call()
                .content();
    }

    // 自定义参数
    public String chatWithOptions(String userMessage) {
        return chatClient.prompt()
                .user(userMessage)
                .options(ChatOptions.builder()
                        .model("gpt-4o")
                        .temperature(0.5)
                        .maxTokens(1000)
                        .build())
                .call()
                .content();
    }
}
```

### 3.2 流式响应

流式响应可以让用户实时看到 AI 的输出，提升用户体验。就像 ChatGPT 那样，文字一个个蹦出来。

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping("/api/chat")
public class StreamChatController {

    private final ChatClient chatClient;

    public StreamChatController(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 流式返回（SSE）
    @GetMapping(value = "/stream", produces = "text/event-stream")
    public Flux<String> streamChat(@RequestParam String message) {
        return chatClient.prompt()
                .user(message)
                .stream()
                .content();
    }

    // 流式返回完整响应
    @GetMapping(value = "/stream/full", produces = "text/event-stream")
    public Flux<ChatResponse> streamFullResponse(@RequestParam String message) {
        return chatClient.prompt()
                .user(message)
                .stream()
                .chatResponse();
    }
}
```

**前端调用示例（JavaScript）：**
```javascript
const eventSource = new EventSource('/api/chat/stream?message=讲个笑话');

eventSource.onmessage = (event) => {
    console.log(event.data);  // 实时输出
    document.getElementById('output').innerHTML += event.data;
};

eventSource.onerror = () => {
    eventSource.close();
};
```

### 3.3 多轮对话

多轮对话需要维护对话历史，让 AI 能够理解上下文。

```java
import org.springframework.ai.chat.messages.*;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class ConversationService {

    private final ChatModel chatModel;
    
    // 存储对话历史（生产环境建议用 Redis）
    private final Map<String, List<Message>> conversationHistory = new ConcurrentHashMap<>();

    public ConversationService(ChatModel chatModel) {
        this.chatModel = chatModel;
    }

    public String chat(String sessionId, String userInput) {
        // 获取或创建对话历史
        List<Message> messages = conversationHistory.computeIfAbsent(
            sessionId, 
            k -> new ArrayList<>(List.of(
                new SystemMessage("你是一个友好的助手，记住用户之前说过的话。")
            ))
        );

        // 添加用户消息
        messages.add(new UserMessage(userInput));

        // 调用模型
        Prompt prompt = new Prompt(messages);
        String response = chatModel.call(prompt)
                .getResult()
                .getOutput()
                .getContent();

        // 保存助手回复
        messages.add(new AssistantMessage(response));

        return response;
    }

    // 清除对话历史
    public void clearHistory(String sessionId) {
        conversationHistory.remove(sessionId);
    }
}
```

### 3.4 ChatClient 配置与定制

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ChatClientConfig {

    @Bean
    public ChatClient chatClient(ChatClient.Builder builder) {
        return builder
                // 默认系统提示词
                .defaultSystem("你是一个专业的技术顾问，回答要准确、简洁。")
                // 默认参数
                .defaultOptions(ChatOptions.builder()
                        .temperature(0.7)
                        .maxTokens(2000)
                        .build())
                // 添加增强器
                .defaultAdvisors(
                        new SimpleLoggerAdvisor(),  // 日志记录
                        new MessageChatMemoryAdvisor(new InMemoryChatMemory())  // 对话记忆
                )
                .build();
    }
}
```

---

## 4. Prompt 工程

### 4.1 Prompt 模板

Prompt 模板允许你定义可复用的提示词，并动态填充变量。这是构建高质量 AI 应用的关键技术。

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.prompt.PromptTemplate;
import org.springframework.stereotype.Service;
import java.util.Map;

@Service
public class PromptService {

    private final ChatClient chatClient;

    public PromptService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 使用字符串模板
    public String translateText(String text, String targetLanguage) {
        String template = """
            请将以下文本翻译成{language}，只返回翻译结果，不要解释：
            
            {text}
            """;
        
        PromptTemplate promptTemplate = new PromptTemplate(template);
        String prompt = promptTemplate.render(Map.of(
                "language", targetLanguage,
                "text", text
        ));

        return chatClient.prompt()
                .user(prompt)
                .call()
                .content();
    }

    // 代码审查模板
    public String reviewCode(String code, String language) {
        String template = """
            你是一个资深的{language}开发者，请审查以下代码并提供改进建议：
            
            ```{language}
            {code}
            ```
            
            请从以下几个方面进行审查：
            1. 代码质量和可读性
            2. 潜在的 Bug
            3. 性能问题
            4. 安全隐患
            5. 最佳实践建议
            """;

        PromptTemplate promptTemplate = new PromptTemplate(template);
        return chatClient.prompt()
                .user(promptTemplate.render(Map.of(
                        "language", language,
                        "code", code
                )))
                .call()
                .content();
    }
}
```

### 4.2 从资源文件加载模板

将 Prompt 模板放在资源文件中，便于管理和修改。

```java
// src/main/resources/prompts/summary.st
// 使用 StringTemplate 语法
请对以下{type}内容进行总结，要求：
1. 提取关键信息
2. 控制在{maxWords}字以内
3. 使用{style}风格

内容：
{content}
```

```java
import org.springframework.ai.chat.prompt.PromptTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
public class ResourcePromptService {

    private final ChatClient chatClient;

    @Value("classpath:/prompts/summary.st")
    private Resource summaryPromptResource;

    public ResourcePromptService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public String summarize(String content, String type, int maxWords) {
        PromptTemplate promptTemplate = new PromptTemplate(summaryPromptResource);
        
        String prompt = promptTemplate.render(Map.of(
                "type", type,
                "maxWords", maxWords,
                "style", "专业简洁",
                "content", content
        ));

        return chatClient.prompt()
                .user(prompt)
                .call()
                .content();
    }
}
```

### 4.3 系统提示词最佳实践

系统提示词（System Prompt）定义了 AI 的角色和行为规范，是 Prompt 工程的核心。

```java
@Service
public class SystemPromptService {

    private final ChatClient chatClient;

    public SystemPromptService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 角色定义 + 行为约束 + 输出格式
    public String expertConsultation(String question, String domain) {
        String systemPrompt = """
            ## 角色定义
            你是一位在{domain}领域拥有20年经验的专家顾问。
            
            ## 行为约束
            - 只回答与{domain}相关的问题
            - 如果问题超出专业范围，礼貌地说明并建议咨询其他专家
            - 回答要基于事实，不确定的内容要明确标注
            - 避免使用过于专业的术语，用通俗易懂的语言解释
            
            ## 输出格式
            1. 先给出简短的直接回答（1-2句话）
            2. 然后详细解释原因
            3. 最后给出可操作的建议
            
            ## 注意事项
            - 不要编造不存在的信息
            - 涉及法律、医疗等敏感领域时，建议咨询专业人士
            """.replace("{domain}", domain);

        return chatClient.prompt()
                .system(systemPrompt)
                .user(question)
                .call()
                .content();
    }
}
```

---

## 5. 输出解析

### 5.1 结构化输出

Spring AI 可以将 AI 的输出自动解析为 Java 对象，这是构建可靠 AI 应用的关键能力。

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Service;

// 定义输出结构
public record BookRecommendation(
    String title,
    String author,
    String genre,
    int publishYear,
    String summary,
    double rating
) {}

public record BookList(List<BookRecommendation> books) {}

@Service
public class StructuredOutputService {

    private final ChatClient chatClient;

    public StructuredOutputService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 返回单个对象
    public BookRecommendation getBookRecommendation(String topic) {
        return chatClient.prompt()
                .user("推荐一本关于" + topic + "的书籍")
                .call()
                .entity(BookRecommendation.class);
    }

    // 返回对象列表
    public List<BookRecommendation> getBookList(String topic, int count) {
        return chatClient.prompt()
                .user("推荐" + count + "本关于" + topic + "的书籍")
                .call()
                .entity(new ParameterizedTypeReference<List<BookRecommendation>>() {});
    }
}
```

### 5.2 使用 BeanOutputConverter

BeanOutputConverter 提供了更精细的控制，可以自定义输出格式说明。

```java
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.ai.chat.prompt.PromptTemplate;

public record SentimentAnalysis(
    String sentiment,      // positive, negative, neutral
    double confidence,     // 0.0 - 1.0
    List<String> keywords,
    String summary
) {}

@Service
public class SentimentService {

    private final ChatClient chatClient;

    public SentimentService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public SentimentAnalysis analyzeSentiment(String text) {
        BeanOutputConverter<SentimentAnalysis> converter = 
            new BeanOutputConverter<>(SentimentAnalysis.class);

        String template = """
            分析以下文本的情感倾向：
            
            {text}
            
            {format}
            """;

        PromptTemplate promptTemplate = new PromptTemplate(template);
        String prompt = promptTemplate.render(Map.of(
                "text", text,
                "format", converter.getFormat()  // 自动生成 JSON Schema 说明
        ));

        String response = chatClient.prompt()
                .user(prompt)
                .call()
                .content();

        return converter.convert(response);
    }
}
```

### 5.3 枚举类型输出

```java
public enum TaskPriority {
    LOW, MEDIUM, HIGH, CRITICAL
}

public record TaskAnalysis(
    String taskName,
    TaskPriority priority,
    int estimatedHours,
    List<String> dependencies
) {}

@Service
public class TaskAnalysisService {

    private final ChatClient chatClient;

    public TaskAnalysisService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    public TaskAnalysis analyzeTask(String taskDescription) {
        return chatClient.prompt()
                .system("""
                    你是一个项目管理专家，负责分析任务并评估优先级。
                    优先级说明：
                    - LOW: 可以延后处理
                    - MEDIUM: 正常优先级
                    - HIGH: 需要优先处理
                    - CRITICAL: 紧急，需要立即处理
                    """)
                .user("分析以下任务：" + taskDescription)
                .call()
                .entity(TaskAnalysis.class);
    }
}
```

---

## 6. Embedding 嵌入

### 6.1 什么是 Embedding？

Embedding（嵌入）是将文本转换为数值向量的技术。这些向量能够捕捉文本的语义信息，使得语义相似的文本在向量空间中距离更近。

简单理解：Embedding 就是给文本"画像"，把文字变成一串数字，这串数字代表了文字的"含义"。

**应用场景：**
- 语义搜索：找到含义相似的内容
- 文本分类：根据向量进行分类
- 推荐系统：找到相似的内容推荐
- RAG：检索增强生成的基础

### 6.2 基本使用

```java
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.embedding.EmbeddingResponse;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class EmbeddingService {

    private final EmbeddingModel embeddingModel;

    public EmbeddingService(EmbeddingModel embeddingModel) {
        this.embeddingModel = embeddingModel;
    }

    // 获取单个文本的向量
    public float[] getEmbedding(String text) {
        return embeddingModel.embed(text);
    }

    // 批量获取向量
    public List<float[]> getEmbeddings(List<String> texts) {
        EmbeddingResponse response = embeddingModel.embedForResponse(texts);
        return response.getResults().stream()
                .map(result -> result.getOutput())
                .toList();
    }

    // 计算两个文本的相似度（余弦相似度）
    public double calculateSimilarity(String text1, String text2) {
        float[] embedding1 = getEmbedding(text1);
        float[] embedding2 = getEmbedding(text2);
        return cosineSimilarity(embedding1, embedding2);
    }

    private double cosineSimilarity(float[] a, float[] b) {
        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;
        
        for (int i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            normA += Math.pow(a[i], 2);
            normB += Math.pow(b[i], 2);
        }
        
        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }
}
```

### 6.3 文档嵌入与相似度搜索

```java
import org.springframework.ai.document.Document;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class DocumentSearchService {

    private final EmbeddingModel embeddingModel;
    
    // 简单的内存存储（生产环境用向量数据库）
    private final List<DocumentWithEmbedding> documents = new ArrayList<>();

    public DocumentSearchService(EmbeddingModel embeddingModel) {
        this.embeddingModel = embeddingModel;
    }

    // 添加文档
    public void addDocument(String content, Map<String, Object> metadata) {
        float[] embedding = embeddingModel.embed(content);
        documents.add(new DocumentWithEmbedding(content, metadata, embedding));
    }

    // 相似度搜索
    public List<String> search(String query, int topK) {
        float[] queryEmbedding = embeddingModel.embed(query);
        
        return documents.stream()
                .map(doc -> new AbstractMap.SimpleEntry<>(
                        doc, 
                        cosineSimilarity(queryEmbedding, doc.embedding())
                ))
                .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
                .limit(topK)
                .map(entry -> entry.getKey().content())
                .toList();
    }

    private record DocumentWithEmbedding(
        String content, 
        Map<String, Object> metadata, 
        float[] embedding
    ) {}

    private double cosineSimilarity(float[] a, float[] b) {
        double dotProduct = 0.0, normA = 0.0, normB = 0.0;
        for (int i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }
}
```

---

## 7. 向量数据库

### 7.1 向量数据库概述

向量数据库专门用于存储和检索向量数据，是构建 RAG 应用的核心组件。

Spring AI 支持的向量数据库：
- **PGVector**：PostgreSQL 扩展，适合已有 PG 的项目
- **Milvus**：高性能向量数据库
- **Chroma**：轻量级，适合开发测试
- **Pinecone**：云原生向量数据库
- **Redis**：Redis Stack 支持向量搜索
- **Elasticsearch**：8.x 版本支持向量搜索

### 7.2 PGVector 配置与使用

```yaml
# application.yml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/vectordb
    username: postgres
    password: postgres
  ai:
    vectorstore:
      pgvector:
        index-type: HNSW
        distance-type: COSINE_DISTANCE
        dimensions: 1536  # OpenAI text-embedding-3-small 的维度
```

```java
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class VectorStoreService {

    private final VectorStore vectorStore;

    public VectorStoreService(VectorStore vectorStore) {
        this.vectorStore = vectorStore;
    }

    // 添加文档
    public void addDocuments(List<String> contents) {
        List<Document> documents = contents.stream()
                .map(content -> new Document(content))
                .toList();
        vectorStore.add(documents);
    }

    // 添加带元数据的文档
    public void addDocumentWithMetadata(String content, Map<String, Object> metadata) {
        Document document = new Document(content, metadata);
        vectorStore.add(List.of(document));
    }

    // 相似度搜索
    public List<Document> search(String query, int topK) {
        return vectorStore.similaritySearch(
            SearchRequest.query(query).withTopK(topK)
        );
    }

    // 带过滤条件的搜索
    public List<Document> searchWithFilter(String query, String filterExpression) {
        return vectorStore.similaritySearch(
            SearchRequest.query(query)
                .withTopK(5)
                .withFilterExpression(filterExpression)
        );
    }

    // 带相似度阈值的搜索
    public List<Document> searchWithThreshold(String query, double threshold) {
        return vectorStore.similaritySearch(
            SearchRequest.query(query)
                .withTopK(10)
                .withSimilarityThreshold(threshold)
        );
    }

    // 删除文档
    public void deleteDocuments(List<String> ids) {
        vectorStore.delete(ids);
    }
}
```

### 7.3 文档加载与分割

处理大文档时，需要先将其分割成小块再存入向量数据库。

```java
import org.springframework.ai.document.Document;
import org.springframework.ai.reader.TextReader;
import org.springframework.ai.reader.pdf.PdfDocumentReader;
import org.springframework.ai.transformer.splitter.TextSplitter;
import org.springframework.ai.transformer.splitter.TokenTextSplitter;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
public class DocumentLoaderService {

    private final VectorStore vectorStore;

    public DocumentLoaderService(VectorStore vectorStore) {
        this.vectorStore = vectorStore;
    }

    // 加载并分割文本文件
    public void loadTextFile(Resource resource) {
        // 读取文档
        TextReader textReader = new TextReader(resource);
        List<Document> documents = textReader.get();

        // 分割文档
        TextSplitter splitter = new TokenTextSplitter(
            500,   // 每块的目标 token 数
            100,   // 块之间的重叠 token 数
            5,     // 最小块大小
            10000, // 最大块大小
            true   // 保持段落完整
        );
        List<Document> chunks = splitter.apply(documents);

        // 存入向量数据库
        vectorStore.add(chunks);
    }

    // 加载 PDF 文件
    public void loadPdfFile(Resource resource) {
        PdfDocumentReader pdfReader = new PdfDocumentReader(resource);
        List<Document> documents = pdfReader.get();

        TextSplitter splitter = new TokenTextSplitter();
        List<Document> chunks = splitter.apply(documents);

        vectorStore.add(chunks);
    }

    // 自定义分割策略
    public void loadWithCustomSplitter(String content, Map<String, Object> metadata) {
        // 按段落分割
        String[] paragraphs = content.split("\n\n");
        
        List<Document> documents = Arrays.stream(paragraphs)
                .filter(p -> !p.isBlank())
                .map(p -> {
                    Map<String, Object> docMetadata = new HashMap<>(metadata);
                    docMetadata.put("charCount", p.length());
                    return new Document(p, docMetadata);
                })
                .toList();

        vectorStore.add(documents);
    }
}
```

### 7.4 Redis 向量存储

```yaml
# application.yml
spring:
  ai:
    vectorstore:
      redis:
        uri: redis://localhost:6379
        index: spring-ai-index
        prefix: doc:
```

```java
// Redis 向量存储使用方式与 PGVector 相同
@Service
public class RedisVectorService {

    private final VectorStore vectorStore;

    public RedisVectorService(VectorStore vectorStore) {
        this.vectorStore = vectorStore;
    }

    public void addDocument(String content) {
        vectorStore.add(List.of(new Document(content)));
    }

    public List<Document> search(String query) {
        return vectorStore.similaritySearch(query);
    }
}
```

---

## 8. RAG 检索增强生成

### 8.1 什么是 RAG？

RAG（Retrieval-Augmented Generation）是一种结合检索和生成的技术。简单来说，就是让 AI 在回答问题前，先从知识库中检索相关信息，然后基于这些信息生成回答。

**为什么需要 RAG？**
- AI 模型的知识有截止日期，无法获取最新信息
- 模型可能产生"幻觉"，编造不存在的信息
- 企业需要 AI 基于私有数据回答问题

**RAG 工作流程：**
```
用户问题 → 向量化 → 检索相关文档 → 构建增强 Prompt → AI 生成回答
```

### 8.2 基础 RAG 实现

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class RagService {

    private final ChatClient chatClient;
    private final VectorStore vectorStore;

    public RagService(ChatClient.Builder builder, VectorStore vectorStore) {
        this.chatClient = builder.build();
        this.vectorStore = vectorStore;
    }

    public String chat(String userQuestion) {
        // 1. 检索相关文档
        List<Document> relevantDocs = vectorStore.similaritySearch(
            SearchRequest.query(userQuestion)
                .withTopK(5)
                .withSimilarityThreshold(0.7)
        );

        // 2. 构建上下文
        String context = relevantDocs.stream()
                .map(Document::getContent)
                .collect(Collectors.joining("\n\n---\n\n"));

        // 3. 构建增强 Prompt
        String systemPrompt = """
            你是一个知识助手。请基于以下参考资料回答用户问题。
            
            规则：
            1. 只使用参考资料中的信息回答
            2. 如果参考资料中没有相关信息，请明确告知用户
            3. 回答要准确、简洁
            4. 如果需要，可以引用具体的参考内容
            
            参考资料：
            %s
            """.formatted(context);

        // 4. 调用 AI 生成回答
        return chatClient.prompt()
                .system(systemPrompt)
                .user(userQuestion)
                .call()
                .content();
    }
}
```

### 8.3 使用 QuestionAnswerAdvisor

Spring AI 提供了内置的 RAG Advisor，简化实现：

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RagConfig {

    @Bean
    public ChatClient ragChatClient(ChatClient.Builder builder, VectorStore vectorStore) {
        return builder
                .defaultAdvisors(
                    new QuestionAnswerAdvisor(
                        vectorStore,
                        SearchRequest.defaults()
                            .withTopK(5)
                            .withSimilarityThreshold(0.7)
                    )
                )
                .build();
    }
}

@Service
public class RagChatService {

    private final ChatClient chatClient;

    public RagChatService(@Qualifier("ragChatClient") ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    public String chat(String question) {
        // QuestionAnswerAdvisor 会自动处理检索和上下文注入
        return chatClient.prompt()
                .user(question)
                .call()
                .content();
    }
}
```

### 8.4 高级 RAG 策略

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.stereotype.Service;

@Service
public class AdvancedRagService {

    private final ChatClient chatClient;
    private final VectorStore vectorStore;

    public AdvancedRagService(ChatClient.Builder builder, VectorStore vectorStore) {
        this.chatClient = builder.build();
        this.vectorStore = vectorStore;
    }

    // 查询重写：让 AI 优化用户问题
    public String chatWithQueryRewrite(String userQuestion) {
        // 1. 重写查询
        String rewrittenQuery = chatClient.prompt()
                .system("将用户问题重写为更适合检索的形式，只返回重写后的问题")
                .user(userQuestion)
                .call()
                .content();

        // 2. 使用重写后的查询检索
        List<Document> docs = vectorStore.similaritySearch(rewrittenQuery);

        // 3. 生成回答
        return generateAnswer(userQuestion, docs);
    }

    // 多查询检索：从多个角度检索
    public String chatWithMultiQuery(String userQuestion) {
        // 1. 生成多个查询变体
        String queryVariants = chatClient.prompt()
                .system("""
                    为以下问题生成3个不同角度的查询变体，用于检索相关文档。
                    每行一个查询，不要编号。
                    """)
                .user(userQuestion)
                .call()
                .content();

        // 2. 对每个变体进行检索并合并结果
        Set<Document> allDocs = new HashSet<>();
        for (String query : queryVariants.split("\n")) {
            if (!query.isBlank()) {
                allDocs.addAll(vectorStore.similaritySearch(query.trim()));
            }
        }

        // 3. 生成回答
        return generateAnswer(userQuestion, new ArrayList<>(allDocs));
    }

    // 带来源引用的 RAG
    public RagResponse chatWithSources(String userQuestion) {
        List<Document> docs = vectorStore.similaritySearch(userQuestion);

        String context = docs.stream()
                .map(d -> "[来源: %s]\n%s".formatted(
                        d.getMetadata().getOrDefault("source", "未知"),
                        d.getContent()
                ))
                .collect(Collectors.joining("\n\n"));

        String answer = chatClient.prompt()
                .system("""
                    基于参考资料回答问题。在回答中引用来源，格式：[来源: xxx]
                    
                    参考资料：
                    """ + context)
                .user(userQuestion)
                .call()
                .content();

        List<String> sources = docs.stream()
                .map(d -> (String) d.getMetadata().getOrDefault("source", "未知"))
                .distinct()
                .toList();

        return new RagResponse(answer, sources);
    }

    private String generateAnswer(String question, List<Document> docs) {
        String context = docs.stream()
                .map(Document::getContent)
                .collect(Collectors.joining("\n\n"));

        return chatClient.prompt()
                .system("基于以下参考资料回答问题：\n" + context)
                .user(question)
                .call()
                .content();
    }

    public record RagResponse(String answer, List<String> sources) {}
}
```

---

## 9. Function Calling

### 9.1 什么是 Function Calling？

Function Calling（函数调用）允许 AI 模型调用你定义的函数来获取实时信息或执行操作。这让 AI 不再局限于静态知识，可以与外部系统交互。

**典型场景：**
- 查询天气、股票等实时数据
- 操作数据库、发送邮件
- 调用第三方 API
- 执行计算任务

### 9.2 定义函数

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Description;
import java.util.function.Function;

@Configuration
public class FunctionConfig {

    // 天气查询函数
    @Bean
    @Description("获取指定城市的当前天气信息")
    public Function<WeatherRequest, WeatherResponse> getWeather() {
        return request -> {
            // 实际项目中调用天气 API
            return new WeatherResponse(
                request.city(),
                "晴",
                25,
                65,
                "东南风 3级"
            );
        };
    }

    // 股票查询函数
    @Bean
    @Description("获取指定股票的实时价格")
    public Function<StockRequest, StockResponse> getStockPrice() {
        return request -> {
            // 实际项目中调用股票 API
            return new StockResponse(
                request.symbol(),
                "阿里巴巴",
                85.50,
                2.3,
                "2024-01-15 15:00:00"
            );
        };
    }

    // 计算器函数
    @Bean
    @Description("执行数学计算，支持加减乘除")
    public Function<CalculatorRequest, CalculatorResponse> calculate() {
        return request -> {
            double result = switch (request.operation()) {
                case "add" -> request.a() + request.b();
                case "subtract" -> request.a() - request.b();
                case "multiply" -> request.a() * request.b();
                case "divide" -> request.b() != 0 ? request.a() / request.b() : Double.NaN;
                default -> throw new IllegalArgumentException("不支持的操作: " + request.operation());
            };
            return new CalculatorResponse(result, request.operation());
        };
    }

    // 请求/响应记录类
    public record WeatherRequest(String city) {}
    public record WeatherResponse(String city, String weather, int temperature, 
                                   int humidity, String wind) {}

    public record StockRequest(String symbol) {}
    public record StockResponse(String symbol, String name, double price, 
                                 double changePercent, String updateTime) {}

    public record CalculatorRequest(double a, double b, String operation) {}
    public record CalculatorResponse(double result, String operation) {}
}
```

### 9.3 使用函数

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class FunctionCallingService {

    private final ChatClient chatClient;

    public FunctionCallingService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 指定可用函数
    public String chatWithFunctions(String userMessage) {
        return chatClient.prompt()
                .user(userMessage)
                .functions("getWeather", "getStockPrice", "calculate")
                .call()
                .content();
    }

    // 动态选择函数
    public String chatWithDynamicFunctions(String userMessage, List<String> functions) {
        return chatClient.prompt()
                .user(userMessage)
                .functions(functions.toArray(new String[0]))
                .call()
                .content();
    }
}
```

**使用示例：**
```java
// 用户问："北京今天天气怎么样？"
// AI 会自动调用 getWeather 函数，然后基于返回结果生成回答

// 用户问："帮我算一下 123 乘以 456"
// AI 会调用 calculate 函数
```

### 9.4 复杂函数示例

```java
import org.springframework.stereotype.Component;
import java.util.function.Function;

// 数据库查询函数
@Component
@Description("查询用户订单信息")
public class OrderQueryFunction implements Function<OrderQueryRequest, OrderQueryResponse> {

    private final OrderRepository orderRepository;

    public OrderQueryFunction(OrderRepository orderRepository) {
        this.orderRepository = orderRepository;
    }

    @Override
    public OrderQueryResponse apply(OrderQueryRequest request) {
        List<Order> orders = orderRepository.findByUserId(request.userId());
        
        if (request.status() != null) {
            orders = orders.stream()
                    .filter(o -> o.getStatus().equals(request.status()))
                    .toList();
        }

        return new OrderQueryResponse(
            orders.size(),
            orders.stream()
                    .map(o -> new OrderInfo(o.getId(), o.getProduct(), o.getAmount(), o.getStatus()))
                    .toList()
        );
    }

    public record OrderQueryRequest(
        @JsonProperty(required = true) String userId,
        @JsonProperty String status  // 可选参数
    ) {}

    public record OrderQueryResponse(int total, List<OrderInfo> orders) {}
    public record OrderInfo(String orderId, String product, double amount, String status) {}
}

// 发送通知函数
@Component
@Description("发送通知消息给用户")
public class SendNotificationFunction implements Function<NotificationRequest, NotificationResponse> {

    private final NotificationService notificationService;

    public SendNotificationFunction(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @Override
    public NotificationResponse apply(NotificationRequest request) {
        boolean success = notificationService.send(
            request.userId(),
            request.channel(),
            request.message()
        );
        return new NotificationResponse(success, success ? "发送成功" : "发送失败");
    }

    public record NotificationRequest(
        String userId,
        String channel,  // email, sms, push
        String message
    ) {}

    public record NotificationResponse(boolean success, String message) {}
}
```

---

## 10. Image 图像模型

### 10.1 图像生成

```java
import org.springframework.ai.image.*;
import org.springframework.stereotype.Service;

@Service
public class ImageService {

    private final ImageModel imageModel;

    public ImageService(ImageModel imageModel) {
        this.imageModel = imageModel;
    }

    // 基础图像生成
    public String generateImage(String prompt) {
        ImageResponse response = imageModel.call(
            new ImagePrompt(prompt)
        );
        return response.getResult().getOutput().getUrl();
    }

    // 带参数的图像生成
    public String generateImageWithOptions(String prompt) {
        ImageOptions options = ImageOptionsBuilder.builder()
                .withModel("dall-e-3")
                .withWidth(1024)
                .withHeight(1024)
                .withN(1)  // 生成数量
                .withQuality("hd")
                .withStyle("vivid")  // vivid 或 natural
                .build();

        ImageResponse response = imageModel.call(
            new ImagePrompt(prompt, options)
        );

        return response.getResult().getOutput().getUrl();
    }

    // 批量生成
    public List<String> generateMultipleImages(String prompt, int count) {
        ImageOptions options = ImageOptionsBuilder.builder()
                .withN(count)
                .build();

        ImageResponse response = imageModel.call(
            new ImagePrompt(prompt, options)
        );

        return response.getResults().stream()
                .map(result -> result.getOutput().getUrl())
                .toList();
    }

    // 获取 Base64 格式
    public String generateImageAsBase64(String prompt) {
        ImageOptions options = ImageOptionsBuilder.builder()
                .withResponseFormat("b64_json")
                .build();

        ImageResponse response = imageModel.call(
            new ImagePrompt(prompt, options)
        );

        return response.getResult().getOutput().getB64Json();
    }
}
```

### 10.2 图像生成 Controller

```java
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import java.util.Base64;

@RestController
@RequestMapping("/api/image")
public class ImageController {

    private final ImageService imageService;

    public ImageController(ImageService imageService) {
        this.imageService = imageService;
    }

    @PostMapping("/generate")
    public ImageGenerationResponse generate(@RequestBody ImageGenerationRequest request) {
        String imageUrl = imageService.generateImageWithOptions(request.prompt());
        return new ImageGenerationResponse(imageUrl);
    }

    @PostMapping(value = "/generate/base64", produces = MediaType.IMAGE_PNG_VALUE)
    public byte[] generateBase64(@RequestBody ImageGenerationRequest request) {
        String base64 = imageService.generateImageAsBase64(request.prompt());
        return Base64.getDecoder().decode(base64);
    }

    public record ImageGenerationRequest(String prompt) {}
    public record ImageGenerationResponse(String imageUrl) {}
}
```

---

## 11. Audio 音频模型

### 11.1 语音转文字（STT）

```java
import org.springframework.ai.audio.transcription.*;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
public class AudioTranscriptionService {

    private final AudioTranscriptionModel transcriptionModel;

    public AudioTranscriptionService(AudioTranscriptionModel transcriptionModel) {
        this.transcriptionModel = transcriptionModel;
    }

    // 基础转录
    public String transcribe(Resource audioFile) {
        AudioTranscriptionPrompt prompt = new AudioTranscriptionPrompt(audioFile);
        AudioTranscriptionResponse response = transcriptionModel.call(prompt);
        return response.getResult().getOutput();
    }

    // 带参数的转录
    public String transcribeWithOptions(Resource audioFile, String language) {
        AudioTranscriptionOptions options = AudioTranscriptionOptions.builder()
                .withModel("whisper-1")
                .withLanguage(language)
                .withTemperature(0.0f)
                .withResponseFormat(AudioTranscriptionFormat.TEXT)
                .build();

        AudioTranscriptionPrompt prompt = new AudioTranscriptionPrompt(audioFile, options);
        return transcriptionModel.call(prompt).getResult().getOutput();
    }

    // 获取带时间戳的转录
    public String transcribeWithTimestamps(Resource audioFile) {
        AudioTranscriptionOptions options = AudioTranscriptionOptions.builder()
                .withResponseFormat(AudioTranscriptionFormat.VERBOSE_JSON)
                .withTimestampGranularities(Set.of("word", "segment"))
                .build();

        AudioTranscriptionPrompt prompt = new AudioTranscriptionPrompt(audioFile, options);
        return transcriptionModel.call(prompt).getResult().getOutput();
    }
}
```

### 11.2 文字转语音（TTS）

```java
import org.springframework.ai.audio.speech.*;
import org.springframework.stereotype.Service;

@Service
public class TextToSpeechService {

    private final SpeechModel speechModel;

    public TextToSpeechService(SpeechModel speechModel) {
        this.speechModel = speechModel;
    }

    // 基础语音合成
    public byte[] synthesize(String text) {
        SpeechPrompt prompt = new SpeechPrompt(text);
        SpeechResponse response = speechModel.call(prompt);
        return response.getResult().getOutput();
    }

    // 带参数的语音合成
    public byte[] synthesizeWithOptions(String text, String voice) {
        SpeechOptions options = SpeechOptions.builder()
                .withModel("tts-1-hd")
                .withVoice(voice)  // alloy, echo, fable, onyx, nova, shimmer
                .withSpeed(1.0f)
                .withResponseFormat("mp3")
                .build();

        SpeechPrompt prompt = new SpeechPrompt(text, options);
        return speechModel.call(prompt).getResult().getOutput();
    }
}
```

### 11.3 音频 Controller

```java
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/audio")
public class AudioController {

    private final AudioTranscriptionService transcriptionService;
    private final TextToSpeechService ttsService;

    public AudioController(AudioTranscriptionService transcriptionService,
                          TextToSpeechService ttsService) {
        this.transcriptionService = transcriptionService;
        this.ttsService = ttsService;
    }

    // 语音转文字
    @PostMapping("/transcribe")
    public TranscriptionResponse transcribe(@RequestParam("file") MultipartFile file) {
        String text = transcriptionService.transcribe(file.getResource());
        return new TranscriptionResponse(text);
    }

    // 文字转语音
    @PostMapping(value = "/synthesize", produces = "audio/mpeg")
    public byte[] synthesize(@RequestBody SynthesizeRequest request) {
        return ttsService.synthesizeWithOptions(request.text(), request.voice());
    }

    public record TranscriptionResponse(String text) {}
    public record SynthesizeRequest(String text, String voice) {}
}
```

---

## 12. Advisors 增强器

### 12.1 Advisor 概述

Advisor 是 Spring AI 的拦截器机制，可以在请求发送前和响应返回后进行处理。类似于 Spring MVC 的拦截器或 AOP。

**内置 Advisor：**
- `SimpleLoggerAdvisor`：日志记录
- `MessageChatMemoryAdvisor`：对话记忆
- `QuestionAnswerAdvisor`：RAG 检索增强
- `SafeGuardAdvisor`：安全过滤

### 12.2 自定义 Advisor

```java
import org.springframework.ai.chat.client.advisor.*;
import org.springframework.ai.chat.client.advisor.api.*;

// 日志记录 Advisor
public class LoggingAdvisor implements CallAroundAdvisor {

    private static final Logger log = LoggerFactory.getLogger(LoggingAdvisor.class);

    @Override
    public String getName() {
        return "LoggingAdvisor";
    }

    @Override
    public int getOrder() {
        return 0;  // 执行顺序，数字越小越先执行
    }

    @Override
    public AdvisedResponse aroundCall(AdvisedRequest request, CallAroundAdvisorChain chain) {
        // 请求前处理
        log.info("Request: {}", request.userText());
        long startTime = System.currentTimeMillis();

        // 调用下一个 Advisor 或实际请求
        AdvisedResponse response = chain.nextAroundCall(request);

        // 响应后处理
        long duration = System.currentTimeMillis() - startTime;
        log.info("Response in {}ms: {}", duration, 
                response.response().getResult().getOutput().getContent());

        return response;
    }
}

// 敏感词过滤 Advisor
public class SensitiveWordFilterAdvisor implements CallAroundAdvisor {

    private final List<String> sensitiveWords;

    public SensitiveWordFilterAdvisor(List<String> sensitiveWords) {
        this.sensitiveWords = sensitiveWords;
    }

    @Override
    public String getName() {
        return "SensitiveWordFilterAdvisor";
    }

    @Override
    public int getOrder() {
        return 1;
    }

    @Override
    public AdvisedResponse aroundCall(AdvisedRequest request, CallAroundAdvisorChain chain) {
        // 检查用户输入
        String userText = request.userText();
        for (String word : sensitiveWords) {
            if (userText.contains(word)) {
                throw new IllegalArgumentException("输入包含敏感词");
            }
        }

        AdvisedResponse response = chain.nextAroundCall(request);

        // 过滤输出中的敏感词
        String content = response.response().getResult().getOutput().getContent();
        for (String word : sensitiveWords) {
            content = content.replace(word, "***");
        }

        // 返回过滤后的响应（需要重新构建响应对象）
        return response;
    }
}
```

### 12.3 使用 Advisor

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AdvisorConfig {

    @Bean
    public ChatClient chatClientWithAdvisors(ChatClient.Builder builder) {
        return builder
                .defaultAdvisors(
                        new LoggingAdvisor(),
                        new SensitiveWordFilterAdvisor(List.of("敏感词1", "敏感词2")),
                        new SimpleLoggerAdvisor()
                )
                .build();
    }
}

// 动态添加 Advisor
@Service
public class DynamicAdvisorService {

    private final ChatClient.Builder chatClientBuilder;

    public DynamicAdvisorService(ChatClient.Builder chatClientBuilder) {
        this.chatClientBuilder = chatClientBuilder;
    }

    public String chatWithCustomAdvisor(String message, boolean enableLogging) {
        ChatClient.Builder builder = chatClientBuilder.clone();
        
        if (enableLogging) {
            builder.defaultAdvisors(new LoggingAdvisor());
        }

        return builder.build()
                .prompt()
                .user(message)
                .call()
                .content();
    }
}
```

---

## 13. 对话记忆

### 13.1 内存对话记忆

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor;
import org.springframework.ai.chat.memory.InMemoryChatMemory;
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.stereotype.Service;

@Service
public class ChatMemoryService {

    private final ChatClient chatClient;
    private final ChatMemory chatMemory;

    public ChatMemoryService(ChatClient.Builder builder) {
        this.chatMemory = new InMemoryChatMemory();
        this.chatClient = builder
                .defaultAdvisors(
                    MessageChatMemoryAdvisor.builder(chatMemory)
                        .withChatMemoryRetrieveSize(10)  // 检索最近10条消息
                        .build()
                )
                .build();
    }

    public String chat(String sessionId, String message) {
        return chatClient.prompt()
                .user(message)
                .advisors(advisor -> advisor
                        .param(MessageChatMemoryAdvisor.CHAT_MEMORY_CONVERSATION_ID_KEY, sessionId)
                )
                .call()
                .content();
    }

    public void clearMemory(String sessionId) {
        chatMemory.clear(sessionId);
    }
}
```

### 13.2 持久化对话记忆（Redis）

```java
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.ai.chat.messages.Message;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Component
public class RedisChatMemory implements ChatMemory {

    private final RedisTemplate<String, Object> redisTemplate;
    private static final String KEY_PREFIX = "chat:memory:";
    private static final long TTL_HOURS = 24;

    public RedisChatMemory(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void add(String conversationId, List<Message> messages) {
        String key = KEY_PREFIX + conversationId;
        for (Message message : messages) {
            redisTemplate.opsForList().rightPush(key, message);
        }
        redisTemplate.expire(key, TTL_HOURS, TimeUnit.HOURS);
    }

    @Override
    public List<Message> get(String conversationId, int lastN) {
        String key = KEY_PREFIX + conversationId;
        Long size = redisTemplate.opsForList().size(key);
        if (size == null || size == 0) {
            return List.of();
        }
        
        long start = Math.max(0, size - lastN);
        List<Object> objects = redisTemplate.opsForList().range(key, start, -1);
        
        return objects.stream()
                .map(obj -> (Message) obj)
                .toList();
    }

    @Override
    public void clear(String conversationId) {
        redisTemplate.delete(KEY_PREFIX + conversationId);
    }
}
```

### 13.3 滑动窗口记忆

当对话很长时，需要限制发送给 AI 的历史消息数量，避免超出 token 限制。

```java
import org.springframework.ai.chat.memory.ChatMemory;
import org.springframework.ai.chat.messages.Message;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SlidingWindowChatMemory implements ChatMemory {

    private final Map<String, LinkedList<Message>> conversations = new ConcurrentHashMap<>();
    private final int maxMessages;

    public SlidingWindowChatMemory(int maxMessages) {
        this.maxMessages = maxMessages;
    }

    @Override
    public void add(String conversationId, List<Message> messages) {
        LinkedList<Message> history = conversations.computeIfAbsent(
            conversationId, 
            k -> new LinkedList<>()
        );
        
        for (Message message : messages) {
            history.addLast(message);
            // 超出限制时移除最早的消息
            while (history.size() > maxMessages) {
                history.removeFirst();
            }
        }
    }

    @Override
    public List<Message> get(String conversationId, int lastN) {
        LinkedList<Message> history = conversations.get(conversationId);
        if (history == null) {
            return List.of();
        }
        
        int start = Math.max(0, history.size() - lastN);
        return new ArrayList<>(history.subList(start, history.size()));
    }

    @Override
    public void clear(String conversationId) {
        conversations.remove(conversationId);
    }
}
```

---

## 14. 多模态

### 14.1 图文混合输入

多模态允许同时发送文本和图像给 AI，让 AI 能够"看图说话"。

```java
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.model.Media;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeTypeUtils;

@Service
public class MultimodalService {

    private final ChatClient chatClient;

    public MultimodalService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // 分析图片内容
    public String analyzeImage(Resource imageResource, String question) {
        return chatClient.prompt()
                .user(userSpec -> userSpec
                        .text(question)
                        .media(MimeTypeUtils.IMAGE_PNG, imageResource)
                )
                .call()
                .content();
    }

    // 通过 URL 分析图片
    public String analyzeImageByUrl(String imageUrl, String question) {
        return chatClient.prompt()
                .user(userSpec -> userSpec
                        .text(question)
                        .media(MimeTypeUtils.IMAGE_JPEG, new URL(imageUrl))
                )
                .call()
                .content();
    }

    // 多图分析
    public String analyzeMultipleImages(List<Resource> images, String question) {
        return chatClient.prompt()
                .user(userSpec -> {
                    userSpec.text(question);
                    for (Resource image : images) {
                        userSpec.media(MimeTypeUtils.IMAGE_PNG, image);
                    }
                })
                .call()
                .content();
    }

    // 图片对比
    public String compareImages(Resource image1, Resource image2) {
        return chatClient.prompt()
                .user(userSpec -> userSpec
                        .text("请对比这两张图片，描述它们的异同点")
                        .media(MimeTypeUtils.IMAGE_PNG, image1)
                        .media(MimeTypeUtils.IMAGE_PNG, image2)
                )
                .call()
                .content();
    }
}
```

### 14.2 多模态 Controller

```java
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/multimodal")
public class MultimodalController {

    private final MultimodalService multimodalService;

    public MultimodalController(MultimodalService multimodalService) {
        this.multimodalService = multimodalService;
    }

    // 上传图片并分析
    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public AnalysisResponse analyzeImage(
            @RequestParam("image") MultipartFile image,
            @RequestParam("question") String question) {
        
        String result = multimodalService.analyzeImage(image.getResource(), question);
        return new AnalysisResponse(result);
    }

    // 通过 URL 分析
    @PostMapping("/analyze-url")
    public AnalysisResponse analyzeByUrl(@RequestBody UrlAnalysisRequest request) {
        String result = multimodalService.analyzeImageByUrl(request.imageUrl(), request.question());
        return new AnalysisResponse(result);
    }

    public record UrlAnalysisRequest(String imageUrl, String question) {}
    public record AnalysisResponse(String analysis) {}
}
```

### 14.3 实用场景示例

```java
@Service
public class VisionApplicationService {

    private final ChatClient chatClient;

    public VisionApplicationService(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    // OCR 文字识别
    public String extractText(Resource image) {
        return chatClient.prompt()
                .user(userSpec -> userSpec
                        .text("请识别图片中的所有文字，按原有格式输出")
                        .media(MimeTypeUtils.IMAGE_PNG, image)
                )
                .call()
                .content();
    }

    // 商品识别
    public ProductInfo identifyProduct(Resource image) {
        return chatClient.prompt()
                .user(userSpec -> userSpec
                        .text("识别图片中的商品，返回商品名称、品牌、预估价格")
                        .media(MimeTypeUtils.IMAGE_PNG, image)
                )
                .call()
                .entity(ProductInfo.class);
    }

    // 图表数据提取
    public ChartData extractChartData(Resource chartImage) {
        return chatClient.prompt()
                .user(userSpec -> userSpec
                        .text("分析这个图表，提取其中的数据和关键信息")
                        .media(MimeTypeUtils.IMAGE_PNG, chartImage)
                )
                .call()
                .entity(ChartData.class);
    }

    public record ProductInfo(String name, String brand, String estimatedPrice, String description) {}
    public record ChartData(String chartType, String title, List<DataPoint> data, String summary) {}
    public record DataPoint(String label, double value) {}
}
```

---

## 15. 常见错误与解决方案

### 15.1 API 连接错误

**错误：Connection refused / Connection timed out**
```java
// 原因：无法连接到 AI 服务
// 解决方案：

// 1. 检查网络连接和代理设置
spring:
  ai:
    openai:
      base-url: https://your-proxy.com/v1  # 使用代理

// 2. 配置超时时间
@Configuration
public class OpenAiConfig {
    @Bean
    public RestClient.Builder restClientBuilder() {
        return RestClient.builder()
                .requestFactory(new SimpleClientHttpRequestFactory() {{
                    setConnectTimeout(Duration.ofSeconds(30));
                    setReadTimeout(Duration.ofSeconds(60));
                }});
    }
}
```

**错误：401 Unauthorized / Invalid API Key**
```yaml
# 原因：API Key 无效或未配置
# 解决方案：

# 1. 检查环境变量
# Windows: set OPENAI_API_KEY=sk-xxx
# Linux: export OPENAI_API_KEY=sk-xxx

# 2. 检查配置文件
spring:
  ai:
    openai:
      api-key: ${OPENAI_API_KEY}  # 确保环境变量已设置
```

**错误：429 Too Many Requests / Rate Limit Exceeded**
```java
// 原因：请求频率超限
// 解决方案：实现重试机制

@Configuration
public class RetryConfig {
    @Bean
    public RetryTemplate retryTemplate() {
        return RetryTemplate.builder()
                .maxAttempts(3)
                .exponentialBackoff(1000, 2, 10000)
                .retryOn(RateLimitException.class)
                .build();
    }
}

@Service
public class ResilientChatService {
    private final ChatClient chatClient;
    private final RetryTemplate retryTemplate;

    public String chat(String message) {
        return retryTemplate.execute(context -> 
            chatClient.prompt().user(message).call().content()
        );
    }
}
```

### 15.2 模型相关错误

**错误：Model not found / Invalid model**
```yaml
# 原因：模型名称错误或无权访问
# 解决方案：使用正确的模型名称

spring:
  ai:
    openai:
      chat:
        options:
          model: gpt-4o  # 确保模型名称正确
          # 常用模型：gpt-4o, gpt-4-turbo, gpt-3.5-turbo
```

**错误：Context length exceeded / Maximum tokens exceeded**
```java
// 原因：输入内容超过模型的上下文长度限制
// 解决方案：

// 1. 限制输入长度
public String chat(String message) {
    if (message.length() > 10000) {
        message = message.substring(0, 10000) + "...";
    }
    return chatClient.prompt().user(message).call().content();
}

// 2. 使用滑动窗口记忆
ChatMemory memory = new SlidingWindowChatMemory(10);  // 只保留最近10条

// 3. 对长文本进行分块处理
public List<String> processLongText(String longText) {
    List<String> chunks = splitIntoChunks(longText, 4000);
    return chunks.stream()
            .map(chunk -> chatClient.prompt().user(chunk).call().content())
            .toList();
}
```

**错误：Content policy violation**
```java
// 原因：内容违反使用政策
// 解决方案：添加内容过滤

@Service
public class SafeChatService {
    private final ChatClient chatClient;

    public String chat(String message) {
        // 预检查敏感内容
        if (containsSensitiveContent(message)) {
            return "抱歉，无法处理该请求";
        }
        
        try {
            return chatClient.prompt().user(message).call().content();
        } catch (ContentPolicyViolationException e) {
            return "内容不符合使用规范，请修改后重试";
        }
    }
}
```

### 15.3 输出解析错误

**错误：JSON parse error / Cannot deserialize**
```java
// 原因：AI 返回的格式不符合预期
// 解决方案：

// 1. 在 Prompt 中明确要求 JSON 格式
public BookInfo getBookInfo(String title) {
    String response = chatClient.prompt()
            .system("""
                你必须以 JSON 格式返回，不要包含任何其他文字。
                格式示例：{"title": "书名", "author": "作者"}
                """)
            .user("介绍《" + title + "》这本书")
            .call()
            .content();
    
    // 清理可能的 markdown 代码块标记
    response = response.replaceAll("```json\\s*", "")
                       .replaceAll("```\\s*", "")
                       .trim();
    
    return objectMapper.readValue(response, BookInfo.class);
}

// 2. 使用 entity() 方法（推荐）
public BookInfo getBookInfoSafe(String title) {
    return chatClient.prompt()
            .user("介绍《" + title + "》这本书")
            .call()
            .entity(BookInfo.class);  // Spring AI 自动处理格式
}

// 3. 添加重试逻辑
public <T> T parseWithRetry(String prompt, Class<T> type, int maxRetries) {
    for (int i = 0; i < maxRetries; i++) {
        try {
            return chatClient.prompt()
                    .user(prompt)
                    .call()
                    .entity(type);
        } catch (Exception e) {
            if (i == maxRetries - 1) throw e;
        }
    }
    throw new RuntimeException("解析失败");
}
```

### 15.4 向量数据库错误

**错误：Vector dimension mismatch**
```java
// 原因：向量维度与数据库配置不匹配
// 解决方案：确保配置一致

// application.yml
spring:
  ai:
    vectorstore:
      pgvector:
        dimensions: 1536  # 必须与 Embedding 模型输出维度一致
        # text-embedding-3-small: 1536
        # text-embedding-3-large: 3072
        # text-embedding-ada-002: 1536
```

**错误：Connection to vector store failed**
```yaml
# 原因：数据库连接问题
# 解决方案：

# 1. 检查数据库是否启动
# 2. 检查连接配置
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/vectordb
    username: postgres
    password: postgres
    
# 3. 确保 pgvector 扩展已安装
# SQL: CREATE EXTENSION IF NOT EXISTS vector;
```

### 15.5 Function Calling 错误

**错误：Function not found**
```java
// 原因：函数未注册或名称不匹配
// 解决方案：

// 1. 确保函数已注册为 Bean
@Bean
@Description("获取天气信息")  // 必须添加描述
public Function<WeatherRequest, WeatherResponse> getWeather() {
    return request -> new WeatherResponse(request.city(), "晴", 25);
}

// 2. 使用正确的函数名（Bean 名称）
chatClient.prompt()
        .user("北京天气")
        .functions("getWeather")  // 与 @Bean 方法名一致
        .call()
        .content();
```

**错误：Function execution failed**
```java
// 原因：函数执行时抛出异常
// 解决方案：添加异常处理

@Bean
@Description("查询订单")
public Function<OrderRequest, OrderResponse> queryOrder() {
    return request -> {
        try {
            Order order = orderService.findById(request.orderId());
            return new OrderResponse(true, order, null);
        } catch (Exception e) {
            // 返回错误信息而非抛出异常
            return new OrderResponse(false, null, "查询失败: " + e.getMessage());
        }
    };
}

public record OrderResponse(boolean success, Order order, String error) {}
```

### 15.6 流式响应错误

**错误：Stream closed / Flux cancelled**
```java
// 原因：客户端提前断开连接
// 解决方案：

@GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
public Flux<String> stream(@RequestParam String message) {
    return chatClient.prompt()
            .user(message)
            .stream()
            .content()
            .onErrorResume(e -> {
                log.error("Stream error", e);
                return Flux.just("发生错误: " + e.getMessage());
            })
            .doOnCancel(() -> log.info("Client disconnected"));
}
```

**错误：SSE connection timeout**
```java
// 原因：连接超时
// 解决方案：配置超时时间

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        configurer.setDefaultTimeout(300000);  // 5分钟
    }
}
```

### 15.7 内存与性能问题

**问题：OutOfMemoryError**
```java
// 原因：对话历史过长或处理大文件
// 解决方案：

// 1. 限制对话历史长度
ChatMemory memory = new SlidingWindowChatMemory(20);

// 2. 分批处理大文件
public void processLargeFile(Resource file) {
    try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(file.getInputStream()))) {
        
        List<String> batch = new ArrayList<>();
        String line;
        
        while ((line = reader.readLine()) != null) {
            batch.add(line);
            if (batch.size() >= 100) {
                processBatch(batch);
                batch.clear();
            }
        }
        
        if (!batch.isEmpty()) {
            processBatch(batch);
        }
    }
}

// 3. 使用流式处理
public Flux<String> streamLargeResponse(String message) {
    return chatClient.prompt()
            .user(message)
            .stream()
            .content();  // 流式返回，不会一次性加载到内存
}
```

**问题：响应缓慢**
```java
// 解决方案：

// 1. 使用异步处理
@Async
public CompletableFuture<String> asyncChat(String message) {
    return CompletableFuture.completedFuture(
        chatClient.prompt().user(message).call().content()
    );
}

// 2. 并行处理多个请求
public List<String> parallelChat(List<String> messages) {
    return messages.parallelStream()
            .map(msg -> chatClient.prompt().user(msg).call().content())
            .toList();
}

// 3. 缓存常见问题的回答
@Cacheable(value = "chatCache", key = "#message")
public String cachedChat(String message) {
    return chatClient.prompt().user(message).call().content();
}
```

---

## 附录：常用配置速查

```yaml
# application.yml 完整配置示例
spring:
  ai:
    # OpenAI 配置
    openai:
      api-key: ${OPENAI_API_KEY}
      base-url: https://api.openai.com
      chat:
        options:
          model: gpt-4o
          temperature: 0.7
          max-tokens: 2000
          top-p: 1.0
          frequency-penalty: 0.0
          presence-penalty: 0.0
      embedding:
        options:
          model: text-embedding-3-small
      image:
        options:
          model: dall-e-3
          quality: hd
          size: 1024x1024
      audio:
        transcription:
          options:
            model: whisper-1
        speech:
          options:
            model: tts-1-hd
            voice: alloy

    # Ollama 配置（本地）
    ollama:
      base-url: http://localhost:11434
      chat:
        options:
          model: llama3
          temperature: 0.7
      embedding:
        options:
          model: nomic-embed-text

    # 向量数据库配置
    vectorstore:
      pgvector:
        index-type: HNSW
        distance-type: COSINE_DISTANCE
        dimensions: 1536

    # 重试配置
    retry:
      max-attempts: 3
      backoff:
        initial-interval: 1000
        multiplier: 2
        max-interval: 10000
```

---

> 💡 **学习建议**：
> 1. 从 ChatClient 基础用法开始，理解 Prompt 的构建方式
> 2. 掌握结构化输出，这是构建可靠应用的关键
> 3. 深入学习 RAG，这是企业级 AI 应用的核心技术
> 4. Function Calling 让 AI 能够与外部系统交互，扩展能力边界
> 5. 关注错误处理和重试机制，提升应用稳定性
