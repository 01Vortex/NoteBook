> Maven 和 Gradle 是 Java 生态中最主流的两大构建工具
> 本笔记从基础到进阶，全面覆盖项目构建、依赖管理、多模块开发等场景

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [项目结构](#3-项目结构)
4. [依赖管理](#4-依赖管理)
5. [生命周期与任务](#5-生命周期与任务)
6. [插件系统](#6-插件系统)
7. [多模块项目](#7-多模块项目)
8. [仓库管理](#8-仓库管理)
9. [构建配置](#9-构建配置)
10. [测试集成](#10-测试集成)
11. [打包与发布](#11-打包与发布)
12. [性能优化](#12-性能优化)
13. [CI/CD 集成](#13-cicd-集成)
14. [Maven 与 Gradle 对比](#14-maven-与-gradle-对比)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是构建工具？

构建工具是自动化项目构建过程的软件，主要负责：

- **依赖管理**：自动下载和管理项目所需的第三方库
- **编译代码**：将源代码编译成字节码或可执行文件
- **运行测试**：自动执行单元测试和集成测试
- **打包部署**：将项目打包成 JAR、WAR 等格式
- **代码质量**：集成代码检查、覆盖率分析等工具

### 1.2 Maven 简介

Maven 是 Apache 基金会的项目，2004 年发布，采用"约定优于配置"的理念：

- **配置文件**：pom.xml（Project Object Model）
- **配置语言**：XML
- **核心理念**：约定优于配置、声明式构建
- **优点**：标准化、文档丰富、生态成熟
- **缺点**：XML 冗长、灵活性较低、构建速度较慢

### 1.3 Gradle 简介

Gradle 是 2012 年发布的新一代构建工具，结合了 Maven 和 Ant 的优点：

- **配置文件**：build.gradle（Groovy）或 build.gradle.kts（Kotlin）
- **配置语言**：Groovy DSL 或 Kotlin DSL
- **核心理念**：约定优于配置 + 灵活的脚本能力
- **优点**：构建速度快、配置简洁、高度灵活
- **缺点**：学习曲线较陡、版本兼容性问题

### 1.4 核心概念对比

| 概念 | Maven | Gradle |
|------|-------|--------|
| 配置文件 | pom.xml | build.gradle / build.gradle.kts |
| 依赖坐标 | groupId:artifactId:version | group:name:version |
| 构建单元 | Phase（阶段） | Task（任务） |
| 依赖范围 | scope | configuration |
| 多模块 | modules | subprojects |
| 插件 | plugin | plugin |

---

## 2. 安装与配置

### 2.1 Maven 安装

#### Windows 安装

```bash
# 方式一：手动安装
# 1. 下载 https://maven.apache.org/download.cgi
# 2. 解压到 D:\tools\apache-maven-3.9.6
# 3. 配置环境变量

# 设置 MAVEN_HOME
setx MAVEN_HOME "D:\tools\apache-maven-3.9.6"

# 添加到 PATH
setx PATH "%PATH%;%MAVEN_HOME%\bin"

# 方式二：使用 Chocolatey
choco install maven

# 方式三：使用 Scoop
scoop install maven
```

#### Linux/macOS 安装

```bash
# Ubuntu/Debian
sudo apt-get install maven

# macOS (Homebrew)
brew install maven

# 验证安装
mvn -v
```

#### Maven 配置文件

Maven 的配置文件 `settings.xml` 位于：
- **全局配置**：`${MAVEN_HOME}/conf/settings.xml`
- **用户配置**：`~/.m2/settings.xml`（优先级更高）

```xml
<!-- ~/.m2/settings.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0
          https://maven.apache.org/xsd/settings-1.2.0.xsd">
    
    <!-- 本地仓库路径 -->
    <localRepository>D:/repository/maven</localRepository>
    
    <!-- 镜像配置 -->
    <mirrors>
        <mirror>
            <id>aliyun</id>
            <name>阿里云公共仓库</name>
            <url>https://maven.aliyun.com/repository/public</url>
            <mirrorOf>central</mirrorOf>
        </mirror>
    </mirrors>
    
    <!-- 代理配置 -->
    <proxies>
        <proxy>
            <id>my-proxy</id>
            <active>true</active>
            <protocol>http</protocol>
            <host>proxy.company.com</host>
            <port>8080</port>
            <nonProxyHosts>localhost|127.0.0.1</nonProxyHosts>
        </proxy>
    </proxies>
    
    <!-- 服务器认证 -->
    <servers>
        <server>
            <id>nexus-releases</id>
            <username>admin</username>
            <password>admin123</password>
        </server>
    </servers>
</settings>
```

### 2.2 Gradle 安装

#### 手动安装

```bash
# Windows
# 1. 下载 https://gradle.org/releases/
# 2. 解压到 D:\tools\gradle-8.5
# 3. 配置环境变量
setx GRADLE_HOME "D:\tools\gradle-8.5"
setx PATH "%PATH%;%GRADLE_HOME%\bin"

# Linux/macOS
wget https://services.gradle.org/distributions/gradle-8.5-bin.zip
unzip gradle-8.5-bin.zip -d /opt/gradle
export GRADLE_HOME=/opt/gradle/gradle-8.5
export PATH=$PATH:$GRADLE_HOME/bin
```

#### 包管理器安装

```bash
# macOS
brew install gradle

# Ubuntu (SDKMAN 推荐)
curl -s "https://get.sdkman.io" | bash
sdk install gradle

# Windows (Chocolatey)
choco install gradle

# 验证安装
gradle -v
```

#### Gradle 配置文件

Gradle 的配置文件位于：
- **全局配置**：`~/.gradle/gradle.properties`
- **项目配置**：`项目根目录/gradle.properties`

```properties
# ~/.gradle/gradle.properties

# JVM 参数
org.gradle.jvmargs=-Xmx2048m -XX:+HeapDumpOnOutOfMemoryError

# 启用守护进程（加速构建）
org.gradle.daemon=true

# 启用并行构建
org.gradle.parallel=true

# 启用构建缓存
org.gradle.caching=true

# 启用配置缓存（Gradle 7.0+）
org.gradle.configuration-cache=true

# 代理配置
systemProp.http.proxyHost=proxy.company.com
systemProp.http.proxyPort=8080
systemProp.https.proxyHost=proxy.company.com
systemProp.https.proxyPort=8080
```

### 2.3 Gradle Wrapper

Gradle Wrapper 是 Gradle 的一个重要特性，它允许项目指定 Gradle 版本，无需预先安装：

```bash
# 生成 Wrapper 文件
gradle wrapper --gradle-version 8.5

# 生成的文件结构
├── gradle/
│   └── wrapper/
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── gradlew        # Linux/macOS 脚本
└── gradlew.bat    # Windows 脚本
```

```properties
# gradle/wrapper/gradle-wrapper.properties
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-8.5-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
```

**使用 Wrapper**：
```bash
# 使用 Wrapper 执行构建（推荐）
./gradlew build      # Linux/macOS
gradlew.bat build    # Windows

# 升级 Gradle 版本
./gradlew wrapper --gradle-version 8.6
```

> **最佳实践**：始终将 Wrapper 文件提交到版本控制，确保团队使用相同的 Gradle 版本。

---

## 3. 项目结构

### 3.1 Maven 标准目录结构

Maven 采用"约定优于配置"，有固定的目录结构：

```
my-project/
├── pom.xml                    # 项目配置文件
├── src/
│   ├── main/
│   │   ├── java/              # Java 源代码
│   │   ├── resources/         # 资源文件（配置、静态文件等）
│   │   └── webapp/            # Web 应用资源（仅 WAR 项目）
│   │       └── WEB-INF/
│   └── test/
│       ├── java/              # 测试代码
│       └── resources/         # 测试资源
└── target/                    # 构建输出目录（自动生成）
    ├── classes/               # 编译后的类文件
    ├── test-classes/          # 编译后的测试类
    └── my-project-1.0.0.jar   # 打包产物
```

### 3.2 基础 pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    
    <modelVersion>4.0.0</modelVersion>
    
    <!-- 项目坐标（GAV） -->
    <groupId>com.example</groupId>        <!-- 组织/公司标识 -->
    <artifactId>my-project</artifactId>   <!-- 项目名称 -->
    <version>1.0.0-SNAPSHOT</version>     <!-- 版本号 -->
    <packaging>jar</packaging>            <!-- 打包类型：jar/war/pom -->
    
    <!-- 项目信息 -->
    <name>My Project</name>
    <description>项目描述</description>
    <url>https://github.com/example/my-project</url>
    
    <!-- 属性定义 -->
    <properties>
        <java.version>17</java.version>
        <maven.compiler.source>${java.version}</maven.compiler.source>
        <maven.compiler.target>${java.version}</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring-boot.version>3.2.0</spring-boot.version>
    </properties>
    
    <!-- 依赖管理 -->
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>${spring-boot.version}</version>
        </dependency>
        
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <!-- 构建配置 -->
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <version>${spring-boot.version}</version>
            </plugin>
        </plugins>
    </build>
</project>
```

### 3.3 Gradle 项目结构

Gradle 默认使用与 Maven 相同的目录结构：

```
my-project/
├── build.gradle               # 构建脚本（Groovy DSL）
├── build.gradle.kts           # 构建脚本（Kotlin DSL）
├── settings.gradle            # 项目设置
├── gradle.properties          # Gradle 属性
├── gradle/
│   └── wrapper/               # Gradle Wrapper
├── src/
│   ├── main/
│   │   ├── java/
│   │   └── resources/
│   └── test/
│       ├── java/
│       └── resources/
└── build/                     # 构建输出目录
    ├── classes/
    ├── libs/                  # JAR 文件
    └── reports/               # 测试报告
```

### 3.4 基础 build.gradle

**Groovy DSL**：
```groovy
// build.gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
    id 'io.spring.dependency-management' version '1.1.4'
}

group = 'com.example'
version = '1.0.0-SNAPSHOT'

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
    // 阿里云镜像
    maven { url 'https://maven.aliyun.com/repository/public' }
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
}

tasks.named('test') {
    useJUnitPlatform()
}
```

**Kotlin DSL**：
```kotlin
// build.gradle.kts
plugins {
    java
    id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
}

group = "com.example"
version = "1.0.0-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
    maven { url = uri("https://maven.aliyun.com/repository/public") }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}

tasks.test {
    useJUnitPlatform()
}
```

### 3.5 settings.gradle

```groovy
// settings.gradle
rootProject.name = 'my-project'

// 多模块项目
include 'module-api'
include 'module-service'
include 'module-web'

// 插件仓库配置
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}
```

---

## 4. 依赖管理

### 4.1 Maven 依赖配置

#### 依赖坐标

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>  <!-- 组织标识 -->
    <artifactId>spring-boot-starter-web</artifactId>  <!-- 项目标识 -->
    <version>3.2.0</version>  <!-- 版本号 -->
    <scope>compile</scope>  <!-- 依赖范围 -->
    <type>jar</type>  <!-- 依赖类型，默认 jar -->
    <classifier>sources</classifier>  <!-- 分类器，如 sources、javadoc -->
    <optional>false</optional>  <!-- 是否可选 -->
</dependency>
```

#### 依赖范围（Scope）

| Scope | 编译 | 测试 | 运行 | 打包 | 说明 |
|-------|------|------|------|------|------|
| compile | ✅ | ✅ | ✅ | ✅ | 默认范围，全程可用 |
| provided | ✅ | ✅ | ❌ | ❌ | 运行时由容器提供（如 Servlet API） |
| runtime | ❌ | ✅ | ✅ | ✅ | 编译时不需要（如 JDBC 驱动） |
| test | ❌ | ✅ | ❌ | ❌ | 仅测试时使用 |
| system | ✅ | ✅ | ✅ | ❌ | 本地系统路径（不推荐） |
| import | - | - | - | - | 导入 BOM（仅在 dependencyManagement 中使用） |

```xml
<dependencies>
    <!-- compile（默认） -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    
    <!-- provided：编译需要，运行时由容器提供 -->
    <dependency>
        <groupId>javax.servlet</groupId>
        <artifactId>javax.servlet-api</artifactId>
        <version>4.0.1</version>
        <scope>provided</scope>
    </dependency>
    
    <!-- runtime：编译不需要，运行时需要 -->
    <dependency>
        <groupId>mysql</groupId>
        <artifactId>mysql-connector-java</artifactId>
        <version>8.0.33</version>
        <scope>runtime</scope>
    </dependency>
    
    <!-- test：仅测试使用 -->
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter</artifactId>
        <version>5.10.0</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

#### 排除依赖

当依赖传递引入了不需要的包时，可以排除：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <exclusions>
        <!-- 排除默认的 Tomcat，使用 Undertow -->
        <exclusion>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-tomcat</artifactId>
        </exclusion>
    </exclusions>
</dependency>

<!-- 使用 Undertow 替代 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-undertow</artifactId>
</dependency>
```

#### 依赖管理（BOM）

使用 `dependencyManagement` 统一管理版本：

```xml
<dependencyManagement>
    <dependencies>
        <!-- 导入 Spring Boot BOM -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>3.2.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
        
        <!-- 导入 Spring Cloud BOM -->
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>2023.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<!-- 使用时无需指定版本 -->
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <!-- 版本由 BOM 管理 -->
    </dependency>
</dependencies>
```

### 4.2 Gradle 依赖配置

#### 依赖配置类型

| Configuration | 说明 | 对应 Maven Scope |
|---------------|------|------------------|
| implementation | 编译和运行时依赖 | compile |
| api | 编译和运行时依赖（会传递） | compile |
| compileOnly | 仅编译时依赖 | provided |
| runtimeOnly | 仅运行时依赖 | runtime |
| testImplementation | 测试编译和运行时依赖 | test |
| testCompileOnly | 仅测试编译时依赖 | - |
| testRuntimeOnly | 仅测试运行时依赖 | - |
| annotationProcessor | 注解处理器 | - |

```groovy
dependencies {
    // 编译和运行时依赖
    implementation 'org.springframework.boot:spring-boot-starter-web'
    
    // 会传递给依赖此项目的其他项目
    api 'com.google.guava:guava:32.1.3-jre'
    
    // 仅编译时需要
    compileOnly 'org.projectlombok:lombok:1.18.30'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
    
    // 仅运行时需要
    runtimeOnly 'mysql:mysql-connector-java:8.0.33'
    
    // 测试依赖
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}
```

#### implementation vs api

```groovy
// 项目 A
dependencies {
    // 使用 implementation：Guava 不会传递给依赖 A 的项目
    implementation 'com.google.guava:guava:32.1.3-jre'
    
    // 使用 api：Guava 会传递给依赖 A 的项目
    api 'com.google.guava:guava:32.1.3-jre'
}

// 项目 B 依赖项目 A
dependencies {
    implementation project(':project-a')
    // 如果 A 使用 implementation，B 无法直接使用 Guava
    // 如果 A 使用 api，B 可以直接使用 Guava
}
```

> **最佳实践**：优先使用 `implementation`，只有当依赖需要暴露给消费者时才使用 `api`。

#### 排除依赖

```groovy
dependencies {
    implementation('org.springframework.boot:spring-boot-starter-web') {
        // 排除特定依赖
        exclude group: 'org.springframework.boot', module: 'spring-boot-starter-tomcat'
    }
    
    // 全局排除
    configurations.all {
        exclude group: 'commons-logging', module: 'commons-logging'
    }
}
```

#### 依赖版本管理（BOM）

```groovy
dependencies {
    // 导入 BOM
    implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.0')
    implementation platform('org.springframework.cloud:spring-cloud-dependencies:2023.0.0')
    
    // 使用时无需指定版本
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.cloud:spring-cloud-starter-netflix-eureka-client'
}
```

**Kotlin DSL**：
```kotlin
dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
    implementation("org.springframework.boot:spring-boot-starter-web")
}
```

#### 强制版本

```groovy
configurations.all {
    resolutionStrategy {
        // 强制使用特定版本
        force 'com.google.guava:guava:32.1.3-jre'
        
        // 版本冲突时失败
        failOnVersionConflict()
        
        // 缓存动态版本的时间
        cacheDynamicVersionsFor 10, 'minutes'
        
        // 缓存变化模块的时间
        cacheChangingModulesFor 0, 'seconds'
    }
}
```

### 4.3 查看依赖树

```bash
# Maven
mvn dependency:tree
mvn dependency:tree -Dincludes=com.google.guava  # 过滤特定依赖

# Gradle
./gradlew dependencies
./gradlew dependencies --configuration runtimeClasspath  # 指定配置
./gradlew dependencyInsight --dependency guava  # 查看特定依赖
```

---

## 5. 生命周期与任务

### 5.1 Maven 生命周期

Maven 有三个内置的生命周期：

#### Clean 生命周期
```
pre-clean → clean → post-clean
```

#### Default 生命周期（最常用）
```
validate → compile → test → package → verify → install → deploy
```

| 阶段 | 说明 |
|------|------|
| validate | 验证项目配置是否正确 |
| compile | 编译源代码 |
| test | 运行单元测试 |
| package | 打包（JAR/WAR） |
| verify | 运行集成测试 |
| install | 安装到本地仓库 |
| deploy | 部署到远程仓库 |

#### Site 生命周期
```
pre-site → site → post-site → site-deploy
```

**执行命令**：
```bash
# 执行到指定阶段（会执行之前的所有阶段）
mvn compile      # 编译
mvn test         # 编译 + 测试
mvn package      # 编译 + 测试 + 打包
mvn install      # 编译 + 测试 + 打包 + 安装到本地仓库
mvn deploy       # 完整流程 + 部署到远程仓库

# 跳过测试
mvn package -DskipTests           # 跳过测试执行
mvn package -Dmaven.test.skip=true  # 跳过测试编译和执行

# 清理并构建
mvn clean package

# 指定配置文件
mvn package -P production
```

### 5.2 Gradle 任务

Gradle 使用任务（Task）而非阶段，更加灵活：

#### 常用内置任务

```bash
# 查看所有任务
./gradlew tasks
./gradlew tasks --all  # 包括隐藏任务

# 常用任务
./gradlew build        # 编译 + 测试 + 打包
./gradlew clean        # 清理构建目录
./gradlew test         # 运行测试
./gradlew jar          # 打包 JAR
./gradlew bootJar      # Spring Boot 打包
./gradlew assemble     # 打包（不运行测试）
./gradlew check        # 运行所有检查（测试、代码检查等）

# 跳过测试
./gradlew build -x test

# 刷新依赖
./gradlew build --refresh-dependencies

# 查看任务依赖
./gradlew build --dry-run
```

#### 自定义任务

```groovy
// 简单任务
task hello {
    doLast {
        println 'Hello, Gradle!'
    }
}

// 带依赖的任务
task buildAll {
    dependsOn 'clean', 'build'
    doLast {
        println '构建完成！'
    }
}

// 复制任务
task copyDocs(type: Copy) {
    from 'src/docs'
    into 'build/docs'
    include '**/*.md'
}

// 删除任务
task cleanLogs(type: Delete) {
    delete fileTree('logs') {
        include '**/*.log'
    }
}

// 执行命令任务
task runScript(type: Exec) {
    workingDir 'scripts'
    commandLine 'bash', 'deploy.sh'
}
```

**Kotlin DSL**：
```kotlin
tasks.register("hello") {
    doLast {
        println("Hello, Gradle!")
    }
}

tasks.register<Copy>("copyDocs") {
    from("src/docs")
    into("build/docs")
    include("**/*.md")
}
```

#### 任务依赖与顺序

```groovy
task taskA {
    doLast { println 'Task A' }
}

task taskB {
    dependsOn taskA  // taskB 依赖 taskA
    doLast { println 'Task B' }
}

task taskC {
    mustRunAfter taskA  // 如果 taskA 执行，taskC 必须在其后
    doLast { println 'Task C' }
}

task taskD {
    shouldRunAfter taskA  // 软依赖，可能不遵守
    doLast { println 'Task D' }
}

task taskE {
    finalizedBy taskA  // taskE 执行后，taskA 一定执行
    doLast { println 'Task E' }
}
```

---

## 6. 插件系统

### 6.1 Maven 插件

#### 插件配置

```xml
<build>
    <plugins>
        <!-- 编译插件 -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <version>3.11.0</version>
            <configuration>
                <source>17</source>
                <target>17</target>
                <encoding>UTF-8</encoding>
                <compilerArgs>
                    <arg>-parameters</arg>
                </compilerArgs>
            </configuration>
        </plugin>
        
        <!-- 打包插件 -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-jar-plugin</artifactId>
            <version>3.3.0</version>
            <configuration>
                <archive>
                    <manifest>
                        <mainClass>com.example.Application</mainClass>
                        <addClasspath>true</addClasspath>
                    </manifest>
                </archive>
            </configuration>
        </plugin>
        
        <!-- 源码插件 -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-source-plugin</artifactId>
            <version>3.3.0</version>
            <executions>
                <execution>
                    <id>attach-sources</id>
                    <phase>verify</phase>
                    <goals>
                        <goal>jar-no-fork</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

#### 常用 Maven 插件

| 插件 | 用途 |
|------|------|
| maven-compiler-plugin | 编译 Java 代码 |
| maven-surefire-plugin | 运行单元测试 |
| maven-failsafe-plugin | 运行集成测试 |
| maven-jar-plugin | 打包 JAR |
| maven-war-plugin | 打包 WAR |
| maven-shade-plugin | 打包 Fat JAR（包含依赖） |
| maven-assembly-plugin | 自定义打包 |
| maven-source-plugin | 生成源码包 |
| maven-javadoc-plugin | 生成 Javadoc |
| maven-resources-plugin | 处理资源文件 |
| spring-boot-maven-plugin | Spring Boot 打包 |

#### 插件管理

```xml
<build>
    <!-- 统一管理插件版本 -->
    <pluginManagement>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
        </plugins>
    </pluginManagement>
    
    <!-- 实际使用插件 -->
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <!-- 版本由 pluginManagement 管理 -->
        </plugin>
    </plugins>
</build>
```

### 6.2 Gradle 插件

#### 应用插件

```groovy
plugins {
    // 核心插件（无需版本）
    id 'java'
    id 'java-library'
    id 'application'
    id 'war'
    
    // 社区插件（需要版本）
    id 'org.springframework.boot' version '3.2.0'
    id 'io.spring.dependency-management' version '1.1.4'
    id 'com.github.johnrengelman.shadow' version '8.1.1'
}

// 旧式写法（不推荐）
apply plugin: 'java'
```

**Kotlin DSL**：
```kotlin
plugins {
    java
    `java-library`
    application
    id("org.springframework.boot") version "3.2.0"
}
```

#### 常用 Gradle 插件

| 插件 | 用途 |
|------|------|
| java | Java 项目支持 |
| java-library | Java 库项目（支持 api 配置） |
| application | 可执行应用 |
| war | WAR 打包 |
| org.springframework.boot | Spring Boot 支持 |
| io.spring.dependency-management | 依赖版本管理 |
| com.github.johnrengelman.shadow | Fat JAR 打包 |
| jacoco | 代码覆盖率 |
| checkstyle | 代码风格检查 |
| pmd | 代码质量检查 |
| spotbugs | Bug 检测 |

#### 插件配置

```groovy
plugins {
    id 'java'
    id 'application'
    id 'jacoco'
}

// 配置 application 插件
application {
    mainClass = 'com.example.Application'
}

// 配置 jacoco 插件
jacoco {
    toolVersion = '0.8.11'
}

jacocoTestReport {
    reports {
        xml.required = true
        html.required = true
    }
}

// 配置 Java 编译
tasks.withType(JavaCompile) {
    options.encoding = 'UTF-8'
    options.compilerArgs << '-parameters'
}
```

---

## 7. 多模块项目

### 7.1 Maven 多模块

#### 项目结构

```
parent-project/
├── pom.xml                    # 父 POM
├── module-api/
│   ├── pom.xml
│   └── src/
├── module-service/
│   ├── pom.xml
│   └── src/
└── module-web/
    ├── pom.xml
    └── src/
```

#### 父 POM

```xml
<!-- parent-project/pom.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>parent-project</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>pom</packaging>  <!-- 父项目必须是 pom 类型 -->
    
    <!-- 子模块列表 -->
    <modules>
        <module>module-api</module>
        <module>module-service</module>
        <module>module-web</module>
    </modules>
    
    <!-- 统一属性 -->
    <properties>
        <java.version>17</java.version>
        <maven.compiler.source>${java.version}</maven.compiler.source>
        <maven.compiler.target>${java.version}</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <spring-boot.version>3.2.0</spring-boot.version>
    </properties>
    
    <!-- 统一依赖版本管理 -->
    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-dependencies</artifactId>
                <version>${spring-boot.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
            
            <!-- 内部模块版本 -->
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>module-api</artifactId>
                <version>${project.version}</version>
            </dependency>
            <dependency>
                <groupId>com.example</groupId>
                <artifactId>module-service</artifactId>
                <version>${project.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>
    
    <!-- 所有子模块共享的依赖 -->
    <dependencies>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <scope>provided</scope>
        </dependency>
    </dependencies>
    
    <!-- 统一插件管理 -->
    <build>
        <pluginManagement>
            <plugins>
                <plugin>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-maven-plugin</artifactId>
                    <version>${spring-boot.version}</version>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>
</project>
```

#### 子模块 POM

```xml
<!-- module-api/pom.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    
    <modelVersion>4.0.0</modelVersion>
    
    <!-- 继承父 POM -->
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent-project</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </parent>
    
    <artifactId>module-api</artifactId>
    <packaging>jar</packaging>
    
    <dependencies>
        <!-- 无需指定版本，由父 POM 管理 -->
        <dependency>
            <groupId>jakarta.validation</groupId>
            <artifactId>jakarta.validation-api</artifactId>
        </dependency>
    </dependencies>
</project>
```

```xml
<!-- module-service/pom.xml -->
<project>
    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent-project</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </parent>
    
    <artifactId>module-service</artifactId>
    
    <dependencies>
        <!-- 依赖内部模块 -->
        <dependency>
            <groupId>com.example</groupId>
            <artifactId>module-api</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
    </dependencies>
</project>
```

#### 多模块构建命令

```bash
# 构建所有模块
mvn clean install

# 只构建指定模块
mvn clean install -pl module-api

# 构建指定模块及其依赖
mvn clean install -pl module-web -am

# 构建指定模块及依赖它的模块
mvn clean install -pl module-api -amd

# 跳过测试
mvn clean install -DskipTests
```

### 7.2 Gradle 多模块

#### 项目结构

```
parent-project/
├── build.gradle               # 根构建脚本
├── settings.gradle            # 项目设置
├── gradle.properties
├── module-api/
│   ├── build.gradle
│   └── src/
├── module-service/
│   ├── build.gradle
│   └── src/
└── module-web/
    ├── build.gradle
    └── src/
```

#### settings.gradle

```groovy
// settings.gradle
rootProject.name = 'parent-project'

include 'module-api'
include 'module-service'
include 'module-web'
```

#### 根 build.gradle

```groovy
// build.gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0' apply false
    id 'io.spring.dependency-management' version '1.1.4' apply false
}

// 所有项目（包括根项目）的配置
allprojects {
    group = 'com.example'
    version = '1.0.0-SNAPSHOT'
    
    repositories {
        mavenCentral()
        maven { url 'https://maven.aliyun.com/repository/public' }
    }
}

// 所有子项目的配置
subprojects {
    apply plugin: 'java'
    apply plugin: 'io.spring.dependency-management'
    
    java {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    
    dependencyManagement {
        imports {
            mavenBom 'org.springframework.boot:spring-boot-dependencies:3.2.0'
        }
    }
    
    dependencies {
        compileOnly 'org.projectlombok:lombok'
        annotationProcessor 'org.projectlombok:lombok'
        
        testImplementation 'org.junit.jupiter:junit-jupiter'
    }
    
    tasks.withType(JavaCompile) {
        options.encoding = 'UTF-8'
    }
    
    test {
        useJUnitPlatform()
    }
}
```

#### 子模块 build.gradle

```groovy
// module-api/build.gradle
plugins {
    id 'java-library'  // 使用 java-library 以支持 api 配置
}

dependencies {
    api 'jakarta.validation:jakarta.validation-api'
}
```

```groovy
// module-service/build.gradle
dependencies {
    implementation project(':module-api')
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    
    runtimeOnly 'mysql:mysql-connector-java'
}
```

```groovy
// module-web/build.gradle
plugins {
    id 'org.springframework.boot'
}

dependencies {
    implementation project(':module-api')
    implementation project(':module-service')
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
```

#### 多模块构建命令

```bash
# 构建所有模块
./gradlew build

# 只构建指定模块
./gradlew :module-api:build

# 清理并构建
./gradlew clean build

# 跳过测试
./gradlew build -x test

# 查看项目结构
./gradlew projects
```

---

## 8. 仓库管理

### 8.1 Maven 仓库

#### 仓库类型

- **本地仓库**：`~/.m2/repository`，缓存下载的依赖
- **中央仓库**：`https://repo.maven.apache.org/maven2`，Maven 官方仓库
- **远程仓库**：公司私有仓库或第三方仓库

#### 配置仓库

```xml
<!-- pom.xml -->
<repositories>
    <!-- 阿里云镜像 -->
    <repository>
        <id>aliyun</id>
        <name>阿里云公共仓库</name>
        <url>https://maven.aliyun.com/repository/public</url>
        <releases>
            <enabled>true</enabled>
        </releases>
        <snapshots>
            <enabled>true</enabled>
            <updatePolicy>always</updatePolicy>
        </snapshots>
    </repository>
    
    <!-- 私有仓库 -->
    <repository>
        <id>nexus-releases</id>
        <url>https://nexus.company.com/repository/maven-releases/</url>
    </repository>
</repositories>

<!-- 插件仓库 -->
<pluginRepositories>
    <pluginRepository>
        <id>aliyun-plugin</id>
        <url>https://maven.aliyun.com/repository/public</url>
    </pluginRepository>
</pluginRepositories>
```

#### 配置镜像（settings.xml）

```xml
<!-- ~/.m2/settings.xml -->
<mirrors>
    <!-- 阿里云镜像（推荐） -->
    <mirror>
        <id>aliyun</id>
        <name>阿里云公共仓库</name>
        <url>https://maven.aliyun.com/repository/public</url>
        <mirrorOf>central</mirrorOf>
    </mirror>
    
    <!-- 镜像所有仓库 -->
    <mirror>
        <id>nexus</id>
        <url>https://nexus.company.com/repository/maven-public/</url>
        <mirrorOf>*</mirrorOf>
    </mirror>
    
    <!-- 镜像除了指定仓库外的所有仓库 -->
    <mirror>
        <id>nexus-partial</id>
        <url>https://nexus.company.com/repository/maven-public/</url>
        <mirrorOf>*,!custom-repo</mirrorOf>
    </mirror>
</mirrors>
```

### 8.2 Gradle 仓库

```groovy
repositories {
    // Maven 中央仓库
    mavenCentral()
    
    // Google 仓库（Android 开发）
    google()
    
    // Gradle 插件仓库
    gradlePluginPortal()
    
    // 阿里云镜像
    maven {
        url 'https://maven.aliyun.com/repository/public'
    }
    
    // 私有仓库（带认证）
    maven {
        url 'https://nexus.company.com/repository/maven-releases/'
        credentials {
            username = project.findProperty('nexusUsername') ?: ''
            password = project.findProperty('nexusPassword') ?: ''
        }
    }
    
    // 本地 Maven 仓库
    mavenLocal()
    
    // 本地目录
    flatDir {
        dirs 'libs'
    }
}
```

**Kotlin DSL**：
```kotlin
repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.aliyun.com/repository/public")
    }
    maven {
        url = uri("https://nexus.company.com/repository/maven-releases/")
        credentials {
            username = project.findProperty("nexusUsername") as String? ?: ""
            password = project.findProperty("nexusPassword") as String? ?: ""
        }
    }
}
```

### 8.3 发布到仓库

#### Maven 发布

```xml
<!-- pom.xml -->
<distributionManagement>
    <repository>
        <id>nexus-releases</id>
        <url>https://nexus.company.com/repository/maven-releases/</url>
    </repository>
    <snapshotRepository>
        <id>nexus-snapshots</id>
        <url>https://nexus.company.com/repository/maven-snapshots/</url>
    </snapshotRepository>
</distributionManagement>
```

```bash
# 发布到仓库
mvn deploy

# 发布到本地仓库
mvn install
```

#### Gradle 发布

```groovy
plugins {
    id 'maven-publish'
}

publishing {
    publications {
        maven(MavenPublication) {
            from components.java
            
            // 自定义 POM
            pom {
                name = 'My Library'
                description = 'A library for...'
                url = 'https://github.com/example/my-library'
                
                licenses {
                    license {
                        name = 'The Apache License, Version 2.0'
                        url = 'http://www.apache.org/licenses/LICENSE-2.0.txt'
                    }
                }
                
                developers {
                    developer {
                        id = 'developer'
                        name = 'Developer Name'
                        email = 'dev@example.com'
                    }
                }
            }
        }
    }
    
    repositories {
        maven {
            def releasesUrl = 'https://nexus.company.com/repository/maven-releases/'
            def snapshotsUrl = 'https://nexus.company.com/repository/maven-snapshots/'
            url = version.endsWith('SNAPSHOT') ? snapshotsUrl : releasesUrl
            
            credentials {
                username = project.findProperty('nexusUsername')
                password = project.findProperty('nexusPassword')
            }
        }
    }
}
```

```bash
# 发布
./gradlew publish

# 发布到本地 Maven 仓库
./gradlew publishToMavenLocal
```

---

## 9. 构建配置

### 9.1 Maven Profiles

Profiles 用于在不同环境下使用不同的配置：

```xml
<profiles>
    <!-- 开发环境 -->
    <profile>
        <id>dev</id>
        <activation>
            <activeByDefault>true</activeByDefault>
        </activation>
        <properties>
            <env>dev</env>
            <db.url>jdbc:mysql://localhost:3306/dev_db</db.url>
        </properties>
    </profile>
    
    <!-- 测试环境 -->
    <profile>
        <id>test</id>
        <properties>
            <env>test</env>
            <db.url>jdbc:mysql://test-server:3306/test_db</db.url>
        </properties>
    </profile>
    
    <!-- 生产环境 -->
    <profile>
        <id>prod</id>
        <properties>
            <env>prod</env>
            <db.url>jdbc:mysql://prod-server:3306/prod_db</db.url>
        </properties>
        <build>
            <plugins>
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <configuration>
                        <debug>false</debug>
                        <optimize>true</optimize>
                    </configuration>
                </plugin>
            </plugins>
        </build>
    </profile>
    
    <!-- 条件激活 -->
    <profile>
        <id>jdk17</id>
        <activation>
            <jdk>17</jdk>
        </activation>
    </profile>
    
    <profile>
        <id>windows</id>
        <activation>
            <os>
                <family>windows</family>
            </os>
        </activation>
    </profile>
</profiles>
```

```bash
# 使用指定 Profile
mvn package -P prod

# 使用多个 Profile
mvn package -P prod,jdk17

# 查看激活的 Profile
mvn help:active-profiles
```

#### 资源过滤

```xml
<build>
    <resources>
        <resource>
            <directory>src/main/resources</directory>
            <filtering>true</filtering>  <!-- 启用变量替换 -->
            <includes>
                <include>**/*.properties</include>
                <include>**/*.yml</include>
            </includes>
        </resource>
        <resource>
            <directory>src/main/resources</directory>
            <filtering>false</filtering>
            <excludes>
                <exclude>**/*.properties</exclude>
                <exclude>**/*.yml</exclude>
            </excludes>
        </resource>
    </resources>
</build>
```

```properties
# application.properties
spring.datasource.url=${db.url}
app.env=${env}
```

### 9.2 Gradle 构建变体

```groovy
// 定义环境配置
ext {
    profiles = [
        dev: [
            'db.url': 'jdbc:mysql://localhost:3306/dev_db',
            'log.level': 'DEBUG'
        ],
        test: [
            'db.url': 'jdbc:mysql://test-server:3306/test_db',
            'log.level': 'INFO'
        ],
        prod: [
            'db.url': 'jdbc:mysql://prod-server:3306/prod_db',
            'log.level': 'WARN'
        ]
    ]
}

// 获取当前环境
def env = project.hasProperty('env') ? project.env : 'dev'
def profile = profiles[env]

// 资源处理
processResources {
    filesMatching('**/*.properties') {
        expand(profile)
    }
    filesMatching('**/*.yml') {
        expand(profile)
    }
}

// 根据环境配置不同的依赖
if (env == 'dev') {
    dependencies {
        implementation 'com.h2database:h2'
    }
} else {
    dependencies {
        runtimeOnly 'mysql:mysql-connector-java'
    }
}
```

```bash
# 使用指定环境
./gradlew build -Penv=prod
```

### 9.3 属性与变量

#### Maven 属性

```xml
<properties>
    <!-- 自定义属性 -->
    <spring-boot.version>3.2.0</spring-boot.version>
    
    <!-- 内置属性 -->
    <!-- ${project.basedir} - 项目根目录 -->
    <!-- ${project.version} - 项目版本 -->
    <!-- ${project.artifactId} - 项目名称 -->
    <!-- ${maven.build.timestamp} - 构建时间 -->
</properties>

<!-- 使用属性 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId>
    <version>${spring-boot.version}</version>
</dependency>
```

#### Gradle 属性

```groovy
// gradle.properties
springBootVersion=3.2.0
myProperty=value

// build.gradle
plugins {
    id 'org.springframework.boot' version "${springBootVersion}"
}

// 使用属性
println project.springBootVersion
println project.findProperty('myProperty') ?: 'default'

// 系统属性
println System.getProperty('java.version')

// 环境变量
println System.getenv('JAVA_HOME')
```

---

## 10. 测试集成

### 10.1 Maven 测试配置

```xml
<build>
    <plugins>
        <!-- 单元测试插件 -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.2.2</version>
            <configuration>
                <!-- 并行执行 -->
                <parallel>methods</parallel>
                <threadCount>4</threadCount>
                
                <!-- 包含/排除测试 -->
                <includes>
                    <include>**/*Test.java</include>
                    <include>**/*Tests.java</include>
                </includes>
                <excludes>
                    <exclude>**/*IntegrationTest.java</exclude>
                </excludes>
                
                <!-- 系统属性 -->
                <systemPropertyVariables>
                    <spring.profiles.active>test</spring.profiles.active>
                </systemPropertyVariables>
            </configuration>
        </plugin>
        
        <!-- 集成测试插件 -->
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-failsafe-plugin</artifactId>
            <version>3.2.2</version>
            <executions>
                <execution>
                    <goals>
                        <goal>integration-test</goal>
                        <goal>verify</goal>
                    </goals>
                </execution>
            </executions>
            <configuration>
                <includes>
                    <include>**/*IntegrationTest.java</include>
                    <include>**/*IT.java</include>
                </includes>
            </configuration>
        </plugin>
        
        <!-- 代码覆盖率 -->
        <plugin>
            <groupId>org.jacoco</groupId>
            <artifactId>jacoco-maven-plugin</artifactId>
            <version>0.8.11</version>
            <executions>
                <execution>
                    <goals>
                        <goal>prepare-agent</goal>
                    </goals>
                </execution>
                <execution>
                    <id>report</id>
                    <phase>test</phase>
                    <goals>
                        <goal>report</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

```bash
# 运行测试
mvn test

# 运行集成测试
mvn verify

# 跳过测试
mvn package -DskipTests

# 运行指定测试类
mvn test -Dtest=UserServiceTest

# 运行指定测试方法
mvn test -Dtest=UserServiceTest#testCreate

# 生成覆盖率报告
mvn test jacoco:report
```

### 10.2 Gradle 测试配置

```groovy
plugins {
    id 'java'
    id 'jacoco'
}

dependencies {
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
    testImplementation 'org.mockito:mockito-core:5.7.0'
    testImplementation 'org.assertj:assertj-core:3.24.2'
}

test {
    useJUnitPlatform()
    
    // 并行执行
    maxParallelForks = Runtime.runtime.availableProcessors()
    
    // 测试过滤
    filter {
        includeTestsMatching '*Test'
        excludeTestsMatching '*IntegrationTest'
    }
    
    // 系统属性
    systemProperty 'spring.profiles.active', 'test'
    
    // 测试日志
    testLogging {
        events 'passed', 'skipped', 'failed'
        showStandardStreams = true
        exceptionFormat = 'full'
    }
    
    // 失败后继续
    ignoreFailures = false
    
    // 测试报告
    reports {
        html.required = true
        junitXml.required = true
    }
    
    // JaCoCo 集成
    finalizedBy jacocoTestReport
}

// 集成测试配置
sourceSets {
    integrationTest {
        java.srcDir 'src/integrationTest/java'
        resources.srcDir 'src/integrationTest/resources'
        compileClasspath += sourceSets.main.output + sourceSets.test.output
        runtimeClasspath += sourceSets.main.output + sourceSets.test.output
    }
}

configurations {
    integrationTestImplementation.extendsFrom testImplementation
    integrationTestRuntimeOnly.extendsFrom testRuntimeOnly
}

task integrationTest(type: Test) {
    description = '运行集成测试'
    group = 'verification'
    
    testClassesDirs = sourceSets.integrationTest.output.classesDirs
    classpath = sourceSets.integrationTest.runtimeClasspath
    
    useJUnitPlatform()
    
    shouldRunAfter test
}

check.dependsOn integrationTest

// JaCoCo 配置
jacoco {
    toolVersion = '0.8.11'
}

jacocoTestReport {
    dependsOn test
    
    reports {
        xml.required = true
        html.required = true
        csv.required = false
    }
    
    // 排除特定类
    afterEvaluate {
        classDirectories.setFrom(files(classDirectories.files.collect {
            fileTree(dir: it, exclude: [
                '**/config/**',
                '**/dto/**',
                '**/*Application*'
            ])
        }))
    }
}

// 覆盖率检查
jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                minimum = 0.8  // 80% 覆盖率
            }
        }
    }
}
```

```bash
# 运行测试
./gradlew test

# 运行集成测试
./gradlew integrationTest

# 跳过测试
./gradlew build -x test

# 运行指定测试
./gradlew test --tests "UserServiceTest"
./gradlew test --tests "*ServiceTest"

# 生成覆盖率报告
./gradlew jacocoTestReport

# 检查覆盖率
./gradlew jacocoTestCoverageVerification
```

---

## 11. 打包与发布

### 11.1 Maven 打包

#### 普通 JAR

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-jar-plugin</artifactId>
    <version>3.3.0</version>
    <configuration>
        <archive>
            <manifest>
                <mainClass>com.example.Application</mainClass>
                <addClasspath>true</addClasspath>
                <classpathPrefix>lib/</classpathPrefix>
            </manifest>
            <manifestEntries>
                <Built-By>${user.name}</Built-By>
                <Build-Time>${maven.build.timestamp}</Build-Time>
            </manifestEntries>
        </archive>
    </configuration>
</plugin>
```

#### Fat JAR（包含所有依赖）

**使用 maven-shade-plugin**：
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-shade-plugin</artifactId>
    <version>3.5.1</version>
    <executions>
        <execution>
            <phase>package</phase>
            <goals>
                <goal>shade</goal>
            </goals>
            <configuration>
                <transformers>
                    <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                        <mainClass>com.example.Application</mainClass>
                    </transformer>
                    <!-- 合并 Spring 配置文件 -->
                    <transformer implementation="org.apache.maven.plugins.shade.resource.AppendingTransformer">
                        <resource>META-INF/spring.handlers</resource>
                    </transformer>
                    <transformer implementation="org.apache.maven.plugins.shade.resource.AppendingTransformer">
                        <resource>META-INF/spring.schemas</resource>
                    </transformer>
                </transformers>
                <filters>
                    <filter>
                        <artifact>*:*</artifact>
                        <excludes>
                            <exclude>META-INF/*.SF</exclude>
                            <exclude>META-INF/*.DSA</exclude>
                            <exclude>META-INF/*.RSA</exclude>
                        </excludes>
                    </filter>
                </filters>
            </configuration>
        </execution>
    </executions>
</plugin>
```

**使用 Spring Boot 插件**：
```xml
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <version>3.2.0</version>
    <executions>
        <execution>
            <goals>
                <goal>repackage</goal>
            </goals>
        </execution>
    </executions>
    <configuration>
        <mainClass>com.example.Application</mainClass>
        <layers>
            <enabled>true</enabled>  <!-- 启用分层打包，优化 Docker 镜像 -->
        </layers>
    </configuration>
</plugin>
```

#### WAR 打包

```xml
<packaging>war</packaging>

<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-war-plugin</artifactId>
    <version>3.4.0</version>
    <configuration>
        <failOnMissingWebXml>false</failOnMissingWebXml>
        <webResources>
            <resource>
                <directory>src/main/webapp</directory>
                <filtering>true</filtering>
            </resource>
        </webResources>
    </configuration>
</plugin>
```

### 11.2 Gradle 打包

#### 普通 JAR

```groovy
jar {
    manifest {
        attributes(
            'Main-Class': 'com.example.Application',
            'Implementation-Title': project.name,
            'Implementation-Version': project.version,
            'Built-By': System.getProperty('user.name'),
            'Build-Time': new Date().format("yyyy-MM-dd'T'HH:mm:ssZ")
        )
    }
}
```

#### Fat JAR（Shadow 插件）

```groovy
plugins {
    id 'com.github.johnrengelman.shadow' version '8.1.1'
}

shadowJar {
    archiveBaseName.set('my-app')
    archiveClassifier.set('')
    archiveVersion.set('')
    
    manifest {
        attributes 'Main-Class': 'com.example.Application'
    }
    
    // 合并服务文件
    mergeServiceFiles()
    
    // 排除签名文件
    exclude 'META-INF/*.SF'
    exclude 'META-INF/*.DSA'
    exclude 'META-INF/*.RSA'
    
    // 重定位包（避免冲突）
    relocate 'com.google', 'shadow.com.google'
}
```

#### Spring Boot 打包

```groovy
plugins {
    id 'org.springframework.boot' version '3.2.0'
}

bootJar {
    archiveBaseName.set('my-app')
    archiveVersion.set('1.0.0')
    
    manifest {
        attributes 'Start-Class': 'com.example.Application'
    }
    
    // 启用分层打包
    layered {
        enabled = true
    }
}

// 禁用普通 jar 任务
jar {
    enabled = false
}
```

```bash
# 打包
./gradlew bootJar

# 运行
java -jar build/libs/my-app-1.0.0.jar
```

---

## 12. 性能优化

### 12.1 Maven 性能优化

```bash
# 并行构建
mvn -T 4 clean install        # 使用 4 个线程
mvn -T 1C clean install       # 每个 CPU 核心 1 个线程

# 离线模式（不检查远程仓库）
mvn -o package

# 跳过测试
mvn package -DskipTests

# 只构建变更的模块
mvn install -pl module-changed -am

# 增量编译
mvn compiler:compile
```

#### Maven Daemon（mvnd）

mvnd 是 Maven 的守护进程版本，显著提升构建速度：

```bash
# 安装 mvnd
# Windows (Chocolatey)
choco install mvndaemon

# macOS
brew install mvndaemon

# 使用 mvnd
mvnd clean install
```

### 12.2 Gradle 性能优化

```properties
# gradle.properties

# 增加 JVM 内存
org.gradle.jvmargs=-Xmx4096m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8

# 启用守护进程（默认开启）
org.gradle.daemon=true

# 启用并行构建
org.gradle.parallel=true

# 启用构建缓存
org.gradle.caching=true

# 启用配置缓存（Gradle 7.0+）
org.gradle.configuration-cache=true

# 按需配置（只配置需要的项目）
org.gradle.configureondemand=true

# 文件系统监视（增量构建）
org.gradle.vfs.watch=true
```

#### 构建扫描

```bash
# 生成构建扫描报告
./gradlew build --scan

# 查看构建性能
./gradlew build --profile
```

#### 依赖缓存

```groovy
configurations.all {
    resolutionStrategy {
        // 缓存动态版本 24 小时
        cacheDynamicVersionsFor 24, 'hours'
        
        // 缓存变化模块 0 秒（SNAPSHOT）
        cacheChangingModulesFor 0, 'seconds'
    }
}
```

### 12.3 CI/CD 优化

```yaml
# GitHub Actions 示例
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # 缓存 Maven 依赖
      - name: Cache Maven packages
        uses: actions/cache@v3
        with:
          path: ~/.m2/repository
          key: ${{ runner.os }}-maven-${{ hashFiles('**/pom.xml') }}
          restore-keys: |
            ${{ runner.os }}-maven-
      
      # 缓存 Gradle 依赖
      - name: Cache Gradle packages
        uses: actions/cache@v3
        with:
          path: |
            ~/.gradle/caches
            ~/.gradle/wrapper
          key: ${{ runner.os }}-gradle-${{ hashFiles('**/*.gradle*', '**/gradle-wrapper.properties') }}
          restore-keys: |
            ${{ runner.os }}-gradle-
      
      - name: Build with Maven
        run: mvn -B package --file pom.xml
      
      # 或 Gradle
      - name: Build with Gradle
        run: ./gradlew build --no-daemon
```

---

## 13. CI/CD 集成

### 13.1 GitHub Actions

#### Maven 项目

```yaml
# .github/workflows/maven.yml
name: Maven CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up JDK 17
      uses: actions/setup-java@v4
      with:
        java-version: '17'
        distribution: 'temurin'
        cache: maven
    
    - name: Build with Maven
      run: mvn -B verify --file pom.xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: target/site/jacoco/jacoco.xml
    
    - name: Upload artifact
      uses: actions/upload-artifact@v3
      with:
        name: package
        path: target/*.jar
```

#### Gradle 项目

```yaml
# .github/workflows/gradle.yml
name: Gradle CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up JDK 17
      uses: actions/setup-java@v4
      with:
        java-version: '17'
        distribution: 'temurin'
        cache: gradle
    
    - name: Grant execute permission for gradlew
      run: chmod +x gradlew
    
    - name: Build with Gradle
      run: ./gradlew build
    
    - name: Upload test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results
        path: build/reports/tests/
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: build/reports/jacoco/test/jacocoTestReport.xml
```

### 13.2 Jenkins Pipeline

```groovy
// Jenkinsfile (Maven)
pipeline {
    agent any
    
    tools {
        maven 'Maven-3.9'
        jdk 'JDK-17'
    }
    
    environment {
        MAVEN_OPTS = '-Xmx1024m'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build') {
            steps {
                sh 'mvn clean compile'
            }
        }
        
        stage('Test') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit 'target/surefire-reports/*.xml'
                    jacoco execPattern: 'target/jacoco.exec'
                }
            }
        }
        
        stage('Package') {
            steps {
                sh 'mvn package -DskipTests'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'mvn deploy -DskipTests'
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            archiveArtifacts artifacts: 'target/*.jar', fingerprint: true
        }
    }
}
```

```groovy
// Jenkinsfile (Gradle)
pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                sh './gradlew clean build'
            }
        }
        
        stage('Test') {
            steps {
                sh './gradlew test'
            }
            post {
                always {
                    junit 'build/test-results/test/*.xml'
                }
            }
        }
        
        stage('Publish') {
            when {
                branch 'main'
            }
            steps {
                sh './gradlew publish'
            }
        }
    }
}
```

### 13.3 Docker 集成

#### Maven Dockerfile

```dockerfile
# 多阶段构建
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app
COPY pom.xml .
# 先下载依赖（利用缓存）
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -DskipTests

# 运行阶段
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

#### Gradle Dockerfile

```dockerfile
# 多阶段构建
FROM gradle:8.5-jdk17 AS builder
WORKDIR /app
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
# 先下载依赖
RUN gradle dependencies --no-daemon
COPY src ./src
RUN gradle bootJar --no-daemon

# 运行阶段
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

#### Spring Boot 分层打包

```dockerfile
# 利用 Spring Boot 分层打包优化 Docker 镜像
FROM eclipse-temurin:17-jre-alpine AS builder
WORKDIR /app
COPY target/*.jar app.jar
RUN java -Djarmode=layertools -jar app.jar extract

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/dependencies/ ./
COPY --from=builder /app/spring-boot-loader/ ./
COPY --from=builder /app/snapshot-dependencies/ ./
COPY --from=builder /app/application/ ./
ENTRYPOINT ["java", "org.springframework.boot.loader.JarLauncher"]
```

---

## 14. Maven 与 Gradle 对比

### 14.1 配置对比

**依赖声明**：

```xml
<!-- Maven -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>3.2.0</version>
</dependency>
```

```groovy
// Gradle
implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
```

**插件配置**：

```xml
<!-- Maven -->
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <version>3.11.0</version>
    <configuration>
        <source>17</source>
        <target>17</target>
    </configuration>
</plugin>
```

```groovy
// Gradle
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
```

### 14.2 综合对比

| 特性 | Maven | Gradle |
|------|-------|--------|
| 配置语言 | XML | Groovy/Kotlin DSL |
| 配置简洁度 | 冗长 | 简洁 |
| 学习曲线 | 平缓 | 较陡 |
| 构建速度 | 较慢 | 快（增量构建、缓存） |
| 灵活性 | 较低 | 高 |
| IDE 支持 | 优秀 | 优秀 |
| 文档 | 丰富 | 较好 |
| 社区 | 成熟 | 活跃 |
| 适用场景 | 传统企业项目 | 大型项目、Android |

### 14.3 选型建议

**选择 Maven**：
- 团队熟悉 Maven
- 项目结构简单标准
- 需要稳定性和广泛兼容性
- 企业级项目，需要严格的构建流程

**选择 Gradle**：
- Android 开发（官方推荐）
- 大型多模块项目
- 需要高度自定义构建逻辑
- 追求构建速度
- 新项目，团队愿意学习

### 14.4 迁移指南

#### Maven 迁移到 Gradle

```bash
# 自动生成 build.gradle
gradle init --type pom
```

生成的 `build.gradle` 需要手动调整和优化。

---

## 15. 常见错误与解决方案

### 15.1 依赖下载失败

**错误信息**：
```
Could not resolve dependencies for project
Could not transfer artifact
Connection timed out
```

**解决方案**：

```bash
# 1. 检查网络连接

# 2. 配置镜像源
# Maven: ~/.m2/settings.xml
<mirrors>
    <mirror>
        <id>aliyun</id>
        <url>https://maven.aliyun.com/repository/public</url>
        <mirrorOf>central</mirrorOf>
    </mirror>
</mirrors>

# Gradle: build.gradle
repositories {
    maven { url 'https://maven.aliyun.com/repository/public' }
    mavenCentral()
}

# 3. 清理缓存重试
# Maven
mvn dependency:purge-local-repository
rm -rf ~/.m2/repository/com/example/problematic-artifact

# Gradle
./gradlew --refresh-dependencies
rm -rf ~/.gradle/caches

# 4. 检查代理设置
# Maven: settings.xml
<proxies>
    <proxy>
        <id>my-proxy</id>
        <active>true</active>
        <protocol>http</protocol>
        <host>proxy.company.com</host>
        <port>8080</port>
    </proxy>
</proxies>

# Gradle: gradle.properties
systemProp.http.proxyHost=proxy.company.com
systemProp.http.proxyPort=8080
```

### 15.2 版本冲突

**错误信息**：
```
Duplicate class found
NoSuchMethodError
ClassNotFoundException (运行时)
```

**解决方案**：

```bash
# 1. 查看依赖树
mvn dependency:tree
./gradlew dependencies

# 2. 查找冲突
mvn dependency:tree -Dincludes=com.google.guava
./gradlew dependencyInsight --dependency guava
```

```xml
<!-- Maven: 排除冲突依赖 -->
<dependency>
    <groupId>com.example</groupId>
    <artifactId>library</artifactId>
    <exclusions>
        <exclusion>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
        </exclusion>
    </exclusions>
</dependency>

<!-- 强制使用特定版本 -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>32.1.3-jre</version>
        </dependency>
    </dependencies>
</dependencyManagement>
```

```groovy
// Gradle: 排除依赖
implementation('com.example:library') {
    exclude group: 'com.google.guava', module: 'guava'
}

// 强制版本
configurations.all {
    resolutionStrategy {
        force 'com.google.guava:guava:32.1.3-jre'
    }
}
```

### 15.3 编译错误

**错误信息**：
```
source release 17 requires target release 17
invalid source release: 17
```

**解决方案**：

```xml
<!-- Maven: 确保编译器配置正确 -->
<properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
</properties>

<!-- 或使用插件配置 -->
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <version>3.11.0</version>
    <configuration>
        <release>17</release>
    </configuration>
</plugin>
```

```groovy
// Gradle
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

// 或
tasks.withType(JavaCompile) {
    options.release = 17
}
```

```bash
# 检查 JAVA_HOME
echo $JAVA_HOME
java -version

# 确保使用正确的 JDK
export JAVA_HOME=/path/to/jdk-17
```

### 15.4 内存不足

**错误信息**：
```
OutOfMemoryError: Java heap space
GC overhead limit exceeded
```

**解决方案**：

```bash
# Maven
export MAVEN_OPTS="-Xmx2048m -XX:MaxMetaspaceSize=512m"

# 或在 .mvn/jvm.config 中配置
-Xmx2048m
-XX:MaxMetaspaceSize=512m
```

```properties
# Gradle: gradle.properties
org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=1024m -XX:+HeapDumpOnOutOfMemoryError
```

### 15.5 插件找不到

**错误信息**：
```
Plugin not found: org.springframework.boot:spring-boot-maven-plugin
No matching plugin found
```

**解决方案**：

```xml
<!-- Maven: 确保插件版本正确 -->
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <version>3.2.0</version>  <!-- 明确指定版本 -->
</plugin>

<!-- 配置插件仓库 -->
<pluginRepositories>
    <pluginRepository>
        <id>central</id>
        <url>https://maven.aliyun.com/repository/public</url>
    </pluginRepository>
</pluginRepositories>
```

```groovy
// Gradle: settings.gradle
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        maven { url 'https://maven.aliyun.com/repository/public' }
    }
}
```

### 15.6 测试失败导致构建中断

**解决方案**：

```bash
# Maven: 跳过测试
mvn package -DskipTests           # 跳过测试执行
mvn package -Dmaven.test.skip=true  # 跳过测试编译和执行

# 测试失败继续构建
mvn package -Dmaven.test.failure.ignore=true

# Gradle: 跳过测试
./gradlew build -x test

# 测试失败继续构建
./gradlew build --continue
```

```groovy
// Gradle: 配置测试失败不中断
test {
    ignoreFailures = true
}
```

### 15.7 SNAPSHOT 版本不更新

**问题描述**：依赖的 SNAPSHOT 版本没有更新到最新

**解决方案**：

```bash
# Maven: 强制更新 SNAPSHOT
mvn clean install -U

# Gradle: 刷新依赖
./gradlew build --refresh-dependencies
```

```groovy
// Gradle: 配置 SNAPSHOT 缓存时间
configurations.all {
    resolutionStrategy {
        cacheChangingModulesFor 0, 'seconds'
    }
}
```

### 15.8 多模块构建顺序错误

**错误信息**：
```
Could not find artifact com.example:module-api
```

**解决方案**：

```bash
# Maven: 先安装依赖模块
mvn install -pl module-api
mvn install -pl module-service -am  # -am 表示同时构建依赖模块

# Gradle: 确保依赖声明正确
dependencies {
    implementation project(':module-api')
}
```

### 15.9 Gradle Wrapper 版本问题

**错误信息**：
```
Could not open cp_settings remapped class cache
Unsupported class file major version
```

**解决方案**：

```bash
# 升级 Gradle Wrapper
./gradlew wrapper --gradle-version 8.5

# 或手动修改 gradle-wrapper.properties
distributionUrl=https\://services.gradle.org/distributions/gradle-8.5-bin.zip

# 清理缓存
rm -rf ~/.gradle/caches
rm -rf .gradle
```

### 15.10 本地仓库损坏

**错误信息**：
```
Could not read artifact descriptor
Checksum validation failed
```

**解决方案**：

```bash
# Maven: 删除损坏的依赖
rm -rf ~/.m2/repository/com/example/corrupted-artifact

# 重新下载
mvn dependency:resolve

# 或清理整个本地仓库（谨慎）
rm -rf ~/.m2/repository

# Gradle: 清理缓存
rm -rf ~/.gradle/caches
./gradlew build --refresh-dependencies
```

### 15.11 IDE 与命令行构建结果不一致

**问题描述**：IDE 中构建成功，命令行失败（或反之）

**解决方案**：

```bash
# 1. 确保使用相同的 JDK
java -version
echo $JAVA_HOME

# 2. 清理 IDE 缓存
# IntelliJ: File -> Invalidate Caches

# 3. 重新导入项目
# IntelliJ: 右键 pom.xml -> Maven -> Reimport
# 或删除 .idea 目录重新打开

# 4. 确保 IDE 使用项目的 Maven/Gradle
# IntelliJ: Settings -> Build Tools -> Maven/Gradle
```

### 15.12 Spring Boot DevTools 热重载失败

**解决方案**：

```xml
<!-- Maven: 确保 DevTools 配置正确 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <scope>runtime</scope>
    <optional>true</optional>
</dependency>

<!-- 配置 fork -->
<plugin>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-maven-plugin</artifactId>
    <configuration>
        <fork>true</fork>
    </configuration>
</plugin>
```

```groovy
// Gradle
dependencies {
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
}
```

---

## 快速参考表

### Maven 常用命令

| 命令 | 说明 |
|------|------|
| `mvn clean` | 清理构建目录 |
| `mvn compile` | 编译源代码 |
| `mvn test` | 运行测试 |
| `mvn package` | 打包 |
| `mvn install` | 安装到本地仓库 |
| `mvn deploy` | 部署到远程仓库 |
| `mvn dependency:tree` | 查看依赖树 |
| `mvn versions:display-dependency-updates` | 检查依赖更新 |
| `mvn -U` | 强制更新 SNAPSHOT |
| `mvn -o` | 离线模式 |
| `mvn -pl module -am` | 构建指定模块及依赖 |
| `mvn -DskipTests` | 跳过测试 |

### Gradle 常用命令

| 命令 | 说明 |
|------|------|
| `./gradlew clean` | 清理构建目录 |
| `./gradlew build` | 完整构建 |
| `./gradlew test` | 运行测试 |
| `./gradlew bootJar` | Spring Boot 打包 |
| `./gradlew dependencies` | 查看依赖 |
| `./gradlew tasks` | 查看所有任务 |
| `./gradlew --refresh-dependencies` | 刷新依赖 |
| `./gradlew -x test` | 跳过测试 |
| `./gradlew --parallel` | 并行构建 |
| `./gradlew --build-cache` | 使用构建缓存 |
| `./gradlew --scan` | 生成构建扫描 |

---

> 💡 **小贴士**：对于新项目，建议优先考虑 Gradle，它在构建速度和灵活性方面都有明显优势。对于已有的 Maven 项目，如果运行稳定，没有必要强行迁移。选择适合团队的工具才是最重要的。
