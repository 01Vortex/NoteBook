

> JVM 调优是 Java 性能优化的核心，直接影响应用的响应速度和稳定性
> 本笔记基于 Java 8 + Spring Boot 2.7.18，涵盖内存模型、GC 原理、调优实战

---

## 目录

1. [JVM 基础概念](#1-jvm-基础概念)
2. [内存模型详解](#2-内存模型详解)
3. [垃圾回收基础](#3-垃圾回收基础)
4. [垃圾收集器详解](#4-垃圾收集器详解)
5. [JVM 参数配置](#5-jvm-参数配置)
6. [监控与诊断工具](#6-监控与诊断工具)
7. [内存问题排查](#7-内存问题排查)
8. [GC 日志分析](#8-gc-日志分析)
9. [Spring Boot 调优](#9-spring-boot-调优)
10. [容器环境调优](#10-容器环境调优)
11. [调优实战案例](#11-调优实战案例)
12. [常见错误与解决方案](#12-常见错误与解决方案)
13. [最佳实践总结](#13-最佳实践总结)

---

## 1. JVM 基础概念

### 1.1 什么是 JVM？

JVM（Java Virtual Machine）是 Java 程序的运行环境，它做三件事：
1. **加载代码**：把 .class 文件加载到内存
2. **管理内存**：自动分配和回收内存（GC）
3. **执行代码**：解释/编译执行字节码

**为什么要调优 JVM？**

想象 JVM 是一个仓库：
- 仓库太小 → 货物放不下（OOM）
- 仓库太大 → 浪费空间和管理成本
- 整理货物太频繁 → 影响正常工作（GC 停顿）
- 整理货物太少 → 仓库很快就满了

JVM 调优就是找到最佳的仓库大小和整理策略！

### 1.2 JVM 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                        JVM 架构                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   类加载子系统                        │   │
│  │  加载 → 链接（验证→准备→解析）→ 初始化               │   │
│  └─────────────────────────────────────────────────────┘   │
│                            ↓                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   运行时数据区                        │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────────────────┐    │   │
│  │  │  方法区  │ │   堆    │ │ 虚拟机栈│本地方法栈│PC │    │   │
│  │  │(元空间) │ │ (Heap)  │ │    (线程私有)        │    │   │
│  │  └─────────┘ └─────────┘ └─────────────────────┘    │   │
│  └─────────────────────────────────────────────────────┘   │
│                            ↓                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    执行引擎                           │   │
│  │  解释器 + JIT编译器 + 垃圾收集器                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 关键术语

| 术语 | 英文 | 说明 |
|------|------|------|
| 堆 | Heap | 存放对象实例，GC 主要管理区域 |
| 栈 | Stack | 存放局部变量、方法调用 |
| 方法区 | Method Area | 存放类信息、常量、静态变量 |
| GC | Garbage Collection | 垃圾回收，自动释放无用对象 |
| STW | Stop The World | GC 时暂停所有应用线程 |
| OOM | OutOfMemoryError | 内存溢出错误 |
| Full GC | Full Garbage Collection | 全堆回收，通常伴随长时间 STW |

---

## 2. 内存模型详解

### 2.1 运行时数据区

```
┌─────────────────────────────────────────────────────────────┐
│                     JVM 内存结构                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    堆内存 (Heap)                      │   │
│  │  ┌─────────────────────┐ ┌─────────────────────┐    │   │
│  │  │      年轻代          │ │       老年代         │    │   │
│  │  │  ┌─────┬─────┬────┐ │ │                     │    │   │
│  │  │  │Eden │ S0  │ S1 │ │ │      Old Gen        │    │   │
│  │  │  │     │     │    │ │ │                     │    │   │
│  │  │  └─────┴─────┴────┘ │ │                     │    │   │
│  │  └─────────────────────┘ └─────────────────────┘    │   │
│  │         -Xmn                    (Heap - Xmn)         │   │
│  │  ←─────────────── -Xms / -Xmx ──────────────────→   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              元空间 (Metaspace) - 本地内存             │   │
│  │              存放类元数据、常量池等                    │   │
│  │              -XX:MetaspaceSize / MaxMetaspaceSize     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ 虚拟机栈  │ │本地方法栈 │ │ 程序计数器│ │ 直接内存  │      │
│  │ -Xss     │ │          │ │          │ │-XX:MaxDirect│     │
│  │(线程私有)│ │(线程私有) │ │(线程私有) │ │MemorySize │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 堆内存分代

**为什么要分代？**

研究表明，大部分对象都是"朝生夕死"的，只有少数对象会长期存活。分代可以针对不同生命周期的对象采用不同的回收策略，提高效率。

```
对象生命周期分布：
┌────────────────────────────────────────────────────────┐
│ ████████████████████████████████                       │ 98% 短命对象
│ ██                                                     │ 2% 长寿对象
└────────────────────────────────────────────────────────┘
```

**分代详解**：

| 区域 | 说明 | 特点 |
|------|------|------|
| Eden | 新对象诞生地 | 大部分对象在这里被回收 |
| Survivor (S0/S1) | 幸存者区，两个交替使用 | 存放经过 Minor GC 的对象 |
| Old Gen | 老年代 | 存放长期存活的对象 |

**对象晋升流程**：
```
新对象 → Eden → (Minor GC) → Survivor → (多次GC后) → Old Gen
                    ↓
              大部分对象在这里被回收
```


### 2.3 内存参数详解

```bash
# 堆内存设置
-Xms512m          # 初始堆大小（建议与 Xmx 相同，避免动态扩展）
-Xmx1024m         # 最大堆大小
-Xmn256m          # 年轻代大小（Eden + 2*Survivor）

# 元空间设置（Java 8+）
-XX:MetaspaceSize=128m      # 元空间初始大小
-XX:MaxMetaspaceSize=256m   # 元空间最大大小

# 栈设置
-Xss256k          # 每个线程的栈大小（默认 1M，可适当减小）

# 直接内存
-XX:MaxDirectMemorySize=256m  # 直接内存最大值

# 比例设置
-XX:NewRatio=2              # 老年代:年轻代 = 2:1
-XX:SurvivorRatio=8         # Eden:S0:S1 = 8:1:1
-XX:MaxTenuringThreshold=15 # 对象晋升老年代的年龄阈值
```

### 2.4 内存大小计算

```
总内存 = 堆内存 + 元空间 + 线程栈 * 线程数 + 直接内存 + JVM自身

示例计算（2G 容器）：
- 堆内存：1G (-Xmx1g)
- 元空间：256M (-XX:MaxMetaspaceSize=256m)
- 线程栈：200 线程 * 256K = 50M
- 直接内存：256M
- JVM 自身：约 100M
- 预留：约 400M

建议：容器内存的 60-70% 分配给堆
```

---

## 3. 垃圾回收基础

### 3.1 什么是垃圾？

垃圾就是不再被引用的对象。JVM 通过以下算法判断对象是否存活：

**引用计数法**（JVM 不使用）：
```java
// 问题：循环引用无法回收
class A {
    B b;
}
class B {
    A a;
}
A a = new A();
B b = new B();
a.b = b;
b.a = a;
a = null;
b = null;
// a 和 b 互相引用，引用计数不为 0，但实际已是垃圾
```

**可达性分析**（JVM 使用）：
```
从 GC Roots 出发，能到达的对象就是存活的

GC Roots 包括：
├── 虚拟机栈中引用的对象（局部变量）
├── 方法区中静态属性引用的对象
├── 方法区中常量引用的对象
├── 本地方法栈中 JNI 引用的对象
└── 同步锁持有的对象
```

### 3.2 垃圾回收算法

#### 标记-清除（Mark-Sweep）

```
标记阶段：标记所有存活对象
清除阶段：清除未标记的对象

优点：简单
缺点：产生内存碎片

┌───┬───┬───┬───┬───┬───┬───┬───┐
│ A │   │ B │   │   │ C │   │ D │  回收前
└───┴───┴───┴───┴───┴───┴───┴───┘
         ↓ 清除后
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ A │ ░ │ B │ ░ │ ░ │ C │ ░ │ D │  碎片化
└───┴───┴───┴───┴───┴───┴───┴───┘
```

#### 标记-复制（Copying）

```
将内存分为两块，每次只用一块
回收时把存活对象复制到另一块

优点：无碎片，效率高
缺点：浪费一半空间

┌───────────────┬───────────────┐
│ A   B   C     │               │  使用中
└───────────────┴───────────────┘
         ↓ 复制后
┌───────────────┬───────────────┐
│               │ A   B   C     │  切换
└───────────────┴───────────────┘
```

#### 标记-整理（Mark-Compact）

```
标记存活对象，然后向一端移动

优点：无碎片
缺点：移动对象开销大

┌───┬───┬───┬───┬───┬───┬───┬───┐
│ A │   │ B │   │   │ C │   │ D │  回收前
└───┴───┴───┴───┴───┴───┴───┴───┘
         ↓ 整理后
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ A │ B │ C │ D │   │   │   │   │  紧凑
└───┴───┴───┴───┴───┴───┴───┴───┘
```

### 3.3 分代收集

```
年轻代：使用复制算法（对象存活率低，复制成本小）
老年代：使用标记-清除或标记-整理（对象存活率高）

Minor GC：只回收年轻代，频繁但快速
Major GC：只回收老年代
Full GC：回收整个堆，耗时长，应尽量避免
```

### 3.4 GC 触发条件

```
Minor GC 触发：
- Eden 区满

Full GC 触发：
- 老年代空间不足
- 元空间不足
- 显式调用 System.gc()（不推荐）
- Minor GC 后存活对象太大，老年代放不下
- CMS GC 时 concurrent mode failure
```

---

## 4. 垃圾收集器详解

### 4.1 收集器概览

```
┌─────────────────────────────────────────────────────────────┐
│                    垃圾收集器家族                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  年轻代收集器          老年代收集器          全堆收集器       │
│  ┌─────────┐          ┌─────────┐          ┌─────────┐     │
│  │ Serial  │←────────→│Serial Old│          │   G1    │     │
│  └─────────┘          └─────────┘          └─────────┘     │
│  ┌─────────┐          ┌─────────┐                          │
│  │ ParNew  │←────────→│   CMS   │                          │
│  └─────────┘          └─────────┘                          │
│  ┌─────────┐          ┌─────────┐                          │
│  │Parallel │←────────→│Parallel │                          │
│  │Scavenge │          │  Old    │                          │
│  └─────────┘          └─────────┘                          │
│                                                             │
│  Java 8 默认：Parallel Scavenge + Parallel Old              │
│  推荐生产：G1（大堆）或 ParNew + CMS（小堆）                  │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Serial 收集器

```
单线程收集器，简单高效，适合单核 CPU 或小内存应用

┌──────────────────────────────────────────────────────────┐
│ 应用线程 ████████████░░░░░░░░░░░░░░░░░░████████████████  │
│ GC 线程                  ████████████                    │
│                          (STW)                           │
└──────────────────────────────────────────────────────────┘

启用参数：
-XX:+UseSerialGC
```

### 4.3 Parallel 收集器（Java 8 默认）

```
多线程并行收集，追求高吞吐量

┌──────────────────────────────────────────────────────────┐
│ 应用线程 ████████████░░░░░░░░░░░░░░░░░░████████████████  │
│ GC 线程1               ████████                          │
│ GC 线程2               ████████                          │
│ GC 线程3               ████████                          │
│                        (STW)                             │
└──────────────────────────────────────────────────────────┘

启用参数：
-XX:+UseParallelGC              # 年轻代
-XX:+UseParallelOldGC           # 老年代
-XX:ParallelGCThreads=4         # GC 线程数
-XX:MaxGCPauseMillis=200        # 最大停顿时间目标
-XX:GCTimeRatio=99              # 吞吐量目标（GC时间占比 1/(1+99)=1%）
```

### 4.4 CMS 收集器

```
并发标记清除，追求低停顿，适合响应时间敏感的应用

┌──────────────────────────────────────────────────────────┐
│ 应用线程 ████░░████████████████████████░░░░████████████  │
│ GC 线程      ██  ████████████████████  ████              │
│           初始  并发标记    并发预清理  重新  并发清除     │
│           标记                        标记               │
│          (STW)                       (STW)              │
└──────────────────────────────────────────────────────────┘

四个阶段：
1. 初始标记（STW）：标记 GC Roots 直接关联的对象，很快
2. 并发标记：与应用线程并发，遍历对象图
3. 重新标记（STW）：修正并发标记期间的变动
4. 并发清除：与应用线程并发，清除垃圾

启用参数：
-XX:+UseConcMarkSweepGC
-XX:+UseParNewGC                      # 年轻代使用 ParNew
-XX:CMSInitiatingOccupancyFraction=70 # 老年代使用 70% 时触发 CMS
-XX:+UseCMSInitiatingOccupancyOnly    # 只使用设定的阈值
-XX:+CMSParallelRemarkEnabled         # 并行重新标记
-XX:+CMSScavengeBeforeRemark          # 重新标记前先 Minor GC
```

**CMS 的问题**：
1. CPU 敏感：并发阶段占用 CPU
2. 浮动垃圾：并发清除时产生的新垃圾
3. 内存碎片：标记-清除算法的固有问题
4. Concurrent Mode Failure：并发收集时老年代满了


### 4.5 G1 收集器（推荐）

G1（Garbage First）是面向服务端的收集器，Java 9+ 默认，Java 8 可用。

```
G1 将堆划分为多个大小相等的 Region，每个 Region 可以是 Eden、Survivor 或 Old

┌────┬────┬────┬────┬────┬────┬────┬────┐
│ E  │ E  │ S  │ O  │ O  │ H  │ E  │ O  │
├────┼────┼────┼────┼────┼────┼────┼────┤
│ O  │ E  │ O  │ O  │ S  │ H  │    │ O  │
├────┼────┼────┼────┼────┼────┼────┼────┤
│ E  │ O  │ O  │    │ E  │ O  │ O  │ E  │
└────┴────┴────┴────┴────┴────┴────┴────┘

E = Eden, S = Survivor, O = Old, H = Humongous（大对象）

特点：
- 可预测的停顿时间（-XX:MaxGCPauseMillis）
- 优先回收垃圾最多的 Region（Garbage First）
- 整体使用标记-整理，Region 之间使用复制算法
```

**G1 收集过程**：

```
Young GC：回收所有年轻代 Region
Mixed GC：回收所有年轻代 + 部分老年代 Region
Full GC：退化为单线程，应尽量避免

┌──────────────────────────────────────────────────────────┐
│ 应用线程 ████░░████████████████░░░░░░████████████████    │
│ GC 线程      ██  ████████████  ██████                    │
│           初始  并发标记      最终    筛选               │
│           标记              标记    回收                 │
│          (STW)             (STW)  (STW)                 │
└──────────────────────────────────────────────────────────┘
```

**G1 参数配置**：

```bash
# 启用 G1
-XX:+UseG1GC

# 核心参数
-XX:MaxGCPauseMillis=200        # 目标停顿时间（默认 200ms）
-XX:G1HeapRegionSize=4m         # Region 大小（1-32M，2的幂）
-XX:G1NewSizePercent=5          # 年轻代最小占比
-XX:G1MaxNewSizePercent=60      # 年轻代最大占比
-XX:InitiatingHeapOccupancyPercent=45  # 触发并发标记的堆占用率

# 调优参数
-XX:G1ReservePercent=10         # 预留空间防止晋升失败
-XX:G1MixedGCCountTarget=8      # Mixed GC 次数目标
-XX:G1MixedGCLiveThresholdPercent=85  # Region 存活率阈值
```

### 4.6 收集器选择指南

```
┌─────────────────────────────────────────────────────────────┐
│                    收集器选择决策树                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  堆大小 < 100M？                                            │
│      └── 是 → Serial                                       │
│      └── 否 ↓                                              │
│                                                             │
│  单核 CPU？                                                 │
│      └── 是 → Serial                                       │
│      └── 否 ↓                                              │
│                                                             │
│  追求吞吐量优先？（批处理、科学计算）                         │
│      └── 是 → Parallel                                     │
│      └── 否 ↓                                              │
│                                                             │
│  堆大小 > 4G？                                              │
│      └── 是 → G1                                           │
│      └── 否 → CMS 或 G1                                    │
│                                                             │
│  Java 8 推荐配置：                                          │
│  - 小堆（< 4G）：ParNew + CMS                               │
│  - 大堆（≥ 4G）：G1                                         │
│  - 超大堆（> 8G）：G1 或考虑升级到 Java 11+ 使用 ZGC        │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. JVM 参数配置

### 5.1 参数分类

```bash
# 标准参数（所有 JVM 都支持）
-version
-help
-server / -client

# -X 参数（非标准，但大多数 JVM 支持）
-Xms          # 初始堆大小
-Xmx          # 最大堆大小
-Xmn          # 年轻代大小
-Xss          # 线程栈大小

# -XX 参数（不稳定，可能随版本变化）
-XX:+UseG1GC              # 布尔型：+ 启用，- 禁用
-XX:MaxGCPauseMillis=200  # 数值型：key=value
```

### 5.2 生产环境推荐配置

#### 小型应用（2G 内存）

```bash
# ParNew + CMS 配置
JAVA_OPTS="
-server
-Xms1g -Xmx1g
-Xmn384m
-XX:MetaspaceSize=128m
-XX:MaxMetaspaceSize=256m
-Xss256k
-XX:+UseParNewGC
-XX:+UseConcMarkSweepGC
-XX:CMSInitiatingOccupancyFraction=75
-XX:+UseCMSInitiatingOccupancyOnly
-XX:+CMSParallelRemarkEnabled
-XX:+CMSScavengeBeforeRemark
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/logs/heapdump.hprof
-XX:+PrintGCDetails
-XX:+PrintGCDateStamps
-Xloggc:/logs/gc.log
"
```

#### 中型应用（4G 内存）

```bash
# G1 配置
JAVA_OPTS="
-server
-Xms3g -Xmx3g
-XX:MetaspaceSize=256m
-XX:MaxMetaspaceSize=512m
-Xss256k
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
-XX:G1HeapRegionSize=8m
-XX:InitiatingHeapOccupancyPercent=45
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/logs/heapdump.hprof
-XX:+PrintGCDetails
-XX:+PrintGCDateStamps
-XX:+PrintGCApplicationStoppedTime
-Xloggc:/logs/gc.log
-XX:+UseGCLogFileRotation
-XX:NumberOfGCLogFiles=10
-XX:GCLogFileSize=100M
"
```

#### 大型应用（8G+ 内存）

```bash
# G1 大堆配置
JAVA_OPTS="
-server
-Xms6g -Xmx6g
-XX:MetaspaceSize=512m
-XX:MaxMetaspaceSize=1g
-Xss512k
-XX:+UseG1GC
-XX:MaxGCPauseMillis=100
-XX:G1HeapRegionSize=16m
-XX:G1NewSizePercent=20
-XX:G1MaxNewSizePercent=40
-XX:InitiatingHeapOccupancyPercent=40
-XX:G1ReservePercent=15
-XX:ConcGCThreads=4
-XX:ParallelGCThreads=8
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/logs/heapdump.hprof
-Xloggc:/logs/gc.log
-XX:+PrintGCDetails
-XX:+PrintGCDateStamps
-XX:+PrintAdaptiveSizePolicy
"
```

### 5.3 常用调试参数

```bash
# 内存溢出时自动 dump
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/path/to/dump.hprof

# OOM 时执行脚本
-XX:OnOutOfMemoryError="kill -9 %p"

# 打印 GC 详情
-XX:+PrintGCDetails
-XX:+PrintGCDateStamps
-XX:+PrintGCTimeStamps
-XX:+PrintGCApplicationStoppedTime
-XX:+PrintGCApplicationConcurrentTime
-XX:+PrintHeapAtGC
-XX:+PrintTenuringDistribution

# GC 日志文件
-Xloggc:/path/to/gc.log
-XX:+UseGCLogFileRotation
-XX:NumberOfGCLogFiles=10
-XX:GCLogFileSize=100M

# 打印类加载信息
-XX:+TraceClassLoading
-XX:+TraceClassUnloading

# 打印 JIT 编译信息
-XX:+PrintCompilation
```

---

## 6. 监控与诊断工具

### 6.1 命令行工具

#### jps - 查看 Java 进程

```bash
jps -l        # 显示完整类名
jps -v        # 显示 JVM 参数
jps -m        # 显示 main 方法参数

# 输出示例
12345 com.example.Application
12346 org.apache.catalina.startup.Bootstrap
```

#### jstat - 统计信息

```bash
# 查看 GC 统计
jstat -gc <pid> 1000 10      # 每秒打印一次，共 10 次
jstat -gcutil <pid> 1000     # 百分比形式

# 输出解释
# S0C/S1C: Survivor 0/1 容量
# S0U/S1U: Survivor 0/1 已用
# EC/EU: Eden 容量/已用
# OC/OU: Old 容量/已用
# MC/MU: Metaspace 容量/已用
# YGC/YGCT: Young GC 次数/时间
# FGC/FGCT: Full GC 次数/时间
# GCT: GC 总时间

# 查看类加载
jstat -class <pid>

# 查看编译统计
jstat -compiler <pid>
```

#### jmap - 内存映射

```bash
# 查看堆内存概况
jmap -heap <pid>

# 查看对象统计（会触发 Full GC）
jmap -histo <pid> | head -20
jmap -histo:live <pid>        # 只统计存活对象

# 导出堆转储
jmap -dump:format=b,file=heap.hprof <pid>
jmap -dump:live,format=b,file=heap.hprof <pid>  # 只导出存活对象
```

#### jstack - 线程堆栈

```bash
# 打印线程堆栈
jstack <pid>
jstack -l <pid>    # 包含锁信息

# 检测死锁
jstack <pid> | grep -A 50 "deadlock"

# 保存到文件
jstack <pid> > thread_dump.txt
```

#### jinfo - 配置信息

```bash
# 查看 JVM 参数
jinfo -flags <pid>

# 查看系统属性
jinfo -sysprops <pid>

# 动态修改参数（部分支持）
jinfo -flag +PrintGCDetails <pid>
jinfo -flag -PrintGCDetails <pid>
```


### 6.2 可视化工具

#### JConsole

```bash
# 启动
jconsole

# 远程连接需要在应用启动时添加
-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.port=9999
-Dcom.sun.management.jmxremote.ssl=false
-Dcom.sun.management.jmxremote.authenticate=false
```

#### VisualVM

```bash
# 下载：https://visualvm.github.io/
# 功能：
# - 监控 CPU、内存、线程
# - 分析堆转储
# - 采样和分析性能
# - 查看 MBean
```

#### JMC（Java Mission Control）

```bash
# Java 8 自带，功能强大
# 启动
jmc

# 飞行记录器（低开销的性能分析）
-XX:+UnlockCommercialFeatures
-XX:+FlightRecorder
-XX:StartFlightRecording=duration=60s,filename=recording.jfr
```

### 6.3 在线诊断工具 Arthas

Arthas 是阿里开源的 Java 诊断工具，功能强大，推荐使用。

```bash
# 安装
curl -O https://arthas.aliyun.com/arthas-boot.jar

# 启动
java -jar arthas-boot.jar

# 常用命令
dashboard          # 实时面板
thread             # 线程信息
thread -n 3        # CPU 占用最高的 3 个线程
thread -b          # 查找阻塞线程
jvm                # JVM 信息
memory             # 内存信息
heapdump /tmp/dump.hprof  # 导出堆转储

# 方法监控
watch com.example.Service method "{params,returnObj}" -x 2
trace com.example.Service method  # 方法调用链路
monitor com.example.Service method -c 5  # 方法调用统计

# 反编译
jad com.example.Service

# 热更新（谨慎使用）
redefine /path/to/Service.class
```

---

## 7. 内存问题排查

### 7.1 内存泄漏排查

**症状**：
- 内存持续增长，Full GC 后不下降
- Full GC 越来越频繁
- 最终 OOM

**排查步骤**：

```bash
# 1. 确认内存增长趋势
jstat -gcutil <pid> 5000

# 2. 导出堆转储
jmap -dump:live,format=b,file=heap.hprof <pid>

# 3. 使用 MAT 分析
# 下载：https://www.eclipse.org/mat/
# 打开 heap.hprof，查看：
# - Leak Suspects Report（泄漏嫌疑报告）
# - Dominator Tree（支配树）
# - Histogram（对象直方图）

# 4. 查找大对象
jmap -histo:live <pid> | head -30
```

**常见泄漏场景**：

```java
// 1. 静态集合持有对象
public class Cache {
    private static Map<String, Object> cache = new HashMap<>();
    
    public void add(String key, Object value) {
        cache.put(key, value);  // 只增不减
    }
}

// 2. 未关闭的资源
public void readFile() {
    InputStream is = new FileInputStream("file.txt");
    // 忘记 close，导致资源泄漏
}

// 3. 监听器未移除
button.addActionListener(listener);
// 忘记 removeActionListener

// 4. ThreadLocal 未清理
private static ThreadLocal<User> userHolder = new ThreadLocal<>();
userHolder.set(user);
// 忘记 remove，线程池场景下会泄漏

// 5. 内部类持有外部类引用
public class Outer {
    private byte[] data = new byte[1024 * 1024];
    
    class Inner {
        // Inner 隐式持有 Outer 引用
        // 如果 Inner 被长期持有，Outer 也无法回收
    }
}
```

### 7.2 OOM 问题排查

#### Java heap space

```bash
# 原因：堆内存不足
# 排查：
1. 检查是否内存泄漏
2. 检查是否有大对象
3. 增加堆内存 -Xmx

# 分析堆转储
jmap -dump:format=b,file=heap.hprof <pid>
# 或配置自动 dump
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/logs/
```

#### Metaspace

```bash
# 原因：类元数据空间不足
# 常见于：
# - 动态生成大量类（CGLib、反射）
# - 热部署频繁
# - 类加载器泄漏

# 排查：
jstat -gcmetacapacity <pid>
jmap -clstats <pid>

# 解决：
-XX:MaxMetaspaceSize=512m  # 增加元空间
# 检查是否有类加载器泄漏
```

#### GC overhead limit exceeded

```bash
# 原因：GC 时间占比过高（默认 98%），但回收效果差
# 说明：内存严重不足或泄漏

# 解决：
1. 增加堆内存
2. 排查内存泄漏
3. 临时禁用（不推荐）：-XX:-UseGCOverheadLimit
```

#### Direct buffer memory

```bash
# 原因：直接内存不足
# 常见于：NIO、Netty 应用

# 排查：
# 检查 ByteBuffer.allocateDirect() 使用
# 检查是否有直接内存泄漏

# 解决：
-XX:MaxDirectMemorySize=512m  # 增加直接内存
# 确保 DirectByteBuffer 被正确释放
```

#### Unable to create new native thread

```bash
# 原因：无法创建新线程
# 可能原因：
# - 线程数达到系统限制
# - 内存不足（每个线程需要栈空间）

# 排查：
cat /proc/<pid>/limits  # 查看进程限制
ulimit -u               # 查看用户线程限制
ps -eLf | grep java | wc -l  # 统计线程数

# 解决：
-Xss256k                # 减小线程栈大小
ulimit -u 65535         # 增加线程限制
# 检查是否有线程泄漏
```

### 7.3 CPU 问题排查

```bash
# 1. 找到 CPU 高的进程
top -c

# 2. 找到 CPU 高的线程
top -Hp <pid>

# 3. 转换线程 ID 为十六进制
printf "%x\n" <tid>

# 4. 查看线程堆栈
jstack <pid> | grep -A 30 <hex_tid>

# 或使用 Arthas
thread -n 3  # 查看 CPU 最高的 3 个线程
```

---

## 8. GC 日志分析

### 8.1 开启 GC 日志

```bash
# Java 8
-XX:+PrintGCDetails
-XX:+PrintGCDateStamps
-XX:+PrintGCTimeStamps
-XX:+PrintHeapAtGC
-XX:+PrintTenuringDistribution
-XX:+PrintGCApplicationStoppedTime
-Xloggc:/logs/gc.log
-XX:+UseGCLogFileRotation
-XX:NumberOfGCLogFiles=10
-XX:GCLogFileSize=100M

# Java 9+
-Xlog:gc*:file=/logs/gc.log:time,uptime,level,tags:filecount=10,filesize=100m
```

### 8.2 GC 日志解读

#### Minor GC 日志

```
2024-01-15T10:30:45.123+0800: 1234.567: [GC (Allocation Failure) 
[PSYoungGen: 524288K->65536K(589824K)] 1048576K->655360K(2013184K), 0.0234567 secs] 
[Times: user=0.08 sys=0.01, real=0.02 secs]

解读：
- 时间戳：2024-01-15T10:30:45.123
- JVM 运行时间：1234.567 秒
- GC 原因：Allocation Failure（分配失败）
- 年轻代：524288K → 65536K（容量 589824K）
- 整个堆：1048576K → 655360K（容量 2013184K）
- 耗时：0.0234567 秒
- user：用户态 CPU 时间
- sys：内核态 CPU 时间
- real：实际耗时（STW 时间）
```

#### Full GC 日志

```
2024-01-15T10:35:12.456+0800: 1500.789: [Full GC (Ergonomics) 
[PSYoungGen: 65536K->0K(589824K)] 
[ParOldGen: 1310720K->524288K(1423360K)] 
1376256K->524288K(2013184K), 
[Metaspace: 102400K->102400K(1150976K)], 0.5678901 secs] 
[Times: user=2.00 sys=0.10, real=0.57 secs]

解读：
- Full GC 原因：Ergonomics（自适应调整）
- 年轻代完全清空
- 老年代：1310720K → 524288K
- 元空间：未变化
- 总耗时：0.57 秒（较长，需要关注）
```

#### G1 GC 日志

```
2024-01-15T10:40:00.000+0800: 2000.000: [GC pause (G1 Evacuation Pause) (young)
, 0.0123456 secs]
   [Parallel Time: 10.5 ms, GC Workers: 4]
      [GC Worker Start (ms): Min: 2000000.0, Avg: 2000000.1, Max: 2000000.2]
      [Ext Root Scanning (ms): Min: 0.5, Avg: 0.6, Max: 0.8]
      [Update RS (ms): Min: 1.0, Avg: 1.2, Max: 1.5]
      [Scan RS (ms): Min: 0.2, Avg: 0.3, Max: 0.4]
      [Code Root Scanning (ms): Min: 0.0, Avg: 0.1, Max: 0.1]
      [Object Copy (ms): Min: 7.0, Avg: 7.5, Max: 8.0]
      [Termination (ms): Min: 0.0, Avg: 0.1, Max: 0.2]
   [Code Root Fixup: 0.1 ms]
   [Code Root Purge: 0.0 ms]
   [Clear CT: 0.2 ms]
   [Other: 1.5 ms]
   [Eden: 256.0M(256.0M)->0.0B(256.0M) Survivors: 32.0M->32.0M Heap: 512.0M(1024.0M)->288.0M(1024.0M)]
 [Times: user=0.04 sys=0.00, real=0.01 secs]
```

### 8.3 GC 日志分析工具

```bash
# GCViewer（离线分析）
# 下载：https://github.com/chewiebug/GCViewer
java -jar gcviewer.jar gc.log

# GCEasy（在线分析）
# 网址：https://gceasy.io/
# 上传 GC 日志，自动生成分析报告

# 关注指标：
# - GC 频率：Minor GC < 10次/分钟，Full GC < 1次/小时
# - GC 耗时：Minor GC < 50ms，Full GC < 1s
# - 吞吐量：> 95%
# - 内存回收率：每次 GC 后内存应明显下降
```


---

## 9. Spring Boot 调优

### 9.1 启动参数配置

```bash
# application.yml 或启动脚本
java -jar app.jar \
  -server \
  -Xms2g -Xmx2g \
  -XX:+UseG1GC \
  -XX:MaxGCPauseMillis=200 \
  -XX:+HeapDumpOnOutOfMemoryError \
  -XX:HeapDumpPath=/logs/heapdump.hprof \
  -Xloggc:/logs/gc.log \
  -XX:+PrintGCDetails \
  -XX:+PrintGCDateStamps
```

### 9.2 Spring Boot Actuator 监控

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus,heapdump,threaddump
  endpoint:
    health:
      show-details: always
  metrics:
    tags:
      application: ${spring.application.name}
```

```bash
# 访问端点
GET /actuator/health          # 健康检查
GET /actuator/metrics         # 指标列表
GET /actuator/metrics/jvm.memory.used  # JVM 内存使用
GET /actuator/heapdump        # 下载堆转储
GET /actuator/threaddump      # 线程转储
```

### 9.3 常见 Spring Boot 内存问题

#### 连接池配置不当

```yaml
# HikariCP 连接池配置
spring:
  datasource:
    hikari:
      minimum-idle: 5           # 最小空闲连接
      maximum-pool-size: 20     # 最大连接数
      idle-timeout: 300000      # 空闲超时（5分钟）
      max-lifetime: 1800000     # 最大生命周期（30分钟）
      connection-timeout: 30000 # 连接超时
      leak-detection-threshold: 60000  # 泄漏检测阈值
```

#### 缓存配置

```java
// 使用 Caffeine 本地缓存
@Configuration
@EnableCaching
public class CacheConfig {
    
    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager();
        manager.setCaffeine(Caffeine.newBuilder()
            .maximumSize(10000)           // 最大条目数
            .expireAfterWrite(10, TimeUnit.MINUTES)  // 写入后过期
            .recordStats());              // 记录统计
        return manager;
    }
}
```

#### 异步线程池配置

```java
@Configuration
@EnableAsync
public class AsyncConfig {
    
    @Bean("taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(50);
        executor.setQueueCapacity(200);
        executor.setKeepAliveSeconds(60);
        executor.setThreadNamePrefix("async-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(60);
        executor.initialize();
        return executor;
    }
}
```

### 9.4 内存优化技巧

```java
// 1. 避免在循环中创建对象
// 错误
for (int i = 0; i < 10000; i++) {
    String s = new String("hello");  // 每次创建新对象
}
// 正确
String s = "hello";
for (int i = 0; i < 10000; i++) {
    // 使用 s
}

// 2. 使用对象池
// Apache Commons Pool
GenericObjectPool<ExpensiveObject> pool = new GenericObjectPool<>(factory);
ExpensiveObject obj = pool.borrowObject();
try {
    // 使用对象
} finally {
    pool.returnObject(obj);
}

// 3. 使用基本类型代替包装类型
// 错误
Long count = 0L;
for (int i = 0; i < 10000; i++) {
    count++;  // 自动装箱，创建新对象
}
// 正确
long count = 0L;

// 4. StringBuilder 代替 String 拼接
// 错误
String result = "";
for (String s : list) {
    result += s;  // 每次创建新 String
}
// 正确
StringBuilder sb = new StringBuilder();
for (String s : list) {
    sb.append(s);
}
String result = sb.toString();

// 5. 及时释放大对象引用
public void process() {
    byte[] largeData = loadLargeData();
    // 处理数据
    processData(largeData);
    // 处理完成后置空，帮助 GC
    largeData = null;
    // 继续其他操作
}

// 6. 使用 try-with-resources
try (InputStream is = new FileInputStream("file.txt");
     BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
    // 自动关闭资源
}

// 7. 合理使用软引用和弱引用
// 软引用：内存不足时回收，适合缓存
SoftReference<byte[]> cache = new SoftReference<>(new byte[1024 * 1024]);

// 弱引用：下次 GC 时回收
WeakReference<Object> weak = new WeakReference<>(new Object());
```

---

## 10. 容器环境调优

### 10.1 Docker 内存限制

```dockerfile
# Dockerfile
FROM openjdk:8-jdk-alpine

# 设置 JVM 参数
ENV JAVA_OPTS="-XX:+UseContainerSupport \
               -XX:MaxRAMPercentage=75.0 \
               -XX:InitialRAMPercentage=50.0 \
               -XX:+HeapDumpOnOutOfMemoryError \
               -XX:HeapDumpPath=/logs/"

COPY app.jar /app.jar
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app.jar"]
```

```bash
# 运行容器
docker run -m 2g --memory-swap 2g -e JAVA_OPTS="-Xmx1536m" my-app

# 注意：
# -m 2g：容器内存限制 2G
# 堆内存建议设置为容器内存的 60-75%
```

### 10.2 Kubernetes 资源配置

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: java-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: my-app:1.0
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        env:
        - name: JAVA_OPTS
          value: >-
            -XX:+UseContainerSupport
            -XX:MaxRAMPercentage=75.0
            -XX:InitialRAMPercentage=50.0
            -XX:+UseG1GC
            -XX:MaxGCPauseMillis=200
            -XX:+HeapDumpOnOutOfMemoryError
            -XX:HeapDumpPath=/logs/
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 5
```

### 10.3 容器感知参数（Java 8u191+）

```bash
# 自动感知容器内存限制
-XX:+UseContainerSupport          # 启用容器支持（默认开启）

# 基于容器内存的百分比设置堆大小
-XX:MaxRAMPercentage=75.0         # 最大堆占容器内存的 75%
-XX:InitialRAMPercentage=50.0     # 初始堆占容器内存的 50%
-XX:MinRAMPercentage=25.0         # 最小堆占容器内存的 25%

# 或者使用固定值
-XX:MaxRAMFraction=2              # 最大堆 = 容器内存 / 2
-XX:MinRAMFraction=4              # 最小堆 = 容器内存 / 4
```

### 10.4 容器环境常见问题

```bash
# 问题1：容器被 OOM Killer 杀死
# 原因：JVM 内存 + 非堆内存 > 容器限制
# 解决：
# - 堆内存设置为容器内存的 60-70%
# - 预留足够的非堆内存（元空间、直接内存、线程栈等）

# 问题2：GC 线程数过多
# 原因：JVM 默认根据宿主机 CPU 核数设置 GC 线程
# 解决：
-XX:ParallelGCThreads=2
-XX:ConcGCThreads=1

# 问题3：启动慢
# 原因：容器 CPU 限制导致 JIT 编译慢
# 解决：
-XX:TieredStopAtLevel=1           # 只使用 C1 编译器
-XX:+TieredCompilation            # 分层编译
-Xshare:off                       # 关闭类数据共享（如果有问题）
```

---

## 11. 调优实战案例

### 11.1 案例一：频繁 Full GC

**现象**：
- Full GC 每分钟发生多次
- 每次 Full GC 耗时 2-3 秒
- 应用响应变慢

**分析**：
```bash
# 查看 GC 情况
jstat -gcutil <pid> 1000

# 输出
S0     S1     E      O      M     YGC   YGCT    FGC   FGCT     GCT
0.00  50.00  80.00  99.50  95.00  1000  10.00   50    100.00  110.00

# 老年代使用率 99.5%，Full GC 50 次，耗时 100 秒
```

**原因**：
1. 堆内存太小
2. 内存泄漏
3. 大对象直接进入老年代

**解决**：
```bash
# 1. 增加堆内存
-Xmx4g

# 2. 调整年轻代比例
-XX:NewRatio=1  # 年轻代:老年代 = 1:1

# 3. 检查大对象
jmap -histo:live <pid> | head -20

# 4. 如果是内存泄漏，分析堆转储
jmap -dump:live,format=b,file=heap.hprof <pid>
```

### 11.2 案例二：Young GC 时间长

**现象**：
- Young GC 频繁，每次 200-500ms
- 应用有明显卡顿

**分析**：
```bash
# GC 日志
[GC (Allocation Failure) [PSYoungGen: 2097152K->524288K(2097152K)] 
3145728K->1572864K(4194304K), 0.3456789 secs]

# 年轻代 2G，每次 GC 耗时 345ms
```

**原因**：
1. 年轻代太大
2. 存活对象太多（Survivor 区溢出）

**解决**：
```bash
# 1. 减小年轻代
-Xmn512m

# 2. 调整 Survivor 比例
-XX:SurvivorRatio=6  # Eden:S0:S1 = 6:1:1

# 3. 使用 G1，控制停顿时间
-XX:+UseG1GC
-XX:MaxGCPauseMillis=100
```

### 11.3 案例三：Metaspace OOM

**现象**：
```
java.lang.OutOfMemoryError: Metaspace
```

**分析**：
```bash
# 查看类加载情况
jstat -class <pid>
# Loaded  Bytes  Unloaded  Bytes     Time
# 50000   100000  100       200      50.00

# 加载了 5 万个类，卸载很少
```

**原因**：
1. 动态生成大量类（反射、CGLib）
2. 热部署导致类加载器泄漏
3. 元空间设置太小

**解决**：
```bash
# 1. 增加元空间
-XX:MaxMetaspaceSize=512m

# 2. 检查类加载
-XX:+TraceClassLoading
-XX:+TraceClassUnloading

# 3. 检查是否有类加载器泄漏
# 使用 MAT 分析 ClassLoader 实例
```

### 11.4 案例四：CPU 100%

**现象**：
- Java 进程 CPU 持续 100%
- 应用无响应

**分析**：
```bash
# 1. 找到 CPU 高的线程
top -Hp <pid>
# PID   %CPU
# 12345  99.0

# 2. 转换为十六进制
printf "%x\n" 12345
# 3039

# 3. 查看线程堆栈
jstack <pid> | grep -A 30 "0x3039"
```

**常见原因**：
1. 死循环
2. 频繁 Full GC
3. 正则表达式回溯
4. 死锁导致的自旋

**解决**：
```java
// 检查代码中的循环
while (true) {
    // 添加退出条件或 sleep
    if (shouldStop) break;
    Thread.sleep(100);
}

// 检查正则表达式
// 避免使用 .* 等贪婪匹配
String regex = "^(a+)+$";  // 危险的正则
```


---

## 12. 常见错误与解决方案

### 12.1 OOM 错误汇总

| 错误类型 | 原因 | 解决方案 |
|----------|------|----------|
| Java heap space | 堆内存不足 | 增加 -Xmx 或排查泄漏 |
| Metaspace | 元空间不足 | 增加 -XX:MaxMetaspaceSize |
| GC overhead limit exceeded | GC 效率太低 | 增加内存或排查泄漏 |
| Direct buffer memory | 直接内存不足 | 增加 -XX:MaxDirectMemorySize |
| Unable to create new native thread | 线程数超限 | 减小 -Xss 或增加系统限制 |
| Requested array size exceeds VM limit | 数组太大 | 检查代码逻辑 |
| Out of swap space | 交换空间不足 | 增加 swap 或减少内存使用 |
| Kill process or sacrifice child | 被 OOM Killer 杀死 | 调整内存配置 |

### 12.2 GC 相关错误

#### Concurrent Mode Failure（CMS）

```bash
# 错误日志
[GC (CMS Initial Mark) ... concurrent mode failure ...]

# 原因：CMS 并发收集时老年代满了
# 解决：
-XX:CMSInitiatingOccupancyFraction=60  # 提前触发 CMS
-XX:+UseCMSInitiatingOccupancyOnly
# 或增加老年代空间
```

#### Promotion Failed

```bash
# 错误日志
[GC (Allocation Failure) -- promotion failed ...]

# 原因：年轻代对象晋升时老年代空间不足
# 解决：
# 1. 增加老年代空间
# 2. 减少大对象
# 3. 调整晋升阈值
-XX:MaxTenuringThreshold=5
```

#### To-space Exhausted（G1）

```bash
# 错误日志
[GC pause (G1 Evacuation Pause) (to-space exhausted) ...]

# 原因：G1 复制存活对象时目标空间不足
# 解决：
-XX:G1ReservePercent=15  # 增加预留空间
-XX:InitiatingHeapOccupancyPercent=35  # 提前触发并发标记
```

### 12.3 启动错误

#### 无法分配足够内存

```bash
# 错误
Error occurred during initialization of VM
Could not reserve enough space for object heap

# 原因：系统可用内存不足
# 解决：
# 1. 减小 -Xmx
# 2. 使用 32 位 JVM（不推荐）
# 3. 增加系统内存或 swap
```

#### 参数冲突

```bash
# 错误
Conflicting collector combinations in option list

# 原因：指定了不兼容的收集器组合
# 解决：检查 GC 参数，确保组合正确
# 正确组合：
# Serial + Serial Old
# ParNew + CMS
# Parallel Scavenge + Parallel Old
# G1（单独使用）
```

### 12.4 性能问题

#### 应用启动慢

```bash
# 可能原因：
# 1. 类加载多
# 2. JIT 编译
# 3. 初始化操作

# 解决：
# 1. 使用类数据共享（CDS）
-Xshare:dump  # 生成共享存档
-Xshare:on    # 使用共享存档

# 2. 分层编译
-XX:+TieredCompilation
-XX:TieredStopAtLevel=1  # 只用 C1（启动快但峰值性能低）

# 3. 预热
# 启动后执行预热请求
```

#### 响应时间不稳定

```bash
# 可能原因：
# 1. GC 停顿
# 2. JIT 编译
# 3. 类加载

# 解决：
# 1. 使用低延迟 GC
-XX:+UseG1GC
-XX:MaxGCPauseMillis=50

# 2. 预编译热点代码
-XX:CompileThreshold=100  # 降低编译阈值

# 3. 禁用偏向锁（如果有大量锁竞争）
-XX:-UseBiasedLocking
```

### 12.5 监控告警阈值

```yaml
# 建议的告警阈值
alerts:
  # 堆内存使用率
  heap_usage:
    warning: 70%
    critical: 85%
  
  # 老年代使用率
  old_gen_usage:
    warning: 75%
    critical: 90%
  
  # Full GC 频率
  full_gc_frequency:
    warning: 1次/小时
    critical: 1次/10分钟
  
  # GC 停顿时间
  gc_pause_time:
    warning: 500ms
    critical: 2s
  
  # GC 吞吐量
  gc_throughput:
    warning: < 95%
    critical: < 90%
```

---

## 13. 最佳实践总结

### 13.1 调优原则

```
1. 先监控，后调优
   - 不要盲目调参
   - 基于数据做决策

2. 一次只改一个参数
   - 便于观察效果
   - 避免参数相互影响

3. 在测试环境验证
   - 不要直接在生产环境调优
   - 使用压测验证效果

4. 记录每次调整
   - 参数变更
   - 效果对比
   - 回滚方案

5. 关注业务指标
   - 响应时间
   - 吞吐量
   - 错误率
```

### 13.2 参数配置清单

```bash
# 生产环境 JVM 参数模板

# ========== 基础配置 ==========
-server                              # 服务器模式
-Xms4g -Xmx4g                        # 堆大小（建议相同）
-XX:MetaspaceSize=256m               # 元空间初始大小
-XX:MaxMetaspaceSize=512m            # 元空间最大大小
-Xss256k                             # 线程栈大小

# ========== GC 配置（G1）==========
-XX:+UseG1GC                         # 使用 G1
-XX:MaxGCPauseMillis=200             # 目标停顿时间
-XX:G1HeapRegionSize=8m              # Region 大小
-XX:InitiatingHeapOccupancyPercent=45  # 并发标记触发阈值
-XX:G1ReservePercent=10              # 预留空间

# ========== GC 日志 ==========
-XX:+PrintGCDetails                  # GC 详情
-XX:+PrintGCDateStamps               # GC 时间戳
-XX:+PrintGCApplicationStoppedTime   # 停顿时间
-Xloggc:/logs/gc.log                 # GC 日志文件
-XX:+UseGCLogFileRotation            # 日志轮转
-XX:NumberOfGCLogFiles=10            # 日志文件数
-XX:GCLogFileSize=100M               # 单个日志大小

# ========== OOM 处理 ==========
-XX:+HeapDumpOnOutOfMemoryError      # OOM 时 dump
-XX:HeapDumpPath=/logs/heapdump.hprof  # dump 路径
-XX:OnOutOfMemoryError="kill -9 %p"  # OOM 时执行脚本

# ========== 其他优化 ==========
-XX:+DisableExplicitGC               # 禁用 System.gc()
-XX:-OmitStackTraceInFastThrow       # 保留完整堆栈
-XX:+AlwaysPreTouch                  # 启动时预分配内存
-Djava.security.egd=file:/dev/./urandom  # 加速随机数生成
```

### 13.3 调优检查清单

```
□ 堆内存配置
  □ -Xms 和 -Xmx 设置相同
  □ 堆大小为可用内存的 60-70%
  □ 年轻代大小合理（堆的 1/3 到 1/2）

□ GC 配置
  □ 选择合适的收集器
  □ 设置合理的停顿时间目标
  □ 开启 GC 日志

□ 监控配置
  □ 开启 JMX 远程监控
  □ 配置 Actuator 端点
  □ 设置告警阈值

□ 异常处理
  □ 配置 OOM 时自动 dump
  □ 配置 OOM 时执行脚本
  □ 保留完整异常堆栈

□ 容器环境
  □ 启用容器支持
  □ 使用百分比配置内存
  □ 限制 GC 线程数
```

### 13.4 常用命令速查

```bash
# 查看进程
jps -lv

# 查看 GC 统计
jstat -gcutil <pid> 1000

# 查看堆内存
jmap -heap <pid>

# 导出堆转储
jmap -dump:live,format=b,file=heap.hprof <pid>

# 查看线程
jstack <pid>

# 查看 JVM 参数
jinfo -flags <pid>

# Arthas 诊断
java -jar arthas-boot.jar
dashboard
thread -n 3
heapdump /tmp/dump.hprof
```

### 13.5 性能指标参考

| 指标 | 良好 | 警告 | 严重 |
|------|------|------|------|
| GC 吞吐量 | > 98% | 95-98% | < 95% |
| Young GC 频率 | < 10次/分 | 10-30次/分 | > 30次/分 |
| Young GC 耗时 | < 50ms | 50-100ms | > 100ms |
| Full GC 频率 | < 1次/天 | 1次/小时 | > 1次/10分 |
| Full GC 耗时 | < 1s | 1-3s | > 3s |
| 堆使用率 | < 70% | 70-85% | > 85% |
| 老年代使用率 | < 70% | 70-85% | > 85% |

---

## 参考资料

- [Oracle JVM 调优指南](https://docs.oracle.com/javase/8/docs/technotes/guides/vm/gctuning/)
- [G1 垃圾收集器](https://www.oracle.com/technetwork/tutorials/tutorials-1876574.html)
- [JVM 参数大全](https://www.oracle.com/java/technologies/javase/vmoptions-jsp.html)
- [Arthas 用户文档](https://arthas.aliyun.com/doc/)
- [GCEasy - GC 日志分析](https://gceasy.io/)
- [MAT - 内存分析工具](https://www.eclipse.org/mat/)
