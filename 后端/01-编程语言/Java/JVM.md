# JVM (Java Virtual Machine) 完全指南

> 基于 Java 8+ 的 JVM 深度学习笔记，从入门到精通

---

## 目录

1. [JVM 概述](#1-jvm-概述)
2. [JVM 架构](#2-jvm-架构)
3. [类加载机制](#3-类加载机制)
4. [运行时数据区](#4-运行时数据区)
5. [垃圾回收 (GC)](#5-垃圾回收-gc)
6. [JVM 调优](#6-jvm-调优)
7. [常见错误与排查](#7-常见错误与排查)
8. [实战案例](#8-实战案例)

---

## 1. JVM 概述

### 1.1 什么是 JVM？

JVM（Java Virtual Machine，Java 虚拟机）是 Java 程序运行的基础。它是一个**抽象的计算机**，提供了一个与平台无关的执行环境。

**通俗理解**：JVM 就像一个"翻译官"，把 Java 字节码翻译成不同操作系统能理解的机器码，这就是 Java "一次编写，到处运行" 的秘密。

```
┌─────────────────────────────────────────────────────────┐
│                    Java 源代码 (.java)                   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼ javac 编译
┌─────────────────────────────────────────────────────────┐
│                    字节码文件 (.class)                   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼ JVM 解释/编译执行
┌─────────────────────────────────────────────────────────┐
│              不同平台的机器码 (Windows/Linux/Mac)         │
└─────────────────────────────────────────────────────────┘
```


### 1.2 JVM、JRE、JDK 的关系

```
┌─────────────────────────────────────────────────────────────────┐
│  JDK (Java Development Kit) - Java 开发工具包                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  开发工具: javac, javadoc, jar, jdb, jconsole 等           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  JRE (Java Runtime Environment) - Java 运行时环境          │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  核心类库: rt.jar, charsets.jar 等                   │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  JVM (Java Virtual Machine) - Java 虚拟机            │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**简单记忆**：
- **JVM**：运行 Java 字节码的虚拟机
- **JRE**：JVM + 核心类库，只能运行 Java 程序
- **JDK**：JRE + 开发工具，可以开发和运行 Java 程序

### 1.3 主流 JVM 实现

| JVM 实现 | 开发商 | 特点 |
|---------|--------|------|
| HotSpot | Oracle/OpenJDK | 最主流，默认 JVM |
| OpenJ9 | Eclipse/IBM | 低内存占用，快速启动 |
| GraalVM | Oracle | 支持多语言，AOT 编译 |
| Azul Zing | Azul | 低延迟，无停顿 GC |

---

## 2. JVM 架构

### 2.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                           JVM 架构                                   │
├─────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    类加载子系统 (Class Loader)                  │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │  │
│  │  │ Bootstrap   │→ │ Extension   │→ │ Application         │    │  │
│  │  │ ClassLoader │  │ ClassLoader │  │ ClassLoader         │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                │                                     │
│                                ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    运行时数据区 (Runtime Data Areas)            │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │  方法区 (Method Area) / 元空间 (Metaspace) [线程共享]     │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────┐  │  │
│  │  │  堆 (Heap) [线程共享]                                    │  │  │
│  │  └─────────────────────────────────────────────────────────┘  │  │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────────────────┐ │  │
│  │  │ 虚拟机栈   │  │ 本地方法栈 │  │ 程序计数器 (PC Register) │ │  │
│  │  │ [线程私有] │  │ [线程私有] │  │ [线程私有]               │ │  │
│  │  └───────────┘  └───────────┘  └───────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                │                                     │
│                                ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    执行引擎 (Execution Engine)                  │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │  │
│  │  │ 解释器      │  │ JIT 编译器   │  │ 垃圾回收器 (GC)      │    │  │
│  │  │ Interpreter │  │ Compiler    │  │ Garbage Collector   │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    本地方法接口 (JNI)                          │  │
│  └───────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    本地方法库 (Native Libraries)               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```


---

## 3. 类加载机制

### 3.1 类的生命周期

一个类从被加载到虚拟机内存开始，到卸载出内存为止，整个生命周期包括以下 7 个阶段：

```
┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐
│  加载   │ → │  验证   │ → │  准备   │ → │  解析   │ → │  初始化 │
│ Loading │   │Verify  │   │Prepare │   │Resolve │   │ Init   │
└────────┘   └────────┘   └────────┘   └────────┘   └────────┘
                 │             │            │
                 └─────────────┴────────────┘
                         连接 (Linking)
                                                      │
                                                      ▼
                                               ┌────────────┐
                                               │   使用      │
                                               │   Using     │
                                               └────────────┘
                                                      │
                                                      ▼
                                               ┌────────────┐
                                               │   卸载      │
                                               │  Unloading  │
                                               └────────────┘
```

### 3.2 各阶段详解

#### 3.2.1 加载 (Loading)

**做什么**：
1. 通过类的全限定名获取定义此类的二进制字节流
2. 将字节流代表的静态存储结构转化为方法区的运行时数据结构
3. 在内存中生成一个代表这个类的 `java.lang.Class` 对象

**通俗理解**：就像把一本书（.class 文件）从书架（硬盘）拿到桌子上（内存），并且做好目录索引（Class 对象）。

#### 3.2.2 验证 (Verification)

**做什么**：确保 Class 文件的字节流符合 JVM 规范，不会危害虚拟机安全。

**验证内容**：
- **文件格式验证**：是否以魔数 `0xCAFEBABE` 开头
- **元数据验证**：语义分析，如是否有父类
- **字节码验证**：数据流和控制流分析
- **符号引用验证**：确保解析能正常执行

```java
// 查看 class 文件的魔数
// 使用 hexdump 或 xxd 命令
// xxd MyClass.class | head -1
// 输出: 00000000: cafe babe 0000 0034 ...
```

#### 3.2.3 准备 (Preparation)

**做什么**：为类的**静态变量**分配内存并设置**默认初始值**（零值）。

```java
public class PrepareExample {
    // 准备阶段：value = 0（int 的默认值）
    // 初始化阶段：value = 123
    public static int value = 123;
    
    // 准备阶段：直接赋值为 123（final 常量在编译期就确定）
    public static final int CONSTANT = 123;
}
```

**各类型默认值**：

| 数据类型 | 默认值 |
|---------|--------|
| byte | 0 |
| short | 0 |
| int | 0 |
| long | 0L |
| float | 0.0f |
| double | 0.0d |
| char | '\u0000' |
| boolean | false |
| reference | null |

#### 3.2.4 解析 (Resolution)

**做什么**：将常量池中的**符号引用**替换为**直接引用**。

**通俗理解**：
- **符号引用**：用一组符号来描述目标，如类名、方法名
- **直接引用**：直接指向目标的指针、偏移量或句柄

```java
// 符号引用示例
public class ResolutionExample {
    // 编译时，System.out 是符号引用
    // 解析后，变成指向 PrintStream 对象的直接引用
    public void print() {
        System.out.println("Hello");
    }
}
```

#### 3.2.5 初始化 (Initialization)

**做什么**：执行类构造器 `<clinit>()` 方法，真正初始化类变量。

**触发初始化的 6 种情况**（主动引用）：

```java
public class InitializationTrigger {
    
    // 1. new 实例化对象
    MyClass obj = new MyClass();
    
    // 2. 访问类的静态变量（非 final）
    int x = MyClass.staticVar;
    
    // 3. 调用类的静态方法
    MyClass.staticMethod();
    
    // 4. 反射调用
    Class.forName("com.example.MyClass");
    
    // 5. 初始化子类时，父类先初始化
    // 6. 包含 main() 方法的主类
}
```

**不会触发初始化的情况**（被动引用）：

```java
public class PassiveReference {
    
    public static void main(String[] args) {
        // 1. 通过子类引用父类的静态字段，不会初始化子类
        System.out.println(SubClass.parentValue); // 只初始化 Parent
        
        // 2. 通过数组定义引用类，不会初始化该类
        Parent[] arr = new Parent[10]; // 不会初始化 Parent
        
        // 3. 引用常量不会触发初始化（常量在编译期存入调用类的常量池）
        System.out.println(Parent.CONSTANT); // 不会初始化 Parent
    }
}

class Parent {
    public static int parentValue = 1;
    public static final String CONSTANT = "hello";
    
    static {
        System.out.println("Parent 初始化");
    }
}

class SubClass extends Parent {
    public static int subValue = 2;
    
    static {
        System.out.println("SubClass 初始化");
    }
}
```


### 3.3 类加载器

#### 3.3.1 类加载器层次结构

```
                    ┌─────────────────────────────┐
                    │   Bootstrap ClassLoader     │  ← 启动类加载器（C++ 实现）
                    │   加载: JAVA_HOME/lib       │     加载核心类库 rt.jar 等
                    └─────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │   Extension ClassLoader     │  ← 扩展类加载器
                    │   加载: JAVA_HOME/lib/ext   │     Java 9+ 改名 Platform ClassLoader
                    └─────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │   Application ClassLoader   │  ← 应用类加载器（系统类加载器）
                    │   加载: classpath           │     加载用户类路径上的类
                    └─────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │   Custom ClassLoader        │  ← 自定义类加载器
                    │   加载: 自定义路径           │     用户自己实现
                    └─────────────────────────────┘
```

#### 3.3.2 双亲委派模型

**工作原理**：当一个类加载器收到类加载请求时，它首先不会自己去尝试加载，而是把请求委派给父类加载器。只有当父加载器无法完成加载时，子加载器才会尝试自己加载。

```
                    加载请求: java.lang.String
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Application ClassLoader                                     │
│  "我先问问我爸能不能加载"                                      │
└─────────────────────────────────────────────────────────────┘
                              │ 委派
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Extension ClassLoader                                       │
│  "我也先问问我爸"                                             │
└─────────────────────────────────────────────────────────────┘
                              │ 委派
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Bootstrap ClassLoader                                       │
│  "String 是核心类，我来加载！"                                 │
│  ✓ 加载成功，返回 Class 对象                                  │
└─────────────────────────────────────────────────────────────┘
```

**为什么需要双亲委派？**

1. **安全性**：防止核心类被篡改。即使你写了一个 `java.lang.String`，也不会被加载
2. **避免重复加载**：父加载器加载过的类，子加载器不会重复加载

```java
// 验证双亲委派
public class ClassLoaderDemo {
    public static void main(String[] args) {
        // String 类由 Bootstrap ClassLoader 加载，返回 null
        System.out.println(String.class.getClassLoader()); // null
        
        // 自定义类由 Application ClassLoader 加载
        System.out.println(ClassLoaderDemo.class.getClassLoader());
        // sun.misc.Launcher$AppClassLoader@...
        
        // 查看类加载器层次
        ClassLoader loader = ClassLoaderDemo.class.getClassLoader();
        while (loader != null) {
            System.out.println(loader);
            loader = loader.getParent();
        }
        System.out.println(loader); // null (Bootstrap)
    }
}
```

#### 3.3.3 双亲委派源码分析

```java
// java.lang.ClassLoader#loadClass
protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
    synchronized (getClassLoadingLock(name)) {
        // 1. 检查类是否已经加载过
        Class<?> c = findLoadedClass(name);
        
        if (c == null) {
            try {
                // 2. 如果有父加载器，委派给父加载器
                if (parent != null) {
                    c = parent.loadClass(name, false);
                } else {
                    // 3. 没有父加载器，委派给 Bootstrap ClassLoader
                    c = findBootstrapClassOrNull(name);
                }
            } catch (ClassNotFoundException e) {
                // 父加载器无法加载
            }
            
            if (c == null) {
                // 4. 父加载器无法加载，自己尝试加载
                c = findClass(name);
            }
        }
        
        if (resolve) {
            resolveClass(c);
        }
        return c;
    }
}
```

#### 3.3.4 打破双亲委派

有些场景需要打破双亲委派模型：

**场景 1：SPI 机制**（如 JDBC、JNDI）

```java
// JDBC 驱动加载示例
// rt.jar 中的 DriverManager 需要加载用户 classpath 下的驱动实现
// 使用线程上下文类加载器打破双亲委派

// 获取线程上下文类加载器
ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();

// ServiceLoader 使用上下文类加载器加载 SPI 实现
ServiceLoader<Driver> drivers = ServiceLoader.load(Driver.class);
```

**场景 2：热部署**（如 Tomcat、OSGi）

```java
// 自定义类加载器实现热部署
public class HotSwapClassLoader extends ClassLoader {
    
    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        // 对于需要热部署的类，不委派给父加载器
        if (name.startsWith("com.myapp.hotswap")) {
            return findClass(name);
        }
        // 其他类仍然使用双亲委派
        return super.loadClass(name);
    }
    
    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] classData = loadClassData(name);
        if (classData == null) {
            throw new ClassNotFoundException(name);
        }
        return defineClass(name, classData, 0, classData.length);
    }
    
    private byte[] loadClassData(String name) {
        // 从文件或网络加载类的字节码
        String path = name.replace('.', '/') + ".class";
        try (InputStream is = new FileInputStream(path)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }
}
```


---

## 4. 运行时数据区

### 4.1 程序计数器 (Program Counter Register)

**特点**：
- 线程私有
- 占用内存很小
- **唯一不会发生 OutOfMemoryError 的区域**

**作用**：记录当前线程执行的字节码指令地址。如果执行的是 Native 方法，计数器值为空（Undefined）。

**为什么需要程序计数器？**

```
线程 A 执行到第 10 行 ──────┐
                          │ CPU 时间片用完，切换到线程 B
线程 B 执行...             │
                          │ 切换回线程 A
线程 A 从第 10 行继续 ◄────┘  ← 程序计数器记住了位置
```

### 4.2 Java 虚拟机栈 (JVM Stack)

**特点**：
- 线程私有
- 生命周期与线程相同
- 描述 Java 方法执行的内存模型

#### 4.2.1 栈帧结构

每个方法调用都会创建一个栈帧（Stack Frame）：

```
┌─────────────────────────────────────────────────────────────┐
│                      JVM 栈 (线程私有)                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │  栈帧 3 (当前方法)                                    │   │
│  │  ┌─────────────────┐  ┌─────────────────────────┐   │   │
│  │  │ 局部变量表       │  │ 操作数栈                 │   │   │
│  │  │ Local Variables │  │ Operand Stack           │   │   │
│  │  └─────────────────┘  └─────────────────────────┘   │   │
│  │  ┌─────────────────┐  ┌─────────────────────────┐   │   │
│  │  │ 动态链接         │  │ 方法返回地址             │   │   │
│  │  │ Dynamic Linking │  │ Return Address          │   │   │
│  │  └─────────────────┘  └─────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  栈帧 2                                              │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  栈帧 1 (main 方法)                                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

#### 4.2.2 局部变量表

存储方法参数和局部变量，以 **Slot（变量槽）** 为单位。

```java
public class LocalVariableDemo {
    
    // 实例方法：slot 0 = this
    public void instanceMethod(int a, long b) {
        // slot 0: this (引用类型，1 slot)
        // slot 1: a (int，1 slot)
        // slot 2-3: b (long，2 slots)
        double c = 1.0;
        // slot 4-5: c (double，2 slots)
    }
    
    // 静态方法：没有 this
    public static void staticMethod(int a) {
        // slot 0: a (int，1 slot)
        int b = 10;
        // slot 1: b (int，1 slot)
    }
}
```

**Slot 复用**：

```java
public void slotReuse() {
    {
        int a = 1;
        // slot 1: a
    }
    // a 的作用域结束，slot 1 可以复用
    int b = 2;
    // slot 1: b (复用了 a 的 slot)
}
```

#### 4.2.3 操作数栈

用于执行字节码指令时存放操作数，是一个后进先出（LIFO）栈。

```java
// 源代码
public int calculate() {
    int a = 1;
    int b = 2;
    return a + b;
}

// 对应的字节码执行过程
// iconst_1      // 将常量 1 压入操作数栈
// istore_1      // 弹出栈顶，存入局部变量表 slot 1 (a)
// iconst_2      // 将常量 2 压入操作数栈
// istore_2      // 弹出栈顶，存入局部变量表 slot 2 (b)
// iload_1       // 将 slot 1 的值压入操作数栈
// iload_2       // 将 slot 2 的值压入操作数栈
// iadd          // 弹出两个值相加，结果压入栈
// ireturn       // 返回栈顶值
```

```
操作数栈变化过程：

iconst_1:  [1]
istore_1:  []
iconst_2:  [2]
istore_2:  []
iload_1:   [1]
iload_2:   [1, 2]
iadd:      [3]
ireturn:   返回 3
```

#### 4.2.4 栈相关异常

```java
// 1. StackOverflowError - 栈深度超过限制
public class StackOverflowDemo {
    private int depth = 0;
    
    public void recursiveCall() {
        depth++;
        recursiveCall(); // 无限递归
    }
    
    public static void main(String[] args) {
        StackOverflowDemo demo = new StackOverflowDemo();
        try {
            demo.recursiveCall();
        } catch (StackOverflowError e) {
            System.out.println("栈溢出，深度: " + demo.depth);
            // 默认栈大小约 512KB-1MB，深度通常在几千到几万
        }
    }
}

// 2. OutOfMemoryError - 无法申请足够的栈内存
// 通常发生在创建大量线程时
public class StackOOMDemo {
    public static void main(String[] args) {
        while (true) {
            new Thread(() -> {
                try {
                    Thread.sleep(Long.MAX_VALUE);
                } catch (InterruptedException e) {}
            }).start();
        }
        // 最终抛出: java.lang.OutOfMemoryError: unable to create new native thread
    }
}
```


### 4.3 本地方法栈 (Native Method Stack)

**作用**：为 Native 方法（用 C/C++ 实现）服务，与虚拟机栈类似。

```java
public class NativeMethodDemo {
    // native 方法由本地方法栈执行
    public native void nativeMethod();
    
    // 常见的 native 方法
    public static void main(String[] args) {
        // Object.hashCode() 是 native 方法
        Object obj = new Object();
        int hash = obj.hashCode();
        
        // System.currentTimeMillis() 是 native 方法
        long time = System.currentTimeMillis();
        
        // Thread.sleep() 是 native 方法
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {}
    }
}
```

### 4.4 堆 (Heap)

**特点**：
- 线程共享
- JVM 管理的最大内存区域
- 垃圾回收的主要区域
- 可以物理上不连续，逻辑上连续

#### 4.4.1 堆内存结构（Java 8+）

```
┌─────────────────────────────────────────────────────────────────────┐
│                           堆 (Heap)                                  │
├─────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                      年轻代 (Young Generation)                 │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │  │
│  │  │    Eden     │  │ Survivor 0  │  │    Survivor 1       │    │  │
│  │  │   (80%)     │  │   (10%)     │  │      (10%)          │    │  │
│  │  │  新对象分配  │  │    From     │  │       To            │    │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                      老年代 (Old Generation)                   │  │
│  │                      存放长期存活的对象                         │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘

默认比例：
- 年轻代 : 老年代 = 1 : 2 (-XX:NewRatio=2)
- Eden : S0 : S1 = 8 : 1 : 1 (-XX:SurvivorRatio=8)
```

#### 4.4.2 对象分配流程

```
                    new Object()
                         │
                         ▼
              ┌─────────────────────┐
              │ 尝试栈上分配 (逃逸分析) │
              └─────────────────────┘
                         │ 不满足条件
                         ▼
              ┌─────────────────────┐
              │ 尝试 TLAB 分配       │  ← Thread Local Allocation Buffer
              └─────────────────────┘     每个线程私有的 Eden 区域
                         │ TLAB 空间不足
                         ▼
              ┌─────────────────────┐
              │ 是否大对象？          │
              └─────────────────────┘
                    │         │
              是    │         │ 否
                    ▼         ▼
         ┌──────────────┐  ┌──────────────┐
         │ 直接进入老年代 │  │ Eden 区分配   │
         └──────────────┘  └──────────────┘
```

```java
// 对象分配示例
public class ObjectAllocationDemo {
    
    public static void main(String[] args) {
        // 1. 小对象 - 优先在 Eden 区分配
        byte[] small = new byte[1024]; // 1KB
        
        // 2. 大对象 - 直接进入老年代
        // -XX:PretenureSizeThreshold=3145728 (3MB)
        byte[] large = new byte[4 * 1024 * 1024]; // 4MB
        
        // 3. 长期存活对象 - 晋升到老年代
        // 对象年龄达到阈值后晋升
        // -XX:MaxTenuringThreshold=15 (默认)
    }
}
```

#### 4.4.3 堆内存参数

```bash
# 堆大小设置
-Xms512m          # 初始堆大小 (建议与 -Xmx 相同，避免动态扩展)
-Xmx1024m         # 最大堆大小

# 年轻代设置
-Xmn256m          # 年轻代大小
-XX:NewRatio=2    # 老年代:年轻代 = 2:1
-XX:SurvivorRatio=8  # Eden:S0:S1 = 8:1:1

# 大对象阈值
-XX:PretenureSizeThreshold=3145728  # 超过 3MB 直接进入老年代

# 晋升年龄
-XX:MaxTenuringThreshold=15  # 对象年龄达到 15 晋升老年代

# TLAB 设置
-XX:+UseTLAB      # 启用 TLAB (默认开启)
-XX:TLABSize=512k # TLAB 大小
```

### 4.5 方法区 / 元空间 (Method Area / Metaspace)

#### 4.5.1 演进历史

```
┌─────────────────────────────────────────────────────────────────────┐
│  Java 7 及之前                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  永久代 (PermGen) - 堆内存的一部分                              │  │
│  │  存储：类信息、常量池、静态变量、JIT 编译代码                    │  │
│  │  问题：大小固定，容易 OOM                                       │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ Java 8
┌─────────────────────────────────────────────────────────────────────┐
│  Java 8+                                                             │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  元空间 (Metaspace) - 使用本地内存 (Native Memory)             │  │
│  │  存储：类信息、方法信息、字段信息                               │  │
│  │  优点：默认无上限，自动扩展                                     │  │
│  └───────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  堆中的字符串常量池                                            │  │
│  │  静态变量也移到堆中                                            │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

#### 4.5.2 方法区存储内容

```java
public class MethodAreaContent {
    
    // 1. 类信息 - 存储在元空间
    // - 类的全限定名
    // - 父类的全限定名
    // - 实现的接口
    // - 访问修饰符
    
    // 2. 字段信息 - 存储在元空间
    private int instanceField;
    private static int staticField;
    
    // 3. 方法信息 - 存储在元空间
    // - 方法名、返回类型、参数
    // - 字节码、操作数栈深度、局部变量表大小
    public void method() {}
    
    // 4. 运行时常量池 - 存储在元空间
    // - 字面量：文本字符串、final 常量
    // - 符号引用：类和接口的全限定名、字段和方法的名称和描述符
    
    // 5. 字符串常量池 - Java 7+ 移到堆中
    String s1 = "hello"; // 字符串字面量
    String s2 = new String("world"); // 堆中创建对象
}
```

#### 4.5.3 元空间参数

```bash
# 元空间设置
-XX:MetaspaceSize=128m      # 初始元空间大小
-XX:MaxMetaspaceSize=256m   # 最大元空间大小 (默认无限制)

# 类元数据区域
-XX:CompressedClassSpaceSize=256m  # 压缩类空间大小

# 查看元空间使用情况
-XX:+PrintGCDetails
```


### 4.6 字符串常量池详解

#### 4.6.1 字符串创建方式

```java
public class StringPoolDemo {
    
    public static void main(String[] args) {
        // 方式 1：字面量 - 直接使用常量池
        String s1 = "hello";
        String s2 = "hello";
        System.out.println(s1 == s2); // true，同一个常量池对象
        
        // 方式 2：new - 在堆中创建新对象
        String s3 = new String("hello");
        System.out.println(s1 == s3); // false，不同对象
        System.out.println(s1.equals(s3)); // true，内容相同
        
        // 方式 3：intern() - 返回常量池中的引用
        String s4 = s3.intern();
        System.out.println(s1 == s4); // true
        
        // 方式 4：拼接
        String s5 = "hel" + "lo"; // 编译期优化，等同于 "hello"
        System.out.println(s1 == s5); // true
        
        String s6 = "hel";
        String s7 = s6 + "lo"; // 运行时拼接，创建新对象
        System.out.println(s1 == s7); // false
    }
}
```

#### 4.6.2 intern() 方法详解

```java
public class InternDemo {
    
    public static void main(String[] args) {
        // Java 7+ 的 intern() 行为
        
        // 情况 1：常量池中已存在
        String s1 = "hello";
        String s2 = new String("hello");
        String s3 = s2.intern();
        System.out.println(s1 == s3); // true
        
        // 情况 2：常量池中不存在
        // Java 7+：intern() 不会复制字符串到常量池
        // 而是在常量池中记录堆中对象的引用
        String s4 = new String("ja") + new String("va");
        // 此时常量池中没有 "java"
        String s5 = s4.intern();
        // s4.intern() 将 s4 的引用放入常量池
        System.out.println(s4 == s5); // true (Java 7+)
        
        String s6 = "java";
        System.out.println(s5 == s6); // true
    }
}
```

#### 4.6.3 字符串内存分析

```
new String("hello") 创建了几个对象？

答案：1 个或 2 个

情况 1：常量池中已有 "hello"
┌─────────────────────────────────────────────────────────────┐
│  堆                                                          │
│  ┌─────────────────┐                                        │
│  │ String 对象      │ ← new 创建的对象 (1 个)                 │
│  │ value ──────────┼──→ 指向常量池中的 char[]                │
│  └─────────────────┘                                        │
│                                                              │
│  字符串常量池                                                 │
│  ┌─────────────────┐                                        │
│  │ "hello"         │ ← 已存在，不创建                        │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘

情况 2：常量池中没有 "hello"
┌─────────────────────────────────────────────────────────────┐
│  堆                                                          │
│  ┌─────────────────┐                                        │
│  │ String 对象      │ ← new 创建的对象 (1 个)                 │
│  └─────────────────┘                                        │
│                                                              │
│  字符串常量池                                                 │
│  ┌─────────────────┐                                        │
│  │ "hello"         │ ← 新创建 (1 个)                         │
│  └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

### 4.7 直接内存 (Direct Memory)

**特点**：
- 不属于 JVM 运行时数据区
- 使用 Native 函数直接分配堆外内存
- 通过 DirectByteBuffer 操作

```java
import java.nio.ByteBuffer;

public class DirectMemoryDemo {
    
    public static void main(String[] args) {
        // 分配直接内存
        // 不受 -Xmx 限制，但受 -XX:MaxDirectMemorySize 限制
        ByteBuffer directBuffer = ByteBuffer.allocateDirect(1024 * 1024); // 1MB
        
        // 写入数据
        directBuffer.put("Hello Direct Memory".getBytes());
        
        // 读取数据
        directBuffer.flip();
        byte[] bytes = new byte[directBuffer.remaining()];
        directBuffer.get(bytes);
        System.out.println(new String(bytes));
        
        // 直接内存 vs 堆内存
        // 直接内存：分配慢，读写快（零拷贝）
        // 堆内存：分配快，读写需要一次拷贝
    }
}
```

```bash
# 直接内存参数
-XX:MaxDirectMemorySize=256m  # 最大直接内存大小
```

---

## 5. 垃圾回收 (GC)

### 5.1 如何判断对象可以回收？

#### 5.1.1 引用计数法（JVM 不使用）

```java
// 引用计数法的问题：循环引用
public class ReferenceCountingGC {
    public Object instance = null;
    
    public static void main(String[] args) {
        ReferenceCountingGC objA = new ReferenceCountingGC();
        ReferenceCountingGC objB = new ReferenceCountingGC();
        
        // 循环引用
        objA.instance = objB;
        objB.instance = objA;
        
        // 置空引用
        objA = null;
        objB = null;
        
        // 如果使用引用计数法，这两个对象永远不会被回收
        // 因为它们互相引用，计数器不为 0
        System.gc();
    }
}
```

#### 5.1.2 可达性分析算法（JVM 使用）

从 **GC Roots** 出发，沿着引用链向下搜索，不可达的对象即为可回收对象。

```
                    GC Roots
                       │
           ┌───────────┼───────────┐
           │           │           │
           ▼           ▼           ▼
        ┌─────┐     ┌─────┐     ┌─────┐
        │ Obj1│     │ Obj2│     │ Obj3│
        └──┬──┘     └──┬──┘     └─────┘
           │           │
           ▼           ▼
        ┌─────┐     ┌─────┐     ┌─────┐
        │ Obj4│     │ Obj5│     │ Obj6│ ← 不可达，可回收
        └─────┘     └─────┘     └──┬──┘
                                   │
                                   ▼
                                ┌─────┐
                                │ Obj7│ ← 不可达，可回收
                                └─────┘
```

**GC Roots 包括**：

```java
public class GCRootsDemo {
    
    // 1. 虚拟机栈中引用的对象
    public void stackReference() {
        Object obj = new Object(); // obj 是 GC Root
    }
    
    // 2. 方法区中类静态属性引用的对象
    private static Object staticObj = new Object(); // staticObj 是 GC Root
    
    // 3. 方法区中常量引用的对象
    private static final Object CONSTANT = new Object(); // CONSTANT 是 GC Root
    
    // 4. 本地方法栈中 JNI 引用的对象
    // native 方法中引用的对象
    
    // 5. 被同步锁持有的对象
    public void synchronizedMethod() {
        Object lock = new Object();
        synchronized (lock) { // lock 是 GC Root
            // ...
        }
    }
    
    // 6. JVM 内部引用
    // 如基本类型对应的 Class 对象、常驻异常对象、系统类加载器等
}
```


### 5.2 四种引用类型

```java
import java.lang.ref.*;

public class ReferenceTypesDemo {
    
    public static void main(String[] args) {
        
        // 1. 强引用 (Strong Reference)
        // 最常见的引用，只要强引用存在，对象就不会被回收
        Object strongRef = new Object();
        strongRef = null; // 只有置空后才可能被回收
        
        // 2. 软引用 (Soft Reference)
        // 内存不足时才会被回收，适合做缓存
        SoftReference<byte[]> softRef = new SoftReference<>(new byte[1024 * 1024]);
        System.out.println(softRef.get()); // 可能返回对象或 null
        
        // 3. 弱引用 (Weak Reference)
        // 下次 GC 时一定会被回收，不管内存是否充足
        WeakReference<Object> weakRef = new WeakReference<>(new Object());
        System.gc();
        System.out.println(weakRef.get()); // 很可能是 null
        
        // 4. 虚引用 (Phantom Reference)
        // 最弱的引用，无法通过虚引用获取对象
        // 主要用于跟踪对象被回收的状态
        ReferenceQueue<Object> queue = new ReferenceQueue<>();
        PhantomReference<Object> phantomRef = new PhantomReference<>(new Object(), queue);
        System.out.println(phantomRef.get()); // 永远返回 null
    }
}
```

**引用强度对比**：

| 引用类型 | 回收时机 | 用途 |
|---------|---------|------|
| 强引用 | 永不回收（除非置空） | 普通对象引用 |
| 软引用 | 内存不足时回收 | 缓存 |
| 弱引用 | 下次 GC 时回收 | WeakHashMap、ThreadLocal |
| 虚引用 | 随时可能回收 | 跟踪对象回收状态 |

### 5.3 垃圾回收算法

#### 5.3.1 标记-清除算法 (Mark-Sweep)

```
标记阶段：标记所有需要回收的对象
┌─────────────────────────────────────────────────────────────┐
│  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐   │
│  │ A │  │ B │  │ C │  │ D │  │ E │  │ F │  │ G │  │ H │   │
│  │   │  │ X │  │   │  │ X │  │   │  │ X │  │   │  │ X │   │
│  └───┘  └───┘  └───┘  └───┘  └───┘  └───┘  └───┘  └───┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ 清除
┌─────────────────────────────────────────────────────────────┐
│  ┌───┐        ┌───┐        ┌───┐        ┌───┐              │
│  │ A │  空闲  │ C │  空闲  │ E │  空闲  │ G │  空闲        │
│  └───┘        └───┘        └───┘        └───┘              │
└─────────────────────────────────────────────────────────────┘

优点：简单
缺点：
1. 效率不高（标记和清除都需要遍历）
2. 产生内存碎片
```

#### 5.3.2 复制算法 (Copying)

```
将内存分为两块，每次只使用一块，GC 时将存活对象复制到另一块

GC 前：
┌─────────────────────────────┬─────────────────────────────┐
│         From 区              │          To 区 (空)         │
│  ┌───┐┌───┐┌───┐┌───┐┌───┐ │                             │
│  │ A ││ B ││ C ││ D ││ E │ │                             │
│  │   ││ X ││   ││ X ││   │ │                             │
│  └───┘└───┘└───┘└───┘└───┘ │                             │
└─────────────────────────────┴─────────────────────────────┘
                              │
                              ▼ 复制存活对象
┌─────────────────────────────┬─────────────────────────────┐
│         From 区 (清空)       │          To 区              │
│                             │  ┌───┐┌───┐┌───┐           │
│                             │  │ A ││ C ││ E │           │
│                             │  └───┘└───┘└───┘           │
└─────────────────────────────┴─────────────────────────────┘

优点：
1. 没有内存碎片
2. 效率高（只需遍历存活对象）

缺点：
1. 内存利用率只有 50%
2. 存活对象多时效率下降

适用场景：年轻代（存活对象少）
```

#### 5.3.3 标记-整理算法 (Mark-Compact)

```
标记阶段：标记所有存活对象
┌─────────────────────────────────────────────────────────────┐
│  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐  ┌───┐   │
│  │ A │  │ B │  │ C │  │ D │  │ E │  │ F │  │ G │  │ H │   │
│  │ ✓ │  │ X │  │ ✓ │  │ X │  │ ✓ │  │ X │  │ ✓ │  │ X │   │
│  └───┘  └───┘  └───┘  └───┘  └───┘  └───┘  └───┘  └───┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ 整理（移动存活对象到一端）
┌─────────────────────────────────────────────────────────────┐
│  ┌───┐┌───┐┌───┐┌───┐                                      │
│  │ A ││ C ││ E ││ G │              空闲空间                 │
│  └───┘└───┘└───┘└───┘                                      │
└─────────────────────────────────────────────────────────────┘

优点：
1. 没有内存碎片
2. 内存利用率高

缺点：
1. 需要移动对象，效率较低
2. 移动时需要暂停用户线程 (STW)

适用场景：老年代（存活对象多）
```

#### 5.3.4 分代收集算法

```
根据对象存活周期不同，将堆分为年轻代和老年代，采用不同的算法

┌─────────────────────────────────────────────────────────────┐
│  年轻代 (Young Generation)                                   │
│  特点：对象存活率低，朝生夕死                                  │
│  算法：复制算法                                               │
│  ┌─────────────────┐  ┌────────┐  ┌────────┐               │
│  │      Eden       │  │   S0   │  │   S1   │               │
│  │    (80%)        │  │ (10%)  │  │ (10%)  │               │
│  └─────────────────┘  └────────┘  └────────┘               │
│                                                              │
│  Minor GC / Young GC：回收年轻代                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ 对象年龄达到阈值
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  老年代 (Old Generation)                                     │
│  特点：对象存活率高                                           │
│  算法：标记-清除 或 标记-整理                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    老年代空间                         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  Major GC / Old GC：回收老年代                               │
│  Full GC：回收整个堆 + 方法区                                 │
└─────────────────────────────────────────────────────────────┘
```


### 5.4 垃圾回收器

#### 5.4.1 垃圾回收器概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                        垃圾回收器                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  年轻代收集器          老年代收集器           整堆收集器              │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐         │
│  │   Serial    │─────→│ Serial Old  │      │     G1      │         │
│  └─────────────┘      └─────────────┘      └─────────────┘         │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐         │
│  │   ParNew    │─────→│     CMS     │      │     ZGC     │         │
│  └─────────────┘      └─────────────┘      │  (Java 11+) │         │
│  ┌─────────────┐      ┌─────────────┐      └─────────────┘         │
│  │  Parallel   │─────→│Parallel Old │      ┌─────────────┐         │
│  │  Scavenge   │      │             │      │  Shenandoah │         │
│  └─────────────┘      └─────────────┘      │  (Java 12+) │         │
│                                            └─────────────┘         │
│                                                                      │
│  ───→ 表示可以配合使用                                               │
└─────────────────────────────────────────────────────────────────────┘
```

#### 5.4.2 Serial 收集器

**特点**：单线程、简单高效、Stop-The-World

```
用户线程: ═══════════╗                    ╔═══════════════
                     ║     STW            ║
GC 线程:             ╚════════════════════╝
                          Serial GC

适用场景：
- 单核 CPU
- 小内存应用
- Client 模式

启用参数：
-XX:+UseSerialGC
```

#### 5.4.3 ParNew 收集器

**特点**：Serial 的多线程版本，常与 CMS 配合

```
用户线程: ═══════════╗                    ╔═══════════════
                     ║     STW            ║
GC 线程 1:           ╠════════════════════╣
GC 线程 2:           ╠════════════════════╣
GC 线程 3:           ╠════════════════════╣
                          ParNew GC

启用参数：
-XX:+UseParNewGC
-XX:ParallelGCThreads=4  # GC 线程数
```

#### 5.4.4 Parallel Scavenge 收集器

**特点**：关注吞吐量（用户代码运行时间 / 总时间）

```java
// 吞吐量 = 用户代码时间 / (用户代码时间 + GC 时间)
// 例如：99% 吞吐量意味着 100 秒中只有 1 秒在 GC

// 启用参数
// -XX:+UseParallelGC (年轻代)
// -XX:+UseParallelOldGC (老年代)

// 吞吐量控制
// -XX:MaxGCPauseMillis=100  // 最大 GC 停顿时间
// -XX:GCTimeRatio=99        // 吞吐量大小 (1/(1+99)=1% GC 时间)

// 自适应调节
// -XX:+UseAdaptiveSizePolicy  // 自动调整 Eden/Survivor 比例
```

#### 5.4.5 CMS 收集器 (Concurrent Mark Sweep)

**特点**：低停顿、并发收集、标记-清除算法

```
CMS 收集过程（4 个阶段）：

用户线程: ═══╗     ╔═══════════════════════════╗     ╔═══════
            ║ STW ║                           ║ STW ║
            ║     ║                           ║     ║
GC 线程:    ╠═════╬═══════════════════════════╬═════╣
            │     │                           │     │
         初始标记  │       并发标记             │ 重新标记
         (很快)   │    (与用户线程并发)         │ (较快)
                  │                           │
                  └───────────────────────────┘
                         并发清除
                    (与用户线程并发)

阶段说明：
1. 初始标记 (Initial Mark) - STW
   - 标记 GC Roots 直接关联的对象
   - 速度很快

2. 并发标记 (Concurrent Mark)
   - 从 GC Roots 开始遍历整个对象图
   - 与用户线程并发执行

3. 重新标记 (Remark) - STW
   - 修正并发标记期间变动的对象
   - 使用增量更新算法

4. 并发清除 (Concurrent Sweep)
   - 清除标记的垃圾对象
   - 与用户线程并发执行
```

```bash
# CMS 参数
-XX:+UseConcMarkSweepGC           # 启用 CMS
-XX:CMSInitiatingOccupancyFraction=70  # 老年代使用 70% 时触发 CMS
-XX:+UseCMSCompactAtFullCollection     # Full GC 时压缩整理
-XX:CMSFullGCsBeforeCompaction=5       # 5 次 Full GC 后压缩
-XX:+CMSParallelRemarkEnabled          # 并行重新标记
```

**CMS 的问题**：

```java
// 1. CPU 敏感 - 并发阶段占用 CPU 资源
// 默认 GC 线程数 = (CPU 核数 + 3) / 4

// 2. 浮动垃圾 - 并发清除阶段产生的新垃圾
// 需要预留空间，否则触发 Concurrent Mode Failure

// 3. 内存碎片 - 标记-清除算法的固有问题
// 可能触发 Full GC 进行压缩
```

#### 5.4.6 G1 收集器 (Garbage First)

**特点**：面向服务端、可预测停顿、Region 化内存布局

```
G1 内存布局：

┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│  E  │  E  │  S  │  O  │  O  │  H  │  E  │  O  │
├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤
│  O  │  E  │  O  │  S  │  E  │  H  │  O  │  E  │
├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤
│  E  │  O  │  E  │  O  │  O  │  E  │  S  │  O  │
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘

E = Eden Region
S = Survivor Region
O = Old Region
H = Humongous Region (大对象，超过 Region 50%)

特点：
- 堆被划分为多个大小相等的 Region (1MB-32MB)
- Region 可以动态分配为 Eden/Survivor/Old
- 优先回收垃圾最多的 Region (Garbage First)
```

```
G1 收集过程：

1. 年轻代 GC (Young GC)
   - 所有 Eden Region 满时触发
   - 存活对象复制到 Survivor 或 Old Region

2. 并发标记周期
   ┌─────────────────────────────────────────────────────────┐
   │ 初始标记 → 并发标记 → 最终标记 → 筛选回收              │
   │  (STW)    (并发)     (STW)     (STW)                   │
   └─────────────────────────────────────────────────────────┘

3. 混合回收 (Mixed GC)
   - 回收所有年轻代 + 部分老年代 Region
   - 根据停顿时间目标选择回收的 Region
```

```bash
# G1 参数
-XX:+UseG1GC                      # 启用 G1 (Java 9+ 默认)
-XX:MaxGCPauseMillis=200          # 目标停顿时间 (默认 200ms)
-XX:G1HeapRegionSize=4m           # Region 大小 (1-32MB，2 的幂)
-XX:G1NewSizePercent=5            # 年轻代最小比例
-XX:G1MaxNewSizePercent=60        # 年轻代最大比例
-XX:InitiatingHeapOccupancyPercent=45  # 触发并发标记的堆占用率
-XX:G1MixedGCCountTarget=8        # 混合回收次数目标
```

#### 5.4.7 ZGC 收集器 (Java 11+)

**特点**：超低延迟（< 10ms）、支持 TB 级堆、并发整理

```bash
# ZGC 参数
-XX:+UseZGC                       # 启用 ZGC
-XX:ZCollectionInterval=5         # GC 周期间隔 (秒)
-Xmx16g                           # 堆大小

# ZGC 特点
# - 停顿时间不随堆大小增加
# - 使用着色指针 (Colored Pointers)
# - 使用读屏障 (Load Barrier)
# - 支持 NUMA 架构
```

#### 5.4.8 收集器选择建议

| 场景 | 推荐收集器 | 参数 |
|------|-----------|------|
| 小内存 (< 100MB) | Serial | -XX:+UseSerialGC |
| 单核 CPU | Serial | -XX:+UseSerialGC |
| 多核 + 高吞吐量 | Parallel | -XX:+UseParallelGC |
| 多核 + 低延迟 | CMS / G1 | -XX:+UseConcMarkSweepGC / -XX:+UseG1GC |
| 大堆 (> 4GB) | G1 | -XX:+UseG1GC |
| 超大堆 + 超低延迟 | ZGC | -XX:+UseZGC |


### 5.5 GC 日志分析

#### 5.5.1 开启 GC 日志

```bash
# Java 8
-XX:+PrintGCDetails              # 打印 GC 详情
-XX:+PrintGCDateStamps           # 打印 GC 时间戳
-XX:+PrintGCTimeStamps           # 打印 GC 相对时间
-Xloggc:/path/to/gc.log          # GC 日志文件路径
-XX:+UseGCLogFileRotation        # 日志文件轮转
-XX:NumberOfGCLogFiles=5         # 保留日志文件数
-XX:GCLogFileSize=10M            # 单个日志文件大小

# Java 9+
-Xlog:gc*:file=/path/to/gc.log:time,uptime,level,tags
```

#### 5.5.2 GC 日志解读

```
# Young GC 日志示例 (Parallel GC)
2024-01-15T10:30:45.123+0800: 1.234: [GC (Allocation Failure) 
    [PSYoungGen: 65536K->10752K(76288K)] 
    65536K->15848K(251392K), 0.0123456 secs] 
    [Times: user=0.03 sys=0.01, real=0.01 secs]

解读：
┌─────────────────────────────────────────────────────────────────────┐
│ 2024-01-15T10:30:45.123+0800  → GC 发生的时间                        │
│ 1.234                         → JVM 启动后的秒数                     │
│ GC (Allocation Failure)       → GC 类型和原因                        │
│ PSYoungGen                    → 年轻代收集器 (Parallel Scavenge)     │
│ 65536K->10752K(76288K)        → 年轻代: 回收前->回收后(总大小)        │
│ 65536K->15848K(251392K)       → 整个堆: 回收前->回收后(总大小)        │
│ 0.0123456 secs                → GC 耗时                             │
│ user=0.03                     → 用户态 CPU 时间                      │
│ sys=0.01                      → 内核态 CPU 时间                      │
│ real=0.01                     → 实际耗时 (墙钟时间)                  │
└─────────────────────────────────────────────────────────────────────┘
```

```
# Full GC 日志示例
2024-01-15T10:35:12.456+0800: 5.678: [Full GC (Ergonomics) 
    [PSYoungGen: 10752K->0K(76288K)] 
    [ParOldGen: 150000K->95000K(175104K)] 
    160752K->95000K(251392K), 
    [Metaspace: 35000K->35000K(1081344K)], 
    0.2345678 secs]

解读：
┌─────────────────────────────────────────────────────────────────────┐
│ Full GC (Ergonomics)          → Full GC，JVM 自动触发               │
│ PSYoungGen: 10752K->0K        → 年轻代被完全清空                     │
│ ParOldGen: 150000K->95000K    → 老年代回收了约 55MB                  │
│ Metaspace: 35000K->35000K     → 元空间没有变化                       │
│ 0.2345678 secs                → Full GC 耗时较长                    │
└─────────────────────────────────────────────────────────────────────┘
```

#### 5.5.3 GC 日志分析工具

```bash
# 1. GCViewer - 图形化分析工具
java -jar gcviewer.jar gc.log

# 2. GCEasy - 在线分析工具
# https://gceasy.io/

# 3. JClarity - 商业工具

# 4. 命令行快速分析
# 统计 GC 次数
grep -c "GC" gc.log

# 统计 Full GC 次数
grep -c "Full GC" gc.log

# 查看最长 GC 停顿
grep "GC" gc.log | awk '{print $NF}' | sort -rn | head -10
```

---

## 6. JVM 调优

### 6.1 调优目标

```
┌─────────────────────────────────────────────────────────────────────┐
│                        JVM 调优目标                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. 低延迟 (Low Latency)                                            │
│     - 减少 GC 停顿时间                                               │
│     - 适用于：交互式应用、实时系统                                    │
│                                                                      │
│  2. 高吞吐量 (High Throughput)                                       │
│     - 最大化应用运行时间                                             │
│     - 适用于：批处理、后台计算                                        │
│                                                                      │
│  3. 低内存占用 (Low Footprint)                                       │
│     - 减少内存使用                                                   │
│     - 适用于：容器环境、嵌入式系统                                    │
│                                                                      │
│  注意：这三个目标往往相互制约，需要根据场景权衡                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 常用调优参数

#### 6.2.1 堆内存参数

```bash
# 堆大小
-Xms4g                    # 初始堆大小 (建议与 -Xmx 相同)
-Xmx4g                    # 最大堆大小

# 年轻代
-Xmn1g                    # 年轻代大小
-XX:NewRatio=2            # 老年代:年轻代 = 2:1
-XX:SurvivorRatio=8       # Eden:S0:S1 = 8:1:1

# 元空间
-XX:MetaspaceSize=256m    # 初始元空间大小
-XX:MaxMetaspaceSize=512m # 最大元空间大小

# 直接内存
-XX:MaxDirectMemorySize=256m

# 栈大小
-Xss256k                  # 每个线程的栈大小
```

#### 6.2.2 GC 相关参数

```bash
# 选择垃圾收集器
-XX:+UseSerialGC          # Serial
-XX:+UseParallelGC        # Parallel (Java 8 默认)
-XX:+UseConcMarkSweepGC   # CMS
-XX:+UseG1GC              # G1 (Java 9+ 默认)
-XX:+UseZGC               # ZGC (Java 11+)

# G1 调优
-XX:MaxGCPauseMillis=200  # 目标停顿时间
-XX:G1HeapRegionSize=4m   # Region 大小
-XX:InitiatingHeapOccupancyPercent=45  # 触发并发标记的阈值

# CMS 调优
-XX:CMSInitiatingOccupancyFraction=70  # 触发 CMS 的阈值
-XX:+UseCMSCompactAtFullCollection     # Full GC 时压缩

# 并行 GC 线程数
-XX:ParallelGCThreads=4   # 并行 GC 线程数
-XX:ConcGCThreads=2       # 并发 GC 线程数
```

#### 6.2.3 JIT 编译参数

```bash
# 编译模式
-Xint                     # 纯解释执行
-Xcomp                    # 纯编译执行
-Xmixed                   # 混合模式 (默认)

# 编译阈值
-XX:CompileThreshold=10000  # 方法调用次数阈值

# 分层编译
-XX:+TieredCompilation    # 启用分层编译 (默认开启)

# 代码缓存
-XX:ReservedCodeCacheSize=256m  # 代码缓存大小
```

### 6.3 调优实战案例

#### 6.3.1 案例一：频繁 Young GC

```java
// 问题代码：大量创建临时对象
public class FrequentYoungGC {
    public void processData() {
        for (int i = 0; i < 1000000; i++) {
            // 每次循环创建新字符串
            String data = "data" + i;
            process(data);
        }
    }
}

// 优化方案
public class OptimizedYoungGC {
    public void processData() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000000; i++) {
            sb.setLength(0); // 重用 StringBuilder
            sb.append("data").append(i);
            process(sb.toString());
        }
    }
}
```

```bash
# JVM 参数调优
# 增大年轻代，减少 Young GC 频率
-Xmn512m
-XX:SurvivorRatio=8
```

#### 6.3.2 案例二：频繁 Full GC

```java
// 问题：大对象直接进入老年代，导致频繁 Full GC
public class FrequentFullGC {
    public void loadLargeData() {
        // 每次加载 10MB 数据
        byte[] data = new byte[10 * 1024 * 1024];
        processData(data);
    }
}

// 优化方案 1：使用对象池
public class OptimizedFullGC {
    private static final ThreadLocal<byte[]> BUFFER = 
        ThreadLocal.withInitial(() -> new byte[10 * 1024 * 1024]);
    
    public void loadLargeData() {
        byte[] data = BUFFER.get();
        // 重用 buffer
        processData(data);
    }
}

// 优化方案 2：分批处理
public class BatchProcessing {
    public void loadLargeData() {
        // 分批加载，每次 1MB
        for (int i = 0; i < 10; i++) {
            byte[] chunk = new byte[1024 * 1024];
            processChunk(chunk);
        }
    }
}
```

```bash
# JVM 参数调优
# 调整大对象阈值
-XX:PretenureSizeThreshold=5242880  # 5MB 以上才直接进入老年代

# 增大老年代
-XX:NewRatio=1  # 年轻代:老年代 = 1:1
```

#### 6.3.3 案例三：内存泄漏

```java
// 问题：静态集合持有对象引用，导致内存泄漏
public class MemoryLeakExample {
    private static List<Object> cache = new ArrayList<>();
    
    public void addToCache(Object obj) {
        cache.add(obj); // 对象永远不会被回收
    }
}

// 优化方案 1：使用弱引用
public class WeakReferenceCache {
    private static List<WeakReference<Object>> cache = new ArrayList<>();
    
    public void addToCache(Object obj) {
        cache.add(new WeakReference<>(obj));
    }
}

// 优化方案 2：使用 LRU 缓存
public class LRUCache {
    private static LinkedHashMap<String, Object> cache = 
        new LinkedHashMap<String, Object>(100, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return size() > 100; // 最多保留 100 个元素
            }
        };
}

// 优化方案 3：使用 Caffeine 缓存
// implementation 'com.github.ben-manes.caffeine:caffeine:3.1.8'
public class CaffeineCache {
    private static Cache<String, Object> cache = Caffeine.newBuilder()
        .maximumSize(1000)
        .expireAfterWrite(10, TimeUnit.MINUTES)
        .build();
}
```


### 6.4 JVM 监控工具

#### 6.4.1 命令行工具

```bash
# jps - 查看 Java 进程
jps -l                    # 显示完整类名
jps -v                    # 显示 JVM 参数

# jstat - 监控 JVM 统计信息
jstat -gc <pid> 1000 10   # 每秒输出 GC 信息，共 10 次
jstat -gcutil <pid> 1000  # 输出 GC 使用率百分比
jstat -class <pid>        # 类加载统计

# jstat 输出解读
#  S0C    S1C    S0U    S1U      EC       EU        OC         OU       MC     MU
# 1024.0 1024.0  0.0   512.0  8192.0   4096.0   20480.0    10240.0  35840.0 34567.0
# S0C/S1C: Survivor 0/1 容量
# S0U/S1U: Survivor 0/1 已使用
# EC/EU: Eden 容量/已使用
# OC/OU: Old 容量/已使用
# MC/MU: Metaspace 容量/已使用

# jinfo - 查看/修改 JVM 参数
jinfo -flags <pid>        # 查看所有 JVM 参数
jinfo -flag MaxHeapSize <pid>  # 查看特定参数
jinfo -flag +PrintGC <pid>     # 动态开启 GC 日志

# jmap - 内存映射工具
jmap -heap <pid>          # 查看堆配置和使用情况
jmap -histo <pid>         # 查看对象统计信息
jmap -histo:live <pid>    # 只统计存活对象 (会触发 Full GC)
jmap -dump:format=b,file=heap.hprof <pid>  # 导出堆转储

# jstack - 线程堆栈工具
jstack <pid>              # 打印线程堆栈
jstack -l <pid>           # 包含锁信息
jstack -F <pid>           # 强制打印 (进程无响应时)

# jcmd - 综合诊断工具 (推荐)
jcmd <pid> help           # 查看可用命令
jcmd <pid> VM.flags       # 查看 JVM 参数
jcmd <pid> GC.heap_info   # 查看堆信息
jcmd <pid> GC.run         # 触发 GC
jcmd <pid> Thread.print   # 打印线程堆栈
jcmd <pid> VM.native_memory summary  # 本地内存使用
```

#### 6.4.2 图形化工具

```bash
# JConsole - JDK 自带
jconsole

# VisualVM - 功能强大的可视化工具
# 下载: https://visualvm.github.io/
visualvm

# JMC (Java Mission Control) - 高级监控工具
# JDK 11+ 需要单独下载
jmc

# Arthas - 阿里开源的诊断工具
# 下载: https://arthas.aliyun.com/
java -jar arthas-boot.jar

# Arthas 常用命令
dashboard              # 实时面板
thread                 # 线程信息
jvm                    # JVM 信息
heapdump /tmp/dump.hprof  # 堆转储
trace com.example.MyClass myMethod  # 方法追踪
watch com.example.MyClass myMethod returnObj  # 观察返回值
```

#### 6.4.3 堆转储分析

```bash
# 生成堆转储
# 方式 1：jmap
jmap -dump:format=b,file=heap.hprof <pid>

# 方式 2：jcmd
jcmd <pid> GC.heap_dump /path/to/heap.hprof

# 方式 3：OOM 时自动生成
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/path/to/dump/

# 分析工具
# 1. Eclipse MAT (Memory Analyzer Tool)
# 2. VisualVM
# 3. JProfiler (商业)
# 4. YourKit (商业)
```

```java
// MAT 分析常用视图
// 1. Histogram - 对象数量和大小统计
// 2. Dominator Tree - 支配树，找出占用内存最多的对象
// 3. Leak Suspects - 自动分析可能的内存泄漏
// 4. OQL (Object Query Language) - 对象查询

// OQL 示例
// 查找所有 String 对象
SELECT * FROM java.lang.String

// 查找大于 1MB 的 byte 数组
SELECT * FROM byte[] WHERE @retainedHeapSize > 1048576

// 查找特定类的实例
SELECT * FROM com.example.MyClass WHERE field > 100
```

---

## 7. 常见错误与排查

### 7.1 OutOfMemoryError

#### 7.1.1 Java heap space

```java
// 原因：堆内存不足
// 场景：创建大量对象、内存泄漏

public class HeapOOM {
    public static void main(String[] args) {
        List<byte[]> list = new ArrayList<>();
        while (true) {
            list.add(new byte[1024 * 1024]); // 每次分配 1MB
        }
    }
}

// 错误信息
// java.lang.OutOfMemoryError: Java heap space
```

**排查步骤**：

```bash
# 1. 查看堆使用情况
jstat -gcutil <pid>

# 2. 生成堆转储
jmap -dump:format=b,file=heap.hprof <pid>

# 3. 使用 MAT 分析
# - 查看 Histogram，找出占用内存最多的对象
# - 查看 Dominator Tree，找出 GC Root 引用链
# - 使用 Leak Suspects 自动分析

# 4. 解决方案
# - 增大堆内存: -Xmx4g
# - 优化代码，减少对象创建
# - 修复内存泄漏
```

#### 7.1.2 Metaspace

```java
// 原因：元空间不足
// 场景：加载大量类、动态生成类

public class MetaspaceOOM {
    public static void main(String[] args) {
        // 使用 CGLib 动态生成大量类
        while (true) {
            Enhancer enhancer = new Enhancer();
            enhancer.setSuperclass(Object.class);
            enhancer.setUseCache(false);
            enhancer.setCallback((MethodInterceptor) (obj, method, args1, proxy) -> 
                proxy.invokeSuper(obj, args1));
            enhancer.create();
        }
    }
}

// 错误信息
// java.lang.OutOfMemoryError: Metaspace
```

**解决方案**：

```bash
# 增大元空间
-XX:MaxMetaspaceSize=512m

# 排查类加载问题
jstat -class <pid>

# 查看加载的类
jcmd <pid> VM.classloader_stats
```

#### 7.1.3 Unable to create new native thread

```java
// 原因：无法创建更多线程
// 场景：创建大量线程、线程泄漏

public class ThreadOOM {
    public static void main(String[] args) {
        while (true) {
            new Thread(() -> {
                try {
                    Thread.sleep(Long.MAX_VALUE);
                } catch (InterruptedException e) {}
            }).start();
        }
    }
}

// 错误信息
// java.lang.OutOfMemoryError: unable to create new native thread
```

**解决方案**：

```bash
# 1. 减小线程栈大小
-Xss256k

# 2. 增加系统线程限制 (Linux)
ulimit -u 65535

# 3. 使用线程池
ExecutorService executor = Executors.newFixedThreadPool(100);

# 4. 排查线程泄漏
jstack <pid> | grep -c "java.lang.Thread.State"
```

#### 7.1.4 Direct buffer memory

```java
// 原因：直接内存不足
// 场景：NIO 操作、Netty 等框架

public class DirectMemoryOOM {
    public static void main(String[] args) {
        List<ByteBuffer> list = new ArrayList<>();
        while (true) {
            list.add(ByteBuffer.allocateDirect(1024 * 1024));
        }
    }
}

// 错误信息
// java.lang.OutOfMemoryError: Direct buffer memory
```

**解决方案**：

```bash
# 增大直接内存限制
-XX:MaxDirectMemorySize=512m

# 手动释放直接内存
((DirectBuffer) buffer).cleaner().clean();
```

### 7.2 StackOverflowError

```java
// 原因：栈深度超过限制
// 场景：无限递归、递归深度过大

public class StackOverflow {
    private int depth = 0;
    
    public void recursiveCall() {
        depth++;
        recursiveCall();
    }
    
    public static void main(String[] args) {
        StackOverflow so = new StackOverflow();
        try {
            so.recursiveCall();
        } catch (StackOverflowError e) {
            System.out.println("栈溢出，深度: " + so.depth);
        }
    }
}

// 错误信息
// java.lang.StackOverflowError
```

**解决方案**：

```bash
# 1. 增大栈大小
-Xss1m

# 2. 优化递归为迭代
# 3. 使用尾递归优化 (Java 不支持，但可以手动改写)
```

```java
// 递归改迭代示例
// 递归版本
public int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// 迭代版本
public int factorialIterative(int n) {
    int result = 1;
    for (int i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}
```


### 7.3 死锁排查

```java
// 死锁示例
public class DeadLockDemo {
    private static final Object lockA = new Object();
    private static final Object lockB = new Object();
    
    public static void main(String[] args) {
        new Thread(() -> {
            synchronized (lockA) {
                System.out.println("Thread 1: 持有 lockA");
                try { Thread.sleep(100); } catch (InterruptedException e) {}
                synchronized (lockB) {
                    System.out.println("Thread 1: 持有 lockB");
                }
            }
        }, "Thread-1").start();
        
        new Thread(() -> {
            synchronized (lockB) {
                System.out.println("Thread 2: 持有 lockB");
                try { Thread.sleep(100); } catch (InterruptedException e) {}
                synchronized (lockA) {
                    System.out.println("Thread 2: 持有 lockA");
                }
            }
        }, "Thread-2").start();
    }
}
```

**排查方法**：

```bash
# 1. 使用 jstack
jstack <pid>

# 输出示例
# Found one Java-level deadlock:
# =============================
# "Thread-2":
#   waiting to lock monitor 0x00007f8b1c003828 (object 0x000000076ab96e80, a java.lang.Object),
#   which is held by "Thread-1"
# "Thread-1":
#   waiting to lock monitor 0x00007f8b1c006218 (object 0x000000076ab96e90, a java.lang.Object),
#   which is held by "Thread-2"

# 2. 使用 jcmd
jcmd <pid> Thread.print

# 3. 使用 Arthas
thread -b  # 查找阻塞线程
```

**预防死锁**：

```java
// 1. 固定加锁顺序
public void transfer(Account from, Account to, int amount) {
    // 按账户 ID 排序，保证加锁顺序一致
    Account first = from.getId() < to.getId() ? from : to;
    Account second = from.getId() < to.getId() ? to : from;
    
    synchronized (first) {
        synchronized (second) {
            from.withdraw(amount);
            to.deposit(amount);
        }
    }
}

// 2. 使用 tryLock 超时
public void transferWithTimeout(Account from, Account to, int amount) {
    while (true) {
        if (from.getLock().tryLock(1, TimeUnit.SECONDS)) {
            try {
                if (to.getLock().tryLock(1, TimeUnit.SECONDS)) {
                    try {
                        from.withdraw(amount);
                        to.deposit(amount);
                        return;
                    } finally {
                        to.getLock().unlock();
                    }
                }
            } finally {
                from.getLock().unlock();
            }
        }
        // 随机等待后重试
        Thread.sleep(new Random().nextInt(100));
    }
}
```

### 7.4 CPU 占用过高排查

```bash
# 1. 找出 CPU 占用最高的进程
top -c

# 2. 找出进程中 CPU 占用最高的线程
top -Hp <pid>

# 3. 将线程 ID 转换为 16 进制
printf "%x\n" <tid>

# 4. 使用 jstack 查找对应线程
jstack <pid> | grep -A 30 <tid_hex>

# 5. 使用 Arthas 一键排查
thread -n 3  # 显示 CPU 占用最高的 3 个线程
```

```java
// 常见原因
// 1. 死循环
while (true) {
    // 没有 sleep 或 wait
}

// 2. 正则表达式回溯
String regex = "(a+)+b";
"aaaaaaaaaaaaaaaaaaaaaaaaaaac".matches(regex); // 灾难性回溯

// 3. 频繁 GC
// 查看 GC 日志确认
```

### 7.5 常见错误速查表

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| OutOfMemoryError: Java heap space | 堆内存不足 | 增大 -Xmx，优化代码，修复内存泄漏 |
| OutOfMemoryError: Metaspace | 元空间不足 | 增大 -XX:MaxMetaspaceSize |
| OutOfMemoryError: unable to create new native thread | 线程数过多 | 减小 -Xss，使用线程池 |
| OutOfMemoryError: Direct buffer memory | 直接内存不足 | 增大 -XX:MaxDirectMemorySize |
| OutOfMemoryError: GC overhead limit exceeded | GC 时间过长 | 增大堆内存，优化代码 |
| StackOverflowError | 栈溢出 | 增大 -Xss，优化递归 |
| ClassNotFoundException | 类找不到 | 检查 classpath |
| NoClassDefFoundError | 类定义找不到 | 检查依赖，类加载顺序 |
| NoSuchMethodError | 方法找不到 | 检查依赖版本冲突 |

---

## 8. 实战案例

### 8.1 生产环境 JVM 配置模板

#### 8.1.1 Web 应用（4GB 内存）

```bash
# 基础配置
-Xms4g -Xmx4g                    # 堆大小固定，避免动态扩展
-Xmn1536m                        # 年轻代 1.5GB
-XX:MetaspaceSize=256m           # 元空间初始大小
-XX:MaxMetaspaceSize=512m        # 元空间最大大小

# G1 收集器
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200         # 目标停顿时间 200ms
-XX:G1HeapRegionSize=4m          # Region 大小

# GC 日志
-Xlog:gc*:file=/var/log/app/gc.log:time,uptime,level,tags:filecount=5,filesize=10m

# OOM 时生成堆转储
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/log/app/

# 其他
-XX:+UseStringDeduplication      # 字符串去重 (G1 专用)
-XX:+DisableExplicitGC           # 禁止显式 GC
```

#### 8.1.2 批处理应用（高吞吐量）

```bash
# 基础配置
-Xms8g -Xmx8g
-Xmn3g

# Parallel 收集器（高吞吐量）
-XX:+UseParallelGC
-XX:+UseParallelOldGC
-XX:ParallelGCThreads=8
-XX:GCTimeRatio=99               # 99% 时间用于应用

# 大页内存（提升性能）
-XX:+UseLargePages
```

#### 8.1.3 低延迟应用

```bash
# 基础配置
-Xms4g -Xmx4g

# ZGC（超低延迟）
-XX:+UseZGC
-XX:ZCollectionInterval=5        # GC 间隔

# 或使用 G1 + 低停顿配置
-XX:+UseG1GC
-XX:MaxGCPauseMillis=50          # 目标停顿 50ms
-XX:G1NewSizePercent=30          # 年轻代比例
-XX:G1MaxNewSizePercent=50
```

### 8.2 性能调优检查清单

```markdown
## JVM 调优检查清单

### 1. 基础检查
- [ ] 堆大小是否合理？(-Xms 和 -Xmx 是否相等？)
- [ ] 年轻代和老年代比例是否合适？
- [ ] 元空间大小是否设置？
- [ ] 是否开启 GC 日志？
- [ ] 是否配置 OOM 时生成堆转储？

### 2. GC 检查
- [ ] GC 频率是否正常？(Young GC < 10次/秒，Full GC < 1次/小时)
- [ ] GC 停顿时间是否可接受？
- [ ] 是否有内存泄漏？(老年代持续增长)
- [ ] 是否选择了合适的垃圾收集器？

### 3. 线程检查
- [ ] 线程数是否合理？
- [ ] 是否有死锁？
- [ ] 是否有线程泄漏？
- [ ] 线程池配置是否合理？

### 4. 代码检查
- [ ] 是否有大对象频繁创建？
- [ ] 是否有不必要的对象创建？
- [ ] 缓存是否有大小限制？
- [ ] 是否正确关闭资源？
```

### 8.3 常用 JVM 参数速查

```bash
# 内存相关
-Xms<size>                       # 初始堆大小
-Xmx<size>                       # 最大堆大小
-Xmn<size>                       # 年轻代大小
-Xss<size>                       # 线程栈大小
-XX:MetaspaceSize=<size>         # 元空间初始大小
-XX:MaxMetaspaceSize=<size>      # 元空间最大大小
-XX:MaxDirectMemorySize=<size>   # 直接内存大小

# GC 相关
-XX:+UseSerialGC                 # Serial 收集器
-XX:+UseParallelGC               # Parallel 收集器
-XX:+UseConcMarkSweepGC          # CMS 收集器
-XX:+UseG1GC                     # G1 收集器
-XX:+UseZGC                      # ZGC 收集器
-XX:MaxGCPauseMillis=<ms>        # 目标停顿时间
-XX:ParallelGCThreads=<n>        # 并行 GC 线程数

# 日志相关
-Xlog:gc*:file=<path>            # GC 日志 (Java 9+)
-XX:+PrintGCDetails              # GC 详情 (Java 8)
-XX:+HeapDumpOnOutOfMemoryError  # OOM 时生成堆转储
-XX:HeapDumpPath=<path>          # 堆转储路径

# 调试相关
-XX:+PrintFlagsFinal             # 打印所有 JVM 参数
-XX:NativeMemoryTracking=summary # 本地内存跟踪
```

---

## 总结

JVM 是 Java 程序运行的基石，理解 JVM 的工作原理对于编写高性能、稳定的 Java 应用至关重要。

**核心知识点回顾**：

1. **类加载机制**：加载 → 验证 → 准备 → 解析 → 初始化，双亲委派保证安全性
2. **运行时数据区**：堆（对象）、栈（方法调用）、方法区（类信息）、程序计数器
3. **垃圾回收**：可达性分析、分代收集、各种 GC 算法和收集器
4. **JVM 调优**：根据场景选择合适的收集器和参数，监控和分析 GC 日志
5. **问题排查**：OOM、死锁、CPU 过高等常见问题的排查方法

**学习建议**：

1. 先理解基本概念，再深入细节
2. 多动手实践，使用各种监控工具
3. 结合实际项目进行调优
4. 关注 JVM 新特性（如 ZGC、Shenandoah）

---

> 📚 参考资料
> - 《深入理解 Java 虚拟机》- 周志明
> - [Oracle JVM 文档](https://docs.oracle.com/javase/specs/jvms/se8/html/)
> - [OpenJDK 源码](https://github.com/openjdk/jdk)
