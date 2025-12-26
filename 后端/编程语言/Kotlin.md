

> Kotlin 是一门现代、简洁、安全的编程语言，可与 Java 100% 互操作
> 本笔记基于 Kotlin 1.9.x 版本
> 适用于 Android 开发、后端开发（Spring Boot）、多平台开发

---

## 目录

1. [Kotlin 简介](#1-kotlin-简介)
2. [环境搭建](#2-环境搭建)
3. [基础语法](#3-基础语法)
4. [数据类型](#4-数据类型)
5. [控制流程](#5-控制流程)
6. [函数](#6-函数)
7. [类与对象](#7-类与对象)
8. [继承与接口](#8-继承与接口)
9. [空安全](#9-空安全)
10. [集合操作](#10-集合操作)
11. [Lambda 与高阶函数](#11-lambda-与高阶函数)
12. [协程](#12-协程)
13. [扩展函数](#13-扩展函数)
14. [委托](#14-委托)
15. [泛型](#15-泛型)
16. [Kotlin 与 Java 互操作](#16-kotlin-与-java-互操作)
17. [常见错误与解决方案](#17-常见错误与解决方案)
18. [最佳实践](#18-最佳实践)

---

## 1. Kotlin 简介

### 1.1 什么是 Kotlin？

Kotlin 是由 JetBrains 开发的现代编程语言，于 2011 年首次发布，2017 年被 Google 宣布为 Android 官方开发语言。

**Kotlin 的特点**：
- **简洁**：减少样板代码，代码量比 Java 少 40%
- **安全**：内置空安全机制，减少 NullPointerException
- **互操作**：与 Java 100% 兼容，可以混合使用
- **现代**：支持协程、扩展函数、数据类等现代特性
- **多平台**：支持 JVM、Android、JavaScript、Native

### 1.2 Kotlin vs Java 对比

```kotlin
// ==================== Java 写法 ====================
public class User {
    private String name;
    private int age;
    
    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public int getAge() { return age; }
    public void setAge(int age) { this.age = age; }
    
    @Override
    public String toString() {
        return "User{name='" + name + "', age=" + age + "}";
    }
    
    @Override
    public boolean equals(Object o) { /* ... */ }
    
    @Override
    public int hashCode() { /* ... */ }
}

// ==================== Kotlin 写法 ====================
data class User(var name: String, var age: Int)
// 一行代码搞定！自动生成 getter/setter、toString、equals、hashCode、copy
```

### 1.3 版本历史

| 版本 | 发布时间 | 主要特性 |
|------|---------|---------|
| 1.0 | 2016.02 | 首个稳定版本 |
| 1.3 | 2018.10 | 协程稳定版 |
| 1.4 | 2020.08 | SAM 转换改进 |
| 1.5 | 2021.05 | JVM Records 支持 |
| 1.6 | 2021.11 | 密封类改进 |
| 1.7 | 2022.06 | K2 编译器 Alpha |
| 1.8 | 2022.12 | Java 19 支持 |
| 1.9 | 2023.07 | K2 编译器 Beta、枚举 entries |


---

## 2. 环境搭建

### 2.1 开发工具

**推荐 IDE**：
- IntelliJ IDEA（Kotlin 原生支持，推荐）
- Android Studio（Android 开发）
- VS Code + Kotlin 插件

### 2.2 Gradle 项目配置

```kotlin
// build.gradle.kts
plugins {
    kotlin("jvm") version "1.9.22"
    application
}

group = "com.example"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Kotlin 标准库
    implementation(kotlin("stdlib"))
    
    // 协程
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    
    // 测试
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(17)  // 使用 Java 17
}

application {
    mainClass.set("com.example.MainKt")
}
```

### 2.3 Maven 项目配置

```xml
<!-- pom.xml -->
<properties>
    <kotlin.version>1.9.22</kotlin.version>
    <java.version>17</java.version>
</properties>

<dependencies>
    <dependency>
        <groupId>org.jetbrains.kotlin</groupId>
        <artifactId>kotlin-stdlib</artifactId>
        <version>${kotlin.version}</version>
    </dependency>
    
    <!-- 协程 -->
    <dependency>
        <groupId>org.jetbrains.kotlinx</groupId>
        <artifactId>kotlinx-coroutines-core</artifactId>
        <version>1.7.3</version>
    </dependency>
</dependencies>

<build>
    <plugins>
        <plugin>
            <groupId>org.jetbrains.kotlin</groupId>
            <artifactId>kotlin-maven-plugin</artifactId>
            <version>${kotlin.version}</version>
            <executions>
                <execution>
                    <id>compile</id>
                    <goals><goal>compile</goal></goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

### 2.4 第一个 Kotlin 程序

```kotlin
// Main.kt
fun main() {
    println("Hello, Kotlin!")
    
    // 带参数的 main 函数
    // fun main(args: Array<String>) {
    //     println("参数: ${args.joinToString()}")
    // }
}
```

---

## 3. 基础语法

### 3.1 变量声明

Kotlin 使用 `val`（不可变）和 `var`（可变）声明变量。

```kotlin
// val - 不可变变量（类似 Java 的 final）
val name: String = "张三"
val age = 25  // 类型推断，自动推断为 Int
// name = "李四"  // ❌ 编译错误，val 不能重新赋值

// var - 可变变量
var count: Int = 0
count = 10  // ✓ 可以重新赋值

// 延迟初始化
lateinit var user: User  // 稍后初始化，只能用于 var 和非基本类型

// 惰性初始化
val config: Config by lazy {
    // 第一次访问时才初始化
    loadConfig()
}
```

**val vs var 选择原则**：
- 优先使用 `val`，除非确实需要修改
- `val` 使代码更安全、更易于理解
- 函数式编程推荐使用不可变数据

### 3.2 基本输出

```kotlin
// 打印输出
println("Hello")           // 带换行
print("World")             // 不带换行

// 字符串模板（重要特性！）
val name = "Kotlin"
val version = 1.9

println("语言: $name")                    // 简单变量
println("版本: ${version}")               // 表达式
println("长度: ${name.length}")           // 调用方法
println("大写: ${name.uppercase()}")      // 调用函数
println("计算: ${1 + 2 * 3}")             // 表达式计算

// 多行字符串
val text = """
    这是第一行
    这是第二行
    缩进会保留
""".trimIndent()  // trimIndent() 去除公共缩进

// 原始字符串（不转义）
val path = """C:\Users\Admin\Documents"""
```

### 3.3 注释

```kotlin
// 单行注释

/*
 * 多行注释
 * 可以跨越多行
 */

/**
 * KDoc 文档注释
 * @param name 用户名
 * @return 问候语
 */
fun greet(name: String): String {
    return "Hello, $name!"
}
```

### 3.4 包和导入

```kotlin
// 包声明
package com.example.demo

// 导入
import java.util.Date
import java.util.*  // 导入包下所有类
import java.util.Date as JavaDate  // 别名导入，解决命名冲突

// Kotlin 默认导入的包
// kotlin.*
// kotlin.annotation.*
// kotlin.collections.*
// kotlin.comparisons.*
// kotlin.io.*
// kotlin.ranges.*
// kotlin.sequences.*
// kotlin.text.*
// java.lang.*
// kotlin.jvm.*
```


---

## 4. 数据类型

### 4.1 基本类型

Kotlin 中一切皆对象，没有 Java 的原始类型（primitive types）。

```kotlin
// 整数类型
val byte: Byte = 127                    // 8位，-128 ~ 127
val short: Short = 32767                // 16位
val int: Int = 2147483647               // 32位（默认）
val long: Long = 9223372036854775807L   // 64位，需要 L 后缀

// 浮点类型
val float: Float = 3.14f                // 32位，需要 f 后缀
val double: Double = 3.141592653589793  // 64位（默认）

// 布尔类型
val isTrue: Boolean = true
val isFalse: Boolean = false

// 字符类型
val char: Char = 'A'
val unicode: Char = '\u0041'  // Unicode 字符

// 字符串类型
val str: String = "Hello, Kotlin"
```

### 4.2 数字字面量

```kotlin
// 十进制
val decimal = 123

// 十六进制（0x 前缀）
val hex = 0x0F  // 15

// 二进制（0b 前缀）
val binary = 0b00001011  // 11

// 下划线分隔（提高可读性）
val million = 1_000_000
val creditCard = 1234_5678_9012_3456L
val hexBytes = 0xFF_EC_DE_5E
```

### 4.3 类型转换

```kotlin
// Kotlin 不支持隐式类型转换，必须显式转换
val intValue: Int = 100
// val longValue: Long = intValue  // ❌ 编译错误

// 显式转换方法
val longValue: Long = intValue.toLong()    // ✓
val doubleValue: Double = intValue.toDouble()
val stringValue: String = intValue.toString()

// 所有数字类型都有这些转换方法
// toByte(), toShort(), toInt(), toLong()
// toFloat(), toDouble(), toChar()

// 字符串转数字
val num1 = "123".toInt()
val num2 = "123".toIntOrNull()  // 转换失败返回 null，更安全
val num3 = "12.34".toDouble()

// 智能类型转换（Smart Cast）
fun demo(obj: Any) {
    if (obj is String) {
        // 在这个分支中，obj 自动转换为 String 类型
        println(obj.length)  // 可以直接调用 String 的方法
    }
}
```

### 4.4 数组

```kotlin
// 创建数组
val intArray: IntArray = intArrayOf(1, 2, 3, 4, 5)
val strArray: Array<String> = arrayOf("a", "b", "c")

// 指定大小创建
val zeros = IntArray(5)  // [0, 0, 0, 0, 0]
val squares = IntArray(5) { i -> i * i }  // [0, 1, 4, 9, 16]

// 访问元素
println(intArray[0])      // 1
println(intArray.get(0))  // 1
intArray[0] = 10
intArray.set(0, 10)

// 数组属性和方法
println(intArray.size)           // 5
println(intArray.indices)        // 0..4
println(intArray.lastIndex)      // 4
println(intArray.isEmpty())      // false
println(intArray.contains(3))    // true
println(3 in intArray)           // true

// 遍历数组
for (item in intArray) {
    println(item)
}

for ((index, value) in intArray.withIndex()) {
    println("$index: $value")
}

intArray.forEach { println(it) }
intArray.forEachIndexed { index, value -> println("$index: $value") }
```

### 4.5 字符串操作

```kotlin
val str = "Hello, Kotlin!"

// 常用属性和方法
str.length                    // 14
str.isEmpty()                 // false
str.isNotEmpty()              // true
str.isBlank()                 // false（空白字符也算非空）
str.isNotBlank()              // true

// 访问字符
str[0]                        // 'H'
str.first()                   // 'H'
str.last()                    // '!'
str.getOrNull(100)            // null（安全访问）

// 查找
str.indexOf("Kotlin")         // 7
str.lastIndexOf("l")          // 10
str.contains("Kotlin")        // true
"Kotlin" in str               // true
str.startsWith("Hello")       // true
str.endsWith("!")             // true

// 截取
str.substring(0, 5)           // "Hello"
str.substring(7)              // "Kotlin!"
str.take(5)                   // "Hello"
str.takeLast(7)               // "Kotlin!"
str.drop(7)                   // "Kotlin!"
str.dropLast(1)               // "Hello, Kotlin"

// 转换
str.uppercase()               // "HELLO, KOTLIN!"
str.lowercase()               // "hello, kotlin!"
str.capitalize()              // 已废弃，使用 replaceFirstChar
str.replaceFirstChar { it.uppercase() }

// 分割和连接
"a,b,c".split(",")            // [a, b, c]
listOf("a", "b", "c").joinToString(",")  // "a,b,c"

// 去除空白
"  hello  ".trim()            // "hello"
"  hello  ".trimStart()       // "hello  "
"  hello  ".trimEnd()         // "  hello"

// 替换
str.replace("Kotlin", "World")  // "Hello, World!"
str.replaceFirst("l", "L")      // "HeLlo, Kotlin!"
```


---

## 5. 控制流程

### 5.1 if 表达式

Kotlin 中 `if` 是表达式，可以返回值。

```kotlin
// 传统用法
val max: Int
if (a > b) {
    max = a
} else {
    max = b
}

// 作为表达式（推荐）
val max = if (a > b) a else b

// 带代码块的表达式
val max = if (a > b) {
    println("a 更大")
    a  // 最后一行是返回值
} else {
    println("b 更大")
    b
}

// 替代三元运算符（Kotlin 没有 ?: 三元运算符）
// Java: int max = a > b ? a : b;
// Kotlin:
val max = if (a > b) a else b
```

### 5.2 when 表达式

`when` 是 Kotlin 的强大特性，替代 Java 的 switch，功能更强大。

```kotlin
// 基本用法
val result = when (x) {
    1 -> "一"
    2 -> "二"
    3, 4 -> "三或四"  // 多个条件
    in 5..10 -> "五到十"  // 范围
    !in 11..20 -> "不在11到20之间"
    else -> "其他"
}

// 不带参数的 when（替代 if-else if 链）
val result = when {
    x < 0 -> "负数"
    x == 0 -> "零"
    x > 0 -> "正数"
    else -> "不可能"
}

// 类型检查
fun describe(obj: Any): String = when (obj) {
    is Int -> "整数: $obj"
    is String -> "字符串，长度: ${obj.length}"
    is List<*> -> "列表，大小: ${obj.size}"
    else -> "未知类型"
}

// 作为语句使用
when (x) {
    1 -> println("x == 1")
    2 -> println("x == 2")
    else -> println("x 是其他值")
}

// 捕获 when 的主题（Kotlin 1.3+）
fun Request.getBody() = when (val response = executeRequest()) {
    is Success -> response.body
    is HttpError -> throw HttpException(response.status)
}
```

### 5.3 for 循环

```kotlin
// 遍历范围
for (i in 1..5) {
    println(i)  // 1, 2, 3, 4, 5
}

// 不包含结束值
for (i in 1 until 5) {
    println(i)  // 1, 2, 3, 4
}

// 倒序
for (i in 5 downTo 1) {
    println(i)  // 5, 4, 3, 2, 1
}

// 步长
for (i in 1..10 step 2) {
    println(i)  // 1, 3, 5, 7, 9
}

// 遍历数组/集合
val items = listOf("apple", "banana", "cherry")
for (item in items) {
    println(item)
}

// 带索引遍历
for ((index, value) in items.withIndex()) {
    println("$index: $value")
}

// 遍历 Map
val map = mapOf("a" to 1, "b" to 2)
for ((key, value) in map) {
    println("$key -> $value")
}
```

### 5.4 while 循环

```kotlin
// while 循环
var x = 5
while (x > 0) {
    println(x)
    x--
}

// do-while 循环（至少执行一次）
var y = 0
do {
    println(y)
    y++
} while (y < 5)
```

### 5.5 跳转语句

```kotlin
// break 和 continue
for (i in 1..10) {
    if (i == 3) continue  // 跳过本次
    if (i == 8) break     // 退出循环
    println(i)
}

// 标签（用于嵌套循环）
outer@ for (i in 1..3) {
    for (j in 1..3) {
        if (i == 2 && j == 2) break@outer  // 跳出外层循环
        println("$i, $j")
    }
}

// return 标签（用于 Lambda）
listOf(1, 2, 3, 4, 5).forEach {
    if (it == 3) return@forEach  // 只跳过当前迭代，相当于 continue
    println(it)
}

// 或者使用匿名函数
listOf(1, 2, 3, 4, 5).forEach(fun(value) {
    if (value == 3) return  // 只从匿名函数返回
    println(value)
})
```

---

## 6. 函数

### 6.1 函数定义

```kotlin
// 基本函数
fun greet(name: String): String {
    return "Hello, $name!"
}

// 单表达式函数（推荐简单函数使用）
fun greet(name: String): String = "Hello, $name!"

// 类型推断（返回类型可省略）
fun greet(name: String) = "Hello, $name!"

// 无返回值（Unit 相当于 Java 的 void）
fun printMessage(message: String): Unit {
    println(message)
}

// Unit 可以省略
fun printMessage(message: String) {
    println(message)
}
```

### 6.2 参数

```kotlin
// 默认参数
fun greet(name: String = "World", greeting: String = "Hello"): String {
    return "$greeting, $name!"
}

greet()                    // "Hello, World!"
greet("Kotlin")            // "Hello, Kotlin!"
greet("Kotlin", "Hi")      // "Hi, Kotlin!"

// 命名参数（可以打乱顺序）
greet(greeting = "Hi", name = "Kotlin")  // "Hi, Kotlin!"

// 可变参数
fun sum(vararg numbers: Int): Int {
    return numbers.sum()
}

sum(1, 2, 3)        // 6
sum(1, 2, 3, 4, 5)  // 15

// 展开数组
val arr = intArrayOf(1, 2, 3)
sum(*arr)  // 使用 * 展开数组
```

### 6.3 局部函数

```kotlin
// 函数内部可以定义函数
fun outer() {
    fun inner() {
        println("内部函数")
    }
    
    inner()  // 调用内部函数
}

// 实际应用：避免代码重复
fun validateUser(user: User) {
    fun validate(value: String, fieldName: String) {
        if (value.isEmpty()) {
            throw IllegalArgumentException("$fieldName 不能为空")
        }
    }
    
    validate(user.name, "姓名")
    validate(user.email, "邮箱")
}
```

### 6.4 中缀函数

```kotlin
// 使用 infix 关键字定义中缀函数
infix fun Int.times(str: String) = str.repeat(this)

// 调用方式
val result = 3 times "Hello "  // "Hello Hello Hello "
// 等价于
val result = 3.times("Hello ")

// 标准库中的中缀函数
val pair = "key" to "value"  // Pair("key", "value")
val range = 1 until 10       // 1..9
```


---

## 7. 类与对象

### 7.1 类的定义

```kotlin
// 最简单的类
class Empty

// 带属性的类
class Person {
    var name: String = ""
    var age: Int = 0
}

// 主构造函数（推荐）
class Person(val name: String, var age: Int)

// 使用
val person = Person("张三", 25)
println(person.name)  // 张三
person.age = 26       // var 可以修改

// 带初始化块
class Person(val name: String, var age: Int) {
    
    // 初始化块，在构造时执行
    init {
        println("创建了一个 Person: $name")
        require(age >= 0) { "年龄不能为负数" }
    }
    
    // 次构造函数
    constructor(name: String) : this(name, 0) {
        println("使用次构造函数")
    }
}

// 带默认值的构造函数
class Person(
    val name: String = "Unknown",
    var age: Int = 0,
    val email: String? = null
)

// 可以用命名参数创建
val p1 = Person()
val p2 = Person(name = "张三")
val p3 = Person(name = "李四", age = 30)
```

### 7.2 属性

```kotlin
class Person {
    // 只读属性
    val id: Long = System.currentTimeMillis()
    
    // 可变属性
    var name: String = ""
    
    // 自定义 getter
    val isAdult: Boolean
        get() = age >= 18
    
    // 自定义 getter 和 setter
    var age: Int = 0
        get() = field  // field 是幕后字段
        set(value) {
            if (value >= 0) {
                field = value
            }
        }
    
    // 延迟初始化
    lateinit var address: String
    
    // 惰性初始化
    val config: Config by lazy {
        loadConfig()
    }
}

// 检查 lateinit 是否已初始化
if (::address.isInitialized) {
    println(address)
}
```

### 7.3 数据类（Data Class）

数据类是 Kotlin 的杀手级特性，自动生成 `equals()`、`hashCode()`、`toString()`、`copy()`、`componentN()` 方法。

```kotlin
// 定义数据类
data class User(
    val id: Long,
    val name: String,
    val email: String,
    val age: Int = 0
)

// 使用
val user1 = User(1, "张三", "zhangsan@example.com")
val user2 = User(1, "张三", "zhangsan@example.com")

// 自动生成的方法
println(user1)                    // User(id=1, name=张三, email=zhangsan@example.com, age=0)
println(user1 == user2)           // true（比较内容）
println(user1.hashCode())         // 自动生成

// copy() 方法 - 复制并修改部分属性
val user3 = user1.copy(name = "李四")
println(user3)  // User(id=1, name=李四, email=zhangsan@example.com, age=0)

// 解构声明
val (id, name, email) = user1
println("$id, $name, $email")

// 在 when 中使用
fun process(user: User) = when {
    user.age < 18 -> "未成年"
    user.age < 60 -> "成年"
    else -> "老年"
}
```

### 7.4 枚举类

```kotlin
// 基本枚举
enum class Direction {
    NORTH, SOUTH, EAST, WEST
}

// 带属性的枚举
enum class Color(val rgb: Int) {
    RED(0xFF0000),
    GREEN(0x00FF00),
    BLUE(0x0000FF);
    
    // 枚举可以有方法
    fun toHex() = "#${rgb.toString(16).padStart(6, '0')}"
}

// 使用
val direction = Direction.NORTH
val color = Color.RED

println(color.rgb)        // 16711680
println(color.toHex())    // #ff0000
println(color.name)       // RED
println(color.ordinal)    // 0

// 遍历枚举（Kotlin 1.9+ 推荐使用 entries）
Color.entries.forEach { println(it) }  // 1.9+ 新特性
Color.values().forEach { println(it) } // 旧方式

// 根据名称获取
val c = Color.valueOf("RED")

// 在 when 中使用
fun describe(color: Color) = when (color) {
    Color.RED -> "红色"
    Color.GREEN -> "绿色"
    Color.BLUE -> "蓝色"
}
```

### 7.5 密封类（Sealed Class）

密封类用于表示受限的类层次结构，所有子类必须在同一文件中定义。

```kotlin
// 定义密封类
sealed class Result<out T> {
    data class Success<T>(val data: T) : Result<T>()
    data class Error(val message: String, val cause: Exception? = null) : Result<Nothing>()
    object Loading : Result<Nothing>()
}

// 使用
fun handleResult(result: Result<String>) = when (result) {
    is Result.Success -> println("成功: ${result.data}")
    is Result.Error -> println("错误: ${result.message}")
    is Result.Loading -> println("加载中...")
    // 不需要 else，因为所有情况都已覆盖
}

// 实际应用：网络请求结果
sealed class NetworkResult<out T> {
    data class Success<T>(val data: T) : NetworkResult<T>()
    data class Failure(val code: Int, val message: String) : NetworkResult<Nothing>()
    object Loading : NetworkResult<Nothing>()
}

fun <T> NetworkResult<T>.onSuccess(action: (T) -> Unit): NetworkResult<T> {
    if (this is NetworkResult.Success) {
        action(data)
    }
    return this
}

fun <T> NetworkResult<T>.onFailure(action: (Int, String) -> Unit): NetworkResult<T> {
    if (this is NetworkResult.Failure) {
        action(code, message)
    }
    return this
}
```

### 7.6 对象（Object）

```kotlin
// 对象声明（单例）
object DatabaseConfig {
    val url = "jdbc:mysql://localhost:3306/test"
    val username = "root"
    
    fun connect() {
        println("连接数据库: $url")
    }
}

// 使用单例
DatabaseConfig.connect()

// 伴生对象（类似 Java 的 static）
class User(val name: String) {
    
    companion object {
        const val MAX_AGE = 150
        
        fun create(name: String): User {
            return User(name)
        }
    }
}

// 使用
val maxAge = User.MAX_AGE
val user = User.create("张三")

// 对象表达式（匿名对象）
val comparator = object : Comparator<String> {
    override fun compare(s1: String, s2: String): Int {
        return s1.length - s2.length
    }
}

// 简化写法（SAM 转换）
val comparator = Comparator<String> { s1, s2 -> s1.length - s2.length }
```


---

## 8. 继承与接口

### 8.1 继承

```kotlin
// Kotlin 中类默认是 final 的，需要 open 关键字才能被继承
open class Animal(val name: String) {
    
    open fun makeSound() {
        println("动物发出声音")
    }
    
    // 没有 open 的方法不能被重写
    fun eat() {
        println("$name 正在吃东西")
    }
}

// 继承
class Dog(name: String, val breed: String) : Animal(name) {
    
    override fun makeSound() {
        println("$name 汪汪叫")
    }
    
    fun fetch() {
        println("$name 去捡球")
    }
}

// 使用
val dog = Dog("旺财", "金毛")
dog.makeSound()  // 旺财 汪汪叫
dog.eat()        // 旺财 正在吃东西
dog.fetch()      // 旺财 去捡球

// 禁止进一步重写
open class Cat(name: String) : Animal(name) {
    final override fun makeSound() {
        println("$name 喵喵叫")
    }
}
```

### 8.2 抽象类

```kotlin
abstract class Shape {
    // 抽象属性
    abstract val area: Double
    
    // 抽象方法
    abstract fun draw()
    
    // 普通方法
    fun describe() {
        println("这是一个形状，面积: $area")
    }
}

class Circle(val radius: Double) : Shape() {
    
    override val area: Double
        get() = Math.PI * radius * radius
    
    override fun draw() {
        println("画一个半径为 $radius 的圆")
    }
}

class Rectangle(val width: Double, val height: Double) : Shape() {
    
    override val area: Double = width * height
    
    override fun draw() {
        println("画一个 $width x $height 的矩形")
    }
}
```

### 8.3 接口

```kotlin
// 定义接口
interface Clickable {
    // 抽象方法
    fun click()
    
    // 带默认实现的方法
    fun showOff() {
        println("我是可点击的")
    }
}

interface Focusable {
    fun setFocus(focused: Boolean)
    
    fun showOff() {
        println("我是可聚焦的")
    }
}

// 实现多个接口
class Button : Clickable, Focusable {
    
    override fun click() {
        println("按钮被点击")
    }
    
    override fun setFocus(focused: Boolean) {
        println("按钮聚焦状态: $focused")
    }
    
    // 必须重写 showOff，因为两个接口都有默认实现
    override fun showOff() {
        super<Clickable>.showOff()  // 调用 Clickable 的实现
        super<Focusable>.showOff()  // 调用 Focusable 的实现
    }
}

// 接口可以有属性
interface Named {
    val name: String  // 抽象属性
    
    val greeting: String  // 带默认实现的属性
        get() = "Hello, $name"
}

class Person(override val name: String) : Named
```

### 8.4 可见性修饰符

```kotlin
// Kotlin 的可见性修饰符
// public    - 默认，到处可见
// private   - 只在声明的文件/类内可见
// protected - 只在类及其子类中可见
// internal  - 在同一模块内可见

class Example {
    public val a = 1       // 到处可见
    private val b = 2      // 只在 Example 类内可见
    protected val c = 3    // 在 Example 及其子类中可见
    internal val d = 4     // 在同一模块内可见
    
    private fun privateMethod() {}
    protected open fun protectedMethod() {}
}

// 顶层声明
private fun topLevelPrivate() {}  // 只在当前文件可见
internal fun topLevelInternal() {} // 在同一模块可见
```

### 8.5 类型检查与转换

```kotlin
// is 检查类型
fun demo(obj: Any) {
    if (obj is String) {
        // 智能转换，obj 自动变成 String 类型
        println(obj.length)
    }
    
    if (obj !is String) {
        println("不是字符串")
    }
}

// as 强制转换
val str: String = obj as String  // 如果转换失败，抛出异常

// as? 安全转换
val str: String? = obj as? String  // 如果转换失败，返回 null

// when 中的类型检查
fun process(obj: Any) = when (obj) {
    is Int -> obj * 2
    is String -> obj.uppercase()
    is List<*> -> obj.size
    else -> "未知类型"
}
```

---

## 9. 空安全

空安全是 Kotlin 最重要的特性之一，从语言层面解决 NullPointerException 问题。

### 9.1 可空类型

```kotlin
// 默认情况下，变量不能为 null
var name: String = "Kotlin"
// name = null  // ❌ 编译错误

// 使用 ? 声明可空类型
var nullableName: String? = "Kotlin"
nullableName = null  // ✓ 可以赋值为 null

// 可空类型不能直接调用方法
// nullableName.length  // ❌ 编译错误
```

### 9.2 安全调用操作符 ?.

```kotlin
val name: String? = null

// 安全调用，如果 name 为 null，返回 null
val length: Int? = name?.length

// 链式安全调用
val city: String? = user?.address?.city

// 配合 let 使用
name?.let {
    println("名字长度: ${it.length}")
}

// 多个可空值
val result = a?.let { aValue ->
    b?.let { bValue ->
        aValue + bValue
    }
}
```

### 9.3 Elvis 操作符 ?:

```kotlin
// 如果左边为 null，使用右边的默认值
val name: String? = null
val displayName = name ?: "Unknown"  // "Unknown"

// 链式使用
val city = user?.address?.city ?: "未知城市"

// 配合 return 或 throw
fun process(name: String?) {
    val n = name ?: return  // 如果为 null，直接返回
    println(n.length)
}

fun validate(name: String?) {
    val n = name ?: throw IllegalArgumentException("name 不能为空")
    println(n)
}
```

### 9.4 非空断言 !!

```kotlin
// !! 断言不为 null，如果为 null 会抛出 NullPointerException
val name: String? = "Kotlin"
val length = name!!.length  // 如果 name 为 null，抛出 NPE

// ⚠️ 谨慎使用 !!，它会破坏空安全
// 只在你确定不为 null 时使用
```

### 9.5 安全转换

```kotlin
// as? 安全转换，失败返回 null
val str: String? = obj as? String

// 配合 Elvis 使用
val str: String = obj as? String ?: ""
```

### 9.6 集合的空安全

```kotlin
// 可空元素的集合
val nullableList: List<String?> = listOf("a", null, "b")

// 可空集合
val nullableCollection: List<String>? = null

// 过滤 null 值
val nonNullList: List<String> = nullableList.filterNotNull()

// 安全访问集合元素
val first = list.firstOrNull()
val element = list.getOrNull(10)
```

### 9.7 平台类型

```kotlin
// 从 Java 代码返回的类型是"平台类型"
// Kotlin 不知道它是否可空，需要自己判断

// Java 代码
// public String getName() { return name; }

// Kotlin 中使用
val name = javaObject.name  // 类型是 String!（平台类型）
// 你需要自己决定是否可空
val safeName: String? = javaObject.name
val unsafeName: String = javaObject.name  // 如果返回 null 会 NPE
```


---

## 10. 集合操作

### 10.1 集合类型

```kotlin
// 不可变集合（只读）
val list: List<String> = listOf("a", "b", "c")
val set: Set<Int> = setOf(1, 2, 3)
val map: Map<String, Int> = mapOf("a" to 1, "b" to 2)

// 可变集合
val mutableList: MutableList<String> = mutableListOf("a", "b", "c")
val mutableSet: MutableSet<Int> = mutableSetOf(1, 2, 3)
val mutableMap: MutableMap<String, Int> = mutableMapOf("a" to 1, "b" to 2)

// 空集合
val emptyList = emptyList<String>()
val emptySet = emptySet<Int>()
val emptyMap = emptyMap<String, Int>()

// ArrayList 和 HashMap
val arrayList = arrayListOf(1, 2, 3)
val hashMap = hashMapOf("a" to 1, "b" to 2)
val linkedMap = linkedMapOf("a" to 1, "b" to 2)  // 保持插入顺序
```

### 10.2 集合操作符

```kotlin
val numbers = listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

// ==================== 转换操作 ====================

// map - 转换每个元素
val doubled = numbers.map { it * 2 }  // [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]

// mapIndexed - 带索引转换
val indexed = numbers.mapIndexed { index, value -> "$index: $value" }

// mapNotNull - 转换并过滤 null
val lengths = listOf("a", "abc", null, "ab").mapNotNull { it?.length }  // [1, 3, 2]

// flatMap - 扁平化映射
val nested = listOf(listOf(1, 2), listOf(3, 4))
val flat = nested.flatMap { it }  // [1, 2, 3, 4]

// flatten - 扁平化
val flattened = nested.flatten()  // [1, 2, 3, 4]

// ==================== 过滤操作 ====================

// filter - 过滤
val evens = numbers.filter { it % 2 == 0 }  // [2, 4, 6, 8, 10]

// filterNot - 反向过滤
val odds = numbers.filterNot { it % 2 == 0 }  // [1, 3, 5, 7, 9]

// filterNotNull - 过滤 null
val nonNull = listOf(1, null, 2, null, 3).filterNotNull()  // [1, 2, 3]

// filterIsInstance - 按类型过滤
val strings = listOf(1, "a", 2, "b").filterIsInstance<String>()  // ["a", "b"]

// take / drop
val first3 = numbers.take(3)      // [1, 2, 3]
val last3 = numbers.takeLast(3)   // [8, 9, 10]
val drop3 = numbers.drop(3)       // [4, 5, 6, 7, 8, 9, 10]

// takeWhile / dropWhile
val takeWhile = numbers.takeWhile { it < 5 }  // [1, 2, 3, 4]
val dropWhile = numbers.dropWhile { it < 5 }  // [5, 6, 7, 8, 9, 10]

// distinct - 去重
val unique = listOf(1, 2, 2, 3, 3, 3).distinct()  // [1, 2, 3]

// ==================== 聚合操作 ====================

// reduce - 累积
val sum = numbers.reduce { acc, i -> acc + i }  // 55

// fold - 带初始值的累积
val sumWithInit = numbers.fold(100) { acc, i -> acc + i }  // 155

// sum / average / max / min
numbers.sum()        // 55
numbers.average()    // 5.5
numbers.maxOrNull()  // 10
numbers.minOrNull()  // 1

// count
numbers.count()                    // 10
numbers.count { it % 2 == 0 }      // 5

// ==================== 分组操作 ====================

// groupBy - 分组
val grouped = numbers.groupBy { if (it % 2 == 0) "偶数" else "奇数" }
// {奇数=[1, 3, 5, 7, 9], 偶数=[2, 4, 6, 8, 10]}

// partition - 分成两组
val (evens, odds) = numbers.partition { it % 2 == 0 }
// evens = [2, 4, 6, 8, 10], odds = [1, 3, 5, 7, 9]

// chunked - 分块
val chunks = numbers.chunked(3)  // [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10]]

// windowed - 滑动窗口
val windows = numbers.windowed(3)  // [[1, 2, 3], [2, 3, 4], [3, 4, 5], ...]

// ==================== 排序操作 ====================

// sorted / sortedDescending
val sorted = numbers.shuffled().sorted()
val desc = numbers.sortedDescending()

// sortedBy / sortedByDescending
data class Person(val name: String, val age: Int)
val people = listOf(Person("Alice", 30), Person("Bob", 25))
val byAge = people.sortedBy { it.age }
val byAgeDesc = people.sortedByDescending { it.age }

// reversed
val reversed = numbers.reversed()  // [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]

// ==================== 查找操作 ====================

// find / firstOrNull
val first = numbers.find { it > 5 }  // 6
val firstOrNull = numbers.firstOrNull { it > 100 }  // null

// any / all / none
numbers.any { it > 5 }   // true（存在大于5的）
numbers.all { it > 0 }   // true（全部大于0）
numbers.none { it < 0 }  // true（没有小于0的）

// contains / in
numbers.contains(5)  // true
5 in numbers         // true

// indexOf / lastIndexOf
numbers.indexOf(5)      // 4
numbers.lastIndexOf(5)  // 4
```

### 10.3 Map 操作

```kotlin
val map = mapOf("a" to 1, "b" to 2, "c" to 3)

// 访问
map["a"]                    // 1
map.get("a")                // 1
map.getOrDefault("d", 0)    // 0
map.getOrElse("d") { 0 }    // 0

// 遍历
for ((key, value) in map) {
    println("$key -> $value")
}

map.forEach { (key, value) ->
    println("$key -> $value")
}

// 转换
val keys = map.keys          // [a, b, c]
val values = map.values      // [1, 2, 3]
val entries = map.entries    // [a=1, b=2, c=3]

// 过滤
val filtered = map.filter { (_, value) -> value > 1 }  // {b=2, c=3}
val filteredKeys = map.filterKeys { it != "a" }        // {b=2, c=3}
val filteredValues = map.filterValues { it > 1 }       // {b=2, c=3}

// 映射
val mapped = map.mapValues { (_, value) -> value * 2 }  // {a=2, b=4, c=6}
val mappedKeys = map.mapKeys { (key, _) -> key.uppercase() }  // {A=1, B=2, C=3}

// 可变 Map 操作
val mutableMap = mutableMapOf("a" to 1)
mutableMap["b"] = 2
mutableMap.put("c", 3)
mutableMap.remove("a")
mutableMap.putIfAbsent("d", 4)
mutableMap.getOrPut("e") { 5 }  // 如果不存在，计算并放入
```

### 10.4 序列（Sequence）

序列是惰性求值的集合，适合处理大数据集。

```kotlin
// 创建序列
val sequence = sequenceOf(1, 2, 3)
val fromList = listOf(1, 2, 3).asSequence()
val generated = generateSequence(1) { it + 1 }  // 无限序列

// 序列 vs 集合
// 集合：每个操作都会创建新集合
val result1 = listOf(1, 2, 3, 4, 5)
    .map { it * 2 }      // 创建新 List
    .filter { it > 5 }   // 创建新 List
    .toList()

// 序列：惰性求值，只在需要时计算
val result2 = listOf(1, 2, 3, 4, 5)
    .asSequence()
    .map { it * 2 }      // 不立即执行
    .filter { it > 5 }   // 不立即执行
    .toList()            // 触发计算

// 处理大数据集时，序列更高效
val bigList = (1..1_000_000).toList()
val result = bigList.asSequence()
    .filter { it % 2 == 0 }
    .map { it * 2 }
    .take(10)
    .toList()
```


---

## 11. Lambda 与高阶函数

### 11.1 Lambda 表达式

```kotlin
// Lambda 语法：{ 参数 -> 函数体 }
val sum = { a: Int, b: Int -> a + b }
println(sum(1, 2))  // 3

// 类型推断
val double: (Int) -> Int = { it * 2 }

// 多行 Lambda
val process = { x: Int ->
    val result = x * 2
    println("处理: $x -> $result")
    result  // 最后一行是返回值
}

// 无参数 Lambda
val greet = { println("Hello!") }

// it - 单参数的隐式名称
val numbers = listOf(1, 2, 3)
numbers.filter { it > 1 }  // it 代表当前元素

// 解构 Lambda 参数
val map = mapOf("a" to 1, "b" to 2)
map.forEach { (key, value) ->
    println("$key -> $value")
}
```

### 11.2 高阶函数

高阶函数是接受函数作为参数或返回函数的函数。

```kotlin
// 函数作为参数
fun calculate(a: Int, b: Int, operation: (Int, Int) -> Int): Int {
    return operation(a, b)
}

val sum = calculate(5, 3) { a, b -> a + b }      // 8
val product = calculate(5, 3) { a, b -> a * b }  // 15

// 函数作为返回值
fun getOperation(type: String): (Int, Int) -> Int {
    return when (type) {
        "add" -> { a, b -> a + b }
        "subtract" -> { a, b -> a - b }
        "multiply" -> { a, b -> a * b }
        else -> { _, _ -> 0 }
    }
}

val add = getOperation("add")
println(add(5, 3))  // 8

// 尾随 Lambda
fun doSomething(name: String, action: () -> Unit) {
    println("开始: $name")
    action()
    println("结束: $name")
}

// 如果 Lambda 是最后一个参数，可以放在括号外面
doSomething("任务") {
    println("执行任务")
}

// 如果只有一个 Lambda 参数，可以省略括号
listOf(1, 2, 3).forEach { println(it) }
```

### 11.3 内联函数

```kotlin
// inline 关键字可以消除 Lambda 的性能开销
inline fun measureTime(action: () -> Unit): Long {
    val start = System.currentTimeMillis()
    action()
    return System.currentTimeMillis() - start
}

// noinline - 不内联某个 Lambda 参数
inline fun foo(inlined: () -> Unit, noinline notInlined: () -> Unit) {
    // ...
}

// crossinline - 禁止非局部返回
inline fun foo(crossinline action: () -> Unit) {
    Runnable {
        action()  // 这里不能使用 return
    }
}
```

### 11.4 作用域函数

Kotlin 提供了 5 个作用域函数：`let`、`run`、`with`、`apply`、`also`。

```kotlin
data class Person(var name: String, var age: Int, var city: String)

// ==================== let ====================
// 对象作为 it，返回 Lambda 结果
// 常用于：空安全调用、转换

val name: String? = "Kotlin"
val length = name?.let {
    println("名字: $it")
    it.length  // 返回值
}

// ==================== run ====================
// 对象作为 this，返回 Lambda 结果
// 常用于：对象配置并计算结果

val result = Person("张三", 25, "北京").run {
    age += 1
    "姓名: $name, 年龄: $age"  // 返回值
}

// 无接收者的 run
val hexString = run {
    val digits = "0123456789ABCDEF"
    val random = java.util.Random()
    buildString {
        repeat(8) {
            append(digits[random.nextInt(16)])
        }
    }
}

// ==================== with ====================
// 对象作为 this，返回 Lambda 结果
// 常用于：对已有对象进行操作

val person = Person("张三", 25, "北京")
val info = with(person) {
    println("姓名: $name")
    println("年龄: $age")
    "来自 $city"  // 返回值
}

// ==================== apply ====================
// 对象作为 this，返回对象本身
// 常用于：对象初始化

val person = Person("", 0, "").apply {
    name = "张三"
    age = 25
    city = "北京"
}

// ==================== also ====================
// 对象作为 it，返回对象本身
// 常用于：附加操作（如日志）

val numbers = mutableListOf(1, 2, 3)
    .also { println("初始列表: $it") }
    .also { it.add(4) }
    .also { println("添加后: $it") }
```

**作用域函数对比表**：

| 函数 | 对象引用 | 返回值 | 是否扩展函数 |
|------|---------|--------|-------------|
| let | it | Lambda 结果 | 是 |
| run | this | Lambda 结果 | 是 |
| with | this | Lambda 结果 | 否 |
| apply | this | 对象本身 | 是 |
| also | it | 对象本身 | 是 |

**选择指南**：
- 需要返回对象本身 → `apply` 或 `also`
- 需要返回计算结果 → `let`、`run` 或 `with`
- 需要用 `it` 引用 → `let` 或 `also`
- 需要用 `this` 引用 → `run`、`with` 或 `apply`

---

## 12. 协程

协程是 Kotlin 的异步编程解决方案，比线程更轻量。

### 12.1 添加依赖

```kotlin
// build.gradle.kts
dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
}
```

### 12.2 基本概念

```kotlin
import kotlinx.coroutines.*

fun main() = runBlocking {  // 创建协程作用域
    
    // launch - 启动协程，不返回结果
    launch {
        delay(1000)  // 非阻塞延迟
        println("World!")
    }
    
    println("Hello,")
    
    // async - 启动协程，返回 Deferred（类似 Future）
    val deferred = async {
        delay(1000)
        "结果"
    }
    
    val result = deferred.await()  // 等待结果
    println(result)
}

// 输出：
// Hello,
// World!
// 结果
```

### 12.3 协程构建器

```kotlin
// runBlocking - 阻塞当前线程，通常用于 main 函数或测试
fun main() = runBlocking {
    // ...
}

// launch - 启动协程，返回 Job
val job = launch {
    // 协程代码
}
job.join()  // 等待完成
job.cancel()  // 取消

// async - 启动协程，返回 Deferred<T>
val deferred = async {
    // 返回结果
    42
}
val result = deferred.await()

// coroutineScope - 创建新的协程作用域
suspend fun doWork() = coroutineScope {
    val a = async { fetchA() }
    val b = async { fetchB() }
    a.await() + b.await()
}
```

### 12.4 挂起函数

```kotlin
// suspend 关键字标记挂起函数
suspend fun fetchUser(id: Long): User {
    delay(1000)  // 模拟网络请求
    return User(id, "用户$id")
}

// 挂起函数只能在协程或其他挂起函数中调用
fun main() = runBlocking {
    val user = fetchUser(1)
    println(user)
}

// 并行执行多个挂起函数
suspend fun fetchUserAndOrders(userId: Long) = coroutineScope {
    val user = async { fetchUser(userId) }
    val orders = async { fetchOrders(userId) }
    
    UserWithOrders(user.await(), orders.await())
}
```

### 12.5 协程上下文和调度器

```kotlin
// Dispatchers - 协程调度器
// Dispatchers.Default - CPU 密集型任务
// Dispatchers.IO - IO 密集型任务
// Dispatchers.Main - 主线程（Android/UI）
// Dispatchers.Unconfined - 不限制线程

fun main() = runBlocking {
    
    launch(Dispatchers.Default) {
        println("Default: ${Thread.currentThread().name}")
    }
    
    launch(Dispatchers.IO) {
        println("IO: ${Thread.currentThread().name}")
    }
    
    // 切换上下文
    launch {
        println("开始: ${Thread.currentThread().name}")
        
        withContext(Dispatchers.IO) {
            println("IO 操作: ${Thread.currentThread().name}")
        }
        
        println("结束: ${Thread.currentThread().name}")
    }
}
```

### 12.6 异常处理

```kotlin
// try-catch
fun main() = runBlocking {
    try {
        launch {
            throw RuntimeException("出错了")
        }.join()
    } catch (e: Exception) {
        println("捕获异常: ${e.message}")
    }
}

// CoroutineExceptionHandler
val handler = CoroutineExceptionHandler { _, exception ->
    println("捕获异常: ${exception.message}")
}

fun main() = runBlocking {
    val job = GlobalScope.launch(handler) {
        throw RuntimeException("出错了")
    }
    job.join()
}

// supervisorScope - 子协程失败不影响其他
suspend fun doWork() = supervisorScope {
    val a = async { 
        delay(100)
        throw RuntimeException("A 失败")
    }
    val b = async { 
        delay(200)
        "B 成功"
    }
    
    try {
        a.await()
    } catch (e: Exception) {
        println("A 异常: ${e.message}")
    }
    
    println(b.await())  // B 仍然可以完成
}
```

### 12.7 Flow（冷流）

```kotlin
import kotlinx.coroutines.flow.*

// 创建 Flow
fun numbers(): Flow<Int> = flow {
    for (i in 1..5) {
        delay(100)
        emit(i)  // 发射值
    }
}

// 收集 Flow
fun main() = runBlocking {
    numbers()
        .filter { it % 2 == 0 }
        .map { it * 2 }
        .collect { println(it) }
}

// Flow 操作符
flow
    .filter { it > 0 }
    .map { it * 2 }
    .take(5)
    .drop(2)
    .distinctUntilChanged()
    .debounce(300)  // 防抖
    .catch { e -> emit(-1) }  // 异常处理
    .onEach { println(it) }
    .onStart { println("开始") }
    .onCompletion { println("完成") }
    .collect { println(it) }

// StateFlow - 状态流
val _state = MutableStateFlow(0)
val state: StateFlow<Int> = _state.asStateFlow()

// SharedFlow - 共享流
val _events = MutableSharedFlow<Event>()
val events: SharedFlow<Event> = _events.asSharedFlow()
```


---

## 13. 扩展函数

扩展函数是 Kotlin 的强大特性，可以在不修改类的情况下为其添加新功能。

### 13.1 扩展函数定义

```kotlin
// 为 String 添加扩展函数
fun String.addExclamation(): String {
    return this + "!"
}

// 使用
val greeting = "Hello".addExclamation()  // "Hello!"

// 为 Int 添加扩展函数
fun Int.isEven(): Boolean = this % 2 == 0
fun Int.isOdd(): Boolean = !this.isEven()

println(4.isEven())  // true
println(5.isOdd())   // true

// 带参数的扩展函数
fun String.repeat(times: Int): String {
    return (1..times).joinToString("") { this }
}

// 泛型扩展函数
fun <T> List<T>.secondOrNull(): T? {
    return if (size >= 2) this[1] else null
}
```

### 13.2 扩展属性

```kotlin
// 扩展属性（不能有幕后字段）
val String.lastChar: Char
    get() = this[length - 1]

val String.firstChar: Char
    get() = this[0]

println("Kotlin".lastChar)   // n
println("Kotlin".firstChar)  // K

// 可变扩展属性
var StringBuilder.lastChar: Char
    get() = this[length - 1]
    set(value) {
        this.setCharAt(length - 1, value)
    }

val sb = StringBuilder("Hello")
sb.lastChar = '!'
println(sb)  // Hell!
```

### 13.3 可空接收者

```kotlin
// 可以为可空类型定义扩展函数
fun String?.orEmpty(): String {
    return this ?: ""
}

val nullString: String? = null
println(nullString.orEmpty())  // ""

// 安全的 toString
fun Any?.safeToString(): String {
    return this?.toString() ?: "null"
}
```

### 13.4 常用扩展函数示例

```kotlin
// 集合扩展
fun <T> List<T>.swap(index1: Int, index2: Int): List<T> {
    val result = this.toMutableList()
    val temp = result[index1]
    result[index1] = result[index2]
    result[index2] = temp
    return result
}

// 字符串扩展
fun String.toSlug(): String {
    return this.lowercase()
        .replace(Regex("[^a-z0-9\\s-]"), "")
        .replace(Regex("\\s+"), "-")
        .trim('-')
}

println("Hello World!".toSlug())  // "hello-world"

// 日期扩展
fun Long.toDateString(): String {
    val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    return sdf.format(java.util.Date(this))
}

println(System.currentTimeMillis().toDateString())

// View 扩展（Android）
fun View.show() { visibility = View.VISIBLE }
fun View.hide() { visibility = View.GONE }
fun View.invisible() { visibility = View.INVISIBLE }
```

---

## 14. 委托

### 14.1 类委托

```kotlin
// 接口
interface Printer {
    fun print(message: String)
}

// 实现类
class ConsolePrinter : Printer {
    override fun print(message: String) {
        println(message)
    }
}

// 使用 by 关键字委托
class LoggingPrinter(printer: Printer) : Printer by printer {
    // 可以重写部分方法
    override fun print(message: String) {
        println("[LOG] $message")
    }
}

// 使用
val printer = LoggingPrinter(ConsolePrinter())
printer.print("Hello")  // [LOG] Hello
```

### 14.2 属性委托

```kotlin
// lazy - 惰性初始化
val lazyValue: String by lazy {
    println("计算中...")
    "Hello"
}

println(lazyValue)  // 计算中... Hello
println(lazyValue)  // Hello（不再计算）

// observable - 可观察属性
var name: String by Delegates.observable("初始值") { prop, old, new ->
    println("${prop.name}: $old -> $new")
}

name = "新值"  // name: 初始值 -> 新值

// vetoable - 可否决属性
var age: Int by Delegates.vetoable(0) { _, _, new ->
    new >= 0  // 只接受非负值
}

age = 25   // 成功
age = -1   // 失败，保持 25

// notNull - 非空委托
var notNullValue: String by Delegates.notNull()
// notNullValue  // 抛出异常，未初始化
notNullValue = "已初始化"
println(notNullValue)  // 已初始化

// Map 委托
class User(map: Map<String, Any?>) {
    val name: String by map
    val age: Int by map
}

val user = User(mapOf("name" to "张三", "age" to 25))
println(user.name)  // 张三
println(user.age)   // 25
```

### 14.3 自定义委托

```kotlin
import kotlin.reflect.KProperty

// 自定义委托类
class TrimDelegate {
    private var value: String = ""
    
    operator fun getValue(thisRef: Any?, property: KProperty<*>): String {
        return value
    }
    
    operator fun setValue(thisRef: Any?, property: KProperty<*>, newValue: String) {
        value = newValue.trim()
    }
}

// 使用
class User {
    var name: String by TrimDelegate()
}

val user = User()
user.name = "  张三  "
println(user.name)  // "张三"

// 使用 ReadWriteProperty 接口
class UpperCaseDelegate : ReadWriteProperty<Any?, String> {
    private var value: String = ""
    
    override fun getValue(thisRef: Any?, property: KProperty<*>): String {
        return value
    }
    
    override fun setValue(thisRef: Any?, property: KProperty<*>, value: String) {
        this.value = value.uppercase()
    }
}
```

---

## 15. 泛型

### 15.1 泛型类和函数

```kotlin
// 泛型类
class Box<T>(val value: T)

val intBox = Box(1)
val stringBox = Box("Hello")

// 泛型函数
fun <T> singletonList(item: T): List<T> {
    return listOf(item)
}

val list = singletonList("Hello")

// 多个类型参数
class Pair<K, V>(val first: K, val second: V)

val pair = Pair("key", 123)
```

### 15.2 类型约束

```kotlin
// 上界约束
fun <T : Comparable<T>> sort(list: List<T>): List<T> {
    return list.sorted()
}

// 多个约束
fun <T> copyWhenGreater(list: List<T>, threshold: T): List<T>
    where T : Comparable<T>,
          T : Number {
    return list.filter { it > threshold }
}
```

### 15.3 型变

```kotlin
// out - 协变（只能作为输出）
interface Producer<out T> {
    fun produce(): T
}

// in - 逆变（只能作为输入）
interface Consumer<in T> {
    fun consume(item: T)
}

// 示例
open class Animal
class Dog : Animal()

// 协变：Producer<Dog> 是 Producer<Animal> 的子类型
val dogProducer: Producer<Dog> = object : Producer<Dog> {
    override fun produce() = Dog()
}
val animalProducer: Producer<Animal> = dogProducer  // ✓

// 逆变：Consumer<Animal> 是 Consumer<Dog> 的子类型
val animalConsumer: Consumer<Animal> = object : Consumer<Animal> {
    override fun consume(item: Animal) {}
}
val dogConsumer: Consumer<Dog> = animalConsumer  // ✓
```

### 15.4 类型擦除和 reified

```kotlin
// 类型擦除：运行时泛型类型信息丢失
fun <T> isType(value: Any): Boolean {
    // return value is T  // ❌ 编译错误，无法检查泛型类型
    return false
}

// reified - 保留类型信息（只能用于 inline 函数）
inline fun <reified T> isType(value: Any): Boolean {
    return value is T  // ✓ 可以检查类型
}

println(isType<String>("Hello"))  // true
println(isType<Int>("Hello"))     // false

// 实际应用：类型安全的 JSON 解析
inline fun <reified T> parseJson(json: String): T {
    return Gson().fromJson(json, T::class.java)
}

val user: User = parseJson("""{"name":"张三","age":25}""")
```

### 15.5 星投影

```kotlin
// * 表示不关心具体类型
fun printList(list: List<*>) {
    list.forEach { println(it) }
}

// 等价于
fun printList(list: List<out Any?>) {
    list.forEach { println(it) }
}
```


---

## 16. Kotlin 与 Java 互操作

### 16.1 在 Kotlin 中调用 Java

```kotlin
// 直接调用 Java 类
import java.util.ArrayList
import java.util.Date

val list = ArrayList<String>()
list.add("Hello")

val date = Date()
println(date.time)

// Java getter/setter 自动转换为属性
// Java: person.getName() / person.setName("xxx")
// Kotlin:
val name = person.name
person.name = "张三"

// 调用 Java 静态方法
val max = Math.max(1, 2)

// 处理 Java 的 null
// Java 返回的类型是"平台类型"，需要自己处理
val result: String? = javaObject.getString()  // 安全方式
val result: String = javaObject.getString()   // 不安全，可能 NPE
```

### 16.2 在 Java 中调用 Kotlin

```kotlin
// Kotlin 文件：Utils.kt
package com.example

// 顶层函数
fun greet(name: String): String {
    return "Hello, $name!"
}

// 顶层属性
val PI = 3.14159

// 带 @JvmStatic 的伴生对象方法
class User {
    companion object {
        @JvmStatic
        fun create(name: String): User = User()
    }
}

// 带 @JvmField 的属性
class Config {
    @JvmField
    val version = "1.0.0"
}

// 带 @JvmOverloads 的默认参数
@JvmOverloads
fun connect(host: String, port: Int = 8080, timeout: Int = 3000) {
    // ...
}
```

```java
// Java 中调用
import com.example.UtilsKt;  // 顶层函数在 文件名Kt 类中

// 调用顶层函数
String greeting = UtilsKt.greet("World");

// 调用顶层属性
double pi = UtilsKt.getPI();

// 调用伴生对象方法
User user = User.create("张三");  // 因为有 @JvmStatic

// 访问字段
Config config = new Config();
String version = config.version;  // 因为有 @JvmField

// 调用带默认参数的函数
UtilsKt.connect("localhost");           // 使用默认端口和超时
UtilsKt.connect("localhost", 9090);     // 使用默认超时
UtilsKt.connect("localhost", 9090, 5000);
```

### 16.3 常用注解

```kotlin
// @JvmStatic - 生成静态方法
class Factory {
    companion object {
        @JvmStatic
        fun create(): Factory = Factory()
    }
}

// @JvmField - 暴露为字段而非 getter/setter
class Config {
    @JvmField
    val name = "config"
}

// @JvmOverloads - 为默认参数生成重载方法
@JvmOverloads
fun foo(a: Int, b: Int = 0, c: Int = 0) {}
// 生成：foo(int a), foo(int a, int b), foo(int a, int b, int c)

// @JvmName - 指定生成的 Java 方法名
@JvmName("getUsers")
fun users(): List<User> = listOf()

// @file:JvmName - 指定生成的类名
@file:JvmName("StringUtils")
package com.example

fun String.toSlug(): String = ...
// Java 中：StringUtils.toSlug(str)

// @Throws - 声明抛出的异常
@Throws(IOException::class)
fun readFile(path: String): String {
    // ...
}
```

### 16.4 SAM 转换

```kotlin
// Java 的函数式接口可以用 Lambda 表示
// Java:
// public interface OnClickListener {
//     void onClick(View v);
// }

// Kotlin 中使用
button.setOnClickListener { view ->
    println("点击了")
}

// 等价于
button.setOnClickListener(object : OnClickListener {
    override fun onClick(v: View) {
        println("点击了")
    }
})

// Kotlin 1.4+ 支持 Kotlin 接口的 SAM 转换
fun interface IntPredicate {
    fun accept(i: Int): Boolean
}

val isEven = IntPredicate { it % 2 == 0 }
```

---

## 17. 常见错误与解决方案

### 17.1 空指针相关

```kotlin
// 错误1：对可空类型直接调用方法
val name: String? = null
// name.length  // ❌ 编译错误

// 解决：使用安全调用
val length = name?.length

// 错误2：滥用 !!
val name: String? = getName()
val length = name!!.length  // ⚠️ 可能 NPE

// 解决：使用安全调用或 Elvis
val length = name?.length ?: 0

// 错误3：平台类型处理不当
val javaString = javaObject.getString()  // 平台类型
val length = javaString.length  // 可能 NPE

// 解决：明确声明可空性
val javaString: String? = javaObject.getString()
val length = javaString?.length ?: 0
```

### 17.2 集合相关

```kotlin
// 错误1：修改不可变集合
val list = listOf(1, 2, 3)
// list.add(4)  // ❌ 编译错误，List 没有 add 方法

// 解决：使用可变集合
val mutableList = mutableListOf(1, 2, 3)
mutableList.add(4)

// 错误2：ConcurrentModificationException
val list = mutableListOf(1, 2, 3, 4, 5)
for (item in list) {
    if (item % 2 == 0) {
        list.remove(item)  // ❌ 运行时异常
    }
}

// 解决：使用 removeIf 或创建新集合
list.removeIf { it % 2 == 0 }
// 或
val newList = list.filter { it % 2 != 0 }

// 错误3：误解 List 的不可变性
val list = listOf(mutableListOf(1, 2, 3))
list[0].add(4)  // ✓ 可以修改内部元素！

// 注意：listOf 创建的是"只读"集合，不是"不可变"集合
```

### 17.3 协程相关

```kotlin
// 错误1：在非协程环境调用挂起函数
suspend fun fetchData(): String {
    delay(1000)
    return "data"
}

// val data = fetchData()  // ❌ 编译错误

// 解决：在协程中调用
val data = runBlocking { fetchData() }
// 或
GlobalScope.launch { val data = fetchData() }

// 错误2：忘记等待协程完成
fun main() {
    GlobalScope.launch {
        delay(1000)
        println("协程完成")
    }
    // 程序立即结束，协程没有执行完
}

// 解决：使用 runBlocking 或 join
fun main() = runBlocking {
    launch {
        delay(1000)
        println("协程完成")
    }
}

// 错误3：协程异常处理不当
GlobalScope.launch {
    throw RuntimeException("出错了")  // 异常被吞掉
}

// 解决：使用 CoroutineExceptionHandler
val handler = CoroutineExceptionHandler { _, e ->
    println("捕获异常: ${e.message}")
}
GlobalScope.launch(handler) {
    throw RuntimeException("出错了")
}
```

### 17.4 类型相关

```kotlin
// 错误1：类型推断导致的问题
val list = listOf(1, 2, 3)  // List<Int>
// list.add("string")  // ❌ 类型不匹配

// 错误2：泛型类型擦除
fun <T> isType(value: Any): Boolean {
    // return value is T  // ❌ 编译错误
    return false
}

// 解决：使用 reified
inline fun <reified T> isType(value: Any): Boolean {
    return value is T
}

// 错误3：数组协变问题
val strings: Array<String> = arrayOf("a", "b")
// val anys: Array<Any> = strings  // ❌ 编译错误，数组不协变

// 解决：使用 List（协变）
val strings: List<String> = listOf("a", "b")
val anys: List<Any> = strings  // ✓
```

### 17.5 作用域函数相关

```kotlin
// 错误1：混淆 let 和 also 的返回值
val result = "Hello".let {
    it.length
}  // result = 5

val result = "Hello".also {
    it.length
}  // result = "Hello"

// 错误2：在 apply 中使用 it
val person = Person().apply {
    // it.name = "张三"  // ❌ apply 中没有 it
    name = "张三"  // ✓ 使用 this（可省略）
}

// 错误3：过度嵌套作用域函数
// ❌ 难以阅读
val result = a?.let { aValue ->
    b?.let { bValue ->
        c?.let { cValue ->
            aValue + bValue + cValue
        }
    }
}

// ✓ 更清晰的写法
val result = if (a != null && b != null && c != null) {
    a + b + c
} else {
    null
}
```


---

## 18. 最佳实践

### 18.1 命名规范

```kotlin
// 包名：小写，不使用下划线
package com.example.myproject

// 类名：大驼峰
class UserRepository
class HttpClient
data class UserDTO

// 函数名：小驼峰
fun getUserById(id: Long): User
fun calculateTotal(): Double

// 属性名：小驼峰
val userName: String
var isActive: Boolean

// 常量：大写下划线
const val MAX_COUNT = 100
val DEFAULT_NAME = "Unknown"  // 非 const 也可以用大写

// 枚举：大写下划线
enum class Status {
    PENDING, APPROVED, REJECTED
}

// 测试方法：可以使用反引号
@Test
fun `should return user when id exists`() { }
```

### 18.2 代码风格

```kotlin
// ✅ 优先使用 val
val name = "Kotlin"  // 优先
var count = 0        // 只在需要修改时使用

// ✅ 优先使用表达式
fun max(a: Int, b: Int) = if (a > b) a else b

// ✅ 使用命名参数提高可读性
createUser(
    name = "张三",
    age = 25,
    email = "zhangsan@example.com"
)

// ✅ 使用 when 替代多个 if-else
val result = when {
    score >= 90 -> "优秀"
    score >= 80 -> "良好"
    score >= 60 -> "及格"
    else -> "不及格"
}

// ✅ 使用解构声明
val (name, age) = user
for ((key, value) in map) { }

// ✅ 使用字符串模板
println("用户: $name, 年龄: $age")

// ✅ 使用作用域函数简化代码
val user = User().apply {
    name = "张三"
    age = 25
}

// ✅ 使用 Elvis 操作符
val displayName = name ?: "Unknown"
```

### 18.3 空安全最佳实践

```kotlin
// ✅ 尽量使用非空类型
class User(
    val name: String,      // 非空
    val email: String?,    // 只有真正可能为空时才用可空类型
)

// ✅ 使用安全调用链
val city = user?.address?.city ?: "未知"

// ✅ 使用 let 处理可空值
user?.let { 
    println("用户: ${it.name}")
}

// ✅ 使用 require/check 进行前置条件检查
fun process(name: String?) {
    requireNotNull(name) { "name 不能为空" }
    // 之后 name 自动变成非空类型
    println(name.length)
}

// ❌ 避免滥用 !!
val length = name!!.length  // 危险

// ✅ 使用 Elvis + throw/return
val length = name?.length ?: throw IllegalArgumentException("name 不能为空")
val length = name?.length ?: return
```

### 18.4 集合操作最佳实践

```kotlin
// ✅ 使用集合操作符而非循环
// ❌
val result = mutableListOf<Int>()
for (item in list) {
    if (item > 0) {
        result.add(item * 2)
    }
}

// ✅
val result = list.filter { it > 0 }.map { it * 2 }

// ✅ 大数据集使用序列
val result = bigList.asSequence()
    .filter { it > 0 }
    .map { it * 2 }
    .take(10)
    .toList()

// ✅ 使用 associate 创建 Map
val userMap = users.associateBy { it.id }

// ✅ 使用 groupBy 分组
val byStatus = orders.groupBy { it.status }

// ✅ 使用 partition 分成两组
val (adults, minors) = users.partition { it.age >= 18 }
```

### 18.5 类设计最佳实践

```kotlin
// ✅ 使用 data class 作为数据载体
data class User(
    val id: Long,
    val name: String,
    val email: String
)

// ✅ 使用 sealed class 表示有限状态
sealed class Result<out T> {
    data class Success<T>(val data: T) : Result<T>()
    data class Error(val message: String) : Result<Nothing>()
    object Loading : Result<Nothing>()
}

// ✅ 使用 object 实现单例
object DatabaseConfig {
    val url = "jdbc:mysql://localhost:3306/test"
}

// ✅ 使用伴生对象提供工厂方法
class User private constructor(val name: String) {
    companion object {
        fun create(name: String): User {
            require(name.isNotBlank()) { "name 不能为空" }
            return User(name)
        }
    }
}

// ✅ 使用扩展函数而非工具类
// ❌ Java 风格
object StringUtils {
    fun isEmail(str: String): Boolean = ...
}

// ✅ Kotlin 风格
fun String.isEmail(): Boolean = ...
```

### 18.6 协程最佳实践

```kotlin
// ✅ 使用结构化并发
class UserRepository(
    private val scope: CoroutineScope
) {
    fun fetchUser(id: Long) = scope.launch {
        // ...
    }
}

// ✅ 使用 withContext 切换调度器
suspend fun fetchData(): String = withContext(Dispatchers.IO) {
    // IO 操作
    api.getData()
}

// ✅ 使用 supervisorScope 隔离失败
suspend fun fetchAll() = supervisorScope {
    val a = async { fetchA() }
    val b = async { fetchB() }
    // a 失败不影响 b
}

// ✅ 正确处理异常
val handler = CoroutineExceptionHandler { _, e ->
    log.error("协程异常", e)
}

scope.launch(handler) {
    // ...
}

// ✅ 使用 Flow 处理数据流
fun observeUsers(): Flow<List<User>> = flow {
    while (true) {
        emit(fetchUsers())
        delay(5000)
    }
}
```

---

## 附录：速查表

### A. 常用操作符

| 操作符 | 说明 | 示例 |
|--------|------|------|
| ?. | 安全调用 | `name?.length` |
| ?: | Elvis | `name ?: "default"` |
| !! | 非空断言 | `name!!.length` |
| as? | 安全转换 | `obj as? String` |
| is | 类型检查 | `obj is String` |
| in | 包含检查 | `x in 1..10` |
| .. | 范围 | `1..10` |
| until | 不含末尾的范围 | `1 until 10` |
| step | 步长 | `1..10 step 2` |
| downTo | 递减范围 | `10 downTo 1` |

### B. 作用域函数对比

| 函数 | 对象引用 | 返回值 | 使用场景 |
|------|---------|--------|---------|
| let | it | Lambda 结果 | 空安全、转换 |
| run | this | Lambda 结果 | 配置并计算 |
| with | this | Lambda 结果 | 对象操作 |
| apply | this | 对象本身 | 对象初始化 |
| also | it | 对象本身 | 附加操作 |

### C. 集合操作速查

| 操作 | 函数 |
|------|------|
| 转换 | map, flatMap, mapNotNull |
| 过滤 | filter, filterNot, filterNotNull |
| 聚合 | reduce, fold, sum, count |
| 分组 | groupBy, partition, chunked |
| 排序 | sorted, sortedBy, reversed |
| 查找 | find, first, last, any, all, none |
| 取值 | take, drop, slice |

---

> 📝 **笔记完成**
> 
> 本笔记涵盖了 Kotlin 1.9.x 的核心内容：
> - 基础语法和数据类型
> - 空安全机制
> - 类、对象、继承
> - 集合操作和 Lambda
> - 协程异步编程
> - 扩展函数和委托
> - 泛型和型变
> - Java 互操作
> - 常见错误和最佳实践
> 
> Kotlin 是一门优雅的语言，建议多写代码，体会其简洁之美！
