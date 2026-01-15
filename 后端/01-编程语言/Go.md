# Go 语言完全指南

> Go（又称 Golang）是 Google 开发的一门静态类型、编译型编程语言
> 以简洁、高效、并发支持强大著称，特别适合构建高性能服务端应用

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [基本语法](#3-基本语法)
4. [数据类型](#4-数据类型)
5. [流程控制](#5-流程控制)
6. [函数](#6-函数)
7. [数组与切片](#7-数组与切片)
8. [Map](#8-map)
9. [结构体](#9-结构体)
10. [接口](#10-接口)
11. [错误处理](#11-错误处理)
12. [并发编程](#12-并发编程)
13. [包管理](#13-包管理)
14. [文件操作](#14-文件操作)
15. [网络编程](#15-网络编程)
16. [数据库操作](#16-数据库操作)
17. [测试](#17-测试)
18. [性能优化](#18-性能优化)
19. [常见错误与解决方案](#19-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Go？

Go 语言诞生于 2009 年，由 Robert Griesemer、Rob Pike 和 Ken Thompson 在 Google 设计。

**通俗理解**：
- Go 是一门"大道至简"的语言，语法简洁，关键字只有 25 个
- 编译速度极快，可以像脚本语言一样快速开发
- 原生支持并发，goroutine 让并发编程变得简单

**核心特点**：

1. **静态类型**：编译时检查类型，减少运行时错误
2. **编译型**：直接编译成机器码，执行效率高
3. **垃圾回收**：自动内存管理，无需手动释放
4. **原生并发**：goroutine + channel 实现 CSP 并发模型
5. **跨平台**：一次编写，编译到多个平台

```go
// 第一个 Go 程序
package main

import "fmt"

func main() {
    fmt.Println("Hello, Go!")
}
```

### 1.2 Go vs 其他语言

| 特性 | Go | Java | Python | C++ |
|------|-----|------|--------|-----|
| 类型系统 | 静态 | 静态 | 动态 | 静态 |
| 编译/解释 | 编译 | 编译+JVM | 解释 | 编译 |
| 垃圾回收 | ✅ | ✅ | ✅ | ❌ |
| 并发模型 | goroutine | 线程 | 线程/协程 | 线程 |
| 泛型 | ✅ (1.18+) | ✅ | ✅ | ✅ |
| 继承 | ❌ 组合 | ✅ | ✅ | ✅ |

### 1.3 适用场景

**适合的场景**：
- 云原生应用（Docker、Kubernetes 都是 Go 写的）
- 微服务架构
- 命令行工具
- 网络服务器
- 分布式系统

**不太适合的场景**：
- GUI 桌面应用
- 移动端开发
- 需要大量泛型的场景（虽然已支持，但生态还在完善）

---

## 2. 环境搭建

### 2.1 安装 Go

```bash
# Windows: 下载安装包
# https://go.dev/dl/

# macOS
brew install go

# Linux
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### 2.2 验证安装

```bash
# 查看版本
go version

# 查看环境变量
go env

# 重要环境变量
# GOROOT: Go 安装目录
# GOPATH: 工作目录（存放依赖）
# GOPROXY: 模块代理（国内推荐设置）
go env -w GOPROXY=https://goproxy.cn,direct
```

### 2.3 项目结构

```
myproject/
├── go.mod          # 模块定义文件
├── go.sum          # 依赖校验文件
├── main.go         # 入口文件
├── cmd/            # 命令行入口
│   └── server/
│       └── main.go
├── internal/       # 私有代码（不可被外部导入）
│   ├── handler/
│   └── service/
├── pkg/            # 公共代码（可被外部导入）
│   └── utils/
├── api/            # API 定义（protobuf、OpenAPI）
├── configs/        # 配置文件
└── test/           # 测试文件
```

### 2.4 初始化项目

```bash
# 创建项目目录
mkdir myproject && cd myproject

# 初始化模块
go mod init github.com/username/myproject

# 创建主文件
echo 'package main

import "fmt"

func main() {
    fmt.Println("Hello, Go!")
}' > main.go

# 运行
go run main.go

# 编译
go build -o myapp main.go

# 安装到 GOPATH/bin
go install
```

---

## 3. 基本语法

### 3.1 变量声明

Go 有多种变量声明方式，理解它们的使用场景很重要。

```go
package main

import "fmt"

func main() {
    // 方式一：完整声明
    var name string = "张三"
    
    // 方式二：类型推断
    var age = 25
    
    // 方式三：短变量声明（最常用，只能在函数内使用）
    city := "北京"
    
    // 方式四：批量声明
    var (
        width  = 100
        height = 200
    )
    
    // 常量声明
    const Pi = 3.14159
    const (
        StatusOK    = 200
        StatusError = 500
    )
    
    // iota：常量生成器
    const (
        Sunday = iota  // 0
        Monday         // 1
        Tuesday        // 2
    )
    
    fmt.Println(name, age, city, width, height)
}
```

**⚠️ 常见错误**：
```go
// ❌ 错误：短变量声明不能用于包级别
package main
name := "张三"  // 语法错误！

// ✅ 正确：包级别使用 var
var name = "张三"

// ❌ 错误：声明了变量但未使用
func main() {
    x := 10  // 编译错误：x declared but not used
}

// ✅ 正确：使用空白标识符忽略
func main() {
    x := 10
    _ = x  // 明确忽略
}

// ❌ 错误：重复声明
func main() {
    x := 10
    x := 20  // 编译错误：no new variables on left side
}

// ✅ 正确：赋值而非声明
func main() {
    x := 10
    x = 20  // 赋值
}
```

### 3.2 基本数据类型

```go
package main

import "fmt"

func main() {
    // 布尔型
    var isActive bool = true
    
    // 整型
    var i8 int8 = 127           // -128 ~ 127
    var i16 int16 = 32767       // -32768 ~ 32767
    var i32 int32 = 2147483647
    var i64 int64 = 9223372036854775807
    var i int = 100             // 根据平台 32 或 64 位
    
    // 无符号整型
    var u8 uint8 = 255          // 0 ~ 255
    var u16 uint16 = 65535
    var u32 uint32 = 4294967295
    var u64 uint64 = 18446744073709551615
    
    // 浮点型
    var f32 float32 = 3.14
    var f64 float64 = 3.141592653589793
    
    // 复数
    var c64 complex64 = 1 + 2i
    var c128 complex128 = 1 + 2i
    
    // 字符串
    var str string = "Hello, 世界"
    
    // 字节和字符
    var b byte = 'A'      // uint8 的别名
    var r rune = '中'     // int32 的别名，表示 Unicode 码点
    
    fmt.Printf("int: %d, float: %f, string: %s\n", i, f64, str)
}
```

### 3.3 类型转换

Go 不支持隐式类型转换，必须显式转换。

```go
package main

import (
    "fmt"
    "strconv"
)

func main() {
    // 数值类型转换
    var i int = 42
    var f float64 = float64(i)
    var u uint = uint(f)
    
    // ⚠️ 注意：可能丢失精度或溢出
    var big int64 = 1000
    var small int8 = int8(big)  // 溢出！结果是 -24
    
    // 字符串与数值转换
    // int -> string
    s1 := strconv.Itoa(42)           // "42"
    s2 := fmt.Sprintf("%d", 42)      // "42"
    
    // string -> int
    n1, err := strconv.Atoi("42")    // 42, nil
    n2, err := strconv.ParseInt("42", 10, 64)  // 42, nil
    
    // float -> string
    s3 := strconv.FormatFloat(3.14, 'f', 2, 64)  // "3.14"
    s4 := fmt.Sprintf("%.2f", 3.14)              // "3.14"
    
    // string -> float
    f1, err := strconv.ParseFloat("3.14", 64)    // 3.14, nil
    
    // bool -> string
    s5 := strconv.FormatBool(true)   // "true"
    
    // string -> bool
    b1, err := strconv.ParseBool("true")  // true, nil
    
    fmt.Println(s1, n1, f1, s5, b1, err)
}
```

**⚠️ 常见错误**：
```go
// ❌ 错误：直接将 int 转为 string
var i int = 65
s := string(i)  // 结果是 "A"（ASCII 码），不是 "65"！

// ✅ 正确：使用 strconv
s := strconv.Itoa(i)  // "65"

// ❌ 错误：忽略转换错误
n, _ := strconv.Atoi("abc")  // n = 0，错误被忽略

// ✅ 正确：检查错误
n, err := strconv.Atoi("abc")
if err != nil {
    fmt.Println("转换失败:", err)
}
```

### 3.4 字符串操作

```go
package main

import (
    "fmt"
    "strings"
    "unicode/utf8"
)

func main() {
    s := "Hello, 世界"
    
    // 长度
    fmt.Println(len(s))                    // 13（字节数）
    fmt.Println(utf8.RuneCountInString(s)) // 9（字符数）
    
    // 遍历
    // 按字节遍历
    for i := 0; i < len(s); i++ {
        fmt.Printf("%c ", s[i])  // 中文会乱码
    }
    
    // 按字符遍历（推荐）
    for i, r := range s {
        fmt.Printf("%d: %c\n", i, r)
    }
    
    // 字符串操作
    fmt.Println(strings.Contains(s, "世界"))     // true
    fmt.Println(strings.HasPrefix(s, "Hello"))  // true
    fmt.Println(strings.HasSuffix(s, "界"))     // true
    fmt.Println(strings.Index(s, "世"))         // 7
    fmt.Println(strings.ToUpper(s))             // HELLO, 世界
    fmt.Println(strings.ToLower(s))             // hello, 世界
    fmt.Println(strings.TrimSpace("  hello  ")) // "hello"
    fmt.Println(strings.Split("a,b,c", ","))    // [a b c]
    fmt.Println(strings.Join([]string{"a", "b"}, "-"))  // "a-b"
    fmt.Println(strings.Replace(s, "世界", "Go", 1))    // "Hello, Go"
    fmt.Println(strings.ReplaceAll(s, "l", "L"))        // "HeLLo, 世界"
    
    // 字符串构建（高效拼接）
    var builder strings.Builder
    builder.WriteString("Hello")
    builder.WriteString(", ")
    builder.WriteString("World")
    result := builder.String()  // "Hello, World"
    
    // 格式化
    name := "张三"
    age := 25
    msg := fmt.Sprintf("姓名: %s, 年龄: %d", name, age)
}
```

---

## 4. 数据类型

### 4.1 指针

Go 支持指针，但不支持指针运算，比 C 更安全。

```go
package main

import "fmt"

func main() {
    // 声明指针
    var p *int          // 零值是 nil
    
    // 获取变量地址
    x := 10
    p = &x              // p 指向 x
    
    // 解引用
    fmt.Println(*p)     // 10
    *p = 20             // 修改 x 的值
    fmt.Println(x)      // 20
    
    // new 函数：分配内存并返回指针
    p2 := new(int)      // *int，值为 0
    *p2 = 100
    
    // 指针作为函数参数（传引用）
    modify(&x)
    fmt.Println(x)      // 值被修改
}

func modify(p *int) {
    *p = 999
}
```

**⚠️ 常见错误**：
```go
// ❌ 错误：解引用 nil 指针
var p *int
fmt.Println(*p)  // panic: runtime error: invalid memory address

// ✅ 正确：先检查 nil
if p != nil {
    fmt.Println(*p)
}

// ❌ 错误：返回局部变量的指针（在 C 中是错误的，Go 中是安全的）
func createInt() *int {
    x := 10
    return &x  // Go 会自动将 x 分配到堆上，这是安全的
}
```

### 4.2 零值

Go 中所有变量都有零值，不存在未初始化的变量。

```go
package main

import "fmt"

func main() {
    var i int           // 0
    var f float64       // 0.0
    var b bool          // false
    var s string        // ""（空字符串）
    var p *int          // nil
    var slice []int     // nil
    var m map[string]int // nil
    var ch chan int     // nil
    var fn func()       // nil
    var iface interface{} // nil
    
    // 结构体的零值是所有字段的零值
    type Person struct {
        Name string
        Age  int
    }
    var person Person   // {"", 0}
    
    fmt.Printf("int: %d, float: %f, bool: %t, string: %q\n", i, f, b, s)
}
```

---

## 5. 流程控制

### 5.1 条件语句

```go
package main

import "fmt"

func main() {
    x := 10
    
    // 基本 if
    if x > 5 {
        fmt.Println("x 大于 5")
    }
    
    // if-else
    if x > 10 {
        fmt.Println("大于 10")
    } else if x > 5 {
        fmt.Println("大于 5，小于等于 10")
    } else {
        fmt.Println("小于等于 5")
    }
    
    // if 带初始化语句（变量作用域仅限于 if 块）
    if y := compute(); y > 0 {
        fmt.Println("y 是正数:", y)
    }
    // fmt.Println(y)  // 错误：y 在这里不可见
    
    // 常见模式：错误检查
    if err := doSomething(); err != nil {
        fmt.Println("出错了:", err)
        return
    }
}

func compute() int { return 42 }
func doSomething() error { return nil }
```

### 5.2 switch 语句

Go 的 switch 比其他语言更强大，不需要 break，支持多种形式。

```go
package main

import (
    "fmt"
    "runtime"
)

func main() {
    // 基本 switch
    day := 3
    switch day {
    case 1:
        fmt.Println("周一")
    case 2:
        fmt.Println("周二")
    case 3:
        fmt.Println("周三")
    default:
        fmt.Println("其他")
    }
    
    // 多值匹配
    switch day {
    case 1, 2, 3, 4, 5:
        fmt.Println("工作日")
    case 6, 7:
        fmt.Println("周末")
    }
    
    // 带初始化语句
    switch os := runtime.GOOS; os {
    case "darwin":
        fmt.Println("macOS")
    case "linux":
        fmt.Println("Linux")
    case "windows":
        fmt.Println("Windows")
    default:
        fmt.Println(os)
    }
    
    // 无表达式 switch（相当于 if-else 链）
    score := 85
    switch {
    case score >= 90:
        fmt.Println("优秀")
    case score >= 80:
        fmt.Println("良好")
    case score >= 60:
        fmt.Println("及格")
    default:
        fmt.Println("不及格")
    }
    
    // fallthrough：继续执行下一个 case
    n := 1
    switch n {
    case 1:
        fmt.Println("一")
        fallthrough  // 继续执行下一个 case
    case 2:
        fmt.Println("二")
    }
    // 输出：一 二
    
    // 类型 switch
    var i interface{} = "hello"
    switch v := i.(type) {
    case int:
        fmt.Println("int:", v)
    case string:
        fmt.Println("string:", v)
    case bool:
        fmt.Println("bool:", v)
    default:
        fmt.Println("未知类型")
    }
}
```

### 5.3 循环语句

Go 只有 for 循环，但可以实现所有循环形式。

```go
package main

import "fmt"

func main() {
    // 标准 for 循环
    for i := 0; i < 5; i++ {
        fmt.Println(i)
    }
    
    // while 形式
    n := 0
    for n < 5 {
        fmt.Println(n)
        n++
    }
    
    // 无限循环
    for {
        fmt.Println("无限循环")
        break  // 使用 break 退出
    }
    
    // range 遍历
    // 遍历切片
    nums := []int{1, 2, 3, 4, 5}
    for index, value := range nums {
        fmt.Printf("索引: %d, 值: %d\n", index, value)
    }
    
    // 只要值
    for _, value := range nums {
        fmt.Println(value)
    }
    
    // 只要索引
    for index := range nums {
        fmt.Println(index)
    }
    
    // 遍历 map
    m := map[string]int{"a": 1, "b": 2}
    for key, value := range m {
        fmt.Printf("%s: %d\n", key, value)
    }
    
    // 遍历字符串（按 rune）
    for i, r := range "Hello, 世界" {
        fmt.Printf("%d: %c\n", i, r)
    }
    
    // 遍历 channel
    ch := make(chan int, 3)
    ch <- 1
    ch <- 2
    ch <- 3
    close(ch)
    for v := range ch {
        fmt.Println(v)
    }
    
    // break 和 continue
    for i := 0; i < 10; i++ {
        if i == 3 {
            continue  // 跳过本次
        }
        if i == 7 {
            break     // 退出循环
        }
        fmt.Println(i)
    }
    
    // 带标签的 break（跳出多层循环）
outer:
    for i := 0; i < 3; i++ {
        for j := 0; j < 3; j++ {
            if i == 1 && j == 1 {
                break outer  // 跳出外层循环
            }
            fmt.Printf("i=%d, j=%d\n", i, j)
        }
    }
}
```

---

## 6. 函数

### 6.1 函数定义

```go
package main

import "fmt"

// 基本函数
func greet(name string) {
    fmt.Println("Hello,", name)
}

// 带返回值
func add(a, b int) int {
    return a + b
}

// 多返回值
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("除数不能为零")
    }
    return a / b, nil
}

// 命名返回值
func rectangle(width, height float64) (area, perimeter float64) {
    area = width * height
    perimeter = 2 * (width + height)
    return  // 裸返回，返回命名的返回值
}

// 可变参数
func sum(nums ...int) int {
    total := 0
    for _, n := range nums {
        total += n
    }
    return total
}

func main() {
    greet("张三")
    
    result := add(1, 2)
    fmt.Println(result)
    
    quotient, err := divide(10, 3)
    if err != nil {
        fmt.Println("错误:", err)
    } else {
        fmt.Println("结果:", quotient)
    }
    
    area, perimeter := rectangle(5, 3)
    fmt.Printf("面积: %.2f, 周长: %.2f\n", area, perimeter)
    
    fmt.Println(sum(1, 2, 3, 4, 5))  // 15
    
    // 展开切片作为可变参数
    nums := []int{1, 2, 3}
    fmt.Println(sum(nums...))  // 6
}
```

### 6.2 匿名函数与闭包

```go
package main

import "fmt"

func main() {
    // 匿名函数
    func() {
        fmt.Println("匿名函数")
    }()  // 立即调用
    
    // 赋值给变量
    add := func(a, b int) int {
        return a + b
    }
    fmt.Println(add(1, 2))
    
    // 闭包：函数可以访问外部变量
    counter := makeCounter()
    fmt.Println(counter())  // 1
    fmt.Println(counter())  // 2
    fmt.Println(counter())  // 3
    
    // 闭包陷阱
    var funcs []func()
    for i := 0; i < 3; i++ {
        // ❌ 错误：所有闭包共享同一个 i
        // funcs = append(funcs, func() {
        //     fmt.Println(i)  // 都会打印 3
        // })
        
        // ✅ 正确：创建局部变量
        i := i  // 创建新的局部变量
        funcs = append(funcs, func() {
            fmt.Println(i)
        })
    }
    for _, f := range funcs {
        f()  // 0, 1, 2
    }
}

// 返回闭包
func makeCounter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}
```

### 6.3 defer 延迟执行

defer 用于延迟执行函数，常用于资源清理。

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    // 基本用法
    defer fmt.Println("最后执行")
    fmt.Println("先执行")
    // 输出：先执行 最后执行
    
    // 多个 defer：后进先出（LIFO）
    defer fmt.Println("1")
    defer fmt.Println("2")
    defer fmt.Println("3")
    // 输出：3 2 1
    
    // 常见用法：关闭文件
    file, err := os.Open("test.txt")
    if err != nil {
        fmt.Println("打开文件失败:", err)
        return
    }
    defer file.Close()  // 确保文件被关闭
    
    // 读取文件...
    
    // defer 参数在声明时求值
    x := 10
    defer fmt.Println("x =", x)  // 打印 10，不是 20
    x = 20
}

// 实际应用：数据库事务
func updateUser(db *sql.DB) error {
    tx, err := db.Begin()
    if err != nil {
        return err
    }
    
    // 使用 defer 确保事务被处理
    defer func() {
        if err != nil {
            tx.Rollback()
        }
    }()
    
    // 执行更新...
    
    return tx.Commit()
}
```

### 6.4 panic 和 recover

panic 用于不可恢复的错误，recover 用于捕获 panic。

```go
package main

import "fmt"

func main() {
    // 使用 recover 捕获 panic
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("捕获到 panic:", r)
        }
    }()
    
    fmt.Println("开始")
    
    // 触发 panic
    panic("出错了！")
    
    fmt.Println("这行不会执行")
}

// 实际应用：安全的函数调用
func safeCall(fn func()) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %v", r)
        }
    }()
    
    fn()
    return nil
}

// 使用
func main() {
    err := safeCall(func() {
        panic("boom!")
    })
    if err != nil {
        fmt.Println("错误:", err)
    }
}
```

**⚠️ 最佳实践**：
```go
// ❌ 不推荐：用 panic 处理普通错误
func getUser(id int) *User {
    if id <= 0 {
        panic("无效的用户 ID")  // 不要这样做
    }
    // ...
}

// ✅ 推荐：返回 error
func getUser(id int) (*User, error) {
    if id <= 0 {
        return nil, fmt.Errorf("无效的用户 ID: %d", id)
    }
    // ...
}

// panic 适用场景：
// 1. 程序初始化失败（如配置文件不存在）
// 2. 不可能发生的情况（表示程序 bug）
// 3. 库的内部错误
```

---

## 7. 数组与切片

### 7.1 数组

数组是固定长度的同类型元素序列。

```go
package main

import "fmt"

func main() {
    // 声明数组
    var arr1 [5]int                    // [0 0 0 0 0]
    arr2 := [5]int{1, 2, 3, 4, 5}      // [1 2 3 4 5]
    arr3 := [...]int{1, 2, 3}          // 自动推断长度 [1 2 3]
    arr4 := [5]int{0: 1, 4: 5}         // 指定索引 [1 0 0 0 5]
    
    // 访问元素
    fmt.Println(arr2[0])  // 1
    arr2[0] = 10
    
    // 数组长度
    fmt.Println(len(arr2))  // 5
    
    // 遍历
    for i, v := range arr2 {
        fmt.Printf("arr2[%d] = %d\n", i, v)
    }
    
    // 多维数组
    matrix := [2][3]int{
        {1, 2, 3},
        {4, 5, 6},
    }
    fmt.Println(matrix[1][2])  // 6
    
    // ⚠️ 数组是值类型，赋值会复制
    a := [3]int{1, 2, 3}
    b := a        // 复制整个数组
    b[0] = 100
    fmt.Println(a)  // [1 2 3]（未改变）
    fmt.Println(b)  // [100 2 3]
}
```

### 7.2 切片

切片是动态数组，是 Go 中最常用的数据结构之一。

```go
package main

import "fmt"

func main() {
    // 创建切片
    var s1 []int                      // nil 切片
    s2 := []int{1, 2, 3}              // 字面量
    s3 := make([]int, 5)              // 长度 5，容量 5
    s4 := make([]int, 3, 10)          // 长度 3，容量 10
    
    // 从数组创建切片
    arr := [5]int{1, 2, 3, 4, 5}
    s5 := arr[1:4]                    // [2 3 4]
    s6 := arr[:3]                     // [1 2 3]
    s7 := arr[2:]                     // [3 4 5]
    s8 := arr[:]                      // [1 2 3 4 5]
    
    // 长度和容量
    fmt.Println(len(s4), cap(s4))     // 3, 10
    
    // 追加元素
    s2 = append(s2, 4)                // [1 2 3 4]
    s2 = append(s2, 5, 6, 7)          // [1 2 3 4 5 6 7]
    
    // 追加切片
    other := []int{8, 9}
    s2 = append(s2, other...)         // [1 2 3 4 5 6 7 8 9]
    
    // 复制切片
    src := []int{1, 2, 3}
    dst := make([]int, len(src))
    copy(dst, src)
    
    // 删除元素
    s := []int{1, 2, 3, 4, 5}
    // 删除索引 2 的元素
    s = append(s[:2], s[3:]...)       // [1 2 4 5]
    
    // 插入元素
    s = []int{1, 2, 4, 5}
    // 在索引 2 处插入 3
    s = append(s[:2], append([]int{3}, s[2:]...)...)  // [1 2 3 4 5]
}
```

### 7.3 切片内部原理

理解切片的内部结构对于避免常见错误很重要。

```go
// 切片的内部结构
type slice struct {
    array unsafe.Pointer  // 指向底层数组
    len   int             // 长度
    cap   int             // 容量
}
```

```go
package main

import "fmt"

func main() {
    // 切片共享底层数组
    arr := [5]int{1, 2, 3, 4, 5}
    s1 := arr[1:4]  // [2 3 4]
    s2 := arr[2:5]  // [3 4 5]
    
    s1[1] = 100     // 修改 s1
    fmt.Println(arr)  // [1 2 100 4 5]（arr 也被修改）
    fmt.Println(s2)   // [100 4 5]（s2 也被修改）
    
    // append 可能导致重新分配
    s := make([]int, 3, 5)  // len=3, cap=5
    s[0], s[1], s[2] = 1, 2, 3
    
    s2 = s[:]
    s = append(s, 4, 5)     // 未超过容量，共享底层数组
    s[0] = 100
    fmt.Println(s2[0])      // 100（被影响）
    
    s = append(s, 6)        // 超过容量，重新分配
    s[0] = 200
    fmt.Println(s2[0])      // 100（不再共享）
}
```

**⚠️ 常见错误**：
```go
// ❌ 错误：在 nil 切片上操作
var s []int
s[0] = 1  // panic: index out of range

// ✅ 正确：使用 append
var s []int
s = append(s, 1)

// ❌ 错误：忘记接收 append 的返回值
s := []int{1, 2, 3}
append(s, 4)  // 返回值被丢弃，s 未改变

// ✅ 正确：接收返回值
s = append(s, 4)

// ❌ 错误：切片作为参数时的陷阱
func modify(s []int) {
    s[0] = 100      // 会影响原切片
    s = append(s, 4) // 不会影响原切片（如果发生重新分配）
}

// ✅ 正确：返回新切片
func modify(s []int) []int {
    s[0] = 100
    s = append(s, 4)
    return s
}
```

---

## 8. Map

Map 是 Go 中的哈希表实现，存储键值对。

### 8.1 基本操作

```go
package main

import "fmt"

func main() {
    // 创建 map
    var m1 map[string]int             // nil map，不能写入
    m2 := map[string]int{}            // 空 map
    m3 := make(map[string]int)        // 空 map
    m4 := make(map[string]int, 100)   // 预分配容量
    m5 := map[string]int{             // 字面量
        "apple":  1,
        "banana": 2,
    }
    
    // 添加/修改元素
    m3["key"] = 100
    
    // 获取元素
    value := m5["apple"]
    fmt.Println(value)  // 1
    
    // 检查键是否存在
    value, ok := m5["orange"]
    if ok {
        fmt.Println("存在:", value)
    } else {
        fmt.Println("不存在")
    }
    
    // 删除元素
    delete(m5, "apple")
    
    // 获取长度
    fmt.Println(len(m5))
    
    // 遍历（顺序不确定）
    for key, value := range m5 {
        fmt.Printf("%s: %d\n", key, value)
    }
    
    // 只遍历键
    for key := range m5 {
        fmt.Println(key)
    }
}
```

### 8.2 Map 进阶

```go
package main

import (
    "fmt"
    "sort"
)

func main() {
    // map 的值可以是任意类型
    // 值为切片
    m1 := map[string][]int{
        "odds":  {1, 3, 5},
        "evens": {2, 4, 6},
    }
    
    // 值为 map（嵌套）
    m2 := map[string]map[string]int{
        "user1": {"age": 25, "score": 90},
        "user2": {"age": 30, "score": 85},
    }
    
    // 值为结构体
    type User struct {
        Name string
        Age  int
    }
    m3 := map[int]User{
        1: {"张三", 25},
        2: {"李四", 30},
    }
    
    // 按键排序遍历
    m := map[string]int{"c": 3, "a": 1, "b": 2}
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    for _, k := range keys {
        fmt.Printf("%s: %d\n", k, m[k])
    }
    
    // 使用 map 实现 Set
    set := make(map[string]struct{})  // 空结构体不占内存
    set["apple"] = struct{}{}
    set["banana"] = struct{}{}
    
    // 检查是否存在
    if _, ok := set["apple"]; ok {
        fmt.Println("apple 存在")
    }
}
```

**⚠️ 常见错误**：
```go
// ❌ 错误：向 nil map 写入
var m map[string]int
m["key"] = 1  // panic: assignment to entry in nil map

// ✅ 正确：先初始化
m := make(map[string]int)
m["key"] = 1

// ❌ 错误：并发读写 map
// map 不是并发安全的，并发读写会 panic
go func() { m["a"] = 1 }()
go func() { _ = m["a"] }()

// ✅ 正确：使用 sync.Map 或加锁
import "sync"

var mu sync.RWMutex
var m = make(map[string]int)

// 写
mu.Lock()
m["key"] = 1
mu.Unlock()

// 读
mu.RLock()
v := m["key"]
mu.RUnlock()

// 或使用 sync.Map
var sm sync.Map
sm.Store("key", 1)
v, ok := sm.Load("key")

// ❌ 错误：直接修改 map 中结构体的字段
type User struct {
    Name string
    Age  int
}
m := map[int]User{1: {"张三", 25}}
m[1].Age = 26  // 编译错误：cannot assign to struct field

// ✅ 正确：整体替换或使用指针
m[1] = User{"张三", 26}
// 或
m2 := map[int]*User{1: {"张三", 25}}
m2[1].Age = 26  // OK
```

---

## 9. 结构体

### 9.1 定义与使用

```go
package main

import "fmt"

// 定义结构体
type Person struct {
    Name    string
    Age     int
    Email   string
    Address Address  // 嵌套结构体
}

type Address struct {
    City    string
    Street  string
}

func main() {
    // 创建结构体
    // 方式一：零值
    var p1 Person
    
    // 方式二：字面量
    p2 := Person{
        Name:  "张三",
        Age:   25,
        Email: "zhangsan@example.com",
        Address: Address{
            City:   "北京",
            Street: "长安街",
        },
    }
    
    // 方式三：按顺序（不推荐，可读性差）
    p3 := Person{"李四", 30, "lisi@example.com", Address{"上海", "南京路"}}
    
    // 方式四：new（返回指针）
    p4 := new(Person)
    p4.Name = "王五"
    
    // 方式五：取地址
    p5 := &Person{Name: "赵六", Age: 35}
    
    // 访问字段
    fmt.Println(p2.Name)
    fmt.Println(p2.Address.City)
    
    // 修改字段
    p2.Age = 26
    
    // 指针访问（自动解引用）
    fmt.Println(p5.Name)  // 等同于 (*p5).Name
}
```

### 9.2 方法

```go
package main

import (
    "fmt"
    "math"
)

type Rectangle struct {
    Width  float64
    Height float64
}

// 值接收者方法
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}

// 指针接收者方法（可以修改结构体）
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}

// 值接收者 vs 指针接收者
// 使用指针接收者的情况：
// 1. 需要修改接收者
// 2. 结构体较大，避免复制
// 3. 保持一致性（如果有一个方法用指针，其他也用指针）

type Circle struct {
    Radius float64
}

func (c Circle) Area() float64 {
    return math.Pi * c.Radius * c.Radius
}

func main() {
    rect := Rectangle{Width: 10, Height: 5}
    fmt.Println("面积:", rect.Area())
    
    rect.Scale(2)
    fmt.Println("缩放后:", rect.Width, rect.Height)
    
    // 指针也可以调用值方法（自动解引用）
    rectPtr := &Rectangle{Width: 3, Height: 4}
    fmt.Println("面积:", rectPtr.Area())
}
```

### 9.3 结构体嵌入（组合）

Go 没有继承，使用组合实现代码复用。

```go
package main

import "fmt"

// 基础结构体
type Animal struct {
    Name string
    Age  int
}

func (a Animal) Eat() {
    fmt.Println(a.Name, "正在吃东西")
}

// 嵌入结构体
type Dog struct {
    Animal        // 匿名嵌入
    Breed  string
}

func (d Dog) Bark() {
    fmt.Println(d.Name, "汪汪叫")
}

// 方法重写
func (d Dog) Eat() {
    fmt.Println(d.Name, "正在吃狗粮")
}

type Cat struct {
    Animal
}

func main() {
    dog := Dog{
        Animal: Animal{Name: "旺财", Age: 3},
        Breed:  "金毛",
    }
    
    // 直接访问嵌入结构体的字段
    fmt.Println(dog.Name)   // 等同于 dog.Animal.Name
    fmt.Println(dog.Age)
    fmt.Println(dog.Breed)
    
    // 调用嵌入结构体的方法
    dog.Eat()   // 调用 Dog.Eat()（重写的方法）
    dog.Animal.Eat()  // 调用 Animal.Eat()
    dog.Bark()
    
    cat := Cat{Animal: Animal{Name: "咪咪", Age: 2}}
    cat.Eat()   // 调用 Animal.Eat()
}
```

### 9.4 结构体标签

标签用于为字段添加元信息，常用于 JSON 序列化、ORM 等。

```go
package main

import (
    "encoding/json"
    "fmt"
)

type User struct {
    ID        int    `json:"id" db:"user_id"`
    Name      string `json:"name" db:"user_name"`
    Email     string `json:"email,omitempty"`  // 空值时省略
    Password  string `json:"-"`                 // 忽略该字段
    Age       int    `json:"age,string"`        // 序列化为字符串
    CreatedAt string `json:"created_at"`
}

func main() {
    user := User{
        ID:       1,
        Name:     "张三",
        Email:    "",
        Password: "secret",
        Age:      25,
    }
    
    // 序列化
    data, _ := json.Marshal(user)
    fmt.Println(string(data))
    // {"id":1,"name":"张三","age":"25","created_at":""}
    
    // 反序列化
    jsonStr := `{"id":2,"name":"李四","email":"lisi@example.com"}`
    var user2 User
    json.Unmarshal([]byte(jsonStr), &user2)
    fmt.Printf("%+v\n", user2)
    
    // 使用反射获取标签
    import "reflect"
    t := reflect.TypeOf(user)
    field, _ := t.FieldByName("Name")
    fmt.Println(field.Tag.Get("json"))  // name
    fmt.Println(field.Tag.Get("db"))    // user_name
}
```

---

## 10. 接口

### 10.1 接口定义与实现

Go 的接口是隐式实现的，不需要显式声明。

```go
package main

import (
    "fmt"
    "math"
)

// 定义接口
type Shape interface {
    Area() float64
    Perimeter() float64
}

// 实现接口（隐式）
type Rectangle struct {
    Width, Height float64
}

func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}

func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}

type Circle struct {
    Radius float64
}

func (c Circle) Area() float64 {
    return math.Pi * c.Radius * c.Radius
}

func (c Circle) Perimeter() float64 {
    return 2 * math.Pi * c.Radius
}

// 使用接口
func PrintShapeInfo(s Shape) {
    fmt.Printf("面积: %.2f, 周长: %.2f\n", s.Area(), s.Perimeter())
}

func main() {
    rect := Rectangle{Width: 10, Height: 5}
    circle := Circle{Radius: 3}
    
    PrintShapeInfo(rect)
    PrintShapeInfo(circle)
    
    // 接口切片
    shapes := []Shape{rect, circle}
    for _, s := range shapes {
        PrintShapeInfo(s)
    }
}
```

### 10.2 空接口与类型断言

```go
package main

import "fmt"

func main() {
    // 空接口可以存储任意类型
    var i interface{}
    i = 42
    i = "hello"
    i = []int{1, 2, 3}
    
    // any 是 interface{} 的别名（Go 1.18+）
    var a any = "world"
    
    // 类型断言
    var x interface{} = "hello"
    
    // 方式一：直接断言（失败会 panic）
    s := x.(string)
    fmt.Println(s)
    
    // 方式二：安全断言
    s, ok := x.(string)
    if ok {
        fmt.Println("是字符串:", s)
    }
    
    // 类型 switch
    switch v := x.(type) {
    case int:
        fmt.Println("int:", v)
    case string:
        fmt.Println("string:", v)
    case bool:
        fmt.Println("bool:", v)
    default:
        fmt.Println("未知类型")
    }
    
    // 实际应用：处理 JSON
    data := map[string]interface{}{
        "name": "张三",
        "age":  25,
        "tags": []string{"go", "python"},
    }
    
    if name, ok := data["name"].(string); ok {
        fmt.Println("姓名:", name)
    }
}
```

### 10.3 常用接口

```go
package main

import (
    "fmt"
    "io"
    "sort"
    "strings"
)

// Stringer 接口（类似 Java 的 toString）
type Person struct {
    Name string
    Age  int
}

func (p Person) String() string {
    return fmt.Sprintf("Person{Name: %s, Age: %d}", p.Name, p.Age)
}

// error 接口
type MyError struct {
    Code    int
    Message string
}

func (e MyError) Error() string {
    return fmt.Sprintf("错误 %d: %s", e.Code, e.Message)
}

// io.Reader 和 io.Writer
func readAll(r io.Reader) ([]byte, error) {
    return io.ReadAll(r)
}

// sort.Interface
type ByAge []Person

func (a ByAge) Len() int           { return len(a) }
func (a ByAge) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByAge) Less(i, j int) bool { return a[i].Age < a[j].Age }

func main() {
    // Stringer
    p := Person{Name: "张三", Age: 25}
    fmt.Println(p)  // Person{Name: 张三, Age: 25}
    
    // error
    err := MyError{Code: 404, Message: "未找到"}
    fmt.Println(err)  // 错误 404: 未找到
    
    // io.Reader
    reader := strings.NewReader("Hello, World!")
    data, _ := readAll(reader)
    fmt.Println(string(data))
    
    // sort.Interface
    people := []Person{
        {"张三", 30},
        {"李四", 25},
        {"王五", 35},
    }
    sort.Sort(ByAge(people))
    fmt.Println(people)  // 按年龄排序
    
    // 使用 sort.Slice（更简洁）
    sort.Slice(people, func(i, j int) bool {
        return people[i].Age < people[j].Age
    })
}
```

### 10.4 接口组合

```go
package main

import "io"

// 接口组合
type ReadWriter interface {
    io.Reader
    io.Writer
}

type ReadWriteCloser interface {
    io.Reader
    io.Writer
    io.Closer
}

// 自定义接口组合
type Saver interface {
    Save() error
}

type Loader interface {
    Load() error
}

type Storage interface {
    Saver
    Loader
}

// 实现
type FileStorage struct {
    Path string
}

func (f *FileStorage) Save() error {
    // 保存到文件
    return nil
}

func (f *FileStorage) Load() error {
    // 从文件加载
    return nil
}

// FileStorage 自动实现了 Storage 接口
```

---

## 11. 错误处理

### 11.1 error 接口

```go
package main

import (
    "errors"
    "fmt"
)

// error 是一个接口
// type error interface {
//     Error() string
// }

func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("除数不能为零")
    }
    return a / b, nil
}

func main() {
    result, err := divide(10, 0)
    if err != nil {
        fmt.Println("错误:", err)
        return
    }
    fmt.Println("结果:", result)
}
```

### 11.2 自定义错误

```go
package main

import (
    "fmt"
)

// 自定义错误类型
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("验证错误 [%s]: %s", e.Field, e.Message)
}

// 带错误码的错误
type AppError struct {
    Code    int
    Message string
    Err     error  // 原始错误
}

func (e *AppError) Error() string {
    if e.Err != nil {
        return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Err)
    }
    return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
    return e.Err
}

// 使用
func validateUser(name string) error {
    if name == "" {
        return &ValidationError{
            Field:   "name",
            Message: "不能为空",
        }
    }
    return nil
}

func main() {
    err := validateUser("")
    if err != nil {
        // 类型断言获取详细信息
        if ve, ok := err.(*ValidationError); ok {
            fmt.Println("字段:", ve.Field)
            fmt.Println("消息:", ve.Message)
        }
    }
}
```

### 11.3 错误包装与检查（Go 1.13+）

```go
package main

import (
    "errors"
    "fmt"
    "os"
)

// 哨兵错误
var (
    ErrNotFound     = errors.New("未找到")
    ErrUnauthorized = errors.New("未授权")
    ErrInternal     = errors.New("内部错误")
)

func findUser(id int) error {
    // 包装错误，添加上下文
    return fmt.Errorf("查找用户 %d 失败: %w", id, ErrNotFound)
}

func main() {
    err := findUser(123)
    
    // errors.Is：检查错误链中是否包含特定错误
    if errors.Is(err, ErrNotFound) {
        fmt.Println("用户不存在")
    }
    
    // errors.As：提取特定类型的错误
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        fmt.Println("路径错误:", pathErr.Path)
    }
    
    // errors.Unwrap：获取被包装的错误
    unwrapped := errors.Unwrap(err)
    fmt.Println("原始错误:", unwrapped)
    
    // 多错误合并（Go 1.20+）
    err1 := errors.New("错误1")
    err2 := errors.New("错误2")
    combined := errors.Join(err1, err2)
    fmt.Println(combined)
}
```

### 11.4 错误处理最佳实践

```go
package main

import (
    "errors"
    "fmt"
    "log"
)

// 1. 尽早返回，减少嵌套
// ❌ 不推荐
func processData(data []byte) error {
    if data != nil {
        if len(data) > 0 {
            // 处理数据
            return nil
        } else {
            return errors.New("数据为空")
        }
    } else {
        return errors.New("数据为 nil")
    }
}

// ✅ 推荐
func processData(data []byte) error {
    if data == nil {
        return errors.New("数据为 nil")
    }
    if len(data) == 0 {
        return errors.New("数据为空")
    }
    // 处理数据
    return nil
}

// 2. 添加上下文信息
func readConfig(path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
    }
    // ...
}

// 3. 只处理一次错误
// ❌ 不推荐：既记录又返回
func doSomething() error {
    err := someOperation()
    if err != nil {
        log.Println("操作失败:", err)  // 记录
        return err                      // 又返回
    }
    return nil
}

// ✅ 推荐：要么处理，要么返回
func doSomething() error {
    err := someOperation()
    if err != nil {
        return fmt.Errorf("操作失败: %w", err)
    }
    return nil
}

// 4. 使用 defer 简化清理
func processFile(path string) (err error) {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    defer func() {
        if cerr := f.Close(); cerr != nil && err == nil {
            err = cerr
        }
    }()
    
    // 处理文件...
    return nil
}
```

---

## 12. 并发编程

### 12.1 Goroutine

Goroutine 是 Go 的轻量级线程，由 Go 运行时管理。

```go
package main

import (
    "fmt"
    "time"
)

func sayHello(name string) {
    for i := 0; i < 3; i++ {
        fmt.Println("Hello,", name)
        time.Sleep(100 * time.Millisecond)
    }
}

func main() {
    // 启动 goroutine
    go sayHello("张三")
    go sayHello("李四")
    
    // 匿名函数
    go func() {
        fmt.Println("匿名 goroutine")
    }()
    
    // 带参数的匿名函数
    name := "王五"
    go func(n string) {
        fmt.Println("Hello,", n)
    }(name)  // 传递参数，避免闭包陷阱
    
    // 等待 goroutine 完成（简单方式）
    time.Sleep(time.Second)
    
    fmt.Println("主函数结束")
}
```

**⚠️ 常见错误**：
```go
// ❌ 错误：闭包陷阱
for i := 0; i < 3; i++ {
    go func() {
        fmt.Println(i)  // 可能都打印 3
    }()
}

// ✅ 正确：传递参数
for i := 0; i < 3; i++ {
    go func(n int) {
        fmt.Println(n)  // 0, 1, 2
    }(i)
}

// ❌ 错误：主函数提前退出
func main() {
    go doWork()
    // 主函数立即退出，goroutine 可能没执行完
}

// ✅ 正确：等待 goroutine 完成
func main() {
    var wg sync.WaitGroup
    wg.Add(1)
    go func() {
        defer wg.Done()
        doWork()
    }()
    wg.Wait()
}
```

### 12.2 Channel

Channel 是 goroutine 之间通信的管道。

```go
package main

import "fmt"

func main() {
    // 创建 channel
    ch := make(chan int)        // 无缓冲 channel
    buffered := make(chan int, 3)  // 缓冲 channel，容量 3
    
    // 发送和接收
    go func() {
        ch <- 42  // 发送
    }()
    value := <-ch  // 接收
    fmt.Println(value)
    
    // 缓冲 channel
    buffered <- 1
    buffered <- 2
    buffered <- 3
    // buffered <- 4  // 阻塞，缓冲区已满
    
    fmt.Println(<-buffered)  // 1
    fmt.Println(<-buffered)  // 2
    
    // 关闭 channel
    close(buffered)
    
    // 从已关闭的 channel 接收
    v, ok := <-buffered
    if ok {
        fmt.Println("收到:", v)
    } else {
        fmt.Println("channel 已关闭")
    }
    
    // 遍历 channel
    ch2 := make(chan int, 5)
    go func() {
        for i := 0; i < 5; i++ {
            ch2 <- i
        }
        close(ch2)  // 必须关闭，否则 range 会阻塞
    }()
    
    for v := range ch2 {
        fmt.Println(v)
    }
}
```

### 12.3 Channel 模式

```go
package main

import (
    "fmt"
    "time"
)

// 生产者-消费者模式
func producer(ch chan<- int) {  // 只写 channel
    for i := 0; i < 5; i++ {
        ch <- i
        time.Sleep(100 * time.Millisecond)
    }
    close(ch)
}

func consumer(ch <-chan int) {  // 只读 channel
    for v := range ch {
        fmt.Println("消费:", v)
    }
}

// 扇出：一个输入，多个输出
func fanOut(input <-chan int, outputs ...chan<- int) {
    for v := range input {
        for _, out := range outputs {
            out <- v
        }
    }
    for _, out := range outputs {
        close(out)
    }
}

// 扇入：多个输入，一个输出
func fanIn(inputs ...<-chan int) <-chan int {
    output := make(chan int)
    var wg sync.WaitGroup
    
    for _, input := range inputs {
        wg.Add(1)
        go func(ch <-chan int) {
            defer wg.Done()
            for v := range ch {
                output <- v
            }
        }(input)
    }
    
    go func() {
        wg.Wait()
        close(output)
    }()
    
    return output
}

// 工作池模式
func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d 处理任务 %d\n", id, job)
        time.Sleep(100 * time.Millisecond)
        results <- job * 2
    }
}

func main() {
    // 生产者-消费者
    ch := make(chan int)
    go producer(ch)
    consumer(ch)
    
    // 工作池
    jobs := make(chan int, 100)
    results := make(chan int, 100)
    
    // 启动 3 个 worker
    for w := 1; w <= 3; w++ {
        go worker(w, jobs, results)
    }
    
    // 发送任务
    for j := 1; j <= 9; j++ {
        jobs <- j
    }
    close(jobs)
    
    // 收集结果
    for r := 1; r <= 9; r++ {
        <-results
    }
}
```

### 12.4 select 语句

select 用于同时等待多个 channel 操作。

```go
package main

import (
    "fmt"
    "time"
)

func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)
    
    go func() {
        time.Sleep(100 * time.Millisecond)
        ch1 <- "来自 ch1"
    }()
    
    go func() {
        time.Sleep(200 * time.Millisecond)
        ch2 <- "来自 ch2"
    }()
    
    // select 等待多个 channel
    for i := 0; i < 2; i++ {
        select {
        case msg1 := <-ch1:
            fmt.Println(msg1)
        case msg2 := <-ch2:
            fmt.Println(msg2)
        }
    }
    
    // 带超时的 select
    select {
    case msg := <-ch1:
        fmt.Println(msg)
    case <-time.After(500 * time.Millisecond):
        fmt.Println("超时")
    }
    
    // 非阻塞操作
    select {
    case msg := <-ch1:
        fmt.Println(msg)
    default:
        fmt.Println("没有数据")
    }
    
    // 退出信号
    done := make(chan struct{})
    go func() {
        for {
            select {
            case <-done:
                fmt.Println("收到退出信号")
                return
            default:
                // 执行工作
                time.Sleep(100 * time.Millisecond)
            }
        }
    }()
    
    time.Sleep(500 * time.Millisecond)
    close(done)  // 发送退出信号
}
```

### 12.5 sync 包

```go
package main

import (
    "fmt"
    "sync"
    "sync/atomic"
)

func main() {
    // WaitGroup：等待一组 goroutine 完成
    var wg sync.WaitGroup
    
    for i := 0; i < 5; i++ {
        wg.Add(1)
        go func(n int) {
            defer wg.Done()
            fmt.Println("Worker", n)
        }(i)
    }
    
    wg.Wait()
    fmt.Println("所有 worker 完成")
    
    // Mutex：互斥锁
    var mu sync.Mutex
    counter := 0
    
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            mu.Lock()
            counter++
            mu.Unlock()
        }()
    }
    wg.Wait()
    fmt.Println("Counter:", counter)
    
    // RWMutex：读写锁
    var rwmu sync.RWMutex
    data := make(map[string]string)
    
    // 写操作
    go func() {
        rwmu.Lock()
        data["key"] = "value"
        rwmu.Unlock()
    }()
    
    // 读操作（可并发）
    go func() {
        rwmu.RLock()
        _ = data["key"]
        rwmu.RUnlock()
    }()
    
    // Once：只执行一次
    var once sync.Once
    initFunc := func() {
        fmt.Println("初始化（只执行一次）")
    }
    
    for i := 0; i < 10; i++ {
        go once.Do(initFunc)
    }
    
    // atomic：原子操作
    var atomicCounter int64
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            atomic.AddInt64(&atomicCounter, 1)
        }()
    }
    wg.Wait()
    fmt.Println("Atomic Counter:", atomicCounter)
    
    // Pool：对象池
    pool := sync.Pool{
        New: func() interface{} {
            return make([]byte, 1024)
        },
    }
    
    buf := pool.Get().([]byte)
    // 使用 buf...
    pool.Put(buf)  // 归还
}
```

### 12.6 context 包

context 用于控制 goroutine 的生命周期和传递请求范围的值。

```go
package main

import (
    "context"
    "fmt"
    "time"
)

func main() {
    // 带取消的 context
    ctx, cancel := context.WithCancel(context.Background())
    
    go func(ctx context.Context) {
        for {
            select {
            case <-ctx.Done():
                fmt.Println("收到取消信号:", ctx.Err())
                return
            default:
                fmt.Println("工作中...")
                time.Sleep(200 * time.Millisecond)
            }
        }
    }(ctx)
    
    time.Sleep(1 * time.Second)
    cancel()  // 取消
    time.Sleep(100 * time.Millisecond)
    
    // 带超时的 context
    ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
    defer cancel2()
    
    select {
    case <-time.After(1 * time.Second):
        fmt.Println("操作完成")
    case <-ctx2.Done():
        fmt.Println("超时:", ctx2.Err())
    }
    
    // 带截止时间的 context
    deadline := time.Now().Add(500 * time.Millisecond)
    ctx3, cancel3 := context.WithDeadline(context.Background(), deadline)
    defer cancel3()
    
    // 带值的 context
    type key string
    ctx4 := context.WithValue(context.Background(), key("userID"), 123)
    
    userID := ctx4.Value(key("userID")).(int)
    fmt.Println("User ID:", userID)
}

// 实际应用：HTTP 请求处理
func handleRequest(ctx context.Context) error {
    // 检查是否已取消
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    // 传递 context 给下游
    result, err := queryDatabase(ctx)
    if err != nil {
        return err
    }
    
    return nil
}
```

---

## 13. 包管理

### 13.1 Go Modules

Go Modules 是 Go 官方的依赖管理方案。

```bash
# 初始化模块
go mod init github.com/username/project

# 添加依赖
go get github.com/gin-gonic/gin
go get github.com/gin-gonic/gin@v1.9.0  # 指定版本
go get github.com/gin-gonic/gin@latest  # 最新版本

# 更新依赖
go get -u github.com/gin-gonic/gin      # 更新到最新
go get -u ./...                          # 更新所有依赖

# 整理依赖
go mod tidy  # 添加缺失的依赖，移除未使用的依赖

# 下载依赖
go mod download

# 查看依赖
go list -m all

# 查看依赖图
go mod graph

# 验证依赖
go mod verify

# 替换依赖（本地开发）
go mod edit -replace github.com/old/pkg=../local/pkg
```

### 13.2 go.mod 文件

```go
module github.com/username/project

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/go-sql-driver/mysql v1.7.0
    gorm.io/gorm v1.25.0
)

require (
    // 间接依赖
    github.com/bytedance/sonic v1.9.1 // indirect
)

// 替换依赖
replace github.com/old/pkg => github.com/new/pkg v1.0.0

// 排除版本
exclude github.com/bad/pkg v1.0.0

// 撤回版本（用于库作者）
retract v1.0.0
```

### 13.3 包的组织

```go
// 包声明
package mypackage

// 导入
import (
    // 标准库
    "fmt"
    "net/http"
    
    // 第三方包
    "github.com/gin-gonic/gin"
    
    // 本地包
    "github.com/username/project/internal/service"
    
    // 别名
    myjson "encoding/json"
    
    // 匿名导入（只执行 init 函数）
    _ "github.com/go-sql-driver/mysql"
    
    // 点导入（不推荐）
    . "fmt"  // 可以直接使用 Println 而不是 fmt.Println
)

// 导出规则：首字母大写的标识符是公开的
func PublicFunc() {}   // 公开
func privateFunc() {}  // 私有

type PublicStruct struct {
    PublicField  string  // 公开
    privateField string  // 私有
}

// init 函数：包初始化时自动执行
func init() {
    fmt.Println("包初始化")
}
```

---

## 14. 文件操作

### 14.1 基本文件操作

```go
package main

import (
    "bufio"
    "fmt"
    "io"
    "os"
)

func main() {
    // 创建文件
    file, err := os.Create("test.txt")
    if err != nil {
        panic(err)
    }
    defer file.Close()
    
    // 写入文件
    file.WriteString("Hello, World!\n")
    file.Write([]byte("第二行\n"))
    
    // 读取整个文件
    data, err := os.ReadFile("test.txt")
    if err != nil {
        panic(err)
    }
    fmt.Println(string(data))
    
    // 写入整个文件
    err = os.WriteFile("output.txt", []byte("内容"), 0644)
    
    // 打开文件
    file2, err := os.Open("test.txt")  // 只读
    if err != nil {
        panic(err)
    }
    defer file2.Close()
    
    // 以指定模式打开
    file3, err := os.OpenFile("test.txt", os.O_RDWR|os.O_APPEND, 0644)
    if err != nil {
        panic(err)
    }
    defer file3.Close()
    
    // 逐行读取
    scanner := bufio.NewScanner(file2)
    for scanner.Scan() {
        fmt.Println(scanner.Text())
    }
    if err := scanner.Err(); err != nil {
        panic(err)
    }
    
    // 使用 bufio.Reader
    file2.Seek(0, 0)  // 重置到文件开头
    reader := bufio.NewReader(file2)
    for {
        line, err := reader.ReadString('\n')
        if err == io.EOF {
            break
        }
        if err != nil {
            panic(err)
        }
        fmt.Print(line)
    }
}
```

### 14.2 目录操作

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
)

func main() {
    // 创建目录
    err := os.Mkdir("testdir", 0755)
    if err != nil && !os.IsExist(err) {
        panic(err)
    }
    
    // 创建多级目录
    err = os.MkdirAll("path/to/dir", 0755)
    
    // 删除目录
    err = os.Remove("testdir")       // 只能删除空目录
    err = os.RemoveAll("path")       // 递归删除
    
    // 读取目录
    entries, err := os.ReadDir(".")
    if err != nil {
        panic(err)
    }
    for _, entry := range entries {
        info, _ := entry.Info()
        fmt.Printf("%s\t%d\t%s\n", entry.Name(), info.Size(), info.Mode())
    }
    
    // 遍历目录树
    err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        fmt.Println(path)
        return nil
    })
    
    // 使用 WalkDir（更高效）
    err = filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
        if err != nil {
            return err
        }
        if !d.IsDir() {
            fmt.Println("文件:", path)
        }
        return nil
    })
    
    // 获取当前目录
    cwd, _ := os.Getwd()
    fmt.Println("当前目录:", cwd)
    
    // 改变当前目录
    os.Chdir("/tmp")
    
    // 获取用户主目录
    home, _ := os.UserHomeDir()
    fmt.Println("主目录:", home)
}
```

### 14.3 文件信息

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
)

func main() {
    // 获取文件信息
    info, err := os.Stat("test.txt")
    if err != nil {
        if os.IsNotExist(err) {
            fmt.Println("文件不存在")
        }
        return
    }
    
    fmt.Println("名称:", info.Name())
    fmt.Println("大小:", info.Size())
    fmt.Println("权限:", info.Mode())
    fmt.Println("修改时间:", info.ModTime())
    fmt.Println("是否目录:", info.IsDir())
    
    // 检查文件是否存在
    if _, err := os.Stat("file.txt"); os.IsNotExist(err) {
        fmt.Println("文件不存在")
    }
    
    // 路径操作
    path := "/home/user/documents/file.txt"
    fmt.Println("目录:", filepath.Dir(path))       // /home/user/documents
    fmt.Println("文件名:", filepath.Base(path))    // file.txt
    fmt.Println("扩展名:", filepath.Ext(path))     // .txt
    fmt.Println("绝对路径:", filepath.Abs("."))
    
    // 路径拼接
    newPath := filepath.Join("dir1", "dir2", "file.txt")
    fmt.Println(newPath)  // dir1/dir2/file.txt（自动处理分隔符）
    
    // 匹配模式
    matches, _ := filepath.Glob("*.txt")
    fmt.Println("匹配的文件:", matches)
    
    // 重命名/移动文件
    os.Rename("old.txt", "new.txt")
    
    // 复制文件
    src, _ := os.Open("source.txt")
    defer src.Close()
    dst, _ := os.Create("dest.txt")
    defer dst.Close()
    io.Copy(dst, src)
}
```

---

## 15. 网络编程

### 15.1 HTTP 服务器

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
)

// 处理函数
func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
}

// JSON 响应
func jsonHandler(w http.ResponseWriter, r *http.Request) {
    data := map[string]interface{}{
        "message": "success",
        "code":    200,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

// 处理不同方法
func userHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        // 获取用户
        fmt.Fprintf(w, "获取用户")
    case http.MethodPost:
        // 创建用户
        var user struct {
            Name string `json:"name"`
            Age  int    `json:"age"`
        }
        json.NewDecoder(r.Body).Decode(&user)
        fmt.Fprintf(w, "创建用户: %s", user.Name)
    default:
        http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
    }
}

func main() {
    // 注册路由
    http.HandleFunc("/", helloHandler)
    http.HandleFunc("/json", jsonHandler)
    http.HandleFunc("/user", userHandler)
    
    // 静态文件服务
    fs := http.FileServer(http.Dir("static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))
    
    // 启动服务器
    fmt.Println("服务器启动在 :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### 15.2 HTTP 客户端

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

func main() {
    // 创建自定义客户端
    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    // GET 请求
    resp, err := client.Get("https://api.example.com/users")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
    
    // POST 请求（JSON）
    data := map[string]interface{}{
        "name": "张三",
        "age":  25,
    }
    jsonData, _ := json.Marshal(data)
    
    resp, err = client.Post(
        "https://api.example.com/users",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    // 自定义请求
    req, err := http.NewRequest("PUT", "https://api.example.com/users/1", bytes.NewBuffer(jsonData))
    if err != nil {
        panic(err)
    }
    
    // 设置请求头
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer token123")
    
    resp, err = client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    fmt.Println("状态码:", resp.StatusCode)
    fmt.Println("响应头:", resp.Header)
}
```

### 15.3 使用 Gin 框架

```bash
go get -u github.com/gin-gonic/gin
```

```go
package main

import (
    "net/http"
    
    "github.com/gin-gonic/gin"
)

type User struct {
    ID   int    `json:"id"`
    Name string `json:"name" binding:"required"`
    Age  int    `json:"age" binding:"required,gte=0,lte=150"`
}

func main() {
    // 创建路由
    r := gin.Default()  // 包含 Logger 和 Recovery 中间件
    
    // 基本路由
    r.GET("/", func(c *gin.Context) {
        c.String(http.StatusOK, "Hello, World!")
    })
    
    // JSON 响应
    r.GET("/json", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "message": "success",
            "code":    200,
        })
    })
    
    // 路径参数
    r.GET("/users/:id", func(c *gin.Context) {
        id := c.Param("id")
        c.JSON(http.StatusOK, gin.H{"id": id})
    })
    
    // 查询参数
    r.GET("/search", func(c *gin.Context) {
        keyword := c.Query("keyword")
        page := c.DefaultQuery("page", "1")
        c.JSON(http.StatusOK, gin.H{
            "keyword": keyword,
            "page":    page,
        })
    })
    
    // POST 请求
    r.POST("/users", func(c *gin.Context) {
        var user User
        if err := c.ShouldBindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        c.JSON(http.StatusCreated, user)
    })
    
    // 路由组
    api := r.Group("/api/v1")
    {
        api.GET("/users", listUsers)
        api.POST("/users", createUser)
        api.GET("/users/:id", getUser)
        api.PUT("/users/:id", updateUser)
        api.DELETE("/users/:id", deleteUser)
    }
    
    // 中间件
    r.Use(Logger())
    r.Use(Auth())
    
    // 启动服务器
    r.Run(":8080")
}

// 中间件示例
func Logger() gin.HandlerFunc {
    return func(c *gin.Context) {
        // 请求前
        start := time.Now()
        
        c.Next()  // 处理请求
        
        // 请求后
        latency := time.Since(start)
        log.Printf("%s %s %v", c.Request.Method, c.Request.URL.Path, latency)
    }
}

func Auth() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
            return
        }
        c.Next()
    }
}
```

---

## 16. 数据库操作

### 16.1 database/sql（标准库）

```go
package main

import (
    "database/sql"
    "fmt"
    "log"
    
    _ "github.com/go-sql-driver/mysql"
)

type User struct {
    ID    int
    Name  string
    Email string
}

func main() {
    // 连接数据库
    dsn := "user:password@tcp(localhost:3306)/dbname?charset=utf8mb4&parseTime=True"
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    
    // 测试连接
    if err := db.Ping(); err != nil {
        log.Fatal(err)
    }
    
    // 配置连接池
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
    
    // 查询单行
    var user User
    err = db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", 1).
        Scan(&user.ID, &user.Name, &user.Email)
    if err == sql.ErrNoRows {
        fmt.Println("用户不存在")
    } else if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%+v\n", user)
    
    // 查询多行
    rows, err := db.Query("SELECT id, name, email FROM users WHERE age > ?", 18)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    
    var users []User
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
            log.Fatal(err)
        }
        users = append(users, u)
    }
    if err := rows.Err(); err != nil {
        log.Fatal(err)
    }
    
    // 插入
    result, err := db.Exec("INSERT INTO users (name, email) VALUES (?, ?)", "张三", "zhangsan@example.com")
    if err != nil {
        log.Fatal(err)
    }
    id, _ := result.LastInsertId()
    affected, _ := result.RowsAffected()
    fmt.Printf("插入 ID: %d, 影响行数: %d\n", id, affected)
    
    // 更新
    result, err = db.Exec("UPDATE users SET name = ? WHERE id = ?", "李四", 1)
    
    // 删除
    result, err = db.Exec("DELETE FROM users WHERE id = ?", 1)
    
    // 事务
    tx, err := db.Begin()
    if err != nil {
        log.Fatal(err)
    }
    
    defer func() {
        if err != nil {
            tx.Rollback()
            return
        }
        err = tx.Commit()
    }()
    
    _, err = tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", 100, 1)
    if err != nil {
        return
    }
    _, err = tx.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", 100, 2)
    if err != nil {
        return
    }
    
    // 预处理语句
    stmt, err := db.Prepare("INSERT INTO users (name, email) VALUES (?, ?)")
    if err != nil {
        log.Fatal(err)
    }
    defer stmt.Close()
    
    for _, u := range users {
        _, err := stmt.Exec(u.Name, u.Email)
        if err != nil {
            log.Fatal(err)
        }
    }
}
```

### 16.2 GORM（ORM 框架）

```bash
go get -u gorm.io/gorm
go get -u gorm.io/driver/mysql
```

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

// 模型定义
type User struct {
    ID        uint           `gorm:"primaryKey"`
    Name      string         `gorm:"size:100;not null"`
    Email     string         `gorm:"uniqueIndex;size:100"`
    Age       int            `gorm:"default:0"`
    Birthday  *time.Time
    CreatedAt time.Time
    UpdatedAt time.Time
    DeletedAt gorm.DeletedAt `gorm:"index"`  // 软删除
}

// 自定义表名
func (User) TableName() string {
    return "users"
}

func main() {
    // 连接数据库
    dsn := "user:password@tcp(localhost:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
    db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatal(err)
    }
    
    // 自动迁移
    db.AutoMigrate(&User{})
    
    // 创建
    user := User{Name: "张三", Email: "zhangsan@example.com", Age: 25}
    result := db.Create(&user)
    fmt.Println("插入 ID:", user.ID)
    fmt.Println("影响行数:", result.RowsAffected)
    
    // 批量创建
    users := []User{
        {Name: "李四", Email: "lisi@example.com"},
        {Name: "王五", Email: "wangwu@example.com"},
    }
    db.Create(&users)
    
    // 查询
    var u User
    db.First(&u, 1)                    // 根据主键
    db.First(&u, "name = ?", "张三")    // 条件查询
    
    // 查询多条
    var userList []User
    db.Find(&userList)                           // 所有
    db.Where("age > ?", 18).Find(&userList)      // 条件
    db.Where("name LIKE ?", "%张%").Find(&userList)
    
    // 链式查询
    db.Where("age > ?", 18).
        Order("created_at desc").
        Limit(10).
        Offset(0).
        Find(&userList)
    
    // 更新
    db.Model(&user).Update("name", "新名字")
    db.Model(&user).Updates(User{Name: "新名字", Age: 30})
    db.Model(&user).Updates(map[string]interface{}{"name": "新名字", "age": 30})
    
    // 删除
    db.Delete(&user)                    // 软删除
    db.Unscoped().Delete(&user)         // 永久删除
    
    // 事务
    err = db.Transaction(func(tx *gorm.DB) error {
        if err := tx.Create(&User{Name: "事务用户"}).Error; err != nil {
            return err
        }
        // 返回 nil 提交事务
        return nil
    })
    
    // 关联查询
    type Post struct {
        ID     uint
        Title  string
        UserID uint
        User   User
    }
    
    var post Post
    db.Preload("User").First(&post, 1)
}
```

---

## 17. 测试

### 17.1 单元测试

```go
// math.go
package math

func Add(a, b int) int {
    return a + b
}

func Divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("除数不能为零")
    }
    return a / b, nil
}
```

```go
// math_test.go
package math

import (
    "testing"
)

// 基本测试
func TestAdd(t *testing.T) {
    result := Add(1, 2)
    expected := 3
    
    if result != expected {
        t.Errorf("Add(1, 2) = %d; want %d", result, expected)
    }
}

// 表驱动测试
func TestAddTable(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"正数相加", 1, 2, 3},
        {"负数相加", -1, -2, -3},
        {"零相加", 0, 0, 0},
        {"正负相加", 1, -1, 0},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("Add(%d, %d) = %d; want %d", tt.a, tt.b, result, tt.expected)
            }
        })
    }
}

// 测试错误情况
func TestDivide(t *testing.T) {
    // 正常情况
    result, err := Divide(10, 2)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result != 5 {
        t.Errorf("Divide(10, 2) = %f; want 5", result)
    }
    
    // 错误情况
    _, err = Divide(10, 0)
    if err == nil {
        t.Error("expected error for division by zero")
    }
}

// 跳过测试
func TestSkip(t *testing.T) {
    if testing.Short() {
        t.Skip("跳过长时间运行的测试")
    }
    // 长时间运行的测试...
}

// 并行测试
func TestParallel(t *testing.T) {
    t.Parallel()  // 标记为可并行
    // 测试代码...
}
```

```bash
# 运行测试
go test                    # 当前包
go test ./...              # 所有包
go test -v                 # 详细输出
go test -run TestAdd       # 运行特定测试
go test -short             # 跳过长时间测试
go test -race              # 检测竞态条件
go test -cover             # 覆盖率
go test -coverprofile=c.out && go tool cover -html=c.out  # 覆盖率报告
```

### 17.2 基准测试

```go
// math_test.go
package math

import "testing"

func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(1, 2)
    }
}

// 带设置的基准测试
func BenchmarkAddWithSetup(b *testing.B) {
    // 设置代码（不计入时间）
    data := prepareData()
    
    b.ResetTimer()  // 重置计时器
    
    for i := 0; i < b.N; i++ {
        processData(data)
    }
}

// 并行基准测试
func BenchmarkAddParallel(b *testing.B) {
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            Add(1, 2)
        }
    })
}

// 内存分配统计
func BenchmarkMemory(b *testing.B) {
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        _ = make([]byte, 1024)
    }
}
```

```bash
# 运行基准测试
go test -bench=.                    # 所有基准测试
go test -bench=BenchmarkAdd         # 特定测试
go test -bench=. -benchmem          # 包含内存统计
go test -bench=. -benchtime=5s      # 运行 5 秒
go test -bench=. -count=5           # 运行 5 次
```

### 17.3 示例测试

```go
// math_test.go
package math

import "fmt"

func ExampleAdd() {
    result := Add(1, 2)
    fmt.Println(result)
    // Output: 3
}

func ExampleAdd_negative() {
    result := Add(-1, -2)
    fmt.Println(result)
    // Output: -3
}
```

### 17.4 Mock 测试

```go
// 使用接口进行 mock
type UserRepository interface {
    GetByID(id int) (*User, error)
    Save(user *User) error
}

// 真实实现
type MySQLUserRepository struct {
    db *sql.DB
}

func (r *MySQLUserRepository) GetByID(id int) (*User, error) {
    // 真实数据库查询
}

// Mock 实现
type MockUserRepository struct {
    users map[int]*User
}

func (r *MockUserRepository) GetByID(id int) (*User, error) {
    if user, ok := r.users[id]; ok {
        return user, nil
    }
    return nil, errors.New("用户不存在")
}

// 测试
func TestUserService(t *testing.T) {
    // 使用 mock
    repo := &MockUserRepository{
        users: map[int]*User{
            1: {ID: 1, Name: "张三"},
        },
    }
    
    service := NewUserService(repo)
    user, err := service.GetUser(1)
    
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if user.Name != "张三" {
        t.Errorf("expected 张三, got %s", user.Name)
    }
}
```

---

## 18. 性能优化

### 18.1 内存优化

```go
package main

import (
    "sync"
)

// 1. 预分配切片容量
func goodSlice() {
    // ❌ 不推荐：多次扩容
    var s []int
    for i := 0; i < 10000; i++ {
        s = append(s, i)
    }
    
    // ✅ 推荐：预分配
    s2 := make([]int, 0, 10000)
    for i := 0; i < 10000; i++ {
        s2 = append(s2, i)
    }
}

// 2. 使用 sync.Pool 复用对象
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 1024)
    },
}

func processWithPool() {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    
    // 使用 buf...
}

// 3. 避免不必要的内存分配
// ❌ 每次调用都分配
func concat(a, b string) string {
    return a + b  // 分配新字符串
}

// ✅ 使用 strings.Builder
func concatMany(strs []string) string {
    var builder strings.Builder
    builder.Grow(calculateSize(strs))  // 预分配
    for _, s := range strs {
        builder.WriteString(s)
    }
    return builder.String()
}

// 4. 使用指针避免复制大结构体
type LargeStruct struct {
    Data [1024]byte
}

// ❌ 值传递，复制整个结构体
func processValue(s LargeStruct) {}

// ✅ 指针传递
func processPointer(s *LargeStruct) {}

// 5. 使用 []byte 而不是 string 进行频繁修改
func modifyBytes() {
    b := []byte("hello")
    b[0] = 'H'  // 直接修改
}
```

### 18.2 并发优化

```go
package main

import (
    "runtime"
    "sync"
)

// 1. 合理设置 GOMAXPROCS
func init() {
    runtime.GOMAXPROCS(runtime.NumCPU())
}

// 2. 使用工作池限制并发数
func workerPool(jobs <-chan int, results chan<- int, workers int) {
    var wg sync.WaitGroup
    
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for job := range jobs {
                results <- process(job)
            }
        }()
    }
    
    wg.Wait()
    close(results)
}

// 3. 使用 channel 控制并发数
func limitedConcurrency(tasks []Task, limit int) {
    sem := make(chan struct{}, limit)
    var wg sync.WaitGroup
    
    for _, task := range tasks {
        wg.Add(1)
        sem <- struct{}{}  // 获取信号量
        
        go func(t Task) {
            defer wg.Done()
            defer func() { <-sem }()  // 释放信号量
            
            t.Execute()
        }(task)
    }
    
    wg.Wait()
}

// 4. 避免锁竞争
// ❌ 全局锁
var globalMu sync.Mutex
var globalData map[string]int

// ✅ 分片锁
type ShardedMap struct {
    shards [256]struct {
        mu   sync.RWMutex
        data map[string]int
    }
}

func (m *ShardedMap) getShard(key string) *struct {
    mu   sync.RWMutex
    data map[string]int
} {
    hash := fnv32(key)
    return &m.shards[hash%256]
}

// 5. 使用原子操作代替锁
var counter int64

func increment() {
    atomic.AddInt64(&counter, 1)
}
```

### 18.3 性能分析

```go
package main

import (
    "net/http"
    _ "net/http/pprof"  // 导入 pprof
    "runtime"
)

func main() {
    // 启动 pprof HTTP 服务
    go func() {
        http.ListenAndServe(":6060", nil)
    }()
    
    // 你的应用代码...
}
```

```bash
# CPU 分析
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# 内存分析
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine 分析
go tool pprof http://localhost:6060/debug/pprof/goroutine

# 阻塞分析
go tool pprof http://localhost:6060/debug/pprof/block

# 生成火焰图
go tool pprof -http=:8080 cpu.prof

# 基准测试生成 profile
go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof
```

```go
// 代码中手动分析
import "runtime/pprof"

func main() {
    // CPU 分析
    f, _ := os.Create("cpu.prof")
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()
    
    // 你的代码...
    
    // 内存分析
    f2, _ := os.Create("mem.prof")
    pprof.WriteHeapProfile(f2)
    f2.Close()
}
```

---

## 19. 常见错误与解决方案

### 19.1 语法与类型错误

```go
// 错误：declared but not used
// 原因：声明了变量但未使用
func main() {
    x := 10  // 编译错误
}
// 解决：使用变量或用 _ 忽略
func main() {
    x := 10
    _ = x
}

// 错误：cannot use x (type int) as type string
// 原因：类型不匹配
var s string = 10  // 错误
// 解决：类型转换
var s string = strconv.Itoa(10)

// 错误：non-declaration statement outside function body
// 原因：在包级别使用 :=
package main
x := 10  // 错误
// 解决：使用 var
var x = 10

// 错误：multiple-value in single-value context
// 原因：多返回值函数用于单值上下文
result := strconv.Atoi("10")  // 错误，Atoi 返回两个值
// 解决：接收所有返回值
result, err := strconv.Atoi("10")
// 或忽略
result, _ := strconv.Atoi("10")
```

### 19.2 切片与 Map 错误

```go
// 错误：index out of range
// 原因：访问越界
s := []int{1, 2, 3}
fmt.Println(s[5])  // panic
// 解决：检查长度
if len(s) > 5 {
    fmt.Println(s[5])
}

// 错误：assignment to entry in nil map
// 原因：向 nil map 写入
var m map[string]int
m["key"] = 1  // panic
// 解决：初始化 map
m := make(map[string]int)
m["key"] = 1

// 错误：切片追加后原切片未改变
s := []int{1, 2, 3}
append(s, 4)  // 返回值被丢弃
fmt.Println(s)  // [1 2 3]
// 解决：接收返回值
s = append(s, 4)

// 错误：切片共享底层数组导致意外修改
original := []int{1, 2, 3, 4, 5}
slice := original[1:3]
slice[0] = 100
fmt.Println(original)  // [1 100 3 4 5]
// 解决：使用 copy 创建独立切片
slice := make([]int, 2)
copy(slice, original[1:3])
```

### 19.3 并发错误

```go
// 错误：fatal error: concurrent map read and map write
// 原因：并发读写 map
var m = make(map[string]int)
go func() { m["a"] = 1 }()
go func() { _ = m["a"] }()
// 解决：使用 sync.Map 或加锁
var mu sync.RWMutex
var m = make(map[string]int)

go func() {
    mu.Lock()
    m["a"] = 1
    mu.Unlock()
}()

go func() {
    mu.RLock()
    _ = m["a"]
    mu.RUnlock()
}()

// 错误：goroutine 泄漏
func leak() {
    ch := make(chan int)
    go func() {
        val := <-ch  // 永远阻塞，因为没有发送者
        fmt.Println(val)
    }()
    // 函数返回，goroutine 泄漏
}
// 解决：使用 context 或 done channel
func noLeak(ctx context.Context) {
    ch := make(chan int)
    go func() {
        select {
        case val := <-ch:
            fmt.Println(val)
        case <-ctx.Done():
            return
        }
    }()
}

// 错误：闭包捕获循环变量
for i := 0; i < 3; i++ {
    go func() {
        fmt.Println(i)  // 可能都打印 3
    }()
}
// 解决：传递参数
for i := 0; i < 3; i++ {
    go func(n int) {
        fmt.Println(n)
    }(i)
}

// 错误：死锁
ch := make(chan int)
ch <- 1  // 阻塞，没有接收者
// 解决：使用缓冲 channel 或在 goroutine 中发送
ch := make(chan int, 1)
ch <- 1
// 或
go func() { ch <- 1 }()
<-ch
```

### 19.4 接口与类型断言错误

```go
// 错误：interface conversion: interface {} is string, not int
// 原因：类型断言失败
var i interface{} = "hello"
n := i.(int)  // panic
// 解决：使用安全断言
n, ok := i.(int)
if !ok {
    fmt.Println("不是 int 类型")
}

// 错误：X does not implement Y (missing method Z)
// 原因：类型未实现接口
type Writer interface {
    Write([]byte) (int, error)
}

type MyWriter struct{}
// 缺少 Write 方法

var w Writer = MyWriter{}  // 编译错误
// 解决：实现所有接口方法
func (m MyWriter) Write(p []byte) (int, error) {
    return len(p), nil
}

// 错误：nil 接口与 nil 值的区别
type MyError struct{}
func (e *MyError) Error() string { return "error" }

func getError() error {
    var err *MyError = nil
    return err  // 返回的不是 nil！
}

func main() {
    err := getError()
    if err != nil {  // true！
        fmt.Println("有错误")  // 会执行
    }
}
// 解决：直接返回 nil
func getError() error {
    return nil
}
```

### 19.5 defer 相关错误

```go
// 错误：defer 参数在声明时求值
func main() {
    x := 10
    defer fmt.Println(x)  // 打印 10，不是 20
    x = 20
}
// 解决：使用闭包
func main() {
    x := 10
    defer func() {
        fmt.Println(x)  // 打印 20
    }()
    x = 20
}

// 错误：循环中的 defer
func processFiles(files []string) error {
    for _, file := range files {
        f, err := os.Open(file)
        if err != nil {
            return err
        }
        defer f.Close()  // 所有 defer 在函数返回时才执行
    }
    return nil
}
// 解决：使用匿名函数
func processFiles(files []string) error {
    for _, file := range files {
        if err := func() error {
            f, err := os.Open(file)
            if err != nil {
                return err
            }
            defer f.Close()
            // 处理文件...
            return nil
        }(); err != nil {
            return err
        }
    }
    return nil
}

// 错误：defer 中修改返回值
func foo() int {
    x := 10
    defer func() {
        x = 20  // 不会影响返回值
    }()
    return x  // 返回 10
}
// 解决：使用命名返回值
func foo() (x int) {
    x = 10
    defer func() {
        x = 20  // 会影响返回值
    }()
    return  // 返回 20
}
```

### 19.6 JSON 序列化错误

```go
// 错误：字段未导出导致 JSON 序列化失败
type User struct {
    name string  // 小写，未导出
    Age  int
}

u := User{name: "张三", Age: 25}
data, _ := json.Marshal(u)
fmt.Println(string(data))  // {"Age":25}，name 丢失
// 解决：导出字段
type User struct {
    Name string `json:"name"`
    Age  int    `json:"age"`
}

// 错误：time.Time 序列化格式
type Event struct {
    Time time.Time `json:"time"`
}
// 默认格式：2006-01-02T15:04:05.999999999Z07:00
// 解决：自定义格式
type CustomTime time.Time

func (t CustomTime) MarshalJSON() ([]byte, error) {
    stamp := time.Time(t).Format("2006-01-02 15:04:05")
    return []byte(`"` + stamp + `"`), nil
}

// 错误：interface{} 反序列化为 float64
var data map[string]interface{}
json.Unmarshal([]byte(`{"count": 10}`), &data)
count := data["count"]  // float64，不是 int
// 解决：类型断言或使用具体类型
count := int(data["count"].(float64))
// 或
type Data struct {
    Count int `json:"count"`
}
```

---

## 总结

Go 语言以简洁、高效、并发支持强大著称，掌握它需要理解：

1. **基础语法**：变量声明、数据类型、流程控制
2. **函数与方法**：多返回值、defer、panic/recover
3. **数据结构**：数组、切片、map、结构体
4. **接口**：隐式实现、空接口、类型断言
5. **错误处理**：error 接口、错误包装、最佳实践
6. **并发编程**：goroutine、channel、sync 包、context
7. **包管理**：Go Modules、项目结构
8. **测试**：单元测试、基准测试、表驱动测试
9. **性能优化**：内存优化、并发优化、pprof 分析

Go 的设计哲学是"少即是多"，通过简单的语法和强大的标准库，可以构建高性能的服务端应用。建议多阅读官方文档和优秀开源项目（如 Docker、Kubernetes）的源码来提升水平。
