> 基于 Java 8 环境，涵盖从基础语法到高级特性的完整知识体系
> Java 是一种广泛使用的面向对象编程语言，具有"一次编写，到处运行"的跨平台特性

---

## 目录

1. [基础概念](#1.基础概念)
2. [基础语法](#2.基础语法)
3. [面向对象编程](#3.面向对象编程)
4. [常用类库](#4.常用类库)
5. [集合框架](#5.集合框架)
6. [异常处理](#6.异常处理)
7. [IO流](#7.io流)
8. [多线程与并发](#8.多线程与并发)
9. [Java 8 新特性](#9.java-8-新特性)
10. [反射与注解](#10.反射与注解)
11. [JVM基础](#11.jvm基础)
12. [常见错误与解决方案](#12.常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Java？

Java 是由 Sun Microsystems（现属于 Oracle）于 1995 年发布的一种面向对象的编程语言。它的设计理念是"Write Once, Run Anywhere"（一次编写，到处运行），这意味着 Java 程序可以在任何安装了 Java 虚拟机（JVM）的平台上运行。

**Java 的主要特点：**
- **跨平台性**：通过 JVM 实现，代码编译成字节码后可在任何平台运行
- **面向对象**：支持封装、继承、多态等 OOP 特性
- **安全性**：提供沙箱安全模型、字节码验证等安全机制
- **健壮性**：强类型检查、异常处理、垃圾回收等特性
- **多线程**：内置多线程支持，便于开发并发程序

### 1.2 JDK、JRE、JVM 的关系

```
┌─────────────────────────────────────────────────────┐
│                      JDK                             │
│  (Java Development Kit - Java 开发工具包)            │
│  ┌─────────────────────────────────────────────┐    │
│  │                    JRE                       │    │
│  │  (Java Runtime Environment - Java 运行环境)  │    │
│  │  ┌─────────────────────────────────────┐    │    │
│  │  │              JVM                     │    │    │
│  │  │  (Java Virtual Machine - Java虚拟机) │    │    │
│  │  └─────────────────────────────────────┘    │    │
│  │  + Java 核心类库                            │    │
│  └─────────────────────────────────────────────┘    │
│  + 编译器(javac) + 调试器(jdb) + 其他开发工具        │
└─────────────────────────────────────────────────────┘
```

| 组件 | 说明 | 包含内容 |
|------|------|----------|
| **JVM** | Java 虚拟机，负责执行字节码 | 类加载器、执行引擎、垃圾回收器 |
| **JRE** | Java 运行环境，运行 Java 程序所需的最小环境 | JVM + Java 核心类库 |
| **JDK** | Java 开发工具包，开发 Java 程序所需的完整环境 | JRE + 编译器 + 调试器 + 其他工具 |

### 1.3 Java 程序执行流程

```
源代码(.java) → 编译器(javac) → 字节码(.class) → JVM → 机器码 → 执行
```

```java
// HelloWorld.java - 第一个 Java 程序
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
```

**编译和运行：**
```bash
# 编译
javac HelloWorld.java

# 运行
java HelloWorld
```

### 1.4 Java 版本历史

| 版本 | 发布时间 | 重要特性 |
|------|----------|----------|
| Java 1.0 | 1996 | 首个正式版本 |
| Java 5 | 2004 | 泛型、枚举、注解、自动装箱 |
| Java 7 | 2011 | try-with-resources、switch 支持字符串 |
| **Java 8** | 2014 | **Lambda、Stream API、Optional、新日期API** |
| Java 11 | 2018 | LTS 版本、HTTP Client、var |
| Java 17 | 2021 | LTS 版本、密封类、模式匹配 |
| Java 21 | 2023 | LTS 版本、虚拟线程、记录模式 |

> **注意**：Java 8 是目前企业中使用最广泛的版本，本笔记主要基于 Java 8。

---

## 2. 基础语法

### 2.1 数据类型

Java 是强类型语言，每个变量都必须声明其类型。数据类型分为两大类：

#### 2.1.1 基本数据类型（8种）

```java
public class DataTypes {
    public static void main(String[] args) {
        // ============ 整数类型 ============
        byte b = 127;           // 1字节，-128 ~ 127
        short s = 32767;        // 2字节，-32768 ~ 32767
        int i = 2147483647;     // 4字节，约 ±21亿（最常用）
        long l = 9223372036854775807L;  // 8字节，需要加 L 后缀
        
        // ============ 浮点类型 ============
        float f = 3.14f;        // 4字节，需要加 f 后缀
        double d = 3.141592653589793;  // 8字节（默认小数类型）
        
        // ============ 字符类型 ============
        char c = 'A';           // 2字节，单个字符，用单引号
        char c2 = 65;           // 也可以用 ASCII 码
        char c3 = '\u0041';     // 也可以用 Unicode
        
        // ============ 布尔类型 ============
        boolean flag = true;    // 只有 true 和 false
        
        // 打印各类型的范围
        System.out.println("byte: " + Byte.MIN_VALUE + " ~ " + Byte.MAX_VALUE);
        System.out.println("short: " + Short.MIN_VALUE + " ~ " + Short.MAX_VALUE);
        System.out.println("int: " + Integer.MIN_VALUE + " ~ " + Integer.MAX_VALUE);
        System.out.println("long: " + Long.MIN_VALUE + " ~ " + Long.MAX_VALUE);
    }
}
```

#### 2.1.2 引用数据类型

```java
public class ReferenceTypes {
    public static void main(String[] args) {
        // 类
        String str = "Hello";
        
        // 数组
        int[] arr = {1, 2, 3};
        
        // 接口（通过实现类）
        List<String> list = new ArrayList<>();
        
        // 枚举
        DayOfWeek day = DayOfWeek.MONDAY;
    }
}
```

### 2.2 类型转换

```java
public class TypeConversion {
    public static void main(String[] args) {
        // ============ 自动类型转换（隐式转换） ============
        // 小类型 → 大类型，自动进行
        byte b = 10;
        int i = b;      // byte → int，自动转换
        long l = i;     // int → long，自动转换
        double d = l;   // long → double，自动转换
        
        // 转换顺序：byte → short → int → long → float → double
        //                    char ↗
        
        // ============ 强制类型转换（显式转换） ============
        // 大类型 → 小类型，需要强制转换，可能丢失精度
        double d2 = 3.99;
        int i2 = (int) d2;  // 结果是 3，小数部分被截断
        
        long l2 = 1000L;
        byte b2 = (byte) l2;  // 可能溢出！
        
        // ============ 常见陷阱 ============
        // 整数运算溢出
        int max = Integer.MAX_VALUE;
        System.out.println(max + 1);  // 输出负数！发生溢出
        
        // 整数除法
        int a = 5, b3 = 2;
        System.out.println(a / b3);      // 输出 2，不是 2.5
        System.out.println(a / (double) b3);  // 输出 2.5
        
        // 浮点数精度问题
        System.out.println(0.1 + 0.2);  // 输出 0.30000000000000004
        // 解决方案：使用 BigDecimal
    }
}
```

### 2.3 变量与常量

```java
public class Variables {
    // 类变量（静态变量）
    static int classVar = 100;
    
    // 实例变量（成员变量）
    int instanceVar = 200;
    
    // 常量（使用 final 修饰）
    static final double PI = 3.14159265358979;
    final String NAME = "Java";
    
    public void method() {
        // 局部变量（必须初始化后才能使用）
        int localVar = 300;
        
        // 局部常量
        final int LOCAL_CONST = 400;
        
        System.out.println(localVar);
    }
    
    public static void main(String[] args) {
        // 变量命名规范
        // 1. 只能包含字母、数字、下划线、美元符号
        // 2. 不能以数字开头
        // 3. 不能使用关键字
        // 4. 区分大小写
        
        // 命名风格
        int myVariable;      // 小驼峰（变量、方法）
        final int MY_CONST = 1;  // 全大写下划线（常量）
        // class MyClass {}   // 大驼峰（类名）
    }
}
```

### 2.4 运算符

```java
public class Operators {
    public static void main(String[] args) {
        // ============ 算术运算符 ============
        int a = 10, b = 3;
        System.out.println(a + b);   // 13 加法
        System.out.println(a - b);   // 7  减法
        System.out.println(a * b);   // 30 乘法
        System.out.println(a / b);   // 3  除法（整数除法）
        System.out.println(a % b);   // 1  取模（求余）
        
        // 自增自减
        int c = 5;
        System.out.println(c++);  // 5，先使用后自增
        System.out.println(++c);  // 7，先自增后使用
        
        // ============ 关系运算符 ============
        System.out.println(a == b);  // false 等于
        System.out.println(a != b);  // true  不等于
        System.out.println(a > b);   // true  大于
        System.out.println(a < b);   // false 小于
        System.out.println(a >= b);  // true  大于等于
        System.out.println(a <= b);  // false 小于等于
        
        // ============ 逻辑运算符 ============
        boolean x = true, y = false;
        System.out.println(x && y);  // false 逻辑与（短路）
        System.out.println(x || y);  // true  逻辑或（短路）
        System.out.println(!x);      // false 逻辑非
        System.out.println(x & y);   // false 逻辑与（不短路）
        System.out.println(x | y);   // true  逻辑或（不短路）
        System.out.println(x ^ y);   // true  逻辑异或
        
        // 短路特性演示
        int num = 5;
        // && 短路：第一个为 false，不执行第二个
        if (false && (++num > 0)) { }
        System.out.println(num);  // 5，num 没有自增
        
        // ============ 位运算符 ============
        int m = 5, n = 3;  // 二进制：5=101, 3=011
        System.out.println(m & n);   // 1   按位与 (001)
        System.out.println(m | n);   // 7   按位或 (111)
        System.out.println(m ^ n);   // 6   按位异或 (110)
        System.out.println(~m);      // -6  按位取反
        System.out.println(m << 1);  // 10  左移（乘2）
        System.out.println(m >> 1);  // 2   右移（除2）
        System.out.println(m >>> 1); // 2   无符号右移
        
        // ============ 赋值运算符 ============
        int d = 10;
        d += 5;   // d = d + 5
        d -= 3;   // d = d - 3
        d *= 2;   // d = d * 2
        d /= 4;   // d = d / 4
        d %= 3;   // d = d % 3
        
        // ============ 三元运算符 ============
        int max = (a > b) ? a : b;  // 如果 a > b，返回 a，否则返回 b
        
        // ============ instanceof 运算符 ============
        String str = "Hello";
        System.out.println(str instanceof String);  // true
        System.out.println(str instanceof Object);  // true
    }
}
```

### 2.5 流程控制

#### 2.5.1 条件语句

```java
public class ConditionStatements {
    public static void main(String[] args) {
        int score = 85;
        
        // ============ if-else 语句 ============
        if (score >= 90) {
            System.out.println("优秀");
        } else if (score >= 80) {
            System.out.println("良好");
        } else if (score >= 60) {
            System.out.println("及格");
        } else {
            System.out.println("不及格");
        }
        
        // ============ switch 语句 ============
        int day = 3;
        switch (day) {
            case 1:
                System.out.println("星期一");
                break;
            case 2:
                System.out.println("星期二");
                break;
            case 3:
                System.out.println("星期三");
                break;
            default:
                System.out.println("其他");
        }
        
        // switch 支持的类型：byte, short, int, char, String(Java 7+), 枚举
        String fruit = "apple";
        switch (fruit) {
            case "apple":
                System.out.println("苹果");
                break;
            case "banana":
                System.out.println("香蕉");
                break;
            default:
                System.out.println("未知水果");
        }
        
        // case 穿透（不加 break）
        int month = 3;
        switch (month) {
            case 3:
            case 4:
            case 5:
                System.out.println("春季");
                break;
            case 6:
            case 7:
            case 8:
                System.out.println("夏季");
                break;
            // ...
        }
    }
}
```

#### 2.5.2 循环语句

```java
public class LoopStatements {
    public static void main(String[] args) {
        // ============ for 循环 ============
        // 适用于已知循环次数的场景
        for (int i = 0; i < 5; i++) {
            System.out.println("for: " + i);
        }
        
        // ============ while 循环 ============
        // 适用于不确定循环次数，先判断后执行
        int j = 0;
        while (j < 5) {
            System.out.println("while: " + j);
            j++;
        }
        
        // ============ do-while 循环 ============
        // 先执行后判断，至少执行一次
        int k = 0;
        do {
            System.out.println("do-while: " + k);
            k++;
        } while (k < 5);
        
        // ============ 增强 for 循环（for-each） ============
        // 适用于遍历数组或集合
        int[] arr = {1, 2, 3, 4, 5};
        for (int num : arr) {
            System.out.println("for-each: " + num);
        }
        
        // ============ 循环控制 ============
        // break：跳出当前循环
        for (int i = 0; i < 10; i++) {
            if (i == 5) {
                break;  // 当 i=5 时跳出循环
            }
            System.out.println(i);
        }
        
        // continue：跳过本次循环，继续下一次
        for (int i = 0; i < 10; i++) {
            if (i % 2 == 0) {
                continue;  // 跳过偶数
            }
            System.out.println(i);  // 只打印奇数
        }
        
        // 带标签的 break/continue（用于多层循环）
        outer:
        for (int i = 0; i < 3; i++) {
            for (int m = 0; m < 3; m++) {
                if (m == 1) {
                    break outer;  // 跳出外层循环
                }
                System.out.println(i + ", " + m);
            }
        }
    }
}
```

### 2.6 数组

```java
public class ArrayDemo {
    public static void main(String[] args) {
        // ============ 一维数组 ============
        // 声明方式
        int[] arr1;           // 推荐
        int arr2[];           // 也可以，但不推荐
        
        // 初始化方式
        int[] arr3 = new int[5];           // 动态初始化，默认值为 0
        int[] arr4 = {1, 2, 3, 4, 5};       // 静态初始化
        int[] arr5 = new int[]{1, 2, 3};   // 静态初始化的完整写法
        
        // 访问元素
        System.out.println(arr4[0]);  // 1，索引从 0 开始
        arr4[0] = 10;                 // 修改元素
        
        // 数组长度
        System.out.println(arr4.length);  // 5
        
        // 遍历数组
        for (int i = 0; i < arr4.length; i++) {
            System.out.println(arr4[i]);
        }
        
        for (int num : arr4) {
            System.out.println(num);
        }
        
        // ============ 二维数组 ============
        // 声明和初始化
        int[][] matrix1 = new int[3][4];  // 3行4列
        int[][] matrix2 = {
            {1, 2, 3},
            {4, 5, 6},
            {7, 8, 9}
        };
        
        // 不规则数组（每行长度可以不同）
        int[][] irregular = new int[3][];
        irregular[0] = new int[2];
        irregular[1] = new int[3];
        irregular[2] = new int[4];
        
        // 遍历二维数组
        for (int i = 0; i < matrix2.length; i++) {
            for (int j = 0; j < matrix2[i].length; j++) {
                System.out.print(matrix2[i][j] + " ");
            }
            System.out.println();
        }
        
        // ============ 数组常用操作 ============
        import java.util.Arrays;
        
        int[] nums = {5, 2, 8, 1, 9};
        
        // 排序
        Arrays.sort(nums);  // [1, 2, 5, 8, 9]
        
        // 二分查找（数组必须有序）
        int index = Arrays.binarySearch(nums, 5);  // 返回索引
        
        // 填充
        int[] filled = new int[5];
        Arrays.fill(filled, 10);  // [10, 10, 10, 10, 10]
        
        // 复制
        int[] copy = Arrays.copyOf(nums, 10);  // 复制并扩展长度
        int[] rangeCopy = Arrays.copyOfRange(nums, 1, 4);  // 复制指定范围
        
        // 比较
        boolean equal = Arrays.equals(arr1, arr2);
        
        // 转字符串
        System.out.println(Arrays.toString(nums));  // [1, 2, 5, 8, 9]
    }
}
```

---

## 3. 面向对象编程

### 3.1 类与对象

```java
/**
 * 类的定义
 * 类是对象的模板，对象是类的实例
 */
public class Person {
    // ============ 成员变量（属性） ============
    private String name;      // 私有属性
    private int age;
    public String gender;     // 公有属性（不推荐）
    
    // 静态变量（类变量）
    private static int count = 0;
    
    // 常量
    public static final String SPECIES = "Human";
    
    // ============ 构造方法 ============
    // 无参构造
    public Person() {
        count++;
    }
    
    // 有参构造
    public Person(String name, int age) {
        this.name = name;  // this 指向当前对象
        this.age = age;
        count++;
    }
    
    // 构造方法重载
    public Person(String name) {
        this(name, 0);  // 调用另一个构造方法
    }
    
    // ============ 成员方法 ============
    // 普通方法
    public void sayHello() {
        System.out.println("Hello, I'm " + name);
    }
    
    // 带参数和返回值的方法
    public String introduce() {
        return "Name: " + name + ", Age: " + age;
    }
    
    // 静态方法
    public static int getCount() {
        return count;
    }
    
    // ============ Getter 和 Setter ============
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public int getAge() {
        return age;
    }
    
    public void setAge(int age) {
        if (age >= 0 && age <= 150) {
            this.age = age;
        }
    }
    
    // ============ toString 方法 ============
    @Override
    public String toString() {
        return "Person{name='" + name + "', age=" + age + "}";
    }
}

// 使用类
public class Main {
    public static void main(String[] args) {
        // 创建对象
        Person p1 = new Person();
        Person p2 = new Person("张三", 25);
        
        // 访问属性和方法
        p1.setName("李四");
        p1.setAge(30);
        p1.sayHello();
        
        System.out.println(p2.introduce());
        System.out.println(Person.getCount());  // 静态方法通过类名调用
    }
}
```

### 3.2 封装

封装是面向对象的三大特性之一，通过访问修饰符控制对类成员的访问。

```java
/**
 * 访问修饰符
 * 
 * | 修饰符      | 同一类 | 同一包 | 子类 | 其他包 |
 * |------------|--------|--------|------|--------|
 * | private    |   ✓    |   ✗    |  ✗   |   ✗    |
 * | default    |   ✓    |   ✓    |  ✗   |   ✗    |
 * | protected  |   ✓    |   ✓    |  ✓   |   ✗    |
 * | public     |   ✓    |   ✓    |  ✓   |   ✓    |
 */
public class BankAccount {
    // 私有属性，外部无法直接访问
    private String accountNumber;
    private double balance;
    
    public BankAccount(String accountNumber, double initialBalance) {
        this.accountNumber = accountNumber;
        this.balance = initialBalance;
    }
    
    // 通过公有方法访问私有属性
    public double getBalance() {
        return balance;
    }
    
    // 在方法中添加业务逻辑
    public void deposit(double amount) {
        if (amount > 0) {
            balance += amount;
            System.out.println("存款成功，当前余额：" + balance);
        } else {
            System.out.println("存款金额必须大于0");
        }
    }
    
    public boolean withdraw(double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            System.out.println("取款成功，当前余额：" + balance);
            return true;
        } else {
            System.out.println("取款失败，余额不足或金额无效");
            return false;
        }
    }
}
```

### 3.3 继承

继承允许子类继承父类的属性和方法，实现代码复用。

```java
/**
 * 父类（基类/超类）
 */
public class Animal {
    protected String name;
    protected int age;
    
    public Animal() {
        System.out.println("Animal 构造方法");
    }
    
    public Animal(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public void eat() {
        System.out.println(name + " is eating");
    }
    
    public void sleep() {
        System.out.println(name + " is sleeping");
    }
}

/**
 * 子类（派生类）
 * 使用 extends 关键字继承
 * Java 只支持单继承，一个类只能有一个直接父类
 */
public class Dog extends Animal {
    private String breed;
    
    public Dog() {
        super();  // 调用父类无参构造，必须在第一行
        System.out.println("Dog 构造方法");
    }
    
    public Dog(String name, int age, String breed) {
        super(name, age);  // 调用父类有参构造
        this.breed = breed;
    }
    
    // 方法重写（Override）
    @Override
    public void eat() {
        System.out.println(name + " is eating dog food");
    }
    
    // 子类特有方法
    public void bark() {
        System.out.println(name + " is barking: Woof!");
    }
    
    // 调用父类方法
    public void parentEat() {
        super.eat();  // 调用父类的 eat 方法
    }
}

/**
 * 继承的使用
 */
public class Main {
    public static void main(String[] args) {
        Dog dog = new Dog("旺财", 3, "金毛");
        dog.eat();    // 调用重写后的方法
        dog.sleep();  // 继承自父类的方法
        dog.bark();   // 子类特有方法
        
        // 向上转型
        Animal animal = new Dog("小黑", 2, "哈士奇");
        animal.eat();   // 调用的是 Dog 的 eat 方法（多态）
        // animal.bark();  // 错误！Animal 类型没有 bark 方法
        
        // 向下转型
        if (animal instanceof Dog) {
            Dog d = (Dog) animal;
            d.bark();  // 现在可以调用了
        }
    }
}
```

### 3.4 多态

多态是指同一个方法调用，由于对象不同可能会有不同的行为。

```java
/**
 * 多态的实现条件：
 * 1. 继承关系
 * 2. 方法重写
 * 3. 父类引用指向子类对象
 */
public class PolymorphismDemo {
    public static void main(String[] args) {
        // 父类引用指向子类对象
        Animal animal1 = new Dog("旺财", 3);
        Animal animal2 = new Cat("咪咪", 2);
        
        // 同样的方法调用，不同的行为
        animal1.makeSound();  // 输出：旺财 says: Woof!
        animal2.makeSound();  // 输出：咪咪 says: Meow!
        
        // 多态的应用：统一处理不同类型的对象
        Animal[] animals = {
            new Dog("小黑", 1),
            new Cat("小白", 2),
            new Dog("大黄", 3)
        };
        
        for (Animal animal : animals) {
            animal.makeSound();  // 自动调用各自的实现
        }
        
        // 多态作为方法参数
        feedAnimal(new Dog("旺财", 3));
        feedAnimal(new Cat("咪咪", 2));
    }
    
    // 方法参数使用父类类型，可以接收任何子类对象
    public static void feedAnimal(Animal animal) {
        System.out.println("Feeding " + animal.getName());
        animal.eat();
    }
}

class Animal {
    protected String name;
    protected int age;
    
    public Animal(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() {
        return name;
    }
    
    public void eat() {
        System.out.println(name + " is eating");
    }
    
    public void makeSound() {
        System.out.println(name + " makes a sound");
    }
}

class Dog extends Animal {
    public Dog(String name, int age) {
        super(name, age);
    }
    
    @Override
    public void makeSound() {
        System.out.println(name + " says: Woof!");
    }
    
    @Override
    public void eat() {
        System.out.println(name + " is eating dog food");
    }
}

class Cat extends Animal {
    public Cat(String name, int age) {
        super(name, age);
    }
    
    @Override
    public void makeSound() {
        System.out.println(name + " says: Meow!");
    }
    
    @Override
    public void eat() {
        System.out.println(name + " is eating cat food");
    }
}
```

### 3.5 抽象类

抽象类是不能被实例化的类，用于定义通用的模板。

```java
/**
 * 抽象类
 * - 使用 abstract 关键字修饰
 * - 不能被实例化
 * - 可以包含抽象方法和普通方法
 * - 子类必须实现所有抽象方法，除非子类也是抽象类
 */
public abstract class Shape {
    protected String color;
    
    public Shape(String color) {
        this.color = color;
    }
    
    // 抽象方法：没有方法体，子类必须实现
    public abstract double getArea();
    public abstract double getPerimeter();
    
    // 普通方法：有方法体，子类可以直接使用或重写
    public void displayColor() {
        System.out.println("Color: " + color);
    }
    
    // 静态方法
    public static void printInfo() {
        System.out.println("This is a shape");
    }
}

/**
 * 具体子类：圆形
 */
public class Circle extends Shape {
    private double radius;
    
    public Circle(String color, double radius) {
        super(color);
        this.radius = radius;
    }
    
    @Override
    public double getArea() {
        return Math.PI * radius * radius;
    }
    
    @Override
    public double getPerimeter() {
        return 2 * Math.PI * radius;
    }
}

/**
 * 具体子类：矩形
 */
public class Rectangle extends Shape {
    private double width;
    private double height;
    
    public Rectangle(String color, double width, double height) {
        super(color);
        this.width = width;
        this.height = height;
    }
    
    @Override
    public double getArea() {
        return width * height;
    }
    
    @Override
    public double getPerimeter() {
        return 2 * (width + height);
    }
}

// 使用
public class Main {
    public static void main(String[] args) {
        // Shape shape = new Shape("red");  // 错误！抽象类不能实例化
        
        Shape circle = new Circle("red", 5);
        Shape rectangle = new Rectangle("blue", 4, 6);
        
        System.out.println("Circle area: " + circle.getArea());
        System.out.println("Rectangle area: " + rectangle.getArea());
    }
}
```

### 3.6 接口

接口是一种完全抽象的类型，定义了一组方法规范。

```java
/**
 * 接口定义
 * - 使用 interface 关键字
 * - 所有方法默认是 public abstract（Java 8 前）
 * - 所有变量默认是 public static final
 * - 一个类可以实现多个接口
 */
public interface Flyable {
    // 常量（默认 public static final）
    int MAX_HEIGHT = 10000;
    
    // 抽象方法（默认 public abstract）
    void fly();
    void land();
    
    // Java 8：默认方法（有方法体）
    default void glide() {
        System.out.println("Gliding...");
    }
    
    // Java 8：静态方法
    static void printInfo() {
        System.out.println("This is Flyable interface");
    }
}

public interface Swimmable {
    void swim();
    
    default void dive() {
        System.out.println("Diving...");
    }
}

/**
 * 实现接口
 * - 使用 implements 关键字
 * - 必须实现接口中所有抽象方法
 * - 可以实现多个接口
 */
public class Duck implements Flyable, Swimmable {
    private String name;
    
    public Duck(String name) {
        this.name = name;
    }
    
    @Override
    public void fly() {
        System.out.println(name + " is flying");
    }
    
    @Override
    public void land() {
        System.out.println(name + " is landing");
    }
    
    @Override
    public void swim() {
        System.out.println(name + " is swimming");
    }
    
    // 可以重写默认方法
    @Override
    public void glide() {
        System.out.println(name + " is gliding gracefully");
    }
}

/**
 * 接口继承
 */
public interface SuperFlyable extends Flyable {
    void superFly();  // 新增方法
}

// 使用
public class Main {
    public static void main(String[] args) {
        Duck duck = new Duck("Donald");
        duck.fly();
        duck.swim();
        duck.glide();
        
        // 接口类型引用
        Flyable flyable = new Duck("Daisy");
        flyable.fly();
        
        Swimmable swimmable = new Duck("Huey");
        swimmable.swim();
        
        // 调用静态方法
        Flyable.printInfo();
    }
}
```

### 3.7 内部类

```java
/**
 * 内部类的四种类型
 */
public class OuterClass {
    private String outerField = "Outer Field";
    private static String staticOuterField = "Static Outer Field";
    
    // ============ 1. 成员内部类 ============
    public class InnerClass {
        private String innerField = "Inner Field";
        
        public void display() {
            // 可以访问外部类的所有成员
            System.out.println(outerField);
            System.out.println(innerField);
        }
        
        // 访问外部类的 this
        public OuterClass getOuter() {
            return OuterClass.this;
        }
    }
    
    // ============ 2. 静态内部类 ============
    public static class StaticInnerClass {
        private String field = "Static Inner Field";
        
        public void display() {
            // 只能访问外部类的静态成员
            System.out.println(staticOuterField);
            // System.out.println(outerField);  // 错误！不能访问非静态成员
        }
    }
    
    // ============ 3. 局部内部类 ============
    public void methodWithLocalClass() {
        final String localVar = "Local Variable";  // Java 8 前必须是 final
        
        class LocalInnerClass {
            public void display() {
                System.out.println(outerField);
                System.out.println(localVar);  // 可以访问局部变量（effectively final）
            }
        }
        
        LocalInnerClass local = new LocalInnerClass();
        local.display();
    }
    
    // ============ 4. 匿名内部类 ============
    public void methodWithAnonymousClass() {
        // 匿名内部类实现接口
        Runnable runnable = new Runnable() {
            @Override
            public void run() {
                System.out.println("Anonymous class running");
            }
        };
        
        // 匿名内部类继承类
        Animal animal = new Animal("匿名动物", 1) {
            @Override
            public void makeSound() {
                System.out.println("Anonymous animal sound");
            }
        };
    }
    
    public static void main(String[] args) {
        OuterClass outer = new OuterClass();
        
        // 创建成员内部类实例
        OuterClass.InnerClass inner = outer.new InnerClass();
        inner.display();
        
        // 创建静态内部类实例
        OuterClass.StaticInnerClass staticInner = new OuterClass.StaticInnerClass();
        staticInner.display();
        
        // 局部内部类
        outer.methodWithLocalClass();
        
        // 匿名内部类
        outer.methodWithAnonymousClass();
    }
}
```

### 3.8 枚举

```java
/**
 * 枚举类型
 * - 使用 enum 关键字
 * - 枚举值是该枚举类型的实例
 * - 可以有构造方法、字段和方法
 */
public enum Season {
    // 枚举值（必须在最前面）
    SPRING("春天", "温暖"),
    SUMMER("夏天", "炎热"),
    AUTUMN("秋天", "凉爽"),
    WINTER("冬天", "寒冷");
    
    // 字段
    private final String chineseName;
    private final String description;
    
    // 构造方法（默认 private）
    Season(String chineseName, String description) {
        this.chineseName = chineseName;
        this.description = description;
    }
    
    // Getter
    public String getChineseName() {
        return chineseName;
    }
    
    public String getDescription() {
        return description;
    }
    
    // 自定义方法
    public void printInfo() {
        System.out.println(chineseName + " - " + description);
    }
}

/**
 * 枚举的使用
 */
public class EnumDemo {
    public static void main(String[] args) {
        // 获取枚举值
        Season spring = Season.SPRING;
        System.out.println(spring);  // SPRING
        System.out.println(spring.getChineseName());  // 春天
        
        // 枚举常用方法
        System.out.println(spring.name());     // SPRING（枚举名称）
        System.out.println(spring.ordinal());  // 0（枚举序号）
        
        // 遍历所有枚举值
        for (Season season : Season.values()) {
            season.printInfo();
        }
        
        // 字符串转枚举
        Season summer = Season.valueOf("SUMMER");
        
        // switch 中使用枚举
        switch (spring) {
            case SPRING:
                System.out.println("春暖花开");
                break;
            case SUMMER:
                System.out.println("烈日炎炎");
                break;
            case AUTUMN:
                System.out.println("秋高气爽");
                break;
            case WINTER:
                System.out.println("白雪皑皑");
                break;
        }
        
        // 枚举比较
        System.out.println(spring == Season.SPRING);  // true
        System.out.println(spring.equals(Season.SPRING));  // true
    }
}

/**
 * 枚举实现接口
 */
public enum Operation implements Calculable {
    ADD {
        @Override
        public double calculate(double a, double b) {
            return a + b;
        }
    },
    SUBTRACT {
        @Override
        public double calculate(double a, double b) {
            return a - b;
        }
    },
    MULTIPLY {
        @Override
        public double calculate(double a, double b) {
            return a * b;
        }
    },
    DIVIDE {
        @Override
        public double calculate(double a, double b) {
            return a / b;
        }
    };
}

interface Calculable {
    double calculate(double a, double b);
}
```

---

## 4. 常用类库

### 4.1 String 类

```java
public class StringDemo {
    public static void main(String[] args) {
        // ============ 创建字符串 ============
        String s1 = "Hello";           // 字符串字面量（存储在字符串常量池）
        String s2 = new String("Hello");  // 创建新对象（存储在堆中）
        String s3 = "Hello";
        
        // == 比较引用，equals 比较内容
        System.out.println(s1 == s3);       // true（同一个常量池对象）
        System.out.println(s1 == s2);       // false（不同对象）
        System.out.println(s1.equals(s2));  // true（内容相同）
        
        // ============ 常用方法 ============
        String str = "Hello, World!";
        
        // 长度
        System.out.println(str.length());  // 13
        
        // 获取字符
        System.out.println(str.charAt(0));  // H
        
        // 查找
        System.out.println(str.indexOf("o"));      // 4（第一次出现）
        System.out.println(str.lastIndexOf("o"));  // 8（最后一次出现）
        System.out.println(str.contains("World")); // true
        
        // 截取
        System.out.println(str.substring(7));      // World!
        System.out.println(str.substring(0, 5));   // Hello
        
        // 替换
        System.out.println(str.replace("World", "Java"));  // Hello, Java!
        System.out.println(str.replaceAll("\\w+", "*"));   // 正则替换
        
        // 分割
        String[] parts = str.split(", ");  // ["Hello", "World!"]
        
        // 大小写转换
        System.out.println(str.toUpperCase());  // HELLO, WORLD!
        System.out.println(str.toLowerCase());  // hello, world!
        
        // 去除空白
        String s = "  Hello  ";
        System.out.println(s.trim());  // "Hello"
        
        // 判断
        System.out.println(str.startsWith("Hello"));  // true
        System.out.println(str.endsWith("!"));        // true
        System.out.println(str.isEmpty());            // false
        System.out.println("".isEmpty());             // true
        
        // 格式化
        String formatted = String.format("Name: %s, Age: %d", "张三", 25);
        System.out.println(formatted);  // Name: 张三, Age: 25
        
        // 连接
        String joined = String.join("-", "2024", "01", "15");  // 2024-01-15
        
        // 转换
        int num = Integer.parseInt("123");
        String numStr = String.valueOf(123);
        char[] chars = str.toCharArray();
        byte[] bytes = str.getBytes();
    }
}
```

### 4.2 StringBuilder 和 StringBuffer

```java
/**
 * String 是不可变的，每次修改都会创建新对象
 * StringBuilder 和 StringBuffer 是可变的，适合频繁修改字符串
 * 
 * StringBuilder：非线程安全，性能更高（推荐）
 * StringBuffer：线程安全，性能较低
 */
public class StringBuilderDemo {
    public static void main(String[] args) {
        // ============ StringBuilder 基本使用 ============
        StringBuilder sb = new StringBuilder();
        
        // 追加
        sb.append("Hello");
        sb.append(" ");
        sb.append("World");
        System.out.println(sb.toString());  // Hello World
        
        // 链式调用
        StringBuilder sb2 = new StringBuilder()
            .append("Java")
            .append(" ")
            .append("Programming");
        
        // 插入
        sb.insert(6, "Beautiful ");  // Hello Beautiful World
        
        // 删除
        sb.delete(6, 16);  // Hello World
        sb.deleteCharAt(5);  // HelloWorld
        
        // 替换
        sb.replace(5, 10, " Java");  // Hello Java
        
        // 反转
        sb.reverse();  // avaJ olleH
        
        // 设置长度
        sb.setLength(5);  // avaJ 
        
        // ============ 性能对比 ============
        long start = System.currentTimeMillis();
        
        // 使用 String（慢）
        String str = "";
        for (int i = 0; i < 100000; i++) {
            str += i;  // 每次都创建新对象
        }
        System.out.println("String: " + (System.currentTimeMillis() - start) + "ms");
        
        start = System.currentTimeMillis();
        
        // 使用 StringBuilder（快）
        StringBuilder sb3 = new StringBuilder();
        for (int i = 0; i < 100000; i++) {
            sb3.append(i);  // 在原对象上修改
        }
        System.out.println("StringBuilder: " + (System.currentTimeMillis() - start) + "ms");
    }
}
```

### 4.3 包装类

```java
/**
 * 基本类型的包装类
 * byte    -> Byte
 * short   -> Short
 * int     -> Integer
 * long    -> Long
 * float   -> Float
 * double  -> Double
 * char    -> Character
 * boolean -> Boolean
 */
public class WrapperClassDemo {
    public static void main(String[] args) {
        // ============ 自动装箱和拆箱（Java 5+） ============
        // 装箱：基本类型 -> 包装类
        Integer num1 = 100;  // 自动装箱
        Integer num2 = Integer.valueOf(100);  // 手动装箱
        
        // 拆箱：包装类 -> 基本类型
        int n1 = num1;  // 自动拆箱
        int n2 = num1.intValue();  // 手动拆箱
        
        // ============ 常用方法 ============
        // 字符串转数字
        int i = Integer.parseInt("123");
        double d = Double.parseDouble("3.14");
        
        // 数字转字符串
        String s1 = Integer.toString(123);
        String s2 = String.valueOf(123);
        
        // 进制转换
        String binary = Integer.toBinaryString(10);  // "1010"
        String octal = Integer.toOctalString(10);    // "12"
        String hex = Integer.toHexString(10);        // "a"
        int fromBinary = Integer.parseInt("1010", 2);  // 10
        
        // 最大最小值
        System.out.println(Integer.MAX_VALUE);  // 2147483647
        System.out.println(Integer.MIN_VALUE);  // -2147483648
        
        // ============ 缓存机制（Integer Cache） ============
        // -128 到 127 之间的 Integer 会被缓存
        Integer a = 127;
        Integer b = 127;
        System.out.println(a == b);  // true（同一个缓存对象）
        
        Integer c = 128;
        Integer d2 = 128;
        System.out.println(c == d2);  // false（不同对象）
        System.out.println(c.equals(d2));  // true（内容相同）
        
        // ============ 注意事项 ============
        // 包装类可以为 null
        Integer nullInt = null;
        // int n = nullInt;  // NullPointerException！
        
        // 比较时使用 equals
        Integer x = 1000;
        Integer y = 1000;
        System.out.println(x.equals(y));  // true（推荐）
    }
}
```

### 4.4 Math 类

```java
public class MathDemo {
    public static void main(String[] args) {
        // 常量
        System.out.println(Math.PI);   // 3.141592653589793
        System.out.println(Math.E);    // 2.718281828459045
        
        // 绝对值
        System.out.println(Math.abs(-10));  // 10
        
        // 最大最小值
        System.out.println(Math.max(10, 20));  // 20
        System.out.println(Math.min(10, 20));  // 10
        
        // 幂运算
        System.out.println(Math.pow(2, 10));  // 1024.0
        System.out.println(Math.sqrt(16));    // 4.0（平方根）
        System.out.println(Math.cbrt(27));    // 3.0（立方根）
        
        // 取整
        System.out.println(Math.ceil(3.1));   // 4.0（向上取整）
        System.out.println(Math.floor(3.9));  // 3.0（向下取整）
        System.out.println(Math.round(3.5));  // 4（四舍五入）
        System.out.println(Math.round(3.4));  // 3
        
        // 随机数
        System.out.println(Math.random());  // [0.0, 1.0) 之间的随机数
        // 生成 [min, max] 之间的随机整数
        int min = 1, max = 100;
        int random = (int) (Math.random() * (max - min + 1)) + min;
        
        // 三角函数（参数为弧度）
        System.out.println(Math.sin(Math.PI / 2));  // 1.0
        System.out.println(Math.cos(0));            // 1.0
        System.out.println(Math.tan(Math.PI / 4));  // 1.0
        
        // 对数
        System.out.println(Math.log(Math.E));   // 1.0（自然对数）
        System.out.println(Math.log10(100));    // 2.0（以10为底）
    }
}
```

### 4.5 日期时间类

```java
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.text.SimpleDateFormat;

public class DateTimeDemo {
    public static void main(String[] args) {
        // ============ Java 8 新日期API（推荐） ============
        
        // LocalDate - 日期（年月日）
        LocalDate today = LocalDate.now();
        LocalDate birthday = LocalDate.of(1990, 5, 15);
        System.out.println("Today: " + today);
        System.out.println("Year: " + today.getYear());
        System.out.println("Month: " + today.getMonthValue());
        System.out.println("Day: " + today.getDayOfMonth());
        System.out.println("Day of Week: " + today.getDayOfWeek());
        
        // LocalTime - 时间（时分秒）
        LocalTime now = LocalTime.now();
        LocalTime time = LocalTime.of(14, 30, 0);
        System.out.println("Now: " + now);
        System.out.println("Hour: " + now.getHour());
        
        // LocalDateTime - 日期时间
        LocalDateTime dateTime = LocalDateTime.now();
        LocalDateTime specific = LocalDateTime.of(2024, 1, 15, 14, 30, 0);
        
        // 日期计算
        LocalDate tomorrow = today.plusDays(1);
        LocalDate lastMonth = today.minusMonths(1);
        LocalDate nextYear = today.plusYears(1);
        
        // 日期比较
        System.out.println(today.isAfter(birthday));   // true
        System.out.println(today.isBefore(tomorrow));  // true
        
        // 计算日期差
        long daysBetween = ChronoUnit.DAYS.between(birthday, today);
        Period period = Period.between(birthday, today);
        System.out.println("Years: " + period.getYears());
        
        // 格式化
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formatted = dateTime.format(formatter);
        System.out.println("Formatted: " + formatted);
        
        // 解析
        LocalDateTime parsed = LocalDateTime.parse("2024-01-15 14:30:00", formatter);
        
        // Instant - 时间戳
        Instant instant = Instant.now();
        long epochMilli = instant.toEpochMilli();  // 毫秒时间戳
        
        // ZonedDateTime - 带时区的日期时间
        ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneId.of("Asia/Shanghai"));
        
        // ============ 旧版日期API（了解即可） ============
        
        // Date
        Date date = new Date();
        System.out.println(date);
        
        // SimpleDateFormat（非线程安全！）
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String dateStr = sdf.format(date);
        // Date parsedDate = sdf.parse("2024-01-15 14:30:00");
        
        // Date 和 LocalDateTime 互转
        LocalDateTime ldt = LocalDateTime.ofInstant(date.toInstant(), ZoneId.systemDefault());
        Date d = Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
    }
}
```

---

## 5. 集合框架

### 5.1 集合框架概述

```
                    Collection (接口)
                         │
         ┌───────────────┼───────────────┐
         │               │               │
       List            Set            Queue
      (有序可重复)    (无序不重复)      (队列)
         │               │               │
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │         │     │         │     │         │
ArrayList  LinkedList  HashSet  TreeSet  PriorityQueue
                        │
                    LinkedHashSet


                      Map (接口)
                         │
         ┌───────────────┼───────────────┐
         │               │               │
      HashMap        TreeMap        LinkedHashMap
         │
    ConcurrentHashMap
```

### 5.2 List 接口

```java
import java.util.*;

public class ListDemo {
    public static void main(String[] args) {
        // ============ ArrayList ============
        // 基于动态数组，查询快，增删慢
        List<String> arrayList = new ArrayList<>();
        
        // 添加元素
        arrayList.add("Apple");
        arrayList.add("Banana");
        arrayList.add("Cherry");
        arrayList.add(1, "Apricot");  // 在指定位置插入
        
        // 获取元素
        String first = arrayList.get(0);
        
        // 修改元素
        arrayList.set(0, "Avocado");
        
        // 删除元素
        arrayList.remove(0);           // 按索引删除
        arrayList.remove("Banana");    // 按元素删除
        
        // 查找
        int index = arrayList.indexOf("Cherry");
        boolean contains = arrayList.contains("Cherry");
        
        // 大小
        int size = arrayList.size();
        boolean isEmpty = arrayList.isEmpty();
        
        // 遍历
        // 方式1：for 循环
        for (int i = 0; i < arrayList.size(); i++) {
            System.out.println(arrayList.get(i));
        }
        
        // 方式2：增强 for
        for (String item : arrayList) {
            System.out.println(item);
        }
        
        // 方式3：迭代器
        Iterator<String> iterator = arrayList.iterator();
        while (iterator.hasNext()) {
            String item = iterator.next();
            System.out.println(item);
            // iterator.remove();  // 安全删除
        }
        
        // 方式4：forEach（Java 8）
        arrayList.forEach(System.out::println);
        
        // 转数组
        String[] array = arrayList.toArray(new String[0]);
        
        // 清空
        arrayList.clear();
        
        // ============ LinkedList ============
        // 基于双向链表，增删快，查询慢
        LinkedList<String> linkedList = new LinkedList<>();
        
        // 特有方法
        linkedList.addFirst("First");
        linkedList.addLast("Last");
        linkedList.getFirst();
        linkedList.getLast();
        linkedList.removeFirst();
        linkedList.removeLast();
        
        // 可以作为栈使用
        linkedList.push("A");  // 入栈
        linkedList.pop();      // 出栈
        
        // 可以作为队列使用
        linkedList.offer("B");  // 入队
        linkedList.poll();      // 出队
        
        // ============ 初始化方式 ============
        // 方式1：Arrays.asList（返回固定大小的 List）
        List<String> list1 = Arrays.asList("A", "B", "C");
        // list1.add("D");  // 错误！不能添加
        
        // 方式2：new ArrayList<>(Arrays.asList(...))
        List<String> list2 = new ArrayList<>(Arrays.asList("A", "B", "C"));
        list2.add("D");  // 可以添加
        
        // 方式3：双括号初始化（不推荐，会创建匿名内部类）
        List<String> list3 = new ArrayList<String>() {{
            add("A");
            add("B");
        }};
        
        // 方式4：Java 9+ List.of（不可变）
        // List<String> list4 = List.of("A", "B", "C");
    }
}
```

### 5.3 Set 接口

```java
import java.util.*;

public class SetDemo {
    public static void main(String[] args) {
        // ============ HashSet ============
        // 基于 HashMap，无序，不重复，允许 null
        Set<String> hashSet = new HashSet<>();
        
        hashSet.add("Apple");
        hashSet.add("Banana");
        hashSet.add("Apple");  // 重复元素，不会添加
        hashSet.add(null);     // 允许 null
        
        System.out.println(hashSet.size());  // 3
        System.out.println(hashSet);  // 顺序不确定
        
        // ============ LinkedHashSet ============
        // 基于 LinkedHashMap，保持插入顺序
        Set<String> linkedHashSet = new LinkedHashSet<>();
        linkedHashSet.add("C");
        linkedHashSet.add("A");
        linkedHashSet.add("B");
        System.out.println(linkedHashSet);  // [C, A, B]
        
        // ============ TreeSet ============
        // 基于红黑树，自动排序，不允许 null
        Set<Integer> treeSet = new TreeSet<>();
        treeSet.add(3);
        treeSet.add(1);
        treeSet.add(2);
        System.out.println(treeSet);  // [1, 2, 3]
        
        // 自定义排序
        Set<String> customTreeSet = new TreeSet<>((s1, s2) -> s2.compareTo(s1));  // 降序
        customTreeSet.add("Apple");
        customTreeSet.add("Banana");
        customTreeSet.add("Cherry");
        System.out.println(customTreeSet);  // [Cherry, Banana, Apple]
        
        // TreeSet 特有方法
        TreeSet<Integer> ts = new TreeSet<>(Arrays.asList(1, 3, 5, 7, 9));
        System.out.println(ts.first());     // 1（最小）
        System.out.println(ts.last());      // 9（最大）
        System.out.println(ts.lower(5));    // 3（小于5的最大元素）
        System.out.println(ts.higher(5));   // 7（大于5的最小元素）
        System.out.println(ts.floor(6));    // 5（小于等于6的最大元素）
        System.out.println(ts.ceiling(6));  // 7（大于等于6的最小元素）
        
        // ============ 集合运算 ============
        Set<Integer> set1 = new HashSet<>(Arrays.asList(1, 2, 3, 4, 5));
        Set<Integer> set2 = new HashSet<>(Arrays.asList(4, 5, 6, 7, 8));
        
        // 并集
        Set<Integer> union = new HashSet<>(set1);
        union.addAll(set2);  // [1, 2, 3, 4, 5, 6, 7, 8]
        
        // 交集
        Set<Integer> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);  // [4, 5]
        
        // 差集
        Set<Integer> difference = new HashSet<>(set1);
        difference.removeAll(set2);  // [1, 2, 3]
    }
}
```

### 5.4 Map 接口

```java
import java.util.*;

public class MapDemo {
    public static void main(String[] args) {
        // ============ HashMap ============
        // 基于哈希表，无序，允许 null 键和值
        Map<String, Integer> hashMap = new HashMap<>();
        
        // 添加/修改
        hashMap.put("Apple", 10);
        hashMap.put("Banana", 20);
        hashMap.put("Cherry", 30);
        hashMap.put("Apple", 15);  // 键已存在，更新值
        
        // 获取
        Integer value = hashMap.get("Apple");  // 15
        Integer defaultValue = hashMap.getOrDefault("Grape", 0);  // 0
        
        // 删除
        hashMap.remove("Banana");
        hashMap.remove("Cherry", 30);  // 只有值匹配时才删除
        
        // 判断
        boolean hasKey = hashMap.containsKey("Apple");
        boolean hasValue = hashMap.containsValue(15);
        
        // 大小
        int size = hashMap.size();
        boolean isEmpty = hashMap.isEmpty();
        
        // 遍历
        // 方式1：遍历键
        for (String key : hashMap.keySet()) {
            System.out.println(key + ": " + hashMap.get(key));
        }
        
        // 方式2：遍历值
        for (Integer val : hashMap.values()) {
            System.out.println(val);
        }
        
        // 方式3：遍历键值对（推荐）
        for (Map.Entry<String, Integer> entry : hashMap.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
        
        // 方式4：forEach（Java 8）
        hashMap.forEach((k, v) -> System.out.println(k + ": " + v));
        
        // Java 8 新方法
        hashMap.putIfAbsent("Grape", 40);  // 键不存在时才添加
        hashMap.computeIfAbsent("Orange", k -> k.length());  // 键不存在时计算值
        hashMap.computeIfPresent("Apple", (k, v) -> v + 10);  // 键存在时计算新值
        hashMap.merge("Apple", 5, Integer::sum);  // 合并值
        
        // ============ LinkedHashMap ============
        // 保持插入顺序
        Map<String, Integer> linkedHashMap = new LinkedHashMap<>();
        linkedHashMap.put("C", 3);
        linkedHashMap.put("A", 1);
        linkedHashMap.put("B", 2);
        System.out.println(linkedHashMap);  // {C=3, A=1, B=2}
        
        // 访问顺序（LRU 缓存）
        Map<String, Integer> lruCache = new LinkedHashMap<>(16, 0.75f, true);
        
        // ============ TreeMap ============
        // 基于红黑树，按键排序
        Map<String, Integer> treeMap = new TreeMap<>();
        treeMap.put("Banana", 2);
        treeMap.put("Apple", 1);
        treeMap.put("Cherry", 3);
        System.out.println(treeMap);  // {Apple=1, Banana=2, Cherry=3}
        
        // 自定义排序
        Map<String, Integer> customTreeMap = new TreeMap<>(Comparator.reverseOrder());
        
        // TreeMap 特有方法
        TreeMap<Integer, String> tm = new TreeMap<>();
        tm.put(1, "A");
        tm.put(3, "C");
        tm.put(5, "E");
        System.out.println(tm.firstKey());     // 1
        System.out.println(tm.lastKey());      // 5
        System.out.println(tm.lowerKey(3));    // 1
        System.out.println(tm.higherKey(3));   // 5
        System.out.println(tm.subMap(1, 5));   // {1=A, 3=C}
        
        // ============ Hashtable ============
        // 线程安全，不允许 null 键和值（已过时，用 ConcurrentHashMap 代替）
        Map<String, Integer> hashtable = new Hashtable<>();
    }
}
```

### 5.5 Collections 工具类

```java
import java.util.*;

public class CollectionsDemo {
    public static void main(String[] args) {
        List<Integer> list = new ArrayList<>(Arrays.asList(3, 1, 4, 1, 5, 9, 2, 6));
        
        // 排序
        Collections.sort(list);  // 升序
        Collections.sort(list, Collections.reverseOrder());  // 降序
        Collections.sort(list, (a, b) -> b - a);  // 自定义排序
        
        // 反转
        Collections.reverse(list);
        
        // 打乱
        Collections.shuffle(list);
        
        // 填充
        Collections.fill(list, 0);
        
        // 复制
        List<Integer> dest = new ArrayList<>(Collections.nCopies(list.size(), 0));
        Collections.copy(dest, list);
        
        // 替换
        Collections.replaceAll(list, 0, 100);
        
        // 查找
        list = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5));
        int index = Collections.binarySearch(list, 3);  // 必须有序
        int max = Collections.max(list);
        int min = Collections.min(list);
        int frequency = Collections.frequency(list, 1);  // 出现次数
        
        // 不可变集合
        List<String> immutableList = Collections.unmodifiableList(new ArrayList<>(Arrays.asList("A", "B")));
        // immutableList.add("C");  // 抛出 UnsupportedOperationException
        
        // 同步集合（线程安全）
        List<String> syncList = Collections.synchronizedList(new ArrayList<>());
        Map<String, Integer> syncMap = Collections.synchronizedMap(new HashMap<>());
        
        // 空集合
        List<String> emptyList = Collections.emptyList();
        Set<String> emptySet = Collections.emptySet();
        Map<String, Integer> emptyMap = Collections.emptyMap();
        
        // 单元素集合
        List<String> singletonList = Collections.singletonList("Only");
        Set<String> singletonSet = Collections.singleton("Only");
        Map<String, Integer> singletonMap = Collections.singletonMap("Key", 1);
    }
}
```

### 5.6 泛型

```java
/**
 * 泛型：参数化类型，在编译时进行类型检查
 */
public class GenericDemo {
    public static void main(String[] args) {
        // ============ 泛型类 ============
        Box<String> stringBox = new Box<>();
        stringBox.set("Hello");
        String s = stringBox.get();  // 不需要强制转换
        
        Box<Integer> intBox = new Box<>();
        intBox.set(123);
        Integer i = intBox.get();
        
        // ============ 泛型方法 ============
        String[] strArray = {"A", "B", "C"};
        printArray(strArray);
        
        Integer[] intArray = {1, 2, 3};
        printArray(intArray);
        
        // ============ 泛型通配符 ============
        List<Integer> intList = Arrays.asList(1, 2, 3);
        List<Double> doubleList = Arrays.asList(1.1, 2.2, 3.3);
        
        printList(intList);
        printList(doubleList);
        
        // ============ 类型擦除 ============
        // 泛型信息只在编译时存在，运行时会被擦除
        List<String> list1 = new ArrayList<>();
        List<Integer> list2 = new ArrayList<>();
        System.out.println(list1.getClass() == list2.getClass());  // true
    }
    
    // 泛型方法
    public static <T> void printArray(T[] array) {
        for (T element : array) {
            System.out.println(element);
        }
    }
    
    // 通配符 ?
    public static void printList(List<?> list) {
        for (Object obj : list) {
            System.out.println(obj);
        }
    }
    
    // 上界通配符 <? extends T>：只能读，不能写
    public static double sumOfList(List<? extends Number> list) {
        double sum = 0;
        for (Number num : list) {
            sum += num.doubleValue();
        }
        return sum;
    }
    
    // 下界通配符 <? super T>：只能写，读取只能是 Object
    public static void addNumbers(List<? super Integer> list) {
        list.add(1);
        list.add(2);
    }
}

/**
 * 泛型类
 */
class Box<T> {
    private T content;
    
    public void set(T content) {
        this.content = content;
    }
    
    public T get() {
        return content;
    }
}

/**
 * 多个类型参数
 */
class Pair<K, V> {
    private K key;
    private V value;
    
    public Pair(K key, V value) {
        this.key = key;
        this.value = value;
    }
    
    public K getKey() { return key; }
    public V getValue() { return value; }
}

/**
 * 泛型接口
 */
interface Generator<T> {
    T generate();
}

class StringGenerator implements Generator<String> {
    @Override
    public String generate() {
        return "Generated String";
    }
}
```

---

## 6. 异常处理

### 6.1 异常体系

```
                    Throwable
                        │
            ┌───────────┴───────────┐
            │                       │
         Error                  Exception
      (严重错误)                  (异常)
            │                       │
    ┌───────┴───────┐       ┌───────┴───────┐
    │               │       │               │
OutOfMemoryError  StackOverflowError  RuntimeException  IOException
                                │               │
                        ┌───────┴───────┐   FileNotFoundException
                        │               │
                NullPointerException  IndexOutOfBoundsException
                        │
                ArrayIndexOutOfBoundsException
```

**异常分类：**
- **Error**：严重错误，程序无法处理，如内存溢出
- **Exception**：
  - **检查型异常（Checked Exception）**：编译时必须处理，如 IOException
  - **运行时异常（RuntimeException）**：编译时不强制处理，如 NullPointerException

### 6.2 异常处理语法

```java
public class ExceptionDemo {
    public static void main(String[] args) {
        // ============ try-catch-finally ============
        try {
            // 可能抛出异常的代码
            int result = 10 / 0;
        } catch (ArithmeticException e) {
            // 处理特定异常
            System.out.println("除数不能为0: " + e.getMessage());
        } catch (Exception e) {
            // 处理其他异常（父类异常放后面）
            System.out.println("发生异常: " + e.getMessage());
        } finally {
            // 无论是否发生异常都会执行
            System.out.println("finally 块执行");
        }
        
        // ============ 多异常捕获（Java 7+） ============
        try {
            // ...
        } catch (IOException | SQLException e) {
            // 同时捕获多种异常
            e.printStackTrace();
        }
        
        // ============ try-with-resources（Java 7+） ============
        // 自动关闭实现了 AutoCloseable 接口的资源
        try (FileInputStream fis = new FileInputStream("file.txt");
             BufferedReader br = new BufferedReader(new InputStreamReader(fis))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 不需要手动关闭资源
        
        // ============ 获取异常信息 ============
        try {
            throw new RuntimeException("测试异常");
        } catch (Exception e) {
            System.out.println(e.getMessage());      // 异常消息
            System.out.println(e.toString());        // 异常类型和消息
            e.printStackTrace();                      // 打印堆栈跟踪
            StackTraceElement[] stackTrace = e.getStackTrace();  // 获取堆栈信息
        }
    }
    
    // ============ throws 声明异常 ============
    // 方法可能抛出的检查型异常必须声明
    public static void readFile(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        // ...
    }
    
    // ============ throw 抛出异常 ============
    public static void validateAge(int age) {
        if (age < 0) {
            throw new IllegalArgumentException("年龄不能为负数");
        }
        if (age > 150) {
            throw new IllegalArgumentException("年龄不能超过150");
        }
    }
}
```

### 6.3 自定义异常

```java
/**
 * 自定义检查型异常
 */
public class BusinessException extends Exception {
    private int errorCode;
    
    public BusinessException(String message) {
        super(message);
    }
    
    public BusinessException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public BusinessException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public int getErrorCode() {
        return errorCode;
    }
}

/**
 * 自定义运行时异常
 */
public class ServiceException extends RuntimeException {
    private String errorCode;
    
    public ServiceException(String message) {
        super(message);
    }
    
    public ServiceException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public String getErrorCode() {
        return errorCode;
    }
}

/**
 * 使用自定义异常
 */
public class UserService {
    public void createUser(String username) throws BusinessException {
        if (username == null || username.isEmpty()) {
            throw new BusinessException("用户名不能为空", 1001);
        }
        if (username.length() < 3) {
            throw new BusinessException("用户名长度不能少于3个字符", 1002);
        }
        // 创建用户...
    }
    
    public void deleteUser(Long id) {
        if (id == null || id <= 0) {
            throw new ServiceException("INVALID_ID", "无效的用户ID");
        }
        // 删除用户...
    }
}
```

### 6.4 异常处理最佳实践

```java
public class ExceptionBestPractice {
    
    // 1. 捕获具体的异常，而不是 Exception
    public void badPractice() {
        try {
            // ...
        } catch (Exception e) {  // 不推荐
            e.printStackTrace();
        }
    }
    
    public void goodPractice() {
        try {
            // ...
        } catch (FileNotFoundException e) {
            // 处理文件不存在
        } catch (IOException e) {
            // 处理其他 IO 异常
        }
    }
    
    // 2. 不要忽略异常
    public void dontIgnore() {
        try {
            // ...
        } catch (Exception e) {
            // 至少记录日志
            logger.error("发生异常", e);
        }
    }
    
    // 3. 使用 try-with-resources 管理资源
    public void useAutoCloseable() {
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            // ...
        } catch (SQLException e) {
            // ...
        }
    }
    
    // 4. 异常信息要有意义
    public void meaningfulMessage(String userId) {
        if (userId == null) {
            throw new IllegalArgumentException("userId 不能为 null");
        }
    }
    
    // 5. 不要在 finally 中使用 return
    public int dontReturnInFinally() {
        try {
            return 1;
        } finally {
            // return 2;  // 不要这样做！会覆盖 try 中的返回值
        }
    }
    
    // 6. 包装底层异常
    public void wrapException() throws ServiceException {
        try {
            // 调用底层方法
        } catch (SQLException e) {
            throw new ServiceException("数据库操作失败", e);
        }
    }
}
```

---

## 7. IO流

### 7.1 IO 流分类

```
                        IO 流
                          │
            ┌─────────────┴─────────────┐
            │                           │
        字节流                         字符流
     (处理二进制)                    (处理文本)
            │                           │
    ┌───────┴───────┐           ┌───────┴───────┐
    │               │           │               │
InputStream    OutputStream   Reader          Writer
    │               │           │               │
FileInputStream FileOutputStream FileReader  FileWriter
BufferedInputStream BufferedOutputStream BufferedReader BufferedWriter
```

### 7.2 File 类

```java
import java.io.*;

public class FileDemo {
    public static void main(String[] args) throws IOException {
        // ============ 创建 File 对象 ============
        File file = new File("test.txt");
        File dir = new File("mydir");
        File fullPath = new File("C:/Users/test/file.txt");
        File combined = new File(dir, "file.txt");
        
        // ============ 文件/目录操作 ============
        // 创建
        boolean created = file.createNewFile();  // 创建文件
        boolean dirCreated = dir.mkdir();        // 创建单级目录
        boolean dirsCreated = dir.mkdirs();      // 创建多级目录
        
        // 删除
        boolean deleted = file.delete();
        
        // 重命名/移动
        File newFile = new File("newname.txt");
        boolean renamed = file.renameTo(newFile);
        
        // ============ 文件信息 ============
        System.out.println("存在: " + file.exists());
        System.out.println("是文件: " + file.isFile());
        System.out.println("是目录: " + file.isDirectory());
        System.out.println("可读: " + file.canRead());
        System.out.println("可写: " + file.canWrite());
        System.out.println("可执行: " + file.canExecute());
        System.out.println("是隐藏: " + file.isHidden());
        System.out.println("文件名: " + file.getName());
        System.out.println("路径: " + file.getPath());
        System.out.println("绝对路径: " + file.getAbsolutePath());
        System.out.println("父目录: " + file.getParent());
        System.out.println("大小: " + file.length() + " bytes");
        System.out.println("最后修改: " + file.lastModified());
        
        // ============ 目录操作 ============
        File directory = new File(".");
        
        // 列出文件名
        String[] fileNames = directory.list();
        
        // 列出 File 对象
        File[] files = directory.listFiles();
        
        // 带过滤器
        File[] txtFiles = directory.listFiles((dir1, name) -> name.endsWith(".txt"));
        
        // 递归遍历目录
        listAllFiles(directory);
    }
    
    public static void listAllFiles(File dir) {
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        listAllFiles(file);  // 递归
                    } else {
                        System.out.println(file.getAbsolutePath());
                    }
                }
            }
        }
    }
}
```

### 7.3 字节流

```java
import java.io.*;

public class ByteStreamDemo {
    public static void main(String[] args) {
        // ============ FileInputStream / FileOutputStream ============
        // 基本字节流，一次读写一个字节
        
        // 写文件
        try (FileOutputStream fos = new FileOutputStream("output.txt")) {
            fos.write(65);  // 写入单个字节
            fos.write("Hello".getBytes());  // 写入字节数组
            fos.write("World".getBytes(), 0, 5);  // 写入部分字节数组
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // 追加写入
        try (FileOutputStream fos = new FileOutputStream("output.txt", true)) {
            fos.write("\nAppended".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // 读文件
        try (FileInputStream fis = new FileInputStream("output.txt")) {
            int data;
            while ((data = fis.read()) != -1) {  // 一次读一个字节
                System.out.print((char) data);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // 使用字节数组读取（更高效）
        try (FileInputStream fis = new FileInputStream("output.txt")) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                System.out.print(new String(buffer, 0, len));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // ============ BufferedInputStream / BufferedOutputStream ============
        // 带缓冲的字节流，性能更好
        
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream("input.txt"));
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("output.txt"))) {
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = bis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
            bos.flush();  // 刷新缓冲区
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // ============ 文件复制 ============
        copyFile("source.txt", "dest.txt");
    }
    
    public static void copyFile(String src, String dest) {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(src));
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(dest))) {
            
            byte[] buffer = new byte[8192];
            int len;
            while ((len = bis.read(buffer)) != -1) {
                bos.write(buffer, 0, len);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

### 7.4 字符流

```java
import java.io.*;

public class CharStreamDemo {
    public static void main(String[] args) {
        // ============ FileReader / FileWriter ============
        // 基本字符流，处理文本文件
        
        // 写文件
        try (FileWriter fw = new FileWriter("output.txt")) {
            fw.write("Hello, 世界!");
            fw.write("\n");
            fw.write("第二行");
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // 读文件
        try (FileReader fr = new FileReader("output.txt")) {
            int ch;
            while ((ch = fr.read()) != -1) {
                System.out.print((char) ch);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // ============ BufferedReader / BufferedWriter ============
        // 带缓冲的字符流，支持按行读写
        
        // 写文件
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("output.txt"))) {
            bw.write("第一行");
            bw.newLine();  // 写入换行符
            bw.write("第二行");
            bw.newLine();
            bw.write("第三行");
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // 读文件（按行读取）
        try (BufferedReader br = new BufferedReader(new FileReader("output.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // ============ InputStreamReader / OutputStreamWriter ============
        // 字节流转字符流，可指定编码
        
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream("output.txt"), "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        try (BufferedWriter bw = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream("output.txt"), "UTF-8"))) {
            bw.write("UTF-8 编码的内容");
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // ============ PrintWriter ============
        // 方便的打印流
        try (PrintWriter pw = new PrintWriter(new FileWriter("output.txt"))) {
            pw.println("Hello");
            pw.printf("Name: %s, Age: %d%n", "张三", 25);
            pw.print("No newline");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

---

## 8. 多线程与并发

### 8.1 线程基础

```java
/**
 * 创建线程的方式
 */
public class ThreadDemo {
    public static void main(String[] args) {
        // ============ 方式1：继承 Thread 类 ============
        MyThread thread1 = new MyThread();
        thread1.start();  // 启动线程
        
        // ============ 方式2：实现 Runnable 接口（推荐） ============
        Thread thread2 = new Thread(new MyRunnable());
        thread2.start();
        
        // 使用 Lambda 表达式
        Thread thread3 = new Thread(() -> {
            System.out.println("Lambda 线程运行中");
        });
        thread3.start();
        
        // ============ 方式3：实现 Callable 接口（有返回值） ============
        FutureTask<Integer> futureTask = new FutureTask<>(new MyCallable());
        Thread thread4 = new Thread(futureTask);
        thread4.start();
        
        try {
            Integer result = futureTask.get();  // 获取返回值（会阻塞）
            System.out.println("Callable 返回值: " + result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // ============ 方式4：线程池（推荐） ============
        ExecutorService executor = Executors.newFixedThreadPool(5);
        executor.submit(() -> System.out.println("线程池任务"));
        executor.shutdown();
    }
}

// 继承 Thread
class MyThread extends Thread {
    @Override
    public void run() {
        System.out.println("MyThread 运行中");
    }
}

// 实现 Runnable
class MyRunnable implements Runnable {
    @Override
    public void run() {
        System.out.println("MyRunnable 运行中");
    }
}

// 实现 Callable
class MyCallable implements Callable<Integer> {
    @Override
    public Integer call() throws Exception {
        return 100;
    }
}
```

### 8.2 线程状态与生命周期

```java
/**
 * 线程状态：
 * NEW -> RUNNABLE -> BLOCKED/WAITING/TIMED_WAITING -> TERMINATED
 */
public class ThreadStateDemo {
    public static void main(String[] args) throws InterruptedException {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });
        
        System.out.println(thread.getState());  // NEW
        
        thread.start();
        System.out.println(thread.getState());  // RUNNABLE
        
        Thread.sleep(100);
        System.out.println(thread.getState());  // TIMED_WAITING
        
        thread.join();  // 等待线程结束
        System.out.println(thread.getState());  // TERMINATED
    }
}

/**
 * 线程常用方法
 */
public class ThreadMethodDemo {
    public static void main(String[] args) throws InterruptedException {
        Thread thread = new Thread(() -> {
            for (int i = 0; i < 5; i++) {
                System.out.println(Thread.currentThread().getName() + ": " + i);
                try {
                    Thread.sleep(500);  // 休眠 500ms
                } catch (InterruptedException e) {
                    System.out.println("线程被中断");
                    return;
                }
            }
        }, "MyThread");
        
        // 设置线程属性
        thread.setName("WorkerThread");
        thread.setPriority(Thread.MAX_PRIORITY);  // 1-10，默认5
        thread.setDaemon(true);  // 设置为守护线程
        
        // 获取线程信息
        System.out.println("线程名: " + thread.getName());
        System.out.println("线程ID: " + thread.getId());
        System.out.println("优先级: " + thread.getPriority());
        System.out.println("是否存活: " + thread.isAlive());
        System.out.println("是否守护线程: " + thread.isDaemon());
        
        thread.start();
        
        // join：等待线程结束
        thread.join();  // 无限等待
        // thread.join(1000);  // 最多等待 1000ms
        
        // interrupt：中断线程
        // thread.interrupt();
        
        // yield：让出 CPU（不常用）
        Thread.yield();
        
        // 获取当前线程
        Thread current = Thread.currentThread();
    }
}
```

### 8.3 线程同步

```java
/**
 * 线程安全问题演示
 */
public class ThreadSafetyDemo {
    private int count = 0;
    
    public static void main(String[] args) throws InterruptedException {
        ThreadSafetyDemo demo = new ThreadSafetyDemo();
        demo.testUnsafe();
    }
    
    public void testUnsafe() throws InterruptedException {
        Thread t1 = new Thread(() -> {
            for (int i = 0; i < 10000; i++) {
                count++;  // 非原子操作，线程不安全
            }
        });
        
        Thread t2 = new Thread(() -> {
            for (int i = 0; i < 10000; i++) {
                count++;
            }
        });
        
        t1.start();
        t2.start();
        t1.join();
        t2.join();
        
        System.out.println("Count: " + count);  // 结果可能小于 20000
    }
}

/**
 * synchronized 同步
 */
public class SynchronizedDemo {
    private int count = 0;
    private final Object lock = new Object();
    
    // 同步方法
    public synchronized void increment() {
        count++;
    }
    
    // 同步代码块
    public void incrementWithBlock() {
        synchronized (lock) {
            count++;
        }
    }
    
    // 静态同步方法（锁的是类对象）
    public static synchronized void staticMethod() {
        // ...
    }
    
    public static void main(String[] args) throws InterruptedException {
        SynchronizedDemo demo = new SynchronizedDemo();
        
        Thread t1 = new Thread(() -> {
            for (int i = 0; i < 10000; i++) {
                demo.increment();
            }
        });
        
        Thread t2 = new Thread(() -> {
            for (int i = 0; i < 10000; i++) {
                demo.increment();
            }
        });
        
        t1.start();
        t2.start();
        t1.join();
        t2.join();
        
        System.out.println("Count: " + demo.count);  // 20000
    }
}

/**
 * Lock 接口
 */
public class LockDemo {
    private int count = 0;
    private final Lock lock = new ReentrantLock();
    
    public void increment() {
        lock.lock();
        try {
            count++;
        } finally {
            lock.unlock();  // 必须在 finally 中释放锁
        }
    }
    
    // 尝试获取锁
    public void tryIncrement() {
        if (lock.tryLock()) {
            try {
                count++;
            } finally {
                lock.unlock();
            }
        } else {
            System.out.println("获取锁失败");
        }
    }
    
    // 可中断的锁
    public void interruptibleIncrement() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            count++;
        } finally {
            lock.unlock();
        }
    }
}
```

### 8.4 线程池

```java
import java.util.concurrent.*;

public class ThreadPoolDemo {
    public static void main(String[] args) {
        // ============ Executors 工厂方法（不推荐生产使用） ============
        
        // 固定大小线程池
        ExecutorService fixedPool = Executors.newFixedThreadPool(5);
        
        // 缓存线程池（线程数不固定）
        ExecutorService cachedPool = Executors.newCachedThreadPool();
        
        // 单线程池
        ExecutorService singlePool = Executors.newSingleThreadExecutor();
        
        // 定时任务线程池
        ScheduledExecutorService scheduledPool = Executors.newScheduledThreadPool(5);
        
        // ============ ThreadPoolExecutor（推荐） ============
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            5,                      // 核心线程数
            10,                     // 最大线程数
            60L,                    // 空闲线程存活时间
            TimeUnit.SECONDS,       // 时间单位
            new LinkedBlockingQueue<>(100),  // 工作队列
            Executors.defaultThreadFactory(),  // 线程工厂
            new ThreadPoolExecutor.AbortPolicy()  // 拒绝策略
        );
        
        // ============ 提交任务 ============
        // execute：无返回值
        executor.execute(() -> {
            System.out.println("执行任务");
        });
        
        // submit：有返回值
        Future<String> future = executor.submit(() -> {
            Thread.sleep(1000);
            return "任务结果";
        });
        
        try {
            String result = future.get();  // 阻塞获取结果
            String resultWithTimeout = future.get(2, TimeUnit.SECONDS);  // 超时获取
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // ============ 批量提交任务 ============
        List<Callable<Integer>> tasks = Arrays.asList(
            () -> 1,
            () -> 2,
            () -> 3
        );
        
        try {
            // invokeAll：等待所有任务完成
            List<Future<Integer>> futures = executor.invokeAll(tasks);
            
            // invokeAny：返回第一个完成的任务结果
            Integer firstResult = executor.invokeAny(tasks);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // ============ 关闭线程池 ============
        executor.shutdown();  // 平滑关闭，等待任务完成
        // executor.shutdownNow();  // 立即关闭，中断正在执行的任务
        
        try {
            // 等待线程池关闭
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
        
        // ============ 定时任务 ============
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
        
        // 延迟执行
        scheduler.schedule(() -> System.out.println("延迟任务"), 5, TimeUnit.SECONDS);
        
        // 固定频率执行
        scheduler.scheduleAtFixedRate(
            () -> System.out.println("固定频率"),
            0,      // 初始延迟
            1,      // 间隔
            TimeUnit.SECONDS
        );
        
        // 固定延迟执行
        scheduler.scheduleWithFixedDelay(
            () -> System.out.println("固定延迟"),
            0,      // 初始延迟
            1,      // 上次结束到下次开始的间隔
            TimeUnit.SECONDS
        );
    }
}

/**
 * 拒绝策略
 */
public class RejectionPolicyDemo {
    // AbortPolicy：抛出 RejectedExecutionException（默认）
    // CallerRunsPolicy：由调用线程执行任务
    // DiscardPolicy：直接丢弃任务
    // DiscardOldestPolicy：丢弃队列中最老的任务
    
    // 自定义拒绝策略
    RejectedExecutionHandler customHandler = (r, executor) -> {
        System.out.println("任务被拒绝: " + r.toString());
        // 可以记录日志、持久化任务等
    };
}
```

### 8.5 并发工具类

```java
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public class ConcurrencyUtilsDemo {
    
    // ============ 原子类 ============
    private AtomicInteger atomicInt = new AtomicInteger(0);
    private AtomicLong atomicLong = new AtomicLong(0);
    private AtomicBoolean atomicBoolean = new AtomicBoolean(false);
    private AtomicReference<String> atomicRef = new AtomicReference<>("initial");
    
    public void atomicDemo() {
        atomicInt.incrementAndGet();  // ++i
        atomicInt.getAndIncrement();  // i++
        atomicInt.addAndGet(10);      // i += 10
        atomicInt.compareAndSet(10, 20);  // CAS 操作
    }
    
    // ============ CountDownLatch（倒计时门闩） ============
    public void countDownLatchDemo() throws InterruptedException {
        int threadCount = 5;
        CountDownLatch latch = new CountDownLatch(threadCount);
        
        for (int i = 0; i < threadCount; i++) {
            new Thread(() -> {
                try {
                    // 执行任务
                    System.out.println(Thread.currentThread().getName() + " 完成");
                } finally {
                    latch.countDown();  // 计数减1
                }
            }).start();
        }
        
        latch.await();  // 等待计数为0
        System.out.println("所有任务完成");
    }
    
    // ============ CyclicBarrier（循环栅栏） ============
    public void cyclicBarrierDemo() {
        int threadCount = 3;
        CyclicBarrier barrier = new CyclicBarrier(threadCount, () -> {
            System.out.println("所有线程到达屏障");
        });
        
        for (int i = 0; i < threadCount; i++) {
            new Thread(() -> {
                try {
                    System.out.println(Thread.currentThread().getName() + " 到达屏障");
                    barrier.await();  // 等待其他线程
                    System.out.println(Thread.currentThread().getName() + " 继续执行");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
    
    // ============ Semaphore（信号量） ============
    public void semaphoreDemo() {
        // 限制同时访问的线程数
        Semaphore semaphore = new Semaphore(3);  // 最多3个线程同时访问
        
        for (int i = 0; i < 10; i++) {
            new Thread(() -> {
                try {
                    semaphore.acquire();  // 获取许可
                    System.out.println(Thread.currentThread().getName() + " 获取许可");
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } finally {
                    semaphore.release();  // 释放许可
                    System.out.println(Thread.currentThread().getName() + " 释放许可");
                }
            }).start();
        }
    }
    
    // ============ 并发集合 ============
    public void concurrentCollectionDemo() {
        // ConcurrentHashMap：线程安全的 HashMap
        ConcurrentHashMap<String, Integer> concurrentMap = new ConcurrentHashMap<>();
        concurrentMap.put("key", 1);
        concurrentMap.putIfAbsent("key", 2);
        concurrentMap.computeIfAbsent("key2", k -> 100);
        
        // CopyOnWriteArrayList：写时复制的 ArrayList
        CopyOnWriteArrayList<String> cowList = new CopyOnWriteArrayList<>();
        cowList.add("item");
        
        // BlockingQueue：阻塞队列
        BlockingQueue<String> blockingQueue = new LinkedBlockingQueue<>(100);
        try {
            blockingQueue.put("item");  // 队列满时阻塞
            String item = blockingQueue.take();  // 队列空时阻塞
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
```

---

## 9. Java 8 新特性

### 9.1 Lambda 表达式

```java
import java.util.*;
import java.util.function.*;

public class LambdaDemo {
    public static void main(String[] args) {
        // ============ Lambda 基本语法 ============
        // (参数) -> { 方法体 }
        
        // 无参数
        Runnable r1 = () -> System.out.println("Hello");
        
        // 单个参数（可省略括号）
        Consumer<String> c1 = s -> System.out.println(s);
        Consumer<String> c2 = (s) -> System.out.println(s);
        
        // 多个参数
        Comparator<Integer> comp = (a, b) -> a - b;
        
        // 多条语句
        Comparator<Integer> comp2 = (a, b) -> {
            System.out.println("比较 " + a + " 和 " + b);
            return a - b;
        };
        
        // 有返回值（单条语句可省略 return）
        Function<Integer, Integer> square = x -> x * x;
        Function<Integer, Integer> square2 = x -> { return x * x; };
        
        // ============ 方法引用 ============
        // 静态方法引用：类名::静态方法名
        Function<String, Integer> parseInt = Integer::parseInt;
        
        // 实例方法引用：对象::实例方法名
        String str = "Hello";
        Supplier<Integer> length = str::length;
        
        // 特定类型的实例方法引用：类名::实例方法名
        Comparator<String> strComp = String::compareTo;
        
        // 构造方法引用：类名::new
        Supplier<ArrayList<String>> listSupplier = ArrayList::new;
        Function<Integer, ArrayList<String>> listWithSize = ArrayList::new;
        
        // ============ 常用函数式接口 ============
        // Predicate<T>：断言，T -> boolean
        Predicate<Integer> isPositive = n -> n > 0;
        System.out.println(isPositive.test(5));  // true
        
        // Function<T, R>：函数，T -> R
        Function<String, Integer> strLength = String::length;
        System.out.println(strLength.apply("Hello"));  // 5
        
        // Consumer<T>：消费者，T -> void
        Consumer<String> printer = System.out::println;
        printer.accept("Hello");
        
        // Supplier<T>：供应者，() -> T
        Supplier<Double> random = Math::random;
        System.out.println(random.get());
        
        // BiFunction<T, U, R>：双参数函数，(T, U) -> R
        BiFunction<Integer, Integer, Integer> add = (a, b) -> a + b;
        System.out.println(add.apply(1, 2));  // 3
        
        // ============ Lambda 在集合中的应用 ============
        List<String> names = Arrays.asList("Alice", "Bob", "Charlie");
        
        // forEach
        names.forEach(System.out::println);
        
        // sort
        names.sort((s1, s2) -> s1.length() - s2.length());
        names.sort(Comparator.comparingInt(String::length));
        
        // removeIf
        List<Integer> numbers = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5));
        numbers.removeIf(n -> n % 2 == 0);  // 移除偶数
    }
}
```

### 9.2 Stream API

```java
import java.util.*;
import java.util.stream.*;

public class StreamDemo {
    public static void main(String[] args) {
        List<String> names = Arrays.asList("Alice", "Bob", "Charlie", "David", "Eve");
        
        // ============ 创建 Stream ============
        // 从集合创建
        Stream<String> stream1 = names.stream();
        Stream<String> parallelStream = names.parallelStream();  // 并行流
        
        // 从数组创建
        Stream<Integer> stream2 = Arrays.stream(new Integer[]{1, 2, 3});
        
        // 使用 Stream.of
        Stream<String> stream3 = Stream.of("A", "B", "C");
        
        // 无限流
        Stream<Integer> infinite = Stream.iterate(0, n -> n + 1);
        Stream<Double> randoms = Stream.generate(Math::random);
        
        // ============ 中间操作（返回 Stream） ============
        names.stream()
            // filter：过滤
            .filter(s -> s.length() > 3)
            // map：转换
            .map(String::toUpperCase)
            // flatMap：扁平化
            // .flatMap(s -> Arrays.stream(s.split("")))
            // sorted：排序
            .sorted()
            .sorted(Comparator.reverseOrder())
            // distinct：去重
            .distinct()
            // limit：限制数量
            .limit(10)
            // skip：跳过
            .skip(2)
            // peek：查看（调试用）
            .peek(System.out::println)
            .collect(Collectors.toList());
        
        // ============ 终端操作（返回结果） ============
        // forEach：遍历
        names.stream().forEach(System.out::println);
        
        // collect：收集
        List<String> list = names.stream().collect(Collectors.toList());
        Set<String> set = names.stream().collect(Collectors.toSet());
        String joined = names.stream().collect(Collectors.joining(", "));
        
        // toArray：转数组
        String[] array = names.stream().toArray(String[]::new);
        
        // count：计数
        long count = names.stream().filter(s -> s.length() > 3).count();
        
        // findFirst / findAny：查找
        Optional<String> first = names.stream().findFirst();
        Optional<String> any = names.parallelStream().findAny();
        
        // anyMatch / allMatch / noneMatch：匹配
        boolean anyMatch = names.stream().anyMatch(s -> s.startsWith("A"));
        boolean allMatch = names.stream().allMatch(s -> s.length() > 2);
        boolean noneMatch = names.stream().noneMatch(s -> s.isEmpty());
        
        // min / max：最值
        Optional<String> min = names.stream().min(Comparator.naturalOrder());
        Optional<String> max = names.stream().max(Comparator.comparingInt(String::length));
        
        // reduce：归约
        Optional<String> reduced = names.stream().reduce((s1, s2) -> s1 + ", " + s2);
        Integer sum = Arrays.asList(1, 2, 3, 4, 5).stream().reduce(0, Integer::sum);
        
        // ============ 数值流 ============
        IntStream intStream = IntStream.range(1, 10);  // 1-9
        IntStream intStreamClosed = IntStream.rangeClosed(1, 10);  // 1-10
        
        int sumInt = IntStream.of(1, 2, 3, 4, 5).sum();
        OptionalDouble avg = IntStream.of(1, 2, 3, 4, 5).average();
        IntSummaryStatistics stats = IntStream.of(1, 2, 3, 4, 5).summaryStatistics();
        
        // ============ 分组和分区 ============
        List<Person> people = Arrays.asList(
            new Person("Alice", 25),
            new Person("Bob", 30),
            new Person("Charlie", 25)
        );
        
        // 分组
        Map<Integer, List<Person>> byAge = people.stream()
            .collect(Collectors.groupingBy(Person::getAge));
        
        // 多级分组
        Map<Integer, Map<String, List<Person>>> multiGroup = people.stream()
            .collect(Collectors.groupingBy(Person::getAge,
                     Collectors.groupingBy(Person::getName)));
        
        // 分区（按条件分成两组）
        Map<Boolean, List<Person>> partition = people.stream()
            .collect(Collectors.partitioningBy(p -> p.getAge() > 25));
        
        // 统计
        Map<Integer, Long> countByAge = people.stream()
            .collect(Collectors.groupingBy(Person::getAge, Collectors.counting()));
    }
}

class Person {
    private String name;
    private int age;
    
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() { return name; }
    public int getAge() { return age; }
}
```

### 9.3 Optional 类

```java
import java.util.Optional;

public class OptionalDemo {
    public static void main(String[] args) {
        // ============ 创建 Optional ============
        // of：值不能为 null
        Optional<String> opt1 = Optional.of("Hello");
        
        // ofNullable：值可以为 null
        Optional<String> opt2 = Optional.ofNullable(null);
        
        // empty：空 Optional
        Optional<String> opt3 = Optional.empty();
        
        // ============ 判断值是否存在 ============
        System.out.println(opt1.isPresent());  // true
        System.out.println(opt2.isPresent());  // false
        
        // Java 11+
        // System.out.println(opt2.isEmpty());  // true
        
        // ============ 获取值 ============
        // get：值不存在时抛出 NoSuchElementException
        String value1 = opt1.get();
        
        // orElse：值不存在时返回默认值
        String value2 = opt2.orElse("Default");
        
        // orElseGet：值不存在时通过 Supplier 获取默认值
        String value3 = opt2.orElseGet(() -> "Generated Default");
        
        // orElseThrow：值不存在时抛出异常
        // String value4 = opt2.orElseThrow(() -> new RuntimeException("值不存在"));
        
        // ============ 条件操作 ============
        // ifPresent：值存在时执行操作
        opt1.ifPresent(System.out::println);
        
        // Java 9+
        // opt1.ifPresentOrElse(
        //     System.out::println,
        //     () -> System.out.println("值不存在")
        // );
        
        // ============ 转换和过滤 ============
        // map：转换值
        Optional<Integer> length = opt1.map(String::length);
        
        // flatMap：转换为 Optional
        Optional<Integer> flatLength = opt1.flatMap(s -> Optional.of(s.length()));
        
        // filter：过滤
        Optional<String> filtered = opt1.filter(s -> s.length() > 3);
        
        // ============ 链式调用 ============
        String result = Optional.ofNullable(getUser())
            .map(User::getAddress)
            .map(Address::getCity)
            .orElse("Unknown");
        
        // ============ 实际应用 ============
        // 避免 NullPointerException
        User user = getUser();
        
        // 传统方式
        String city1 = null;
        if (user != null) {
            Address address = user.getAddress();
            if (address != null) {
                city1 = address.getCity();
            }
        }
        if (city1 == null) {
            city1 = "Unknown";
        }
        
        // 使用 Optional
        String city2 = Optional.ofNullable(user)
            .map(User::getAddress)
            .map(Address::getCity)
            .orElse("Unknown");
    }
    
    static User getUser() {
        return null;
    }
}

class User {
    private Address address;
    public Address getAddress() { return address; }
}

class Address {
    private String city;
    public String getCity() { return city; }
}
```

---

## 10. 反射与注解

### 10.1 反射

```java
import java.lang.reflect.*;

public class ReflectionDemo {
    public static void main(String[] args) throws Exception {
        // ============ 获取 Class 对象 ============
        // 方式1：类名.class
        Class<String> clazz1 = String.class;
        
        // 方式2：对象.getClass()
        String str = "Hello";
        Class<?> clazz2 = str.getClass();
        
        // 方式3：Class.forName()
        Class<?> clazz3 = Class.forName("java.lang.String");
        
        // ============ 获取类信息 ============
        Class<Person> personClass = Person.class;
        
        System.out.println("类名: " + personClass.getName());
        System.out.println("简单类名: " + personClass.getSimpleName());
        System.out.println("包名: " + personClass.getPackage().getName());
        System.out.println("父类: " + personClass.getSuperclass().getName());
        System.out.println("接口: " + Arrays.toString(personClass.getInterfaces()));
        System.out.println("修饰符: " + Modifier.toString(personClass.getModifiers()));
        
        // ============ 获取构造方法 ============
        // 获取所有 public 构造方法
        Constructor<?>[] constructors = personClass.getConstructors();
        
        // 获取所有构造方法（包括私有）
        Constructor<?>[] allConstructors = personClass.getDeclaredConstructors();
        
        // 获取指定构造方法
        Constructor<Person> constructor = personClass.getConstructor(String.class, int.class);
        
        // 创建实例
        Person person = constructor.newInstance("张三", 25);
        
        // 访问私有构造方法
        Constructor<Person> privateConstructor = personClass.getDeclaredConstructor();
        privateConstructor.setAccessible(true);  // 取消访问检查
        Person person2 = privateConstructor.newInstance();
        
        // ============ 获取字段 ============
        // 获取所有 public 字段（包括继承的）
        Field[] fields = personClass.getFields();
        
        // 获取所有字段（不包括继承的）
        Field[] allFields = personClass.getDeclaredFields();
        
        // 获取指定字段
        Field nameField = personClass.getDeclaredField("name");
        nameField.setAccessible(true);
        
        // 读取字段值
        String name = (String) nameField.get(person);
        
        // 设置字段值
        nameField.set(person, "李四");
        
        // ============ 获取方法 ============
        // 获取所有 public 方法（包括继承的）
        Method[] methods = personClass.getMethods();
        
        // 获取所有方法（不包括继承的）
        Method[] allMethods = personClass.getDeclaredMethods();
        
        // 获取指定方法
        Method setNameMethod = personClass.getMethod("setName", String.class);
        Method getNameMethod = personClass.getMethod("getName");
        
        // 调用方法
        setNameMethod.invoke(person, "王五");
        String result = (String) getNameMethod.invoke(person);
        
        // 调用私有方法
        Method privateMethod = personClass.getDeclaredMethod("privateMethod");
        privateMethod.setAccessible(true);
        privateMethod.invoke(person);
        
        // ============ 获取注解 ============
        // 获取类上的注解
        Annotation[] annotations = personClass.getAnnotations();
        
        // 获取指定注解
        if (personClass.isAnnotationPresent(MyAnnotation.class)) {
            MyAnnotation annotation = personClass.getAnnotation(MyAnnotation.class);
            System.out.println(annotation.value());
        }
    }
}
```

### 10.2 注解

```java
import java.lang.annotation.*;
import java.lang.reflect.*;

/**
 * 自定义注解
 */
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})  // 注解可以用在哪里
@Retention(RetentionPolicy.RUNTIME)  // 注解保留到什么时候
@Documented  // 是否包含在 JavaDoc 中
@Inherited   // 是否可以被继承
public @interface MyAnnotation {
    // 注解属性
    String value() default "";
    int count() default 0;
    String[] tags() default {};
    Class<?> clazz() default Object.class;
}

/**
 * 元注解说明
 * 
 * @Target：指定注解可以用在哪些地方
 *   - TYPE：类、接口、枚举
 *   - FIELD：字段
 *   - METHOD：方法
 *   - PARAMETER：方法参数
 *   - CONSTRUCTOR：构造方法
 *   - LOCAL_VARIABLE：局部变量
 *   - ANNOTATION_TYPE：注解
 *   - PACKAGE：包
 * 
 * @Retention：指定注解保留到什么时候
 *   - SOURCE：只在源码中保留，编译时丢弃
 *   - CLASS：保留到字节码，运行时丢弃（默认）
 *   - RUNTIME：保留到运行时，可以通过反射获取
 */

/**
 * 使用注解
 */
@MyAnnotation(value = "类注解", count = 1, tags = {"tag1", "tag2"})
public class AnnotationDemo {
    
    @MyAnnotation("字段注解")
    private String name;
    
    @MyAnnotation(value = "方法注解", count = 2)
    public void doSomething() {
        // ...
    }
    
    public static void main(String[] args) throws Exception {
        Class<AnnotationDemo> clazz = AnnotationDemo.class;
        
        // 获取类上的注解
        if (clazz.isAnnotationPresent(MyAnnotation.class)) {
            MyAnnotation annotation = clazz.getAnnotation(MyAnnotation.class);
            System.out.println("value: " + annotation.value());
            System.out.println("count: " + annotation.count());
            System.out.println("tags: " + Arrays.toString(annotation.tags()));
        }
        
        // 获取字段上的注解
        Field field = clazz.getDeclaredField("name");
        MyAnnotation fieldAnnotation = field.getAnnotation(MyAnnotation.class);
        System.out.println("字段注解: " + fieldAnnotation.value());
        
        // 获取方法上的注解
        Method method = clazz.getMethod("doSomething");
        MyAnnotation methodAnnotation = method.getAnnotation(MyAnnotation.class);
        System.out.println("方法注解: " + methodAnnotation.value());
    }
}

/**
 * 常用内置注解
 */
public class BuiltInAnnotations {
    
    @Override  // 标识方法重写
    public String toString() {
        return "BuiltInAnnotations";
    }
    
    @Deprecated  // 标识已过时
    public void oldMethod() {
        // ...
    }
    
    @SuppressWarnings("unchecked")  // 抑制警告
    public void suppressWarning() {
        List list = new ArrayList();  // 原始类型警告被抑制
    }
    
    @SafeVarargs  // 抑制可变参数警告
    public final <T> void safeVarargs(T... args) {
        // ...
    }
    
    @FunctionalInterface  // 标识函数式接口
    interface MyFunction {
        void apply();
    }
}
```

---

## 11. JVM基础

### 11.1 JVM 内存结构

```
┌─────────────────────────────────────────────────────────────┐
│                         JVM 内存                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    方法区 (Method Area)               │   │
│  │  - 类信息、常量、静态变量、JIT编译后的代码              │   │
│  │  - Java 8 后改为元空间 (Metaspace)，使用本地内存        │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                      堆 (Heap)                        │   │
│  │  - 对象实例和数组                                      │   │
│  │  - 垃圾回收的主要区域                                  │   │
│  │  ┌─────────────────┬─────────────────────────────┐   │   │
│  │  │   新生代 (Young) │        老年代 (Old)          │   │   │
│  │  │  Eden | S0 | S1  │                             │   │   │
│  │  └─────────────────┴─────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌──────────────────────┐  ┌──────────────────────┐       │
│  │   虚拟机栈 (Stack)    │  │   本地方法栈          │       │
│  │  - 线程私有           │  │  - Native 方法        │       │
│  │  - 栈帧：局部变量表、  │  │                      │       │
│  │    操作数栈、动态链接  │  │                      │       │
│  └──────────────────────┘  └──────────────────────┘       │
│  ┌──────────────────────┐                                  │
│  │   程序计数器 (PC)     │                                  │
│  │  - 当前线程执行位置    │                                  │
│  └──────────────────────┘                                  │
└─────────────────────────────────────────────────────────────┘
```

### 11.2 垃圾回收

```java
/**
 * 垃圾回收基础
 */
public class GCDemo {
    public static void main(String[] args) {
        // 建议 JVM 进行垃圾回收（不保证立即执行）
        System.gc();
        
        // 获取运行时信息
        Runtime runtime = Runtime.getRuntime();
        System.out.println("最大内存: " + runtime.maxMemory() / 1024 / 1024 + "MB");
        System.out.println("总内存: " + runtime.totalMemory() / 1024 / 1024 + "MB");
        System.out.println("空闲内存: " + runtime.freeMemory() / 1024 / 1024 + "MB");
        System.out.println("已用内存: " + (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024 + "MB");
    }
    
    // finalize 方法（不推荐使用，Java 9 已废弃）
    @Override
    protected void finalize() throws Throwable {
        System.out.println("对象被回收");
        super.finalize();
    }
}

/**
 * 垃圾回收算法：
 * 1. 标记-清除 (Mark-Sweep)
 * 2. 复制算法 (Copying)
 * 3. 标记-整理 (Mark-Compact)
 * 4. 分代收集 (Generational Collection)
 * 
 * 垃圾收集器：
 * - Serial：单线程，适合小内存
 * - Parallel：多线程，吞吐量优先
 * - CMS：并发标记清除，低延迟
 * - G1：分区收集，平衡吞吐量和延迟
 * - ZGC：超低延迟（Java 11+）
 */
```

### 11.3 常用 JVM 参数

```bash
# 堆内存设置
-Xms512m          # 初始堆大小
-Xmx1024m         # 最大堆大小
-Xmn256m          # 新生代大小

# 栈大小
-Xss256k          # 每个线程的栈大小

# 元空间（Java 8+）
-XX:MetaspaceSize=128m
-XX:MaxMetaspaceSize=256m

# 垃圾收集器
-XX:+UseSerialGC          # Serial
-XX:+UseParallelGC        # Parallel
-XX:+UseConcMarkSweepGC   # CMS
-XX:+UseG1GC              # G1

# GC 日志
-XX:+PrintGCDetails
-XX:+PrintGCDateStamps
-Xloggc:gc.log

# 堆转储
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/path/to/dump
```

---

## 12. 常见错误与解决方案

### 12.1 NullPointerException

```java
/**
 * 空指针异常 - 最常见的运行时异常
 */
public class NullPointerDemo {
    
    // 错误示例
    public void badExample() {
        String str = null;
        int length = str.length();  // NullPointerException!
        
        List<String> list = null;
        list.add("item");  // NullPointerException!
        
        User user = getUser();
        String name = user.getName();  // 如果 user 为 null，抛出异常
    }
    
    // 正确示例
    public void goodExample() {
        // 方式1：null 检查
        String str = null;
        if (str != null) {
            int length = str.length();
        }
        
        // 方式2：使用 Optional
        Optional<String> optStr = Optional.ofNullable(str);
        int length = optStr.map(String::length).orElse(0);
        
        // 方式3：使用 Objects.requireNonNull
        String name = Objects.requireNonNull(str, "str 不能为 null");
        
        // 方式4：使用 StringUtils（Apache Commons）
        // if (StringUtils.isNotEmpty(str)) { ... }
        
        // 方式5：使用 @NonNull 注解（编译时检查）
    }
    
    User getUser() { return null; }
}
```

### 12.2 ArrayIndexOutOfBoundsException

```java
/**
 * 数组越界异常
 */
public class ArrayIndexDemo {
    
    // 错误示例
    public void badExample() {
        int[] arr = {1, 2, 3};
        int value = arr[3];  // ArrayIndexOutOfBoundsException! 索引范围是 0-2
        
        for (int i = 0; i <= arr.length; i++) {  // 错误：<= 应该是 <
            System.out.println(arr[i]);
        }
    }
    
    // 正确示例
    public void goodExample() {
        int[] arr = {1, 2, 3};
        
        // 方式1：检查索引
        int index = 3;
        if (index >= 0 && index < arr.length) {
            int value = arr[index];
        }
        
        // 方式2：使用增强 for 循环
        for (int value : arr) {
            System.out.println(value);
        }
        
        // 方式3：正确的循环条件
        for (int i = 0; i < arr.length; i++) {
            System.out.println(arr[i]);
        }
    }
}
```

### 12.3 ClassCastException

```java
/**
 * 类型转换异常
 */
public class ClassCastDemo {
    
    // 错误示例
    public void badExample() {
        Object obj = "Hello";
        Integer num = (Integer) obj;  // ClassCastException!
        
        Animal animal = new Cat();
        Dog dog = (Dog) animal;  // ClassCastException!
    }
    
    // 正确示例
    public void goodExample() {
        Object obj = "Hello";
        
        // 方式1：使用 instanceof 检查
        if (obj instanceof Integer) {
            Integer num = (Integer) obj;
        }
        
        // 方式2：使用泛型避免转换
        List<String> list = new ArrayList<>();
        String str = list.get(0);  // 不需要转换
        
        // 方式3：Java 16+ 模式匹配
        // if (obj instanceof String s) {
        //     System.out.println(s.length());
        // }
    }
}
```

### 12.4 ConcurrentModificationException

```java
/**
 * 并发修改异常
 */
public class ConcurrentModificationDemo {
    
    // 错误示例
    public void badExample() {
        List<String> list = new ArrayList<>(Arrays.asList("A", "B", "C"));
        
        // 在遍历时修改集合
        for (String item : list) {
            if ("B".equals(item)) {
                list.remove(item);  // ConcurrentModificationException!
            }
        }
    }
    
    // 正确示例
    public void goodExample() {
        List<String> list = new ArrayList<>(Arrays.asList("A", "B", "C"));
        
        // 方式1：使用迭代器的 remove 方法
        Iterator<String> iterator = list.iterator();
        while (iterator.hasNext()) {
            String item = iterator.next();
            if ("B".equals(item)) {
                iterator.remove();
            }
        }
        
        // 方式2：使用 removeIf（Java 8+）
        list.removeIf(item -> "B".equals(item));
        
        // 方式3：使用 CopyOnWriteArrayList
        List<String> cowList = new CopyOnWriteArrayList<>(Arrays.asList("A", "B", "C"));
        for (String item : cowList) {
            if ("B".equals(item)) {
                cowList.remove(item);  // 安全
            }
        }
        
        // 方式4：收集要删除的元素，遍历后删除
        List<String> toRemove = new ArrayList<>();
        for (String item : list) {
            if ("B".equals(item)) {
                toRemove.add(item);
            }
        }
        list.removeAll(toRemove);
    }
}
```

### 12.5 OutOfMemoryError

```java
/**
 * 内存溢出错误
 */
public class OutOfMemoryDemo {
    
    // 堆内存溢出
    public void heapOOM() {
        List<byte[]> list = new ArrayList<>();
        while (true) {
            list.add(new byte[1024 * 1024]);  // 每次分配 1MB
        }
        // java.lang.OutOfMemoryError: Java heap space
    }
    
    // 栈溢出
    public void stackOverflow() {
        stackOverflow();  // 无限递归
        // java.lang.StackOverflowError
    }
    
    // 解决方案
    // 1. 增加堆内存：-Xmx2g
    // 2. 检查内存泄漏
    // 3. 使用内存分析工具（MAT、VisualVM）
    // 4. 优化代码，避免创建大量对象
    // 5. 使用对象池
}
```

### 12.6 NumberFormatException

```java
/**
 * 数字格式异常
 */
public class NumberFormatDemo {
    
    // 错误示例
    public void badExample() {
        int num1 = Integer.parseInt("abc");    // NumberFormatException!
        int num2 = Integer.parseInt("12.34");  // NumberFormatException!
        int num3 = Integer.parseInt("");       // NumberFormatException!
        int num4 = Integer.parseInt(null);     // NumberFormatException!
    }
    
    // 正确示例
    public void goodExample() {
        String str = "123";
        
        // 方式1：try-catch
        try {
            int num = Integer.parseInt(str);
        } catch (NumberFormatException e) {
            System.out.println("无效的数字格式");
        }
        
        // 方式2：正则验证
        if (str != null && str.matches("-?\\d+")) {
            int num = Integer.parseInt(str);
        }
        
        // 方式3：使用 Apache Commons
        // if (NumberUtils.isCreatable(str)) {
        //     int num = NumberUtils.toInt(str);
        // }
    }
}
```

### 12.7 常见编码问题

```java
/**
 * 编码问题
 */
public class EncodingDemo {
    
    public void encodingIssues() throws Exception {
        // 问题1：乱码
        String str = "中文";
        byte[] bytes = str.getBytes("UTF-8");
        String decoded = new String(bytes, "GBK");  // 乱码！
        
        // 正确：使用相同编码
        String correct = new String(bytes, "UTF-8");
        
        // 问题2：文件读取乱码
        // 使用 InputStreamReader 指定编码
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(new FileInputStream("file.txt"), "UTF-8"))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        }
        
        // 问题3：HTTP 请求乱码
        // 设置请求和响应编码
        // request.setCharacterEncoding("UTF-8");
        // response.setContentType("text/html;charset=UTF-8");
    }
}
```

### 12.8 equals 和 hashCode

```java
/**
 * equals 和 hashCode 问题
 */
public class EqualsHashCodeDemo {
    
    // 错误示例：只重写 equals，不重写 hashCode
    static class BadPerson {
        private String name;
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            BadPerson person = (BadPerson) obj;
            return Objects.equals(name, person.name);
        }
        // 没有重写 hashCode！
    }
    
    // 正确示例：同时重写 equals 和 hashCode
    static class GoodPerson {
        private String name;
        private int age;
        
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            GoodPerson person = (GoodPerson) obj;
            return age == person.age && Objects.equals(name, person.name);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(name, age);
        }
    }
    
    public static void main(String[] args) {
        // 问题演示
        Set<BadPerson> badSet = new HashSet<>();
        BadPerson p1 = new BadPerson();
        p1.name = "张三";
        BadPerson p2 = new BadPerson();
        p2.name = "张三";
        
        badSet.add(p1);
        badSet.add(p2);
        System.out.println(badSet.size());  // 2，而不是预期的 1
        
        // 正确示例
        Set<GoodPerson> goodSet = new HashSet<>();
        GoodPerson g1 = new GoodPerson();
        g1.name = "张三";
        g1.age = 25;
        GoodPerson g2 = new GoodPerson();
        g2.name = "张三";
        g2.age = 25;
        
        goodSet.add(g1);
        goodSet.add(g2);
        System.out.println(goodSet.size());  // 1
    }
}
```

---

## 总结

本笔记涵盖了 Java 从基础到进阶的核心知识点：

1. **基础概念**：JDK/JRE/JVM 关系、程序执行流程
2. **基础语法**：数据类型、运算符、流程控制、数组
3. **面向对象**：类与对象、封装、继承、多态、抽象类、接口
4. **常用类库**：String、包装类、Math、日期时间
5. **集合框架**：List、Set、Map、泛型
6. **异常处理**：异常体系、try-catch、自定义异常
7. **IO 流**：字节流、字符流、文件操作
8. **多线程**：线程创建、同步、线程池、并发工具
9. **Java 8 新特性**：Lambda、Stream、Optional
10. **反射与注解**：Class 对象、反射操作、自定义注解
11. **JVM 基础**：内存结构、垃圾回收、JVM 参数
12. **常见错误**：各种异常的原因和解决方案

掌握这些知识点，你就具备了扎实的 Java 基础，可以进一步学习 Spring、Spring Boot 等框架。

---

## 参考资料

- [Oracle Java 官方文档](https://docs.oracle.com/javase/8/docs/)
- [Java SE 8 API 文档](https://docs.oracle.com/javase/8/docs/api/)
- [Effective Java（第三版）](https://www.oreilly.com/library/view/effective-java-3rd/9780134686097/)
