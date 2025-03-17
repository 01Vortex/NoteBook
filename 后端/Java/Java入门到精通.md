# Java基础语法

## 注释

**1、多行注释**

Ctrl + Shift + /

**2、文档注释**


/**  +  Enter



## Java 对象和类

Java 作为一种面向对象的编程语言，支持以下基本概念：

1、**类（Class）**：

- 定义对象的蓝图，包括属性和方法。
- 示例：`public class Car { ... }`

**2、对象（Object）**：

- 类的实例，具有状态和行为。
- 示例：`Car myCar = new Car();`

**3、继承（Inheritance）**：

- 一个类可以继承另一个类的属性和方法。
- 示例：`public class Dog extends Animal { ... }`

**4、封装（Encapsulation）**：

- 将对象的状态（字段）私有化，通过公共方法访问。

- 示例：

  ```
  private String name; 
  public String getName() { return name; }
  ```

**5、多态（Polymorphism）**：

- 对象可以表现为多种形态，主要通过方法重载和方法重写实现。
- 示例：
  - 方法重载：`public int add(int a, int b) { ... }` 和 `public double add(double a, double b) { ... }`
  - 方法重写：`@Override public void makeSound() { System.out.println("Meow"); }`

**6、抽象（Abstraction）**：

- 使用抽象类和接口来定义必须实现的方法，不提供具体实现。
- 示例：
  - 抽象类：`public abstract class Shape { abstract void draw(); }`
  - 接口：`public interface Animal { void eat(); }`

**7、接口（Interface）**：

- 定义类必须实现的方法，支持多重继承。
- 示例：`public interface Drivable { void drive(); }`

**8、方法（Method）**：

- 定义类的行为，包含在类中的函数。
- 示例：`public void displayInfo() { System.out.println("Info"); }`





## Java基本数据类型

byte    short   int  long   float double  char   boolean



## Java常见引用类型

1.**类（Class）**: 这是最常见的引用类型，用于创建对象。例如，`String`, `ArrayList`, `Scanner` 等都是类类型。

2.**接口（Interface）**: 接口定义了一组方法规范，任何实现了该接口的类都必须实现这些方法。例如，`Comparable`, `Serializable` 等。

 3.**数组（Array）**: 数组是一种用来存储固定大小的同类型元素的数据结构。例如，`int[]`, `String[]` 等。

4.**枚举（Enum）**: 枚举是一种特殊的类，用于表示一组固定的常量，例如季节、方向等。



==引用类型与基本数据类型（如 int, double, char等）相对，基本数据类型直接存储值，而引用类型存储的是指向对象的引用（内存地址）。==





## 变量命名

**1、驼峰命名**

```
public static int myStaticVariable;
```



**2、常量命名**

```
public static final int MAX_SIZE = 100;
```



**3、类命名**

```
public class MyClass {  
    // 类的成员和方法  大写开头
}
```





## Java修饰符

### 访问控制修饰符(4个)

- public  所有包都能访问

- protected  本包+其他包的子类

- default    只有本包

- private  本类



### 非访问修饰符(6个)

#### 1.**static**：表示类的，而不是实例的。它用于创建类方法、类变量和静态代码块。

```java
public class MyClass {
    // 静态变量
    public static int staticVar = 10;

    // 静态方法
    public static void staticMethod() {
        System.out.println("This is a static method.");
    }

    // 静态初始化块
    static {
        System.out.println("Static block initialized.");
    }
}
```

对于 `static` 成员，你可以==直接通过类名来调用，而不需要创建类的实例==。

```java
   public class Main {
       public static void main(String[] args) {
           // 调用静态变量
           System.out.println(MyClass.staticVar);
   
           // 调用静态方法
           MyClass.staticMethod();
   
           // 调用静态初始化块中初始化的静态变量
           System.out.println(MyClass.staticVarAfterInit);
       }
   }
   
   class MyClass {
       public static int staticVar = 10;
       public static int staticVarAfterInit;
   
       static {
           staticVarAfterInit = 20;
       }
   
       public static void staticMethod() {
           System.out.println("This is a static method.");
       }
   }
```

#### 2.**final**：表示最终的，不可变的。它可以用于类、方法和变量。

```java
public class FinalExample {
    // final变量
    public final int finalVar = 20;

    // final方法
    public final void finalMethod() {
        System.out.println("This is a final method.");
    }

    // final类
    public final class FinalInnerClass {
        // ...
    }
}
```

`final` 修饰符通常用于声明常量或确保方法或类不能被继承。调用 `final` 方法和变量与调用普通方法和变量没有区别。

```java
   public class FinalExample {
       public final int finalVar = 20;
   
       public final void finalMethod() {
           System.out.println("This is a final method.");
       }
   }
   
   public class Main {
       public static void main(String[] args) {
           FinalExample example = new FinalExample();
           System.out.println(example.finalVar); // 调用final变量
           example.finalMethod(); // 调用final方法
       }
   }
```



#### 3.**abstract**：表示抽象的，不能实例化的。它用于抽象类和抽象方法。
- abstract方法(没有方法体)需通过子类实现
- abstract类(不能实例化)必须通过==它的子类的实例来调用==。

```java
//抽象类A
   public abstract class A {
//抽象方法   
       public abstract void abstractMethod();
   }
   
   public class B extends A {
       @Override
       public void abstractMethod() {
           System.out.println("Implemented abstract method.");
       }
   }
   
   public class Main {
       public static void main(String[] args) {
           B example = new B();
           example.abstractMethod(); // 调用抽象方法
       }
   }
```


#### 4.**synchronized**：表示同步的，用于控制对方法或代码块的并发访问。

```java
public class SynchronizedExample {
    // 同步方法
    public synchronized void synchronizedMethod() {
        // 同步代码块
        synchronized (this) {
            System.out.println("This is a synchronized method.");
        }
    }
}
```

`synchronized` 方法或代码块需要在多线程环境中特别注意，它确保了同一时间只有一个线程可以执行该方法或代码块。

```java
   public class SynchronizedExample {
       public synchronized void synchronizedMethod() {
           System.out.println("This is a synchronized method.");
       }
   }

   public class Main {
       public static void main(String[] args) {
           SynchronizedExample example = new SynchronizedExample();
           // 同步调用
           synchronized (example) {
               example.synchronizedMethod();
           }
       }
   }
   ```


#### 5.**volatile**：表示易变的，确保变量在多线程中的可见性。

```java
public class VolatileExample {
    // volatile变量
    public volatile boolean flag = false;
}
   ```

`volatile` 关键字确保了变量的可见性，但调用方式与普通变量相同。

```java
   public class VolatileExample {
       public volatile boolean flag = false;
   }
   
   public class Main {
       public static void main(String[] args) {
           VolatileExample example = new VolatileExample();
           if (example.flag) {
               // 执行相关操作
           }
       }
   }
```

   

#### 6.**transient**：表示瞬时的，用于阻止序列化过程中特定变量的序列化。

```java
import java.io.Serializable;

public class TransientExample implements Serializable {
    // transient变量，不会被序列化
    transient int transientVar = 100;
}
```

`transient` 关键字用于阻止对象的序列化，调用时通常是在对象的序列化和反序列化过程中。

```java
import java.io.*;

public class TransientExample implements Serializable {
    transient int transientVar = 100;
}

public class Main {
    public static void main(String[] args) {
        TransientExample example = new TransientExample();
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("example.ser"))) {
            out.writeObject(example);
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("example.ser"))) {
            TransientExample loadedExample = (TransientExample) in.readObject();
            // 注意：transientVar不会被反序列化，其值为默认值
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```





## Java 运算符

- #### 算术运算符

​    `+  -  *  /  %  ++  --`

- #### 关系运算符

  `==  !=  >  <  >=  <=`   返回0或1

- #### 位运算符

  

- #### 逻辑运算符

  | &&    | 称为逻辑与运算符。当且仅当两个操作数都为真，条件才为真。     | （A && B）为假。    |
  | ----- | ------------------------------------------------------------ | ------------------- |
  | \| \| | 称为逻辑或操作符。如果任何两个操作数任何一个为真，条件为真。 | （A \| \| B）为真。 |
  | ！    | 称为逻辑非运算符。用来反转操作数的逻辑状态。如果条件为true，则逻辑非运算符将得到false。 | ！（A && B）        |

- #### 短路逻辑运算符

  1. - **与运算符 `&&`**：总是评估两个操作数，不短路。    ==2true才true   其余false==

     - **逻辑与短路运算符 `&&`**：如果第一个操作数为 `false`，则不评估第二个操作数，短路。 ==结果false==

     - **逻辑或短路运算符 `||`**：如果第一个操作数为 `true`，则不评估第二个操作数，短路。    ==结果true==

       ==短路可以避免不必要的操作数评估，提高效率。==

- #### 赋值运算符（求总用）

  | =    | 简单的赋值运算符，将右操作数的值赋给左侧操作数           | C = A + B将把A + B得到的值赋给C          |
  | ---- | -------------------------------------------------------- | ---------------------------------------- |
  | +=   | 加和赋值操作符，它把左操作数和右操作数相加赋值给左操作数 | C + = A等价于C = C + A                   |
  | -=   | 减和赋值操作符，它把左操作数和右操作数相减赋值给左操作数 | C - = A等价于C = C - A                   |
  | *=   | 乘和赋值操作符，它把左操作数和右操作数相乘赋值给左操作数 | C * = A等价于C = C * A                   |
  | /=   | 除和赋值操作符，它把左操作数和右操作数相除赋值给左操作数 | C / = A，C 与 A 同类型时等价于 C = C / A |

- #### 其他运算符

#####       -条件运算符(三元运算符)（?:）

  `int max = (a > b) ? a : b; // 如果a大于b True，则三元运算符结果为a，如果a大于b False则三元运算符结果为为b`

  ==true 1  false 2==

#####       -instanceof 运算符（instanceof` 运算符在 Java 中用于检查一个对象是否是一个特定类的实例，或者是否实现了某个接口。如果对象是给定类或接口的实例，则 `instanceof` 运算符返回 `true`；否则返回 `false）

 `Object obj = new String("Hello, World!");`

`obj 是一个 String 类型的对象。 obj 是一个 Object 类型的对象。 obj 实现了 Cloneable 接口。`



==obj 是一个 String 类型的对象，所以 obj instanceof String返回 true。由于所有 Java 对象都继承自 Object 类，obj instanceof Object也返回 true。此外，String 类实现了 Cloneable 接口，因此 obj instanceof Cloneable 同样返回 true。==





## Java运算符优先级



以下是从最高优先级到最低优先级的 Java 运算符列表，以及它们的结合性：

 1.**后缀运算符**：
`expr++`（后缀递增）和 `expr--`（后缀递减）

 - 结合性：从左到右

2.**一元运算符**：`++expr`（前缀递增）、`--expr`（前缀递减）、`+`（正号）、`-`（负号）、`~`（按位取反）、`!`（逻辑非）、`(类型)`（类型转换）

 - 结合性：从右到左


3.**乘性运算符**：`*`（乘）、`/`（除）、`%`（取模）

 - 结合性：从左到右



4.**加性运算符**：`+`（加）、`-`（减）

 - 结合性：从左到右

 5.**位移运算符**：`<<`（左移）、`>>`（右移）、`>>>`（无符号右移）

- 结合性：从左到右

6.**关系运算符**：`<`（小于）、`<=`（小于等于）、`>`（大于）、`>=`（大于等于）、`instanceof`（类型检查）

- 结合性：从左到右

7.**相等性运算符**：`==`（等于）、`!=`（不等于）

 - 结合性：从左到右

 8.**按位与运算符**：`&`

 - 结合性：从左到右

9.**按位异或运算符**：`^`

- 结合性：从左到右

10.**按位或运算符**：`|`

 - 结合性：从左到右

 11.**逻辑与运算符**：`&&`

 - 结合性：从左到右

12.**逻辑或运算符**：`||`

 - 结合性：从左到右

13.**三元条件运算符**：`? :`

- 结合性：从右到左

14.**赋值运算符**：`=`, `+=`, `-=`, `*=`, `/=`, `%=`, `<<=`, `>>=`, `>>>=`, `&=`, `^=`, `|=`

- 结合性：从右到左

15.**逗号运算符**：`,`

 - 结合性：从左到右





## Java 循环结构 

1. **for 循环**：用于已知循环次数的情况。
   ```java
   for (初始化表达式; 循环条件表达式; 更新表达式) {
       // 循环体
   }
   ```
   例如，打印数字 1 到 10：
   ```java
   for (int i = 1; i <= 10; i++) {
       System.out.println(i);
   }
   ```

2. **增强型 for 循环（for-each 循环）**：用于遍历数组或集合。
   ```java
   for (元素类型 单个元素 : 集合或数组) {
       // 循环体
   }
   ```
   例如，遍历数组：
   ```java
   int[] numbers = {1, 2, 3, 4, 5};
   for (int number : numbers) {
       System.out.println(number);
   }
   ```

3. **while 循环**：当不知道循环次数，但知道循环条件时使用。
   ```java
   while (循环条件表达式) {
       // 循环体
   }
   ```
   例如，使用 while 循环打印数字 1 到 10：
   ```java
   int i = 1;
   while (i <= 10) {
       System.out.println(i);
       i++;
   }
   ```

4. **do-while 循环**：至少执行一次循环体，之后再检查条件。
   ```java
   do {
       // 循环体
   } while (循环条件表达式);
   ```
   例如，使用 do-while 循环打印数字 1 到 10：
   ```java
   int i = 1;
   do {
       System.out.println(i);
       i++;
   } while (i <= 10);
   ```



## Java条件语句

### 1. `if` 语句

`if` 语句是最基本的条件语句，它根据给定的条件判断是否执行特定的代码块。

```java
int number = 10;

if (number > 0) {
    System.out.println("该数是正数。");
}
```

### 2. `else` 和 `else if`

`else` 和 `else if` 语句可以与 `if` 语句结合使用，以处理多个条件。

```java
int number = -5;

if (number > 0) {
    System.out.println("该数是正数。");
} else if (number < 0) {
    System.out.println("该数是负数。");
} else {
    System.out.println("该数是零。");
}
```

### 3. 嵌套 `if` 语句

你可以在 `if` 语句内部使用另一个 `if` 语句，称为嵌套 `if`。

```java
int number = 10;
int anotherNumber = 20;

if (number > 0) {
    if (anotherNumber > number) {
        System.out.println("第二个数更大。");
    } else {
        System.out.println("第一个数更大。");
    }
}
```

### 4. `switch` 语句

`switch` 语句用于基于不同的情况执行不同的代码块。它通常用于当有多个固定选项时。

```java
int value = 2;

switch (value) {
    case 1:
        System.out.println("值是1");
        break;
    case 2:
        System.out.println("值是2");
        break;
    case 3:
        System.out.println("值是3");
        break;
    default:
        System.out.println("值不是1、2或3");
}
```

在 `switch` 语句中，`break` 关键字用来防止代码继续执行到下一个 `case`。`default` 关键字用于处理所有未明确列出的情况。



## Java Number & Math 类
在Java中，`Number` 和 `Math` 类是处理数字和执行数学运算的重要工具。`Number` 是一个抽象类，作为数字包装类（如 `Integer`, `Double`, `Float`, `Long` 等）的父类。而 `Math` 类提供了一系列静态方法和常量，用于执行基本的数学运算。

### Number 类

`Number` 是所有包装类（如 `Integer`, `Double`, `Float`, `Long`, `Short`, `Byte`）的抽象父类。它提供了一些方法，可以将数字对象转换为不同的基本数据类型。

- `intValue()`: 将数字转换为 `int` 类型。
- `doubleValue()`: 将数字转换为 `double` 类型。
- `floatValue()`: 将数字转换为 `float` 类型。
- `longValue()`: 将数字转换为 `long` 类型。
- `shortValue()`: 将数字转换为 `short` 类型。
- `byteValue()`: 将数字转换为 `byte` 类型。

### Math 类

`Math` 类包含了一系列静态方法和常量，用于执行数学运算，如三角函数、指数、对数、平方根等。

#### 常用方法

- `Math.abs(x)`: 返回 `x` 的绝对值。
- `Math.max(x, y)`: 返回 `x` 和 `y` 中的最大值。
- `Math.min(x, y)`: 返回 `x` 和 `y` 中的最小值。
- `Math.sqrt(x)`: 返回 `x` 的平方根。
- `Math.pow(x, y)`: 返回 `x` 的 `y` 次幂。
- `Math.exp(x)`: 返回 `e` 的 `x` 次幂。
- `Math.log(x)`: 返回 `x` 的自然对数（以 `e` 为底）。
- `Math.sin(x)`, `Math.cos(x)`, `Math.tan(x)`: 分别返回 `x` 的正弦、余弦和正切值。
- `Math.toRadians(x)`: 将角度转换为弧度。
- `Math.toDegrees(x)`: 将弧度转换为角度。

#### 常用常量

- `Math.PI`: 圆周率的值。
- `Math.E`: 自然对数的底数。

### 示例

```java
public class MathExample {
    public static void main(String[] args) {
        // 使用 Math 类的方法
        System.out.println("圆周率 PI: " + Math.PI);
        System.out.println("2的3次方: " + Math.pow(2, 3));
        System.out.println("平方根 of 16: " + Math.sqrt(16));
        
        // 使用 Number 类的方法
        Integer num = 10;
        System.out.println("数字的 double 值: " + num.doubleValue());
    }
}
```

`Number` 类和 `Math` 类是Java标准库中非常基础且广泛使用的类，它们为处理数字和执行数学运算提供了丰富的工具。



## Java Character 类
在Java中，`Character` 类是包装了基本数据类型 `char` 的对象。它位于 `java.lang` 包中，提供了各种方法来处理 `char` 类型的数据。这些方法包括字符的分类、转换、比较等。

### 常用方法

下面是一些 `Character` 类中常用的方法：

#### 字符分类方法

- `isLetter(char ch)`: 判断是否为字母。
- `isDigit(char ch)`: 判断是否为数字。
- `isWhitespace(char ch)`: 判断是否为空白字符（如空格、制表符等）。
- `isUpperCase(char ch)`: 判断是否为大写字母。
- `isLowerCase(char ch)`: 判断是否为小写字母。
- `isJavaIdentifierStart(char ch)`: 判断是否可以作为Java标识符的起始字符。
- `isJavaIdentifierPart(char ch)`: 判断是否可以作为Java标识符的一部分。

#### 字符转换方法

- `toUpperCase(char ch)`: 将字符转换为大写。
- `toLowerCase(char ch)`: 将字符转换为小写。
- `toString(char ch)`: 将字符转换为字符串。

#### 数值转换方法

- `getNumericValue(char ch)`: 返回字符代表的数值，适用于字符 '0'-'9'。
- ` digit(int ch, int radix)`: 返回指定基数（radix）下字符代表的数值。

### 示例

下面是一个使用 `Character` 类方法的简单示例：

```java
public class CharacterExample {
    public static void main(String[] args) {
        char ch = 'a';
        
        // 字符分类
        System.out.println("Is '" + ch + "' a letter? " + Character.isLetter(ch));
        System.out.println("Is '" + ch + "' an uppercase letter? " + Character.isUpperCase(ch));
        
        // 字符转换
        System.out.println("Uppercase of '" + ch + "' is: " + Character.toUpperCase(ch));
        System.out.println("Lowercase of '" + ch + "' is: " + Character.toLowerCase(ch));
        
        // 数值转换
        System.out.println("Numeric value of '9' is: " + Character.getNumericValue('9'));
    }
}
```

`Character` 类还包含其他一些方法和特性，比如用于Unicode字符处理的方法，以及一些用于字符编码的静态字段。这个类是处理字符数据和执行字符相关操作时不可或缺的工具。



## Java String 类
在Java中，`String` 类是用于处理文本字符串的一个核心类。字符串在Java中是不可变的，这意味着一旦创建了一个字符串，它的值就不能被改变。如果需要修改字符串，实际上会创建一个新的字符串对象。

### 常用方法

`String` 类提供了大量的方法来处理字符串，以下是一些常用的方法：

#### 创建和初始化

- `String str = "Hello";`: 创建一个包含文本 "Hello" 的字符串。
- `String str = new String("Hello");`: 使用构造函数创建一个字符串。

#### 连接

- `+` 运算符：用于连接字符串。
- `concat(String str)`: 连接字符串。

#### 比较

- `equals(Object anObject)`: 比较两个字符串的内容是否相等。
- `equalsIgnoreCase(String anotherString)`: 比较两个字符串的内容是否相等，忽略大小写。

#### 查找

- `indexOf(int ch)` 或 `indexOf(String str)`: 查找字符或子字符串在字符串中首次出现的位置。
- `lastIndexOf(int ch)` 或 `lastIndexOf(String str)`: 查找字符或子字符串在字符串中最后出现的位置。

#### 截取和分割

- `substring(int beginIndex)` 或 `substring(int beginIndex, int endIndex)`: 截取字符串的一部分。
- `split(String regex)`: 根据正则表达式分割字符串。

#### 替换

- `replace(char oldChar, char newChar)`: 替换字符串中所有出现的指定字符。
- `replaceAll(String regex, String replacement)`: 使用给定的替换值替换字符串中匹配正则表达式的所有序列。

#### 转换

- `toLowerCase()`: 将字符串转换为小写。
- `toUpperCase()`: 将字符串转换为大写。
- `trim()`: 去除字符串两端的空白字符。

#### 其他

- `length()`: 返回字符串的长度。
- `charAt(int index)`: 返回指定索引处的字符。
- `contains(CharSequence s)`: 判断字符串是否包含指定的字符序列。

### 示例

下面是一个使用 `String` 类方法的简单示例：

```java
public class StringExample {
    public static void main(String[] args) {
        String str = "Hello World!";
        
        // 字符串连接
        String newStr = str + " Java is fun!";
        
        // 查找字符
        int index = str.indexOf('o');
        System.out.println("字符 'o' 首次出现的位置: " + index);
        
        // 替换字符
        String replacedStr = str.replace('o', 'a');
        System.out.println("替换后的字符串: " + replacedStr);
        
        // 转换大小写
        String upperStr = str.toUpperCase();
        System.out.println("转换为大写: " + upperStr);
        
        // 截取字符串
        String subStr = str.substring(0, 5);
        System.out.println("截取的子字符串: " + subStr);
    }
}
```

`String` 类是Java编程中使用最频繁的类之一，它提供了丰富的API来处理字符串数据。由于字符串的不可变性，频繁的字符串操作可能会导致性能问题，因此在需要大量修改字符串时，可以考虑使用 `StringBuilder` 或 `StringBuffer` 类。





## Java StringBuffer
在Java中，`StringBuffer` 是一个可变的字符序列。与 `String` 类不同，`StringBuffer` 提供了可以修改字符串内容的方法，这使得它在需要频繁修改字符串内容时更加高效。`StringBuffer` 是线程安全的，这意味着它可以在多线程环境中安全使用。

### 主要特点

- **可变性**：`StringBuffer` 对象的内容可以被修改。
- **线程安全**：`StringBuffer` 的方法都是同步的，可以在多线程环境中安全使用。
- **性能**：由于其可变性，`StringBuffer` 在频繁修改字符串时比 `String` 更高效。

### 常用方法

- `append(String s)`: 将指定的字符串追加到此字符序列。
- `insert(int offset, String s)`: 在此字符序列的指定位置插入字符串。
- `delete(int start, int end)`: 移除此序列的子字符串的字符。
- `replace(int start, int end, String str)`: 使用给定的 `str` 替换此序列的子字符串中的字符。
- `reverse()`: 将字符序列用其反转形式替换。
- `setLength(int newLength)`: 设置字符序列的长度。

### 示例

下面是一个使用 `StringBuffer` 类方法的简单示例：

```java
public class StringBufferExample {
    public static void main(String[] args) {
        StringBuffer sb = new StringBuffer("Hello");

        // 追加字符串
        sb.append(" World");
        System.out.println(sb); // 输出: Hello World

        // 插入字符串
        sb.insert(5, "Java");
        System.out.println(sb); // 输出: Hello Java World

        // 删除字符串
        sb.delete(5, 10);
        System.out.println(sb); // 输出: Hello World

        // 替换字符串
        sb.replace(6, 12, "Java");
        System.out.println(sb); // 输出: Hello Java

        // 反转字符串
        sb.reverse();
        System.out.println(sb); // 输出: alueJ olleH

        // 设置长度
        sb.setLength(5);
        System.out.println(sb); // 输出: alueJ
    }
}
```

### 性能考虑

由于 `StringBuffer` 的方法是同步的，它在单线程环境中比 `StringBuilder` 略慢。如果你不需要线程安全，并且在单线程环境中工作，推荐使用 `StringBuilder`，它提供了与 `StringBuffer` 几乎相同的方法，但没有同步开销。

```java
StringBuilder sb = new StringBuilder("Hello");
```

`StringBuffer` 和 `StringBuilder` 都是处理可变字符串的强大工具，特别是在需要频繁修改字符串内容时。选择哪一个取决于你的具体需求，特别是在多线程环境下的考虑。


## Java 数组
在Java中，数组是一种数据结构，用于存储固定大小的同类型元素。数组可以存储基本数据类型（如 `int`, `double`, `char` 等）或对象（如 `String`, 自定义对象等）。数组一旦创建，其大小就固定不变。

### 声明和初始化

#### 声明数组

```java
int[] numbers; // 声明一个整型数组
String[] names; // 声明一个字符串数组
```

#### 初始化数组

```java
// 静态初始化
int[] numbers = {1, 2, 3, 4, 5};

// 动态初始化
String[] names = new String[5]; // 创建一个长度为5的字符串数组
```

### 访问和修改数组元素

数组的索引从0开始，可以使用索引来访问和修改数组中的元素。

```java
int[] numbers = {1, 2, 3, 4, 5};
numbers[0] = 10; // 修改第一个元素
int firstNumber = numbers[0]; // 获取第一个元素
```

### 数组的长度

使用 `length` 属性可以获取数组的长度。

```java
int length = numbers.length; // 获取数组的长度
```

### 遍历数组

可以使用 `for` 循环或 `for-each` 循环遍历数组中的所有元素。

```java
// 使用 for 循环
for (int i = 0; i < numbers.length; i++) {
    System.out.println(numbers[i]);
}

// 使用 for-each 循环
for (int number : numbers) {
    System.out.println(number);
}
```

### 多维数组

Java也支持多维数组，即数组的元素本身也是数组。

```java
// 声明并初始化二维数组
int[][] matrix = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

// 访问二维数组元素
int element = matrix[1][2]; // 获取第二行第三列的元素
```

### 示例

下面是一个使用数组的简单示例：

```java
public class ArrayExample {
    public static void main(String[] args) {
        // 声明并初始化数组
        int[] numbers = {10, 20, 30, 40, 50};
        
        // 遍历数组并打印每个元素
        for (int i = 0; i < numbers.length; i++) {
            System.out.println("Element at index " + i + ": " + numbers[i]);
        }
    }
}
```

数组是Java编程中非常基础且广泛使用的数据结构，适用于存储和操作固定数量的数据集合。



## Java 日期时间
在Java中，处理日期和时间可以通过旧的 `java.util.Date` 和 `java.util.Calendar` 类，但它们已被更现代的 `java.time` 包中的类所取代，该包从Java 8开始引入。`java.time` 包提供了更清晰、更易用的API来处理日期和时间。

### java.time 包中的关键类

- `LocalDate`: 仅包含日期（年、月、日）。
- `LocalTime`: 仅包含时间（时、分、秒、纳秒）。
- `LocalDateTime`: 包含日期和时间。
- `ZonedDateTime`: 包含日期、时间和时区信息。
- `Instant`: 表示时间线上的一点，通常用于表示时间戳。
- `Period`: 用于表示两个日期之间的期间。
- `Duration`: 用于表示两个时间点之间的持续时间。

### 示例

#### 创建日期和时间

```java
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.Instant;

public class DateTimeExample {
    public static void main(String[] args) {
        // 当前日期
        LocalDate today = LocalDate.now();
        System.out.println("Today's date: " + today);

        // 当前时间
        LocalTime now = LocalTime.now();
        System.out.println("Current time: " + now);

        // 当前日期和时间
        LocalDateTime currentDateTime = LocalDateTime.now();
        System.out.println("Current date and time: " + currentDateTime);

        // 当前日期和时间（带时区）
        ZonedDateTime currentZonedDateTime = ZonedDateTime.now();
        System.out.println("Current date and time with timezone: " + currentZonedDateTime);

        // 当前时间戳
        Instant currentInstant = Instant.now();
        System.out.println("Current timestamp: " + currentInstant);
    }
}
```

#### 日期时间操作

```java
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

public class DateTimeOperations {
    public static void main(String[] args) {
        LocalDate date1 = LocalDate.of(2023, 3, 15);
        LocalDate date2 = LocalDate.of(2023, 3, 20);

        // 计算两个日期之间的天数差
        long daysBetween = ChronoUnit.DAYS.between(date1, date2);
        System.out.println("Days between " + date1 + " and " + date2 + ": " + daysBetween);
    }
}
```

### 时区处理

`java.time` 包中的类支持时区，可以轻松地处理不同时区的日期和时间。

```java
import java.time.ZonedDateTime;
import java.time.ZoneId;

public class TimezoneExample {
    public static void main(String[] args) {
        // 创建一个特定时区的日期时间
        ZonedDateTime东京时间 = ZonedDateTime.of(2023, 3, 15, 12, 0, 0, 0, ZoneId.of("Asia/Tokyo"));
        System.out.println("Time in Tokyo: " + 东京时间);

        // 转换时区
        ZonedDateTime纽约时间 = 东京时间.withZoneSameInstant(ZoneId.of("America/New_York"));
        System.out.println("Time in New York: " + 纽约时间);
    }
}
```

`java.time` 包提供了一套全面的API来处理日期和时间，它比旧的 `Date` 和 `Calendar` 类更加强大和灵活。对于大多数日期和时间处理任务，推荐使用 `java.time` 包中的类。



## Java 正则表达式

在Java中，正则表达式（Regular Expressions）是一种强大的文本处理工具，用于搜索、匹配和操作字符串。Java通过 `java.util.regex` 包提供了对正则表达式的支持，主要包含三个类：`Pattern`、`Matcher` 和 `PatternSyntaxException`。

### Pattern 类

`Pattern` 类用于编译正则表达式模式。你可以使用 `Pattern.compile(String regex)` 方法来创建一个 `Pattern` 对象。

### Matcher 类

`Matcher` 类用于对输入字符串进行匹配操作。一旦你有了一个 `Pattern` 对象，你可以使用它的 `matcher(CharSequence input)` 方法来创建一个 `Matcher` 对象。

### 示例

下面是一个使用正则表达式进行匹配操作的简单示例：

```java
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class RegexExample {
    public static void main(String[] args) {
        // 编译正则表达式
        Pattern pattern = Pattern.compile("Java");

        // 待匹配的字符串
        String text = "I love Java programming.";

        // 创建Matcher对象
        Matcher matcher = pattern.matcher(text);

        // 检查是否存在匹配
        if (matcher.find()) {
            System.out.println("Match found!");
        } else {
            System.out.println("No match found.");
        }
    }
}
```

### 常用方法

- `find()`: 检查是否存在至少一个匹配。
- `matches()`: 检查整个输入字符串是否匹配模式。
- `group()`: 返回上一次匹配操作的结果。
- `start()`, `end()`: 返回匹配的开始和结束索引。

### 正则表达式语法

正则表达式包含普通字符（如字母和数字）和特殊字符（称为“元字符”）。以下是一些常用的元字符：

- `.`: 匹配除换行符以外的任意字符。
- `^`: 匹配输入字符串的开始位置。
- `$`: 匹配输入字符串的结束位置。
- `*`: 匹配前面的子表达式零次或多次。
- `+`: 匹配前面的子表达式一次或多次。
- `?`: 匹配前面的子表达式零次或一次。
- `{n}`: 匹配确定的n次。
- `{n,}`: 至少匹配n次。
- `{n,m}`: 匹配至少n次，至多m次。
- `[abc]`: 字符集合，匹配集合中的任一字符。
- `|`: 或运算符，匹配左边或右边的表达式。
- `\`: 转义字符，用于匹配特殊字符。

### 示例：使用正则表达式提取信息

```java
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class RegexExtractExample {
    public static void main(String[] args) {
        String text = "Name: Alice, Age: 30, Location: Wonderland";
        Pattern pattern = Pattern.compile("Name: (.*?), Age: (.*?), Location: (.*?)");

        Matcher matcher = pattern.matcher(text);

        if (matcher.find()) {
            System.out.println("Name: " + matcher.group(1));
            System.out.println("Age: " + matcher.group(2));
            System.out.println("Location: " + matcher.group(3));
        }
    }
}
```

在这个例子中，我们使用了括号来创建捕获组，这样就可以从匹配的字符串中提取特定的信息。

Java的正则表达式功能非常强大，可以处理复杂的文本匹配和操作任务。通过练习和学习正则表达式的语法和模式，你可以有效地利用它们来解决各种文本处理问题
。




## Java 方法
在Java中，方法（Method）是执行特定任务的代码块，它们是类或对象行为的封装。方法可以执行操作、计算值、处理数据或执行其他方法。每个方法都有一个名称、返回类型、参数列表（可能为空）和一个方法体。

### 方法的组成

1. **返回类型**：方法可以返回任何类型的数据，包括基本数据类型和对象类型。如果方法不返回任何值，则其返回类型为 `void`。

2. **方法名**：方法名应该遵循驼峰命名规则，并且能够清晰地表达方法的功能。

3. **参数列表**：参数列表定义了方法需要的输入参数，每个参数由类型和名称组成。如果方法不需要任何参数，则可以省略参数列表或使用 `void`。

4. **方法体**：方法体包含执行任务所需的代码语句。

### 示例

下面是一个简单的Java类，其中包含几个方法：

```java
public class Calculator {
    // 加法方法
    public int add(int number1, int number2) {
        return number1 + number2;
    }

    // 减法方法
    public int subtract(int number1, int number2) {
        return number1 - number2;
    }

    // 无参数方法示例
    public void printMessage() {
        System.out.println("Hello, World!");
    }
}
```

### 如何调用方法

要调用一个对象的方法，你需要先创建该类的一个实例，然后使用点操作符（`.`）来调用方法。

```java
public class Main {
    public static void main(String[] args) {
        Calculator calc = new Calculator(); // 创建Calculator类的实例
        
        // 调用add方法
        int sum = calc.add(10, 5);
        System.out.println("Sum: " + sum);
        
        // 调用subtract方法
        int difference = calc.subtract(10, 5);
        System.out.println("Difference: " + difference);
        
        // 调用printMessage方法
        calc.printMessage();
    }
}
```

### 方法重载（Overloading）

Java允许同一个类中存在多个同名方法，只要它们的参数列表不同（参数的个数或类型不同）。这称为方法重载（Method Overloading）。

```java
public class Calculator {
    // 加法方法，两个整数参数
    public int add(int number1, int number2) {
        return number1 + number2;
    }

    // 加法方法，三个整数参数
    public int add(int number1, int number2, int number3) {
        return number1 + number2 + number3;
    }
}
```

在这个例子中，`Calculator` 类有两个 `add` 方法，但它们的参数列表不同，因此它们可以共存于同一个类中。

### 方法访问修饰符

Java提供了不同的访问修饰符来控制方法的访问级别，包括 `public`, `protected`, `private` 和默认（无修饰符，即包访问权限）。访问修饰符决定了哪些其他类可以调用该方法。

- `public`: 任何其他类都可以调用该方法。
- `protected`: 同一个包内的类和所有子类可以调用该方法。
- `private`: 只有定义该方法的类可以调用该方法。
- 默认（无修饰符）: 同一个包内的类可以调用该方法。

方法是面向对象编程的核心概念之一，它们允许你组织和重用代码，同时控制对类内部行为的访问。





## Java Stream、File、IO
在Java中，处理文件和I/O（输入/输出）操作是常见的任务。Java 8 引入了流（Streams）的概念，它提供了一种高效且易于理解的方式来处理数据集合。结合文件操作，可以实现对文件内容的读取、写入和处理。

### Java Stream

Java Stream API 提供了一种高级的迭代方式，可以对集合、数组等进行操作。它支持顺序和并行处理，并且可以轻松地与Lambda表达式结合使用。

#### 创建流

- 从集合创建流：`collection.stream()`
- 从数组创建流：`Arrays.stream(array)`
- 使用Stream类的静态方法：`Stream.of(values)`

#### 常用操作

- `filter(Predicate<T> predicate)`: 过滤元素。
- `map(Function<T, R> mapper)`: 转换元素。
- `forEach(Consumer<T> action)`: 对每个元素执行操作。
- `collect(Collectors.toList())`: 收集结果到列表。

### 文件操作

Java提供了 `java.io` 和 `java.nio` 包来处理文件和I/O操作。`java.nio.file` 包中的 `Paths` 和 `Files` 类提供了更简洁和现代的文件操作API。

#### 读取文件

```java
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

public class ReadFileExample {
    public static void main(String[] args) {
        try (Stream<String> stream = Files.lines(Paths.get("example.txt"), StandardCharsets.UTF_8)) {
            stream.forEach(System.out::println);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

#### 写入文件

```java
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

public class WriteFileExample {
    public static void main(String[] args) {
        String content = "Hello, World!";
        try {
            Files.write(Paths.get("output.txt"), content.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

### 示例：使用Stream API处理文件内容

```java
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

public class FileProcessingExample {
    public static void main(String[] args) {
        String filePath = "example.txt";
        try (Stream<String> stream = Files.lines(Paths.get(filePath), StandardCharsets.UTF_8)) {
            stream
                .filter(line -> !line.trim().isEmpty()) // 过滤掉空行
                .map(String::toUpperCase) // 转换为大写
                .forEach(System.out::println); // 打印每行
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

在这个例子中，我们读取一个名为 `example.txt` 的文件，过滤掉空行，将每行转换为大写，然后打印出来。

### 注意事项

- 文件操作可能会抛出 `IOException`，因此需要妥善处理异常。
- 使用 `try-with-resources` 语句可以自动关闭资源，避免资源泄露。

Java的Stream API和文件I/O操作提供了强大的工具来处理数据和文件，使得代码更加简洁和易于理解。通过结合使用这些API，可以高效地完成复杂的文件处理任务。


## Java Scanner类
在Java中，`Scanner` 类是一个非常实用的工具，用于从不同的输入源（如控制台、文件、字符串等）读取基本类型值和字符串。`Scanner` 类位于 `java.util` 包中，它通过分隔符扫描输入文本，从而提取出需要的数据。

### 基本使用

#### 导入Scanner类

首先，需要导入 `Scanner` 类：

```java
import java.util.Scanner;
```

#### 创建Scanner对象

创建 `Scanner` 对象时，你可以指定输入源。例如，从控制台读取输入：

```java
Scanner scanner = new Scanner(System.in);
```

或者，从文件读取输入：

```java
Scanner scanner = new Scanner(new File("input.txt"));
```

#### 使用Scanner读取数据

`Scanner` 类提供了多种方法来读取不同类型的数据：

- `nextLine()`: 读取一行文本。
- `nextInt()`: 读取一个整数。
- `nextDouble()`: 读取一个双精度浮点数。
- `next()`: 读取一个字符串，直到遇到分隔符（默认是空白字符）。
- `hasNextXxx()`: 检查是否还有下一个类型为Xxx的输入。

### 示例：从控制台读取输入

```java
import java.util.Scanner;

public class ScannerExample {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("请输入你的名字：");
        String name = scanner.nextLine();
        System.out.println("你好, " + name + "!");

        System.out.println("请输入你的年龄：");
        int age = scanner.nextInt();
        System.out.println("你选择了 " + age + " 岁。");

        scanner.close(); // 关闭Scanner对象
    }
}
```

### 注意事项

- 使用完 `Scanner` 对象后，应该调用 `close()` 方法来关闭它，释放相关资源。如果使用 `try-with-resources` 语句，可以自动关闭资源。
- 当使用 `nextInt()`, `nextDouble()` 等方法时，如果输入的格式不正确，`Scanner` 会抛出 `InputMismatchException`。因此，可能需要使用 `try-catch` 语句来处理异常。
- `nextLine()` 读取的是上一个读取操作之后的整行文本。如果在读取整数或浮点数后直接使用 `nextLine()`，可能会得到一个空行，因为 `nextInt()` 或 `nextDouble()` 会留下行尾的换行符。

`Scanner` 类是处理输入的便捷工具，尤其适用于简单的控制台应用程序。对于更复杂的输入处理，可能需要考虑使用正则表达式或 `java.util.Scanner` 的高级特性。


## Scanner高级用法
`Scanner` 类除了基本的输入读取功能外，还提供了一些高级用法，比如自定义分隔符、使用正则表达式匹配、跳过和查找特定的输入等。下面是一些高级用法的示例：

### 自定义分隔符

你可以使用 `useDelimiter(String pattern)` 方法来设置 `Scanner` 的分隔符，这允许你根据自定义的正则表达式来分割输入。

```java
import java.util.Scanner;

public class ScannerDelimiterExample {
    public static void main(String[] args) {
        String input = "one,two,three,four";
        Scanner scanner = new Scanner(input);
        
        // 设置分隔符为逗号
        scanner.useDelimiter(",");
        
        while (scanner.hasNext()) {
            System.out.println(scanner.next());
        }
        
        scanner.close();
    }
}
```

### 使用正则表达式匹配

`Scanner` 类提供了 `hasNext(String pattern)` 和 `findInLine(String pattern)` 方法，允许你使用正则表达式来检查和匹配输入。

```java
import java.util.Scanner;

public class ScannerRegexExample {
    public static void main(String[] args) {
        String input = "The quick brown fox jumps over the lazy dog";
        Scanner scanner = new Scanner(input);
        
        // 检查是否有匹配正则表达式的下一个元素
        if (scanner.hasNext("[a-z]+")) {
            System.out.println("Found a word: " + scanner.next("[a-z]+"));
        }
        
        scanner.close();
    }
}
```

### 跳过输入

`Scanner` 类提供了 `nextLine()` 和 `next()` 方法来跳过当前行或当前分隔符之间的输入。

```java
import java.util.Scanner;

public class ScannerSkipExample {
    public static void main(String[] args) {
        String input = "123 hello 456";
        Scanner scanner = new Scanner(input);
        
        // 跳过数字
        scanner.nextInt();
        scanner.next(); // 跳过数字后的空白字符
        
        // 读取并打印下一个单词
        System.out.println("Next word: " + scanner.next());
        
        scanner.close();
    }
}
```

### 查找特定的输入

`findInLine(String pattern)` 方法可以用来查找当前行中与正则表达式匹配的字符串。

```java
import java.util.Scanner;

public class ScannerFindInLineExample {
    public static void main(String[] args) {
        String input = "The quick brown fox jumps over the lazy dog";
        Scanner scanner = new Scanner(input);
        
        // 查找并打印第一个单词
        System.out.println("First word: " + scanner.findInLine("[a-z]+"));
        
        scanner.close();
    }
}
```

### 使用try-with-resources自动关闭Scanner

为了确保 `Scanner` 对象在使用完毕后能够被正确关闭，推荐使用try-with-resources语句。

```java
import java.util.Scanner;

public class ScannerAutoCloseExample {
    public static void main(String[] args) {
        String input = "123 hello 456";
        try (Scanner scanner = new Scanner(input)) {
            // 使用Scanner读取输入
            System.out.println("Next number: " + scanner.nextInt());
            System.out.println("Next word: " + scanner.next());
        } // Scanner在此处自动关闭
    }
}
```

这些高级用法使得 `Scanner` 类在处理复杂的输入场景时更加灵活和强大。通过自定义分隔符、使用正则表达式匹配、跳过和查找特定输入，你可以根据具体需求来定制输入处理逻辑。



## Java异常处理
在 Java 中，异常处理主要依赖于几个关键字：`try`, `catch`, `finally`, `throw`, 和 `throws`。下面是这些关键字的详细说明和使用方法：

### 1. try-catch
`try-catch` 块用于捕获和处理异常。`try` 块内放置可能抛出异常的代码，`catch` 块用于捕获并处理特定类型的异常。

```java
try {
    // 可能抛出异常的代码
} catch (ExceptionType name) {
    // 处理异常的代码
}
```

可以有多个 `catch` 块来捕获不同类型的异常。

### 2. finally
`finally` 块跟随在 `try-catch` 块之后，无论是否捕获到异常，`finally` 块中的代码都会被执行。通常用于执行清理资源的操作，如关闭文件流。

```java
try {
    // 可能抛出异常的代码
} catch (ExceptionType name) {
    // 处理异常的代码
} finally {
    // 无论是否捕获到异常都会执行的代码
}
```

### 3. throw
`throw` 关键字用于显式地抛出一个异常。通常在方法内部，当遇到错误条件时，你可以创建一个异常实例并用 `throw` 抛出。

```java
throw new ExceptionType("Error message");
```

### 4. throws
`throws` 关键字用在方法签名中，声明该方法可能抛出的异常。这样，调用该方法的代码就必须处理或声明这些异常。

```java
public void myMethod() throws ExceptionType1, ExceptionType2 {
    // 方法代码
}
```

### 5. 自定义异常
你可以通过继承 `Exception` 类或其子类来创建自定义异常。

```java
public class MyException extends Exception {
    public MyException(String message) {
        super(message);
    }
}
```

### 6. 异常链
在 Java 7 之后，可以使用异常链来保留原始异常的上下文信息。

```java
try {
    // 可能抛出异常的代码
} catch (ExceptionType cause) {
    throw new ExceptionType("Error message", cause);
}
```

### 7. try-with-resources
Java 7 引入了 try-with-resources 语句，用于自动管理资源，如关闭实现了 `AutoCloseable` 接口的对象。

```java
try (Resource resource = new Resource()) {
    // 使用资源的代码
}
// 资源会在 try 块结束时自动关闭
```

### 示例代码
下面是一个包含上述元素的示例：

```java
import java.io.*;

public class ExceptionHandlingExample {
    public static void main(String[] args) {
        try {
            FileInputStream file = new FileInputStream("nonexistentfile.txt");
        } catch (FileNotFoundException e) {
            // 使用异常链
            throw new RuntimeException("File not found", e);
        } finally {
            System.out.println("This is the finally block.");
        }
    }
}
```

在实际开发中，合理使用异常处理机制可以提高程序的健壮性和可维护性。注意，不要用异常处理来控制正常的程序流程，异常应该只用于处理异常情况。



# Java面向对象
## Java 继承
在Java中，继承是一个非常重要的概念，它允许创建一个类（称为子类或派生类）来继承另一个类（称为父类或基类）的属性和方法。继承是面向对象编程（OOP）的四大基本特性之一（另外三个是封装、多态和抽象）。

继承的主要目的是代码复用和创建一个更加有组织的代码结构。通过继承，子类可以拥有父类的所有字段和方法，也可以添加新的字段和方法，或者重写父类的方法。

下面是一个简单的Java继承的例子：

```java
// 父类（基类）
class Animal {
    // 父类的属性
    String name;

    // 父类的方法
    void eat() {
        System.out.println(name + "正在吃食物。");
    }
}

// 子类（派生类）
class Dog extends Animal {
    // 子类可以有自己的属性
    String breed;

    // 子类可以有自己的方法
    void bark() {
        System.out.println(name + "正在吠叫。");
    }

    // 重写父类的方法
    @Override
    void eat() {
        System.out.println(name + "这只" + breed + "正在吃骨头。");
    }
}

public class Main {
    public static void main(String[] args) {
        Dog myDog = new Dog();
        myDog.name = "旺财";
        myDog.breed = "中华田园犬";

        // 调用继承自Animal的方法
        myDog.eat();
        // 调用Dog类自己的方法
        myDog.bark();
    }
}
```

在这个例子中，`Animal` 是一个基类，它有一个属性 `name` 和一个方法 `eat()`。`Dog` 类继承自 `Animal` 类，这意味着 `Dog` 类可以使用 `Animal` 类的属性和方法。`Dog` 类还添加了它自己的属性 `breed` 和方法 `bark()`，并且重写了 `eat()` 方法以提供特定于狗的行为。

使用继承时需要注意以下几点：

1. Java不支持多重继承，即一个类不能直接继承多个类（一个儿子不能认2个爹）。但是可以通过接口实现多重继承的效果。
2. `extends` 关键字用于创建继承关系。
3. 子类可以继承父类的非私有成员（字段和方法）。
4. 子类可以添加新的字段和方法，也可以重写继承来的方法。
5. ==构造方法不会被继承==，但子类构造器可以调用父类的构造器（用super(参数/无参数)；）。

super 调用父类构造器必须是子类构造器中的第一条语句。
`Child() {`
        `super(); // 使用super调用父类的无参构造器`
        `// 子类特有的初始化代码`
    `}`

继承是Java编程中非常强大的特性，它有助于创建更加模块化和可维护的代码。

## 继承关键字
## extends 关键字

`class Dog extends Animal {`
    `// 子类可以有自己的属性和方法`
    `void bark() {`
        `System.out.println(name + "正在吠叫。");`
    `}`
`}`
## implements关键字
1.一个类可以实现多个接口，用逗号分隔每个接口名称。
```java
//类C接入接口A,B
public class C implements A,B {
}
```
2.实现接口的类必须提供接口中所有方法的具体实现，除非该类被声明为抽象类。

3.接口可以包含常量、方法规范（Java 8 之前）和默认方法、静态方法（Java 8 及以后）。
```java
// Java 8之前的接口定义
interface MyInterface {
    int SOME_CONSTANT = 10; // 常量
    
// 接口中的方法默认是public和abstract的
    void abstractMethod(); // 抽象方法
}

// Java 8及以后的接口定义
interface NewInterface {
    int SOME_CONSTANT = 10; // 仍然可以定义常量
    
// 接口中的方法默认是public和abstract的
    void abstractMethod(); // 仍然可以定义抽象方法

    // 默认方法
    default void defaultMethod() {
        System.out.println("这是默认方法");
    }

    // 静态方法
    static void staticMethod() {
        System.out.println("这是静态方法");
    }
}
```
java8两个方法使用场景
- 默认方法：允许接口在不破坏现有实现的情况下进行扩展，使得接口可以添加新的功能而不需要修改所有实现该接口的类。

- 静态方法：提供了一种在接口级别执行操作的方式，而不需要创建接口的实例。
4.实现接口的类可以同时继承一个类（使用 extends 关键字）和实现多个接口。
```java
// 一个类同时继承Animal类并实现Runner接口
class Dog extends Animal implements Runner {
    void run() {
         System.out.println("Dog is running");
     }
}
```

## 向上转型与向下转型

向上转型（Upcasting）和向下转型（Downcasting）是Java中处理继承关系时非常重要的概念。下面通过实例来解释这两种转型，并讨论它们的运用空间。

### 向上转型（Upcasting）

向上转型是将子类对象赋值给父类类型的变量。这是自动发生的，因为子类对象可以被视为父类对象。

**实例**（父类类型变量调用子类重写方法）：

```java
class Animal {
    public void makeSound() {
        System.out.println("Animal makes a sound");
    }
}

class Dog extends Animal {
    @Override
    public void makeSound() {
        System.out.println("Dog barks");
    }
}

public class UpcastingExample {
    public static void main(String[] args) {
        Animal myDog = new Dog(); // 向上转型
        myDog.makeSound(); // 输出: Dog barks
    }
}
```

在这个例子中，`Dog` 类继承自 `Animal` 类。创建了一个 `Dog` 类的实例，并将其赋值给 `Animal` 类型的变量 `myDog`。调用 `makeSound()` 方法时，实际调用的是 `Dog` 类中重写的版本。

### 向下转型（Downcasting）

向下转型是将父类类型的变量转换为子类类型的变量。这需要显式地进行类型转换，并且在运行时可能会抛出 `ClassCastException`，如果类型不匹配的话。

**实例**：

```java
class Animal {
    public void makeSound() {
        System.out.println("Animal makes a sound");
    }
}

class Dog extends Animal {
    @Override
    public void makeSound() {
        System.out.println("Dog barks");
    }
}

class Cat extends Animal {
    @Override
    public void makeSound() {
        System.out.println("Cat meows");
    }
}

public class DowncastingExample {
    public static void main(String[] args) {
        Animal myAnimal = new Dog(); // 向上转型
        myAnimal.makeSound(); // 输出: Dog barks

        if (myAnimal instanceof Dog) {
            Dog myDog = (Dog) myAnimal; // 向下转型
            myDog.makeSound(); // 输出: Dog barks
        }
    }
}
```

在这个例子中，`myAnimal` 是一个 `Animal` 类型的变量，它实际上引用了一个 `Dog` 类的实例。为了调用 `Dog` 类特有的方法，我们首先检查 `myAnimal` 是否真的是 `Dog` 类型的实例，然后进行向下转型。

### 运用空间

- **多态**：向上转型是实现多态的关键。它允许你编写通用的代码，可以处理不同子类的对象。例如，你可以创建一个 `Animal` 类型的列表，然后添加 `Dog`、`Cat` 等不同类型的对象，然后统一处理它们。

- **代码灵活性和可维护性**：通过向上转型，你可以轻松地更改底层使用的具体类，而不需要修改使用这些对象的代码。

- **类型检查和转换**：向下转型通常用于需要访问子类特有功能的场景。在向下转型之前，使用 `instanceof` 操作符进行类型检查是一个好习惯，以确保类型安全。

- **设计模式**：在使用工厂模式、策略模式等设计模式时，向上转型和向下转型是常见的操作。

在实际开发中，向上转型非常常见，因为它支持多态和代码的灵活性。而向下转型则需要谨慎使用，确保类型转换的正确性，以避免运行时错误。

## super 与 this 关键字
在Java中，`super` 和 `this` 都是引用关键字，但它们的用途和含义有所不同。它们都用于引用对象的特定部分，但指向的上下文不同。

### this 关键字

`this` 关键字用于引用当前对象的实例。它主要用于以下情况：
- 在方法内部引用当前对象的字段，尤其是当方法的参数与字段同名时。

- 调用当前类的其他构造器（构造器重载时使用）。

 - 传递当前对象作为参数。


示例代码

```java
class Person {
    String name;

    Person(String name) {
        this.name = name; // 使用this来区分字段和参数
    }

    void printInfo() {
        System.out.println("Name: " + this.name); // 引用当前对象的name字段
    }
}
```

### super关键字
`super` 关键字用于引用父类的成员（字段、方法和构造器）。它主要用于以下情况：
  - 访问父类被子类覆盖的字段。
```java
//父类和子类都定义了一个变量name
super.name; // 调用父类字段
this.name;  //访问子类字段
```
  - 调用父类的方法。
  - 调用父类的构造器。

示例代码：

```java
    Dog() {
        super(); // 调用父类的构造器
        super.eat(); // 调用父类的方法
    }
```

### 总结

- `this` 关键字引用当前对象，用于区分成员变量和局部变量，调用当前类的其他构造器或方法。
- `super` 关键字引用父类的成员，用于访问和调用父类的字段、方法和构造器。

理解这两个关键字的用途对于编写清晰、高效的Java代码非常重要。
## final 关键字
### 1. final 类
当一个类被声明为 `final` 时，这意味着这个类不能被继承。任何尝试继承 `final` 类的类都会导致编译错误。

```java
final class FinalClass {
    // 类的实现
}
```

### 2. final 方法
当一个方法被声明为 `final` 时，这意味着这个方法不能被子类覆盖（重写）。这通常用于防止子类改变方法的行为。

```java
class BaseClass {
    final void finalMethod() {
        // 方法实现
    }
}

class DerivedClass extends BaseClass {
    // 编译错误：无法覆盖final方法finalMethod()
}
```

### 3. final 变量
当一个变量被声明为 `final` 时，这意味着一旦给 `final` 变量赋值之后，它的值就不能被改变。对于基本数据类型变量，这意味着你不能重新赋值；对于对象引用变量，这意味着你不能改变引用，使其指向另一个对象，但对象本身的内容是可以改变的。

```java
final int finalInt = 10;
final int[] finalArray = new int[5];

// finalInt = 20; // 编译错误：无法为final变量赋值

finalArray[0] = 5; // 合法操作：改变数组内容
// finalArray = new int[10]; // 编译错误：无法改变final变量引用
```

### final 关键字的其他用途：

- **final 参数**：在方法参数中使用 `final` 关键字，意味着该参数在方法内部不能被修改。
- **final 局部变量**：在方法内部声明的 `final` 局部变量必须在声明时或每个构造块中初始化，之后不能被重新赋值。

### 注意事项：

- 对于 `final` 对象引用，虽然不能改变引用本身，但可以改变引用指向的对象的内容。例如，如果有一个 `final` 引用指向一个对象，你不能让这个引用指向另一个对象，但你可以修改对象的字段。
- `final` 关键字常用于设计不可变类，确保对象一旦创建，其状态就不能被改变。

`final` 关键字在Java中是一个非常有用的工具，用于确保类、方法和变量的不可变性，从而提高代码的安全性和可维护性




## 构造器
在Java中，构造器（Constructor）是一种特殊的方法，用于在创建对象时初始化对象，即为对象的成员变量赋初值。

特点：
- 名称与类名相同：构造器的名称必须与它所属的类名完全一致。
```java
class Person {
    String name;
    int age;
    // 无参构造器
    Person() {
         this.name = "Unknown";
         this.age = 0;
     }
    // 带参构造器
    Person(String name, int age){
         this.name = name;
         this.age = age;
     }
}
```
- 没有返回类型：构造器没有返回类型，甚至不包括 void。

- 可以重载：一个类可以有多个构造器，只要它们的参数列表不同（参数的个数或类型不同），这称为构造器重载。

- 默认构造器：如果一个类没有显式定义任何构造器，Java编译器会自动提供一个无参的默认构造器。但一旦定义了至少一个构造器，编译器就不会再提供默认构造器。


### 注意事项：
**构造器调用**：创建对象时，构造器会被自动调用。构造器的调用是对象创建过程的一部分。

**与父类构造器的调用**：如果一个类继承自另一个类，子类的构造器会隐式或显式地调用父类的构造器。如果子类构造器没有显式调用父类的构造器，编译器会尝试插入一个对父类无参构造器的调用。如果父类没有无参构造器，子类构造器必须显式地使用 super 关键字调用父类的带参构造器。
```java
class Child extends Parent {
    Child() {
    // 显式调用父类的无参构造器
    super();                         System.out.println("Child constructor");
     }
}
```
**构造器不能被继承**：构造器不能被继承，因此子类不能继承父类的构造器。

   类名不同就注定了不能继承构造器

构造器是Java面向对象编程中非常重要的概念，它确保了对象在创建时能够被正确地初始化。


## Java 重写(Override)与重载(Overload)
在Java中，重写（Override）和重载（Overload）是两个与方法相关的重要概念，它们都与多态性有关，但含义和使用场景不同。

### 重写（Override）

重写是子类对父类中同名同参数的方法进行重新实现的过程。这是实现多态的关键机制之一。

- **规则**：
  - 方法签名必须相同（方法名和参数列表都相同）。
  - 返回类型可以是父类方法返回类型的子类型。
  - 访问权限==不能比父类中的方法更严格==（例如，父类中是`public`，子类中不能是`protected`或`private`）。
  - 可以抛出与父类方法相同的异常或其子集。
  - 使用`@Override`注解来明确表示重写，虽然不是必须的，但这是一个好习惯。

- **目的**：
  - 允许子类提供特定于自己的行为实现，而父类提供通用的框架。

### 重载（Overload）

重载是指在同一个类中定义多个同名方法，但这些方法的参数列表不同（参数的个数或类型不同）。

- **规则**：
  - 方法名相同，但参数列表不同。
  - 返回类型可以相同也可以不同，与方法重载无关。
  - 访问权限可以不同。
  - 可以抛出不同的异常。

- **目的**：
  - 提供同一个方法的多个版本，以处理不同的参数类型或参数数量，从而提高方法的灵活性和可用性。

### 示例

```java
class Animal {
    public void makeSound() {
        System.out.println("Animal makes a sound");
    }
}

class Dog extends Animal {
    // 重写
    @Override
    public void makeSound() {
        System.out.println("Dog barks");
    }
    
    // 重载
    public void makeSound(int times) {
        for (int i = 0; i < times; i++) {
            System.out.println("Dog barks");
        }
    }
}
```


理解这两个概念对于编写灵活、可维护的Java代码非常重要。重写允许子类定制或扩展父类的行为，而重载则允许方法根据不同的输入参数提供不同的功能。


## Java 多态
Java中的多态是面向对象编程的一个核心概念，它允许我们==通过一个通用的接口来操作不同的具体类型对象==。多态主要体现在以下几个方面：

父类类型   父类类型的变量 ＝ 子类对象
### 1. 方法重写（Method Overriding）
这是多态最常见的形式之一。当子类拥有与父类同名同参数的方法时，子类的方法会覆盖父类的方法。在运行时，根据对象的实际类型调用相应的方法，这就是运行时多态。

```java
class Animal {
    public void makeSound() {
        System.out.println("Animal makes a sound");
    }
}

class Dog extends Animal {
    @Override
    public void makeSound() {
        System.out.println("Dog barks");
    }
}

public class TestPolymorphism {
    public static void main(String[] args) {
        Animal myAnimal = new Animal();
        Animal myDog = new Dog(); // 多态性：引用变量是Animal类型，实际对象是Dog类型
        
        myAnimal.makeSound(); // 输出: Animal makes a sound
        myDog.makeSound();    // 输出: Dog barks
    }
}
```

### 2. 接口和抽象类
通过接口和抽象类，可以定义一些方法，然后由实现这些接口或继承这些抽象类的具体类来提供具体实现。这样，可以使用接口或抽象类类型的引用来指向实现类的对象，实现多态。

```java
interface Vehicle {
    void start();
}

class Car implements Vehicle {
    public void start() {
        System.out.println("Car starts with a roar");
    }
}

class Motorcycle implements Vehicle {
    public void start() {
        System.out.println("Motorcycle starts with a hum");
    }
}

public class TestPolymorphism {
    public static void main(String[] args) {
        Vehicle myCar = new Car();
        Vehicle myMotorcycle = new Motorcycle();
        
        myCar.start();           // 输出: Car starts with a roar
        myMotorcycle.start();    // 输出: Motorcycle starts with a hum
    }
}
```

### 3. 类型转换
在多态中，可以将父类类型的引用指向子类对象。向上转型（Upcasting）是自动的，而向下转型（Downcasting）需要显式进行，并且可能需要进行类型检查。

```java
Animal animal = new Dog(); // 向上转型，Animal引用指向Dog对象
Dog dog = (Dog) animal;    // 向下转型，需要显式转换
```

### 4. 方法重载（Method Overloading）
方法重载允许一个类拥有多个同名方法，只要它们的参数列表不同（参数类型、个数或顺序不同）。编译器根据方法的参数列表来区分不同的方法。

```java
class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
    
    public double add(double a, double b) {
        return a + b;
    }
}
```

多态性使得程序更加灵活，易于扩展，同时减少了代码的重复。通过多态，可以编写出通用的代码，这些代码可以适用于不同的对象类型，从而提高代码的复用性和可维护性。



## Java抽象类
在Java中，==抽象类是一种不能被实例化的类==。抽象类可以包含抽象方法和具体方法。抽象方法是没有具体实现的方法，只有方法签名和返回类型，没有方法体。具体方法则有完整的实现。

在非抽象子类可以实现抽象类中的抽象函数并创建对象调用


1. **声明抽象类**：使用关键字 `abstract` 前缀来声明一个抽象类。
   ```java
   public abstract class Animal {
       // ...
   }
   ```

2. **定义抽象方法**：==抽象方法没有方法体，只有声明。==
   ```java
   public abstract void makeSound();
   ```

3. **实现抽象方法**：在非抽象子类中，必须实现所有的抽象方法。
   ```java
   public class Dog extends Animal {
       @Override
       public void makeSound() {
           System.out.println("Woof!");
       }
   }
   ```

4. **实例化**：由于抽象类不能实例化，你不能直接创建它的对象。
   ```java
   Animal animal = new Animal(); // 错误：无法实例化抽象类
   ```

5. **使用抽象类的目的**：抽象类通常用于==定义一个通用的模板，让子类继承并实现具体的功能==。它还可以包含具体的方法和变量。

6. **抽象类和接口的区别**：虽然两者都可以包含抽象方法，但抽象类可以包含具体的方法和变量，而接口通常只包含抽象方法、默认方法和静态方法。此外，==一个类可以实现多个接口，但只能继承一个抽象类==。

7. **抽象类的使用场景**：当你希望某些方法在子类中被共享，或者你想要强制子类实现某些方法时，可以使用抽象类。

8. 抽象类中不一定包含抽象方法，但是有抽象方法的类必定是抽象类

9. 构造方法，类方法(static修饰静态方法，由类名直接调用)不能声明为抽象方法。

10. 抽象类的子类必须给出抽象类中的抽象方法的具体实现，除非该子类也是抽象类





下面是一个简单的例子，展示如何定义和使用抽象类：

```java
// 定义一个抽象类
public abstract class Shape {
    private String color;

    public Shape(String color) {
        this.color = color;
    }

    // 抽象方法，计算面积
    public abstract double area();

    // 具体方法，返回颜色
    public String getColor() {
        return color;
    }
}

// 实现抽象类
public class Rectangle extends Shape {
    private double width;
    private double height;

    public Rectangle(double width, double height, String color) {
        super(color);
        this.width = width;
        this.height = height;
    }

    @Override
    public double area() {
        return width * height;
    }
}

// 使用
public class Main {
    public static void main(String[] args) {
        Shape rectangle = new Rectangle(5.0, 3.0, "Red");
        System.out.println("The area of the rectangle is: " + rectangle.area());
    }
}
```



## Java 封装
在Java中，封装（Encapsulation）是面向对象编程（OOP）的四个基本概念之一，它指的是将对象的状态（属性）和行为（方法）捆绑在一起，并对外隐藏对象的实现细节。封装的目的是保护对象内部的数据不被外部直接访问和修改，而是通过定义的公共接口来控制对这些数据的访问。

封装通过以下方式实现：

1. **私有成员变量**：将类的成员变量（属性）声明为私有（使用 `private` 关键字）。这样，这些变量就不能直接从类的外部访问。

2. **公共方法**：提供公共的getter和setter方法（有时称为访问器和修改器）来访问和修改私有变量。通过这些方法，可以控制对变量的访问级别和验证输入数据。

3. **构造方法**：使用构造方法来初始化对象的状态，确保对象在创建时具有有效的状态。

下面是一个简单的封装示例：
- 构造器初始化
- get方法获取私有变量的值
- set方法修改私有变量的值

```java
public class Person {
    // 私有成员变量
    private String name;
    private int age;

    // 构造方法
    public Person(String name, int age) {
        this.name = name;
        this.setAge(age); // 使用setter方法来设置年龄，可以在这里加入验证逻辑
    }

    //自定义setAge方法
    //返回类型是 void，表示这个方法不返回任何值
    public void setAge(age){
    if (age > 0) {
            this.age = age; // 设置属性值age(无需用int类型 return age)
        } else {            System.out.println("无效的年龄");
        }
    }

    // 公共getter方法
    public String getName() {
        return name;
    }

    // 公共setter方法
    public void setName(String newName) {
        this.name = newName;
    }

    // 公共getter方法
    public int getAge() {
        return age;
        }
}





public class Main {
    public static void main(String[] args) {
        // 创建Person类的实例
        Person person = new Person("Alice", 30);

        // 使用公共方法访问属性
        System.out.println("Name: " + person.getName()); // 输出: Name: Alice
        System.out.println("Age: " + person.getAge());   // 输出: Age: 30

        // 使用公共方法修改属性
        person.setName("Bob");
        person.setAge(25);

        // 再次访问修改后的属性
        System.out.println("Updated Name: " + person.getName()); // 输出: Updated Name: Bob
        System.out.println("Updated Age: " + person.getAge());   // 输出: Updated Age: 25
    }
}
```


- 通常 set 方法不会返回任何值，因为它们的目的是设置属性值，而不是返回数据。如果你需要获取属性值，应该使用 get 方法，例如 getAge()。

- setAge 方法的好处包括：
  1.**数据验证**：可以在设置属性值之前进行检查，确保数据的有效性。例如，年龄不能是负数。

  2.**封装**：通过 setAge 方法，age 属性被封装起来，外部代码不能直接修改它，只能通过 setAge 方法进行修改。这样可以确保所有对 age 的修改都会经过验证。

  3.**灵活性**：如果将来需要改变 age 属性的存储方式或验证逻辑，只需修改 setAge 方法即可，而不需要修改使用这个属性的外部代码。

  4.**控制访问**：setAge 方法可以提供额外的逻辑，比如在设置新值之前检查是否满足某些条件，或者在设置新值后执行其他操作。


## Java 接口
在Java中，接口（Interface）是一种引用类型，它定义了一组方法规范，但不提供这些方法的具体实现。接口主要用于实现多态和解耦，允许不同的类实现相同的接口，从而具有相同的方法签名，但可以有不同的实现。

接口的主要特点包括：

1. **抽象方法**：接口中的方法默认是抽象的，即没有方法体。从Java 8开始，接口也可以包含默认方法和静态方法，这些方法可以有实现。

2. **常量**：接口中可以定义常量，这些常量默认是 `public static final` 类型的，即它们是公开的、静态的、最终的（不可变的）。

3. **实现接口**：类通过 `implements` 关键字来实现接口。实现接口的类必须提供接口中所有抽象方法的具体实现。

4. **多重实现**：一个类可以实现多个接口，这提供了实现多继承的机制。

5. **默认方法和静态方法**：从Java 8开始，接口可以包含默认方法（使用 `default` 关键字)，静态方法（使用 `static` 关键字）。
   静态方法访问静态变量
```java
public static void printStaticCount() {
//count为静态变量，静态方法直接访问
        System.out.println("当前计数器的静态值为: " + count);
     }
}  
```

默认方法提供了一个默认的实现，类可以继承这个实现，也可以覆盖它。==静态方法属于接口本身，不能被类覆盖==。

接口名.接口的静态方法
~~子类名.接口的静态方法~~
https://www.runoob.com/java/java8-default-methods.html

  6.**接口特性**
  - 接口没有实例化对象，也就没有让对象实例初始化的构造函数

  - 接口中的变量会被隐式的指定为 public static final 变量，接口中的方法会被隐式的指定为 public abstract
![[Screenshot_20240930_110511.jpg]]

下面是一个简单的接口示例：

```java
// 定义一个接口
public interface Drawable {
    // 抽象方法
     void draw();

     // 默认方法
     default void printInfo() {
         System.out.println("This is a default method in an interface.");
     }

     // 静态方法
     static void printInterfaceInfo() {
         System.out.println("This is a static method in an interface.");
     }
}

// 实现接口的类
public class Circle implements Drawable {
    @Override
     public void draw() {
         System.out.println("Drawing a circle.");
     }

     // 可以选择覆盖默认方法
     @Override
     public void printInfo() {
         System.out.println("Circle class implementing Drawable interface.");
     }
}

// 使用
public class Main {
    public static void main(String[] args) {
        Drawable circle = new Circle();
         circle.draw(); // 输出: Drawing a circle.
         circle.printInfo(); // 输出: Circle class implementing Drawable interface.
         Drawable.printInterfaceInfo(); // 输出: This is a static method in an interface.
     }
}
```


接口是Java中实现抽象和多态的关键机制之一，它们在定义通用行为和协议时非常有用。


## Java枚举
在Java中，枚举（Enum）是一种特殊的数据类型，它允许你定义一组命名的常量。枚举类型非常适合表示固定数量的常量值，比如季节、方向、颜色等。Java枚举类型提供了一种类型安全的方式来处理一组固定的常量。

### 枚举的基本特性

1. **唯一性**：枚举常量是唯一的，不能有重复的值。
2. **类型安全**：枚举类型提供编译时类型检查，可以避免将错误的值赋给枚举变量。
3. **封装性**：枚举常量可以看作是枚举类的实例，它们被封装在枚举类中。
4. **方法和字段**：枚举可以包含字段、方法和其他成员，就像普通的类一样。
5. **实现接口**：枚举可以实现接口，提供额外的行为。

### 定义枚举

定义枚举的基本语法如下：

```java
public enum Season {
    SPRING, SUMMER, AUTUMN, WINTER;
}
```

这里定义了一个名为 `Season` 的枚举类型，它有四个枚举常量：`SPRING`、`SUMMER`、`AUTUMN` 和 `WINTER`。

### 使用枚举

```java
public class EnumDemo {
    public static void main(String[] args) {
        Season currentSeason = Season.SPRING;      
        switch (currentSeason) {
            case SPRING:              ​System.out.println("春天来了！");
                break;
            case SUMMER:
            System.out.println("夏天热辣辣！");
                break;
            case AUTUMN:               ​System.out.println("秋天的落叶很美！");
                break;
            case WINTER:             ​System.out.println("冬天的雪很白！");
                break;
            default:                System.out.println("未知季节");
                break;
        }
    }
}
```

### 枚举的高级特性

1. **字段和构造器**：枚举可以有字段和构造器，用于为每个枚举常量存储和初始化数据。

```java
public enum Season {
    SPRING("春天"),
    SUMMER("夏天"),
    AUTUMN("秋天"),
    WINTER("冬天");
    
    private final String seasonName;
      
    private Season(String seasonName) {
        this.seasonName = seasonName;
    }
    
    public String getSeasonName() {
        return seasonName;
    }
}
```

2. **方法**：枚举可以包含方法，包括抽象方法。

```java
public enum Operation {
    PLUS {
        @Override
        public double apply(double x, double y) { return x + y; }
    },
    MINUS {
        @Override
        public double apply(double x, double y) { return x - y; }
    };
    
    public abstract double apply(double x, double y);
}
```

3. **实现接口**：枚举可以实现接口，实现接口中定义的方法。

```java
public interface Operation {
    double apply(double x, double y);
}

public enum Operation implements Operation {
    PLUS("+") {
        @Override
        public double apply(double x, double y) { return x + y; }
    },
    MINUS("-") {
        @Override3
        public double apply(double x, double y) { return x - y; }
    };
    
    private final String symbol;
    
    Operation(String symbol) {
        this.symbol = symbol;
    }
    
    public String toString() {
        return symbol;
    }
}
```

枚举类型在Java中非常强大和灵活，它们不仅限于简单的常量集合，还可以实现复杂的逻辑和行为。


## Java包
在Java中，包（package）是一种封装机制，用于组织类和接口。包的主要作用是：

1. **避免命名冲突**：当多个开发者或项目使用相同名称的类时，包可以确保类名的唯一性。
2. **访问控制**：通过包，可以控制类和接口的访问权限，比如哪些类可以被其他包中的代码访问。
3. **命名空间管理**：包为类和接口提供了一个命名空间，有助于管理大型项目中的代码结构。

### 定义包

要将类或接口放入包中，你需要在文件的顶部声明包名。例如：

```java
package com.example.utilities;

public class Utils {
    // 类的实现
}
```

上面的代码表示 `Utils` 类属于 `com.example.utilities` 包。

### 包的命名约定

- 包名通常全部使用小写字母。
- 为了防止命名冲突，包名通常以公司的域名倒序作为包名的开始，例如 `com.example`。
- 包名可以是多层结构，用点（`.`）分隔每一层。

### 使用包

要使用其他包中的类或接口，你需要导入它们。有两种导入方式：

1. **导入特定的类或接口**：

```java
import com.example.utilities.Utils;

public class Main {
    public static void main(String[] args) {
        Utils utility = new Utils();
        // 使用 Utils 类
    }
}
```

2. **导入包中的所有类或接口**（不推荐，因为这会增加编译时间）：

```java
import com.example.utilities.*;

public class Main {
    public static void main(String[] args) {
        Utils utility = new Utils();
        // 使用 Utils 类
    }
}
```

### 默认包

如果一个类没有声明包名，那么它属于默认包。在实际开发中，不推荐使用默认包，因为这会降低代码的组织性和可维护性。

### 访问修饰符和包

访问修饰符（如 `public`, `protected`, `private` 和默认访问）与包的使用密切相关：

- `public` 类或成员可以被任何其他类访问。
- `protected` 成员可以被同一个包内的类以及其他包中的子类访问。
- 默认访问（没有指定访问修饰符）允许同一个包内的类访问。
- `private` 成员只能被定义它们的类访问。

### 包的目录结构

在文件系统中，包的结构通常与目录结构相对应。例如，`com.example.utilities.Utils` 类应该位于名为 `com/example/utilities/` 的目录中。

### 总结

包是Java中组织类和接口的重要机制，它有助于避免命名冲突，控制访问权限，并管理大型项目的代码结构。正确使用包可以提高代码的可读性和可维护性。



## Java反射
https://www.runoob.com/java/java-reflection.html
在Java中，每个类在运行时都有一个与之对应的`Class`对象，它包含了关于类的元数据信息。==`Class`对象是Java反射机制的核心==，它允许程序在运行时动态地访问和操作类的信息。

### 如何获取一个对象的`Class`对象

有几种方式可以获取一个对象的`Class`对象：

1. **使用`.getClass()`方法**：
   如果你有一个对象实例，可以通过调用该对象的`.getClass()`方法来获取它的`Class`对象。

   ```java
   Object obj = new Object();
   Class<?> clazz = obj.getClass();
   ```

2. **使用`.class`语法**：
   如果你知道类的名称，可以直接使用类名后跟`.class`来获取其`Class`对象。

   ```java
   Class<?> clazz = Object.class;
   ```

3. **使用`Class.forName()`方法**：
   如果你有一个类的全限定名（包括包名），可以使用`Class.forName()`静态方法来获取`Class`对象。这种方式常用于动态加载类。

   ```java
   try {
       Class<?> clazz = Class.forName("java.lang.Object");
   } catch (ClassNotFoundException e) {
       e.printStackTrace();
   }
   ```

### `Class`对象的作用

`Class`对象允许你在运行时执行以下操作：

- **创建类的新实例**：使用`Class`对象的`newInstance()`方法可以创建类的新实例（需要类有一个无参构造器）。
- **获取类的方法、字段、构造器等信息**：通过`getDeclaredMethods()`, `getDeclaredFields()`, `getDeclaredConstructors()`等方法可以获取类的详细信息。
- **访问和修改私有字段和方法**：通过`Field`, `Method`, `Constructor`等类的`setAccessible(true)`方法，可以访问和修改私有成员。
- **动态代理**：可以使用`Proxy`类和`InvocationHandler`接口结合`Class`对象来创建动态代理对象。

### 示例

假设有一个简单的类`Person`：

```java
public class Person {
    private String name;
    private int age;

    public Person() {
    }

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    // getters and setters
}
```

获取`Person`类的`Class`对象并创建实例：

```java
// 通过对象实例获取
Person person = new Person();
Class<?> personClass = person.getClass();

// 通过类名获取
Class<?> personClassDirect = Person.class;

// 通过全限定名获取
try {
    Class<?> personClassFromName = Class.forName("com.example.Person");
} catch (ClassNotFoundException e) {
    e.printStackTrace();
}
```

使用`Class`对象创建`Person`类的新实例：

```java
try {
    Person newPerson = (Person) personClass.getConstructor(String.class, int.class).newInstance("Alice", 30);
} catch (Exception e) {
    e.printStackTrace();
}
```

`Class`对象是Java反射机制的基础，它为运行时的类操作提供了强大的支持。




# Java高级教程

## java数据结构
在Java中，数据结构是组织和存储数据的一种方式，以便于访问和修改。Java标准库提供了丰富的数据结构实现，包括集合框架（Collections Framework）中的`List`, `Set`, `Map`等接口以及它们的多种实现类。下面是一些常用数据结构的实例：

### 1. 列表（List）

`List`是一种有序集合，可以包含重复的元素。`ArrayList`和`LinkedList`是`List`接口的两种常用实现。

```java
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class ListExample {
    public static void main(String[] args) {
       //通过接口创建数据结构（运用向上转型，父类变量调用子类方法）
       // new ArrayList<>()：这是创建ArrayList实例的表达式
       //List是 ArrayList的父类，<>里限制了arrayList存什么类型的对象，空着表示任意对象
       
        List<String> arrayList = new ArrayList<>();
        arrayList.add("Apple");
        arrayList.add("Banana");
        arrayList.add("Cherry");
        System.out.println(arrayList);

        // LinkedList 示例
        List<String> linkedList = new LinkedList<>();
        linkedList.add("Dog");
        linkedList.add("Elephant");
        linkedList.add("Fox");
        System.out.println(linkedList);
    }
}
```

### 2. 集合（Set）

`Set`是一种不允许重复元素的集合。`HashSet`和`TreeSet`是`Set`接口的两种常用实现。

```java
import java.util.HashSet;
import java.util.TreeSet;
import java.util.Set;

public class SetExample {
    public static void main(String[] args) {
        // HashSet 示例
        Set<String> hashSet = new HashSet<>();
        hashSet.add("Red");
        hashSet.add("Green");
        hashSet.add("Blue");
        System.out.println(hashSet);

        // TreeSet 示例
        Set<String> treeSet = new TreeSet<>();
        treeSet.add("Orange");
        treeSet.add("Purple");
        treeSet.add("Yellow");
        System.out.println(treeSet);
    }
}
```

### 3. 映射（Map）

`Map`是一种存储键值对的数据结构。`HashMap`和`TreeMap`是`Map`接口的两种常用实现。

```java
import java.util.HashMap;
import java.util.TreeMap;
import java.util.Map;

public class MapExample {
    public static void main(String[] args) {
        // HashMap 示例
        Map<String, Integer> hashMap = new HashMap<>();
        hashMap.put("One", 1);
        hashMap.put("Two", 2);
        hashMap.put("Three", 3);
        System.out.println(hashMap);

        // TreeMap 示例
        Map<String, Integer> treeMap = new TreeMap<>();
        treeMap.put("Four", 4);
        treeMap.put("Five", 5);
        treeMap.put("Six", 6);
        System.out.println(treeMap);
    }
}
```

### 4. 队列（Queue）

`Queue`是一种特殊的列表，用于在处理之前临时存储元素。`LinkedList`实现了`Queue`接口。

```java
import java.util.Queue;
import java.util.LinkedList;

public class QueueExample {
    public static void main(String[] args) {
        Queue<String> queue = new LinkedList<>();
        queue.offer("First");
        queue.offer("Second");
        queue.offer("Third");
        System.out.println(queue.poll()); // 输出: First
        System.out.println(queue); // 输出: [Second, Third]
    }
}
```

### 5. 双端队列（Deque）

`Deque`（双端队列）是一种可以在两端进行插入和删除操作的队列。`ArrayDeque`是`Deque`接口的一个常用实现。

```java
import java.util.Deque;
import java.util.ArrayDeque;

public class DequeExample {
    public static void main(String[] args) {
        Deque<String> deque = new ArrayDeque<>();
        deque.offerFirst("First");
        deque.offerLast("Last");
        System.out.println(deque.pollFirst()); // 输出: First
        System.out.println(deque); // 输出: [Last]
    }
}
```

这些是Java中一些基本的数据结构实例。根据具体需求选择合适的数据结构非常重要，因为不同的数据结构在性能和功能上有所差异。例如，`ArrayList`在随机访问元素时表现良好，而`LinkedList`在插入和删除操作上更高效。同样，`HashMap`提供了快速的查找和插入操作，而`TreeMap`则保持了键的排序。


## 高级应用实例

### 1. 使用`PriorityQueue`实现优先级队列

`PriorityQueue`是一个基于优先级堆的无界队列，它允许插入任意类型的对象，并根据提供的比较器（Comparator）或对象的自然顺序来管理元素的顺序。

```java
import java.util.PriorityQueue;
import java.util.Comparator;

class Task {
    private int priority;
    private String description;

    public Task(int priority, String description) {
        this.priority = priority;
        this.description = description;
    }

    public int getPriority() {
        return priority;
    }

    @Override
    public String toString() {
        return description;
    }
}

public class PriorityQueueExample {
    public static void main(String[] args) {
    //Task::getPriority是一个方法引用，它等价于一个lambda表达式task -> task.getPriority()。
        PriorityQueue<Task> priorityQueue = new PriorityQueue<>(Comparator.comparingInt(Task::getPriority));
      //通过Task类的getPriority方法来获取一个整数，并根据这个整数来比较两个Task对象
        priorityQueue.add(new Task(3, "Task 3"));
        priorityQueue.add(new Task(1, "Task 1"));
        priorityQueue.add(new Task(2, "Task 2"));

        // 处理队列中的任务
while (!priorityQueue.isEmpty()) {
Task task=priorityQueue.poll(); // 获取并移除队列头元素
  ​System.out.println("Processing task: " + task); 
            // 处理任务
            // 任务处理完毕后，它被移出队列
        }
        // 队列现在为空，因为所有任务都已被处理并移出
        System.out.println("All tasks have been processed.");
    }
}
//由于 PriorityQueue 是根据任务的优先级排序的，所以输出的顺序是优先级最低到最高
// 输出: Task 1, Task 2, Task 3

//调用 poll() 方法来获取队列中的头元素（即优先级最低的任务），然后打印出一条处理任务的消息。由于 poll() 方法的调用，获取的任务被从队列中移除。
```

### 2. 使用`HashMap`和自定义对象作为键

当使用自定义对象作为`HashMap`的键时，需要确保对象正确地实现了`equals()`和`hashCode()`方法。

```java
import java.util.HashMap;

class CustomKey {
    private String key;

    public CustomKey(String key) {
        this.key = key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomKey that = (CustomKey) o;
        return key.equals(that.key);
    }

    @Override
    public int hashCode() {
        return key.hashCode();
    }
}

public class HashMapWithCustomKey {
    public static void main(String[] args) {
        HashMap<CustomKey, String> map = new HashMap<>();
        map.put(new CustomKey("key1"), "value1");
        map.put(new CustomKey("key2"), "value2");

        System.out.println(map.get(new CustomKey("key1"))); // 输出: value1
    }
}
```

### 3. 使用`TreeMap`进行排序

`TreeMap`可以根据键的自然顺序或构造时提供的`Comparator`进行排序。

```java
import java.util.TreeMap;

public class TreeMapExample {
    public static void main(String[] args) {
        TreeMap<Integer, String> treeMap = new TreeMap<>();
        treeMap.put(3, "Three");
        treeMap.put(1, "One");
        treeMap.put(2, "Two");

        System.out.println(treeMap); // 输出: {1=One, 2=Two, 3=Three}
    }
}
```

### 4. 使用`ConcurrentHashMap`实现线程安全的映射

`ConcurrentHashMap`是线程安全的`HashMap`，适用于多线程环境。

```java
import java.util.concurrent.ConcurrentHashMap;

public class ConcurrentHashMapExample {
    public static void main(String[] args) {
        ConcurrentHashMap<String, String> concurrentMap = new ConcurrentHashMap<>();
        concurrentMap.putIfAbsent("key1", "value1");
        concurrentMap.putIfAbsent("key2", "value2");

        System.out.println(concurrentMap.get("key1")); // 输出: value1
    }
}
```

### 5. 使用`LinkedHashMap`保持插入顺序

`LinkedHashMap`继承自`HashMap`，但它维护了元素的插入顺序。

```java
import java.util.LinkedHashMap;
import java.util.Map;

public class LinkedHashMapExample {
    public static void main(String[] args) {
        LinkedHashMap<String, String> linkedMap = new LinkedHashMap<>();
        linkedMap.put("one", "1");
        linkedMap.put("two", "2");
        linkedMap.put("three", "3");

        System.out.println(linkedMap); // 输出: {one=1, two=2, three=3}
    }
}
```

这些高级应用实例展示了Java集合框架的灵活性和强大功能。通过合理使用这些数据结构，可以有效地解决各种复杂的数据管理问题。



`ArrayList` 是 Java 集合框架中的一部分，它是一个动态数组的数据结构。它允许存储任意类型的对象，包括 `null`。`ArrayList` 提供了动态数组的功能，这意味着它可以根据需要自动扩展容量。`ArrayList` 实现了 `List` 接口，因此它支持列表的所有操作，包括插入、删除、访问和搜索元素。



## Java ArrayList
https://www.runoob.com/java/java-arraylist.html
### 创建 ArrayList 实例

创建 `ArrayList` 实例非常简单，你可以指定它将存储的对象类型：

```java
import java.util.ArrayList;

public class ArrayListExample {
    public static void main(String[] args) {
        // 创建一个可以存储 String 类型对象的 ArrayList
        ArrayList<String> stringList = new ArrayList<>();

        // 添加元素
        stringList.add("Apple");
        stringList.add("Banana");
        stringList.add("Cherry");

        // 访问元素
        System.out.println(stringList.get(0)); // 输出: Apple

        // 遍历 ArrayList
        for (String fruit : stringList) {
            System.out.println(fruit);
        }
    }
}
```

### ArrayList 的特点

- **动态数组**：`ArrayList` 在内部通过数组实现，当数组容量不足以存储更多元素时，它会自动创建一个新的更大的数组，并将旧数组的元素复制到新数组中。
- **索引访问**：可以通过索引快速访问元素，索引从 0 开始。
- **可变大小**：`ArrayList` 的大小会根据添加或删除元素自动调整。
- **非同步**：`ArrayList` 不是线程安全的，如果多个线程同时访问同一个 `ArrayList` 实例，并且至少有一个线程修改了列表，那么它必须在外部进行同步。

### 常用方法

- `add(E element)`：在列表末尾添加指定的元素。
- `add(int index, E element)`：在列表的指定位置插入指定的元素。
- `get(int index)`：访问列表中指定位置的元素。
- `set(int index, E element)`：用指定的元素替换列表中指定位置的元素。
- `remove(int index)`：移除列表中指定位置的元素。
- `size()`：返回列表中的元素数量。
- `isEmpty()`：如果列表不包含元素，则返回 `true`。
- `contains(Object o)`：如果列表包含指定的元素，则返回 `true`。

`ArrayList` 是 Java 中使用最广泛的集合之一，适用于需要快速访问和修改元素的场景。


## Java LinkedList
https://www.runoob.com/java/java-linkedlist.html
`LinkedList` 是 Java 集合框架中的一个类，实现了 `List` 和 `Deque` 接口。它是一个双向链表结构，允许在列表的任何位置快速插入和删除元素。由于其链表的特性，`LinkedList` 不支持通过索引快速访问元素，但提供了高效的插入和删除操作。

### 创建 LinkedList 实例

创建 `LinkedList` 实例非常简单，你可以指定它将存储的对象类型：

```java
import java.util.LinkedList;

public class LinkedListExample {
    public static void main(String[] args) {
        // 创建一个可以存储 String 类型对象的 LinkedList
        LinkedList<String> linkedList = new LinkedList<>();

        // 添加元素
        linkedList.add("Apple");
        linkedList.add("Banana");
        linkedList.add("Cherry");

        // 访问元素
        System.out.println(linkedList.get(0)); // 输出: Apple

        // 遍历 LinkedList
        for (String fruit : linkedList) {
            System.out.println(fruit);
        }
    }
}
```

### LinkedList 的特点

- **双向链表**：每个节点包含数据以及指向前一个和后一个节点的引用。
- **快速插入和删除**：在链表的任何位置添加或删除元素都非常快速，因为不需要移动其他元素。
- **非同步**：`LinkedList` 不是线程安全的，如果多个线程同时访问同一个 `LinkedList` 实例，并且至少有一个线程修改了列表，那么它必须在外部进行同步。
- **非随机访问**：由于 `LinkedList` 是基于链表的，所以不能像 `ArrayList` 那样通过索引快速访问元素。访问元素需要从头节点开始遍历链表。

### 常用方法

- `add(E element)`：在链表末尾添加指定的元素。
- `add(int index, E element)`：在链表的指定位置插入指定的元素。
- `get(int index)`：访问链表中指定位置的元素。
- `set(int index, E element)`：用指定的元素替换链表中指定位置的元素。
- `remove(int index)`：移除链表中指定位置的元素。
- `size()`：返回链表中的元素数量。
- `isEmpty()`：如果链表不包含元素，则返回 `true`。
- `contains(Object o)`：如果链表包含指定的元素，则返回 `true`。

### 示例：使用 LinkedList 作为栈

`LinkedList` 也实现了 `Deque` 接口，因此可以作为栈（后进先出）使用：

```java
import java.util.LinkedList;

public class StackExample {
    public static void main(String[] args) {
        LinkedList<String> stack = new LinkedList<>();

        // 入栈操作
        stack.push("First");
        stack.push("Second");
        stack.push("Third");

        // 出栈操作
        while (!stack.isEmpty()) {
            System.out.println(stack.pop()); // 输出: Third, Second, First
        }
    }
}
```

`LinkedList` 是一个灵活的数据结构，适用于需要频繁插入和删除操作的场景，尤其是在列表的两端。然而，由于其非随机访问的特性，如果需要频繁通过索引访问元素，`ArrayList` 可能是更好的选择。



## Java HashSet
https://www.runoob.com/java/java-hashset.html
`HashSet` 是 Java 集合框架中的一个类，实现了 `Set` 接口。它基于哈希表（实际上是一个 `HashMap` 的实例）来存储唯一元素，不保证元素的顺序。`HashSet` 允许存储 `null` 值，但不允许重复元素。

### 创建 HashSet 实例

创建 `HashSet` 实例非常简单，你可以指定它将存储的对象类型：

```java
import java.util.HashSet;

public class HashSetExample {
    public static void main(String[] args) {
        // 创建一个可以存储 String 类型对象的 HashSet
         HashSet<String> hashSet = new HashSet<>();

         // 添加元素
         hashSet.add("Apple");
         hashSet.add("Banana");
         hashSet.add("Cherry");

         // 遍历 HashSet
         for (String fruit : hashSet) {
             System.out.println(fruit);
         }
     }
}
```

### HashSet 的特点

- **基于哈希表**：`HashSet` 使用哈希表来存储元素，因此它提供了非常快速的插入、删除和查找操作。
- **不允许重复**：`HashSet` 不允许存储重复的元素。
- **允许 `null` 值**：可以向 `HashSet` 中添加一个 `null` 值。
- **非同步**：`HashSet` 不是线程安全的，如果多个线程同时访问同一个 `HashSet` 实例，并且至少有一个线程修改了集合，那么它必须在外部进行同步。
- **无序集合**：`HashSet` 不保证元素的顺序，元素的迭代顺序可能与插入顺序不同。

### 常用方法

- `add(E element)`：如果集合中尚未包含指定的元素，则添加该元素。
- `remove(Object o)`：如果集合中包含指定的元素，则移除它。
- `contains(Object o)`：如果集合包含指定的元素，则返回 `true`。
- `isEmpty()`：如果集合不包含任何元素，则返回 `true`。
- `size()`：返回集合中的元素数量。

### 示例：使用 HashSet 存储自定义对象

当你使用 `HashSet` 存储自定义对象时，需要确保对象的类正确地实现了 `equals()` 和 `hashCode()` 方法，以确保 `HashSet` 能够正确地识别和管理重复元素。

```java
import java.util.HashSet;

class Person {
    private String name;

    public Person(String name) {
        this.name = name;
     }

    @Override
     public boolean equals(Object obj) {
     //this表示当前对象
     //Object类型为类
         if (this == obj) return true;
    //getClass() 方法返回当前对象的 Class 对象，它包含了关于类的详细信息，如类名、方法、字段等
         if (obj == null || getClass() != obj.getClass()) return false;
         Person person = (Person) obj;
         return name != null ? name.equals(person.name) : person.name == null;
     }

     @Override
     public int hashCode() {
         return name != null ? name.hashCode() : 0;
     }
}

public class HashSetWithCustomObject {
    public static void main(String[] args) {
         HashSet<Person> hashSet = new HashSet<>();
         hashSet.add(new Person("Alice"));
         hashSet.add(new Person("Bob"));
         hashSet.add(new Person("Alice")); // 不会添加，因为 Alice 已存在

         for (Person person : hashSet) {
             System.out.println(person.name);
         }
     }
}
```

在这个例子中，`Person` 类重写了 `equals()` 和 `hashCode()` 方法，以确保 `HashSet` 可以正确地识别 `Person` 对象是否相等。这样，即使创建了两个具有相同姓名的 `Person` 对象，`HashSet` 也只会存储一个实例。

![[IMG_20241010_113700.jpg]]


## Java HashMap
`HashMap` 是 Java 集合框架中的一个类，实现了 `Map` 接口。它存储键值对，其中每个键都是唯一的。`HashMap` 允许使用 `null` 值和 `null` 键。它不保证映射的顺序；特别是，它不保证该顺序随时间的推移保持不变。

### 创建 HashMap 实例

创建 `HashMap` 实例非常简单，你可以指定它将存储键和值的类型：

```java
import java.util.HashMap;

public class HashMapExample {
    public static void main(String[] args) {
        // 创建一个可以存储 String 键和 Integer 值的 HashMap
        HashMap<String, Integer> map = new HashMap<>();

        // 添加键值对
        map.put("Apple", 1);
        map.put("Banana", 2);
        map.put("Cherry", 3);

        // 获取值
        System.out.println(map.get("Apple")); // 输出: 1

        // 遍历 HashMap
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }
}
```

### HashMap 的特点

- **基于哈希表**：`HashMap` 使用哈希表来存储键值对，因此它提供了非常快速的插入、删除和查找操作。
- **键唯一**：每个键只能映射到一个值。
- **允许 `null` 值和 `null` 键**：可以存储一个或多个键为 `null` 的键值对。
- **非同步**：`HashMap` 不是线程安全的，如果多个线程同时访问同一个 `HashMap` 实例，并且至少有一个线程修改了集合，那么它必须在外部进行同步。
- **无序集合**：`HashMap` 不保证元素的顺序，元素的迭代顺序可能与插入顺序不同。

### 常用方法

- `put(K key, V value)`：将指定的键与值关联（插入或更新）。
- `get(Object key)`：返回与指定键关联的值，如果不存在，则返回 `null`。
- `remove(Object key)`：移除与指定键关联的键值对。
- `containsKey(Object key)`：如果此映射包含指定键的映射关系，则返回 `true`。
- `size()`：返回映射中的键值对数量。

### 示例：使用 HashMap 存储自定义对象

当你使用 `HashMap` 存储自定义对象时，需要确保对象的类正确地实现了 `equals()` 和 `hashCode()` 方法，以确保 `HashMap` 能够正确地识别和管理重复键。

```java
import java.util.HashMap;

class Person {
    private String name;

    public Person(String name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Person person = (Person) obj;
        return name != null ? name.equals(person.name) : person.name == null;
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}

public class HashMapWithCustomObject {
    public static void main(String[] args) {
        HashMap<Person, Integer> map = new HashMap<>();
        map.put(new Person("Alice"), 1);
        map.put(new Person("Bob"), 2);
        map.put(new Person("Alice"), 3); // 不会添加，因为 Alice 已存在

        for (Map.Entry<Person, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey().name + ": " + entry.getValue());
        }
    }
}
```

在这个例子中，`Person` 类重写了 `equals()` 和 `hashCode()` 方法，以确保 `HashMap` 可以正确地识别 `Person` 对象是否相等。这样，即使创建了两个具有相同姓名的 `Person` 对象，`HashMap` 也只会存储一个实例。



## Java Iterator（迭代器）
在Java中，`Iterator`是一个接口，用于提供一种方法来访问集合中的元素，而无需暴露集合的内部结构。它主要用于遍历集合（如`List`, `Set`等），并且是Java集合框架的核心部分之一。使用`Iterator`可以安全地在遍历集合时进行元素的删除操作，但不支持添加元素。

### 主要方法

- `boolean hasNext()`: 检查是否存在下一个元素，如果存在返回`true`，否则返回`false`。
- `E next()`: 返回集合中的下一个元素，并将迭代器的位置移动到下一个元素。如果迭代器已经到达集合末尾，则抛出`NoSuchElementException`。
- `void remove()`: 删除由`next()`方法返回的最后一个元素。如果在调用`next()`之前调用此方法，或者在上一次调用`next()`之后已经调用过`remove()`，则会抛出`IllegalStateException`。

### 使用示例

下面是一个使用`Iterator`遍历`ArrayList`的简单示例：

```java
import java.util.ArrayList;
import java.util.Iterator;

public class IteratorExample {
    public static void main(String[] args) {
        ArrayList<String> list = new ArrayList<>();
        list.add("Apple");
        list.add("Banana");
        list.add("Cherry");

        Iterator<String> iterator = list.iterator();
        while (iterator.hasNext()) {
            String element = iterator.next();
            System.out.println(element);
            // 如果需要在遍历时删除元素，可以使用 iterator.remove();
        }
    }
}
```

### 注意事项

- **单向遍历**：`Iterator`只能向前遍历，不能后退。
- **删除操作**：`Iterator`允许在遍历过程中安全地删除元素，但不支持添加元素。
- **并发修改**：如果在使用迭代器遍历集合的过程中，通过集合自身的`remove`方法或其他方式修改了集合（除了迭代器的`remove`方法），那么迭代器会立即抛出`ConcurrentModificationException`异常，以避免不可预见的行为。

`Iterator`是处理集合时非常重要的工具，特别是在需要在遍历过程中修改集合的场景中。对于需要双向遍历或在遍历时修改集合的更复杂场景，可以使用`ListIterator`，它是`Iterator`的一个扩展。

##### ==拓展一==：要用到Iterator类的实例必须导包
![[Screenshot_20241012_023234.jpg]]


##### ==拓展二==：调用函数返回实例，必须用他相应的类型变量来存，所以必须导包
![[Screenshot_20241012_023647.jpg]]




## Java Object 类
在Java中，`Object`类位于Java类层次结构的最顶端。它是所有类的最终父类，意味着所有的Java类（无论是直接声明的还是间接继承的）都隐式地继承自`Object`类。因此，`Object`类中定义的方法在所有Java对象中都是可用的。

### 主要方法

`Object`类提供了一些基本的方法，这些方法在所有Java对象中都可以使用：

1. `toString()`: 返回对象的字符串表示形式，通常用于调试和日志记录。
2. `equals(Object obj)`: 检查指定的对象是否与当前对象相等。
3. `hashCode()`: 返回对象的哈希码值，用于哈希表（如`HashMap`）中。
4. `getClass()`: 返回对象的运行时类。
5. `clone()`: 创建并返回当前对象的一个副本。
6. `finalize()`: 当垃圾收集器确定没有引用指向一个对象时，会调用该对象的`finalize()`方法。
7. `notify()`, `notifyAll()`, `wait()`: 这些方法用于线程间的通信。

### 注意事项

- 由于`Object`是所有类的父类，因此在Java中不能创建`Object`类的实例。
- 如果一个类没有明确地继承自其他类，则默认继承自`Object`类。
- 重写`Object`类的方法时，需要遵循Java的约定，以确保类的行为符合预期。




## Java泛型
Java泛型是Java编程语言中用于处理类型参数化的一种机制。它允许在编译时提供类型安全检查，同时避免了类型转换的需要。泛型在Java 5中引入，极大地增强了Java集合框架的类型安全性，并允许创建可重用的通用代码。

### 泛型类和接口

泛型类和接口允许在类或接口定义时使用类型参数。这些类型参数在创建类或接口的实例时会被具体化。

#### 泛型类示例

```java
//大写是类型小写是变量
public class Box<T> {
    private T t;

    public void set(T t) {
        this.t = t;
    }

    public T get() {
        return t;
    }
}
```

在这个例子中，`Box`是一个泛型类，`T`是类型参数。你可以创建不同类型的`Box`，如`Box<Integer>`, `Box<String>`等。

#### 泛型接口示例

```java
public interface List<E> {
    void add(E e);
    E get(int index);
}
```

`List`接口使用类型参数`E`，表示列表中元素的类型。

### 泛型方法

泛型方法是在方法级别上使用类型参数的。泛型方法可以在普通类中定义，也可以在泛型类中定义。

#### 泛型方法示例

```java
public class Util {
    public static <T> void printArray(T[] inputArray) {
        for (T element : inputArray) {
            System.out.printf("%s ", element);
        }
        System.out.println();
    }
}
```

在这个例子中，`printArray`是一个泛型方法，`<T>`表示方法接受的数组类型参数。

### 类型通配符

类型通配符`?`用于表示未知的类型。它经常用于泛型类或方法的参数中，以提供更灵活的类型处理。

#### 类型通配符示例

```java
public void processElements(List<?> elements) {
    for (Object element : elements) {
        System.out.println(element);
    }
}
```

在这个例子中，`processElements`方法可以接受任何类型的`List`。

### 泛型的限制

- 不能创建泛型类型的数组，例如`new T[10]`是不允许的。
- 不能实例化泛型类型参数，例如`new T()`是不允许的。
- 不能使用基本数据类型作为泛型类型参数，例如`Box<int>`是不允许的，但可以使用`Box<Integer>`。

### 泛型的好处

- **类型安全**：泛型增强了代码的类型安全性，编译器可以在编译时检查类型错误。
- **减少类型转换**：使用泛型后，不需要在运行时进行类型转换。
- **代码复用**：泛型代码可以适用于多种数据类型，提高了代码的复用性。

泛型是Java语言中一个非常重要的特性，它在集合框架、算法实现、工具类等方面提供了强大的支持，使得Java程序更加健壮和易于维护。




## Java序列化
Java序列化是指将对象状态转换为可保存或传输的格式的过程。在Java中，这种格式通常是字节流，它可以被写入文件、存储到数据库或通过网络传输到另一台计算机环境。当需要时，这些字节流可以被反序列化，即重新构造成对象。序列化机制使得对象能够在需要时跨越不同的Java虚拟机（JVM）实例或持久化存储。

### 为什么需要序列化

- **持久化存储**：将对象保存到磁盘，以便在需要时重新加载。
- **网络传输**：通过网络发送对象到远程系统。
- **缓存**：将对象状态保存在缓存中，以便快速访问。

### 如何实现序列化

要使一个类的对象可被序列化，该类必须实现`java.io.Serializable`接口。==这个接口是一个标记接口，没有包含任何方法，它的存在仅仅是为了标识哪些类的对象可以被序列化。

#### 示例

```java
import java.io.Serializable;

public class Person implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String name;
    private int age;
    
    // 构造器、getter和setter省略
    
    // Person类的其他方法
}
```

在上面的例子中，`Person`类实现了`Serializable`接口，因此它的对象可以被序列化。

#### 序列化对象

要序列化一个对象，你需要使用`ObjectOutputStream`，它负责将对象写入输出流。

```java
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SerializationExample {
    public static void main(String[] args) {
        Person person = new Person("Alice", 30);
        
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("person.ser"))) {
            out.writeObject(person);
            System.out.println("Person object has been serialized");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

#### 反序列化对象

反序列化对象需要使用`ObjectInputStream`，它负责从输入流中读取对象。

```java
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class DeserializationExample {
    public static void main(String[] args) {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("person.ser"))) {
            Person person = (Person) in.readObject();
            System.out.println("Person object has been deserialized");
            // 输出反序列化后的对象信息
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### 注意事项

- **serialVersionUID**：在`Serializable`类中，通常会声明一个`serialVersionUID`字段，这是一个版本控制的标识符。当类的结构发生变化时（比如添加或删除字段），这个标识符也应该相应地改变。如果不声明，编译器会自动生成一个，但为了确保兼容性，最好手动指定。
- **瞬态（transient）和静态（static）字段**：使用`transient`关键字标记的字段不会被序列化。静态字段也不被序列化，因为它们属于类，不属于对象实例。
- **安全性**：序列化和反序列化过程中可能涉及安全问题，特别是当对象包含敏感信息时。确保敏感数据在序列化前得到适当处理。

Java序列化是处理对象持久化和网络传输的强大工具，但需要谨慎使用，以避免潜在的安全风险。




## Java网络编程
Java网络编程允许你创建能够通过网络进行通信的应用程序。Java提供了丰富的API来处理网络编程，主要集中在`java.net`包中。网络编程可以分为两个主要部分：客户端编程和服务器端编程。

### 客户端编程

客户端编程涉及创建能够连接到服务器并与其通信的应用程序。最常用的类是`Socket`类，它代表了客户端和服务器之间的连接。

#### 示例：简单的客户端

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class SimpleClient {
    public static void main(String[] args) {
        String host = "localhost"; // 服务器地址
        int port = 12345; // 服务器端口号

        try (Socket socket = new Socket(host, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            
            // 发送消息给服务器
            out.println("Hello, Server!");

            // 读取服务器的响应
            String response = in.readLine();
            System.out.println("Server says: " + response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### 服务器端编程

服务器端编程涉及创建能够接受客户端连接并与其通信的应用程序。`ServerSocket`类用于监听特定端口的连接请求。

#### 示例：简单的服务器

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class SimpleServer {
    public static void main(String[] args) {
        int port = 12345; // 服务器监听的端口号

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server is listening on port " + port);

            // 等待客户端连接
            Socket socket = serverSocket.accept();
            System.out.println("Client connected");

            // 读取客户端发送的消息
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String inputLine = in.readLine();
            System.out.println("Received from client: " + inputLine);

            // 向客户端发送响应
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            out.println("Hello, Client!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### 注意事项

- **异常处理**：网络编程中，很多操作都可能抛出异常，如`IOException`。因此，合理地处理这些异常非常重要。
- **资源管理**：使用`try-with-resources`语句可以自动关闭资源，如`Socket`和`ServerSocket`，避免资源泄露。
- **多线程**：对于多客户端服务器，通常需要为每个客户端连接创建一个新的线程，以便并行处理多个客户端请求。
- **安全性**：网络通信可能面临安全风险，如数据篡改、重放攻击等。使用加密和认证机制（如SSL/TLS）来保护通信安全。

Java网络编程提供了强大的工具来构建客户端和服务器应用程序，使得通过网络进行数据交换变得简单。然而，网络编程也带来了复杂性，特别是在处理并发和安全性方面。




## Java发送邮件
在Java中发送邮件通常使用JavaMail API，这是一个用于处理电子邮件的API。要使用JavaMail，首先需要添加依赖到你的项目中。如果你使用Maven，可以在`pom.xml`文件中添加以下依赖：

```xml
<!-- JavaMail API -->
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>javax.mail</artifactId>
    <version>1.6.2</version>
</dependency>
```

请注意，版本号`1.6.2`是示例，你应该使用最新版本的JavaMail依赖。

### 发送邮件示例

以下是一个使用JavaMail发送邮件的基本示例：

```java
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class EmailSender {
    public static void main(String[] args) {
        // 设置邮件服务器的属性
        Properties properties = new Properties();
        properties.put("mail.smtp.host", "smtp.example.com"); // SMTP服务器地址
        properties.put("mail.smtp.port", "587"); // SMTP服务器端口
        properties.put("mail.smtp.auth", "true"); // 需要认证
        properties.put("mail.smtp.starttls.enable", "true"); // 启用TLS

        // 创建会话（Session）
        Session session = Session.getInstance(properties, new javax.mail.Authenticator() {
            protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                return new javax.mail.PasswordAuthentication("your-email@example.com", "your-password");
            }
        });

        try {
            // 创建邮件消息
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("your-email@example.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient-email@example.com"));
            message.setSubject("Test Email Subject");
            message.setText("This is a test email sent from JavaMail.");

            // 发送邮件
            Transport.send(message);
            System.out.println("Email sent successfully");
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }
}
```

### 注意事项

- **SMTP服务器**：你需要知道你的邮件服务提供商的SMTP服务器地址和端口。例如，Gmail的SMTP服务器地址是`smtp.gmail.com`，端口通常是`587`。
- **认证**：大多数邮件服务器需要认证，因此你需要提供有效的邮箱地址和密码。出于安全考虑，建议使用应用专用密码而不是你的常规邮箱密码。
- **TLS/SSL**：为了安全，邮件发送通常需要使用TLS或SSL加密。确保在属性中启用相应的设置。
- **异常处理**：发送邮件过程中可能会抛出`MessagingException`，应当妥善处理这些异常。
- **邮件内容**：邮件内容可以是纯文本，也可以是HTML格式。在上面的例子中，我们使用了`setText`方法来设置纯文本内容，如果需要发送HTML内容，可以使用`setHtml`方法。

请根据你的邮件服务提供商的具体要求调整SMTP服务器设置和认证信息。如果你使用的是Gmail或其他需要特定安全设置的邮件服务，可能需要额外的配置，如允许不够安全的应用访问等。


## Java多线程编程
Java多线程编程允许你创建多个线程来执行多个任务，从而提高程序的效率和响应性。Java提供了多种方式来实现多线程，主要集中在`java.lang.Thread`类和`java.util.concurrent`包中。

### 使用Thread类

最直接的方式是通过继承`Thread`类并重写其`run`方法来创建线程。

#### 示例

```java
public class MyThread extends Thread {
    @Override
    public void run() {
        // 线程执行的代码
        System.out.println("Thread is running");
    }

    public static void main(String[] args) {
        MyThread thread = new MyThread();
        thread.start(); // 启动线程
    }
}
```

### 使用Runnable接口

另一种方式是实现`Runnable`接口，并将实现类的实例传递给`Thread`对象。

#### 示例

```java
public class MyRunnable implements Runnable {
    @Override
    public void run() {
        // 线程执行的代码
        System.out.println("Thread is running");
    }

    public static void main(String[] args) {
        Thread thread = new Thread(new MyRunnable());
        thread.start(); // 启动线程
    }
}
```

### 使用Callable和FutureTask

`Callable`接口类似于`Runnable`，但它可以返回一个结果，并可能抛出异常。`FutureTask`可以包装`Callable`对象，并提供获取结果的方法。

#### 示例

```java
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

public class MyCallable implements Callable<String> {
    @Override
    public String call() throws Exception {
        // 线程执行的代码，并返回结果
        return "Result from Callable";
    }

    public static void main(String[] args) {
        FutureTask<String> futureTask = new FutureTask<>(new MyCallable());
        Thread thread = new Thread(futureTask);
        thread.start();

        try {
            // 获取Callable执行的结果
            String result = futureTask.get();
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### 使用ExecutorService

`ExecutorService`是Java并发API中的一个接口，用于管理线程池。它提供了一种更高级的线程管理方式。

#### 示例

```java
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ExecutorServiceExample {
    public static void main(String[] args) {
        // 创建一个固定大小的线程池
        ExecutorService executorService = Executors.newFixedThreadPool(2);

        // 提交任务到线程池
        executorService.submit(() -> System.out.println("Task 1"));
        executorService.submit(() -> System.out.println("Task 2"));

        // 关闭线程池，不再接受新任务，但会完成所有已提交的任务
        executorService.shutdown();

        try {
            // 等待所有任务完成
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
}
```

### 注意事项

- **线程安全**：当多个线程访问共享资源时，需要确保线程安全，避免竞态条件和数据不一致的问题。可以使用`synchronized`关键字、锁（`ReentrantLock`）或其他并发工具（如`AtomicInteger`）来保证线程安全。
- **资源管理**：确保线程使用的所有资源在不再需要时被正确关闭或释放。
- **异常处理**：线程中的异常不应该被忽略，应当合理处理，避免程序崩溃。
- **线程池**：对于需要频繁创建和销毁线程的场景，使用线程池可以减少资源消耗和提高性能。

Java多线程编程是构建高效、响应式应用程序的关键技术之一。合理使用线程和线程池可以显著提高应用程序的性能和资源利用率。


## Java Applet 基础
Java Applet 是一种小型的Java应用程序，它通常嵌入在网页中，并在支持Java的Web浏览器内运行。Applet利用了完整的Java API支持，因此它是一个全功能的Java应用程序。以下是关于Java Applet的一些基础知识：

### Applet的特点

- **嵌入式运行**：Applet被设计为嵌入在HTML页面中，当用户浏览包含Applet的HTML页面时，Applet的代码会被下载到用户的机器上。
- **沙箱安全**：Applet运行在Web浏览器强制执行的严格安全规则下，这种安全机制被称为沙箱安全。这意味着Applet不能访问本地文件系统、网络等资源，除非特别授权。
- **生命周期管理**：Applet有特定的生命周期，包括初始化（init）、启动（start）、停止（stop）和销毁（destroy）等阶段。浏览器或Applet查看器会调用这些方法来管理Applet的生命周期。

### Applet的生命周期

- **init()**：此方法的目的是为Applet提供所需的任何初始化。在Applet标签内的param标签被处理后调用该方法。
- **start()**：浏览器调用init方法后，此方法被自动调用。每当用户从其他页面返回到包含Applet的页面时，则调用该方法。
- **stop()**：当用户从包含Applet的页面移除的时候，此方法自动被调用。因此，可以在相同的Applet中反复调用该方法。
- **destroy()**：此方法仅当浏览器正常关闭时调用。因为Applet只有在HTML网页上有效，所以你不应该在用户离开包含Applet的页面后遗漏任何资源。
- **paint()**：此方法在start()方法之后立即被调用，或者在Applet需要重绘在浏览器的时候调用。paint()方法实际上继承于java.awt。

### Applet的使用

要在HTML页面中嵌入Applet，可以使用`<applet>`标签。以下是一个简单的例子：

```html
<html>
    <title>The Hello, World Applet</title>
    <applet code="HelloWorldApplet.class" width="320" height="120">
        If your browser was Java-enabled, a "Hello, World" message would appear here.
    </applet>
</html>
```

在这个例子中，`<applet>`标签的`code`属性指定了要运行的Applet类。`width`和`height`属性用来指定Applet运行面板的初始大小。

### 注意事项

- **安全性**：由于安全原因，现代浏览器已经不再支持Applet。因此，Applet技术已经逐渐被其他技术（如JavaScript和HTML5）所取代。
- **替代方案**：如果你需要在网页中嵌入交互式内容，可以考虑使用JavaScript、Web Components、或者框架如React、Vue等。

尽管Applet技术已经不再被广泛使用，了解其基础知识对于理解Java早期的Web开发技术仍然具有一定的价值。



## Java文档注释

在Java中，文档注释（也称为Javadoc注释）是一种特殊的注释方式，用于生成API文档。Javadoc注释使用特定的标记（tags）来描述类、方法、字段等的用途、参数、返回值和可能抛出的异常等信息。这些注释被Javadoc工具读取，并生成格式化的HTML文档。

### 文档注释的格式

文档注释以`/**`开始，以`*/`结束。每个Javadoc注释通常包含以下部分：

- **概述描述**：注释的第一段，通常是一个简洁的描述，用于概述类、方法或字段的功能。
- **详细描述**：紧随概述描述之后，可以包含更详细的说明。
- **标记（Tags）**：以`@`符号开始，用于提供特定类型的信息，如参数、返回值、异常等。

### 常用的Javadoc标记

- `@author`：指定类或接口的作者。
- `@version`：指定类或接口的版本。
- `@param`：描述方法的参数。
- `@return`：描述方法的返回值。
- `@throws` 或 `@exception`：描述方法可能抛出的异常。
- `@see`：提供一个参考链接，指向其他相关类、方法或文档。
- `@since`：指定该类或方法是从哪个版本开始引入的。
- `@deprecated`：标记已弃用的类、方法或字段，建议用户使用新的替代项。

### 示例

```java
/**
 * This is a simple class to demonstrate Javadoc comments.
 *
 * @author Your Name
 * @version 1.0
 */
public class MyClass {
    /**
     * This method adds two integers and returns the result.
     *
     * @param a the first integer to add
     * @param b the second integer to add
     * @return the sum of a and b
     */
    public int add(int a, int b) {
        return a + b;
    }
}
```

### 生成Javadoc文档

要生成Javadoc文档，可以使用JDK提供的`javadoc`工具。在命令行中，导航到包含Java源文件的目录，然后运行以下命令：

```sh
javadoc -d <output-directory> *.java
```

这里`<output-directory>`是你希望生成的文档存放的目录，`*.java`表示当前目录下所有的Java源文件。

### 注意事项

- **保持注释的简洁和相关性**：Javadoc注释应该简洁明了，只包含与API文档相关的信息。
- **遵循标准格式**：使用标准的Javadoc格式可以帮助用户更好地理解和使用你的代码。
- **更新文档**：随着代码的更新，确保文档注释也得到相应的更新。

Javadoc注释是Java开发中非常重要的一个部分，它有助于提高代码的可读性和可维护性，同时为其他开发者或用户提供了清晰的API文档。


## Java 8 新特性
Java 8是Java语言的一个重要版本，引入了许多新特性，这些特性旨在简化代码、提高开发效率以及增强Java语言的表达能力。下面是一些Java 8的关键新特性：

### 1. Lambda表达式

Lambda表达式是Java 8引入的一个核心特性，它允许你以更简洁的方式表示匿名内部类。Lambda表达式可以被看作是简洁的函数式接口实现。

```java
// 使用Lambda表达式简化代码
button.addActionListener(e -> System.out.println("Clicked"));
```

### 2. Stream API

Stream API提供了一种高效且易于使用的处理数据的方式。它允许你以声明式处理数据集合，支持过滤、映射、归约、查找等操作。

```java
List<String> names = Arrays.asList("Alice", "Bob", "Charlie");
names.stream()
     .filter(name -> name.startsWith("A"))
     .forEach(System.out::println);
```

### 3. 接口中的默认方法和静态方法

Java 8允许在接口中定义默认方法和静态方法，这为接口的演进提供了更大的灵活性。

```java
public interface MyInterface {
    default void defaultMethod() {
        System.out.println("This is a default method");
    }

    static void staticMethod() {
        System.out.println("This is a static method");
    }
}
```

### 4. 新的日期时间API

新的日期时间API（java.time包）提供了更好的日期和时间处理能力，解决了旧的`java.util.Date`和`Calendar`类的许多问题。

```java
LocalDate date = LocalDate.of(2023, 3, 15);
LocalTime time = LocalTime.of(10, 30);
LocalDateTime dateTime = LocalDateTime.of(date, time);
```

### 5. 方法引用

方法引用提供了一种引用方法而不执行它的简洁方式，可以与Lambda表达式结合使用。

```java
// 引用静态方法
Function<String, Integer> stringLength = String::length;

// 引用实例方法
BiPredicate<String, String> startsWith = String::startsWith;

// 引用构造函数
Supplier<List<String>> listFactory = ArrayList::new;
```

### 6. Optional类

`Optional`类是一个容器对象，它可能包含也可能不包含非`null`的值。它用于避免`NullPointerException`，并提供了一种优雅的方式来处理可能为空的值。

```java
Optional<String> optional = Optional.of("Hello");
optional.ifPresent(System.out::println);
```

### 7. Nashorn JavaScript引擎

Nashorn是一个高性能的JavaScript引擎，允许在Java平台上运行JavaScript代码。

### 8. 并行数组和集合

Java 8引入了并行流（parallel streams），允许集合和数组以并行方式处理，从而提高大规模数据处理的性能。

```java
List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5);
int sum = numbers.parallelStream().mapToInt(n -> n).sum();
```

### 9. 新的Map API

Java 8为`Map`接口添加了几个有用的方法，如`forEach`、`compute`、`merge`等。

```java
Map<String, Integer> map = new HashMap<>();
map.put("one", 1);
map.put("two", 2);
map.forEach((key, value) -> System.out.println(key + " : " + value));
```

### 10. 新的类型注解

Java 8引入了类型注解，允许在任何使用类型的地方使用注解，例如泛型声明、类型转换等。

Java 8的这些新特性极大地增强了Java语言的功能，使得Java开发更加高效和现代化。这些特性在现代Java开发中被广泛使用，是学习Java时必须掌握的重要内容。




## Java MySQL 连接
在Java中连接MySQL数据库，通常需要使用JDBC（Java Database Connectivity）API。为了连接MySQL，你还需要MySQL提供的JDBC驱动程序。以下是连接MySQL数据库的基本步骤：

### 步骤 1: 添加MySQL JDBC驱动依赖

如果你使用Maven，可以在`pom.xml`文件中添加以下依赖：

```xml
<!-- MySQL JDBC Driver -->
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>8.0.23</version> <!-- 请使用最新的版本号 -->
</dependency>
```

如果你不使用Maven，需要手动下载MySQL JDBC驱动（`mysql-connector-java-x.x.xx-bin.jar`），然后将其添加到项目的类路径中。

### 步骤 2: 加载驱动并建立连接

```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class MySQLConnection {
    public static void main(String[] args) {
        // 数据库URL，通常格式为jdbc:mysql://<host>:<port>/<database>
        String url = "jdbc:mysql://localhost:3306/your_database";
        // 数据库用户名
        String user = "your_username";
        // 数据库密码
        String password = "your_password";

        Connection conn = null;
        try {
            // 加载并注册JDBC驱动
            Class.forName("com.mysql.cj.jdbc.Driver");
            // 建立连接
            conn = DriverManager.getConnection(url, user, password);
            System.out.println("Connected to the MySQL server successfully.");
        } catch (ClassNotFoundException e) {
            System.out.println("MySQL JDBC Driver not found.");
            e.printStackTrace();
        } catch (SQLException e) {
            System.out.println("Connection to the database failed.");
            e.printStackTrace();
        } finally {
            // 关闭连接
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

### 注意事项

- **驱动版本**：确保你使用的JDBC驱动版本与你的MySQL服务器版本兼容。
- **异常处理**：连接数据库时可能会抛出`ClassNotFoundException`和`SQLException`，应当妥善处理这些异常。
- **资源管理**：使用`try-with-resources`语句可以自动关闭资源，避免资源泄露。
- **安全性**：出于安全考虑，不要在代码中硬编码数据库的用户名和密码。考虑使用配置文件或环境变量来管理敏感信息。
- **连接池**：对于生产环境，建议使用连接池来管理数据库连接，以提高性能和资源利用率。

以上步骤展示了如何在Java中连接到MySQL数据库。在实际应用中，你可能还需要执行SQL语句、处理结果集等操作，这些可以通过`Statement`或`PreparedStatement`以及`ResultSet`等类来完成。


## Java 9新特性
Java 9引入了多项新特性，旨在增强Java平台的模块化、性能和开发者的生产力。以下是Java 9的一些主要新特性：

### 1. 平台模块系统（Jigsaw项目）

Java 9引入了模块系统，这是Jigsaw项目的一部分，旨在简化大型应用程序的构建和维护。模块系统允许开发者将代码组织成模块，每个模块可以定义自己的依赖关系和公共API。这有助于减少应用程序的大小，并提高其安全性。

### 2. 接口私有方法

Java 9允许在接口中声明私有方法。这使得接口可以包含辅助方法，这些方法可以被接口中的默认方法或静态方法调用，但对外部不可见。

### 3. Try-With Resources改进

Java 9扩展了try-with-resources语句，允许使用非final或effectively-final变量，这使得资源管理更加灵活。

### 4. 匿名类改进

Java 9允许在匿名类中使用钻石运算符（<>），这简化了匿名类的创建过程。

### 5. @SafeVarargs注释

Java 9允许将@SafeVarargs注释应用于接受varargs参数的方法或构造函数，以确保这些方法不会对varargs参数执行不安全的操作。

### 6. 集合工厂方法

Java 9为集合接口添加了工厂方法，如`List.of()`, `Set.of()`, `Map.of()`等，用于创建不可变集合实例。

### 7. Process API改进

Java 9改进了Process API，引入了`java.lang.ProcessHandle`接口，用于更好地管理和控制操作系统进程。

### 8. 新版本字符串方案

Java 9引入了一种新的版本字符串方案，它由主要版本、次要版本、安全版本和修补程序更新版本组成。

### 9. JShell: Java Shell (REPL)

JShell是一个交互式Java REPL工具，允许开发者直接执行Java代码并立即查看结果，非常适合快速测试和学习Java语言。

### 10. 控制面板

Java 9重写了控制面板，使其成为JavaFX应用程序，并改变了存储位置。

### 11. 流API改进

Java 9对流API进行了改进，添加了新的方法如`dropWhile`, `takeWhile`, `ofNullable`等，以及对`iterate`方法的重载，以支持更复杂的流操作。

### 12. 针对Microsoft Windows及更多应用程序的安装程序增强功能

Java 9包括了针对Microsoft Windows及其他应用程序的安装程序增强功能，使得安装和配置Java应用程序更加容易。

以上是Java 9的一些核心新特性，它们为Java开发者提供了新的工具和方法，以构建更加模块化、高效和安全的应用程序。




# Java实例
### 1. [菜鸟教程实例](https://www.runoob.com/java/java-examples.html)




