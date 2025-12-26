

> Python 是一种简洁、易读、功能强大的高级编程语言，广泛应用于 Web 开发、数据科学、AI 等领域
> 本笔记基于 Python 3.10.x，涵盖从入门到进阶的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [数据类型](#3-数据类型)
4. [运算符](#4-运算符)
5. [流程控制](#5-流程控制)
6. [函数](#6-函数)
7. [面向对象](#7-面向对象)
8. [模块与包](#8-模块与包)
9. [文件操作](#9-文件操作)
10. [异常处理](#10-异常处理)
11. [迭代器与生成器](#11-迭代器与生成器)
12. [装饰器](#12-装饰器)
13. [并发编程](#13-并发编程)
14. [类型提示](#14-类型提示)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Python？

Python 是由 Guido van Rossum 于 1991 年创建的编程语言。它的设计哲学强调代码的可读性和简洁性。

**Python 的特点：**
- **简洁易学**：语法简单，接近自然语言
- **解释型**：无需编译，直接运行
- **动态类型**：变量无需声明类型
- **跨平台**：Windows、Linux、Mac 都能运行
- **丰富的库**：标准库强大，第三方库众多

### 1.2 第一个程序

```python
print("Hello, Python!")
```

---

## 2. 环境搭建

### 2.1 安装 Python

```bash
# Windows: 从 python.org 下载，安装时勾选 "Add Python to PATH"
# Linux: sudo apt install python3.10
# Mac: brew install python@3.10

# 验证安装
python --version
pip --version
```

### 2.2 虚拟环境

虚拟环境可以为每个项目创建独立的 Python 环境，避免依赖冲突。

```bash
# 创建虚拟环境
python -m venv myenv

# 激活虚拟环境
# Windows
myenv\Scripts\activate
# Linux/Mac
source myenv/bin/activate

# 退出虚拟环境
deactivate

# 查看已安装的包
pip list

# 导出依赖
pip freeze > requirements.txt

# 安装依赖
pip install -r requirements.txt
```

### 2.3 pip 包管理

```bash
# 安装包
pip install package_name
pip install package_name==1.0.0  # 指定版本

# 升级包
pip install --upgrade package_name

# 卸载包
pip uninstall package_name

# 搜索包
pip search package_name

# 配置国内镜像（加速下载）
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

---

## 3. 数据类型

### 3.1 数字类型

```python
# 整数 (int) - 无大小限制
a = 10
b = -5
c = 0b1010      # 二进制 = 10
d = 0o12        # 八进制 = 10
e = 0xA         # 十六进制 = 10
big = 10 ** 100  # 支持任意大整数

# 浮点数 (float)
f = 3.14
g = 2.5e-3      # 科学计数法 = 0.0025

# 复数 (complex)
h = 3 + 4j
print(h.real)   # 实部: 3.0
print(h.imag)   # 虚部: 4.0

# 类型转换
int("123")      # 字符串转整数
float("3.14")   # 字符串转浮点
str(123)        # 数字转字符串

# 数学运算
print(10 / 3)   # 除法: 3.333...
print(10 // 3)  # 整除: 3
print(10 % 3)   # 取余: 1
print(2 ** 10)  # 幂运算: 1024
```

### 3.2 字符串 (str)

```python
# 创建字符串
s1 = 'Hello'
s2 = "World"
s3 = '''多行
字符串'''
s4 = """也可以
用双引号"""

# 字符串是不可变的
s = "hello"
# s[0] = 'H'  # ❌ 错误！

# 字符串操作
s = "Hello, World!"
print(len(s))           # 长度: 13
print(s[0])             # 索引: H
print(s[-1])            # 负索引: !
print(s[0:5])           # 切片: Hello
print(s[::2])           # 步长: Hlo ol!
print(s[::-1])          # 反转: !dlroW ,olleH

# 常用方法
s = "  hello world  "
print(s.strip())        # 去除两端空白
print(s.upper())        # 转大写
print(s.lower())        # 转小写
print(s.replace("world", "python"))  # 替换
print(s.split())        # 分割: ['hello', 'world']
print("-".join(['a', 'b', 'c']))     # 连接: a-b-c
print("hello".startswith("he"))      # True
print("hello".endswith("lo"))        # True
print("hello".find("l"))             # 查找: 2
print("hello".count("l"))            # 计数: 2

# 格式化字符串
name = "Alice"
age = 25

# f-string (推荐，Python 3.6+)
print(f"Name: {name}, Age: {age}")
print(f"Next year: {age + 1}")
print(f"Pi: {3.14159:.2f}")  # 保留2位小数

# format 方法
print("Name: {}, Age: {}".format(name, age))
print("Name: {n}, Age: {a}".format(n=name, a=age))

# % 格式化（旧方式）
print("Name: %s, Age: %d" % (name, age))
```

### 3.3 列表 (list)

列表是 Python 中最常用的数据结构，可以存储任意类型的元素，且可以修改。

```python
# 创建列表
lst = [1, 2, 3, 4, 5]
mixed = [1, "hello", 3.14, True, [1, 2]]  # 可以混合类型
empty = []
from_range = list(range(5))  # [0, 1, 2, 3, 4]

# 访问元素
print(lst[0])       # 第一个: 1
print(lst[-1])      # 最后一个: 5
print(lst[1:3])     # 切片: [2, 3]
print(lst[::2])     # 步长: [1, 3, 5]

# 修改元素
lst[0] = 10
lst[1:3] = [20, 30]

# 添加元素
lst.append(6)           # 末尾添加
lst.insert(0, 0)        # 指定位置插入
lst.extend([7, 8, 9])   # 扩展列表
lst += [10, 11]         # 同 extend

# 删除元素
lst.pop()               # 删除并返回最后一个
lst.pop(0)              # 删除并返回指定位置
lst.remove(5)           # 删除第一个匹配的值
del lst[0]              # 删除指定位置
lst.clear()             # 清空列表

# 查找
lst = [1, 2, 3, 2, 1]
print(2 in lst)         # True
print(lst.index(2))     # 第一个2的位置: 1
print(lst.count(2))     # 2出现的次数: 2

# 排序
lst = [3, 1, 4, 1, 5, 9]
lst.sort()              # 原地排序
lst.sort(reverse=True)  # 降序
sorted_lst = sorted(lst)  # 返回新列表
lst.reverse()           # 原地反转

# 列表推导式（非常重要！）
squares = [x**2 for x in range(10)]
evens = [x for x in range(20) if x % 2 == 0]
matrix = [[i*j for j in range(3)] for i in range(3)]

# 嵌套列表
matrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]
print(matrix[1][2])  # 6

# 列表解包
a, b, c = [1, 2, 3]
first, *rest = [1, 2, 3, 4, 5]  # first=1, rest=[2,3,4,5]
first, *middle, last = [1, 2, 3, 4, 5]  # middle=[2,3,4]
```

### 3.4 元组 (tuple)

元组与列表类似，但是不可变的。适合存储不应该被修改的数据。

```python
# 创建元组
t = (1, 2, 3)
t = 1, 2, 3           # 括号可省略
single = (1,)         # 单元素元组必须加逗号
empty = ()
from_list = tuple([1, 2, 3])

# 访问（与列表相同）
print(t[0])
print(t[1:])

# 元组是不可变的
# t[0] = 10  # ❌ 错误！

# 但如果元组包含可变对象，该对象可以修改
t = ([1, 2], [3, 4])
t[0].append(3)  # ✅ 可以

# 元组解包
x, y, z = (1, 2, 3)
a, b = b, a  # 交换变量

# 命名元组（更有意义的元组）
from collections import namedtuple

Point = namedtuple('Point', ['x', 'y'])
p = Point(3, 4)
print(p.x, p.y)  # 3 4
print(p[0], p[1])  # 也可以用索引
```

### 3.5 字典 (dict)

字典是键值对的集合，查找速度极快（O(1)）。

```python
# 创建字典
d = {'name': 'Alice', 'age': 25}
d = dict(name='Alice', age=25)
d = dict([('name', 'Alice'), ('age', 25)])
empty = {}

# 访问
print(d['name'])        # Alice
print(d.get('name'))    # Alice
print(d.get('gender', 'Unknown'))  # 默认值

# 修改/添加
d['age'] = 26
d['gender'] = 'Female'

# 删除
del d['gender']
age = d.pop('age')      # 删除并返回
d.clear()               # 清空

# 遍历
d = {'a': 1, 'b': 2, 'c': 3}
for key in d:
    print(key, d[key])

for key, value in d.items():
    print(key, value)

for key in d.keys():
    print(key)

for value in d.values():
    print(value)

# 常用方法
print('a' in d)         # 检查键是否存在
print(d.keys())         # 所有键
print(d.values())       # 所有值
print(d.items())        # 所有键值对
d.update({'d': 4})      # 更新/合并

# 字典推导式
squares = {x: x**2 for x in range(5)}
# {0: 0, 1: 1, 2: 4, 3: 9, 4: 16}

# 合并字典（Python 3.9+）
d1 = {'a': 1}
d2 = {'b': 2}
merged = d1 | d2        # {'a': 1, 'b': 2}
d1 |= d2                # 原地合并
```

### 3.6 集合 (set)

集合是无序、不重复元素的集合，适合去重和集合运算。

```python
# 创建集合
s = {1, 2, 3, 3, 2, 1}  # {1, 2, 3} 自动去重
s = set([1, 2, 3, 3])
empty = set()  # 注意：{} 是空字典

# 添加/删除
s.add(4)
s.remove(4)     # 不存在会报错
s.discard(4)    # 不存在不报错
s.pop()         # 随机删除一个
s.clear()

# 集合运算
a = {1, 2, 3, 4}
b = {3, 4, 5, 6}

print(a | b)    # 并集: {1, 2, 3, 4, 5, 6}
print(a & b)    # 交集: {3, 4}
print(a - b)    # 差集: {1, 2}
print(a ^ b)    # 对称差集: {1, 2, 5, 6}

print(a.union(b))
print(a.intersection(b))
print(a.difference(b))
print(a.symmetric_difference(b))

# 子集/超集
print({1, 2} <= {1, 2, 3})  # 子集: True
print({1, 2, 3} >= {1, 2})  # 超集: True

# 集合推导式
squares = {x**2 for x in range(10)}

# 冻结集合（不可变集合）
fs = frozenset([1, 2, 3])
# fs.add(4)  # ❌ 错误！
```

### 3.7 布尔类型与 None

```python
# 布尔值
True
False

# 假值（以下都被视为 False）
False
None
0
0.0
''
[]
{}
set()

# 布尔运算
print(True and False)   # False
print(True or False)    # True
print(not True)         # False

# None（表示空值）
x = None
print(x is None)        # True（推荐用 is 判断）
print(x == None)        # True（不推荐）

# 类型检查
print(type(123))        # <class 'int'>
print(isinstance(123, int))  # True
print(isinstance(123, (int, float)))  # True
```

---

## 4. 运算符

### 4.1 算术运算符

```python
a, b = 10, 3

print(a + b)    # 加法: 13
print(a - b)    # 减法: 7
print(a * b)    # 乘法: 30
print(a / b)    # 除法: 3.333...
print(a // b)   # 整除: 3
print(a % b)    # 取余: 1
print(a ** b)   # 幂: 1000
print(-a)       # 取负: -10

# 复合赋值
a += 1  # a = a + 1
a -= 1
a *= 2
a /= 2
a //= 2
a %= 2
a **= 2
```

### 4.2 比较运算符

```python
a, b = 10, 20

print(a == b)   # 等于: False
print(a != b)   # 不等于: True
print(a > b)    # 大于: False
print(a < b)    # 小于: True
print(a >= b)   # 大于等于: False
print(a <= b)   # 小于等于: True

# 链式比较
x = 5
print(1 < x < 10)   # True
print(1 < x and x < 10)  # 等价写法
```

### 4.3 逻辑运算符

```python
a, b = True, False

print(a and b)  # 与: False
print(a or b)   # 或: True
print(not a)    # 非: False

# 短路求值
# and: 第一个为假，返回第一个；否则返回第二个
# or: 第一个为真，返回第一个；否则返回第二个
print(0 and 1)      # 0
print(1 and 2)      # 2
print(0 or 1)       # 1
print(1 or 2)       # 1

# 实际应用
name = input_name or "Anonymous"  # 默认值
result = condition and value1 or value2  # 三元表达式（不推荐）
```

### 4.4 位运算符

```python
a, b = 0b1010, 0b1100  # 10, 12

print(bin(a & b))   # 与: 0b1000 (8)
print(bin(a | b))   # 或: 0b1110 (14)
print(bin(a ^ b))   # 异或: 0b0110 (6)
print(bin(~a))      # 取反: -0b1011 (-11)
print(bin(a << 2))  # 左移: 0b101000 (40)
print(bin(a >> 2))  # 右移: 0b10 (2)
```

### 4.5 成员与身份运算符

```python
# 成员运算符
lst = [1, 2, 3]
print(1 in lst)     # True
print(4 not in lst) # True

# 身份运算符
a = [1, 2, 3]
b = [1, 2, 3]
c = a

print(a == b)   # True（值相等）
print(a is b)   # False（不是同一对象）
print(a is c)   # True（是同一对象）

# 注意：小整数和短字符串会被缓存
x = 256
y = 256
print(x is y)   # True（被缓存）

x = 257
y = 257
print(x is y)   # False（不一定，取决于实现）
```

### 4.6 海象运算符（Python 3.8+）

海象运算符 `:=` 允许在表达式中赋值。

```python
# 传统写法
line = input()
while line != 'quit':
    print(line)
    line = input()

# 使用海象运算符
while (line := input()) != 'quit':
    print(line)

# 在列表推导式中使用
data = [1, 2, 3, 4, 5]
results = [y for x in data if (y := x * 2) > 4]
# [6, 8, 10]

# 在条件表达式中使用
if (n := len(data)) > 3:
    print(f"List has {n} elements")
```

---

## 5. 流程控制

### 5.1 条件语句

```python
# if-elif-else
age = 18

if age < 18:
    print("未成年")
elif age < 60:
    print("成年人")
else:
    print("老年人")

# 单行条件表达式（三元运算符）
status = "成年" if age >= 18 else "未成年"

# 多条件
if 18 <= age < 60:
    print("工作年龄")

# 条件嵌套
if age >= 18:
    if age < 60:
        print("成年工作者")
```

### 5.2 match-case（Python 3.10+）

这是 Python 3.10 的重要新特性，类似其他语言的 switch-case，但更强大。

```python
# 基本用法
def http_status(status):
    match status:
        case 200:
            return "OK"
        case 404:
            return "Not Found"
        case 500:
            return "Internal Server Error"
        case _:  # 默认情况
            return "Unknown"

# 匹配多个值
match status:
    case 200 | 201 | 204:
        return "Success"
    case 400 | 401 | 403 | 404:
        return "Client Error"

# 匹配序列
match point:
    case (0, 0):
        print("Origin")
    case (0, y):
        print(f"On Y axis at {y}")
    case (x, 0):
        print(f"On X axis at {x}")
    case (x, y):
        print(f"Point at ({x}, {y})")

# 匹配字典
match config:
    case {"debug": True}:
        print("Debug mode")
    case {"host": host, "port": port}:
        print(f"Server at {host}:{port}")

# 匹配类
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

match point:
    case Point(x=0, y=0):
        print("Origin")
    case Point(x=x, y=y):
        print(f"Point({x}, {y})")

# 带守卫条件
match point:
    case (x, y) if x == y:
        print("On diagonal")
    case (x, y):
        print(f"Not on diagonal")
```

### 5.3 循环语句

```python
# for 循环
for i in range(5):
    print(i)  # 0, 1, 2, 3, 4

for i in range(1, 10, 2):  # 起始, 结束, 步长
    print(i)  # 1, 3, 5, 7, 9

# 遍历列表
fruits = ['apple', 'banana', 'cherry']
for fruit in fruits:
    print(fruit)

# 带索引遍历
for i, fruit in enumerate(fruits):
    print(f"{i}: {fruit}")

for i, fruit in enumerate(fruits, start=1):  # 从1开始
    print(f"{i}: {fruit}")

# 遍历字典
d = {'a': 1, 'b': 2}
for key, value in d.items():
    print(f"{key}: {value}")

# 同时遍历多个序列
names = ['Alice', 'Bob']
ages = [25, 30]
for name, age in zip(names, ages):
    print(f"{name} is {age}")

# while 循环
count = 0
while count < 5:
    print(count)
    count += 1

# break 和 continue
for i in range(10):
    if i == 3:
        continue  # 跳过本次
    if i == 7:
        break     # 退出循环
    print(i)

# else 子句（循环正常结束时执行）
for i in range(5):
    if i == 10:
        break
else:
    print("循环正常结束")  # 会执行

for i in range(5):
    if i == 3:
        break
else:
    print("循环正常结束")  # 不会执行
```

---

## 6. 函数

### 6.1 函数定义与调用

```python
# 基本定义
def greet(name):
    """这是文档字符串，描述函数功能"""
    return f"Hello, {name}!"

# 调用
result = greet("Alice")
print(result)

# 无返回值（返回 None）
def say_hello():
    print("Hello!")

# 多返回值（实际返回元组）
def get_info():
    return "Alice", 25, "Female"

name, age, gender = get_info()
```

### 6.2 参数类型

```python
# 位置参数
def add(a, b):
    return a + b

add(1, 2)

# 默认参数
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"

greet("Alice")           # Hello, Alice!
greet("Alice", "Hi")     # Hi, Alice!

# ⚠️ 默认参数陷阱：不要用可变对象作为默认值
def bad_append(item, lst=[]):  # ❌ 错误！
    lst.append(item)
    return lst

def good_append(item, lst=None):  # ✅ 正确
    if lst is None:
        lst = []
    lst.append(item)
    return lst

# 关键字参数
def person(name, age, city):
    print(f"{name}, {age}, {city}")

person(name="Alice", age=25, city="Beijing")
person("Alice", city="Beijing", age=25)  # 可以混用

# 可变位置参数 (*args)
def sum_all(*args):
    return sum(args)

sum_all(1, 2, 3, 4, 5)  # 15

# 可变关键字参数 (**kwargs)
def print_info(**kwargs):
    for key, value in kwargs.items():
        print(f"{key}: {value}")

print_info(name="Alice", age=25)

# 混合使用
def func(a, b, *args, c=10, **kwargs):
    print(f"a={a}, b={b}")
    print(f"args={args}")
    print(f"c={c}")
    print(f"kwargs={kwargs}")

func(1, 2, 3, 4, c=20, x=100, y=200)

# 仅限关键字参数（* 后面的参数）
def func(a, b, *, c, d):
    pass

func(1, 2, c=3, d=4)  # ✅
# func(1, 2, 3, 4)    # ❌ 错误

# 仅限位置参数（Python 3.8+，/ 前面的参数）
def func(a, b, /, c, d):
    pass

func(1, 2, c=3, d=4)  # ✅
func(1, 2, 3, d=4)    # ✅
# func(a=1, b=2, c=3, d=4)  # ❌ 错误
```

### 6.3 Lambda 表达式

Lambda 是匿名函数，适合简单的一次性函数。

```python
# 基本语法
add = lambda x, y: x + y
print(add(1, 2))  # 3

# 常与高阶函数配合使用
numbers = [1, 2, 3, 4, 5]

# map
squares = list(map(lambda x: x**2, numbers))

# filter
evens = list(filter(lambda x: x % 2 == 0, numbers))

# sorted
students = [('Alice', 25), ('Bob', 20), ('Charlie', 30)]
sorted_by_age = sorted(students, key=lambda x: x[1])

# reduce
from functools import reduce
total = reduce(lambda x, y: x + y, numbers)
```

### 6.4 高阶函数

```python
# 函数作为参数
def apply(func, value):
    return func(value)

result = apply(lambda x: x * 2, 5)  # 10

# 函数作为返回值
def multiplier(n):
    def multiply(x):
        return x * n
    return multiply

double = multiplier(2)
triple = multiplier(3)
print(double(5))  # 10
print(triple(5))  # 15

# 闭包
def counter():
    count = 0
    def increment():
        nonlocal count  # 声明使用外层变量
        count += 1
        return count
    return increment

c = counter()
print(c())  # 1
print(c())  # 2
print(c())  # 3
```

---

## 7. 面向对象

### 7.1 类的定义

```python
class Person:
    """人类"""
    
    # 类属性（所有实例共享）
    species = "Homo sapiens"
    
    # 构造方法
    def __init__(self, name, age):
        # 实例属性
        self.name = name
        self.age = age
        self._protected = "受保护"  # 约定：单下划线表示受保护
        self.__private = "私有"     # 双下划线表示私有
    
    # 实例方法
    def greet(self):
        return f"Hello, I'm {self.name}"
    
    # 类方法
    @classmethod
    def from_string(cls, s):
        name, age = s.split(',')
        return cls(name, int(age))
    
    # 静态方法
    @staticmethod
    def is_adult(age):
        return age >= 18
    
    # 属性装饰器
    @property
    def info(self):
        return f"{self.name}, {self.age}"
    
    @info.setter
    def info(self, value):
        self.name, age = value.split(',')
        self.age = int(age)
    
    # 特殊方法
    def __str__(self):
        return f"Person({self.name}, {self.age})"
    
    def __repr__(self):
        return f"Person('{self.name}', {self.age})"
    
    def __eq__(self, other):
        return self.name == other.name and self.age == other.age

# 使用
p = Person("Alice", 25)
print(p.name)           # Alice
print(p.greet())        # Hello, I'm Alice
print(Person.species)   # Homo sapiens

# 类方法
p2 = Person.from_string("Bob,30")

# 静态方法
print(Person.is_adult(20))  # True

# 属性
print(p.info)           # Alice, 25
p.info = "Charlie,35"
print(p.name)           # Charlie
```

### 7.2 继承

```python
class Animal:
    def __init__(self, name):
        self.name = name
    
    def speak(self):
        raise NotImplementedError("子类必须实现此方法")

class Dog(Animal):
    def __init__(self, name, breed):
        super().__init__(name)  # 调用父类构造
        self.breed = breed
    
    def speak(self):
        return f"{self.name} says Woof!"

class Cat(Animal):
    def speak(self):
        return f"{self.name} says Meow!"

# 使用
dog = Dog("Buddy", "Golden Retriever")
cat = Cat("Whiskers")

print(dog.speak())  # Buddy says Woof!
print(cat.speak())  # Whiskers says Meow!

# 检查继承关系
print(isinstance(dog, Dog))     # True
print(isinstance(dog, Animal))  # True
print(issubclass(Dog, Animal))  # True

# 多重继承
class A:
    def method(self):
        print("A")

class B(A):
    def method(self):
        print("B")
        super().method()

class C(A):
    def method(self):
        print("C")
        super().method()

class D(B, C):
    def method(self):
        print("D")
        super().method()

d = D()
d.method()  # D B C A（MRO 顺序）
print(D.__mro__)  # 方法解析顺序
```

### 7.3 特殊方法（魔术方法）

```python
class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    # 字符串表示
    def __str__(self):
        return f"Vector({self.x}, {self.y})"
    
    def __repr__(self):
        return f"Vector({self.x}, {self.y})"
    
    # 运算符重载
    def __add__(self, other):
        return Vector(self.x + other.x, self.y + other.y)
    
    def __sub__(self, other):
        return Vector(self.x - other.x, self.y - other.y)
    
    def __mul__(self, scalar):
        return Vector(self.x * scalar, self.y * scalar)
    
    def __rmul__(self, scalar):
        return self.__mul__(scalar)
    
    # 比较
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
    
    def __lt__(self, other):
        return (self.x**2 + self.y**2) < (other.x**2 + other.y**2)
    
    # 长度
    def __len__(self):
        return 2
    
    # 索引访问
    def __getitem__(self, index):
        if index == 0:
            return self.x
        elif index == 1:
            return self.y
        raise IndexError("Index out of range")
    
    # 迭代
    def __iter__(self):
        yield self.x
        yield self.y
    
    # 布尔值
    def __bool__(self):
        return self.x != 0 or self.y != 0
    
    # 调用
    def __call__(self):
        return (self.x**2 + self.y**2) ** 0.5

# 使用
v1 = Vector(3, 4)
v2 = Vector(1, 2)

print(v1 + v2)      # Vector(4, 6)
print(v1 * 2)       # Vector(6, 8)
print(2 * v1)       # Vector(6, 8)
print(v1())         # 5.0（调用）
print(list(v1))     # [3, 4]
```

### 7.4 数据类（Python 3.7+）

数据类自动生成 `__init__`、`__repr__`、`__eq__` 等方法。

```python
from dataclasses import dataclass, field
from typing import List

@dataclass
class Person:
    name: str
    age: int
    email: str = ""  # 默认值

@dataclass
class Student:
    name: str
    age: int
    grades: List[int] = field(default_factory=list)  # 可变默认值
    
    # 自定义方法
    def average(self):
        return sum(self.grades) / len(self.grades) if self.grades else 0

# 使用
p1 = Person("Alice", 25)
p2 = Person("Alice", 25)
print(p1 == p2)  # True（自动生成 __eq__）
print(p1)        # Person(name='Alice', age=25, email='')

# 不可变数据类
@dataclass(frozen=True)
class Point:
    x: float
    y: float

p = Point(1.0, 2.0)
# p.x = 3.0  # ❌ 错误！不可修改

# 排序支持
@dataclass(order=True)
class Product:
    sort_index: float = field(init=False, repr=False)
    name: str
    price: float
    
    def __post_init__(self):
        self.sort_index = self.price

products = [Product("A", 100), Product("B", 50)]
print(sorted(products))  # 按价格排序
```

### 7.5 抽象基类

```python
from abc import ABC, abstractmethod

class Shape(ABC):
    @abstractmethod
    def area(self):
        pass
    
    @abstractmethod
    def perimeter(self):
        pass
    
    # 可以有具体方法
    def description(self):
        return f"Area: {self.area()}, Perimeter: {self.perimeter()}"

class Rectangle(Shape):
    def __init__(self, width, height):
        self.width = width
        self.height = height
    
    def area(self):
        return self.width * self.height
    
    def perimeter(self):
        return 2 * (self.width + self.height)

class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius
    
    def area(self):
        import math
        return math.pi * self.radius ** 2
    
    def perimeter(self):
        import math
        return 2 * math.pi * self.radius

# shape = Shape()  # ❌ 错误！不能实例化抽象类
rect = Rectangle(3, 4)
print(rect.description())
```

---

## 8. 模块与包

### 8.1 模块导入

```python
# 导入整个模块
import math
print(math.pi)
print(math.sqrt(16))

# 导入特定内容
from math import pi, sqrt
print(pi)
print(sqrt(16))

# 导入所有（不推荐）
from math import *

# 别名
import numpy as np
from math import sqrt as square_root

# 条件导入
try:
    import ujson as json
except ImportError:
    import json

# 延迟导入（在函数内导入）
def process_data():
    import pandas as pd  # 只在需要时导入
    return pd.DataFrame()
```

### 8.2 创建模块

```python
# mymodule.py
"""这是模块的文档字符串"""

# 模块级变量
VERSION = "1.0.0"

# 模块级函数
def greet(name):
    return f"Hello, {name}!"

# 模块级类
class Calculator:
    def add(self, a, b):
        return a + b

# 模块被直接运行时执行
if __name__ == "__main__":
    print("模块被直接运行")
    print(greet("World"))
```

```python
# 使用模块
import mymodule

print(mymodule.VERSION)
print(mymodule.greet("Alice"))
calc = mymodule.Calculator()
```

### 8.3 包结构

```
mypackage/
├── __init__.py
├── module1.py
├── module2.py
└── subpackage/
    ├── __init__.py
    └── module3.py
```

```python
# mypackage/__init__.py
from .module1 import func1
from .module2 import func2

__all__ = ['func1', 'func2']  # 控制 from package import * 的行为

# 使用
from mypackage import func1
from mypackage.subpackage import module3
```

---

## 9. 文件操作

### 9.1 文件读写

```python
# 写入文件
with open('file.txt', 'w', encoding='utf-8') as f:
    f.write('Hello, World!\n')
    f.write('Second line\n')
    f.writelines(['Line 3\n', 'Line 4\n'])

# 读取文件
with open('file.txt', 'r', encoding='utf-8') as f:
    content = f.read()        # 读取全部
    # content = f.readline()  # 读取一行
    # content = f.readlines() # 读取所有行（列表）

# 逐行读取（推荐，内存友好）
with open('file.txt', 'r', encoding='utf-8') as f:
    for line in f:
        print(line.strip())

# 追加模式
with open('file.txt', 'a', encoding='utf-8') as f:
    f.write('Appended line\n')

# 二进制模式
with open('image.png', 'rb') as f:
    data = f.read()

with open('copy.png', 'wb') as f:
    f.write(data)

# 文件模式
# 'r'  - 读取（默认）
# 'w'  - 写入（覆盖）
# 'a'  - 追加
# 'x'  - 创建（文件存在则报错）
# 'b'  - 二进制模式
# 't'  - 文本模式（默认）
# '+'  - 读写模式
```

### 9.2 路径操作

```python
from pathlib import Path

# 创建路径对象
p = Path('folder/file.txt')
p = Path.home() / 'documents' / 'file.txt'

# 路径信息
print(p.name)       # file.txt
print(p.stem)       # file
print(p.suffix)     # .txt
print(p.parent)     # folder
print(p.parts)      # ('folder', 'file.txt')

# 路径操作
print(p.exists())       # 是否存在
print(p.is_file())      # 是否是文件
print(p.is_dir())       # 是否是目录
print(p.absolute())     # 绝对路径
print(p.resolve())      # 解析路径

# 目录操作
folder = Path('new_folder')
folder.mkdir(exist_ok=True)           # 创建目录
folder.mkdir(parents=True, exist_ok=True)  # 创建多级目录

# 遍历目录
for item in Path('.').iterdir():
    print(item)

# 递归遍历
for py_file in Path('.').rglob('*.py'):
    print(py_file)

# 文件操作
p = Path('file.txt')
p.write_text('Hello', encoding='utf-8')
content = p.read_text(encoding='utf-8')
p.unlink()  # 删除文件

# 重命名/移动
p.rename('new_name.txt')
```

### 9.3 JSON 操作

```python
import json

# Python 对象转 JSON 字符串
data = {'name': 'Alice', 'age': 25, 'hobbies': ['reading', 'coding']}
json_str = json.dumps(data, ensure_ascii=False, indent=2)

# JSON 字符串转 Python 对象
data = json.loads(json_str)

# 写入 JSON 文件
with open('data.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

# 读取 JSON 文件
with open('data.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 自定义序列化
from datetime import datetime

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

data = {'time': datetime.now()}
json_str = json.dumps(data, cls=DateTimeEncoder)
```

### 9.4 CSV 操作

```python
import csv

# 写入 CSV
with open('data.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Name', 'Age', 'City'])
    writer.writerow(['Alice', 25, 'Beijing'])
    writer.writerows([
        ['Bob', 30, 'Shanghai'],
        ['Charlie', 35, 'Guangzhou']
    ])

# 读取 CSV
with open('data.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    header = next(reader)  # 跳过表头
    for row in reader:
        print(row)

# 使用字典
with open('data.csv', 'w', newline='', encoding='utf-8') as f:
    fieldnames = ['Name', 'Age', 'City']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerow({'Name': 'Alice', 'Age': 25, 'City': 'Beijing'})

with open('data.csv', 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row['Name'], row['Age'])
```

---

## 10. 异常处理

### 10.1 基本异常处理

```python
# try-except
try:
    result = 10 / 0
except ZeroDivisionError:
    print("除数不能为零")

# 捕获多种异常
try:
    value = int("abc")
except (ValueError, TypeError) as e:
    print(f"转换错误: {e}")

# 捕获所有异常
try:
    risky_operation()
except Exception as e:
    print(f"发生错误: {e}")

# try-except-else-finally
try:
    result = 10 / 2
except ZeroDivisionError:
    print("除数为零")
else:
    print(f"结果: {result}")  # 没有异常时执行
finally:
    print("清理工作")  # 总是执行
```

### 10.2 常见异常类型

```python
# 常见内置异常
BaseException           # 所有异常的基类
├── SystemExit          # sys.exit() 引发
├── KeyboardInterrupt   # Ctrl+C 中断
├── GeneratorExit       # 生成器关闭
└── Exception           # 常规异常基类
    ├── StopIteration       # 迭代器耗尽
    ├── ArithmeticError     # 算术错误
    │   ├── ZeroDivisionError   # 除零
    │   └── OverflowError       # 溢出
    ├── LookupError         # 查找错误
    │   ├── IndexError          # 索引越界
    │   └── KeyError            # 键不存在
    ├── AttributeError      # 属性不存在
    ├── TypeError           # 类型错误
    ├── ValueError          # 值错误
    ├── FileNotFoundError   # 文件不存在
    ├── PermissionError     # 权限错误
    ├── ImportError         # 导入错误
    └── RuntimeError        # 运行时错误
```

### 10.3 自定义异常

```python
# 自定义异常类
class ValidationError(Exception):
    """验证错误"""
    pass

class UserNotFoundError(Exception):
    """用户不存在"""
    def __init__(self, user_id, message="User not found"):
        self.user_id = user_id
        self.message = message
        super().__init__(self.message)
    
    def __str__(self):
        return f"{self.message}: {self.user_id}"

# 使用
def get_user(user_id):
    if user_id < 0:
        raise ValidationError("User ID must be positive")
    if user_id > 1000:
        raise UserNotFoundError(user_id)
    return {"id": user_id, "name": "Alice"}

try:
    user = get_user(-1)
except ValidationError as e:
    print(f"验证错误: {e}")
except UserNotFoundError as e:
    print(f"用户不存在: {e.user_id}")
```

### 10.4 异常链

```python
# 异常链（保留原始异常信息）
try:
    result = int("abc")
except ValueError as e:
    raise RuntimeError("Failed to parse value") from e

# 输出会显示两个异常的完整信息

# 抑制原始异常
try:
    result = int("abc")
except ValueError:
    raise RuntimeError("Failed to parse value") from None
```

### 10.5 上下文管理器

```python
# 使用 with 语句自动管理资源
with open('file.txt', 'r') as f:
    content = f.read()
# 文件自动关闭

# 自定义上下文管理器（类方式）
class DatabaseConnection:
    def __init__(self, host):
        self.host = host
    
    def __enter__(self):
        print(f"Connecting to {self.host}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        print("Closing connection")
        if exc_type is not None:
            print(f"Exception: {exc_val}")
        return False  # 不抑制异常

with DatabaseConnection("localhost") as db:
    print("Using database")

# 使用 contextlib
from contextlib import contextmanager

@contextmanager
def timer():
    import time
    start = time.time()
    yield
    end = time.time()
    print(f"Elapsed: {end - start:.2f}s")

with timer():
    # 执行一些操作
    sum(range(1000000))

# 多个上下文管理器（Python 3.10+ 支持括号）
with (
    open('input.txt', 'r') as f_in,
    open('output.txt', 'w') as f_out
):
    f_out.write(f_in.read())
```

---

## 11. 迭代器与生成器

### 11.1 迭代器

```python
# 可迭代对象：实现了 __iter__ 方法
# 迭代器：实现了 __iter__ 和 __next__ 方法

# 使用 iter() 和 next()
lst = [1, 2, 3]
it = iter(lst)
print(next(it))  # 1
print(next(it))  # 2
print(next(it))  # 3
# print(next(it))  # StopIteration

# 自定义迭代器
class CountDown:
    def __init__(self, start):
        self.start = start
    
    def __iter__(self):
        return self
    
    def __next__(self):
        if self.start <= 0:
            raise StopIteration
        self.start -= 1
        return self.start + 1

for num in CountDown(5):
    print(num)  # 5, 4, 3, 2, 1
```

### 11.2 生成器

生成器是一种特殊的迭代器，使用 `yield` 关键字。

```python
# 生成器函数
def countdown(n):
    while n > 0:
        yield n
        n -= 1

for num in countdown(5):
    print(num)

# 生成器表达式
squares = (x**2 for x in range(10))
print(list(squares))

# 生成器的优势：惰性求值，节省内存
def read_large_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            yield line.strip()

# yield from（委托生成器）
def chain(*iterables):
    for it in iterables:
        yield from it

list(chain([1, 2], [3, 4], [5, 6]))  # [1, 2, 3, 4, 5, 6]

# 生成器的 send 方法
def accumulator():
    total = 0
    while True:
        value = yield total
        if value is None:
            break
        total += value

gen = accumulator()
next(gen)       # 启动生成器，返回 0
gen.send(10)    # 返回 10
gen.send(20)    # 返回 30
gen.send(30)    # 返回 60
```

---

## 12. 装饰器

### 12.1 基本装饰器

装饰器是一种修改函数行为的优雅方式，本质上是一个接受函数并返回函数的函数。

```python
# 基本装饰器
def my_decorator(func):
    def wrapper(*args, **kwargs):
        print("Before function call")
        result = func(*args, **kwargs)
        print("After function call")
        return result
    return wrapper

@my_decorator
def say_hello(name):
    print(f"Hello, {name}!")

say_hello("Alice")
# Before function call
# Hello, Alice!
# After function call

# 等价于
# say_hello = my_decorator(say_hello)
```

### 12.2 保留函数元信息

```python
from functools import wraps

def my_decorator(func):
    @wraps(func)  # 保留原函数的元信息
    def wrapper(*args, **kwargs):
        """Wrapper docstring"""
        return func(*args, **kwargs)
    return wrapper

@my_decorator
def greet(name):
    """Greet someone"""
    return f"Hello, {name}!"

print(greet.__name__)  # greet（不是 wrapper）
print(greet.__doc__)   # Greet someone
```

### 12.3 带参数的装饰器

```python
def repeat(times):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for _ in range(times):
                result = func(*args, **kwargs)
            return result
        return wrapper
    return decorator

@repeat(3)
def say_hello():
    print("Hello!")

say_hello()  # 打印 3 次 Hello!

# 实用示例：重试装饰器
def retry(max_attempts=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            import time
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt < max_attempts - 1:
                        time.sleep(delay)
                    else:
                        raise
        return wrapper
    return decorator

@retry(max_attempts=3, delay=2)
def fetch_data():
    # 可能失败的操作
    pass
```

### 12.4 类装饰器

```python
# 装饰器类
class Timer:
    def __init__(self, func):
        self.func = func
        wraps(func)(self)
    
    def __call__(self, *args, **kwargs):
        import time
        start = time.time()
        result = self.func(*args, **kwargs)
        end = time.time()
        print(f"{self.func.__name__} took {end - start:.4f}s")
        return result

@Timer
def slow_function():
    import time
    time.sleep(1)

slow_function()

# 用装饰器装饰类
def singleton(cls):
    instances = {}
    @wraps(cls)
    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return get_instance

@singleton
class Database:
    def __init__(self):
        print("Initializing database")

db1 = Database()  # Initializing database
db2 = Database()  # 不会再初始化
print(db1 is db2)  # True
```

### 12.5 常用内置装饰器

```python
class MyClass:
    # 静态方法
    @staticmethod
    def static_method():
        pass
    
    # 类方法
    @classmethod
    def class_method(cls):
        pass
    
    # 属性
    @property
    def value(self):
        return self._value
    
    @value.setter
    def value(self, val):
        self._value = val

# functools 装饰器
from functools import lru_cache, cached_property

# 缓存装饰器
@lru_cache(maxsize=128)
def fibonacci(n):
    if n < 2:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

# 缓存属性（Python 3.8+）
class DataLoader:
    @cached_property
    def data(self):
        print("Loading data...")
        return [1, 2, 3, 4, 5]
```

---

## 13. 并发编程

### 13.1 多线程

```python
import threading
import time

# 创建线程
def worker(name, delay):
    print(f"{name} starting")
    time.sleep(delay)
    print(f"{name} finished")

# 方式一：直接创建
t1 = threading.Thread(target=worker, args=("Thread-1", 2))
t2 = threading.Thread(target=worker, args=("Thread-2", 1))

t1.start()
t2.start()

t1.join()  # 等待线程完成
t2.join()

# 方式二：继承 Thread
class MyThread(threading.Thread):
    def __init__(self, name, delay):
        super().__init__()
        self.name = name
        self.delay = delay
    
    def run(self):
        print(f"{self.name} starting")
        time.sleep(self.delay)
        print(f"{self.name} finished")

# 线程锁
lock = threading.Lock()
counter = 0

def increment():
    global counter
    with lock:
        temp = counter
        time.sleep(0.001)
        counter = temp + 1

threads = [threading.Thread(target=increment) for _ in range(100)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(counter)  # 100

# 线程池
from concurrent.futures import ThreadPoolExecutor

def task(n):
    time.sleep(1)
    return n * 2

with ThreadPoolExecutor(max_workers=4) as executor:
    # 提交单个任务
    future = executor.submit(task, 5)
    print(future.result())  # 10
    
    # 批量提交
    results = executor.map(task, [1, 2, 3, 4, 5])
    print(list(results))  # [2, 4, 6, 8, 10]
```

### 13.2 多进程

```python
import multiprocessing
import os

def worker(name):
    print(f"{name} running in process {os.getpid()}")

if __name__ == "__main__":
    # 创建进程
    p1 = multiprocessing.Process(target=worker, args=("Process-1",))
    p2 = multiprocessing.Process(target=worker, args=("Process-2",))
    
    p1.start()
    p2.start()
    
    p1.join()
    p2.join()
    
    # 进程池
    from concurrent.futures import ProcessPoolExecutor
    
    def cpu_bound_task(n):
        return sum(i * i for i in range(n))
    
    with ProcessPoolExecutor(max_workers=4) as executor:
        results = executor.map(cpu_bound_task, [10**6] * 4)
        print(list(results))
    
    # 进程间通信
    from multiprocessing import Queue, Pipe
    
    # 队列
    q = multiprocessing.Queue()
    q.put("Hello")
    print(q.get())
    
    # 管道
    parent_conn, child_conn = multiprocessing.Pipe()
    parent_conn.send("Hello")
    print(child_conn.recv())
```

### 13.3 异步编程

```python
import asyncio

# 定义协程
async def say_hello(name, delay):
    await asyncio.sleep(delay)
    print(f"Hello, {name}!")
    return f"Done: {name}"

# 运行协程
async def main():
    # 顺序执行
    await say_hello("Alice", 1)
    await say_hello("Bob", 1)
    
    # 并发执行
    results = await asyncio.gather(
        say_hello("Alice", 1),
        say_hello("Bob", 1),
        say_hello("Charlie", 1)
    )
    print(results)
    
    # 创建任务
    task1 = asyncio.create_task(say_hello("Alice", 1))
    task2 = asyncio.create_task(say_hello("Bob", 1))
    await task1
    await task2

# 运行
asyncio.run(main())

# 异步迭代器
async def async_range(n):
    for i in range(n):
        await asyncio.sleep(0.1)
        yield i

async def main():
    async for num in async_range(5):
        print(num)

# 异步上下文管理器
class AsyncResource:
    async def __aenter__(self):
        print("Acquiring resource")
        await asyncio.sleep(0.1)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        print("Releasing resource")
        await asyncio.sleep(0.1)

async def main():
    async with AsyncResource() as resource:
        print("Using resource")

# 超时控制
async def main():
    try:
        async with asyncio.timeout(1.0):
            await asyncio.sleep(2.0)
    except asyncio.TimeoutError:
        print("Timeout!")

# 信号量（限制并发数）
async def limited_task(sem, name):
    async with sem:
        print(f"{name} starting")
        await asyncio.sleep(1)
        print(f"{name} done")

async def main():
    sem = asyncio.Semaphore(2)  # 最多2个并发
    tasks = [limited_task(sem, f"Task-{i}") for i in range(5)]
    await asyncio.gather(*tasks)
```

---

## 14. 类型提示

### 14.1 基本类型提示

```python
# 变量类型提示
name: str = "Alice"
age: int = 25
height: float = 1.75
is_student: bool = True

# 函数类型提示
def greet(name: str) -> str:
    return f"Hello, {name}!"

def add(a: int, b: int) -> int:
    return a + b

# 无返回值
def say_hello() -> None:
    print("Hello!")
```

### 14.2 复杂类型

```python
from typing import List, Dict, Tuple, Set, Optional, Union, Any, Callable

# 容器类型
def process_items(items: List[int]) -> List[int]:
    return [x * 2 for x in items]

def get_user(users: Dict[str, int]) -> Dict[str, int]:
    return users

def get_point() -> Tuple[int, int]:
    return (1, 2)

# Python 3.9+ 可以直接使用内置类型
def process_items(items: list[int]) -> list[int]:
    return [x * 2 for x in items]

# Optional（可能为 None）
def find_user(user_id: int) -> Optional[str]:
    # 等价于 Union[str, None]
    return None

# Union（多种类型）
def process(value: Union[int, str]) -> str:
    return str(value)

# Python 3.10+ 可以用 | 代替 Union
def process(value: int | str) -> str:
    return str(value)

# Any（任意类型）
def log(message: Any) -> None:
    print(message)

# Callable（可调用对象）
def apply(func: Callable[[int, int], int], a: int, b: int) -> int:
    return func(a, b)
```

### 14.3 高级类型提示

```python
from typing import TypeVar, Generic, Protocol, Literal, Final, TypedDict

# 泛型
T = TypeVar('T')

def first(items: list[T]) -> T:
    return items[0]

# 泛型类
class Stack(Generic[T]):
    def __init__(self) -> None:
        self._items: list[T] = []
    
    def push(self, item: T) -> None:
        self._items.append(item)
    
    def pop(self) -> T:
        return self._items.pop()

stack: Stack[int] = Stack()
stack.push(1)

# Protocol（结构化子类型）
class Drawable(Protocol):
    def draw(self) -> None: ...

def render(obj: Drawable) -> None:
    obj.draw()

# 任何有 draw 方法的对象都可以传入

# Literal（字面量类型）
def set_mode(mode: Literal["read", "write", "append"]) -> None:
    pass

set_mode("read")  # ✅
# set_mode("delete")  # ❌ 类型检查器会报错

# Final（常量）
from typing import Final
MAX_SIZE: Final = 100
# MAX_SIZE = 200  # 类型检查器会警告

# TypedDict（类型化字典）
class UserDict(TypedDict):
    name: str
    age: int
    email: str

user: UserDict = {"name": "Alice", "age": 25, "email": "alice@example.com"}

# 可选字段
class UserDict(TypedDict, total=False):
    name: str
    age: int
    email: str  # 可选
```

### 14.4 类型检查工具

```bash
# 安装 mypy
pip install mypy

# 运行类型检查
mypy script.py

# 配置文件 mypy.ini
[mypy]
python_version = 3.10
warn_return_any = True
warn_unused_ignores = True
disallow_untyped_defs = True
```

---

## 15. 常见错误与解决方案

### 15.1 语法错误

**错误：IndentationError**
```python
# ❌ 错误：缩进不一致
def func():
    print("hello")
  print("world")  # 缩进错误

# ✅ 正确
def func():
    print("hello")
    print("world")
```

**错误：SyntaxError: invalid syntax**
```python
# ❌ 常见原因
if x = 5:      # 应该用 ==
print "hello"  # Python 3 需要括号
def func(a=1, b):  # 默认参数后不能有非默认参数

# ✅ 正确
if x == 5:
print("hello")
def func(b, a=1):
```

### 15.2 类型错误

**错误：TypeError**
```python
# ❌ 字符串和数字相加
result = "age: " + 25
# ✅ 正确
result = "age: " + str(25)
result = f"age: {25}"

# ❌ 不可迭代对象
for i in 123:
    print(i)
# ✅ 正确
for i in str(123):
    print(i)

# ❌ 参数数量错误
def func(a, b):
    pass
func(1)  # 缺少参数
# ✅ 正确
func(1, 2)
```

### 15.3 名称错误

**错误：NameError**
```python
# ❌ 变量未定义
print(undefined_var)

# ❌ 作用域问题
def func():
    print(x)  # x 在后面定义
    x = 10

# ✅ 正确
def func():
    x = 10
    print(x)
```

### 15.4 索引和键错误

**错误：IndexError / KeyError**
```python
# ❌ 索引越界
lst = [1, 2, 3]
print(lst[5])

# ✅ 安全访问
if len(lst) > 5:
    print(lst[5])
# 或使用切片（不会报错）
print(lst[5:6])  # []

# ❌ 键不存在
d = {'a': 1}
print(d['b'])

# ✅ 安全访问
print(d.get('b'))  # None
print(d.get('b', 'default'))  # default
```

### 15.5 属性错误

**错误：AttributeError**
```python
# ❌ 对象没有该属性
"hello".append("!")  # 字符串没有 append 方法

# ✅ 检查属性
if hasattr(obj, 'method'):
    obj.method()

# 或使用 getattr
method = getattr(obj, 'method', None)
if method:
    method()
```

### 15.6 可变默认参数陷阱

```python
# ❌ 危险：可变默认参数
def append_to(item, lst=[]):
    lst.append(item)
    return lst

print(append_to(1))  # [1]
print(append_to(2))  # [1, 2] 不是 [2]！

# ✅ 正确做法
def append_to(item, lst=None):
    if lst is None:
        lst = []
    lst.append(item)
    return lst
```

### 15.7 循环中修改列表

```python
# ❌ 危险：循环中修改列表
lst = [1, 2, 3, 4, 5]
for item in lst:
    if item % 2 == 0:
        lst.remove(item)
print(lst)  # [1, 3, 5]? 不一定！

# ✅ 正确做法
# 方法一：创建新列表
lst = [x for x in lst if x % 2 != 0]

# 方法二：遍历副本
for item in lst[:]:
    if item % 2 == 0:
        lst.remove(item)

# 方法三：倒序遍历
for i in range(len(lst) - 1, -1, -1):
    if lst[i] % 2 == 0:
        del lst[i]
```

### 15.8 浮点数精度问题

```python
# ❌ 浮点数比较
print(0.1 + 0.2 == 0.3)  # False!
print(0.1 + 0.2)  # 0.30000000000000004

# ✅ 正确做法
import math
print(math.isclose(0.1 + 0.2, 0.3))  # True

# 或使用 decimal
from decimal import Decimal
print(Decimal('0.1') + Decimal('0.2') == Decimal('0.3'))  # True
```

### 15.9 编码问题

```python
# ❌ 编码错误
with open('file.txt', 'r') as f:  # 可能报 UnicodeDecodeError
    content = f.read()

# ✅ 指定编码
with open('file.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 处理编码错误
with open('file.txt', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()
```

### 15.10 导入错误

```python
# ❌ 循环导入
# a.py
from b import func_b
# b.py
from a import func_a  # 循环导入！

# ✅ 解决方案
# 1. 重构代码，消除循环依赖
# 2. 延迟导入（在函数内导入）
def func():
    from b import func_b
    func_b()

# 3. 导入模块而非函数
import b
b.func_b()
```

---

## 附录：常用内置函数

```python
# 类型转换
int(), float(), str(), bool(), list(), tuple(), dict(), set()

# 数学
abs(), round(), min(), max(), sum(), pow(), divmod()

# 序列操作
len(), sorted(), reversed(), enumerate(), zip(), map(), filter()
range(), slice(), all(), any()

# 输入输出
print(), input(), open()

# 对象操作
type(), isinstance(), issubclass(), id(), hash()
getattr(), setattr(), hasattr(), delattr()
dir(), vars(), globals(), locals()

# 迭代器
iter(), next()

# 其他
help(), callable(), eval(), exec(), compile()
```

---

> 💡 **学习建议**：
> 1. 多写代码，实践是最好的老师
> 2. 阅读优秀的开源项目代码
> 3. 使用类型提示，提高代码质量
> 4. 善用 Python 标准库
> 5. 遇到问题先查官方文档
