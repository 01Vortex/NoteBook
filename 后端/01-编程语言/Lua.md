> Lua 是一种轻量级、高效的脚本语言,广泛应用于游戏开发、嵌入式系统和配置管理
> 本笔记涵盖 Lua 5.1-5.4 版本的核心特性和最佳实践

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [基本语法](#3-基本语法)
4. [数据类型](#4-数据类型)
5. [运算符](#5-运算符)
6. [控制结构](#6-控制结构)
7. [函数](#7-函数)
8. [表(Table)](#8-表table)
9. [模块与包](#9-模块与包)
10. [元表与元方法](#10-元表与元方法)
11. [协程(Coroutine)](#11-协程coroutine)
12. [文件IO](#12-文件io)
13. [错误处理](#13-错误处理)
14. [面向对象编程](#14-面向对象编程)
15. [性能优化](#15-性能优化)
16. [常见错误与解决方案](#16-常见错误与解决方案)
17. [最佳实践](#17-最佳实践)

---

## 1. 基础概念

### 1.1 什么是 Lua?

Lua 是一种轻量级、可嵌入的脚本语言,具有以下特点:

- **轻量级**: 完整解释器仅约 200KB
- **高效**: 执行速度快,内存占用小
- **可嵌入**: 易于集成到 C/C++ 程序中
- **简洁**: 语法简单,易于学习
- **动态类型**: 运行时类型检查

### 1.2 应用场景

```lua
-- 游戏开发: World of Warcraft, Angry Birds
-- 嵌入式脚本: Redis, Nginx (OpenResty)
-- 配置文件: Neovim, Wireshark
-- 数据处理: Apache APISIX
```

### 1.3 版本差异


| 版本 | 主要特性 |
|------|---------|
| Lua 5.1 | 最广泛使用,LuaJIT 基于此版本 |
| Lua 5.2 | 引入 _ENV, goto 语句 |
| Lua 5.3 | 整数类型,位运算符 |
| Lua 5.4 | to-be-closed 变量,常量 |

---

## 2. 环境搭建

### 2.1 安装 Lua

**Windows:**
```bash
# 下载预编译版本
# https://github.com/rjpcomputing/luaforwindows/releases
```

**Linux/Mac:**
```bash
# Ubuntu/Debian
sudo apt-get install lua5.4

# CentOS/RHEL
sudo yum install lua

# macOS
brew install lua
```

### 2.2 验证安装

```bash
lua -v
# Lua 5.4.4  Copyright (C) 1994-2022 Lua.org, PUC-Rio
```

### 2.3 交互式解释器

```lua
$ lua
Lua 5.4.4  Copyright (C) 1994-2022 Lua.org, PUC-Rio
> print("Hello, Lua!")
Hello, Lua!
> os.exit()
```

### 2.4 运行脚本

```bash
# 创建文件 hello.lua
lua hello.lua
```

---

## 3. 基本语法

### 3.1 注释


```lua
-- 单行注释

--[[
  多行注释
  可以跨越多行
]]

--[=[
  嵌套多行注释
  --[[ 内部注释 ]]
]=]
```

### 3.2 标识符规则

```lua
-- 合法标识符
local myVar = 1
local _private = 2
local userName123 = "John"

-- 不合法(保留字)
-- local and = 1  -- 错误
-- local function = 2  -- 错误

-- Lua 保留字
-- and break do else elseif end false for function
-- goto if in local nil not or repeat return
-- then true until while
```

### 3.3 语句分隔

```lua
-- 分号可选
local a = 1; local b = 2
local c = 3  local d = 4  -- 推荐不使用分号

-- 多行语句
local result = 1 + 2 + 3 +
               4 + 5 + 6
```

### 3.4 代码块

```lua
-- do...end 创建局部作用域
do
  local x = 10
  print(x)  -- 10
end
-- print(x)  -- nil (x 不可见)
```

---

## 4. 数据类型

### 4.1 八种基本类型

```lua
-- 1. nil (空值)
local a = nil
print(type(a))  -- nil

-- 2. boolean (布尔)
local b = true
local c = false
print(type(b))  -- boolean

-- 3. number (数字)
local d = 42        -- 整数
local e = 3.14      -- 浮点数
local f = 1.5e-10   -- 科学计数法
print(type(d))      -- number

-- 4. string (字符串)
local g = "Hello"
local h = 'World'
local i = [[多行
字符串]]
print(type(g))      -- string

-- 5. table (表)
local j = {1, 2, 3}
local k = {name = "Lua", version = 5.4}
print(type(j))      -- table

-- 6. function (函数)
local l = function() return 1 end
print(type(l))      -- function

-- 7. userdata (用户数据)
-- C 语言创建的数据类型

-- 8. thread (线程/协程)
local m = coroutine.create(function() end)
print(type(m))      -- thread
```

### 4.2 类型转换

```lua
-- 字符串转数字
local str = "123"
local num = tonumber(str)
print(num + 1)  -- 124

-- 数字转字符串
local n = 456
local s = tostring(n)
print(s .. "789")  -- "456789"

-- 自动转换(算术运算)
print("10" + 20)   -- 30
print("3.14" * 2)  -- 6.28

-- 字符串拼接不会自动转换
print(10 .. 20)    -- "1020"
```

### 4.3 nil 的特殊性

```lua
-- nil 表示"无值"
local x
print(x)  -- nil

-- 删除表元素
local t = {a = 1, b = 2}
t.a = nil
print(t.a)  -- nil

-- 条件判断: nil 和 false 为假,其他为真
if nil then
  print("不会执行")
end

if 0 then
  print("会执行")  -- 0 是真值!
end
```

---

## 5. 运算符

### 5.1 算术运算符


```lua
local a, b = 10, 3

print(a + b)   -- 13  加法
print(a - b)   -- 7   减法
print(a * b)   -- 30  乘法
print(a / b)   -- 3.333... 除法
print(a % b)   -- 1   取模
print(a ^ b)   -- 1000 幂运算
print(-a)      -- -10 负号

-- Lua 5.3+ 整数除法
print(a // b)  -- 3   向下取整除法
```

### 5.2 关系运算符

```lua
local x, y = 5, 10

print(x == y)  -- false 等于
print(x ~= y)  -- true  不等于
print(x < y)   -- true  小于
print(x > y)   -- false 大于
print(x <= y)  -- true  小于等于
print(x >= y)  -- false 大于等于

-- 字符串比较(字典序)
print("abc" < "abd")  -- true

-- 表比较(引用比较)
local t1 = {1, 2}
local t2 = {1, 2}
print(t1 == t2)  -- false (不同引用)
print(t1 == t1)  -- true  (相同引用)
```

### 5.3 逻辑运算符

```lua
-- and: 返回第一个假值或最后一个值
print(true and false)    -- false
print(nil and 5)         -- nil
print(10 and 20)         -- 20

-- or: 返回第一个真值或最后一个值
print(true or false)     -- true
print(nil or 5)          -- 5
print(false or nil)      -- nil

-- not: 返回布尔值
print(not true)          -- false
print(not nil)           -- true
print(not 0)             -- false (0 是真值)

-- 短路求值
local function expensive()
  print("执行了")
  return true
end

false and expensive()    -- 不会打印"执行了"
true or expensive()      -- 不会打印"执行了"
```

### 5.4 字符串运算符


```lua
-- 字符串连接
local str1 = "Hello"
local str2 = "World"
print(str1 .. " " .. str2)  -- "Hello World"

-- 数字会自动转换
print("Result: " .. 42)     -- "Result: 42"

-- 字符串长度
print(#"Lua")               -- 3
print(#"你好")              -- 6 (UTF-8 字节数)
```

### 5.5 位运算符 (Lua 5.3+)

```lua
local a, b = 0b1100, 0b1010  -- 二进制字面量

print(a & b)   -- 8   (1000) 按位与
print(a | b)   -- 14  (1110) 按位或
print(a ~ b)   -- 6   (0110) 按位异或
print(~a)      -- -13 按位取反
print(a << 1)  -- 24  左移
print(a >> 1)  -- 6   右移
```

### 5.6 运算符优先级

```lua
-- 从高到低
-- ^
-- not  #  - (一元)
-- *  /  //  %
-- +  -
-- ..
-- <<  >>
-- &
-- ~
-- |
-- <  >  <=  >=  ~=  ==
-- and
-- or

-- 示例
print(2 + 3 * 4)      -- 14 (不是 20)
print(2 ^ 3 ^ 2)      -- 512 (右结合: 2^(3^2))
print(not nil or 1)   -- true
```

---

## 6. 控制结构

### 6.1 if 语句

```lua
-- 基本形式
local score = 85

if score >= 90 then
  print("优秀")
elseif score >= 80 then
  print("良好")
elseif score >= 60 then
  print("及格")
else
  print("不及格")
end

-- 单行形式
if score >= 60 then print("通过") end

-- 三元运算符模拟
local result = score >= 60 and "通过" or "不通过"
print(result)
```

### 6.2 while 循环


```lua
-- 基本 while
local i = 1
while i <= 5 do
  print(i)
  i = i + 1
end

-- 无限循环
while true do
  local input = io.read()
  if input == "quit" then
    break
  end
  print("你输入了: " .. input)
end
```

### 6.3 repeat...until 循环

```lua
-- 至少执行一次
local count = 0
repeat
  count = count + 1
  print(count)
until count >= 5

-- 注意: 条件为真时退出(与 while 相反)
```

### 6.4 for 循环

```lua
-- 数值 for (起始, 结束, 步长)
for i = 1, 10 do
  print(i)  -- 1 到 10
end

for i = 10, 1, -1 do
  print(i)  -- 10 到 1
end

for i = 1, 10, 2 do
  print(i)  -- 1, 3, 5, 7, 9
end

-- 泛型 for (遍历迭代器)
local t = {10, 20, 30}
for index, value in ipairs(t) do
  print(index, value)
end

local person = {name = "Lua", age = 30}
for key, value in pairs(person) do
  print(key, value)
end
```

### 6.5 break 和 goto

```lua
-- break: 跳出循环
for i = 1, 10 do
  if i == 5 then
    break
  end
  print(i)  -- 1, 2, 3, 4
end

-- goto (Lua 5.2+)
local x = 10
if x > 5 then
  goto skip
end
print("不会执行")
::skip::
print("跳转到这里")

-- goto 限制: 不能跳入块内部
```

---

## 7. 函数

### 7.1 函数定义


```lua
-- 基本定义
function add(a, b)
  return a + b
end

-- 匿名函数
local multiply = function(a, b)
  return a * b
end

-- 调用
print(add(3, 5))       -- 8
print(multiply(3, 5))  -- 15
```

### 7.2 多返回值

```lua
function divmod(a, b)
  return a // b, a % b  -- 返回商和余数
end

local quotient, remainder = divmod(10, 3)
print(quotient, remainder)  -- 3  1

-- 只接收部分返回值
local q = divmod(10, 3)
print(q)  -- 3

-- 接收所有返回值到表
local results = {divmod(10, 3)}
print(results[1], results[2])  -- 3  1
```

### 7.3 可变参数

```lua
function sum(...)
  local args = {...}  -- 打包成表
  local total = 0
  for _, v in ipairs(args) do
    total = total + v
  end
  return total
end

print(sum(1, 2, 3, 4, 5))  -- 15

-- select 函数
function printArgs(...)
  print("参数个数:", select("#", ...))
  print("第2个参数:", select(2, ...))
end

printArgs(10, 20, 30)
-- 参数个数: 3
-- 第2个参数: 20  30
```

### 7.4 命名参数

```lua
-- 使用表模拟命名参数
function createUser(options)
  local name = options.name or "Anonymous"
  local age = options.age or 0
  local email = options.email or ""
  
  return {name = name, age = age, email = email}
end

local user = createUser{
  name = "Alice",
  age = 25,
  email = "alice@example.com"
}
```

### 7.5 闭包


```lua
function counter()
  local count = 0
  return function()
    count = count + 1
    return count
  end
end

local c1 = counter()
print(c1())  -- 1
print(c1())  -- 2

local c2 = counter()
print(c2())  -- 1 (独立的计数器)
```

### 7.6 尾调用优化

```lua
-- 尾调用: 函数最后一个动作是调用另一个函数
function factorial(n, acc)
  acc = acc or 1
  if n <= 1 then
    return acc
  end
  return factorial(n - 1, n * acc)  -- 尾调用
end

print(factorial(5))  -- 120

-- 非尾调用(会增加栈)
function bad_factorial(n)
  if n <= 1 then
    return 1
  end
  return n * bad_factorial(n - 1)  -- 不是尾调用
end
```

---

## 8. 表(Table)

### 8.1 表的创建

```lua
-- 空表
local t1 = {}

-- 数组式表(索引从 1 开始)
local t2 = {10, 20, 30}
print(t2[1])  -- 10

-- 字典式表
local t3 = {
  name = "Lua",
  version = 5.4,
  ["full-name"] = "Lua Language"
}
print(t3.name)         -- "Lua"
print(t3["version"])   -- 5.4

-- 混合表
local t4 = {
  10, 20, 30,           -- 数组部分
  name = "Mixed",       -- 哈希部分
  [100] = "sparse"
}
```

### 8.2 表的操作

```lua
local fruits = {"apple", "banana"}

-- 插入
table.insert(fruits, "orange")        -- 末尾插入
table.insert(fruits, 2, "grape")      -- 指定位置插入

-- 删除
local removed = table.remove(fruits)  -- 删除末尾
local second = table.remove(fruits, 2) -- 删除指定位置

-- 排序
local numbers = {5, 2, 8, 1, 9}
table.sort(numbers)
print(table.concat(numbers, ", "))    -- "1, 2, 5, 8, 9"

-- 自定义排序
table.sort(numbers, function(a, b)
  return a > b  -- 降序
end)

-- 连接
local words = {"Hello", "Lua", "World"}
print(table.concat(words, " "))       -- "Hello Lua World"
```

### 8.3 表的遍历


```lua
local t = {10, 20, 30, name = "test"}

-- ipairs: 遍历数组部分(遇到 nil 停止)
for i, v in ipairs(t) do
  print(i, v)  -- 1 10, 2 20, 3 30
end

-- pairs: 遍历所有键值对(顺序不确定)
for k, v in pairs(t) do
  print(k, v)  -- 1 10, 2 20, 3 30, name test
end

-- 数值索引遍历
for i = 1, #t do
  print(i, t[i])
end
```

### 8.4 表作为数据结构

```lua
-- 栈
local stack = {}
table.insert(stack, 1)  -- push
table.insert(stack, 2)
local top = table.remove(stack)  -- pop

-- 队列
local queue = {}
table.insert(queue, 1)  -- enqueue
table.insert(queue, 2)
local front = table.remove(queue, 1)  -- dequeue

-- 集合
local set = {}
set["apple"] = true
set["banana"] = true
if set["apple"] then
  print("apple 在集合中")
end

-- 链表
local list = {value = 1}
list.next = {value = 2}
list.next.next = {value = 3}
```

---

## 9. 模块与包

### 9.1 创建模块

```lua
-- mymodule.lua
local M = {}

-- 私有函数
local function private_func()
  return "私有"
end

-- 公有函数
function M.public_func()
  return "公有"
end

function M.add(a, b)
  return a + b
end

-- 模块变量
M.version = "1.0"

return M
```

### 9.2 使用模块

```lua
-- 加载模块
local mymodule = require("mymodule")

print(mymodule.add(3, 5))      -- 8
print(mymodule.version)        -- "1.0"
print(mymodule.public_func())  -- "公有"

-- 选择性导入
local add = require("mymodule").add
print(add(10, 20))  -- 30
```

### 9.3 模块搜索路径


```lua
-- 查看搜索路径
print(package.path)
-- ./?.lua;/usr/local/share/lua/5.4/?.lua;...

-- 修改搜索路径
package.path = package.path .. ";/my/lua/?.lua"

-- 查看已加载模块
for k, v in pairs(package.loaded) do
  print(k, v)
end

-- 重新加载模块
package.loaded["mymodule"] = nil
local mymodule = require("mymodule")
```

### 9.4 包管理器

```lua
-- LuaRocks: Lua 的包管理器
-- 安装: https://luarocks.org/

-- 安装包
-- luarocks install luasocket

-- 使用已安装的包
local socket = require("socket")
```

---

## 10. 元表与元方法

### 10.1 元表基础

```lua
-- 创建表和元表
local t = {value = 10}
local mt = {
  __add = function(a, b)
    return {value = a.value + b.value}
  end
}

-- 设置元表
setmetatable(t, mt)

-- 使用元方法
local t2 = {value = 20}
setmetatable(t2, mt)
local t3 = t + t2
print(t3.value)  -- 30

-- 获取元表
print(getmetatable(t) == mt)  -- true
```

### 10.2 常用元方法

```lua
local mt = {
  -- 算术运算
  __add = function(a, b) return a.value + b.value end,
  __sub = function(a, b) return a.value - b.value end,
  __mul = function(a, b) return a.value * b.value end,
  __div = function(a, b) return a.value / b.value end,
  __mod = function(a, b) return a.value % b.value end,
  __pow = function(a, b) return a.value ^ b.value end,
  __unm = function(a) return -a.value end,
  
  -- 关系运算
  __eq = function(a, b) return a.value == b.value end,
  __lt = function(a, b) return a.value < b.value end,
  __le = function(a, b) return a.value <= b.value end,
  
  -- 其他
  __concat = function(a, b) return tostring(a.value) .. tostring(b.value) end,
  __len = function(a) return a.value end,
  __tostring = function(a) return "Value: " .. a.value end,
  __call = function(a, ...) print("调用表", ...) end
}
```

### 10.3 __index 元方法


```lua
-- __index 作为函数
local mt = {
  __index = function(table, key)
    return "默认值: " .. key
  end
}

local t = {}
setmetatable(t, mt)
print(t.name)  -- "默认值: name"

-- __index 作为表(原型继承)
local prototype = {
  greet = function(self)
    return "Hello, " .. self.name
  end
}

local mt = {__index = prototype}

local obj = {name = "Lua"}
setmetatable(obj, mt)
print(obj:greet())  -- "Hello, Lua"
```

### 10.4 __newindex 元方法

```lua
-- 拦截赋值操作
local mt = {
  __newindex = function(table, key, value)
    print("尝试设置 " .. key .. " = " .. tostring(value))
    rawset(table, key, value)  -- 绕过元方法直接设置
  end
}

local t = {}
setmetatable(t, mt)
t.name = "Lua"  -- 打印: 尝试设置 name = Lua

-- 只读表
local function readonly(t)
  local proxy = {}
  local mt = {
    __index = t,
    __newindex = function(table, key, value)
      error("表是只读的")
    end
  }
  setmetatable(proxy, mt)
  return proxy
end

local config = readonly({debug = true})
print(config.debug)  -- true
-- config.debug = false  -- 错误: 表是只读的
```

---

## 11. 协程(Coroutine)

### 11.1 协程基础

```lua
-- 创建协程
local co = coroutine.create(function()
  print("协程开始")
  coroutine.yield()
  print("协程继续")
  coroutine.yield()
  print("协程结束")
end)

-- 查看状态
print(coroutine.status(co))  -- suspended

-- 恢复执行
coroutine.resume(co)  -- 打印: 协程开始
coroutine.resume(co)  -- 打印: 协程继续
coroutine.resume(co)  -- 打印: 协程结束

print(coroutine.status(co))  -- dead
```

### 11.2 协程通信


```lua
local co = coroutine.create(function(a, b)
  print("接收:", a, b)
  local x, y = coroutine.yield(a + b)
  print("接收:", x, y)
  return x * y
end)

-- resume 传递参数给协程
local success, result = coroutine.resume(co, 10, 20)
print("返回:", result)  -- 30

-- 再次 resume 传递参数给 yield
local success, result = coroutine.resume(co, 5, 6)
print("返回:", result)  -- 30
```

### 11.3 生产者-消费者模式

```lua
function producer()
  return coroutine.create(function()
    for i = 1, 5 do
      print("生产:", i)
      coroutine.yield(i)
    end
  end)
end

function consumer(prod)
  while true do
    local status, value = coroutine.resume(prod)
    if not status then break end
    print("消费:", value)
  end
end

consumer(producer())
```

### 11.4 协程实现迭代器

```lua
function range(n)
  return coroutine.wrap(function()
    for i = 1, n do
      coroutine.yield(i)
    end
  end)
end

for i in range(5) do
  print(i)  -- 1, 2, 3, 4, 5
end
```

---

## 12. 文件IO

### 12.1 简单文件操作

```lua
-- 读取整个文件
local file = io.open("test.txt", "r")
if file then
  local content = file:read("*a")  -- 读取全部
  print(content)
  file:close()
end

-- 写入文件
local file = io.open("output.txt", "w")
if file then
  file:write("Hello, Lua!\n")
  file:write("第二行\n")
  file:close()
end

-- 追加模式
local file = io.open("output.txt", "a")
if file then
  file:write("追加内容\n")
  file:close()
end
```

### 12.2 读取模式


```lua
local file = io.open("test.txt", "r")
if file then
  -- "*a" 或 "*all": 读取全部
  local all = file:read("*a")
  
  -- "*l" 或 "*line": 读取一行(不含换行符)
  file:seek("set", 0)  -- 回到开头
  local line = file:read("*l")
  
  -- "*L": 读取一行(含换行符)
  local line_with_newline = file:read("*L")
  
  -- "*n" 或 "*number": 读取数字
  local num = file:read("*n")
  
  -- 数字: 读取指定字节数
  local bytes = file:read(10)
  
  file:close()
end

-- 逐行读取
local file = io.open("test.txt", "r")
if file then
  for line in file:lines() do
    print(line)
  end
  file:close()
end
```

### 12.3 文件模式

```lua
-- "r"  只读(默认)
-- "w"  只写(覆盖)
-- "a"  追加
-- "r+" 读写(文件必须存在)
-- "w+" 读写(覆盖)
-- "a+" 读写(追加)
-- "b"  二进制模式(Windows)

-- 二进制文件
local file = io.open("image.png", "rb")
if file then
  local data = file:read("*a")
  file:close()
end
```

### 12.4 标准输入输出

```lua
-- 标准输入
print("请输入你的名字:")
local name = io.read()
print("你好, " .. name)

-- 标准输出
io.write("不换行输出")
io.write("继续输出\n")

-- 标准错误
io.stderr:write("错误信息\n")

-- 设置默认文件
io.input("input.txt")
local line = io.read()
io.output("output.txt")
io.write("输出到文件\n")
```

---

## 13. 错误处理

### 13.1 assert

```lua
-- assert: 条件为假时抛出错误
local function divide(a, b)
  assert(b ~= 0, "除数不能为零")
  return a / b
end

print(divide(10, 2))  -- 5
-- print(divide(10, 0))  -- 错误: 除数不能为零
```

### 13.2 error


```lua
-- error: 主动抛出错误
local function check_age(age)
  if age < 0 then
    error("年龄不能为负数", 2)  -- 2 表示错误位置在调用者
  end
  return age
end

-- check_age(-5)  -- 错误
```

### 13.3 pcall 和 xpcall

```lua
-- pcall: 保护模式调用
local function risky_function()
  error("出错了!")
end

local status, err = pcall(risky_function)
if not status then
  print("捕获错误:", err)
end

-- xpcall: 带错误处理函数
local function error_handler(err)
  print("错误处理:", err)
  print(debug.traceback())
  return "处理后的错误"
end

local status, result = xpcall(risky_function, error_handler)
print(status, result)
```

### 13.4 错误处理最佳实践

```lua
-- 返回 nil + 错误信息
local function safe_divide(a, b)
  if b == 0 then
    return nil, "除数不能为零"
  end
  return a / b
end

local result, err = safe_divide(10, 0)
if not result then
  print("错误:", err)
else
  print("结果:", result)
end

-- 资源清理
local function process_file(filename)
  local file = io.open(filename, "r")
  if not file then
    return nil, "无法打开文件"
  end
  
  local success, result = pcall(function()
    -- 处理文件
    return file:read("*a")
  end)
  
  file:close()  -- 确保关闭
  
  if not success then
    return nil, result
  end
  return result
end
```

---

## 14. 面向对象编程

### 14.1 基础类实现


```lua
-- 定义类
local Person = {}
Person.__index = Person

-- 构造函数
function Person:new(name, age)
  local obj = {
    name = name,
    age = age
  }
  setmetatable(obj, self)
  return obj
end

-- 方法
function Person:greet()
  return "你好, 我是 " .. self.name
end

function Person:get_age()
  return self.age
end

-- 使用
local p1 = Person:new("张三", 25)
print(p1:greet())  -- "你好, 我是 张三"
print(p1:get_age())  -- 25
```

### 14.2 继承

```lua
-- 父类
local Animal = {}
Animal.__index = Animal

function Animal:new(name)
  local obj = {name = name}
  setmetatable(obj, self)
  return obj
end

function Animal:speak()
  return self.name .. " 发出声音"
end

-- 子类
local Dog = setmetatable({}, {__index = Animal})
Dog.__index = Dog

function Dog:new(name, breed)
  local obj = Animal.new(self, name)
  obj.breed = breed
  setmetatable(obj, self)
  return obj
end

function Dog:speak()
  return self.name .. " 汪汪叫"
end

function Dog:get_breed()
  return self.breed
end

-- 使用
local dog = Dog:new("旺财", "金毛")
print(dog:speak())      -- "旺财 汪汪叫"
print(dog:get_breed())  -- "金毛"
```

### 14.3 私有成员

```lua
function Person:new(name, age)
  local private = {
    ssn = "123-45-6789"  -- 私有数据
  }
  
  local obj = {
    name = name,
    age = age
  }
  
  function obj:get_ssn()
    return private.ssn
  end
  
  setmetatable(obj, self)
  return obj
end
```

### 14.4 多态


```lua
local animals = {
  Dog:new("旺财", "金毛"),
  Animal:new("动物")
}

for _, animal in ipairs(animals) do
  print(animal:speak())
end
-- 旺财 汪汪叫
-- 动物 发出声音
```

---

## 15. 性能优化

### 15.1 局部变量优化

```lua
-- 慢: 全局变量访问
function slow()
  for i = 1, 1000000 do
    math.sin(i)
  end
end

-- 快: 局部变量缓存
function fast()
  local sin = math.sin
  for i = 1, 1000000 do
    sin(i)
  end
end
```

### 15.2 表预分配

```lua
-- 慢: 动态增长
local t = {}
for i = 1, 1000 do
  t[i] = i
end

-- 快: 预分配
local t = {}
for i = 1, 1000 do
  t[i] = i
end
```

### 15.3 字符串拼接优化

```lua
-- 慢: 使用 .. 拼接
local s = ""
for i = 1, 1000 do
  s = s .. i
end

-- 快: 使用 table.concat
local t = {}
for i = 1, 1000 do
  t[i] = i
end
local s = table.concat(t)
```

### 15.4 避免创建临时表

```lua
-- 慢
function sum(...)
  local args = {...}
  local total = 0
  for i = 1, #args do
    total = total + args[i]
  end
  return total
end

-- 快
function sum(...)
  local total = 0
  for i = 1, select("#", ...) do
    total = total + select(i, ...)
  end
  return total
end
```

### 15.5 使用 LuaJIT

```lua
-- LuaJIT 是 Lua 的 JIT 编译器,性能提升 10-100 倍
-- 安装: https://luajit.org/

-- 检查是否运行在 LuaJIT
if jit then
  print("运行在 LuaJIT " .. jit.version)
else
  print("运行在标准 Lua")
end
```

---

## 16. 常见错误与解决方案

### 16.1 索引从 1 开始


```lua
-- ❌ 错误: 从 0 开始
local t = {10, 20, 30}
print(t[0])  -- nil

-- ✅ 正确: 从 1 开始
print(t[1])  -- 10
```

### 16.2 全局变量污染

```lua
-- ❌ 错误: 忘记 local
function test()
  x = 10  -- 全局变量!
end
test()
print(x)  -- 10

-- ✅ 正确: 使用 local
function test()
  local x = 10
end
test()
print(x)  -- nil

-- 检测全局变量
setmetatable(_G, {
  __newindex = function(_, key, value)
    error("尝试创建全局变量: " .. key, 2)
  end
})
```

### 16.3 表引用问题

```lua
-- ❌ 错误: 浅拷贝
local t1 = {1, 2, {3, 4}}
local t2 = t1
t2[1] = 100
print(t1[1])  -- 100 (被修改了!)

-- ✅ 正确: 深拷贝
local function deepcopy(obj)
  if type(obj) ~= "table" then
    return obj
  end
  local new_table = {}
  for k, v in pairs(obj) do
    new_table[deepcopy(k)] = deepcopy(v)
  end
  return setmetatable(new_table, getmetatable(obj))
end

local t1 = {1, 2, {3, 4}}
local t2 = deepcopy(t1)
t2[1] = 100
print(t1[1])  -- 1 (未被修改)
```

### 16.4 字符串不可变

```lua
-- ❌ 错误: 尝试修改字符串
local s = "hello"
-- s[1] = "H"  -- 错误!

-- ✅ 正确: 创建新字符串
local s = "hello"
s = "H" .. s:sub(2)
print(s)  -- "Hello"
```

### 16.5 nil 导致的循环提前结束

```lua
-- ❌ 错误: ipairs 遇到 nil 停止
local t = {1, 2, nil, 4, 5}
for i, v in ipairs(t) do
  print(i, v)  -- 只打印 1, 2
end

-- ✅ 正确: 使用数值循环
for i = 1, #t do
  print(i, t[i])  -- 打印所有(包括 nil)
end

-- 或使用 pairs
for i, v in pairs(t) do
  print(i, v)
end
```

### 16.6 除法返回浮点数


```lua
-- ❌ 错误: 期望整数结果
print(10 / 2)  -- 5.0 (浮点数)

-- ✅ 正确: 使用整数除法 (Lua 5.3+)
print(10 // 2)  -- 5 (整数)

-- 或使用 math.floor
print(math.floor(10 / 2))  -- 5
```

### 16.7 字符串连接类型错误

```lua
-- ❌ 错误: 连接 nil
local name = nil
-- print("Hello, " .. name)  -- 错误!

-- ✅ 正确: 检查或转换
local name = nil
print("Hello, " .. (name or "Guest"))
print("Hello, " .. tostring(name))
```

### 16.8 函数调用括号问题

```lua
-- ❌ 错误: 缺少括号
local function test()
  return {1, 2, 3}
end

-- print(test[1])  -- 错误: 尝试索引函数

-- ✅ 正确: 添加括号
print(test()[1])  -- 1

-- 特殊情况: 单参数可省略括号
print "Hello"  -- 等同于 print("Hello")
print {1, 2}   -- 等同于 print({1, 2})
```

### 16.9 模块循环依赖

```lua
-- ❌ 错误: 模块 A 和 B 互相 require

-- moduleA.lua
local B = require("moduleB")
local A = {}
function A.test() return B.value end
return A

-- moduleB.lua
local A = require("moduleA")  -- 循环依赖!
local B = {}
B.value = 10
return B

-- ✅ 正确: 延迟加载
-- moduleA.lua
local A = {}
function A.test()
  local B = require("moduleB")  -- 延迟加载
  return B.value
end
return A
```

### 16.10 协程错误处理

```lua
-- ❌ 错误: 协程内错误未捕获
local co = coroutine.create(function()
  error("协程错误")
end)
-- coroutine.resume(co)  -- 错误会传播

-- ✅ 正确: 检查返回值
local co = coroutine.create(function()
  error("协程错误")
end)
local ok, err = coroutine.resume(co)
if not ok then
  print("捕获错误:", err)
end
```

---

## 17. 最佳实践

### 17.1 代码风格


```lua
-- 命名规范
local my_variable = 1        -- 蛇形命名(推荐)
local MyClass = {}           -- 大驼峰(类)
local CONSTANT_VALUE = 100   -- 全大写(常量)

-- 缩进: 2 或 4 空格
function example()
  if true then
    print("缩进")
  end
end

-- 避免全局变量
local function my_function()
  local x = 10  -- 总是使用 local
end

-- 提前返回
function validate(value)
  if not value then
    return nil, "值不能为空"
  end
  if value < 0 then
    return nil, "值不能为负"
  end
  return value
end
```

### 17.2 模块设计

```lua
-- 模块模板
local M = {}

-- 私有变量
local private_var = 0

-- 私有函数
local function private_func()
  return private_var
end

-- 公有函数
function M.public_func()
  return private_func()
end

-- 常量
M.VERSION = "1.0.0"

return M
```

### 17.3 错误处理策略

```lua
-- 库函数: 返回 nil + 错误信息
function M.safe_operation(param)
  if not param then
    return nil, "参数不能为空"
  end
  -- 执行操作
  return result
end

-- 应用代码: 使用 assert
local result = assert(M.safe_operation(value))

-- 关键路径: 使用 pcall
local ok, result = pcall(risky_function)
if not ok then
  -- 处理错误
end
```

### 17.4 性能建议

```lua
-- 1. 缓存常用函数
local insert = table.insert
local concat = table.concat

-- 2. 避免在循环中创建函数
-- ❌ 慢
for i = 1, 1000 do
  local f = function() return i end
end

-- ✅ 快
local function make_func(i)
  return function() return i end
end
for i = 1, 1000 do
  local f = make_func(i)
end

-- 3. 使用局部变量
local sin, cos = math.sin, math.cos
for i = 1, 1000000 do
  sin(i)
  cos(i)
end
```

### 17.5 调试技巧


```lua
-- 打印调试
local function debug_print(...)
  print(string.format("[DEBUG] %s", table.concat({...}, " ")))
end

-- 查看变量类型和值
local function inspect(var, name)
  name = name or "variable"
  print(string.format("%s: type=%s, value=%s", 
    name, type(var), tostring(var)))
end

-- 堆栈跟踪
local function trace()
  print(debug.traceback())
end

-- 断点调试
local function breakpoint()
  print("断点: " .. debug.traceback())
  io.read()  -- 等待输入
end

-- 性能测试
local function benchmark(func, iterations)
  iterations = iterations or 1000000
  local start = os.clock()
  for i = 1, iterations do
    func()
  end
  local elapsed = os.clock() - start
  print(string.format("执行 %d 次耗时: %.4f 秒", iterations, elapsed))
end
```

### 17.6 常用工具库

```lua
-- LuaRocks 推荐包
-- luasocket: 网络编程
-- luafilesystem: 文件系统操作
-- penlight: 实用工具集
-- luajson: JSON 解析
-- luasql: 数据库访问

-- 安装示例
-- luarocks install luasocket
-- luarocks install luafilesystem
```

### 17.7 测试

```lua
-- 简单测试框架
local function test(name, func)
  local ok, err = pcall(func)
  if ok then
    print("✓ " .. name)
  else
    print("✗ " .. name .. ": " .. err)
  end
end

local function assert_equal(actual, expected)
  if actual ~= expected then
    error(string.format("期望 %s, 实际 %s", 
      tostring(expected), tostring(actual)))
  end
end

-- 使用
test("加法测试", function()
  assert_equal(1 + 1, 2)
end)

test("字符串测试", function()
  assert_equal("hello" .. " world", "hello world")
end)
```

### 17.8 文档注释

```lua
--- 计算两个数的和
-- @param a number 第一个数
-- @param b number 第二个数
-- @return number 两数之和
-- @usage local result = add(1, 2)
function M.add(a, b)
  return a + b
end

--- 用户类
-- @class User
-- @field name string 用户名
-- @field age number 年龄
local User = {}
```

### 17.9 安全编程


```lua
-- 沙箱环境
local function create_sandbox()
  local env = {
    print = print,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    pairs = pairs,
    ipairs = ipairs,
    -- 只暴露安全函数
  }
  return env
end

-- 执行不受信任的代码
local function run_untrusted(code)
  local func, err = load(code, "sandbox", "t", create_sandbox())
  if not func then
    return nil, err
  end
  return pcall(func)
end

-- 输入验证
local function validate_input(input)
  assert(type(input) == "string", "输入必须是字符串")
  assert(#input > 0, "输入不能为空")
  assert(#input <= 1000, "输入过长")
  return input
end
```

### 17.10 实战示例: HTTP 服务器

```lua
-- 使用 LuaSocket 实现简单 HTTP 服务器
local socket = require("socket")

local function http_server(port)
  local server = assert(socket.bind("*", port))
  print("服务器启动在端口 " .. port)
  
  while true do
    local client = server:accept()
    client:settimeout(10)
    
    local request = client:receive()
    if request then
      print("收到请求: " .. request)
      
      local response = [[
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<body>
  <h1>Hello from Lua!</h1>
  <p>当前时间: ]] .. os.date() .. [[</p>
</body>
</html>
]]
      
      client:send(response)
    end
    
    client:close()
  end
end

-- 启动服务器
-- http_server(8080)
```

### 17.11 实战示例: 配置文件解析

```lua
-- config.lua
return {
  database = {
    host = "localhost",
    port = 3306,
    username = "root",
    password = "secret"
  },
  server = {
    port = 8080,
    workers = 4
  }
}

-- 加载配置
local function load_config(filename)
  local config = dofile(filename)
  return config
end

local cfg = load_config("config.lua")
print(cfg.database.host)  -- "localhost"
```

### 17.12 实战示例: 简单 ORM


```lua
local Model = {}
Model.__index = Model

function Model:new(table_name)
  local obj = {
    table_name = table_name,
    fields = {}
  }
  setmetatable(obj, self)
  return obj
end

function Model:where(conditions)
  self.conditions = conditions
  return self
end

function Model:select(fields)
  self.fields = fields or {"*"}
  return self
end

function Model:to_sql()
  local sql = "SELECT " .. table.concat(self.fields, ", ")
  sql = sql .. " FROM " .. self.table_name
  
  if self.conditions then
    local where_clauses = {}
    for k, v in pairs(self.conditions) do
      table.insert(where_clauses, 
        string.format("%s = '%s'", k, v))
    end
    sql = sql .. " WHERE " .. table.concat(where_clauses, " AND ")
  end
  
  return sql
end

-- 使用
local users = Model:new("users")
local sql = users:select({"id", "name"}):where({status = "active"}):to_sql()
print(sql)
-- SELECT id, name FROM users WHERE status = 'active'
```

---

## 附录

### A. 常用标准库

```lua
-- 基础库
print, type, tonumber, tostring, pairs, ipairs, next
assert, error, pcall, xpcall
setmetatable, getmetatable
require, dofile, loadfile, load

-- 字符串库 (string)
string.len, string.sub, string.upper, string.lower
string.find, string.match, string.gmatch, string.gsub
string.format, string.byte, string.char
string.rep, string.reverse

-- 表库 (table)
table.insert, table.remove, table.sort, table.concat
table.pack, table.unpack (Lua 5.2+)

-- 数学库 (math)
math.abs, math.ceil, math.floor, math.max, math.min
math.sqrt, math.pow, math.exp, math.log
math.sin, math.cos, math.tan, math.asin, math.acos, math.atan
math.pi, math.huge, math.random, math.randomseed

-- IO 库 (io)
io.open, io.close, io.read, io.write
io.input, io.output, io.lines, io.flush

-- OS 库 (os)
os.clock, os.date, os.time, os.difftime
os.execute, os.exit, os.getenv, os.remove, os.rename

-- 调试库 (debug)
debug.traceback, debug.getinfo, debug.sethook
```

### B. 学习资源

```lua
-- 官方文档
-- https://www.lua.org/manual/5.4/

-- 在线教程
-- https://www.runoob.com/lua/lua-tutorial.html
-- https://learnxinyminutes.com/docs/lua/

-- 书籍推荐
-- 《Programming in Lua》(官方书籍)
-- 《Lua 程序设计》(中文版)

-- 社区
-- Lua 用户论坛: https://www.lua.org/lua-l.html
-- GitHub: https://github.com/lua/lua
```

### C. 版本迁移指南


```lua
-- Lua 5.1 -> 5.2
-- 1. _ENV 替代 setfenv/getfenv
-- 2. module() 函数被移除
-- 3. unpack 移到 table.unpack
-- 4. loadstring 改为 load

-- Lua 5.2 -> 5.3
-- 1. 整数类型支持
-- 2. 位运算符 (&, |, ~, <<, >>)
-- 3. // 整数除法运算符
-- 4. utf8 库

-- Lua 5.3 -> 5.4
-- 1. const 变量 (local x <const> = 10)
-- 2. to-be-closed 变量 (local f <close> = io.open(...))
-- 3. 新的随机数生成器
-- 4. 警告系统
```

### D. 性能对比

```lua
-- 测试代码
local function benchmark_test()
  -- 全局 vs 局部
  local iterations = 10000000
  
  -- 全局访问
  local start = os.clock()
  for i = 1, iterations do
    math.sin(i)
  end
  print("全局访问:", os.clock() - start)
  
  -- 局部缓存
  local sin = math.sin
  start = os.clock()
  for i = 1, iterations do
    sin(i)
  end
  print("局部缓存:", os.clock() - start)
end

-- 结果示例:
-- 全局访问: 2.34 秒
-- 局部缓存: 1.87 秒 (快 20%)
```

### E. 常见应用场景

```lua
-- 1. 游戏脚本
-- World of Warcraft, Roblox, Angry Birds

-- 2. 嵌入式脚本
-- Redis (Lua 脚本)
-- Nginx (OpenResty)
-- Wireshark (协议分析)

-- 3. 配置文件
-- Neovim, Awesome WM

-- 4. 数据处理
-- Apache APISIX (API 网关)

-- 5. 测试框架
-- Busted (BDD 测试框架)
```

---

## 总结

Lua 是一门简洁而强大的脚本语言,具有以下核心优势:

1. **轻量高效**: 解释器小巧,执行速度快
2. **易于嵌入**: 与 C/C++ 无缝集成
3. **灵活表结构**: 表可实现数组、字典、对象等
4. **元表机制**: 实现强大的元编程能力
5. **协程支持**: 轻量级并发编程

掌握 Lua 的关键:
- 理解表的本质和用法
- 熟练使用元表和元方法
- 掌握模块化编程
- 注意性能优化技巧
- 避免常见陷阱(全局变量、索引从1开始等)

通过本笔记的学习,你应该能够:
- ✅ 编写规范的 Lua 代码
- ✅ 使用面向对象编程
- ✅ 进行模块化开发
- ✅ 处理错误和异常
- ✅ 优化代码性能
- ✅ 避免常见错误

继续学习建议:
1. 阅读优秀开源项目源码
2. 实践小项目(配置解析器、简单服务器等)
3. 学习 LuaJIT 和 FFI
4. 探索 Lua 在特定领域的应用(游戏、Web等)

---

> 最后更新: 2024
> 适用版本: Lua 5.1 - 5.4
> 作者: Kiro AI Assistant
```
