# Shell 脚本完整学习笔记

> Shell 是 Linux/Unix 系统的命令解释器，Shell 脚本是自动化运维的基础
> 本笔记基于 Bash (Bourne Again Shell)
> 涵盖从入门到高级的完整内容

---

## 目录

1. [Shell 简介](#1-shell-简介)
2. [基础语法](#2-基础语法)
3. [变量](#3-变量)
4. [字符串操作](#4-字符串操作)
5. [数组](#5-数组)
6. [运算符](#6-运算符)
7. [条件判断](#7-条件判断)
8. [循环结构](#8-循环结构)
9. [函数](#9-函数)
10. [输入输出](#10-输入输出)
11. [文件操作](#11-文件操作)
12. [文本处理](#12-文本处理)
13. [正则表达式](#13-正则表达式)
14. [进程管理](#14-进程管理)
15. [实战脚本](#15-实战脚本)
16. [调试技巧](#16-调试技巧)
17. [常见错误与解决方案](#17-常见错误与解决方案)
18. [最佳实践](#18-最佳实践)

---

## 1. Shell 简介

### 1.1 什么是 Shell？

Shell 是用户与 Linux 内核之间的桥梁，它接收用户输入的命令，解释后传递给内核执行。Shell 脚本就是将多个命令组合在一起，实现自动化操作。

```
┌─────────────────────────────────────────────────────────────────┐
│                        Shell 工作原理                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   用户 ──> Shell ──> 内核 ──> 硬件                               │
│                                                                 │
│   用户输入命令                                                   │
│       ↓                                                         │
│   Shell 解释命令                                                 │
│       ↓                                                         │
│   内核执行操作                                                   │
│       ↓                                                         │
│   返回结果给用户                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 常见 Shell 类型

| Shell | 说明 | 特点 |
|-------|------|------|
| bash | Bourne Again Shell | Linux 默认 Shell，功能强大 |
| sh | Bourne Shell | 最早的 Shell，兼容性好 |
| zsh | Z Shell | 功能丰富，Oh My Zsh 流行 |
| csh | C Shell | 语法类似 C 语言 |
| ksh | Korn Shell | 兼容 sh，增加了很多特性 |

```bash
# 查看当前使用的 Shell
echo $SHELL

# 查看系统支持的 Shell
cat /etc/shells

# 切换 Shell
chsh -s /bin/zsh
```

### 1.3 第一个 Shell 脚本

```bash
#!/bin/bash
# 这是我的第一个 Shell 脚本
# 作者：Your Name
# 日期：2024-01-15

echo "Hello, Shell!"
echo "当前时间：$(date)"
echo "当前用户：$(whoami)"
echo "当前目录：$(pwd)"
```

**执行脚本的三种方式**：

```bash
# 方式1：添加执行权限后直接运行
chmod +x hello.sh
./hello.sh

# 方式2：使用 bash 命令运行（不需要执行权限）
bash hello.sh

# 方式3：使用 source 或 . 运行（在当前 Shell 环境执行）
source hello.sh
. hello.sh
```

---

## 2. 基础语法

### 2.1 脚本结构

```bash
#!/bin/bash
#===============================================
# 脚本名称：example.sh
# 脚本描述：这是一个示例脚本
# 作者：Your Name
# 创建日期：2024-01-15
# 版本：1.0
#===============================================

# 全局变量
VERSION="1.0"
AUTHOR="Your Name"

# 函数定义
function show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help    显示帮助信息"
    echo "  -v, --version 显示版本信息"
}

# 主逻辑
main() {
    echo "脚本开始执行..."
    # 业务逻辑
    echo "脚本执行完成"
}

# 入口
main "$@"
```

### 2.2 注释

```bash
# 单行注释

# 多行注释方式1（推荐）
# 这是第一行注释
# 这是第二行注释
# 这是第三行注释

# 多行注释方式2（Here Document）
: '
这是多行注释
可以写很多行
不会被执行
'

# 多行注释方式3
: <<'COMMENT'
这也是多行注释
可以写很多行
COMMENT
```

### 2.3 命令执行

```bash
# 方式1：反引号（不推荐，难以嵌套）
result=`date`

# 方式2：$() 语法（推荐）
result=$(date)

# 嵌套命令
files=$(ls $(pwd))

# 多条命令
# ; 顺序执行，不管前面是否成功
cmd1 ; cmd2 ; cmd3

# && 前面成功才执行后面
cmd1 && cmd2 && cmd3

# || 前面失败才执行后面
cmd1 || cmd2

# 组合使用
make && make install || echo "编译失败"
```

### 2.4 退出状态

```bash
# 每个命令执行后都有退出状态码
# 0 表示成功，非 0 表示失败

ls /tmp
echo $?  # 0（成功）

ls /nonexistent
echo $?  # 非 0（失败）

# 在脚本中设置退出状态
exit 0   # 成功退出
exit 1   # 失败退出
```


---

## 3. 变量

### 3.1 变量定义与使用

```bash
# 定义变量（等号两边不能有空格！）
name="张三"
age=25
is_admin=true

# 使用变量
echo $name
echo ${name}      # 推荐使用花括号，更清晰
echo "我是${name}，今年${age}岁"

# 只读变量
readonly PI=3.14159
PI=3.14  # 报错：readonly variable

# 删除变量
unset name
echo $name  # 空
```

### 3.2 变量类型

```bash
# 1. 局部变量（只在当前 Shell 有效）
local_var="局部变量"

# 2. 环境变量（子进程可以继承）
export GLOBAL_VAR="环境变量"

# 3. 特殊变量
$0    # 脚本名称
$1    # 第一个参数
$2    # 第二个参数
$#    # 参数个数
$*    # 所有参数（作为一个字符串）
$@    # 所有参数（作为独立字符串）
$$    # 当前进程 PID
$!    # 最后一个后台进程 PID
$?    # 上一个命令的退出状态
```

### 3.3 $* 和 $@ 的区别

```bash
#!/bin/bash
# test.sh

echo "使用 \$*:"
for arg in "$*"; do
    echo "  $arg"
done

echo "使用 \$@:"
for arg in "$@"; do
    echo "  $arg"
done

# 执行：./test.sh a b c
# 输出：
# 使用 $*:
#   a b c        （一个整体）
# 使用 $@:
#   a            （独立的参数）
#   b
#   c
```

### 3.4 变量默认值

```bash
# ${var:-default}  如果 var 未定义或为空，返回 default
echo ${name:-"默认名字"}

# ${var:=default}  如果 var 未定义或为空，设置为 default 并返回
echo ${name:="默认名字"}

# ${var:+value}    如果 var 已定义且非空，返回 value
echo ${name:+"名字已设置"}

# ${var:?message}  如果 var 未定义或为空，打印错误信息并退出
echo ${name:?"name 变量未设置"}

# 实际应用
DB_HOST=${DB_HOST:-"localhost"}
DB_PORT=${DB_PORT:-3306}
```

### 3.5 环境变量

```bash
# 常用环境变量
echo $HOME       # 用户主目录
echo $USER       # 当前用户名
echo $PATH       # 命令搜索路径
echo $PWD        # 当前工作目录
echo $SHELL      # 当前 Shell
echo $LANG       # 语言设置
echo $HOSTNAME   # 主机名

# 设置环境变量
export MY_VAR="my value"

# 永久设置（添加到配置文件）
# ~/.bashrc      当前用户
# /etc/profile   所有用户

# 修改 PATH
export PATH=$PATH:/usr/local/bin
```

---

## 4. 字符串操作

### 4.1 字符串定义

```bash
# 单引号：原样输出，不解析变量
str1='hello $name'
echo $str1  # hello $name

# 双引号：解析变量和转义字符
name="world"
str2="hello $name"
echo $str2  # hello world

# 不加引号：会进行单词分割和通配符扩展
str3=hello
```

### 4.2 字符串操作

```bash
str="Hello, World!"

# 获取长度
echo ${#str}           # 13

# 截取子串
echo ${str:0:5}        # Hello（从位置0开始，取5个字符）
echo ${str:7}          # World!（从位置7到末尾）
echo ${str: -6}        # World!（从倒数第6个开始，注意空格）
echo ${str: -6:5}      # World（从倒数第6个开始，取5个）

# 查找替换
echo ${str/World/Shell}     # Hello, Shell!（替换第一个）
echo ${str//l/L}            # HeLLo, WorLd!（替换所有）

# 删除匹配
filename="backup.tar.gz"
echo ${filename#*.}         # tar.gz（从左删除最短匹配）
echo ${filename##*.}        # gz（从左删除最长匹配）
echo ${filename%.*}         # backup.tar（从右删除最短匹配）
echo ${filename%%.*}        # backup（从右删除最长匹配）

# 大小写转换（Bash 4.0+）
echo ${str^^}          # HELLO, WORLD!（全部大写）
echo ${str,,}          # hello, world!（全部小写）
echo ${str^}           # Hello, World!（首字母大写）
```

### 4.3 字符串拼接

```bash
str1="Hello"
str2="World"

# 直接拼接
str3=$str1$str2
echo $str3  # HelloWorld

# 使用双引号
str4="$str1 $str2"
echo $str4  # Hello World

# 使用花括号
str5="${str1}_${str2}"
echo $str5  # Hello_World
```

### 4.4 字符串比较

```bash
str1="hello"
str2="world"

# 相等
[ "$str1" = "$str2" ]   # 注意空格
[ "$str1" == "$str2" ]  # Bash 扩展

# 不相等
[ "$str1" != "$str2" ]

# 为空
[ -z "$str1" ]  # 长度为0返回真

# 非空
[ -n "$str1" ]  # 长度非0返回真

# 字典序比较
[[ "$str1" < "$str2" ]]   # str1 在 str2 前面
[[ "$str1" > "$str2" ]]   # str1 在 str2 后面
```

---

## 5. 数组

### 5.1 索引数组

```bash
# 定义数组
arr=(a b c d e)
arr[0]="first"
arr[1]="second"

# 访问元素
echo ${arr[0]}      # first
echo ${arr[1]}      # second
echo ${arr[-1]}     # e（最后一个元素，Bash 4.3+）

# 获取所有元素
echo ${arr[@]}      # first second c d e
echo ${arr[*]}      # first second c d e

# 获取数组长度
echo ${#arr[@]}     # 5

# 获取元素长度
echo ${#arr[0]}     # 5（"first" 的长度）

# 获取所有索引
echo ${!arr[@]}     # 0 1 2 3 4

# 数组切片
echo ${arr[@]:1:3}  # second c d（从索引1开始，取3个）
```

### 5.2 数组操作

```bash
arr=(a b c d e)

# 添加元素
arr+=(f g)
arr[${#arr[@]}]="h"

# 删除元素
unset arr[2]        # 删除索引2的元素
echo ${arr[@]}      # a b d e f g h（c 被删除）

# 遍历数组
for item in "${arr[@]}"; do
    echo "$item"
done

# 带索引遍历
for i in "${!arr[@]}"; do
    echo "arr[$i] = ${arr[$i]}"
done
```

### 5.3 关联数组（Bash 4.0+）

```bash
# 声明关联数组
declare -A user

# 赋值
user[name]="张三"
user[age]=25
user[email]="zhangsan@example.com"

# 或者一次性赋值
declare -A config=(
    [host]="localhost"
    [port]=3306
    [user]="root"
)

# 访问
echo ${user[name]}      # 张三
echo ${config[host]}    # localhost

# 获取所有键
echo ${!user[@]}        # name age email

# 获取所有值
echo ${user[@]}         # 张三 25 zhangsan@example.com

# 遍历
for key in "${!user[@]}"; do
    echo "$key: ${user[$key]}"
done
```
