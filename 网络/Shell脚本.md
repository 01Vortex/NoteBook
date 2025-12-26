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


---

## 6. 运算符

### 6.1 算术运算

```bash
a=10
b=3

# 方式1：expr（注意空格）
result=$(expr $a + $b)
result=$(expr $a - $b)
result=$(expr $a \* $b)   # 乘法需要转义
result=$(expr $a / $b)
result=$(expr $a % $b)

# 方式2：$(()) 推荐
result=$((a + b))
result=$((a - b))
result=$((a * b))
result=$((a / b))
result=$((a % b))
result=$((a ** 2))    # 幂运算

# 方式3：$[]
result=$[a + b]

# 方式4：let
let result=a+b
let a++
let a--
let a+=5

# 方式5：bc（支持浮点运算）
result=$(echo "scale=2; 10 / 3" | bc)   # 3.33
result=$(echo "scale=4; sqrt(2)" | bc)  # 1.4142

# 自增自减
((a++))
((a--))
((++a))
((--a))
```

### 6.2 关系运算符

```bash
a=10
b=20

# 数值比较（用于 [ ] 和 test）
[ $a -eq $b ]   # 等于 (equal)
[ $a -ne $b ]   # 不等于 (not equal)
[ $a -gt $b ]   # 大于 (greater than)
[ $a -lt $b ]   # 小于 (less than)
[ $a -ge $b ]   # 大于等于 (greater or equal)
[ $a -le $b ]   # 小于等于 (less or equal)

# 数值比较（用于 (( ))）
(( a == b ))
(( a != b ))
(( a > b ))
(( a < b ))
(( a >= b ))
(( a <= b ))
```

### 6.3 逻辑运算符

```bash
# 在 [ ] 中
[ $a -gt 5 -a $b -lt 30 ]   # AND
[ $a -gt 5 -o $b -lt 30 ]   # OR
[ ! $a -gt 5 ]              # NOT

# 在 [[ ]] 中（推荐）
[[ $a -gt 5 && $b -lt 30 ]]  # AND
[[ $a -gt 5 || $b -lt 30 ]]  # OR
[[ ! $a -gt 5 ]]             # NOT

# 命令级别
cmd1 && cmd2    # cmd1 成功才执行 cmd2
cmd1 || cmd2    # cmd1 失败才执行 cmd2
```

### 6.4 文件测试运算符

```bash
file="/etc/passwd"
dir="/tmp"

# 文件类型测试
[ -e $file ]    # 文件存在
[ -f $file ]    # 是普通文件
[ -d $dir ]     # 是目录
[ -L $file ]    # 是符号链接
[ -b $file ]    # 是块设备
[ -c $file ]    # 是字符设备
[ -p $file ]    # 是管道
[ -S $file ]    # 是 Socket

# 文件权限测试
[ -r $file ]    # 可读
[ -w $file ]    # 可写
[ -x $file ]    # 可执行
[ -u $file ]    # 有 SUID 位
[ -g $file ]    # 有 SGID 位
[ -k $file ]    # 有粘滞位

# 文件属性测试
[ -s $file ]    # 文件大小不为0
[ -N $file ]    # 文件自上次读取后被修改

# 文件比较
[ $file1 -nt $file2 ]   # file1 比 file2 新
[ $file1 -ot $file2 ]   # file1 比 file2 旧
[ $file1 -ef $file2 ]   # 是同一个文件（硬链接）
```

---

## 7. 条件判断

### 7.1 if 语句

```bash
# 基本语法
if [ condition ]; then
    commands
fi

# if-else
if [ condition ]; then
    commands
else
    commands
fi

# if-elif-else
if [ condition1 ]; then
    commands
elif [ condition2 ]; then
    commands
else
    commands
fi

# 实际示例
#!/bin/bash
read -p "请输入分数: " score

if [ $score -ge 90 ]; then
    echo "优秀"
elif [ $score -ge 80 ]; then
    echo "良好"
elif [ $score -ge 60 ]; then
    echo "及格"
else
    echo "不及格"
fi
```

### 7.2 [ ] 和 [[ ]] 的区别

```bash
# [ ] 是 test 命令的简写，POSIX 兼容
# [[ ]] 是 Bash 扩展，功能更强大

# 1. 字符串比较
str="hello world"

# [ ] 中变量必须加引号
[ "$str" = "hello world" ]   # 正确
[ $str = "hello world" ]     # 错误！会被分割

# [[ ]] 中可以不加引号
[[ $str = "hello world" ]]   # 正确

# 2. 模式匹配（只有 [[ ]] 支持）
[[ $str == hello* ]]         # 通配符匹配
[[ $str =~ ^hello ]]         # 正则匹配

# 3. 逻辑运算
# [ ] 使用 -a 和 -o
[ $a -gt 5 -a $b -lt 10 ]

# [[ ]] 使用 && 和 ||
[[ $a -gt 5 && $b -lt 10 ]]

# 4. 推荐使用 [[ ]]，更安全、功能更强
```

### 7.3 case 语句

```bash
#!/bin/bash
# case 语句示例

read -p "请输入选项 (y/n): " choice

case $choice in
    y|Y|yes|YES)
        echo "你选择了是"
        ;;
    n|N|no|NO)
        echo "你选择了否"
        ;;
    *)
        echo "无效选项"
        ;;
esac

# 更复杂的示例
case $1 in
    start)
        echo "启动服务..."
        ;;
    stop)
        echo "停止服务..."
        ;;
    restart)
        echo "重启服务..."
        ;;
    status)
        echo "查看状态..."
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
```

### 7.4 条件表达式

```bash
# 三元运算符模拟
result=$([ $a -gt $b ] && echo "a大" || echo "b大")

# 简洁的条件执行
[ -f /etc/passwd ] && echo "文件存在"
[ -f /nonexistent ] || echo "文件不存在"

# 组合使用
[ -f "$file" ] && cat "$file" || echo "文件不存在"
```

---

## 8. 循环结构

### 8.1 for 循环

```bash
# 基本语法
for var in list; do
    commands
done

# 遍历列表
for i in 1 2 3 4 5; do
    echo $i
done

# 遍历范围
for i in {1..10}; do
    echo $i
done

# 带步长
for i in {0..100..10}; do
    echo $i  # 0, 10, 20, ..., 100
done

# 遍历数组
arr=(a b c d e)
for item in "${arr[@]}"; do
    echo $item
done

# 遍历文件
for file in /etc/*.conf; do
    echo "配置文件: $file"
done

# 遍历命令输出
for user in $(cat /etc/passwd | cut -d: -f1); do
    echo "用户: $user"
done

# C 风格 for 循环
for ((i=0; i<10; i++)); do
    echo $i
done

# 无限循环
for ((;;)); do
    echo "无限循环"
    sleep 1
done
```

### 8.2 while 循环

```bash
# 基本语法
while [ condition ]; do
    commands
done

# 计数循环
count=1
while [ $count -le 5 ]; do
    echo "第 $count 次"
    ((count++))
done

# 读取文件
while read line; do
    echo "$line"
done < /etc/passwd

# 读取文件（保留空格）
while IFS= read -r line; do
    echo "$line"
done < file.txt

# 无限循环
while true; do
    echo "运行中..."
    sleep 1
done

# 或者
while :; do
    echo "运行中..."
    sleep 1
done
```

### 8.3 until 循环

```bash
# until 与 while 相反，条件为假时执行
count=1
until [ $count -gt 5 ]; do
    echo "第 $count 次"
    ((count++))
done
```

### 8.4 循环控制

```bash
# break - 跳出循环
for i in {1..10}; do
    if [ $i -eq 5 ]; then
        break
    fi
    echo $i
done
# 输出: 1 2 3 4

# continue - 跳过本次循环
for i in {1..10}; do
    if [ $i -eq 5 ]; then
        continue
    fi
    echo $i
done
# 输出: 1 2 3 4 6 7 8 9 10

# break n - 跳出 n 层循环
for i in {1..3}; do
    for j in {1..3}; do
        if [ $j -eq 2 ]; then
            break 2  # 跳出两层循环
        fi
        echo "$i-$j"
    done
done
```

### 8.5 select 菜单

```bash
#!/bin/bash
# select 创建菜单

PS3="请选择操作: "  # 设置提示符

select opt in "查看" "添加" "删除" "退出"; do
    case $opt in
        "查看")
            echo "执行查看操作"
            ;;
        "添加")
            echo "执行添加操作"
            ;;
        "删除")
            echo "执行删除操作"
            ;;
        "退出")
            echo "再见！"
            break
            ;;
        *)
            echo "无效选项"
            ;;
    esac
done
```


---

## 9. 函数

### 9.1 函数定义

```bash
# 方式1：使用 function 关键字
function greet() {
    echo "Hello, $1!"
}

# 方式2：省略 function（推荐）
greet() {
    echo "Hello, $1!"
}

# 调用函数
greet "World"
greet "Shell"
```

### 9.2 函数参数

```bash
#!/bin/bash

show_info() {
    echo "函数名: $FUNCNAME"
    echo "参数个数: $#"
    echo "所有参数: $@"
    echo "第一个参数: $1"
    echo "第二个参数: $2"
}

show_info "参数1" "参数2" "参数3"

# 输出：
# 函数名: show_info
# 参数个数: 3
# 所有参数: 参数1 参数2 参数3
# 第一个参数: 参数1
# 第二个参数: 参数2
```

### 9.3 函数返回值

```bash
# 方式1：使用 return（只能返回 0-255 的整数）
is_even() {
    if [ $(($1 % 2)) -eq 0 ]; then
        return 0  # 真
    else
        return 1  # 假
    fi
}

if is_even 4; then
    echo "4 是偶数"
fi

# 方式2：使用 echo 输出（推荐，可以返回任意值）
add() {
    local result=$(($1 + $2))
    echo $result
}

sum=$(add 10 20)
echo "10 + 20 = $sum"

# 方式3：使用全局变量
RESULT=""
multiply() {
    RESULT=$(($1 * $2))
}

multiply 5 6
echo "5 * 6 = $RESULT"
```

### 9.4 局部变量

```bash
#!/bin/bash

global_var="全局变量"

test_scope() {
    local local_var="局部变量"
    global_var="修改后的全局变量"
    
    echo "函数内 - local_var: $local_var"
    echo "函数内 - global_var: $global_var"
}

test_scope

echo "函数外 - local_var: $local_var"      # 空
echo "函数外 - global_var: $global_var"    # 修改后的全局变量
```

### 9.5 递归函数

```bash
#!/bin/bash

# 计算阶乘
factorial() {
    local n=$1
    if [ $n -le 1 ]; then
        echo 1
    else
        local prev=$(factorial $((n - 1)))
        echo $((n * prev))
    fi
}

echo "5! = $(factorial 5)"  # 120

# 计算斐波那契数列
fibonacci() {
    local n=$1
    if [ $n -le 1 ]; then
        echo $n
    else
        local a=$(fibonacci $((n - 1)))
        local b=$(fibonacci $((n - 2)))
        echo $((a + b))
    fi
}

echo "fib(10) = $(fibonacci 10)"  # 55
```

### 9.6 函数库

```bash
# lib/utils.sh - 函数库文件
#!/bin/bash

# 日志函数
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $1" >&2
}

log_warn() {
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# 检查命令是否存在
command_exists() {
    command -v "$1" &> /dev/null
}

# 检查是否为 root 用户
is_root() {
    [ "$(id -u)" -eq 0 ]
}

# 确认操作
confirm() {
    local prompt="${1:-确认操作?}"
    read -p "$prompt [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]]
}
```

```bash
# main.sh - 主脚本
#!/bin/bash

# 引入函数库
source lib/utils.sh
# 或者
. lib/utils.sh

# 使用函数
log_info "脚本开始执行"

if ! is_root; then
    log_error "需要 root 权限"
    exit 1
fi

if confirm "是否继续?"; then
    log_info "继续执行..."
else
    log_info "用户取消"
    exit 0
fi
```

---

## 10. 输入输出

### 10.1 read 命令

```bash
# 基本读取
read name
echo "你好, $name"

# 带提示
read -p "请输入用户名: " username

# 静默输入（密码）
read -s -p "请输入密码: " password
echo  # 换行

# 限时输入
read -t 5 -p "5秒内输入: " input

# 限制字符数
read -n 1 -p "按任意键继续..." key

# 读取到数组
read -a arr -p "输入多个值（空格分隔）: "
echo "第一个: ${arr[0]}"

# 设置分隔符
IFS=':' read -r user pass uid gid info home shell <<< "root:x:0:0:root:/root:/bin/bash"
echo "用户: $user, 主目录: $home"

# 读取多行
while read -r line; do
    echo "行: $line"
done << EOF
第一行
第二行
第三行
EOF
```

### 10.2 输出命令

```bash
# echo
echo "Hello World"
echo -n "不换行"        # 不换行
echo -e "换行\n制表\t"  # 解释转义字符

# printf（更强大的格式化）
printf "姓名: %s, 年龄: %d\n" "张三" 25
printf "%-10s %5d\n" "张三" 25    # 左对齐，右对齐
printf "%05d\n" 42                # 补零
printf "%.2f\n" 3.14159           # 小数位数

# 格式说明符
# %s - 字符串
# %d - 整数
# %f - 浮点数
# %x - 十六进制
# %o - 八进制
# %% - 百分号
```

### 10.3 重定向

```bash
# 标准输入(0)、标准输出(1)、标准错误(2)

# 输出重定向
echo "hello" > file.txt      # 覆盖写入
echo "world" >> file.txt     # 追加写入

# 错误重定向
cmd 2> error.log             # 错误输出到文件
cmd 2>> error.log            # 错误追加到文件

# 同时重定向
cmd > output.log 2>&1        # 标准输出和错误都到文件
cmd &> output.log            # 简写形式
cmd > output.log 2> error.log  # 分开重定向

# 丢弃输出
cmd > /dev/null              # 丢弃标准输出
cmd 2> /dev/null             # 丢弃错误输出
cmd &> /dev/null             # 丢弃所有输出

# 输入重定向
cmd < input.txt              # 从文件读取输入
cmd << EOF                   # Here Document
line1
line2
EOF

# Here String
cmd <<< "input string"
```

### 10.4 管道

```bash
# 基本管道
cat file.txt | grep "pattern" | sort | uniq

# 管道与重定向组合
cat file.txt | grep "error" > errors.txt

# tee - 同时输出到屏幕和文件
cat file.txt | tee output.txt
cat file.txt | tee -a output.txt  # 追加模式

# xargs - 将输入转换为命令参数
find . -name "*.txt" | xargs rm
find . -name "*.txt" | xargs -I {} cp {} /backup/
echo "a b c" | xargs -n 1 echo  # 每个参数单独处理
```

### 10.5 进程替换

```bash
# <() 将命令输出作为文件
diff <(ls dir1) <(ls dir2)

# >() 将文件作为命令输入
tee >(gzip > file.gz) < input.txt

# 实际应用：比较两个命令的输出
diff <(sort file1.txt) <(sort file2.txt)
```


---

## 11. 文件操作

### 11.1 文件测试

```bash
#!/bin/bash

file="/etc/passwd"

# 检查文件是否存在
if [ -e "$file" ]; then
    echo "文件存在"
fi

# 检查是否为普通文件
if [ -f "$file" ]; then
    echo "是普通文件"
fi

# 检查是否为目录
if [ -d "/tmp" ]; then
    echo "是目录"
fi

# 检查文件是否可读
if [ -r "$file" ]; then
    echo "文件可读"
fi

# 检查文件是否为空
if [ -s "$file" ]; then
    echo "文件非空"
fi

# 综合示例
check_file() {
    local file=$1
    
    if [ ! -e "$file" ]; then
        echo "文件不存在: $file"
        return 1
    fi
    
    echo "文件信息: $file"
    echo "  类型: $(file -b "$file")"
    echo "  大小: $(stat -c %s "$file") 字节"
    echo "  权限: $(stat -c %A "$file")"
    echo "  所有者: $(stat -c %U "$file")"
    echo "  修改时间: $(stat -c %y "$file")"
}

check_file "/etc/passwd"
```

### 11.2 文件操作命令

```bash
# 创建文件
touch file.txt
> file.txt                    # 创建空文件或清空文件

# 复制文件
cp source.txt dest.txt
cp -r source_dir dest_dir     # 递归复制目录
cp -p file.txt backup/        # 保留属性

# 移动/重命名
mv old.txt new.txt
mv file.txt /path/to/dir/

# 删除文件
rm file.txt
rm -f file.txt                # 强制删除
rm -r dir/                    # 递归删除目录
rm -rf dir/                   # 强制递归删除

# 创建目录
mkdir dir
mkdir -p path/to/dir          # 递归创建

# 删除目录
rmdir dir                     # 只能删除空目录
rm -r dir                     # 删除非空目录

# 链接
ln source.txt hard_link.txt   # 硬链接
ln -s source.txt soft_link.txt  # 软链接

# 查找文件
find /path -name "*.txt"
find /path -type f -mtime -7  # 7天内修改的文件
find /path -size +100M        # 大于100M的文件
find /path -name "*.log" -exec rm {} \;  # 查找并删除
```

### 11.3 文件内容操作

```bash
# 查看文件
cat file.txt                  # 显示全部内容
head -n 10 file.txt           # 显示前10行
tail -n 10 file.txt           # 显示后10行
tail -f file.txt              # 实时跟踪文件
less file.txt                 # 分页查看
more file.txt                 # 分页查看

# 统计
wc file.txt                   # 行数、单词数、字节数
wc -l file.txt                # 只显示行数
wc -w file.txt                # 只显示单词数
wc -c file.txt                # 只显示字节数

# 排序
sort file.txt                 # 排序
sort -r file.txt              # 逆序
sort -n file.txt              # 数字排序
sort -k 2 file.txt            # 按第2列排序
sort -t: -k3 -n /etc/passwd   # 指定分隔符

# 去重
uniq file.txt                 # 去除相邻重复行
sort file.txt | uniq          # 先排序再去重
sort file.txt | uniq -c       # 统计重复次数
sort file.txt | uniq -d       # 只显示重复行

# 比较
diff file1.txt file2.txt
diff -u file1.txt file2.txt   # unified 格式
diff -y file1.txt file2.txt   # 并排显示

# 合并
cat file1.txt file2.txt > merged.txt
paste file1.txt file2.txt     # 按列合并
join file1.txt file2.txt      # 按字段合并
```

### 11.4 临时文件

```bash
#!/bin/bash

# 创建临时文件
tmpfile=$(mktemp)
echo "临时文件: $tmpfile"

# 创建临时目录
tmpdir=$(mktemp -d)
echo "临时目录: $tmpdir"

# 使用临时文件
echo "some data" > "$tmpfile"
cat "$tmpfile"

# 清理临时文件（使用 trap）
cleanup() {
    rm -f "$tmpfile"
    rm -rf "$tmpdir"
    echo "清理完成"
}

trap cleanup EXIT  # 脚本退出时自动清理

# 业务逻辑
echo "处理中..."
```

---

## 12. 文本处理

### 12.1 grep

```bash
# 基本搜索
grep "pattern" file.txt

# 常用选项
grep -i "pattern" file.txt    # 忽略大小写
grep -v "pattern" file.txt    # 反向匹配（不包含）
grep -n "pattern" file.txt    # 显示行号
grep -c "pattern" file.txt    # 统计匹配行数
grep -l "pattern" *.txt       # 只显示文件名
grep -r "pattern" dir/        # 递归搜索
grep -w "word" file.txt       # 全词匹配
grep -A 2 "pattern" file.txt  # 显示匹配行及后2行
grep -B 2 "pattern" file.txt  # 显示匹配行及前2行
grep -C 2 "pattern" file.txt  # 显示匹配行及前后2行

# 正则表达式
grep -E "pattern1|pattern2" file.txt  # 扩展正则
grep "^start" file.txt        # 以 start 开头
grep "end$" file.txt          # 以 end 结尾
grep "^$" file.txt            # 空行
grep -E "[0-9]+" file.txt     # 数字

# 实际应用
grep -r "TODO" --include="*.py" .  # 搜索 Python 文件中的 TODO
ps aux | grep nginx           # 查找进程
cat /var/log/syslog | grep -i error  # 查找错误日志
```

### 12.2 sed

```bash
# sed - 流编辑器

# 替换
sed 's/old/new/' file.txt         # 替换每行第一个
sed 's/old/new/g' file.txt        # 替换所有
sed 's/old/new/gi' file.txt       # 忽略大小写
sed -i 's/old/new/g' file.txt     # 直接修改文件
sed -i.bak 's/old/new/g' file.txt # 修改并备份

# 删除
sed '/pattern/d' file.txt         # 删除匹配行
sed '1d' file.txt                 # 删除第1行
sed '1,5d' file.txt               # 删除1-5行
sed '$d' file.txt                 # 删除最后一行
sed '/^$/d' file.txt              # 删除空行
sed '/^#/d' file.txt              # 删除注释行

# 插入和追加
sed '1i\新的第一行' file.txt      # 在第1行前插入
sed '1a\新的第二行' file.txt      # 在第1行后追加
sed '/pattern/i\插入行' file.txt  # 在匹配行前插入
sed '/pattern/a\追加行' file.txt  # 在匹配行后追加

# 打印
sed -n '5p' file.txt              # 只打印第5行
sed -n '1,10p' file.txt           # 打印1-10行
sed -n '/pattern/p' file.txt     # 打印匹配行

# 多个命令
sed -e 's/a/A/g' -e 's/b/B/g' file.txt
sed 's/a/A/g; s/b/B/g' file.txt

# 实际应用
# 修改配置文件
sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config

# 批量重命名
for f in *.txt; do
    mv "$f" "$(echo $f | sed 's/old/new/')"
done
```

### 12.3 awk

```bash
# awk - 强大的文本处理工具

# 基本语法
awk 'pattern { action }' file.txt

# 打印列
awk '{print $1}' file.txt         # 打印第1列
awk '{print $1, $3}' file.txt     # 打印第1和第3列
awk '{print $NF}' file.txt        # 打印最后一列
awk '{print NR, $0}' file.txt     # 打印行号和整行

# 内置变量
# $0 - 整行
# $1, $2... - 第n列
# NF - 列数
# NR - 行号
# FS - 字段分隔符
# RS - 记录分隔符
# OFS - 输出字段分隔符

# 指定分隔符
awk -F: '{print $1, $3}' /etc/passwd
awk -F'[,:]' '{print $1}' file.txt  # 多个分隔符

# 条件过滤
awk '$3 > 100' file.txt           # 第3列大于100
awk '/pattern/' file.txt          # 包含 pattern
awk '$1 == "root"' /etc/passwd    # 第1列等于 root
awk 'NR > 1' file.txt             # 跳过第一行

# 计算
awk '{sum += $1} END {print sum}' file.txt  # 求和
awk '{sum += $1} END {print sum/NR}' file.txt  # 平均值
awk 'BEGIN {max=0} $1>max {max=$1} END {print max}' file.txt  # 最大值

# 格式化输出
awk '{printf "%-10s %5d\n", $1, $2}' file.txt

# BEGIN 和 END
awk 'BEGIN {print "开始"} {print $0} END {print "结束"}' file.txt

# 实际应用
# 统计日志中各 IP 的访问次数
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10

# 计算文件大小总和
ls -l | awk '{sum += $5} END {print sum}'

# 提取特定字段
awk -F: '$3 >= 1000 {print $1}' /etc/passwd  # UID >= 1000 的用户
```

### 12.4 cut 和 tr

```bash
# cut - 按列切割
cut -d: -f1 /etc/passwd           # 以:分隔，取第1列
cut -d: -f1,3 /etc/passwd         # 取第1和第3列
cut -d: -f1-3 /etc/passwd         # 取第1到第3列
cut -c1-10 file.txt               # 取每行前10个字符

# tr - 字符转换
echo "hello" | tr 'a-z' 'A-Z'     # 小写转大写
echo "hello" | tr -d 'l'          # 删除字符
echo "hello   world" | tr -s ' '  # 压缩重复字符
cat file.txt | tr '\n' ' '        # 换行转空格
```


---

## 13. 正则表达式

### 13.1 基本正则表达式（BRE）

```bash
# 基本元字符
.       # 匹配任意单个字符
*       # 匹配前一个字符0次或多次
^       # 匹配行首
$       # 匹配行尾
[]      # 字符集合
[^]     # 否定字符集合
\       # 转义字符

# 示例
grep "^root" /etc/passwd          # 以 root 开头
grep "bash$" /etc/passwd          # 以 bash 结尾
grep "^$" file.txt                # 空行
grep "r..t" /etc/passwd           # r 和 t 之间有两个字符
grep "ro*t" file.txt              # r 后面有0个或多个 o
grep "[aeiou]" file.txt           # 包含元音字母
grep "[^0-9]" file.txt            # 不包含数字
grep "^[^#]" file.txt             # 不以 # 开头的行
```

### 13.2 扩展正则表达式（ERE）

```bash
# 使用 grep -E 或 egrep

# 扩展元字符
+       # 匹配前一个字符1次或多次
?       # 匹配前一个字符0次或1次
|       # 或
()      # 分组
{n}     # 匹配n次
{n,}    # 匹配至少n次
{n,m}   # 匹配n到m次

# 示例
grep -E "go+d" file.txt           # good, goood, gooood...
grep -E "colou?r" file.txt        # color 或 colour
grep -E "cat|dog" file.txt        # cat 或 dog
grep -E "(ab)+" file.txt          # ab, abab, ababab...
grep -E "[0-9]{3}" file.txt       # 3个数字
grep -E "[0-9]{2,4}" file.txt     # 2到4个数字

# 常用正则
grep -E "^[0-9]+$" file.txt       # 纯数字行
grep -E "^[a-zA-Z]+$" file.txt    # 纯字母行
grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" file.txt  # 邮箱
grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" file.txt  # IP地址
```

### 13.3 Bash 正则匹配

```bash
#!/bin/bash

# 使用 =~ 进行正则匹配
string="hello123world"

if [[ $string =~ [0-9]+ ]]; then
    echo "包含数字"
    echo "匹配内容: ${BASH_REMATCH[0]}"  # 123
fi

# 验证邮箱
email="test@example.com"
email_regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

if [[ $email =~ $email_regex ]]; then
    echo "有效的邮箱"
else
    echo "无效的邮箱"
fi

# 验证 IP 地址
ip="192.168.1.100"
ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

if [[ $ip =~ $ip_regex ]]; then
    echo "有效的 IP 地址"
fi

# 提取匹配组
date_str="2024-01-15"
if [[ $date_str =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2})$ ]]; then
    echo "年: ${BASH_REMATCH[1]}"
    echo "月: ${BASH_REMATCH[2]}"
    echo "日: ${BASH_REMATCH[3]}"
fi
```

---

## 14. 进程管理

### 14.1 进程查看

```bash
# ps - 查看进程
ps                    # 当前终端进程
ps aux                # 所有进程（BSD 风格）
ps -ef                # 所有进程（System V 风格）
ps -u username        # 指定用户的进程
ps -p 1234            # 指定 PID 的进程

# top - 动态查看进程
top
top -p 1234           # 监控指定进程
top -u username       # 监控指定用户

# htop - 更友好的 top（需要安装）
htop

# pgrep - 根据名称查找进程
pgrep nginx           # 返回 PID
pgrep -l nginx        # 返回 PID 和名称
pgrep -u root         # 指定用户的进程
```

### 14.2 进程控制

```bash
# 后台运行
command &             # 后台运行
nohup command &       # 后台运行，忽略挂断信号
nohup command > output.log 2>&1 &  # 后台运行并记录日志

# 作业控制
jobs                  # 查看后台作业
fg %1                 # 将作业1调到前台
bg %1                 # 将作业1放到后台
Ctrl+Z                # 暂停当前进程
Ctrl+C                # 终止当前进程

# 终止进程
kill PID              # 发送 SIGTERM（15）
kill -9 PID           # 发送 SIGKILL（9），强制终止
kill -HUP PID         # 发送 SIGHUP（1），重新加载配置
killall nginx         # 终止所有 nginx 进程
pkill -f "pattern"    # 根据模式终止进程

# 常用信号
# 1  SIGHUP   挂断
# 2  SIGINT   中断（Ctrl+C）
# 9  SIGKILL  强制终止
# 15 SIGTERM  终止（默认）
# 18 SIGCONT  继续
# 19 SIGSTOP  停止
```

### 14.3 进程优先级

```bash
# nice - 启动时设置优先级（-20 到 19，越小优先级越高）
nice -n 10 command    # 以较低优先级运行

# renice - 修改运行中进程的优先级
renice 10 -p PID      # 修改指定进程
renice 10 -u username # 修改指定用户的所有进程
```

### 14.4 脚本中的进程管理

```bash
#!/bin/bash

# 获取脚本自身 PID
echo "当前脚本 PID: $$"

# 获取父进程 PID
echo "父进程 PID: $PPID"

# 后台运行并获取 PID
sleep 100 &
bg_pid=$!
echo "后台进程 PID: $bg_pid"

# 等待后台进程
wait $bg_pid
echo "后台进程已结束"

# 等待所有后台进程
wait

# 检查进程是否存在
if kill -0 $pid 2>/dev/null; then
    echo "进程 $pid 存在"
else
    echo "进程 $pid 不存在"
fi

# 超时执行
timeout 5 command     # 5秒超时
timeout --signal=KILL 5 command  # 超时后强制终止
```

### 14.5 trap 信号处理

```bash
#!/bin/bash

# 捕获信号
cleanup() {
    echo "收到退出信号，清理中..."
    rm -f /tmp/myapp.pid
    exit 0
}

# 注册信号处理
trap cleanup SIGINT SIGTERM EXIT

# 忽略信号
trap '' SIGHUP

# 恢复默认处理
trap - SIGINT

# 实际应用：优雅退出
#!/bin/bash

PID_FILE="/tmp/myapp.pid"
LOG_FILE="/tmp/myapp.log"

cleanup() {
    echo "正在停止服务..."
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGINT SIGTERM

# 记录 PID
echo $$ > "$PID_FILE"

# 主循环
while true; do
    echo "$(date): 服务运行中..." >> "$LOG_FILE"
    sleep 5
done
```

---

## 15. 实战脚本

### 15.1 系统监控脚本

```bash
#!/bin/bash
#===============================================
# 系统监控脚本
# 监控 CPU、内存、磁盘使用情况
#===============================================

# 配置
THRESHOLD_CPU=80
THRESHOLD_MEM=80
THRESHOLD_DISK=90
LOG_FILE="/var/log/system_monitor.log"

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

# 检查 CPU 使用率
check_cpu() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    cpu_usage=${cpu_usage%.*}  # 取整数部分
    
    if [ "$cpu_usage" -gt "$THRESHOLD_CPU" ]; then
        log "[警告] CPU 使用率过高: ${cpu_usage}%"
        return 1
    fi
    log "[正常] CPU 使用率: ${cpu_usage}%"
    return 0
}

# 检查内存使用率
check_memory() {
    local mem_info=$(free | grep Mem)
    local total=$(echo $mem_info | awk '{print $2}')
    local used=$(echo $mem_info | awk '{print $3}')
    local usage=$((used * 100 / total))
    
    if [ "$usage" -gt "$THRESHOLD_MEM" ]; then
        log "[警告] 内存使用率过高: ${usage}%"
        return 1
    fi
    log "[正常] 内存使用率: ${usage}%"
    return 0
}

# 检查磁盘使用率
check_disk() {
    local alert=0
    
    while read line; do
        local usage=$(echo $line | awk '{print $5}' | tr -d '%')
        local mount=$(echo $line | awk '{print $6}')
        
        if [ "$usage" -gt "$THRESHOLD_DISK" ]; then
            log "[警告] 磁盘 $mount 使用率过高: ${usage}%"
            alert=1
        fi
    done < <(df -h | grep -E '^/dev/')
    
    if [ $alert -eq 0 ]; then
        log "[正常] 磁盘使用率正常"
    fi
    return $alert
}

# 主函数
main() {
    log "========== 系统监控开始 =========="
    
    check_cpu
    check_memory
    check_disk
    
    log "========== 系统监控结束 =========="
}

main
```

### 15.2 日志分析脚本

```bash
#!/bin/bash
#===============================================
# Nginx 访问日志分析脚本
#===============================================

LOG_FILE="${1:-/var/log/nginx/access.log}"

if [ ! -f "$LOG_FILE" ]; then
    echo "日志文件不存在: $LOG_FILE"
    exit 1
fi

echo "========== Nginx 日志分析 =========="
echo "日志文件: $LOG_FILE"
echo ""

# 总请求数
total=$(wc -l < "$LOG_FILE")
echo "总请求数: $total"
echo ""

# Top 10 IP
echo "Top 10 访问 IP:"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10
echo ""

# Top 10 URL
echo "Top 10 访问 URL:"
awk '{print $7}' "$LOG_FILE" | sort | uniq -c | sort -rn | head -10
echo ""

# HTTP 状态码统计
echo "HTTP 状态码统计:"
awk '{print $9}' "$LOG_FILE" | sort | uniq -c | sort -rn
echo ""

# 每小时请求数
echo "每小时请求数:"
awk '{print $4}' "$LOG_FILE" | cut -d: -f2 | sort | uniq -c
echo ""

# 错误请求（4xx, 5xx）
echo "错误请求数:"
awk '$9 ~ /^[45]/' "$LOG_FILE" | wc -l
```

### 15.3 备份脚本

```bash
#!/bin/bash
#===============================================
# 数据库备份脚本
#===============================================

# 配置
DB_HOST="localhost"
DB_USER="root"
DB_PASS="password"
DB_NAME="mydb"
BACKUP_DIR="/backup/mysql"
KEEP_DAYS=7

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 备份文件名
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/${DB_NAME}_${DATE}.sql.gz"

# 执行备份
echo "开始备份数据库: $DB_NAME"
mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" | gzip > "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "备份成功: $BACKUP_FILE"
    echo "文件大小: $(du -h "$BACKUP_FILE" | cut -f1)"
else
    echo "备份失败!"
    exit 1
fi

# 清理旧备份
echo "清理 $KEEP_DAYS 天前的备份..."
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$KEEP_DAYS -delete

echo "当前备份文件:"
ls -lh "$BACKUP_DIR"
```

### 15.4 服务管理脚本

```bash
#!/bin/bash
#===============================================
# 服务管理脚本
#===============================================

APP_NAME="myapp"
APP_PATH="/opt/myapp"
PID_FILE="/var/run/${APP_NAME}.pid"
LOG_FILE="/var/log/${APP_NAME}.log"

start() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "$APP_NAME 已经在运行 (PID: $pid)"
            return 1
        fi
    fi
    
    echo "启动 $APP_NAME..."
    nohup "$APP_PATH/bin/start.sh" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    echo "$APP_NAME 已启动 (PID: $!)"
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "$APP_NAME 未运行"
        return 1
    fi
    
    pid=$(cat "$PID_FILE")
    echo "停止 $APP_NAME (PID: $pid)..."
    kill "$pid"
    
    # 等待进程结束
    for i in {1..30}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$PID_FILE"
            echo "$APP_NAME 已停止"
            return 0
        fi
        sleep 1
    done
    
    # 强制终止
    echo "强制终止..."
    kill -9 "$pid"
    rm -f "$PID_FILE"
}

status() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "$APP_NAME 正在运行 (PID: $pid)"
            return 0
        fi
    fi
    echo "$APP_NAME 未运行"
    return 1
}

restart() {
    stop
    sleep 2
    start
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
```


---

## 16. 调试技巧

### 16.1 调试选项

```bash
# 方式1：在脚本中设置
#!/bin/bash
set -x  # 开启调试模式，打印每条命令
set +x  # 关闭调试模式

set -e  # 遇到错误立即退出
set +e  # 关闭错误退出

set -u  # 使用未定义变量时报错
set -o pipefail  # 管道中任何命令失败则整体失败

# 组合使用（推荐）
set -euo pipefail

# 方式2：运行时指定
bash -x script.sh   # 调试模式
bash -n script.sh   # 语法检查（不执行）
bash -v script.sh   # 显示脚本内容

# 方式3：部分调试
#!/bin/bash
echo "正常执行"

set -x
# 这部分会打印调试信息
problematic_code
set +x

echo "继续正常执行"
```

### 16.2 调试技巧

```bash
#!/bin/bash

# 1. 打印变量值
debug() {
    echo "[DEBUG] $*" >&2
}

name="test"
debug "name = $name"

# 2. 打印函数调用栈
print_stack() {
    local i=0
    while caller $i; do
        ((i++))
    done
}

# 3. 条件调试
DEBUG=${DEBUG:-false}

debug_log() {
    if [ "$DEBUG" = "true" ]; then
        echo "[DEBUG] $*" >&2
    fi
}

# 使用：DEBUG=true ./script.sh

# 4. 使用 trap 调试
trap 'echo "Line $LINENO: $BASH_COMMAND"' DEBUG

# 5. 检查命令是否存在
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "错误: 命令 '$1' 未找到"
        exit 1
    fi
}

check_command "curl"
check_command "jq"
```

### 16.3 错误处理

```bash
#!/bin/bash
set -euo pipefail

# 错误处理函数
error_handler() {
    local line=$1
    local code=$2
    local command=$3
    echo "错误发生在第 $line 行"
    echo "命令: $command"
    echo "退出码: $code"
}

trap 'error_handler $LINENO $? "$BASH_COMMAND"' ERR

# 自定义错误处理
die() {
    echo "错误: $1" >&2
    exit "${2:-1}"
}

# 使用
[ -f "$file" ] || die "文件不存在: $file"

# try-catch 模拟
try() {
    "$@"
    return $?
}

catch() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "捕获错误，退出码: $exit_code"
        return $exit_code
    fi
}

# 使用
if ! try some_command; then
    catch
    # 错误处理
fi
```

---

## 17. 常见错误与解决方案

### 17.1 语法错误

```bash
# 错误1：变量赋值有空格
name = "value"   # ❌ 错误
name="value"     # ✓ 正确

# 错误2：条件判断缺少空格
if [$a -eq $b]; then   # ❌ 错误
if [ $a -eq $b ]; then # ✓ 正确

# 错误3：字符串比较用错运算符
if [ $a == $b ]; then  # ❌ 在 [ ] 中应该用 =
if [ "$a" = "$b" ]; then  # ✓ 正确

# 错误4：数值比较用错运算符
if [ $a > $b ]; then   # ❌ > 会被当作重定向
if [ $a -gt $b ]; then # ✓ 正确
if (( a > b )); then   # ✓ 或使用 (( ))

# 错误5：忘记引号
file="my file.txt"
cat $file              # ❌ 会被分割成两个参数
cat "$file"            # ✓ 正确
```

### 17.2 变量相关错误

```bash
# 错误1：变量未定义
echo $undefined_var    # 空值，不报错
set -u                 # 开启后会报错
echo ${var:-default}   # 使用默认值

# 错误2：变量名拼接错误
echo $name_suffix      # ❌ 会查找 name_suffix 变量
echo ${name}_suffix    # ✓ 正确

# 错误3：命令替换错误
result=`date`          # 旧语法，难以嵌套
result=$(date)         # ✓ 推荐

# 错误4：数组访问错误
arr=(a b c)
echo $arr              # ❌ 只输出第一个元素
echo ${arr[@]}         # ✓ 输出所有元素
```

### 17.3 文件和路径错误

```bash
# 错误1：路径包含空格
cd /path/to/my folder  # ❌ 错误
cd "/path/to/my folder" # ✓ 正确

# 错误2：相对路径问题
./script.sh            # 当前目录
source script.sh       # 可能找不到

# 解决：使用脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

# 错误3：文件不存在
cat /nonexistent       # 报错
[ -f "$file" ] && cat "$file"  # 先检查

# 错误4：权限问题
./script.sh            # Permission denied
chmod +x script.sh     # 添加执行权限
bash script.sh         # 或直接用 bash 运行
```

### 17.4 循环和条件错误

```bash
# 错误1：for 循环变量被修改
for file in $(ls *.txt); do  # ❌ 文件名有空格会出问题
for file in *.txt; do        # ✓ 正确

# 错误2：while 循环中的管道
cat file.txt | while read line; do
    count=$((count + 1))
done
echo $count  # ❌ 输出 0，因为管道创建了子 shell

# 解决方案
while read line; do
    count=$((count + 1))
done < file.txt
echo $count  # ✓ 正确

# 错误3：条件判断中的命令
if [ $(command) ]; then  # ❌ 如果命令输出为空会报错
if [ -n "$(command)" ]; then  # ✓ 正确

# 错误4：测试空变量
if [ $var = "value" ]; then  # ❌ var 为空时语法错误
if [ "$var" = "value" ]; then  # ✓ 正确
```

### 17.5 其他常见错误

```bash
# 错误1：Here Document 缩进
cat << EOF
    内容
EOF    # ❌ EOF 前不能有空格

cat <<-EOF
    内容
	EOF    # ✓ 使用 <<- 可以有 Tab 缩进

# 错误2：函数返回值
get_value() {
    return "string"  # ❌ return 只能返回数字
}

get_value() {
    echo "string"    # ✓ 使用 echo 返回字符串
}
result=$(get_value)

# 错误3：后台进程
command &
# 脚本立即结束，后台进程可能被终止

command &
wait  # 等待后台进程完成

# 错误4：信号处理
trap "rm -f $tmpfile" EXIT  # ❌ 变量在 trap 定义时展开
trap 'rm -f $tmpfile' EXIT  # ✓ 使用单引号，运行时展开
```

---

## 18. 最佳实践

### 18.1 脚本模板

```bash
#!/bin/bash
#===============================================
# 脚本名称：script_name.sh
# 脚本描述：脚本功能描述
# 作者：Your Name
# 创建日期：2024-01-15
# 版本：1.0.0
#===============================================

set -euo pipefail

# 全局变量
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}.log"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly NC='\033[0m'  # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" >&2
}

# 错误处理
die() {
    log_error "$1"
    exit "${2:-1}"
}

# 清理函数
cleanup() {
    log_info "清理临时文件..."
    # 清理逻辑
}

trap cleanup EXIT

# 帮助信息
show_help() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
    -h, --help      显示帮助信息
    -v, --version   显示版本信息
    -d, --debug     开启调试模式

Examples:
    $SCRIPT_NAME -h
    $SCRIPT_NAME --debug
EOF
}

# 参数解析
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME version 1.0.0"
                exit 0
                ;;
            -d|--debug)
                set -x
                shift
                ;;
            *)
                die "未知参数: $1"
                ;;
        esac
    done
}

# 主函数
main() {
    parse_args "$@"
    
    log_info "脚本开始执行..."
    
    # 业务逻辑
    
    log_info "脚本执行完成"
}

# 入口
main "$@"
```

### 18.2 编码规范

```bash
# 1. 使用有意义的变量名
# ❌
a=10
b="hello"

# ✓
max_retry_count=10
greeting_message="hello"

# 2. 使用常量
readonly MAX_CONNECTIONS=100
readonly CONFIG_FILE="/etc/myapp/config.conf"

# 3. 函数命名
# 使用小写字母和下划线
check_disk_space() { }
send_notification() { }

# 4. 缩进使用 4 个空格或 1 个 Tab（保持一致）

# 5. 长命令换行
curl -X POST \
    -H "Content-Type: application/json" \
    -d '{"key": "value"}' \
    "https://api.example.com/endpoint"

# 6. 注释
# 单行注释说明下一行代码
complex_command

# 多行注释说明复杂逻辑
# 第一步：做什么
# 第二步：做什么
# 第三步：做什么
```

### 18.3 安全实践

```bash
# 1. 始终引用变量
rm -rf "$dir"          # ✓
rm -rf $dir            # ❌ 危险！

# 2. 使用 set 选项
set -euo pipefail

# 3. 验证输入
validate_input() {
    local input=$1
    
    # 检查是否为空
    [ -z "$input" ] && die "输入不能为空"
    
    # 检查是否包含危险字符
    if [[ "$input" =~ [^a-zA-Z0-9_-] ]]; then
        die "输入包含非法字符"
    fi
}

# 4. 使用绝对路径
/usr/bin/rm -f "$file"

# 5. 检查命令执行结果
if ! command; then
    die "命令执行失败"
fi

# 6. 限制权限
umask 077  # 新建文件只有所有者可读写

# 7. 避免使用 eval
# ❌ 危险
eval "$user_input"

# 8. 临时文件安全
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT
```

### 18.4 性能优化

```bash
# 1. 减少外部命令调用
# ❌ 慢
for i in $(seq 1 1000); do
    result=$(echo "$i * 2" | bc)
done

# ✓ 快
for ((i=1; i<=1000; i++)); do
    result=$((i * 2))
done

# 2. 使用内置字符串操作
# ❌
filename=$(basename "$path")
dirname=$(dirname "$path")

# ✓
filename=${path##*/}
dirname=${path%/*}

# 3. 避免不必要的子 shell
# ❌
result=$(cat file.txt)

# ✓
result=$(<file.txt)

# 4. 批量处理
# ❌
for file in *.txt; do
    grep "pattern" "$file"
done

# ✓
grep "pattern" *.txt

# 5. 使用数组而非多次调用
files=(*.txt)
for file in "${files[@]}"; do
    process "$file"
done
```

---

## 附录：速查表

### A. 特殊变量

| 变量 | 说明 |
|------|------|
| $0 | 脚本名称 |
| $1-$9 | 位置参数 |
| $# | 参数个数 |
| $* | 所有参数（一个字符串） |
| $@ | 所有参数（独立字符串） |
| $? | 上一命令退出状态 |
| $$ | 当前进程 PID |
| $! | 最后后台进程 PID |

### B. 字符串操作

| 操作 | 语法 |
|------|------|
| 长度 | ${#str} |
| 截取 | ${str:start:length} |
| 替换 | ${str/old/new} |
| 删除前缀 | ${str#pattern} |
| 删除后缀 | ${str%pattern} |

### C. 测试运算符

| 运算符 | 说明 |
|--------|------|
| -eq | 等于 |
| -ne | 不等于 |
| -gt | 大于 |
| -lt | 小于 |
| -ge | 大于等于 |
| -le | 小于等于 |
| -f | 是文件 |
| -d | 是目录 |
| -e | 存在 |
| -r | 可读 |
| -w | 可写 |
| -x | 可执行 |

---

> 📝 **笔记完成**
> 
> 本笔记涵盖了 Shell 脚本的完整内容：
> - 基础语法和变量
> - 字符串和数组操作
> - 条件判断和循环
> - 函数和输入输出
> - 文本处理（grep、sed、awk）
> - 进程管理和信号处理
> - 实战脚本示例
> - 调试技巧和最佳实践
> 
> Shell 脚本是运维自动化的基础，建议多写多练！
ame=$(dirname "$path")

# ✓
filename=${path##*/}
dirname=${path%/*}

# 3. 避免不必要的子 shell
# ❌
result=$(cat file.txt)

# ✓
result=$(<file.txt)

# 4. 使用数组而不是字符串拼接
# ❌
files=""
for f in *.txt; do
    files="$files $f"
done

# ✓
files=()
for f in *.txt; do
    files+=("$f")
done

# 5. 并行处理
# 串行
for file in *.txt; do
    process "$file"
done

# 并行
for file in *.txt; do
    process "$file" &
done
wait

# 使用 xargs 并行
find . -name "*.txt" | xargs -P 4 -I {} process {}

# 6. 使用更高效的工具
# ❌ 多次管道
cat file | grep pattern | awk '{print $1}'

# ✓ 一次 awk 完成
awk '/pattern/ {print $1}' file
```

---

## 19. 高级主题

### 19.1 协程（Coprocess）

```bash
#!/bin/bash
# Bash 4.0+ 支持协程

# 启动协程
coproc BC { bc -l; }

# 向协程发送数据
echo "scale=4; 22/7" >&${BC[1]}

# 从协程读取结果
read result <&${BC[0]}
echo "结果: $result"

# 关闭协程
exec {BC[1]}>&-
```

### 19.2 命名管道（FIFO）

```bash
#!/bin/bash

# 创建命名管道
mkfifo /tmp/myfifo

# 生产者（后台运行）
(
    for i in {1..5}; do
        echo "消息 $i"
        sleep 1
    done
) > /tmp/myfifo &

# 消费者
while read line; do
    echo "收到: $line"
done < /tmp/myfifo

# 清理
rm /tmp/myfifo
```

### 19.3 文件描述符

```bash
#!/bin/bash

# 打开文件描述符
exec 3> output.txt      # 写入
exec 4< input.txt       # 读取
exec 5<> file.txt       # 读写

# 使用文件描述符
echo "写入内容" >&3
read line <&4

# 关闭文件描述符
exec 3>&-
exec 4<&-
exec 5<&-

# 复制文件描述符
exec 6>&1               # 保存标准输出
exec 1> log.txt         # 重定向标准输出
echo "这会写入文件"
exec 1>&6               # 恢复标准输出
exec 6>&-               # 关闭备份

# 实际应用：同时输出到屏幕和文件
exec 3>&1 4>&2
exec 1> >(tee -a stdout.log) 2> >(tee -a stderr.log >&2)

echo "标准输出"
echo "标准错误" >&2

exec 1>&3 2>&4
exec 3>&- 4>&-
```

### 19.4 锁机制

```bash
#!/bin/bash

LOCK_FILE="/tmp/myapp.lock"

# 方式1：使用 flock
(
    flock -n 200 || { echo "另一个实例正在运行"; exit 1; }
    
    # 业务逻辑
    echo "获得锁，开始执行..."
    sleep 10
    
) 200>"$LOCK_FILE"

# 方式2：使用 mkdir（原子操作）
acquire_lock() {
    local lock_dir="/tmp/myapp.lock"
    if mkdir "$lock_dir" 2>/dev/null; then
        trap 'rm -rf "$lock_dir"' EXIT
        return 0
    fi
    return 1
}

if ! acquire_lock; then
    echo "另一个实例正在运行"
    exit 1
fi

# 业务逻辑
echo "获得锁，开始执行..."

# 方式3：使用 PID 文件
PID_FILE="/tmp/myapp.pid"

if [ -f "$PID_FILE" ]; then
    old_pid=$(cat "$PID_FILE")
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "进程已在运行 (PID: $old_pid)"
        exit 1
    fi
    rm -f "$PID_FILE"
fi

echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE"' EXIT
```

### 19.5 网络编程

```bash
#!/bin/bash

# 使用 /dev/tcp 进行网络通信（Bash 内置）

# 检查端口是否开放
check_port() {
    local host=$1
    local port=$2
    
    if timeout 3 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo "$host:$port 开放"
        return 0
    else
        echo "$host:$port 关闭"
        return 1
    fi
}

check_port "localhost" 22
check_port "google.com" 80

# 简单的 HTTP 请求
http_get() {
    local host=$1
    local path=${2:-/}
    
    exec 3<>/dev/tcp/$host/80
    
    echo -e "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" >&3
    
    cat <&3
    
    exec 3<&-
}

# 简单的 TCP 服务器（使用 nc）
# 服务端
nc -l -p 8080 -e /bin/bash

# 客户端
nc localhost 8080
```

### 19.6 JSON 处理

```bash
#!/bin/bash

# 使用 jq 处理 JSON（需要安装）

json='{"name":"张三","age":25,"skills":["bash","python"]}'

# 提取字段
echo "$json" | jq '.name'           # "张三"
echo "$json" | jq -r '.name'        # 张三（去掉引号）
echo "$json" | jq '.age'            # 25
echo "$json" | jq '.skills[0]'      # "bash"

# 修改 JSON
echo "$json" | jq '.age = 26'
echo "$json" | jq '.skills += ["go"]'

# 遍历数组
echo "$json" | jq -r '.skills[]'

# 构建 JSON
jq -n --arg name "李四" --arg age 30 \
    '{"name": $name, "age": ($age | tonumber)}'

# 不使用 jq 的简单解析（不推荐用于复杂 JSON）
parse_json_value() {
    local json=$1
    local key=$2
    echo "$json" | grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | \
        sed "s/\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"/\1/"
}

name=$(parse_json_value "$json" "name")
echo "姓名: $name"
```

---

## 20. 常用代码片段

### 20.1 参数处理

```bash
#!/bin/bash

# 使用 getopts 处理短选项
while getopts "hvf:o:" opt; do
    case $opt in
        h) show_help; exit 0 ;;
        v) VERBOSE=true ;;
        f) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        ?) exit 1 ;;
    esac
done
shift $((OPTIND - 1))

# 处理长选项
while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_help
            exit 0
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --file=*)
            INPUT_FILE="${1#*=}"
            shift
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "未知选项: $1"
            exit 1
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
```

### 20.2 配置文件解析

```bash
#!/bin/bash

# 配置文件格式：key=value
CONFIG_FILE="config.conf"

# 读取配置
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        while IFS='=' read -r key value; do
            # 跳过注释和空行
            [[ $key =~ ^[[:space:]]*# ]] && continue
            [[ -z $key ]] && continue
            
            # 去除空格
            key=$(echo "$key" | xargs)
            value=$(echo "$value" | xargs)
            
            # 导出为环境变量
            export "$key=$value"
        done < "$CONFIG_FILE"
    fi
}

# 获取配置值
get_config() {
    local key=$1
    local default=$2
    local value
    
    value=$(grep "^$key=" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2-)
    echo "${value:-$default}"
}

# 设置配置值
set_config() {
    local key=$1
    local value=$2
    
    if grep -q "^$key=" "$CONFIG_FILE" 2>/dev/null; then
        sed -i "s/^$key=.*/$key=$value/" "$CONFIG_FILE"
    else
        echo "$key=$value" >> "$CONFIG_FILE"
    fi
}

# 使用示例
load_config
DB_HOST=$(get_config "DB_HOST" "localhost")
DB_PORT=$(get_config "DB_PORT" "3306")
```

### 20.3 日志轮转

```bash
#!/bin/bash

LOG_FILE="/var/log/myapp.log"
MAX_SIZE=$((10 * 1024 * 1024))  # 10MB
MAX_FILES=5

rotate_log() {
    local log_file=$1
    local max_size=$2
    local max_files=$3
    
    # 检查文件大小
    if [ -f "$log_file" ]; then
        local size=$(stat -c %s "$log_file")
        
        if [ "$size" -gt "$max_size" ]; then
            # 轮转日志
            for ((i=max_files-1; i>=1; i--)); do
                if [ -f "${log_file}.$i" ]; then
                    mv "${log_file}.$i" "${log_file}.$((i+1))"
                fi
            done
            
            mv "$log_file" "${log_file}.1"
            touch "$log_file"
            
            # 删除超出数量的日志
            rm -f "${log_file}.$((max_files+1))"
            
            echo "日志已轮转"
        fi
    fi
}

# 写日志时检查轮转
log() {
    rotate_log "$LOG_FILE" "$MAX_SIZE" "$MAX_FILES"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}
```

### 20.4 进度条

```bash
#!/bin/bash

# 简单进度条
progress_bar() {
    local current=$1
    local total=$2
    local width=${3:-50}
    
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    
    printf "\r["
    printf "%${filled}s" | tr ' ' '#'
    printf "%${empty}s" | tr ' ' '-'
    printf "] %3d%%" "$percent"
}

# 使用示例
total=100
for ((i=1; i<=total; i++)); do
    progress_bar $i $total
    sleep 0.05
done
echo

# 旋转指示器
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# 使用示例
long_running_command &
spinner $!
```

### 20.5 颜色输出

```bash
#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'

# 粗体
BOLD='\033[1m'
# 下划线
UNDERLINE='\033[4m'
# 重置
NC='\033[0m'

# 背景色
BG_RED='\033[41m'
BG_GREEN='\033[42m'

# 使用函数
print_color() {
    local color=$1
    shift
    echo -e "${color}$*${NC}"
}

print_success() {
    print_color "$GREEN" "✓ $*"
}

print_error() {
    print_color "$RED" "✗ $*"
}

print_warning() {
    print_color "$YELLOW" "⚠ $*"
}

print_info() {
    print_color "$BLUE" "ℹ $*"
}

# 使用示例
print_success "操作成功"
print_error "操作失败"
print_warning "警告信息"
print_info "提示信息"

# 检查是否支持颜色
if [ -t 1 ] && [ "$(tput colors 2>/dev/null)" -ge 8 ]; then
    USE_COLOR=true
else
    USE_COLOR=false
fi
```

---

## 21. 速查表

### 21.1 特殊变量

| 变量 | 说明 |
|------|------|
| `$0` | 脚本名称 |
| `$1-$9` | 位置参数 |
| `${10}` | 第10个及以后的参数 |
| `$#` | 参数个数 |
| `$*` | 所有参数（作为一个字符串） |
| `$@` | 所有参数（作为独立字符串） |
| `$$` | 当前进程 PID |
| `$!` | 最后一个后台进程 PID |
| `$?` | 上一个命令的退出状态 |
| `$-` | 当前 Shell 选项 |
| `$_` | 上一个命令的最后一个参数 |

### 21.2 字符串操作

| 操作 | 语法 | 说明 |
|------|------|------|
| 长度 | `${#str}` | 字符串长度 |
| 截取 | `${str:pos:len}` | 从 pos 开始取 len 个字符 |
| 替换 | `${str/old/new}` | 替换第一个 |
| 全替换 | `${str//old/new}` | 替换所有 |
| 删除前缀 | `${str#pattern}` | 最短匹配 |
| 删除前缀 | `${str##pattern}` | 最长匹配 |
| 删除后缀 | `${str%pattern}` | 最短匹配 |
| 删除后缀 | `${str%%pattern}` | 最长匹配 |
| 大写 | `${str^^}` | 全部大写 |
| 小写 | `${str,,}` | 全部小写 |
| 默认值 | `${str:-default}` | 为空则返回默认值 |
| 赋默认值 | `${str:=default}` | 为空则赋值并返回 |

### 21.3 测试操作符

| 文件测试 | 说明 |
|----------|------|
| `-e file` | 文件存在 |
| `-f file` | 是普通文件 |
| `-d file` | 是目录 |
| `-r file` | 可读 |
| `-w file` | 可写 |
| `-x file` | 可执行 |
| `-s file` | 文件大小不为0 |
| `-L file` | 是符号链接 |

| 字符串测试 | 说明 |
|------------|------|
| `-z str` | 字符串为空 |
| `-n str` | 字符串非空 |
| `str1 = str2` | 字符串相等 |
| `str1 != str2` | 字符串不等 |

| 数值比较 | 说明 |
|----------|------|
| `-eq` | 等于 |
| `-ne` | 不等于 |
| `-gt` | 大于 |
| `-lt` | 小于 |
| `-ge` | 大于等于 |
| `-le` | 小于等于 |

### 21.4 常用命令

```bash
# 文本处理
grep    # 搜索文本
sed     # 流编辑器
awk     # 文本处理
cut     # 按列切割
tr      # 字符转换
sort    # 排序
uniq    # 去重
wc      # 统计

# 文件操作
find    # 查找文件
xargs   # 构建参数
tee     # 分流输出

# 系统信息
ps      # 进程状态
top     # 动态进程
df      # 磁盘空间
du      # 目录大小
free    # 内存使用

# 网络
curl    # HTTP 客户端
wget    # 下载工具
nc      # 网络工具
ss      # 套接字统计
```

---

## 总结

Shell 脚本是 Linux/Unix 系统管理和自动化的核心技能。通过本笔记的学习，你应该掌握了：

1. **基础知识**：变量、字符串、数组、运算符
2. **流程控制**：条件判断、循环结构、函数
3. **输入输出**：重定向、管道、进程替换
4. **文本处理**：grep、sed、awk 三剑客
5. **进程管理**：进程控制、信号处理
6. **调试技巧**：调试选项、错误处理
7. **最佳实践**：编码规范、安全实践、性能优化
8. **高级主题**：协程、命名管道、文件描述符、锁机制

持续练习和实践是掌握 Shell 脚本的关键。建议从简单的自动化任务开始，逐步挑战更复杂的脚本编写。

---

> 最后更新：2024-01-15
> 作者：Shell 学习笔记
