

> ECMAScript 6（ES2015）及后续版本为 JavaScript 带来了革命性的改进
> 本笔记涵盖 ES6 到 ES2024 的核心特性，从基础到高级循序渐进

---

## 目录

1. [变量声明](#1-变量声明)
2. [解构赋值](#2-解构赋值)
3. [字符串扩展](#3-字符串扩展)
4. [数值扩展](#4-数值扩展)
5. [数组扩展](#5-数组扩展)
6. [对象扩展](#6-对象扩展)
7. [函数扩展](#7-函数扩展)
8. [Symbol](#8-symbol)
9. [Set 和 Map](#9-set-和-map)
10. [Promise](#10-promise)
11. [Iterator 和 Generator](#11-iterator-和-generator)
12. [Class 类](#12-class-类)
13. [Module 模块](#13-module-模块)
14. [Proxy 和 Reflect](#14-proxy-和-reflect)
15. [async/await](#15-asyncawait)
16. [ES2020+ 新特性](#16-es2020-新特性)
17. [常见错误与解决方案](#17-常见错误与解决方案)

---

## 1. 变量声明

ES6 引入了 `let` 和 `const`，解决了 `var` 的诸多问题。

### 1.1 var 的问题

```javascript
// 问题1：变量提升（Hoisting）
console.log(name)  // undefined（不报错，但很奇怪）
var name = 'John'

// 问题2：没有块级作用域
if (true) {
  var age = 25
}
console.log(age)  // 25（泄漏到外部）

// 问题3：可以重复声明
var x = 1
var x = 2  // 不报错

// 问题4：循环中的闭包问题
for (var i = 0; i < 3; i++) {
  setTimeout(() => console.log(i), 100)
}
// 输出：3, 3, 3（而非 0, 1, 2）
```

### 1.2 let 关键字

`let` 声明的变量具有块级作用域，不会变量提升。

```javascript
// 块级作用域
if (true) {
  let age = 25
}
console.log(age)  // ReferenceError: age is not defined

// 暂时性死区（TDZ）
console.log(name)  // ReferenceError
let name = 'John'

// 不能重复声明
let x = 1
let x = 2  // SyntaxError: Identifier 'x' has already been declared

// 循环中正常工作
for (let i = 0; i < 3; i++) {
  setTimeout(() => console.log(i), 100)
}
// 输出：0, 1, 2 ✅

// 经典面试题
for (let i = 0; i < 5; i++) {
  // 每次循环都会创建新的 i
}
```

### 1.3 const 关键字

`const` 声明常量，必须初始化且不能重新赋值。

```javascript
// 必须初始化
const PI  // SyntaxError: Missing initializer

// 不能重新赋值
const PI = 3.14159
PI = 3.14  // TypeError: Assignment to constant variable

// 但对象的属性可以修改！
const user = { name: 'John' }
user.name = 'Jane'  // ✅ 可以
user.age = 25       // ✅ 可以
user = {}           // ❌ TypeError

// 冻结对象
const frozenUser = Object.freeze({ name: 'John' })
frozenUser.name = 'Jane'  // 静默失败（严格模式下报错）
console.log(frozenUser.name)  // 'John'

// 深度冻结
function deepFreeze(obj) {
  Object.keys(obj).forEach(key => {
    if (typeof obj[key] === 'object' && obj[key] !== null) {
      deepFreeze(obj[key])
    }
  })
  return Object.freeze(obj)
}
```

### 1.4 最佳实践

```javascript
// ✅ 推荐：默认使用 const
const API_URL = 'https://api.example.com'
const config = { timeout: 5000 }

// ✅ 需要重新赋值时使用 let
let count = 0
count++

// ❌ 避免使用 var
var oldStyle = 'deprecated'
```

---

## 2. 解构赋值

解构赋值让我们可以从数组或对象中提取值，赋给变量。

### 2.1 数组解构

```javascript
// 基本用法
const [a, b, c] = [1, 2, 3]
console.log(a, b, c)  // 1 2 3

// 跳过元素
const [first, , third] = [1, 2, 3]
console.log(first, third)  // 1 3

// 剩余元素
const [head, ...tail] = [1, 2, 3, 4, 5]
console.log(head)  // 1
console.log(tail)  // [2, 3, 4, 5]

// 默认值
const [x = 1, y = 2] = [10]
console.log(x, y)  // 10 2

// 交换变量（无需临时变量）
let m = 1, n = 2
;[m, n] = [n, m]
console.log(m, n)  // 2 1

// 嵌套解构
const [a, [b, c]] = [1, [2, 3]]
console.log(a, b, c)  // 1 2 3

// 从函数返回值解构
function getCoordinates() {
  return [10, 20]
}
const [x, y] = getCoordinates()
```

### 2.2 对象解构

```javascript
// 基本用法
const { name, age } = { name: 'John', age: 25 }
console.log(name, age)  // 'John' 25

// 重命名
const { name: userName, age: userAge } = { name: 'John', age: 25 }
console.log(userName, userAge)  // 'John' 25

// 默认值
const { name, age = 18 } = { name: 'John' }
console.log(name, age)  // 'John' 18

// 重命名 + 默认值
const { name: n, age: a = 18 } = { name: 'John' }
console.log(n, a)  // 'John' 18

// 嵌套解构
const user = {
  name: 'John',
  address: {
    city: 'Beijing',
    zip: '100000'
  }
}
const { address: { city, zip } } = user
console.log(city, zip)  // 'Beijing' '100000'

// 剩余属性
const { name, ...rest } = { name: 'John', age: 25, city: 'Beijing' }
console.log(name)  // 'John'
console.log(rest)  // { age: 25, city: 'Beijing' }

// 函数参数解构
function greet({ name, age = 18 }) {
  console.log(`Hello, ${name}! You are ${age} years old.`)
}
greet({ name: 'John' })  // Hello, John! You are 18 years old.

// 复杂的参数解构
function createUser({
  name,
  age = 18,
  role = 'user',
  settings: { theme = 'light', notifications = true } = {}
} = {}) {
  return { name, age, role, theme, notifications }
}
```

### 2.3 解构的实际应用

```javascript
// 1. 导入模块的部分内容
import { useState, useEffect } from 'react'

// 2. 处理 API 响应
const { data, status, message } = await fetch('/api/user').then(r => r.json())

// 3. 配置对象
function ajax({ url, method = 'GET', headers = {}, body = null }) {
  // ...
}

// 4. React 组件 props
function UserCard({ name, avatar, bio = 'No bio' }) {
  return (
    <div>
      <img src={avatar} alt={name} />
      <h2>{name}</h2>
      <p>{bio}</p>
    </div>
  )
}

// 5. 遍历 Map
const map = new Map([['a', 1], ['b', 2]])
for (const [key, value] of map) {
  console.log(key, value)
}
```

---

## 3. 字符串扩展

### 3.1 模板字符串

模板字符串使用反引号（`）包裹，支持多行和插值。

```javascript
// 基本插值
const name = 'John'
const greeting = `Hello, ${name}!`
console.log(greeting)  // 'Hello, John!'

// 表达式插值
const a = 10, b = 20
console.log(`Sum: ${a + b}`)  // 'Sum: 30'
console.log(`Is adult: ${a >= 18 ? 'Yes' : 'No'}`)

// 多行字符串
const html = `
  <div class="card">
    <h2>${title}</h2>
    <p>${content}</p>
  </div>
`

// 嵌套模板
const items = ['Apple', 'Banana', 'Orange']
const list = `
  <ul>
    ${items.map(item => `<li>${item}</li>`).join('')}
  </ul>
`

// 调用函数
function upper(str) {
  return str.toUpperCase()
}
console.log(`Hello, ${upper('world')}!`)  // 'Hello, WORLD!'
```

### 3.2 标签模板

标签模板是一种特殊的函数调用形式。

```javascript
// 基本语法
function tag(strings, ...values) {
  console.log(strings)  // ['Hello, ', '! You are ', ' years old.']
  console.log(values)   // ['John', 25]
  return strings.reduce((result, str, i) => 
    result + str + (values[i] || ''), ''
  )
}

const name = 'John', age = 25
const result = tag`Hello, ${name}! You are ${age} years old.`

// 实际应用：防止 XSS
function safeHtml(strings, ...values) {
  const escape = str => String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
  
  return strings.reduce((result, str, i) => 
    result + str + (values[i] ? escape(values[i]) : ''), ''
  )
}

const userInput = '<script>alert("XSS")</script>'
const safe = safeHtml`<div>${userInput}</div>`
// '<div>&lt;script&gt;alert("XSS")&lt;/script&gt;</div>'

// 实际应用：styled-components
const Button = styled.button`
  background: ${props => props.primary ? 'blue' : 'white'};
  color: ${props => props.primary ? 'white' : 'blue'};
  padding: 10px 20px;
`
```

### 3.3 新增字符串方法

```javascript
const str = 'Hello, World!'

// includes() - 是否包含
str.includes('World')     // true
str.includes('world')     // false（区分大小写）
str.includes('o', 5)      // true（从索引5开始查找）

// startsWith() - 是否以...开头
str.startsWith('Hello')   // true
str.startsWith('World', 7) // true（从索引7开始）

// endsWith() - 是否以...结尾
str.endsWith('!')         // true
str.endsWith('World', 12) // true（前12个字符）

// repeat() - 重复
'ab'.repeat(3)            // 'ababab'
'*'.repeat(10)            // '**********'

// padStart() / padEnd() - 填充（ES2017）
'5'.padStart(3, '0')      // '005'
'5'.padEnd(3, '0')        // '500'
'abc'.padStart(6, '123')  // '123abc'
'abc'.padEnd(6, '123')    // 'abc123'

// trimStart() / trimEnd() - 去除空白（ES2019）
'  hello  '.trimStart()   // 'hello  '
'  hello  '.trimEnd()     // '  hello'
'  hello  '.trim()        // 'hello'

// replaceAll() - 替换所有（ES2021）
'aabbcc'.replace('b', 'x')     // 'aaxbcc'（只替换第一个）
'aabbcc'.replaceAll('b', 'x')  // 'aaxxcc'（替换所有）

// at() - 索引访问（ES2022）
str.at(0)    // 'H'
str.at(-1)   // '!'（负索引从末尾开始）
str.at(-2)   // 'd'
```

---

## 4. 数值扩展

### 4.1 二进制和八进制

```javascript
// 二进制（0b 或 0B 前缀）
const binary = 0b1010  // 10
const binary2 = 0B1111 // 15

// 八进制（0o 或 0O 前缀）
const octal = 0o755    // 493
const octal2 = 0O17    // 15

// 十六进制（0x 或 0X 前缀，ES5 就有）
const hex = 0xFF       // 255
```

### 4.2 Number 扩展

```javascript
// Number.isFinite() - 是否有限
Number.isFinite(100)       // true
Number.isFinite(Infinity)  // false
Number.isFinite(NaN)       // false
Number.isFinite('100')     // false（不会类型转换）
isFinite('100')            // true（全局函数会转换）

// Number.isNaN() - 是否为 NaN
Number.isNaN(NaN)          // true
Number.isNaN('NaN')        // false（不会类型转换）
isNaN('NaN')               // true（全局函数会转换）

// Number.isInteger() - 是否为整数
Number.isInteger(25)       // true
Number.isInteger(25.0)     // true
Number.isInteger(25.1)     // false

// Number.isSafeInteger() - 是否为安全整数
Number.isSafeInteger(Math.pow(2, 53) - 1)  // true
Number.isSafeInteger(Math.pow(2, 53))      // false

// Number.parseInt() / Number.parseFloat()
Number.parseInt('123abc')    // 123
Number.parseFloat('3.14abc') // 3.14

// 常量
Number.MAX_SAFE_INTEGER  // 9007199254740991 (2^53 - 1)
Number.MIN_SAFE_INTEGER  // -9007199254740991
Number.EPSILON           // 2.220446049250313e-16（最小精度）

// 解决浮点数精度问题
0.1 + 0.2 === 0.3  // false
Math.abs(0.1 + 0.2 - 0.3) < Number.EPSILON  // true
```

### 4.3 BigInt（ES2020）

用于表示任意精度的整数。

```javascript
// 创建 BigInt
const big1 = 9007199254740991n  // 字面量
const big2 = BigInt(9007199254740991)  // 构造函数
const big3 = BigInt('9007199254740991')

// 运算
const a = 10n
const b = 3n
a + b   // 13n
a - b   // 7n
a * b   // 30n
a / b   // 3n（整除）
a % b   // 1n

// 不能与普通数字混合运算
10n + 10  // TypeError
10n + BigInt(10)  // 20n ✅

// 比较
10n === 10   // false（类型不同）
10n == 10    // true（值相等）
10n > 5      // true

// 转换
Number(10n)  // 10
String(10n)  // '10'
```

### 4.4 Math 扩展

```javascript
// Math.trunc() - 去除小数部分
Math.trunc(4.9)    // 4
Math.trunc(-4.9)   // -4
Math.trunc('4.9')  // 4

// Math.sign() - 判断正负
Math.sign(5)    // 1
Math.sign(-5)   // -1
Math.sign(0)    // 0

// Math.cbrt() - 立方根
Math.cbrt(8)    // 2
Math.cbrt(27)   // 3

// Math.hypot() - 平方和的平方根
Math.hypot(3, 4)  // 5（勾股定理）

// Math.log2() / Math.log10()
Math.log2(8)    // 3
Math.log10(100) // 2

// Math.expm1() / Math.log1p()
Math.expm1(1)   // e^1 - 1 ≈ 1.718
Math.log1p(1)   // ln(1+1) ≈ 0.693

// 指数运算符（ES2016）
2 ** 10         // 1024
2 ** 0.5        // 1.414...（平方根）
let x = 2
x **= 3         // x = 8
```

---

## 5. 数组扩展

### 5.1 扩展运算符

```javascript
// 展开数组
const arr1 = [1, 2, 3]
const arr2 = [...arr1, 4, 5]  // [1, 2, 3, 4, 5]

// 复制数组（浅拷贝）
const copy = [...arr1]

// 合并数组
const merged = [...arr1, ...arr2]

// 字符串转数组
const chars = [...'hello']  // ['h', 'e', 'l', 'l', 'o']

// 函数调用
function sum(a, b, c) {
  return a + b + c
}
const nums = [1, 2, 3]
sum(...nums)  // 6

// 与解构结合
const [first, ...rest] = [1, 2, 3, 4]
// first = 1, rest = [2, 3, 4]

// 类数组转数组
const nodeList = document.querySelectorAll('div')
const divArray = [...nodeList]
```

### 5.2 Array.from()

将类数组或可迭代对象转为数组。

```javascript
// 类数组转数组
const arrayLike = { 0: 'a', 1: 'b', 2: 'c', length: 3 }
Array.from(arrayLike)  // ['a', 'b', 'c']

// 字符串
Array.from('hello')  // ['h', 'e', 'l', 'l', 'o']

// Set
Array.from(new Set([1, 2, 2, 3]))  // [1, 2, 3]

// Map
Array.from(new Map([['a', 1], ['b', 2]]))  // [['a', 1], ['b', 2]]

// 第二个参数：映射函数
Array.from([1, 2, 3], x => x * 2)  // [2, 4, 6]
Array.from({ length: 5 }, (_, i) => i)  // [0, 1, 2, 3, 4]

// 生成序列
Array.from({ length: 10 }, (_, i) => i + 1)  // [1, 2, ..., 10]

// 初始化二维数组
const matrix = Array.from({ length: 3 }, () => Array(3).fill(0))
// [[0,0,0], [0,0,0], [0,0,0]]
```

### 5.3 Array.of()

创建数组，解决 `new Array()` 的怪异行为。

```javascript
// new Array 的问题
new Array(3)      // [empty × 3]（3个空位）
new Array(3, 4)   // [3, 4]

// Array.of 行为一致
Array.of(3)       // [3]
Array.of(3, 4)    // [3, 4]
Array.of()        // []
```

### 5.4 实例方法

```javascript
const arr = [1, 2, 3, 4, 5]

// find() - 找到第一个满足条件的元素
arr.find(x => x > 3)  // 4
arr.find(x => x > 10) // undefined

// findIndex() - 找到第一个满足条件的索引
arr.findIndex(x => x > 3)  // 3
arr.findIndex(x => x > 10) // -1

// findLast() / findLastIndex()（ES2023）
arr.findLast(x => x > 3)       // 5
arr.findLastIndex(x => x > 3)  // 4

// includes() - 是否包含（ES2016）
arr.includes(3)      // true
arr.includes(3, 3)   // false（从索引3开始）
[NaN].includes(NaN)  // true（indexOf 无法检测 NaN）

// fill() - 填充
[1, 2, 3].fill(0)        // [0, 0, 0]
[1, 2, 3].fill(0, 1)     // [1, 0, 0]
[1, 2, 3].fill(0, 1, 2)  // [1, 0, 3]

// copyWithin() - 内部复制
[1, 2, 3, 4, 5].copyWithin(0, 3)  // [4, 5, 3, 4, 5]

// flat() - 扁平化（ES2019）
[1, [2, [3, [4]]]].flat()     // [1, 2, [3, [4]]]
[1, [2, [3, [4]]]].flat(2)    // [1, 2, 3, [4]]
[1, [2, [3, [4]]]].flat(Infinity)  // [1, 2, 3, 4]

// flatMap() - map + flat(1)
[1, 2, 3].flatMap(x => [x, x * 2])  // [1, 2, 2, 4, 3, 6]

// at() - 索引访问（ES2022）
arr.at(0)   // 1
arr.at(-1)  // 5
arr.at(-2)  // 4

// toSorted() / toReversed() / toSpliced()（ES2023）
// 不修改原数组，返回新数组
const sorted = arr.toSorted((a, b) => b - a)  // [5, 4, 3, 2, 1]
const reversed = arr.toReversed()  // [5, 4, 3, 2, 1]
const spliced = arr.toSpliced(1, 2, 'a', 'b')  // [1, 'a', 'b', 4, 5]

// with()（ES2023）- 替换指定索引的元素
arr.with(0, 10)  // [10, 2, 3, 4, 5]
arr.with(-1, 10) // [1, 2, 3, 4, 10]
```


---

## 6. 对象扩展

### 6.1 属性简写

```javascript
// 属性简写
const name = 'John'
const age = 25

// ES5
const user1 = { name: name, age: age }

// ES6
const user2 = { name, age }

// 方法简写
const obj = {
  // ES5
  sayHello: function() {
    console.log('Hello')
  },
  
  // ES6
  sayHi() {
    console.log('Hi')
  },
  
  // 计算属性名
  ['say' + 'Bye']() {
    console.log('Bye')
  }
}
```

### 6.2 计算属性名

```javascript
const key = 'name'
const prefix = 'user'

const obj = {
  [key]: 'John',
  [`${prefix}Age`]: 25,
  [`${prefix}Email`]: 'john@example.com',
  ['get' + 'Name']() {
    return this.name
  }
}

console.log(obj.name)      // 'John'
console.log(obj.userAge)   // 25
console.log(obj.getName()) // 'John'
```

### 6.3 Object 新方法

```javascript
// Object.is() - 严格相等比较
Object.is(NaN, NaN)   // true（=== 返回 false）
Object.is(+0, -0)     // false（=== 返回 true）
Object.is(1, 1)       // true

// Object.assign() - 合并对象（浅拷贝）
const target = { a: 1 }
const source1 = { b: 2 }
const source2 = { c: 3 }
Object.assign(target, source1, source2)
// target = { a: 1, b: 2, c: 3 }

// 常用于浅拷贝
const copy = Object.assign({}, original)

// Object.keys() / Object.values() / Object.entries()
const user = { name: 'John', age: 25 }
Object.keys(user)     // ['name', 'age']
Object.values(user)   // ['John', 25]
Object.entries(user)  // [['name', 'John'], ['age', 25]]

// Object.fromEntries()（ES2019）
const entries = [['name', 'John'], ['age', 25]]
Object.fromEntries(entries)  // { name: 'John', age: 25 }

// Map 转对象
const map = new Map([['a', 1], ['b', 2]])
Object.fromEntries(map)  // { a: 1, b: 2 }

// Object.getOwnPropertyDescriptors()（ES2017）
const obj = { name: 'John' }
Object.getOwnPropertyDescriptors(obj)
// { name: { value: 'John', writable: true, enumerable: true, configurable: true } }

// Object.hasOwn()（ES2022）- 替代 hasOwnProperty
const obj = { name: 'John' }
Object.hasOwn(obj, 'name')      // true
Object.hasOwn(obj, 'toString')  // false
```

### 6.4 扩展运算符（对象）

```javascript
// 复制对象（浅拷贝）
const original = { a: 1, b: 2 }
const copy = { ...original }

// 合并对象
const obj1 = { a: 1, b: 2 }
const obj2 = { c: 3, d: 4 }
const merged = { ...obj1, ...obj2 }  // { a: 1, b: 2, c: 3, d: 4 }

// 覆盖属性
const defaults = { theme: 'light', lang: 'en' }
const userSettings = { theme: 'dark' }
const settings = { ...defaults, ...userSettings }
// { theme: 'dark', lang: 'en' }

// 添加/修改属性
const user = { name: 'John', age: 25 }
const updatedUser = { ...user, age: 26, city: 'Beijing' }
// { name: 'John', age: 26, city: 'Beijing' }

// 剩余属性
const { name, ...rest } = { name: 'John', age: 25, city: 'Beijing' }
// name = 'John', rest = { age: 25, city: 'Beijing' }
```

---

## 7. 函数扩展

### 7.1 默认参数

```javascript
// ES5 方式
function greet(name) {
  name = name || 'Guest'
  console.log('Hello, ' + name)
}

// ES6 默认参数
function greet(name = 'Guest') {
  console.log(`Hello, ${name}`)
}

greet()        // 'Hello, Guest'
greet('John')  // 'Hello, John'
greet('')      // 'Hello, '（空字符串不会触发默认值）

// 默认值可以是表达式
function getDefault() {
  return 'Default'
}
function test(value = getDefault()) {
  console.log(value)
}

// 默认值可以引用前面的参数
function createUser(name, email = `${name}@example.com`) {
  return { name, email }
}
createUser('john')  // { name: 'john', email: 'john@example.com' }

// 与解构结合
function ajax({ url, method = 'GET', headers = {} } = {}) {
  console.log(url, method, headers)
}
ajax({ url: '/api/users' })
ajax()  // 不传参数也不会报错
```

### 7.2 剩余参数

```javascript
// 替代 arguments
function sum(...numbers) {
  return numbers.reduce((total, n) => total + n, 0)
}
sum(1, 2, 3, 4, 5)  // 15

// 与普通参数结合
function log(level, ...messages) {
  console.log(`[${level}]`, ...messages)
}
log('INFO', 'User logged in', 'ID: 123')

// 剩余参数必须是最后一个
function invalid(a, ...rest, b) {}  // SyntaxError
```

### 7.3 箭头函数

```javascript
// 基本语法
const add = (a, b) => a + b

// 单个参数可省略括号
const double = x => x * 2

// 无参数
const greet = () => 'Hello'

// 多行需要花括号和 return
const sum = (a, b) => {
  const result = a + b
  return result
}

// 返回对象需要括号
const createUser = (name, age) => ({ name, age })

// 箭头函数的特点
const obj = {
  name: 'John',
  
  // 普通函数：this 指向调用者
  sayHello: function() {
    console.log(this.name)  // 'John'
  },
  
  // 箭头函数：this 继承自外层作用域
  sayHi: () => {
    console.log(this.name)  // undefined（this 是全局对象）
  },
  
  // 正确使用箭头函数
  delayedGreet: function() {
    setTimeout(() => {
      console.log(this.name)  // 'John'（继承自 delayedGreet 的 this）
    }, 1000)
  }
}

// 箭头函数不能作为构造函数
const Person = (name) => {
  this.name = name
}
new Person('John')  // TypeError

// 箭头函数没有 arguments
const fn = () => {
  console.log(arguments)  // ReferenceError
}

// 使用剩余参数替代
const fn = (...args) => {
  console.log(args)
}
```

### 7.4 箭头函数使用场景

```javascript
// ✅ 适合使用箭头函数
// 1. 回调函数
const numbers = [1, 2, 3]
numbers.map(n => n * 2)
numbers.filter(n => n > 1)
numbers.reduce((sum, n) => sum + n, 0)

// 2. Promise 链
fetch('/api/user')
  .then(res => res.json())
  .then(data => console.log(data))
  .catch(err => console.error(err))

// 3. 需要保持 this 的回调
class Counter {
  constructor() {
    this.count = 0
    setInterval(() => {
      this.count++  // this 正确指向 Counter 实例
    }, 1000)
  }
}

// ❌ 不适合使用箭头函数
// 1. 对象方法
const obj = {
  name: 'John',
  greet: () => console.log(this.name)  // ❌ this 不是 obj
}

// 2. 原型方法
function Person(name) {
  this.name = name
}
Person.prototype.greet = () => {
  console.log(this.name)  // ❌ this 不是实例
}

// 3. 需要 arguments 的函数
// 4. 构造函数
// 5. 需要动态 this 的函数（如事件处理器）
button.addEventListener('click', function() {
  console.log(this)  // button 元素
})
```

---

## 8. Symbol

Symbol 是 ES6 引入的新原始类型，表示独一无二的值。

### 8.1 基本用法

```javascript
// 创建 Symbol
const s1 = Symbol()
const s2 = Symbol()
s1 === s2  // false（每个 Symbol 都是唯一的）

// 带描述的 Symbol
const s3 = Symbol('description')
console.log(s3.toString())  // 'Symbol(description)'
console.log(s3.description) // 'description'（ES2019）

// Symbol 不能与其他类型运算
const s = Symbol('test')
s + ''     // TypeError
`${s}`     // TypeError
Number(s)  // TypeError
Boolean(s) // true（可以转布尔值）
```

### 8.2 作为属性名

```javascript
// Symbol 作为属性名
const name = Symbol('name')
const age = Symbol('age')

const user = {
  [name]: 'John',
  [age]: 25,
  city: 'Beijing'
}

console.log(user[name])  // 'John'
console.log(user.name)   // undefined（不能用点语法）

// Symbol 属性不会被常规方法遍历
Object.keys(user)                    // ['city']
Object.getOwnPropertyNames(user)     // ['city']
JSON.stringify(user)                 // '{"city":"Beijing"}'

// 获取 Symbol 属性
Object.getOwnPropertySymbols(user)   // [Symbol(name), Symbol(age)]
Reflect.ownKeys(user)                // ['city', Symbol(name), Symbol(age)]
```

### 8.3 Symbol.for() 和 Symbol.keyFor()

```javascript
// Symbol.for() - 全局注册表
const s1 = Symbol.for('foo')
const s2 = Symbol.for('foo')
s1 === s2  // true（从全局注册表获取同一个 Symbol）

// Symbol.keyFor() - 获取全局 Symbol 的 key
Symbol.keyFor(s1)  // 'foo'

const s3 = Symbol('bar')
Symbol.keyFor(s3)  // undefined（非全局 Symbol）
```

### 8.4 内置 Symbol

```javascript
// Symbol.iterator - 定义迭代器
const obj = {
  data: [1, 2, 3],
  [Symbol.iterator]() {
    let index = 0
    return {
      next: () => {
        if (index < this.data.length) {
          return { value: this.data[index++], done: false }
        }
        return { done: true }
      }
    }
  }
}
for (const item of obj) {
  console.log(item)  // 1, 2, 3
}

// Symbol.toStringTag - 自定义 toString 标签
class MyClass {
  get [Symbol.toStringTag]() {
    return 'MyClass'
  }
}
console.log(Object.prototype.toString.call(new MyClass()))
// '[object MyClass]'

// Symbol.hasInstance - 自定义 instanceof 行为
class MyArray {
  static [Symbol.hasInstance](instance) {
    return Array.isArray(instance)
  }
}
[] instanceof MyArray  // true

// Symbol.toPrimitive - 自定义类型转换
const obj = {
  [Symbol.toPrimitive](hint) {
    if (hint === 'number') return 42
    if (hint === 'string') return 'hello'
    return true
  }
}
+obj      // 42
`${obj}`  // 'hello'
obj + ''  // 'true'
```


---

## 9. Set 和 Map

### 9.1 Set

Set 是值的集合，成员唯一，没有重复值。

```javascript
// 创建 Set
const set = new Set()
const set2 = new Set([1, 2, 3, 3, 4])  // 自动去重
console.log(set2)  // Set(4) {1, 2, 3, 4}

// 基本操作
set.add(1)
set.add(2)
set.add(2)  // 重复值不会添加
set.size    // 2

set.has(1)  // true
set.has(3)  // false

set.delete(1)  // true
set.delete(3)  // false（不存在）

set.clear()  // 清空

// 遍历
const set3 = new Set(['a', 'b', 'c'])
for (const item of set3) {
  console.log(item)
}
set3.forEach((value, key) => {
  console.log(value, key)  // value 和 key 相同
})

// 转数组
const arr = [...set3]
const arr2 = Array.from(set3)

// 实际应用：数组去重
const unique = [...new Set([1, 2, 2, 3, 3, 3])]  // [1, 2, 3]

// 实际应用：字符串去重
const uniqueChars = [...new Set('aabbcc')].join('')  // 'abc'

// 实际应用：集合运算
const a = new Set([1, 2, 3])
const b = new Set([2, 3, 4])

// 并集
const union = new Set([...a, ...b])  // {1, 2, 3, 4}

// 交集
const intersection = new Set([...a].filter(x => b.has(x)))  // {2, 3}

// 差集
const difference = new Set([...a].filter(x => !b.has(x)))  // {1}
```

### 9.2 WeakSet

WeakSet 只能存储对象，且是弱引用（不阻止垃圾回收）。

```javascript
const ws = new WeakSet()

let obj = { name: 'John' }
ws.add(obj)
ws.has(obj)  // true

obj = null  // 对象可能被垃圾回收
// ws 中的引用也会自动消失

// WeakSet 不可遍历，没有 size 属性
// 常用于存储 DOM 节点或标记对象
const visitedNodes = new WeakSet()
function visit(node) {
  if (visitedNodes.has(node)) return
  visitedNodes.add(node)
  // 处理节点...
}
```

### 9.3 Map

Map 是键值对的集合，键可以是任意类型。

```javascript
// 创建 Map
const map = new Map()
const map2 = new Map([
  ['name', 'John'],
  ['age', 25]
])

// 基本操作
map.set('key', 'value')
map.set({ id: 1 }, 'object key')  // 对象作为键
map.set(function() {}, 'function key')  // 函数作为键

map.get('key')  // 'value'
map.has('key')  // true
map.delete('key')
map.clear()
map.size  // 0

// 链式调用
map.set('a', 1).set('b', 2).set('c', 3)

// 遍历
const map3 = new Map([['a', 1], ['b', 2], ['c', 3]])

for (const [key, value] of map3) {
  console.log(key, value)
}

map3.forEach((value, key) => {
  console.log(key, value)
})

// 获取键/值/条目
map3.keys()     // MapIterator {'a', 'b', 'c'}
map3.values()   // MapIterator {1, 2, 3}
map3.entries()  // MapIterator {['a', 1], ['b', 2], ['c', 3]}

// 转数组
const arr = [...map3]  // [['a', 1], ['b', 2], ['c', 3]]

// 转对象
const obj = Object.fromEntries(map3)  // { a: 1, b: 2, c: 3 }

// 对象转 Map
const obj2 = { x: 1, y: 2 }
const map4 = new Map(Object.entries(obj2))

// Map vs Object
// Map 的优势：
// 1. 键可以是任意类型
// 2. 有 size 属性
// 3. 迭代顺序是插入顺序
// 4. 性能更好（频繁增删）
```

### 9.4 WeakMap

WeakMap 的键必须是对象，且是弱引用。

```javascript
const wm = new WeakMap()

let obj = { name: 'John' }
wm.set(obj, 'metadata')
wm.get(obj)  // 'metadata'

obj = null  // 对象可能被垃圾回收
// wm 中的条目也会自动消失

// 常用场景：存储私有数据
const privateData = new WeakMap()

class Person {
  constructor(name, age) {
    privateData.set(this, { name, age })
  }
  
  getName() {
    return privateData.get(this).name
  }
}

// 常用场景：缓存计算结果
const cache = new WeakMap()

function expensiveOperation(obj) {
  if (cache.has(obj)) {
    return cache.get(obj)
  }
  const result = /* 复杂计算 */ obj.value * 2
  cache.set(obj, result)
  return result
}
```

---

## 10. Promise

Promise 是异步编程的解决方案，解决了回调地狱问题。

### 10.1 基本用法

```javascript
// 创建 Promise
const promise = new Promise((resolve, reject) => {
  // 异步操作
  setTimeout(() => {
    const success = true
    if (success) {
      resolve('成功的数据')
    } else {
      reject(new Error('失败的原因'))
    }
  }, 1000)
})

// 使用 Promise
promise
  .then(data => {
    console.log('成功:', data)
    return '处理后的数据'
  })
  .then(data => {
    console.log('链式调用:', data)
  })
  .catch(error => {
    console.error('失败:', error)
  })
  .finally(() => {
    console.log('无论成功失败都执行')
  })
```

### 10.2 Promise 状态

```javascript
// Promise 有三种状态：
// 1. pending（进行中）
// 2. fulfilled（已成功）
// 3. rejected（已失败）

// 状态一旦改变就不会再变
const p = new Promise((resolve, reject) => {
  resolve('first')
  resolve('second')  // 无效
  reject('error')    // 无效
})
p.then(console.log)  // 'first'
```

### 10.3 Promise 静态方法

```javascript
// Promise.resolve() - 创建已成功的 Promise
Promise.resolve('success')
Promise.resolve(existingPromise)  // 返回原 Promise

// Promise.reject() - 创建已失败的 Promise
Promise.reject(new Error('failed'))

// Promise.all() - 所有都成功才成功
const p1 = Promise.resolve(1)
const p2 = Promise.resolve(2)
const p3 = Promise.resolve(3)

Promise.all([p1, p2, p3])
  .then(([r1, r2, r3]) => {
    console.log(r1, r2, r3)  // 1 2 3
  })

// 有一个失败就失败
const p4 = Promise.reject('error')
Promise.all([p1, p4])
  .catch(err => console.log(err))  // 'error'

// Promise.allSettled()（ES2020）- 等待所有完成
Promise.allSettled([p1, p4])
  .then(results => {
    console.log(results)
    // [
    //   { status: 'fulfilled', value: 1 },
    //   { status: 'rejected', reason: 'error' }
    // ]
  })

// Promise.race() - 第一个完成的结果
Promise.race([
  new Promise(resolve => setTimeout(() => resolve('slow'), 1000)),
  new Promise(resolve => setTimeout(() => resolve('fast'), 500))
]).then(console.log)  // 'fast'

// Promise.any()（ES2021）- 第一个成功的结果
Promise.any([
  Promise.reject('error1'),
  Promise.resolve('success'),
  Promise.reject('error2')
]).then(console.log)  // 'success'

// 全部失败才失败
Promise.any([
  Promise.reject('error1'),
  Promise.reject('error2')
]).catch(err => {
  console.log(err)  // AggregateError
  console.log(err.errors)  // ['error1', 'error2']
})
```

### 10.4 Promise 链式调用

```javascript
// then 返回新的 Promise
fetch('/api/user')
  .then(response => response.json())  // 返回 Promise
  .then(user => fetch(`/api/posts?userId=${user.id}`))
  .then(response => response.json())
  .then(posts => console.log(posts))
  .catch(error => console.error(error))

// 在 then 中抛出错误
Promise.resolve()
  .then(() => {
    throw new Error('出错了')
  })
  .catch(err => {
    console.log(err.message)  // '出错了'
    return '恢复正常'
  })
  .then(data => {
    console.log(data)  // '恢复正常'
  })
```

### 10.5 实际应用

```javascript
// 封装 Ajax
function ajax(url, options = {}) {
  return new Promise((resolve, reject) => {
    fetch(url, options)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`)
        }
        return response.json()
      })
      .then(resolve)
      .catch(reject)
  })
}

// 超时处理
function timeout(promise, ms) {
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Timeout')), ms)
  })
  return Promise.race([promise, timeoutPromise])
}

timeout(fetch('/api/data'), 5000)
  .then(data => console.log(data))
  .catch(err => console.log(err.message))

// 重试机制
async function retry(fn, retries = 3, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn()
    } catch (err) {
      if (i === retries - 1) throw err
      await new Promise(r => setTimeout(r, delay))
    }
  }
}

// 并发控制
async function asyncPool(limit, items, fn) {
  const results = []
  const executing = []
  
  for (const item of items) {
    const p = Promise.resolve().then(() => fn(item))
    results.push(p)
    
    if (limit <= items.length) {
      const e = p.then(() => executing.splice(executing.indexOf(e), 1))
      executing.push(e)
      
      if (executing.length >= limit) {
        await Promise.race(executing)
      }
    }
  }
  
  return Promise.all(results)
}
```


---

## 11. Iterator 和 Generator

### 11.1 Iterator（迭代器）

迭代器是一种接口，为各种数据结构提供统一的访问机制。

```javascript
// 迭代器协议
// 对象必须有 next() 方法，返回 { value, done }

// 手动实现迭代器
function createIterator(array) {
  let index = 0
  return {
    next() {
      if (index < array.length) {
        return { value: array[index++], done: false }
      }
      return { value: undefined, done: true }
    }
  }
}

const iterator = createIterator([1, 2, 3])
iterator.next()  // { value: 1, done: false }
iterator.next()  // { value: 2, done: false }
iterator.next()  // { value: 3, done: false }
iterator.next()  // { value: undefined, done: true }

// 可迭代协议
// 对象必须有 [Symbol.iterator] 方法，返回迭代器

const iterable = {
  data: [1, 2, 3],
  [Symbol.iterator]() {
    let index = 0
    return {
      next: () => {
        if (index < this.data.length) {
          return { value: this.data[index++], done: false }
        }
        return { done: true }
      }
    }
  }
}

// 可以使用 for...of
for (const item of iterable) {
  console.log(item)  // 1, 2, 3
}

// 可以使用扩展运算符
console.log([...iterable])  // [1, 2, 3]

// 原生可迭代对象
// Array, String, Map, Set, arguments, NodeList, TypedArray
```

### 11.2 Generator（生成器）

Generator 函数可以暂停执行和恢复执行。

```javascript
// 基本语法
function* generator() {
  yield 1
  yield 2
  yield 3
}

const gen = generator()
gen.next()  // { value: 1, done: false }
gen.next()  // { value: 2, done: false }
gen.next()  // { value: 3, done: false }
gen.next()  // { value: undefined, done: true }

// Generator 是可迭代的
for (const value of generator()) {
  console.log(value)  // 1, 2, 3
}

// yield 表达式的值
function* gen() {
  const a = yield 1
  console.log('a:', a)
  const b = yield 2
  console.log('b:', b)
  return 3
}

const g = gen()
g.next()      // { value: 1, done: false }
g.next('A')   // 打印 'a: A', { value: 2, done: false }
g.next('B')   // 打印 'b: B', { value: 3, done: true }

// yield* 委托
function* gen1() {
  yield 1
  yield 2
}

function* gen2() {
  yield* gen1()  // 委托给 gen1
  yield 3
}

[...gen2()]  // [1, 2, 3]

// 实际应用：生成 ID
function* idGenerator() {
  let id = 1
  while (true) {
    yield id++
  }
}

const getId = idGenerator()
getId.next().value  // 1
getId.next().value  // 2
getId.next().value  // 3

// 实际应用：遍历树结构
function* traverseTree(node) {
  yield node.value
  for (const child of node.children || []) {
    yield* traverseTree(child)
  }
}

const tree = {
  value: 1,
  children: [
    { value: 2, children: [{ value: 4 }, { value: 5 }] },
    { value: 3 }
  ]
}

[...traverseTree(tree)]  // [1, 2, 4, 5, 3]

// 实际应用：异步流程控制（async/await 之前的方案）
function* asyncFlow() {
  const user = yield fetch('/api/user')
  const posts = yield fetch(`/api/posts?userId=${user.id}`)
  return posts
}
```

---

## 12. Class 类

ES6 的 Class 是构造函数的语法糖，让面向对象编程更清晰。

### 12.1 基本语法

```javascript
// ES5 构造函数
function PersonES5(name, age) {
  this.name = name
  this.age = age
}
PersonES5.prototype.sayHello = function() {
  console.log(`Hello, I'm ${this.name}`)
}

// ES6 Class
class Person {
  // 构造函数
  constructor(name, age) {
    this.name = name
    this.age = age
  }
  
  // 实例方法
  sayHello() {
    console.log(`Hello, I'm ${this.name}`)
  }
  
  // Getter
  get info() {
    return `${this.name}, ${this.age} years old`
  }
  
  // Setter
  set info(value) {
    [this.name, this.age] = value.split(', ')
  }
  
  // 静态方法
  static create(name, age) {
    return new Person(name, age)
  }
  
  // 静态属性
  static species = 'Human'
}

const person = new Person('John', 25)
person.sayHello()  // "Hello, I'm John"
person.info        // "John, 25 years old"
Person.species     // "Human"
Person.create('Jane', 30)
```

### 12.2 继承

```javascript
class Animal {
  constructor(name) {
    this.name = name
  }
  
  speak() {
    console.log(`${this.name} makes a sound`)
  }
  
  static isAnimal(obj) {
    return obj instanceof Animal
  }
}

class Dog extends Animal {
  constructor(name, breed) {
    super(name)  // 必须先调用 super
    this.breed = breed
  }
  
  // 重写父类方法
  speak() {
    console.log(`${this.name} barks`)
  }
  
  // 调用父类方法
  speakLoud() {
    super.speak()
    console.log('WOOF!')
  }
}

const dog = new Dog('Buddy', 'Golden Retriever')
dog.speak()      // "Buddy barks"
dog.speakLoud()  // "Buddy makes a sound" "WOOF!"
Dog.isAnimal(dog)  // true（继承静态方法）
```

### 12.3 私有属性和方法（ES2022）

```javascript
class BankAccount {
  // 私有属性（# 前缀）
  #balance = 0
  #pin
  
  constructor(initialBalance, pin) {
    this.#balance = initialBalance
    this.#pin = pin
  }
  
  // 私有方法
  #validatePin(pin) {
    return this.#pin === pin
  }
  
  // 公共方法
  deposit(amount) {
    this.#balance += amount
  }
  
  withdraw(amount, pin) {
    if (!this.#validatePin(pin)) {
      throw new Error('Invalid PIN')
    }
    if (amount > this.#balance) {
      throw new Error('Insufficient funds')
    }
    this.#balance -= amount
    return amount
  }
  
  getBalance(pin) {
    if (!this.#validatePin(pin)) {
      throw new Error('Invalid PIN')
    }
    return this.#balance
  }
  
  // 静态私有属性
  static #bankName = 'MyBank'
  
  static getBankName() {
    return BankAccount.#bankName
  }
}

const account = new BankAccount(1000, '1234')
account.deposit(500)
account.getBalance('1234')  // 1500
account.#balance  // SyntaxError: Private field
```

### 12.4 类表达式和其他特性

```javascript
// 类表达式
const MyClass = class {
  constructor() {}
}

// 命名类表达式
const MyClass2 = class NamedClass {
  static getName() {
    return NamedClass.name
  }
}

// 立即实例化
const instance = new class {
  constructor(name) {
    this.name = name
  }
}('John')

// 计算属性名
const methodName = 'dynamicMethod'
class MyClass3 {
  [methodName]() {
    return 'dynamic!'
  }
}

// new.target
class Parent {
  constructor() {
    if (new.target === Parent) {
      throw new Error('Parent cannot be instantiated directly')
    }
  }
}

class Child extends Parent {
  constructor() {
    super()
  }
}

new Parent()  // Error
new Child()   // OK
```

---

## 13. Module 模块

ES6 模块是 JavaScript 的官方模块系统。

### 13.1 导出（export）

```javascript
// named-exports.js

// 单个导出
export const name = 'John'
export const age = 25

export function greet() {
  console.log('Hello!')
}

export class Person {
  constructor(name) {
    this.name = name
  }
}

// 统一导出
const x = 1
const y = 2
export { x, y }

// 重命名导出
export { x as valueX, y as valueY }

// 默认导出（每个模块只能有一个）
export default function() {
  console.log('Default export')
}

// 或者
const defaultValue = 'default'
export default defaultValue

// 同时有默认导出和命名导出
export default class User {}
export const createUser = () => new User()
```

### 13.2 导入（import）

```javascript
// 导入命名导出
import { name, age, greet } from './named-exports.js'

// 重命名导入
import { name as userName, age as userAge } from './named-exports.js'

// 导入所有命名导出
import * as utils from './named-exports.js'
console.log(utils.name, utils.age)

// 导入默认导出
import myDefault from './default-export.js'

// 同时导入默认和命名导出
import defaultExport, { name, age } from './mixed-exports.js'

// 仅执行模块（副作用导入）
import './side-effects.js'

// 动态导入（返回 Promise）
const module = await import('./dynamic-module.js')
// 或
import('./dynamic-module.js').then(module => {
  module.doSomething()
})

// 条件导入
if (condition) {
  const { feature } = await import('./feature.js')
}
```

### 13.3 重新导出

```javascript
// re-export.js

// 重新导出所有
export * from './module-a.js'

// 重新导出部分
export { foo, bar } from './module-b.js'

// 重命名重新导出
export { foo as myFoo } from './module-c.js'

// 重新导出默认导出
export { default } from './module-d.js'
export { default as MyDefault } from './module-e.js'

// 聚合导出（常用于 index.js）
export * from './user.js'
export * from './product.js'
export * from './order.js'
```

### 13.4 模块特性

```javascript
// 1. 模块自动使用严格模式
// 2. 模块有自己的作用域
// 3. 模块只执行一次（单例）
// 4. 导入是只读的（不能重新赋值）
// 5. 导入是实时绑定的（live binding）

// counter.js
export let count = 0
export function increment() {
  count++
}

// main.js
import { count, increment } from './counter.js'
console.log(count)  // 0
increment()
console.log(count)  // 1（实时更新）
count = 10  // TypeError: Assignment to constant variable
```


---

## 14. Proxy 和 Reflect

### 14.1 Proxy 基础

Proxy 用于创建对象的代理，可以拦截和自定义对象的基本操作。

```javascript
// 基本语法
const proxy = new Proxy(target, handler)

// 简单示例
const user = { name: 'John', age: 25 }

const userProxy = new Proxy(user, {
  // 拦截读取
  get(target, property, receiver) {
    console.log(`Getting ${property}`)
    return target[property]
  },
  
  // 拦截设置
  set(target, property, value, receiver) {
    console.log(`Setting ${property} to ${value}`)
    target[property] = value
    return true  // 必须返回 true 表示成功
  }
})

userProxy.name      // 打印 "Getting name", 返回 "John"
userProxy.age = 26  // 打印 "Setting age to 26"
```

### 14.2 常用拦截器

```javascript
const handler = {
  // 读取属性
  get(target, prop, receiver) {
    return Reflect.get(target, prop, receiver)
  },
  
  // 设置属性
  set(target, prop, value, receiver) {
    return Reflect.set(target, prop, value, receiver)
  },
  
  // 检查属性是否存在
  has(target, prop) {
    return Reflect.has(target, prop)
  },
  
  // 删除属性
  deleteProperty(target, prop) {
    return Reflect.deleteProperty(target, prop)
  },
  
  // 获取所有属性键
  ownKeys(target) {
    return Reflect.ownKeys(target)
  },
  
  // 函数调用
  apply(target, thisArg, args) {
    return Reflect.apply(target, thisArg, args)
  },
  
  // 构造函数调用
  construct(target, args, newTarget) {
    return Reflect.construct(target, args, newTarget)
  },
  
  // 获取属性描述符
  getOwnPropertyDescriptor(target, prop) {
    return Reflect.getOwnPropertyDescriptor(target, prop)
  },
  
  // 定义属性
  defineProperty(target, prop, descriptor) {
    return Reflect.defineProperty(target, prop, descriptor)
  },
  
  // 获取原型
  getPrototypeOf(target) {
    return Reflect.getPrototypeOf(target)
  },
  
  // 设置原型
  setPrototypeOf(target, proto) {
    return Reflect.setPrototypeOf(target, proto)
  },
  
  // 是否可扩展
  isExtensible(target) {
    return Reflect.isExtensible(target)
  },
  
  // 阻止扩展
  preventExtensions(target) {
    return Reflect.preventExtensions(target)
  }
}
```

### 14.3 实际应用

```javascript
// 1. 数据验证
function createValidator(target, validators) {
  return new Proxy(target, {
    set(obj, prop, value) {
      if (validators[prop]) {
        if (!validators[prop](value)) {
          throw new Error(`Invalid value for ${prop}`)
        }
      }
      obj[prop] = value
      return true
    }
  })
}

const user = createValidator({}, {
  age: value => typeof value === 'number' && value > 0,
  email: value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
})

user.age = 25        // OK
user.age = -1        // Error: Invalid value for age
user.email = 'test'  // Error: Invalid value for email

// 2. 响应式数据（Vue 3 原理）
function reactive(target) {
  return new Proxy(target, {
    get(obj, prop) {
      track(obj, prop)  // 收集依赖
      const value = obj[prop]
      return typeof value === 'object' ? reactive(value) : value
    },
    set(obj, prop, value) {
      obj[prop] = value
      trigger(obj, prop)  // 触发更新
      return true
    }
  })
}

// 3. 私有属性
function createPrivate(target, privateProps) {
  return new Proxy(target, {
    get(obj, prop) {
      if (privateProps.includes(prop)) {
        throw new Error(`Cannot access private property: ${prop}`)
      }
      return obj[prop]
    },
    set(obj, prop, value) {
      if (privateProps.includes(prop)) {
        throw new Error(`Cannot set private property: ${prop}`)
      }
      obj[prop] = value
      return true
    },
    has(obj, prop) {
      if (privateProps.includes(prop)) {
        return false
      }
      return prop in obj
    }
  })
}

// 4. 默认值
function withDefaults(target, defaults) {
  return new Proxy(target, {
    get(obj, prop) {
      return prop in obj ? obj[prop] : defaults[prop]
    }
  })
}

const config = withDefaults({}, { timeout: 5000, retries: 3 })
config.timeout  // 5000
config.retries  // 3

// 5. 负索引数组
function createArray(...elements) {
  return new Proxy(elements, {
    get(arr, prop) {
      let index = Number(prop)
      if (index < 0) {
        index = arr.length + index
      }
      return arr[index]
    }
  })
}

const arr = createArray(1, 2, 3, 4, 5)
arr[-1]  // 5
arr[-2]  // 4
```

### 14.4 Reflect

Reflect 提供了操作对象的方法，与 Proxy 的拦截器一一对应。

```javascript
// Reflect 的优势
// 1. 返回布尔值表示操作是否成功
// 2. 函数式操作
// 3. 与 Proxy 配合使用

const obj = { name: 'John' }

// 传统方式 vs Reflect
'name' in obj                    // true
Reflect.has(obj, 'name')         // true

delete obj.name                  // true
Reflect.deleteProperty(obj, 'name')  // true

Object.keys(obj)                 // ['name']
Reflect.ownKeys(obj)             // ['name']

// 在 Proxy 中使用 Reflect
const proxy = new Proxy(obj, {
  get(target, prop, receiver) {
    console.log(`Getting ${prop}`)
    return Reflect.get(target, prop, receiver)
  },
  set(target, prop, value, receiver) {
    console.log(`Setting ${prop}`)
    return Reflect.set(target, prop, value, receiver)
  }
})
```

---

## 15. async/await

async/await 是 Promise 的语法糖，让异步代码看起来像同步代码。

### 15.1 基本用法

```javascript
// async 函数
async function fetchUser() {
  return 'John'  // 自动包装成 Promise.resolve('John')
}

fetchUser().then(console.log)  // 'John'

// await 等待 Promise
async function getUser() {
  const response = await fetch('/api/user')
  const user = await response.json()
  return user
}

// 等价于
function getUser() {
  return fetch('/api/user')
    .then(response => response.json())
}

// 错误处理
async function fetchData() {
  try {
    const response = await fetch('/api/data')
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Fetch failed:', error)
    throw error
  }
}
```

### 15.2 并行执行

```javascript
// 串行执行（慢）
async function serial() {
  const user = await fetchUser()      // 等待完成
  const posts = await fetchPosts()    // 再等待完成
  return { user, posts }
}

// 并行执行（快）
async function parallel() {
  const [user, posts] = await Promise.all([
    fetchUser(),
    fetchPosts()
  ])
  return { user, posts }
}

// 并行执行，独立处理结果
async function parallelIndependent() {
  const userPromise = fetchUser()
  const postsPromise = fetchPosts()
  
  const user = await userPromise
  const posts = await postsPromise
  
  return { user, posts }
}
```

### 15.3 循环中的 async/await

```javascript
const urls = ['/api/1', '/api/2', '/api/3']

// 串行处理
async function serialFetch() {
  const results = []
  for (const url of urls) {
    const response = await fetch(url)
    results.push(await response.json())
  }
  return results
}

// 并行处理
async function parallelFetch() {
  const promises = urls.map(url => fetch(url).then(r => r.json()))
  return Promise.all(promises)
}

// 注意：forEach 不能正确处理 async
urls.forEach(async url => {
  const data = await fetch(url)  // 不会等待
})

// 使用 for...of 代替
for (const url of urls) {
  const data = await fetch(url)  // 正确等待
}
```

### 15.4 顶层 await（ES2022）

```javascript
// 在模块顶层使用 await
// module.js
const response = await fetch('/api/config')
export const config = await response.json()

// 动态导入
const module = await import('./dynamic-module.js')

// 条件导入
const { feature } = await import(
  process.env.NODE_ENV === 'production'
    ? './feature.prod.js'
    : './feature.dev.js'
)
```

### 15.5 实际应用模式

```javascript
// 1. 重试机制
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url)
      if (response.ok) return response.json()
    } catch (error) {
      if (i === retries - 1) throw error
      await new Promise(r => setTimeout(r, 1000 * (i + 1)))
    }
  }
}

// 2. 超时控制
async function fetchWithTimeout(url, timeout = 5000) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeout)
  
  try {
    const response = await fetch(url, { signal: controller.signal })
    return response.json()
  } finally {
    clearTimeout(timeoutId)
  }
}

// 3. 并发限制
async function asyncPool(limit, items, fn) {
  const results = []
  const executing = new Set()
  
  for (const item of items) {
    const promise = fn(item).then(result => {
      executing.delete(promise)
      return result
    })
    
    results.push(promise)
    executing.add(promise)
    
    if (executing.size >= limit) {
      await Promise.race(executing)
    }
  }
  
  return Promise.all(results)
}

// 使用
const urls = [/* 100 个 URL */]
const results = await asyncPool(5, urls, url => fetch(url).then(r => r.json()))

// 4. 错误聚合
async function fetchAll(urls) {
  const results = await Promise.allSettled(
    urls.map(url => fetch(url).then(r => r.json()))
  )
  
  const successes = results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value)
  
  const failures = results
    .filter(r => r.status === 'rejected')
    .map(r => r.reason)
  
  return { successes, failures }
}
```

---

## 16. ES2020+ 新特性

### 16.1 ES2020

```javascript
// 可选链操作符 ?.
const user = { address: { city: 'Beijing' } }
user?.address?.city      // 'Beijing'
user?.contact?.phone     // undefined（不报错）
user?.getName?.()        // undefined（方法调用）
user?.friends?.[0]       // undefined（数组访问）

// 空值合并操作符 ??
const value = null ?? 'default'   // 'default'
const value2 = '' ?? 'default'    // ''（空字符串不是 null/undefined）
const value3 = 0 ?? 'default'     // 0

// 与 || 的区别
'' || 'default'   // 'default'（|| 会把假值都替换）
'' ?? 'default'   // ''（?? 只替换 null/undefined）

// globalThis
// 统一的全局对象访问
globalThis.setTimeout  // 浏览器和 Node.js 都可用

// Promise.allSettled
const results = await Promise.allSettled([
  Promise.resolve(1),
  Promise.reject('error'),
  Promise.resolve(3)
])
// [
//   { status: 'fulfilled', value: 1 },
//   { status: 'rejected', reason: 'error' },
//   { status: 'fulfilled', value: 3 }
// ]

// BigInt
const big = 9007199254740991n
big + 1n  // 9007199254740992n

// String.prototype.matchAll
const str = 'test1test2test3'
const matches = [...str.matchAll(/test(\d)/g)]
// [['test1', '1'], ['test2', '2'], ['test3', '3']]

// 动态 import()
const module = await import('./module.js')
```

### 16.2 ES2021

```javascript
// 逻辑赋值操作符
let a = null
a ||= 'default'  // a = a || 'default'
a &&= 'value'    // a = a && 'value'
a ??= 'default'  // a = a ?? 'default'

// String.prototype.replaceAll
'aabbcc'.replaceAll('b', 'x')  // 'aaxxcc'

// Promise.any
const first = await Promise.any([
  fetch('/api/server1'),
  fetch('/api/server2'),
  fetch('/api/server3')
])  // 返回第一个成功的

// WeakRef 和 FinalizationRegistry
const ref = new WeakRef(largeObject)
ref.deref()  // 获取对象（可能是 undefined）

const registry = new FinalizationRegistry(heldValue => {
  console.log(`Object with ${heldValue} was garbage collected`)
})
registry.register(object, 'some identifier')

// 数字分隔符
const billion = 1_000_000_000
const bytes = 0xFF_FF_FF_FF
const binary = 0b1010_0001_1000_0101
```

### 16.3 ES2022

```javascript
// 类私有属性和方法
class MyClass {
  #privateField = 'private'
  #privateMethod() { return 'private method' }
  
  static #staticPrivate = 'static private'
}

// 类静态块
class Config {
  static data
  
  static {
    // 复杂的静态初始化
    try {
      this.data = JSON.parse(localStorage.getItem('config'))
    } catch {
      this.data = {}
    }
  }
}

// 顶层 await
const data = await fetch('/api/data').then(r => r.json())

// at() 方法
[1, 2, 3].at(-1)  // 3
'hello'.at(-1)    // 'o'

// Object.hasOwn()
Object.hasOwn({ a: 1 }, 'a')  // true

// Error cause
throw new Error('Failed', { cause: originalError })

// RegExp /d 标志（匹配索引）
const match = /a+/.exec('aaab')
match.indices  // [[0, 3]]
```

### 16.4 ES2023

```javascript
// 数组方法（不修改原数组）
const arr = [3, 1, 2]
arr.toSorted()           // [1, 2, 3]，arr 不变
arr.toReversed()         // [2, 1, 3]，arr 不变
arr.toSpliced(1, 1, 'a') // [3, 'a', 2]，arr 不变
arr.with(0, 'x')         // ['x', 1, 2]，arr 不变

// findLast / findLastIndex
[1, 2, 3, 2, 1].findLast(x => x === 2)       // 2（从后往前找）
[1, 2, 3, 2, 1].findLastIndex(x => x === 2)  // 3

// Hashbang 语法
#!/usr/bin/env node
console.log('Hello')

// WeakMap 支持 Symbol 作为键
const wm = new WeakMap()
const key = Symbol('key')
wm.set(key, 'value')
```

### 16.5 ES2024

```javascript
// Promise.withResolvers()
const { promise, resolve, reject } = Promise.withResolvers()
// 等价于
let resolve, reject
const promise = new Promise((res, rej) => {
  resolve = res
  reject = rej
})

// Object.groupBy / Map.groupBy
const items = [
  { type: 'fruit', name: 'apple' },
  { type: 'fruit', name: 'banana' },
  { type: 'vegetable', name: 'carrot' }
]

Object.groupBy(items, item => item.type)
// {
//   fruit: [{ type: 'fruit', name: 'apple' }, { type: 'fruit', name: 'banana' }],
//   vegetable: [{ type: 'vegetable', name: 'carrot' }]
// }

// Atomics.waitAsync
// 用于 SharedArrayBuffer 的异步等待

// 正则表达式 v 标志
/[\p{Script=Greek}&&\p{Letter}]/v  // 交集
/[\p{Script=Greek}--\p{Letter}]/v  // 差集
```


---

## 17. 常见错误与解决方案

### 17.1 变量声明相关

```javascript
// ❌ 错误：暂时性死区
console.log(x)  // ReferenceError
let x = 1

// ✅ 解决：先声明后使用
let x = 1
console.log(x)

// ❌ 错误：const 重新赋值
const PI = 3.14
PI = 3.14159  // TypeError

// ✅ 解决：使用 let 或修改对象属性
let pi = 3.14
pi = 3.14159

const config = { timeout: 5000 }
config.timeout = 10000  // OK

// ❌ 错误：块级作用域误解
for (var i = 0; i < 3; i++) {
  setTimeout(() => console.log(i), 100)
}
// 输出：3, 3, 3

// ✅ 解决：使用 let
for (let i = 0; i < 3; i++) {
  setTimeout(() => console.log(i), 100)
}
// 输出：0, 1, 2
```

### 17.2 解构赋值相关

```javascript
// ❌ 错误：解构 undefined/null
const { name } = undefined  // TypeError
const [first] = null        // TypeError

// ✅ 解决：提供默认值
const { name } = undefined || {}
const { name = 'default' } = data ?? {}

// ❌ 错误：嵌套解构时父级不存在
const { address: { city } } = { name: 'John' }  // TypeError

// ✅ 解决：使用可选链或默认值
const { address: { city } = {} } = { name: 'John' }
// 或
const city = user?.address?.city

// ❌ 错误：解构时变量名冲突
const name = 'existing'
const { name } = user  // SyntaxError

// ✅ 解决：重命名
const { name: userName } = user
```

### 17.3 箭头函数相关

```javascript
// ❌ 错误：箭头函数作为对象方法
const obj = {
  name: 'John',
  greet: () => {
    console.log(this.name)  // undefined
  }
}

// ✅ 解决：使用普通函数
const obj = {
  name: 'John',
  greet() {
    console.log(this.name)  // 'John'
  }
}

// ❌ 错误：箭头函数作为构造函数
const Person = (name) => {
  this.name = name
}
new Person('John')  // TypeError

// ✅ 解决：使用普通函数或 class
function Person(name) {
  this.name = name
}
// 或
class Person {
  constructor(name) {
    this.name = name
  }
}

// ❌ 错误：箭头函数使用 arguments
const fn = () => {
  console.log(arguments)  // ReferenceError
}

// ✅ 解决：使用剩余参数
const fn = (...args) => {
  console.log(args)
}
```

### 17.4 Promise 相关

```javascript
// ❌ 错误：忘记 return
fetch('/api/user')
  .then(response => {
    response.json()  // 忘记 return
  })
  .then(data => {
    console.log(data)  // undefined
  })

// ✅ 解决：记得 return
fetch('/api/user')
  .then(response => response.json())
  .then(data => console.log(data))

// ❌ 错误：在 then 中嵌套 Promise
fetch('/api/user')
  .then(response => {
    response.json().then(data => {
      // 嵌套地狱
    })
  })

// ✅ 解决：链式调用
fetch('/api/user')
  .then(response => response.json())
  .then(data => {
    // 扁平结构
  })

// ❌ 错误：忘记处理错误
fetch('/api/user')
  .then(response => response.json())
// 如果失败，错误会被静默吞掉

// ✅ 解决：添加 catch
fetch('/api/user')
  .then(response => response.json())
  .catch(error => console.error(error))

// ❌ 错误：Promise 构造函数中的错误
new Promise((resolve, reject) => {
  throw new Error('oops')  // 会被捕获
  // 但异步错误不会
  setTimeout(() => {
    throw new Error('async error')  // 不会被捕获！
  }, 0)
})

// ✅ 解决：在异步代码中使用 reject
new Promise((resolve, reject) => {
  setTimeout(() => {
    try {
      // 可能出错的代码
    } catch (error) {
      reject(error)
    }
  }, 0)
})
```

### 17.5 async/await 相关

```javascript
// ❌ 错误：忘记 await
async function getData() {
  const response = fetch('/api/data')  // 忘记 await
  return response.json()  // TypeError: response.json is not a function
}

// ✅ 解决：添加 await
async function getData() {
  const response = await fetch('/api/data')
  return response.json()
}

// ❌ 错误：在非 async 函数中使用 await
function getData() {
  const data = await fetch('/api/data')  // SyntaxError
}

// ✅ 解决：声明为 async
async function getData() {
  const data = await fetch('/api/data')
}

// ❌ 错误：forEach 中使用 await
const urls = ['/api/1', '/api/2']
urls.forEach(async url => {
  await fetch(url)  // 不会等待
})
console.log('done')  // 立即执行

// ✅ 解决：使用 for...of 或 Promise.all
for (const url of urls) {
  await fetch(url)
}
// 或
await Promise.all(urls.map(url => fetch(url)))

// ❌ 错误：串行执行本可并行的操作
async function slow() {
  const a = await fetchA()  // 等待
  const b = await fetchB()  // 再等待
}

// ✅ 解决：并行执行
async function fast() {
  const [a, b] = await Promise.all([fetchA(), fetchB()])
}
```

### 17.6 模块相关

```javascript
// ❌ 错误：循环依赖
// a.js
import { b } from './b.js'
export const a = 'a' + b

// b.js
import { a } from './a.js'
export const b = 'b' + a  // a 是 undefined

// ✅ 解决：重构代码，避免循环依赖
// 或使用函数延迟访问
// a.js
import { getB } from './b.js'
export const a = 'a'
export function getA() { return a + getB() }

// ❌ 错误：导入不存在的导出
import { nonExistent } from './module.js'  // SyntaxError

// ✅ 解决：检查导出名称
import { existingExport } from './module.js'

// ❌ 错误：修改导入的绑定
import { count } from './counter.js'
count = 10  // TypeError

// ✅ 解决：导入修改函数
import { count, setCount } from './counter.js'
setCount(10)
```

### 17.7 类相关

```javascript
// ❌ 错误：忘记调用 super
class Child extends Parent {
  constructor() {
    this.name = 'child'  // ReferenceError
  }
}

// ✅ 解决：先调用 super
class Child extends Parent {
  constructor() {
    super()
    this.name = 'child'
  }
}

// ❌ 错误：在 super 之前使用 this
class Child extends Parent {
  constructor() {
    this.name = 'child'  // ReferenceError
    super()
  }
}

// ✅ 解决：super 必须在 this 之前
class Child extends Parent {
  constructor() {
    super()
    this.name = 'child'
  }
}

// ❌ 错误：类不会提升
const instance = new MyClass()  // ReferenceError
class MyClass {}

// ✅ 解决：先定义后使用
class MyClass {}
const instance = new MyClass()
```

### 17.8 可选链和空值合并

```javascript
// ❌ 错误：混淆 ?? 和 ||
const value = 0
const result = value || 'default'  // 'default'（0 是假值）

// ✅ 解决：使用 ?? 只处理 null/undefined
const result = value ?? 'default'  // 0

// ❌ 错误：可选链与函数调用
const obj = { method: null }
obj.method?.()  // 不会报错，返回 undefined
obj.method()    // TypeError

// ❌ 错误：?? 与 || 或 && 混用（无括号）
a ?? b || c  // SyntaxError

// ✅ 解决：使用括号
(a ?? b) || c
a ?? (b || c)
```

---

## 附录：ES6+ 特性速查表

### 按版本分类

| 版本 | 主要特性 |
|------|----------|
| ES2015 (ES6) | let/const, 箭头函数, 类, 模块, Promise, 解构, 模板字符串, Symbol, Set/Map, Iterator/Generator, Proxy/Reflect |
| ES2016 | Array.includes(), 指数运算符 ** |
| ES2017 | async/await, Object.values/entries, 字符串填充, 尾逗号 |
| ES2018 | 异步迭代, Promise.finally, Rest/Spread 属性, 正则改进 |
| ES2019 | Array.flat/flatMap, Object.fromEntries, String.trimStart/trimEnd, 可选 catch 绑定 |
| ES2020 | 可选链 ?., 空值合并 ??, BigInt, Promise.allSettled, globalThis, 动态 import() |
| ES2021 | 逻辑赋值, String.replaceAll, Promise.any, WeakRef, 数字分隔符 |
| ES2022 | 类私有属性, 顶层 await, at(), Object.hasOwn, Error cause |
| ES2023 | toSorted/toReversed/toSpliced/with, findLast/findLastIndex |
| ES2024 | Promise.withResolvers, Object.groupBy, 正则 v 标志 |

### 常用语法速查

```javascript
// 变量声明
let x = 1
const y = 2

// 解构
const { a, b } = obj
const [x, y] = arr

// 模板字符串
`Hello, ${name}!`

// 箭头函数
const fn = (x) => x * 2

// 默认参数
function fn(x = 1) {}

// 剩余参数
function fn(...args) {}

// 扩展运算符
[...arr1, ...arr2]
{ ...obj1, ...obj2 }

// 可选链
obj?.prop?.method?.()

// 空值合并
value ?? 'default'

// 类
class MyClass extends Parent {}

// 模块
import { x } from './module.js'
export const y = 1

// Promise
promise.then().catch().finally()

// async/await
async function fn() {
  const data = await promise
}
```

---

> 📝 **笔记说明**
> - 本笔记涵盖 ES6 (ES2015) 到 ES2024 的主要特性
> - 建议配合 MDN 文档深入学习：https://developer.mozilla.org/
> - 使用 Babel 可以在旧浏览器中使用新特性

---

*最后更新：2024年*
