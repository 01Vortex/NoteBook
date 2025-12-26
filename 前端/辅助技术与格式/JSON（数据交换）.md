# JSON 完整学习笔记

> JSON（JavaScript Object Notation）是一种轻量级的数据交换格式
> 它易于人阅读和编写，同时也易于机器解析和生成

---

## 目录

1. [基础概念](#1-基础概念)
2. [JSON 语法规则](#2-json-语法规则)
3. [JSON 数据类型](#3-json-数据类型)
4. [JavaScript 中的 JSON 操作](#4-javascript-中的-json-操作)
5. [JSON Schema 验证](#5-json-schema-验证)
6. [JSON 与 HTTP 请求](#6-json-与-http-请求)
7. [JSON 文件操作](#7-json-文件操作)
8. [JSON 高级技巧](#8-json-高级技巧)
9. [JSON 与其他格式对比](#9-json-与其他格式对比)
10. [性能优化](#10-性能优化)
11. [安全注意事项](#11-安全注意事项)
12. [常见错误与解决方案](#12-常见错误与解决方案)
13. [最佳实践](#13-最佳实践)

---

## 1. 基础概念

### 1.1 什么是 JSON？

JSON（JavaScript Object Notation，JavaScript 对象表示法）是一种基于文本的数据交换格式。虽然它源自 JavaScript，但它是**语言无关**的，几乎所有现代编程语言都支持 JSON。

**JSON 的特点：**
- **轻量级**：相比 XML，JSON 格式更简洁，数据量更小
- **易读性**：人类可以直接阅读和理解 JSON 数据
- **易解析**：机器可以快速解析和生成 JSON
- **语言无关**：几乎所有编程语言都有 JSON 解析库
- **自描述性**：数据结构清晰，键值对形式直观

### 1.2 JSON 的历史

JSON 由 Douglas Crockford 在 2001 年左右提出，最初是为了解决 JavaScript 与服务器之间的数据交换问题。2013 年，JSON 被 ECMA 标准化为 ECMA-404，2017 年成为 RFC 8259 标准。

### 1.3 JSON 的应用场景

1. **Web API 数据交换**：RESTful API 最常用的数据格式
2. **配置文件**：如 `package.json`、`tsconfig.json`
3. **数据存储**：NoSQL 数据库（如 MongoDB）使用类 JSON 格式
4. **日志记录**：结构化日志通常使用 JSON 格式
5. **前后端通信**：Ajax 请求的标准数据格式

---

## 2. JSON 语法规则

### 2.1 基本语法

JSON 的语法非常简单，只有几条核心规则：

```json
{
  "name": "张三",
  "age": 25,
  "isStudent": false,
  "courses": ["数学", "英语", "物理"],
  "address": {
    "city": "北京",
    "street": "朝阳区xxx街道"
  },
  "spouse": null
}
```

**核心规则：**

1. **数据以键值对形式存在**：`"key": value`
2. **键必须是双引号包裹的字符串**：`"name"` ✅，`name` ❌，`'name'` ❌
3. **值可以是多种类型**：字符串、数字、布尔值、null、数组、对象
4. **数据由逗号分隔**：多个键值对之间用逗号分隔
5. **对象用花括号包裹**：`{ }`
6. **数组用方括号包裹**：`[ ]`
7. **不支持注释**：JSON 标准不允许注释（这是常见的坑）


### 2.2 正确与错误示例对比

```json
// ❌ 错误示例 1：键没有用双引号
{
  name: "张三"
}

// ✅ 正确示例
{
  "name": "张三"
}
```

```json
// ❌ 错误示例 2：使用单引号
{
  'name': '张三'
}

// ✅ 正确示例
{
  "name": "张三"
}
```

```json
// ❌ 错误示例 3：末尾有多余逗号（trailing comma）
{
  "name": "张三",
  "age": 25,
}

// ✅ 正确示例
{
  "name": "张三",
  "age": 25
}
```

```json
// ❌ 错误示例 4：包含注释
{
  "name": "张三", // 这是名字
  "age": 25 /* 这是年龄 */
}

// ✅ 正确示例（JSON 不支持注释）
{
  "name": "张三",
  "age": 25
}
```

```json
// ❌ 错误示例 5：使用 undefined
{
  "name": "张三",
  "age": undefined
}

// ✅ 正确示例（使用 null 代替）
{
  "name": "张三",
  "age": null
}
```

### 2.3 字符串转义

JSON 字符串中的特殊字符需要转义：

| 转义序列 | 含义 |
|---------|------|
| `\"` | 双引号 |
| `\\` | 反斜杠 |
| `\/` | 正斜杠（可选） |
| `\b` | 退格符 |
| `\f` | 换页符 |
| `\n` | 换行符 |
| `\r` | 回车符 |
| `\t` | 制表符 |
| `\uXXXX` | Unicode 字符 |

```json
{
  "message": "他说：\"你好！\"",
  "path": "C:\\Users\\Documents",
  "multiline": "第一行\n第二行",
  "chinese": "\u4e2d\u6587"
}
```

---

## 3. JSON 数据类型

JSON 支持六种数据类型，理解这些类型是正确使用 JSON 的基础。

### 3.1 字符串（String）

字符串必须用**双引号**包裹，支持 Unicode 字符。

```json
{
  "name": "张三",
  "greeting": "Hello, World!",
  "emoji": "😀",
  "unicode": "\u0048\u0065\u006c\u006c\u006f"
}
```

**注意事项：**
- 必须使用双引号，不能使用单引号
- 字符串中的双引号需要转义：`\"`
- 支持 Unicode 转义：`\uXXXX`

### 3.2 数字（Number）

JSON 中的数字可以是整数或浮点数，支持科学计数法。

```json
{
  "integer": 42,
  "negative": -17,
  "float": 3.14159,
  "scientific": 1.23e10,
  "scientificNegative": 5.67e-8
}
```

**注意事项：**
- 不支持八进制（`0777`）和十六进制（`0xFF`）
- 不支持 `NaN` 和 `Infinity`
- 不支持前导零：`007` ❌
- 数字不需要引号包裹

```json
// ❌ 错误示例
{
  "octal": 0777,
  "hex": 0xFF,
  "nan": NaN,
  "infinity": Infinity,
  "leadingZero": 007
}

// ✅ 正确示例
{
  "octal": 511,
  "hex": 255,
  "nan": null,
  "infinity": null,
  "leadingZero": 7
}
```

### 3.3 布尔值（Boolean）

只有两个值：`true` 和 `false`，必须小写。

```json
{
  "isActive": true,
  "isDeleted": false
}
```

**注意事项：**
- 必须小写：`true` ✅，`True` ❌，`TRUE` ❌
- 不需要引号包裹

### 3.4 空值（Null）

表示空值或不存在，只有一个值：`null`，必须小写。

```json
{
  "middleName": null,
  "spouse": null
}
```

**注意事项：**
- 必须小写：`null` ✅，`Null` ❌，`NULL` ❌
- 不同于 JavaScript 的 `undefined`，JSON 不支持 `undefined`

### 3.5 数组（Array）

有序的值列表，用方括号包裹，元素之间用逗号分隔。

```json
{
  "numbers": [1, 2, 3, 4, 5],
  "strings": ["apple", "banana", "cherry"],
  "mixed": [1, "two", true, null],
  "nested": [[1, 2], [3, 4], [5, 6]],
  "empty": []
}
```

**注意事项：**
- 数组元素可以是任意 JSON 类型
- 数组可以嵌套
- 最后一个元素后不能有逗号

### 3.6 对象（Object）

无序的键值对集合，用花括号包裹。

```json
{
  "person": {
    "name": "张三",
    "age": 25,
    "address": {
      "city": "北京",
      "country": "中国"
    }
  },
  "empty": {}
}
```

**注意事项：**
- 键必须是字符串（双引号包裹）
- 值可以是任意 JSON 类型
- 对象可以嵌套
- 键的顺序不保证（虽然大多数实现会保持顺序）


---

## 4. JavaScript 中的 JSON 操作

JavaScript 提供了内置的 `JSON` 对象来处理 JSON 数据，主要有两个方法：`JSON.parse()` 和 `JSON.stringify()`。

### 4.1 JSON.parse() - 解析 JSON 字符串

将 JSON 字符串转换为 JavaScript 对象。

```javascript
// 基本用法
const jsonString = '{"name": "张三", "age": 25}'
const obj = JSON.parse(jsonString)
console.log(obj.name) // "张三"
console.log(obj.age)  // 25

// 解析数组
const arrayString = '[1, 2, 3, 4, 5]'
const arr = JSON.parse(arrayString)
console.log(arr) // [1, 2, 3, 4, 5]

// 解析嵌套结构
const nestedString = '{"user": {"name": "张三", "hobbies": ["读书", "游泳"]}}'
const nested = JSON.parse(nestedString)
console.log(nested.user.hobbies[0]) // "读书"
```

#### reviver 参数（转换函数）

`JSON.parse()` 的第二个参数是一个转换函数，可以在解析过程中对值进行转换。

```javascript
// 将日期字符串转换为 Date 对象
const jsonString = '{"name": "张三", "birthday": "1998-05-15"}'

const obj = JSON.parse(jsonString, (key, value) => {
  // 检测日期格式的字符串
  if (key === 'birthday' && typeof value === 'string') {
    return new Date(value)
  }
  return value
})

console.log(obj.birthday instanceof Date) // true
console.log(obj.birthday.getFullYear())   // 1998
```

```javascript
// 过滤敏感信息
const jsonString = '{"username": "admin", "password": "123456", "email": "admin@example.com"}'

const obj = JSON.parse(jsonString, (key, value) => {
  if (key === 'password') {
    return undefined // 返回 undefined 会删除该属性
  }
  return value
})

console.log(obj) // { username: "admin", email: "admin@example.com" }
```

```javascript
// 数值转换
const jsonString = '{"price": "99.99", "quantity": "5"}'

const obj = JSON.parse(jsonString, (key, value) => {
  if (key === 'price' || key === 'quantity') {
    return Number(value)
  }
  return value
})

console.log(typeof obj.price)    // "number"
console.log(obj.price * obj.quantity) // 499.95
```

### 4.2 JSON.stringify() - 序列化为 JSON 字符串

将 JavaScript 对象转换为 JSON 字符串。

```javascript
// 基本用法
const obj = { name: '张三', age: 25 }
const jsonString = JSON.stringify(obj)
console.log(jsonString) // '{"name":"张三","age":25}'

// 序列化数组
const arr = [1, 2, 3, 4, 5]
console.log(JSON.stringify(arr)) // '[1,2,3,4,5]'

// 序列化嵌套结构
const nested = {
  user: {
    name: '张三',
    hobbies: ['读书', '游泳']
  }
}
console.log(JSON.stringify(nested))
// '{"user":{"name":"张三","hobbies":["读书","游泳"]}}'
```

#### replacer 参数（过滤器）

第二个参数可以是数组或函数，用于过滤或转换属性。

```javascript
// 使用数组指定要包含的属性
const obj = {
  name: '张三',
  age: 25,
  password: '123456',
  email: 'zhangsan@example.com'
}

// 只序列化指定的属性
const jsonString = JSON.stringify(obj, ['name', 'email'])
console.log(jsonString) // '{"name":"张三","email":"zhangsan@example.com"}'
```

```javascript
// 使用函数进行转换
const obj = {
  name: '张三',
  age: 25,
  password: '123456',
  salary: 10000
}

const jsonString = JSON.stringify(obj, (key, value) => {
  // 过滤敏感信息
  if (key === 'password') {
    return undefined
  }
  // 转换数值
  if (key === 'salary') {
    return value * 1.1 // 加薪 10%
  }
  return value
})

console.log(jsonString) // '{"name":"张三","age":25,"salary":11000}'
```

#### space 参数（格式化）

第三个参数用于美化输出，可以是数字（缩进空格数）或字符串（缩进字符）。

```javascript
const obj = {
  name: '张三',
  age: 25,
  address: {
    city: '北京',
    street: '朝阳区'
  }
}

// 使用 2 个空格缩进
console.log(JSON.stringify(obj, null, 2))
/*
{
  "name": "张三",
  "age": 25,
  "address": {
    "city": "北京",
    "street": "朝阳区"
  }
}
*/

// 使用 Tab 缩进
console.log(JSON.stringify(obj, null, '\t'))

// 使用自定义字符
console.log(JSON.stringify(obj, null, '----'))
```

### 4.3 特殊值的处理

JavaScript 中有些值在 JSON 序列化时会有特殊行为：

```javascript
const obj = {
  // 这些值会被转换为 null
  undefinedValue: undefined,  // 会被忽略（对象属性）
  functionValue: function() {}, // 会被忽略
  symbolValue: Symbol('test'),  // 会被忽略
  
  // 这些值会被转换为 null（在数组中）
  array: [undefined, function() {}, Symbol('test')],
  
  // 特殊数值
  nan: NaN,           // 转换为 null
  infinity: Infinity, // 转换为 null
  negInfinity: -Infinity, // 转换为 null
  
  // 正常值
  nullValue: null,    // 保持为 null
  date: new Date(),   // 转换为 ISO 字符串
  regex: /test/g,     // 转换为空对象 {}
}

console.log(JSON.stringify(obj, null, 2))
/*
{
  "array": [null, null, null],
  "nan": null,
  "infinity": null,
  "negInfinity": null,
  "nullValue": null,
  "date": "2024-01-15T08:30:00.000Z",
  "regex": {}
}
*/
```

### 4.4 toJSON 方法

如果对象有 `toJSON` 方法，`JSON.stringify()` 会调用它来获取序列化的值。

```javascript
// 自定义序列化行为
const user = {
  name: '张三',
  password: '123456',
  birthday: new Date('1998-05-15'),
  
  toJSON() {
    return {
      name: this.name,
      // 不包含密码
      birthday: this.birthday.toLocaleDateString('zh-CN')
    }
  }
}

console.log(JSON.stringify(user))
// '{"name":"张三","birthday":"1998/5/15"}'
```

```javascript
// Date 对象内置了 toJSON 方法
const date = new Date('2024-01-15T08:30:00Z')
console.log(date.toJSON()) // "2024-01-15T08:30:00.000Z"
console.log(JSON.stringify({ date })) // '{"date":"2024-01-15T08:30:00.000Z"}'
```


### 4.5 深拷贝技巧

利用 JSON 方法可以实现简单的深拷贝：

```javascript
const original = {
  name: '张三',
  hobbies: ['读书', '游泳'],
  address: {
    city: '北京'
  }
}

// 深拷贝
const copy = JSON.parse(JSON.stringify(original))

// 修改拷贝不会影响原对象
copy.hobbies.push('跑步')
copy.address.city = '上海'

console.log(original.hobbies) // ['读书', '游泳']
console.log(original.address.city) // '北京'
```

**注意：这种方法有局限性：**

```javascript
const obj = {
  date: new Date(),           // 会变成字符串
  func: function() {},        // 会丢失
  undefined: undefined,       // 会丢失
  symbol: Symbol('test'),     // 会丢失
  regex: /test/g,             // 会变成空对象
  infinity: Infinity,         // 会变成 null
  nan: NaN,                   // 会变成 null
  // 循环引用会报错
}

// 更好的深拷贝方案
// 1. 使用 structuredClone（现代浏览器）
const copy1 = structuredClone(original)

// 2. 使用 lodash
import { cloneDeep } from 'lodash'
const copy2 = cloneDeep(original)
```

---

## 5. JSON Schema 验证

JSON Schema 是一种用于描述和验证 JSON 数据结构的规范。它可以确保 JSON 数据符合预期的格式。

### 5.1 基本概念

JSON Schema 本身也是 JSON 格式，用于定义数据的结构、类型和约束。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://example.com/user.schema.json",
  "title": "User",
  "description": "用户信息",
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "description": "用户名"
    },
    "age": {
      "type": "integer",
      "minimum": 0,
      "maximum": 150
    },
    "email": {
      "type": "string",
      "format": "email"
    }
  },
  "required": ["name", "email"]
}
```

### 5.2 常用关键字

#### 类型关键字

```json
{
  "type": "string"    // 字符串
  "type": "number"    // 数字（整数或浮点数）
  "type": "integer"   // 整数
  "type": "boolean"   // 布尔值
  "type": "null"      // 空值
  "type": "array"     // 数组
  "type": "object"    // 对象
}
```

#### 字符串约束

```json
{
  "type": "string",
  "minLength": 1,           // 最小长度
  "maxLength": 100,         // 最大长度
  "pattern": "^[a-zA-Z]+$", // 正则表达式
  "format": "email"         // 预定义格式
}
```

常用 format 值：
- `email` - 邮箱
- `uri` - URI
- `date` - 日期（YYYY-MM-DD）
- `date-time` - 日期时间（ISO 8601）
- `time` - 时间
- `ipv4` - IPv4 地址
- `ipv6` - IPv6 地址
- `uuid` - UUID

#### 数字约束

```json
{
  "type": "number",
  "minimum": 0,           // 最小值
  "maximum": 100,         // 最大值
  "exclusiveMinimum": 0,  // 大于（不包含）
  "exclusiveMaximum": 100,// 小于（不包含）
  "multipleOf": 5         // 必须是 5 的倍数
}
```

#### 数组约束

```json
{
  "type": "array",
  "items": {              // 数组元素的 schema
    "type": "string"
  },
  "minItems": 1,          // 最少元素数
  "maxItems": 10,         // 最多元素数
  "uniqueItems": true     // 元素必须唯一
}
```

#### 对象约束

```json
{
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "age": { "type": "integer" }
  },
  "required": ["name"],           // 必需属性
  "additionalProperties": false,  // 不允许额外属性
  "minProperties": 1,             // 最少属性数
  "maxProperties": 10             // 最多属性数
}
```

### 5.3 JavaScript 中使用 JSON Schema

使用 `ajv` 库进行 JSON Schema 验证：

```bash
npm install ajv ajv-formats
```

```javascript
import Ajv from 'ajv'
import addFormats from 'ajv-formats'

const ajv = new Ajv()
addFormats(ajv)

// 定义 Schema
const userSchema = {
  type: 'object',
  properties: {
    name: { type: 'string', minLength: 1 },
    age: { type: 'integer', minimum: 0, maximum: 150 },
    email: { type: 'string', format: 'email' }
  },
  required: ['name', 'email'],
  additionalProperties: false
}

// 编译 Schema
const validate = ajv.compile(userSchema)

// 验证数据
const validData = {
  name: '张三',
  age: 25,
  email: 'zhangsan@example.com'
}

const invalidData = {
  name: '',
  age: -5,
  email: 'invalid-email'
}

console.log(validate(validData))   // true
console.log(validate(invalidData)) // false
console.log(validate.errors)       // 错误详情
```

### 5.4 复杂 Schema 示例

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Product",
  "type": "object",
  "properties": {
    "id": {
      "type": "integer",
      "description": "产品ID"
    },
    "name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "price": {
      "type": "number",
      "minimum": 0,
      "exclusiveMinimum": 0
    },
    "category": {
      "type": "string",
      "enum": ["electronics", "clothing", "food", "other"]
    },
    "tags": {
      "type": "array",
      "items": { "type": "string" },
      "uniqueItems": true,
      "maxItems": 10
    },
    "dimensions": {
      "type": "object",
      "properties": {
        "length": { "type": "number", "minimum": 0 },
        "width": { "type": "number", "minimum": 0 },
        "height": { "type": "number", "minimum": 0 }
      },
      "required": ["length", "width", "height"]
    },
    "inStock": {
      "type": "boolean",
      "default": true
    }
  },
  "required": ["id", "name", "price"],
  "additionalProperties": false
}
```


---

## 6. JSON 与 HTTP 请求

在 Web 开发中，JSON 是前后端数据交换的标准格式。

### 6.1 使用 Fetch API

```javascript
// GET 请求
async function getUsers() {
  try {
    const response = await fetch('https://api.example.com/users')
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    
    const data = await response.json() // 自动解析 JSON
    console.log(data)
    return data
  } catch (error) {
    console.error('获取用户失败:', error)
    throw error
  }
}

// POST 请求
async function createUser(userData) {
  try {
    const response = await fetch('https://api.example.com/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json', // 重要：指定内容类型
        'Accept': 'application/json'
      },
      body: JSON.stringify(userData) // 序列化为 JSON 字符串
    })
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    
    const data = await response.json()
    return data
  } catch (error) {
    console.error('创建用户失败:', error)
    throw error
  }
}

// 使用示例
const newUser = {
  name: '张三',
  email: 'zhangsan@example.com',
  age: 25
}

createUser(newUser).then(user => {
  console.log('创建成功:', user)
})
```

### 6.2 使用 Axios

Axios 是一个流行的 HTTP 客户端，自动处理 JSON 序列化和解析。

```bash
npm install axios
```

```javascript
import axios from 'axios'

// 创建实例
const api = axios.create({
  baseURL: 'https://api.example.com',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// GET 请求
async function getUsers() {
  try {
    const response = await api.get('/users')
    return response.data // axios 自动解析 JSON
  } catch (error) {
    console.error('获取用户失败:', error.response?.data || error.message)
    throw error
  }
}

// POST 请求
async function createUser(userData) {
  try {
    // axios 自动将对象序列化为 JSON
    const response = await api.post('/users', userData)
    return response.data
  } catch (error) {
    console.error('创建用户失败:', error.response?.data || error.message)
    throw error
  }
}

// PUT 请求
async function updateUser(id, userData) {
  try {
    const response = await api.put(`/users/${id}`, userData)
    return response.data
  } catch (error) {
    console.error('更新用户失败:', error.response?.data || error.message)
    throw error
  }
}

// DELETE 请求
async function deleteUser(id) {
  try {
    await api.delete(`/users/${id}`)
    return true
  } catch (error) {
    console.error('删除用户失败:', error.response?.data || error.message)
    throw error
  }
}
```

### 6.3 请求拦截器处理 JSON

```javascript
import axios from 'axios'

const api = axios.create({
  baseURL: 'https://api.example.com'
})

// 请求拦截器
api.interceptors.request.use(
  config => {
    // 自动添加 token
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    // 确保 Content-Type 正确
    if (config.data && typeof config.data === 'object') {
      config.headers['Content-Type'] = 'application/json'
    }
    
    return config
  },
  error => Promise.reject(error)
)

// 响应拦截器
api.interceptors.response.use(
  response => {
    // 统一处理响应数据
    const { code, data, message } = response.data
    
    if (code === 0 || code === 200) {
      return data
    }
    
    // 业务错误
    return Promise.reject(new Error(message || '请求失败'))
  },
  error => {
    // HTTP 错误处理
    if (error.response) {
      const { status, data } = error.response
      
      switch (status) {
        case 401:
          // 未授权，跳转登录
          window.location.href = '/login'
          break
        case 403:
          console.error('没有权限')
          break
        case 404:
          console.error('资源不存在')
          break
        case 500:
          console.error('服务器错误')
          break
        default:
          console.error(data?.message || '请求失败')
      }
    } else if (error.request) {
      console.error('网络错误，请检查网络连接')
    }
    
    return Promise.reject(error)
  }
)
```

### 6.4 处理 JSON 响应错误

```javascript
async function fetchWithErrorHandling(url) {
  try {
    const response = await fetch(url)
    
    // 检查 Content-Type
    const contentType = response.headers.get('content-type')
    
    if (!contentType || !contentType.includes('application/json')) {
      throw new Error('响应不是 JSON 格式')
    }
    
    // 尝试解析 JSON
    const data = await response.json()
    
    if (!response.ok) {
      // 服务器返回了错误状态码，但响应体是 JSON
      throw new Error(data.message || `HTTP ${response.status}`)
    }
    
    return data
  } catch (error) {
    if (error instanceof SyntaxError) {
      // JSON 解析错误
      console.error('JSON 解析失败:', error)
      throw new Error('服务器返回了无效的 JSON')
    }
    throw error
  }
}
```

---

## 7. JSON 文件操作

### 7.1 Node.js 中读写 JSON 文件

```javascript
import fs from 'fs'
import path from 'path'

// 同步读取
function readJsonFileSync(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8')
    return JSON.parse(content)
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.error('文件不存在:', filePath)
    } else if (error instanceof SyntaxError) {
      console.error('JSON 格式错误:', error.message)
    }
    throw error
  }
}

// 异步读取
async function readJsonFile(filePath) {
  try {
    const content = await fs.promises.readFile(filePath, 'utf-8')
    return JSON.parse(content)
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.error('文件不存在:', filePath)
    } else if (error instanceof SyntaxError) {
      console.error('JSON 格式错误:', error.message)
    }
    throw error
  }
}

// 同步写入
function writeJsonFileSync(filePath, data, pretty = true) {
  try {
    const content = pretty 
      ? JSON.stringify(data, null, 2) 
      : JSON.stringify(data)
    fs.writeFileSync(filePath, content, 'utf-8')
  } catch (error) {
    console.error('写入文件失败:', error)
    throw error
  }
}

// 异步写入
async function writeJsonFile(filePath, data, pretty = true) {
  try {
    const content = pretty 
      ? JSON.stringify(data, null, 2) 
      : JSON.stringify(data)
    await fs.promises.writeFile(filePath, content, 'utf-8')
  } catch (error) {
    console.error('写入文件失败:', error)
    throw error
  }
}

// 使用示例
const config = readJsonFileSync('./config.json')
config.version = '2.0.0'
writeJsonFileSync('./config.json', config)
```

### 7.2 使用 require 导入 JSON（Node.js）

```javascript
// Node.js 可以直接 require JSON 文件
const config = require('./config.json')
console.log(config)

// ES 模块中使用 import（需要 Node.js 17.5+ 或配置）
import config from './config.json' assert { type: 'json' }
```

### 7.3 浏览器中读取 JSON 文件

```javascript
// 通过 fetch 读取
async function loadJsonFile(url) {
  const response = await fetch(url)
  return response.json()
}

// 读取本地文件（通过 input）
function readLocalJsonFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result)
        resolve(data)
      } catch (error) {
        reject(new Error('JSON 解析失败'))
      }
    }
    
    reader.onerror = () => reject(new Error('文件读取失败'))
    reader.readAsText(file)
  })
}

// HTML
// <input type="file" id="fileInput" accept=".json" />

document.getElementById('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files[0]
  if (file) {
    try {
      const data = await readLocalJsonFile(file)
      console.log('文件内容:', data)
    } catch (error) {
      console.error('读取失败:', error)
    }
  }
})
```

### 7.4 下载 JSON 文件

```javascript
function downloadJson(data, filename = 'data.json') {
  const jsonString = JSON.stringify(data, null, 2)
  const blob = new Blob([jsonString], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  
  URL.revokeObjectURL(url)
}

// 使用示例
const userData = {
  name: '张三',
  age: 25,
  hobbies: ['读书', '游泳']
}

downloadJson(userData, 'user.json')
```


---

## 8. JSON 高级技巧

### 8.1 处理循环引用

JSON.stringify 无法处理循环引用，会抛出错误。

```javascript
// 循环引用示例
const obj = { name: '张三' }
obj.self = obj // 循环引用

// ❌ 这会报错
// JSON.stringify(obj) // TypeError: Converting circular structure to JSON

// ✅ 解决方案 1：使用 replacer 过滤循环引用
function stringifyWithCircular(obj) {
  const seen = new WeakSet()
  
  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular]'
      }
      seen.add(value)
    }
    return value
  })
}

console.log(stringifyWithCircular(obj))
// '{"name":"张三","self":"[Circular]"}'

// ✅ 解决方案 2：使用第三方库
// npm install flatted
import { stringify, parse } from 'flatted'

const jsonString = stringify(obj)
const restored = parse(jsonString)
```

### 8.2 处理大数字

JavaScript 的 Number 类型有精度限制，大于 `Number.MAX_SAFE_INTEGER`（9007199254740991）的整数会丢失精度。

```javascript
// 问题演示
const jsonString = '{"id": 9007199254740993}'
const obj = JSON.parse(jsonString)
console.log(obj.id) // 9007199254740992（精度丢失！）

// ✅ 解决方案 1：使用字符串
const jsonString2 = '{"id": "9007199254740993"}'
const obj2 = JSON.parse(jsonString2)
console.log(obj2.id) // "9007199254740993"
console.log(BigInt(obj2.id)) // 9007199254740993n

// ✅ 解决方案 2：使用 json-bigint 库
// npm install json-bigint
import JSONBig from 'json-bigint'

const jsonString3 = '{"id": 9007199254740993}'
const obj3 = JSONBig.parse(jsonString3)
console.log(obj3.id.toString()) // "9007199254740993"
```

### 8.3 JSON 路径查询（JSONPath）

JSONPath 是一种查询 JSON 数据的表达式语言，类似于 XPath。

```bash
npm install jsonpath
```

```javascript
import jp from 'jsonpath'

const data = {
  store: {
    book: [
      { category: 'fiction', author: '作者A', title: '书籍1', price: 29.99 },
      { category: 'fiction', author: '作者B', title: '书籍2', price: 39.99 },
      { category: 'tech', author: '作者C', title: '书籍3', price: 49.99 }
    ],
    bicycle: {
      color: 'red',
      price: 199.99
    }
  }
}

// 获取所有书籍的作者
const authors = jp.query(data, '$.store.book[*].author')
console.log(authors) // ['作者A', '作者B', '作者C']

// 获取所有价格
const prices = jp.query(data, '$..price')
console.log(prices) // [29.99, 39.99, 49.99, 199.99]

// 获取第一本书
const firstBook = jp.query(data, '$.store.book[0]')
console.log(firstBook)

// 获取价格小于 40 的书
const cheapBooks = jp.query(data, '$.store.book[?(@.price < 40)]')
console.log(cheapBooks)

// 获取 fiction 类别的书
const fictionBooks = jp.query(data, '$.store.book[?(@.category == "fiction")]')
console.log(fictionBooks)
```

### 8.4 JSON Patch（增量更新）

JSON Patch 是一种描述 JSON 文档变更的格式（RFC 6902）。

```bash
npm install fast-json-patch
```

```javascript
import { applyPatch, compare } from 'fast-json-patch'

// 原始数据
const original = {
  name: '张三',
  age: 25,
  hobbies: ['读书', '游泳']
}

// 定义补丁操作
const patch = [
  { op: 'replace', path: '/name', value: '李四' },
  { op: 'add', path: '/email', value: 'lisi@example.com' },
  { op: 'remove', path: '/age' },
  { op: 'add', path: '/hobbies/-', value: '跑步' }
]

// 应用补丁
const result = applyPatch(original, patch)
console.log(result.newDocument)
/*
{
  name: '李四',
  hobbies: ['读书', '游泳', '跑步'],
  email: 'lisi@example.com'
}
*/

// 比较两个对象，生成补丁
const obj1 = { name: '张三', age: 25 }
const obj2 = { name: '李四', age: 26, email: 'lisi@example.com' }

const diff = compare(obj1, obj2)
console.log(diff)
/*
[
  { op: 'replace', path: '/name', value: '李四' },
  { op: 'replace', path: '/age', value: 26 },
  { op: 'add', path: '/email', value: 'lisi@example.com' }
]
*/
```

### 8.5 JSON 合并

```javascript
// 浅合并
const obj1 = { a: 1, b: 2 }
const obj2 = { b: 3, c: 4 }
const merged = { ...obj1, ...obj2 }
console.log(merged) // { a: 1, b: 3, c: 4 }

// 深合并
function deepMerge(target, source) {
  const result = { ...target }
  
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (
        typeof source[key] === 'object' &&
        source[key] !== null &&
        !Array.isArray(source[key]) &&
        typeof target[key] === 'object' &&
        target[key] !== null &&
        !Array.isArray(target[key])
      ) {
        result[key] = deepMerge(target[key], source[key])
      } else {
        result[key] = source[key]
      }
    }
  }
  
  return result
}

const config1 = {
  server: { host: 'localhost', port: 3000 },
  database: { host: 'localhost' }
}

const config2 = {
  server: { port: 8080 },
  database: { port: 5432, name: 'mydb' }
}

const mergedConfig = deepMerge(config1, config2)
console.log(mergedConfig)
/*
{
  server: { host: 'localhost', port: 8080 },
  database: { host: 'localhost', port: 5432, name: 'mydb' }
}
*/

// 使用 lodash 的 merge
import { merge } from 'lodash'
const result = merge({}, config1, config2)
```

### 8.6 JSON 压缩与解压

```javascript
// 使用 pako 进行 gzip 压缩
// npm install pako
import pako from 'pako'

// 压缩
function compressJson(data) {
  const jsonString = JSON.stringify(data)
  const compressed = pako.gzip(jsonString)
  return compressed
}

// 解压
function decompressJson(compressed) {
  const decompressed = pako.ungzip(compressed, { to: 'string' })
  return JSON.parse(decompressed)
}

// 使用示例
const largeData = {
  users: Array.from({ length: 1000 }, (_, i) => ({
    id: i,
    name: `用户${i}`,
    email: `user${i}@example.com`
  }))
}

const compressed = compressJson(largeData)
console.log('原始大小:', JSON.stringify(largeData).length)
console.log('压缩后大小:', compressed.length)

const restored = decompressJson(compressed)
console.log('解压后数据条数:', restored.users.length)
```


---

## 9. JSON 与其他格式对比

### 9.1 JSON vs XML

| 特性 | JSON | XML |
|------|------|-----|
| 可读性 | 简洁易读 | 相对冗长 |
| 数据大小 | 较小 | 较大（标签占用空间） |
| 解析速度 | 快 | 较慢 |
| 数据类型 | 支持基本类型 | 全部是字符串 |
| 注释 | 不支持 | 支持 |
| 命名空间 | 不支持 | 支持 |
| 属性 | 不支持 | 支持 |
| 数组 | 原生支持 | 需要重复元素 |

```xml
<!-- XML 示例 -->
<user>
  <name>张三</name>
  <age>25</age>
  <hobbies>
    <hobby>读书</hobby>
    <hobby>游泳</hobby>
  </hobbies>
</user>
```

```json
// JSON 示例（更简洁）
{
  "name": "张三",
  "age": 25,
  "hobbies": ["读书", "游泳"]
}
```

### 9.2 JSON vs YAML

| 特性 | JSON | YAML |
|------|------|------|
| 可读性 | 好 | 更好（无引号和括号） |
| 注释 | 不支持 | 支持 |
| 多行字符串 | 需要转义 | 原生支持 |
| 引用 | 不支持 | 支持锚点和别名 |
| 复杂度 | 简单 | 相对复杂 |
| 解析速度 | 快 | 较慢 |

```yaml
# YAML 示例
name: 张三
age: 25
hobbies:
  - 读书
  - 游泳
address:
  city: 北京
  street: 朝阳区
description: |
  这是一段
  多行文本
```

```json
// 等价的 JSON
{
  "name": "张三",
  "age": 25,
  "hobbies": ["读书", "游泳"],
  "address": {
    "city": "北京",
    "street": "朝阳区"
  },
  "description": "这是一段\n多行文本"
}
```

### 9.3 JSON vs CSV

| 特性 | JSON | CSV |
|------|------|-----|
| 结构 | 层级结构 | 扁平表格 |
| 数据类型 | 多种类型 | 全部是字符串 |
| 嵌套数据 | 支持 | 不支持 |
| 文件大小 | 较大 | 较小 |
| 可读性 | 好 | 简单数据好 |
| 适用场景 | API、配置 | 表格数据、导出 |

```csv
name,age,city
张三,25,北京
李四,30,上海
```

```json
[
  { "name": "张三", "age": 25, "city": "北京" },
  { "name": "李四", "age": 30, "city": "上海" }
]
```

### 9.4 JSON5 - JSON 的超集

JSON5 是 JSON 的扩展，支持更多特性：

```javascript
// JSON5 示例
{
  // 支持注释
  name: '张三',  // 键可以不加引号
  'age': 25,     // 支持单引号
  hobbies: [
    '读书',
    '游泳',      // 支持尾随逗号
  ],
  description: '这是一段\
很长的文本',     // 支持多行字符串
  hex: 0xFF,     // 支持十六进制
  infinity: Infinity,  // 支持 Infinity
  nan: NaN,      // 支持 NaN
}
```

```bash
npm install json5
```

```javascript
import JSON5 from 'json5'

const json5String = `{
  // 配置文件
  name: '我的应用',
  version: '1.0.0',
  dependencies: {
    lodash: '^4.17.21',
  },
}`

const config = JSON5.parse(json5String)
console.log(config)
```

---

## 10. 性能优化

### 10.1 大数据量处理

```javascript
// 问题：一次性解析大 JSON 会阻塞主线程
const hugeJsonString = '...' // 假设是一个很大的 JSON 字符串

// ❌ 不推荐：同步解析
const data = JSON.parse(hugeJsonString) // 可能阻塞几秒

// ✅ 推荐：使用 Web Worker
// worker.js
self.onmessage = function(e) {
  const data = JSON.parse(e.data)
  self.postMessage(data)
}

// main.js
const worker = new Worker('worker.js')
worker.postMessage(hugeJsonString)
worker.onmessage = function(e) {
  const data = e.data
  console.log('解析完成', data)
}
```

### 10.2 流式解析

对于超大 JSON 文件，可以使用流式解析：

```bash
npm install stream-json
```

```javascript
import { parser } from 'stream-json'
import { streamArray } from 'stream-json/streamers/StreamArray'
import fs from 'fs'

// 流式读取大型 JSON 数组
const pipeline = fs.createReadStream('large-array.json')
  .pipe(parser())
  .pipe(streamArray())

let count = 0

pipeline.on('data', ({ key, value }) => {
  // 逐个处理数组元素
  count++
  if (count % 10000 === 0) {
    console.log(`已处理 ${count} 条数据`)
  }
})

pipeline.on('end', () => {
  console.log(`总共处理 ${count} 条数据`)
})
```

### 10.3 序列化优化

```javascript
// 减少序列化的数据量
const user = {
  id: 1,
  name: '张三',
  password: '123456', // 敏感信息
  createdAt: new Date(),
  updatedAt: new Date(),
  // ... 很多其他字段
}

// ✅ 只序列化需要的字段
const jsonString = JSON.stringify(user, ['id', 'name'])

// ✅ 使用 toJSON 方法
class User {
  constructor(data) {
    Object.assign(this, data)
  }
  
  toJSON() {
    // 只返回需要序列化的字段
    return {
      id: this.id,
      name: this.name
    }
  }
}
```

### 10.4 缓存解析结果

```javascript
// 使用 Map 缓存解析结果
const parseCache = new Map()

function cachedParse(jsonString) {
  if (parseCache.has(jsonString)) {
    return parseCache.get(jsonString)
  }
  
  const result = JSON.parse(jsonString)
  parseCache.set(jsonString, result)
  return result
}

// 使用 WeakMap 缓存（自动垃圾回收）
const objectCache = new WeakMap()

function cachedStringify(obj) {
  if (objectCache.has(obj)) {
    return objectCache.get(obj)
  }
  
  const result = JSON.stringify(obj)
  objectCache.set(obj, result)
  return result
}
```

### 10.5 避免重复序列化

```javascript
// ❌ 不推荐：重复序列化
function logData(data) {
  console.log(JSON.stringify(data))
  sendToServer(JSON.stringify(data))
  saveToFile(JSON.stringify(data))
}

// ✅ 推荐：只序列化一次
function logData(data) {
  const jsonString = JSON.stringify(data)
  console.log(jsonString)
  sendToServer(jsonString)
  saveToFile(jsonString)
}
```


---

## 11. 安全注意事项

### 11.1 JSON 注入攻击

```javascript
// ❌ 危险：直接拼接用户输入
const userInput = '", "admin": true, "x": "'
const jsonString = `{"name": "${userInput}"}`
// 结果：{"name": "", "admin": true, "x": ""}

// ✅ 安全：使用 JSON.stringify
const safeJson = JSON.stringify({ name: userInput })
// 结果：{"name":"\", \"admin\": true, \"x\": \""}
```

### 11.2 避免使用 eval 解析 JSON

```javascript
// ❌ 极度危险：使用 eval
const jsonString = '{"name": "张三"}'
const data = eval('(' + jsonString + ')') // 可能执行恶意代码

// 恶意输入示例
const malicious = '(function() { /* 恶意代码 */ })()'
eval('(' + malicious + ')') // 会执行恶意代码

// ✅ 安全：使用 JSON.parse
const data = JSON.parse(jsonString)
```

### 11.3 防止原型污染

```javascript
// 原型污染攻击示例
const maliciousJson = '{"__proto__": {"isAdmin": true}}'
const obj = JSON.parse(maliciousJson)

// 在某些情况下，这可能影响所有对象
const newObj = {}
console.log(newObj.isAdmin) // 可能是 true

// ✅ 防护措施 1：使用 Object.create(null)
function safeParse(jsonString) {
  const obj = JSON.parse(jsonString)
  return Object.assign(Object.create(null), obj)
}

// ✅ 防护措施 2：过滤危险属性
function safeParse2(jsonString) {
  return JSON.parse(jsonString, (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return undefined
    }
    return value
  })
}

// ✅ 防护措施 3：使用 Object.freeze
const parsed = JSON.parse(jsonString)
Object.freeze(Object.prototype)
```

### 11.4 敏感数据处理

```javascript
// ❌ 不要在 JSON 中存储敏感信息
const user = {
  name: '张三',
  password: '123456',      // 密码
  creditCard: '1234-5678', // 信用卡
  ssn: '123-45-6789'       // 社会安全号
}

// ✅ 序列化时过滤敏感字段
const sensitiveFields = ['password', 'creditCard', 'ssn', 'token']

function safeStringify(obj) {
  return JSON.stringify(obj, (key, value) => {
    if (sensitiveFields.includes(key)) {
      return undefined
    }
    return value
  })
}

// ✅ 使用类的 toJSON 方法
class User {
  constructor(data) {
    this.name = data.name
    this.password = data.password
    this.email = data.email
  }
  
  toJSON() {
    return {
      name: this.name,
      email: this.email
      // 不包含 password
    }
  }
}
```

### 11.5 验证 JSON 数据

```javascript
// 始终验证从外部接收的 JSON 数据
async function fetchUserData(userId) {
  const response = await fetch(`/api/users/${userId}`)
  const data = await response.json()
  
  // ✅ 验证数据结构
  if (!data || typeof data !== 'object') {
    throw new Error('无效的响应数据')
  }
  
  if (typeof data.name !== 'string') {
    throw new Error('用户名必须是字符串')
  }
  
  if (typeof data.age !== 'number' || data.age < 0) {
    throw new Error('年龄必须是正数')
  }
  
  return data
}

// ✅ 使用 JSON Schema 验证
import Ajv from 'ajv'

const ajv = new Ajv()
const validate = ajv.compile(userSchema)

async function fetchAndValidate(url) {
  const response = await fetch(url)
  const data = await response.json()
  
  if (!validate(data)) {
    console.error('验证失败:', validate.errors)
    throw new Error('数据验证失败')
  }
  
  return data
}
```

### 11.6 限制 JSON 大小

```javascript
// 服务端：限制请求体大小
// Express.js 示例
import express from 'express'

const app = express()
app.use(express.json({ limit: '1mb' })) // 限制 JSON 大小为 1MB

// 客户端：检查响应大小
async function fetchWithSizeLimit(url, maxSize = 1024 * 1024) {
  const response = await fetch(url)
  
  const contentLength = response.headers.get('content-length')
  if (contentLength && parseInt(contentLength) > maxSize) {
    throw new Error('响应数据过大')
  }
  
  const text = await response.text()
  if (text.length > maxSize) {
    throw new Error('响应数据过大')
  }
  
  return JSON.parse(text)
}
```

---

## 12. 常见错误与解决方案

### 12.1 SyntaxError: Unexpected token

**错误原因：** JSON 格式不正确

```javascript
// ❌ 错误示例
JSON.parse("{'name': 'test'}") // 单引号
JSON.parse("{name: 'test'}")   // 键没有引号
JSON.parse('{"name": "test",}') // 尾随逗号

// ✅ 正确示例
JSON.parse('{"name": "test"}')
```

**调试技巧：**

```javascript
function safeParse(jsonString) {
  try {
    return JSON.parse(jsonString)
  } catch (error) {
    if (error instanceof SyntaxError) {
      // 尝试找出错误位置
      const match = error.message.match(/position (\d+)/)
      if (match) {
        const position = parseInt(match[1])
        const start = Math.max(0, position - 20)
        const end = Math.min(jsonString.length, position + 20)
        console.error('错误位置附近:', jsonString.slice(start, end))
        console.error('错误位置:', ' '.repeat(position - start) + '^')
      }
    }
    throw error
  }
}
```

### 12.2 SyntaxError: Unexpected end of JSON input

**错误原因：** JSON 字符串不完整

```javascript
// ❌ 错误示例
JSON.parse('')           // 空字符串
JSON.parse('{"name":')   // 不完整的 JSON
JSON.parse('{"name": "test"') // 缺少闭合括号

// ✅ 解决方案：检查字符串是否为空
function safeParse(jsonString) {
  if (!jsonString || jsonString.trim() === '') {
    return null
  }
  return JSON.parse(jsonString)
}
```

### 12.3 TypeError: Converting circular structure to JSON

**错误原因：** 对象包含循环引用

```javascript
// ❌ 错误示例
const obj = { name: '张三' }
obj.self = obj
JSON.stringify(obj) // TypeError

// ✅ 解决方案：过滤循环引用
function stringifyWithCircular(obj) {
  const seen = new WeakSet()
  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular]'
      }
      seen.add(value)
    }
    return value
  })
}
```

### 12.4 数字精度丢失

**错误原因：** JavaScript 数字精度限制

```javascript
// ❌ 问题示例
const json = '{"id": 9007199254740993}'
const obj = JSON.parse(json)
console.log(obj.id) // 9007199254740992（精度丢失）

// ✅ 解决方案 1：使用字符串
const json2 = '{"id": "9007199254740993"}'

// ✅ 解决方案 2：使用 BigInt
const id = BigInt('9007199254740993')

// ✅ 解决方案 3：使用 json-bigint 库
import JSONBig from 'json-bigint'
const obj2 = JSONBig.parse(json)
```

### 12.5 日期处理问题

**错误原因：** JSON 不支持 Date 类型

```javascript
// 问题：Date 被转换为字符串
const obj = { date: new Date() }
const json = JSON.stringify(obj)
const parsed = JSON.parse(json)
console.log(parsed.date instanceof Date) // false
console.log(typeof parsed.date) // "string"

// ✅ 解决方案：使用 reviver 转换
const parsed2 = JSON.parse(json, (key, value) => {
  // ISO 日期格式正则
  const dateRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/
  if (typeof value === 'string' && dateRegex.test(value)) {
    return new Date(value)
  }
  return value
})
console.log(parsed2.date instanceof Date) // true
```

### 12.6 undefined 被忽略

**错误原因：** JSON 不支持 undefined

```javascript
// 问题：undefined 值被忽略
const obj = {
  name: '张三',
  age: undefined,
  hobbies: [1, undefined, 3]
}
console.log(JSON.stringify(obj))
// '{"name":"张三","hobbies":[1,null,3]}'
// age 被忽略，数组中的 undefined 变成 null

// ✅ 解决方案：使用 null 代替 undefined
const obj2 = {
  name: '张三',
  age: null,
  hobbies: [1, null, 3]
}
```


### 12.7 特殊字符导致解析失败

**错误原因：** 字符串中包含未转义的特殊字符

```javascript
// ❌ 问题示例
const str = '{"message": "Hello\nWorld"}' // 换行符未转义
JSON.parse(str) // SyntaxError

// ✅ 解决方案：确保特殊字符被转义
const obj = { message: 'Hello\nWorld' }
const json = JSON.stringify(obj) // 自动转义
console.log(json) // '{"message":"Hello\\nWorld"}'
JSON.parse(json) // 正常解析
```

### 12.8 Content-Type 不匹配

**错误原因：** HTTP 请求/响应的 Content-Type 设置不正确

```javascript
// ❌ 问题：服务器返回的不是 JSON
fetch('/api/data')
  .then(res => res.json()) // 如果响应不是 JSON，会报错
  .catch(err => console.error(err))

// ✅ 解决方案：检查 Content-Type
async function fetchJson(url) {
  const response = await fetch(url)
  
  const contentType = response.headers.get('content-type')
  if (!contentType || !contentType.includes('application/json')) {
    const text = await response.text()
    throw new Error(`期望 JSON 响应，但收到: ${contentType}\n内容: ${text.slice(0, 100)}`)
  }
  
  return response.json()
}

// ✅ 发送请求时设置正确的 Content-Type
fetch('/api/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json' // 重要！
  },
  body: JSON.stringify(data)
})
```

### 12.9 BOM 字符导致解析失败

**错误原因：** 文件开头有 BOM（字节顺序标记）

```javascript
// 问题：UTF-8 BOM 会导致解析失败
// BOM 是 \uFEFF 字符

// ✅ 解决方案：移除 BOM
function removeBOM(str) {
  if (str.charCodeAt(0) === 0xFEFF) {
    return str.slice(1)
  }
  return str
}

const jsonWithBOM = '\uFEFF{"name": "test"}'
const cleanJson = removeBOM(jsonWithBOM)
const obj = JSON.parse(cleanJson)
```

### 12.10 对象属性顺序问题

**注意：** JSON 规范不保证对象属性顺序

```javascript
// 虽然大多数实现会保持顺序，但不应依赖它
const obj = { c: 3, a: 1, b: 2 }
const json = JSON.stringify(obj)
const parsed = JSON.parse(json)
console.log(Object.keys(parsed)) // 通常是 ['c', 'a', 'b']，但不保证

// ✅ 如果需要有序数据，使用数组
const orderedData = [
  { key: 'c', value: 3 },
  { key: 'a', value: 1 },
  { key: 'b', value: 2 }
]
```

---

## 13. 最佳实践

### 13.1 命名规范

```json
// ✅ 推荐：使用 camelCase（JavaScript 风格）
{
  "firstName": "张",
  "lastName": "三",
  "phoneNumber": "13800138000"
}

// ✅ 也可以：使用 snake_case（Python/Ruby 风格）
{
  "first_name": "张",
  "last_name": "三",
  "phone_number": "13800138000"
}

// ❌ 避免：混合使用不同命名风格
{
  "firstName": "张",
  "last_name": "三",
  "Phone-Number": "13800138000"
}
```

### 13.2 数据结构设计

```json
// ✅ 推荐：扁平化结构（易于处理）
{
  "userId": 1,
  "userName": "张三",
  "userEmail": "zhangsan@example.com",
  "addressCity": "北京",
  "addressStreet": "朝阳区"
}

// ✅ 推荐：适度嵌套（逻辑清晰）
{
  "user": {
    "id": 1,
    "name": "张三",
    "email": "zhangsan@example.com"
  },
  "address": {
    "city": "北京",
    "street": "朝阳区"
  }
}

// ❌ 避免：过度嵌套
{
  "data": {
    "user": {
      "info": {
        "personal": {
          "name": {
            "first": "三",
            "last": "张"
          }
        }
      }
    }
  }
}
```

### 13.3 API 响应格式

```json
// ✅ 推荐：统一的响应格式
{
  "code": 0,
  "message": "success",
  "data": {
    "users": [...],
    "total": 100,
    "page": 1,
    "pageSize": 10
  }
}

// ✅ 错误响应
{
  "code": 400,
  "message": "参数错误",
  "errors": [
    { "field": "email", "message": "邮箱格式不正确" },
    { "field": "age", "message": "年龄必须大于0" }
  ]
}
```

### 13.4 版本控制

```json
// ✅ 在 API 响应中包含版本信息
{
  "version": "1.0",
  "data": {...}
}

// ✅ 配置文件版本
{
  "$schema": "https://example.com/config.schema.json",
  "version": "2.0.0",
  "settings": {...}
}
```

### 13.5 空值处理

```javascript
// ✅ 明确区分"没有值"和"值为空"
{
  "name": "张三",
  "nickname": null,      // 明确表示没有昵称
  "bio": ""              // 有值，但是空字符串
  // middleName 不存在  // 字段不存在
}

// ✅ 处理空值的函数
function getValue(obj, key, defaultValue = null) {
  if (!(key in obj)) {
    return defaultValue // 字段不存在
  }
  if (obj[key] === null) {
    return defaultValue // 值为 null
  }
  return obj[key]
}
```

### 13.6 类型一致性

```javascript
// ❌ 避免：同一字段不同类型
[
  { "id": 1, "name": "张三" },
  { "id": "2", "name": "李四" }  // id 类型不一致
]

// ✅ 推荐：保持类型一致
[
  { "id": 1, "name": "张三" },
  { "id": 2, "name": "李四" }
]
```

### 13.7 错误处理封装

```javascript
// ✅ 封装 JSON 操作，统一错误处理
class JsonHelper {
  static parse(jsonString, defaultValue = null) {
    if (!jsonString || typeof jsonString !== 'string') {
      return defaultValue
    }
    
    try {
      return JSON.parse(jsonString)
    } catch (error) {
      console.error('JSON 解析失败:', error.message)
      return defaultValue
    }
  }
  
  static stringify(obj, pretty = false) {
    try {
      return pretty 
        ? JSON.stringify(obj, null, 2) 
        : JSON.stringify(obj)
    } catch (error) {
      console.error('JSON 序列化失败:', error.message)
      return null
    }
  }
  
  static isValid(jsonString) {
    try {
      JSON.parse(jsonString)
      return true
    } catch {
      return false
    }
  }
}

// 使用示例
const data = JsonHelper.parse(jsonString, {})
const json = JsonHelper.stringify(obj, true)
```

### 13.8 TypeScript 类型定义

```typescript
// ✅ 为 JSON 数据定义类型
interface User {
  id: number
  name: string
  email: string
  age?: number
  hobbies: string[]
  address: {
    city: string
    street: string
  }
}

// 类型安全的解析
function parseUser(jsonString: string): User {
  const data = JSON.parse(jsonString)
  
  // 运行时验证
  if (typeof data.id !== 'number') {
    throw new Error('id 必须是数字')
  }
  if (typeof data.name !== 'string') {
    throw new Error('name 必须是字符串')
  }
  // ... 更多验证
  
  return data as User
}

// 使用 Zod 进行运行时验证
import { z } from 'zod'

const UserSchema = z.object({
  id: z.number(),
  name: z.string(),
  email: z.string().email(),
  age: z.number().optional(),
  hobbies: z.array(z.string()),
  address: z.object({
    city: z.string(),
    street: z.string()
  })
})

type User = z.infer<typeof UserSchema>

function parseUser(jsonString: string): User {
  const data = JSON.parse(jsonString)
  return UserSchema.parse(data) // 自动验证并返回类型安全的数据
}
```

---

## 总结

JSON 是现代 Web 开发中最重要的数据交换格式之一。通过本笔记的学习，你应该能够：

1. **掌握基础**：理解 JSON 的语法规则和数据类型
2. **熟练操作**：使用 `JSON.parse()` 和 `JSON.stringify()` 进行数据转换
3. **数据验证**：使用 JSON Schema 验证数据结构
4. **网络通信**：在 HTTP 请求中正确使用 JSON
5. **文件操作**：读写 JSON 文件
6. **高级技巧**：处理循环引用、大数字、流式解析等
7. **安全意识**：避免 JSON 注入、原型污染等安全问题
8. **性能优化**：处理大数据量、避免重复序列化
9. **错误处理**：识别和解决常见的 JSON 错误
10. **最佳实践**：遵循命名规范、设计良好的数据结构

**推荐资源：**
- [JSON 官方网站](https://www.json.org/json-zh.html)
- [JSON Schema 官方文档](https://json-schema.org/)
- [MDN JSON 文档](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/JSON)
- [RFC 8259 - JSON 规范](https://tools.ietf.org/html/rfc8259)