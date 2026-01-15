# Node.js 完全指南

> Node.js 是一个基于 Chrome V8 引擎的 JavaScript 运行时环境
> 它让 JavaScript 可以脱离浏览器运行在服务器端，实现全栈开发

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [模块系统](#3-模块系统)
4. [核心模块](#4-核心模块)
5. [异步编程](#5-异步编程)
6. [事件循环](#6-事件循环)
7. [文件系统](#7-文件系统)
8. [HTTP 服务](#8-http-服务)
9. [Express 框架](#9-express-框架)
10. [数据库操作](#10-数据库操作)
11. [错误处理](#11-错误处理)
12. [流与缓冲区](#12-流与缓冲区)
13. [进程与集群](#13-进程与集群)
14. [安全最佳实践](#14-安全最佳实践)
15. [性能优化](#15-性能优化)
16. [常见错误与解决方案](#16-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Node.js？

Node.js 不是一门编程语言，也不是一个框架，而是一个 **JavaScript 运行时环境**。

**通俗理解**：
- 浏览器中的 JavaScript = JavaScript 语法 + Web API（DOM、BOM）
- Node.js 中的 JavaScript = JavaScript 语法 + Node API（文件、网络、进程等）

**核心特点**：

1. **单线程**：主线程只有一个，但通过事件循环实现高并发
2. **非阻塞 I/O**：I/O 操作不会阻塞主线程
3. **事件驱动**：基于事件和回调机制
4. **跨平台**：支持 Windows、Linux、macOS

```javascript
// 第一个 Node.js 程序
console.log('Hello, Node.js!');

// 查看 Node.js 版本信息
console.log('Node.js 版本:', process.version);
console.log('运行平台:', process.platform);
console.log('CPU 架构:', process.arch);
```

### 1.2 Node.js vs 浏览器 JavaScript

| 特性 | 浏览器 | Node.js |
|------|--------|---------|
| 全局对象 | `window` | `global` / `globalThis` |
| DOM 操作 | ✅ 支持 | ❌ 不支持 |
| 文件操作 | ❌ 不支持 | ✅ 支持 |
| 网络请求 | `fetch` / `XMLHttpRequest` | `http` / `https` 模块 |
| 模块系统 | ES Modules | CommonJS + ES Modules |

### 1.3 适用场景

**适合的场景**：
- I/O 密集型应用（文件操作、网络请求）
- RESTful API 服务
- 实时应用（聊天、游戏）
- 微服务架构
- 命令行工具

**不适合的场景**：
- CPU 密集型计算（可用 Worker Threads 缓解）
- 大量同步计算任务

---

## 2. 环境搭建

### 2.1 安装 Node.js

**推荐使用 nvm（Node Version Manager）管理多版本**：

```bash
# Windows 使用 nvm-windows
# 下载地址: https://github.com/coreybutler/nvm-windows

# 安装指定版本
nvm install 20.10.0

# 切换版本
nvm use 20.10.0

# 查看已安装版本
nvm list

# 设置默认版本
nvm alias default 20.10.0
```

### 2.2 验证安装

```bash
# 查看 Node.js 版本
node -v

# 查看 npm 版本
npm -v

# 进入 REPL 交互环境
node
> 1 + 1
2
> .exit  # 退出 REPL
```

### 2.3 运行 JavaScript 文件

```bash
# 创建文件 app.js
echo console.log('Hello World') > app.js

# 运行文件
node app.js

# 使用 --watch 模式（Node.js 18+）自动重启
node --watch app.js
```

### 2.4 package.json 配置

```json
{
  "name": "my-project",
  "version": "1.0.0",
  "description": "项目描述",
  "main": "index.js",
  "type": "module",  // 启用 ES Modules
  "scripts": {
    "start": "node index.js",
    "dev": "node --watch index.js",
    "test": "node --test"
  },
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

**常见错误 ❌**：
```bash
# 错误：没有 package.json 就安装依赖
npm install express
# 解决：先初始化项目
npm init -y
npm install express
```

---

## 3. 模块系统

### 3.1 CommonJS 模块（传统方式）

Node.js 默认使用 CommonJS 模块系统，使用 `require` 导入，`module.exports` 导出。

```javascript
// ========== math.js ==========
// 方式一：逐个导出
exports.add = (a, b) => a + b;
exports.subtract = (a, b) => a - b;

// 方式二：整体导出（推荐）
module.exports = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
  PI: 3.14159
};

// 方式三：导出类
class Calculator {
  add(a, b) { return a + b; }
}
module.exports = Calculator;

// ========== app.js ==========
// 导入整个模块
const math = require('./math');
console.log(math.add(1, 2)); // 3

// 解构导入
const { add, subtract } = require('./math');
console.log(add(1, 2)); // 3

// 导入类
const Calculator = require('./math');
const calc = new Calculator();
```

**⚠️ 常见错误**：
```javascript
// ❌ 错误：exports 被重新赋值后失效
exports = { add: (a, b) => a + b };  // 这样不会导出任何东西！

// ✅ 正确：使用 module.exports
module.exports = { add: (a, b) => a + b };

// ❌ 错误：混用 exports 和 module.exports
exports.add = (a, b) => a + b;
module.exports = { subtract: (a, b) => a - b };  // add 会丢失！

// ✅ 正确：只用一种方式
module.exports = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b
};
```

### 3.2 ES Modules（现代方式）

ES Modules 是 JavaScript 官方标准，使用 `import` / `export` 语法。

**启用方式**：
1. 文件扩展名使用 `.mjs`
2. 或在 `package.json` 中设置 `"type": "module"`

```javascript
// ========== math.mjs ==========
// 命名导出
export const add = (a, b) => a + b;
export const subtract = (a, b) => a - b;
export const PI = 3.14159;

// 默认导出
export default class Calculator {
  multiply(a, b) { return a * b; }
}

// ========== app.mjs ==========
// 命名导入
import { add, subtract } from './math.mjs';

// 默认导入
import Calculator from './math.mjs';

// 全部导入
import * as math from './math.mjs';
console.log(math.add(1, 2));

// 动态导入（返回 Promise）
const module = await import('./math.mjs');
```

### 3.3 CommonJS vs ES Modules 对比

| 特性 | CommonJS | ES Modules |
|------|----------|------------|
| 语法 | `require` / `module.exports` | `import` / `export` |
| 加载时机 | 运行时加载 | 编译时加载 |
| 加载方式 | 同步 | 异步 |
| 顶层 await | ❌ 不支持 | ✅ 支持 |
| 文件扩展名 | `.js` / `.cjs` | `.mjs` 或配置 type |
| `this` 指向 | `module.exports` | `undefined` |

**⚠️ 常见错误**：
```javascript
// ❌ 错误：在 ES Modules 中使用 require
import fs from 'fs';
const path = require('path');  // 报错！

// ✅ 正确：统一使用 import
import fs from 'fs';
import path from 'path';

// ❌ 错误：忘记文件扩展名
import { add } from './math';  // 可能报错

// ✅ 正确：ES Modules 需要完整路径
import { add } from './math.mjs';
import { add } from './math.js';
```

### 3.4 模块解析规则

```javascript
// 1. 核心模块（最高优先级）
const fs = require('fs');
const path = require('path');

// 2. 文件模块（以 ./ 或 ../ 开头）
const myModule = require('./myModule');
// 查找顺序：myModule.js → myModule.json → myModule.node → myModule/index.js

// 3. 第三方模块（从 node_modules 查找）
const express = require('express');
// 查找顺序：当前目录 node_modules → 父目录 node_modules → ... → 全局 node_modules
```

---

## 4. 核心模块

Node.js 内置了许多核心模块，无需安装即可使用。

### 4.1 path 模块 - 路径处理

```javascript
const path = require('path');

// 拼接路径（自动处理分隔符）
const fullPath = path.join('/users', 'john', 'documents', 'file.txt');
// Windows: \users\john\documents\file.txt
// Linux/Mac: /users/john/documents/file.txt

// 解析为绝对路径
const absolutePath = path.resolve('src', 'index.js');
// 返回: /当前工作目录/src/index.js

// 获取路径各部分
console.log(path.dirname('/users/john/file.txt'));   // /users/john
console.log(path.basename('/users/john/file.txt'));  // file.txt
console.log(path.extname('/users/john/file.txt'));   // .txt

// 解析路径对象
const pathObj = path.parse('/users/john/file.txt');
// { root: '/', dir: '/users/john', base: 'file.txt', ext: '.txt', name: 'file' }

// 格式化路径对象
const formatted = path.format({ dir: '/users/john', base: 'file.txt' });
// /users/john/file.txt

// 规范化路径
console.log(path.normalize('/users//john/../jane/./file.txt'));
// /users/jane/file.txt
```

**⚠️ 常见错误**：
```javascript
// ❌ 错误：手动拼接路径（跨平台问题）
const filePath = __dirname + '/data/' + 'file.txt';

// ✅ 正确：使用 path.join
const filePath = path.join(__dirname, 'data', 'file.txt');

// ❌ 错误：混淆 __dirname 和 process.cwd()
// __dirname: 当前文件所在目录
// process.cwd(): 命令执行时的工作目录
```

### 4.2 url 模块 - URL 处理

```javascript
const { URL, URLSearchParams } = require('url');

// 解析 URL
const myUrl = new URL('https://example.com:8080/path?name=john&age=30#section');

console.log(myUrl.protocol);  // https:
console.log(myUrl.hostname);  // example.com
console.log(myUrl.port);      // 8080
console.log(myUrl.pathname);  // /path
console.log(myUrl.search);    // ?name=john&age=30
console.log(myUrl.hash);      // #section
console.log(myUrl.origin);    // https://example.com:8080

// 操作查询参数
const params = myUrl.searchParams;
console.log(params.get('name'));     // john
console.log(params.has('age'));      // true
params.append('city', 'beijing');
params.set('name', 'jane');
params.delete('age');
console.log(myUrl.href);  // 完整 URL

// 构建 URL
const newUrl = new URL('/api/users', 'https://api.example.com');
newUrl.searchParams.set('page', '1');
console.log(newUrl.href);  // https://api.example.com/api/users?page=1
```

### 4.3 os 模块 - 操作系统信息

```javascript
const os = require('os');

// 系统信息
console.log('操作系统:', os.type());        // Windows_NT / Linux / Darwin
console.log('系统平台:', os.platform());    // win32 / linux / darwin
console.log('CPU 架构:', os.arch());        // x64 / arm64
console.log('主机名:', os.hostname());
console.log('系统版本:', os.release());

// 内存信息
console.log('总内存:', (os.totalmem() / 1024 / 1024 / 1024).toFixed(2) + ' GB');
console.log('可用内存:', (os.freemem() / 1024 / 1024 / 1024).toFixed(2) + ' GB');

// CPU 信息
console.log('CPU 核心数:', os.cpus().length);
console.log('CPU 信息:', os.cpus()[0].model);

// 用户信息
console.log('用户目录:', os.homedir());
console.log('临时目录:', os.tmpdir());
console.log('用户信息:', os.userInfo());

// 系统运行时间
console.log('系统运行时间:', (os.uptime() / 3600).toFixed(2) + ' 小时');

// 网络接口
console.log('网络接口:', os.networkInterfaces());
```

### 4.4 util 模块 - 实用工具

```javascript
const util = require('util');

// promisify：将回调函数转为 Promise
const fs = require('fs');
const readFileAsync = util.promisify(fs.readFile);

async function readFile() {
  const content = await readFileAsync('file.txt', 'utf8');
  console.log(content);
}

// callbackify：将 Promise 函数转为回调风格
const asyncFn = async () => 'Hello';
const callbackFn = util.callbackify(asyncFn);
callbackFn((err, result) => {
  console.log(result);  // Hello
});

// format：格式化字符串
console.log(util.format('%s:%d', 'count', 10));  // count:10
console.log(util.format('%j', { name: 'john' })); // {"name":"john"}

// inspect：对象转字符串（调试用）
const obj = { a: 1, b: { c: 2, d: { e: 3 } } };
console.log(util.inspect(obj, { depth: null, colors: true }));

// types：类型检查
console.log(util.types.isPromise(Promise.resolve()));  // true
console.log(util.types.isDate(new Date()));            // true
console.log(util.types.isRegExp(/abc/));               // true

// deprecate：标记废弃函数
const oldFunction = util.deprecate(() => {
  console.log('旧函数');
}, '此函数已废弃，请使用 newFunction');
```

### 4.5 events 模块 - 事件发射器

事件驱动是 Node.js 的核心特性，EventEmitter 是实现事件机制的基础类。

```javascript
const EventEmitter = require('events');

// 创建事件发射器
const emitter = new EventEmitter();

// 监听事件
emitter.on('message', (data) => {
  console.log('收到消息:', data);
});

// 只监听一次
emitter.once('connect', () => {
  console.log('连接成功（只触发一次）');
});

// 触发事件
emitter.emit('message', 'Hello World');
emitter.emit('message', { text: '你好' });
emitter.emit('connect');
emitter.emit('connect');  // 不会触发

// 移除监听器
const handler = (data) => console.log(data);
emitter.on('data', handler);
emitter.off('data', handler);  // 或 emitter.removeListener('data', handler)

// 移除所有监听器
emitter.removeAllListeners('message');

// 获取监听器信息
console.log(emitter.listenerCount('message'));
console.log(emitter.eventNames());

// 错误处理（必须监听 error 事件，否则会抛出异常）
emitter.on('error', (err) => {
  console.error('发生错误:', err.message);
});
emitter.emit('error', new Error('出错了'));
```

**继承 EventEmitter 创建自定义类**：
```javascript
class MyServer extends EventEmitter {
  constructor() {
    super();
    this.connected = false;
  }

  connect() {
    // 模拟异步连接
    setTimeout(() => {
      this.connected = true;
      this.emit('connected');
    }, 1000);
  }

  send(data) {
    if (!this.connected) {
      this.emit('error', new Error('未连接'));
      return;
    }
    this.emit('data', data);
  }
}

const server = new MyServer();
server.on('connected', () => console.log('已连接'));
server.on('data', (data) => console.log('数据:', data));
server.on('error', (err) => console.error('错误:', err.message));
server.connect();
```

---

## 5. 异步编程

Node.js 的核心优势在于异步非阻塞 I/O，理解异步编程是掌握 Node.js 的关键。

### 5.1 回调函数（Callback）

回调是最原始的异步处理方式，Node.js 遵循"错误优先回调"约定。

```javascript
const fs = require('fs');

// 错误优先回调：第一个参数是错误对象
fs.readFile('file.txt', 'utf8', (err, data) => {
  if (err) {
    console.error('读取失败:', err.message);
    return;
  }
  console.log('文件内容:', data);
});

// 自定义异步函数
function fetchUser(id, callback) {
  setTimeout(() => {
    if (id <= 0) {
      callback(new Error('无效的用户 ID'));
      return;
    }
    callback(null, { id, name: 'John' });
  }, 1000);
}

fetchUser(1, (err, user) => {
  if (err) {
    console.error(err.message);
    return;
  }
  console.log(user);
});
```

**⚠️ 回调地狱（Callback Hell）**：
```javascript
// ❌ 糟糕的代码：嵌套过深，难以维护
fs.readFile('file1.txt', 'utf8', (err, data1) => {
  if (err) return console.error(err);
  fs.readFile('file2.txt', 'utf8', (err, data2) => {
    if (err) return console.error(err);
    fs.readFile('file3.txt', 'utf8', (err, data3) => {
      if (err) return console.error(err);
      console.log(data1, data2, data3);
    });
  });
});
```

### 5.2 Promise

Promise 是解决回调地狱的方案，表示一个异步操作的最终结果。

```javascript
// 创建 Promise
const myPromise = new Promise((resolve, reject) => {
  setTimeout(() => {
    const success = true;
    if (success) {
      resolve('操作成功');
    } else {
      reject(new Error('操作失败'));
    }
  }, 1000);
});

// 使用 Promise
myPromise
  .then(result => console.log(result))
  .catch(err => console.error(err.message))
  .finally(() => console.log('操作完成'));
```

```javascript
// 将回调函数转为 Promise
const fs = require('fs');
const util = require('util');

// 方式一：手动包装
function readFilePromise(path) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, 'utf8', (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

// 方式二：使用 util.promisify
const readFileAsync = util.promisify(fs.readFile);

// 方式三：使用 fs.promises（推荐）
const fsPromises = require('fs').promises;
// 或 const fsPromises = require('fs/promises');

// Promise 链式调用
readFileAsync('file1.txt', 'utf8')
  .then(data1 => {
    console.log(data1);
    return readFileAsync('file2.txt', 'utf8');
  })
  .then(data2 => {
    console.log(data2);
    return readFileAsync('file3.txt', 'utf8');
  })
  .then(data3 => console.log(data3))
  .catch(err => console.error('读取失败:', err.message));

// Promise 静态方法
// Promise.all：所有都成功才成功
const promises = [
  fetch('/api/user'),
  fetch('/api/posts'),
  fetch('/api/comments')
];
Promise.all(promises)
  .then(([user, posts, comments]) => {
    console.log('全部完成');
  })
  .catch(err => console.error('有一个失败了'));

// Promise.allSettled：等待所有完成（不管成功失败）
Promise.allSettled(promises)
  .then(results => {
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        console.log('成功:', result.value);
      } else {
        console.log('失败:', result.reason);
      }
    });
  });

// Promise.race：返回最先完成的
Promise.race(promises).then(first => console.log('最快的:', first));

// Promise.any：返回最先成功的
Promise.any(promises).then(first => console.log('最先成功:', first));
```

### 5.3 async/await

async/await 是 Promise 的语法糖，让异步代码看起来像同步代码。

```javascript
const fs = require('fs').promises;

// async 函数总是返回 Promise
async function readFiles() {
  try {
    // await 等待 Promise 完成
    const data1 = await fs.readFile('file1.txt', 'utf8');
    const data2 = await fs.readFile('file2.txt', 'utf8');
    const data3 = await fs.readFile('file3.txt', 'utf8');
    
    console.log(data1, data2, data3);
    return { data1, data2, data3 };
  } catch (err) {
    console.error('读取失败:', err.message);
    throw err;  // 重新抛出错误
  }
}

// 调用 async 函数
readFiles()
  .then(result => console.log('完成'))
  .catch(err => console.error('出错'));

// 或使用 IIFE
(async () => {
  const result = await readFiles();
})();
```

**并行执行 vs 串行执行**：
```javascript
// ❌ 串行执行（慢）：每个请求等待上一个完成
async function fetchSequential() {
  const user = await fetch('/api/user');      // 1秒
  const posts = await fetch('/api/posts');    // 1秒
  const comments = await fetch('/api/comments'); // 1秒
  // 总共 3 秒
}

// ✅ 并行执行（快）：同时发起所有请求
async function fetchParallel() {
  const [user, posts, comments] = await Promise.all([
    fetch('/api/user'),
    fetch('/api/posts'),
    fetch('/api/comments')
  ]);
  // 总共约 1 秒
}

// 部分并行：有依赖关系时
async function fetchMixed() {
  // 先获取用户
  const user = await fetch('/api/user');
  
  // 然后并行获取用户的帖子和评论
  const [posts, comments] = await Promise.all([
    fetch(`/api/users/${user.id}/posts`),
    fetch(`/api/users/${user.id}/comments`)
  ]);
}
```

**⚠️ 常见错误**：
```javascript
// ❌ 错误：在循环中使用 await（串行执行）
async function processItems(items) {
  for (const item of items) {
    await processItem(item);  // 一个一个处理，很慢
  }
}

// ✅ 正确：并行处理
async function processItems(items) {
  await Promise.all(items.map(item => processItem(item)));
}

// ❌ 错误：忘记 await
async function getData() {
  const data = fetchData();  // 返回 Promise，不是数据！
  console.log(data);  // Promise { <pending> }
}

// ✅ 正确：使用 await
async function getData() {
  const data = await fetchData();
  console.log(data);  // 实际数据
}

// ❌ 错误：在非 async 函数中使用 await
function getData() {
  const data = await fetchData();  // SyntaxError!
}

// ✅ 正确：声明为 async
async function getData() {
  const data = await fetchData();
}
```

### 5.4 顶层 await（ES Modules）

在 ES Modules 中，可以在模块顶层使用 await。

```javascript
// config.mjs
const response = await fetch('https://api.example.com/config');
export const config = await response.json();

// app.mjs
import { config } from './config.mjs';
console.log(config);  // 配置已加载完成
```

---

## 6. 事件循环

理解事件循环是掌握 Node.js 异步机制的关键。

### 6.1 事件循环阶段

```
   ┌───────────────────────────┐
┌─>│           timers          │  执行 setTimeout/setInterval 回调
│  └─────────────┬─────────────┘
│  ┌─────────────┴─────────────┐
│  │     pending callbacks     │  执行系统操作回调（如 TCP 错误）
│  └─────────────┬─────────────┘
│  ┌─────────────┴─────────────┐
│  │       idle, prepare       │  内部使用
│  └─────────────┬─────────────┘
│  ┌─────────────┴─────────────┐
│  │           poll            │  获取新的 I/O 事件，执行 I/O 回调
│  └─────────────┬─────────────┘
│  ┌─────────────┴─────────────┐
│  │           check           │  执行 setImmediate 回调
│  └─────────────┬─────────────┘
│  ┌─────────────┴─────────────┐
└──┤      close callbacks      │  执行 close 事件回调
   └───────────────────────────┘
```

### 6.2 微任务与宏任务

```javascript
// 宏任务（Macro Task）：setTimeout, setInterval, setImmediate, I/O
// 微任务（Micro Task）：Promise.then, process.nextTick, queueMicrotask

console.log('1. 同步代码');

setTimeout(() => console.log('2. setTimeout'), 0);

setImmediate(() => console.log('3. setImmediate'));

Promise.resolve().then(() => console.log('4. Promise.then'));

process.nextTick(() => console.log('5. process.nextTick'));

queueMicrotask(() => console.log('6. queueMicrotask'));

console.log('7. 同步代码结束');

// 输出顺序：
// 1. 同步代码
// 7. 同步代码结束
// 5. process.nextTick（最高优先级微任务）
// 4. Promise.then
// 6. queueMicrotask
// 2. setTimeout（取决于系统，可能在 setImmediate 前后）
// 3. setImmediate
```

### 6.3 process.nextTick vs setImmediate

```javascript
// process.nextTick：在当前操作完成后立即执行（微任务）
// setImmediate：在当前事件循环结束后执行（宏任务）

// 在主模块中，顺序不确定
setTimeout(() => console.log('setTimeout'), 0);
setImmediate(() => console.log('setImmediate'));

// 在 I/O 回调中，setImmediate 总是先执行
const fs = require('fs');
fs.readFile('file.txt', () => {
  setTimeout(() => console.log('setTimeout'), 0);
  setImmediate(() => console.log('setImmediate'));
  // 输出：setImmediate, setTimeout
});

// process.nextTick 的递归可能阻塞事件循环
// ❌ 危险：可能导致 I/O 饥饿
function recursiveNextTick() {
  process.nextTick(recursiveNextTick);
}

// ✅ 安全：使用 setImmediate 允许 I/O 执行
function recursiveImmediate() {
  setImmediate(recursiveImmediate);
}
```

### 6.4 实际应用示例

```javascript
// 延迟执行，确保同步代码先完成
class Database {
  constructor() {
    this.connected = false;
    // 使用 nextTick 确保事件监听器已注册
    process.nextTick(() => {
      this.emit('ready');
    });
  }
}

const db = new Database();
db.on('ready', () => console.log('数据库就绪'));  // 能正常触发

// 分批处理大量数据，避免阻塞事件循环
async function processLargeArray(items) {
  const batchSize = 100;
  
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    
    // 处理当前批次
    for (const item of batch) {
      processItem(item);
    }
    
    // 让出事件循环，允许其他任务执行
    await new Promise(resolve => setImmediate(resolve));
  }
}
```

---

## 7. 文件系统

fs 模块提供了文件系统操作的完整 API。

### 7.1 同步 vs 异步 API

```javascript
const fs = require('fs');
const fsPromises = require('fs').promises;

// ❌ 同步 API（阻塞主线程，仅用于启动时）
try {
  const data = fs.readFileSync('file.txt', 'utf8');
  console.log(data);
} catch (err) {
  console.error(err);
}

// ✅ 回调 API
fs.readFile('file.txt', 'utf8', (err, data) => {
  if (err) {
    console.error(err);
    return;
  }
  console.log(data);
});

// ✅ Promise API（推荐）
async function readFile() {
  try {
    const data = await fsPromises.readFile('file.txt', 'utf8');
    console.log(data);
  } catch (err) {
    console.error(err);
  }
}
```

### 7.2 文件读写

```javascript
const fs = require('fs').promises;
const path = require('path');

// 读取文件
async function readFile() {
  // 读取文本文件
  const text = await fs.readFile('file.txt', 'utf8');
  
  // 读取二进制文件
  const buffer = await fs.readFile('image.png');
  
  // 读取 JSON 文件
  const json = JSON.parse(await fs.readFile('config.json', 'utf8'));
}

// 写入文件
async function writeFile() {
  // 写入文本（覆盖）
  await fs.writeFile('output.txt', 'Hello World', 'utf8');
  
  // 写入 JSON
  const data = { name: 'John', age: 30 };
  await fs.writeFile('data.json', JSON.stringify(data, null, 2));
  
  // 追加内容
  await fs.appendFile('log.txt', '新的日志行\n');
  
  // 写入选项
  await fs.writeFile('file.txt', 'content', {
    encoding: 'utf8',
    mode: 0o644,  // 文件权限
    flag: 'w'     // w=覆盖, a=追加, wx=不存在才创建
  });
}

// 复制文件
await fs.copyFile('source.txt', 'dest.txt');

// 重命名/移动文件
await fs.rename('old.txt', 'new.txt');
await fs.rename('file.txt', 'subdir/file.txt');  // 移动

// 删除文件
await fs.unlink('file.txt');

// 截断文件
await fs.truncate('file.txt', 100);  // 保留前 100 字节
```

### 7.3 目录操作

```javascript
const fs = require('fs').promises;

// 创建目录
await fs.mkdir('newdir');
await fs.mkdir('path/to/deep/dir', { recursive: true });  // 递归创建

// 读取目录
const files = await fs.readdir('.');
console.log(files);  // ['file1.txt', 'file2.txt', 'subdir']

// 读取目录（包含文件类型）
const entries = await fs.readdir('.', { withFileTypes: true });
for (const entry of entries) {
  if (entry.isFile()) {
    console.log('文件:', entry.name);
  } else if (entry.isDirectory()) {
    console.log('目录:', entry.name);
  }
}

// 删除目录
await fs.rmdir('emptydir');
await fs.rm('dir', { recursive: true, force: true });  // 递归删除

// 递归遍历目录
async function walkDir(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      await walkDir(fullPath);  // 递归
    } else {
      console.log(fullPath);
    }
  }
}
```

### 7.4 文件信息与权限

```javascript
const fs = require('fs').promises;

// 获取文件信息
const stats = await fs.stat('file.txt');
console.log('大小:', stats.size, '字节');
console.log('创建时间:', stats.birthtime);
console.log('修改时间:', stats.mtime);
console.log('是否文件:', stats.isFile());
console.log('是否目录:', stats.isDirectory());
console.log('是否符号链接:', stats.isSymbolicLink());

// 检查文件是否存在
async function fileExists(path) {
  try {
    await fs.access(path);
    return true;
  } catch {
    return false;
  }
}

// 检查权限
await fs.access('file.txt', fs.constants.R_OK);  // 可读
await fs.access('file.txt', fs.constants.W_OK);  // 可写
await fs.access('file.txt', fs.constants.X_OK);  // 可执行

// 修改权限
await fs.chmod('script.sh', 0o755);

// 修改所有者（需要权限）
await fs.chown('file.txt', uid, gid);
```

### 7.5 文件监听

```javascript
const fs = require('fs');

// 监听文件变化
const watcher = fs.watch('file.txt', (eventType, filename) => {
  console.log(`事件: ${eventType}, 文件: ${filename}`);
});

// 监听目录
fs.watch('.', { recursive: true }, (eventType, filename) => {
  console.log(`${filename} 发生了 ${eventType}`);
});

// 停止监听
watcher.close();

// 更精确的监听（轮询方式，性能较低）
fs.watchFile('file.txt', { interval: 1000 }, (curr, prev) => {
  if (curr.mtime !== prev.mtime) {
    console.log('文件被修改');
  }
});

// 停止轮询监听
fs.unwatchFile('file.txt');
```

**⚠️ 常见错误**：
```javascript
// ❌ 错误：检查存在后再操作（竞态条件）
if (fs.existsSync('file.txt')) {
  fs.readFileSync('file.txt');  // 文件可能已被删除！
}

// ✅ 正确：直接操作，捕获错误
try {
  const data = await fs.readFile('file.txt', 'utf8');
} catch (err) {
  if (err.code === 'ENOENT') {
    console.log('文件不存在');
  }
}

// ❌ 错误：忘记处理编码
const data = await fs.readFile('file.txt');  // 返回 Buffer
console.log(data);  // <Buffer 48 65 6c 6c 6f>

// ✅ 正确：指定编码
const data = await fs.readFile('file.txt', 'utf8');  // 返回字符串
```

---

## 8. HTTP 服务

### 8.1 创建 HTTP 服务器

```javascript
const http = require('http');

// 创建服务器
const server = http.createServer((req, res) => {
  // req: 请求对象（可读流）
  // res: 响应对象（可写流）
  
  console.log(`${req.method} ${req.url}`);
  console.log('Headers:', req.headers);
  
  // 设置响应头
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.statusCode = 200;
  
  // 发送响应
  res.end('Hello World');
});

// 启动服务器
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});

// 错误处理
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`端口 ${PORT} 已被占用`);
  }
});
```

### 8.2 处理不同请求

```javascript
const http = require('http');
const url = require('url');

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;
  const method = req.method;
  
  // 设置 CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  // 处理预检请求
  if (method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }
  
  // 路由处理
  if (pathname === '/' && method === 'GET') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<h1>首页</h1>');
  }
  else if (pathname === '/api/users' && method === 'GET') {
    const users = [{ id: 1, name: 'John' }];
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(users));
  }
  else if (pathname === '/api/users' && method === 'POST') {
    // 读取请求体
    const body = await getRequestBody(req);
    const user = JSON.parse(body);
    
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 201;
    res.end(JSON.stringify({ id: 2, ...user }));
  }
  else {
    res.statusCode = 404;
    res.end('Not Found');
  }
});

// 读取请求体
function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

server.listen(3000);
```

### 8.3 HTTP 客户端请求

```javascript
const http = require('http');
const https = require('https');

// 使用 http/https 模块发送请求
function httpGet(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    
    client.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(JSON.parse(data));
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    }).on('error', reject);
  });
}

// POST 请求
function httpPost(url, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === 'https:' ? https : http;
    const data = JSON.stringify(body);
    
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };
    
    const req = client.request(options, (res) => {
      let responseData = '';
      res.on('data', chunk => responseData += chunk);
      res.on('end', () => resolve(JSON.parse(responseData)));
    });
    
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// 使用 fetch（Node.js 18+）
async function fetchExample() {
  // GET 请求
  const response = await fetch('https://api.example.com/users');
  const users = await response.json();
  
  // POST 请求
  const newUser = await fetch('https://api.example.com/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'John' })
  }).then(res => res.json());
}
```

---

## 9. Express 框架

Express 是最流行的 Node.js Web 框架，简化了 HTTP 服务开发。

### 9.1 基础使用

```bash
# 安装
npm install express
```

```javascript
const express = require('express');
const app = express();

// 中间件：解析 JSON 请求体
app.use(express.json());

// 中间件：解析 URL 编码的请求体
app.use(express.urlencoded({ extended: true }));

// 静态文件服务
app.use(express.static('public'));

// 路由
app.get('/', (req, res) => {
  res.send('Hello World');
});

app.get('/api/users', (req, res) => {
  res.json([{ id: 1, name: 'John' }]);
});

app.post('/api/users', (req, res) => {
  const user = req.body;
  res.status(201).json({ id: 2, ...user });
});

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
```

### 9.2 路由详解

```javascript
const express = require('express');
const app = express();

// 路由参数
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  res.json({ id: userId });
});

// 多个参数
app.get('/users/:userId/posts/:postId', (req, res) => {
  const { userId, postId } = req.params;
  res.json({ userId, postId });
});

// 查询参数
app.get('/search', (req, res) => {
  // GET /search?q=node&page=1
  const { q, page = 1 } = req.query;
  res.json({ query: q, page });
});

// 路由分组
const router = express.Router();

router.get('/', (req, res) => res.json([]));
router.get('/:id', (req, res) => res.json({ id: req.params.id }));
router.post('/', (req, res) => res.status(201).json(req.body));
router.put('/:id', (req, res) => res.json({ id: req.params.id, ...req.body }));
router.delete('/:id', (req, res) => res.status(204).send());

app.use('/api/users', router);

// 链式路由
app.route('/api/posts')
  .get((req, res) => res.json([]))
  .post((req, res) => res.status(201).json(req.body));
```

### 9.3 中间件

中间件是 Express 的核心概念，用于处理请求-响应周期中的各个阶段。

```javascript
const express = require('express');
const app = express();

// 应用级中间件
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();  // 调用下一个中间件
});

// 带路径的中间件
app.use('/api', (req, res, next) => {
  console.log('API 请求');
  next();
});

// 多个中间件函数
app.use('/admin', 
  (req, res, next) => {
    // 验证身份
    if (!req.headers.authorization) {
      return res.status(401).json({ error: '未授权' });
    }
    next();
  },
  (req, res, next) => {
    // 验证权限
    next();
  }
);

// 错误处理中间件（4个参数）
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: '服务器内部错误' });
});

// 自定义中间件
function requestLogger(options = {}) {
  return (req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`${req.method} ${req.url} ${res.statusCode} ${duration}ms`);
    });
    
    next();
  };
}

app.use(requestLogger());

// 异步中间件
app.use(async (req, res, next) => {
  try {
    const user = await getUserFromToken(req.headers.authorization);
    req.user = user;
    next();
  } catch (err) {
    next(err);  // 传递错误到错误处理中间件
  }
});
```

### 9.4 常用中间件

```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const app = express();

// CORS 跨域
app.use(cors({
  origin: ['http://localhost:3000', 'https://example.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// 安全头
app.use(helmet());

// 日志
app.use(morgan('combined'));  // 或 'dev', 'tiny'

// 压缩响应
app.use(compression());

// 限流
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 分钟
  max: 100,  // 最多 100 次请求
  message: '请求过于频繁，请稍后再试'
});
app.use('/api', limiter);

// 请求体大小限制
app.use(express.json({ limit: '10mb' }));
```

### 9.5 错误处理

```javascript
const express = require('express');
const app = express();

// 自定义错误类
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
  }
}

// 异步路由包装器
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// 使用包装器
app.get('/users/:id', asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    throw new AppError('用户不存在', 404);
  }
  res.json(user);
}));

// 404 处理
app.use((req, res, next) => {
  next(new AppError('资源不存在', 404));
});

// 全局错误处理
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.isOperational ? err.message : '服务器内部错误';
  
  // 开发环境返回详细错误
  if (process.env.NODE_ENV === 'development') {
    res.status(statusCode).json({
      error: message,
      stack: err.stack
    });
  } else {
    res.status(statusCode).json({ error: message });
  }
});
```

---

## 10. 数据库操作

### 10.1 MySQL

```bash
npm install mysql2
```

```javascript
const mysql = require('mysql2/promise');

// 创建连接池
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'mydb',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 查询
async function getUsers() {
  const [rows] = await pool.query('SELECT * FROM users');
  return rows;
}

// 参数化查询（防止 SQL 注入）
async function getUserById(id) {
  const [rows] = await pool.query(
    'SELECT * FROM users WHERE id = ?',
    [id]
  );
  return rows[0];
}

// 插入
async function createUser(name, email) {
  const [result] = await pool.query(
    'INSERT INTO users (name, email) VALUES (?, ?)',
    [name, email]
  );
  return result.insertId;
}

// 事务
async function transferMoney(fromId, toId, amount) {
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    await connection.query(
      'UPDATE accounts SET balance = balance - ? WHERE id = ?',
      [amount, fromId]
    );
    
    await connection.query(
      'UPDATE accounts SET balance = balance + ? WHERE id = ?',
      [amount, toId]
    );
    
    await connection.commit();
  } catch (err) {
    await connection.rollback();
    throw err;
  } finally {
    connection.release();
  }
}
```

### 10.2 MongoDB

```bash
npm install mongodb
# 或使用 Mongoose ODM
npm install mongoose
```

```javascript
// 原生 MongoDB 驱动
const { MongoClient, ObjectId } = require('mongodb');

const uri = 'mongodb://localhost:27017';
const client = new MongoClient(uri);

async function main() {
  await client.connect();
  const db = client.db('mydb');
  const users = db.collection('users');
  
  // 插入
  const result = await users.insertOne({ name: 'John', age: 30 });
  console.log('插入 ID:', result.insertedId);
  
  // 查询
  const user = await users.findOne({ _id: new ObjectId('...') });
  const allUsers = await users.find({ age: { $gte: 18 } }).toArray();
  
  // 更新
  await users.updateOne(
    { _id: new ObjectId('...') },
    { $set: { name: 'Jane' } }
  );
  
  // 删除
  await users.deleteOne({ _id: new ObjectId('...') });
}

// 使用 Mongoose
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/mydb');

// 定义 Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  age: { type: Number, min: 0 },
  createdAt: { type: Date, default: Date.now }
});

// 创建 Model
const User = mongoose.model('User', userSchema);

// CRUD 操作
async function mongooseExample() {
  // 创建
  const user = new User({ name: 'John', email: 'john@example.com' });
  await user.save();
  
  // 或
  const user2 = await User.create({ name: 'Jane', email: 'jane@example.com' });
  
  // 查询
  const users = await User.find({ age: { $gte: 18 } });
  const oneUser = await User.findById('...');
  const byEmail = await User.findOne({ email: 'john@example.com' });
  
  // 更新
  await User.findByIdAndUpdate('...', { name: 'New Name' });
  
  // 删除
  await User.findByIdAndDelete('...');
}
```

### 10.3 Redis

```bash
npm install redis
```

```javascript
const redis = require('redis');

const client = redis.createClient({
  url: 'redis://localhost:6379'
});

client.on('error', err => console.error('Redis 错误:', err));

async function redisExample() {
  await client.connect();
  
  // 字符串
  await client.set('name', 'John');
  await client.set('token', 'abc123', { EX: 3600 });  // 1小时过期
  const name = await client.get('name');
  
  // 哈希
  await client.hSet('user:1', { name: 'John', age: '30' });
  const user = await client.hGetAll('user:1');
  
  // 列表
  await client.lPush('queue', 'task1');
  await client.rPush('queue', 'task2');
  const task = await client.lPop('queue');
  
  // 集合
  await client.sAdd('tags', ['node', 'javascript', 'backend']);
  const tags = await client.sMembers('tags');
  
  // 有序集合
  await client.zAdd('leaderboard', [
    { score: 100, value: 'player1' },
    { score: 200, value: 'player2' }
  ]);
  const top = await client.zRange('leaderboard', 0, 9, { REV: true });
  
  // 发布订阅
  const subscriber = client.duplicate();
  await subscriber.connect();
  
  await subscriber.subscribe('channel', (message) => {
    console.log('收到消息:', message);
  });
  
  await client.publish('channel', 'Hello');
  
  await client.quit();
}
```

---

## 11. 错误处理

### 11.1 错误类型

```javascript
// 1. 同步错误
try {
  JSON.parse('invalid json');
} catch (err) {
  console.error('解析错误:', err.message);
}

// 2. 异步错误（回调）
fs.readFile('nonexistent.txt', (err, data) => {
  if (err) {
    console.error('读取错误:', err.message);
    return;
  }
});

// 3. Promise 错误
fetchData()
  .then(data => console.log(data))
  .catch(err => console.error('请求错误:', err.message));

// 4. async/await 错误
async function getData() {
  try {
    const data = await fetchData();
    return data;
  } catch (err) {
    console.error('获取数据错误:', err.message);
    throw err;  // 重新抛出或返回默认值
  }
}
```

### 11.2 自定义错误类

```javascript
// 基础错误类
class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.isOperational = true;  // 可预期的操作错误
    Error.captureStackTrace(this, this.constructor);
  }
}

// 具体错误类型
class ValidationError extends AppError {
  constructor(message, field) {
    super(message, 400);
    this.field = field;
  }
}

class NotFoundError extends AppError {
  constructor(resource = '资源') {
    super(`${resource}不存在`, 404);
  }
}

class UnauthorizedError extends AppError {
  constructor(message = '未授权') {
    super(message, 401);
  }
}

class ForbiddenError extends AppError {
  constructor(message = '禁止访问') {
    super(message, 403);
  }
}

// 使用
function getUser(id) {
  const user = users.find(u => u.id === id);
  if (!user) {
    throw new NotFoundError('用户');
  }
  return user;
}
```

### 11.3 全局错误处理

```javascript
// 未捕获的异常
process.on('uncaughtException', (err) => {
  console.error('未捕获的异常:', err);
  // 记录日志
  // 优雅关闭服务器
  process.exit(1);  // 必须退出，状态可能不一致
});

// 未处理的 Promise 拒绝
process.on('unhandledRejection', (reason, promise) => {
  console.error('未处理的 Promise 拒绝:', reason);
  // 可以选择退出或继续运行
});

// 优雅关闭
process.on('SIGTERM', () => {
  console.log('收到 SIGTERM 信号');
  server.close(() => {
    console.log('服务器已关闭');
    // 关闭数据库连接等
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('收到 SIGINT 信号（Ctrl+C）');
  process.exit(0);
});
```

### 11.4 错误处理最佳实践

```javascript
// 1. 使用 async/await + try/catch
async function processOrder(orderId) {
  try {
    const order = await Order.findById(orderId);
    if (!order) throw new NotFoundError('订单');
    
    await validateOrder(order);
    await processPayment(order);
    await sendConfirmation(order);
    
    return { success: true };
  } catch (err) {
    // 根据错误类型处理
    if (err instanceof ValidationError) {
      return { success: false, error: err.message };
    }
    // 重新抛出未知错误
    throw err;
  }
}

// 2. 错误包装
async function fetchUserData(userId) {
  try {
    const response = await fetch(`/api/users/${userId}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } catch (err) {
    // 包装原始错误，添加上下文
    throw new AppError(`获取用户 ${userId} 数据失败: ${err.message}`, 500);
  }
}

// 3. 重试机制
async function fetchWithRetry(url, options = {}, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fetch(url, options);
    } catch (err) {
      if (i === retries - 1) throw err;
      
      const delay = Math.pow(2, i) * 1000;  // 指数退避
      console.log(`重试 ${i + 1}/${retries}，等待 ${delay}ms`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// 4. 断路器模式
class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 30000;
    this.failures = 0;
    this.state = 'CLOSED';
    this.nextAttempt = Date.now();
  }

  async call(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        throw new Error('断路器打开，服务暂时不可用');
      }
      this.state = 'HALF_OPEN';
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  onFailure() {
    this.failures++;
    if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.resetTimeout;
    }
  }
}
```

---

## 12. 流与缓冲区

### 12.1 Buffer（缓冲区）

Buffer 用于处理二进制数据，在文件操作、网络通信中广泛使用。

```javascript
// 创建 Buffer
const buf1 = Buffer.alloc(10);           // 10 字节，初始化为 0
const buf2 = Buffer.allocUnsafe(10);     // 10 字节，未初始化（更快但不安全）
const buf3 = Buffer.from('Hello');       // 从字符串创建
const buf4 = Buffer.from([1, 2, 3, 4]);  // 从数组创建
const buf5 = Buffer.from('48656c6c6f', 'hex');  // 从十六进制

// 读写操作
const buf = Buffer.alloc(10);
buf.write('Hello');
console.log(buf.toString());  // Hello

// 读取特定位置
buf[0] = 72;  // 'H' 的 ASCII 码
console.log(buf[0]);  // 72

// 转换
console.log(buf.toString('utf8'));
console.log(buf.toString('hex'));
console.log(buf.toString('base64'));
console.log([...buf]);  // 转为数组

// 比较
const a = Buffer.from('ABC');
const b = Buffer.from('ABD');
console.log(a.compare(b));  // -1 (a < b)
console.log(a.equals(Buffer.from('ABC')));  // true

// 拼接
const combined = Buffer.concat([buf1, buf2, buf3]);

// 切片（共享内存）
const slice = buf.slice(0, 5);

// 复制（独立内存）
const copy = Buffer.alloc(5);
buf.copy(copy, 0, 0, 5);
```

### 12.2 Stream（流）

流是处理大量数据的高效方式，避免一次性加载全部数据到内存。

```javascript
const fs = require('fs');
const { pipeline } = require('stream/promises');

// 四种流类型：
// Readable - 可读流（数据源）
// Writable - 可写流（数据目标）
// Duplex - 双工流（可读可写）
// Transform - 转换流（处理数据）

// 可读流
const readable = fs.createReadStream('large-file.txt', {
  encoding: 'utf8',
  highWaterMark: 64 * 1024  // 64KB 缓冲区
});

readable.on('data', (chunk) => {
  console.log('收到数据块:', chunk.length);
});

readable.on('end', () => {
  console.log('读取完成');
});

readable.on('error', (err) => {
  console.error('读取错误:', err);
});

// 可写流
const writable = fs.createWriteStream('output.txt');

writable.write('Hello ');
writable.write('World');
writable.end('!');  // 结束写入

writable.on('finish', () => {
  console.log('写入完成');
});

// 管道（pipe）- 连接流
const readStream = fs.createReadStream('input.txt');
const writeStream = fs.createWriteStream('output.txt');

readStream.pipe(writeStream);

// 使用 pipeline（推荐，自动处理错误和清理）
async function copyFile() {
  await pipeline(
    fs.createReadStream('input.txt'),
    fs.createWriteStream('output.txt')
  );
  console.log('复制完成');
}
```

### 12.3 转换流

```javascript
const { Transform } = require('stream');
const zlib = require('zlib');
const crypto = require('crypto');

// 自定义转换流
class UpperCaseTransform extends Transform {
  _transform(chunk, encoding, callback) {
    const upperCased = chunk.toString().toUpperCase();
    this.push(upperCased);
    callback();
  }
}

// 使用转换流
const upperCase = new UpperCaseTransform();
process.stdin.pipe(upperCase).pipe(process.stdout);

// 压缩文件
async function compressFile(input, output) {
  await pipeline(
    fs.createReadStream(input),
    zlib.createGzip(),
    fs.createWriteStream(output)
  );
}

// 解压文件
async function decompressFile(input, output) {
  await pipeline(
    fs.createReadStream(input),
    zlib.createGunzip(),
    fs.createWriteStream(output)
  );
}

// 加密文件
async function encryptFile(input, output, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  const writeStream = fs.createWriteStream(output);
  writeStream.write(iv);  // 先写入 IV
  
  await pipeline(
    fs.createReadStream(input),
    cipher,
    writeStream
  );
}

// 链式处理
async function processFile() {
  await pipeline(
    fs.createReadStream('input.txt'),
    new UpperCaseTransform(),
    zlib.createGzip(),
    fs.createWriteStream('output.txt.gz')
  );
}
```

### 12.4 实际应用：大文件处理

```javascript
const fs = require('fs');
const readline = require('readline');

// 逐行读取大文件
async function processLargeFile(filePath) {
  const fileStream = fs.createReadStream(filePath);
  
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });
  
  let lineCount = 0;
  
  for await (const line of rl) {
    lineCount++;
    // 处理每一行
    if (line.includes('ERROR')) {
      console.log(`第 ${lineCount} 行: ${line}`);
    }
  }
  
  console.log(`总行数: ${lineCount}`);
}

// HTTP 流式响应
const http = require('http');

http.createServer((req, res) => {
  if (req.url === '/download') {
    const filePath = 'large-file.zip';
    const stat = fs.statSync(filePath);
    
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', stat.size);
    res.setHeader('Content-Disposition', 'attachment; filename=file.zip');
    
    fs.createReadStream(filePath).pipe(res);
  }
}).listen(3000);

// 流式上传处理
const express = require('express');
const app = express();

app.post('/upload', (req, res) => {
  const writeStream = fs.createWriteStream('uploaded-file');
  
  req.pipe(writeStream);
  
  req.on('end', () => {
    res.json({ message: '上传成功' });
  });
  
  req.on('error', (err) => {
    res.status(500).json({ error: '上传失败' });
  });
});
```

---

## 13. 进程与集群

### 13.1 process 对象

```javascript
// 环境变量
console.log(process.env.NODE_ENV);
console.log(process.env.PORT);

// 命令行参数
// node app.js arg1 arg2
console.log(process.argv);
// ['node路径', '脚本路径', 'arg1', 'arg2']

// 进程信息
console.log('进程 ID:', process.pid);
console.log('父进程 ID:', process.ppid);
console.log('Node 版本:', process.version);
console.log('工作目录:', process.cwd());
console.log('内存使用:', process.memoryUsage());
console.log('CPU 使用:', process.cpuUsage());
console.log('运行时间:', process.uptime(), '秒');

// 标准输入输出
process.stdout.write('输出到控制台\n');
process.stderr.write('错误输出\n');

process.stdin.on('data', (data) => {
  console.log('输入:', data.toString());
});

// 退出进程
process.exit(0);  // 正常退出
process.exit(1);  // 异常退出

// 退出事件
process.on('exit', (code) => {
  console.log('进程退出，代码:', code);
});

// 下一个事件循环
process.nextTick(() => {
  console.log('nextTick 回调');
});
```

### 13.2 child_process（子进程）

```javascript
const { exec, execFile, spawn, fork } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// exec：执行 shell 命令（有缓冲区限制）
exec('ls -la', (err, stdout, stderr) => {
  if (err) {
    console.error('错误:', err);
    return;
  }
  console.log('输出:', stdout);
});

// Promise 版本
async function runCommand() {
  const { stdout } = await execAsync('node --version');
  console.log('Node 版本:', stdout.trim());
}

// execFile：执行可执行文件（更安全，不经过 shell）
execFile('node', ['--version'], (err, stdout) => {
  console.log(stdout);
});

// spawn：流式处理（适合大量输出）
const ls = spawn('ls', ['-la']);

ls.stdout.on('data', (data) => {
  console.log('stdout:', data.toString());
});

ls.stderr.on('data', (data) => {
  console.error('stderr:', data.toString());
});

ls.on('close', (code) => {
  console.log('子进程退出，代码:', code);
});

// fork：创建 Node.js 子进程（支持 IPC 通信）
// parent.js
const child = fork('child.js');

child.send({ type: 'task', data: [1, 2, 3, 4, 5] });

child.on('message', (msg) => {
  console.log('收到子进程消息:', msg);
});

// child.js
process.on('message', (msg) => {
  if (msg.type === 'task') {
    const result = msg.data.reduce((a, b) => a + b, 0);
    process.send({ type: 'result', data: result });
  }
});
```

### 13.3 cluster（集群）

cluster 模块允许创建多个工作进程，充分利用多核 CPU。

```javascript
const cluster = require('cluster');
const http = require('http');
const os = require('os');

const numCPUs = os.cpus().length;

if (cluster.isPrimary) {
  console.log(`主进程 ${process.pid} 正在运行`);
  
  // 创建工作进程
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  // 监听工作进程退出
  cluster.on('exit', (worker, code, signal) => {
    console.log(`工作进程 ${worker.process.pid} 退出`);
    // 重新创建工作进程
    cluster.fork();
  });
  
  // 监听工作进程消息
  for (const id in cluster.workers) {
    cluster.workers[id].on('message', (msg) => {
      console.log('收到工作进程消息:', msg);
    });
  }
} else {
  // 工作进程创建 HTTP 服务器
  http.createServer((req, res) => {
    res.writeHead(200);
    res.end(`工作进程 ${process.pid} 处理请求\n`);
    
    // 发送消息给主进程
    process.send({ type: 'request', pid: process.pid });
  }).listen(8000);
  
  console.log(`工作进程 ${process.pid} 已启动`);
}
```

### 13.4 Worker Threads（工作线程）

Worker Threads 用于 CPU 密集型任务，避免阻塞主线程。

```javascript
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

if (isMainThread) {
  // 主线程
  console.log('主线程');
  
  // 创建工作线程
  const worker = new Worker(__filename, {
    workerData: { numbers: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] }
  });
  
  worker.on('message', (result) => {
    console.log('计算结果:', result);
  });
  
  worker.on('error', (err) => {
    console.error('工作线程错误:', err);
  });
  
  worker.on('exit', (code) => {
    console.log('工作线程退出，代码:', code);
  });
} else {
  // 工作线程
  const { numbers } = workerData;
  
  // CPU 密集型计算
  const sum = numbers.reduce((a, b) => a + b, 0);
  
  // 发送结果给主线程
  parentPort.postMessage(sum);
}

// 使用单独的工作线程文件
// main.js
const { Worker } = require('worker_threads');

function runWorker(data) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('./worker.js', { workerData: data });
    worker.on('message', resolve);
    worker.on('error', reject);
  });
}

async function main() {
  const result = await runWorker({ task: 'compute', value: 1000000 });
  console.log(result);
}

// worker.js
const { parentPort, workerData } = require('worker_threads');

function heavyComputation(n) {
  let result = 0;
  for (let i = 0; i < n; i++) {
    result += Math.sqrt(i);
  }
  return result;
}

const result = heavyComputation(workerData.value);
parentPort.postMessage(result);
```

---

## 14. 安全最佳实践

### 14.1 输入验证

```javascript
const Joi = require('joi');

// 使用 Joi 进行输入验证
const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).required(),
  age: Joi.number().integer().min(0).max(150)
});

async function validateUser(data) {
  try {
    const value = await userSchema.validateAsync(data);
    return { valid: true, data: value };
  } catch (err) {
    return { valid: false, error: err.details[0].message };
  }
}

// Express 中间件
function validate(schema) {
  return async (req, res, next) => {
    try {
      req.body = await schema.validateAsync(req.body);
      next();
    } catch (err) {
      res.status(400).json({ error: err.details[0].message });
    }
  };
}

app.post('/users', validate(userSchema), (req, res) => {
  // req.body 已验证
});
```

### 14.2 防止注入攻击

```javascript
// SQL 注入防护
// ❌ 危险：字符串拼接
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ✅ 安全：参数化查询
const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);

// NoSQL 注入防护
// ❌ 危险：直接使用用户输入
const user = await User.findOne({ username: req.body.username });

// ✅ 安全：类型检查
const username = String(req.body.username);
const user = await User.findOne({ username });

// 命令注入防护
// ❌ 危险：使用 exec
exec(`ls ${userInput}`, callback);  // 用户可输入 "; rm -rf /"

// ✅ 安全：使用 execFile 或 spawn
execFile('ls', [userInput], callback);

// XSS 防护
const escapeHtml = (str) => {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
};

// 或使用库
const xss = require('xss');
const safeHtml = xss(userInput);
```

### 14.3 身份认证与授权

```javascript
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 密码哈希
async function hashPassword(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// JWT 认证
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '7d';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// 认证中间件
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }
  
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({ error: '无效的认证令牌' });
  }
  
  req.user = decoded;
  next();
}

// 授权中间件
function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: '权限不足' });
    }
    next();
  };
}

// 使用
app.get('/admin', authenticate, authorize('admin'), (req, res) => {
  res.json({ message: '管理员页面' });
});
```

### 14.4 安全配置

```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');

const app = express();

// 安全 HTTP 头
app.use(helmet());

// 限流
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: '请求过于频繁'
}));

// 防止 HTTP 参数污染
app.use(hpp());

// 防止 NoSQL 注入
app.use(mongoSanitize());

// 请求体大小限制
app.use(express.json({ limit: '10kb' }));

// HTTPS 重定向（生产环境）
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(`https://${req.hostname}${req.url}`);
    }
    next();
  });
}

// 敏感信息不要硬编码
// ❌ 错误
const secret = 'my-secret-key';

// ✅ 正确：使用环境变量
const secret = process.env.JWT_SECRET;

// 使用 .env 文件（开发环境）
require('dotenv').config();
```

---

## 15. 性能优化

### 15.1 代码层面优化

```javascript
// 1. 避免同步操作
// ❌ 阻塞事件循环
const data = fs.readFileSync('file.txt');

// ✅ 异步操作
const data = await fs.promises.readFile('file.txt');

// 2. 使用流处理大文件
// ❌ 一次性加载
const content = await fs.promises.readFile('large-file.txt');

// ✅ 流式处理
const stream = fs.createReadStream('large-file.txt');

// 3. 缓存计算结果
const cache = new Map();

function expensiveOperation(key) {
  if (cache.has(key)) {
    return cache.get(key);
  }
  
  const result = /* 耗时计算 */;
  cache.set(key, result);
  return result;
}

// 4. 使用对象池
class ObjectPool {
  constructor(createFn, size = 10) {
    this.createFn = createFn;
    this.pool = Array.from({ length: size }, createFn);
  }
  
  acquire() {
    return this.pool.pop() || this.createFn();
  }
  
  release(obj) {
    this.pool.push(obj);
  }
}

// 5. 避免内存泄漏
// ❌ 闭包持有大对象引用
function createHandler() {
  const largeData = loadLargeData();
  return () => {
    // largeData 永远不会被回收
  };
}

// ✅ 只保留需要的数据
function createHandler() {
  const largeData = loadLargeData();
  const neededValue = largeData.value;
  return () => {
    console.log(neededValue);
  };
}

// 6. 使用 WeakMap/WeakSet 避免内存泄漏
const cache = new WeakMap();

function getMetadata(obj) {
  if (!cache.has(obj)) {
    cache.set(obj, computeMetadata(obj));
  }
  return cache.get(obj);
}
```

### 15.2 数据库优化

```javascript
// 1. 使用连接池
const pool = mysql.createPool({
  connectionLimit: 10,
  // ...
});

// 2. 添加索引
// CREATE INDEX idx_email ON users(email);

// 3. 只查询需要的字段
// ❌ 查询所有字段
const users = await User.find({});

// ✅ 只查询需要的字段
const users = await User.find({}).select('name email');

// 4. 分页查询
const page = 1;
const limit = 20;
const users = await User.find({})
  .skip((page - 1) * limit)
  .limit(limit);

// 5. 批量操作
// ❌ 逐条插入
for (const user of users) {
  await User.create(user);
}

// ✅ 批量插入
await User.insertMany(users);

// 6. 使用 Redis 缓存
async function getUser(id) {
  // 先查缓存
  const cached = await redis.get(`user:${id}`);
  if (cached) {
    return JSON.parse(cached);
  }
  
  // 查数据库
  const user = await User.findById(id);
  
  // 写入缓存
  await redis.set(`user:${id}`, JSON.stringify(user), 'EX', 3600);
  
  return user;
}
```

### 15.3 HTTP 优化

```javascript
const compression = require('compression');

// 1. 启用 Gzip 压缩
app.use(compression());

// 2. 设置缓存头
app.use('/static', express.static('public', {
  maxAge: '1y',
  etag: true
}));

// 3. 使用 HTTP/2
const http2 = require('http2');
const fs = require('fs');

const server = http2.createSecureServer({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
});

// 4. 响应流式传输
app.get('/large-data', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.write('[');
  
  let first = true;
  const cursor = db.collection('items').find().stream();
  
  cursor.on('data', (doc) => {
    if (!first) res.write(',');
    first = false;
    res.write(JSON.stringify(doc));
  });
  
  cursor.on('end', () => {
    res.write(']');
    res.end();
  });
});
```

### 15.4 监控与分析

```javascript
// 1. 内存监控
setInterval(() => {
  const usage = process.memoryUsage();
  console.log({
    heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)} MB`,
    heapTotal: `${Math.round(usage.heapTotal / 1024 / 1024)} MB`,
    rss: `${Math.round(usage.rss / 1024 / 1024)} MB`
  });
}, 10000);

// 2. 性能计时
const { performance, PerformanceObserver } = require('perf_hooks');

// 使用 performance.mark 和 measure
performance.mark('start');
// ... 执行操作
performance.mark('end');
performance.measure('操作耗时', 'start', 'end');

const observer = new PerformanceObserver((list) => {
  const entries = list.getEntries();
  entries.forEach(entry => {
    console.log(`${entry.name}: ${entry.duration}ms`);
  });
});
observer.observe({ entryTypes: ['measure'] });

// 3. 使用 console.time
console.time('数据库查询');
await db.query('SELECT * FROM users');
console.timeEnd('数据库查询');

// 4. 使用 --inspect 调试
// node --inspect app.js
// 然后在 Chrome 打开 chrome://inspect

// 5. 生成堆快照
const v8 = require('v8');
const fs = require('fs');

function takeHeapSnapshot() {
  const snapshotStream = v8.writeHeapSnapshot();
  console.log('堆快照已保存:', snapshotStream);
}

// 6. CPU 分析
// node --prof app.js
// node --prof-process isolate-*.log > processed.txt
```

---

## 16. 常见错误与解决方案

### 16.1 模块相关错误

```javascript
// 错误：Cannot find module 'xxx'
// 原因：模块未安装或路径错误
// 解决：
npm install xxx
// 或检查路径是否正确
const module = require('./path/to/module');  // 相对路径需要 ./

// 错误：SyntaxError: Cannot use import statement outside a module
// 原因：在 CommonJS 环境中使用 ES Modules 语法
// 解决：
// 方案1：在 package.json 中添加 "type": "module"
// 方案2：将文件扩展名改为 .mjs
// 方案3：使用 require 代替 import

// 错误：ReferenceError: require is not defined in ES module scope
// 原因：在 ES Modules 中使用 require
// 解决：
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const fs = require('fs');

// 错误：Error [ERR_REQUIRE_ESM]: require() of ES Module
// 原因：尝试用 require 导入 ES Module 包
// 解决：使用动态 import
const module = await import('esm-package');
```

### 16.2 异步相关错误

```javascript
// 错误：UnhandledPromiseRejectionWarning
// 原因：Promise 拒绝未被捕获
// 解决：
// 方案1：添加 .catch()
fetchData().catch(err => console.error(err));

// 方案2：使用 try/catch
async function main() {
  try {
    await fetchData();
  } catch (err) {
    console.error(err);
  }
}

// 方案3：全局处理
process.on('unhandledRejection', (reason, promise) => {
  console.error('未处理的 Promise 拒绝:', reason);
});

// 错误：Callback was already called
// 原因：回调函数被多次调用
// 解决：确保每个代码路径只调用一次回调
function processData(data, callback) {
  if (!data) {
    return callback(new Error('无数据'));  // 使用 return
  }
  // 处理数据
  callback(null, result);
}

// 错误：await is only valid in async functions
// 原因：在非 async 函数中使用 await
// 解决：将函数声明为 async
async function getData() {
  const data = await fetchData();
}
```

### 16.3 文件系统错误

```javascript
// 错误：ENOENT: no such file or directory
// 原因：文件或目录不存在
// 解决：
async function safeReadFile(path) {
  try {
    return await fs.promises.readFile(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.log('文件不存在');
      return null;
    }
    throw err;
  }
}

// 错误：EACCES: permission denied
// 原因：没有文件访问权限
// 解决：检查文件权限或以管理员身份运行

// 错误：EMFILE: too many open files
// 原因：同时打开的文件过多
// 解决：
// 方案1：使用流而不是一次性读取
// 方案2：限制并发数
const pLimit = require('p-limit');
const limit = pLimit(10);  // 最多同时处理 10 个

const results = await Promise.all(
  files.map(file => limit(() => processFile(file)))
);

// 错误：EEXIST: file already exists
// 原因：尝试创建已存在的文件/目录
// 解决：
await fs.promises.mkdir('dir', { recursive: true });  // 不会报错
```

### 16.4 网络相关错误

```javascript
// 错误：EADDRINUSE: address already in use
// 原因：端口已被占用
// 解决：
const server = app.listen(PORT, () => {
  console.log(`服务器运行在端口 ${PORT}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`端口 ${PORT} 已被占用，尝试端口 ${PORT + 1}`);
    server.listen(PORT + 1);
  }
});

// 错误：ECONNREFUSED: Connection refused
// 原因：目标服务器未运行或拒绝连接
// 解决：检查目标服务是否运行，端口是否正确

// 错误：ETIMEDOUT: connection timed out
// 原因：连接超时
// 解决：增加超时时间或检查网络
const response = await fetch(url, {
  signal: AbortSignal.timeout(30000)  // 30 秒超时
});

// 错误：ECONNRESET: Connection reset by peer
// 原因：连接被对方重置
// 解决：实现重试机制
async function fetchWithRetry(url, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fetch(url);
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}
```

### 16.5 内存相关错误

```javascript
// 错误：FATAL ERROR: CALL_AND_RETRY_LAST Allocation failed - JavaScript heap out of memory
// 原因：内存不足
// 解决：
// 方案1：增加内存限制
// node --max-old-space-size=4096 app.js

// 方案2：优化代码，避免内存泄漏
// - 及时清理不用的变量
// - 使用流处理大文件
// - 避免闭包持有大对象

// 方案3：分批处理数据
async function processLargeData(items) {
  const batchSize = 1000;
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    await processBatch(batch);
    
    // 强制垃圾回收（需要 --expose-gc 参数）
    if (global.gc) global.gc();
  }
}

// 错误：RangeError: Maximum call stack size exceeded
// 原因：递归过深或无限递归
// 解决：
// 方案1：改用迭代
// 方案2：使用尾递归优化
// 方案3：使用 setImmediate 分割调用栈
function processDeep(items, index = 0) {
  if (index >= items.length) return;
  
  processItem(items[index]);
  
  // 避免栈溢出
  setImmediate(() => processDeep(items, index + 1));
}
```

### 16.6 Express 常见错误

```javascript
// 错误：Cannot set headers after they are sent to the client
// 原因：响应已发送后又尝试发送
// 解决：确保只发送一次响应
app.get('/api/data', (req, res) => {
  if (!data) {
    return res.status(404).json({ error: '未找到' });  // 使用 return
  }
  res.json(data);  // 不会执行
});

// 错误：req.body is undefined
// 原因：未配置 body 解析中间件
// 解决：
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 错误：Error: Route.get() requires a callback function
// 原因：路由处理函数未定义或导入错误
// 解决：检查处理函数是否正确导出和导入
// controller.js
module.exports.getUsers = (req, res) => { ... };

// routes.js
const { getUsers } = require('./controller');
router.get('/users', getUsers);

// 错误：404 Not Found（路由不匹配）
// 原因：路由顺序问题或路径错误
// 解决：
// 1. 检查路由顺序（具体路由放在通配路由前面）
app.get('/users/profile', handler);  // 先
app.get('/users/:id', handler);      // 后

// 2. 检查路径是否正确（注意前导斜杠）
app.use('/api', router);  // router 中的路由不需要 /api 前缀
```

### 16.7 数据库常见错误

```javascript
// 错误：MongooseError: Operation `users.find()` buffering timed out
// 原因：数据库连接未建立
// 解决：确保连接成功后再进行操作
await mongoose.connect(uri);
console.log('数据库已连接');
// 然后再进行查询

// 错误：E11000 duplicate key error
// 原因：违反唯一索引约束
// 解决：
try {
  await User.create({ email: 'test@example.com' });
} catch (err) {
  if (err.code === 11000) {
    console.log('邮箱已存在');
  }
}

// 错误：CastError: Cast to ObjectId failed
// 原因：无效的 MongoDB ObjectId
// 解决：
const mongoose = require('mongoose');

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

app.get('/users/:id', (req, res) => {
  if (!isValidObjectId(req.params.id)) {
    return res.status(400).json({ error: '无效的 ID' });
  }
  // ...
});

// 错误：ER_ACCESS_DENIED_ERROR (MySQL)
// 原因：数据库认证失败
// 解决：检查用户名、密码、主机、数据库名是否正确
```

### 16.8 调试技巧

```javascript
// 1. 使用 console 方法
console.log('普通日志');
console.error('错误日志');
console.warn('警告日志');
console.table([{ a: 1, b: 2 }, { a: 3, b: 4 }]);
console.time('操作');
// ... 操作
console.timeEnd('操作');
console.trace('调用栈');

// 2. 使用 debugger
function problematicFunction() {
  debugger;  // 在此处暂停
  // ...
}
// 运行：node inspect app.js

// 3. 使用 Node.js 内置调试器
// node --inspect app.js
// 然后在 Chrome 打开 chrome://inspect

// 4. 使用 debug 模块
const debug = require('debug')('app:server');
debug('服务器启动');
// 运行：DEBUG=app:* node app.js

// 5. 错误堆栈优化
Error.stackTraceLimit = 50;  // 增加堆栈深度

// 6. 异步堆栈追踪
// node --async-stack-traces app.js
```

---

## 总结

Node.js 是一个强大的服务器端 JavaScript 运行时，掌握它需要理解：

1. **核心概念**：事件循环、非阻塞 I/O、单线程模型
2. **模块系统**：CommonJS 和 ES Modules 的使用和区别
3. **异步编程**：回调、Promise、async/await 的正确使用
4. **核心模块**：fs、path、http、events 等内置模块
5. **Web 开发**：Express 框架、中间件、路由、错误处理
6. **数据库操作**：MySQL、MongoDB、Redis 的连接和操作
7. **性能优化**：流处理、缓存、集群、Worker Threads
8. **安全实践**：输入验证、防注入、认证授权

持续学习和实践是掌握 Node.js 的关键，建议多阅读官方文档和优秀开源项目的源码。
