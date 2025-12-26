# JavaScript 完整学习笔记

> JavaScript（简称 JS）是一门动态、弱类型的编程语言，最初设计用于网页交互，现在已经发展成为全栈开发语言。它可以运行在浏览器（前端）和 Node.js（后端）环境中。
>
> 本笔记从零基础到高级特性，涵盖 ES6+ 现代语法，适合系统学习。

---

## 目录

1. [基础概念](#1-基础概念)
2. [变量与数据类型](#2-变量与数据类型)
3. [运算符](#3-运算符)
4. [流程控制](#4-流程控制)
5. [函数](#5-函数)
6. [数组](#6-数组)
7. [对象](#7-对象)
8. [字符串](#8-字符串)
9. [ES6+ 新特性](#9-es6-新特性)
10. [异步编程](#10-异步编程)
11. [面向对象编程](#11-面向对象编程)
12. [DOM 操作](#12-dom-操作)
13. [事件处理](#13-事件处理)
14. [BOM 浏览器对象](#14-bom-浏览器对象)
15. [错误处理](#15-错误处理)
16. [模块化](#16-模块化)
17. [常见错误汇总](#17-常见错误汇总)

---

## 1. 基础概念

### 1.1 什么是 JavaScript？

JavaScript 的特点：
| 特性 | 说明 |
|------|------|
| 解释型语言 | 不需要编译，直接运行 |
| 动态类型 | 变量类型可以随时改变 |
| 弱类型 | 不同类型可以进行运算 |
| 单线程 | 一次只能执行一个任务 |
| 事件驱动 | 通过事件触发代码执行 |

### 1.2 JavaScript 的运行环境

```
浏览器环境：
├── Chrome (V8 引擎)
├── Firefox (SpiderMonkey)
├── Safari (JavaScriptCore)
└── Edge (V8 引擎)

服务器环境：
└── Node.js (V8 引擎)
```

### 1.3 在 HTML 中使用 JavaScript

```html
<!-- 方式1：内联脚本 -->
<button onclick="alert('Hello!')">点击</button>

<!-- 方式2：内部脚本 -->
<script>
    console.log('Hello, JavaScript!');
</script>

<!-- 方式3：外部脚本（推荐） -->
<script src="script.js"></script>

<!-- 方式4：模块化脚本 -->
<script type="module" src="app.js"></script>
```

> **最佳实践**：将 `<script>` 标签放在 `</body>` 前，或使用 `defer` 属性，避免阻塞页面渲染。

```html
<!-- 推荐写法 -->
<script src="script.js" defer></script>
```

### 1.4 控制台输出

```javascript
// 普通输出
console.log('普通信息');

// 警告
console.warn('警告信息');

// 错误
console.error('错误信息');

// 表格形式
console.table([{name: 'John', age: 25}, {name: 'Jane', age: 22}]);

// 分组
console.group('分组标题');
console.log('内容1');
console.log('内容2');
console.groupEnd();

// 计时
console.time('计时器');
// ... 代码 ...
console.timeEnd('计时器');
```

---

## 2. 变量与数据类型

### 2.1 变量声明

JavaScript 有三种声明变量的方式：

```javascript
// var - 旧方式，有变量提升，函数作用域
var name = 'John';

// let - ES6，块级作用域，可重新赋值（推荐）
let age = 25;

// const - ES6，块级作用域，不可重新赋值（推荐）
const PI = 3.14159;
```

**三者区别：**

| 特性 | var | let | const |
|------|-----|-----|-------|
| 作用域 | 函数作用域 | 块级作用域 | 块级作用域 |
| 变量提升 | ✅ | ❌ | ❌ |
| 重复声明 | ✅ | ❌ | ❌ |
| 重新赋值 | ✅ | ✅ | ❌ |
| 暂时性死区 | ❌ | ✅ | ✅ |

```javascript
// 变量提升示例
console.log(a); // undefined（var 会提升）
var a = 1;

console.log(b); // ReferenceError（let 不会提升）
let b = 2;

// 块级作用域示例
{
    var x = 1;
    let y = 2;
    const z = 3;
}
console.log(x); // 1（var 可以访问）
console.log(y); // ReferenceError（let 不可访问）

// const 注意事项
const obj = { name: 'John' };
obj.name = 'Jane';  // ✅ 可以修改属性
obj = {};           // ❌ 不能重新赋值
```

> **最佳实践**：优先使用 `const`，需要重新赋值时使用 `let`，避免使用 `var`。

### 2.2 数据类型

JavaScript 有 8 种数据类型：

**原始类型（7种）：**
```javascript
// 1. Number - 数字（整数和浮点数）
let num = 42;
let float = 3.14;
let infinity = Infinity;
let notANumber = NaN;

// 2. String - 字符串
let str1 = 'Hello';
let str2 = "World";
let str3 = `Template ${str1}`;  // 模板字符串

// 3. Boolean - 布尔值
let isTrue = true;
let isFalse = false;

// 4. Undefined - 未定义
let undef;
console.log(undef); // undefined

// 5. Null - 空值
let empty = null;

// 6. Symbol - 唯一标识符（ES6）
let sym = Symbol('description');

// 7. BigInt - 大整数（ES2020）
let bigNum = 9007199254740991n;
let bigNum2 = BigInt(9007199254740991);
```

**引用类型（1种）：**
```javascript
// Object - 对象（包括数组、函数、日期等）
let obj = { name: 'John' };
let arr = [1, 2, 3];
let func = function() {};
let date = new Date();
let regex = /pattern/;
```

### 2.3 类型检测

```javascript
// typeof - 检测原始类型
typeof 42;          // "number"
typeof 'hello';     // "string"
typeof true;        // "boolean"
typeof undefined;   // "undefined"
typeof null;        // "object" ⚠️ 历史遗留 bug
typeof Symbol();    // "symbol"
typeof 10n;         // "bigint"
typeof {};          // "object"
typeof [];          // "object" ⚠️ 数组也是 object
typeof function(){}; // "function"

// 检测数组
Array.isArray([1, 2, 3]);  // true

// 检测 null
value === null;

// instanceof - 检测引用类型
[] instanceof Array;       // true
{} instanceof Object;      // true
new Date() instanceof Date; // true

// Object.prototype.toString - 最准确的方法
Object.prototype.toString.call([]);      // "[object Array]"
Object.prototype.toString.call({});      // "[object Object]"
Object.prototype.toString.call(null);    // "[object Null]"
Object.prototype.toString.call(undefined); // "[object Undefined]"
```

### 2.4 类型转换

#### 显式转换

```javascript
// 转换为字符串
String(123);        // "123"
(123).toString();   // "123"
123 + '';           // "123"

// 转换为数字
Number('123');      // 123
Number('12.34');    // 12.34
Number('abc');      // NaN
Number(true);       // 1
Number(false);      // 0
Number(null);       // 0
Number(undefined);  // NaN
parseInt('123px');  // 123（解析整数）
parseFloat('12.34'); // 12.34（解析浮点数）
+'123';             // 123（一元加号）

// 转换为布尔值
Boolean(1);         // true
Boolean(0);         // false
Boolean('hello');   // true
Boolean('');        // false
Boolean(null);      // false
Boolean(undefined); // false
Boolean({});        // true（空对象也是 true！）
Boolean([]);        // true（空数组也是 true！）
!!value;            // 双重否定转布尔
```

**假值（Falsy）列表：**
```javascript
// 以下值转换为布尔值都是 false
false
0
-0
0n
''
null
undefined
NaN
```

#### 隐式转换

```javascript
// 字符串拼接
'5' + 3;        // "53"（数字转字符串）
'5' + true;     // "5true"

// 数学运算（除了 +）
'5' - 3;        // 2（字符串转数字）
'5' * '2';      // 10
'10' / '2';     // 5

// 比较运算
'5' == 5;       // true（类型转换后比较）
'5' === 5;      // false（严格比较，不转换）

// 逻辑运算
!0;             // true
!!'hello';      // true
```

> **⚠️ 常见错误 #1：隐式类型转换陷阱**
> ```javascript
> [] + [];        // ""（空字符串）
> [] + {};        // "[object Object]"
> {} + [];        // 0（{} 被解析为代码块）
> true + true;    // 2
> '2' + 1;        // "21"
> '2' - 1;        // 1
> ```

---

## 3. 运算符

### 3.1 算术运算符

```javascript
// 基本运算
5 + 3;      // 8  加法
5 - 3;      // 2  减法
5 * 3;      // 15 乘法
5 / 3;      // 1.666... 除法
5 % 3;      // 2  取余
5 ** 3;     // 125 幂运算（ES7）

// 自增自减
let a = 5;
a++;        // 后置：先返回值，再加1
++a;        // 前置：先加1，再返回值
a--;        // 后置递减
--a;        // 前置递减

// 复合赋值
a += 5;     // a = a + 5
a -= 5;     // a = a - 5
a *= 5;     // a = a * 5
a /= 5;     // a = a / 5
a %= 5;     // a = a % 5
a **= 2;    // a = a ** 2
```

### 3.2 比较运算符

```javascript
// 相等比较
5 == '5';       // true（宽松相等，会类型转换）
5 === '5';      // false（严格相等，不转换）
5 != '5';       // false
5 !== '5';      // true

// 大小比较
5 > 3;          // true
5 < 3;          // false
5 >= 5;         // true
5 <= 5;         // true

// 字符串比较（按字符编码）
'a' < 'b';      // true
'10' < '9';     // true（字符串比较，'1' < '9'）
```

> **最佳实践**：始终使用 `===` 和 `!==` 进行比较，避免隐式类型转换带来的问题。

### 3.3 逻辑运算符

```javascript
// 与、或、非
true && false;  // false
true || false;  // true
!true;          // false

// 短路求值
let a = null;
let b = a || 'default';     // 'default'（a 为假值时取后者）
let c = a && a.name;        // null（a 为假值时直接返回）

// 空值合并运算符（ES2020）
let d = null ?? 'default';  // 'default'（只有 null/undefined 时取后者）
let e = 0 ?? 'default';     // 0（0 不是 null/undefined）
let f = 0 || 'default';     // 'default'（0 是假值）

// 逻辑赋值运算符（ES2021）
a ||= 'default';    // a = a || 'default'
a &&= 'value';      // a = a && 'value'
a ??= 'default';    // a = a ?? 'default'
```

### 3.4 其他运算符

```javascript
// 三元运算符
let result = condition ? 'yes' : 'no';

// 逗号运算符
let x = (1, 2, 3);  // x = 3（返回最后一个值）

// 展开运算符（ES6）
let arr1 = [1, 2, 3];
let arr2 = [...arr1, 4, 5];  // [1, 2, 3, 4, 5]

let obj1 = { a: 1 };
let obj2 = { ...obj1, b: 2 }; // { a: 1, b: 2 }

// 可选链运算符（ES2020）
let user = { address: { city: 'Beijing' } };
let city = user?.address?.city;     // 'Beijing'
let zip = user?.address?.zip;       // undefined（不会报错）
let method = user?.getName?.();     // undefined（方法不存在）

// typeof 运算符
typeof 'hello';     // "string"

// instanceof 运算符
[] instanceof Array; // true

// in 运算符
'name' in { name: 'John' };  // true
0 in [1, 2, 3];              // true（检查索引）

// delete 运算符
let obj = { a: 1, b: 2 };
delete obj.a;       // true，obj = { b: 2 }
```

### 3.5 运算符优先级

从高到低（常用）：
```
1. ()                    括号
2. ++ -- !               一元运算符
3. ** * / %              算术运算符
4. + -                   加减
5. < > <= >= instanceof  比较
6. == != === !==         相等
7. &&                    逻辑与
8. ||                    逻辑或
9. ??                    空值合并
10. ? :                  三元
11. = += -= ...          赋值
```

> **最佳实践**：不确定优先级时，使用括号明确表达意图。

---

## 4. 流程控制

### 4.1 条件语句

#### if...else

```javascript
let score = 85;

if (score >= 90) {
    console.log('优秀');
} else if (score >= 80) {
    console.log('良好');
} else if (score >= 60) {
    console.log('及格');
} else {
    console.log('不及格');
}
```

#### switch

```javascript
let day = 'Monday';

switch (day) {
    case 'Monday':
    case 'Tuesday':
    case 'Wednesday':
    case 'Thursday':
    case 'Friday':
        console.log('工作日');
        break;
    case 'Saturday':
    case 'Sunday':
        console.log('周末');
        break;
    default:
        console.log('无效的日期');
}
```

> **注意**：switch 使用严格相等（===）比较，别忘了 `break`！

### 4.2 循环语句

#### for 循环

```javascript
// 基本 for 循环
for (let i = 0; i < 5; i++) {
    console.log(i);
}

// for...in（遍历对象的键）
let obj = { a: 1, b: 2, c: 3 };
for (let key in obj) {
    console.log(key, obj[key]);
}

// for...of（遍历可迭代对象的值，ES6）
let arr = [1, 2, 3];
for (let value of arr) {
    console.log(value);
}

// 遍历字符串
for (let char of 'Hello') {
    console.log(char);
}
```

#### while 循环

```javascript
// while
let i = 0;
while (i < 5) {
    console.log(i);
    i++;
}

// do...while（至少执行一次）
let j = 0;
do {
    console.log(j);
    j++;
} while (j < 5);
```

#### 循环控制

```javascript
// break - 跳出循环
for (let i = 0; i < 10; i++) {
    if (i === 5) break;
    console.log(i);  // 0, 1, 2, 3, 4
}

// continue - 跳过本次迭代
for (let i = 0; i < 5; i++) {
    if (i === 2) continue;
    console.log(i);  // 0, 1, 3, 4
}

// 标签语句（跳出多层循环）
outer: for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 3; j++) {
        if (i === 1 && j === 1) break outer;
        console.log(i, j);
    }
}
```

---

## 5. 函数

### 5.1 函数定义

```javascript
// 函数声明（会提升）
function greet(name) {
    return `Hello, ${name}!`;
}

// 函数表达式（不会提升）
const greet = function(name) {
    return `Hello, ${name}!`;
};

// 箭头函数（ES6，推荐）
const greet = (name) => {
    return `Hello, ${name}!`;
};

// 箭头函数简写
const greet = name => `Hello, ${name}!`;  // 单参数可省略括号，单行可省略 return

// 立即执行函数（IIFE）
(function() {
    console.log('立即执行');
})();

// 箭头函数 IIFE
(() => {
    console.log('立即执行');
})();
```

### 5.2 函数参数

```javascript
// 默认参数（ES6）
function greet(name = 'Guest') {
    return `Hello, ${name}!`;
}
greet();        // "Hello, Guest!"
greet('John');  // "Hello, John!"

// 剩余参数（ES6）
function sum(...numbers) {
    return numbers.reduce((a, b) => a + b, 0);
}
sum(1, 2, 3, 4);  // 10

// 解构参数
function createUser({ name, age, city = 'Unknown' }) {
    return { name, age, city };
}
createUser({ name: 'John', age: 25 });

// arguments 对象（旧方式，箭头函数没有）
function oldSum() {
    let total = 0;
    for (let i = 0; i < arguments.length; i++) {
        total += arguments[i];
    }
    return total;
}
```

### 5.3 箭头函数 vs 普通函数

```javascript
// 1. this 绑定不同
const obj = {
    name: 'John',
    // 普通函数：this 指向调用者
    sayHi: function() {
        console.log(this.name);  // 'John'
    },
    // 箭头函数：this 继承外层作用域
    sayHello: () => {
        console.log(this.name);  // undefined（this 是外层的 this）
    },
    // 常见场景：回调函数
    delayedGreet: function() {
        setTimeout(() => {
            console.log(this.name);  // 'John'（箭头函数继承 this）
        }, 1000);
    }
};

// 2. 箭头函数没有 arguments
const arrowFunc = () => {
    console.log(arguments);  // ReferenceError
};

// 3. 箭头函数不能作为构造函数
const Person = (name) => {
    this.name = name;
};
new Person('John');  // TypeError

// 4. 箭头函数没有 prototype
const arrow = () => {};
console.log(arrow.prototype);  // undefined
```

### 5.4 高阶函数

高阶函数是接收函数作为参数或返回函数的函数。

```javascript
// 函数作为参数
function doOperation(a, b, operation) {
    return operation(a, b);
}
doOperation(5, 3, (a, b) => a + b);  // 8
doOperation(5, 3, (a, b) => a * b);  // 15

// 函数作为返回值
function multiplier(factor) {
    return function(number) {
        return number * factor;
    };
}
const double = multiplier(2);
const triple = multiplier(3);
double(5);  // 10
triple(5);  // 15

// 柯里化
const curry = (fn) => {
    return function curried(...args) {
        if (args.length >= fn.length) {
            return fn.apply(this, args);
        }
        return (...args2) => curried.apply(this, args.concat(args2));
    };
};

const add = (a, b, c) => a + b + c;
const curriedAdd = curry(add);
curriedAdd(1)(2)(3);  // 6
curriedAdd(1, 2)(3);  // 6
```

### 5.5 闭包

闭包是指函数能够访问其外部作用域的变量，即使外部函数已经执行完毕。

```javascript
// 基本闭包
function outer() {
    let count = 0;
    return function inner() {
        count++;
        return count;
    };
}
const counter = outer();
counter();  // 1
counter();  // 2
counter();  // 3

// 闭包的应用：私有变量
function createPerson(name) {
    let _age = 0;  // 私有变量
    return {
        getName: () => name,
        getAge: () => _age,
        setAge: (age) => {
            if (age > 0) _age = age;
        }
    };
}
const person = createPerson('John');
person.getAge();    // 0
person.setAge(25);
person.getAge();    // 25
person._age;        // undefined（无法直接访问）

// 闭包的应用：函数工厂
function createMultiplier(factor) {
    return (number) => number * factor;
}
const double = createMultiplier(2);
const triple = createMultiplier(3);

// ⚠️ 闭包陷阱：循环中的闭包
for (var i = 0; i < 3; i++) {
    setTimeout(() => console.log(i), 100);
}
// 输出：3, 3, 3（因为 var 没有块级作用域）

// 解决方案1：使用 let
for (let i = 0; i < 3; i++) {
    setTimeout(() => console.log(i), 100);
}
// 输出：0, 1, 2

// 解决方案2：使用 IIFE
for (var i = 0; i < 3; i++) {
    ((j) => {
        setTimeout(() => console.log(j), 100);
    })(i);
}
```

### 5.6 this 关键字

```javascript
// 1. 全局上下文
console.log(this);  // 浏览器：window，Node.js：global

// 2. 对象方法
const obj = {
    name: 'John',
    greet() {
        console.log(this.name);  // 'John'
    }
};

// 3. 构造函数
function Person(name) {
    this.name = name;
}
const p = new Person('John');  // this 指向新创建的对象

// 4. 显式绑定
function greet() {
    console.log(this.name);
}
const user = { name: 'John' };

greet.call(user);           // 'John'（立即调用）
greet.apply(user);          // 'John'（立即调用）
const boundGreet = greet.bind(user);  // 返回绑定后的函数
boundGreet();               // 'John'

// call vs apply
function introduce(greeting, punctuation) {
    console.log(`${greeting}, I'm ${this.name}${punctuation}`);
}
introduce.call(user, 'Hello', '!');     // 参数逐个传递
introduce.apply(user, ['Hello', '!']);  // 参数作为数组

// 5. 事件处理器
button.addEventListener('click', function() {
    console.log(this);  // button 元素
});

button.addEventListener('click', () => {
    console.log(this);  // 外层的 this（通常是 window）
});
```

---

## 6. 数组

### 6.1 创建数组

```javascript
// 字面量（推荐）
const arr1 = [1, 2, 3];

// 构造函数
const arr2 = new Array(1, 2, 3);
const arr3 = new Array(5);  // 创建长度为 5 的空数组

// Array.of（ES6）
const arr4 = Array.of(5);   // [5]（避免 new Array 的歧义）

// Array.from（ES6）
const arr5 = Array.from('hello');  // ['h', 'e', 'l', 'l', 'o']
const arr6 = Array.from({ length: 5 }, (_, i) => i);  // [0, 1, 2, 3, 4]
const arr7 = Array.from(new Set([1, 2, 2, 3]));  // [1, 2, 3]

// 填充数组
const arr8 = new Array(5).fill(0);  // [0, 0, 0, 0, 0]
```

### 6.2 数组方法

#### 增删改查

```javascript
const arr = [1, 2, 3, 4, 5];

// 添加元素
arr.push(6);        // 末尾添加，返回新长度 [1,2,3,4,5,6]
arr.unshift(0);     // 开头添加，返回新长度 [0,1,2,3,4,5,6]

// 删除元素
arr.pop();          // 删除末尾，返回删除的元素
arr.shift();        // 删除开头，返回删除的元素

// splice - 万能方法（会修改原数组）
arr.splice(2, 1);           // 从索引2删除1个元素
arr.splice(2, 0, 'a');      // 在索引2插入'a'
arr.splice(2, 1, 'a', 'b'); // 替换索引2的元素为'a','b'

// 查找元素
arr.indexOf(3);         // 返回索引，没找到返回 -1
arr.lastIndexOf(3);     // 从后往前找
arr.includes(3);        // 返回 true/false（ES7）
arr.find(x => x > 3);   // 返回第一个满足条件的元素
arr.findIndex(x => x > 3);  // 返回第一个满足条件的索引

// 访问元素
arr[0];             // 第一个元素
arr.at(-1);         // 最后一个元素（ES2022）
arr.at(-2);         // 倒数第二个元素
```

#### 遍历方法

```javascript
const arr = [1, 2, 3, 4, 5];

// forEach - 遍历（无返回值）
arr.forEach((item, index, array) => {
    console.log(item, index);
});

// map - 映射（返回新数组）
const doubled = arr.map(x => x * 2);  // [2, 4, 6, 8, 10]

// filter - 过滤（返回新数组）
const evens = arr.filter(x => x % 2 === 0);  // [2, 4]

// reduce - 归约（返回单个值）
const sum = arr.reduce((acc, cur) => acc + cur, 0);  // 15
const max = arr.reduce((a, b) => Math.max(a, b));    // 5

// reduceRight - 从右往左归约
const str = ['a', 'b', 'c'].reduceRight((acc, cur) => acc + cur);  // 'cba'

// every - 是否全部满足
arr.every(x => x > 0);  // true

// some - 是否有一个满足
arr.some(x => x > 4);   // true

// flat - 扁平化（ES2019）
const nested = [1, [2, [3, [4]]]];
nested.flat();      // [1, 2, [3, [4]]]
nested.flat(2);     // [1, 2, 3, [4]]
nested.flat(Infinity);  // [1, 2, 3, 4]

// flatMap - map + flat
const sentences = ['Hello World', 'Hi there'];
sentences.flatMap(s => s.split(' '));  // ['Hello', 'World', 'Hi', 'there']
```

#### 排序和转换

```javascript
const arr = [3, 1, 4, 1, 5, 9];

// sort - 排序（会修改原数组）
arr.sort();                     // 默认按字符串排序
arr.sort((a, b) => a - b);      // 升序
arr.sort((a, b) => b - a);      // 降序

// 对象数组排序
const users = [
    { name: 'John', age: 25 },
    { name: 'Jane', age: 22 }
];
users.sort((a, b) => a.age - b.age);

// reverse - 反转（会修改原数组）
arr.reverse();

// toSorted/toReversed - 不修改原数组（ES2023）
const sorted = arr.toSorted((a, b) => a - b);
const reversed = arr.toReversed();

// join - 转字符串
[1, 2, 3].join('-');  // "1-2-3"

// slice - 截取（不修改原数组）
arr.slice(1, 3);      // 从索引1到3（不含3）
arr.slice(-2);        // 最后两个元素

// concat - 合并（不修改原数组）
[1, 2].concat([3, 4]);  // [1, 2, 3, 4]
[...[1, 2], ...[3, 4]]; // [1, 2, 3, 4]（展开运算符）
```

### 6.3 数组解构

```javascript
const arr = [1, 2, 3, 4, 5];

// 基本解构
const [a, b, c] = arr;  // a=1, b=2, c=3

// 跳过元素
const [first, , third] = arr;  // first=1, third=3

// 剩余元素
const [head, ...tail] = arr;  // head=1, tail=[2,3,4,5]

// 默认值
const [x = 0, y = 0] = [1];  // x=1, y=0

// 交换变量
let m = 1, n = 2;
[m, n] = [n, m];  // m=2, n=1
```

---

## 7. 对象

### 7.1 创建对象

```javascript
// 字面量（推荐）
const obj = {
    name: 'John',
    age: 25,
    greet() {
        return `Hello, I'm ${this.name}`;
    }
};

// 构造函数
const obj2 = new Object();
obj2.name = 'John';

// Object.create
const proto = { greet() { return 'Hello'; } };
const obj3 = Object.create(proto);

// 属性简写（ES6）
const name = 'John';
const age = 25;
const obj4 = { name, age };  // { name: 'John', age: 25 }

// 计算属性名（ES6）
const key = 'dynamicKey';
const obj5 = {
    [key]: 'value',
    ['prefix_' + key]: 'another value'
};
```

### 7.2 对象操作

```javascript
const obj = { name: 'John', age: 25 };

// 访问属性
obj.name;           // 点语法
obj['name'];        // 方括号语法
obj['first-name'];  // 特殊字符必须用方括号

// 添加/修改属性
obj.city = 'Beijing';
obj['country'] = 'China';

// 删除属性
delete obj.age;

// 检查属性
'name' in obj;              // true（包括原型链）
obj.hasOwnProperty('name'); // true（只检查自身）
Object.hasOwn(obj, 'name'); // true（ES2022，推荐）

// 获取键/值/键值对
Object.keys(obj);       // ['name', 'city', 'country']
Object.values(obj);     // ['John', 'Beijing', 'China']
Object.entries(obj);    // [['name','John'], ['city','Beijing'], ...]

// 从键值对创建对象
Object.fromEntries([['a', 1], ['b', 2]]);  // { a: 1, b: 2 }

// 合并对象
const merged = Object.assign({}, obj, { email: 'john@example.com' });
const merged2 = { ...obj, email: 'john@example.com' };  // 展开运算符（推荐）

// 冻结对象
Object.freeze(obj);     // 不能添加、删除、修改属性
Object.isFrozen(obj);   // true

// 密封对象
Object.seal(obj);       // 不能添加、删除，但可以修改
Object.isSealed(obj);   // true

// 阻止扩展
Object.preventExtensions(obj);  // 不能添加新属性
Object.isExtensible(obj);       // false
```

### 7.3 对象解构

```javascript
const user = {
    name: 'John',
    age: 25,
    address: {
        city: 'Beijing',
        country: 'China'
    }
};

// 基本解构
const { name, age } = user;

// 重命名
const { name: userName, age: userAge } = user;

// 默认值
const { name, email = 'unknown' } = user;

// 嵌套解构
const { address: { city } } = user;

// 剩余属性
const { name, ...rest } = user;  // rest = { age: 25, address: {...} }

// 函数参数解构
function greet({ name, age = 0 }) {
    return `${name} is ${age} years old`;
}
greet(user);
```

### 7.4 对象遍历

```javascript
const obj = { a: 1, b: 2, c: 3 };

// for...in（包括原型链上的可枚举属性）
for (let key in obj) {
    if (obj.hasOwnProperty(key)) {
        console.log(key, obj[key]);
    }
}

// Object.keys + forEach
Object.keys(obj).forEach(key => {
    console.log(key, obj[key]);
});

// Object.entries + for...of（推荐）
for (let [key, value] of Object.entries(obj)) {
    console.log(key, value);
}
```

---

## 8. 字符串

### 8.1 字符串创建

```javascript
// 字面量
const str1 = 'Hello';
const str2 = "World";
const str3 = `Template`;  // 模板字符串（ES6）

// 构造函数（不推荐）
const str4 = new String('Hello');  // 返回对象，不是原始值

// 模板字符串
const name = 'John';
const greeting = `Hello, ${name}!`;  // 支持表达式
const multiLine = `
    第一行
    第二行
`;

// 标签模板
function highlight(strings, ...values) {
    return strings.reduce((result, str, i) => {
        return result + str + (values[i] ? `<mark>${values[i]}</mark>` : '');
    }, '');
}
const highlighted = highlight`Hello ${name}, welcome!`;
```

### 8.2 字符串方法

```javascript
const str = 'Hello, World!';

// 长度
str.length;  // 13

// 访问字符
str[0];             // 'H'
str.charAt(0);      // 'H'
str.charCodeAt(0);  // 72（字符编码）
str.at(-1);         // '!'（ES2022）

// 查找
str.indexOf('o');       // 4（第一次出现的位置）
str.lastIndexOf('o');   // 8（最后一次出现的位置）
str.includes('World');  // true（ES6）
str.startsWith('Hello'); // true（ES6）
str.endsWith('!');      // true（ES6）
str.search(/world/i);   // 7（正则搜索）

// 截取
str.slice(0, 5);        // 'Hello'
str.slice(-6);          // 'World!'
str.substring(0, 5);    // 'Hello'
str.substr(0, 5);       // 'Hello'（已废弃）

// 大小写
str.toUpperCase();      // 'HELLO, WORLD!'
str.toLowerCase();      // 'hello, world!'

// 去除空白
'  hello  '.trim();     // 'hello'
'  hello  '.trimStart(); // 'hello  '
'  hello  '.trimEnd();  // '  hello'

// 填充
'5'.padStart(3, '0');   // '005'
'5'.padEnd(3, '0');     // '500'

// 重复
'ab'.repeat(3);         // 'ababab'

// 替换
str.replace('World', 'JavaScript');     // 替换第一个
str.replaceAll('o', '0');               // 替换所有（ES2021）
str.replace(/o/g, '0');                 // 正则替换所有

// 分割
str.split(', ');        // ['Hello', 'World!']
str.split('');          // ['H', 'e', 'l', 'l', 'o', ...]

// 连接
['Hello', 'World'].join(' ');  // 'Hello World'
'Hello'.concat(' ', 'World');  // 'Hello World'
```

### 8.3 正则表达式

```javascript
// 创建正则
const regex1 = /pattern/flags;
const regex2 = new RegExp('pattern', 'flags');

// 常用标志
// g - 全局匹配
// i - 忽略大小写
// m - 多行模式
// s - 点号匹配换行符
// u - Unicode 模式

// 正则方法
const str = 'Hello World';
/world/i.test(str);         // true
/world/i.exec(str);         // ['World', index: 6, ...]
str.match(/o/g);            // ['o', 'o']
str.matchAll(/o/g);         // 迭代器
str.search(/world/i);       // 6
str.replace(/world/i, 'JS'); // 'Hello JS'

// 常用正则
const patterns = {
    email: /^[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)+$/,
    phone: /^1[3-9]\d{9}$/,
    url: /^https?:\/\/[\w-]+(\.[\w-]+)+([\w.,@?^=%&:/~+#-]*)?$/,
    chinese: /[\u4e00-\u9fa5]/,
    number: /^\d+$/,
    password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/
};

// 捕获组
const dateStr = '2024-01-15';
const match = dateStr.match(/(\d{4})-(\d{2})-(\d{2})/);
// match[0] = '2024-01-15'
// match[1] = '2024'
// match[2] = '01'
// match[3] = '15'

// 命名捕获组（ES2018）
const match2 = dateStr.match(/(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/);
// match2.groups = { year: '2024', month: '01', day: '15' }
```

---

## 9. ES6+ 新特性

### 9.1 let 和 const

见 [2.1 变量声明](#21-变量声明)

### 9.2 解构赋值

见 [6.3 数组解构](#63-数组解构) 和 [7.3 对象解构](#73-对象解构)

### 9.3 展开运算符

```javascript
// 数组展开
const arr1 = [1, 2, 3];
const arr2 = [...arr1, 4, 5];  // [1, 2, 3, 4, 5]

// 对象展开
const obj1 = { a: 1, b: 2 };
const obj2 = { ...obj1, c: 3 };  // { a: 1, b: 2, c: 3 }

// 函数参数
function sum(a, b, c) {
    return a + b + c;
}
sum(...[1, 2, 3]);  // 6

// 复制数组/对象（浅拷贝）
const arrCopy = [...arr1];
const objCopy = { ...obj1 };
```

### 9.4 Set 和 Map

```javascript
// Set - 唯一值集合
const set = new Set([1, 2, 2, 3, 3, 3]);
set.add(4);
set.delete(1);
set.has(2);         // true
set.size;           // 3
set.clear();

// Set 转数组
const arr = [...set];
const arr2 = Array.from(set);

// 数组去重
const unique = [...new Set([1, 2, 2, 3])];  // [1, 2, 3]

// Map - 键值对集合（键可以是任意类型）
const map = new Map();
map.set('name', 'John');
map.set({ id: 1 }, 'object key');
map.get('name');    // 'John'
map.has('name');    // true
map.delete('name');
map.size;           // 1
map.clear();

// Map 初始化
const map2 = new Map([
    ['a', 1],
    ['b', 2]
]);

// Map 遍历
for (let [key, value] of map2) {
    console.log(key, value);
}
map2.forEach((value, key) => {
    console.log(key, value);
});

// WeakSet 和 WeakMap（弱引用，键必须是对象）
const weakSet = new WeakSet();
const weakMap = new WeakMap();
// 当对象没有其他引用时，会被垃圾回收
```

### 9.5 Symbol

```javascript
// 创建 Symbol
const sym1 = Symbol();
const sym2 = Symbol('description');
const sym3 = Symbol('description');
sym2 === sym3;  // false（每个 Symbol 都是唯一的）

// 全局 Symbol
const globalSym = Symbol.for('global');
const sameSym = Symbol.for('global');
globalSym === sameSym;  // true

// 获取描述
Symbol.keyFor(globalSym);  // 'global'

// 作为对象属性（不会被常规遍历）
const obj = {
    [sym1]: 'private value',
    name: 'John'
};
Object.keys(obj);           // ['name']
Object.getOwnPropertySymbols(obj);  // [sym1]

// 内置 Symbol
Symbol.iterator;    // 定义迭代器
Symbol.toStringTag; // 定义 toString 标签
Symbol.hasInstance; // 定义 instanceof 行为
```

### 9.6 迭代器和生成器

```javascript
// 迭代器协议
const iterable = {
    [Symbol.iterator]() {
        let i = 0;
        return {
            next() {
                if (i < 3) {
                    return { value: i++, done: false };
                }
                return { value: undefined, done: true };
            }
        };
    }
};

for (let value of iterable) {
    console.log(value);  // 0, 1, 2
}

// 生成器函数
function* generator() {
    yield 1;
    yield 2;
    yield 3;
}

const gen = generator();
gen.next();  // { value: 1, done: false }
gen.next();  // { value: 2, done: false }
gen.next();  // { value: 3, done: false }
gen.next();  // { value: undefined, done: true }

// 生成器遍历
for (let value of generator()) {
    console.log(value);  // 1, 2, 3
}

// 生成器委托
function* gen1() {
    yield 1;
    yield 2;
}
function* gen2() {
    yield* gen1();
    yield 3;
}
[...gen2()];  // [1, 2, 3]

// 异步生成器
async function* asyncGenerator() {
    yield await Promise.resolve(1);
    yield await Promise.resolve(2);
}
```

### 9.7 Proxy 和 Reflect

```javascript
// Proxy - 代理对象操作
const target = { name: 'John', age: 25 };

const handler = {
    get(target, prop) {
        console.log(`Getting ${prop}`);
        return target[prop];
    },
    set(target, prop, value) {
        console.log(`Setting ${prop} to ${value}`);
        if (prop === 'age' && typeof value !== 'number') {
            throw new TypeError('Age must be a number');
        }
        target[prop] = value;
        return true;
    }
};

const proxy = new Proxy(target, handler);
proxy.name;         // Getting name -> 'John'
proxy.age = 30;     // Setting age to 30
proxy.age = 'old';  // TypeError

// 常用拦截器
const fullHandler = {
    get(target, prop, receiver) {},
    set(target, prop, value, receiver) {},
    has(target, prop) {},           // in 操作符
    deleteProperty(target, prop) {},
    apply(target, thisArg, args) {}, // 函数调用
    construct(target, args) {}       // new 操作符
};

// Reflect - 操作对象的方法
Reflect.get(target, 'name');
Reflect.set(target, 'name', 'Jane');
Reflect.has(target, 'name');
Reflect.deleteProperty(target, 'name');

// 响应式数据（Vue 3 原理）
function reactive(obj) {
    return new Proxy(obj, {
        get(target, prop) {
            // 收集依赖
            track(target, prop);
            return Reflect.get(target, prop);
        },
        set(target, prop, value) {
            const result = Reflect.set(target, prop, value);
            // 触发更新
            trigger(target, prop);
            return result;
        }
    });
}
```

---

## 10. 异步编程

### 10.1 回调函数

```javascript
// 回调函数是最基本的异步模式
function fetchData(callback) {
    setTimeout(() => {
        callback(null, { data: 'Hello' });
    }, 1000);
}

fetchData((error, result) => {
    if (error) {
        console.error(error);
        return;
    }
    console.log(result);
});

// 回调地狱（Callback Hell）
fetchUser(userId, (user) => {
    fetchOrders(user.id, (orders) => {
        fetchProducts(orders[0].productId, (product) => {
            // 嵌套越来越深...
        });
    });
});
```

### 10.2 Promise

Promise 是解决回调地狱的方案，表示一个异步操作的最终结果。

```javascript
// 创建 Promise
const promise = new Promise((resolve, reject) => {
    setTimeout(() => {
        const success = true;
        if (success) {
            resolve('成功的数据');
        } else {
            reject(new Error('失败的原因'));
        }
    }, 1000);
});

// 使用 Promise
promise
    .then(result => {
        console.log(result);
        return '下一步数据';
    })
    .then(result => {
        console.log(result);
    })
    .catch(error => {
        console.error(error);
    })
    .finally(() => {
        console.log('无论成功失败都执行');
    });

// Promise 状态
// pending -> fulfilled (resolved)
// pending -> rejected

// Promise 静态方法
Promise.resolve('value');   // 创建已解决的 Promise
Promise.reject('error');    // 创建已拒绝的 Promise

// Promise.all - 全部成功才成功
Promise.all([
    fetch('/api/users'),
    fetch('/api/posts')
]).then(([users, posts]) => {
    console.log(users, posts);
}).catch(error => {
    // 任一失败就进入 catch
});

// Promise.allSettled - 等待全部完成（ES2020）
Promise.allSettled([
    Promise.resolve(1),
    Promise.reject('error')
]).then(results => {
    // [{ status: 'fulfilled', value: 1 }, { status: 'rejected', reason: 'error' }]
});

// Promise.race - 第一个完成的结果
Promise.race([
    fetch('/api/fast'),
    fetch('/api/slow')
]).then(result => {
    // 最快的结果
});

// Promise.any - 第一个成功的结果（ES2021）
Promise.any([
    Promise.reject('error1'),
    Promise.resolve('success'),
    Promise.reject('error2')
]).then(result => {
    // 'success'
});
```

### 10.3 async/await

async/await 是 Promise 的语法糖，让异步代码看起来像同步代码。

```javascript
// async 函数
async function fetchData() {
    return 'Hello';  // 自动包装成 Promise.resolve('Hello')
}

// await 等待 Promise
async function getData() {
    try {
        const response = await fetch('/api/data');
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// 并行执行
async function parallel() {
    // 串行（慢）
    const user = await fetchUser();
    const posts = await fetchPosts();
    
    // 并行（快）
    const [user2, posts2] = await Promise.all([
        fetchUser(),
        fetchPosts()
    ]);
}

// 循环中的 async/await
async function processArray(array) {
    // 串行处理
    for (const item of array) {
        await processItem(item);
    }
    
    // 并行处理
    await Promise.all(array.map(item => processItem(item)));
}

// 顶层 await（ES2022，模块中可用）
const data = await fetch('/api/data').then(r => r.json());

// 错误处理
async function withErrorHandling() {
    try {
        const result = await riskyOperation();
        return result;
    } catch (error) {
        // 处理错误
        console.error(error);
        return defaultValue;
    } finally {
        // 清理工作
    }
}
```

### 10.4 事件循环

JavaScript 是单线程的，通过事件循环处理异步操作。

```javascript
// 执行顺序示例
console.log('1');  // 同步

setTimeout(() => {
    console.log('2');  // 宏任务
}, 0);

Promise.resolve().then(() => {
    console.log('3');  // 微任务
});

console.log('4');  // 同步

// 输出顺序：1, 4, 3, 2

// 任务队列
// 1. 同步代码（调用栈）
// 2. 微任务（Promise.then, queueMicrotask, MutationObserver）
// 3. 宏任务（setTimeout, setInterval, I/O, UI 渲染）

// 更复杂的例子
async function async1() {
    console.log('async1 start');
    await async2();
    console.log('async1 end');
}

async function async2() {
    console.log('async2');
}

console.log('script start');

setTimeout(() => {
    console.log('setTimeout');
}, 0);

async1();

new Promise((resolve) => {
    console.log('promise1');
    resolve();
}).then(() => {
    console.log('promise2');
});

console.log('script end');

// 输出：
// script start
// async1 start
// async2
// promise1
// script end
// async1 end
// promise2
// setTimeout
```

### 10.5 Fetch API

```javascript
// 基本 GET 请求
fetch('/api/users')
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => console.log(data))
    .catch(error => console.error(error));

// async/await 版本
async function getUsers() {
    const response = await fetch('/api/users');
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
}

// POST 请求
fetch('/api/users', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name: 'John', age: 25 })
});

// 完整配置
fetch(url, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer token'
    },
    body: JSON.stringify(data),
    mode: 'cors',
    credentials: 'include',  // 携带 cookie
    cache: 'no-cache',
    signal: abortController.signal  // 取消请求
});

// 取消请求
const controller = new AbortController();
fetch(url, { signal: controller.signal });
controller.abort();  // 取消

// 超时处理
async function fetchWithTimeout(url, timeout = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
        const response = await fetch(url, { signal: controller.signal });
        return response;
    } finally {
        clearTimeout(timeoutId);
    }
}
```

---

## 11. 面向对象编程

### 11.1 构造函数（ES5）

```javascript
// 构造函数
function Person(name, age) {
    this.name = name;
    this.age = age;
}

// 原型方法
Person.prototype.greet = function() {
    return `Hello, I'm ${this.name}`;
};

// 静态方法
Person.create = function(name, age) {
    return new Person(name, age);
};

// 创建实例
const john = new Person('John', 25);
john.greet();  // "Hello, I'm John"

// 继承
function Student(name, age, grade) {
    Person.call(this, name, age);  // 调用父构造函数
    this.grade = grade;
}

// 继承原型
Student.prototype = Object.create(Person.prototype);
Student.prototype.constructor = Student;

// 子类方法
Student.prototype.study = function() {
    return `${this.name} is studying`;
};
```

### 11.2 Class（ES6）

```javascript
// 类声明
class Person {
    // 私有字段（ES2022）
    #privateField = 'private';
    
    // 静态字段
    static count = 0;
    
    // 构造函数
    constructor(name, age) {
        this.name = name;
        this.age = age;
        Person.count++;
    }
    
    // 实例方法
    greet() {
        return `Hello, I'm ${this.name}`;
    }
    
    // Getter
    get info() {
        return `${this.name}, ${this.age}`;
    }
    
    // Setter
    set info(value) {
        [this.name, this.age] = value.split(', ');
    }
    
    // 私有方法（ES2022）
    #privateMethod() {
        return this.#privateField;
    }
    
    // 静态方法
    static create(name, age) {
        return new Person(name, age);
    }
}

// 使用
const john = new Person('John', 25);
john.greet();       // "Hello, I'm John"
john.info;          // "John, 25"
john.info = 'Jane, 22';
Person.count;       // 1
Person.create('Bob', 30);

// 继承
class Student extends Person {
    constructor(name, age, grade) {
        super(name, age);  // 调用父类构造函数
        this.grade = grade;
    }
    
    // 重写方法
    greet() {
        return `${super.greet()}, I'm a student`;
    }
    
    study() {
        return `${this.name} is studying`;
    }
}

const student = new Student('Alice', 20, 'A');
student.greet();  // "Hello, I'm Alice, I'm a student"
student instanceof Student;  // true
student instanceof Person;   // true
```

### 11.3 原型链

```javascript
// 原型链示意
// john -> Person.prototype -> Object.prototype -> null

const john = new Person('John', 25);

// 检查原型
john.__proto__ === Person.prototype;  // true
Person.prototype.__proto__ === Object.prototype;  // true
Object.prototype.__proto__ === null;  // true

// 获取原型
Object.getPrototypeOf(john);  // Person.prototype

// 设置原型
Object.setPrototypeOf(obj, proto);

// 检查原型链
john instanceof Person;  // true
Person.prototype.isPrototypeOf(john);  // true

// 属性查找顺序
// 1. 实例自身属性
// 2. 原型属性
// 3. 原型的原型...
// 4. 直到 null
```

### 11.4 Mixin 模式

```javascript
// Mixin - 组合多个对象的功能
const canEat = {
    eat() {
        return `${this.name} is eating`;
    }
};

const canWalk = {
    walk() {
        return `${this.name} is walking`;
    }
};

const canSwim = {
    swim() {
        return `${this.name} is swimming`;
    }
};

class Animal {
    constructor(name) {
        this.name = name;
    }
}

// 混入功能
Object.assign(Animal.prototype, canEat, canWalk);

class Fish extends Animal {}
Object.assign(Fish.prototype, canSwim);

const dog = new Animal('Dog');
dog.eat();   // "Dog is eating"
dog.walk();  // "Dog is walking"

const fish = new Fish('Nemo');
fish.swim(); // "Nemo is swimming"
```

---

## 12. DOM 操作

### 12.1 获取元素

```javascript
// 单个元素
document.getElementById('id');
document.querySelector('.class');       // 第一个匹配的元素
document.querySelector('#id .class');   // CSS 选择器

// 多个元素
document.getElementsByClassName('class');  // HTMLCollection（实时）
document.getElementsByTagName('div');      // HTMLCollection
document.querySelectorAll('.class');       // NodeList（静态）

// 特殊元素
document.documentElement;  // <html>
document.head;             // <head>
document.body;             // <body>

// 遍历 DOM
element.parentElement;     // 父元素
element.children;          // 子元素集合
element.firstElementChild; // 第一个子元素
element.lastElementChild;  // 最后一个子元素
element.previousElementSibling;  // 上一个兄弟元素
element.nextElementSibling;      // 下一个兄弟元素
element.closest('.class'); // 最近的祖先元素
```

### 12.2 创建和修改元素

```javascript
// 创建元素
const div = document.createElement('div');
const text = document.createTextNode('Hello');
const fragment = document.createDocumentFragment();

// 设置内容
element.textContent = 'Text';      // 纯文本
element.innerHTML = '<b>HTML</b>'; // HTML（注意 XSS）
element.innerText = 'Text';        // 考虑样式的文本

// 设置属性
element.id = 'myId';
element.className = 'class1 class2';
element.setAttribute('data-id', '123');
element.getAttribute('data-id');
element.removeAttribute('data-id');
element.hasAttribute('data-id');

// dataset（data-* 属性）
element.dataset.id = '123';    // data-id="123"
element.dataset.userName = 'John';  // data-user-name="John"

// 类操作
element.classList.add('active');
element.classList.remove('active');
element.classList.toggle('active');
element.classList.contains('active');
element.classList.replace('old', 'new');

// 样式操作
element.style.color = 'red';
element.style.backgroundColor = 'blue';
element.style.cssText = 'color: red; background: blue;';
getComputedStyle(element).color;  // 获取计算后的样式
```

### 12.3 插入和删除元素

```javascript
// 插入元素
parent.appendChild(child);           // 末尾添加
parent.insertBefore(newNode, referenceNode);  // 在参考节点前插入
parent.append(child1, child2, 'text');  // 末尾添加多个
parent.prepend(child);               // 开头添加

// 现代插入方法
element.before(newElement);          // 元素前面
element.after(newElement);           // 元素后面
element.replaceWith(newElement);     // 替换元素

// insertAdjacentHTML
element.insertAdjacentHTML('beforebegin', '<div>Before</div>');
element.insertAdjacentHTML('afterbegin', '<div>First child</div>');
element.insertAdjacentHTML('beforeend', '<div>Last child</div>');
element.insertAdjacentHTML('afterend', '<div>After</div>');

// 删除元素
element.remove();                    // 删除自身
parent.removeChild(child);           // 删除子元素

// 克隆元素
element.cloneNode(false);            // 浅克隆
element.cloneNode(true);             // 深克隆（包括子元素）
```

### 12.4 元素尺寸和位置

```javascript
// 元素尺寸
element.offsetWidth;   // 包含边框的宽度
element.offsetHeight;  // 包含边框的高度
element.clientWidth;   // 不包含边框的宽度
element.clientHeight;  // 不包含边框的高度
element.scrollWidth;   // 滚动内容的宽度
element.scrollHeight;  // 滚动内容的高度

// 元素位置
element.offsetTop;     // 相对于 offsetParent 的顶部距离
element.offsetLeft;    // 相对于 offsetParent 的左侧距离
element.getBoundingClientRect();  // 相对于视口的位置

// 滚动
element.scrollTop;     // 滚动的垂直距离
element.scrollLeft;    // 滚动的水平距离
element.scrollTo(0, 100);
element.scrollBy(0, 50);
element.scrollIntoView({ behavior: 'smooth' });

// 视口尺寸
window.innerWidth;
window.innerHeight;
document.documentElement.clientWidth;
document.documentElement.clientHeight;
```

---

## 13. 事件处理

### 13.1 事件绑定

```javascript
// 方式1：HTML 属性（不推荐）
<button onclick="handleClick()">Click</button>

// 方式2：DOM 属性
element.onclick = function(event) {
    console.log('Clicked');
};

// 方式3：addEventListener（推荐）
element.addEventListener('click', function(event) {
    console.log('Clicked');
});

// 移除事件
const handler = (e) => console.log(e);
element.addEventListener('click', handler);
element.removeEventListener('click', handler);

// 事件选项
element.addEventListener('click', handler, {
    capture: false,  // 捕获阶段触发
    once: true,      // 只触发一次
    passive: true    // 不会调用 preventDefault
});
```

### 13.2 事件对象

```javascript
element.addEventListener('click', function(event) {
    // 事件类型
    event.type;           // 'click'
    
    // 目标元素
    event.target;         // 触发事件的元素
    event.currentTarget;  // 绑定事件的元素
    
    // 鼠标位置
    event.clientX;        // 相对于视口
    event.clientY;
    event.pageX;          // 相对于文档
    event.pageY;
    event.offsetX;        // 相对于元素
    event.offsetY;
    
    // 键盘信息
    event.key;            // 按键值
    event.code;           // 按键代码
    event.altKey;         // Alt 键是否按下
    event.ctrlKey;        // Ctrl 键是否按下
    event.shiftKey;       // Shift 键是否按下
    event.metaKey;        // Meta 键是否按下
    
    // 阻止默认行为
    event.preventDefault();
    
    // 阻止冒泡
    event.stopPropagation();
    
    // 阻止其他处理器
    event.stopImmediatePropagation();
});
```

### 13.3 事件冒泡和捕获

```javascript
// 事件流：捕获 -> 目标 -> 冒泡
// 
// 捕获阶段：从 window 到目标元素
// 目标阶段：在目标元素上
// 冒泡阶段：从目标元素到 window

// 默认是冒泡阶段触发
parent.addEventListener('click', () => console.log('parent'));
child.addEventListener('click', () => console.log('child'));
// 点击 child：child -> parent

// 捕获阶段触发
parent.addEventListener('click', () => console.log('parent'), true);
// 点击 child：parent -> child

// 阻止冒泡
child.addEventListener('click', (e) => {
    e.stopPropagation();
    console.log('child');
});
// 点击 child：只输出 child
```

### 13.4 事件委托

事件委托利用冒泡机制，在父元素上处理子元素的事件。

```javascript
// 不好的做法：给每个按钮绑定事件
document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', handleClick);
});

// 好的做法：事件委托
document.querySelector('.container').addEventListener('click', (e) => {
    if (e.target.matches('.btn')) {
        handleClick(e);
    }
    // 或者
    const btn = e.target.closest('.btn');
    if (btn) {
        handleClick(e);
    }
});

// 优点：
// 1. 减少内存占用
// 2. 动态添加的元素也能响应事件
// 3. 代码更简洁
```

### 13.5 常用事件

```javascript
// 鼠标事件
'click'         // 点击
'dblclick'      // 双击
'mousedown'     // 按下
'mouseup'       // 释放
'mousemove'     // 移动
'mouseenter'    // 进入（不冒泡）
'mouseleave'    // 离开（不冒泡）
'mouseover'     // 进入（冒泡）
'mouseout'      // 离开（冒泡）
'contextmenu'   // 右键菜单

// 键盘事件
'keydown'       // 按下
'keyup'         // 释放
'keypress'      // 按键（已废弃）

// 表单事件
'submit'        // 提交
'reset'         // 重置
'input'         // 输入
'change'        // 值改变（失焦后）
'focus'         // 获得焦点
'blur'          // 失去焦点

// 窗口事件
'load'          // 加载完成
'DOMContentLoaded'  // DOM 加载完成
'resize'        // 窗口大小改变
'scroll'        // 滚动

// 触摸事件
'touchstart'    // 触摸开始
'touchmove'     // 触摸移动
'touchend'      // 触摸结束

// 拖拽事件
'dragstart'     // 开始拖拽
'drag'          // 拖拽中
'dragend'       // 拖拽结束
'dragenter'     // 进入目标
'dragleave'     // 离开目标
'dragover'      // 在目标上方
'drop'          // 放下
```

---

## 14. BOM 浏览器对象

### 14.1 window 对象

```javascript
// 窗口尺寸
window.innerWidth;   // 视口宽度
window.innerHeight;  // 视口高度
window.outerWidth;   // 窗口宽度
window.outerHeight;  // 窗口高度

// 滚动
window.scrollX;      // 水平滚动距离
window.scrollY;      // 垂直滚动距离
window.scrollTo(0, 100);
window.scrollBy(0, 50);

// 弹窗
window.alert('消息');
window.confirm('确认？');  // 返回 true/false
window.prompt('请输入');   // 返回输入值或 null

// 打开/关闭窗口
const newWindow = window.open('url', '_blank', 'width=500,height=400');
newWindow.close();

// 定时器
const timeoutId = setTimeout(() => {}, 1000);
clearTimeout(timeoutId);

const intervalId = setInterval(() => {}, 1000);
clearInterval(intervalId);

// requestAnimationFrame（动画推荐）
function animate() {
    // 动画逻辑
    requestAnimationFrame(animate);
}
const animationId = requestAnimationFrame(animate);
cancelAnimationFrame(animationId);
```

### 14.2 location 对象

```javascript
// URL: https://example.com:8080/path/page.html?name=John#section

location.href;      // 完整 URL
location.protocol;  // 'https:'
location.host;      // 'example.com:8080'
location.hostname;  // 'example.com'
location.port;      // '8080'
location.pathname;  // '/path/page.html'
location.search;    // '?name=John'
location.hash;      // '#section'
location.origin;    // 'https://example.com:8080'

// 导航
location.href = 'https://example.com';  // 跳转
location.assign('https://example.com'); // 跳转
location.replace('https://example.com'); // 替换（无历史记录）
location.reload();  // 刷新
location.reload(true);  // 强制刷新

// 解析查询参数
const params = new URLSearchParams(location.search);
params.get('name');     // 'John'
params.has('name');     // true
params.set('age', '25');
params.delete('name');
params.toString();      // 'age=25'
```

### 14.3 history 对象

```javascript
// 历史记录
history.length;         // 历史记录数量
history.back();         // 后退
history.forward();      // 前进
history.go(-2);         // 后退 2 页
history.go(1);          // 前进 1 页

// HTML5 History API
history.pushState({ page: 1 }, 'Title', '/page1');  // 添加历史记录
history.replaceState({ page: 2 }, 'Title', '/page2');  // 替换当前记录

// 监听历史变化
window.addEventListener('popstate', (event) => {
    console.log(event.state);  // { page: 1 }
});
```

### 14.4 navigator 对象

```javascript
// 浏览器信息
navigator.userAgent;    // 用户代理字符串
navigator.language;     // 语言
navigator.languages;    // 语言列表
navigator.platform;     // 平台
navigator.onLine;       // 是否在线
navigator.cookieEnabled; // Cookie 是否启用

// 地理位置
navigator.geolocation.getCurrentPosition(
    (position) => {
        console.log(position.coords.latitude);
        console.log(position.coords.longitude);
    },
    (error) => {
        console.error(error);
    }
);

// 剪贴板
navigator.clipboard.writeText('Hello');
navigator.clipboard.readText().then(text => console.log(text));

// 媒体设备
navigator.mediaDevices.getUserMedia({ video: true, audio: true });
```

### 14.5 存储

```javascript
// localStorage - 永久存储
localStorage.setItem('key', 'value');
localStorage.getItem('key');
localStorage.removeItem('key');
localStorage.clear();
localStorage.length;
localStorage.key(0);  // 获取第 n 个键名

// sessionStorage - 会话存储（关闭标签页清除）
sessionStorage.setItem('key', 'value');
// 方法同 localStorage

// 存储对象
const user = { name: 'John', age: 25 };
localStorage.setItem('user', JSON.stringify(user));
const savedUser = JSON.parse(localStorage.getItem('user'));

// 监听存储变化
window.addEventListener('storage', (event) => {
    console.log(event.key);       // 改变的键
    console.log(event.oldValue);  // 旧值
    console.log(event.newValue);  // 新值
    console.log(event.url);       // 触发变化的页面
});

// Cookie
document.cookie = 'name=John';
document.cookie = 'age=25; expires=Fri, 31 Dec 2024 23:59:59 GMT; path=/';
document.cookie;  // 'name=John; age=25'

// 解析 Cookie
function getCookie(name) {
    const cookies = document.cookie.split('; ');
    for (const cookie of cookies) {
        const [key, value] = cookie.split('=');
        if (key === name) return decodeURIComponent(value);
    }
    return null;
}
```

---

## 15. 错误处理

### 15.1 try...catch

```javascript
// 基本用法
try {
    // 可能出错的代码
    throw new Error('Something went wrong');
} catch (error) {
    // 处理错误
    console.error(error.message);
    console.error(error.stack);
} finally {
    // 无论是否出错都执行
    console.log('Cleanup');
}

// 错误类型
try {
    // ...
} catch (error) {
    if (error instanceof TypeError) {
        console.log('类型错误');
    } else if (error instanceof ReferenceError) {
        console.log('引用错误');
    } else if (error instanceof SyntaxError) {
        console.log('语法错误');
    } else {
        throw error;  // 重新抛出未知错误
    }
}

// 自定义错误
class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

throw new ValidationError('Invalid input');
```

### 15.2 异步错误处理

```javascript
// Promise 错误处理
fetch('/api/data')
    .then(response => response.json())
    .catch(error => {
        console.error('Fetch error:', error);
    });

// async/await 错误处理
async function fetchData() {
    try {
        const response = await fetch('/api/data');
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error:', error);
        throw error;  // 或返回默认值
    }
}

// 全局错误处理
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled rejection:', event.reason);
    event.preventDefault();  // 阻止默认处理
});
```

### 15.3 错误边界模式

```javascript
// 安全执行函数
function safeExecute(fn, fallback = null) {
    try {
        return fn();
    } catch (error) {
        console.error(error);
        return fallback;
    }
}

const result = safeExecute(() => JSON.parse(invalidJson), {});

// 异步安全执行
async function safeAsync(promise, fallback = null) {
    try {
        return await promise;
    } catch (error) {
        console.error(error);
        return fallback;
    }
}

const data = await safeAsync(fetch('/api/data').then(r => r.json()), []);
```

---

## 16. 模块化

### 16.1 ES Modules（推荐）

```javascript
// 导出 - math.js
export const PI = 3.14159;

export function add(a, b) {
    return a + b;
}

export class Calculator {
    // ...
}

// 默认导出
export default function multiply(a, b) {
    return a * b;
}

// 导入 - main.js
import multiply, { PI, add, Calculator } from './math.js';
import * as math from './math.js';  // 导入所有
import { add as sum } from './math.js';  // 重命名

// 动态导入
const module = await import('./math.js');
// 或
import('./math.js').then(module => {
    module.add(1, 2);
});

// 重新导出
export { add, PI } from './math.js';
export * from './math.js';
export { default } from './math.js';
```

```html
<!-- HTML 中使用 -->
<script type="module" src="main.js"></script>
```

### 16.2 CommonJS（Node.js）

```javascript
// 导出 - math.js
const PI = 3.14159;

function add(a, b) {
    return a + b;
}

module.exports = { PI, add };
// 或
exports.PI = PI;
exports.add = add;

// 导入 - main.js
const { PI, add } = require('./math.js');
const math = require('./math.js');
```

### 16.3 模块模式（旧方式）

```javascript
// IIFE 模块模式
const MyModule = (function() {
    // 私有变量
    let privateVar = 0;
    
    // 私有函数
    function privateFunc() {
        return privateVar;
    }
    
    // 公开 API
    return {
        increment() {
            privateVar++;
        },
        getValue() {
            return privateFunc();
        }
    };
})();

MyModule.increment();
MyModule.getValue();  // 1
```

---

## 17. 常见错误汇总

### 错误 #1：== 和 === 混淆

```javascript
// ❌ 错误
if (value == null) { }
if (value == 0) { }

// ✅ 正确
if (value === null || value === undefined) { }
if (value === 0) { }

// 特殊情况：检查 null 或 undefined 可以用 ==
if (value == null) { }  // 等价于 value === null || value === undefined
```

### 错误 #2：this 指向问题

```javascript
// ❌ 错误
const obj = {
    name: 'John',
    greet: () => {
        console.log(this.name);  // undefined（箭头函数没有自己的 this）
    }
};

// ✅ 正确
const obj = {
    name: 'John',
    greet() {
        console.log(this.name);  // 'John'
    }
};

// ❌ 错误：回调中丢失 this
class Counter {
    count = 0;
    increment() {
        this.count++;
    }
}
const counter = new Counter();
setTimeout(counter.increment, 100);  // this 丢失

// ✅ 正确
setTimeout(() => counter.increment(), 100);
setTimeout(counter.increment.bind(counter), 100);
```

### 错误 #3：异步循环问题

```javascript
// ❌ 错误：forEach 不等待异步
async function processItems(items) {
    items.forEach(async (item) => {
        await processItem(item);  // 不会等待
    });
    console.log('Done');  // 立即执行
}

// ✅ 正确：使用 for...of
async function processItems(items) {
    for (const item of items) {
        await processItem(item);
    }
    console.log('Done');  // 全部完成后执行
}

// ✅ 正确：并行处理
async function processItems(items) {
    await Promise.all(items.map(item => processItem(item)));
    console.log('Done');
}
```

### 错误 #4：浅拷贝陷阱

```javascript
// ❌ 错误：以为是深拷贝
const original = { a: 1, b: { c: 2 } };
const copy = { ...original };
copy.b.c = 3;
console.log(original.b.c);  // 3（原对象也被修改了！）

// ✅ 正确：深拷贝
const deepCopy = JSON.parse(JSON.stringify(original));  // 简单对象
const deepCopy2 = structuredClone(original);  // 现代方法（ES2022）
```

### 错误 #5：数组方法返回值

```javascript
// ❌ 错误：forEach 没有返回值
const doubled = [1, 2, 3].forEach(x => x * 2);  // undefined

// ✅ 正确：使用 map
const doubled = [1, 2, 3].map(x => x * 2);  // [2, 4, 6]

// ❌ 错误：sort 会修改原数组
const arr = [3, 1, 2];
const sorted = arr.sort();
console.log(arr);  // [1, 2, 3]（原数组被修改）

// ✅ 正确：先复制
const sorted = [...arr].sort();
const sorted2 = arr.toSorted();  // ES2023
```

### 错误 #6：闭包变量问题

```javascript
// ❌ 错误
for (var i = 0; i < 3; i++) {
    setTimeout(() => console.log(i), 100);
}
// 输出：3, 3, 3

// ✅ 正确：使用 let
for (let i = 0; i < 3; i++) {
    setTimeout(() => console.log(i), 100);
}
// 输出：0, 1, 2
```

### 错误 #7：typeof null

```javascript
// ❌ 错误
if (typeof value === 'object') {
    value.property;  // 如果 value 是 null 会报错
}

// ✅ 正确
if (value !== null && typeof value === 'object') {
    value.property;
}
```

### 错误 #8：浮点数精度

```javascript
// ❌ 错误
0.1 + 0.2 === 0.3;  // false
0.1 + 0.2;          // 0.30000000000000004

// ✅ 正确
Math.abs(0.1 + 0.2 - 0.3) < Number.EPSILON;  // true
(0.1 * 10 + 0.2 * 10) / 10 === 0.3;  // true（转整数计算）
```

### 错误 #9：数组/对象引用

```javascript
// ❌ 错误
const arr1 = [1, 2, 3];
const arr2 = arr1;
arr2.push(4);
console.log(arr1);  // [1, 2, 3, 4]（原数组被修改）

// ✅ 正确
const arr2 = [...arr1];
const arr3 = arr1.slice();
```

### 错误 #10：事件处理器内存泄漏

```javascript
// ❌ 错误：匿名函数无法移除
element.addEventListener('click', () => {
    // ...
});

// ✅ 正确：保存引用以便移除
const handler = () => { /* ... */ };
element.addEventListener('click', handler);
element.removeEventListener('click', handler);

// 组件销毁时清理
class Component {
    constructor() {
        this.handleClick = this.handleClick.bind(this);
        element.addEventListener('click', this.handleClick);
    }
    
    destroy() {
        element.removeEventListener('click', this.handleClick);
    }
}
```

---

## 附录：实用代码片段

### 防抖和节流

```javascript
// 防抖：延迟执行，重复触发会重置计时器
function debounce(fn, delay) {
    let timer = null;
    return function(...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}

// 使用：搜索框输入
const search = debounce((keyword) => {
    console.log('Searching:', keyword);
}, 300);

// 节流：固定时间内只执行一次
function throttle(fn, interval) {
    let lastTime = 0;
    return function(...args) {
        const now = Date.now();
        if (now - lastTime >= interval) {
            lastTime = now;
            fn.apply(this, args);
        }
    };
}

// 使用：滚动事件
window.addEventListener('scroll', throttle(() => {
    console.log('Scrolling');
}, 100));
```

### 深拷贝

```javascript
function deepClone(obj, hash = new WeakMap()) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj);
    if (obj instanceof RegExp) return new RegExp(obj);
    if (hash.has(obj)) return hash.get(obj);  // 处理循环引用
    
    const clone = Array.isArray(obj) ? [] : {};
    hash.set(obj, clone);
    
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            clone[key] = deepClone(obj[key], hash);
        }
    }
    return clone;
}

// 或使用现代方法
const clone = structuredClone(obj);  // ES2022
```

### 类型判断

```javascript
function getType(value) {
    return Object.prototype.toString.call(value).slice(8, -1).toLowerCase();
}

getType([]);        // 'array'
getType({});        // 'object'
getType(null);      // 'null'
getType(undefined); // 'undefined'
getType(new Date()); // 'date'
```

### 数组操作

```javascript
// 数组去重
const unique = [...new Set(arr)];

// 数组扁平化
const flat = arr.flat(Infinity);

// 数组分组
function groupBy(arr, key) {
    return arr.reduce((groups, item) => {
        const group = item[key];
        groups[group] = groups[group] || [];
        groups[group].push(item);
        return groups;
    }, {});
}

// 数组随机排序
const shuffled = arr.sort(() => Math.random() - 0.5);

// 数组交集
const intersection = arr1.filter(x => arr2.includes(x));

// 数组差集
const difference = arr1.filter(x => !arr2.includes(x));
```

### 对象操作

```javascript
// 安全获取嵌套属性
function get(obj, path, defaultValue) {
    return path.split('.').reduce((o, p) => o?.[p], obj) ?? defaultValue;
}
get({ a: { b: { c: 1 } } }, 'a.b.c');  // 1
get({ a: 1 }, 'a.b.c', 'default');     // 'default'

// 对象过滤
function pick(obj, keys) {
    return keys.reduce((result, key) => {
        if (key in obj) result[key] = obj[key];
        return result;
    }, {});
}

function omit(obj, keys) {
    return Object.keys(obj)
        .filter(key => !keys.includes(key))
        .reduce((result, key) => {
            result[key] = obj[key];
            return result;
        }, {});
}
```

### 格式化

```javascript
// 数字格式化
function formatNumber(num) {
    return num.toLocaleString('zh-CN');
}
formatNumber(1234567);  // '1,234,567'

// 日期格式化
function formatDate(date, format = 'YYYY-MM-DD') {
    const d = new Date(date);
    const map = {
        YYYY: d.getFullYear(),
        MM: String(d.getMonth() + 1).padStart(2, '0'),
        DD: String(d.getDate()).padStart(2, '0'),
        HH: String(d.getHours()).padStart(2, '0'),
        mm: String(d.getMinutes()).padStart(2, '0'),
        ss: String(d.getSeconds()).padStart(2, '0')
    };
    return format.replace(/YYYY|MM|DD|HH|mm|ss/g, match => map[match]);
}
formatDate(new Date(), 'YYYY-MM-DD HH:mm:ss');

// 文件大小格式化
function formatFileSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024;
        i++;
    }
    return `${bytes.toFixed(2)} ${units[i]}`;
}
```

---

> 📝 **学习建议**
> 
> 1. 先掌握基础语法，再学习 ES6+ 新特性
> 2. 多写代码，多调试，理解执行过程
> 3. 使用浏览器开发者工具（F12）调试
> 4. 阅读优秀开源项目的代码
> 5. 关注 MDN 文档：https://developer.mozilla.org/zh-CN/docs/Web/JavaScript
> 6. 了解 JavaScript 引擎的工作原理（事件循环、垃圾回收等）
