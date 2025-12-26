

> TypeScript 是 JavaScript 的超集，添加了静态类型检查和其他特性
> 本笔记涵盖从基础到高级的完整 TypeScript 知识体系

---

## 目录

1. [基础概念](#1.基础概念)
2. [基础类型](#2.基础类型)
3. [函数](#3.函数)
4. [接口与类型别名](#4.接口与类型别名)
5. [类](#5.类)
6. [泛型](#6.泛型)
7. [类型操作](#7.类型操作)
8. [高级类型](#8.高级类型)
9. [模块与命名空间](#9.模块与命名空间)
10. [装饰器](#10.装饰器)
11. [类型声明文件](#11.类型声明文件)
12. [常见错误与解决方案](#12.常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 TypeScript？

TypeScript 是由微软开发的开源编程语言，它是 JavaScript 的超集，这意味着任何有效的 JavaScript 代码都是有效的 TypeScript 代码。TypeScript 最大的特点是添加了**静态类型系统**，可以在编译时发现错误，而不是在运行时。

**TypeScript 的优势：**
- **类型安全**：在编译时捕获错误，减少运行时 bug
- **更好的 IDE 支持**：智能提示、自动补全、重构支持
- **代码可读性**：类型注解作为文档，代码更易理解
- **大型项目友好**：更好的代码组织和维护性
- **渐进式采用**：可以逐步将 JavaScript 项目迁移到 TypeScript

### 1.2 环境搭建

```bash
# 全局安装 TypeScript
npm install -g typescript

# 查看版本
tsc --version

# 初始化 TypeScript 项目
tsc --init

# 编译单个文件
tsc hello.ts

# 监听模式编译
tsc --watch

# 使用 ts-node 直接运行 TypeScript
npm install -g ts-node
ts-node hello.ts
```

### 1.3 tsconfig.json 配置

```json
{
  "compilerOptions": {
    // 编译目标
    "target": "ES2020",
    
    // 模块系统
    "module": "ESNext",
    "moduleResolution": "node",
    
    // 严格模式（强烈推荐开启）
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true,
    "strictPropertyInitialization": true,
    "noImplicitThis": true,
    "alwaysStrict": true,
    
    // 额外检查
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    
    // 输出配置
    "outDir": "./dist",
    "rootDir": "./src",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    
    // 路径别名
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@components/*": ["src/components/*"]
    },
    
    // 其他
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

### 1.4 TypeScript 编译过程

```
TypeScript 源码 (.ts)
        │
        ▼
   TypeScript 编译器 (tsc)
        │
        ├── 类型检查（报告错误）
        │
        ▼
   JavaScript 代码 (.js)
        │
        ▼
   JavaScript 运行时执行
```

**重要概念：类型擦除**
TypeScript 的类型信息只存在于编译时，编译后的 JavaScript 代码中不包含任何类型信息。这意味着：
- 类型检查只在编译时进行
- 运行时无法获取类型信息
- 类型不会影响运行时性能

---

## 2. 基础类型

### 2.1 原始类型

```typescript
// ============ 基本类型 ============

// 字符串
let name: string = '张三'
let greeting: string = `Hello, ${name}`

// 数字（整数和浮点数都是 number）
let age: number = 25
let price: number = 99.99
let hex: number = 0xf00d      // 十六进制
let binary: number = 0b1010   // 二进制
let octal: number = 0o744     // 八进制

// 布尔值
let isDone: boolean = false
let isActive: boolean = true

// null 和 undefined
let n: null = null
let u: undefined = undefined

// 在严格模式下，null 和 undefined 不能赋值给其他类型
// let str: string = null  // 错误！

// 可以使用联合类型
let nullableString: string | null = null

// ============ 特殊类型 ============

// bigint（ES2020+）
let bigNumber: bigint = 100n
let anotherBig: bigint = BigInt(100)

// symbol
let sym1: symbol = Symbol('key')
let sym2: symbol = Symbol('key')
console.log(sym1 === sym2)  // false，每个 Symbol 都是唯一的

// unique symbol（唯一符号类型）
const uniqueSym: unique symbol = Symbol('unique')
```

### 2.2 数组类型

```typescript
// ============ 数组 ============

// 方式1：类型[]
let numbers: number[] = [1, 2, 3, 4, 5]
let names: string[] = ['Alice', 'Bob', 'Charlie']

// 方式2：Array<类型>（泛型语法）
let scores: Array<number> = [90, 85, 92]
let items: Array<string> = ['a', 'b', 'c']

// 只读数组
let readonlyArr: readonly number[] = [1, 2, 3]
let readonlyArr2: ReadonlyArray<number> = [1, 2, 3]
// readonlyArr.push(4)  // 错误！只读数组不能修改

// 多维数组
let matrix: number[][] = [
  [1, 2, 3],
  [4, 5, 6],
  [7, 8, 9]
]

// 混合类型数组（使用联合类型）
let mixed: (string | number)[] = [1, 'two', 3, 'four']
```

### 2.3 元组类型

```typescript
// ============ 元组（Tuple） ============
// 元组是固定长度和类型的数组

// 基本元组
let tuple: [string, number] = ['张三', 25]
// tuple = [25, '张三']  // 错误！类型顺序不对
// tuple = ['张三']      // 错误！长度不对

// 访问元组元素
let userName: string = tuple[0]
let userAge: number = tuple[1]

// 解构元组
let [tName, tAge] = tuple

// 可选元素
let optionalTuple: [string, number?] = ['张三']
let optionalTuple2: [string, number?] = ['张三', 25]

// 剩余元素
let restTuple: [string, ...number[]] = ['scores', 90, 85, 92, 88]

// 只读元组
let readonlyTuple: readonly [string, number] = ['张三', 25]
// readonlyTuple[0] = '李四'  // 错误！

// 命名元组（TypeScript 4.0+）
type NamedTuple = [name: string, age: number, active?: boolean]
let person: NamedTuple = ['张三', 25]
```

### 2.4 特殊类型

```typescript
// ============ any 类型 ============
// any 表示任意类型，关闭类型检查（尽量避免使用）
let anything: any = 'hello'
anything = 123
anything = true
anything.foo.bar  // 不会报错，但运行时可能出错

// ============ unknown 类型 ============
// unknown 是类型安全的 any，必须先进行类型检查才能使用
let unknownValue: unknown = 'hello'

// unknownValue.toUpperCase()  // 错误！不能直接使用

// 必须先进行类型检查
if (typeof unknownValue === 'string') {
  console.log(unknownValue.toUpperCase())  // 正确
}

// 或使用类型断言
let str = unknownValue as string

// ============ void 类型 ============
// void 表示没有返回值
function logMessage(message: string): void {
  console.log(message)
  // 没有 return 或 return undefined
}

// void 类型的变量只能赋值 undefined
let voidValue: void = undefined

// ============ never 类型 ============
// never 表示永远不会有值（函数永远不会正常返回）

// 抛出异常的函数
function throwError(message: string): never {
  throw new Error(message)
}

// 无限循环的函数
function infiniteLoop(): never {
  while (true) {
    // ...
  }
}

// never 用于穷尽检查
type Shape = 'circle' | 'square' | 'triangle'

function getArea(shape: Shape): number {
  switch (shape) {
    case 'circle':
      return Math.PI * 10 * 10
    case 'square':
      return 10 * 10
    case 'triangle':
      return (10 * 10) / 2
    default:
      // 如果所有情况都处理了，这里的 shape 类型是 never
      const exhaustiveCheck: never = shape
      return exhaustiveCheck
  }
}

// ============ object 类型 ============
// object 表示非原始类型
let obj: object = { name: '张三' }
let arr: object = [1, 2, 3]
let fn: object = function() {}

// obj.name  // 错误！object 类型不能访问属性

// 使用具体的对象类型
let user: { name: string; age: number } = {
  name: '张三',
  age: 25
}
```

### 2.5 类型推断与类型断言

```typescript
// ============ 类型推断 ============
// TypeScript 会自动推断变量类型

let inferredString = 'hello'  // 推断为 string
let inferredNumber = 123      // 推断为 number
let inferredArray = [1, 2, 3] // 推断为 number[]

// 最佳通用类型
let mixedArray = [1, 'two', null]  // 推断为 (string | number | null)[]

// 上下文类型推断
window.addEventListener('click', (event) => {
  // event 自动推断为 MouseEvent
  console.log(event.clientX, event.clientY)
})

// ============ 类型断言 ============
// 告诉编译器"我知道这个值的类型"

// 方式1：as 语法（推荐）
let someValue: unknown = 'hello world'
let strLength: number = (someValue as string).length

// 方式2：尖括号语法（在 JSX 中不能使用）
let strLength2: number = (<string>someValue).length

// 双重断言（谨慎使用）
let value: string = 'hello'
// let num: number = value as number  // 错误！
let num: number = value as unknown as number  // 可以，但危险

// const 断言
let literalArray = [1, 2, 3] as const  // readonly [1, 2, 3]
let literalObject = { name: '张三', age: 25 } as const
// literalObject.name = '李四'  // 错误！只读

// 非空断言（!）
function getValue(): string | undefined {
  return 'hello'
}
let value2: string = getValue()!  // 断言不为 undefined

// ============ 类型守卫 ============
// 类型守卫用于在运行时缩小类型范围

// typeof 守卫
function padLeft(value: string, padding: string | number): string {
  if (typeof padding === 'number') {
    return ' '.repeat(padding) + value
  }
  return padding + value
}

// instanceof 守卫
class Dog {
  bark() { console.log('Woof!') }
}
class Cat {
  meow() { console.log('Meow!') }
}

function makeSound(animal: Dog | Cat) {
  if (animal instanceof Dog) {
    animal.bark()
  } else {
    animal.meow()
  }
}

// in 守卫
interface Fish {
  swim: () => void
}
interface Bird {
  fly: () => void
}

function move(animal: Fish | Bird) {
  if ('swim' in animal) {
    animal.swim()
  } else {
    animal.fly()
  }
}

// 自定义类型守卫
function isFish(animal: Fish | Bird): animal is Fish {
  return (animal as Fish).swim !== undefined
}

function doSomething(animal: Fish | Bird) {
  if (isFish(animal)) {
    animal.swim()  // TypeScript 知道这里是 Fish
  } else {
    animal.fly()   // TypeScript 知道这里是 Bird
  }
}
```

---

## 3. 函数

### 3.1 函数类型

```typescript
// ============ 函数声明 ============

// 基本函数声明
function add(a: number, b: number): number {
  return a + b
}

// 函数表达式
const subtract = function(a: number, b: number): number {
  return a - b
}

// 箭头函数
const multiply = (a: number, b: number): number => a * b

// 完整的函数类型注解
const divide: (a: number, b: number) => number = (a, b) => a / b

// ============ 可选参数和默认参数 ============

// 可选参数（必须放在必选参数后面）
function greet(name: string, greeting?: string): string {
  return `${greeting || 'Hello'}, ${name}!`
}
greet('张三')           // "Hello, 张三!"
greet('张三', '你好')   // "你好, 张三!"

// 默认参数
function greet2(name: string, greeting: string = 'Hello'): string {
  return `${greeting}, ${name}!`
}

// 默认参数可以放在任意位置
function greet3(greeting: string = 'Hello', name: string): string {
  return `${greeting}, ${name}!`
}
greet3(undefined, '张三')  // "Hello, 张三!"

// ============ 剩余参数 ============

function sum(...numbers: number[]): number {
  return numbers.reduce((acc, curr) => acc + curr, 0)
}
sum(1, 2, 3, 4, 5)  // 15

// 剩余参数与其他参数组合
function buildName(firstName: string, ...restNames: string[]): string {
  return firstName + ' ' + restNames.join(' ')
}

// ============ 函数重载 ============

// 重载签名
function format(value: string): string
function format(value: number): string
function format(value: Date): string

// 实现签名
function format(value: string | number | Date): string {
  if (typeof value === 'string') {
    return value.trim()
  } else if (typeof value === 'number') {
    return value.toFixed(2)
  } else {
    return value.toISOString()
  }
}

format('  hello  ')  // "hello"
format(3.14159)      // "3.14"
format(new Date())   // ISO 日期字符串

// 更复杂的重载示例
function createElement(tag: 'div'): HTMLDivElement
function createElement(tag: 'span'): HTMLSpanElement
function createElement(tag: 'input'): HTMLInputElement
function createElement(tag: string): HTMLElement {
  return document.createElement(tag)
}

const div = createElement('div')    // HTMLDivElement
const span = createElement('span')  // HTMLSpanElement
```

### 3.2 this 类型

```typescript
// ============ this 参数 ============

interface User {
  name: string
  greet(this: User): void
}

const user: User = {
  name: '张三',
  greet() {
    console.log(`Hello, ${this.name}`)
  }
}

user.greet()  // 正确

// const greetFn = user.greet
// greetFn()  // 错误！this 上下文不对

// ============ this 类型 ============

class Calculator {
  private value: number = 0
  
  add(n: number): this {
    this.value += n
    return this
  }
  
  subtract(n: number): this {
    this.value -= n
    return this
  }
  
  multiply(n: number): this {
    this.value *= n
    return this
  }
  
  getValue(): number {
    return this.value
  }
}

// 链式调用
const result = new Calculator()
  .add(10)
  .subtract(3)
  .multiply(2)
  .getValue()  // 14

// 子类继承时 this 类型会正确推断
class ScientificCalculator extends Calculator {
  sin(): this {
    this['value'] = Math.sin(this.getValue())
    return this
  }
}
```

---

## 4. 接口与类型别名

### 4.1 接口（Interface）

```typescript
// ============ 基本接口 ============

interface User {
  name: string
  age: number
  email: string
}

const user: User = {
  name: '张三',
  age: 25,
  email: 'zhangsan@example.com'
}

// ============ 可选属性和只读属性 ============

interface Config {
  readonly id: number      // 只读属性
  name: string
  description?: string     // 可选属性
  readonly tags?: string[] // 只读可选属性
}

const config: Config = {
  id: 1,
  name: 'My Config'
}

// config.id = 2  // 错误！只读属性不能修改

// ============ 索引签名 ============

// 字符串索引签名
interface StringDictionary {
  [key: string]: string
}

const dict: StringDictionary = {
  name: '张三',
  city: '北京'
}

// 数字索引签名
interface NumberArray {
  [index: number]: string
}

const arr: NumberArray = ['a', 'b', 'c']

// 混合索引签名
interface MixedDictionary {
  [key: string]: string | number
  length: number  // 必须兼容索引签名的类型
}

// ============ 函数类型接口 ============

interface SearchFunc {
  (source: string, subString: string): boolean
}

const search: SearchFunc = (source, subString) => {
  return source.includes(subString)
}

// ============ 可调用接口 ============

interface CallableInterface {
  (x: number, y: number): number
  description: string
}

const add: CallableInterface = Object.assign(
  (x: number, y: number) => x + y,
  { description: '加法函数' }
)

// ============ 构造函数接口 ============

interface ClockConstructor {
  new (hour: number, minute: number): ClockInterface
}

interface ClockInterface {
  tick(): void
}

// ============ 接口继承 ============

interface Animal {
  name: string
}

interface Mammal extends Animal {
  warmBlooded: true
}

interface Dog extends Mammal {
  breed: string
  bark(): void
}

// 多重继承
interface Pet extends Animal, Mammal {
  owner: string
}

// ============ 接口合并 ============
// 同名接口会自动合并

interface Box {
  width: number
  height: number
}

interface Box {
  depth: number
}

// Box 现在有 width, height, depth 三个属性
const box: Box = {
  width: 10,
  height: 20,
  depth: 30
}
```

### 4.2 类型别名（Type Alias）

```typescript
// ============ 基本类型别名 ============

type ID = string | number
type Name = string

let userId: ID = 123
userId = 'abc123'

// ============ 对象类型别名 ============

type User = {
  name: string
  age: number
  email?: string
}

// ============ 联合类型 ============

type Status = 'pending' | 'approved' | 'rejected'
type Result = Success | Failure

type Success = {
  success: true
  data: any
}

type Failure = {
  success: false
  error: string
}

// ============ 交叉类型 ============

type Person = {
  name: string
  age: number
}

type Employee = {
  employeeId: string
  department: string
}

type EmployeePerson = Person & Employee

const employee: EmployeePerson = {
  name: '张三',
  age: 25,
  employeeId: 'E001',
  department: '技术部'
}

// ============ 函数类型别名 ============

type MathOperation = (a: number, b: number) => number

const add: MathOperation = (a, b) => a + b
const subtract: MathOperation = (a, b) => a - b

// ============ 泛型类型别名 ============

type Container<T> = {
  value: T
}

type Nullable<T> = T | null
type Optional<T> = T | undefined

// ============ 条件类型别名 ============

type IsString<T> = T extends string ? true : false

type A = IsString<string>  // true
type B = IsString<number>  // false

// ============ 模板字面量类型 ============

type EventName = 'click' | 'focus' | 'blur'
type EventHandler = `on${Capitalize<EventName>}`
// 'onClick' | 'onFocus' | 'onBlur'
```

### 4.3 Interface vs Type

```typescript
// ============ 相同点 ============

// 都可以描述对象
interface IUser {
  name: string
  age: number
}

type TUser = {
  name: string
  age: number
}

// 都可以扩展
interface IAnimal {
  name: string
}
interface IDog extends IAnimal {
  breed: string
}

type TAnimal = {
  name: string
}
type TDog = TAnimal & {
  breed: string
}

// 接口可以扩展类型别名，类型别名也可以扩展接口
interface IExtended extends TAnimal {
  age: number
}

type TExtended = IAnimal & {
  age: number
}

// ============ 不同点 ============

// 1. 类型别名可以用于原始类型、联合类型、元组
type ID = string | number
type Tuple = [string, number]
type Primitive = string

// 接口不能

// 2. 接口可以声明合并
interface Box {
  width: number
}
interface Box {
  height: number
}
// Box 有 width 和 height

// 类型别名不能重复声明
// type Box = { width: number }
// type Box = { height: number }  // 错误！

// 3. 接口可以被类实现
interface Printable {
  print(): void
}

class Document implements Printable {
  print() {
    console.log('Printing...')
  }
}

// ============ 推荐使用场景 ============
// - 定义对象结构：优先使用 interface
// - 需要联合类型、交叉类型、元组：使用 type
// - 需要声明合并：使用 interface
// - 需要计算属性：使用 type
```

---

## 5. 类

### 5.1 类的基础

```typescript
// ============ 基本类定义 ============

class Person {
  // 属性声明
  name: string
  age: number
  
  // 构造函数
  constructor(name: string, age: number) {
    this.name = name
    this.age = age
  }
  
  // 方法
  greet(): string {
    return `Hello, I'm ${this.name}`
  }
}

const person = new Person('张三', 25)
console.log(person.greet())

// ============ 访问修饰符 ============

class Employee {
  public name: string       // 公开（默认）
  private salary: number    // 私有，只能在类内部访问
  protected department: string  // 受保护，可以在子类中访问
  readonly id: string       // 只读
  
  constructor(name: string, salary: number, department: string) {
    this.name = name
    this.salary = salary
    this.department = department
    this.id = Math.random().toString(36).substr(2, 9)
  }
  
  // 私有方法
  private calculateBonus(): number {
    return this.salary * 0.1
  }
  
  // 公开方法访问私有属性
  public getAnnualSalary(): number {
    return this.salary * 12 + this.calculateBonus()
  }
}

const emp = new Employee('张三', 10000, '技术部')
console.log(emp.name)        // 正确
// console.log(emp.salary)   // 错误！私有属性
// console.log(emp.department)  // 错误！受保护属性

// ============ 参数属性 ============
// 在构造函数参数中直接声明和初始化属性

class User {
  constructor(
    public name: string,
    private age: number,
    readonly id: string
  ) {
    // 不需要手动赋值
  }
}

// ============ Getter 和 Setter ============

class Circle {
  private _radius: number = 0
  
  get radius(): number {
    return this._radius
  }
  
  set radius(value: number) {
    if (value < 0) {
      throw new Error('半径不能为负数')
    }
    this._radius = value
  }
  
  get area(): number {
    return Math.PI * this._radius ** 2
  }
}

const circle = new Circle()
circle.radius = 5
console.log(circle.area)  // 78.54...
```

### 5.2 继承与多态

```typescript
// ============ 类继承 ============

class Animal {
  constructor(public name: string) {}
  
  move(distance: number = 0): void {
    console.log(`${this.name} moved ${distance}m`)
  }
}

class Dog extends Animal {
  constructor(name: string, public breed: string) {
    super(name)  // 调用父类构造函数
  }
  
  // 重写父类方法
  move(distance: number = 5): void {
    console.log('Running...')
    super.move(distance)  // 调用父类方法
  }
  
  // 子类特有方法
  bark(): void {
    console.log('Woof! Woof!')
  }
}

class Bird extends Animal {
  fly(distance: number = 10): void {
    console.log(`${this.name} flew ${distance}m`)
  }
  
  move(distance: number = 10): void {
    console.log('Flying...')
    this.fly(distance)
  }
}

// 多态
const animals: Animal[] = [
  new Dog('旺财', '金毛'),
  new Bird('小鸟')
]

animals.forEach(animal => {
  animal.move()  // 调用各自的 move 方法
})

// ============ 抽象类 ============

abstract class Shape {
  abstract name: string
  
  // 抽象方法（子类必须实现）
  abstract getArea(): number
  abstract getPerimeter(): number
  
  // 普通方法
  describe(): string {
    return `This is a ${this.name} with area ${this.getArea()}`
  }
}

class Rectangle extends Shape {
  name = 'Rectangle'
  
  constructor(
    private width: number,
    private height: number
  ) {
    super()
  }
  
  getArea(): number {
    return this.width * this.height
  }
  
  getPerimeter(): number {
    return 2 * (this.width + this.height)
  }
}

// const shape = new Shape()  // 错误！不能实例化抽象类
const rect = new Rectangle(10, 5)
console.log(rect.describe())
```

### 5.3 接口实现

```typescript
// ============ 类实现接口 ============

interface Printable {
  print(): void
}

interface Loggable {
  log(message: string): void
}

// 实现多个接口
class Document implements Printable, Loggable {
  constructor(public content: string) {}
  
  print(): void {
    console.log(`Printing: ${this.content}`)
  }
  
  log(message: string): void {
    console.log(`[LOG] ${message}`)
  }
}

// ============ 接口继承类 ============

class Control {
  private state: any
}

// 接口继承类，会继承类的成员（包括私有成员的类型）
interface SelectableControl extends Control {
  select(): void
}

// 只有 Control 的子类才能实现 SelectableControl
class Button extends Control implements SelectableControl {
  select(): void {
    console.log('Button selected')
  }
}

// class Image implements SelectableControl {  // 错误！
//   select(): void {}
// }
```

### 5.4 静态成员

```typescript
class MathUtils {
  // 静态属性
  static PI: number = 3.14159265359
  
  // 静态方法
  static add(a: number, b: number): number {
    return a + b
  }
  
  static multiply(a: number, b: number): number {
    return a * b
  }
  
  // 静态块（TypeScript 4.4+）
  static {
    console.log('MathUtils class initialized')
  }
}

// 通过类名访问静态成员
console.log(MathUtils.PI)
console.log(MathUtils.add(1, 2))

// 单例模式
class Singleton {
  private static instance: Singleton
  
  private constructor() {}
  
  static getInstance(): Singleton {
    if (!Singleton.instance) {
      Singleton.instance = new Singleton()
    }
    return Singleton.instance
  }
}

const s1 = Singleton.getInstance()
const s2 = Singleton.getInstance()
console.log(s1 === s2)  // true
```

---

## 6. 泛型

### 6.1 泛型基础

```typescript
// ============ 为什么需要泛型？ ============

// 不使用泛型：需要为每种类型写重复代码
function identityNumber(arg: number): number {
  return arg
}
function identityString(arg: string): string {
  return arg
}

// 使用 any：失去类型检查
function identityAny(arg: any): any {
  return arg
}

// 使用泛型：保持类型安全，代码复用
function identity<T>(arg: T): T {
  return arg
}

// 使用泛型函数
let output1 = identity<string>('hello')  // 显式指定类型
let output2 = identity('hello')          // 类型推断
let output3 = identity(123)              // number

// ============ 泛型函数 ============

// 多个类型参数
function pair<T, U>(first: T, second: U): [T, U] {
  return [first, second]
}

const p = pair('hello', 123)  // [string, number]

// 泛型约束
function getLength<T extends { length: number }>(arg: T): number {
  return arg.length
}

getLength('hello')     // 5
getLength([1, 2, 3])   // 3
// getLength(123)      // 错误！number 没有 length 属性

// 使用接口约束
interface Lengthwise {
  length: number
}

function logLength<T extends Lengthwise>(arg: T): T {
  console.log(arg.length)
  return arg
}

// ============ keyof 约束 ============

function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
  return obj[key]
}

const person = { name: '张三', age: 25 }
const name = getProperty(person, 'name')  // string
const age = getProperty(person, 'age')    // number
// getProperty(person, 'email')  // 错误！'email' 不是 person 的键
```

### 6.2 泛型接口和类型

```typescript
// ============ 泛型接口 ============

interface GenericIdentityFn<T> {
  (arg: T): T
}

const myIdentity: GenericIdentityFn<number> = (arg) => arg

// 泛型接口描述对象
interface Container<T> {
  value: T
  getValue(): T
  setValue(value: T): void
}

// ============ 泛型类型别名 ============

type Result<T> = {
  success: boolean
  data: T
  error?: string
}

type ApiResponse<T> = Result<T> & {
  statusCode: number
  timestamp: Date
}

// 使用
const userResponse: ApiResponse<{ name: string; age: number }> = {
  success: true,
  data: { name: '张三', age: 25 },
  statusCode: 200,
  timestamp: new Date()
}

// ============ 泛型默认值 ============

interface PaginatedResult<T = any> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

// 使用默认类型
const result1: PaginatedResult = {
  items: [1, 2, 3],
  total: 100,
  page: 1,
  pageSize: 10
}

// 指定类型
const result2: PaginatedResult<string> = {
  items: ['a', 'b', 'c'],
  total: 100,
  page: 1,
  pageSize: 10
}
```

### 6.3 泛型类

```typescript
// ============ 泛型类 ============

class GenericNumber<T> {
  zeroValue: T
  add: (x: T, y: T) => T
  
  constructor(zeroValue: T, addFn: (x: T, y: T) => T) {
    this.zeroValue = zeroValue
    this.add = addFn
  }
}

const myNumber = new GenericNumber<number>(0, (x, y) => x + y)
const myString = new GenericNumber<string>('', (x, y) => x + y)

// ============ 泛型栈 ============

class Stack<T> {
  private items: T[] = []
  
  push(item: T): void {
    this.items.push(item)
  }
  
  pop(): T | undefined {
    return this.items.pop()
  }
  
  peek(): T | undefined {
    return this.items[this.items.length - 1]
  }
  
  isEmpty(): boolean {
    return this.items.length === 0
  }
  
  size(): number {
    return this.items.length
  }
}

const numberStack = new Stack<number>()
numberStack.push(1)
numberStack.push(2)
console.log(numberStack.pop())  // 2

// ============ 泛型仓库模式 ============

interface Entity {
  id: string | number
}

class Repository<T extends Entity> {
  private items: Map<string | number, T> = new Map()
  
  add(item: T): void {
    this.items.set(item.id, item)
  }
  
  get(id: string | number): T | undefined {
    return this.items.get(id)
  }
  
  getAll(): T[] {
    return Array.from(this.items.values())
  }
  
  remove(id: string | number): boolean {
    return this.items.delete(id)
  }
  
  update(item: T): void {
    if (this.items.has(item.id)) {
      this.items.set(item.id, item)
    }
  }
}

interface User extends Entity {
  id: number
  name: string
  email: string
}

const userRepo = new Repository<User>()
userRepo.add({ id: 1, name: '张三', email: 'zhangsan@example.com' })
```

### 6.4 泛型工具类型

```typescript
// ============ 内置泛型工具类型 ============

interface User {
  id: number
  name: string
  email: string
  age: number
}

// Partial<T> - 所有属性变为可选
type PartialUser = Partial<User>
// { id?: number; name?: string; email?: string; age?: number }

// Required<T> - 所有属性变为必选
type RequiredUser = Required<PartialUser>

// Readonly<T> - 所有属性变为只读
type ReadonlyUser = Readonly<User>

// Pick<T, K> - 选取部分属性
type UserBasic = Pick<User, 'id' | 'name'>
// { id: number; name: string }

// Omit<T, K> - 排除部分属性
type UserWithoutEmail = Omit<User, 'email'>
// { id: number; name: string; age: number }

// Record<K, T> - 创建键值对类型
type UserRecord = Record<string, User>
// { [key: string]: User }

type Status = 'pending' | 'approved' | 'rejected'
type StatusMessages = Record<Status, string>
// { pending: string; approved: string; rejected: string }

// Exclude<T, U> - 从联合类型中排除
type T1 = Exclude<'a' | 'b' | 'c', 'a'>  // 'b' | 'c'

// Extract<T, U> - 从联合类型中提取
type T2 = Extract<'a' | 'b' | 'c', 'a' | 'f'>  // 'a'

// NonNullable<T> - 排除 null 和 undefined
type T3 = NonNullable<string | null | undefined>  // string

// ReturnType<T> - 获取函数返回类型
function getUser() {
  return { id: 1, name: '张三' }
}
type UserReturn = ReturnType<typeof getUser>
// { id: number; name: string }

// Parameters<T> - 获取函数参数类型
function createUser(name: string, age: number): User {
  return { id: 1, name, email: '', age }
}
type CreateUserParams = Parameters<typeof createUser>
// [string, number]

// InstanceType<T> - 获取构造函数实例类型
class MyClass {
  x = 0
  y = 0
}
type MyInstance = InstanceType<typeof MyClass>
// MyClass
```

---

## 7. 类型操作

### 7.1 联合类型与交叉类型

```typescript
// ============ 联合类型（Union Types） ============
// 表示"或"的关系，值可以是多种类型之一

type StringOrNumber = string | number

let value: StringOrNumber = 'hello'
value = 123  // 也可以

// 联合类型只能访问共有成员
function printId(id: string | number) {
  // console.log(id.toUpperCase())  // 错误！number 没有 toUpperCase
  console.log(id.toString())  // 正确，两者都有 toString
  
  // 类型收窄后可以访问特定成员
  if (typeof id === 'string') {
    console.log(id.toUpperCase())
  }
}

// 字面量联合类型
type Direction = 'up' | 'down' | 'left' | 'right'
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'
type StatusCode = 200 | 201 | 400 | 404 | 500

// 可辨识联合（Discriminated Unions）
interface Circle {
  kind: 'circle'
  radius: number
}

interface Square {
  kind: 'square'
  sideLength: number
}

interface Rectangle {
  kind: 'rectangle'
  width: number
  height: number
}

type Shape = Circle | Square | Rectangle

function getArea(shape: Shape): number {
  switch (shape.kind) {
    case 'circle':
      return Math.PI * shape.radius ** 2
    case 'square':
      return shape.sideLength ** 2
    case 'rectangle':
      return shape.width * shape.height
  }
}

// ============ 交叉类型（Intersection Types） ============
// 表示"且"的关系，合并多个类型

interface Person {
  name: string
  age: number
}

interface Employee {
  employeeId: string
  department: string
}

type EmployeePerson = Person & Employee

const emp: EmployeePerson = {
  name: '张三',
  age: 25,
  employeeId: 'E001',
  department: '技术部'
}

// 交叉类型合并同名属性
interface A {
  x: number
  y: string
}

interface B {
  x: number  // 相同类型，保留
  z: boolean
}

type AB = A & B
// { x: number; y: string; z: boolean }

// 冲突的属性类型会变成 never
interface C {
  x: string  // 与 A 的 x 类型冲突
}

type AC = A & C
// x 的类型是 number & string = never
```

### 7.2 类型收窄

```typescript
// ============ typeof 收窄 ============

function padLeft(padding: number | string, input: string): string {
  if (typeof padding === 'number') {
    return ' '.repeat(padding) + input
  }
  return padding + input
}

// ============ 真值收窄 ============

function printAll(strs: string | string[] | null) {
  if (strs) {  // 排除 null 和空字符串
    if (typeof strs === 'object') {
      for (const s of strs) {
        console.log(s)
      }
    } else {
      console.log(strs)
    }
  }
}

// ============ 相等性收窄 ============

function example(x: string | number, y: string | boolean) {
  if (x === y) {
    // x 和 y 都是 string
    console.log(x.toUpperCase())
  }
}

// ============ in 操作符收窄 ============

interface Fish {
  swim(): void
}

interface Bird {
  fly(): void
}

function move(animal: Fish | Bird) {
  if ('swim' in animal) {
    animal.swim()
  } else {
    animal.fly()
  }
}

// ============ instanceof 收窄 ============

function logValue(x: Date | string) {
  if (x instanceof Date) {
    console.log(x.toUTCString())
  } else {
    console.log(x.toUpperCase())
  }
}

// ============ 类型谓词（Type Predicates） ============

function isFish(pet: Fish | Bird): pet is Fish {
  return (pet as Fish).swim !== undefined
}

function getSmallPet(): Fish | Bird {
  return Math.random() > 0.5 
    ? { swim: () => console.log('swimming') }
    : { fly: () => console.log('flying') }
}

const pet = getSmallPet()
if (isFish(pet)) {
  pet.swim()
} else {
  pet.fly()
}

// ============ 断言函数（Assertion Functions） ============

function assertIsString(val: unknown): asserts val is string {
  if (typeof val !== 'string') {
    throw new Error('Not a string!')
  }
}

function processValue(value: unknown) {
  assertIsString(value)
  // 这里 value 的类型是 string
  console.log(value.toUpperCase())
}
```

### 7.3 keyof 和 typeof

```typescript
// ============ keyof 操作符 ============
// 获取对象类型的所有键的联合类型

interface Person {
  name: string
  age: number
  email: string
}

type PersonKeys = keyof Person  // 'name' | 'age' | 'email'

// 用于约束函数参数
function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
  return obj[key]
}

const person: Person = { name: '张三', age: 25, email: 'test@example.com' }
const name = getProperty(person, 'name')  // string
const age = getProperty(person, 'age')    // number

// keyof 与索引签名
interface StringMap {
  [key: string]: string
}
type StringMapKeys = keyof StringMap  // string | number

// ============ typeof 操作符 ============
// 获取值的类型

const user = {
  name: '张三',
  age: 25,
  address: {
    city: '北京',
    street: '长安街'
  }
}

type User = typeof user
// {
//   name: string;
//   age: number;
//   address: {
//     city: string;
//     street: string;
//   }
// }

// 获取函数类型
function createUser(name: string, age: number) {
  return { name, age, id: Math.random() }
}

type CreateUserFn = typeof createUser
// (name: string, age: number) => { name: string; age: number; id: number }

// 结合 ReturnType
type UserType = ReturnType<typeof createUser>
// { name: string; age: number; id: number }

// ============ 索引访问类型 ============

type PersonName = Person['name']  // string
type PersonAge = Person['age']    // number

// 使用联合类型索引
type PersonNameOrAge = Person['name' | 'age']  // string | number

// 使用 keyof
type PersonValues = Person[keyof Person]  // string | number

// 数组元素类型
const MyArray = [
  { name: '张三', age: 25 },
  { name: '李四', age: 30 }
]

type ArrayElement = typeof MyArray[number]
// { name: string; age: number }

type AgeType = typeof MyArray[number]['age']  // number
```

---

## 8. 高级类型

### 8.1 条件类型

```typescript
// ============ 基本条件类型 ============
// T extends U ? X : Y

type IsString<T> = T extends string ? true : false

type A = IsString<string>   // true
type B = IsString<number>   // false
type C = IsString<'hello'>  // true

// ============ 条件类型与联合类型 ============
// 条件类型会分发到联合类型的每个成员

type ToArray<T> = T extends any ? T[] : never

type StrOrNumArray = ToArray<string | number>
// string[] | number[]（不是 (string | number)[]）

// 阻止分发行为
type ToArrayNonDist<T> = [T] extends [any] ? T[] : never

type StrOrNumArray2 = ToArrayNonDist<string | number>
// (string | number)[]

// ============ infer 关键字 ============
// 在条件类型中推断类型

// 获取函数返回类型
type MyReturnType<T> = T extends (...args: any[]) => infer R ? R : never

type FnReturn = MyReturnType<() => string>  // string
type FnReturn2 = MyReturnType<(x: number) => boolean>  // boolean

// 获取函数参数类型
type MyParameters<T> = T extends (...args: infer P) => any ? P : never

type FnParams = MyParameters<(a: string, b: number) => void>
// [a: string, b: number]

// 获取数组元素类型
type ArrayElement<T> = T extends (infer E)[] ? E : never

type Elem = ArrayElement<string[]>  // string
type Elem2 = ArrayElement<[string, number]>  // string | number

// 获取 Promise 解析类型
type Awaited<T> = T extends Promise<infer U> ? Awaited<U> : T

type PromiseResult = Awaited<Promise<string>>  // string
type NestedPromise = Awaited<Promise<Promise<number>>>  // number

// ============ 实用条件类型 ============

// 提取函数类型
type FunctionPropertyNames<T> = {
  [K in keyof T]: T[K] extends Function ? K : never
}[keyof T]

interface Part {
  id: number
  name: string
  updatePart(newName: string): void
  deletePart(): void
}

type FnNames = FunctionPropertyNames<Part>
// 'updatePart' | 'deletePart'

// 提取非函数属性
type NonFunctionPropertyNames<T> = {
  [K in keyof T]: T[K] extends Function ? never : K
}[keyof T]

type DataNames = NonFunctionPropertyNames<Part>
// 'id' | 'name'
```

### 8.2 映射类型

```typescript
// ============ 基本映射类型 ============

type OptionsFlags<T> = {
  [K in keyof T]: boolean
}

interface Features {
  darkMode: () => void
  newUserProfile: () => void
}

type FeatureFlags = OptionsFlags<Features>
// { darkMode: boolean; newUserProfile: boolean }

// ============ 映射修饰符 ============

// 添加 readonly
type Readonly<T> = {
  readonly [K in keyof T]: T[K]
}

// 移除 readonly
type Mutable<T> = {
  -readonly [K in keyof T]: T[K]
}

// 添加可选
type Partial<T> = {
  [K in keyof T]?: T[K]
}

// 移除可选
type Required<T> = {
  [K in keyof T]-?: T[K]
}

// ============ 键重映射（as 子句） ============

// 重命名键
type Getters<T> = {
  [K in keyof T as `get${Capitalize<string & K>}`]: () => T[K]
}

interface Person {
  name: string
  age: number
}

type PersonGetters = Getters<Person>
// { getName: () => string; getAge: () => number }

// 过滤键
type RemoveKind<T> = {
  [K in keyof T as Exclude<K, 'kind'>]: T[K]
}

interface Circle {
  kind: 'circle'
  radius: number
}

type CircleWithoutKind = RemoveKind<Circle>
// { radius: number }

// 只保留特定类型的属性
type OnlyStringProperties<T> = {
  [K in keyof T as T[K] extends string ? K : never]: T[K]
}

interface Mixed {
  name: string
  age: number
  email: string
  active: boolean
}

type StringProps = OnlyStringProperties<Mixed>
// { name: string; email: string }

// ============ 深度映射 ============

type DeepReadonly<T> = {
  readonly [K in keyof T]: T[K] extends object
    ? DeepReadonly<T[K]>
    : T[K]
}

interface NestedObject {
  name: string
  address: {
    city: string
    street: string
  }
}

type ReadonlyNested = DeepReadonly<NestedObject>
// 所有嵌套属性都是只读的
```

### 8.3 模板字面量类型

```typescript
// ============ 基本模板字面量类型 ============

type World = 'world'
type Greeting = `hello ${World}`  // 'hello world'

// 联合类型展开
type Color = 'red' | 'green' | 'blue'
type Size = 'small' | 'medium' | 'large'

type ColorSize = `${Color}-${Size}`
// 'red-small' | 'red-medium' | 'red-large' |
// 'green-small' | 'green-medium' | 'green-large' |
// 'blue-small' | 'blue-medium' | 'blue-large'

// ============ 内置字符串操作类型 ============

type Uppercase<S extends string> = intrinsic
type Lowercase<S extends string> = intrinsic
type Capitalize<S extends string> = intrinsic
type Uncapitalize<S extends string> = intrinsic

type Upper = Uppercase<'hello'>      // 'HELLO'
type Lower = Lowercase<'HELLO'>      // 'hello'
type Cap = Capitalize<'hello'>       // 'Hello'
type Uncap = Uncapitalize<'Hello'>   // 'hello'

// ============ 实用示例 ============

// 事件处理器类型
type EventName = 'click' | 'focus' | 'blur'
type EventHandler = `on${Capitalize<EventName>}`
// 'onClick' | 'onFocus' | 'onBlur'

// CSS 属性类型
type CSSProperty = 'margin' | 'padding' | 'border'
type CSSDirection = 'top' | 'right' | 'bottom' | 'left'
type CSSPropertyWithDirection = `${CSSProperty}-${CSSDirection}`
// 'margin-top' | 'margin-right' | ... | 'border-left'

// 从对象类型生成 getter/setter
type PropEventSource<T> = {
  on<K extends string & keyof T>(
    eventName: `${K}Changed`,
    callback: (newValue: T[K]) => void
  ): void
}

interface Person {
  name: string
  age: number
}

declare function makeWatchedObject<T>(obj: T): T & PropEventSource<T>

const person = makeWatchedObject({
  name: '张三',
  age: 25
})

person.on('nameChanged', (newName) => {
  // newName 的类型是 string
  console.log(`Name changed to ${newName}`)
})

person.on('ageChanged', (newAge) => {
  // newAge 的类型是 number
  console.log(`Age changed to ${newAge}`)
})
```

---

## 9. 模块与命名空间

### 9.1 ES 模块

```typescript
// ============ 导出 ============

// math.ts
// 命名导出
export const PI = 3.14159
export function add(a: number, b: number): number {
  return a + b
}
export class Calculator {
  // ...
}

// 导出类型
export interface MathOperation {
  (a: number, b: number): number
}

export type NumberArray = number[]

// 默认导出
export default class MathUtils {
  static PI = 3.14159
}

// 重新导出
export { add as addition } from './math'
export * from './utils'
export * as utils from './utils'

// ============ 导入 ============

// 命名导入
import { PI, add, Calculator } from './math'

// 重命名导入
import { add as addition } from './math'

// 默认导入
import MathUtils from './math'

// 混合导入
import MathUtils, { PI, add } from './math'

// 命名空间导入
import * as math from './math'
console.log(math.PI)
console.log(math.add(1, 2))

// 仅导入类型（不会在编译后的 JS 中出现）
import type { MathOperation, NumberArray } from './math'
import { type MathOperation, add } from './math'

// 动态导入
async function loadMath() {
  const math = await import('./math')
  console.log(math.PI)
}

// ============ 模块解析 ============

// tsconfig.json
{
  "compilerOptions": {
    "moduleResolution": "node",  // 或 "bundler"
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@components/*": ["src/components/*"]
    }
  }
}

// 使用路径别名
import { Button } from '@/components/Button'
import { utils } from '@/utils'
```

### 9.2 命名空间

```typescript
// ============ 命名空间定义 ============
// 命名空间用于组织代码，避免全局命名冲突
// 在现代 TypeScript 中，推荐使用 ES 模块代替命名空间

namespace Validation {
  // 导出的成员可以在命名空间外访问
  export interface StringValidator {
    isValid(s: string): boolean
  }
  
  // 内部实现
  const lettersRegexp = /^[A-Za-z]+$/
  const numberRegexp = /^[0-9]+$/
  
  export class LettersOnlyValidator implements StringValidator {
    isValid(s: string): boolean {
      return lettersRegexp.test(s)
    }
  }
  
  export class ZipCodeValidator implements StringValidator {
    isValid(s: string): boolean {
      return s.length === 5 && numberRegexp.test(s)
    }
  }
}

// 使用命名空间
const validator = new Validation.LettersOnlyValidator()
console.log(validator.isValid('Hello'))  // true

// ============ 嵌套命名空间 ============

namespace Shapes {
  export namespace Polygons {
    export class Triangle {
      // ...
    }
    export class Square {
      // ...
    }
  }
}

const triangle = new Shapes.Polygons.Triangle()

// ============ 命名空间别名 ============

import Polygons = Shapes.Polygons
const square = new Polygons.Square()

// ============ 声明合并 ============

namespace Animals {
  export class Dog {
    bark() { console.log('Woof!') }
  }
}

namespace Animals {
  export class Cat {
    meow() { console.log('Meow!') }
  }
}

// Animals 现在包含 Dog 和 Cat
const dog = new Animals.Dog()
const cat = new Animals.Cat()
```

### 9.3 全局声明

```typescript
// ============ 全局变量声明 ============

// global.d.ts
declare global {
  // 全局变量
  var DEBUG: boolean
  
  // 全局函数
  function log(message: string): void
  
  // 扩展全局接口
  interface Window {
    myCustomProperty: string
  }
  
  interface Array<T> {
    customMethod(): T[]
  }
}

// 必须导出空对象使文件成为模块
export {}

// 使用
window.myCustomProperty = 'hello'
console.log(DEBUG)

// ============ 环境声明 ============

// 声明已存在的全局变量（不生成代码）
declare const jQuery: (selector: string) => any
declare const $: typeof jQuery

// 声明模块
declare module 'some-untyped-module' {
  export function doSomething(): void
  export const version: string
}

// 模块扩展
declare module 'vue' {
  interface ComponentCustomProperties {
    $http: typeof axios
  }
}
```

---

## 10. 装饰器

### 10.1 装饰器基础

```typescript
// 启用装饰器需要在 tsconfig.json 中配置：
// "experimentalDecorators": true
// "emitDecoratorMetadata": true

// ============ 类装饰器 ============

function sealed(constructor: Function) {
  Object.seal(constructor)
  Object.seal(constructor.prototype)
}

@sealed
class Greeter {
  greeting: string
  constructor(message: string) {
    this.greeting = message
  }
  greet() {
    return `Hello, ${this.greeting}`
  }
}

// 装饰器工厂（返回装饰器的函数）
function classDecorator<T extends { new (...args: any[]): {} }>(constructor: T) {
  return class extends constructor {
    newProperty = 'new property'
    hello = 'override'
  }
}

@classDecorator
class MyClass {
  property = 'property'
  hello: string
  constructor(m: string) {
    this.hello = m
  }
}

// 带参数的装饰器工厂
function log(prefix: string) {
  return function (constructor: Function) {
    console.log(`${prefix}: ${constructor.name}`)
  }
}

@log('Creating class')
class Example {}

// ============ 方法装饰器 ============

function enumerable(value: boolean) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    descriptor.enumerable = value
  }
}

function logMethod(
  target: any,
  propertyKey: string,
  descriptor: PropertyDescriptor
) {
  const originalMethod = descriptor.value
  
  descriptor.value = function (...args: any[]) {
    console.log(`Calling ${propertyKey} with args:`, args)
    const result = originalMethod.apply(this, args)
    console.log(`Result:`, result)
    return result
  }
  
  return descriptor
}

class Calculator {
  @enumerable(false)
  @logMethod
  add(a: number, b: number): number {
    return a + b
  }
}

const calc = new Calculator()
calc.add(1, 2)
// 输出:
// Calling add with args: [1, 2]
// Result: 3
```

### 10.2 属性和参数装饰器

```typescript
// ============ 属性装饰器 ============

function format(formatString: string) {
  return function (target: any, propertyKey: string) {
    let value: string
    
    const getter = function () {
      return value
    }
    
    const setter = function (newVal: string) {
      value = formatString.replace('%s', newVal)
    }
    
    Object.defineProperty(target, propertyKey, {
      get: getter,
      set: setter,
      enumerable: true,
      configurable: true
    })
  }
}

class Greeter {
  @format('Hello, %s!')
  greeting: string
  
  constructor(message: string) {
    this.greeting = message
  }
}

const greeter = new Greeter('World')
console.log(greeter.greeting)  // "Hello, World!"

// ============ 参数装饰器 ============

function required(
  target: Object,
  propertyKey: string | symbol,
  parameterIndex: number
) {
  const existingRequiredParameters: number[] = 
    Reflect.getOwnMetadata('required', target, propertyKey) || []
  existingRequiredParameters.push(parameterIndex)
  Reflect.defineMetadata('required', existingRequiredParameters, target, propertyKey)
}

function validate(
  target: any,
  propertyKey: string,
  descriptor: PropertyDescriptor
) {
  const method = descriptor.value
  
  descriptor.value = function (...args: any[]) {
    const requiredParameters: number[] = 
      Reflect.getOwnMetadata('required', target, propertyKey) || []
    
    for (const index of requiredParameters) {
      if (args[index] === undefined || args[index] === null) {
        throw new Error(`Missing required argument at position ${index}`)
      }
    }
    
    return method.apply(this, args)
  }
}

class UserService {
  @validate
  createUser(@required name: string, age?: number) {
    console.log(`Creating user: ${name}, age: ${age}`)
  }
}

// ============ 装饰器执行顺序 ============

function first() {
  console.log('first(): factory evaluated')
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    console.log('first(): called')
  }
}

function second() {
  console.log('second(): factory evaluated')
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    console.log('second(): called')
  }
}

class ExampleClass {
  @first()
  @second()
  method() {}
}

// 输出:
// first(): factory evaluated
// second(): factory evaluated
// second(): called
// first(): called
// 工厂函数从上到下执行，装饰器从下到上执行
```

---

## 11. 类型声明文件

### 11.1 声明文件基础

```typescript
// ============ .d.ts 文件 ============
// 声明文件只包含类型信息，不包含实现

// types/jquery.d.ts
declare const jQuery: (selector: string) => any
declare const $: typeof jQuery

declare function ajax(url: string, settings?: any): void

declare namespace jQuery {
  function ajax(url: string, settings?: any): void
  function get(url: string): any
  function post(url: string, data?: any): any
}

// ============ 模块声明 ============

// types/lodash.d.ts
declare module 'lodash' {
  export function chunk<T>(array: T[], size?: number): T[][]
  export function compact<T>(array: T[]): T[]
  export function concat<T>(...arrays: T[][]): T[]
  // ...
}

// 通配符模块声明
declare module '*.css' {
  const content: { [className: string]: string }
  export default content
}

declare module '*.png' {
  const value: string
  export default value
}

declare module '*.json' {
  const value: any
  export default value
}

// ============ 全局声明 ============

// types/global.d.ts
declare global {
  interface Window {
    __APP_VERSION__: string
    __DEV__: boolean
  }
  
  namespace NodeJS {
    interface ProcessEnv {
      NODE_ENV: 'development' | 'production' | 'test'
      API_URL: string
    }
  }
}

export {}

// ============ 三斜线指令 ============

/// <reference path="./types/jquery.d.ts" />
/// <reference types="node" />
/// <reference lib="es2015" />
```

### 11.2 为第三方库编写声明

```typescript
// ============ 为无类型库编写声明 ============

// 假设有一个无类型的库 my-lib
// types/my-lib.d.ts

declare module 'my-lib' {
  // 导出的函数
  export function init(config: Config): void
  export function process(data: any): Result
  
  // 导出的类
  export class MyClass {
    constructor(options?: Options)
    doSomething(): void
    getValue(): string
  }
  
  // 导出的接口
  export interface Config {
    apiKey: string
    debug?: boolean
  }
  
  export interface Options {
    name: string
    timeout?: number
  }
  
  export interface Result {
    success: boolean
    data: any
    error?: string
  }
  
  // 默认导出
  const myLib: {
    init: typeof init
    process: typeof process
    MyClass: typeof MyClass
  }
  
  export default myLib
}

// ============ 扩展已有类型 ============

// 扩展 Express Request
declare namespace Express {
  interface Request {
    user?: {
      id: string
      name: string
      role: string
    }
  }
}

// 扩展 Vue
declare module 'vue' {
  interface ComponentCustomProperties {
    $http: typeof import('axios').default
    $store: import('vuex').Store<any>
  }
}

// 扩展 Window
interface Window {
  gtag: (...args: any[]) => void
  dataLayer: any[]
}
```

### 11.3 发布类型声明

```json
// package.json
{
  "name": "my-library",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": [
    "dist"
  ],
  "scripts": {
    "build": "tsc",
    "prepublishOnly": "npm run build"
  }
}

// tsconfig.json
{
  "compilerOptions": {
    "declaration": true,
    "declarationMap": true,
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src/**/*"]
}
```

---

## 12. 常见错误与解决方案

### 12.1 类型错误

```typescript
// ============ 错误1：类型不匹配 ============

// ❌ 错误
let name: string = 123
// Type 'number' is not assignable to type 'string'

// ✅ 正确
let name: string = '张三'
let name2: string | number = 123  // 使用联合类型

// ============ 错误2：对象缺少属性 ============

interface User {
  name: string
  age: number
  email: string
}

// ❌ 错误
const user: User = {
  name: '张三',
  age: 25
}
// Property 'email' is missing in type

// ✅ 正确
const user: User = {
  name: '张三',
  age: 25,
  email: 'zhangsan@example.com'
}

// 或者使用 Partial
const partialUser: Partial<User> = {
  name: '张三',
  age: 25
}

// ============ 错误3：对象有多余属性 ============

// ❌ 错误（对象字面量会严格检查）
const user2: User = {
  name: '张三',
  age: 25,
  email: 'test@example.com',
  phone: '123456'  // 多余属性
}
// Object literal may only specify known properties

// ✅ 正确方案1：使用类型断言
const user3 = {
  name: '张三',
  age: 25,
  email: 'test@example.com',
  phone: '123456'
} as User

// ✅ 正确方案2：使用索引签名
interface UserWithExtra extends User {
  [key: string]: any
}

// ============ 错误4：null/undefined 错误 ============

function getLength(str: string | null): number {
  // ❌ 错误
  // return str.length
  // Object is possibly 'null'
  
  // ✅ 正确方案1：类型守卫
  if (str !== null) {
    return str.length
  }
  return 0
  
  // ✅ 正确方案2：可选链
  return str?.length ?? 0
  
  // ✅ 正确方案3：非空断言（确定不为 null 时使用）
  return str!.length
}

// ============ 错误5：函数返回类型不匹配 ============

// ❌ 错误
function getValue(): string {
  // return 123
  // Type 'number' is not assignable to type 'string'
  
  // 可能忘记返回
  // Function lacks ending return statement
}

// ✅ 正确
function getValue(): string {
  return 'value'
}

// 或者允许返回 undefined
function getValue2(): string | undefined {
  // 可以不返回
}
```

### 12.2 泛型错误

```typescript
// ============ 错误1：泛型约束不满足 ============

function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
  return obj[key]
}

const person = { name: '张三', age: 25 }

// ❌ 错误
// getProperty(person, 'email')
// Argument of type '"email"' is not assignable to parameter of type '"name" | "age"'

// ✅ 正确
getProperty(person, 'name')

// ============ 错误2：泛型类型推断失败 ============

function identity<T>(arg: T): T {
  return arg
}

// ❌ 可能的问题：类型推断为字面量类型
const result = identity('hello')  // 类型是 'hello'，不是 string

// ✅ 显式指定类型
const result2 = identity<string>('hello')  // 类型是 string

// ============ 错误3：泛型数组操作 ============

function firstElement<T>(arr: T[]): T {
  // ❌ 错误：数组可能为空
  // return arr[0]
  // 返回类型应该是 T | undefined
  
  // ✅ 正确
  return arr[0]  // 返回类型是 T（可能是 undefined）
}

function firstElementSafe<T>(arr: T[]): T | undefined {
  return arr.length > 0 ? arr[0] : undefined
}

// ============ 错误4：泛型默认值 ============

// ❌ 错误：没有默认值时必须指定类型
interface Container<T> {
  value: T
}
// const c: Container = { value: 'hello' }
// Generic type 'Container<T>' requires 1 type argument(s)

// ✅ 正确：提供默认值
interface ContainerWithDefault<T = any> {
  value: T
}
const c: ContainerWithDefault = { value: 'hello' }
```

### 12.3 模块错误

```typescript
// ============ 错误1：找不到模块 ============

// ❌ 错误
// import { something } from 'unknown-module'
// Cannot find module 'unknown-module'

// ✅ 解决方案1：安装类型声明
// npm install @types/unknown-module

// ✅ 解决方案2：创建声明文件
// types/unknown-module.d.ts
declare module 'unknown-module' {
  export function something(): void
}

// ============ 错误2：模块没有默认导出 ============

// ❌ 错误
// import React from 'react'
// Module has no default export (在某些配置下)

// ✅ 解决方案1：使用命名导入
import * as React from 'react'

// ✅ 解决方案2：启用 esModuleInterop
// tsconfig.json: "esModuleInterop": true

// ============ 错误3：导入类型错误 ============

// ❌ 错误：运行时导入类型
import { MyInterface } from './types'
// 如果 MyInterface 只是类型，编译后会报错

// ✅ 正确：使用 import type
import type { MyInterface } from './types'

// 或者混合导入
import { someFunction, type MyInterface } from './module'

// ============ 错误4：循环依赖 ============

// a.ts
import { B } from './b'
export class A {
  b: B
}

// b.ts
import { A } from './a'
export class B {
  a: A
}

// ✅ 解决方案：使用接口或类型
// types.ts
export interface IA {
  b: IB
}
export interface IB {
  a: IA
}
```

### 12.4 配置错误

```typescript
// ============ 错误1：严格模式问题 ============

// 开启 strict 模式后的常见问题

// strictNullChecks
function process(value: string | null) {
  // ❌ 错误
  // console.log(value.length)
  
  // ✅ 正确
  if (value !== null) {
    console.log(value.length)
  }
}

// strictPropertyInitialization
class MyClass {
  // ❌ 错误
  // name: string
  // Property 'name' has no initializer
  
  // ✅ 正确方案1：初始化
  name: string = ''
  
  // ✅ 正确方案2：在构造函数中初始化
  age: number
  constructor() {
    this.age = 0
  }
  
  // ✅ 正确方案3：使用明确赋值断言
  email!: string
}

// noImplicitAny
// ❌ 错误
// function fn(arg) { }
// Parameter 'arg' implicitly has an 'any' type

// ✅ 正确
function fn(arg: unknown) { }

// ============ 错误2：路径别名不工作 ============

// tsconfig.json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  }
}

// 如果使用 Vite，还需要配置 vite.config.ts
import path from 'path'

export default {
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src')
    }
  }
}

// ============ 错误3：装饰器不工作 ============

// tsconfig.json
{
  "compilerOptions": {
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  }
}
```

### 12.5 最佳实践

```typescript
// ============ 1. 优先使用 unknown 而不是 any ============

// ❌ 不推荐
function processData(data: any) {
  data.foo.bar  // 不会报错，但可能运行时出错
}

// ✅ 推荐
function processData(data: unknown) {
  if (typeof data === 'object' && data !== null && 'foo' in data) {
    // 类型安全
  }
}

// ============ 2. 使用类型守卫而不是类型断言 ============

// ❌ 不推荐
function isString(value: unknown): boolean {
  return typeof value === 'string'
}
const str = value as string  // 危险

// ✅ 推荐
function isString(value: unknown): value is string {
  return typeof value === 'string'
}
if (isString(value)) {
  value.toUpperCase()  // 类型安全
}

// ============ 3. 使用 const 断言 ============

// ❌ 类型太宽泛
const config = {
  endpoint: '/api',
  timeout: 3000
}
// 类型是 { endpoint: string; timeout: number }

// ✅ 使用 const 断言
const config = {
  endpoint: '/api',
  timeout: 3000
} as const
// 类型是 { readonly endpoint: "/api"; readonly timeout: 3000 }

// ============ 4. 使用 satisfies 操作符（TS 4.9+） ============

type Colors = 'red' | 'green' | 'blue'
type RGB = [number, number, number]

// ✅ 既能检查类型，又能保留字面量类型
const palette = {
  red: [255, 0, 0],
  green: '#00ff00',
  blue: [0, 0, 255]
} satisfies Record<Colors, string | RGB>

// palette.red 的类型是 [number, number, number]
// palette.green 的类型是 string

// ============ 5. 避免过度使用类型断言 ============

// ❌ 不推荐
const element = document.getElementById('app') as HTMLDivElement

// ✅ 推荐：使用类型守卫
const element = document.getElementById('app')
if (element instanceof HTMLDivElement) {
  // 类型安全
}

// ============ 6. 使用 readonly 保护数据 ============

interface Config {
  readonly apiUrl: string
  readonly timeout: number
}

function processConfig(config: Readonly<Config>) {
  // config.apiUrl = 'new url'  // 错误！
}
```

---

## 总结

本笔记涵盖了 TypeScript 从基础到高级的核心知识点：

1. **基础概念**：TypeScript 简介、环境搭建、配置文件
2. **基础类型**：原始类型、数组、元组、特殊类型、类型断言
3. **函数**：函数类型、可选参数、重载、this 类型
4. **接口与类型别名**：接口定义、类型别名、两者区别
5. **类**：访问修饰符、继承、抽象类、静态成员
6. **泛型**：泛型函数、泛型类、泛型约束、工具类型
7. **类型操作**：联合类型、交叉类型、类型收窄、keyof/typeof
8. **高级类型**：条件类型、映射类型、模板字面量类型
9. **模块与命名空间**：ES 模块、命名空间、全局声明
10. **装饰器**：类装饰器、方法装饰器、属性装饰器
11. **类型声明文件**：.d.ts 文件、第三方库声明
12. **常见错误**：类型错误、泛型错误、模块错误、最佳实践

掌握这些知识点，你就能够熟练使用 TypeScript 开发类型安全的应用程序。

---

## 参考资料

- [TypeScript 官方文档](https://www.typescriptlang.org/docs/)
- [TypeScript 中文文档](https://www.tslang.cn/docs/home.html)
- [TypeScript Deep Dive](https://basarat.gitbook.io/typescript/)
- [Type Challenges](https://github.com/type-challenges/type-challenges)
