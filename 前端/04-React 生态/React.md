

> React 是用于构建用户界面的 JavaScript 库，由 Facebook 开发和维护
> 本笔记基于 React 18，涵盖从入门到高级的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [JSX 语法](#2-jsx-语法)
3. [组件基础](#3-组件基础)
4. [Props 属性](#4-props-属性)
5. [State 状态](#5-state-状态)
6. [事件处理](#6-事件处理)
7. [条件渲染](#7-条件渲染)
8. [列表渲染](#8-列表渲染)
9. [表单处理](#9-表单处理)
10. [Hooks 基础](#10-hooks-基础)
11. [Hooks 进阶](#11-hooks-进阶)
12. [Context 上下文](#12-context-上下文)
13. [Refs 引用](#13-refs-引用)
14. [组件通信](#14-组件通信)
15. [性能优化](#15-性能优化)
16. [React 18 新特性](#16-react-18-新特性)
17. [常见错误与解决方案](#17-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 React？

React 是一个用于构建用户界面的 JavaScript 库。它的核心思想是：**UI = f(state)**，即界面是状态的函数。

**核心特点：**
- **声明式**：描述 UI 应该是什么样子，而非如何操作 DOM
- **组件化**：将 UI 拆分为独立、可复用的组件
- **单向数据流**：数据从父组件流向子组件
- **虚拟 DOM**：通过 diff 算法高效更新真实 DOM

### 1.2 React 18 新特性概览

```
┌─────────────────────────────────────────────────────────────────────┐
│                    React 18 核心更新                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  并发特性 (Concurrent Features):                                     │
│  • 自动批处理 (Automatic Batching)                                  │
│  • Transitions (过渡更新)                                           │
│  • Suspense 改进                                                    │
│                                                                      │
│  新的 Hooks:                                                         │
│  • useId - 生成唯一 ID                                              │
│  • useTransition - 标记非紧急更新                                   │
│  • useDeferredValue - 延迟更新值                                    │
│  • useSyncExternalStore - 订阅外部存储                              │
│  • useInsertionEffect - CSS-in-JS 库使用                            │
│                                                                      │
│  新的 API:                                                           │
│  • createRoot - 新的根节点 API                                      │
│  • hydrateRoot - 新的 SSR hydration API                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 创建 React 项目

```bash
# 使用 Vite（推荐）
pnpm create vite@latest my-react-app -- --template react-ts
cd my-react-app
pnpm install
pnpm run dev

# 使用 Create React App
npx create-react-app my-app --template typescript
cd my-app
npm start

# 使用 Next.js（全栈框架）
npx create-next-app@latest my-next-app
```

### 1.4 项目结构

```
my-react-app/
├── public/
│   └── index.html
├── src/
│   ├── components/       # 通用组件
│   │   ├── Button/
│   │   │   ├── index.tsx
│   │   │   └── style.css
│   │   └── ...
│   ├── pages/           # 页面组件
│   ├── hooks/           # 自定义 Hooks
│   ├── contexts/        # Context 定义
│   ├── services/        # API 服务
│   ├── utils/           # 工具函数
│   ├── types/           # TypeScript 类型
│   ├── App.tsx
│   ├── main.tsx         # 入口文件
│   └── index.css
├── package.json
├── tsconfig.json
└── vite.config.ts
```

### 1.5 入口文件（React 18）

```tsx
// src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

// React 18 新的创建根节点方式
const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
)

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)

// React 17 及之前的方式（已废弃）
// ReactDOM.render(<App />, document.getElementById('root'))
```

---

## 2. JSX 语法

JSX 是 JavaScript 的语法扩展，让我们可以在 JS 中编写类似 HTML 的代码。

### 2.1 基本语法

```tsx
// JSX 会被编译为 React.createElement 调用
const element = <h1>Hello, World!</h1>

// 等价于
const element = React.createElement('h1', null, 'Hello, World!')

// 多行 JSX 需要用括号包裹
const element = (
  <div>
    <h1>Title</h1>
    <p>Content</p>
  </div>
)

// JSX 必须有一个根元素
// ❌ 错误
const element = (
  <h1>Title</h1>
  <p>Content</p>
)

// ✅ 正确 - 使用 Fragment
const element = (
  <>
    <h1>Title</h1>
    <p>Content</p>
  </>
)

// 或者使用 React.Fragment
const element = (
  <React.Fragment>
    <h1>Title</h1>
    <p>Content</p>
  </React.Fragment>
)
```

### 2.2 表达式插值

```tsx
const name = 'John'
const age = 25
const user = { name: 'Jane', avatar: '/avatar.jpg' }

// 变量插值
const element = <h1>Hello, {name}!</h1>

// 表达式
const element = <p>Age: {age + 1}</p>

// 函数调用
const element = <p>{name.toUpperCase()}</p>

// 三元表达式
const element = <p>{age >= 18 ? 'Adult' : 'Minor'}</p>

// 对象属性
const element = <img src={user.avatar} alt={user.name} />

// 注意：不能使用语句（if、for 等）
// ❌ 错误
const element = <p>{if (true) 'yes'}</p>
```

### 2.3 属性（Props）

```tsx
// 字符串属性
<input type="text" placeholder="Enter name" />

// 表达式属性
<input value={inputValue} onChange={handleChange} />

// 布尔属性
<input disabled />           // 等价于 disabled={true}
<input disabled={false} />   // 不禁用

// 展开属性
const props = { type: 'text', placeholder: 'Enter...' }
<input {...props} />

// className（不是 class）
<div className="container">Content</div>

// style（对象形式，驼峰命名）
<div style={{ backgroundColor: 'red', fontSize: '16px' }}>
  Styled content
</div>

// htmlFor（不是 for）
<label htmlFor="username">Username</label>
<input id="username" />

// dangerouslySetInnerHTML（谨慎使用）
<div dangerouslySetInnerHTML={{ __html: '<b>Bold</b>' }} />
```

### 2.4 注释

```tsx
const element = (
  <div>
    {/* 这是 JSX 注释 */}
    <h1>Title</h1>
    {/* 
      多行注释
      也是这样写
    */}
  </div>
)
```

---

## 3. 组件基础

### 3.1 函数组件（推荐）

```tsx
// 基本函数组件
function Welcome() {
  return <h1>Hello, World!</h1>
}

// 箭头函数组件
const Welcome = () => {
  return <h1>Hello, World!</h1>
}

// 简写（单行返回）
const Welcome = () => <h1>Hello, World!</h1>

// 带 Props 的组件
interface WelcomeProps {
  name: string
  age?: number  // 可选属性
}

const Welcome: React.FC<WelcomeProps> = ({ name, age = 18 }) => {
  return (
    <div>
      <h1>Hello, {name}!</h1>
      <p>Age: {age}</p>
    </div>
  )
}

// 或者不使用 React.FC
function Welcome({ name, age = 18 }: WelcomeProps) {
  return (
    <div>
      <h1>Hello, {name}!</h1>
      <p>Age: {age}</p>
    </div>
  )
}

// 使用组件
<Welcome name="John" />
<Welcome name="Jane" age={25} />
```

### 3.2 类组件（了解即可）

```tsx
import React, { Component } from 'react'

interface Props {
  name: string
}

interface State {
  count: number
}

class Welcome extends Component<Props, State> {
  // 初始化 state
  state: State = {
    count: 0
  }
  
  // 或者在构造函数中初始化
  constructor(props: Props) {
    super(props)
    this.state = { count: 0 }
  }
  
  // 方法需要绑定 this
  handleClick = () => {
    this.setState({ count: this.state.count + 1 })
  }
  
  render() {
    return (
      <div>
        <h1>Hello, {this.props.name}!</h1>
        <p>Count: {this.state.count}</p>
        <button onClick={this.handleClick}>Add</button>
      </div>
    )
  }
}
```

### 3.3 组件组合

```tsx
// 组件可以包含其他组件
function App() {
  return (
    <div>
      <Header />
      <Main />
      <Footer />
    </div>
  )
}

function Header() {
  return <header>Header</header>
}

function Main() {
  return (
    <main>
      <Sidebar />
      <Content />
    </main>
  )
}

// children 属性
interface CardProps {
  title: string
  children: React.ReactNode
}

function Card({ title, children }: CardProps) {
  return (
    <div className="card">
      <h2>{title}</h2>
      <div className="card-body">{children}</div>
    </div>
  )
}

// 使用
<Card title="My Card">
  <p>This is the card content.</p>
  <button>Click me</button>
</Card>
```


---

## 4. Props 属性

Props 是组件的输入，从父组件传递给子组件，是只读的。

### 4.1 基本用法

```tsx
// 定义 Props 类型
interface UserCardProps {
  name: string
  age: number
  email?: string           // 可选
  avatar?: string
  onEdit?: () => void      // 函数类型
  children?: React.ReactNode
}

// 使用 Props
function UserCard({ 
  name, 
  age, 
  email = 'N/A',  // 默认值
  avatar,
  onEdit,
  children 
}: UserCardProps) {
  return (
    <div className="user-card">
      {avatar && <img src={avatar} alt={name} />}
      <h2>{name}</h2>
      <p>Age: {age}</p>
      <p>Email: {email}</p>
      {onEdit && <button onClick={onEdit}>Edit</button>}
      {children}
    </div>
  )
}

// 使用组件
<UserCard 
  name="John" 
  age={25} 
  email="john@example.com"
  onEdit={() => console.log('Edit clicked')}
>
  <p>Additional content</p>
</UserCard>
```

### 4.2 Props 类型

```tsx
interface ComponentProps {
  // 基本类型
  name: string
  age: number
  isActive: boolean
  
  // 数组
  items: string[]
  users: User[]
  
  // 对象
  user: {
    name: string
    age: number
  }
  
  // 函数
  onClick: () => void
  onChange: (value: string) => void
  onSubmit: (data: FormData) => Promise<void>
  
  // React 相关类型
  children: React.ReactNode          // 任意子元素
  element: React.ReactElement        // React 元素
  style?: React.CSSProperties        // 样式对象
  className?: string
  
  // 事件处理器
  onClick: React.MouseEventHandler<HTMLButtonElement>
  onChange: React.ChangeEventHandler<HTMLInputElement>
  
  // 联合类型
  status: 'loading' | 'success' | 'error'
  size: 'small' | 'medium' | 'large'
  
  // 泛型
  data: T
  items: T[]
}
```

### 4.3 Props 解构与默认值

```tsx
// 方式1：参数解构 + 默认值
function Button({ 
  children, 
  variant = 'primary',
  size = 'medium',
  disabled = false,
  onClick 
}: ButtonProps) {
  return (
    <button 
      className={`btn btn-${variant} btn-${size}`}
      disabled={disabled}
      onClick={onClick}
    >
      {children}
    </button>
  )
}

// 方式2：defaultProps（不推荐，将被废弃）
Button.defaultProps = {
  variant: 'primary',
  size: 'medium'
}

// 方式3：使用对象展开
function Button(props: ButtonProps) {
  const { 
    children, 
    variant, 
    size, 
    ...rest 
  } = {
    variant: 'primary',
    size: 'medium',
    ...props
  }
  
  return <button {...rest}>{children}</button>
}
```

### 4.4 Props 透传

```tsx
// 透传所有 props
interface WrapperProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string
}

function Wrapper({ title, children, ...rest }: WrapperProps) {
  return (
    <div {...rest}>
      <h2>{title}</h2>
      {children}
    </div>
  )
}

// 使用时可以传递任意 div 属性
<Wrapper 
  title="My Title" 
  className="wrapper" 
  onClick={() => {}}
  data-testid="wrapper"
>
  Content
</Wrapper>
```

---

## 5. State 状态

State 是组件的内部数据，可以随时间变化并触发重新渲染。

### 5.1 useState 基础

```tsx
import { useState } from 'react'

function Counter() {
  // 声明状态：[当前值, 更新函数] = useState(初始值)
  const [count, setCount] = useState(0)
  
  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={() => setCount(count + 1)}>+1</button>
      <button onClick={() => setCount(count - 1)}>-1</button>
      <button onClick={() => setCount(0)}>Reset</button>
    </div>
  )
}

// 多个状态
function Form() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [age, setAge] = useState(0)
  
  return (
    <form>
      <input value={name} onChange={e => setName(e.target.value)} />
      <input value={email} onChange={e => setEmail(e.target.value)} />
      <input 
        type="number" 
        value={age} 
        onChange={e => setAge(Number(e.target.value))} 
      />
    </form>
  )
}
```

### 5.2 状态更新

```tsx
function Counter() {
  const [count, setCount] = useState(0)
  
  // 直接设置新值
  const reset = () => setCount(0)
  
  // 基于当前值更新（推荐）
  const increment = () => setCount(prev => prev + 1)
  const decrement = () => setCount(prev => prev - 1)
  
  // ❌ 错误：连续调用可能不会按预期工作
  const addThree = () => {
    setCount(count + 1)  // count 是旧值
    setCount(count + 1)  // count 还是旧值
    setCount(count + 1)  // count 还是旧值
    // 结果只加了 1
  }
  
  // ✅ 正确：使用函数式更新
  const addThreeCorrect = () => {
    setCount(prev => prev + 1)
    setCount(prev => prev + 1)
    setCount(prev => prev + 1)
    // 结果加了 3
  }
  
  return (/* ... */)
}
```

### 5.3 对象和数组状态

```tsx
// 对象状态
function UserForm() {
  const [user, setUser] = useState({
    name: '',
    email: '',
    age: 0
  })
  
  // ❌ 错误：直接修改状态
  const updateName = (name: string) => {
    user.name = name  // 不会触发重新渲染
    setUser(user)     // 引用没变，React 认为没有变化
  }
  
  // ✅ 正确：创建新对象
  const updateName = (name: string) => {
    setUser({ ...user, name })
  }
  
  // 更新嵌套对象
  const [state, setState] = useState({
    user: {
      name: 'John',
      address: {
        city: 'Beijing'
      }
    }
  })
  
  const updateCity = (city: string) => {
    setState({
      ...state,
      user: {
        ...state.user,
        address: {
          ...state.user.address,
          city
        }
      }
    })
  }
  
  return (/* ... */)
}

// 数组状态
function TodoList() {
  const [todos, setTodos] = useState<string[]>([])
  
  // 添加元素
  const addTodo = (todo: string) => {
    setTodos([...todos, todo])
  }
  
  // 删除元素
  const removeTodo = (index: number) => {
    setTodos(todos.filter((_, i) => i !== index))
  }
  
  // 更新元素
  const updateTodo = (index: number, newValue: string) => {
    setTodos(todos.map((todo, i) => i === index ? newValue : todo))
  }
  
  // 插入元素
  const insertTodo = (index: number, todo: string) => {
    setTodos([
      ...todos.slice(0, index),
      todo,
      ...todos.slice(index)
    ])
  }
  
  return (/* ... */)
}
```

### 5.4 惰性初始化

```tsx
// 当初始值需要复杂计算时，使用函数形式
function ExpensiveComponent() {
  // ❌ 每次渲染都会执行
  const [data, setData] = useState(expensiveComputation())
  
  // ✅ 只在首次渲染时执行
  const [data, setData] = useState(() => expensiveComputation())
  
  // 从 localStorage 读取
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('theme')
    return saved || 'light'
  })
  
  return (/* ... */)
}
```

---

## 6. 事件处理

### 6.1 基本事件处理

```tsx
function EventDemo() {
  // 点击事件
  const handleClick = () => {
    console.log('Button clicked')
  }
  
  // 带参数的事件处理
  const handleItemClick = (id: number) => {
    console.log('Item clicked:', id)
  }
  
  // 带事件对象
  const handleButtonClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    console.log('Button clicked at:', e.clientX, e.clientY)
  }
  
  return (
    <div>
      {/* 基本用法 */}
      <button onClick={handleClick}>Click me</button>
      
      {/* 内联函数 */}
      <button onClick={() => console.log('Inline click')}>
        Inline
      </button>
      
      {/* 传递参数 */}
      <button onClick={() => handleItemClick(1)}>Item 1</button>
      
      {/* 事件对象 */}
      <button onClick={handleButtonClick}>With Event</button>
    </div>
  )
}
```

### 6.2 常用事件类型

```tsx
function EventTypes() {
  // 鼠标事件
  const handleMouseEnter = (e: React.MouseEvent<HTMLDivElement>) => {}
  const handleMouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {}
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {}
  
  // 键盘事件
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      console.log('Enter pressed')
    }
  }
  
  // 表单事件
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    console.log(e.target.value)
  }
  
  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    console.log('Form submitted')
  }
  
  // 焦点事件
  const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {}
  const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {}
  
  // 滚动事件
  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {}
  
  return (
    <div 
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onScroll={handleScroll}
    >
      <form onSubmit={handleSubmit}>
        <input 
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          onFocus={handleFocus}
          onBlur={handleBlur}
        />
        <button type="submit">Submit</button>
      </form>
    </div>
  )
}
```

### 6.3 事件对象

```tsx
function EventObject() {
  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    // 阻止默认行为
    e.preventDefault()
    
    // 阻止冒泡
    e.stopPropagation()
    
    // 事件目标
    console.log(e.target)        // 触发事件的元素
    console.log(e.currentTarget) // 绑定事件的元素
    
    // 鼠标位置
    console.log(e.clientX, e.clientY)  // 相对于视口
    console.log(e.pageX, e.pageY)      // 相对于页面
    console.log(e.screenX, e.screenY)  // 相对于屏幕
    
    // 修饰键
    console.log(e.ctrlKey, e.shiftKey, e.altKey, e.metaKey)
  }
  
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    console.log(e.key)      // 按键值：'Enter', 'a', 'Escape'
    console.log(e.code)     // 按键代码：'Enter', 'KeyA', 'Escape'
    console.log(e.keyCode)  // 已废弃
  }
  
  return (/* ... */)
}
```


---

## 7. 条件渲染

### 7.1 基本条件渲染

```tsx
function ConditionalDemo({ isLoggedIn }: { isLoggedIn: boolean }) {
  // 方式1：if 语句
  if (isLoggedIn) {
    return <UserDashboard />
  }
  return <LoginForm />
}

// 方式2：三元表达式
function Greeting({ isLoggedIn }: { isLoggedIn: boolean }) {
  return (
    <div>
      {isLoggedIn ? <UserDashboard /> : <LoginForm />}
    </div>
  )
}

// 方式3：逻辑与 &&
function Notification({ hasMessage }: { hasMessage: boolean }) {
  return (
    <div>
      {hasMessage && <span className="badge">New</span>}
    </div>
  )
}

// ⚠️ 注意：&& 的陷阱
function Counter({ count }: { count: number }) {
  // ❌ 当 count 为 0 时，会渲染 "0"
  return <div>{count && <span>{count} items</span>}</div>
  
  // ✅ 正确做法
  return <div>{count > 0 && <span>{count} items</span>}</div>
  // 或
  return <div>{count ? <span>{count} items</span> : null}</div>
}
```

### 7.2 多条件渲染

```tsx
type Status = 'loading' | 'success' | 'error'

function StatusDisplay({ status }: { status: Status }) {
  // 方式1：多个 if
  if (status === 'loading') return <Spinner />
  if (status === 'error') return <ErrorMessage />
  return <Content />
  
  // 方式2：switch
  switch (status) {
    case 'loading':
      return <Spinner />
    case 'error':
      return <ErrorMessage />
    case 'success':
      return <Content />
    default:
      return null
  }
}

// 方式3：对象映射（推荐）
const statusComponents: Record<Status, React.ReactNode> = {
  loading: <Spinner />,
  success: <Content />,
  error: <ErrorMessage />
}

function StatusDisplay({ status }: { status: Status }) {
  return <>{statusComponents[status]}</>
}

// 方式4：组件映射
const StatusComponent: Record<Status, React.FC> = {
  loading: Spinner,
  success: Content,
  error: ErrorMessage
}

function StatusDisplay({ status }: { status: Status }) {
  const Component = StatusComponent[status]
  return <Component />
}
```

### 7.3 条件样式

```tsx
function Button({ variant, disabled }: ButtonProps) {
  // 方式1：模板字符串
  const className = `btn btn-${variant} ${disabled ? 'btn-disabled' : ''}`
  
  // 方式2：数组 join
  const classNames = [
    'btn',
    `btn-${variant}`,
    disabled && 'btn-disabled'
  ].filter(Boolean).join(' ')
  
  // 方式3：使用 clsx 库（推荐）
  import clsx from 'clsx'
  const className = clsx(
    'btn',
    `btn-${variant}`,
    { 'btn-disabled': disabled }
  )
  
  return <button className={className}>Click</button>
}
```

---

## 8. 列表渲染

### 8.1 基本列表渲染

```tsx
function TodoList() {
  const todos = [
    { id: 1, text: 'Learn React', done: false },
    { id: 2, text: 'Build App', done: false },
    { id: 3, text: 'Deploy', done: true }
  ]
  
  return (
    <ul>
      {todos.map(todo => (
        <li key={todo.id}>
          {todo.text} {todo.done && '✓'}
        </li>
      ))}
    </ul>
  )
}
```

### 8.2 Key 的重要性

```tsx
// ❌ 错误：使用索引作为 key（列表会变化时）
{items.map((item, index) => (
  <Item key={index} data={item} />
))}

// ✅ 正确：使用唯一且稳定的 ID
{items.map(item => (
  <Item key={item.id} data={item} />
))}

// Key 的作用：
// 1. 帮助 React 识别哪些元素改变了
// 2. 提高列表更新性能
// 3. 保持组件状态

// 什么时候可以用索引作为 key：
// 1. 列表是静态的，不会改变
// 2. 列表不会重新排序
// 3. 列表不会被过滤
// 4. 列表项没有自己的状态
```

### 8.3 列表组件抽取

```tsx
interface Todo {
  id: number
  text: string
  done: boolean
}

interface TodoItemProps {
  todo: Todo
  onToggle: (id: number) => void
  onDelete: (id: number) => void
}

// 抽取列表项组件
function TodoItem({ todo, onToggle, onDelete }: TodoItemProps) {
  return (
    <li className={todo.done ? 'done' : ''}>
      <input 
        type="checkbox" 
        checked={todo.done}
        onChange={() => onToggle(todo.id)}
      />
      <span>{todo.text}</span>
      <button onClick={() => onDelete(todo.id)}>Delete</button>
    </li>
  )
}

// 列表组件
function TodoList() {
  const [todos, setTodos] = useState<Todo[]>([])
  
  const handleToggle = (id: number) => {
    setTodos(todos.map(todo =>
      todo.id === id ? { ...todo, done: !todo.done } : todo
    ))
  }
  
  const handleDelete = (id: number) => {
    setTodos(todos.filter(todo => todo.id !== id))
  }
  
  return (
    <ul>
      {todos.map(todo => (
        <TodoItem 
          key={todo.id}
          todo={todo}
          onToggle={handleToggle}
          onDelete={handleDelete}
        />
      ))}
    </ul>
  )
}
```

### 8.4 空列表处理

```tsx
function UserList({ users }: { users: User[] }) {
  if (users.length === 0) {
    return <p className="empty">No users found</p>
  }
  
  return (
    <ul>
      {users.map(user => (
        <li key={user.id}>{user.name}</li>
      ))}
    </ul>
  )
}

// 或者使用条件渲染
function UserList({ users }: { users: User[] }) {
  return (
    <>
      {users.length === 0 ? (
        <p className="empty">No users found</p>
      ) : (
        <ul>
          {users.map(user => (
            <li key={user.id}>{user.name}</li>
          ))}
        </ul>
      )}
    </>
  )
}
```

---

## 9. 表单处理

### 9.1 受控组件

```tsx
function ControlledForm() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    age: 0,
    gender: 'male',
    agree: false,
    bio: ''
  })
  
  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value, type } = e.target
    const checked = (e.target as HTMLInputElement).checked
    
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    console.log('Form data:', formData)
  }
  
  return (
    <form onSubmit={handleSubmit}>
      {/* 文本输入 */}
      <input
        type="text"
        name="username"
        value={formData.username}
        onChange={handleChange}
        placeholder="Username"
      />
      
      {/* 邮箱输入 */}
      <input
        type="email"
        name="email"
        value={formData.email}
        onChange={handleChange}
        placeholder="Email"
      />
      
      {/* 密码输入 */}
      <input
        type="password"
        name="password"
        value={formData.password}
        onChange={handleChange}
        placeholder="Password"
      />
      
      {/* 数字输入 */}
      <input
        type="number"
        name="age"
        value={formData.age}
        onChange={handleChange}
      />
      
      {/* 单选框 */}
      <label>
        <input
          type="radio"
          name="gender"
          value="male"
          checked={formData.gender === 'male'}
          onChange={handleChange}
        />
        Male
      </label>
      <label>
        <input
          type="radio"
          name="gender"
          value="female"
          checked={formData.gender === 'female'}
          onChange={handleChange}
        />
        Female
      </label>
      
      {/* 复选框 */}
      <label>
        <input
          type="checkbox"
          name="agree"
          checked={formData.agree}
          onChange={handleChange}
        />
        I agree to terms
      </label>
      
      {/* 下拉选择 */}
      <select name="gender" value={formData.gender} onChange={handleChange}>
        <option value="male">Male</option>
        <option value="female">Female</option>
        <option value="other">Other</option>
      </select>
      
      {/* 文本域 */}
      <textarea
        name="bio"
        value={formData.bio}
        onChange={handleChange}
        placeholder="Bio"
      />
      
      <button type="submit">Submit</button>
    </form>
  )
}
```

### 9.2 非受控组件

```tsx
import { useRef } from 'react'

function UncontrolledForm() {
  const inputRef = useRef<HTMLInputElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    // 通过 ref 获取值
    console.log('Input value:', inputRef.current?.value)
    console.log('Files:', fileRef.current?.files)
  }
  
  return (
    <form onSubmit={handleSubmit}>
      {/* 使用 defaultValue 设置初始值 */}
      <input 
        ref={inputRef}
        type="text" 
        defaultValue="initial value"
      />
      
      {/* 文件输入只能是非受控的 */}
      <input 
        ref={fileRef}
        type="file" 
        multiple
      />
      
      <button type="submit">Submit</button>
    </form>
  )
}
```

### 9.3 表单验证

```tsx
interface FormErrors {
  username?: string
  email?: string
  password?: string
}

function ValidatedForm() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: ''
  })
  const [errors, setErrors] = useState<FormErrors>({})
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  
  const validate = (data: typeof formData): FormErrors => {
    const errors: FormErrors = {}
    
    if (!data.username) {
      errors.username = 'Username is required'
    } else if (data.username.length < 3) {
      errors.username = 'Username must be at least 3 characters'
    }
    
    if (!data.email) {
      errors.email = 'Email is required'
    } else if (!/\S+@\S+\.\S+/.test(data.email)) {
      errors.email = 'Email is invalid'
    }
    
    if (!data.password) {
      errors.password = 'Password is required'
    } else if (data.password.length < 6) {
      errors.password = 'Password must be at least 6 characters'
    }
    
    return errors
  }
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    const newData = { ...formData, [name]: value }
    setFormData(newData)
    
    // 实时验证
    if (touched[name]) {
      setErrors(validate(newData))
    }
  }
  
  const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    const { name } = e.target
    setTouched({ ...touched, [name]: true })
    setErrors(validate(formData))
  }
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const validationErrors = validate(formData)
    setErrors(validationErrors)
    setTouched({ username: true, email: true, password: true })
    
    if (Object.keys(validationErrors).length === 0) {
      console.log('Form is valid:', formData)
    }
  }
  
  return (
    <form onSubmit={handleSubmit}>
      <div>
        <input
          name="username"
          value={formData.username}
          onChange={handleChange}
          onBlur={handleBlur}
          className={errors.username && touched.username ? 'error' : ''}
        />
        {errors.username && touched.username && (
          <span className="error-message">{errors.username}</span>
        )}
      </div>
      {/* 其他字段类似 */}
      <button type="submit">Submit</button>
    </form>
  )
}
```


---

## 10. Hooks 基础

Hooks 是 React 16.8 引入的特性，让函数组件也能使用状态和其他 React 特性。

### 10.1 useState

```tsx
import { useState } from 'react'

function Counter() {
  // 基本用法
  const [count, setCount] = useState(0)
  
  // 对象状态
  const [user, setUser] = useState({ name: '', age: 0 })
  
  // 数组状态
  const [items, setItems] = useState<string[]>([])
  
  // 惰性初始化
  const [data, setData] = useState(() => {
    return expensiveComputation()
  })
  
  return (/* ... */)
}
```

### 10.2 useEffect

useEffect 用于处理副作用：数据获取、订阅、DOM 操作等。

```tsx
import { useState, useEffect } from 'react'

function UserProfile({ userId }: { userId: number }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  
  // 基本用法：每次渲染后执行
  useEffect(() => {
    console.log('Component rendered')
  })
  
  // 空依赖数组：只在挂载时执行一次
  useEffect(() => {
    console.log('Component mounted')
  }, [])
  
  // 有依赖：依赖变化时执行
  useEffect(() => {
    setLoading(true)
    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(data => {
        setUser(data)
        setLoading(false)
      })
  }, [userId])  // userId 变化时重新获取
  
  // 清理函数：组件卸载或依赖变化前执行
  useEffect(() => {
    const subscription = eventEmitter.subscribe(handleEvent)
    
    return () => {
      subscription.unsubscribe()  // 清理
    }
  }, [])
  
  // 定时器示例
  useEffect(() => {
    const timer = setInterval(() => {
      console.log('Tick')
    }, 1000)
    
    return () => clearInterval(timer)  // 清理定时器
  }, [])
  
  // 事件监听示例
  useEffect(() => {
    const handleResize = () => {
      console.log('Window resized')
    }
    
    window.addEventListener('resize', handleResize)
    
    return () => {
      window.removeEventListener('resize', handleResize)
    }
  }, [])
  
  if (loading) return <div>Loading...</div>
  if (!user) return <div>User not found</div>
  
  return <div>{user.name}</div>
}
```

### 10.3 useEffect 依赖陷阱

```tsx
function SearchComponent() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  
  // ❌ 错误：缺少依赖
  useEffect(() => {
    fetch(`/api/search?q=${query}`)
      .then(res => res.json())
      .then(setResults)
  }, [])  // query 变化时不会重新搜索
  
  // ✅ 正确：包含所有依赖
  useEffect(() => {
    fetch(`/api/search?q=${query}`)
      .then(res => res.json())
      .then(setResults)
  }, [query])
  
  // ❌ 错误：对象/数组作为依赖
  const options = { limit: 10 }
  useEffect(() => {
    fetch(`/api/search?q=${query}&limit=${options.limit}`)
  }, [query, options])  // options 每次都是新对象，导致无限循环
  
  // ✅ 正确：使用 useMemo 或提取到组件外
  const options = useMemo(() => ({ limit: 10 }), [])
  // 或
  const limit = 10
  useEffect(() => {
    fetch(`/api/search?q=${query}&limit=${limit}`)
  }, [query, limit])
  
  return (/* ... */)
}
```

### 10.4 useLayoutEffect

useLayoutEffect 在 DOM 更新后同步执行，用于需要读取 DOM 布局的场景。

```tsx
import { useLayoutEffect, useRef, useState } from 'react'

function Tooltip({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const [position, setPosition] = useState({ top: 0, left: 0 })
  
  // useLayoutEffect 在浏览器绑制前执行
  // 避免闪烁
  useLayoutEffect(() => {
    if (ref.current) {
      const rect = ref.current.getBoundingClientRect()
      setPosition({
        top: rect.top - 30,
        left: rect.left + rect.width / 2
      })
    }
  }, [])
  
  return (
    <div ref={ref}>
      {children}
      <div style={{ position: 'absolute', ...position }}>
        Tooltip
      </div>
    </div>
  )
}
```

### 10.5 Hooks 规则

```tsx
// ✅ 规则1：只在函数组件或自定义 Hook 中调用 Hooks
function MyComponent() {
  const [count, setCount] = useState(0)  // ✅
}

function useCustomHook() {
  const [state, setState] = useState(0)  // ✅
}

// ❌ 不能在普通函数中调用
function regularFunction() {
  const [count, setCount] = useState(0)  // ❌
}

// ✅ 规则2：只在顶层调用 Hooks
function MyComponent() {
  const [count, setCount] = useState(0)  // ✅ 顶层
  
  // ❌ 不能在条件语句中
  if (condition) {
    const [name, setName] = useState('')  // ❌
  }
  
  // ❌ 不能在循环中
  for (let i = 0; i < 3; i++) {
    useEffect(() => {})  // ❌
  }
  
  // ❌ 不能在嵌套函数中
  const handleClick = () => {
    const [value, setValue] = useState(0)  // ❌
  }
}
```

---

## 11. Hooks 进阶

### 11.1 useReducer

适用于复杂状态逻辑。

```tsx
import { useReducer } from 'react'

// 定义状态类型
interface State {
  count: number
  step: number
}

// 定义 Action 类型
type Action =
  | { type: 'increment' }
  | { type: 'decrement' }
  | { type: 'reset' }
  | { type: 'setStep'; payload: number }

// 初始状态
const initialState: State = {
  count: 0,
  step: 1
}

// Reducer 函数
function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'increment':
      return { ...state, count: state.count + state.step }
    case 'decrement':
      return { ...state, count: state.count - state.step }
    case 'reset':
      return initialState
    case 'setStep':
      return { ...state, step: action.payload }
    default:
      return state
  }
}

function Counter() {
  const [state, dispatch] = useReducer(reducer, initialState)
  
  return (
    <div>
      <p>Count: {state.count}</p>
      <p>Step: {state.step}</p>
      <button onClick={() => dispatch({ type: 'increment' })}>+</button>
      <button onClick={() => dispatch({ type: 'decrement' })}>-</button>
      <button onClick={() => dispatch({ type: 'reset' })}>Reset</button>
      <input
        type="number"
        value={state.step}
        onChange={e => dispatch({ 
          type: 'setStep', 
          payload: Number(e.target.value) 
        })}
      />
    </div>
  )
}
```

### 11.2 useCallback

缓存函数引用，避免子组件不必要的重新渲染。

```tsx
import { useCallback, useState, memo } from 'react'

// 子组件使用 memo 包裹
const ExpensiveChild = memo(({ onClick }: { onClick: () => void }) => {
  console.log('Child rendered')
  return <button onClick={onClick}>Click</button>
})

function Parent() {
  const [count, setCount] = useState(0)
  const [name, setName] = useState('')
  
  // ❌ 每次渲染都创建新函数，导致子组件重新渲染
  const handleClick = () => {
    console.log('Clicked')
  }
  
  // ✅ 使用 useCallback 缓存函数
  const handleClickMemo = useCallback(() => {
    console.log('Clicked')
  }, [])  // 空依赖，函数永不变化
  
  // 带依赖的 useCallback
  const handleClickWithCount = useCallback(() => {
    console.log('Count:', count)
  }, [count])  // count 变化时更新函数
  
  return (
    <div>
      <input value={name} onChange={e => setName(e.target.value)} />
      <ExpensiveChild onClick={handleClickMemo} />
    </div>
  )
}
```

### 11.3 useMemo

缓存计算结果，避免重复计算。

```tsx
import { useMemo, useState } from 'react'

function ExpensiveComponent({ items }: { items: number[] }) {
  const [filter, setFilter] = useState('')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc')
  
  // ❌ 每次渲染都重新计算
  const processedItems = items
    .filter(item => item.toString().includes(filter))
    .sort((a, b) => sortOrder === 'asc' ? a - b : b - a)
  
  // ✅ 使用 useMemo 缓存结果
  const processedItemsMemo = useMemo(() => {
    console.log('Computing...')
    return items
      .filter(item => item.toString().includes(filter))
      .sort((a, b) => sortOrder === 'asc' ? a - b : b - a)
  }, [items, filter, sortOrder])  // 只有依赖变化时才重新计算
  
  // 缓存对象
  const config = useMemo(() => ({
    theme: 'dark',
    language: 'en'
  }), [])
  
  return (
    <ul>
      {processedItemsMemo.map(item => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  )
}
```

### 11.4 自定义 Hook

```tsx
// useLocalStorage - 持久化状态
function useLocalStorage<T>(key: string, initialValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = localStorage.getItem(key)
      return item ? JSON.parse(item) : initialValue
    } catch {
      return initialValue
    }
  })
  
  const setValue = (value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value
      setStoredValue(valueToStore)
      localStorage.setItem(key, JSON.stringify(valueToStore))
    } catch (error) {
      console.error(error)
    }
  }
  
  return [storedValue, setValue] as const
}

// 使用
function App() {
  const [theme, setTheme] = useLocalStorage('theme', 'light')
  return <button onClick={() => setTheme(t => t === 'light' ? 'dark' : 'light')}>
    Toggle Theme
  </button>
}

// useFetch - 数据获取
function useFetch<T>(url: string) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  
  useEffect(() => {
    const controller = new AbortController()
    
    setLoading(true)
    fetch(url, { signal: controller.signal })
      .then(res => {
        if (!res.ok) throw new Error('Network error')
        return res.json()
      })
      .then(setData)
      .catch(err => {
        if (err.name !== 'AbortError') {
          setError(err)
        }
      })
      .finally(() => setLoading(false))
    
    return () => controller.abort()
  }, [url])
  
  return { data, loading, error }
}

// 使用
function UserList() {
  const { data: users, loading, error } = useFetch<User[]>('/api/users')
  
  if (loading) return <div>Loading...</div>
  if (error) return <div>Error: {error.message}</div>
  
  return (
    <ul>
      {users?.map(user => <li key={user.id}>{user.name}</li>)}
    </ul>
  )
}

// useDebounce - 防抖
function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState(value)
  
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  
  return debouncedValue
}

// useToggle - 切换状态
function useToggle(initialValue = false) {
  const [value, setValue] = useState(initialValue)
  
  const toggle = useCallback(() => setValue(v => !v), [])
  const setTrue = useCallback(() => setValue(true), [])
  const setFalse = useCallback(() => setValue(false), [])
  
  return { value, toggle, setTrue, setFalse }
}

// usePrevious - 获取上一次的值
function usePrevious<T>(value: T): T | undefined {
  const ref = useRef<T>()
  
  useEffect(() => {
    ref.current = value
  }, [value])
  
  return ref.current
}
```


---

## 12. Context 上下文

Context 提供了一种在组件树中传递数据的方式，无需手动逐层传递 props。

### 12.1 创建和使用 Context

```tsx
import { createContext, useContext, useState, ReactNode } from 'react'

// 1. 定义类型
interface ThemeContextType {
  theme: 'light' | 'dark'
  toggleTheme: () => void
}

// 2. 创建 Context
const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

// 3. 创建 Provider 组件
function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<'light' | 'dark'>('light')
  
  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light')
  }
  
  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

// 4. 创建自定义 Hook（推荐）
function useTheme() {
  const context = useContext(ThemeContext)
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

// 5. 使用
function App() {
  return (
    <ThemeProvider>
      <Header />
      <Main />
    </ThemeProvider>
  )
}

function Header() {
  const { theme, toggleTheme } = useTheme()
  
  return (
    <header className={theme}>
      <button onClick={toggleTheme}>
        Switch to {theme === 'light' ? 'dark' : 'light'}
      </button>
    </header>
  )
}
```

### 12.2 多个 Context 组合

```tsx
// AuthContext
interface AuthContextType {
  user: User | null
  login: (credentials: Credentials) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  
  const login = async (credentials: Credentials) => {
    const user = await authService.login(credentials)
    setUser(user)
  }
  
  const logout = () => {
    authService.logout()
    setUser(null)
  }
  
  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

// 组合多个 Provider
function AppProviders({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <ThemeProvider>
        <LanguageProvider>
          {children}
        </LanguageProvider>
      </ThemeProvider>
    </AuthProvider>
  )
}

function App() {
  return (
    <AppProviders>
      <Router />
    </AppProviders>
  )
}
```

### 12.3 Context 性能优化

```tsx
// ❌ 问题：value 对象每次都是新的，导致所有消费者重新渲染
function BadProvider({ children }: { children: ReactNode }) {
  const [count, setCount] = useState(0)
  
  return (
    <MyContext.Provider value={{ count, setCount }}>
      {children}
    </MyContext.Provider>
  )
}

// ✅ 解决：使用 useMemo 缓存 value
function GoodProvider({ children }: { children: ReactNode }) {
  const [count, setCount] = useState(0)
  
  const value = useMemo(() => ({ count, setCount }), [count])
  
  return (
    <MyContext.Provider value={value}>
      {children}
    </MyContext.Provider>
  )
}

// ✅ 更好：拆分 Context
const CountContext = createContext(0)
const SetCountContext = createContext<React.Dispatch<React.SetStateAction<number>>>(() => {})

function CountProvider({ children }: { children: ReactNode }) {
  const [count, setCount] = useState(0)
  
  return (
    <CountContext.Provider value={count}>
      <SetCountContext.Provider value={setCount}>
        {children}
      </SetCountContext.Provider>
    </CountContext.Provider>
  )
}

// 只读取 count 的组件不会因为 setCount 变化而重新渲染
function DisplayCount() {
  const count = useContext(CountContext)
  return <div>{count}</div>
}

// 只需要 setCount 的组件不会因为 count 变化而重新渲染
function IncrementButton() {
  const setCount = useContext(SetCountContext)
  return <button onClick={() => setCount(c => c + 1)}>+</button>
}
```

---

## 13. Refs 引用

### 13.1 useRef 基础

```tsx
import { useRef, useEffect } from 'react'

function TextInput() {
  // 创建 ref
  const inputRef = useRef<HTMLInputElement>(null)
  
  // 自动聚焦
  useEffect(() => {
    inputRef.current?.focus()
  }, [])
  
  const handleClick = () => {
    // 访问 DOM 元素
    inputRef.current?.select()
  }
  
  return (
    <div>
      <input ref={inputRef} type="text" />
      <button onClick={handleClick}>Select All</button>
    </div>
  )
}

// 存储可变值（不触发重新渲染）
function Timer() {
  const [count, setCount] = useState(0)
  const intervalRef = useRef<number | null>(null)
  
  const start = () => {
    if (intervalRef.current !== null) return
    intervalRef.current = window.setInterval(() => {
      setCount(c => c + 1)
    }, 1000)
  }
  
  const stop = () => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
  }
  
  useEffect(() => {
    return () => stop()  // 清理
  }, [])
  
  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={start}>Start</button>
      <button onClick={stop}>Stop</button>
    </div>
  )
}
```

### 13.2 forwardRef

将 ref 转发给子组件。

```tsx
import { forwardRef, useRef, useImperativeHandle } from 'react'

// 基本用法
const FancyInput = forwardRef<HTMLInputElement, { label: string }>(
  ({ label }, ref) => {
    return (
      <label>
        {label}
        <input ref={ref} type="text" />
      </label>
    )
  }
)

function Parent() {
  const inputRef = useRef<HTMLInputElement>(null)
  
  return (
    <div>
      <FancyInput ref={inputRef} label="Name" />
      <button onClick={() => inputRef.current?.focus()}>
        Focus
      </button>
    </div>
  )
}

// useImperativeHandle - 自定义暴露给父组件的实例值
interface InputHandle {
  focus: () => void
  clear: () => void
  getValue: () => string
}

const CustomInput = forwardRef<InputHandle, { label: string }>(
  ({ label }, ref) => {
    const inputRef = useRef<HTMLInputElement>(null)
    
    useImperativeHandle(ref, () => ({
      focus: () => inputRef.current?.focus(),
      clear: () => {
        if (inputRef.current) inputRef.current.value = ''
      },
      getValue: () => inputRef.current?.value || ''
    }))
    
    return (
      <label>
        {label}
        <input ref={inputRef} type="text" />
      </label>
    )
  }
)

function Parent() {
  const inputRef = useRef<InputHandle>(null)
  
  return (
    <div>
      <CustomInput ref={inputRef} label="Name" />
      <button onClick={() => inputRef.current?.focus()}>Focus</button>
      <button onClick={() => inputRef.current?.clear()}>Clear</button>
      <button onClick={() => alert(inputRef.current?.getValue())}>
        Get Value
      </button>
    </div>
  )
}
```

### 13.3 回调 Ref

```tsx
function MeasureExample() {
  const [height, setHeight] = useState(0)
  
  // 回调 ref：元素挂载/卸载时调用
  const measuredRef = useCallback((node: HTMLDivElement | null) => {
    if (node !== null) {
      setHeight(node.getBoundingClientRect().height)
    }
  }, [])
  
  return (
    <div>
      <div ref={measuredRef}>
        Content with dynamic height
      </div>
      <p>Height: {height}px</p>
    </div>
  )
}
```

---

## 14. 组件通信

### 14.1 父子通信

```tsx
// 父 -> 子：通过 props
function Parent() {
  const [message, setMessage] = useState('Hello')
  
  return <Child message={message} />
}

function Child({ message }: { message: string }) {
  return <p>{message}</p>
}

// 子 -> 父：通过回调函数
function Parent() {
  const [value, setValue] = useState('')
  
  const handleChange = (newValue: string) => {
    setValue(newValue)
  }
  
  return (
    <div>
      <p>Value: {value}</p>
      <Child onChange={handleChange} />
    </div>
  )
}

function Child({ onChange }: { onChange: (value: string) => void }) {
  return (
    <input onChange={e => onChange(e.target.value)} />
  )
}
```

### 14.2 兄弟通信

```tsx
// 通过共同的父组件
function Parent() {
  const [sharedData, setSharedData] = useState('')
  
  return (
    <div>
      <SiblingA onDataChange={setSharedData} />
      <SiblingB data={sharedData} />
    </div>
  )
}

function SiblingA({ onDataChange }: { onDataChange: (data: string) => void }) {
  return <input onChange={e => onDataChange(e.target.value)} />
}

function SiblingB({ data }: { data: string }) {
  return <p>Received: {data}</p>
}
```

### 14.3 跨层级通信

```tsx
// 使用 Context（见第12节）

// 或使用状态管理库（Zustand 示例）
import { create } from 'zustand'

interface Store {
  count: number
  increment: () => void
  decrement: () => void
}

const useStore = create<Store>((set) => ({
  count: 0,
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
}))

// 任意组件都可以访问
function DeepChild() {
  const { count, increment } = useStore()
  
  return (
    <div>
      <p>Count: {count}</p>
      <button onClick={increment}>+</button>
    </div>
  )
}
```

---

## 15. 性能优化

### 15.1 React.memo

```tsx
import { memo } from 'react'

// 基本用法：浅比较 props
const ExpensiveComponent = memo(function ExpensiveComponent({ data }: Props) {
  console.log('Rendering ExpensiveComponent')
  return <div>{/* 复杂渲染 */}</div>
})

// 自定义比较函数
const CustomMemo = memo(
  function MyComponent({ user }: { user: User }) {
    return <div>{user.name}</div>
  },
  (prevProps, nextProps) => {
    // 返回 true 表示 props 相等，不需要重新渲染
    return prevProps.user.id === nextProps.user.id
  }
)

// 什么时候使用 memo：
// 1. 组件渲染开销大
// 2. 组件经常以相同的 props 重新渲染
// 3. 父组件频繁更新但子组件 props 不变
```

### 15.2 useMemo 和 useCallback

```tsx
function OptimizedComponent({ items }: { items: Item[] }) {
  // 缓存计算结果
  const sortedItems = useMemo(() => {
    return [...items].sort((a, b) => a.name.localeCompare(b.name))
  }, [items])
  
  // 缓存函数引用
  const handleClick = useCallback((id: number) => {
    console.log('Clicked:', id)
  }, [])
  
  return (
    <ul>
      {sortedItems.map(item => (
        <MemoizedItem 
          key={item.id} 
          item={item} 
          onClick={handleClick}
        />
      ))}
    </ul>
  )
}

const MemoizedItem = memo(function Item({ 
  item, 
  onClick 
}: { 
  item: Item
  onClick: (id: number) => void 
}) {
  return (
    <li onClick={() => onClick(item.id)}>
      {item.name}
    </li>
  )
})
```

### 15.3 代码分割

```tsx
import { lazy, Suspense } from 'react'

// 懒加载组件
const HeavyComponent = lazy(() => import('./HeavyComponent'))
const Dashboard = lazy(() => import('./pages/Dashboard'))

function App() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <HeavyComponent />
    </Suspense>
  )
}

// 路由级别的代码分割
import { Routes, Route } from 'react-router-dom'

const Home = lazy(() => import('./pages/Home'))
const About = lazy(() => import('./pages/About'))
const Contact = lazy(() => import('./pages/Contact'))

function App() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
        <Route path="/contact" element={<Contact />} />
      </Routes>
    </Suspense>
  )
}
```

### 15.4 虚拟列表

```tsx
// 使用 react-window
import { FixedSizeList } from 'react-window'

function VirtualList({ items }: { items: Item[] }) {
  const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => (
    <div style={style}>
      {items[index].name}
    </div>
  )
  
  return (
    <FixedSizeList
      height={400}
      width={300}
      itemCount={items.length}
      itemSize={35}
    >
      {Row}
    </FixedSizeList>
  )
}
```

### 15.5 避免不必要的渲染

```tsx
// 1. 状态下沉
// ❌ 整个组件因为 input 变化而重新渲染
function Parent() {
  const [inputValue, setInputValue] = useState('')
  
  return (
    <div>
      <input value={inputValue} onChange={e => setInputValue(e.target.value)} />
      <ExpensiveChild />  {/* 每次输入都重新渲染 */}
    </div>
  )
}

// ✅ 将状态下沉到需要的组件
function Parent() {
  return (
    <div>
      <SearchInput />  {/* 状态在这里 */}
      <ExpensiveChild />  {/* 不受影响 */}
    </div>
  )
}

function SearchInput() {
  const [inputValue, setInputValue] = useState('')
  return <input value={inputValue} onChange={e => setInputValue(e.target.value)} />
}

// 2. 内容提升
// ❌ children 每次都重新渲染
function Parent() {
  const [count, setCount] = useState(0)
  
  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>{count}</button>
      <ExpensiveChild />
    </div>
  )
}

// ✅ 将不变的内容作为 children 传入
function App() {
  return (
    <Parent>
      <ExpensiveChild />  {/* 在 App 中创建，不受 Parent 状态影响 */}
    </Parent>
  )
}

function Parent({ children }: { children: React.ReactNode }) {
  const [count, setCount] = useState(0)
  
  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>{count}</button>
      {children}
    </div>
  )
}
```


---

## 16. React 18 新特性

### 16.1 并发渲染

React 18 引入了并发渲染，允许 React 同时准备多个版本的 UI。

```tsx
// 启用并发特性（使用 createRoot）
import { createRoot } from 'react-dom/client'

const root = createRoot(document.getElementById('root')!)
root.render(<App />)
```

### 16.2 自动批处理

React 18 自动批处理所有状态更新，包括 Promise、setTimeout 等。

```tsx
function Counter() {
  const [count, setCount] = useState(0)
  const [flag, setFlag] = useState(false)
  
  // React 17：setTimeout 中的更新不会批处理，触发两次渲染
  // React 18：自动批处理，只触发一次渲染
  const handleClick = () => {
    setTimeout(() => {
      setCount(c => c + 1)
      setFlag(f => !f)
      // React 18 只会触发一次重新渲染
    }, 0)
  }
  
  // Promise 中也会自动批处理
  const handleFetch = async () => {
    const data = await fetchData()
    setCount(data.count)
    setFlag(data.flag)
    // 只触发一次重新渲染
  }
  
  // 如果需要立即更新（不批处理）
  import { flushSync } from 'react-dom'
  
  const handleUrgent = () => {
    flushSync(() => {
      setCount(c => c + 1)
    })
    // DOM 已更新
    flushSync(() => {
      setFlag(f => !f)
    })
    // DOM 再次更新
  }
  
  return (/* ... */)
}
```

### 16.3 useTransition

标记非紧急更新，让紧急更新（如输入）优先。

```tsx
import { useState, useTransition } from 'react'

function SearchResults() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<string[]>([])
  const [isPending, startTransition] = useTransition()
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value
    
    // 紧急更新：输入框立即响应
    setQuery(value)
    
    // 非紧急更新：搜索结果可以延迟
    startTransition(() => {
      const filtered = largeList.filter(item => 
        item.toLowerCase().includes(value.toLowerCase())
      )
      setResults(filtered)
    })
  }
  
  return (
    <div>
      <input value={query} onChange={handleChange} />
      {isPending && <span>Loading...</span>}
      <ul>
        {results.map(item => <li key={item}>{item}</li>)}
      </ul>
    </div>
  )
}
```

### 16.4 useDeferredValue

延迟更新某个值，类似于防抖但由 React 控制。

```tsx
import { useState, useDeferredValue, useMemo } from 'react'

function SearchResults({ query }: { query: string }) {
  // 延迟更新 query
  const deferredQuery = useDeferredValue(query)
  
  // 使用延迟的值进行计算
  const results = useMemo(() => {
    return largeList.filter(item => 
      item.toLowerCase().includes(deferredQuery.toLowerCase())
    )
  }, [deferredQuery])
  
  // 判断是否正在等待
  const isStale = query !== deferredQuery
  
  return (
    <ul style={{ opacity: isStale ? 0.5 : 1 }}>
      {results.map(item => <li key={item}>{item}</li>)}
    </ul>
  )
}

function App() {
  const [query, setQuery] = useState('')
  
  return (
    <div>
      <input 
        value={query} 
        onChange={e => setQuery(e.target.value)} 
      />
      <SearchResults query={query} />
    </div>
  )
}
```

### 16.5 useId

生成唯一 ID，适用于无障碍属性。

```tsx
import { useId } from 'react'

function FormField({ label }: { label: string }) {
  const id = useId()
  
  return (
    <div>
      <label htmlFor={id}>{label}</label>
      <input id={id} type="text" />
    </div>
  )
}

// 多个相关元素
function PasswordField() {
  const id = useId()
  
  return (
    <div>
      <label htmlFor={`${id}-password`}>Password</label>
      <input 
        id={`${id}-password`} 
        type="password"
        aria-describedby={`${id}-hint`}
      />
      <p id={`${id}-hint`}>
        Password must be at least 8 characters
      </p>
    </div>
  )
}
```

### 16.6 Suspense 改进

```tsx
import { Suspense } from 'react'

// 数据获取（需要支持 Suspense 的库，如 React Query、SWR）
function UserProfile({ userId }: { userId: number }) {
  return (
    <Suspense fallback={<div>Loading user...</div>}>
      <UserDetails userId={userId} />
      <Suspense fallback={<div>Loading posts...</div>}>
        <UserPosts userId={userId} />
      </Suspense>
    </Suspense>
  )
}

// 嵌套 Suspense
function App() {
  return (
    <Suspense fallback={<div>Loading app...</div>}>
      <Header />
      <Suspense fallback={<div>Loading content...</div>}>
        <MainContent />
      </Suspense>
      <Footer />
    </Suspense>
  )
}
```

### 16.7 useSyncExternalStore

订阅外部存储（如 Redux、Zustand）。

```tsx
import { useSyncExternalStore } from 'react'

// 简单的外部存储
const store = {
  state: { count: 0 },
  listeners: new Set<() => void>(),
  
  subscribe(listener: () => void) {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  },
  
  getSnapshot() {
    return this.state
  },
  
  increment() {
    this.state = { count: this.state.count + 1 }
    this.listeners.forEach(listener => listener())
  }
}

function Counter() {
  const state = useSyncExternalStore(
    store.subscribe.bind(store),
    store.getSnapshot.bind(store)
  )
  
  return (
    <div>
      <p>Count: {state.count}</p>
      <button onClick={() => store.increment()}>+</button>
    </div>
  )
}
```

---

## 17. 常见错误与解决方案

### 17.1 状态更新问题

```tsx
// ❌ 错误：直接修改状态
const [user, setUser] = useState({ name: 'John', age: 25 })
user.name = 'Jane'  // 不会触发重新渲染
setUser(user)       // 引用没变，React 认为没有变化

// ✅ 正确：创建新对象
setUser({ ...user, name: 'Jane' })

// ❌ 错误：异步获取旧状态
const [count, setCount] = useState(0)
const handleClick = () => {
  setTimeout(() => {
    setCount(count + 1)  // count 是旧值
  }, 1000)
}

// ✅ 正确：使用函数式更新
const handleClick = () => {
  setTimeout(() => {
    setCount(prev => prev + 1)
  }, 1000)
}

// ❌ 错误：在渲染期间更新状态
function BadComponent() {
  const [count, setCount] = useState(0)
  setCount(1)  // 无限循环！
  return <div>{count}</div>
}

// ✅ 正确：在 useEffect 或事件处理器中更新
function GoodComponent() {
  const [count, setCount] = useState(0)
  useEffect(() => {
    setCount(1)
  }, [])
  return <div>{count}</div>
}
```

### 17.2 useEffect 问题

```tsx
// ❌ 错误：缺少依赖
const [count, setCount] = useState(0)
useEffect(() => {
  const timer = setInterval(() => {
    setCount(count + 1)  // count 永远是 0
  }, 1000)
  return () => clearInterval(timer)
}, [])  // 缺少 count 依赖

// ✅ 正确：使用函数式更新
useEffect(() => {
  const timer = setInterval(() => {
    setCount(prev => prev + 1)
  }, 1000)
  return () => clearInterval(timer)
}, [])

// ❌ 错误：对象/函数作为依赖导致无限循环
const options = { page: 1 }  // 每次渲染都是新对象
useEffect(() => {
  fetchData(options)
}, [options])  // 无限循环

// ✅ 正确：使用 useMemo 或提取依赖
const options = useMemo(() => ({ page: 1 }), [])
// 或
const page = 1
useEffect(() => {
  fetchData({ page })
}, [page])

// ❌ 错误：忘记清理
useEffect(() => {
  const subscription = eventEmitter.subscribe(handler)
  // 忘记返回清理函数，导致内存泄漏
}, [])

// ✅ 正确：返回清理函数
useEffect(() => {
  const subscription = eventEmitter.subscribe(handler)
  return () => subscription.unsubscribe()
}, [])
```

### 17.3 条件渲染问题

```tsx
// ❌ 错误：&& 渲染 0
const count = 0
return <div>{count && <span>Count: {count}</span>}</div>
// 渲染结果：<div>0</div>

// ✅ 正确：使用布尔表达式
return <div>{count > 0 && <span>Count: {count}</span>}</div>
// 或
return <div>{count ? <span>Count: {count}</span> : null}</div>

// ❌ 错误：条件渲染导致 Hooks 顺序变化
function BadComponent({ isLoggedIn }) {
  if (isLoggedIn) {
    const [user, setUser] = useState(null)  // 条件中使用 Hook
  }
  // ...
}

// ✅ 正确：Hooks 必须在顶层
function GoodComponent({ isLoggedIn }) {
  const [user, setUser] = useState(null)
  
  if (!isLoggedIn) {
    return <LoginForm />
  }
  // ...
}
```

### 17.4 Key 问题

```tsx
// ❌ 错误：使用索引作为 key（列表会变化时）
{items.map((item, index) => (
  <Item key={index} data={item} />
))}

// ✅ 正确：使用唯一 ID
{items.map(item => (
  <Item key={item.id} data={item} />
))}

// ❌ 错误：key 不稳定
{items.map(item => (
  <Item key={Math.random()} data={item} />  // 每次都是新 key
))}

// ❌ 错误：兄弟元素 key 重复
{items.map(item => (
  <Item key="same-key" data={item} />  // 所有元素 key 相同
))}
```

### 17.5 事件处理问题

```tsx
// ❌ 错误：直接调用函数
<button onClick={handleClick()}>Click</button>
// handleClick 在渲染时就被调用了

// ✅ 正确：传递函数引用
<button onClick={handleClick}>Click</button>
// 或
<button onClick={() => handleClick()}>Click</button>

// ❌ 错误：传递参数时直接调用
<button onClick={handleClick(id)}>Click</button>

// ✅ 正确：使用箭头函数
<button onClick={() => handleClick(id)}>Click</button>

// ❌ 错误：忘记阻止默认行为
<form onSubmit={handleSubmit}>  {/* 页面会刷新 */}

// ✅ 正确：阻止默认行为
const handleSubmit = (e: React.FormEvent) => {
  e.preventDefault()
  // ...
}
```

### 17.6 异步问题

```tsx
// ❌ 错误：组件卸载后更新状态
useEffect(() => {
  fetchData().then(data => {
    setData(data)  // 组件可能已卸载
  })
}, [])

// ✅ 正确：使用 AbortController 或标志位
useEffect(() => {
  let isMounted = true
  
  fetchData().then(data => {
    if (isMounted) {
      setData(data)
    }
  })
  
  return () => {
    isMounted = false
  }
}, [])

// 或使用 AbortController
useEffect(() => {
  const controller = new AbortController()
  
  fetch(url, { signal: controller.signal })
    .then(res => res.json())
    .then(setData)
    .catch(err => {
      if (err.name !== 'AbortError') {
        setError(err)
      }
    })
  
  return () => controller.abort()
}, [url])
```

### 17.7 性能问题

```tsx
// ❌ 错误：在渲染中创建新对象/函数
function Parent() {
  return (
    <Child 
      style={{ color: 'red' }}  // 每次都是新对象
      onClick={() => {}}         // 每次都是新函数
    />
  )
}

// ✅ 正确：使用 useMemo/useCallback
function Parent() {
  const style = useMemo(() => ({ color: 'red' }), [])
  const handleClick = useCallback(() => {}, [])
  
  return <Child style={style} onClick={handleClick} />
}

// ❌ 错误：不必要的状态
function BadComponent() {
  const [fullName, setFullName] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  
  useEffect(() => {
    setFullName(`${firstName} ${lastName}`)
  }, [firstName, lastName])
}

// ✅ 正确：派生状态不需要存储
function GoodComponent() {
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  
  const fullName = `${firstName} ${lastName}`  // 直接计算
}
```

---

## 附录：常用 API 速查

### Hooks

| Hook | 用途 |
|------|------|
| `useState` | 状态管理 |
| `useEffect` | 副作用处理 |
| `useContext` | 读取 Context |
| `useReducer` | 复杂状态逻辑 |
| `useCallback` | 缓存函数 |
| `useMemo` | 缓存计算结果 |
| `useRef` | 引用 DOM 或存储可变值 |
| `useId` | 生成唯一 ID |
| `useTransition` | 标记非紧急更新 |
| `useDeferredValue` | 延迟更新值 |

### 组件 API

| API | 用途 |
|-----|------|
| `memo` | 组件记忆化 |
| `forwardRef` | 转发 ref |
| `lazy` | 懒加载组件 |
| `Suspense` | 等待异步内容 |
| `Fragment` | 无额外 DOM 的包装器 |
| `StrictMode` | 开发模式检查 |

---

> 📝 **笔记说明**
> - 本笔记基于 React 18 编写
> - 建议配合官方文档学习：https://react.dev/
> - 推荐使用 TypeScript 进行类型安全的开发

---

*最后更新：2024年*
