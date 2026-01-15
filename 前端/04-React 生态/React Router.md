

> React Router 是 React 应用中最流行的路由解决方案，用于构建单页应用（SPA）
> 本笔记基于 React Router v6，涵盖从入门到高级的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [基本路由](#3-基本路由)
4. [路由导航](#4-路由导航)
5. [嵌套路由](#5-嵌套路由)
6. [动态路由](#6-动态路由)
7. [编程式导航](#7-编程式导航)
8. [路由参数](#8-路由参数)
9. [路由守卫](#9-路由守卫)
10. [数据加载](#10-数据加载)
11. [懒加载](#11-懒加载)
12. [滚动恢复](#12-滚动恢复)
13. [路由配置](#13-路由配置)
14. [常见错误与解决方案](#14-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 React Router？

React Router 是一个基于 React 的路由库，它允许你在单页应用中实现多页面的导航体验。用户点击链接时，不会真正刷新页面，而是通过 JavaScript 动态更新页面内容。

**核心概念：**
- **路由（Route）**：URL 路径与组件的映射关系
- **导航（Navigation）**：在不同路由之间切换
- **历史记录（History）**：浏览器的前进/后退功能

### 1.2 React Router v6 vs v5

```
┌─────────────────────────────────────────────────────────────────────┐
│                    React Router v6 主要变化                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  路由定义:                                                           │
│  • <Switch> → <Routes>                                              │
│  • <Route component={...}> → <Route element={<.../>}>               │
│  • 不再需要 exact 属性（默认精确匹配）                                │
│                                                                      │
│  导航:                                                               │
│  • useHistory() → useNavigate()                                     │
│  • <Redirect> → <Navigate>                                          │
│                                                                      │
│  嵌套路由:                                                           │
│  • 使用 <Outlet> 渲染子路由                                         │
│  • 相对路径更加直观                                                  │
│                                                                      │
│  新特性:                                                             │
│  • 数据路由（Data Router）                                          │
│  • loader 和 action                                                 │
│  • 更好的 TypeScript 支持                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 路由模式

```tsx
// 1. BrowserRouter - 使用 HTML5 History API（推荐）
// URL 格式：https://example.com/users/123
import { BrowserRouter } from 'react-router-dom'

// 2. HashRouter - 使用 URL hash
// URL 格式：https://example.com/#/users/123
import { HashRouter } from 'react-router-dom'

// 3. MemoryRouter - 内存中的路由（测试/非浏览器环境）
import { MemoryRouter } from 'react-router-dom'

// 4. StaticRouter - 服务端渲染
import { StaticRouter } from 'react-router-dom/server'
```

---

## 2. 安装与配置

### 2.1 安装

```bash
# npm
npm install react-router-dom

# yarn
yarn add react-router-dom

# pnpm
pnpm add react-router-dom
```

### 2.2 基本配置

```tsx
// src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)
```

```tsx
// src/App.tsx
import { Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import About from './pages/About'
import NotFound from './pages/NotFound'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/about" element={<About />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

export default App
```

### 2.3 项目结构

```
src/
├── components/        # 通用组件
│   ├── Layout/
│   └── ...
├── pages/            # 页面组件
│   ├── Home/
│   ├── About/
│   ├── User/
│   └── NotFound/
├── router/           # 路由配置
│   ├── index.tsx     # 路由定义
│   └── guards.tsx    # 路由守卫
├── App.tsx
└── main.tsx
```

---

## 3. 基本路由

### 3.1 Routes 和 Route

```tsx
import { Routes, Route } from 'react-router-dom'

function App() {
  return (
    <Routes>
      {/* 基本路由 */}
      <Route path="/" element={<Home />} />
      <Route path="/about" element={<About />} />
      <Route path="/contact" element={<Contact />} />
      
      {/* 404 页面 - 匹配所有未定义的路由 */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

// 页面组件
function Home() {
  return <h1>Home Page</h1>
}

function About() {
  return <h1>About Page</h1>
}

function NotFound() {
  return <h1>404 - Page Not Found</h1>
}
```

### 3.2 路由匹配规则

```tsx
<Routes>
  {/* 精确匹配（v6 默认行为） */}
  <Route path="/" element={<Home />} />
  
  {/* 路径参数 */}
  <Route path="/users/:id" element={<UserDetail />} />
  
  {/* 可选参数 */}
  <Route path="/posts/:id?" element={<Posts />} />
  
  {/* 通配符 - 匹配所有 */}
  <Route path="*" element={<NotFound />} />
  
  {/* 通配符 - 匹配子路径 */}
  <Route path="/files/*" element={<FileExplorer />} />
</Routes>
```

### 3.3 索引路由

```tsx
<Routes>
  <Route path="/users" element={<UsersLayout />}>
    {/* 索引路由：当访问 /users 时显示 */}
    <Route index element={<UserList />} />
    
    {/* 子路由：/users/:id */}
    <Route path=":id" element={<UserDetail />} />
  </Route>
</Routes>
```

---

## 4. 路由导航

### 4.1 Link 组件

```tsx
import { Link } from 'react-router-dom'

function Navigation() {
  return (
    <nav>
      {/* 基本链接 */}
      <Link to="/">Home</Link>
      <Link to="/about">About</Link>
      
      {/* 带状态的链接 */}
      <Link to="/profile" state={{ from: 'navigation' }}>
        Profile
      </Link>
      
      {/* 替换历史记录（不能后退） */}
      <Link to="/login" replace>
        Login
      </Link>
      
      {/* 相对路径 */}
      <Link to="../">Go Back</Link>
      <Link to="./details">Details</Link>
    </nav>
  )
}
```

### 4.2 NavLink 组件

NavLink 是特殊的 Link，可以知道自己是否处于激活状态。

```tsx
import { NavLink } from 'react-router-dom'

function Navigation() {
  return (
    <nav>
      {/* 自动添加 active 类名 */}
      <NavLink to="/">Home</NavLink>
      
      {/* 自定义激活样式 */}
      <NavLink 
        to="/about"
        className={({ isActive }) => isActive ? 'active' : ''}
      >
        About
      </NavLink>
      
      {/* 使用 style */}
      <NavLink
        to="/contact"
        style={({ isActive }) => ({
          color: isActive ? 'red' : 'black',
          fontWeight: isActive ? 'bold' : 'normal'
        })}
      >
        Contact
      </NavLink>
      
      {/* 使用 children 函数 */}
      <NavLink to="/profile">
        {({ isActive, isPending }) => (
          <span className={isActive ? 'active' : isPending ? 'pending' : ''}>
            Profile
          </span>
        )}
      </NavLink>
      
      {/* end 属性：精确匹配（子路由不激活父路由） */}
      <NavLink to="/users" end>
        Users
      </NavLink>
    </nav>
  )
}
```

### 4.3 Navigate 组件

用于重定向。

```tsx
import { Navigate } from 'react-router-dom'

// 条件重定向
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuth()
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  
  return <>{children}</>
}

// 在路由配置中重定向
<Routes>
  <Route path="/" element={<Home />} />
  <Route path="/home" element={<Navigate to="/" replace />} />
  <Route path="/old-path" element={<Navigate to="/new-path" />} />
</Routes>
```


---

## 5. 嵌套路由

嵌套路由是 React Router 的核心特性，允许你构建复杂的页面布局。

### 5.1 基本嵌套

```tsx
import { Routes, Route, Outlet } from 'react-router-dom'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        {/* 这些路由会渲染在 Layout 的 <Outlet /> 位置 */}
        <Route index element={<Home />} />
        <Route path="about" element={<About />} />
        <Route path="users" element={<Users />}>
          <Route index element={<UserList />} />
          <Route path=":id" element={<UserDetail />} />
        </Route>
      </Route>
    </Routes>
  )
}

// 布局组件
function Layout() {
  return (
    <div>
      <header>
        <nav>
          <Link to="/">Home</Link>
          <Link to="/about">About</Link>
          <Link to="/users">Users</Link>
        </nav>
      </header>
      
      <main>
        {/* 子路由在这里渲染 */}
        <Outlet />
      </main>
      
      <footer>Footer</footer>
    </div>
  )
}

// Users 布局
function Users() {
  return (
    <div>
      <h1>Users</h1>
      <nav>
        <Link to="/users">All Users</Link>
      </nav>
      {/* 子路由在这里渲染 */}
      <Outlet />
    </div>
  )
}
```

### 5.2 Outlet 上下文

```tsx
import { Outlet, useOutletContext } from 'react-router-dom'

// 父组件传递上下文
function UsersLayout() {
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  
  return (
    <div>
      <h1>Users</h1>
      {/* 通过 context 传递数据给子路由 */}
      <Outlet context={{ selectedUser, setSelectedUser }} />
    </div>
  )
}

// 定义上下文类型
interface UsersContext {
  selectedUser: User | null
  setSelectedUser: (user: User | null) => void
}

// 子组件接收上下文
function UserDetail() {
  const { selectedUser, setSelectedUser } = useOutletContext<UsersContext>()
  
  return (
    <div>
      <h2>{selectedUser?.name}</h2>
    </div>
  )
}
```

### 5.3 多层嵌套

```tsx
<Routes>
  <Route path="/" element={<RootLayout />}>
    <Route index element={<Home />} />
    
    <Route path="dashboard" element={<DashboardLayout />}>
      <Route index element={<DashboardHome />} />
      
      <Route path="settings" element={<SettingsLayout />}>
        <Route index element={<GeneralSettings />} />
        <Route path="profile" element={<ProfileSettings />} />
        <Route path="security" element={<SecuritySettings />} />
      </Route>
      
      <Route path="analytics" element={<Analytics />} />
    </Route>
  </Route>
</Routes>

// URL: /dashboard/settings/profile
// 渲染层级: RootLayout > DashboardLayout > SettingsLayout > ProfileSettings
```

### 5.4 无布局嵌套

有时候你只想组织路由，不需要额外的布局组件。

```tsx
<Routes>
  <Route path="/">
    <Route index element={<Home />} />
    
    {/* 无布局的路由组 */}
    <Route path="auth">
      <Route path="login" element={<Login />} />
      <Route path="register" element={<Register />} />
      <Route path="forgot-password" element={<ForgotPassword />} />
    </Route>
  </Route>
</Routes>

// /auth/login -> <Login />
// /auth/register -> <Register />
```

---

## 6. 动态路由

### 6.1 路径参数

```tsx
import { useParams } from 'react-router-dom'

// 路由定义
<Route path="/users/:userId" element={<UserProfile />} />
<Route path="/posts/:postId/comments/:commentId" element={<Comment />} />

// 获取参数
function UserProfile() {
  const { userId } = useParams<{ userId: string }>()
  
  return <div>User ID: {userId}</div>
}

function Comment() {
  const { postId, commentId } = useParams<{
    postId: string
    commentId: string
  }>()
  
  return (
    <div>
      Post: {postId}, Comment: {commentId}
    </div>
  )
}
```

### 6.2 可选参数

```tsx
// 使用 ? 表示可选
<Route path="/products/:category?" element={<Products />} />

function Products() {
  const { category } = useParams<{ category?: string }>()
  
  if (category) {
    return <div>Category: {category}</div>
  }
  
  return <div>All Products</div>
}

// /products -> All Products
// /products/electronics -> Category: electronics
```

### 6.3 通配符参数

```tsx
// 使用 * 匹配剩余路径
<Route path="/files/*" element={<FileExplorer />} />

function FileExplorer() {
  const { '*': filePath } = useParams()
  
  return <div>File Path: {filePath}</div>
}

// /files/documents/report.pdf -> File Path: documents/report.pdf
```

### 6.4 类型安全的参数

```tsx
// 定义参数类型
interface UserParams {
  userId: string
}

// 使用泛型
function UserProfile() {
  const params = useParams<UserParams>()
  
  // params.userId 是 string | undefined
  if (!params.userId) {
    return <div>Invalid user</div>
  }
  
  return <div>User: {params.userId}</div>
}

// 更严格的类型（使用 as）
function UserProfile() {
  const { userId } = useParams() as UserParams
  
  // 注意：这假设 userId 一定存在
  return <div>User: {userId}</div>
}
```

---

## 7. 编程式导航

### 7.1 useNavigate

```tsx
import { useNavigate } from 'react-router-dom'

function LoginForm() {
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      await login(credentials)
      
      // 导航到首页
      navigate('/')
      
      // 替换当前历史记录（不能后退）
      navigate('/dashboard', { replace: true })
      
      // 传递状态
      navigate('/profile', { state: { from: 'login' } })
      
      // 相对导航
      navigate('../')  // 上一级
      navigate('./details')  // 当前级别的 details
      
      // 后退/前进
      navigate(-1)  // 后退一步
      navigate(-2)  // 后退两步
      navigate(1)   // 前进一步
      
    } catch (error) {
      console.error('Login failed')
    }
  }
  
  return <form onSubmit={handleSubmit}>...</form>
}
```

### 7.2 导航选项

```tsx
const navigate = useNavigate()

// 完整选项
navigate('/path', {
  replace: true,           // 替换当前历史记录
  state: { key: 'value' }, // 传递状态
  preventScrollReset: true, // 阻止滚动重置
  relative: 'path',        // 相对于路径而非路由
})
```

### 7.3 获取导航状态

```tsx
import { useLocation, useNavigationType } from 'react-router-dom'

function MyComponent() {
  const location = useLocation()
  const navigationType = useNavigationType()
  
  // location 对象
  console.log(location.pathname)  // '/users/123'
  console.log(location.search)    // '?tab=profile'
  console.log(location.hash)      // '#section1'
  console.log(location.state)     // { from: 'login' }
  console.log(location.key)       // 唯一标识
  
  // 导航类型
  console.log(navigationType)  // 'POP' | 'PUSH' | 'REPLACE'
  
  return <div>...</div>
}
```

### 7.4 阻止导航

```tsx
import { useBlocker } from 'react-router-dom'

function EditForm() {
  const [isDirty, setIsDirty] = useState(false)
  
  // 当表单有未保存的更改时阻止导航
  const blocker = useBlocker(
    ({ currentLocation, nextLocation }) =>
      isDirty && currentLocation.pathname !== nextLocation.pathname
  )
  
  return (
    <div>
      <form onChange={() => setIsDirty(true)}>
        {/* 表单内容 */}
      </form>
      
      {blocker.state === 'blocked' && (
        <div className="modal">
          <p>You have unsaved changes. Are you sure you want to leave?</p>
          <button onClick={() => blocker.proceed()}>Leave</button>
          <button onClick={() => blocker.reset()}>Stay</button>
        </div>
      )}
    </div>
  )
}
```

---

## 8. 路由参数

### 8.1 查询参数

```tsx
import { useSearchParams } from 'react-router-dom'

function ProductList() {
  const [searchParams, setSearchParams] = useSearchParams()
  
  // 获取参数
  const page = searchParams.get('page') || '1'
  const category = searchParams.get('category')
  const sort = searchParams.get('sort') || 'newest'
  
  // 获取所有同名参数
  const tags = searchParams.getAll('tag')  // ['react', 'typescript']
  
  // 检查参数是否存在
  const hasFilter = searchParams.has('filter')
  
  // 设置参数
  const handlePageChange = (newPage: number) => {
    setSearchParams({ page: String(newPage), sort })
  }
  
  // 追加参数
  const addFilter = (filter: string) => {
    searchParams.set('filter', filter)
    setSearchParams(searchParams)
  }
  
  // 删除参数
  const clearFilter = () => {
    searchParams.delete('filter')
    setSearchParams(searchParams)
  }
  
  // 使用函数式更新
  const toggleSort = () => {
    setSearchParams(prev => {
      prev.set('sort', prev.get('sort') === 'asc' ? 'desc' : 'asc')
      return prev
    })
  }
  
  return (
    <div>
      <p>Page: {page}</p>
      <p>Category: {category}</p>
      <p>Sort: {sort}</p>
      
      <button onClick={() => handlePageChange(Number(page) + 1)}>
        Next Page
      </button>
    </div>
  )
}
```

### 8.2 状态参数

```tsx
import { useLocation, useNavigate, Link } from 'react-router-dom'

// 通过 Link 传递状态
<Link to="/profile" state={{ from: 'home', timestamp: Date.now() }}>
  Profile
</Link>

// 通过 navigate 传递状态
const navigate = useNavigate()
navigate('/profile', { state: { from: 'home' } })

// 接收状态
function Profile() {
  const location = useLocation()
  const state = location.state as { from?: string } | null
  
  return (
    <div>
      {state?.from && <p>You came from: {state.from}</p>}
    </div>
  )
}
```

### 8.3 组合使用

```tsx
function UserProfile() {
  const { userId } = useParams<{ userId: string }>()
  const [searchParams] = useSearchParams()
  const location = useLocation()
  
  const tab = searchParams.get('tab') || 'overview'
  const state = location.state as { from?: string } | null
  
  return (
    <div>
      <h1>User: {userId}</h1>
      <p>Current Tab: {tab}</p>
      {state?.from && <p>Came from: {state.from}</p>}
      
      <nav>
        <Link to={`/users/${userId}?tab=overview`}>Overview</Link>
        <Link to={`/users/${userId}?tab=posts`}>Posts</Link>
        <Link to={`/users/${userId}?tab=settings`}>Settings</Link>
      </nav>
    </div>
  )
}
```


---

## 9. 路由守卫

### 9.1 认证守卫

```tsx
import { Navigate, useLocation } from 'react-router-dom'

// 认证上下文
interface AuthContextType {
  user: User | null
  login: (credentials: Credentials) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}

// 受保护的路由组件
interface ProtectedRouteProps {
  children: React.ReactNode
  requiredRoles?: string[]
}

function ProtectedRoute({ children, requiredRoles }: ProtectedRouteProps) {
  const { user } = useAuth()
  const location = useLocation()
  
  // 未登录，重定向到登录页
  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  
  // 检查角色权限
  if (requiredRoles && !requiredRoles.some(role => user.roles.includes(role))) {
    return <Navigate to="/unauthorized" replace />
  }
  
  return <>{children}</>
}

// 使用
function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      
      {/* 受保护的路由 */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        }
      />
      
      {/* 需要特定角色 */}
      <Route
        path="/admin"
        element={
          <ProtectedRoute requiredRoles={['admin']}>
            <AdminPanel />
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}
```

### 9.2 布局级守卫

```tsx
// 受保护的布局
function ProtectedLayout() {
  const { user, loading } = useAuth()
  const location = useLocation()
  
  if (loading) {
    return <LoadingSpinner />
  }
  
  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  
  return (
    <div>
      <Header user={user} />
      <Outlet />
      <Footer />
    </div>
  )
}

// 路由配置
<Routes>
  <Route path="/" element={<PublicLayout />}>
    <Route index element={<Home />} />
    <Route path="about" element={<About />} />
  </Route>
  
  {/* 所有子路由都受保护 */}
  <Route element={<ProtectedLayout />}>
    <Route path="dashboard" element={<Dashboard />} />
    <Route path="profile" element={<Profile />} />
    <Route path="settings" element={<Settings />} />
  </Route>
</Routes>
```

### 9.3 登录后重定向

```tsx
function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  
  // 获取来源页面
  const from = (location.state as { from?: Location })?.from?.pathname || '/'
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      await login(credentials)
      // 登录成功后返回来源页面
      navigate(from, { replace: true })
    } catch (error) {
      // 处理错误
    }
  }
  
  return <form onSubmit={handleSubmit}>...</form>
}
```

### 9.4 权限组件

```tsx
interface PermissionProps {
  children: React.ReactNode
  permissions: string[]
  fallback?: React.ReactNode
}

function Permission({ children, permissions, fallback = null }: PermissionProps) {
  const { user } = useAuth()
  
  const hasPermission = permissions.every(
    permission => user?.permissions.includes(permission)
  )
  
  if (!hasPermission) {
    return <>{fallback}</>
  }
  
  return <>{children}</>
}

// 使用
function Dashboard() {
  return (
    <div>
      <h1>Dashboard</h1>
      
      <Permission permissions={['read:users']}>
        <UserList />
      </Permission>
      
      <Permission 
        permissions={['write:users']} 
        fallback={<p>You don't have permission to create users</p>}
      >
        <CreateUserButton />
      </Permission>
    </div>
  )
}
```

---

## 10. 数据加载

React Router v6.4+ 引入了数据路由，支持在路由级别加载数据。

### 10.1 创建数据路由

```tsx
import {
  createBrowserRouter,
  RouterProvider,
  useLoaderData,
} from 'react-router-dom'

// 创建路由
const router = createBrowserRouter([
  {
    path: '/',
    element: <Root />,
    children: [
      {
        index: true,
        element: <Home />,
      },
      {
        path: 'users',
        element: <Users />,
        loader: usersLoader,  // 数据加载器
      },
      {
        path: 'users/:userId',
        element: <UserDetail />,
        loader: userDetailLoader,
      },
    ],
  },
])

// 使用 RouterProvider
function App() {
  return <RouterProvider router={router} />
}
```

### 10.2 Loader 函数

```tsx
import { LoaderFunctionArgs } from 'react-router-dom'

// 基本 loader
async function usersLoader() {
  const response = await fetch('/api/users')
  if (!response.ok) {
    throw new Response('Failed to load users', { status: 500 })
  }
  return response.json()
}

// 带参数的 loader
async function userDetailLoader({ params }: LoaderFunctionArgs) {
  const response = await fetch(`/api/users/${params.userId}`)
  if (!response.ok) {
    throw new Response('User not found', { status: 404 })
  }
  return response.json()
}

// 带查询参数的 loader
async function searchLoader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url)
  const query = url.searchParams.get('q')
  
  const response = await fetch(`/api/search?q=${query}`)
  return response.json()
}

// 在组件中使用数据
function Users() {
  const users = useLoaderData() as User[]
  
  return (
    <ul>
      {users.map(user => (
        <li key={user.id}>{user.name}</li>
      ))}
    </ul>
  )
}
```

### 10.3 Action 函数

处理表单提交和数据变更。

```tsx
import {
  Form,
  useActionData,
  useNavigation,
  redirect,
} from 'react-router-dom'

// Action 函数
async function createUserAction({ request }: ActionFunctionArgs) {
  const formData = await request.formData()
  const name = formData.get('name')
  const email = formData.get('email')
  
  // 验证
  const errors: Record<string, string> = {}
  if (!name) errors.name = 'Name is required'
  if (!email) errors.email = 'Email is required'
  
  if (Object.keys(errors).length > 0) {
    return { errors }
  }
  
  // 创建用户
  await fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify({ name, email }),
  })
  
  // 重定向
  return redirect('/users')
}

// 路由配置
{
  path: 'users/new',
  element: <CreateUser />,
  action: createUserAction,
}

// 组件
function CreateUser() {
  const actionData = useActionData() as { errors?: Record<string, string> }
  const navigation = useNavigation()
  
  const isSubmitting = navigation.state === 'submitting'
  
  return (
    <Form method="post">
      <div>
        <label>Name</label>
        <input name="name" />
        {actionData?.errors?.name && (
          <span className="error">{actionData.errors.name}</span>
        )}
      </div>
      
      <div>
        <label>Email</label>
        <input name="email" type="email" />
        {actionData?.errors?.email && (
          <span className="error">{actionData.errors.email}</span>
        )}
      </div>
      
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Creating...' : 'Create User'}
      </button>
    </Form>
  )
}
```

### 10.4 错误处理

```tsx
import { useRouteError, isRouteErrorResponse } from 'react-router-dom'

// 错误边界组件
function ErrorBoundary() {
  const error = useRouteError()
  
  if (isRouteErrorResponse(error)) {
    // 路由错误响应
    return (
      <div>
        <h1>{error.status}</h1>
        <p>{error.statusText}</p>
        {error.data?.message && <p>{error.data.message}</p>}
      </div>
    )
  }
  
  // 其他错误
  return (
    <div>
      <h1>Oops!</h1>
      <p>Something went wrong</p>
    </div>
  )
}

// 路由配置
const router = createBrowserRouter([
  {
    path: '/',
    element: <Root />,
    errorElement: <ErrorBoundary />,  // 根级错误边界
    children: [
      {
        path: 'users/:userId',
        element: <UserDetail />,
        loader: userDetailLoader,
        errorElement: <UserError />,  // 路由级错误边界
      },
    ],
  },
])
```

### 10.5 加载状态

```tsx
import { useNavigation } from 'react-router-dom'

function Root() {
  const navigation = useNavigation()
  
  // navigation.state: 'idle' | 'loading' | 'submitting'
  const isLoading = navigation.state === 'loading'
  
  return (
    <div>
      {isLoading && <LoadingBar />}
      <Outlet />
    </div>
  )
}

// 或使用 defer 实现流式加载
import { defer, Await } from 'react-router-dom'

async function dashboardLoader() {
  // 关键数据立即加载
  const user = await fetchUser()
  
  // 非关键数据延迟加载
  const statsPromise = fetchStats()
  const notificationsPromise = fetchNotifications()
  
  return defer({
    user,
    stats: statsPromise,
    notifications: notificationsPromise,
  })
}

function Dashboard() {
  const { user, stats, notifications } = useLoaderData() as {
    user: User
    stats: Promise<Stats>
    notifications: Promise<Notification[]>
  }
  
  return (
    <div>
      <h1>Welcome, {user.name}</h1>
      
      <Suspense fallback={<StatsLoading />}>
        <Await resolve={stats}>
          {(resolvedStats) => <StatsPanel stats={resolvedStats} />}
        </Await>
      </Suspense>
      
      <Suspense fallback={<NotificationsLoading />}>
        <Await resolve={notifications} errorElement={<NotificationsError />}>
          {(resolvedNotifications) => (
            <NotificationsList notifications={resolvedNotifications} />
          )}
        </Await>
      </Suspense>
    </div>
  )
}
```

---

## 11. 懒加载

### 11.1 基本懒加载

```tsx
import { lazy, Suspense } from 'react'
import { Routes, Route } from 'react-router-dom'

// 懒加载组件
const Home = lazy(() => import('./pages/Home'))
const About = lazy(() => import('./pages/About'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const UserProfile = lazy(() => import('./pages/UserProfile'))

function App() {
  return (
    <Suspense fallback={<LoadingSpinner />}>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/users/:id" element={<UserProfile />} />
      </Routes>
    </Suspense>
  )
}
```

### 11.2 路由级 Suspense

```tsx
function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route
          index
          element={
            <Suspense fallback={<PageLoading />}>
              <Home />
            </Suspense>
          }
        />
        <Route
          path="dashboard"
          element={
            <Suspense fallback={<PageLoading />}>
              <Dashboard />
            </Suspense>
          }
        />
      </Route>
    </Routes>
  )
}
```

### 11.3 预加载

```tsx
// 定义懒加载组件
const Dashboard = lazy(() => import('./pages/Dashboard'))

// 预加载函数
const preloadDashboard = () => import('./pages/Dashboard')

function Navigation() {
  return (
    <nav>
      <Link to="/">Home</Link>
      {/* 鼠标悬停时预加载 */}
      <Link 
        to="/dashboard" 
        onMouseEnter={preloadDashboard}
      >
        Dashboard
      </Link>
    </nav>
  )
}
```

### 11.4 数据路由的懒加载

```tsx
const router = createBrowserRouter([
  {
    path: '/',
    element: <Root />,
    children: [
      {
        path: 'dashboard',
        // 懒加载整个路由模块
        lazy: () => import('./routes/dashboard'),
      },
    ],
  },
])

// routes/dashboard.tsx
export async function loader() {
  const data = await fetchDashboardData()
  return data
}

export function Component() {
  const data = useLoaderData()
  return <Dashboard data={data} />
}

// 可选：错误边界
export function ErrorBoundary() {
  return <DashboardError />
}
```


---

## 12. 滚动恢复

### 12.1 基本滚动恢复

```tsx
import { ScrollRestoration } from 'react-router-dom'

function Root() {
  return (
    <>
      <Outlet />
      {/* 自动恢复滚动位置 */}
      <ScrollRestoration />
    </>
  )
}
```

### 12.2 自定义滚动行为

```tsx
<ScrollRestoration
  getKey={(location, matches) => {
    // 默认使用 location.key
    // 可以自定义 key 来控制滚动恢复
    
    // 按路径恢复（同一路径共享滚动位置）
    return location.pathname
    
    // 或者某些路径不恢复
    const paths = ['/home', '/about']
    return paths.includes(location.pathname)
      ? location.pathname
      : location.key
  }}
/>
```

### 12.3 手动滚动控制

```tsx
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

function ScrollToTop() {
  const { pathname } = useLocation()
  
  useEffect(() => {
    window.scrollTo(0, 0)
  }, [pathname])
  
  return null
}

// 使用
function App() {
  return (
    <>
      <ScrollToTop />
      <Routes>...</Routes>
    </>
  )
}
```

### 12.4 滚动到锚点

```tsx
import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

function ScrollToHash() {
  const { hash } = useLocation()
  
  useEffect(() => {
    if (hash) {
      const element = document.querySelector(hash)
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' })
      }
    }
  }, [hash])
  
  return null
}

// 链接到锚点
<Link to="/page#section1">Go to Section 1</Link>
```

---

## 13. 路由配置

### 13.1 集中式路由配置

```tsx
// src/router/routes.tsx
import { RouteObject } from 'react-router-dom'
import { lazy } from 'react'

// 懒加载组件
const Home = lazy(() => import('@/pages/Home'))
const About = lazy(() => import('@/pages/About'))
const Dashboard = lazy(() => import('@/pages/Dashboard'))
const UserList = lazy(() => import('@/pages/User/List'))
const UserDetail = lazy(() => import('@/pages/User/Detail'))
const Login = lazy(() => import('@/pages/Login'))
const NotFound = lazy(() => import('@/pages/NotFound'))

// 布局组件
import RootLayout from '@/layouts/RootLayout'
import DashboardLayout from '@/layouts/DashboardLayout'
import AuthLayout from '@/layouts/AuthLayout'

// 路由守卫
import ProtectedRoute from '@/components/ProtectedRoute'

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <RootLayout />,
    children: [
      { index: true, element: <Home /> },
      { path: 'about', element: <About /> },
      
      // 受保护的路由
      {
        element: <ProtectedRoute />,
        children: [
          {
            path: 'dashboard',
            element: <DashboardLayout />,
            children: [
              { index: true, element: <Dashboard /> },
              { path: 'users', element: <UserList /> },
              { path: 'users/:id', element: <UserDetail /> },
            ],
          },
        ],
      },
    ],
  },
  
  // 认证路由
  {
    path: '/auth',
    element: <AuthLayout />,
    children: [
      { path: 'login', element: <Login /> },
      { path: 'register', element: <Register /> },
    ],
  },
  
  // 404
  { path: '*', element: <NotFound /> },
]
```

```tsx
// src/router/index.tsx
import { createBrowserRouter } from 'react-router-dom'
import { routes } from './routes'

export const router = createBrowserRouter(routes)
```

```tsx
// src/App.tsx
import { RouterProvider } from 'react-router-dom'
import { router } from './router'

function App() {
  return <RouterProvider router={router} />
}
```

### 13.2 使用 useRoutes

```tsx
import { useRoutes } from 'react-router-dom'

function App() {
  const element = useRoutes([
    {
      path: '/',
      element: <Layout />,
      children: [
        { index: true, element: <Home /> },
        { path: 'about', element: <About /> },
        {
          path: 'users',
          children: [
            { index: true, element: <UserList /> },
            { path: ':id', element: <UserDetail /> },
          ],
        },
      ],
    },
    { path: '*', element: <NotFound /> },
  ])
  
  return element
}
```

### 13.3 动态路由配置

```tsx
// 根据用户权限动态生成路由
function useRouteConfig() {
  const { user } = useAuth()
  
  const routes = useMemo(() => {
    const baseRoutes: RouteObject[] = [
      { path: '/', element: <Home /> },
      { path: '/about', element: <About /> },
    ]
    
    if (user) {
      baseRoutes.push({
        path: '/dashboard',
        element: <Dashboard />,
      })
      
      if (user.role === 'admin') {
        baseRoutes.push({
          path: '/admin',
          element: <AdminPanel />,
        })
      }
    }
    
    baseRoutes.push({ path: '*', element: <NotFound /> })
    
    return baseRoutes
  }, [user])
  
  return routes
}

function App() {
  const routes = useRouteConfig()
  const element = useRoutes(routes)
  
  return element
}
```

### 13.4 路由元信息

```tsx
// 定义路由元信息类型
interface RouteMeta {
  title?: string
  requiresAuth?: boolean
  roles?: string[]
}

interface AppRouteObject extends RouteObject {
  meta?: RouteMeta
  children?: AppRouteObject[]
}

// 路由配置
const routes: AppRouteObject[] = [
  {
    path: '/',
    element: <Home />,
    meta: { title: 'Home' },
  },
  {
    path: '/dashboard',
    element: <Dashboard />,
    meta: { 
      title: 'Dashboard',
      requiresAuth: true,
    },
  },
  {
    path: '/admin',
    element: <Admin />,
    meta: {
      title: 'Admin Panel',
      requiresAuth: true,
      roles: ['admin'],
    },
  },
]

// 使用路由元信息
function useRouteMeta() {
  const location = useLocation()
  
  const findRoute = (
    routes: AppRouteObject[],
    pathname: string
  ): AppRouteObject | undefined => {
    for (const route of routes) {
      if (matchPath(route.path || '', pathname)) {
        return route
      }
      if (route.children) {
        const child = findRoute(route.children, pathname)
        if (child) return child
      }
    }
  }
  
  return findRoute(routes, location.pathname)?.meta
}

// 更新页面标题
function TitleUpdater() {
  const meta = useRouteMeta()
  
  useEffect(() => {
    if (meta?.title) {
      document.title = `${meta.title} | My App`
    }
  }, [meta])
  
  return null
}
```

---

## 14. 常见错误与解决方案

### 14.1 路由不匹配

```tsx
// ❌ 错误：忘记包裹 BrowserRouter
function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
    </Routes>
  )
}
// 报错：useRoutes() may be used only in the context of a <Router>

// ✅ 正确：在入口处包裹
ReactDOM.createRoot(root).render(
  <BrowserRouter>
    <App />
  </BrowserRouter>
)

// ❌ 错误：路径不以 / 开头（在根级别）
<Route path="about" element={<About />} />

// ✅ 正确：根级路由以 / 开头
<Route path="/about" element={<About />} />

// ❌ 错误：嵌套路由使用绝对路径
<Route path="/users" element={<Users />}>
  <Route path="/users/:id" element={<UserDetail />} />
</Route>

// ✅ 正确：嵌套路由使用相对路径
<Route path="/users" element={<Users />}>
  <Route path=":id" element={<UserDetail />} />
</Route>
```

### 14.2 导航问题

```tsx
// ❌ 错误：在组件外使用 useNavigate
const navigate = useNavigate()  // 报错

function handleClick() {
  navigate('/home')
}

// ✅ 正确：在组件内使用
function MyComponent() {
  const navigate = useNavigate()
  
  const handleClick = () => {
    navigate('/home')
  }
  
  return <button onClick={handleClick}>Go Home</button>
}

// ❌ 错误：Link 的 to 属性使用对象但格式错误
<Link to={{ path: '/users' }}>Users</Link>

// ✅ 正确：使用 pathname
<Link to={{ pathname: '/users', search: '?page=1' }}>Users</Link>
// 或直接使用字符串
<Link to="/users?page=1">Users</Link>
```

### 14.3 参数获取问题

```tsx
// ❌ 错误：useParams 返回的是字符串
function UserDetail() {
  const { userId } = useParams()
  
  // userId 是 string | undefined，不是 number
  const user = users.find(u => u.id === userId)  // 可能找不到
}

// ✅ 正确：转换类型
function UserDetail() {
  const { userId } = useParams()
  
  const user = users.find(u => u.id === Number(userId))
  // 或
  const user = users.find(u => String(u.id) === userId)
}

// ❌ 错误：假设参数一定存在
function UserDetail() {
  const { userId } = useParams<{ userId: string }>()
  
  // userId 可能是 undefined
  fetch(`/api/users/${userId}`)  // 可能是 /api/users/undefined
}

// ✅ 正确：处理 undefined 情况
function UserDetail() {
  const { userId } = useParams<{ userId: string }>()
  
  if (!userId) {
    return <Navigate to="/users" />
  }
  
  // 现在 userId 一定有值
  fetch(`/api/users/${userId}`)
}
```

### 14.4 嵌套路由问题

```tsx
// ❌ 错误：忘记添加 Outlet
function Layout() {
  return (
    <div>
      <Header />
      {/* 子路由无处渲染 */}
      <Footer />
    </div>
  )
}

// ✅ 正确：添加 Outlet
function Layout() {
  return (
    <div>
      <Header />
      <Outlet />  {/* 子路由在这里渲染 */}
      <Footer />
    </div>
  )
}

// ❌ 错误：索引路由使用 path
<Route path="/users" element={<Users />}>
  <Route path="" element={<UserList />} />  {/* 不会匹配 */}
</Route>

// ✅ 正确：使用 index
<Route path="/users" element={<Users />}>
  <Route index element={<UserList />} />
</Route>
```

### 14.5 重定向问题

```tsx
// ❌ 错误：在渲染期间调用 navigate
function MyComponent() {
  const navigate = useNavigate()
  
  if (someCondition) {
    navigate('/other')  // 不应该在渲染期间调用
  }
  
  return <div>...</div>
}

// ✅ 正确：使用 Navigate 组件
function MyComponent() {
  if (someCondition) {
    return <Navigate to="/other" />
  }
  
  return <div>...</div>
}

// ✅ 或在 useEffect 中调用
function MyComponent() {
  const navigate = useNavigate()
  
  useEffect(() => {
    if (someCondition) {
      navigate('/other')
    }
  }, [someCondition, navigate])
  
  return <div>...</div>
}
```

### 14.6 状态丢失问题

```tsx
// ❌ 问题：刷新页面后 state 丢失
<Link to="/profile" state={{ from: 'home' }}>Profile</Link>

function Profile() {
  const location = useLocation()
  const from = location.state?.from  // 刷新后是 null
}

// ✅ 解决：重要数据使用 URL 参数
<Link to="/profile?from=home">Profile</Link>

function Profile() {
  const [searchParams] = useSearchParams()
  const from = searchParams.get('from')  // 刷新后仍然存在
}

// ✅ 或使用 sessionStorage
function Profile() {
  const location = useLocation()
  
  useEffect(() => {
    if (location.state?.from) {
      sessionStorage.setItem('from', location.state.from)
    }
  }, [location.state])
  
  const from = location.state?.from || sessionStorage.getItem('from')
}
```

### 14.7 懒加载问题

```tsx
// ❌ 错误：懒加载组件没有 Suspense
const Dashboard = lazy(() => import('./Dashboard'))

function App() {
  return (
    <Routes>
      <Route path="/dashboard" element={<Dashboard />} />
    </Routes>
  )
}
// 报错：A component suspended while responding to synchronous input

// ✅ 正确：添加 Suspense
function App() {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Suspense>
  )
}

// ❌ 错误：在组件内部定义懒加载
function App() {
  // 每次渲染都创建新的懒加载组件
  const Dashboard = lazy(() => import('./Dashboard'))
  
  return <Route path="/dashboard" element={<Dashboard />} />
}

// ✅ 正确：在组件外部定义
const Dashboard = lazy(() => import('./Dashboard'))

function App() {
  return <Route path="/dashboard" element={<Dashboard />} />
}
```

### 14.8 数据加载问题

```tsx
// ❌ 错误：loader 中使用 hooks
async function userLoader({ params }) {
  const { user } = useAuth()  // 不能在 loader 中使用 hooks
  return fetchUser(params.id)
}

// ✅ 正确：通过其他方式获取数据
async function userLoader({ params, request }) {
  // 从 cookie 或 localStorage 获取 token
  const token = getAuthToken()
  
  const response = await fetch(`/api/users/${params.id}`, {
    headers: { Authorization: `Bearer ${token}` }
  })
  
  return response.json()
}

// ❌ 错误：忘记处理 loader 错误
async function userLoader({ params }) {
  const response = await fetch(`/api/users/${params.id}`)
  return response.json()  // 如果请求失败会返回错误的数据
}

// ✅ 正确：处理错误
async function userLoader({ params }) {
  const response = await fetch(`/api/users/${params.id}`)
  
  if (!response.ok) {
    throw new Response('User not found', { status: 404 })
  }
  
  return response.json()
}
```

---

## 附录：常用 API 速查

### 组件

| 组件 | 用途 |
|------|------|
| `<BrowserRouter>` | HTML5 History 路由 |
| `<HashRouter>` | Hash 路由 |
| `<Routes>` | 路由容器 |
| `<Route>` | 路由定义 |
| `<Link>` | 导航链接 |
| `<NavLink>` | 带激活状态的链接 |
| `<Navigate>` | 重定向 |
| `<Outlet>` | 子路由出口 |
| `<ScrollRestoration>` | 滚动恢复 |

### Hooks

| Hook | 用途 |
|------|------|
| `useNavigate` | 编程式导航 |
| `useParams` | 获取路径参数 |
| `useSearchParams` | 获取/设置查询参数 |
| `useLocation` | 获取当前位置 |
| `useRoutes` | 配置式路由 |
| `useOutletContext` | 获取 Outlet 上下文 |
| `useLoaderData` | 获取 loader 数据 |
| `useActionData` | 获取 action 数据 |
| `useNavigation` | 获取导航状态 |
| `useBlocker` | 阻止导航 |

---

> 📝 **笔记说明**
> - 本笔记基于 React Router v6.4+ 编写
> - 建议配合官方文档学习：https://reactrouter.com/
> - 数据路由特性需要使用 createBrowserRouter

---

*最后更新：2024年*
