

> Next.js 是一个基于 React 的全栈 Web 框架，提供服务端渲染(SSR)、静态生成(SSG)、API 路由等强大功能
> 本笔记基于 Next.js 13+ App Router + TypeScript

---

## 目录

1. [基础概念](#1-基础概念)
2. [项目搭建](#2-项目搭建)
3. [App Router 路由系统](#3-app-router-路由系统)
4. [页面与布局](#4-页面与布局)
5. [服务端组件与客户端组件](#5-服务端组件与客户端组件)
6. [数据获取](#6-数据获取)
7. [服务端操作 Server Actions](#7-服务端操作-server-actions)
8. [路由处理程序 Route Handlers](#8-路由处理程序-route-handlers)
9. [中间件 Middleware](#9-中间件-middleware)
10. [样式处理](#10-样式处理)
11. [图片与字体优化](#11-图片与字体优化)
12. [元数据与 SEO](#12-元数据与-seo)
13. [缓存机制](#13-缓存机制)
14. [错误处理](#14-错误处理)
15. [国际化 i18n](#15-国际化-i18n)
16. [身份认证](#16-身份认证)
17. [部署与优化](#17-部署与优化)
18. [常见错误与解决方案](#18-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Next.js？

Next.js 是由 Vercel 公司开发的 React 框架，它在 React 的基础上提供了许多开箱即用的功能：

- **服务端渲染 (SSR)**：页面在服务器上渲染，有利于 SEO 和首屏加载速度
- **静态站点生成 (SSG)**：在构建时生成静态 HTML，适合内容不常变化的页面
- **增量静态再生 (ISR)**：结合 SSG 和 SSR 的优点，可以在运行时更新静态页面
- **文件系统路由**：基于文件夹结构自动生成路由，无需手动配置
- **API 路由**：可以在同一项目中创建后端 API
- **内置优化**：自动代码分割、图片优化、字体优化等

### 1.2 Next.js 13+ 的重大变化

Next.js 13 引入了全新的 **App Router**，这是一个基于 React Server Components 的新路由系统：

| 特性 | Pages Router (旧) | App Router (新) |
|------|------------------|-----------------|
| 目录 | `pages/` | `app/` |
| 默认组件类型 | 客户端组件 | 服务端组件 |
| 数据获取 | `getServerSideProps` 等 | `async/await` 直接获取 |
| 布局 | `_app.js`, `_document.js` | `layout.tsx` |
| 加载状态 | 手动处理 | `loading.tsx` |
| 错误处理 | `_error.js` | `error.tsx` |

### 1.3 渲染模式详解

```
┌─────────────────────────────────────────────────────────────┐
│                    Next.js 渲染模式                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CSR (客户端渲染)     SSR (服务端渲染)     SSG (静态生成)      │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐    │
│  │ 浏览器请求   │     │ 浏览器请求   │     │ 构建时生成   │    │
│  │     ↓       │     │     ↓       │     │     ↓       │    │
│  │ 下载空HTML  │     │ 服务器渲染   │     │ 静态HTML    │    │
│  │     ↓       │     │     ↓       │     │     ↓       │    │
│  │ 下载JS      │     │ 返回完整HTML │     │ CDN分发     │    │
│  │     ↓       │     │     ↓       │     │     ↓       │    │
│  │ 客户端渲染   │     │ 客户端水合   │     │ 客户端水合   │    │
│  └─────────────┘     └─────────────┘     └─────────────┘    │
│                                                             │
│  适用：后台管理系统    适用：动态内容页面    适用：博客、文档   │
│  SEO：差              SEO：好              SEO：最好         │
│  首屏：慢             首屏：快              首屏：最快        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. 项目搭建

### 2.1 创建项目

```bash
# 使用 create-next-app 创建项目（推荐）
npx create-next-app@latest my-app

# 创建时会询问以下选项：
# ✔ Would you like to use TypeScript? Yes
# ✔ Would you like to use ESLint? Yes
# ✔ Would you like to use Tailwind CSS? Yes
# ✔ Would you like to use `src/` directory? Yes
# ✔ Would you like to use App Router? Yes
# ✔ Would you like to customize the default import alias? No

# 进入项目目录
cd my-app

# 启动开发服务器
npm run dev
```

### 2.2 项目结构

```
my-app/
├── src/
│   ├── app/                    # App Router 目录
│   │   ├── layout.tsx          # 根布局（必需）
│   │   ├── page.tsx            # 首页
│   │   ├── globals.css         # 全局样式
│   │   ├── favicon.ico         # 网站图标
│   │   ├── loading.tsx         # 加载状态
│   │   ├── error.tsx           # 错误处理
│   │   ├── not-found.tsx       # 404 页面
│   │   └── api/                # API 路由
│   │       └── route.ts
│   ├── components/             # 组件目录
│   ├── lib/                    # 工具函数
│   └── types/                  # TypeScript 类型
├── public/                     # 静态资源
├── next.config.js              # Next.js 配置
├── tailwind.config.ts          # Tailwind 配置
├── tsconfig.json               # TypeScript 配置
└── package.json
```

### 2.3 配置文件详解

```typescript
// next.config.js - Next.js 核心配置文件
/** @type {import('next').NextConfig} */
const nextConfig = {
  // 实验性功能
  experimental: {
    serverActions: true,        // 启用 Server Actions
    typedRoutes: true,          // 类型安全的路由
  },
  
  // 图片优化配置
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'example.com',
        port: '',
        pathname: '/images/**',
      },
    ],
    // 或使用 domains（已废弃，推荐 remotePatterns）
    // domains: ['example.com'],
  },
  
  // 重定向配置
  async redirects() {
    return [
      {
        source: '/old-page',
        destination: '/new-page',
        permanent: true,  // 301 永久重定向
      },
    ]
  },
  
  // 重写配置（URL 代理）
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'https://api.example.com/:path*',
      },
    ]
  },
  
  // 请求头配置
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
        ],
      },
    ]
  },
  
  // 环境变量（客户端可访问需要 NEXT_PUBLIC_ 前缀）
  env: {
    CUSTOM_KEY: 'custom-value',
  },
  
  // 输出模式
  output: 'standalone',  // 用于 Docker 部署
  
  // 基础路径（部署到子目录时使用）
  basePath: '/docs',
  
  // 严格模式
  reactStrictMode: true,
}

module.exports = nextConfig
```

### 2.4 环境变量

```bash
# .env.local - 本地开发环境（不提交到 git）
DATABASE_URL=postgresql://localhost:5432/mydb
API_SECRET=my-secret-key

# 客户端可访问的环境变量必须以 NEXT_PUBLIC_ 开头
NEXT_PUBLIC_API_URL=https://api.example.com
NEXT_PUBLIC_SITE_NAME=My Website

# .env.development - 开发环境
# .env.production - 生产环境
# .env.test - 测试环境
```

```typescript
// 使用环境变量
// 服务端（可以访问所有环境变量）
const dbUrl = process.env.DATABASE_URL

// 客户端（只能访问 NEXT_PUBLIC_ 开头的）
const apiUrl = process.env.NEXT_PUBLIC_API_URL
```

---

## 3. App Router 路由系统

### 3.1 文件系统路由

Next.js 使用文件系统作为路由，`app` 目录下的文件夹结构直接映射为 URL 路径：

```
app/
├── page.tsx                    → /
├── about/
│   └── page.tsx                → /about
├── blog/
│   ├── page.tsx                → /blog
│   └── [slug]/
│       └── page.tsx            → /blog/:slug (动态路由)
├── shop/
│   └── [...slug]/
│       └── page.tsx            → /shop/* (捕获所有路由)
└── (marketing)/                → 路由组（不影响 URL）
    ├── about/
    │   └── page.tsx            → /about
    └── contact/
        └── page.tsx            → /contact
```

### 3.2 特殊文件约定

| 文件名 | 作用 |
|--------|------|
| `page.tsx` | 页面组件，使路由可访问 |
| `layout.tsx` | 布局组件，包裹子页面 |
| `loading.tsx` | 加载状态 UI |
| `error.tsx` | 错误处理 UI |
| `not-found.tsx` | 404 页面 |
| `route.ts` | API 路由处理程序 |
| `template.tsx` | 类似 layout，但每次导航都重新挂载 |
| `default.tsx` | 并行路由的默认 UI |

### 3.3 动态路由

```typescript
// app/blog/[slug]/page.tsx - 单个动态参数
interface PageProps {
  params: { slug: string }
}

export default function BlogPost({ params }: PageProps) {
  return <h1>文章: {params.slug}</h1>
}

// 访问 /blog/hello-world → params.slug = "hello-world"
```

```typescript
// app/blog/[...slug]/page.tsx - 捕获所有路由
interface PageProps {
  params: { slug: string[] }
}

export default function CatchAll({ params }: PageProps) {
  return <h1>路径: {params.slug.join('/')}</h1>
}

// 访问 /blog/2024/01/hello → params.slug = ["2024", "01", "hello"]
```

```typescript
// app/blog/[[...slug]]/page.tsx - 可选捕获所有路由
// 可以匹配 /blog 和 /blog/xxx/xxx
interface PageProps {
  params: { slug?: string[] }
}

export default function OptionalCatchAll({ params }: PageProps) {
  if (!params.slug) {
    return <h1>博客首页</h1>
  }
  return <h1>路径: {params.slug.join('/')}</h1>
}
```

### 3.4 路由组

路由组使用 `(folderName)` 语法，不会影响 URL 路径，用于组织代码或共享布局：

```
app/
├── (marketing)/           # 营销页面组
│   ├── layout.tsx         # 营销页面共享布局
│   ├── about/
│   │   └── page.tsx       → /about
│   └── contact/
│       └── page.tsx       → /contact
├── (shop)/                # 商店页面组
│   ├── layout.tsx         # 商店页面共享布局
│   ├── products/
│   │   └── page.tsx       → /products
│   └── cart/
│       └── page.tsx       → /cart
└── layout.tsx             # 根布局
```

### 3.5 并行路由

并行路由允许在同一布局中同时渲染多个页面，使用 `@folderName` 语法：

```
app/
├── layout.tsx
├── page.tsx
├── @dashboard/
│   ├── page.tsx
│   └── loading.tsx
└── @analytics/
    ├── page.tsx
    └── loading.tsx
```

```typescript
// app/layout.tsx
export default function Layout({
  children,
  dashboard,
  analytics,
}: {
  children: React.ReactNode
  dashboard: React.ReactNode
  analytics: React.ReactNode
}) {
  return (
    <div>
      {children}
      <div className="grid grid-cols-2">
        {dashboard}
        {analytics}
      </div>
    </div>
  )
}
```

### 3.6 拦截路由

拦截路由可以在当前布局中加载另一个路由的内容，常用于模态框：

```
app/
├── feed/
│   └── page.tsx
├── photo/
│   └── [id]/
│       └── page.tsx        # 直接访问 /photo/1 显示完整页面
└── @modal/
    └── (.)photo/
        └── [id]/
            └── page.tsx    # 从 feed 点击时显示模态框
```

拦截约定：
- `(.)` - 匹配同级路由
- `(..)` - 匹配上一级路由
- `(..)(..)` - 匹配上两级路由
- `(...)` - 匹配根路由

### 3.7 导航

```typescript
// 使用 Link 组件（推荐）
import Link from 'next/link'

export default function Navigation() {
  return (
    <nav>
      {/* 基础链接 */}
      <Link href="/about">关于我们</Link>
      
      {/* 动态路由 */}
      <Link href={`/blog/${post.slug}`}>阅读更多</Link>
      
      {/* 带查询参数 */}
      <Link href={{ pathname: '/search', query: { q: 'nextjs' } }}>
        搜索
      </Link>
      
      {/* 替换历史记录（不能后退） */}
      <Link href="/dashboard" replace>
        仪表盘
      </Link>
      
      {/* 滚动到顶部（默认行为） */}
      <Link href="/page" scroll={true}>
        页面
      </Link>
      
      {/* 预加载（默认启用） */}
      <Link href="/heavy-page" prefetch={true}>
        重页面
      </Link>
    </nav>
  )
}
```

```typescript
// 使用 useRouter（客户端组件）
'use client'

import { useRouter, usePathname, useSearchParams } from 'next/navigation'

export default function NavigationButtons() {
  const router = useRouter()
  const pathname = usePathname()           // 当前路径
  const searchParams = useSearchParams()   // 查询参数
  
  return (
    <div>
      <p>当前路径: {pathname}</p>
      <p>搜索词: {searchParams.get('q')}</p>
      
      {/* 编程式导航 */}
      <button onClick={() => router.push('/dashboard')}>
        去仪表盘
      </button>
      
      {/* 替换当前历史记录 */}
      <button onClick={() => router.replace('/login')}>
        去登录
      </button>
      
      {/* 后退 */}
      <button onClick={() => router.back()}>
        返回
      </button>
      
      {/* 前进 */}
      <button onClick={() => router.forward()}>
        前进
      </button>
      
      {/* 刷新当前路由 */}
      <button onClick={() => router.refresh()}>
        刷新
      </button>
      
      {/* 预加载路由 */}
      <button onMouseEnter={() => router.prefetch('/heavy-page')}>
        悬停预加载
      </button>
    </div>
  )
}
```

```typescript
// 使用 redirect（服务端组件或 Server Actions）
import { redirect } from 'next/navigation'

export default async function Page() {
  const user = await getUser()
  
  if (!user) {
    redirect('/login')  // 服务端重定向
  }
  
  return <div>欢迎, {user.name}</div>
}
```

---

## 4. 页面与布局

### 4.1 页面 (page.tsx)

页面是路由的 UI，只有存在 `page.tsx` 文件，该路由才可访问：

```typescript
// app/page.tsx - 首页
export default function Home() {
  return (
    <main>
      <h1>欢迎来到我的网站</h1>
    </main>
  )
}
```

```typescript
// app/dashboard/page.tsx - 带参数的页面
interface PageProps {
  params: { id: string }                    // 动态路由参数
  searchParams: { [key: string]: string }   // URL 查询参数
}

export default function Dashboard({ params, searchParams }: PageProps) {
  return (
    <div>
      <h1>仪表盘</h1>
      <p>排序方式: {searchParams.sort || '默认'}</p>
    </div>
  )
}
```

### 4.2 布局 (layout.tsx)

布局是多个页面共享的 UI，在导航时保持状态，不会重新渲染：

```typescript
// app/layout.tsx - 根布局（必需）
import { Inter } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata = {
  title: 'My App',
  description: 'A Next.js application',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="zh-CN">
      <body className={inter.className}>
        <header>
          <nav>导航栏</nav>
        </header>
        <main>{children}</main>
        <footer>页脚</footer>
      </body>
    </html>
  )
}
```

```typescript
// app/dashboard/layout.tsx - 嵌套布局
export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="flex">
      <aside className="w-64">
        <nav>侧边栏导航</nav>
      </aside>
      <main className="flex-1">{children}</main>
    </div>
  )
}
```

### 4.3 模板 (template.tsx)

模板类似布局，但每次导航都会重新挂载，适合需要重置状态的场景：

```typescript
// app/dashboard/template.tsx
'use client'

import { useEffect } from 'react'

export default function Template({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    // 每次导航都会执行
    console.log('页面访问统计')
  }, [])

  return <div>{children}</div>
}
```

### 4.4 加载状态 (loading.tsx)

```typescript
// app/dashboard/loading.tsx
export default function Loading() {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500" />
    </div>
  )
}
```

```typescript
// 使用 Suspense 手动控制加载状态
import { Suspense } from 'react'

export default function Page() {
  return (
    <div>
      <h1>仪表盘</h1>
      <Suspense fallback={<div>加载统计数据...</div>}>
        <Statistics />
      </Suspense>
      <Suspense fallback={<div>加载图表...</div>}>
        <Charts />
      </Suspense>
    </div>
  )
}
```

### 4.5 错误处理 (error.tsx)

```typescript
// app/dashboard/error.tsx
'use client'  // 错误组件必须是客户端组件

import { useEffect } from 'react'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // 记录错误到日志服务
    console.error(error)
  }, [error])

  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <h2 className="text-2xl font-bold text-red-600">出错了！</h2>
      <p className="text-gray-600 mt-2">{error.message}</p>
      <button
        onClick={reset}
        className="mt-4 px-4 py-2 bg-blue-500 text-white rounded"
      >
        重试
      </button>
    </div>
  )
}
```

```typescript
// app/global-error.tsx - 全局错误处理（包括根布局错误）
'use client'

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <html>
      <body>
        <h2>发生严重错误</h2>
        <button onClick={reset}>重试</button>
      </body>
    </html>
  )
}
```

### 4.6 404 页面 (not-found.tsx)

```typescript
// app/not-found.tsx
import Link from 'next/link'

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <h1 className="text-6xl font-bold text-gray-800">404</h1>
      <h2 className="text-2xl text-gray-600 mt-4">页面未找到</h2>
      <p className="text-gray-500 mt-2">抱歉，您访问的页面不存在</p>
      <Link
        href="/"
        className="mt-6 px-6 py-3 bg-blue-500 text-white rounded-lg"
      >
        返回首页
      </Link>
    </div>
  )
}
```

```typescript
// 手动触发 404
import { notFound } from 'next/navigation'

export default async function Page({ params }: { params: { id: string } }) {
  const post = await getPost(params.id)
  
  if (!post) {
    notFound()  // 触发 not-found.tsx
  }
  
  return <article>{post.content}</article>
}
```


---

## 5. 服务端组件与客户端组件

### 5.1 核心概念

Next.js 13+ 默认使用 React Server Components (RSC)，这是理解 App Router 的关键：

```
┌─────────────────────────────────────────────────────────────┐
│              服务端组件 vs 客户端组件                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  服务端组件 (默认)              客户端组件 ('use client')     │
│  ┌─────────────────────┐       ┌─────────────────────┐      │
│  │ ✅ 直接访问数据库    │       │ ✅ 使用 useState     │      │
│  │ ✅ 访问后端资源      │       │ ✅ 使用 useEffect    │      │
│  │ ✅ 保护敏感信息      │       │ ✅ 事件监听器        │      │
│  │ ✅ 减少客户端 JS     │       │ ✅ 浏览器 API        │      │
│  │ ❌ 不能用 hooks     │       │ ✅ 自定义 hooks      │      │
│  │ ❌ 不能用浏览器 API  │       │ ❌ 不能直接访问数据库 │      │
│  └─────────────────────┘       └─────────────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 服务端组件

```typescript
// app/posts/page.tsx - 服务端组件（默认）
// 可以直接使用 async/await，无需 'use client'

import { db } from '@/lib/db'

export default async function PostsPage() {
  // 直接在组件中查询数据库
  const posts = await db.post.findMany()
  
  // 可以访问服务端环境变量
  const apiKey = process.env.API_SECRET_KEY
  
  return (
    <ul>
      {posts.map(post => (
        <li key={post.id}>{post.title}</li>
      ))}
    </ul>
  )
}
```

### 5.3 客户端组件

```typescript
// components/Counter.tsx - 客户端组件
'use client'  // 必须在文件顶部声明

import { useState } from 'react'

export default function Counter() {
  const [count, setCount] = useState(0)
  
  return (
    <div>
      <p>计数: {count}</p>
      <button onClick={() => setCount(count + 1)}>
        增加
      </button>
    </div>
  )
}
```

### 5.4 组件组合模式

```typescript
// ✅ 正确：服务端组件包裹客户端组件
// app/dashboard/page.tsx (服务端组件)
import { db } from '@/lib/db'
import InteractiveChart from '@/components/InteractiveChart'

export default async function Dashboard() {
  const data = await db.analytics.findMany()
  
  return (
    <div>
      <h1>仪表盘</h1>
      {/* 将数据作为 props 传递给客户端组件 */}
      <InteractiveChart data={data} />
    </div>
  )
}

// components/InteractiveChart.tsx (客户端组件)
'use client'

import { useState } from 'react'

export default function InteractiveChart({ data }: { data: any[] }) {
  const [filter, setFilter] = useState('all')
  
  return (
    <div>
      <select onChange={(e) => setFilter(e.target.value)}>
        <option value="all">全部</option>
        <option value="recent">最近</option>
      </select>
      {/* 渲染图表 */}
    </div>
  )
}
```

```typescript
// ✅ 正确：使用 children 模式
// components/ClientWrapper.tsx
'use client'

import { useState } from 'react'

export default function ClientWrapper({ 
  children 
}: { 
  children: React.ReactNode 
}) {
  const [isOpen, setIsOpen] = useState(false)
  
  return (
    <div>
      <button onClick={() => setIsOpen(!isOpen)}>
        切换
      </button>
      {isOpen && children}
    </div>
  )
}

// app/page.tsx (服务端组件)
import ClientWrapper from '@/components/ClientWrapper'
import ServerComponent from '@/components/ServerComponent'

export default function Page() {
  return (
    <ClientWrapper>
      {/* ServerComponent 仍然在服务端渲染 */}
      <ServerComponent />
    </ClientWrapper>
  )
}
```

### 5.5 何时使用哪种组件

| 场景 | 推荐组件类型 |
|------|-------------|
| 获取数据 | 服务端组件 |
| 访问后端资源 | 服务端组件 |
| 保护敏感信息 | 服务端组件 |
| 减少客户端 JS | 服务端组件 |
| 添加交互性 | 客户端组件 |
| 使用 React hooks | 客户端组件 |
| 使用浏览器 API | 客户端组件 |
| 使用状态管理 | 客户端组件 |
| 使用 Context | 客户端组件 |

---

## 6. 数据获取

### 6.1 服务端数据获取

```typescript
// app/posts/page.tsx - 基础数据获取
async function getPosts() {
  const res = await fetch('https://api.example.com/posts', {
    // 缓存选项
    cache: 'force-cache',     // 默认，等同于 SSG
    // cache: 'no-store',     // 不缓存，等同于 SSR
  })
  
  if (!res.ok) {
    throw new Error('获取文章失败')
  }
  
  return res.json()
}

export default async function PostsPage() {
  const posts = await getPosts()
  
  return (
    <ul>
      {posts.map((post: any) => (
        <li key={post.id}>{post.title}</li>
      ))}
    </ul>
  )
}
```

### 6.2 缓存与重新验证

```typescript
// 基于时间的重新验证 (ISR)
async function getPosts() {
  const res = await fetch('https://api.example.com/posts', {
    next: { revalidate: 3600 }  // 每小时重新验证
  })
  return res.json()
}

// 基于标签的重新验证
async function getPost(id: string) {
  const res = await fetch(`https://api.example.com/posts/${id}`, {
    next: { tags: ['posts', `post-${id}`] }
  })
  return res.json()
}

// 在 Server Action 中触发重新验证
'use server'
import { revalidateTag, revalidatePath } from 'next/cache'

export async function updatePost(id: string, data: any) {
  await db.post.update({ where: { id }, data })
  
  revalidateTag(`post-${id}`)  // 重新验证特定标签
  revalidatePath('/posts')      // 重新验证特定路径
}
```

### 6.3 并行数据获取

```typescript
// ✅ 推荐：并行获取数据
export default async function Page() {
  // 同时发起多个请求
  const [posts, users, comments] = await Promise.all([
    getPosts(),
    getUsers(),
    getComments(),
  ])
  
  return (
    <div>
      <PostList posts={posts} />
      <UserList users={users} />
      <CommentList comments={comments} />
    </div>
  )
}

// ❌ 避免：串行获取数据（瀑布流）
export default async function Page() {
  const posts = await getPosts()      // 等待完成
  const users = await getUsers()      // 再等待完成
  const comments = await getComments() // 再等待完成
  // ...
}
```

### 6.4 使用 Suspense 流式渲染

```typescript
import { Suspense } from 'react'

// 慢速数据组件
async function SlowData() {
  const data = await fetch('https://api.example.com/slow-data', {
    cache: 'no-store'
  }).then(r => r.json())
  
  return <div>{data.content}</div>
}

// 快速数据组件
async function FastData() {
  const data = await fetch('https://api.example.com/fast-data').then(r => r.json())
  return <div>{data.content}</div>
}

export default function Page() {
  return (
    <div>
      {/* 快速内容先显示 */}
      <Suspense fallback={<div>加载快速数据...</div>}>
        <FastData />
      </Suspense>
      
      {/* 慢速内容后显示，不阻塞页面 */}
      <Suspense fallback={<div>加载慢速数据...</div>}>
        <SlowData />
      </Suspense>
    </div>
  )
}
```

### 6.5 客户端数据获取

```typescript
// 使用 SWR（推荐）
'use client'

import useSWR from 'swr'

const fetcher = (url: string) => fetch(url).then(r => r.json())

export default function Profile() {
  const { data, error, isLoading, mutate } = useSWR('/api/user', fetcher, {
    revalidateOnFocus: true,      // 窗口聚焦时重新验证
    revalidateOnReconnect: true,  // 网络恢复时重新验证
    refreshInterval: 0,           // 轮询间隔（0 表示禁用）
  })
  
  if (isLoading) return <div>加载中...</div>
  if (error) return <div>加载失败</div>
  
  return (
    <div>
      <h1>{data.name}</h1>
      <button onClick={() => mutate()}>刷新</button>
    </div>
  )
}
```

```typescript
// 使用 React Query
'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export default function Posts() {
  const queryClient = useQueryClient()
  
  // 查询
  const { data, isLoading, error } = useQuery({
    queryKey: ['posts'],
    queryFn: () => fetch('/api/posts').then(r => r.json()),
    staleTime: 5 * 60 * 1000,  // 5分钟内数据视为新鲜
  })
  
  // 变更
  const mutation = useMutation({
    mutationFn: (newPost: any) => 
      fetch('/api/posts', {
        method: 'POST',
        body: JSON.stringify(newPost),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['posts'] })
    },
  })
  
  if (isLoading) return <div>加载中...</div>
  if (error) return <div>错误: {error.message}</div>
  
  return (
    <div>
      {data.map((post: any) => (
        <div key={post.id}>{post.title}</div>
      ))}
      <button onClick={() => mutation.mutate({ title: '新文章' })}>
        添加文章
      </button>
    </div>
  )
}
```

### 6.6 静态生成参数

```typescript
// app/blog/[slug]/page.tsx
// 为动态路由生成静态页面

// 生成静态参数
export async function generateStaticParams() {
  const posts = await fetch('https://api.example.com/posts').then(r => r.json())
  
  return posts.map((post: any) => ({
    slug: post.slug,
  }))
}

// 页面组件
export default async function Post({ params }: { params: { slug: string } }) {
  const post = await fetch(`https://api.example.com/posts/${params.slug}`).then(r => r.json())
  
  return <article>{post.content}</article>
}

// 配置动态行为
export const dynamicParams = true  // 允许访问未预生成的路径
// export const dynamicParams = false  // 未预生成的路径返回 404
```


---

## 7. 服务端操作 Server Actions

### 7.1 什么是 Server Actions？

Server Actions 是在服务器上执行的异步函数，可以在服务端和客户端组件中调用，用于处理表单提交和数据变更。

```typescript
// 定义 Server Action 的两种方式

// 方式1：在单独文件中定义（推荐）
// app/actions.ts
'use server'

export async function createPost(formData: FormData) {
  const title = formData.get('title') as string
  const content = formData.get('content') as string
  
  await db.post.create({
    data: { title, content }
  })
  
  revalidatePath('/posts')
}

// 方式2：在服务端组件内定义
export default async function Page() {
  async function handleSubmit(formData: FormData) {
    'use server'
    // 处理逻辑
  }
  
  return <form action={handleSubmit}>...</form>
}
```

### 7.2 表单处理

```typescript
// app/actions.ts
'use server'

import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'
import { z } from 'zod'

// 定义验证 schema
const PostSchema = z.object({
  title: z.string().min(1, '标题不能为空').max(100, '标题最多100字'),
  content: z.string().min(10, '内容至少10字'),
})

// 定义返回类型
type ActionState = {
  errors?: {
    title?: string[]
    content?: string[]
  }
  message?: string
}

export async function createPost(
  prevState: ActionState,
  formData: FormData
): Promise<ActionState> {
  // 验证数据
  const validatedFields = PostSchema.safeParse({
    title: formData.get('title'),
    content: formData.get('content'),
  })
  
  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: '验证失败',
    }
  }
  
  try {
    await db.post.create({
      data: validatedFields.data
    })
  } catch (error) {
    return { message: '创建失败，请重试' }
  }
  
  revalidatePath('/posts')
  redirect('/posts')
}
```

```typescript
// app/posts/new/page.tsx
'use client'

import { useFormState, useFormStatus } from 'react-dom'
import { createPost } from '@/app/actions'

// 提交按钮组件
function SubmitButton() {
  const { pending } = useFormStatus()
  
  return (
    <button 
      type="submit" 
      disabled={pending}
      className="bg-blue-500 text-white px-4 py-2 rounded disabled:opacity-50"
    >
      {pending ? '提交中...' : '创建文章'}
    </button>
  )
}

export default function NewPostPage() {
  const [state, formAction] = useFormState(createPost, {})
  
  return (
    <form action={formAction} className="space-y-4">
      <div>
        <label htmlFor="title">标题</label>
        <input
          id="title"
          name="title"
          type="text"
          className="border rounded px-3 py-2 w-full"
        />
        {state.errors?.title && (
          <p className="text-red-500 text-sm">{state.errors.title[0]}</p>
        )}
      </div>
      
      <div>
        <label htmlFor="content">内容</label>
        <textarea
          id="content"
          name="content"
          rows={5}
          className="border rounded px-3 py-2 w-full"
        />
        {state.errors?.content && (
          <p className="text-red-500 text-sm">{state.errors.content[0]}</p>
        )}
      </div>
      
      {state.message && (
        <p className="text-red-500">{state.message}</p>
      )}
      
      <SubmitButton />
    </form>
  )
}
```

### 7.3 乐观更新

```typescript
'use client'

import { useOptimistic } from 'react'
import { addTodo } from '@/app/actions'

export default function TodoList({ todos }: { todos: Todo[] }) {
  const [optimisticTodos, addOptimisticTodo] = useOptimistic(
    todos,
    (state, newTodo: string) => [
      ...state,
      { id: Date.now(), text: newTodo, completed: false }
    ]
  )
  
  async function handleSubmit(formData: FormData) {
    const text = formData.get('text') as string
    addOptimisticTodo(text)  // 立即更新 UI
    await addTodo(formData)   // 实际提交
  }
  
  return (
    <div>
      <form action={handleSubmit}>
        <input name="text" type="text" />
        <button type="submit">添加</button>
      </form>
      <ul>
        {optimisticTodos.map(todo => (
          <li key={todo.id}>{todo.text}</li>
        ))}
      </ul>
    </div>
  )
}
```

### 7.4 非表单调用

```typescript
// app/actions.ts
'use server'

export async function incrementLike(postId: string) {
  await db.post.update({
    where: { id: postId },
    data: { likes: { increment: 1 } }
  })
  revalidatePath('/posts')
}

export async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } })
  revalidatePath('/posts')
}
```

```typescript
// components/LikeButton.tsx
'use client'

import { useTransition } from 'react'
import { incrementLike } from '@/app/actions'

export default function LikeButton({ postId }: { postId: string }) {
  const [isPending, startTransition] = useTransition()
  
  return (
    <button
      onClick={() => {
        startTransition(() => {
          incrementLike(postId)
        })
      }}
      disabled={isPending}
    >
      {isPending ? '点赞中...' : '👍 点赞'}
    </button>
  )
}
```

---

## 8. 路由处理程序 Route Handlers

### 8.1 基础用法

Route Handlers 用于创建 API 端点，使用 Web Request 和 Response API：

```typescript
// app/api/posts/route.ts
import { NextRequest, NextResponse } from 'next/server'

// GET 请求
export async function GET(request: NextRequest) {
  const posts = await db.post.findMany()
  
  return NextResponse.json(posts)
}

// POST 请求
export async function POST(request: NextRequest) {
  const body = await request.json()
  
  const post = await db.post.create({
    data: body
  })
  
  return NextResponse.json(post, { status: 201 })
}

// 支持的 HTTP 方法：GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
```

### 8.2 动态路由处理

```typescript
// app/api/posts/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'

interface RouteParams {
  params: { id: string }
}

// GET /api/posts/123
export async function GET(
  request: NextRequest,
  { params }: RouteParams
) {
  const post = await db.post.findUnique({
    where: { id: params.id }
  })
  
  if (!post) {
    return NextResponse.json(
      { error: '文章不存在' },
      { status: 404 }
    )
  }
  
  return NextResponse.json(post)
}

// PUT /api/posts/123
export async function PUT(
  request: NextRequest,
  { params }: RouteParams
) {
  const body = await request.json()
  
  const post = await db.post.update({
    where: { id: params.id },
    data: body
  })
  
  return NextResponse.json(post)
}

// DELETE /api/posts/123
export async function DELETE(
  request: NextRequest,
  { params }: RouteParams
) {
  await db.post.delete({
    where: { id: params.id }
  })
  
  return new NextResponse(null, { status: 204 })
}
```

### 8.3 请求处理

```typescript
// app/api/search/route.ts
import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  // 获取查询参数
  const searchParams = request.nextUrl.searchParams
  const query = searchParams.get('q')
  const page = parseInt(searchParams.get('page') || '1')
  const limit = parseInt(searchParams.get('limit') || '10')
  
  // 获取请求头
  const authHeader = request.headers.get('authorization')
  
  // 获取 cookies
  const token = request.cookies.get('token')?.value
  
  const results = await db.post.findMany({
    where: { title: { contains: query || '' } },
    skip: (page - 1) * limit,
    take: limit,
  })
  
  return NextResponse.json({
    data: results,
    page,
    limit,
  })
}
```

### 8.4 响应处理

```typescript
// app/api/example/route.ts
import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  // JSON 响应
  return NextResponse.json({ message: 'Hello' })
  
  // 设置状态码
  return NextResponse.json({ error: 'Not found' }, { status: 404 })
  
  // 设置响应头
  return NextResponse.json(
    { data: 'value' },
    {
      headers: {
        'Cache-Control': 'max-age=3600',
        'X-Custom-Header': 'custom-value',
      },
    }
  )
  
  // 设置 cookies
  const response = NextResponse.json({ success: true })
  response.cookies.set('token', 'abc123', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 * 7, // 7 天
  })
  return response
  
  // 重定向
  return NextResponse.redirect(new URL('/login', request.url))
  
  // 流式响应
  const stream = new ReadableStream({
    async start(controller) {
      controller.enqueue(new TextEncoder().encode('Hello '))
      await new Promise(r => setTimeout(r, 1000))
      controller.enqueue(new TextEncoder().encode('World'))
      controller.close()
    },
  })
  return new NextResponse(stream)
}
```

### 8.5 CORS 配置

```typescript
// app/api/cors/route.ts
import { NextRequest, NextResponse } from 'next/server'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}

export async function OPTIONS(request: NextRequest) {
  return NextResponse.json({}, { headers: corsHeaders })
}

export async function GET(request: NextRequest) {
  const data = { message: 'Hello from API' }
  
  return NextResponse.json(data, { headers: corsHeaders })
}
```

### 8.6 文件上传

```typescript
// app/api/upload/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { writeFile } from 'fs/promises'
import path from 'path'

export async function POST(request: NextRequest) {
  const formData = await request.formData()
  const file = formData.get('file') as File
  
  if (!file) {
    return NextResponse.json(
      { error: '没有上传文件' },
      { status: 400 }
    )
  }
  
  // 验证文件类型
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
  if (!allowedTypes.includes(file.type)) {
    return NextResponse.json(
      { error: '不支持的文件类型' },
      { status: 400 }
    )
  }
  
  // 验证文件大小 (5MB)
  if (file.size > 5 * 1024 * 1024) {
    return NextResponse.json(
      { error: '文件太大' },
      { status: 400 }
    )
  }
  
  const bytes = await file.arrayBuffer()
  const buffer = Buffer.from(bytes)
  
  const filename = `${Date.now()}-${file.name}`
  const filepath = path.join(process.cwd(), 'public/uploads', filename)
  
  await writeFile(filepath, buffer)
  
  return NextResponse.json({
    url: `/uploads/${filename}`,
    filename,
  })
}
```


---

## 9. 中间件 Middleware

### 9.1 基础概念

中间件允许你在请求完成之前运行代码，可以用于：
- 身份验证和授权
- 重定向和重写
- 设置请求/响应头
- A/B 测试
- 地理位置检测

```typescript
// middleware.ts（必须放在项目根目录或 src 目录）
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  // 获取请求信息
  const pathname = request.nextUrl.pathname
  const token = request.cookies.get('token')?.value
  
  console.log(`请求路径: ${pathname}`)
  
  // 继续处理请求
  return NextResponse.next()
}

// 配置匹配路径
export const config = {
  matcher: [
    // 匹配所有路径，排除静态资源
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
}
```

### 9.2 身份验证

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { verifyToken } from '@/lib/auth'

// 需要认证的路径
const protectedPaths = ['/dashboard', '/profile', '/settings']

// 公开路径
const publicPaths = ['/login', '/register', '/forgot-password']

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  const token = request.cookies.get('token')?.value
  
  // 检查是否是受保护的路径
  const isProtectedPath = protectedPaths.some(path => 
    pathname.startsWith(path)
  )
  
  // 检查是否是公开路径
  const isPublicPath = publicPaths.some(path => 
    pathname.startsWith(path)
  )
  
  // 验证 token
  const isValidToken = token ? await verifyToken(token) : false
  
  // 未登录访问受保护页面 → 重定向到登录
  if (isProtectedPath && !isValidToken) {
    const loginUrl = new URL('/login', request.url)
    loginUrl.searchParams.set('from', pathname)
    return NextResponse.redirect(loginUrl)
  }
  
  // 已登录访问登录页 → 重定向到首页
  if (isPublicPath && isValidToken) {
    return NextResponse.redirect(new URL('/dashboard', request.url))
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/profile/:path*',
    '/settings/:path*',
    '/login',
    '/register',
  ],
}
```

### 9.3 重定向和重写

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  
  // 重定向：URL 会改变
  if (pathname === '/old-page') {
    return NextResponse.redirect(new URL('/new-page', request.url))
  }
  
  // 重写：URL 不变，但显示不同内容
  if (pathname === '/blog') {
    return NextResponse.rewrite(new URL('/news', request.url))
  }
  
  // 基于条件重写（A/B 测试）
  const bucket = request.cookies.get('bucket')?.value || 'a'
  if (pathname === '/experiment') {
    return NextResponse.rewrite(
      new URL(`/experiment/${bucket}`, request.url)
    )
  }
  
  return NextResponse.next()
}
```

### 9.4 设置请求头

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  // 克隆请求头
  const requestHeaders = new Headers(request.headers)
  
  // 添加自定义请求头
  requestHeaders.set('x-request-id', crypto.randomUUID())
  requestHeaders.set('x-pathname', request.nextUrl.pathname)
  
  // 创建响应
  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  })
  
  // 设置响应头
  response.headers.set('x-response-time', Date.now().toString())
  
  // 安全相关响应头
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('Referrer-Policy', 'origin-when-cross-origin')
  
  return response
}
```

### 9.5 地理位置和国际化

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const locales = ['en', 'zh', 'ja']
const defaultLocale = 'en'

function getLocale(request: NextRequest): string {
  // 从 cookie 获取
  const cookieLocale = request.cookies.get('locale')?.value
  if (cookieLocale && locales.includes(cookieLocale)) {
    return cookieLocale
  }
  
  // 从 Accept-Language 头获取
  const acceptLanguage = request.headers.get('accept-language')
  if (acceptLanguage) {
    const preferredLocale = acceptLanguage
      .split(',')[0]
      .split('-')[0]
      .toLowerCase()
    if (locales.includes(preferredLocale)) {
      return preferredLocale
    }
  }
  
  // 从地理位置获取（Vercel Edge）
  const country = request.geo?.country
  if (country === 'CN') return 'zh'
  if (country === 'JP') return 'ja'
  
  return defaultLocale
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  
  // 检查路径是否已包含语言前缀
  const pathnameHasLocale = locales.some(
    locale => pathname.startsWith(`/${locale}/`) || pathname === `/${locale}`
  )
  
  if (pathnameHasLocale) return NextResponse.next()
  
  // 重定向到带语言前缀的路径
  const locale = getLocale(request)
  request.nextUrl.pathname = `/${locale}${pathname}`
  
  return NextResponse.redirect(request.nextUrl)
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
}
```

### 9.6 速率限制

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

// 简单的内存存储（生产环境应使用 Redis）
const rateLimit = new Map<string, { count: number; timestamp: number }>()

const WINDOW_SIZE = 60 * 1000  // 1 分钟
const MAX_REQUESTS = 100       // 最大请求数

export function middleware(request: NextRequest) {
  // 只对 API 路由进行限制
  if (!request.nextUrl.pathname.startsWith('/api')) {
    return NextResponse.next()
  }
  
  const ip = request.ip || request.headers.get('x-forwarded-for') || 'unknown'
  const now = Date.now()
  
  const record = rateLimit.get(ip)
  
  if (!record || now - record.timestamp > WINDOW_SIZE) {
    // 新窗口
    rateLimit.set(ip, { count: 1, timestamp: now })
    return NextResponse.next()
  }
  
  if (record.count >= MAX_REQUESTS) {
    return NextResponse.json(
      { error: '请求过于频繁，请稍后再试' },
      { status: 429 }
    )
  }
  
  record.count++
  return NextResponse.next()
}
```

---

## 10. 样式处理

### 10.1 CSS Modules

```css
/* styles/Button.module.css */
.button {
  padding: 10px 20px;
  border-radius: 5px;
  border: none;
  cursor: pointer;
}

.primary {
  background-color: #0070f3;
  color: white;
}

.secondary {
  background-color: #eaeaea;
  color: #333;
}

.button:hover {
  opacity: 0.9;
}
```

```typescript
// components/Button.tsx
import styles from '@/styles/Button.module.css'

interface ButtonProps {
  variant?: 'primary' | 'secondary'
  children: React.ReactNode
}

export default function Button({ variant = 'primary', children }: ButtonProps) {
  return (
    <button className={`${styles.button} ${styles[variant]}`}>
      {children}
    </button>
  )
}
```

### 10.2 Tailwind CSS

```typescript
// tailwind.config.ts
import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}

export default config
```

```typescript
// components/Card.tsx
export default function Card({ title, description }: { 
  title: string
  description: string 
}) {
  return (
    <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
      <h2 className="text-xl font-bold text-gray-800 mb-2">{title}</h2>
      <p className="text-gray-600">{description}</p>
      <button className="mt-4 px-4 py-2 bg-primary-500 text-white rounded hover:bg-primary-600 transition-colors">
        了解更多
      </button>
    </div>
  )
}
```

### 10.3 CSS-in-JS (styled-components)

```typescript
// 注意：styled-components 需要客户端组件
// lib/registry.tsx
'use client'

import React, { useState } from 'react'
import { useServerInsertedHTML } from 'next/navigation'
import { ServerStyleSheet, StyleSheetManager } from 'styled-components'

export default function StyledComponentsRegistry({
  children,
}: {
  children: React.ReactNode
}) {
  const [styledComponentsStyleSheet] = useState(() => new ServerStyleSheet())

  useServerInsertedHTML(() => {
    const styles = styledComponentsStyleSheet.getStyleElement()
    styledComponentsStyleSheet.instance.clearTag()
    return <>{styles}</>
  })

  if (typeof window !== 'undefined') return <>{children}</>

  return (
    <StyleSheetManager sheet={styledComponentsStyleSheet.instance}>
      {children}
    </StyleSheetManager>
  )
}
```

```typescript
// app/layout.tsx
import StyledComponentsRegistry from '@/lib/registry'

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html>
      <body>
        <StyledComponentsRegistry>{children}</StyledComponentsRegistry>
      </body>
    </html>
  )
}
```

```typescript
// components/StyledButton.tsx
'use client'

import styled from 'styled-components'

const Button = styled.button<{ $primary?: boolean }>`
  padding: 10px 20px;
  border-radius: 5px;
  border: none;
  cursor: pointer;
  background-color: ${props => props.$primary ? '#0070f3' : '#eaeaea'};
  color: ${props => props.$primary ? 'white' : '#333'};
  
  &:hover {
    opacity: 0.9;
  }
`

export default function StyledButton() {
  return (
    <div>
      <Button $primary>主要按钮</Button>
      <Button>次要按钮</Button>
    </div>
  )
}
```

### 10.4 全局样式

```css
/* app/globals.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* 自定义全局样式 */
:root {
  --foreground-rgb: 0, 0, 0;
  --background-rgb: 255, 255, 255;
}

@media (prefers-color-scheme: dark) {
  :root {
    --foreground-rgb: 255, 255, 255;
    --background-rgb: 0, 0, 0;
  }
}

body {
  color: rgb(var(--foreground-rgb));
  background: rgb(var(--background-rgb));
}

/* 自定义组件类 */
@layer components {
  .btn {
    @apply px-4 py-2 rounded font-medium transition-colors;
  }
  
  .btn-primary {
    @apply bg-blue-500 text-white hover:bg-blue-600;
  }
  
  .card {
    @apply bg-white rounded-lg shadow-md p-6;
  }
}
```


---

## 11. 图片与字体优化

### 11.1 Image 组件

Next.js 的 Image 组件提供自动图片优化：

```typescript
import Image from 'next/image'

export default function Gallery() {
  return (
    <div>
      {/* 本地图片（自动获取尺寸） */}
      <Image
        src="/images/hero.jpg"
        alt="Hero image"
        width={800}
        height={600}
        priority  // 首屏图片使用 priority
      />
      
      {/* 远程图片（必须指定尺寸） */}
      <Image
        src="https://example.com/photo.jpg"
        alt="Remote image"
        width={400}
        height={300}
      />
      
      {/* 填充父容器 */}
      <div className="relative w-full h-64">
        <Image
          src="/images/banner.jpg"
          alt="Banner"
          fill
          className="object-cover"
        />
      </div>
      
      {/* 响应式图片 */}
      <Image
        src="/images/responsive.jpg"
        alt="Responsive"
        width={800}
        height={600}
        sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
      />
      
      {/* 模糊占位符 */}
      <Image
        src="/images/photo.jpg"
        alt="Photo"
        width={400}
        height={300}
        placeholder="blur"
        blurDataURL="data:image/jpeg;base64,/9j/4AAQSkZJRg..."
      />
    </div>
  )
}
```

### 11.2 Image 配置

```typescript
// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    // 允许的远程图片域名
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'images.unsplash.com',
      },
      {
        protocol: 'https',
        hostname: '**.example.com',  // 通配符
      },
    ],
    
    // 设备尺寸断点
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    
    // 图片尺寸
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    
    // 图片格式
    formats: ['image/avif', 'image/webp'],
    
    // 禁用优化（不推荐）
    // unoptimized: true,
  },
}

module.exports = nextConfig
```

### 11.3 字体优化

```typescript
// app/layout.tsx
import { Inter, Roboto_Mono } from 'next/font/google'

// 加载 Google 字体
const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter',
})

const robotoMono = Roboto_Mono({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-roboto-mono',
})

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="zh-CN" className={`${inter.variable} ${robotoMono.variable}`}>
      <body className={inter.className}>{children}</body>
    </html>
  )
}
```

```typescript
// 使用本地字体
import localFont from 'next/font/local'

const myFont = localFont({
  src: [
    {
      path: './fonts/MyFont-Regular.woff2',
      weight: '400',
      style: 'normal',
    },
    {
      path: './fonts/MyFont-Bold.woff2',
      weight: '700',
      style: 'normal',
    },
  ],
  variable: '--font-my-font',
})

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="zh-CN" className={myFont.variable}>
      <body>{children}</body>
    </html>
  )
}
```

```css
/* 在 CSS 中使用字体变量 */
body {
  font-family: var(--font-inter);
}

code {
  font-family: var(--font-roboto-mono);
}
```

---

## 12. 元数据与 SEO

### 12.1 静态元数据

```typescript
// app/layout.tsx 或 app/page.tsx
import type { Metadata } from 'next'

export const metadata: Metadata = {
  // 基础元数据
  title: '我的网站',
  description: '这是一个使用 Next.js 构建的网站',
  keywords: ['Next.js', 'React', 'JavaScript'],
  authors: [{ name: '作者名', url: 'https://example.com' }],
  creator: '创建者',
  publisher: '发布者',
  
  // 图标
  icons: {
    icon: '/favicon.ico',
    shortcut: '/shortcut-icon.png',
    apple: '/apple-icon.png',
  },
  
  // Open Graph（社交分享）
  openGraph: {
    title: '我的网站',
    description: '这是一个使用 Next.js 构建的网站',
    url: 'https://example.com',
    siteName: '我的网站',
    images: [
      {
        url: 'https://example.com/og-image.jpg',
        width: 1200,
        height: 630,
        alt: '网站预览图',
      },
    ],
    locale: 'zh_CN',
    type: 'website',
  },
  
  // Twitter 卡片
  twitter: {
    card: 'summary_large_image',
    title: '我的网站',
    description: '这是一个使用 Next.js 构建的网站',
    creator: '@username',
    images: ['https://example.com/twitter-image.jpg'],
  },
  
  // 机器人指令
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  
  // 验证
  verification: {
    google: 'google-site-verification-code',
    yandex: 'yandex-verification-code',
  },
}
```

### 12.2 动态元数据

```typescript
// app/blog/[slug]/page.tsx
import type { Metadata, ResolvingMetadata } from 'next'

interface Props {
  params: { slug: string }
  searchParams: { [key: string]: string | string[] | undefined }
}

export async function generateMetadata(
  { params, searchParams }: Props,
  parent: ResolvingMetadata
): Promise<Metadata> {
  const post = await fetch(`https://api.example.com/posts/${params.slug}`).then(
    r => r.json()
  )
  
  // 获取父级元数据
  const previousImages = (await parent).openGraph?.images || []
  
  return {
    title: post.title,
    description: post.excerpt,
    openGraph: {
      title: post.title,
      description: post.excerpt,
      images: [post.coverImage, ...previousImages],
    },
  }
}

export default async function Page({ params }: Props) {
  const post = await fetch(`https://api.example.com/posts/${params.slug}`).then(
    r => r.json()
  )
  
  return <article>{post.content}</article>
}
```

### 12.3 模板标题

```typescript
// app/layout.tsx
export const metadata: Metadata = {
  title: {
    template: '%s | 我的网站',  // %s 会被子页面标题替换
    default: '我的网站',        // 默认标题
  },
}

// app/about/page.tsx
export const metadata: Metadata = {
  title: '关于我们',  // 最终显示：关于我们 | 我的网站
}

// app/blog/page.tsx
export const metadata: Metadata = {
  title: {
    absolute: '博客',  // 忽略模板，只显示：博客
  },
}
```

### 12.4 生成 Sitemap

```typescript
// app/sitemap.ts
import { MetadataRoute } from 'next'

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const baseUrl = 'https://example.com'
  
  // 获取动态页面
  const posts = await fetch('https://api.example.com/posts').then(r => r.json())
  
  const postUrls = posts.map((post: any) => ({
    url: `${baseUrl}/blog/${post.slug}`,
    lastModified: new Date(post.updatedAt),
    changeFrequency: 'weekly' as const,
    priority: 0.8,
  }))
  
  return [
    {
      url: baseUrl,
      lastModified: new Date(),
      changeFrequency: 'daily',
      priority: 1,
    },
    {
      url: `${baseUrl}/about`,
      lastModified: new Date(),
      changeFrequency: 'monthly',
      priority: 0.5,
    },
    ...postUrls,
  ]
}
```

### 12.5 生成 robots.txt

```typescript
// app/robots.ts
import { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: '*',
        allow: '/',
        disallow: ['/admin/', '/api/', '/private/'],
      },
      {
        userAgent: 'Googlebot',
        allow: '/',
      },
    ],
    sitemap: 'https://example.com/sitemap.xml',
  }
}
```

### 12.6 JSON-LD 结构化数据

```typescript
// app/blog/[slug]/page.tsx
export default async function BlogPost({ params }: { params: { slug: string } }) {
  const post = await getPost(params.slug)
  
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: post.title,
    description: post.excerpt,
    image: post.coverImage,
    datePublished: post.publishedAt,
    dateModified: post.updatedAt,
    author: {
      '@type': 'Person',
      name: post.author.name,
    },
  }
  
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <article>
        <h1>{post.title}</h1>
        <div>{post.content}</div>
      </article>
    </>
  )
}
```


---

## 13. 缓存机制

### 13.1 缓存概述

Next.js 有多层缓存机制，理解它们对于优化应用性能至关重要：

```
┌─────────────────────────────────────────────────────────────┐
│                    Next.js 缓存层级                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 请求记忆化 (Request Memoization)                         │
│     └─ 同一渲染过程中相同请求只执行一次                        │
│                                                             │
│  2. 数据缓存 (Data Cache)                                    │
│     └─ fetch 请求结果持久化存储                               │
│                                                             │
│  3. 完整路由缓存 (Full Route Cache)                          │
│     └─ 静态渲染的页面 HTML 和 RSC Payload                    │
│                                                             │
│  4. 路由缓存 (Router Cache)                                  │
│     └─ 客户端缓存已访问的路由                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 13.2 fetch 缓存控制

```typescript
// 默认缓存（等同于 SSG）
const data = await fetch('https://api.example.com/data')

// 不缓存（等同于 SSR）
const data = await fetch('https://api.example.com/data', {
  cache: 'no-store'
})

// 基于时间重新验证（ISR）
const data = await fetch('https://api.example.com/data', {
  next: { revalidate: 3600 }  // 1小时后重新验证
})

// 基于标签重新验证
const data = await fetch('https://api.example.com/data', {
  next: { tags: ['posts'] }
})
```

### 13.3 路由段配置

```typescript
// app/dashboard/page.tsx

// 强制动态渲染
export const dynamic = 'force-dynamic'
// 'auto' | 'force-dynamic' | 'error' | 'force-static'

// 动态参数行为
export const dynamicParams = true
// true: 允许动态生成未预渲染的路径
// false: 未预渲染的路径返回 404

// 重新验证时间
export const revalidate = 3600  // 秒
// false: 不重新验证（默认）
// 0: 总是重新验证
// number: 指定秒数后重新验证

// 运行时
export const runtime = 'nodejs'
// 'nodejs' | 'edge'

// 首选区域（Edge 运行时）
export const preferredRegion = 'auto'
// 'auto' | 'global' | 'home' | ['iad1', 'sfo1']
```

### 13.4 手动重新验证

```typescript
// app/actions.ts
'use server'

import { revalidatePath, revalidateTag } from 'next/cache'

// 重新验证特定路径
export async function updatePost(id: string, data: any) {
  await db.post.update({ where: { id }, data })
  
  revalidatePath('/posts')           // 重新验证列表页
  revalidatePath(`/posts/${id}`)     // 重新验证详情页
  revalidatePath('/posts/[slug]', 'page')  // 重新验证动态路由
  revalidatePath('/', 'layout')      // 重新验证布局
}

// 重新验证标签
export async function refreshPosts() {
  revalidateTag('posts')
}
```

```typescript
// 通过 API 路由重新验证
// app/api/revalidate/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { revalidatePath, revalidateTag } from 'next/cache'

export async function POST(request: NextRequest) {
  const { secret, path, tag } = await request.json()
  
  // 验证密钥
  if (secret !== process.env.REVALIDATION_SECRET) {
    return NextResponse.json({ error: 'Invalid secret' }, { status: 401 })
  }
  
  if (path) {
    revalidatePath(path)
    return NextResponse.json({ revalidated: true, path })
  }
  
  if (tag) {
    revalidateTag(tag)
    return NextResponse.json({ revalidated: true, tag })
  }
  
  return NextResponse.json({ error: 'Missing path or tag' }, { status: 400 })
}
```

### 13.5 unstable_cache

```typescript
// 缓存非 fetch 的数据获取
import { unstable_cache } from 'next/cache'

const getCachedUser = unstable_cache(
  async (id: string) => {
    return await db.user.findUnique({ where: { id } })
  },
  ['user'],  // 缓存键
  {
    tags: ['users'],
    revalidate: 3600,
  }
)

export default async function UserProfile({ params }: { params: { id: string } }) {
  const user = await getCachedUser(params.id)
  return <div>{user.name}</div>
}
```

### 13.6 禁用缓存

```typescript
// 方式1：使用 no-store
const data = await fetch(url, { cache: 'no-store' })

// 方式2：使用动态函数
import { cookies, headers } from 'next/headers'

export default async function Page() {
  const cookieStore = cookies()  // 使用动态函数会禁用缓存
  const headersList = headers()
  // ...
}

// 方式3：路由段配置
export const dynamic = 'force-dynamic'
export const revalidate = 0
```

---

## 14. 错误处理

### 14.1 错误边界

```typescript
// app/dashboard/error.tsx
'use client'

import { useEffect } from 'react'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // 发送错误到日志服务
    console.error('Dashboard Error:', error)
  }, [error])

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-red-600 mb-4">
          出错了！
        </h2>
        <p className="text-gray-600 mb-4">
          {error.message || '发生了未知错误'}
        </p>
        {error.digest && (
          <p className="text-sm text-gray-400 mb-4">
            错误 ID: {error.digest}
          </p>
        )}
        <button
          onClick={reset}
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
        >
          重试
        </button>
      </div>
    </div>
  )
}
```

### 14.2 全局错误处理

```typescript
// app/global-error.tsx
// 处理根布局中的错误
'use client'

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <html>
      <body>
        <div className="min-h-screen flex items-center justify-center bg-gray-100">
          <div className="text-center">
            <h1 className="text-4xl font-bold text-red-600 mb-4">
              严重错误
            </h1>
            <p className="text-gray-600 mb-4">
              应用程序遇到了严重问题
            </p>
            <button
              onClick={reset}
              className="px-6 py-3 bg-blue-500 text-white rounded-lg"
            >
              重新加载应用
            </button>
          </div>
        </div>
      </body>
    </html>
  )
}
```

### 14.3 自定义错误类

```typescript
// lib/errors.ts
export class AppError extends Error {
  constructor(
    message: string,
    public statusCode: number = 500,
    public code?: string
  ) {
    super(message)
    this.name = 'AppError'
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string) {
    super(`${resource} 不存在`, 404, 'NOT_FOUND')
    this.name = 'NotFoundError'
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = '未授权访问') {
    super(message, 401, 'UNAUTHORIZED')
    this.name = 'UnauthorizedError'
  }
}

export class ValidationError extends AppError {
  constructor(
    message: string,
    public errors: Record<string, string[]>
  ) {
    super(message, 400, 'VALIDATION_ERROR')
    this.name = 'ValidationError'
  }
}
```

### 14.4 API 错误处理

```typescript
// app/api/posts/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { NotFoundError, ValidationError } from '@/lib/errors'

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const post = await db.post.findUnique({
      where: { id: params.id }
    })
    
    if (!post) {
      throw new NotFoundError('文章')
    }
    
    return NextResponse.json(post)
  } catch (error) {
    if (error instanceof NotFoundError) {
      return NextResponse.json(
        { error: error.message, code: error.code },
        { status: error.statusCode }
      )
    }
    
    console.error('Unexpected error:', error)
    return NextResponse.json(
      { error: '服务器内部错误' },
      { status: 500 }
    )
  }
}
```

### 14.5 Server Action 错误处理

```typescript
// app/actions.ts
'use server'

import { z } from 'zod'

const schema = z.object({
  email: z.string().email('请输入有效的邮箱'),
  password: z.string().min(8, '密码至少8位'),
})

type ActionResult = {
  success: boolean
  message?: string
  errors?: Record<string, string[]>
}

export async function login(
  prevState: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  try {
    const validatedFields = schema.safeParse({
      email: formData.get('email'),
      password: formData.get('password'),
    })
    
    if (!validatedFields.success) {
      return {
        success: false,
        errors: validatedFields.error.flatten().fieldErrors,
      }
    }
    
    const user = await authenticateUser(validatedFields.data)
    
    if (!user) {
      return {
        success: false,
        message: '邮箱或密码错误',
      }
    }
    
    // 设置 session...
    
    return { success: true }
  } catch (error) {
    console.error('Login error:', error)
    return {
      success: false,
      message: '登录失败，请稍后重试',
    }
  }
}
```

---

## 15. 国际化 i18n

### 15.1 基于路由的国际化

```
app/
├── [lang]/
│   ├── layout.tsx
│   ├── page.tsx
│   └── about/
│       └── page.tsx
└── dictionaries/
    ├── en.json
    └── zh.json
```

```json
// dictionaries/en.json
{
  "home": {
    "title": "Welcome",
    "description": "This is a Next.js application"
  },
  "about": {
    "title": "About Us",
    "content": "We are a team of developers"
  },
  "common": {
    "learnMore": "Learn More",
    "contact": "Contact Us"
  }
}
```

```json
// dictionaries/zh.json
{
  "home": {
    "title": "欢迎",
    "description": "这是一个 Next.js 应用"
  },
  "about": {
    "title": "关于我们",
    "content": "我们是一个开发团队"
  },
  "common": {
    "learnMore": "了解更多",
    "contact": "联系我们"
  }
}
```

```typescript
// lib/dictionaries.ts
import 'server-only'

const dictionaries = {
  en: () => import('@/dictionaries/en.json').then(m => m.default),
  zh: () => import('@/dictionaries/zh.json').then(m => m.default),
}

export type Locale = keyof typeof dictionaries

export const getDictionary = async (locale: Locale) => {
  return dictionaries[locale]()
}
```

```typescript
// app/[lang]/layout.tsx
import { Locale } from '@/lib/dictionaries'

export async function generateStaticParams() {
  return [{ lang: 'en' }, { lang: 'zh' }]
}

export default function Layout({
  children,
  params,
}: {
  children: React.ReactNode
  params: { lang: Locale }
}) {
  return (
    <html lang={params.lang}>
      <body>{children}</body>
    </html>
  )
}
```

```typescript
// app/[lang]/page.tsx
import { getDictionary, Locale } from '@/lib/dictionaries'
import Link from 'next/link'

export default async function Home({
  params: { lang },
}: {
  params: { lang: Locale }
}) {
  const dict = await getDictionary(lang)
  
  return (
    <main>
      <h1>{dict.home.title}</h1>
      <p>{dict.home.description}</p>
      <Link href={`/${lang}/about`}>
        {dict.common.learnMore}
      </Link>
    </main>
  )
}
```

### 15.2 语言切换组件

```typescript
// components/LanguageSwitcher.tsx
'use client'

import { usePathname, useRouter } from 'next/navigation'
import { Locale } from '@/lib/dictionaries'

const languages: { code: Locale; name: string }[] = [
  { code: 'en', name: 'English' },
  { code: 'zh', name: '中文' },
]

export default function LanguageSwitcher({ currentLang }: { currentLang: Locale }) {
  const pathname = usePathname()
  const router = useRouter()
  
  const switchLanguage = (newLang: Locale) => {
    // 替换路径中的语言代码
    const newPath = pathname.replace(`/${currentLang}`, `/${newLang}`)
    router.push(newPath)
  }
  
  return (
    <div className="flex gap-2">
      {languages.map(lang => (
        <button
          key={lang.code}
          onClick={() => switchLanguage(lang.code)}
          className={`px-3 py-1 rounded ${
            currentLang === lang.code
              ? 'bg-blue-500 text-white'
              : 'bg-gray-200'
          }`}
        >
          {lang.name}
        </button>
      ))}
    </div>
  )
}
```

### 15.3 中间件自动检测语言

```typescript
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

const locales = ['en', 'zh']
const defaultLocale = 'en'

function getLocale(request: NextRequest): string {
  // 从 cookie 获取
  const cookieLocale = request.cookies.get('NEXT_LOCALE')?.value
  if (cookieLocale && locales.includes(cookieLocale)) {
    return cookieLocale
  }
  
  // 从 Accept-Language 获取
  const acceptLanguage = request.headers.get('accept-language')
  if (acceptLanguage) {
    const preferred = acceptLanguage.split(',')[0].split('-')[0]
    if (locales.includes(preferred)) {
      return preferred
    }
  }
  
  return defaultLocale
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  
  // 检查路径是否已有语言前缀
  const pathnameHasLocale = locales.some(
    locale => pathname.startsWith(`/${locale}/`) || pathname === `/${locale}`
  )
  
  if (pathnameHasLocale) return
  
  // 重定向到带语言前缀的路径
  const locale = getLocale(request)
  request.nextUrl.pathname = `/${locale}${pathname}`
  
  const response = NextResponse.redirect(request.nextUrl)
  response.cookies.set('NEXT_LOCALE', locale)
  
  return response
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
}
```


---

## 16. 身份认证

### 16.1 使用 NextAuth.js (Auth.js)

```bash
npm install next-auth
```

```typescript
// app/api/auth/[...nextauth]/route.ts
import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import GitHubProvider from 'next-auth/providers/github'
import GoogleProvider from 'next-auth/providers/google'
import { PrismaAdapter } from '@auth/prisma-adapter'
import { prisma } from '@/lib/prisma'
import bcrypt from 'bcryptjs'

const handler = NextAuth({
  adapter: PrismaAdapter(prisma),
  
  providers: [
    // GitHub OAuth
    GitHubProvider({
      clientId: process.env.GITHUB_ID!,
      clientSecret: process.env.GITHUB_SECRET!,
    }),
    
    // Google OAuth
    GoogleProvider({
      clientId: process.env.GOOGLE_ID!,
      clientSecret: process.env.GOOGLE_SECRET!,
    }),
    
    // 邮箱密码登录
    CredentialsProvider({
      name: 'credentials',
      credentials: {
        email: { label: '邮箱', type: 'email' },
        password: { label: '密码', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error('请输入邮箱和密码')
        }
        
        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        })
        
        if (!user || !user.password) {
          throw new Error('用户不存在')
        }
        
        const isValid = await bcrypt.compare(
          credentials.password,
          user.password
        )
        
        if (!isValid) {
          throw new Error('密码错误')
        }
        
        return {
          id: user.id,
          email: user.email,
          name: user.name,
          image: user.image,
        }
      },
    }),
  ],
  
  session: {
    strategy: 'jwt',
  },
  
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
      }
      return token
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string
      }
      return session
    },
  },
  
  pages: {
    signIn: '/login',
    error: '/login',
  },
})

export { handler as GET, handler as POST }
```

### 16.2 Session Provider

```typescript
// components/Providers.tsx
'use client'

import { SessionProvider } from 'next-auth/react'

export default function Providers({ children }: { children: React.ReactNode }) {
  return <SessionProvider>{children}</SessionProvider>
}

// app/layout.tsx
import Providers from '@/components/Providers'

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
```

### 16.3 获取 Session

```typescript
// 服务端组件
import { getServerSession } from 'next-auth'
import { authOptions } from '@/app/api/auth/[...nextauth]/route'

export default async function ProfilePage() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    redirect('/login')
  }
  
  return (
    <div>
      <h1>欢迎, {session.user?.name}</h1>
      <img src={session.user?.image} alt="头像" />
    </div>
  )
}
```

```typescript
// 客户端组件
'use client'

import { useSession, signIn, signOut } from 'next-auth/react'

export default function AuthButton() {
  const { data: session, status } = useSession()
  
  if (status === 'loading') {
    return <div>加载中...</div>
  }
  
  if (session) {
    return (
      <div>
        <span>已登录: {session.user?.email}</span>
        <button onClick={() => signOut()}>退出</button>
      </div>
    )
  }
  
  return (
    <div>
      <button onClick={() => signIn('github')}>GitHub 登录</button>
      <button onClick={() => signIn('google')}>Google 登录</button>
      <button onClick={() => signIn()}>邮箱登录</button>
    </div>
  )
}
```

### 16.4 登录表单

```typescript
// app/login/page.tsx
'use client'

import { useState } from 'react'
import { signIn } from 'next-auth/react'
import { useRouter, useSearchParams } from 'next/navigation'

export default function LoginPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const callbackUrl = searchParams.get('callbackUrl') || '/dashboard'
  const error = searchParams.get('error')
  
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    
    const result = await signIn('credentials', {
      email,
      password,
      redirect: false,
    })
    
    setIsLoading(false)
    
    if (result?.error) {
      alert(result.error)
    } else {
      router.push(callbackUrl)
    }
  }
  
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-full max-w-md p-8 bg-white rounded-lg shadow">
        <h1 className="text-2xl font-bold mb-6">登录</h1>
        
        {error && (
          <div className="mb-4 p-3 bg-red-100 text-red-700 rounded">
            登录失败，请重试
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">邮箱</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 border rounded"
              required
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium mb-1">密码</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 border rounded"
              required
            />
          </div>
          
          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:opacity-50"
          >
            {isLoading ? '登录中...' : '登录'}
          </button>
        </form>
        
        <div className="mt-6">
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-white text-gray-500">或</span>
            </div>
          </div>
          
          <div className="mt-6 space-y-3">
            <button
              onClick={() => signIn('github', { callbackUrl })}
              className="w-full py-2 border rounded flex items-center justify-center gap-2"
            >
              GitHub 登录
            </button>
            <button
              onClick={() => signIn('google', { callbackUrl })}
              className="w-full py-2 border rounded flex items-center justify-center gap-2"
            >
              Google 登录
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
```

### 16.5 保护路由

```typescript
// middleware.ts
import { withAuth } from 'next-auth/middleware'
import { NextResponse } from 'next/server'

export default withAuth(
  function middleware(req) {
    // 可以在这里添加额外的逻辑
    return NextResponse.next()
  },
  {
    callbacks: {
      authorized: ({ token, req }) => {
        // 检查是否有 token
        if (req.nextUrl.pathname.startsWith('/admin')) {
          return token?.role === 'admin'
        }
        return !!token
      },
    },
  }
)

export const config = {
  matcher: ['/dashboard/:path*', '/admin/:path*', '/profile/:path*'],
}
```

---

## 17. 部署与优化

### 17.1 构建优化

```typescript
// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  // 输出独立部署包
  output: 'standalone',
  
  // 压缩
  compress: true,
  
  // 生产环境移除 console
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },
  
  // 实验性功能
  experimental: {
    // 优化包导入
    optimizePackageImports: ['@heroicons/react', 'lodash'],
  },
  
  // Webpack 配置
  webpack: (config, { isServer }) => {
    // 自定义配置
    return config
  },
}

module.exports = nextConfig
```

### 17.2 Bundle 分析

```bash
# 安装分析工具
npm install @next/bundle-analyzer

# next.config.js
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
})

module.exports = withBundleAnalyzer({
  // 其他配置
})

# 运行分析
ANALYZE=true npm run build
```

### 17.3 Docker 部署

```dockerfile
# Dockerfile
FROM node:18-alpine AS base

# 安装依赖
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# 构建
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# 生产镜像
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/mydb
    depends_on:
      - db
  
  db:
    image: postgres:15
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=mydb
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### 17.4 Vercel 部署

```json
// vercel.json
{
  "buildCommand": "npm run build",
  "outputDirectory": ".next",
  "framework": "nextjs",
  "regions": ["hnd1"],
  "env": {
    "DATABASE_URL": "@database-url"
  },
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        }
      ]
    }
  ],
  "redirects": [
    {
      "source": "/old-path",
      "destination": "/new-path",
      "permanent": true
    }
  ]
}
```

### 17.5 性能优化清单

```typescript
// 1. 图片优化
import Image from 'next/image'
<Image src="/hero.jpg" alt="Hero" width={800} height={600} priority />

// 2. 字体优化
import { Inter } from 'next/font/google'
const inter = Inter({ subsets: ['latin'], display: 'swap' })

// 3. 动态导入
import dynamic from 'next/dynamic'
const HeavyComponent = dynamic(() => import('./HeavyComponent'), {
  loading: () => <p>加载中...</p>,
  ssr: false,  // 禁用服务端渲染
})

// 4. 代码分割
// 自动按路由分割，无需手动配置

// 5. 预加载
import Link from 'next/link'
<Link href="/about" prefetch={true}>关于</Link>

// 6. 缓存策略
export const revalidate = 3600  // ISR

// 7. 流式渲染
import { Suspense } from 'react'
<Suspense fallback={<Loading />}>
  <SlowComponent />
</Suspense>
```


---

## 18. 常见错误与解决方案

### 18.1 "use client" 相关错误

#### 错误1：在服务端组件中使用 hooks

```typescript
// ❌ 错误：服务端组件不能使用 hooks
// app/page.tsx
import { useState } from 'react'

export default function Page() {
  const [count, setCount] = useState(0)  // 报错！
  return <div>{count}</div>
}

// ✅ 正确：添加 'use client' 指令
'use client'

import { useState } from 'react'

export default function Page() {
  const [count, setCount] = useState(0)
  return <div>{count}</div>
}
```

#### 错误2：在客户端组件中导入服务端组件

```typescript
// ❌ 错误：客户端组件不能直接导入服务端组件
'use client'

import ServerComponent from './ServerComponent'  // 会变成客户端组件

// ✅ 正确：通过 children 传递
'use client'

export default function ClientWrapper({ children }: { children: React.ReactNode }) {
  return <div onClick={() => {}}>{children}</div>
}

// 在服务端组件中使用
import ClientWrapper from './ClientWrapper'
import ServerComponent from './ServerComponent'

export default function Page() {
  return (
    <ClientWrapper>
      <ServerComponent />
    </ClientWrapper>
  )
}
```

### 18.2 数据获取错误

#### 错误3：在客户端组件中使用 async/await

```typescript
// ❌ 错误：客户端组件不能是 async 函数
'use client'

export default async function Page() {  // 报错！
  const data = await fetch('/api/data')
  return <div>{data}</div>
}

// ✅ 正确：使用 useEffect 或数据获取库
'use client'

import { useState, useEffect } from 'react'

export default function Page() {
  const [data, setData] = useState(null)
  
  useEffect(() => {
    fetch('/api/data')
      .then(res => res.json())
      .then(setData)
  }, [])
  
  return <div>{data}</div>
}

// ✅ 更好：使用 SWR
'use client'

import useSWR from 'swr'

export default function Page() {
  const { data, error, isLoading } = useSWR('/api/data', fetcher)
  
  if (isLoading) return <div>加载中...</div>
  if (error) return <div>加载失败</div>
  
  return <div>{data}</div>
}
```

#### 错误4：fetch 缓存问题

```typescript
// ❌ 问题：数据不更新
const data = await fetch('https://api.example.com/data')  // 默认缓存

// ✅ 解决：禁用缓存或设置重新验证
const data = await fetch('https://api.example.com/data', {
  cache: 'no-store'  // 每次请求都获取新数据
})

// 或使用 ISR
const data = await fetch('https://api.example.com/data', {
  next: { revalidate: 60 }  // 60秒后重新验证
})
```

### 18.3 路由相关错误

#### 错误5：动态路由参数类型错误

```typescript
// ❌ 错误：params 是 Promise（Next.js 15+）
export default function Page({ params }: { params: { id: string } }) {
  return <div>{params.id}</div>  // 可能报错
}

// ✅ 正确：await params（Next.js 15+）
export default async function Page({ 
  params 
}: { 
  params: Promise<{ id: string }> 
}) {
  const { id } = await params
  return <div>{id}</div>
}

// Next.js 13-14 仍然使用同步方式
export default function Page({ params }: { params: { id: string } }) {
  return <div>{params.id}</div>
}
```

#### 错误6：useRouter 导入错误

```typescript
// ❌ 错误：从 next/router 导入（Pages Router）
import { useRouter } from 'next/router'

// ✅ 正确：从 next/navigation 导入（App Router）
import { useRouter } from 'next/navigation'
```

### 18.4 Server Actions 错误

#### 错误7：Server Action 返回不可序列化的数据

```typescript
// ❌ 错误：返回 Date 对象
'use server'

export async function getData() {
  return {
    createdAt: new Date()  // Date 不可序列化
  }
}

// ✅ 正确：转换为字符串
'use server'

export async function getData() {
  return {
    createdAt: new Date().toISOString()
  }
}
```

#### 错误8：在 Server Action 中使用 redirect 后继续执行

```typescript
// ❌ 错误：redirect 后的代码仍会执行
'use server'

export async function createPost(formData: FormData) {
  await db.post.create({ data: { ... } })
  redirect('/posts')
  console.log('这行代码仍会执行！')  // 不会执行，redirect 会抛出错误
}

// ✅ 正确：redirect 会抛出 NEXT_REDIRECT 错误，终止执行
'use server'

export async function createPost(formData: FormData) {
  try {
    await db.post.create({ data: { ... } })
  } catch (error) {
    return { error: '创建失败' }
  }
  redirect('/posts')  // 放在 try-catch 外部
}
```

### 18.5 样式相关错误

#### 错误9：CSS Modules 类名不生效

```typescript
// ❌ 错误：使用字符串类名
import styles from './Button.module.css'

<button className="button">按钮</button>  // 不生效

// ✅ 正确：使用 styles 对象
<button className={styles.button}>按钮</button>
```

#### 错误10：Tailwind 类名不生效

```typescript
// ❌ 问题：动态类名不生效
const color = 'red'
<div className={`bg-${color}-500`}>内容</div>  // 不生效

// ✅ 正确：使用完整类名
const colorClasses = {
  red: 'bg-red-500',
  blue: 'bg-blue-500',
}
<div className={colorClasses[color]}>内容</div>

// 或在 safelist 中添加
// tailwind.config.js
module.exports = {
  safelist: ['bg-red-500', 'bg-blue-500'],
}
```

### 18.6 环境变量错误

#### 错误11：客户端无法访问环境变量

```typescript
// ❌ 错误：客户端无法访问
// .env
API_KEY=secret

// 客户端组件
const key = process.env.API_KEY  // undefined

// ✅ 正确：使用 NEXT_PUBLIC_ 前缀
// .env
NEXT_PUBLIC_API_URL=https://api.example.com

// 客户端组件
const url = process.env.NEXT_PUBLIC_API_URL  // 可以访问
```

### 18.7 Image 组件错误

#### 错误12：远程图片未配置

```typescript
// ❌ 错误：未配置远程图片域名
<Image src="https://example.com/image.jpg" alt="Image" width={400} height={300} />
// Error: Invalid src prop

// ✅ 正确：在 next.config.js 中配置
// next.config.js
module.exports = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'example.com',
      },
    ],
  },
}
```

#### 错误13：fill 模式下父元素没有定位

```typescript
// ❌ 错误：父元素没有 position
<div>
  <Image src="/image.jpg" alt="Image" fill />
</div>
// 图片可能溢出或不显示

// ✅ 正确：父元素需要 position: relative
<div className="relative w-full h-64">
  <Image src="/image.jpg" alt="Image" fill className="object-cover" />
</div>
```

### 18.8 中间件错误

#### 错误14：中间件位置错误

```
// ❌ 错误：中间件放在 app 目录下
app/
├── middleware.ts  // 不会生效
└── page.tsx

// ✅ 正确：中间件放在项目根目录或 src 目录
middleware.ts  // 项目根目录
// 或
src/
├── middleware.ts  // src 目录
└── app/
```

### 18.9 TypeScript 错误

#### 错误15：Metadata 类型错误

```typescript
// ❌ 错误：类型不匹配
export const metadata = {
  title: 123,  // 应该是 string
}

// ✅ 正确：使用正确的类型
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: '我的网站',
  description: '网站描述',
}
```

### 18.10 常见调试技巧

```typescript
// 1. 检查组件是服务端还是客户端
console.log('Is Server:', typeof window === 'undefined')

// 2. 检查环境变量
console.log('NODE_ENV:', process.env.NODE_ENV)
console.log('Public URL:', process.env.NEXT_PUBLIC_API_URL)

// 3. 使用 React DevTools 检查组件树

// 4. 使用 Network 面板检查请求

// 5. 检查构建输出
// npm run build 会显示每个路由的渲染模式：
// ○ (Static)   - 静态生成
// ● (SSG)      - 静态生成（带数据）
// λ (Dynamic)  - 动态渲染
// ƒ (Dynamic)  - 动态渲染（使用动态函数）

// 6. 使用 next info 检查环境
// npx next info
```

---

## 总结

Next.js 13+ 的 App Router 带来了全新的开发范式：

1. **服务端优先**：默认使用服务端组件，减少客户端 JavaScript
2. **简化数据获取**：直接在组件中使用 async/await
3. **灵活的缓存**：多层缓存机制，精细控制数据新鲜度
4. **流式渲染**：使用 Suspense 实现渐进式加载
5. **Server Actions**：简化表单处理和数据变更

掌握这些概念后，你就能构建高性能、SEO 友好的现代 Web 应用了！

---

> 📚 参考资源
> - [Next.js 官方文档](https://nextjs.org/docs)
> - [Next.js GitHub](https://github.com/vercel/next.js)
> - [Vercel 部署文档](https://vercel.com/docs)
> - [React Server Components](https://react.dev/blog/2023/03/22/react-labs-what-we-have-been-working-on-march-2023)
