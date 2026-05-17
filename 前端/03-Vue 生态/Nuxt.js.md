# Nuxt.js 全栈开发指南

> Nuxt.js 是基于 Vue.js 的服务端渲染框架，提供开箱即用的 SSR、SSG 和 SPA 解决方案
> 本笔记基于 Nuxt 3 + Vue 3 + TypeScript，涵盖从入门到生产的完整实践

---

## 目录

1. [Nuxt.js 简介](#1-nuxtjs-简介)
2. [项目搭建](#2-项目搭建)
3. [目录结构](#3-目录结构)
4. [路由系统](#4-路由系统)
5. [页面与布局](#5-页面与布局)
6. [数据获取](#6-数据获取)
7. [状态管理](#7-状态管理)
8. [组件开发](#8-组件开发)
9. [插件系统](#9-插件系统)
10. [中间件](#10-中间件)
11. [SEO优化](#11-seo优化)
12. [部署上线](#12-部署上线)
13. [常见错误与解决方案](#13-常见错误与解决方案)
14. [性能优化](#14-性能优化)
15. [最佳实践](#15-最佳实践)

---

## 1. Nuxt.js 简介

### 1.1 什么是 Nuxt.js

Nuxt.js 是一个基于 Vue.js 的通用应用框架，提供：
- 服务端渲染 (SSR)
- 静态站点生成 (SSG)
- 单页应用 (SPA)
- 文件系统路由
- 自动代码分割
- SEO 友好

### 1.2 核心特性

```
✓ 自动路由生成
✓ 服务端渲染
✓ 静态站点生成
✓ 自动代码分割
✓ 热模块替换
✓ TypeScript 支持
✓ 模块化架构
✓ SEO 优化
```

### 1.3 渲染模式对比

```
SSR (服务端渲染)
- 首屏快
- SEO 友好
- 服务器压力大

SSG (静态生成)
- 性能最佳
- 部署简单
- 内容更新需重新构建

SPA (单页应用)
- 交互流畅
- 首屏慢
- SEO 较差
```

---

## 2. 项目搭建

### 2.1 创建项目

```bash
# 使用 npx
npx nuxi@latest init my-nuxt-app

# 使用 pnpm (推荐)
pnpm dlx nuxi@latest init my-nuxt-app

# 进入项目
cd my-nuxt-app

# 安装依赖
pnpm install

# 启动开发服务器
pnpm dev
```

### 2.2 项目配置

**nuxt.config.ts:**

```typescript
// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  // 开发工具
  devtools: { enabled: true },
  
  // TypeScript 配置
  typescript: {
    strict: true,
    typeCheck: true
  },
  
  // 应用配置
  app: {
    head: {
      title: 'My Nuxt App',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'description', content: 'My amazing Nuxt application' }
      ],
      link: [
        { rel: 'icon', type: 'image/x-icon', href: '/favicon.ico' }
      ]
    }
  },
  
  // CSS 配置
  css: ['~/assets/css/main.css'],
  
  // 模块
  modules: [
    '@nuxtjs/tailwindcss',
    '@pinia/nuxt'
  ],
  
  // 运行时配置
  runtimeConfig: {
    // 服务端可用
    apiSecret: process.env.API_SECRET,
    // 客户端和服务端都可用
    public: {
      apiBase: process.env.API_BASE_URL || 'http://localhost:3000'
    }
  }
})
```

### 2.3 环境变量

**.env:**

```bash
# API 配置
API_BASE_URL=https://api.example.com
API_SECRET=your-secret-key

# 数据库配置
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
```

---

## 3. 目录结构

### 3.1 标准目录

```
my-nuxt-app/
├── .nuxt/              # 构建输出（自动生成）
├── .output/            # 生产构建输出
├── assets/             # 静态资源（需要处理）
│   ├── css/
│   ├── images/
│   └── fonts/
├── components/         # Vue 组件（自动导入）
│   ├── common/
│   └── layout/
├── composables/        # 组合式函数（自动导入）
├── layouts/            # 布局组件
│   ├── default.vue
│   └── admin.vue
├── middleware/         # 路由中间件
│   ├── auth.ts
│   └── guest.ts
├── pages/              # 页面组件（自动路由）
│   ├── index.vue
│   ├── about.vue
│   └── users/
│       ├── index.vue
│       └── [id].vue
├── plugins/            # 插件
│   └── api.ts
├── public/             # 静态文件（不处理）
│   └── favicon.ico
├── server/             # 服务端代码
│   ├── api/           # API 路由
│   ├── middleware/    # 服务端中间件
│   └── utils/         # 服务端工具
├── stores/             # Pinia 状态管理
│   └── user.ts
├── utils/              # 工具函数（自动导入）
├── app.vue             # 根组件
├── nuxt.config.ts      # Nuxt 配置
├── package.json
└── tsconfig.json
```

### 3.2 自动导入规则

```typescript
// components/ - 组件自动导入
// 使用: <MyComponent />
// 文件: components/MyComponent.vue

// composables/ - 组合式函数自动导入
// 使用: const data = useMyComposable()
// 文件: composables/useMyComposable.ts

// utils/ - 工具函数自动导入
// 使用: const result = myUtil()
// 文件: utils/myUtil.ts
```

---

## 4. 路由系统

### 4.1 基础路由

**pages/index.vue:**

```vue
<template>
  <div>
    <h1>首页</h1>
    <NuxtLink to="/about">关于我们</NuxtLink>
  </div>
</template>
```

**pages/about.vue:**

```vue
<template>
  <div>
    <h1>关于我们</h1>
  </div>
</template>
```

**生成的路由:**

```javascript
[
  { path: '/', component: 'pages/index.vue' },
  { path: '/about', component: 'pages/about.vue' }
]
```

### 4.2 动态路由

**pages/users/[id].vue:**

```vue
<script setup lang="ts">
const route = useRoute()
const userId = route.params.id

// 或使用组合式函数
const { data: user } = await useFetch(`/api/users/${userId}`)
</script>

<template>
  <div>
    <h1>用户详情: {{ userId }}</h1>
    <div v-if="user">
      <p>姓名: {{ user.name }}</p>
      <p>邮箱: {{ user.email }}</p>
    </div>
  </div>
</template>
```

### 4.3 嵌套路由

**pages/users/index.vue:**

```vue
<template>
  <div>
    <h1>用户列表</h1>
    <NuxtPage />
  </div>
</template>
```

**pages/users/profile.vue:**

```vue
<template>
  <div>
    <h2>用户资料</h2>
  </div>
</template>
```

### 4.4 路由导航

```vue
<script setup lang="ts">
const router = useRouter()

// 编程式导航
const goToAbout = () => {
  router.push('/about')
}

const goToUser = (id: number) => {
  router.push({
    path: `/users/${id}`,
    query: { tab: 'profile' }
  })
}

// 返回上一页
const goBack = () => {
  router.back()
}
</script>

<template>
  <div>
    <!-- 声明式导航 -->
    <NuxtLink to="/about">关于</NuxtLink>
    <NuxtLink :to="`/users/${userId}`">用户</NuxtLink>
    
    <!-- 编程式导航 -->
    <button @click="goToAbout">跳转到关于</button>
    <button @click="goBack">返回</button>
  </div>
</template>
```

### 4.5 路由中间件

**middleware/auth.ts:**

```typescript
export default defineNuxtRouteMiddleware((to, from) => {
  const user = useState('user')
  
  // 未登录跳转到登录页
  if (!user.value) {
    return navigateTo('/login')
  }
})
```

**使用中间件:**

```vue
<script setup lang="ts">
// 页面级中间件
definePageMeta({
  middleware: 'auth'
})
</script>
```

---

## 5. 页面与布局

### 5.1 默认布局

**layouts/default.vue:**

```vue
<template>
  <div class="layout">
    <header>
      <nav>
        <NuxtLink to="/">首页</NuxtLink>
        <NuxtLink to="/about">关于</NuxtLink>
      </nav>
    </header>
    
    <main>
      <slot />
    </main>
    
    <footer>
      <p>&copy; 2024 My App</p>
    </footer>
  </div>
</template>

<style scoped>
.layout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

main {
  flex: 1;
  padding: 20px;
}
</style>
```

### 5.2 自定义布局

**layouts/admin.vue:**

```vue
<template>
  <div class="admin-layout">
    <aside class="sidebar">
      <nav>
        <NuxtLink to="/admin">仪表盘</NuxtLink>
        <NuxtLink to="/admin/users">用户管理</NuxtLink>
      </nav>
    </aside>
    
    <div class="content">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.admin-layout {
  display: flex;
}

.sidebar {
  width: 250px;
  background: #f5f5f5;
}

.content {
  flex: 1;
  padding: 20px;
}
</style>
```

**使用自定义布局:**

```vue
<script setup lang="ts">
definePageMeta({
  layout: 'admin'
})
</script>

<template>
  <div>
    <h1>管理后台</h1>
  </div>
</template>
```

### 5.3 页面过渡

**nuxt.config.ts:**

```typescript
export default defineNuxtConfig({
  app: {
    pageTransition: { name: 'page', mode: 'out-in' }
  }
})
```

**assets/css/main.css:**

```css
.page-enter-active,
.page-leave-active {
  transition: all 0.3s;
}

.page-enter-from,
.page-leave-to {
  opacity: 0;
  transform: translateY(20px);
}
```

---

## 6. 数据获取

### 6.1 useFetch

```vue
<script setup lang="ts">
interface User {
  id: number
  name: string
  email: string
}

// 基础用法
const { data, pending, error, refresh } = await useFetch<User[]>('/api/users')

// 带参数
const userId = ref(1)
const { data: user } = await useFetch(`/api/users/${userId.value}`)

// 响应式参数
const { data: users } = await useFetch('/api/users', {
  query: { page: 1, limit: 10 }
})

// POST 请求
const createUser = async () => {
  const { data } = await useFetch('/api/users', {
    method: 'POST',
    body: { name: 'John', email: 'john@example.com' }
  })
}
</script>

<template>
  <div>
    <div v-if="pending">加载中...</div>
    <div v-else-if="error">错误: {{ error.message }}</div>
    <div v-else>
      <div v-for="user in data" :key="user.id">
        {{ user.name }}
      </div>
      <button @click="refresh">刷新</button>
    </div>
  </div>
</template>
```

### 6.2 useAsyncData

```vue
<script setup lang="ts">
// 自定义数据获取
const { data, pending } = await useAsyncData('users', () => {
  return $fetch('/api/users')
})

// 带依赖
const userId = ref(1)
const { data: user } = await useAsyncData(
  `user-${userId.value}`,
  () => $fetch(`/api/users/${userId.value}`),
  {
    watch: [userId] // 监听变化
  }
)

// 懒加载
const { data, pending, execute } = await useAsyncData(
  'users',
  () => $fetch('/api/users'),
  { lazy: true }
)
</script>
```

### 6.3 服务端 API

**server/api/users.ts:**

```typescript
export default defineEventHandler(async (event) => {
  // GET 请求
  if (event.method === 'GET') {
    return [
      { id: 1, name: 'John', email: 'john@example.com' },
      { id: 2, name: 'Jane', email: 'jane@example.com' }
    ]
  }
  
  // POST 请求
  if (event.method === 'POST') {
    const body = await readBody(event)
    // 处理数据
    return { success: true, data: body }
  }
})
```

**server/api/users/[id].ts:**

```typescript
export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id')
  
  // 模拟数据库查询
  const user = await db.users.findById(id)
  
  if (!user) {
    throw createError({
      statusCode: 404,
      message: '用户不存在'
    })
  }
  
  return user
})
```



---

## 7. 状态管理

### 7.1 useState

```vue
<script setup lang="ts">
// 定义全局状态
const counter = useState('counter', () => 0)

// 使用状态
const increment = () => {
  counter.value++
}
</script>

<template>
  <div>
    <p>计数: {{ counter }}</p>
    <button @click="increment">增加</button>
  </div>
</template>
```

### 7.2 Pinia 状态管理

**stores/user.ts:**

```typescript
import { defineStore } from 'pinia'

interface User {
  id: number
  name: string
  email: string
}

export const useUserStore = defineStore('user', () => {
  // State
  const user = ref<User | null>(null)
  const isLoggedIn = computed(() => !!user.value)
  
  // Actions
  const login = async (email: string, password: string) => {
    const { data } = await useFetch('/api/auth/login', {
      method: 'POST',
      body: { email, password }
    })
    
    if (data.value) {
      user.value = data.value.user
    }
  }
  
  const logout = () => {
    user.value = null
  }
  
  return {
    user,
    isLoggedIn,
    login,
    logout
  }
})
```

**使用 Store:**

```vue
<script setup lang="ts">
const userStore = useUserStore()

const handleLogin = async () => {
  await userStore.login('user@example.com', 'password')
}
</script>

<template>
  <div>
    <div v-if="userStore.isLoggedIn">
      <p>欢迎, {{ userStore.user?.name }}</p>
      <button @click="userStore.logout">退出</button>
    </div>
    <div v-else>
      <button @click="handleLogin">登录</button>
    </div>
  </div>
</template>
```

---

## 8. 组件开发

### 8.1 自动导入组件

**components/common/Button.vue:**

```vue
<script setup lang="ts">
interface Props {
  type?: 'primary' | 'secondary'
  loading?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  type: 'primary',
  loading: false
})

const emit = defineEmits<{
  click: []
}>()
</script>

<template>
  <button
    :class="['btn', `btn-${type}`]"
    :disabled="loading"
    @click="emit('click')"
  >
    <span v-if="loading">加载中...</span>
    <slot v-else />
  </button>
</template>

<style scoped>
.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.btn-primary {
  background: #42b983;
  color: white;
}

.btn-secondary {
  background: #f5f5f5;
  color: #333;
}
</style>
```

**使用组件:**

```vue
<template>
  <div>
    <!-- 自动导入，无需 import -->
    <CommonButton type="primary" @click="handleClick">
      点击我
    </CommonButton>
  </div>
</template>
```

### 8.2 组合式函数

**composables/useCounter.ts:**

```typescript
export const useCounter = (initialValue = 0) => {
  const count = ref(initialValue)
  
  const increment = () => {
    count.value++
  }
  
  const decrement = () => {
    count.value--
  }
  
  const reset = () => {
    count.value = initialValue
  }
  
  return {
    count: readonly(count),
    increment,
    decrement,
    reset
  }
}
```

**使用:**

```vue
<script setup lang="ts">
const { count, increment, decrement, reset } = useCounter(10)
</script>

<template>
  <div>
    <p>计数: {{ count }}</p>
    <button @click="increment">+</button>
    <button @click="decrement">-</button>
    <button @click="reset">重置</button>
  </div>
</template>
```

---

## 9. 插件系统

### 9.1 创建插件

**plugins/api.ts:**

```typescript
export default defineNuxtPlugin(() => {
  const config = useRuntimeConfig()
  
  const api = $fetch.create({
    baseURL: config.public.apiBase,
    onRequest({ options }) {
      // 添加认证头
      const token = useCookie('token')
      if (token.value) {
        options.headers = {
          ...options.headers,
          Authorization: `Bearer ${token.value}`
        }
      }
    },
    onResponseError({ response }) {
      // 统一错误处理
      if (response.status === 401) {
        navigateTo('/login')
      }
    }
  })
  
  return {
    provide: {
      api
    }
  }
})
```

**使用插件:**

```vue
<script setup lang="ts">
const { $api } = useNuxtApp()

const fetchUsers = async () => {
  const users = await $api('/users')
  return users
}
</script>
```

### 9.2 第三方插件

**plugins/element-plus.ts:**

```typescript
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'

export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.vueApp.use(ElementPlus)
})
```

---

## 10. 中间件

### 10.1 路由中间件

**middleware/auth.ts:**

```typescript
export default defineNuxtRouteMiddleware((to, from) => {
  const userStore = useUserStore()
  
  // 检查登录状态
  if (!userStore.isLoggedIn) {
    return navigateTo('/login')
  }
  
  // 检查权限
  if (to.meta.requiresAdmin && !userStore.user?.isAdmin) {
    return navigateTo('/403')
  }
})
```

### 10.2 全局中间件

**middleware/logger.global.ts:**

```typescript
export default defineNuxtRouteMiddleware((to, from) => {
  console.log('导航:', from.path, '->', to.path)
})
```

### 10.3 服务端中间件

**server/middleware/log.ts:**

```typescript
export default defineEventHandler((event) => {
  console.log('请求:', event.method, event.path)
})
```

---

## 11. SEO优化

### 11.1 页面元信息

```vue
<script setup lang="ts">
// 静态元信息
useHead({
  title: '我的页面',
  meta: [
    { name: 'description', content: '页面描述' },
    { property: 'og:title', content: '我的页面' }
  ]
})

// 动态元信息
const route = useRoute()
const { data: article } = await useFetch(`/api/articles/${route.params.id}`)

useSeoMeta({
  title: article.value?.title,
  description: article.value?.description,
  ogTitle: article.value?.title,
  ogDescription: article.value?.description,
  ogImage: article.value?.image
})
</script>
```

### 11.2 结构化数据

```vue
<script setup lang="ts">
useHead({
  script: [
    {
      type: 'application/ld+json',
      children: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'Article',
        headline: '文章标题',
        author: {
          '@type': 'Person',
          name: '作者名'
        }
      })
    }
  ]
})
</script>
```

---

## 12. 部署上线

### 12.1 构建配置

```bash
# SSR 构建
pnpm build

# 预览
pnpm preview

# 静态生成
pnpm generate
```

### 12.2 Vercel 部署

```bash
# 安装 Vercel CLI
npm i -g vercel

# 部署
vercel

# 生产部署
vercel --prod
```

### 12.3 Docker 部署

**Dockerfile:**

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["node", ".output/server/index.mjs"]
```

---

## 13. 常见错误与解决方案

### 13.1 Hydration 不匹配

**错误:**
```
Hydration node mismatch
```

**原因:**
- 服务端和客户端渲染结果不一致
- 使用了浏览器特定的 API

**解决:**
```vue
<script setup lang="ts">
// 使用 ClientOnly 组件
</script>

<template>
  <div>
    <ClientOnly>
      <div>{{ new Date().toLocaleString() }}</div>
    </ClientOnly>
  </div>
</template>
```

### 13.2 组件未找到

**错误:**
```
Component not found
```

**解决:**
```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  components: [
    {
      path: '~/components',
      pathPrefix: false
    }
  ]
})
```

### 13.3 环境变量未定义

**错误:**
```
Cannot read property of undefined
```

**解决:**
```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  runtimeConfig: {
    public: {
      apiBase: process.env.API_BASE_URL || 'http://localhost:3000'
    }
  }
})
```

### 13.4 路由跳转失败

**问题:**
```
navigateTo 不生效
```

**解决:**
```typescript
// 使用 return
export default defineNuxtRouteMiddleware((to, from) => {
  return navigateTo('/login') // 必须 return
})
```

---

## 14. 性能优化

### 14.1 懒加载

```vue
<script setup lang="ts">
// 组件懒加载
const LazyComponent = defineAsyncComponent(() => 
  import('~/components/HeavyComponent.vue')
)

// 数据懒加载
const { data, pending, execute } = await useAsyncData(
  'users',
  () => $fetch('/api/users'),
  { lazy: true }
)
</script>
```

### 14.2 图片优化

```vue
<template>
  <NuxtImg
    src="/images/hero.jpg"
    width="800"
    height="600"
    loading="lazy"
    format="webp"
  />
</template>
```

### 14.3 代码分割

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  vite: {
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            'vendor': ['vue', 'vue-router'],
            'ui': ['element-plus']
          }
        }
      }
    }
  }
})
```

---

## 15. 最佳实践

### 15.1 项目结构

```
推荐结构:
- 按功能模块组织
- 组件分类清晰
- 复用性高的放 composables
- 业务逻辑放 stores
```

### 15.2 命名规范

```typescript
// 组件: PascalCase
components/UserCard.vue

// 组合式函数: use开头
composables/useAuth.ts

// 工具函数: camelCase
utils/formatDate.ts

// 常量: UPPER_CASE
const API_BASE_URL = 'https://api.example.com'
```

### 15.3 类型安全

```typescript
// 定义类型
interface User {
  id: number
  name: string
  email: string
}

// 使用泛型
const { data } = await useFetch<User[]>('/api/users')
```

---

## 实战技巧总结

### 快速开发模板

```vue
<script setup lang="ts">
// 1. 定义类型
interface Props {
  title: string
}

// 2. 接收 props
const props = defineProps<Props>()

// 3. 数据获取
const { data, pending } = await useFetch('/api/data')

// 4. 响应式状态
const count = ref(0)

// 5. 计算属性
const doubleCount = computed(() => count.value * 2)

// 6. 方法
const handleClick = () => {
  count.value++
}
</script>

<template>
  <div>
    <h1>{{ title }}</h1>
    <div v-if="pending">加载中...</div>
    <div v-else>{{ data }}</div>
  </div>
</template>
```

### 常用命令

```bash
# 开发
pnpm dev

# 构建
pnpm build

# 预览
pnpm preview

# 生成静态站点
pnpm generate

# 类型检查
pnpm typecheck

# 代码检查
pnpm lint
```

---

## 参考资源

**官方文档:**
- Nuxt 3: https://nuxt.com/
- Vue 3: https://vuejs.org/
- Pinia: https://pinia.vuejs.org/

**学习资源:**
- Nuxt 3 教程
- Vue Mastery
- Nuxt Modules

---

> 💡 **提示**: Nuxt.js 提供了强大的约定优于配置理念，遵循最佳实践可以大大提高开发效率。
