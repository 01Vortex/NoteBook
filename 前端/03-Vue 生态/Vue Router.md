> Vue Router 是 Vue.js 官方的路由管理器，用于构建单页面应用
> 本笔记基于 Vue Router 4.x + Vue 3 + TypeScript + Composition API

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [路由定义](#3-路由定义)
4. [导航方式](#4-导航方式)
5. [动态路由](#5-动态路由)
6. [嵌套路由](#6-嵌套路由)
7. [命名路由与命名视图](#7-命名路由与命名视图)
8. [路由传参](#8-路由传参)
9. [导航守卫](#9-导航守卫)
10. [路由元信息](#10-路由元信息)
11. [路由懒加载](#11-路由懒加载)
12. [滚动行为](#12-滚动行为)
13. [路由过渡动画](#13-路由过渡动画)
14. [编程式导航](#14-编程式导航)
15. [路由模式](#15-路由模式)
16. [最佳实践](#16-最佳实践)
17. [性能优化](#17-性能优化)
18. [常见错误与解决方案](#18-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Vue Router？

Vue Router 是 Vue.js 的官方路由管理器，用于构建单页面应用（SPA）：

- **路由映射**: URL 与组件的映射关系
- **导航管理**: 控制页面跳转和历史记录
- **嵌套路由**: 支持多层级路由结构
- **导航守卫**: 路由跳转前后的钩子函数
- **懒加载**: 按需加载路由组件

### 1.2 核心概念

```typescript
// Router: 路由器实例
// Route: 当前激活的路由信息
// RouteRecord: 路由配置记录
// NavigationGuard: 导航守卫
// RouterLink: 声明式导航组件
// RouterView: 路由视图组件
```

### 1.3 Vue Router 4 vs 3

```typescript
// Vue Router 4 (Vue 3)
// ✅ 使用 createRouter 创建实例
// ✅ 使用 createWebHistory/createWebHashHistory
// ✅ 完整的 TypeScript 支持
// ✅ Composition API 支持
// ✅ 更小的包体积

// Vue Router 3 (Vue 2)
// ❌ 使用 new VueRouter
// ❌ mode: 'history' / 'hash'
// ❌ TypeScript 支持有限
```

---

## 2. 安装与配置

### 2.1 安装 Vue Router

```bash
# npm
npm install vue-router@4

# yarn
yarn add vue-router@4

# pnpm
pnpm add vue-router@4
```

### 2.2 基础配置


```typescript
// router/index.ts
import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

// 定义路由
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: () => import('@/views/Home.vue')
  },
  {
    path: '/about',
    name: 'About',
    component: () => import('@/views/About.vue')
  }
]

// 创建路由实例
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes
})

export default router
```

```typescript
// main.ts
import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

const app = createApp(App)

app.use(router)
app.mount('#app')
```

```vue
<!-- App.vue -->
<template>
  <div id="app">
    <nav>
      <RouterLink to="/">首页</RouterLink>
      <RouterLink to="/about">关于</RouterLink>
    </nav>
    
    <!-- 路由出口 -->
    <RouterView />
  </div>
</template>

<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
</script>
```

### 2.3 目录结构

```
src/
├── router/
│   ├── index.ts              # 路由主文件
│   ├── routes.ts             # 路由配置
│   ├── guards.ts             # 导航守卫
│   └── modules/              # 路由模块
│       ├── user.ts
│       └── admin.ts
├── views/                    # 页面组件
│   ├── Home.vue
│   ├── About.vue
│   └── User/
│       ├── Profile.vue
│       └── Settings.vue
└── main.ts
```

---

## 3. 路由定义

### 3.1 基础路由

```typescript
import { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: () => import('@/views/Home.vue')
  },
  {
    path: '/about',
    name: 'About',
    component: () => import('@/views/About.vue')
  },
  {
    path: '/contact',
    component: () => import('@/views/Contact.vue')
    // 可以不设置 name
  }
]
```

### 3.2 重定向

```typescript
const routes: RouteRecordRaw[] = [
  // 简单重定向
  {
    path: '/home',
    redirect: '/'
  },
  
  // 命名路由重定向
  {
    path: '/old-about',
    redirect: { name: 'About' }
  },
  
  // 动态重定向
  {
    path: '/search/:keyword',
    redirect: to => {
      return { path: '/results', query: { q: to.params.keyword } }
    }
  },
  
  // 别名
  {
    path: '/user/:id',
    component: () => import('@/views/User.vue'),
    alias: ['/u/:id', '/profile/:id']
  }
]
```

### 3.3 404 页面

```typescript
const routes: RouteRecordRaw[] = [
  // ... 其他路由
  
  // 捕获所有未匹配的路由
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue')
  },
  
  // 或者重定向到首页
  {
    path: '/:pathMatch(.*)*',
    redirect: '/'
  }
]
```

---

## 4. 导航方式

### 4.1 声明式导航

```vue
<template>
  <!-- 基础用法 -->
  <RouterLink to="/">首页</RouterLink>
  <RouterLink to="/about">关于</RouterLink>
  
  <!-- 命名路由 -->
  <RouterLink :to="{ name: 'User', params: { id: 123 } }">
    用户详情
  </RouterLink>
  
  <!-- 带查询参数 -->
  <RouterLink :to="{ path: '/search', query: { q: 'vue' } }">
    搜索
  </RouterLink>
  
  <!-- 自定义激活类名 -->
  <RouterLink 
    to="/about" 
    active-class="active"
    exact-active-class="exact-active"
  >
    关于
  </RouterLink>
  
  <!-- 自定义渲染 -->
  <RouterLink to="/about" custom v-slot="{ navigate, isActive }">
    <button @click="navigate" :class="{ active: isActive }">
      关于我们
    </button>
  </RouterLink>
  
  <!-- 替换历史记录 -->
  <RouterLink to="/about" replace>关于</RouterLink>
</template>
```

### 4.2 编程式导航

```typescript
import { useRouter } from 'vue-router'

const router = useRouter()

// 字符串路径
router.push('/about')

// 对象形式
router.push({ path: '/about' })

// 命名路由
router.push({ name: 'User', params: { id: 123 } })

// 带查询参数
router.push({ path: '/search', query: { q: 'vue' } })

// 带 hash
router.push({ path: '/about', hash: '#team' })

// 替换当前历史记录
router.replace({ path: '/about' })

// 前进/后退
router.go(1)   // 前进一步
router.go(-1)  // 后退一步
router.back()  // 后退
router.forward() // 前进
```

---

## 5. 动态路由

### 5.1 路径参数

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/user/:id',
    name: 'User',
    component: () => import('@/views/User.vue')
  },
  
  // 多个参数
  {
    path: '/post/:category/:id',
    component: () => import('@/views/Post.vue')
  },
  
  // 可选参数
  {
    path: '/article/:id?',
    component: () => import('@/views/Article.vue')
  },
  
  // 正则约束
  {
    path: '/user/:id(\\d+)',  // 只匹配数字
    component: () => import('@/views/User.vue')
  },
  
  // 可重复参数
  {
    path: '/files/:path(.*)',  // 匹配任意路径
    component: () => import('@/views/Files.vue')
  }
]
```

### 5.2 获取路由参数


```vue
<script setup lang="ts">
import { useRoute } from 'vue-router'
import { computed, watch } from 'vue'

const route = useRoute()

// 获取参数
const userId = computed(() => route.params.id)
const keyword = computed(() => route.query.q)

// 监听参数变化
watch(() => route.params.id, (newId, oldId) => {
  console.log(`用户ID从 ${oldId} 变为 ${newId}`)
  // 重新加载数据
  fetchUserData(newId)
})

// 或使用 watchEffect
import { watchEffect } from 'vue'

watchEffect(() => {
  console.log('当前用户ID:', route.params.id)
  fetchUserData(route.params.id)
})
</script>

<template>
  <div>
    <h1>用户 {{ userId }}</h1>
    <p>搜索关键词: {{ keyword }}</p>
  </div>
</template>
```

### 5.3 动态添加路由

```typescript
import { useRouter } from 'vue-router'

const router = useRouter()

// 添加路由
router.addRoute({
  path: '/admin',
  name: 'Admin',
  component: () => import('@/views/Admin.vue')
})

// 添加嵌套路由
router.addRoute('ParentRouteName', {
  path: 'child',
  component: () => import('@/views/Child.vue')
})

// 删除路由
router.removeRoute('Admin')

// 检查路由是否存在
if (router.hasRoute('Admin')) {
  console.log('Admin 路由存在')
}

// 获取所有路由
const routes = router.getRoutes()
```

---

## 6. 嵌套路由

### 6.1 定义嵌套路由

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/user/:id',
    component: () => import('@/views/User.vue'),
    children: [
      {
        // 当 /user/:id 匹配成功时
        // UserHome 会被渲染在 User 的 <router-view> 中
        path: '',
        component: () => import('@/views/user/Home.vue')
      },
      {
        // 当 /user/:id/profile 匹配成功时
        path: 'profile',
        component: () => import('@/views/user/Profile.vue')
      },
      {
        // 当 /user/:id/posts 匹配成功时
        path: 'posts',
        component: () => import('@/views/user/Posts.vue')
      }
    ]
  }
]
```

### 6.2 嵌套路由组件

```vue
<!-- views/User.vue -->
<template>
  <div class="user">
    <h2>用户 {{ $route.params.id }}</h2>
    
    <nav>
      <RouterLink :to="`/user/${$route.params.id}`">首页</RouterLink>
      <RouterLink :to="`/user/${$route.params.id}/profile`">资料</RouterLink>
      <RouterLink :to="`/user/${$route.params.id}/posts`">文章</RouterLink>
    </nav>
    
    <!-- 子路由出口 -->
    <RouterView />
  </div>
</template>
```

### 6.3 多层嵌套

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/dashboard',
    component: () => import('@/layouts/Dashboard.vue'),
    children: [
      {
        path: 'analytics',
        component: () => import('@/views/dashboard/Analytics.vue'),
        children: [
          {
            path: 'overview',
            component: () => import('@/views/dashboard/analytics/Overview.vue')
          },
          {
            path: 'reports',
            component: () => import('@/views/dashboard/analytics/Reports.vue')
          }
        ]
      }
    ]
  }
]
```

---

## 7. 命名路由与命名视图

### 7.1 命名路由

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/user/:id',
    name: 'UserProfile',
    component: () => import('@/views/User.vue')
  }
]

// 使用命名路由导航
router.push({ name: 'UserProfile', params: { id: 123 } })
```

```vue
<template>
  <!-- 声明式导航 -->
  <RouterLink :to="{ name: 'UserProfile', params: { id: 123 } }">
    用户资料
  </RouterLink>
</template>
```

### 7.2 命名视图

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    components: {
      default: () => import('@/views/Home.vue'),
      sidebar: () => import('@/components/Sidebar.vue'),
      footer: () => import('@/components/Footer.vue')
    }
  },
  {
    path: '/settings',
    components: {
      default: () => import('@/views/Settings.vue'),
      sidebar: () => import('@/components/SettingsSidebar.vue')
    }
  }
]
```

```vue
<!-- App.vue -->
<template>
  <div id="app">
    <RouterView />
    <RouterView name="sidebar" />
    <RouterView name="footer" />
  </div>
</template>
```

### 7.3 嵌套命名视图

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/dashboard',
    component: () => import('@/layouts/Dashboard.vue'),
    children: [
      {
        path: '',
        components: {
          default: () => import('@/views/dashboard/Main.vue'),
          sidebar: () => import('@/views/dashboard/Sidebar.vue')
        }
      }
    ]
  }
]
```

---

## 8. 路由传参

### 8.1 Params 参数

```typescript
// 定义路由
{
  path: '/user/:id',
  name: 'User',
  component: () => import('@/views/User.vue')
}

// 传递参数
router.push({ name: 'User', params: { id: 123 } })

// ❌ 错误: path 和 params 不能同时使用
router.push({ path: '/user', params: { id: 123 } })  // params 会被忽略

// ✅ 正确
router.push({ path: `/user/${123}` })
router.push({ name: 'User', params: { id: 123 } })
```

### 8.2 Query 参数

```typescript
// 传递查询参数
router.push({ 
  path: '/search', 
  query: { 
    q: 'vue',
    page: 1,
    sort: 'date'
  } 
})
// 结果: /search?q=vue&page=1&sort=date

// 获取查询参数
const route = useRoute()
console.log(route.query.q)      // 'vue'
console.log(route.query.page)   // '1' (注意是字符串)
```

### 8.3 Props 传参

```typescript
// 布尔模式: params 作为 props
{
  path: '/user/:id',
  component: User,
  props: true
}

// 对象模式: 静态 props
{
  path: '/promotion',
  component: Promotion,
  props: { newsletter: true }
}

// 函数模式: 动态 props
{
  path: '/search',
  component: Search,
  props: route => ({ 
    query: route.query.q,
    page: Number(route.query.page) || 1
  })
}
```

```vue
<!-- User.vue -->
<script setup lang="ts">
// 接收 props
defineProps<{
  id: string
}>()
</script>

<template>
  <div>用户ID: {{ id }}</div>
</template>
```

### 8.4 State 传参（隐藏参数）


```typescript
// 传递隐藏参数（不会显示在 URL 中）
router.push({
  name: 'User',
  params: { id: 123 },
  state: {
    from: 'homepage',
    timestamp: Date.now()
  }
})

// 获取 state
const route = useRoute()
console.log(history.state.from)  // 'homepage'
```

---

## 9. 导航守卫

### 9.1 全局前置守卫

```typescript
// router/index.ts
import { useUserStore } from '@/stores/user'

router.beforeEach(async (to, from, next) => {
  // to: 即将进入的路由
  // from: 当前导航正要离开的路由
  // next: 必须调用来 resolve 这个钩子
  
  console.log('导航到:', to.path)
  
  // 检查是否需要登录
  if (to.meta.requiresAuth) {
    const userStore = useUserStore()
    
    if (!userStore.isLoggedIn) {
      // 重定向到登录页
      next({ name: 'Login', query: { redirect: to.fullPath } })
    } else {
      next()  // 继续导航
    }
  } else {
    next()  // 确保一定要调用 next()
  }
})

// 或使用返回值（推荐）
router.beforeEach(async (to, from) => {
  const userStore = useUserStore()
  
  // 返回 false 取消导航
  if (to.meta.requiresAuth && !userStore.isLoggedIn) {
    return { name: 'Login', query: { redirect: to.fullPath } }
  }
  
  // 返回 undefined 或 true 继续导航
  return true
})
```

### 9.2 全局解析守卫

```typescript
router.beforeResolve(async (to, from) => {
  // 在导航被确认之前，所有组件内守卫和异步路由组件被解析之后调用
  
  if (to.meta.requiresCamera) {
    try {
      await askForCameraPermission()
    } catch (error) {
      return false  // 取消导航
    }
  }
})
```

### 9.3 全局后置钩子

```typescript
router.afterEach((to, from, failure) => {
  // 导航完成后调用
  // 不接受 next 函数，不会改变导航
  
  // 发送页面浏览统计
  sendToAnalytics(to.fullPath)
  
  // 设置页面标题
  document.title = to.meta.title || '默认标题'
  
  // 关闭加载动画
  hideLoadingIndicator()
  
  // 检查导航失败
  if (failure) {
    console.error('导航失败:', failure)
  }
})
```

### 9.4 路由独享守卫

```typescript
const routes: RouteRecordRaw[] = [
  {
    path: '/admin',
    component: () => import('@/views/Admin.vue'),
    beforeEnter: (to, from) => {
      // 只在进入该路由时触发
      const userStore = useUserStore()
      
      if (!userStore.isAdmin) {
        return { name: 'Home' }
      }
    }
  },
  
  // 多个守卫
  {
    path: '/users/:id',
    component: () => import('@/views/User.vue'),
    beforeEnter: [checkAuth, checkPermission]
  }
]

function checkAuth(to: RouteLocationNormalized) {
  const userStore = useUserStore()
  if (!userStore.isLoggedIn) {
    return { name: 'Login' }
  }
}

function checkPermission(to: RouteLocationNormalized) {
  // 检查权限逻辑
}
```

### 9.5 组件内守卫

```vue
<script setup lang="ts">
import { onBeforeRouteLeave, onBeforeRouteUpdate } from 'vue-router'

// 离开当前路由前
onBeforeRouteLeave((to, from) => {
  const answer = window.confirm('确定要离开吗？未保存的更改将丢失。')
  
  if (!answer) {
    return false  // 取消导航
  }
})

// 路由参数变化时（同一组件复用）
onBeforeRouteUpdate((to, from) => {
  // 响应路由参数的变化
  console.log('用户ID从', from.params.id, '变为', to.params.id)
  fetchUserData(to.params.id)
})
</script>
```

### 9.6 守卫执行顺序

```typescript
// 完整的导航解析流程:
// 1. 导航被触发
// 2. 在失活的组件里调用 beforeRouteLeave 守卫
// 3. 调用全局的 beforeEach 守卫
// 4. 在重用的组件里调用 beforeRouteUpdate 守卫
// 5. 在路由配置里调用 beforeEnter
// 6. 解析异步路由组件
// 7. 在被激活的组件里调用 beforeRouteEnter
// 8. 调用全局的 beforeResolve 守卫
// 9. 导航被确认
// 10. 调用全局的 afterEach 钩子
// 11. 触发 DOM 更新
// 12. 调用 beforeRouteEnter 守卫中传给 next 的回调函数
```

---

## 10. 路由元信息

### 10.1 定义元信息

```typescript
// router/index.ts
declare module 'vue-router' {
  interface RouteMeta {
    requiresAuth?: boolean
    roles?: string[]
    title?: string
    icon?: string
    keepAlive?: boolean
    transition?: string
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/admin',
    component: () => import('@/views/Admin.vue'),
    meta: {
      requiresAuth: true,
      roles: ['admin'],
      title: '管理后台',
      icon: 'admin-icon'
    }
  },
  {
    path: '/profile',
    component: () => import('@/views/Profile.vue'),
    meta: {
      requiresAuth: true,
      title: '个人资料',
      keepAlive: true
    }
  }
]
```

### 10.2 使用元信息

```typescript
// 在导航守卫中使用
router.beforeEach((to, from) => {
  // 检查权限
  if (to.meta.requiresAuth) {
    // 验证登录
  }
  
  // 检查角色
  if (to.meta.roles) {
    const userStore = useUserStore()
    if (!to.meta.roles.includes(userStore.role)) {
      return { name: 'Forbidden' }
    }
  }
  
  // 设置标题
  if (to.meta.title) {
    document.title = to.meta.title
  }
})
```

```vue
<script setup lang="ts">
import { useRoute } from 'vue-router'
import { computed } from 'vue'

const route = useRoute()

// 在组件中访问
const pageTitle = computed(() => route.meta.title)
const needsAuth = computed(() => route.meta.requiresAuth)
</script>

<template>
  <div>
    <h1>{{ pageTitle }}</h1>
    <p v-if="needsAuth">此页面需要登录</p>
  </div>
</template>
```

### 10.3 动态面包屑

```vue
<script setup lang="ts">
import { useRoute } from 'vue-router'
import { computed } from 'vue'

const route = useRoute()

const breadcrumbs = computed(() => {
  return route.matched.map(record => ({
    name: record.meta.title || record.name,
    path: record.path
  }))
})
</script>

<template>
  <nav class="breadcrumb">
    <RouterLink 
      v-for="(item, index) in breadcrumbs" 
      :key="index"
      :to="item.path"
    >
      {{ item.name }}
    </RouterLink>
  </nav>
</template>
```

---

## 11. 路由懒加载

### 11.1 基础懒加载

```typescript
// ❌ 不推荐: 直接导入（会打包到主 bundle）
import Home from '@/views/Home.vue'

const routes = [
  {
    path: '/',
    component: Home
  }
]

// ✅ 推荐: 懒加载
const routes = [
  {
    path: '/',
    component: () => import('@/views/Home.vue')
  }
]
```

### 11.2 分组懒加载

```typescript
// 使用 webpack 的魔法注释进行分组
const routes: RouteRecordRaw[] = [
  {
    path: '/user',
    component: () => import(/* webpackChunkName: "user" */ '@/views/User.vue')
  },
  {
    path: '/user/profile',
    component: () => import(/* webpackChunkName: "user" */ '@/views/UserProfile.vue')
  },
  {
    path: '/admin',
    component: () => import(/* webpackChunkName: "admin" */ '@/views/Admin.vue')
  }
]

// Vite 使用
const routes: RouteRecordRaw[] = [
  {
    path: '/user',
    component: () => import('@/views/User.vue')
  }
]
```

### 11.3 预加载和预获取

```typescript
// 预加载（高优先级）
{
  path: '/important',
  component: () => import(
    /* webpackPrefetch: true */
    '@/views/Important.vue'
  )
}

// 预获取（低优先级）
{
  path: '/optional',
  component: () => import(
    /* webpackPreload: true */
    '@/views/Optional.vue'
  )
}
```

---

## 12. 滚动行为

### 12.1 基础滚动行为


```typescript
const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    // savedPosition: 浏览器前进/后退时的位置
    
    // 返回保存的位置
    if (savedPosition) {
      return savedPosition
    }
    
    // 滚动到锚点
    if (to.hash) {
      return {
        el: to.hash,
        behavior: 'smooth'
      }
    }
    
    // 滚动到顶部
    return { top: 0 }
  }
})
```

### 12.2 延迟滚动

```typescript
scrollBehavior(to, from, savedPosition) {
  return new Promise((resolve) => {
    setTimeout(() => {
      if (savedPosition) {
        resolve(savedPosition)
      } else {
        resolve({ top: 0 })
      }
    }, 500)
  })
}
```

### 12.3 条件滚动

```typescript
scrollBehavior(to, from, savedPosition) {
  // 如果是从详情页返回列表页，保持位置
  if (from.name === 'Detail' && to.name === 'List') {
    return savedPosition || { top: 0 }
  }
  
  // 如果有 hash，滚动到锚点
  if (to.hash) {
    return {
      el: to.hash,
      top: 80,  // 偏移量（考虑固定头部）
      behavior: 'smooth'
    }
  }
  
  // 默认滚动到顶部
  return { top: 0 }
}
```

---

## 13. 路由过渡动画

### 13.1 基础过渡

```vue
<template>
  <router-view v-slot="{ Component, route }">
    <transition name="fade" mode="out-in">
      <component :is="Component" :key="route.path" />
    </transition>
  </router-view>
</template>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
```

### 13.2 动态过渡

```vue
<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const transitionName = ref('fade')

watch(() => route.meta.transition, (transition) => {
  transitionName.value = transition as string || 'fade'
})
</script>

<template>
  <router-view v-slot="{ Component }">
    <transition :name="transitionName" mode="out-in">
      <component :is="Component" />
    </transition>
  </router-view>
</template>
```

### 13.3 基于路由深度的过渡

```vue
<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()

const transitionName = computed(() => {
  const toDepth = route.path.split('/').length
  const fromDepth = route.matched.length
  return toDepth < fromDepth ? 'slide-right' : 'slide-left'
})
</script>

<template>
  <router-view v-slot="{ Component }">
    <transition :name="transitionName">
      <component :is="Component" />
    </transition>
  </router-view>
</template>

<style scoped>
.slide-left-enter-active,
.slide-left-leave-active,
.slide-right-enter-active,
.slide-right-leave-active {
  transition: all 0.3s ease;
}

.slide-left-enter-from {
  transform: translateX(100%);
}

.slide-left-leave-to {
  transform: translateX(-100%);
}

.slide-right-enter-from {
  transform: translateX(-100%);
}

.slide-right-leave-to {
  transform: translateX(100%);
}
</style>
```

---

## 14. 编程式导航

### 14.1 基础导航

```typescript
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()

// 导航到不同的位置
router.push('/home')
router.push({ path: '/home' })
router.push({ name: 'Home' })
router.push({ path: '/user', query: { id: 123 } })

// 替换当前位置
router.replace('/home')

// 前进/后退
router.go(1)
router.go(-1)
router.back()
router.forward()
```

### 14.2 导航失败处理

```typescript
import { NavigationFailureType, isNavigationFailure } from 'vue-router'

// 捕获导航错误
router.push('/admin').catch(failure => {
  if (isNavigationFailure(failure, NavigationFailureType.aborted)) {
    console.log('导航被中止')
  }
  
  if (isNavigationFailure(failure, NavigationFailureType.cancelled)) {
    console.log('导航被取消')
  }
  
  if (isNavigationFailure(failure, NavigationFailureType.duplicated)) {
    console.log('重复导航')
  }
})

// 或使用 async/await
async function navigateToAdmin() {
  try {
    await router.push('/admin')
  } catch (failure) {
    if (isNavigationFailure(failure)) {
      console.log('导航失败:', failure)
    }
  }
}
```

### 14.3 等待导航完成

```typescript
// 等待导航完成后执行操作
await router.push('/user/123')
console.log('导航完成')

// 或使用 isReady
await router.isReady()
console.log('路由器已准备就绪')
```

---

## 15. 路由模式

### 15.1 History 模式

```typescript
import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes
})

// URL 示例: https://example.com/user/123
// 优点: URL 美观，无 # 号
// 缺点: 需要服务器配置支持
```

### 15.2 Hash 模式

```typescript
import { createRouter, createWebHashHistory } from 'vue-router'

const router = createRouter({
  history: createWebHashHistory(),
  routes
})

// URL 示例: https://example.com/#/user/123
// 优点: 无需服务器配置
// 缺点: URL 有 # 号，SEO 不友好
```

### 15.3 Memory 模式（SSR）

```typescript
import { createRouter, createMemoryHistory } from 'vue-router'

const router = createRouter({
  history: createMemoryHistory(),
  routes
})

// 用于 Node.js 环境，不操作浏览器历史
```

### 15.4 服务器配置

```nginx
# Nginx 配置
location / {
  try_files $uri $uri/ /index.html;
}
```

```apache
# Apache 配置 (.htaccess)
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteBase /
  RewriteRule ^index\.html$ - [L]
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteRule . /index.html [L]
</IfModule>
```

---

## 16. 最佳实践

### 16.1 路由组织结构

```typescript
// ✅ 推荐: 模块化路由
// router/modules/user.ts
export default [
  {
    path: '/user',
    component: () => import('@/layouts/UserLayout.vue'),
    children: [
      {
        path: 'profile',
        name: 'UserProfile',
        component: () => import('@/views/user/Profile.vue')
      },
      {
        path: 'settings',
        name: 'UserSettings',
        component: () => import('@/views/user/Settings.vue')
      }
    ]
  }
]

// router/index.ts
import userRoutes from './modules/user'
import adminRoutes from './modules/admin'

const routes = [
  ...userRoutes,
  ...adminRoutes
]
```

### 16.2 路由命名规范

```typescript
// ✅ 推荐
const routes = [
  { path: '/user', name: 'User' },
  { path: '/user/profile', name: 'UserProfile' },
  { path: '/user/settings', name: 'UserSettings' },
  { path: '/admin', name: 'Admin' },
  { path: '/admin/users', name: 'AdminUsers' }
]

// ❌ 不推荐
const routes = [
  { path: '/user', name: 'user' },
  { path: '/user/profile', name: 'profile' },  // 不明确
  { path: '/admin', name: 'admin_page' }       // 命名不一致
]
```

### 16.3 权限控制


```typescript
// router/guards.ts
import { useUserStore } from '@/stores/user'
import type { NavigationGuardNext, RouteLocationNormalized } from 'vue-router'

export function setupGuards(router: Router) {
  // 权限检查
  router.beforeEach(async (to, from) => {
    const userStore = useUserStore()
    
    // 白名单路由
    const whiteList = ['Login', 'Register', 'Home']
    
    if (whiteList.includes(to.name as string)) {
      return true
    }
    
    // 检查登录
    if (!userStore.isLoggedIn) {
      return {
        name: 'Login',
        query: { redirect: to.fullPath }
      }
    }
    
    // 检查角色权限
    if (to.meta.roles) {
      const hasPermission = to.meta.roles.includes(userStore.role)
      if (!hasPermission) {
        return { name: 'Forbidden' }
      }
    }
    
    return true
  })
  
  // 页面标题
  router.afterEach((to) => {
    document.title = to.meta.title || '默认标题'
  })
  
  // 进度条
  router.beforeEach(() => {
    NProgress.start()
  })
  
  router.afterEach(() => {
    NProgress.done()
  })
}
```

### 16.4 路由懒加载策略

```typescript
// ✅ 推荐: 按功能模块分组
const routes = [
  {
    path: '/user',
    component: () => import(/* webpackChunkName: "user" */ '@/views/User.vue')
  },
  {
    path: '/admin',
    component: () => import(/* webpackChunkName: "admin" */ '@/views/Admin.vue')
  }
]

// ✅ 推荐: 首屏不懒加载
const routes = [
  {
    path: '/',
    component: Home  // 直接导入
  },
  {
    path: '/about',
    component: () => import('@/views/About.vue')  // 懒加载
  }
]
```

### 16.5 路由参数验证

```typescript
const routes = [
  {
    path: '/user/:id(\\d+)',  // 只接受数字
    component: () => import('@/views/User.vue'),
    beforeEnter: (to) => {
      const id = Number(to.params.id)
      if (id < 1 || id > 1000000) {
        return { name: 'NotFound' }
      }
    }
  }
]
```

### 16.6 错误处理

```typescript
// 全局错误处理
router.onError((error) => {
  console.error('路由错误:', error)
  
  if (error.message.includes('Failed to fetch dynamically imported module')) {
    window.location.reload()
  }
})

// 组件加载失败处理
const routes = [
  {
    path: '/user',
    component: () => import('@/views/User.vue').catch(() => {
      return import('@/views/ErrorPage.vue')
    })
  }
]
```

---

## 17. 性能优化

### 17.1 路由预加载

```typescript
// 鼠标悬停时预加载
import { useRouter } from 'vue-router'

function prefetchRoute(routeName: string) {
  const router = useRouter()
  const route = router.resolve({ name: routeName })
  
  if (route.matched.length > 0) {
    route.matched.forEach(record => {
      if (record.components) {
        Object.values(record.components).forEach(component => {
          if (typeof component === 'function') {
            component()  // 触发懒加载
          }
        })
      }
    })
  }
}
```

```vue
<template>
  <RouterLink 
    to="/user" 
    @mouseenter="prefetchRoute('User')"
  >
    用户页面
  </RouterLink>
</template>
```

### 17.2 Keep-Alive 缓存

```vue
<template>
  <router-view v-slot="{ Component, route }">
    <keep-alive :include="cachedViews">
      <component :is="Component" :key="route.fullPath" />
    </keep-alive>
  </router-view>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()

// 根据路由元信息决定是否缓存
const cachedViews = computed(() => {
  return route.matched
    .filter(record => record.meta.keepAlive)
    .map(record => record.name)
})
</script>
```

### 17.3 减少路由嵌套层级

```typescript
// ❌ 不推荐: 过深的嵌套
{
  path: '/dashboard',
  children: [
    {
      path: 'analytics',
      children: [
        {
          path: 'reports',
          children: [
            {
              path: 'monthly',
              component: MonthlyReport
            }
          ]
        }
      ]
    }
  ]
}

// ✅ 推荐: 扁平化
{
  path: '/dashboard/analytics/reports/monthly',
  component: MonthlyReport
}
```

### 17.4 路由懒加载优化

```typescript
// 使用动态导入
const routes = [
  {
    path: '/heavy',
    component: () => import(
      /* webpackChunkName: "heavy" */
      /* webpackPrefetch: true */
      '@/views/Heavy.vue'
    )
  }
]
```

---

## 18. 常见错误与解决方案

### 18.1 路由重复导航错误

```typescript
// ❌ 错误: 导航到当前路由
router.push('/current-page')
// Error: Avoided redundant navigation to current location

// ✅ 解决方案 1: 检查当前路由
if (route.path !== '/target') {
  router.push('/target')
}

// ✅ 解决方案 2: 捕获错误
router.push('/current-page').catch(err => {
  if (err.name !== 'NavigationDuplicated') {
    throw err
  }
})

// ✅ 解决方案 3: 使用 replace
router.replace('/current-page')
```

### 18.2 params 参数丢失

```typescript
// ❌ 错误: path 和 params 一起使用
router.push({
  path: '/user',
  params: { id: 123 }  // params 会被忽略
})

// ✅ 解决方案 1: 使用命名路由
router.push({
  name: 'User',
  params: { id: 123 }
})

// ✅ 解决方案 2: 拼接路径
router.push({
  path: `/user/${123}`
})
```

### 18.3 动态路由参数变化组件不更新

```typescript
// ❌ 问题: 从 /user/1 到 /user/2，组件不重新渲染

// ✅ 解决方案 1: 监听路由变化
watch(() => route.params.id, (newId) => {
  fetchUserData(newId)
})

// ✅ 解决方案 2: 使用 key
<router-view :key="$route.fullPath" />

// ✅ 解决方案 3: 使用 beforeRouteUpdate
onBeforeRouteUpdate((to, from) => {
  fetchUserData(to.params.id)
})
```

### 18.4 导航守卫死循环

```typescript
// ❌ 错误: 无限重定向
router.beforeEach((to, from) => {
  if (!isLoggedIn) {
    return { name: 'Login' }  // 如果 Login 也需要登录，会死循环
  }
})

// ✅ 解决方案: 添加白名单
router.beforeEach((to, from) => {
  const whiteList = ['Login', 'Register']
  
  if (!whiteList.includes(to.name as string) && !isLoggedIn) {
    return { name: 'Login' }
  }
})
```

### 18.5 异步路由组件加载失败

```typescript
// ❌ 问题: 网络问题导致组件加载失败

// ✅ 解决方案: 添加错误处理
const routes = [
  {
    path: '/user',
    component: () => import('@/views/User.vue').catch(() => {
      // 加载失败时显示错误页面
      return import('@/views/ErrorPage.vue')
    })
  }
]

// 或全局处理
router.onError((error) => {
  if (error.message.includes('Failed to fetch')) {
    console.error('组件加载失败，尝试重新加载')
    window.location.reload()
  }
})
```

### 18.6 beforeRouteEnter 中无法访问 this

```typescript
// ❌ 错误
beforeRouteEnter(to, from, next) {
  this.fetchData()  // this 是 undefined
}

// ✅ 解决方案: 使用 next 回调
beforeRouteEnter(to, from, next) {
  next(vm => {
    vm.fetchData()  // vm 是组件实例
  })
}

// ✅ Setup 语法: 使用 onBeforeRouteEnter
import { onBeforeRouteEnter } from 'vue-router'

onBeforeRouteEnter((to, from, next) => {
  // 在这里无法访问组件实例
  // 可以在 next 回调中访问
  next()
})
```

### 18.7 query 参数类型问题

```typescript
// ❌ 问题: query 参数都是字符串
const page = route.query.page  // "1" (字符串)

// ✅ 解决方案: 类型转换
const page = Number(route.query.page) || 1
const isActive = route.query.active === 'true'

// 或使用 props
{
  path: '/list',
  component: List,
  props: route => ({
    page: Number(route.query.page) || 1,
    pageSize: Number(route.query.pageSize) || 10
  })
}
```

### 18.8 路由懒加载后 TypeScript 类型丢失

```typescript
// ❌ 问题: 懒加载后类型推断失效

// ✅ 解决方案: 显式类型标注
import type { Component } from 'vue'

const routes: RouteRecordRaw[] = [
  {
    path: '/user',
    component: (() => import('@/views/User.vue')) as Component
  }
]
```

### 18.9 嵌套路由 404

```typescript
// ❌ 错误: 子路由路径以 / 开头
{
  path: '/user',
  children: [
    {
      path: '/profile',  // 错误！会匹配 /profile 而不是 /user/profile
      component: Profile
    }
  ]
}

// ✅ 正确: 子路由路径不要以 / 开头
{
  path: '/user',
  children: [
    {
      path: 'profile',  // 正确！匹配 /user/profile
      component: Profile
    }
  ]
}
```

### 18.10 History 模式刷新 404

```typescript
// ❌ 问题: History 模式下刷新页面 404

// ✅ 解决方案: 配置服务器
// Nginx
location / {
  try_files $uri $uri/ /index.html;
}

// 或使用 Hash 模式
const router = createRouter({
  history: createWebHashHistory(),
  routes
})
```

---

## 19. 实战示例

### 19.1 完整的路由配置


```typescript
// router/index.ts
import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useUserStore } from '@/stores/user'
import NProgress from 'nprogress'
import 'nprogress/nprogress.css'

// 路由配置
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: () => import('@/views/Home.vue'),
    meta: { title: '首页' }
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue'),
    meta: { title: '登录', guest: true }
  },
  {
    path: '/dashboard',
    component: () => import('@/layouts/Dashboard.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/Index.vue'),
        meta: { title: '控制台', keepAlive: true }
      },
      {
        path: 'profile',
        name: 'Profile',
        component: () => import('@/views/dashboard/Profile.vue'),
        meta: { title: '个人资料' }
      }
    ]
  },
  {
    path: '/admin',
    component: () => import('@/layouts/Admin.vue'),
    meta: { requiresAuth: true, roles: ['admin'] },
    children: [
      {
        path: 'users',
        name: 'AdminUsers',
        component: () => import('@/views/admin/Users.vue'),
        meta: { title: '用户管理' }
      }
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue'),
    meta: { title: '404' }
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) {
      return savedPosition
    }
    if (to.hash) {
      return { el: to.hash, behavior: 'smooth' }
    }
    return { top: 0 }
  }
})

// 全局前置守卫
router.beforeEach(async (to, from) => {
  NProgress.start()
  
  const userStore = useUserStore()
  
  // 已登录用户访问登录页，重定向到首页
  if (to.meta.guest && userStore.isLoggedIn) {
    return { name: 'Home' }
  }
  
  // 需要认证的路由
  if (to.meta.requiresAuth && !userStore.isLoggedIn) {
    return {
      name: 'Login',
      query: { redirect: to.fullPath }
    }
  }
  
  // 角色权限检查
  if (to.meta.roles) {
    const hasPermission = (to.meta.roles as string[]).includes(userStore.role)
    if (!hasPermission) {
      return { name: 'Forbidden' }
    }
  }
})

// 全局后置钩子
router.afterEach((to) => {
  NProgress.done()
  document.title = (to.meta.title as string) || '默认标题'
})

export default router
```

### 19.2 权限路由系统


```typescript
// router/permission.ts
import router from './index'
import { useUserStore } from '@/stores/user'
import { usePermissionStore } from '@/stores/permission'

const whiteList = ['/login', '/register', '/404']

router.beforeEach(async (to, from, next) => {
  const userStore = useUserStore()
  const permissionStore = usePermissionStore()
  
  if (userStore.token) {
    if (to.path === '/login') {
      next({ path: '/' })
    } else {
      // 检查是否已获取用户信息
      if (!userStore.roles || userStore.roles.length === 0) {
        try {
          // 获取用户信息
          const { roles } = await userStore.getUserInfo()
          
          // 根据角色生成可访问路由
          const accessRoutes = await permissionStore.generateRoutes(roles)
          
          // 动态添加路由
          accessRoutes.forEach(route => {
            router.addRoute(route)
          })
          
          // 重新导航，确保 addRoute 已完成
          next({ ...to, replace: true })
        } catch (error) {
          // 获取用户信息失败，清除 token 并重定向到登录页
          await userStore.logout()
          next(`/login?redirect=${to.path}`)
        }
      } else {
        next()
      }
    }
  } else {
    // 未登录
    if (whiteList.includes(to.path)) {
      next()
    } else {
      next(`/login?redirect=${to.path}`)
    }
  }
})
```

### 19.3 面包屑导航

```vue
<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()

interface Breadcrumb {
  title: string
  path: string
  disabled: boolean
}

const breadcrumbs = computed<Breadcrumb[]>(() => {
  const matched = route.matched.filter(item => item.meta?.title)
  
  return matched.map((item, index) => ({
    title: item.meta.title as string,
    path: item.path,
    disabled: index === matched.length - 1
  }))
})

function handleClick(item: Breadcrumb) {
  if (!item.disabled) {
    router.push(item.path)
  }
}
</script>

<template>
  <nav class="breadcrumb">
    <span 
      v-for="(item, index) in breadcrumbs" 
      :key="index"
      @click="handleClick(item)"
      :class="{ disabled: item.disabled }"
    >
      {{ item.title }}
      <span v-if="index < breadcrumbs.length - 1" class="separator">/</span>
    </span>
  </nav>
</template>

<style scoped>
.breadcrumb {
  display: flex;
  gap: 8px;
  padding: 16px;
}

.breadcrumb span {
  cursor: pointer;
  color: #1890ff;
}

.breadcrumb span.disabled {
  cursor: default;
  color: #666;
}

.separator {
  margin: 0 8px;
  color: #999;
}
</style>
```

### 19.4 标签页导航

```vue
<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

interface Tab {
  name: string
  title: string
  path: string
}

const route = useRoute()
const router = useRouter()

const tabs = ref<Tab[]>([
  { name: 'Home', title: '首页', path: '/' }
])

const activeTab = ref(route.name as string)

// 监听路由变化，添加标签
watch(() => route.name, (newName) => {
  if (newName && !tabs.value.find(tab => tab.name === newName)) {
    tabs.value.push({
      name: newName as string,
      title: route.meta.title as string || newName as string,
      path: route.path
    })
  }
  activeTab.value = newName as string
})

function closeTab(tab: Tab) {
  const index = tabs.value.findIndex(t => t.name === tab.name)
  
  if (index > -1) {
    tabs.value.splice(index, 1)
    
    // 如果关闭的是当前标签，跳转到前一个标签
    if (tab.name === activeTab.value && tabs.value.length > 0) {
      const targetTab = tabs.value[Math.max(0, index - 1)]
      router.push(targetTab.path)
    }
  }
}

function closeOthers(tab: Tab) {
  tabs.value = tabs.value.filter(t => t.name === tab.name || t.name === 'Home')
}

function closeAll() {
  tabs.value = [tabs.value[0]]
  router.push('/')
}
</script>

<template>
  <div class="tabs">
    <div 
      v-for="tab in tabs" 
      :key="tab.name"
      :class="['tab', { active: tab.name === activeTab }]"
      @click="router.push(tab.path)"
    >
      <span>{{ tab.title }}</span>
      <button 
        v-if="tab.name !== 'Home'"
        @click.stop="closeTab(tab)"
        class="close-btn"
      >
        ×
      </button>
    </div>
  </div>
</template>
```

---

## 总结

Vue Router 是 Vue.js 生态中强大的路由管理工具，核心特性包括：

**核心功能：**
- ✅ 声明式和编程式导航
- ✅ 动态路由匹配
- ✅ 嵌套路由支持
- ✅ 完整的导航守卫系统
- ✅ 路由懒加载
- ✅ 滚动行为控制
- ✅ 完整的 TypeScript 支持

**最佳实践要点：**
1. 使用命名路由提高可维护性
2. 合理使用路由懒加载优化性能
3. 通过导航守卫实现权限控制
4. 使用路由元信息管理页面配置
5. 模块化组织路由配置
6. 正确处理路由参数类型
7. 配置合适的滚动行为

**常见陷阱：**
- ❌ path 和 params 同时使用
- ❌ 动态路由参数变化组件不更新
- ❌ 导航守卫死循环
- ❌ 嵌套路由路径配置错误
- ❌ History 模式服务器配置缺失
- ❌ query 参数类型未转换

通过本笔记的学习，你应该能够：
- ✅ 熟练配置和使用 Vue Router
- ✅ 实现复杂的路由结构
- ✅ 掌握导航守卫的使用
- ✅ 优化路由性能
- ✅ 处理常见路由问题
- ✅ 构建权限路由系统

继续学习建议：
1. 实践完整的多页面应用
2. 研究大型项目的路由架构
3. 学习服务端渲染中的路由处理
4. 探索路由动画和过渡效果

---

> 最后更新: 2024
> 适用版本: Vue Router 4.x + Vue 3.x
> 官方文档: https://router.vuejs.org/
> 作者: Kiro AI Assistant
```
