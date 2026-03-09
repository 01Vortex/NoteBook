> Pinia 是 Vue 3 官方推荐的状态管理库，是 Vuex 的继任者
> 本笔记基于 Pinia 2.x + Vue 3 + TypeScript + Composition API

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [定义 Store](#3-定义-store)
4. [State 状态](#4-state-状态)
5. [Getters 计算属性](#5-getters-计算属性)
6. [Actions 动作](#6-actions-动作)
7. [在组件中使用](#7-在组件中使用)
8. [Store 组合](#8-store-组合)
9. [插件系统](#9-插件系统)
10. [持久化存储](#10-持久化存储)
11. [TypeScript 支持](#11-typescript-支持)
12. [DevTools 调试](#12-devtools-调试)
13. [最佳实践](#13-最佳实践)
14. [性能优化](#14-性能优化)
15. [常见错误与解决方案](#15-常见错误与解决方案)
16. [迁移指南](#16-迁移指南)

---

## 1. 基础概念

### 1.1 什么是 Pinia？

Pinia 是 Vue 的专属状态管理库，具有以下特点：

- **轻量**: 约 1KB，比 Vuex 更小
- **类型安全**: 完整的 TypeScript 支持
- **模块化**: 每个 Store 都是独立的
- **DevTools**: 完整的开发工具支持
- **插件系统**: 可扩展的插件机制
- **服务端渲染**: 支持 SSR

### 1.2 Pinia vs Vuex

```typescript
// Vuex 4
// ❌ 需要 mutations
// ❌ 模块嵌套复杂
// ❌ TypeScript 支持不完善

// Pinia
// ✅ 无需 mutations
// ✅ 扁平化结构
// ✅ 完整 TypeScript 支持
// ✅ 更简洁的 API
```

### 1.3 核心概念

```typescript
// Store = State + Getters + Actions
// State: 存储数据
// Getters: 计算属性
// Actions: 修改状态的方法（支持同步和异步）
```

---

## 2. 安装与配置

### 2.1 安装 Pinia

```bash
# npm
npm install pinia

# yarn
yarn add pinia

# pnpm
pnpm add pinia
```

### 2.2 创建 Pinia 实例


```typescript
// main.ts
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.mount('#app')
```

### 2.3 目录结构

```
src/
├── stores/
│   ├── index.ts          # 导出所有 store
│   ├── user.ts           # 用户 store
│   ├── cart.ts           # 购物车 store
│   └── counter.ts        # 计数器 store
├── main.ts
└── App.vue
```

---

## 3. 定义 Store

### 3.1 Options API 风格

```typescript
// stores/counter.ts
import { defineStore } from 'pinia'

export const useCounterStore = defineStore('counter', {
  // State
  state: () => ({
    count: 0,
    name: 'Counter'
  }),
  
  // Getters
  getters: {
    doubleCount: (state) => state.count * 2,
    
    // 访问其他 getter
    doubleCountPlusOne(): number {
      return this.doubleCount + 1
    }
  },
  
  // Actions
  actions: {
    increment() {
      this.count++
    },
    
    decrement() {
      this.count--
    },
    
    incrementBy(amount: number) {
      this.count += amount
    }
  }
})
```

### 3.2 Setup 风格（推荐）

```typescript
// stores/counter.ts
import { ref, computed } from 'vue'
import { defineStore } from 'pinia'

export const useCounterStore = defineStore('counter', () => {
  // State
  const count = ref(0)
  const name = ref('Counter')
  
  // Getters
  const doubleCount = computed(() => count.value * 2)
  const doubleCountPlusOne = computed(() => doubleCount.value + 1)
  
  // Actions
  function increment() {
    count.value++
  }
  
  function decrement() {
    count.value--
  }
  
  function incrementBy(amount: number) {
    count.value += amount
  }
  
  return {
    count,
    name,
    doubleCount,
    doubleCountPlusOne,
    increment,
    decrement,
    incrementBy
  }
})
```

### 3.3 命名规范

```typescript
// ✅ 推荐: use + 名称 + Store
export const useUserStore = defineStore('user', {})
export const useCartStore = defineStore('cart', {})
export const useProductStore = defineStore('product', {})

// ❌ 不推荐
export const UserStore = defineStore('user', {})
export const user = defineStore('user', {})
```

---

## 4. State 状态

### 4.1 定义 State


```typescript
// stores/user.ts
import { defineStore } from 'pinia'

interface User {
  id: number
  name: string
  email: string
  avatar?: string
}

export const useUserStore = defineStore('user', {
  state: () => ({
    user: null as User | null,
    token: '',
    isLoggedIn: false,
    preferences: {
      theme: 'light',
      language: 'zh-CN'
    },
    loginHistory: [] as string[]
  }),
  
  actions: {
    setUser(user: User) {
      this.user = user
      this.isLoggedIn = true
    }
  }
})
```

### 4.2 访问 State

```typescript
// 组件中
import { useUserStore } from '@/stores/user'

const userStore = useUserStore()

// 直接访问
console.log(userStore.user)
console.log(userStore.isLoggedIn)

// 修改 state
userStore.user = { id: 1, name: 'Alice', email: 'alice@example.com' }
userStore.isLoggedIn = true
```

### 4.3 重置 State

```typescript
const userStore = useUserStore()

// 重置到初始状态
userStore.$reset()
```

### 4.4 批量修改 State

```typescript
// ❌ 不推荐: 多次修改
userStore.user = newUser
userStore.token = newToken
userStore.isLoggedIn = true

// ✅ 推荐: 使用 $patch
userStore.$patch({
  user: newUser,
  token: newToken,
  isLoggedIn: true
})

// ✅ 推荐: 使用函数形式（复杂逻辑）
userStore.$patch((state) => {
  state.user = newUser
  state.token = newToken
  state.loginHistory.push(new Date().toISOString())
})
```

### 4.5 替换整个 State

```typescript
// 完全替换 state
userStore.$state = {
  user: null,
  token: '',
  isLoggedIn: false,
  preferences: { theme: 'dark', language: 'en-US' },
  loginHistory: []
}
```

---

## 5. Getters 计算属性

### 5.1 基础 Getter

```typescript
export const useUserStore = defineStore('user', {
  state: () => ({
    firstName: 'John',
    lastName: 'Doe',
    age: 25
  }),
  
  getters: {
    // 自动推断返回类型
    fullName: (state) => `${state.firstName} ${state.lastName}`,
    
    // 显式指定返回类型
    isAdult: (state): boolean => state.age >= 18,
    
    // 访问其他 getter
    greeting(): string {
      return `Hello, ${this.fullName}!`
    }
  }
})
```

### 5.2 带参数的 Getter


```typescript
export const useProductStore = defineStore('product', {
  state: () => ({
    products: [
      { id: 1, name: 'iPhone', price: 999, category: 'phone' },
      { id: 2, name: 'iPad', price: 799, category: 'tablet' },
      { id: 3, name: 'MacBook', price: 1999, category: 'laptop' }
    ]
  }),
  
  getters: {
    // 返回函数实现带参数的 getter
    getProductById: (state) => {
      return (id: number) => state.products.find(p => p.id === id)
    },
    
    getProductsByCategory: (state) => {
      return (category: string) => {
        return state.products.filter(p => p.category === category)
      }
    },
    
    // 价格范围筛选
    getProductsByPriceRange: (state) => {
      return (min: number, max: number) => {
        return state.products.filter(p => p.price >= min && p.price <= max)
      }
    }
  }
})

// 使用
const productStore = useProductStore()
const phone = productStore.getProductById(1)
const phones = productStore.getProductsByCategory('phone')
const affordable = productStore.getProductsByPriceRange(500, 1000)
```

### 5.3 访问其他 Store 的 Getter

```typescript
import { useUserStore } from './user'

export const useCartStore = defineStore('cart', {
  state: () => ({
    items: []
  }),
  
  getters: {
    // 访问其他 store
    summary(): string {
      const userStore = useUserStore()
      return `${userStore.fullName} 的购物车有 ${this.items.length} 件商品`
    }
  }
})
```

### 5.4 Setup 风格的 Getter

```typescript
import { ref, computed } from 'vue'
import { defineStore } from 'pinia'

export const useUserStore = defineStore('user', () => {
  const firstName = ref('John')
  const lastName = ref('Doe')
  
  // Getter 就是 computed
  const fullName = computed(() => `${firstName.value} ${lastName.value}`)
  
  // 带参数的 getter
  const getGreeting = computed(() => {
    return (time: string) => `${time}, ${fullName.value}!`
  })
  
  return { firstName, lastName, fullName, getGreeting }
})
```

---

## 6. Actions 动作

### 6.1 同步 Actions

```typescript
export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0
  }),
  
  actions: {
    increment() {
      this.count++
    },
    
    decrement() {
      this.count--
    },
    
    incrementBy(amount: number) {
      this.count += amount
    },
    
    reset() {
      this.count = 0
    },
    
    // 调用其他 action
    doubleIncrement() {
      this.increment()
      this.increment()
    }
  }
})
```

### 6.2 异步 Actions


```typescript
import axios from 'axios'

interface LoginParams {
  username: string
  password: string
}

export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    token: '',
    loading: false,
    error: null as string | null
  }),
  
  actions: {
    // 异步登录
    async login(params: LoginParams) {
      this.loading = true
      this.error = null
      
      try {
        const response = await axios.post('/api/login', params)
        this.user = response.data.user
        this.token = response.data.token
        
        // 保存到 localStorage
        localStorage.setItem('token', this.token)
        
        return response.data
      } catch (error: any) {
        this.error = error.message
        throw error
      } finally {
        this.loading = false
      }
    },
    
    // 异步获取用户信息
    async fetchUserInfo() {
      try {
        const response = await axios.get('/api/user/info')
        this.user = response.data
      } catch (error: any) {
        console.error('获取用户信息失败:', error)
        throw error
      }
    },
    
    // 登出
    async logout() {
      try {
        await axios.post('/api/logout')
      } finally {
        this.user = null
        this.token = ''
        localStorage.removeItem('token')
      }
    }
  }
})
```

### 6.3 访问其他 Store 的 Actions

```typescript
import { useUserStore } from './user'

export const useCartStore = defineStore('cart', {
  state: () => ({
    items: []
  }),
  
  actions: {
    async checkout() {
      const userStore = useUserStore()
      
      // 检查登录状态
      if (!userStore.user) {
        throw new Error('请先登录')
      }
      
      // 执行结账逻辑
      const response = await axios.post('/api/checkout', {
        userId: userStore.user.id,
        items: this.items
      })
      
      return response.data
    }
  }
})
```

### 6.4 订阅 Actions

```typescript
const userStore = useUserStore()

// 订阅 action 调用
userStore.$onAction(({
  name,      // action 名称
  store,     // store 实例
  args,      // 传递给 action 的参数
  after,     // action 成功后的钩子
  onError    // action 失败后的钩子
}) => {
  console.log(`Action ${name} 被调用，参数:`, args)
  
  after((result) => {
    console.log(`Action ${name} 执行成功，结果:`, result)
  })
  
  onError((error) => {
    console.error(`Action ${name} 执行失败:`, error)
  })
})
```

---

## 7. 在组件中使用

### 7.1 基础使用


```vue
<script setup lang="ts">
import { useCounterStore } from '@/stores/counter'

const counterStore = useCounterStore()

// 直接访问
console.log(counterStore.count)
console.log(counterStore.doubleCount)

// 调用 action
counterStore.increment()
counterStore.incrementBy(10)
</script>

<template>
  <div>
    <p>Count: {{ counterStore.count }}</p>
    <p>Double: {{ counterStore.doubleCount }}</p>
    <button @click="counterStore.increment">+1</button>
    <button @click="counterStore.decrement">-1</button>
  </div>
</template>
```

### 7.2 解构使用（响应式丢失问题）

```vue
<script setup lang="ts">
import { useCounterStore } from '@/stores/counter'

const counterStore = useCounterStore()

// ❌ 错误: 解构会失去响应式
const { count, doubleCount } = counterStore

// ✅ 正确: 使用 storeToRefs
import { storeToRefs } from 'pinia'
const { count, doubleCount } = storeToRefs(counterStore)

// ✅ Actions 可以直接解构（不需要响应式）
const { increment, decrement } = counterStore
</script>

<template>
  <div>
    <p>Count: {{ count }}</p>
    <p>Double: {{ doubleCount }}</p>
    <button @click="increment">+1</button>
    <button @click="decrement">-1</button>
  </div>
</template>
```

### 7.3 在 Options API 中使用

```vue
<script lang="ts">
import { defineComponent } from 'vue'
import { mapStores, mapState, mapActions } from 'pinia'
import { useCounterStore } from '@/stores/counter'

export default defineComponent({
  computed: {
    // 访问整个 store
    ...mapStores(useCounterStore),
    // this.counterStore
    
    // 映射 state 和 getters
    ...mapState(useCounterStore, ['count', 'doubleCount']),
    // this.count, this.doubleCount
    
    // 自定义名称
    ...mapState(useCounterStore, {
      myCount: 'count',
      myDouble: 'doubleCount'
    })
  },
  
  methods: {
    // 映射 actions
    ...mapActions(useCounterStore, ['increment', 'decrement']),
    // this.increment(), this.decrement()
    
    handleClick() {
      this.increment()
    }
  }
})
</script>
```

### 7.4 在 setup 外使用

```typescript
// router/index.ts
import { createRouter } from 'vue-router'
import { useUserStore } from '@/stores/user'

const router = createRouter({
  // ...
})

router.beforeEach((to, from) => {
  // ✅ 在导航守卫中使用
  const userStore = useUserStore()
  
  if (to.meta.requiresAuth && !userStore.isLoggedIn) {
    return '/login'
  }
})

export default router
```

---

## 8. Store 组合

### 8.1 在 Store 中使用其他 Store


```typescript
// stores/cart.ts
import { defineStore } from 'pinia'
import { useUserStore } from './user'
import { useProductStore } from './product'

export const useCartStore = defineStore('cart', {
  state: () => ({
    items: [] as Array<{ productId: number; quantity: number }>
  }),
  
  getters: {
    // 组合多个 store
    cartSummary(): string {
      const userStore = useUserStore()
      const productStore = useProductStore()
      
      const total = this.items.reduce((sum, item) => {
        const product = productStore.getProductById(item.productId)
        return sum + (product?.price || 0) * item.quantity
      }, 0)
      
      return `${userStore.fullName} 的购物车总价: ¥${total}`
    }
  },
  
  actions: {
    addItem(productId: number, quantity: number) {
      const userStore = useUserStore()
      
      if (!userStore.isLoggedIn) {
        throw new Error('请先登录')
      }
      
      const existingItem = this.items.find(item => item.productId === productId)
      
      if (existingItem) {
        existingItem.quantity += quantity
      } else {
        this.items.push({ productId, quantity })
      }
    }
  }
})
```

### 8.2 共享 Store 逻辑

```typescript
// stores/composables/useLoading.ts
import { ref } from 'vue'

export function useLoading() {
  const loading = ref(false)
  const error = ref<string | null>(null)
  
  async function withLoading<T>(fn: () => Promise<T>): Promise<T> {
    loading.value = true
    error.value = null
    
    try {
      return await fn()
    } catch (e: any) {
      error.value = e.message
      throw e
    } finally {
      loading.value = false
    }
  }
  
  return { loading, error, withLoading }
}

// stores/user.ts
import { defineStore } from 'pinia'
import { useLoading } from './composables/useLoading'

export const useUserStore = defineStore('user', () => {
  const { loading, error, withLoading } = useLoading()
  
  const user = ref(null)
  
  async function fetchUser() {
    return withLoading(async () => {
      const response = await axios.get('/api/user')
      user.value = response.data
    })
  }
  
  return { user, loading, error, fetchUser }
})
```

---

## 9. 插件系统

### 9.1 创建插件

```typescript
// plugins/piniaLogger.ts
import { PiniaPluginContext } from 'pinia'

export function piniaLogger(context: PiniaPluginContext) {
  const { store } = context
  
  // 订阅 state 变化
  store.$subscribe((mutation, state) => {
    console.log(`[${store.$id}] State 变化:`, mutation.type)
    console.log('新状态:', state)
  })
  
  // 订阅 action
  store.$onAction(({ name, args }) => {
    console.log(`[${store.$id}] Action ${name} 被调用，参数:`, args)
  })
}

// main.ts
import { createPinia } from 'pinia'
import { piniaLogger } from './plugins/piniaLogger'

const pinia = createPinia()
pinia.use(piniaLogger)
```

### 9.2 扩展 Store


```typescript
// plugins/piniaReset.ts
import { PiniaPluginContext } from 'pinia'

export function piniaReset({ store }: PiniaPluginContext) {
  const initialState = JSON.parse(JSON.stringify(store.$state))
  
  // 添加自定义方法
  store.$reset = () => {
    store.$patch(initialState)
  }
}

// 使用
const pinia = createPinia()
pinia.use(piniaReset)
```

### 9.3 添加全局属性

```typescript
// plugins/piniaRouter.ts
import { PiniaPluginContext } from 'pinia'
import { Router } from 'vue-router'
import { markRaw } from 'vue'

declare module 'pinia' {
  export interface PiniaCustomProperties {
    router: Router
  }
}

export function piniaRouter(router: Router) {
  return ({ store }: PiniaPluginContext) => {
    store.router = markRaw(router)
  }
}

// main.ts
import router from './router'
pinia.use(piniaRouter(router))

// 在 store 中使用
export const useUserStore = defineStore('user', {
  actions: {
    logout() {
      this.user = null
      this.router.push('/login')  // 可以直接使用 router
    }
  }
})
```

---

## 10. 持久化存储

### 10.1 使用 pinia-plugin-persistedstate

```bash
npm install pinia-plugin-persistedstate
```

```typescript
// main.ts
import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'

const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)
```

### 10.2 配置持久化

```typescript
// stores/user.ts
export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    token: '',
    preferences: {
      theme: 'light',
      language: 'zh-CN'
    }
  }),
  
  // 启用持久化
  persist: true
})

// 自定义配置
export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    token: '',
    preferences: { theme: 'light' }
  }),
  
  persist: {
    key: 'my-user-store',           // 存储的 key
    storage: sessionStorage,         // 存储位置
    paths: ['token', 'preferences']  // 只持久化部分 state
  }
})
```

### 10.3 手动实现持久化

```typescript
// stores/user.ts
export const useUserStore = defineStore('user', {
  state: () => ({
    token: localStorage.getItem('token') || '',
    user: JSON.parse(localStorage.getItem('user') || 'null')
  }),
  
  actions: {
    setToken(token: string) {
      this.token = token
      localStorage.setItem('token', token)
    },
    
    setUser(user: any) {
      this.user = user
      localStorage.setItem('user', JSON.stringify(user))
    },
    
    clearAuth() {
      this.token = ''
      this.user = null
      localStorage.removeItem('token')
      localStorage.removeItem('user')
    }
  }
})
```

### 10.4 加密存储


```typescript
// utils/storage.ts
import CryptoJS from 'crypto-js'

const SECRET_KEY = 'your-secret-key'

export const secureStorage = {
  setItem(key: string, value: any) {
    const encrypted = CryptoJS.AES.encrypt(
      JSON.stringify(value),
      SECRET_KEY
    ).toString()
    localStorage.setItem(key, encrypted)
  },
  
  getItem(key: string) {
    const encrypted = localStorage.getItem(key)
    if (!encrypted) return null
    
    try {
      const decrypted = CryptoJS.AES.decrypt(encrypted, SECRET_KEY)
      return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8))
    } catch {
      return null
    }
  },
  
  removeItem(key: string) {
    localStorage.removeItem(key)
  }
}

// stores/user.ts
export const useUserStore = defineStore('user', {
  state: () => ({
    token: secureStorage.getItem('token') || ''
  }),
  
  persist: {
    storage: {
      getItem: (key) => secureStorage.getItem(key),
      setItem: (key, value) => secureStorage.setItem(key, value),
      removeItem: (key) => secureStorage.removeItem(key)
    }
  }
})
```

---

## 11. TypeScript 支持

### 11.1 类型定义

```typescript
// types/user.ts
export interface User {
  id: number
  username: string
  email: string
  avatar?: string
  role: 'admin' | 'user' | 'guest'
}

export interface UserState {
  user: User | null
  token: string
  isLoggedIn: boolean
  loading: boolean
  error: string | null
}

// stores/user.ts
import { defineStore } from 'pinia'
import type { User, UserState } from '@/types/user'

export const useUserStore = defineStore('user', {
  state: (): UserState => ({
    user: null,
    token: '',
    isLoggedIn: false,
    loading: false,
    error: null
  }),
  
  getters: {
    userRole: (state): string => {
      return state.user?.role || 'guest'
    },
    
    isAdmin(): boolean {
      return this.user?.role === 'admin'
    }
  },
  
  actions: {
    setUser(user: User): void {
      this.user = user
      this.isLoggedIn = true
    }
  }
})
```

### 11.2 Setup 风格的类型推断

```typescript
import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import type { User } from '@/types/user'

export const useUserStore = defineStore('user', () => {
  // 自动推断类型
  const user = ref<User | null>(null)
  const token = ref('')
  const loading = ref(false)
  
  // 自动推断返回类型
  const isLoggedIn = computed(() => !!user.value)
  const userRole = computed(() => user.value?.role || 'guest')
  
  // 显式指定参数类型
  function setUser(newUser: User): void {
    user.value = newUser
  }
  
  async function login(username: string, password: string): Promise<void> {
    loading.value = true
    try {
      // 登录逻辑
    } finally {
      loading.value = false
    }
  }
  
  return {
    user,
    token,
    loading,
    isLoggedIn,
    userRole,
    setUser,
    login
  }
})
```

### 11.3 扩展 Store 类型

```typescript
// types/pinia.d.ts
import 'pinia'
import type { Router } from 'vue-router'

declare module 'pinia' {
  export interface PiniaCustomProperties {
    router: Router
    $api: typeof import('@/api').default
  }
  
  export interface PiniaCustomStateProperties<S> {
    createdAt: Date
  }
}
```

---

## 12. DevTools 调试

### 12.1 启用 DevTools

```typescript
// main.ts
import { createPinia } from 'pinia'

const pinia = createPinia()

// 开发环境自动启用 DevTools
if (import.meta.env.DEV) {
  // Pinia 会自动连接到 Vue DevTools
}

app.use(pinia)
```

### 12.2 自定义 DevTools 标签

```typescript
export const useUserStore = defineStore('user', {
  state: () => ({
    user: null
  }),
  
  actions: {
    setUser(user: any) {
      this.user = user
      
      // 在 DevTools 中显示自定义事件
      this.$patch({
        user
      })
    }
  }
})
```

### 12.3 调试技巧

```typescript
const userStore = useUserStore()

// 查看当前 state
console.log(userStore.$state)

// 订阅 state 变化
userStore.$subscribe((mutation, state) => {
  console.log('State 变化:', mutation.type)
  console.log('新状态:', state)
})

// 订阅 action
userStore.$onAction(({ name, args, after, onError }) => {
  console.log(`Action ${name} 开始`)
  
  after((result) => {
    console.log(`Action ${name} 完成:`, result)
  })
  
  onError((error) => {
    console.error(`Action ${name} 失败:`, error)
  })
})
```

---

## 13. 最佳实践

### 13.1 Store 组织结构

```typescript
// ✅ 推荐: 按功能模块划分
stores/
├── user.ts          # 用户相关
├── auth.ts          # 认证相关
├── cart.ts          # 购物车
├── product.ts       # 商品
└── order.ts         # 订单

// ❌ 不推荐: 单一大 store
stores/
└── index.ts         # 所有状态都在一个文件
```

### 13.2 命名规范

```typescript
// ✅ Store 命名
export const useUserStore = defineStore('user', {})
export const useCartStore = defineStore('cart', {})

// ✅ State 命名
state: () => ({
  user: null,           // 单数
  products: [],         // 复数
  isLoading: false,     // 布尔值用 is/has 前缀
  hasError: false
})

// ✅ Action 命名
actions: {
  fetchUser() {},       // 获取数据用 fetch
  setUser() {},         // 设置数据用 set
  updateUser() {},      // 更新数据用 update
  deleteUser() {},      // 删除数据用 delete
  resetUser() {}        // 重置数据用 reset
}
```

### 13.3 状态设计原则


```typescript
// ✅ 推荐: 扁平化状态
state: () => ({
  userId: 1,
  userName: 'Alice',
  userEmail: 'alice@example.com'
})

// ❌ 不推荐: 过度嵌套
state: () => ({
  user: {
    info: {
      personal: {
        name: 'Alice'
      }
    }
  }
})

// ✅ 推荐: 合理分组
state: () => ({
  user: {
    id: 1,
    name: 'Alice',
    email: 'alice@example.com'
  },
  preferences: {
    theme: 'light',
    language: 'zh-CN'
  }
})
```

### 13.4 异步处理模式

```typescript
export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    loading: false,
    error: null as string | null
  }),
  
  actions: {
    // ✅ 推荐: 统一的错误处理
    async fetchUser(id: number) {
      this.loading = true
      this.error = null
      
      try {
        const response = await axios.get(`/api/users/${id}`)
        this.user = response.data
        return response.data
      } catch (error: any) {
        this.error = error.message
        throw error
      } finally {
        this.loading = false
      }
    },
    
    // ✅ 推荐: 乐观更新
    async updateUser(id: number, data: any) {
      const oldUser = this.user
      
      // 立即更新 UI
      this.user = { ...this.user, ...data }
      
      try {
        await axios.put(`/api/users/${id}`, data)
      } catch (error) {
        // 失败时回滚
        this.user = oldUser
        throw error
      }
    }
  }
})
```

### 13.5 避免直接修改 State

```typescript
// ❌ 错误: 在组件中直接修改
const userStore = useUserStore()
userStore.user.name = 'Bob'  // 不推荐

// ✅ 正确: 通过 action 修改
const userStore = useUserStore()
userStore.updateUserName('Bob')

// 或使用 $patch
userStore.$patch({
  user: { ...userStore.user, name: 'Bob' }
})
```

### 13.6 合理使用 Getters

```typescript
export const useProductStore = defineStore('product', {
  state: () => ({
    products: []
  }),
  
  getters: {
    // ✅ 推荐: 简单计算
    productCount: (state) => state.products.length,
    
    // ✅ 推荐: 过滤和映射
    activeProducts: (state) => {
      return state.products.filter(p => p.status === 'active')
    },
    
    // ❌ 不推荐: 复杂计算（应该在组件中使用 computed）
    complexCalculation: (state) => {
      // 大量计算...
    }
  }
})
```

### 13.7 Store 拆分策略

```typescript
// ✅ 推荐: 按业务领域拆分
// stores/user/profile.ts
export const useUserProfileStore = defineStore('userProfile', {})

// stores/user/settings.ts
export const useUserSettingsStore = defineStore('userSettings', {})

// stores/user/index.ts
export { useUserProfileStore } from './profile'
export { useUserSettingsStore } from './settings'

// ❌ 不推荐: 所有用户相关状态都在一个 store
export const useUserStore = defineStore('user', {
  state: () => ({
    profile: {},
    settings: {},
    orders: {},
    addresses: {},
    // ... 太多状态
  })
})
```

---

## 14. 性能优化

### 14.1 按需加载 Store

```typescript
// router/index.ts
const routes = [
  {
    path: '/admin',
    component: () => import('@/views/Admin.vue'),
    beforeEnter: async () => {
      // 只在需要时加载 admin store
      const { useAdminStore } = await import('@/stores/admin')
      const adminStore = useAdminStore()
      await adminStore.init()
    }
  }
]
```

### 14.2 避免不必要的响应式

```typescript
import { markRaw } from 'vue'

export const useDataStore = defineStore('data', {
  state: () => ({
    // ✅ 大型数据使用 markRaw
    largeData: markRaw([]),
    
    // ✅ 第三方库实例使用 markRaw
    chartInstance: markRaw(null)
  }),
  
  actions: {
    setChartInstance(instance: any) {
      this.chartInstance = markRaw(instance)
    }
  }
})
```

### 14.3 使用 shallowRef

```typescript
import { shallowRef } from 'vue'
import { defineStore } from 'pinia'

export const useDataStore = defineStore('data', () => {
  // 只追踪引用变化，不追踪内部属性
  const largeList = shallowRef<any[]>([])
  
  function updateList(newList: any[]) {
    largeList.value = newList
  }
  
  return { largeList, updateList }
})
```

### 14.4 批量更新优化

```typescript
// ❌ 慢: 多次触发响应式更新
userStore.firstName = 'John'
userStore.lastName = 'Doe'
userStore.age = 30
userStore.email = 'john@example.com'

// ✅ 快: 一次性更新
userStore.$patch({
  firstName: 'John',
  lastName: 'Doe',
  age: 30,
  email: 'john@example.com'
})
```

### 14.5 缓存计算结果

```typescript
export const useProductStore = defineStore('product', {
  state: () => ({
    products: [],
    categoryCache: new Map()
  }),
  
  getters: {
    getProductsByCategory: (state) => {
      return (category: string) => {
        // 使用缓存
        if (state.categoryCache.has(category)) {
          return state.categoryCache.get(category)
        }
        
        const result = state.products.filter(p => p.category === category)
        state.categoryCache.set(category, result)
        return result
      }
    }
  },
  
  actions: {
    addProduct(product: any) {
      this.products.push(product)
      // 清除缓存
      this.categoryCache.clear()
    }
  }
})
```

---

## 15. 常见错误与解决方案

### 15.1 解构丢失响应式


```typescript
// ❌ 错误: 直接解构失去响应式
const { count, doubleCount } = useCounterStore()
console.log(count)  // 不会响应变化

// ✅ 解决方案 1: 使用 storeToRefs
import { storeToRefs } from 'pinia'
const counterStore = useCounterStore()
const { count, doubleCount } = storeToRefs(counterStore)

// ✅ 解决方案 2: 不解构，直接使用
const counterStore = useCounterStore()
console.log(counterStore.count)
```

### 15.2 在 setup 外使用 Store

```typescript
// ❌ 错误: 在 setup 外使用
import { useUserStore } from '@/stores/user'
const userStore = useUserStore()  // 错误！pinia 还未安装

export default {
  setup() {
    // ...
  }
}

// ✅ 解决方案: 在 setup 内使用
export default {
  setup() {
    const userStore = useUserStore()  // 正确
    return { userStore }
  }
}

// ✅ 或在函数内使用
import { useUserStore } from '@/stores/user'

export function checkAuth() {
  const userStore = useUserStore()  // 正确
  return userStore.isLoggedIn
}
```

### 15.3 循环依赖问题

```typescript
// ❌ 错误: 循环依赖
// stores/user.ts
import { useCartStore } from './cart'
export const useUserStore = defineStore('user', {
  actions: {
    test() {
      const cartStore = useCartStore()  // 可能导致问题
    }
  }
})

// stores/cart.ts
import { useUserStore } from './user'
export const useCartStore = defineStore('cart', {
  actions: {
    test() {
      const userStore = useUserStore()  // 循环依赖
    }
  }
})

// ✅ 解决方案: 在函数内部导入
// stores/user.ts
export const useUserStore = defineStore('user', {
  actions: {
    test() {
      const { useCartStore } = await import('./cart')
      const cartStore = useCartStore()
    }
  }
})
```

### 15.4 State 初始化问题

```typescript
// ❌ 错误: 引用类型共享
export const useUserStore = defineStore('user', {
  state: () => {
    const defaultPreferences = { theme: 'light' }
    return {
      preferences: defaultPreferences  // 错误！
    }
  }
})

// ✅ 解决方案: 每次返回新对象
export const useUserStore = defineStore('user', {
  state: () => ({
    preferences: { theme: 'light' }  // 正确
  })
})
```

### 15.5 异步 Action 错误处理

```typescript
// ❌ 错误: 没有错误处理
export const useUserStore = defineStore('user', {
  actions: {
    async fetchUser() {
      const response = await axios.get('/api/user')
      this.user = response.data
      // 如果请求失败，会导致未捕获的错误
    }
  }
})

// ✅ 解决方案: 完整的错误处理
export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    loading: false,
    error: null
  }),
  
  actions: {
    async fetchUser() {
      this.loading = true
      this.error = null
      
      try {
        const response = await axios.get('/api/user')
        this.user = response.data
      } catch (error: any) {
        this.error = error.message
        console.error('获取用户失败:', error)
      } finally {
        this.loading = false
      }
    }
  }
})
```

### 15.6 忘记返回 Setup Store

```typescript
// ❌ 错误: 忘记返回
export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  
  function increment() {
    count.value++
  }
  
  // 忘记返回！
})

// ✅ 解决方案: 必须返回
export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  
  function increment() {
    count.value++
  }
  
  return { count, increment }  // 必须返回
})
```

### 15.7 $reset 在 Setup Store 中不可用

```typescript
// ❌ 错误: Setup Store 没有 $reset
export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  return { count }
})

const store = useCounterStore()
store.$reset()  // 错误！Setup Store 没有 $reset

// ✅ 解决方案: 手动实现 reset
export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  
  function $reset() {
    count.value = 0
  }
  
  return { count, $reset }
})
```

### 15.8 持久化后的类型问题

```typescript
// ❌ 错误: 从 localStorage 读取的数据类型不正确
export const useUserStore = defineStore('user', {
  state: () => ({
    loginTime: new Date()  // Date 对象
  }),
  
  persist: true
  // localStorage 会将 Date 转为字符串
})

// ✅ 解决方案: 序列化和反序列化
export const useUserStore = defineStore('user', {
  state: () => ({
    loginTime: new Date()
  }),
  
  persist: {
    serializer: {
      serialize: (state) => {
        return JSON.stringify({
          ...state,
          loginTime: state.loginTime.toISOString()
        })
      },
      deserialize: (value) => {
        const state = JSON.parse(value)
        return {
          ...state,
          loginTime: new Date(state.loginTime)
        }
      }
    }
  }
})
```

### 15.9 在 Getter 中修改 State

```typescript
// ❌ 错误: 在 getter 中修改 state
export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0,
    accessCount: 0
  }),
  
  getters: {
    doubleCount: (state) => {
      state.accessCount++  // 错误！不要在 getter 中修改 state
      return state.count * 2
    }
  }
})

// ✅ 解决方案: 使用 action
export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0,
    accessCount: 0
  }),
  
  getters: {
    doubleCount: (state) => state.count * 2
  },
  
  actions: {
    getDoubleCountAndTrack() {
      this.accessCount++
      return this.doubleCount
    }
  }
})
```

### 15.10 多个实例共享问题


```typescript
// ❌ 错误: SSR 中多个请求共享 store
// server.js
const pinia = createPinia()  // 所有请求共享同一个实例

app.use(pinia)

// ✅ 解决方案: 每个请求创建新实例
app.use((req, res, next) => {
  const pinia = createPinia()
  req.pinia = pinia
  next()
})
```

---

## 16. 迁移指南

### 16.1 从 Vuex 迁移

```typescript
// Vuex 3/4
export default {
  namespaced: true,
  
  state: {
    count: 0
  },
  
  mutations: {
    INCREMENT(state) {
      state.count++
    }
  },
  
  actions: {
    increment({ commit }) {
      commit('INCREMENT')
    }
  },
  
  getters: {
    doubleCount: state => state.count * 2
  }
}

// Pinia (Options API 风格)
export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0
  }),
  
  actions: {
    increment() {
      this.count++  // 无需 mutations
    }
  },
  
  getters: {
    doubleCount: (state) => state.count * 2
  }
})

// Pinia (Setup 风格)
export const useCounterStore = defineStore('counter', () => {
  const count = ref(0)
  const doubleCount = computed(() => count.value * 2)
  
  function increment() {
    count.value++
  }
  
  return { count, doubleCount, increment }
})
```

### 16.2 Vuex 模块迁移

```typescript
// Vuex 模块
// store/modules/user.js
export default {
  namespaced: true,
  state: { user: null },
  mutations: { SET_USER(state, user) { state.user = user } },
  actions: {
    setUser({ commit }, user) {
      commit('SET_USER', user)
    }
  }
}

// store/index.js
import user from './modules/user'
export default createStore({
  modules: { user }
})

// 使用
this.$store.dispatch('user/setUser', userData)

// Pinia
// stores/user.ts
export const useUserStore = defineStore('user', {
  state: () => ({ user: null }),
  actions: {
    setUser(user) {
      this.user = user
    }
  }
})

// 使用
const userStore = useUserStore()
userStore.setUser(userData)
```

### 16.3 辅助函数迁移

```typescript
// Vuex
import { mapState, mapActions } from 'vuex'

export default {
  computed: {
    ...mapState('user', ['user', 'isLoggedIn'])
  },
  methods: {
    ...mapActions('user', ['login', 'logout'])
  }
}

// Pinia
import { mapState, mapActions } from 'pinia'
import { useUserStore } from '@/stores/user'

export default {
  computed: {
    ...mapState(useUserStore, ['user', 'isLoggedIn'])
  },
  methods: {
    ...mapActions(useUserStore, ['login', 'logout'])
  }
}

// 或使用 Composition API (推荐)
import { useUserStore } from '@/stores/user'

const userStore = useUserStore()
const { user, isLoggedIn } = storeToRefs(userStore)
const { login, logout } = userStore
```

---

## 17. 实战示例

### 17.1 完整的用户认证 Store

```typescript
// stores/auth.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'
import router from '@/router'

interface User {
  id: number
  username: string
  email: string
  role: string
}

interface LoginParams {
  username: string
  password: string
}

export const useAuthStore = defineStore('auth', () => {
  // State
  const user = ref<User | null>(null)
  const token = ref(localStorage.getItem('token') || '')
  const loading = ref(false)
  const error = ref<string | null>(null)
  
  // Getters
  const isLoggedIn = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.role === 'admin')
  const userName = computed(() => user.value?.username || 'Guest')
  
  // Actions
  async function login(params: LoginParams) {
    loading.value = true
    error.value = null
    
    try {
      const response = await axios.post('/api/auth/login', params)
      const { user: userData, token: userToken } = response.data
      
      user.value = userData
      token.value = userToken
      
      // 保存到 localStorage
      localStorage.setItem('token', userToken)
      
      // 设置 axios 默认 header
      axios.defaults.headers.common['Authorization'] = `Bearer ${userToken}`
      
      // 跳转到首页
      router.push('/')
      
      return userData
    } catch (err: any) {
      error.value = err.response?.data?.message || '登录失败'
      throw err
    } finally {
      loading.value = false
    }
  }
  
  async function logout() {
    try {
      await axios.post('/api/auth/logout')
    } catch (err) {
      console.error('登出请求失败:', err)
    } finally {
      user.value = null
      token.value = ''
      localStorage.removeItem('token')
      delete axios.defaults.headers.common['Authorization']
      router.push('/login')
    }
  }
  
  async function fetchUserInfo() {
    if (!token.value) return
    
    try {
      const response = await axios.get('/api/auth/me')
      user.value = response.data
    } catch (err) {
      console.error('获取用户信息失败:', err)
      // Token 可能已过期，清除登录状态
      await logout()
    }
  }
  
  async function updateProfile(data: Partial<User>) {
    loading.value = true
    
    try {
      const response = await axios.put('/api/auth/profile', data)
      user.value = response.data
      return response.data
    } catch (err: any) {
      error.value = err.response?.data?.message || '更新失败'
      throw err
    } finally {
      loading.value = false
    }
  }
  
  function $reset() {
    user.value = null
    token.value = ''
    loading.value = false
    error.value = null
  }
  
  return {
    user,
    token,
    loading,
    error,
    isLoggedIn,
    isAdmin,
    userName,
    login,
    logout,
    fetchUserInfo,
    updateProfile,
    $reset
  }
}, {
  persist: {
    paths: ['token']  // 只持久化 token
  }
})
```

### 17.2 购物车 Store


```typescript
// stores/cart.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useAuthStore } from './auth'

interface CartItem {
  id: number
  productId: number
  name: string
  price: number
  quantity: number
  image: string
}

export const useCartStore = defineStore('cart', () => {
  const authStore = useAuthStore()
  
  // State
  const items = ref<CartItem[]>([])
  const loading = ref(false)
  
  // Getters
  const itemCount = computed(() => {
    return items.value.reduce((total, item) => total + item.quantity, 0)
  })
  
  const totalPrice = computed(() => {
    return items.value.reduce((total, item) => {
      return total + item.price * item.quantity
    }, 0)
  })
  
  const isEmpty = computed(() => items.value.length === 0)
  
  // Actions
  function addItem(product: Omit<CartItem, 'quantity'>) {
    const existingItem = items.value.find(item => item.productId === product.productId)
    
    if (existingItem) {
      existingItem.quantity++
    } else {
      items.value.push({ ...product, quantity: 1 })
    }
  }
  
  function removeItem(productId: number) {
    const index = items.value.findIndex(item => item.productId === productId)
    if (index > -1) {
      items.value.splice(index, 1)
    }
  }
  
  function updateQuantity(productId: number, quantity: number) {
    const item = items.value.find(item => item.productId === productId)
    if (item) {
      if (quantity <= 0) {
        removeItem(productId)
      } else {
        item.quantity = quantity
      }
    }
  }
  
  function clearCart() {
    items.value = []
  }
  
  async function checkout() {
    if (!authStore.isLoggedIn) {
      throw new Error('请先登录')
    }
    
    if (isEmpty.value) {
      throw new Error('购物车为空')
    }
    
    loading.value = true
    
    try {
      const response = await axios.post('/api/orders/checkout', {
        items: items.value
      })
      
      clearCart()
      return response.data
    } catch (error) {
      throw error
    } finally {
      loading.value = false
    }
  }
  
  return {
    items,
    loading,
    itemCount,
    totalPrice,
    isEmpty,
    addItem,
    removeItem,
    updateQuantity,
    clearCart,
    checkout
  }
}, {
  persist: true
})
```

### 17.3 通知 Store

```typescript
// stores/notification.ts
import { defineStore } from 'pinia'
import { ref } from 'vue'

interface Notification {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  message: string
  duration?: number
}

export const useNotificationStore = defineStore('notification', () => {
  const notifications = ref<Notification[]>([])
  
  function add(notification: Omit<Notification, 'id'>) {
    const id = Date.now().toString()
    const newNotification = { id, ...notification }
    
    notifications.value.push(newNotification)
    
    // 自动移除
    const duration = notification.duration || 3000
    setTimeout(() => {
      remove(id)
    }, duration)
    
    return id
  }
  
  function remove(id: string) {
    const index = notifications.value.findIndex(n => n.id === id)
    if (index > -1) {
      notifications.value.splice(index, 1)
    }
  }
  
  function success(message: string, duration?: number) {
    return add({ type: 'success', message, duration })
  }
  
  function error(message: string, duration?: number) {
    return add({ type: 'error', message, duration })
  }
  
  function warning(message: string, duration?: number) {
    return add({ type: 'warning', message, duration })
  }
  
  function info(message: string, duration?: number) {
    return add({ type: 'info', message, duration })
  }
  
  function clear() {
    notifications.value = []
  }
  
  return {
    notifications,
    add,
    remove,
    success,
    error,
    warning,
    info,
    clear
  }
})
```

### 17.4 主题 Store

```typescript
// stores/theme.ts
import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

type Theme = 'light' | 'dark' | 'auto'

export const useThemeStore = defineStore('theme', () => {
  const theme = ref<Theme>('auto')
  const systemTheme = ref<'light' | 'dark'>('light')
  
  // 监听系统主题变化
  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  
  function updateSystemTheme() {
    systemTheme.value = mediaQuery.matches ? 'dark' : 'light'
  }
  
  mediaQuery.addEventListener('change', updateSystemTheme)
  updateSystemTheme()
  
  // 应用主题
  function applyTheme() {
    const actualTheme = theme.value === 'auto' ? systemTheme.value : theme.value
    
    if (actualTheme === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }
  
  // 监听主题变化
  watch([theme, systemTheme], applyTheme, { immediate: true })
  
  function setTheme(newTheme: Theme) {
    theme.value = newTheme
  }
  
  function toggleTheme() {
    if (theme.value === 'light') {
      theme.value = 'dark'
    } else if (theme.value === 'dark') {
      theme.value = 'light'
    } else {
      theme.value = systemTheme.value === 'light' ? 'dark' : 'light'
    }
  }
  
  return {
    theme,
    systemTheme,
    setTheme,
    toggleTheme
  }
}, {
  persist: true
})
```

---

## 18. 测试

### 18.1 单元测试

```typescript
// stores/__tests__/counter.spec.ts
import { setActivePinia, createPinia } from 'pinia'
import { useCounterStore } from '../counter'
import { describe, it, expect, beforeEach } from 'vitest'

describe('Counter Store', () => {
  beforeEach(() => {
    // 每个测试前创建新的 pinia 实例
    setActivePinia(createPinia())
  })
  
  it('初始状态正确', () => {
    const store = useCounterStore()
    expect(store.count).toBe(0)
  })
  
  it('increment 增加计数', () => {
    const store = useCounterStore()
    store.increment()
    expect(store.count).toBe(1)
  })
  
  it('incrementBy 按指定数量增加', () => {
    const store = useCounterStore()
    store.incrementBy(5)
    expect(store.count).toBe(5)
  })
  
  it('doubleCount getter 正确计算', () => {
    const store = useCounterStore()
    store.count = 10
    expect(store.doubleCount).toBe(20)
  })
  
  it('$reset 重置状态', () => {
    const store = useCounterStore()
    store.count = 100
    store.$reset()
    expect(store.count).toBe(0)
  })
})
```

### 18.2 异步 Action 测试

```typescript
// stores/__tests__/user.spec.ts
import { setActivePinia, createPinia } from 'pinia'
import { useUserStore } from '../user'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import axios from 'axios'

vi.mock('axios')

describe('User Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })
  
  it('login 成功', async () => {
    const mockUser = { id: 1, username: 'test', email: 'test@example.com' }
    const mockToken = 'mock-token'
    
    vi.mocked(axios.post).mockResolvedValue({
      data: { user: mockUser, token: mockToken }
    })
    
    const store = useUserStore()
    await store.login({ username: 'test', password: '123456' })
    
    expect(store.user).toEqual(mockUser)
    expect(store.token).toBe(mockToken)
    expect(store.isLoggedIn).toBe(true)
  })
  
  it('login 失败处理错误', async () => {
    vi.mocked(axios.post).mockRejectedValue({
      response: { data: { message: '用户名或密码错误' } }
    })
    
    const store = useUserStore()
    
    await expect(
      store.login({ username: 'test', password: 'wrong' })
    ).rejects.toThrow()
    
    expect(store.error).toBe('用户名或密码错误')
    expect(store.isLoggedIn).toBe(false)
  })
})
```

---

## 总结

Pinia 是 Vue 3 生态中强大而优雅的状态管理解决方案，具有以下核心优势:

**核心特性:**
- ✅ 轻量级，仅约 1KB
- ✅ 完整的 TypeScript 支持
- ✅ 模块化设计，无需嵌套
- ✅ 支持 Composition API 和 Options API
- ✅ 完善的 DevTools 支持
- ✅ 可扩展的插件系统

**最佳实践要点:**
1. 使用 Setup 风格获得更好的类型推断
2. 通过 storeToRefs 解构保持响应式
3. 合理拆分 Store，按业务领域组织
4. 统一的异步错误处理模式
5. 使用插件实现持久化和日志
6. 避免在 Getter 中修改 State
7. 批量更新使用 $patch 优化性能

**常见陷阱:**
- ❌ 直接解构 Store 丢失响应式
- ❌ 在 setup 外使用 Store
- ❌ 循环依赖问题
- ❌ Setup Store 忘记返回
- ❌ 在 Getter 中修改 State

通过本笔记的学习，你应该能够:
- ✅ 熟练使用 Pinia 管理应用状态
- ✅ 编写类型安全的 Store
- ✅ 实现复杂的状态逻辑
- ✅ 优化性能和调试问题
- ✅ 从 Vuex 平滑迁移

继续学习建议:
1. 实践完整的项目案例
2. 探索 Pinia 插件生态
3. 学习 SSR 中的状态管理
4. 研究大型应用的状态架构设计

---

> 最后更新: 2024
> 适用版本: Pinia 2.x + Vue 3.x
> 官方文档: https://pinia.vuejs.org/
> 作者: Kiro AI Assistant
```
