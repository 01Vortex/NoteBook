> 单元测试是保证代码质量的重要手段，Vitest 和 Jest 是前端最流行的测试框架
> 本笔记基于 Vitest 1.x / Jest 29.x + Vue 3 + TypeScript

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [基础语法](#3-基础语法)
4. [断言匹配器](#4-断言匹配器)
5. [异步测试](#5-异步测试)
6. [Mock 模拟](#6-mock-模拟)
7. [测试 Vue 组件](#7-测试-vue-组件)
8. [测试 Pinia Store](#8-测试-pinia-store)
9. [测试 Composables](#9-测试-composables)
10. [测试覆盖率](#10-测试覆盖率)
11. [快照测试](#11-快照测试)
12. [测试钩子](#12-测试钩子)
13. [测试隔离](#13-测试隔离)
14. [最佳实践](#14-最佳实践)
15. [性能优化](#15-性能优化)
16. [常见错误与解决方案](#16-常见错误与解决方案)
17. [Vitest vs Jest](#17-vitest-vs-jest)

---

## 1. 基础概念

### 1.1 什么是单元测试？

单元测试是对软件中最小可测试单元进行检查和验证：

- **独立性**: 每个测试独立运行，互不影响
- **快速**: 测试执行速度快
- **可重复**: 多次运行结果一致
- **自动化**: 可自动执行和验证

### 1.2 为什么需要单元测试？

```typescript
// 1. 提前发现 bug
// 2. 重构时保证功能不变
// 3. 作为代码文档
// 4. 提高代码质量
// 5. 增强开发信心
```

### 1.3 测试金字塔

```
       /\
      /  \     E2E 测试（少量）
     /____\
    /      \   集成测试（适量）
   /________\
  /          \ 单元测试（大量）
 /____________\
```

### 1.4 Vitest vs Jest

| 特性 | Vitest | Jest |
|------|--------|------|
| 速度 | 极快（基于 Vite） | 较快 |
| 配置 | 简单（复用 Vite 配置） | 需要单独配置 |
| ESM 支持 | 原生支持 | 需要配置 |
| TypeScript | 开箱即用 | 需要 ts-jest |
| Vue 3 | 完美支持 | 需要额外配置 |
| 生态 | 较新 | 成熟 |

---

## 2. 环境搭建

### 2.1 安装 Vitest

```bash
# npm
npm install -D vitest @vitest/ui

# yarn
yarn add -D vitest @vitest/ui

# pnpm
pnpm add -D vitest @vitest/ui
```

### 2.2 配置 Vitest

```typescript
// vite.config.ts
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true,              // 全局 API
    environment: 'jsdom',       // 模拟浏览器环境
    setupFiles: './tests/setup.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html']
    }
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})
```

### 2.3 安装 Jest

```bash
npm install -D jest @types/jest ts-jest
npm install -D @vue/test-utils
```

### 2.4 配置 Jest

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy'
  },
  transform: {
    '^.+\\.vue$': '@vue/vue3-jest',
    '^.+\\.tsx?$': 'ts-jest'
  },
  collectCoverageFrom: [
    'src/**/*.{ts,tsx,vue}',
    '!src/**/*.d.ts'
  ]
}
```

### 2.5 package.json 脚本

```json
{
  "scripts": {
    "test": "vitest",
    "test:ui": "vitest --ui",
    "test:run": "vitest run",
    "test:coverage": "vitest --coverage"
  }
}
```

### 2.6 测试文件结构

```
src/
├── components/
│   ├── Button.vue
│   └── __tests__/
│       └── Button.spec.ts
├── utils/
│   ├── math.ts
│   └── __tests__/
│       └── math.spec.ts
└── stores/
    ├── user.ts
    └── __tests__/
        └── user.spec.ts
```

---

## 3. 基础语法

### 3.1 describe 和 test

```typescript
// 测试套件
describe('Math Utils', () => {
  // 单个测试用例
  test('adds 1 + 2 to equal 3', () => {
    expect(1 + 2).toBe(3)
  })
  
  // it 是 test 的别名
  it('subtracts 5 - 2 to equal 3', () => {
    expect(5 - 2).toBe(3)
  })
  
  // 嵌套测试套件
  describe('multiply', () => {
    test('multiplies 2 * 3 to equal 6', () => {
      expect(2 * 3).toBe(6)
    })
  })
})
```

### 3.2 跳过和仅运行

```typescript
// 跳过测试
test.skip('this test will be skipped', () => {
  expect(true).toBe(false)
})

// 仅运行此测试
test.only('only this test will run', () => {
  expect(true).toBe(true)
})

// 跳过整个套件
describe.skip('skipped suite', () => {
  test('will not run', () => {})
})

// 仅运行此套件
describe.only('only suite', () => {
  test('will run', () => {})
})
```

### 3.3 测试标记

```typescript
// 并发运行
test.concurrent('test 1', async () => {
  await someAsyncOperation()
})

test.concurrent('test 2', async () => {
  await anotherAsyncOperation()
})

// 待办测试
test.todo('implement this feature')
```

---

## 4. 断言匹配器

### 4.1 基础匹配器


```typescript
describe('Basic Matchers', () => {
  test('toBe - 严格相等（===）', () => {
    expect(2 + 2).toBe(4)
    expect('hello').toBe('hello')
  })
  
  test('toEqual - 深度相等', () => {
    const obj = { name: 'Alice', age: 25 }
    expect(obj).toEqual({ name: 'Alice', age: 25 })
  })
  
  test('not - 取反', () => {
    expect(1 + 1).not.toBe(3)
  })
  
  test('toBeTruthy / toBeFalsy', () => {
    expect(true).toBeTruthy()
    expect(1).toBeTruthy()
    expect('hello').toBeTruthy()
    
    expect(false).toBeFalsy()
    expect(0).toBeFalsy()
    expect('').toBeFalsy()
    expect(null).toBeFalsy()
    expect(undefined).toBeFalsy()
  })
  
  test('toBeNull / toBeUndefined / toBeDefined', () => {
    expect(null).toBeNull()
    expect(undefined).toBeUndefined()
    expect('value').toBeDefined()
  })
})
```

### 4.2 数字匹配器

```typescript
describe('Number Matchers', () => {
  test('toBeGreaterThan / toBeLessThan', () => {
    expect(10).toBeGreaterThan(5)
    expect(5).toBeLessThan(10)
  })
  
  test('toBeGreaterThanOrEqual / toBeLessThanOrEqual', () => {
    expect(10).toBeGreaterThanOrEqual(10)
    expect(5).toBeLessThanOrEqual(5)
  })
  
  test('toBeCloseTo - 浮点数比较', () => {
    expect(0.1 + 0.2).toBeCloseTo(0.3)
  })
})
```

### 4.3 字符串匹配器

```typescript
describe('String Matchers', () => {
  test('toMatch - 正则匹配', () => {
    expect('hello world').toMatch(/world/)
    expect('test@example.com').toMatch(/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/)
  })
  
  test('toContain - 包含子串', () => {
    expect('hello world').toContain('world')
  })
})
```

### 4.4 数组和对象匹配器

```typescript
describe('Array and Object Matchers', () => {
  test('toContain - 数组包含', () => {
    const arr = [1, 2, 3, 4, 5]
    expect(arr).toContain(3)
  })
  
  test('toHaveLength - 长度', () => {
    expect([1, 2, 3]).toHaveLength(3)
    expect('hello').toHaveLength(5)
  })
  
  test('toHaveProperty - 对象属性', () => {
    const obj = { name: 'Alice', age: 25 }
    expect(obj).toHaveProperty('name')
    expect(obj).toHaveProperty('name', 'Alice')
  })
  
  test('toMatchObject - 部分匹配', () => {
    const obj = { name: 'Alice', age: 25, city: 'NYC' }
    expect(obj).toMatchObject({ name: 'Alice', age: 25 })
  })
  
  test('arrayContaining - 数组包含', () => {
    expect([1, 2, 3, 4]).toEqual(expect.arrayContaining([2, 3]))
  })
  
  test('objectContaining - 对象包含', () => {
    const obj = { name: 'Alice', age: 25, city: 'NYC' }
    expect(obj).toEqual(expect.objectContaining({
      name: 'Alice',
      age: 25
    }))
  })
})
```

### 4.5 异常匹配器

```typescript
describe('Exception Matchers', () => {
  test('toThrow - 抛出异常', () => {
    function throwError() {
      throw new Error('Something went wrong')
    }
    
    expect(throwError).toThrow()
    expect(throwError).toThrow('Something went wrong')
    expect(throwError).toThrow(/wrong/)
  })
})
```

---

## 5. 异步测试

### 5.1 Promise 测试

```typescript
describe('Promise Tests', () => {
  test('resolves to value', () => {
    return expect(Promise.resolve('success')).resolves.toBe('success')
  })
  
  test('rejects with error', () => {
    return expect(Promise.reject('error')).rejects.toBe('error')
  })
  
  // 使用 async/await
  test('async/await - success', async () => {
    const data = await fetchData()
    expect(data).toBe('success')
  })
  
  test('async/await - error', async () => {
    await expect(fetchError()).rejects.toThrow('Error')
  })
})
```

### 5.2 回调函数测试

```typescript
describe('Callback Tests', () => {
  test('callback with done', (done) => {
    function callback(data: string) {
      try {
        expect(data).toBe('success')
        done()
      } catch (error) {
        done(error)
      }
    }
    
    fetchDataWithCallback(callback)
  })
})
```

### 5.3 定时器测试

```typescript
describe('Timer Tests', () => {
  beforeEach(() => {
    vi.useFakeTimers()  // Vitest
    // jest.useFakeTimers()  // Jest
  })
  
  afterEach(() => {
    vi.restoreAllMocks()
  })
  
  test('setTimeout', () => {
    const callback = vi.fn()
    
    setTimeout(callback, 1000)
    
    expect(callback).not.toHaveBeenCalled()
    
    vi.advanceTimersByTime(1000)
    
    expect(callback).toHaveBeenCalledTimes(1)
  })
  
  test('setInterval', () => {
    const callback = vi.fn()
    
    setInterval(callback, 1000)
    
    vi.advanceTimersByTime(3000)
    
    expect(callback).toHaveBeenCalledTimes(3)
  })
  
  test('runAllTimers', () => {
    const callback = vi.fn()
    
    setTimeout(callback, 1000)
    setTimeout(callback, 2000)
    
    vi.runAllTimers()
    
    expect(callback).toHaveBeenCalledTimes(2)
  })
})
```

---

## 6. Mock 模拟

### 6.1 Mock 函数

```typescript
describe('Mock Functions', () => {
  test('basic mock', () => {
    const mockFn = vi.fn()
    
    mockFn('hello')
    mockFn('world')
    
    expect(mockFn).toHaveBeenCalledTimes(2)
    expect(mockFn).toHaveBeenCalledWith('hello')
    expect(mockFn).toHaveBeenLastCalledWith('world')
  })
  
  test('mock return value', () => {
    const mockFn = vi.fn()
    mockFn.mockReturnValue(42)
    
    expect(mockFn()).toBe(42)
  })
  
  test('mock return value once', () => {
    const mockFn = vi.fn()
    mockFn
      .mockReturnValueOnce(1)
      .mockReturnValueOnce(2)
      .mockReturnValue(3)
    
    expect(mockFn()).toBe(1)
    expect(mockFn()).toBe(2)
    expect(mockFn()).toBe(3)
    expect(mockFn()).toBe(3)
  })
  
  test('mock implementation', () => {
    const mockFn = vi.fn((x: number) => x * 2)
    
    expect(mockFn(5)).toBe(10)
  })
  
  test('mock resolved value', async () => {
    const mockFn = vi.fn()
    mockFn.mockResolvedValue('success')
    
    await expect(mockFn()).resolves.toBe('success')
  })
  
  test('mock rejected value', async () => {
    const mockFn = vi.fn()
    mockFn.mockRejectedValue(new Error('failed'))
    
    await expect(mockFn()).rejects.toThrow('failed')
  })
})
```

### 6.2 Mock 模块

```typescript
// utils/api.ts
export async function fetchUser(id: number) {
  const response = await fetch(`/api/users/${id}`)
  return response.json()
}

// __tests__/api.spec.ts
import { vi, describe, test, expect } from 'vitest'
import { fetchUser } from '../api'

// Mock 整个模块
vi.mock('../api', () => ({
  fetchUser: vi.fn()
}))

describe('API Tests', () => {
  test('fetchUser', async () => {
    const mockUser = { id: 1, name: 'Alice' }
    
    vi.mocked(fetchUser).mockResolvedValue(mockUser)
    
    const user = await fetchUser(1)
    
    expect(user).toEqual(mockUser)
    expect(fetchUser).toHaveBeenCalledWith(1)
  })
})
```

### 6.3 部分 Mock

```typescript
// 只 mock 部分导出
vi.mock('../utils', async () => {
  const actual = await vi.importActual('../utils')
  return {
    ...actual,
    fetchData: vi.fn()
  }
})
```

### 6.4 Mock Axios

```typescript
import axios from 'axios'
import { vi } from 'vitest'

vi.mock('axios')

describe('Axios Mock', () => {
  test('get request', async () => {
    const mockData = { data: { id: 1, name: 'Alice' } }
    vi.mocked(axios.get).mockResolvedValue(mockData)
    
    const response = await axios.get('/api/users/1')
    
    expect(response.data).toEqual({ id: 1, name: 'Alice' })
    expect(axios.get).toHaveBeenCalledWith('/api/users/1')
  })
})
```

### 6.5 Spy 监听

```typescript
describe('Spy Tests', () => {
  test('spy on method', () => {
    const obj = {
      method: (x: number) => x * 2
    }
    
    const spy = vi.spyOn(obj, 'method')
    
    obj.method(5)
    
    expect(spy).toHaveBeenCalledWith(5)
    expect(spy).toHaveReturnedWith(10)
    
    spy.mockRestore()
  })
  
  test('spy on console', () => {
    const spy = vi.spyOn(console, 'log')
    
    console.log('hello')
    
    expect(spy).toHaveBeenCalledWith('hello')
    
    spy.mockRestore()
  })
})
```

---

## 7. 测试 Vue 组件

### 7.1 安装依赖

```bash
npm install -D @vue/test-utils @vitest/ui jsdom
```

### 7.2 基础组件测试


```vue
<!-- Button.vue -->
<template>
  <button 
    :class="['btn', `btn-${type}`]"
    :disabled="disabled"
    @click="handleClick"
  >
    <slot />
  </button>
</template>

<script setup lang="ts">
defineProps<{
  type?: 'primary' | 'secondary'
  disabled?: boolean
}>()

const emit = defineEmits<{
  click: [event: MouseEvent]
}>()

function handleClick(event: MouseEvent) {
  emit('click', event)
}
</script>
```

```typescript
// Button.spec.ts
import { describe, test, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import Button from '../Button.vue'

describe('Button Component', () => {
  test('renders slot content', () => {
    const wrapper = mount(Button, {
      slots: {
        default: 'Click Me'
      }
    })
    
    expect(wrapper.text()).toBe('Click Me')
  })
  
  test('applies type class', () => {
    const wrapper = mount(Button, {
      props: {
        type: 'primary'
      }
    })
    
    expect(wrapper.classes()).toContain('btn-primary')
  })
  
  test('disabled state', () => {
    const wrapper = mount(Button, {
      props: {
        disabled: true
      }
    })
    
    expect(wrapper.attributes('disabled')).toBeDefined()
  })
  
  test('emits click event', async () => {
    const wrapper = mount(Button)
    
    await wrapper.trigger('click')
    
    expect(wrapper.emitted()).toHaveProperty('click')
    expect(wrapper.emitted('click')).toHaveLength(1)
  })
  
  test('does not emit when disabled', async () => {
    const wrapper = mount(Button, {
      props: {
        disabled: true
      }
    })
    
    await wrapper.trigger('click')
    
    expect(wrapper.emitted('click')).toBeUndefined()
  })
})
```

### 7.3 测试 Props 和 Emits

```vue
<!-- Counter.vue -->
<template>
  <div>
    <p>Count: {{ count }}</p>
    <button @click="increment">+</button>
    <button @click="decrement">-</button>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{
  initialCount?: number
}>()

const emit = defineEmits<{
  change: [count: number]
}>()

const count = ref(props.initialCount || 0)

function increment() {
  count.value++
  emit('change', count.value)
}

function decrement() {
  count.value--
  emit('change', count.value)
}
</script>
```

```typescript
// Counter.spec.ts
import { mount } from '@vue/test-utils'
import Counter from '../Counter.vue'

describe('Counter Component', () => {
  test('initializes with default count', () => {
    const wrapper = mount(Counter)
    expect(wrapper.text()).toContain('Count: 0')
  })
  
  test('initializes with custom count', () => {
    const wrapper = mount(Counter, {
      props: {
        initialCount: 10
      }
    })
    expect(wrapper.text()).toContain('Count: 10')
  })
  
  test('increments count', async () => {
    const wrapper = mount(Counter)
    
    await wrapper.find('button').trigger('click')
    
    expect(wrapper.text()).toContain('Count: 1')
    expect(wrapper.emitted('change')?.[0]).toEqual([1])
  })
  
  test('decrements count', async () => {
    const wrapper = mount(Counter, {
      props: { initialCount: 5 }
    })
    
    await wrapper.findAll('button')[1].trigger('click')
    
    expect(wrapper.text()).toContain('Count: 4')
  })
})
```

### 7.4 测试异步组件

```vue
<!-- UserProfile.vue -->
<template>
  <div v-if="loading">Loading...</div>
  <div v-else-if="error">{{ error }}</div>
  <div v-else>
    <h1>{{ user?.name }}</h1>
    <p>{{ user?.email }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { fetchUser } from '@/api/user'

const props = defineProps<{
  userId: number
}>()

const user = ref(null)
const loading = ref(true)
const error = ref('')

onMounted(async () => {
  try {
    user.value = await fetchUser(props.userId)
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})
</script>
```

```typescript
// UserProfile.spec.ts
import { mount, flushPromises } from '@vue/test-utils'
import { vi } from 'vitest'
import UserProfile from '../UserProfile.vue'
import * as userApi from '@/api/user'

vi.mock('@/api/user')

describe('UserProfile Component', () => {
  test('shows loading state', () => {
    const wrapper = mount(UserProfile, {
      props: { userId: 1 }
    })
    
    expect(wrapper.text()).toContain('Loading...')
  })
  
  test('displays user data', async () => {
    const mockUser = { name: 'Alice', email: 'alice@example.com' }
    vi.mocked(userApi.fetchUser).mockResolvedValue(mockUser)
    
    const wrapper = mount(UserProfile, {
      props: { userId: 1 }
    })
    
    await flushPromises()
    
    expect(wrapper.text()).toContain('Alice')
    expect(wrapper.text()).toContain('alice@example.com')
  })
  
  test('displays error message', async () => {
    vi.mocked(userApi.fetchUser).mockRejectedValue(new Error('Failed to fetch'))
    
    const wrapper = mount(UserProfile, {
      props: { userId: 1 }
    })
    
    await flushPromises()
    
    expect(wrapper.text()).toContain('Failed to fetch')
  })
})
```

### 7.5 测试 Composables

```typescript
// useCounter.ts
import { ref, computed } from 'vue'

export function useCounter(initialValue = 0) {
  const count = ref(initialValue)
  const doubleCount = computed(() => count.value * 2)
  
  function increment() {
    count.value++
  }
  
  function decrement() {
    count.value--
  }
  
  function reset() {
    count.value = initialValue
  }
  
  return {
    count,
    doubleCount,
    increment,
    decrement,
    reset
  }
}
```

```typescript
// useCounter.spec.ts
import { describe, test, expect } from 'vitest'
import { useCounter } from '../useCounter'

describe('useCounter', () => {
  test('initializes with default value', () => {
    const { count } = useCounter()
    expect(count.value).toBe(0)
  })
  
  test('initializes with custom value', () => {
    const { count } = useCounter(10)
    expect(count.value).toBe(10)
  })
  
  test('increments count', () => {
    const { count, increment } = useCounter()
    increment()
    expect(count.value).toBe(1)
  })
  
  test('decrements count', () => {
    const { count, decrement } = useCounter(5)
    decrement()
    expect(count.value).toBe(4)
  })
  
  test('computes double count', () => {
    const { count, doubleCount, increment } = useCounter()
    increment()
    increment()
    expect(doubleCount.value).toBe(4)
  })
  
  test('resets to initial value', () => {
    const { count, increment, reset } = useCounter(10)
    increment()
    increment()
    reset()
    expect(count.value).toBe(10)
  })
})
```

---

## 8. 测试 Pinia Store

### 8.1 基础 Store 测试

```typescript
// stores/counter.ts
import { defineStore } from 'pinia'

export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0
  }),
  
  getters: {
    doubleCount: (state) => state.count * 2
  },
  
  actions: {
    increment() {
      this.count++
    },
    
    async incrementAsync() {
      await new Promise(resolve => setTimeout(resolve, 100))
      this.count++
    }
  }
})
```

```typescript
// stores/__tests__/counter.spec.ts
import { setActivePinia, createPinia } from 'pinia'
import { useCounterStore } from '../counter'

describe('Counter Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })
  
  test('initializes with default state', () => {
    const store = useCounterStore()
    expect(store.count).toBe(0)
  })
  
  test('increments count', () => {
    const store = useCounterStore()
    store.increment()
    expect(store.count).toBe(1)
  })
  
  test('computes double count', () => {
    const store = useCounterStore()
    store.count = 5
    expect(store.doubleCount).toBe(10)
  })
  
  test('increments asynchronously', async () => {
    const store = useCounterStore()
    await store.incrementAsync()
    expect(store.count).toBe(1)
  })
  
  test('resets state', () => {
    const store = useCounterStore()
    store.count = 10
    store.$reset()
    expect(store.count).toBe(0)
  })
})
```

### 8.2 测试 Store 组合

```typescript
// stores/user.ts
import { defineStore } from 'pinia'
import { useCartStore } from './cart'

export const useUserStore = defineStore('user', {
  state: () => ({
    user: null,
    isLoggedIn: false
  }),
  
  actions: {
    login(user: any) {
      this.user = user
      this.isLoggedIn = true
    },
    
    logout() {
      this.user = null
      this.isLoggedIn = false
      
      // 清空购物车
      const cartStore = useCartStore()
      cartStore.clear()
    }
  }
})
```

```typescript
// stores/__tests__/user.spec.ts
import { setActivePinia, createPinia } from 'pinia'
import { useUserStore } from '../user'
import { useCartStore } from '../cart'

describe('User Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })
  
  test('login sets user', () => {
    const store = useUserStore()
    const user = { id: 1, name: 'Alice' }
    
    store.login(user)
    
    expect(store.user).toEqual(user)
    expect(store.isLoggedIn).toBe(true)
  })
  
  test('logout clears cart', () => {
    const userStore = useUserStore()
    const cartStore = useCartStore()
    
    cartStore.addItem({ id: 1, name: 'Product' })
    userStore.logout()
    
    expect(cartStore.items).toHaveLength(0)
  })
})
```

---

## 9. 测试 Composables

### 9.1 测试带副作用的 Composable

```typescript
// useLocalStorage.ts
import { ref, watch } from 'vue'

export function useLocalStorage<T>(key: string, defaultValue: T) {
  const data = ref<T>(defaultValue)
  
  // 从 localStorage 读取
  const stored = localStorage.getItem(key)
  if (stored) {
    try {
      data.value = JSON.parse(stored)
    } catch (e) {
      console.error('Failed to parse localStorage value')
    }
  }
  
  // 监听变化并保存
  watch(data, (newValue) => {
    localStorage.setItem(key, JSON.stringify(newValue))
  }, { deep: true })
  
  return data
}
```

```typescript
// useLocalStorage.spec.ts
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { useLocalStorage } from '../useLocalStorage'

describe('useLocalStorage', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })
  
  test('initializes with default value', () => {
    const data = useLocalStorage('test', 'default')
    expect(data.value).toBe('default')
  })
  
  test('reads from localStorage', () => {
    localStorage.setItem('test', JSON.stringify('stored'))
    const data = useLocalStorage('test', 'default')
    expect(data.value).toBe('stored')
  })
  
  test('saves to localStorage on change', async () => {
    const data = useLocalStorage('test', 'initial')
    
    data.value = 'updated'
    
    await vi.waitFor(() => {
      expect(localStorage.getItem('test')).toBe(JSON.stringify('updated'))
    })
  })
})
```

---

## 10. 测试覆盖率

### 10.1 配置覆盖率

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'tests/',
        '**/*.spec.ts',
        '**/*.test.ts',
        '**/types.ts'
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80
      }
    }
  }
})
```

### 10.2 运行覆盖率

```bash
# 生成覆盖率报告
npm run test:coverage

# 查看 HTML 报告
open coverage/index.html
```

### 10.3 覆盖率指标

```typescript
// 行覆盖率 (Line Coverage): 代码行被执行的比例
// 函数覆盖率 (Function Coverage): 函数被调用的比例
// 分支覆盖率 (Branch Coverage): 条件分支被执行的比例
// 语句覆盖率 (Statement Coverage): 语句被执行的比例
```

---

## 11. 快照测试

### 11.1 基础快照

```typescript
import { mount } from '@vue/test-utils'
import Button from '../Button.vue'

describe('Button Snapshot', () => {
  test('matches snapshot', () => {
    const wrapper = mount(Button, {
      slots: {
        default: 'Click Me'
      }
    })
    
    expect(wrapper.html()).toMatchSnapshot()
  })
})
```

### 11.2 内联快照

```typescript
test('inline snapshot', () => {
  const data = { name: 'Alice', age: 25 }
  
  expect(data).toMatchInlineSnapshot(`
    {
      "age": 25,
      "name": "Alice",
    }
  `)
})
```

### 11.3 更新快照

```bash
# 更新所有快照
npm run test -- -u

# 交互式更新
npm run test -- --watch
# 按 u 更新快照
```

---

## 12. 测试钩子

### 12.1 生命周期钩子


```typescript
describe('Lifecycle Hooks', () => {
  // 所有测试前执行一次
  beforeAll(() => {
    console.log('Setup before all tests')
  })
  
  // 每个测试前执行
  beforeEach(() => {
    console.log('Setup before each test')
  })
  
  // 每个测试后执行
  afterEach(() => {
    console.log('Cleanup after each test')
  })
  
  // 所有测试后执行一次
  afterAll(() => {
    console.log('Cleanup after all tests')
  })
  
  test('test 1', () => {
    expect(true).toBe(true)
  })
  
  test('test 2', () => {
    expect(true).toBe(true)
  })
})
```

### 12.2 钩子作用域

```typescript
describe('Outer Suite', () => {
  beforeEach(() => {
    console.log('Outer beforeEach')
  })
  
  test('outer test', () => {})
  
  describe('Inner Suite', () => {
    beforeEach(() => {
      console.log('Inner beforeEach')
    })
    
    test('inner test', () => {
      // 执行顺序:
      // 1. Outer beforeEach
      // 2. Inner beforeEach
      // 3. test
    })
  })
})
```

---

## 13. 测试隔离

### 13.1 Mock 清理

```typescript
describe('Mock Cleanup', () => {
  afterEach(() => {
    vi.clearAllMocks()    // 清除调用记录
    vi.resetAllMocks()    // 重置实现
    vi.restoreAllMocks()  // 恢复原始实现
  })
  
  test('test 1', () => {
    const mockFn = vi.fn()
    mockFn()
    expect(mockFn).toHaveBeenCalledTimes(1)
  })
  
  test('test 2', () => {
    const mockFn = vi.fn()
    // 不会受 test 1 影响
    expect(mockFn).toHaveBeenCalledTimes(0)
  })
})
```

### 13.2 DOM 清理

```typescript
import { cleanup } from '@vue/test-utils'

describe('Component Tests', () => {
  afterEach(() => {
    cleanup()  // 清理挂载的组件
  })
  
  test('test 1', () => {
    const wrapper = mount(Component)
    // ...
  })
})
```

### 13.3 全局状态清理

```typescript
describe('Store Tests', () => {
  beforeEach(() => {
    setActivePinia(createPinia())  // 每次创建新的 Pinia 实例
  })
  
  test('test 1', () => {
    const store = useStore()
    store.count = 10
  })
  
  test('test 2', () => {
    const store = useStore()
    // count 是 0，不受 test 1 影响
    expect(store.count).toBe(0)
  })
})
```

---

## 14. 最佳实践

### 14.1 测试命名规范

```typescript
// ✅ 推荐: 描述性命名
describe('UserService', () => {
  describe('login', () => {
    test('should return user data when credentials are valid', () => {})
    test('should throw error when credentials are invalid', () => {})
    test('should save token to localStorage on success', () => {})
  })
})

// ❌ 不推荐: 模糊命名
describe('test', () => {
  test('test1', () => {})
  test('test2', () => {})
})
```

### 14.2 AAA 模式

```typescript
test('adds item to cart', () => {
  // Arrange (准备)
  const cart = new ShoppingCart()
  const item = { id: 1, name: 'Product', price: 100 }
  
  // Act (执行)
  cart.addItem(item)
  
  // Assert (断言)
  expect(cart.items).toHaveLength(1)
  expect(cart.total).toBe(100)
})
```

### 14.3 单一职责

```typescript
// ✅ 推荐: 每个测试只测一个功能点
test('increments count', () => {
  const counter = new Counter()
  counter.increment()
  expect(counter.value).toBe(1)
})

test('decrements count', () => {
  const counter = new Counter()
  counter.decrement()
  expect(counter.value).toBe(-1)
})

// ❌ 不推荐: 一个测试测多个功能
test('counter operations', () => {
  const counter = new Counter()
  counter.increment()
  expect(counter.value).toBe(1)
  counter.decrement()
  expect(counter.value).toBe(0)
  counter.reset()
  expect(counter.value).toBe(0)
})
```

### 14.4 避免测试实现细节

```typescript
// ❌ 不推荐: 测试实现细节
test('uses internal method', () => {
  const component = mount(Component)
  expect(component.vm.internalMethod).toBeDefined()
})

// ✅ 推荐: 测试行为和输出
test('displays correct result', () => {
  const component = mount(Component)
  expect(component.text()).toContain('Expected Result')
})
```

### 14.5 使用测试工具函数

```typescript
// tests/utils.ts
export function createMockUser(overrides = {}) {
  return {
    id: 1,
    name: 'Test User',
    email: 'test@example.com',
    ...overrides
  }
}

export function mountWithProviders(component: any, options = {}) {
  return mount(component, {
    global: {
      plugins: [createPinia()],
      stubs: {
        RouterLink: true
      }
    },
    ...options
  })
}

// 使用
test('displays user name', () => {
  const user = createMockUser({ name: 'Alice' })
  const wrapper = mountWithProviders(UserProfile, {
    props: { user }
  })
  expect(wrapper.text()).toContain('Alice')
})
```

### 14.6 测试边界条件

```typescript
describe('divide function', () => {
  test('divides positive numbers', () => {
    expect(divide(10, 2)).toBe(5)
  })
  
  test('divides negative numbers', () => {
    expect(divide(-10, 2)).toBe(-5)
  })
  
  test('handles zero dividend', () => {
    expect(divide(0, 5)).toBe(0)
  })
  
  test('throws error on division by zero', () => {
    expect(() => divide(10, 0)).toThrow('Division by zero')
  })
  
  test('handles decimal results', () => {
    expect(divide(10, 3)).toBeCloseTo(3.333, 2)
  })
})
```

---

## 15. 性能优化

### 15.1 并行测试

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    threads: true,        // 启用多线程
    isolate: true,        // 隔离测试环境
    maxThreads: 4,        // 最大线程数
    minThreads: 1         // 最小线程数
  }
})
```

### 15.2 测试分片

```bash
# 将测试分成 3 片，运行第 1 片
vitest --shard=1/3

# CI 环境中并行运行
# Job 1: vitest --shard=1/3
# Job 2: vitest --shard=2/3
# Job 3: vitest --shard=3/3
```

### 15.3 跳过慢速测试

```typescript
// 标记慢速测试
test('slow test', async () => {
  // 长时间运行的测试
}, 10000)  // 超时时间 10 秒

// 开发时跳过
test.skipIf(process.env.NODE_ENV === 'development')('slow integration test', () => {
  // ...
})
```

### 15.4 优化 Mock

```typescript
// ❌ 慢: 每次都创建新的 mock
beforeEach(() => {
  vi.mock('axios')
})

// ✅ 快: 在文件顶层 mock 一次
vi.mock('axios')

describe('tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()  // 只清除调用记录
  })
})
```

---

## 16. 常见错误与解决方案

### 16.1 异步测试未等待

```typescript
// ❌ 错误: 没有等待异步操作
test('fetches data', () => {
  fetchData().then(data => {
    expect(data).toBeDefined()  // 可能不会执行
  })
})

// ✅ 解决方案 1: 返回 Promise
test('fetches data', () => {
  return fetchData().then(data => {
    expect(data).toBeDefined()
  })
})

// ✅ 解决方案 2: 使用 async/await
test('fetches data', async () => {
  const data = await fetchData()
  expect(data).toBeDefined()
})

// ✅ 解决方案 3: 使用 resolves
test('fetches data', () => {
  return expect(fetchData()).resolves.toBeDefined()
})
```

### 16.2 组件更新未等待

```typescript
// ❌ 错误: 没有等待 DOM 更新
test('updates text', () => {
  const wrapper = mount(Component)
  wrapper.find('button').trigger('click')
  expect(wrapper.text()).toContain('Updated')  // 可能失败
})

// ✅ 解决方案: 使用 await
test('updates text', async () => {
  const wrapper = mount(Component)
  await wrapper.find('button').trigger('click')
  expect(wrapper.text()).toContain('Updated')
})
```

### 16.3 Mock 未清理

```typescript
// ❌ 错误: Mock 影响其他测试
test('test 1', () => {
  vi.spyOn(console, 'log')
  // ...
})

test('test 2', () => {
  console.log('test')
  // console.log 仍然被 spy
})

// ✅ 解决方案: 清理 Mock
afterEach(() => {
  vi.restoreAllMocks()
})
```

### 16.4 测试顺序依赖

```typescript
// ❌ 错误: 测试之间有依赖
let sharedState = 0

test('test 1', () => {
  sharedState = 10
  expect(sharedState).toBe(10)
})

test('test 2', () => {
  expect(sharedState).toBe(10)  // 依赖 test 1
})

// ✅ 解决方案: 每个测试独立
test('test 1', () => {
  const state = 10
  expect(state).toBe(10)
})

test('test 2', () => {
  const state = 10
  expect(state).toBe(10)
})
```

### 16.5 忘记 Mock 模块

```typescript
// ❌ 错误: 使用真实的 API 调用
test('fetches user', async () => {
  const user = await fetchUser(1)  // 真实的网络请求
  expect(user).toBeDefined()
})

// ✅ 解决方案: Mock API
vi.mock('@/api/user')

test('fetches user', async () => {
  vi.mocked(fetchUser).mockResolvedValue({ id: 1, name: 'Alice' })
  const user = await fetchUser(1)
  expect(user).toBeDefined()
})
```

### 16.6 测试超时

```typescript
// ❌ 错误: 测试超时
test('long running test', async () => {
  await veryLongOperation()  // 超过默认 5 秒
})

// ✅ 解决方案 1: 增加超时时间
test('long running test', async () => {
  await veryLongOperation()
}, 10000)  // 10 秒超时

// ✅ 解决方案 2: 使用 fake timers
test('long running test', () => {
  vi.useFakeTimers()
  const callback = vi.fn()
  
  setTimeout(callback, 10000)
  vi.advanceTimersByTime(10000)
  
  expect(callback).toHaveBeenCalled()
  vi.restoreAllMocks()
})
```

### 16.7 Pinia Store 未初始化

```typescript
// ❌ 错误: 没有设置 Pinia
test('uses store', () => {
  const store = useStore()  // 错误: Pinia 未初始化
})

// ✅ 解决方案
beforeEach(() => {
  setActivePinia(createPinia())
})

test('uses store', () => {
  const store = useStore()
  expect(store).toBeDefined()
})
```

### 16.8 快照过时

```typescript
// ❌ 问题: 快照与实际不符

// ✅ 解决方案: 更新快照
// npm run test -- -u

// 或者检查代码是否真的改变了
test('matches snapshot', () => {
  const wrapper = mount(Component)
  expect(wrapper.html()).toMatchSnapshot()
})
```

---

## 17. Vitest vs Jest

### 17.1 主要区别


```typescript
// Vitest
import { describe, test, expect, vi } from 'vitest'

// Jest
import { describe, test, expect, jest } from '@jest/globals'

// API 基本相同，主要区别:
// 1. Vitest 使用 vi，Jest 使用 jest
// 2. Vitest 原生支持 ESM
// 3. Vitest 配置更简单
// 4. Vitest 速度更快
```

### 17.2 迁移指南

```typescript
// Jest → Vitest 迁移步骤

// 1. 替换依赖
// npm uninstall jest @types/jest ts-jest
// npm install -D vitest @vitest/ui

// 2. 更新配置
// 删除 jest.config.js
// 在 vite.config.ts 中添加 test 配置

// 3. 替换 API
// jest.fn() → vi.fn()
// jest.mock() → vi.mock()
// jest.spyOn() → vi.spyOn()

// 4. 更新脚本
// "test": "jest" → "test": "vitest"
```

### 17.3 兼容性

```typescript
// Vitest 提供 Jest 兼容模式
// vitest.config.ts
export default defineConfig({
  test: {
    globals: true,  // 启用全局 API
    alias: {
      // 兼容 Jest 导入
      '@jest/globals': 'vitest'
    }
  }
})
```

---

## 18. 实战示例

### 18.1 完整的表单测试

```vue
<!-- LoginForm.vue -->
<template>
  <form @submit.prevent="handleSubmit">
    <div>
      <input 
        v-model="username" 
        type="text" 
        placeholder="用户名"
        data-testid="username-input"
      />
      <span v-if="errors.username" class="error">
        {{ errors.username }}
      </span>
    </div>
    
    <div>
      <input 
        v-model="password" 
        type="password" 
        placeholder="密码"
        data-testid="password-input"
      />
      <span v-if="errors.password" class="error">
        {{ errors.password }}
      </span>
    </div>
    
    <button 
      type="submit" 
      :disabled="loading"
      data-testid="submit-button"
    >
      {{ loading ? '登录中...' : '登录' }}
    </button>
    
    <div v-if="error" class="error">{{ error }}</div>
  </form>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useUserStore } from '@/stores/user'

const router = useRouter()
const userStore = useUserStore()

const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
const errors = ref<Record<string, string>>({})

function validate() {
  errors.value = {}
  
  if (!username.value) {
    errors.value.username = '请输入用户名'
  }
  
  if (!password.value) {
    errors.value.password = '请输入密码'
  } else if (password.value.length < 6) {
    errors.value.password = '密码至少6位'
  }
  
  return Object.keys(errors.value).length === 0
}

async function handleSubmit() {
  if (!validate()) return
  
  loading.value = true
  error.value = ''
  
  try {
    await userStore.login({
      username: username.value,
      password: password.value
    })
    router.push('/')
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}
</script>
```

```typescript
// LoginForm.spec.ts
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import LoginForm from '../LoginForm.vue'
import { useUserStore } from '@/stores/user'

const router = createRouter({
  history: createMemoryHistory(),
  routes: [
    { path: '/', component: { template: '<div>Home</div>' } },
    { path: '/login', component: LoginForm }
  ]
})

describe('LoginForm', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })
  
  function mountForm() {
    return mount(LoginForm, {
      global: {
        plugins: [router]
      }
    })
  }
  
  test('renders form fields', () => {
    const wrapper = mountForm()
    
    expect(wrapper.find('[data-testid="username-input"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="password-input"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="submit-button"]').exists()).toBe(true)
  })
  
  test('shows validation errors', async () => {
    const wrapper = mountForm()
    
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.text()).toContain('请输入用户名')
    expect(wrapper.text()).toContain('请输入密码')
  })
  
  test('validates password length', async () => {
    const wrapper = mountForm()
    
    await wrapper.find('[data-testid="username-input"]').setValue('user')
    await wrapper.find('[data-testid="password-input"]').setValue('123')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.text()).toContain('密码至少6位')
  })
  
  test('submits form with valid data', async () => {
    const wrapper = mountForm()
    const userStore = useUserStore()
    const loginSpy = vi.spyOn(userStore, 'login').mockResolvedValue()
    
    await wrapper.find('[data-testid="username-input"]').setValue('testuser')
    await wrapper.find('[data-testid="password-input"]').setValue('password123')
    await wrapper.find('form').trigger('submit')
    
    expect(loginSpy).toHaveBeenCalledWith({
      username: 'testuser',
      password: 'password123'
    })
  })
  
  test('shows loading state', async () => {
    const wrapper = mountForm()
    const userStore = useUserStore()
    
    vi.spyOn(userStore, 'login').mockImplementation(() => {
      return new Promise(resolve => setTimeout(resolve, 100))
    })
    
    await wrapper.find('[data-testid="username-input"]').setValue('user')
    await wrapper.find('[data-testid="password-input"]').setValue('password')
    
    const submitPromise = wrapper.find('form').trigger('submit')
    await flushPromises()
    
    expect(wrapper.find('[data-testid="submit-button"]').text()).toBe('登录中...')
    expect(wrapper.find('[data-testid="submit-button"]').attributes('disabled')).toBeDefined()
    
    await submitPromise
  })
  
  test('displays error message on failure', async () => {
    const wrapper = mountForm()
    const userStore = useUserStore()
    
    vi.spyOn(userStore, 'login').mockRejectedValue(new Error('用户名或密码错误'))
    
    await wrapper.find('[data-testid="username-input"]').setValue('user')
    await wrapper.find('[data-testid="password-input"]').setValue('wrong')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    
    expect(wrapper.text()).toContain('用户名或密码错误')
  })
  
  test('redirects to home on success', async () => {
    const wrapper = mountForm()
    const userStore = useUserStore()
    const pushSpy = vi.spyOn(router, 'push')
    
    vi.spyOn(userStore, 'login').mockResolvedValue()
    
    await wrapper.find('[data-testid="username-input"]').setValue('user')
    await wrapper.find('[data-testid="password-input"]').setValue('password')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    
    expect(pushSpy).toHaveBeenCalledWith('/')
  })
})
```

### 18.2 测试工具函数集合

```typescript
// tests/test-utils.ts
import { mount } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { createRouter, createMemoryHistory } from 'vue-router'
import type { ComponentMountingOptions } from '@vue/test-utils'

export function createTestPinia() {
  return createPinia()
}

export function createTestRouter(routes = []) {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div>Home</div>' } },
      ...routes
    ]
  })
}

export function mountWithPlugins(
  component: any,
  options: ComponentMountingOptions<any> = {}
) {
  const pinia = createTestPinia()
  const router = createTestRouter()
  
  return mount(component, {
    global: {
      plugins: [pinia, router],
      stubs: {
        Teleport: true,
        Transition: false
      },
      ...options.global
    },
    ...options
  })
}

export function createMockUser(overrides = {}) {
  return {
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
    role: 'user',
    ...overrides
  }
}

export async function waitForAsync() {
  return new Promise(resolve => setTimeout(resolve, 0))
}
```

---

## 总结

单元测试是保证代码质量的重要手段，掌握 Vitest/Jest 能够：

**核心优势：**
- ✅ 提前发现 bug，减少线上问题
- ✅ 重构时保证功能不变
- ✅ 作为代码文档，提高可维护性
- ✅ 提升开发信心和效率
- ✅ 强制思考代码设计

**最佳实践要点：**
1. 遵循 AAA 模式（Arrange-Act-Assert）
2. 每个测试只测一个功能点
3. 使用描述性的测试名称
4. 避免测试实现细节
5. 测试边界条件和异常情况
6. 保持测试独立性
7. 及时清理 Mock 和副作用

**常见陷阱：**
- ❌ 异步测试未等待
- ❌ 组件更新未等待
- ❌ Mock 未清理影响其他测试
- ❌ 测试之间有依赖关系
- ❌ 忘记 Mock 外部依赖
- ❌ 测试超时未处理

通过本笔记的学习，你应该能够：
- ✅ 熟练使用 Vitest/Jest 编写测试
- ✅ 测试 Vue 组件和 Composables
- ✅ 测试 Pinia Store
- ✅ 使用 Mock 模拟依赖
- ✅ 处理异步测试
- ✅ 生成测试覆盖率报告
- ✅ 避免常见测试错误

继续学习建议：
1. 实践 TDD（测试驱动开发）
2. 学习集成测试和 E2E 测试
3. 研究测试金字塔理论
4. 探索测试覆盖率优化策略

---

> 最后更新: 2024
> 适用版本: Vitest 1.x / Jest 29.x + Vue 3.x
> 官方文档: https://vitest.dev / https://jestjs.io
> 作者: Kiro AI Assistant
```
