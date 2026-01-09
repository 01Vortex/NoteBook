

> Vue 3 是一个用于构建用户界面的渐进式 JavaScript 框架
> 本笔记基于 Vue 3 + Composition API + TypeScript

---

## 目录

1. [基础概念](#1-基础概念)
2. [项目搭建](#2-项目搭建)
3. [模板语法](#3-模板语法)
4. [响应式基础](#4-响应式基础)
5. [计算属性与侦听器](#5-计算属性与侦听器)
6. [条件与列表渲染](#6-条件与列表渲染)
7. [事件处理](#7-事件处理)
8. [表单绑定](#8-表单绑定)
9. [组件基础](#9-组件基础)
10. [组件通信](#10-组件通信)
11. [生命周期](#11-生命周期)
12. [组合式函数](#12-组合式函数)
13. [路由管理](#13-路由管理)
14. [状态管理](#14-状态管理)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Vue？

Vue 是一个用于构建用户界面的渐进式框架。与其他大型框架不同，Vue 被设计为可以自底向上逐层应用。Vue 的核心库只关注视图层，便于与第三方库或既有项目整合。

**Vue 3 的主要特点：**
- **Composition API**：更灵活的代码组织方式，更好的逻辑复用
- **更好的 TypeScript 支持**：源码使用 TypeScript 重写
- **更小的包体积**：Tree-shaking 支持，按需引入
- **更快的渲染性能**：虚拟 DOM 重写，编译时优化
- **新的内置组件**：Fragment、Teleport、Suspense

### 1.2 Options API vs Composition API

Vue 3 提供了两种编写组件的方式：

```javascript
// ============ Options API（选项式 API） ============
// Vue 2 的传统写法，通过选项对象组织代码
export default {
  data() {
    return {
      count: 0
    }
  },
  computed: {
    doubleCount() {
      return this.count * 2
    }
  },
  methods: {
    increment() {
      this.count++
    }
  },
  mounted() {
    console.log('组件已挂载')
  }
}

// ============ Composition API（组合式 API） ============
// Vue 3 推荐的写法，通过函数组织代码
import { ref, computed, onMounted } from 'vue'

export default {
  setup() {
    const count = ref(0)
    
    const doubleCount = computed(() => count.value * 2)
    
    const increment = () => {
      count.value++
    }
    
    onMounted(() => {
      console.log('组件已挂载')
    })
    
    return { count, doubleCount, increment }
  }
}
```

**为什么推荐 Composition API？**
1. **更好的代码组织**：相关逻辑可以放在一起，而不是分散在不同选项中
2. **更好的逻辑复用**：可以轻松提取和复用逻辑（组合式函数）
3. **更好的类型推断**：对 TypeScript 更友好
4. **更小的生产包体积**：更好的 Tree-shaking

### 1.3 `<script setup>` 语法糖

Vue 3.2 引入的 `<script setup>` 是 Composition API 的语法糖，让代码更简洁：

```vue
<!-- 传统 Composition API -->
<script>
import { ref } from 'vue'

export default {
  setup() {
    const count = ref(0)
    const increment = () => count.value++
    return { count, increment }
  }
}
</script>

<!-- 使用 <script setup>（推荐） -->
<script setup>
import { ref } from 'vue'

const count = ref(0)
const increment = () => count.value++
// 不需要 return，顶层变量自动暴露给模板
</script>
```

---

## 2. 项目搭建

### 2.1 使用 Vite 创建项目（推荐）

```bash
# 使用 npm
npm create vite@latest my-vue-app -- --template vue

# 使用 yarn
yarn create vite my-vue-app --template vue

# 使用 pnpm
pnpm create vite my-vue-app --template vue

# 使用 TypeScript 模板
npm create vite@latest my-vue-app -- --template vue-ts

# 进入项目目录
cd my-vue-app

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

### 2.2 项目结构

```
my-vue-app/
├── node_modules/          # 依赖包
├── public/                # 静态资源（不会被编译）
│   └── favicon.ico
├── src/
│   ├── assets/           # 静态资源（会被编译）
│   ├── components/       # 组件
│   ├── views/            # 页面组件
│   ├── router/           # 路由配置
│   ├── stores/           # 状态管理（Pinia）
│   ├── composables/      # 组合式函数
│   ├── utils/            # 工具函数
│   ├── api/              # API 接口
│   ├── types/            # TypeScript 类型定义
│   ├── App.vue           # 根组件
│   └── main.ts           # 入口文件
├── index.html            # HTML 模板
├── package.json          # 项目配置
├── vite.config.ts        # Vite 配置
├── tsconfig.json         # TypeScript 配置
└── README.md
```

### 2.3 入口文件配置

```typescript
// src/main.ts
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'

// 引入全局样式
import './assets/main.css'

// 创建应用实例
const app = createApp(App)

// 使用插件
app.use(createPinia())  // 状态管理
app.use(router)         // 路由

// 全局配置
app.config.errorHandler = (err, vm, info) => {
  console.error('全局错误:', err, info)
}

// 全局属性
app.config.globalProperties.$http = axios

// 挂载应用
app.mount('#app')
```

### 2.4 Vite 配置

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  plugins: [vue()],
  
  // 路径别名
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@components': path.resolve(__dirname, 'src/components'),
    }
  },
  
  // 开发服务器配置
  server: {
    port: 3000,
    open: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  },
  
  // 构建配置
  build: {
    outDir: 'dist',
    sourcemap: true,
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      }
    }
  }
})
```

---

## 3. 模板语法

### 3.1 文本插值

```vue
<template>
  <!-- 双大括号插值（Mustache 语法） -->
  <p>消息: {{ message }}</p>
  
  <!-- 支持 JavaScript 表达式 -->
  <p>{{ message.split('').reverse().join('') }}</p>
  <p>{{ number + 1 }}</p>
  <p>{{ ok ? '是' : '否' }}</p>
  <p>{{ message.toUpperCase() }}</p>
  
  <!-- 只能是单个表达式，以下是错误的 -->
  <!-- {{ var a = 1 }} -->
  <!-- {{ if (ok) { return message } }} -->
  
  <!-- 原始 HTML（使用 v-html） -->
  <p v-html="rawHtml"></p>
  
  <!-- 一次性插值（不会响应式更新） -->
  <p v-once>这个值不会改变: {{ message }}</p>
</template>

<script setup>
import { ref } from 'vue'

const message = ref('Hello Vue!')
const number = ref(10)
const ok = ref(true)
const rawHtml = ref('<span style="color: red">红色文字</span>')
</script>
```

### 3.2 属性绑定

```vue
<template>
  <!-- v-bind 绑定属性 -->
  <div v-bind:id="dynamicId"></div>
  
  <!-- 简写形式（推荐） -->
  <div :id="dynamicId"></div>
  <img :src="imageUrl" :alt="imageAlt">
  <a :href="url">链接</a>
  
  <!-- 布尔属性 -->
  <button :disabled="isDisabled">按钮</button>
  
  <!-- 动态绑定多个属性 -->
  <div v-bind="objectOfAttrs"></div>
  
  <!-- 绑定 class -->
  <!-- 对象语法 -->
  <div :class="{ active: isActive, 'text-danger': hasError }"></div>
  
  <!-- 数组语法 -->
  <div :class="[activeClass, errorClass]"></div>
  
  <!-- 混合使用 -->
  <div :class="[{ active: isActive }, errorClass]"></div>
  
  <!-- 绑定 style -->
  <!-- 对象语法 -->
  <div :style="{ color: activeColor, fontSize: fontSize + 'px' }"></div>
  
  <!-- 绑定样式对象 -->
  <div :style="styleObject"></div>
  
  <!-- 数组语法（多个样式对象） -->
  <div :style="[baseStyles, overridingStyles]"></div>
</template>

<script setup>
import { ref, reactive } from 'vue'

const dynamicId = ref('my-id')
const imageUrl = ref('/images/logo.png')
const imageAlt = ref('Logo')
const url = ref('https://vuejs.org')
const isDisabled = ref(false)

// 动态绑定多个属性
const objectOfAttrs = reactive({
  id: 'container',
  class: 'wrapper',
  'data-index': 1
})

// class 绑定
const isActive = ref(true)
const hasError = ref(false)
const activeClass = ref('active')
const errorClass = ref('text-danger')

// style 绑定
const activeColor = ref('red')
const fontSize = ref(14)
const styleObject = reactive({
  color: 'blue',
  fontSize: '16px',
  fontWeight: 'bold'
})
</script>
```

### 3.3 指令

```vue
<template>
  <!-- v-if / v-else-if / v-else：条件渲染 -->
  <div v-if="type === 'A'">A</div>
  <div v-else-if="type === 'B'">B</div>
  <div v-else>其他</div>
  
  <!-- v-show：显示/隐藏（通过 CSS display） -->
  <div v-show="isVisible">可见内容</div>
  
  <!-- v-for：列表渲染 -->
  <ul>
    <li v-for="item in items" :key="item.id">{{ item.name }}</li>
  </ul>
  
  <!-- v-on：事件监听 -->
  <button v-on:click="handleClick">点击</button>
  <button @click="handleClick">点击（简写）</button>
  
  <!-- v-model：双向绑定 -->
  <input v-model="inputValue">
  
  <!-- v-text：设置文本内容 -->
  <span v-text="message"></span>
  
  <!-- v-html：设置 HTML 内容（注意 XSS 风险） -->
  <div v-html="htmlContent"></div>
  
  <!-- v-pre：跳过编译（显示原始 Mustache 标签） -->
  <span v-pre>{{ 这不会被编译 }}</span>
  
  <!-- v-cloak：隐藏未编译的模板 -->
  <div v-cloak>{{ message }}</div>
  
  <!-- v-memo：缓存模板（Vue 3.2+） -->
  <div v-memo="[valueA, valueB]">
    <!-- 只有当 valueA 或 valueB 变化时才重新渲染 -->
  </div>
</template>

<script setup>
import { ref } from 'vue'

const type = ref('A')
const isVisible = ref(true)
const items = ref([
  { id: 1, name: '项目1' },
  { id: 2, name: '项目2' }
])
const inputValue = ref('')
const message = ref('Hello')
const htmlContent = ref('<strong>加粗文字</strong>')

const handleClick = () => {
  console.log('按钮被点击')
}
</script>

<style>
/* v-cloak 配合使用 */
[v-cloak] {
  display: none;
}
</style>
```

---

## 4. 响应式基础

### 4.1 ref

`ref` 用于创建响应式的基本类型数据，也可以用于对象。

```vue
<template>
  <div>
    <p>计数: {{ count }}</p>
    <p>用户名: {{ user.name }}</p>
    <button @click="increment">+1</button>
  </div>
</template>

<script setup>
import { ref } from 'vue'

// 基本类型
const count = ref(0)
const message = ref('Hello')
const isActive = ref(true)

// 对象类型
const user = ref({
  name: '张三',
  age: 25
})

// 在 JS 中访问/修改需要 .value
const increment = () => {
  count.value++
  console.log(count.value)
}

// 修改对象属性
const updateUser = () => {
  user.value.name = '李四'
  // 或者替换整个对象
  user.value = { name: '王五', age: 30 }
}

// 在模板中自动解包，不需要 .value
// {{ count }} 而不是 {{ count.value }}
</script>
```

### 4.2 reactive

`reactive` 用于创建响应式的对象或数组，返回的是 Proxy 对象。

```vue
<template>
  <div>
    <p>姓名: {{ state.user.name }}</p>
    <p>年龄: {{ state.user.age }}</p>
    <ul>
      <li v-for="item in state.items" :key="item.id">{{ item.name }}</li>
    </ul>
  </div>
</template>

<script setup>
import { reactive } from 'vue'

// 创建响应式对象
const state = reactive({
  user: {
    name: '张三',
    age: 25
  },
  items: [
    { id: 1, name: '项目1' },
    { id: 2, name: '项目2' }
  ],
  count: 0
})

// 直接修改属性（不需要 .value）
const updateName = () => {
  state.user.name = '李四'
}

// 添加数组元素
const addItem = () => {
  state.items.push({ id: 3, name: '项目3' })
}

// ⚠️ 注意：不能直接替换整个 reactive 对象
// state = { ... }  // 错误！会失去响应性

// 正确做法：修改属性或使用 Object.assign
Object.assign(state, { count: 10 })
</script>
```

### 4.3 ref vs reactive

```vue
<script setup>
import { ref, reactive } from 'vue'

// ============ 使用 ref 的场景 ============
// 1. 基本类型
const count = ref(0)
const message = ref('Hello')

// 2. 需要替换整个对象
const user = ref({ name: '张三' })
user.value = { name: '李四' }  // 可以替换

// 3. 需要解构
const { value: countValue } = count  // 但会失去响应性

// ============ 使用 reactive 的场景 ============
// 1. 复杂对象/嵌套对象
const state = reactive({
  user: { name: '张三', age: 25 },
  settings: { theme: 'dark' }
})

// 2. 不需要替换整个对象
state.user.name = '李四'  // 直接修改

// ============ 推荐做法 ============
// 简单数据用 ref，复杂状态用 reactive
// 或者统一使用 ref（更一致）

// 使用 ref 管理复杂状态
const appState = ref({
  user: null,
  isLoading: false,
  error: null
})

// 修改时
appState.value.isLoading = true
appState.value.user = { name: '张三' }
</script>
```

### 4.4 toRef 和 toRefs

```vue
<script setup>
import { reactive, toRef, toRefs } from 'vue'

const state = reactive({
  name: '张三',
  age: 25,
  email: 'zhangsan@example.com'
})

// ============ toRef：创建单个属性的 ref ============
const nameRef = toRef(state, 'name')
// nameRef.value 和 state.name 是同步的

nameRef.value = '李四'
console.log(state.name)  // '李四'

// ============ toRefs：将整个对象转换为 refs ============
const { name, age, email } = toRefs(state)
// 现在 name, age, email 都是 ref

name.value = '王五'
console.log(state.name)  // '王五'

// ============ 常见用途：在组合式函数中返回响应式状态 ============
function useUser() {
  const user = reactive({
    name: '张三',
    age: 25
  })
  
  // 返回 toRefs，这样解构后仍保持响应性
  return toRefs(user)
}

// 使用时可以解构
const { name: userName, age: userAge } = useUser()
</script>
```

### 4.5 shallowRef 和 shallowReactive

```vue
<script setup>
import { shallowRef, shallowReactive, triggerRef } from 'vue'

// ============ shallowRef：只有 .value 是响应式的 ============
const shallowState = shallowRef({
  nested: {
    count: 0
  }
})

// 这不会触发更新
shallowState.value.nested.count++

// 需要替换整个 .value 才会触发更新
shallowState.value = { nested: { count: 1 } }

// 或者手动触发更新
shallowState.value.nested.count++
triggerRef(shallowState)

// ============ shallowReactive：只有根级属性是响应式的 ============
const shallowObj = shallowReactive({
  count: 0,
  nested: {
    value: 1
  }
})

// 这会触发更新
shallowObj.count++

// 这不会触发更新
shallowObj.nested.value++

// ============ 使用场景 ============
// 1. 大型数据结构，只需要监听顶层变化
// 2. 性能优化，避免深层响应式转换
</script>
```

### 4.6 readonly

```vue
<script setup>
import { ref, reactive, readonly } from 'vue'

const original = reactive({
  count: 0,
  user: {
    name: '张三'
  }
})

// 创建只读代理
const readonlyState = readonly(original)

// 尝试修改会在开发环境发出警告
// readonlyState.count++  // 警告：无法修改只读属性

// 原始对象修改会反映到只读代理
original.count++
console.log(readonlyState.count)  // 1

// ============ 使用场景 ============
// 1. 向子组件传递状态，防止子组件修改
// 2. 保护全局状态
</script>
```

---

## 5. 计算属性与侦听器

### 5.1 computed 计算属性

```vue
<template>
  <div>
    <p>原始消息: {{ message }}</p>
    <p>反转消息: {{ reversedMessage }}</p>
    <p>全名: {{ fullName }}</p>
    
    <input v-model="firstName" placeholder="名">
    <input v-model="lastName" placeholder="姓">
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const message = ref('Hello Vue')
const firstName = ref('三')
const lastName = ref('张')

// ============ 只读计算属性 ============
const reversedMessage = computed(() => {
  return message.value.split('').reverse().join('')
})

// ============ 可写计算属性 ============
const fullName = computed({
  get() {
    return lastName.value + firstName.value
  },
  set(newValue) {
    // 假设输入格式是 "姓名"
    lastName.value = newValue.charAt(0)
    firstName.value = newValue.slice(1)
  }
})

// 设置计算属性
fullName.value = '李四'  // lastName = '李', firstName = '四'

// ============ 计算属性 vs 方法 ============
// 计算属性：有缓存，依赖不变时不会重新计算
// 方法：每次调用都会执行

// 计算属性（推荐）
const computedValue = computed(() => {
  console.log('计算属性执行')
  return message.value.length
})

// 方法
const getLength = () => {
  console.log('方法执行')
  return message.value.length
}

// 在模板中多次使用：
// {{ computedValue }} {{ computedValue }}  // 只执行一次
// {{ getLength() }} {{ getLength() }}      // 执行两次
</script>
```

### 5.2 watch 侦听器

```vue
<script setup>
import { ref, reactive, watch } from 'vue'

const count = ref(0)
const message = ref('Hello')
const user = reactive({
  name: '张三',
  age: 25,
  address: {
    city: '北京'
  }
})

// ============ 侦听单个 ref ============
watch(count, (newValue, oldValue) => {
  console.log(`count 从 ${oldValue} 变为 ${newValue}`)
})

// ============ 侦听多个源 ============
watch([count, message], ([newCount, newMessage], [oldCount, oldMessage]) => {
  console.log(`count: ${oldCount} -> ${newCount}`)
  console.log(`message: ${oldMessage} -> ${newMessage}`)
})

// ============ 侦听 reactive 对象 ============
// 侦听整个对象（自动深度侦听）
watch(user, (newValue, oldValue) => {
  // 注意：newValue 和 oldValue 是同一个对象
  console.log('user 变化了', newValue)
})

// 侦听对象的某个属性（使用 getter 函数）
watch(
  () => user.name,
  (newName, oldName) => {
    console.log(`name 从 ${oldName} 变为 ${newName}`)
  }
)

// 侦听嵌套属性
watch(
  () => user.address.city,
  (newCity) => {
    console.log(`city 变为 ${newCity}`)
  }
)

// ============ 深度侦听 ============
watch(
  () => user.address,
  (newAddress) => {
    console.log('address 变化了', newAddress)
  },
  { deep: true }  // 深度侦听
)

// ============ 立即执行 ============
watch(
  count,
  (newValue) => {
    console.log(`当前值: ${newValue}`)
  },
  { immediate: true }  // 立即执行一次
)

// ============ 一次性侦听（Vue 3.4+） ============
watch(
  count,
  (newValue) => {
    console.log(`只触发一次: ${newValue}`)
  },
  { once: true }
)

// ============ 停止侦听 ============
const stopWatch = watch(count, (newValue) => {
  console.log(newValue)
  if (newValue > 10) {
    stopWatch()  // 停止侦听
  }
})

// ============ 清理副作用 ============
watch(count, (newValue, oldValue, onCleanup) => {
  const timer = setTimeout(() => {
    console.log('延迟操作')
  }, 1000)
  
  // 在下次回调执行前或侦听器停止时调用
  onCleanup(() => {
    clearTimeout(timer)
  })
})
</script>
```

### 5.3 watchEffect

```vue
<script setup>
import { ref, watchEffect, watchPostEffect, watchSyncEffect } from 'vue'

const count = ref(0)
const message = ref('Hello')

// ============ watchEffect：自动追踪依赖 ============
// 不需要指定侦听源，自动追踪回调中使用的响应式数据
watchEffect(() => {
  console.log(`count: ${count.value}, message: ${message.value}`)
  // 自动追踪 count 和 message
})

// ============ 与 watch 的区别 ============
// watch：
// - 需要明确指定侦听源
// - 可以获取新旧值
// - 默认懒执行（不立即执行）

// watchEffect：
// - 自动追踪依赖
// - 不能获取旧值
// - 立即执行

// ============ 执行时机 ============
// 默认在组件更新前执行
watchEffect(() => {
  console.log('默认：组件更新前执行')
})

// 在组件更新后执行（可以访问更新后的 DOM）
watchPostEffect(() => {
  console.log('组件更新后执行')
})

// 或者使用 flush 选项
watchEffect(
  () => {
    console.log('组件更新后执行')
  },
  { flush: 'post' }
)

// 同步执行（谨慎使用）
watchSyncEffect(() => {
  console.log('同步执行')
})

// ============ 停止侦听 ============
const stop = watchEffect(() => {
  console.log(count.value)
})

// 手动停止
stop()

// ============ 清理副作用 ============
watchEffect((onCleanup) => {
  const controller = new AbortController()
  
  fetch('/api/data', { signal: controller.signal })
    .then(res => res.json())
    .then(data => console.log(data))
  
  onCleanup(() => {
    controller.abort()  // 取消请求
  })
})
</script>
```

---

## 6. 条件与列表渲染

### 6.1 条件渲染

```vue
<template>
  <!-- ============ v-if / v-else-if / v-else ============ -->
  <!-- 真正的条件渲染，条件为假时元素不会被渲染到 DOM -->
  <div v-if="type === 'A'">类型 A</div>
  <div v-else-if="type === 'B'">类型 B</div>
  <div v-else-if="type === 'C'">类型 C</div>
  <div v-else>其他类型</div>
  
  <!-- 在 <template> 上使用 v-if（不会渲染额外元素） -->
  <template v-if="showDetails">
    <h1>标题</h1>
    <p>段落1</p>
    <p>段落2</p>
  </template>
  
  <!-- ============ v-show ============ -->
  <!-- 通过 CSS display 控制显示/隐藏，元素始终在 DOM 中 -->
  <div v-show="isVisible">可见内容</div>
  
  <!-- ============ v-if vs v-show ============ -->
  <!-- 
    v-if：
    - 真正的条件渲染
    - 切换时有更高的开销（创建/销毁）
    - 适合条件很少改变的场景
    
    v-show：
    - 只是 CSS 切换
    - 初始渲染开销较高
    - 适合频繁切换的场景
  -->
  
  <!-- 频繁切换用 v-show -->
  <div v-show="isTabActive">Tab 内容</div>
  
  <!-- 条件很少改变用 v-if -->
  <div v-if="isLoggedIn">用户信息</div>
  
  <!-- ============ v-if 和 v-for ============ -->
  <!-- ⚠️ 不推荐同时使用 v-if 和 v-for -->
  <!-- 错误示例 -->
  <!-- <li v-for="item in items" v-if="item.isActive">{{ item.name }}</li> -->
  
  <!-- 正确做法1：使用计算属性过滤 -->
  <li v-for="item in activeItems" :key="item.id">{{ item.name }}</li>
  
  <!-- 正确做法2：将 v-if 移到外层 -->
  <template v-if="shouldShowList">
    <li v-for="item in items" :key="item.id">{{ item.name }}</li>
  </template>
</template>

<script setup>
import { ref, computed } from 'vue'

const type = ref('A')
const showDetails = ref(true)
const isVisible = ref(true)
const isTabActive = ref(true)
const isLoggedIn = ref(false)
const shouldShowList = ref(true)

const items = ref([
  { id: 1, name: '项目1', isActive: true },
  { id: 2, name: '项目2', isActive: false },
  { id: 3, name: '项目3', isActive: true }
])

// 使用计算属性过滤
const activeItems = computed(() => {
  return items.value.filter(item => item.isActive)
})
</script>
```

### 6.2 列表渲染

```vue
<template>
  <!-- ============ 基本用法 ============ -->
  <!-- 遍历数组 -->
  <ul>
    <li v-for="item in items" :key="item.id">
      {{ item.name }}
    </li>
  </ul>
  
  <!-- 带索引 -->
  <ul>
    <li v-for="(item, index) in items" :key="item.id">
      {{ index }}. {{ item.name }}
    </li>
  </ul>
  
  <!-- 遍历对象 -->
  <ul>
    <li v-for="(value, key) in userInfo" :key="key">
      {{ key }}: {{ value }}
    </li>
  </ul>
  
  <!-- 带索引遍历对象 -->
  <ul>
    <li v-for="(value, key, index) in userInfo" :key="key">
      {{ index }}. {{ key }}: {{ value }}
    </li>
  </ul>
  
  <!-- 遍历数字范围 -->
  <span v-for="n in 10" :key="n">{{ n }} </span>
  <!-- 输出: 1 2 3 4 5 6 7 8 9 10 -->
  
  <!-- 在 <template> 上使用 v-for -->
  <template v-for="item in items" :key="item.id">
    <h3>{{ item.name }}</h3>
    <p>{{ item.description }}</p>
    <hr>
  </template>
  
  <!-- ============ key 的重要性 ============ -->
  <!-- 
    key 用于 Vue 的虚拟 DOM 算法，帮助识别节点
    - 必须是唯一的
    - 不要使用 index 作为 key（除非列表是静态的）
    - 使用稳定的唯一标识符（如 id）
  -->
  
  <!-- ❌ 错误：使用 index 作为 key -->
  <li v-for="(item, index) in items" :key="index">{{ item.name }}</li>
  
  <!-- ✅ 正确：使用唯一 id 作为 key -->
  <li v-for="item in items" :key="item.id">{{ item.name }}</li>
  
  <!-- ============ 组件上使用 v-for ============ -->
  <MyComponent
    v-for="item in items"
    :key="item.id"
    :item="item"
    @remove="removeItem(item.id)"
  />
</template>

<script setup>
import { ref, reactive } from 'vue'

const items = ref([
  { id: 1, name: '项目1', description: '描述1' },
  { id: 2, name: '项目2', description: '描述2' },
  { id: 3, name: '项目3', description: '描述3' }
])

const userInfo = reactive({
  name: '张三',
  age: 25,
  email: 'zhangsan@example.com'
})

// ============ 数组更新检测 ============
// 以下方法会触发视图更新
const addItem = () => {
  items.value.push({ id: 4, name: '项目4' })
}

const removeItem = (id) => {
  const index = items.value.findIndex(item => item.id === id)
  if (index > -1) {
    items.value.splice(index, 1)
  }
}

const updateItem = () => {
  // 直接修改数组元素
  items.value[0].name = '修改后的项目1'
  
  // 或者替换整个数组
  items.value = items.value.filter(item => item.id !== 2)
}

// 变更方法（会修改原数组）：
// push(), pop(), shift(), unshift(), splice(), sort(), reverse()

// 替换方法（返回新数组）：
// filter(), concat(), slice(), map()
</script>
```

---

## 7. 事件处理

### 7.1 事件监听

```vue
<template>
  <!-- ============ 基本用法 ============ -->
  <!-- 内联处理器 -->
  <button @click="count++">+1</button>
  
  <!-- 方法处理器 -->
  <button @click="increment">+1</button>
  
  <!-- 调用方法并传参 -->
  <button @click="greet('Hello')">打招呼</button>
  
  <!-- 访问原生事件对象 -->
  <button @click="handleClick">点击</button>
  
  <!-- 内联语句中访问事件对象 -->
  <button @click="handleClick($event)">点击</button>
  <button @click="(event) => handleClick(event)">点击</button>
  
  <!-- 传递参数和事件对象 -->
  <button @click="submitForm('form1', $event)">提交</button>
  
  <!-- ============ 事件修饰符 ============ -->
  <!-- .stop：阻止事件冒泡 -->
  <div @click="parentClick">
    <button @click.stop="childClick">点击不会冒泡</button>
  </div>
  
  <!-- .prevent：阻止默认行为 -->
  <form @submit.prevent="onSubmit">
    <button type="submit">提交</button>
  </form>
  <a href="https://vuejs.org" @click.prevent="handleLink">链接</a>
  
  <!-- .capture：使用捕获模式 -->
  <div @click.capture="handleCapture">捕获模式</div>
  
  <!-- .self：只有事件源是元素本身时才触发 -->
  <div @click.self="handleSelf">
    <button>点击按钮不会触发 div 的事件</button>
  </div>
  
  <!-- .once：只触发一次 -->
  <button @click.once="doOnce">只触发一次</button>
  
  <!-- .passive：提升滚动性能 -->
  <div @scroll.passive="onScroll">滚动区域</div>
  
  <!-- 修饰符可以链式调用 -->
  <a @click.stop.prevent="handleClick">链式修饰符</a>
  
  <!-- ============ 按键修饰符 ============ -->
  <!-- 按键别名 -->
  <input @keyup.enter="submit">
  <input @keyup.tab="handleTab">
  <input @keyup.delete="handleDelete">
  <input @keyup.esc="cancel">
  <input @keyup.space="handleSpace">
  <input @keyup.up="handleUp">
  <input @keyup.down="handleDown">
  <input @keyup.left="handleLeft">
  <input @keyup.right="handleRight">
  
  <!-- 系统修饰键 -->
  <input @keyup.ctrl.enter="submitWithCtrl">
  <input @keyup.alt.enter="submitWithAlt">
  <input @keyup.shift.enter="submitWithShift">
  <input @keyup.meta.enter="submitWithMeta">
  
  <!-- .exact：精确匹配 -->
  <button @click.ctrl.exact="onCtrlClick">仅 Ctrl + 点击</button>
  <button @click.exact="onClick">没有任何修饰键时点击</button>
  
  <!-- ============ 鼠标按键修饰符 ============ -->
  <button @click.left="handleLeftClick">左键点击</button>
  <button @click.right="handleRightClick">右键点击</button>
  <button @click.middle="handleMiddleClick">中键点击</button>
</template>

<script setup>
import { ref } from 'vue'

const count = ref(0)

const increment = () => {
  count.value++
}

const greet = (message) => {
  alert(message)
}

// 事件处理器会自动接收事件对象
const handleClick = (event) => {
  console.log('事件类型:', event.type)
  console.log('目标元素:', event.target)
  console.log('当前元素:', event.currentTarget)
}

const submitForm = (formId, event) => {
  console.log('表单ID:', formId)
  console.log('事件:', event)
}

const parentClick = () => console.log('父元素点击')
const childClick = () => console.log('子元素点击')

const onSubmit = () => {
  console.log('表单提交')
}

const handleLink = () => {
  console.log('链接点击，但不会跳转')
}

const submit = () => console.log('Enter 键提交')
const cancel = () => console.log('Esc 键取消')
</script>
```

### 7.2 自定义事件

```vue
<!-- 子组件 ChildComponent.vue -->
<template>
  <button @click="handleClick">点击触发事件</button>
  <button @click="handleSubmit">提交</button>
</template>

<script setup>
// 声明要触发的事件
const emit = defineEmits(['click', 'submit', 'update:modelValue'])

// 带验证的事件声明
const emit2 = defineEmits({
  // 无验证
  click: null,
  
  // 带验证函数
  submit: (payload) => {
    if (payload.email && payload.password) {
      return true
    }
    console.warn('无效的提交数据')
    return false
  }
})

const handleClick = () => {
  emit('click')
}

const handleSubmit = () => {
  emit('submit', {
    email: 'test@example.com',
    password: '123456'
  })
}

// 用于 v-model
const updateValue = (value) => {
  emit('update:modelValue', value)
}
</script>

<!-- 父组件 -->
<template>
  <ChildComponent
    @click="handleChildClick"
    @submit="handleChildSubmit"
  />
</template>

<script setup>
import ChildComponent from './ChildComponent.vue'

const handleChildClick = () => {
  console.log('子组件被点击')
}

const handleChildSubmit = (data) => {
  console.log('收到提交数据:', data)
}
</script>
```

---

## 8. 表单绑定

### 8.1 v-model 基础

```vue
<template>
  <!-- ============ 文本输入 ============ -->
  <input v-model="message" placeholder="输入消息">
  <p>消息: {{ message }}</p>
  
  <!-- ============ 多行文本 ============ -->
  <textarea v-model="content" placeholder="输入内容"></textarea>
  
  <!-- ============ 复选框 ============ -->
  <!-- 单个复选框（布尔值） -->
  <input type="checkbox" id="agree" v-model="isAgreed">
  <label for="agree">同意协议</label>
  <p>是否同意: {{ isAgreed }}</p>
  
  <!-- 多个复选框（数组） -->
  <input type="checkbox" id="jack" value="Jack" v-model="selectedNames">
  <label for="jack">Jack</label>
  <input type="checkbox" id="john" value="John" v-model="selectedNames">
  <label for="john">John</label>
  <input type="checkbox" id="mike" value="Mike" v-model="selectedNames">
  <label for="mike">Mike</label>
  <p>选中的名字: {{ selectedNames }}</p>
  
  <!-- ============ 单选按钮 ============ -->
  <input type="radio" id="male" value="male" v-model="gender">
  <label for="male">男</label>
  <input type="radio" id="female" value="female" v-model="gender">
  <label for="female">女</label>
  <p>性别: {{ gender }}</p>
  
  <!-- ============ 下拉选择 ============ -->
  <!-- 单选 -->
  <select v-model="selectedCity">
    <option disabled value="">请选择</option>
    <option value="beijing">北京</option>
    <option value="shanghai">上海</option>
    <option value="guangzhou">广州</option>
  </select>
  <p>选中的城市: {{ selectedCity }}</p>
  
  <!-- 多选 -->
  <select v-model="selectedCities" multiple>
    <option value="beijing">北京</option>
    <option value="shanghai">上海</option>
    <option value="guangzhou">广州</option>
  </select>
  <p>选中的城市: {{ selectedCities }}</p>
  
  <!-- 动态选项 -->
  <select v-model="selectedOption">
    <option v-for="option in options" :key="option.value" :value="option.value">
      {{ option.label }}
    </option>
  </select>
</template>

<script setup>
import { ref } from 'vue'

const message = ref('')
const content = ref('')
const isAgreed = ref(false)
const selectedNames = ref([])
const gender = ref('')
const selectedCity = ref('')
const selectedCities = ref([])
const selectedOption = ref('')

const options = ref([
  { value: 'a', label: '选项 A' },
  { value: 'b', label: '选项 B' },
  { value: 'c', label: '选项 C' }
])
</script>
```

### 8.2 v-model 修饰符

```vue
<template>
  <!-- ============ .lazy ============ -->
  <!-- 默认在 input 事件时同步，.lazy 改为在 change 事件时同步 -->
  <input v-model.lazy="lazyMessage">
  
  <!-- ============ .number ============ -->
  <!-- 自动将输入转换为数字 -->
  <input v-model.number="age" type="number">
  <p>类型: {{ typeof age }}</p>
  
  <!-- ============ .trim ============ -->
  <!-- 自动去除首尾空格 -->
  <input v-model.trim="trimmedMessage">
  
  <!-- 修饰符可以组合使用 -->
  <input v-model.lazy.trim="combinedMessage">
</template>

<script setup>
import { ref } from 'vue'

const lazyMessage = ref('')
const age = ref(0)
const trimmedMessage = ref('')
const combinedMessage = ref('')
</script>
```

### 8.3 组件上的 v-model

```vue
<!-- 子组件 CustomInput.vue -->
<template>
  <input
    :value="modelValue"
    @input="$emit('update:modelValue', $event.target.value)"
  >
</template>

<script setup>
defineProps(['modelValue'])
defineEmits(['update:modelValue'])
</script>

<!-- 或者使用 computed -->
<template>
  <input v-model="value">
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps(['modelValue'])
const emit = defineEmits(['update:modelValue'])

const value = computed({
  get() {
    return props.modelValue
  },
  set(value) {
    emit('update:modelValue', value)
  }
})
</script>

<!-- 父组件使用 -->
<template>
  <CustomInput v-model="searchText" />
  <!-- 等价于 -->
  <CustomInput
    :modelValue="searchText"
    @update:modelValue="searchText = $event"
  />
</template>

<!-- ============ 多个 v-model 绑定 ============ -->
<!-- 子组件 UserForm.vue -->
<template>
  <input
    :value="firstName"
    @input="$emit('update:firstName', $event.target.value)"
    placeholder="名"
  >
  <input
    :value="lastName"
    @input="$emit('update:lastName', $event.target.value)"
    placeholder="姓"
  >
</template>

<script setup>
defineProps(['firstName', 'lastName'])
defineEmits(['update:firstName', 'update:lastName'])
</script>

<!-- 父组件使用 -->
<template>
  <UserForm
    v-model:firstName="first"
    v-model:lastName="last"
  />
</template>

<!-- ============ 自定义 v-model 修饰符 ============ -->
<!-- 子组件 -->
<template>
  <input
    :value="modelValue"
    @input="handleInput"
  >
</template>

<script setup>
const props = defineProps({
  modelValue: String,
  modelModifiers: {
    default: () => ({})
  }
})

const emit = defineEmits(['update:modelValue'])

const handleInput = (e) => {
  let value = e.target.value
  
  // 检查是否有 capitalize 修饰符
  if (props.modelModifiers.capitalize) {
    value = value.charAt(0).toUpperCase() + value.slice(1)
  }
  
  emit('update:modelValue', value)
}
</script>

<!-- 父组件使用 -->
<template>
  <MyInput v-model.capitalize="text" />
</template>
```

---

## 9. 组件基础

### 9.1 组件定义与注册

```vue
<!-- ============ 单文件组件（SFC） ============ -->
<!-- MyButton.vue -->
<template>
  <button class="my-button" @click="handleClick">
    <slot>默认文本</slot>
  </button>
</template>

<script setup>
const emit = defineEmits(['click'])

const handleClick = () => {
  emit('click')
}
</script>

<style scoped>
.my-button {
  padding: 8px 16px;
  border-radius: 4px;
  background-color: #409eff;
  color: white;
  border: none;
  cursor: pointer;
}

.my-button:hover {
  background-color: #66b1ff;
}
</style>

<!-- ============ 使用组件 ============ -->
<!-- App.vue -->
<template>
  <!-- 在 <script setup> 中导入的组件自动注册 -->
  <MyButton @click="handleClick">点击我</MyButton>
  
  <!-- 组件名可以使用 PascalCase 或 kebab-case -->
  <my-button>另一个按钮</my-button>
</template>

<script setup>
import MyButton from './components/MyButton.vue'

const handleClick = () => {
  console.log('按钮被点击')
}
</script>

<!-- ============ 全局注册 ============ -->
<!-- main.ts -->
<script>
import { createApp } from 'vue'
import App from './App.vue'
import MyButton from './components/MyButton.vue'

const app = createApp(App)

// 全局注册组件
app.component('MyButton', MyButton)

// 批量全局注册
const components = import.meta.glob('./components/*.vue', { eager: true })
Object.entries(components).forEach(([path, module]) => {
  const name = path.match(/\/([^/]+)\.vue$/)[1]
  app.component(name, module.default)
})

app.mount('#app')
</script>
```

### 9.2 Props

```vue
<!-- 子组件 UserCard.vue -->
<template>
  <div class="user-card">
    <h3>{{ title }}</h3>
    <p>姓名: {{ name }}</p>
    <p>年龄: {{ age }}</p>
    <p>邮箱: {{ email }}</p>
    <p v-if="isAdmin">管理员</p>
    <ul>
      <li v-for="tag in tags" :key="tag">{{ tag }}</li>
    </ul>
  </div>
</template>

<script setup>
// ============ 基本声明 ============
// 数组形式（简单）
// const props = defineProps(['name', 'age', 'email'])

// ============ 对象形式（推荐） ============
const props = defineProps({
  // 基本类型检查
  name: String,
  
  // 多种类型
  age: [String, Number],
  
  // 必填
  email: {
    type: String,
    required: true
  },
  
  // 默认值
  title: {
    type: String,
    default: '用户信息'
  },
  
  // 对象/数组默认值必须使用工厂函数
  tags: {
    type: Array,
    default: () => []
  },
  
  // 自定义验证
  status: {
    type: String,
    validator: (value) => {
      return ['active', 'inactive', 'pending'].includes(value)
    }
  },
  
  // 布尔类型
  isAdmin: {
    type: Boolean,
    default: false
  }
})

// 访问 props
console.log(props.name)
</script>

<!-- ============ TypeScript 类型声明 ============ -->
<script setup lang="ts">
interface Props {
  name: string
  age?: number
  email: string
  title?: string
  tags?: string[]
  isAdmin?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  age: 0,
  title: '用户信息',
  tags: () => [],
  isAdmin: false
})
</script>

<!-- 父组件使用 -->
<template>
  <!-- 静态 prop -->
  <UserCard name="张三" email="zhangsan@example.com" />
  
  <!-- 动态 prop -->
  <UserCard
    :name="userName"
    :age="userAge"
    :email="userEmail"
    :tags="['VIP', '活跃']"
    is-admin
  />
  
  <!-- 传递对象的所有属性 -->
  <UserCard v-bind="userInfo" />
</template>

<script setup>
import { ref, reactive } from 'vue'
import UserCard from './UserCard.vue'

const userName = ref('李四')
const userAge = ref(25)
const userEmail = ref('lisi@example.com')

const userInfo = reactive({
  name: '王五',
  age: 30,
  email: 'wangwu@example.com'
})
</script>
```

### 9.3 Slots 插槽

```vue
<!-- 子组件 Card.vue -->
<template>
  <div class="card">
    <!-- ============ 默认插槽 ============ -->
    <div class="card-body">
      <slot>默认内容</slot>
    </div>
    
    <!-- ============ 具名插槽 ============ -->
    <div class="card-header">
      <slot name="header">默认标题</slot>
    </div>
    
    <div class="card-footer">
      <slot name="footer"></slot>
    </div>
    
    <!-- ============ 作用域插槽 ============ -->
    <div class="card-list">
      <slot name="item" v-for="item in items" :key="item.id" :item="item" :index="index">
        {{ item.name }}
      </slot>
    </div>
  </div>
</template>

<script setup>
defineProps({
  items: {
    type: Array,
    default: () => []
  }
})
</script>

<!-- 父组件使用 -->
<template>
  <Card :items="items">
    <!-- 默认插槽 -->
    <p>这是卡片内容</p>
    
    <!-- 具名插槽 -->
    <template #header>
      <h2>自定义标题</h2>
    </template>
    
    <!-- v-slot 的完整写法 -->
    <template v-slot:footer>
      <button>确定</button>
    </template>
    
    <!-- 作用域插槽 -->
    <template #item="{ item, index }">
      <div class="custom-item">
        {{ index + 1 }}. {{ item.name }} - {{ item.price }}
      </div>
    </template>
    
    <!-- 解构插槽 props -->
    <template #item="slotProps">
      <div>{{ slotProps.item.name }}</div>
    </template>
  </Card>
  
  <!-- ============ 动态插槽名 ============ -->
  <Card>
    <template #[dynamicSlotName]>
      动态插槽内容
    </template>
  </Card>
</template>

<script setup>
import { ref } from 'vue'
import Card from './Card.vue'

const items = ref([
  { id: 1, name: '商品1', price: 100 },
  { id: 2, name: '商品2', price: 200 }
])

const dynamicSlotName = ref('header')
</script>
```

---

## 10. 组件通信

### 10.1 Props / Emit（父子通信）

```vue
<!-- 父组件 -->
<template>
  <Child
    :message="parentMessage"
    :count="count"
    @update="handleUpdate"
    @increment="handleIncrement"
  />
</template>

<script setup>
import { ref } from 'vue'
import Child from './Child.vue'

const parentMessage = ref('来自父组件的消息')
const count = ref(0)

const handleUpdate = (newMessage) => {
  parentMessage.value = newMessage
}

const handleIncrement = (value) => {
  count.value += value
}
</script>

<!-- 子组件 Child.vue -->
<template>
  <div>
    <p>{{ message }}</p>
    <p>计数: {{ count }}</p>
    <button @click="updateMessage">更新消息</button>
    <button @click="increment">+1</button>
  </div>
</template>

<script setup>
const props = defineProps({
  message: String,
  count: Number
})

const emit = defineEmits(['update', 'increment'])

const updateMessage = () => {
  emit('update', '新消息')
}

const increment = () => {
  emit('increment', 1)
}
</script>
```

### 10.2 provide / inject（跨层级通信）

```vue
<!-- 祖先组件 -->
<template>
  <div>
    <h1>祖先组件</h1>
    <Parent />
  </div>
</template>

<script setup>
import { ref, provide, readonly } from 'vue'
import Parent from './Parent.vue'

// 提供响应式数据
const theme = ref('dark')
const user = ref({ name: '张三', age: 25 })

// 提供方法
const updateTheme = (newTheme) => {
  theme.value = newTheme
}

// 使用 provide 提供数据
provide('theme', theme)
provide('user', readonly(user))  // 只读，防止子组件修改
provide('updateTheme', updateTheme)

// 使用 Symbol 作为 key（推荐）
const themeKey = Symbol('theme')
provide(themeKey, theme)
</script>

<!-- 中间组件 Parent.vue -->
<template>
  <div>
    <h2>父组件（不需要接收数据）</h2>
    <Child />
  </div>
</template>

<script setup>
import Child from './Child.vue'
</script>

<!-- 后代组件 Child.vue -->
<template>
  <div>
    <h3>子组件</h3>
    <p>主题: {{ theme }}</p>
    <p>用户: {{ user.name }}</p>
    <button @click="changeTheme">切换主题</button>
  </div>
</template>

<script setup>
import { inject } from 'vue'

// 注入数据
const theme = inject('theme')
const user = inject('user')
const updateTheme = inject('updateTheme')

// 提供默认值
const message = inject('message', '默认消息')

// 使用工厂函数作为默认值
const config = inject('config', () => ({ debug: false }), true)

const changeTheme = () => {
  updateTheme(theme.value === 'dark' ? 'light' : 'dark')
}
</script>
```

### 10.3 模板引用（ref）

```vue
<template>
  <!-- DOM 元素引用 -->
  <input ref="inputRef" type="text">
  
  <!-- 组件引用 -->
  <ChildComponent ref="childRef" />
  
  <!-- v-for 中的引用（数组） -->
  <div v-for="item in items" :key="item.id" :ref="setItemRef">
    {{ item.name }}
  </div>
  
  <button @click="focusInput">聚焦输入框</button>
  <button @click="callChildMethod">调用子组件方法</button>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import ChildComponent from './ChildComponent.vue'

// DOM 引用
const inputRef = ref(null)

// 组件引用
const childRef = ref(null)

// v-for 引用
const itemRefs = ref([])
const setItemRef = (el) => {
  if (el) {
    itemRefs.value.push(el)
  }
}

const items = ref([
  { id: 1, name: '项目1' },
  { id: 2, name: '项目2' }
])

onMounted(() => {
  // 访问 DOM 元素
  console.log(inputRef.value)  // <input> 元素
  
  // 访问组件实例
  console.log(childRef.value)
})

const focusInput = () => {
  inputRef.value?.focus()
}

const callChildMethod = () => {
  childRef.value?.someMethod()
}
</script>

<!-- 子组件需要使用 defineExpose 暴露方法 -->
<!-- ChildComponent.vue -->
<script setup>
import { ref } from 'vue'

const count = ref(0)

const someMethod = () => {
  console.log('子组件方法被调用')
}

const increment = () => {
  count.value++
}

// 暴露给父组件
defineExpose({
  someMethod,
  increment,
  count
})
</script>
```

### 10.4 事件总线（mitt）

```typescript
// eventBus.ts
import mitt from 'mitt'

type Events = {
  'user-login': { userId: string; username: string }
  'user-logout': void
  'notification': string
}

export const emitter = mitt<Events>()

// 组件 A：发送事件
<script setup>
import { emitter } from '@/utils/eventBus'

const login = () => {
  emitter.emit('user-login', { userId: '123', username: '张三' })
}

const logout = () => {
  emitter.emit('user-logout')
}

const notify = () => {
  emitter.emit('notification', '这是一条通知')
}
</script>

// 组件 B：监听事件
<script setup>
import { onMounted, onUnmounted } from 'vue'
import { emitter } from '@/utils/eventBus'

const handleLogin = (data) => {
  console.log('用户登录:', data)
}

const handleNotification = (message) => {
  console.log('收到通知:', message)
}

onMounted(() => {
  emitter.on('user-login', handleLogin)
  emitter.on('notification', handleNotification)
})

onUnmounted(() => {
  // 移除监听器
  emitter.off('user-login', handleLogin)
  emitter.off('notification', handleNotification)
  
  // 或者移除所有监听器
  // emitter.all.clear()
})
</script>
```

---

## 11. 生命周期

### 11.1 生命周期钩子

```vue
<script setup>
import {
  onBeforeMount,
  onMounted,
  onBeforeUpdate,
  onUpdated,
  onBeforeUnmount,
  onUnmounted,
  onActivated,
  onDeactivated,
  onErrorCaptured
} from 'vue'

// ============ 挂载阶段 ============

// 组件挂载到 DOM 之前
onBeforeMount(() => {
  console.log('onBeforeMount: 组件即将挂载')
  // 此时还不能访问 DOM
})

// 组件挂载完成后
onMounted(() => {
  console.log('onMounted: 组件已挂载')
  // 可以访问 DOM
  // 适合：发起 API 请求、添加事件监听、操作 DOM
})

// ============ 更新阶段 ============

// 响应式数据变化，DOM 更新之前
onBeforeUpdate(() => {
  console.log('onBeforeUpdate: 数据已变化，DOM 即将更新')
})

// DOM 更新完成后
onUpdated(() => {
  console.log('onUpdated: DOM 已更新')
  // 注意：避免在此修改状态，可能导致无限循环
})

// ============ 卸载阶段 ============

// 组件卸载之前
onBeforeUnmount(() => {
  console.log('onBeforeUnmount: 组件即将卸载')
  // 适合：清理定时器、取消订阅、移除事件监听
})

// 组件卸载完成后
onUnmounted(() => {
  console.log('onUnmounted: 组件已卸载')
})

// ============ keep-alive 相关 ============

// 组件被激活时（从缓存中恢复）
onActivated(() => {
  console.log('onActivated: 组件被激活')
})

// 组件被停用时（进入缓存）
onDeactivated(() => {
  console.log('onDeactivated: 组件被停用')
})

// ============ 错误处理 ============

// 捕获后代组件的错误
onErrorCaptured((err, instance, info) => {
  console.error('捕获到错误:', err)
  console.log('错误组件:', instance)
  console.log('错误信息:', info)
  
  // 返回 false 阻止错误继续向上传播
  return false
})
</script>
```

### 11.2 生命周期图示

```
                    ┌─────────────────────────────────────┐
                    │           创建阶段                   │
                    │  setup() 在所有选项之前执行          │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │         onBeforeMount               │
                    │    组件即将挂载到 DOM                │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │           onMounted                 │
                    │    组件已挂载，可以访问 DOM          │
                    └─────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
        ┌───────────────────┐           ┌───────────────────┐
        │  onBeforeUpdate   │           │   onActivated     │
        │  数据变化，更新前  │           │  (keep-alive)     │
        └───────────────────┘           └───────────────────┘
                    │                               │
                    ▼                               ▼
        ┌───────────────────┐           ┌───────────────────┐
        │    onUpdated      │           │  onDeactivated    │
        │   DOM 已更新      │           │  (keep-alive)     │
        └───────────────────┘           └───────────────────┘
                    │
                    ▼
        ┌───────────────────────────────────────────────────┐
        │                 onBeforeUnmount                   │
        │                  组件即将卸载                      │
        └───────────────────────────────────────────────────┘
                                    │
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │                   onUnmounted                     │
        │                   组件已卸载                       │
        └───────────────────────────────────────────────────┘
```

### 11.3 实际应用示例

```vue
<template>
  <div>
    <p>计数: {{ count }}</p>
    <button @click="count++">+1</button>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, onBeforeUnmount } from 'vue'

const count = ref(0)

// ============ 发起 API 请求 ============
onMounted(async () => {
  try {
    const response = await fetch('/api/data')
    const data = await response.json()
    console.log('数据加载完成:', data)
  } catch (error) {
    console.error('数据加载失败:', error)
  }
})

// ============ 添加/移除事件监听 ============
const handleResize = () => {
  console.log('窗口大小:', window.innerWidth, window.innerHeight)
}

onMounted(() => {
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
})

// ============ 定时器清理 ============
let timer = null

onMounted(() => {
  timer = setInterval(() => {
    console.log('定时器执行')
  }, 1000)
})

onBeforeUnmount(() => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
})

// ============ 第三方库初始化/销毁 ============
let chartInstance = null

onMounted(() => {
  // 初始化图表
  // chartInstance = new Chart(...)
})

onUnmounted(() => {
  // 销毁图表
  if (chartInstance) {
    chartInstance.destroy()
    chartInstance = null
  }
})
</script>
```

---

## 12. 组合式函数

组合式函数（Composables）是 Vue 3 中复用有状态逻辑的主要方式。

### 12.1 基本示例

```typescript
// composables/useMouse.ts
import { ref, onMounted, onUnmounted } from 'vue'

export function useMouse() {
  const x = ref(0)
  const y = ref(0)

  const update = (event: MouseEvent) => {
    x.value = event.pageX
    y.value = event.pageY
  }

  onMounted(() => {
    window.addEventListener('mousemove', update)
  })

  onUnmounted(() => {
    window.removeEventListener('mousemove', update)
  })

  return { x, y }
}

// 使用
<template>
  <p>鼠标位置: {{ x }}, {{ y }}</p>
</template>

<script setup>
import { useMouse } from '@/composables/useMouse'

const { x, y } = useMouse()
</script>
```

### 12.2 常用组合式函数

```typescript
// ============ useCounter ============
// composables/useCounter.ts
import { ref, computed } from 'vue'

export function useCounter(initialValue = 0) {
  const count = ref(initialValue)
  
  const increment = () => count.value++
  const decrement = () => count.value--
  const reset = () => count.value = initialValue
  const double = computed(() => count.value * 2)
  
  return {
    count,
    increment,
    decrement,
    reset,
    double
  }
}

// ============ useFetch ============
// composables/useFetch.ts
import { ref, watchEffect, toValue } from 'vue'

export function useFetch<T>(url: string | Ref<string>) {
  const data = ref<T | null>(null)
  const error = ref<Error | null>(null)
  const isLoading = ref(false)

  const fetchData = async () => {
    isLoading.value = true
    error.value = null
    
    try {
      const response = await fetch(toValue(url))
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      data.value = await response.json()
    } catch (e) {
      error.value = e as Error
    } finally {
      isLoading.value = false
    }
  }

  // 如果 url 是响应式的，自动重新请求
  watchEffect(() => {
    fetchData()
  })

  return { data, error, isLoading, refetch: fetchData }
}

// 使用
<script setup>
import { useFetch } from '@/composables/useFetch'

const { data, error, isLoading } = useFetch('/api/users')
</script>

// ============ useLocalStorage ============
// composables/useLocalStorage.ts
import { ref, watch } from 'vue'

export function useLocalStorage<T>(key: string, defaultValue: T) {
  const storedValue = localStorage.getItem(key)
  const data = ref<T>(storedValue ? JSON.parse(storedValue) : defaultValue)

  watch(
    data,
    (newValue) => {
      localStorage.setItem(key, JSON.stringify(newValue))
    },
    { deep: true }
  )

  return data
}

// 使用
<script setup>
import { useLocalStorage } from '@/composables/useLocalStorage'

const theme = useLocalStorage('theme', 'light')
const user = useLocalStorage('user', { name: '', email: '' })
</script>

// ============ useDebounce ============
// composables/useDebounce.ts
import { ref, watch } from 'vue'

export function useDebounce<T>(value: Ref<T>, delay = 300) {
  const debouncedValue = ref(value.value) as Ref<T>
  let timer: ReturnType<typeof setTimeout>

  watch(value, (newValue) => {
    clearTimeout(timer)
    timer = setTimeout(() => {
      debouncedValue.value = newValue
    }, delay)
  })

  return debouncedValue
}

// 使用
<script setup>
import { ref } from 'vue'
import { useDebounce } from '@/composables/useDebounce'

const searchText = ref('')
const debouncedSearch = useDebounce(searchText, 500)

// debouncedSearch 会在 searchText 停止变化 500ms 后更新
</script>

// ============ useToggle ============
// composables/useToggle.ts
import { ref } from 'vue'

export function useToggle(initialValue = false) {
  const state = ref(initialValue)
  
  const toggle = () => {
    state.value = !state.value
  }
  
  const setTrue = () => {
    state.value = true
  }
  
  const setFalse = () => {
    state.value = false
  }
  
  return {
    state,
    toggle,
    setTrue,
    setFalse
  }
}

// ============ useClickOutside ============
// composables/useClickOutside.ts
import { onMounted, onUnmounted, Ref } from 'vue'

export function useClickOutside(
  elementRef: Ref<HTMLElement | null>,
  callback: () => void
) {
  const handler = (event: MouseEvent) => {
    if (elementRef.value && !elementRef.value.contains(event.target as Node)) {
      callback()
    }
  }

  onMounted(() => {
    document.addEventListener('click', handler)
  })

  onUnmounted(() => {
    document.removeEventListener('click', handler)
  })
}

// 使用
<template>
  <div ref="dropdownRef">
    <button @click="isOpen = !isOpen">打开下拉</button>
    <div v-if="isOpen">下拉内容</div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useClickOutside } from '@/composables/useClickOutside'

const dropdownRef = ref(null)
const isOpen = ref(false)

useClickOutside(dropdownRef, () => {
  isOpen.value = false
})
</script>
```

### 12.3 组合式函数最佳实践

```typescript
// ============ 命名约定 ============
// 以 "use" 开头
// useMouse, useFetch, useCounter

// ============ 返回值约定 ============
// 返回普通对象，包含 ref 和函数
// 不要返回单个 ref（不利于解构）

// 好的做法
export function useCounter() {
  const count = ref(0)
  return { count, increment, decrement }
}

// 不好的做法
export function useCounter() {
  return ref(0)  // 不利于扩展
}

// ============ 接收响应式参数 ============
import { toValue, MaybeRefOrGetter } from 'vue'

export function useFetch(url: MaybeRefOrGetter<string>) {
  watchEffect(() => {
    // toValue 会自动处理 ref、getter 和普通值
    fetch(toValue(url))
  })
}

// 可以传入不同类型的参数
useFetch('/api/users')           // 字符串
useFetch(urlRef)                 // ref
useFetch(() => `/api/users/${id.value}`)  // getter

// ============ 副作用清理 ============
export function useEventListener(
  target: EventTarget,
  event: string,
  callback: EventListener
) {
  onMounted(() => {
    target.addEventListener(event, callback)
  })
  
  onUnmounted(() => {
    target.removeEventListener(event, callback)
  })
}

// ============ 组合多个组合式函数 ============
export function useUserProfile(userId: Ref<string>) {
  const { data: user, isLoading: userLoading } = useFetch(
    () => `/api/users/${userId.value}`
  )
  
  const { data: posts, isLoading: postsLoading } = useFetch(
    () => `/api/users/${userId.value}/posts`
  )
  
  const isLoading = computed(() => userLoading.value || postsLoading.value)
  
  return {
    user,
    posts,
    isLoading
  }
}
```

---

## 13. 路由管理

### 13.1 Vue Router 基础配置

```typescript
// router/index.ts
import { createRouter, createWebHistory, RouteRecordRaw } from 'vue-router'

// 路由配置
const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'Home',
    component: () => import('@/views/Home.vue'),
    meta: { title: '首页', requiresAuth: false }
  },
  {
    path: '/about',
    name: 'About',
    component: () => import('@/views/About.vue'),
    meta: { title: '关于' }
  },
  {
    path: '/user/:id',
    name: 'User',
    component: () => import('@/views/User.vue'),
    props: true,  // 将路由参数作为 props 传递
    meta: { title: '用户详情', requiresAuth: true }
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: () => import('@/views/Dashboard.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'DashboardHome',
        component: () => import('@/views/dashboard/Home.vue')
      },
      {
        path: 'settings',
        name: 'DashboardSettings',
        component: () => import('@/views/dashboard/Settings.vue')
      }
    ]
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/Login.vue')
  },
  {
    // 重定向
    path: '/home',
    redirect: '/'
  },
  {
    // 别名
    path: '/users',
    alias: '/people',
    component: () => import('@/views/Users.vue')
  },
  {
    // 404 页面
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('@/views/NotFound.vue')
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) {
      return savedPosition
    } else {
      return { top: 0 }
    }
  }
})

// 全局前置守卫
router.beforeEach((to, from, next) => {
  // 设置页面标题
  document.title = to.meta.title as string || '默认标题'
  
  // 权限验证
  if (to.meta.requiresAuth) {
    const isAuthenticated = localStorage.getItem('token')
    if (!isAuthenticated) {
      next({ name: 'Login', query: { redirect: to.fullPath } })
      return
    }
  }
  
  next()
})

// 全局后置钩子
router.afterEach((to, from) => {
  // 可以用于分析、日志等
  console.log(`从 ${from.path} 导航到 ${to.path}`)
})

export default router
```

### 13.2 路由使用

```vue
<template>
  <div>
    <!-- ============ 声明式导航 ============ -->
    <router-link to="/">首页</router-link>
    <router-link :to="{ name: 'About' }">关于</router-link>
    <router-link :to="{ name: 'User', params: { id: 123 } }">用户</router-link>
    <router-link :to="{ path: '/search', query: { q: 'vue' } }">搜索</router-link>
    
    <!-- 自定义激活类名 -->
    <router-link to="/" active-class="active" exact-active-class="exact-active">
      首页
    </router-link>
    
    <!-- 替换历史记录（不能后退） -->
    <router-link to="/about" replace>关于</router-link>
    
    <!-- ============ 路由视图 ============ -->
    <router-view />
    
    <!-- 命名视图 -->
    <router-view name="sidebar" />
    <router-view name="main" />
    
    <!-- 带过渡动画 -->
    <router-view v-slot="{ Component }">
      <transition name="fade" mode="out-in">
        <component :is="Component" />
      </transition>
    </router-view>
    
    <!-- keep-alive 缓存 -->
    <router-view v-slot="{ Component }">
      <keep-alive>
        <component :is="Component" />
      </keep-alive>
    </router-view>
  </div>
</template>

<script setup>
import { useRouter, useRoute, onBeforeRouteLeave, onBeforeRouteUpdate } from 'vue-router'

const router = useRouter()
const route = useRoute()

// ============ 获取路由信息 ============
console.log('当前路径:', route.path)
console.log('路由参数:', route.params)
console.log('查询参数:', route.query)
console.log('路由名称:', route.name)
console.log('完整路径:', route.fullPath)
console.log('路由元信息:', route.meta)

// ============ 编程式导航 ============
const goToHome = () => {
  router.push('/')
}

const goToUser = (id: number) => {
  router.push({ name: 'User', params: { id } })
}

const goToSearch = (keyword: string) => {
  router.push({ path: '/search', query: { q: keyword } })
}

const goBack = () => {
  router.back()
  // 或 router.go(-1)
}

const goForward = () => {
  router.forward()
  // 或 router.go(1)
}

const replaceRoute = () => {
  router.replace('/about')
}

// ============ 组件内守卫 ============
// 路由离开前
onBeforeRouteLeave((to, from) => {
  const answer = window.confirm('确定要离开吗？未保存的更改将丢失。')
  if (!answer) return false
})

// 路由更新时（同一组件，参数变化）
onBeforeRouteUpdate((to, from) => {
  console.log('路由参数更新:', to.params)
})
</script>

<style>
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

### 13.3 路由参数响应式

```vue
<template>
  <div>
    <h1>用户: {{ userId }}</h1>
    <p>用户信息: {{ user }}</p>
  </div>
</template>

<script setup>
import { computed, watch } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()

// 方式1：使用 computed
const userId = computed(() => route.params.id)

// 方式2：使用 watch
watch(
  () => route.params.id,
  (newId) => {
    console.log('用户ID变化:', newId)
    // 重新获取用户数据
    fetchUser(newId)
  },
  { immediate: true }
)

// 方式3：使用 props（推荐）
// 在路由配置中设置 props: true
const props = defineProps<{
  id: string
}>()

const fetchUser = async (id: string) => {
  // 获取用户数据
}
</script>
```

---

## 14. 状态管理

### 14.1 Pinia 基础

```typescript
// stores/counter.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

// ============ 选项式写法 ============
export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0,
    name: 'Counter'
  }),
  
  getters: {
    doubleCount: (state) => state.count * 2,
    
    // 使用 this 访问其他 getter
    doubleCountPlusOne(): number {
      return this.doubleCount + 1
    }
  },
  
  actions: {
    increment() {
      this.count++
    },
    
    async fetchData() {
      const response = await fetch('/api/data')
      const data = await response.json()
      this.count = data.count
    }
  }
})

// ============ 组合式写法（推荐） ============
export const useCounterStore = defineStore('counter', () => {
  // state
  const count = ref(0)
  const name = ref('Counter')
  
  // getters
  const doubleCount = computed(() => count.value * 2)
  
  // actions
  const increment = () => {
    count.value++
  }
  
  const decrement = () => {
    count.value--
  }
  
  const reset = () => {
    count.value = 0
  }
  
  const incrementAsync = async () => {
    await new Promise(resolve => setTimeout(resolve, 1000))
    count.value++
  }
  
  return {
    count,
    name,
    doubleCount,
    increment,
    decrement,
    reset,
    incrementAsync
  }
})
```

### 14.2 在组件中使用

```vue
<template>
  <div>
    <p>计数: {{ counter.count }}</p>
    <p>双倍: {{ counter.doubleCount }}</p>
    <p>名称: {{ name }}</p>
    
    <button @click="counter.increment">+1</button>
    <button @click="counter.decrement">-1</button>
    <button @click="counter.reset">重置</button>
    <button @click="counter.incrementAsync">异步+1</button>
    
    <!-- 直接修改 state -->
    <button @click="counter.count++">直接+1</button>
  </div>
</template>

<script setup>
import { storeToRefs } from 'pinia'
import { useCounterStore } from '@/stores/counter'

const counter = useCounterStore()

// ============ 解构响应式状态 ============
// 错误：直接解构会失去响应性
// const { count, doubleCount } = counter

// 正确：使用 storeToRefs
const { count, name, doubleCount } = storeToRefs(counter)

// actions 可以直接解构
const { increment, decrement } = counter

// ============ 修改 state ============
// 方式1：直接修改
counter.count++

// 方式2：使用 $patch（批量修改）
counter.$patch({
  count: counter.count + 1,
  name: 'New Name'
})

// 方式3：使用 $patch 函数形式
counter.$patch((state) => {
  state.count++
  state.name = 'Updated'
})

// 方式4：替换整个 state
counter.$state = { count: 10, name: 'Reset' }

// ============ 重置 state ============
counter.$reset()

// ============ 订阅 state 变化 ============
counter.$subscribe((mutation, state) => {
  console.log('mutation type:', mutation.type)
  console.log('mutation storeId:', mutation.storeId)
  console.log('new state:', state)
  
  // 持久化到 localStorage
  localStorage.setItem('counter', JSON.stringify(state))
})

// ============ 订阅 actions ============
counter.$onAction(({
  name,      // action 名称
  store,     // store 实例
  args,      // 传递给 action 的参数
  after,     // action 成功后的钩子
  onError    // action 失败后的钩子
}) => {
  console.log(`Action ${name} 被调用，参数:`, args)
  
  after((result) => {
    console.log(`Action ${name} 完成，结果:`, result)
  })
  
  onError((error) => {
    console.error(`Action ${name} 失败:`, error)
  })
})
</script>
```

### 14.3 Store 之间的交互

```typescript
// stores/user.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useUserStore = defineStore('user', () => {
  const user = ref<User | null>(null)
  const token = ref<string | null>(null)
  
  const isLoggedIn = computed(() => !!token.value)
  
  const login = async (credentials: { username: string; password: string }) => {
    const response = await fetch('/api/login', {
      method: 'POST',
      body: JSON.stringify(credentials)
    })
    const data = await response.json()
    user.value = data.user
    token.value = data.token
  }
  
  const logout = () => {
    user.value = null
    token.value = null
  }
  
  return { user, token, isLoggedIn, login, logout }
})

// stores/cart.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { useUserStore } from './user'

export const useCartStore = defineStore('cart', () => {
  const items = ref<CartItem[]>([])
  
  // 使用其他 store
  const userStore = useUserStore()
  
  const totalPrice = computed(() => {
    return items.value.reduce((sum, item) => sum + item.price * item.quantity, 0)
  })
  
  const addItem = (item: CartItem) => {
    // 检查用户是否登录
    if (!userStore.isLoggedIn) {
      throw new Error('请先登录')
    }
    
    const existingItem = items.value.find(i => i.id === item.id)
    if (existingItem) {
      existingItem.quantity++
    } else {
      items.value.push({ ...item, quantity: 1 })
    }
  }
  
  const removeItem = (itemId: number) => {
    const index = items.value.findIndex(i => i.id === itemId)
    if (index > -1) {
      items.value.splice(index, 1)
    }
  }
  
  const clearCart = () => {
    items.value = []
  }
  
  return { items, totalPrice, addItem, removeItem, clearCart }
})
```

### 14.4 Pinia 持久化

```typescript
// 安装插件: npm install pinia-plugin-persistedstate

// main.ts
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'

const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)

const app = createApp(App)
app.use(pinia)
app.mount('#app')

// stores/user.ts
export const useUserStore = defineStore('user', () => {
  const token = ref<string | null>(null)
  const user = ref<User | null>(null)
  
  return { token, user }
}, {
  persist: true  // 启用持久化
})

// 自定义持久化配置
export const useSettingsStore = defineStore('settings', () => {
  const theme = ref('light')
  const language = ref('zh-CN')
  
  return { theme, language }
}, {
  persist: {
    key: 'app-settings',  // 存储的 key
    storage: localStorage,  // 存储方式
    paths: ['theme'],  // 只持久化指定字段
  }
})
```

---

## 15. 常见错误与解决方案

### 15.1 响应式相关错误

```vue
<script setup>
import { ref, reactive, toRefs } from 'vue'

// ============ 错误1：解构 reactive 对象失去响应性 ============
const state = reactive({ count: 0, name: '张三' })

// ❌ 错误：解构后失去响应性
const { count, name } = state
count++  // 不会触发更新

// ✅ 正确：使用 toRefs
const { count, name } = toRefs(state)
count.value++  // 会触发更新

// ============ 错误2：替换整个 reactive 对象 ============
let state2 = reactive({ count: 0 })

// ❌ 错误：替换整个对象会失去响应性
state2 = reactive({ count: 10 })

// ✅ 正确：修改属性或使用 ref
const state3 = ref({ count: 0 })
state3.value = { count: 10 }  // 可以替换

// 或者使用 Object.assign
Object.assign(state2, { count: 10 })

// ============ 错误3：忘记 .value ============
const count = ref(0)

// ❌ 错误：在 JS 中忘记 .value
count++  // 不会工作

// ✅ 正确
count.value++

// ============ 错误4：在模板中使用 .value ============
// ❌ 错误：模板中不需要 .value
// <p>{{ count.value }}</p>

// ✅ 正确：模板中自动解包
// <p>{{ count }}</p>

// ============ 错误5：异步操作中丢失响应性 ============
const user = ref(null)

// ❌ 可能的问题：在异步回调中
setTimeout(() => {
  // 确保使用 .value
  user.value = { name: '张三' }
}, 1000)
</script>
```

### 15.2 组件相关错误

```vue
<!-- ============ 错误1：Props 直接修改 ============ -->
<script setup>
const props = defineProps(['count'])

// ❌ 错误：直接修改 props
// props.count++  // 会报警告

// ✅ 正确：使用 emit 通知父组件修改
const emit = defineEmits(['update:count'])
const increment = () => {
  emit('update:count', props.count + 1)
}

// 或者使用本地副本
const localCount = ref(props.count)
</script>

<!-- ============ 错误2：v-for 没有 key ============ -->
<template>
  <!-- ❌ 错误：没有 key -->
  <li v-for="item in items">{{ item.name }}</li>
  
  <!-- ❌ 错误：使用 index 作为 key（列表会变化时） -->
  <li v-for="(item, index) in items" :key="index">{{ item.name }}</li>
  
  <!-- ✅ 正确：使用唯一标识符 -->
  <li v-for="item in items" :key="item.id">{{ item.name }}</li>
</template>

<!-- ============ 错误3：v-if 和 v-for 同时使用 ============ -->
<template>
  <!-- ❌ 错误：v-if 和 v-for 在同一元素上 -->
  <li v-for="item in items" v-if="item.isActive" :key="item.id">
    {{ item.name }}
  </li>
  
  <!-- ✅ 正确：使用计算属性过滤 -->
  <li v-for="item in activeItems" :key="item.id">
    {{ item.name }}
  </li>
  
  <!-- ✅ 正确：使用 template 包裹 -->
  <template v-for="item in items" :key="item.id">
    <li v-if="item.isActive">{{ item.name }}</li>
  </template>
</template>

<script setup>
import { computed } from 'vue'

const items = ref([...])
const activeItems = computed(() => items.value.filter(item => item.isActive))
</script>

<!-- ============ 错误4：组件未正确导入 ============ -->
<script setup>
// ❌ 错误：忘记导入组件
// <MyComponent />  // 会报错

// ✅ 正确：导入组件
import MyComponent from './MyComponent.vue'
</script>

<!-- ============ 错误5：异步组件加载失败 ============ -->
<script setup>
import { defineAsyncComponent } from 'vue'

// ✅ 带错误处理的异步组件
const AsyncComponent = defineAsyncComponent({
  loader: () => import('./HeavyComponent.vue'),
  loadingComponent: LoadingSpinner,
  errorComponent: ErrorDisplay,
  delay: 200,
  timeout: 3000
})
</script>
```

### 15.3 生命周期相关错误

```vue
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

// ============ 错误1：在 setup 外使用生命周期钩子 ============
// ❌ 错误：在异步回调中注册生命周期钩子
setTimeout(() => {
  onMounted(() => {})  // 不会工作
}, 0)

// ✅ 正确：在 setup 顶层同步注册
onMounted(() => {
  console.log('组件已挂载')
})

// ============ 错误2：忘记清理副作用 ============
let timer = null

// ❌ 错误：没有清理定时器
onMounted(() => {
  timer = setInterval(() => {
    console.log('tick')
  }, 1000)
})

// ✅ 正确：在 onUnmounted 中清理
onUnmounted(() => {
  if (timer) {
    clearInterval(timer)
  }
})

// ============ 错误3：在 onMounted 前访问 DOM ============
const inputRef = ref(null)

// ❌ 错误：setup 阶段 DOM 还不存在
// console.log(inputRef.value)  // null

// ✅ 正确：在 onMounted 中访问
onMounted(() => {
  console.log(inputRef.value)  // DOM 元素
  inputRef.value?.focus()
})
</script>
```

### 15.4 路由相关错误

```vue
<script setup>
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()

// ============ 错误1：在 setup 外使用 useRouter ============
// ❌ 错误：在异步回调中调用
// setTimeout(() => {
//   const router = useRouter()  // 可能不工作
// }, 0)

// ✅ 正确：在 setup 顶层调用
const router = useRouter()

// ============ 错误2：路由参数不响应 ============
// ❌ 错误：直接使用，不会响应参数变化
const userId = route.params.id

// ✅ 正确：使用 computed 或 watch
const userId = computed(() => route.params.id)

watch(
  () => route.params.id,
  (newId) => {
    fetchUser(newId)
  },
  { immediate: true }
)

// ============ 错误3：导航守卫中忘记调用 next ============
// 在 Vue Router 4 中，next 是可选的
// 但如果使用了 next，必须确保调用

// ✅ 推荐：不使用 next，直接返回
router.beforeEach((to, from) => {
  if (to.meta.requiresAuth && !isAuthenticated()) {
    return { name: 'Login' }
  }
  // 不返回或返回 true 表示允许导航
})
</script>
```

### 15.5 TypeScript 相关错误

```vue
<script setup lang="ts">
import { ref, PropType } from 'vue'

// ============ 错误1：Props 类型定义错误 ============
interface User {
  id: number
  name: string
}

// ❌ 错误：使用 PropType 但类型不匹配
// const props = defineProps({
//   user: Object as PropType<string>  // 类型不匹配
// })

// ✅ 正确
const props = defineProps<{
  user: User
  count?: number
}>()

// ============ 错误2：ref 类型推断问题 ============
// ❌ 可能的问题：类型推断为 never
const items = ref([])  // Ref<never[]>

// ✅ 正确：显式指定类型
const items = ref<User[]>([])

// ============ 错误3：事件类型定义 ============
// ✅ 正确的事件类型定义
const emit = defineEmits<{
  (e: 'update', value: string): void
  (e: 'delete', id: number): void
}>()

// 或者使用对象语法
const emit = defineEmits<{
  update: [value: string]
  delete: [id: number]
}>()

// ============ 错误4：模板引用类型 ============
// ❌ 错误：类型不正确
const inputRef = ref(null)

// ✅ 正确
const inputRef = ref<HTMLInputElement | null>(null)
const componentRef = ref<InstanceType<typeof MyComponent> | null>(null)
</script>
```

### 15.6 性能相关问题

```vue
<script setup>
import { ref, computed, shallowRef, markRaw } from 'vue'

// ============ 问题1：大型列表性能 ============
// ❌ 问题：大型列表全部响应式
const bigList = ref(Array(10000).fill(null).map((_, i) => ({ id: i, name: `Item ${i}` })))

// ✅ 优化：使用 shallowRef
const bigList = shallowRef([...])

// ✅ 优化：虚拟滚动
// 使用 vue-virtual-scroller 等库

// ============ 问题2：不必要的响应式转换 ============
// ❌ 问题：第三方库实例被转换为响应式
const map = ref(new Map())  // Map 会被深度转换

// ✅ 优化：使用 markRaw 或 shallowRef
import L from 'leaflet'
const mapInstance = shallowRef(null)
onMounted(() => {
  mapInstance.value = markRaw(L.map('map'))
})

// ============ 问题3：计算属性中的复杂计算 ============
// ❌ 问题：每次访问都重新计算
const expensiveComputed = computed(() => {
  return items.value.map(item => {
    // 复杂计算...
    return heavyCalculation(item)
  })
})

// ✅ 优化：使用缓存或 memo
import { useMemoize } from '@vueuse/core'
const memoizedCalculation = useMemoize(heavyCalculation)

// ============ 问题4：频繁的 watch 触发 ============
// ❌ 问题：每次输入都触发
watch(searchText, async (newValue) => {
  const results = await search(newValue)
})

// ✅ 优化：使用防抖
import { watchDebounced } from '@vueuse/core'
watchDebounced(
  searchText,
  async (newValue) => {
    const results = await search(newValue)
  },
  { debounce: 300 }
)
</script>
```

---

## 总结

本笔记涵盖了 Vue 3 从基础到进阶的核心知识点：

1. **基础概念**：Vue 3 特点、Composition API vs Options API
2. **项目搭建**：Vite 创建项目、项目结构、配置
3. **模板语法**：插值、属性绑定、指令
4. **响应式基础**：ref、reactive、toRefs、readonly
5. **计算属性与侦听器**：computed、watch、watchEffect
6. **条件与列表渲染**：v-if、v-show、v-for
7. **事件处理**：事件监听、修饰符、自定义事件
8. **表单绑定**：v-model、修饰符、组件 v-model
9. **组件基础**：组件定义、Props、Slots
10. **组件通信**：Props/Emit、provide/inject、模板引用
11. **生命周期**：各阶段钩子函数
12. **组合式函数**：逻辑复用、常用 Composables
13. **路由管理**：Vue Router 配置与使用
14. **状态管理**：Pinia 使用与最佳实践
15. **常见错误**：响应式、组件、生命周期、路由、TypeScript 相关问题

掌握这些知识点，你就能够熟练使用 Vue 3 开发现代化的 Web 应用。

---

## 参考资料

- [Vue 3 官方文档](https://cn.vuejs.org/)
- [Vue Router 官方文档](https://router.vuejs.org/zh/)
- [Pinia 官方文档](https://pinia.vuejs.org/zh/)
- [VueUse](https://vueuse.org/)
