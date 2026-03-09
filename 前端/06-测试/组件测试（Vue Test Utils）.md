> Vue Test Utils 是 Vue.js 官方的组件测试工具库，用于测试 Vue 组件
> 本笔记基于 Vue Test Utils 2.x + Vue 3 + TypeScript + Vitest

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [挂载组件](#3-挂载组件)
4. [查找元素](#4-查找元素)
5. [触发事件](#5-触发事件)
6. [测试 Props](#6-测试-props)
7. [测试 Emits](#7-测试-emits)
8. [测试 Slots](#8-测试-slots)
9. [测试 Computed 和 Methods](#9-测试-computed-和-methods)
10. [测试异步行为](#10-测试异步行为)
11. [测试 Vuex/Pinia](#11-测试-vuexpinia)
12. [测试 Vue Router](#12-测试-vue-router)
13. [测试 Composables](#13-测试-composables)
14. [Stubs 和 Mocks](#14-stubs-和-mocks)
15. [测试表单](#15-测试表单)
16. [最佳实践](#16-最佳实践)
17. [常见错误与解决方案](#17-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Vue Test Utils？

Vue Test Utils (VTU) 是 Vue.js 官方的组件单元测试库：

- **挂载组件**: 在测试环境中渲染组件
- **查询元素**: 查找和操作 DOM 元素
- **触发事件**: 模拟用户交互
- **断言验证**: 验证组件行为和输出

### 1.2 核心 API

```typescript
// mount: 完整挂载组件（包含子组件）
// shallowMount: 浅挂载（子组件被 stub）
// wrapper: 组件包装器，提供测试方法
// find/findAll: 查找元素
// trigger: 触发事件
// setProps: 设置 props
// setValue: 设置表单值
```

### 1.3 测试流程

```typescript
// 1. 挂载组件
const wrapper = mount(Component)

// 2. 与组件交互
await wrapper.find('button').trigger('click')

// 3. 断言结果
expect(wrapper.text()).toContain('Expected')
```

---

## 2. 环境搭建

### 2.1 安装依赖

```bash
# npm
npm install -D @vue/test-utils vitest jsdom

# yarn
yarn add -D @vue/test-utils vitest jsdom

# pnpm
pnpm add -D @vue/test-utils vitest jsdom
```

### 2.2 配置 Vitest

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts']
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})
```

### 2.3 测试环境设置

```typescript
// tests/setup.ts
import { config } from '@vue/test-utils'

// 全局配置
config.global.stubs = {
  // 默认 stub 的组件
  Teleport: true,
  Transition: false
}

// 全局 mocks
config.global.mocks = {
  $t: (key: string) => key  // i18n mock
}
```

---

## 3. 挂载组件

### 3.1 基础挂载

```typescript
import { mount } from '@vue/test-utils'
import MyComponent from '@/components/MyComponent.vue'

describe('MyComponent', () => {
  test('mounts correctly', () => {
    const wrapper = mount(MyComponent)
    expect(wrapper.exists()).toBe(true)
  })
})
```

### 3.2 mount vs shallowMount

```vue
<!-- Parent.vue -->
<template>
  <div>
    <h1>Parent</h1>
    <Child />
  </div>
</template>
```

```typescript
import { mount, shallowMount } from '@vue/test-utils'
import Parent from './Parent.vue'

// mount: 完整渲染（包括 Child 组件）
test('mount renders child', () => {
  const wrapper = mount(Parent)
  expect(wrapper.html()).toContain('Child content')
})

// shallowMount: 浅渲染（Child 被 stub）
test('shallowMount stubs child', () => {
  const wrapper = shallowMount(Parent)
  expect(wrapper.html()).toContain('<child-stub>')
})
```

### 3.3 挂载选项

```typescript
const wrapper = mount(Component, {
  // Props
  props: {
    title: 'Test Title',
    count: 10
  },
  
  // Slots
  slots: {
    default: 'Default slot content',
    header: '<h1>Header</h1>'
  },
  
  // Global 配置
  global: {
    // 插件
    plugins: [router, pinia],
    
    // 组件
    components: {
      CustomComponent
    },
    
    // Directives
    directives: {
      focus: {}
    },
    
    // Mocks
    mocks: {
      $t: (key: string) => key
    },
    
    // Stubs
    stubs: {
      ChildComponent: true,
      RouterLink: true
    },
    
    // Provide
    provide: {
      theme: 'dark'
    }
  },
  
  // 附加到 DOM
  attachTo: document.body
})
```

---

## 4. 查找元素

### 4.1 find 和 findAll

```vue
<template>
  <div>
    <button class="btn">Click</button>
    <button class="btn">Submit</button>
    <input id="username" />
    <span data-testid="message">Hello</span>
  </div>
</template>
```

```typescript
const wrapper = mount(Component)

// CSS 选择器
wrapper.find('.btn')              // 第一个 .btn
wrapper.findAll('.btn')           // 所有 .btn
wrapper.find('#username')         // id 选择器
wrapper.find('button')            // 标签选择器

// data-testid (推荐)
wrapper.find('[data-testid="message"]')

// 组件选择器
wrapper.findComponent(ChildComponent)
wrapper.findAllComponents(ChildComponent)
```

### 4.2 get 和 getAll

```typescript
// get: 找不到会抛出错误
const button = wrapper.get('button')

// find: 找不到返回 undefined
const button = wrapper.find('button')

// 推荐使用 get 进行断言
expect(wrapper.get('.btn').text()).toBe('Click')
```

### 4.3 查找方法对比

```typescript
describe('Finding Elements', () => {
  test('find methods', () => {
    const wrapper = mount(Component)
    
    // ✅ 推荐: data-testid
    wrapper.find('[data-testid="submit-btn"]')
    
    // ✅ 可以: 语义化选择器
    wrapper.find('button[type="submit"]')
    
    // ❌ 不推荐: 依赖样式类
    wrapper.find('.btn-primary')
    
    // ❌ 不推荐: 依赖文本内容
    wrapper.find('button:contains("Submit")')
  })
})
```

---

## 5. 触发事件

### 5.1 基础事件触发

```vue
<template>
  <button @click="handleClick">Click Me</button>
  <input @input="handleInput" />
  <form @submit.prevent="handleSubmit">
    <button type="submit">Submit</button>
  </form>
</template>
```

```typescript
describe('Event Triggering', () => {
  test('triggers click event', async () => {
    const wrapper = mount(Component)
    
    await wrapper.find('button').trigger('click')
    
    // 验证事件效果
    expect(wrapper.emitted()).toHaveProperty('click')
  })
  
  test('triggers input event', async () => {
    const wrapper = mount(Component)
    
    await wrapper.find('input').trigger('input')
  })
  
  test('triggers submit event', async () => {
    const wrapper = mount(Component)
    
    await wrapper.find('form').trigger('submit')
  })
})
```

### 5.2 带参数的事件

```typescript
test('triggers event with data', async () => {
  const wrapper = mount(Component)
  
  await wrapper.find('button').trigger('click', {
    button: 0,  // 鼠标左键
    clientX: 100,
    clientY: 200
  })
})

test('triggers keyboard event', async () => {
  const wrapper = mount(Component)
  
  await wrapper.find('input').trigger('keydown', {
    key: 'Enter',
    code: 'Enter'
  })
})
```

### 5.3 等待 DOM 更新

```typescript
test('waits for DOM update', async () => {
  const wrapper = mount(Component)
  
  // ❌ 错误: 没有等待
  wrapper.find('button').trigger('click')
  expect(wrapper.text()).toContain('Updated')  // 可能失败
  
  // ✅ 正确: 使用 await
  await wrapper.find('button').trigger('click')
  expect(wrapper.text()).toContain('Updated')
})
```

---

## 6. 测试 Props

### 6.1 传递 Props

```vue
<!-- Button.vue -->
<template>
  <button :class="`btn-${type}`" :disabled="disabled">
    {{ text }}
  </button>
</template>

<script setup lang="ts">
defineProps<{
  text: string
  type?: 'primary' | 'secondary'
  disabled?: boolean
}>()
</script>
```

```typescript
describe('Button Props', () => {
  test('renders with text prop', () => {
    const wrapper = mount(Button, {
      props: {
        text: 'Click Me'
      }
    })
    
    expect(wrapper.text()).toBe('Click Me')
  })
  
  test('applies type class', () => {
    const wrapper = mount(Button, {
      props: {
        text: 'Submit',
        type: 'primary'
      }
    })
    
    expect(wrapper.classes()).toContain('btn-primary')
  })
  
  test('disables button', () => {
    const wrapper = mount(Button, {
      props: {
        text: 'Disabled',
        disabled: true
      }
    })
    
    expect(wrapper.attributes('disabled')).toBeDefined()
  })
})
```

### 6.2 动态更新 Props

```typescript
test('updates when props change', async () => {
  const wrapper = mount(Button, {
    props: {
      text: 'Initial'
    }
  })
  
  expect(wrapper.text()).toBe('Initial')
  
  // 更新 props
  await wrapper.setProps({ text: 'Updated' })
  
  expect(wrapper.text()).toBe('Updated')
})
```

### 6.3 Props 验证

```typescript
test('validates required props', () => {
  // 测试缺少必需 props 时的行为
  const wrapper = mount(Button, {
    props: {
      // text 是必需的，但未提供
    }
  })
  
  // Vue 会在控制台警告
  // 可以通过 spy console.warn 来验证
})
```

---

## 7. 测试 Emits

### 7.1 基础 Emit 测试


```vue
<!-- Counter.vue -->
<template>
  <div>
    <p>{{ count }}</p>
    <button @click="increment">+</button>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const emit = defineEmits<{
  change: [count: number]
  increment: []
}>()

const count = ref(0)

function increment() {
  count.value++
  emit('change', count.value)
  emit('increment')
}
</script>
```

```typescript
describe('Counter Emits', () => {
  test('emits change event', async () => {
    const wrapper = mount(Counter)
    
    await wrapper.find('button').trigger('click')
    
    // 检查事件是否被触发
    expect(wrapper.emitted()).toHaveProperty('change')
    
    // 检查触发次数
    expect(wrapper.emitted('change')).toHaveLength(1)
    
    // 检查事件参数
    expect(wrapper.emitted('change')?.[0]).toEqual([1])
  })
  
  test('emits multiple events', async () => {
    const wrapper = mount(Counter)
    
    await wrapper.find('button').trigger('click')
    
    expect(wrapper.emitted()).toHaveProperty('change')
    expect(wrapper.emitted()).toHaveProperty('increment')
  })
  
  test('emits event multiple times', async () => {
    const wrapper = mount(Counter)
    
    await wrapper.find('button').trigger('click')
    await wrapper.find('button').trigger('click')
    await wrapper.find('button').trigger('click')
    
    expect(wrapper.emitted('change')).toHaveLength(3)
    expect(wrapper.emitted('change')?.[0]).toEqual([1])
    expect(wrapper.emitted('change')?.[1]).toEqual([2])
    expect(wrapper.emitted('change')?.[2]).toEqual([3])
  })
})
```

### 7.2 监听 Emit

```typescript
test('listens to emitted events', async () => {
  const onChangeSpy = vi.fn()
  
  const wrapper = mount(Counter, {
    attrs: {
      onChange: onChangeSpy
    }
  })
  
  await wrapper.find('button').trigger('click')
  
  expect(onChangeSpy).toHaveBeenCalledWith(1)
  expect(onChangeSpy).toHaveBeenCalledTimes(1)
})
```

---

## 8. 测试 Slots

### 8.1 默认插槽

```vue
<!-- Card.vue -->
<template>
  <div class="card">
    <slot />
  </div>
</template>
```

```typescript
describe('Card Slots', () => {
  test('renders default slot', () => {
    const wrapper = mount(Card, {
      slots: {
        default: '<p>Card Content</p>'
      }
    })
    
    expect(wrapper.html()).toContain('<p>Card Content</p>')
  })
  
  test('renders text in default slot', () => {
    const wrapper = mount(Card, {
      slots: {
        default: 'Simple text'
      }
    })
    
    expect(wrapper.text()).toBe('Simple text')
  })
})
```

### 8.2 具名插槽

```vue
<!-- Layout.vue -->
<template>
  <div class="layout">
    <header>
      <slot name="header" />
    </header>
    <main>
      <slot />
    </main>
    <footer>
      <slot name="footer" />
    </footer>
  </div>
</template>
```

```typescript
describe('Layout Slots', () => {
  test('renders named slots', () => {
    const wrapper = mount(Layout, {
      slots: {
        header: '<h1>Header</h1>',
        default: '<p>Content</p>',
        footer: '<p>Footer</p>'
      }
    })
    
    expect(wrapper.find('header').html()).toContain('<h1>Header</h1>')
    expect(wrapper.find('main').html()).toContain('<p>Content</p>')
    expect(wrapper.find('footer').html()).toContain('<p>Footer</p>')
  })
})
```

### 8.3 作用域插槽

```vue
<!-- List.vue -->
<template>
  <ul>
    <li v-for="item in items" :key="item.id">
      <slot :item="item" :index="item.id" />
    </li>
  </ul>
</template>

<script setup lang="ts">
defineProps<{
  items: Array<{ id: number; name: string }>
}>()
</script>
```

```typescript
describe('List Scoped Slots', () => {
  test('renders scoped slot', () => {
    const items = [
      { id: 1, name: 'Item 1' },
      { id: 2, name: 'Item 2' }
    ]
    
    const wrapper = mount(List, {
      props: { items },
      slots: {
        default: `
          <template #default="{ item, index }">
            <span>{{ index }}: {{ item.name }}</span>
          </template>
        `
      }
    })
    
    expect(wrapper.html()).toContain('1: Item 1')
    expect(wrapper.html()).toContain('2: Item 2')
  })
})
```

---

## 9. 测试 Computed 和 Methods

### 9.1 测试 Computed

```vue
<template>
  <div>
    <p>{{ fullName }}</p>
    <p>{{ isAdult }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  firstName: string
  lastName: string
  age: number
}>()

const fullName = computed(() => `${props.firstName} ${props.lastName}`)
const isAdult = computed(() => props.age >= 18)
</script>
```

```typescript
describe('Computed Properties', () => {
  test('computes full name', () => {
    const wrapper = mount(Component, {
      props: {
        firstName: 'John',
        lastName: 'Doe',
        age: 25
      }
    })
    
    expect(wrapper.text()).toContain('John Doe')
  })
  
  test('computes isAdult', async () => {
    const wrapper = mount(Component, {
      props: {
        firstName: 'John',
        lastName: 'Doe',
        age: 16
      }
    })
    
    expect(wrapper.text()).toContain('false')
    
    await wrapper.setProps({ age: 18 })
    
    expect(wrapper.text()).toContain('true')
  })
})
```

### 9.2 测试 Methods

```vue
<template>
  <div>
    <button @click="increment">Increment</button>
    <p>{{ count }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const count = ref(0)

function increment() {
  count.value++
}

// 暴露给测试
defineExpose({ increment })
</script>
```

```typescript
describe('Methods', () => {
  test('calls increment method', async () => {
    const wrapper = mount(Component)
    
    // 通过 UI 触发
    await wrapper.find('button').trigger('click')
    expect(wrapper.text()).toContain('1')
    
    // 直接调用方法
    wrapper.vm.increment()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('2')
  })
})
```

---

## 10. 测试异步行为

### 10.1 异步数据加载

```vue
<template>
  <div>
    <div v-if="loading">Loading...</div>
    <div v-else-if="error">{{ error }}</div>
    <div v-else>{{ data }}</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'

const loading = ref(true)
const error = ref('')
const data = ref(null)

onMounted(async () => {
  try {
    const response = await fetch('/api/data')
    data.value = await response.json()
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})
</script>
```

```typescript
import { flushPromises } from '@vue/test-utils'

describe('Async Component', () => {
  beforeEach(() => {
    global.fetch = vi.fn()
  })
  
  test('shows loading state', () => {
    const wrapper = mount(AsyncComponent)
    expect(wrapper.text()).toContain('Loading...')
  })
  
  test('displays data after loading', async () => {
    vi.mocked(fetch).mockResolvedValue({
      json: async () => ({ message: 'Success' })
    } as Response)
    
    const wrapper = mount(AsyncComponent)
    
    // 等待所有 Promise 完成
    await flushPromises()
    
    expect(wrapper.text()).toContain('Success')
  })
  
  test('displays error on failure', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('Failed'))
    
    const wrapper = mount(AsyncComponent)
    await flushPromises()
    
    expect(wrapper.text()).toContain('Failed')
  })
})
```

### 10.2 测试定时器

```vue
<template>
  <div>
    <p>{{ message }}</p>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'

const message = ref('Initial')

onMounted(() => {
  setTimeout(() => {
    message.value = 'Updated'
  }, 1000)
})
</script>
```

```typescript
describe('Timer Component', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  
  afterEach(() => {
    vi.restoreAllMocks()
  })
  
  test('updates message after timeout', async () => {
    const wrapper = mount(TimerComponent)
    
    expect(wrapper.text()).toBe('Initial')
    
    // 快进时间
    vi.advanceTimersByTime(1000)
    await wrapper.vm.$nextTick()
    
    expect(wrapper.text()).toBe('Updated')
  })
})
```

---

## 11. 测试 Vuex/Pinia

### 11.1 测试 Pinia Store

```typescript
import { setActivePinia, createPinia } from 'pinia'
import { useCounterStore } from '@/stores/counter'

describe('Component with Pinia', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })
  
  test('uses store', () => {
    const wrapper = mount(Component, {
      global: {
        plugins: [createPinia()]
      }
    })
    
    const store = useCounterStore()
    expect(store.count).toBe(0)
  })
  
  test('updates store', async () => {
    const wrapper = mount(Component, {
      global: {
        plugins: [createPinia()]
      }
    })
    
    const store = useCounterStore()
    store.increment()
    
    await wrapper.vm.$nextTick()
    
    expect(wrapper.text()).toContain('1')
  })
})
```

### 11.2 Mock Store

```typescript
test('mocks store', () => {
  const mockStore = {
    count: 10,
    increment: vi.fn()
  }
  
  const wrapper = mount(Component, {
    global: {
      provide: {
        counterStore: mockStore
      }
    }
  })
  
  expect(wrapper.text()).toContain('10')
})
```

---

## 12. 测试 Vue Router

### 12.1 基础路由测试

```typescript
import { createRouter, createMemoryHistory } from 'vue-router'

const router = createRouter({
  history: createMemoryHistory(),
  routes: [
    { path: '/', component: Home },
    { path: '/about', component: About }
  ]
})

describe('Component with Router', () => {
  test('renders with router', () => {
    const wrapper = mount(Component, {
      global: {
        plugins: [router]
      }
    })
    
    expect(wrapper.exists()).toBe(true)
  })
})
```

### 12.2 测试路由导航

```vue
<template>
  <div>
    <RouterLink to="/about">About</RouterLink>
  </div>
</template>
```

```typescript
test('navigates to about page', async () => {
  const wrapper = mount(Component, {
    global: {
      plugins: [router]
    }
  })
  
  await wrapper.find('a').trigger('click')
  await router.isReady()
  
  expect(router.currentRoute.value.path).toBe('/about')
})
```

### 12.3 Stub RouterLink

```typescript
test('stubs router link', () => {
  const wrapper = mount(Component, {
    global: {
      stubs: {
        RouterLink: true
      }
    }
  })
  
  expect(wrapper.html()).toContain('<router-link-stub')
})
```

---

## 13. 测试 Composables

### 13.1 独立测试 Composable

```typescript
// useCounter.ts
import { ref } from 'vue'

export function useCounter(initial = 0) {
  const count = ref(initial)
  
  function increment() {
    count.value++
  }
  
  return { count, increment }
}
```

```typescript
describe('useCounter', () => {
  test('increments count', () => {
    const { count, increment } = useCounter()
    
    expect(count.value).toBe(0)
    
    increment()
    
    expect(count.value).toBe(1)
  })
})
```

### 13.2 在组件中测试 Composable

```vue
<template>
  <div>
    <p>{{ count }}</p>
    <button @click="increment">+</button>
  </div>
</template>

<script setup lang="ts">
import { useCounter } from '@/composables/useCounter'

const { count, increment } = useCounter()
</script>
```

```typescript
test('uses composable in component', async () => {
  const wrapper = mount(Component)
  
  expect(wrapper.text()).toContain('0')
  
  await wrapper.find('button').trigger('click')
  
  expect(wrapper.text()).toContain('1')
})
```

---

## 14. Stubs 和 Mocks

### 14.1 Stub 子组件


```vue
<!-- Parent.vue -->
<template>
  <div>
    <h1>Parent</h1>
    <ChildComponent :data="data" />
  </div>
</template>
```

```typescript
describe('Stubbing Components', () => {
  test('stubs child component', () => {
    const wrapper = mount(Parent, {
      global: {
        stubs: {
          ChildComponent: true  // 使用默认 stub
        }
      }
    })
    
    expect(wrapper.html()).toContain('<child-component-stub')
  })
  
  test('stubs with custom component', () => {
    const CustomStub = {
      template: '<div>Custom Stub</div>'
    }
    
    const wrapper = mount(Parent, {
      global: {
        stubs: {
          ChildComponent: CustomStub
        }
      }
    })
    
    expect(wrapper.text()).toContain('Custom Stub')
  })
  
  test('stubs all children with shallow', () => {
    const wrapper = shallowMount(Parent)
    
    // 所有子组件都被 stub
    expect(wrapper.html()).toContain('-stub')
  })
})
```

### 14.2 Mock 全局属性

```typescript
test('mocks global properties', () => {
  const wrapper = mount(Component, {
    global: {
      mocks: {
        $t: (key: string) => `translated_${key}`,
        $route: {
          params: { id: '123' }
        }
      }
    }
  })
  
  // 组件内可以使用 $t 和 $route
})
```

### 14.3 Mock 第三方库

```typescript
// Mock axios
vi.mock('axios')

test('mocks axios', async () => {
  const mockData = { data: { message: 'Success' } }
  vi.mocked(axios.get).mockResolvedValue(mockData)
  
  const wrapper = mount(Component)
  await flushPromises()
  
  expect(wrapper.text()).toContain('Success')
})
```

---

## 15. 测试表单

### 15.1 输入框测试

```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input 
      v-model="username" 
      type="text"
      data-testid="username"
    />
    <input 
      v-model="password" 
      type="password"
      data-testid="password"
    />
    <button type="submit">Submit</button>
  </form>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const username = ref('')
const password = ref('')

const emit = defineEmits<{
  submit: [data: { username: string; password: string }]
}>()

function handleSubmit() {
  emit('submit', {
    username: username.value,
    password: password.value
  })
}
</script>
```

```typescript
describe('Form Component', () => {
  test('updates input value', async () => {
    const wrapper = mount(FormComponent)
    
    const input = wrapper.find('[data-testid="username"]')
    
    await input.setValue('testuser')
    
    expect((input.element as HTMLInputElement).value).toBe('testuser')
  })
  
  test('submits form data', async () => {
    const wrapper = mount(FormComponent)
    
    await wrapper.find('[data-testid="username"]').setValue('user')
    await wrapper.find('[data-testid="password"]').setValue('pass123')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.emitted('submit')?.[0]).toEqual([{
      username: 'user',
      password: 'pass123'
    }])
  })
})
```

### 15.2 复选框和单选框

```vue
<template>
  <div>
    <input 
      v-model="checked" 
      type="checkbox"
      data-testid="checkbox"
    />
    
    <input 
      v-model="selected" 
      type="radio" 
      value="option1"
      data-testid="radio1"
    />
    <input 
      v-model="selected" 
      type="radio" 
      value="option2"
      data-testid="radio2"
    />
  </div>
</template>
```

```typescript
describe('Checkbox and Radio', () => {
  test('checks checkbox', async () => {
    const wrapper = mount(Component)
    
    const checkbox = wrapper.find('[data-testid="checkbox"]')
    
    await checkbox.setValue(true)
    
    expect((checkbox.element as HTMLInputElement).checked).toBe(true)
  })
  
  test('selects radio button', async () => {
    const wrapper = mount(Component)
    
    await wrapper.find('[data-testid="radio2"]').setValue()
    
    const radio = wrapper.find('[data-testid="radio2"]').element as HTMLInputElement
    expect(radio.checked).toBe(true)
  })
})
```

### 15.3 下拉选择框

```vue
<template>
  <select v-model="selected" data-testid="select">
    <option value="">请选择</option>
    <option value="option1">选项1</option>
    <option value="option2">选项2</option>
  </select>
</template>
```

```typescript
test('selects option', async () => {
  const wrapper = mount(Component)
  
  const select = wrapper.find('[data-testid="select"]')
  
  await select.setValue('option2')
  
  expect((select.element as HTMLSelectElement).value).toBe('option2')
})
```

### 15.4 表单验证

```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input v-model="email" type="email" />
    <span v-if="errors.email" class="error">
      {{ errors.email }}
    </span>
    <button type="submit">Submit</button>
  </form>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const email = ref('')
const errors = ref<Record<string, string>>({})

function validate() {
  errors.value = {}
  
  if (!email.value) {
    errors.value.email = '邮箱不能为空'
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email.value)) {
    errors.value.email = '邮箱格式不正确'
  }
  
  return Object.keys(errors.value).length === 0
}

function handleSubmit() {
  if (validate()) {
    // 提交表单
  }
}
</script>
```

```typescript
describe('Form Validation', () => {
  test('shows required error', async () => {
    const wrapper = mount(FormComponent)
    
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.find('.error').text()).toBe('邮箱不能为空')
  })
  
  test('shows format error', async () => {
    const wrapper = mount(FormComponent)
    
    await wrapper.find('input').setValue('invalid-email')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.find('.error').text()).toBe('邮箱格式不正确')
  })
  
  test('submits valid form', async () => {
    const wrapper = mount(FormComponent)
    
    await wrapper.find('input').setValue('test@example.com')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.find('.error').exists()).toBe(false)
  })
})
```

---

## 16. 最佳实践

### 16.1 使用 data-testid

```vue
<!-- ✅ 推荐: 使用 data-testid -->
<template>
  <button data-testid="submit-btn">Submit</button>
</template>

<!-- ❌ 不推荐: 依赖样式类 -->
<template>
  <button class="btn btn-primary">Submit</button>
</template>
```

```typescript
// ✅ 推荐
wrapper.find('[data-testid="submit-btn"]')

// ❌ 不推荐
wrapper.find('.btn-primary')
```

### 16.2 测试用户行为而非实现

```typescript
// ❌ 不推荐: 测试内部实现
test('calls internal method', () => {
  const wrapper = mount(Component)
  const spy = vi.spyOn(wrapper.vm, 'internalMethod')
  wrapper.vm.internalMethod()
  expect(spy).toHaveBeenCalled()
})

// ✅ 推荐: 测试用户可见的行为
test('displays result after button click', async () => {
  const wrapper = mount(Component)
  await wrapper.find('button').trigger('click')
  expect(wrapper.text()).toContain('Expected Result')
})
```

### 16.3 保持测试独立

```typescript
// ❌ 不推荐: 测试之间有依赖
let wrapper: any

beforeAll(() => {
  wrapper = mount(Component)
})

test('test 1', () => {
  wrapper.find('button').trigger('click')
})

test('test 2', () => {
  // 依赖 test 1 的状态
  expect(wrapper.text()).toContain('1')
})

// ✅ 推荐: 每个测试独立
test('test 1', () => {
  const wrapper = mount(Component)
  wrapper.find('button').trigger('click')
  expect(wrapper.text()).toContain('1')
})

test('test 2', () => {
  const wrapper = mount(Component)
  expect(wrapper.text()).toContain('0')
})
```

### 16.4 使用辅助函数

```typescript
// tests/utils.ts
export function createWrapper(component: any, options = {}) {
  return mount(component, {
    global: {
      plugins: [createPinia(), createRouter()],
      stubs: {
        Teleport: true,
        Transition: false
      }
    },
    ...options
  })
}

// 使用
test('uses helper', () => {
  const wrapper = createWrapper(Component, {
    props: { title: 'Test' }
  })
  
  expect(wrapper.exists()).toBe(true)
})
```

### 16.5 合理使用 shallowMount

```typescript
// ✅ 适合使用 shallowMount 的场景
// 1. 只测试当前组件逻辑
// 2. 子组件已经有自己的测试
// 3. 子组件渲染很慢

test('uses shallowMount', () => {
  const wrapper = shallowMount(Parent)
  expect(wrapper.find('h1').text()).toBe('Parent')
})

// ✅ 适合使用 mount 的场景
// 1. 需要测试组件间交互
// 2. 需要测试完整的渲染结果

test('uses mount', () => {
  const wrapper = mount(Parent)
  expect(wrapper.findComponent(Child).exists()).toBe(true)
})
```

### 16.6 清理副作用

```typescript
describe('Component with Side Effects', () => {
  afterEach(() => {
    // 清理 DOM
    document.body.innerHTML = ''
    
    // 清理定时器
    vi.clearAllTimers()
    
    // 清理 Mock
    vi.restoreAllMocks()
  })
  
  test('test with side effects', () => {
    const wrapper = mount(Component, {
      attachTo: document.body
    })
    
    // 测试逻辑
  })
})
```

### 16.7 测试边界情况

```typescript
describe('Edge Cases', () => {
  test('handles empty array', () => {
    const wrapper = mount(List, {
      props: { items: [] }
    })
    
    expect(wrapper.text()).toContain('No items')
  })
  
  test('handles null value', () => {
    const wrapper = mount(Component, {
      props: { data: null }
    })
    
    expect(wrapper.text()).toContain('No data')
  })
  
  test('handles very long text', () => {
    const longText = 'a'.repeat(10000)
    const wrapper = mount(Component, {
      props: { text: longText }
    })
    
    expect(wrapper.text()).toContain(longText)
  })
})
```

---

## 17. 常见错误与解决方案

### 17.1 未等待异步更新

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

### 17.2 查找元素失败

```typescript
// ❌ 错误: 元素不存在
test('finds element', () => {
  const wrapper = mount(Component)
  const button = wrapper.find('.non-existent')
  button.trigger('click')  // 错误: button 不存在
})

// ✅ 解决方案 1: 使用 get (会抛出错误)
test('finds element', () => {
  const wrapper = mount(Component)
  const button = wrapper.get('.btn')  // 找不到会抛出错误
  button.trigger('click')
})

// ✅ 解决方案 2: 先检查存在性
test('finds element', () => {
  const wrapper = mount(Component)
  const button = wrapper.find('.btn')
  
  if (button.exists()) {
    button.trigger('click')
  }
})
```

### 17.3 Props 未响应

```typescript
// ❌ 错误: 直接修改 props
test('updates props', async () => {
  const wrapper = mount(Component, {
    props: { count: 0 }
  })
  
  wrapper.props().count = 10  // 错误: 不会触发更新
  expect(wrapper.text()).toContain('10')
})

// ✅ 解决方案: 使用 setProps
test('updates props', async () => {
  const wrapper = mount(Component, {
    props: { count: 0 }
  })
  
  await wrapper.setProps({ count: 10 })
  expect(wrapper.text()).toContain('10')
})
```

### 17.4 事件未触发

```typescript
// ❌ 错误: 在禁用的元素上触发事件
test('triggers event', async () => {
  const wrapper = mount(Component, {
    props: { disabled: true }
  })
  
  await wrapper.find('button').trigger('click')
  expect(wrapper.emitted('click')).toBeDefined()  // 失败
})

// ✅ 解决方案: 检查元素状态
test('triggers event', async () => {
  const wrapper = mount(Component, {
    props: { disabled: false }
  })
  
  await wrapper.find('button').trigger('click')
  expect(wrapper.emitted('click')).toBeDefined()
})
```

### 17.5 Teleport 组件问题

```vue
<template>
  <Teleport to="body">
    <div class="modal">Modal Content</div>
  </Teleport>
</template>
```

```typescript
// ❌ 错误: 在 wrapper 中查找
test('finds teleported content', () => {
  const wrapper = mount(Component)
  expect(wrapper.find('.modal').exists()).toBe(false)  // 找不到
})

// ✅ 解决方案 1: Stub Teleport
test('stubs teleport', () => {
  const wrapper = mount(Component, {
    global: {
      stubs: {
        Teleport: true
      }
    }
  })
  
  expect(wrapper.find('.modal').exists()).toBe(true)
})

// ✅ 解决方案 2: 在 document 中查找
test('finds in document', () => {
  const wrapper = mount(Component, {
    attachTo: document.body
  })
  
  expect(document.querySelector('.modal')).toBeTruthy()
  
  wrapper.unmount()
})
```

### 17.6 v-model 测试问题

```vue
<template>
  <input v-model="value" />
</template>
```

```typescript
// ❌ 错误: 直接设置 value 属性
test('updates v-model', async () => {
  const wrapper = mount(Component)
  const input = wrapper.find('input')
  
  input.element.value = 'new value'  // 不会触发 v-model 更新
  expect(wrapper.vm.value).toBe('new value')  // 失败
})

// ✅ 解决方案: 使用 setValue
test('updates v-model', async () => {
  const wrapper = mount(Component)
  
  await wrapper.find('input').setValue('new value')
  expect(wrapper.vm.value).toBe('new value')
})
```

### 17.7 Router 未初始化

```typescript
// ❌ 错误: 使用 RouterLink 但未提供 router
test('uses router link', () => {
  const wrapper = mount(Component)  // 错误: router 未定义
  expect(wrapper.find('a').exists()).toBe(true)
})

// ✅ 解决方案 1: 提供 router
test('uses router link', () => {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: []
  })
  
  const wrapper = mount(Component, {
    global: {
      plugins: [router]
    }
  })
  
  expect(wrapper.find('a').exists()).toBe(true)
})

// ✅ 解决方案 2: Stub RouterLink
test('stubs router link', () => {
  const wrapper = mount(Component, {
    global: {
      stubs: {
        RouterLink: true
      }
    }
  })
  
  expect(wrapper.html()).toContain('router-link-stub')
})
```

### 17.8 Transition 动画问题

```vue
<template>
  <Transition>
    <div v-if="show">Content</div>
  </Transition>
</template>
```

```typescript
// ❌ 问题: Transition 会延迟渲染
test('shows content', async () => {
  const wrapper = mount(Component, {
    props: { show: true }
  })
  
  expect(wrapper.text()).toContain('Content')  // 可能失败
})

// ✅ 解决方案: Stub Transition
test('shows content', () => {
  const wrapper = mount(Component, {
    props: { show: true },
    global: {
      stubs: {
        Transition: false  // 禁用过渡效果
      }
    }
  })
  
  expect(wrapper.text()).toContain('Content')
})
```

---

## 18. 实战示例

### 18.1 完整的 Todo 组件测试

```vue
<!-- TodoList.vue -->
<template>
  <div class="todo-list">
    <form @submit.prevent="addTodo">
      <input 
        v-model="newTodo" 
        placeholder="添加待办事项"
        data-testid="todo-input"
      />
      <button type="submit" data-testid="add-btn">添加</button>
    </form>
    
    <ul>
      <li 
        v-for="todo in todos" 
        :key="todo.id"
        :data-testid="`todo-${todo.id}`"
      >
        <input 
          type="checkbox"
          :checked="todo.completed"
          @change="toggleTodo(todo.id)"
        />
        <span :class="{ completed: todo.completed }">
          {{ todo.text }}
        </span>
        <button @click="removeTodo(todo.id)">删除</button>
      </li>
    </ul>
    
    <div class="stats">
      <span>总计: {{ todos.length }}</span>
      <span>已完成: {{ completedCount }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

interface Todo {
  id: number
  text: string
  completed: boolean
}

const newTodo = ref('')
const todos = ref<Todo[]>([])
let nextId = 1

const completedCount = computed(() => {
  return todos.value.filter(t => t.completed).length
})

function addTodo() {
  if (!newTodo.value.trim()) return
  
  todos.value.push({
    id: nextId++,
    text: newTodo.value,
    completed: false
  })
  
  newTodo.value = ''
}

function toggleTodo(id: number) {
  const todo = todos.value.find(t => t.id === id)
  if (todo) {
    todo.completed = !todo.completed
  }
}

function removeTodo(id: number) {
  const index = todos.value.findIndex(t => t.id === id)
  if (index > -1) {
    todos.value.splice(index, 1)
  }
}
</script>

<style scoped>
.completed {
  text-decoration: line-through;
  color: #999;
}
</style>
```

```typescript
// TodoList.spec.ts
import { describe, test, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TodoList from '../TodoList.vue'

describe('TodoList Component', () => {
  test('renders empty list', () => {
    const wrapper = mount(TodoList)
    
    expect(wrapper.find('ul').exists()).toBe(true)
    expect(wrapper.findAll('li')).toHaveLength(0)
    expect(wrapper.text()).toContain('总计: 0')
  })
  
  test('adds new todo', async () => {
    const wrapper = mount(TodoList)
    
    await wrapper.find('[data-testid="todo-input"]').setValue('Buy milk')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.findAll('li')).toHaveLength(1)
    expect(wrapper.text()).toContain('Buy milk')
    expect(wrapper.text()).toContain('总计: 1')
  })
  
  test('does not add empty todo', async () => {
    const wrapper = mount(TodoList)
    
    await wrapper.find('[data-testid="todo-input"]').setValue('   ')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.findAll('li')).toHaveLength(0)
  })
  
  test('clears input after adding', async () => {
    const wrapper = mount(TodoList)
    
    const input = wrapper.find('[data-testid="todo-input"]')
    await input.setValue('New todo')
    await wrapper.find('form').trigger('submit')
    
    expect((input.element as HTMLInputElement).value).toBe('')
  })
  
  test('toggles todo completion', async () => {
    const wrapper = mount(TodoList)
    
    await wrapper.find('[data-testid="todo-input"]').setValue('Task 1')
    await wrapper.find('form').trigger('submit')
    
    const checkbox = wrapper.find('input[type="checkbox"]')
    await checkbox.setValue(true)
    
    expect(wrapper.find('.completed').exists()).toBe(true)
    expect(wrapper.text()).toContain('已完成: 1')
  })
  
  test('removes todo', async () => {
    const wrapper = mount(TodoList)
    
    await wrapper.find('[data-testid="todo-input"]').setValue('Task 1')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.findAll('li')).toHaveLength(1)
    
    await wrapper.find('button:last-child').trigger('click')
    
    expect(wrapper.findAll('li')).toHaveLength(0)
  })
  
  test('adds multiple todos', async () => {
    const wrapper = mount(TodoList)
    
    const todos = ['Task 1', 'Task 2', 'Task 3']
    
    for (const todo of todos) {
      await wrapper.find('[data-testid="todo-input"]').setValue(todo)
      await wrapper.find('form').trigger('submit')
    }
    
    expect(wrapper.findAll('li')).toHaveLength(3)
    expect(wrapper.text()).toContain('总计: 3')
  })
  
  test('counts completed todos correctly', async () => {
    const wrapper = mount(TodoList)
    
    // 添加3个待办
    for (let i = 1; i <= 3; i++) {
      await wrapper.find('[data-testid="todo-input"]').setValue(`Task ${i}`)
      await wrapper.find('form').trigger('submit')
    }
    
    // 完成2个
    const checkboxes = wrapper.findAll('input[type="checkbox"]')
    await checkboxes[0].setValue(true)
    await checkboxes[1].setValue(true)
    
    expect(wrapper.text()).toContain('已完成: 2')
  })
})
```

---

## 总结

Vue Test Utils 是测试 Vue 组件的强大工具，掌握它能够：

**核心优势：**
- ✅ 完整的组件测试能力
- ✅ 模拟用户交互
- ✅ 测试组件通信
- ✅ 支持异步测试
- ✅ 灵活的 Mock 和 Stub

**最佳实践要点：**
1. 使用 data-testid 定位元素
2. 测试用户行为而非实现细节
3. 保持测试独立性
4. 等待异步更新完成
5. 合理使用 mount 和 shallowMount
6. 测试边界情况
7. 及时清理副作用

**常见陷阱：**
- ❌ 未等待异步更新
- ❌ 查找元素失败
- ❌ Props 未正确更新
- ❌ 事件未触发
- ❌ Teleport 组件查找问题
- ❌ v-model 测试错误
- ❌ Router 未初始化

通过本笔记的学习，你应该能够：
- ✅ 熟练使用 Vue Test Utils API
- ✅ 测试各种类型的组件
- ✅ 处理异步行为
- ✅ Mock 依赖和子组件
- ✅ 测试表单交互
- ✅ 编写可维护的测试代码
- ✅ 避免常见测试错误

继续学习建议：
1. 实践完整的组件测试套件
2. 学习 E2E 测试补充单元测试
3. 研究测试驱动开发（TDD）
4. 探索测试覆盖率优化

---

> 最后更新: 2024
> 适用版本: Vue Test Utils 2.x + Vue 3.x
> 官方文档: https://test-utils.vuejs.org/
> 作者: Kiro AI Assistant
```
