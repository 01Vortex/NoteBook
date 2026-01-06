# Vue I18n 国际化完全指南

> 国际化（Internationalization，简称 i18n）是让应用支持多语言的技术方案
> 本笔记基于 Vue 3 + Vue I18n v9，涵盖从入门到高级的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [基本使用](#3-基本使用)
4. [消息格式化](#4-消息格式化)
5. [复数处理](#5-复数处理)
6. [日期时间格式化](#6-日期时间格式化)
7. [数字格式化](#7-数字格式化)
8. [组件插值](#8-组件插值)
9. [语言切换](#9-语言切换)
10. [懒加载与按需加载](#10-懒加载与按需加载)
11. [与 Vue Router 集成](#11-与-vue-router-集成)
12. [与 Pinia 集成](#12-与-pinia-集成)
13. [TypeScript 支持](#13-typescript-支持)
14. [最佳实践](#14-最佳实践)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是国际化？

国际化（i18n）是指设计和开发应用程序时，使其能够适应不同语言和地区的过程。"i18n" 这个缩写来自于 "internationalization" 这个单词，首字母 i 和末字母 n 之间有 18 个字母。

与之相关的概念：
- **本地化（L10n）**：将国际化的应用适配到特定语言/地区的过程
- **区域设置（Locale）**：语言和地区的组合，如 `zh-CN`（简体中文-中国）、`en-US`（英语-美国）

### 1.2 为什么需要国际化？

```
┌─────────────────────────────────────────────────────────────────────┐
│                    国际化的价值                                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  业务价值:                                                           │
│  • 扩大用户群体，触达全球市场                                         │
│  • 提升用户体验，用户使用母语更舒适                                    │
│  • 满足法规要求，某些地区强制要求本地语言                              │
│                                                                      │
│  技术价值:                                                           │
│  • 文本与代码分离，便于维护                                          │
│  • 统一管理翻译资源                                                  │
│  • 支持动态切换语言，无需刷新页面                                     │
│                                                                      │
│  需要国际化的内容:                                                    │
│  • 界面文本（按钮、标签、提示等）                                     │
│  • 日期时间格式（2024/01/15 vs 01/15/2024）                         │
│  • 数字格式（1,234.56 vs 1.234,56）                                 │
│  • 货币格式（¥100 vs $100）                                         │
│  • 复数形式（1 item vs 2 items）                                    │
│  • 文本方向（LTR vs RTL）                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Vue I18n 简介

Vue I18n 是 Vue.js 官方推荐的国际化插件，提供了：
- 简单的 API 进行文本翻译
- 支持消息格式化（插值、复数等）
- 日期时间和数字的本地化格式
- 组件级别的翻译
- 与 Vue 生态系统的深度集成

### 1.4 Locale 命名规范

```
语言代码-地区代码

常见示例：
zh-CN  → 简体中文（中国大陆）
zh-TW  → 繁体中文（台湾）
zh-HK  → 繁体中文（香港）
en-US  → 英语（美国）
en-GB  → 英语（英国）
ja-JP  → 日语（日本）
ko-KR  → 韩语（韩国）
fr-FR  → 法语（法国）
de-DE  → 德语（德国）
es-ES  → 西班牙语（西班牙）
pt-BR  → 葡萄牙语（巴西）
ar-SA  → 阿拉伯语（沙特）→ RTL 语言
he-IL  → 希伯来语（以色列）→ RTL 语言
```

---

## 2. 安装与配置

### 2.1 安装

```bash
# npm
npm install vue-i18n@9

# yarn
yarn add vue-i18n@9

# pnpm
pnpm add vue-i18n@9
```

### 2.2 基础配置

**项目结构：**
```
src/
├── i18n/
│   ├── index.ts          # i18n 实例配置
│   └── locales/          # 语言文件目录
│       ├── zh-CN.ts      # 简体中文
│       ├── en-US.ts      # 英语
│       └── ja-JP.ts      # 日语
├── main.ts
└── App.vue
```

**创建语言文件：**

```typescript
// src/i18n/locales/zh-CN.ts
export default {
  common: {
    confirm: '确认',
    cancel: '取消',
    save: '保存',
    delete: '删除',
    edit: '编辑',
    search: '搜索',
    loading: '加载中...',
    noData: '暂无数据',
  },
  nav: {
    home: '首页',
    about: '关于',
    contact: '联系我们',
  },
  user: {
    login: '登录',
    logout: '退出登录',
    register: '注册',
    username: '用户名',
    password: '密码',
    email: '邮箱',
  },
  message: {
    welcome: '欢迎回来，{name}！',
    loginSuccess: '登录成功',
    loginFailed: '登录失败，请重试',
  },
}
```

```typescript
// src/i18n/locales/en-US.ts
export default {
  common: {
    confirm: 'Confirm',
    cancel: 'Cancel',
    save: 'Save',
    delete: 'Delete',
    edit: 'Edit',
    search: 'Search',
    loading: 'Loading...',
    noData: 'No Data',
  },
  nav: {
    home: 'Home',
    about: 'About',
    contact: 'Contact',
  },
  user: {
    login: 'Login',
    logout: 'Logout',
    register: 'Register',
    username: 'Username',
    password: 'Password',
    email: 'Email',
  },
  message: {
    welcome: 'Welcome back, {name}!',
    loginSuccess: 'Login successful',
    loginFailed: 'Login failed, please try again',
  },
}
```

**创建 i18n 实例：**

```typescript
// src/i18n/index.ts
import { createI18n } from 'vue-i18n'
import zhCN from './locales/zh-CN'
import enUS from './locales/en-US'

// 获取浏览器语言
function getDefaultLocale(): string {
  const browserLang = navigator.language
  const savedLang = localStorage.getItem('locale')
  
  if (savedLang) {
    return savedLang
  }
  
  // 匹配浏览器语言
  if (browserLang.startsWith('zh')) {
    return 'zh-CN'
  }
  
  return 'en-US'
}

const i18n = createI18n({
  // 使用 Composition API 模式
  legacy: false,
  
  // 全局注入 $t 函数
  globalInjection: true,
  
  // 默认语言
  locale: getDefaultLocale(),
  
  // 回退语言（当前语言没有对应翻译时使用）
  fallbackLocale: 'en-US',
  
  // 语言包
  messages: {
    'zh-CN': zhCN,
    'en-US': enUS,
  },
  
  // 缺失翻译时的警告
  missingWarn: process.env.NODE_ENV === 'development',
  fallbackWarn: process.env.NODE_ENV === 'development',
})

export default i18n
```

**在 main.ts 中注册：**

```typescript
// src/main.ts
import { createApp } from 'vue'
import App from './App.vue'
import i18n from './i18n'

const app = createApp(App)

app.use(i18n)
app.mount('#app')
```

### 2.3 配置选项详解

```typescript
const i18n = createI18n({
  // ===== 核心配置 =====
  
  // 是否使用 Legacy API（Vue 2 风格）
  // false = 使用 Composition API（推荐）
  legacy: false,
  
  // 当前语言
  locale: 'zh-CN',
  
  // 回退语言，可以是字符串或数组
  fallbackLocale: ['en-US', 'en'],
  
  // 语言包
  messages: {
    'zh-CN': { /* ... */ },
    'en-US': { /* ... */ },
  },
  
  // ===== 全局配置 =====
  
  // 是否全局注入 $t, $d, $n 等函数
  globalInjection: true,
  
  // 是否允许在模板中使用 HTML
  warnHtmlMessage: true,
  
  // ===== 格式化配置 =====
  
  // 日期时间格式
  datetimeFormats: {
    'zh-CN': { /* ... */ },
    'en-US': { /* ... */ },
  },
  
  // 数字格式
  numberFormats: {
    'zh-CN': { /* ... */ },
    'en-US': { /* ... */ },
  },
  
  // ===== 开发配置 =====
  
  // 缺失翻译警告
  missingWarn: true,
  
  // 回退警告
  fallbackWarn: true,
  
  // 自定义缺失处理函数
  missing: (locale, key, vm) => {
    console.warn(`Missing translation: ${key} in ${locale}`)
    return key
  },
})
```

---

## 3. 基本使用

### 3.1 在模板中使用

```vue
<template>
  <div>
    <!-- 方式1：使用 $t 函数（推荐） -->
    <h1>{{ $t('nav.home') }}</h1>
    
    <!-- 方式2：使用 v-t 指令 -->
    <p v-t="'common.loading'"></p>
    
    <!-- 方式3：使用 <i18n-t> 组件 -->
    <i18n-t keypath="message.welcome" tag="p">
      <template #name>
        <strong>{{ username }}</strong>
      </template>
    </i18n-t>
    
    <!-- 在属性中使用 -->
    <input :placeholder="$t('user.username')" />
    <button :title="$t('common.save')">{{ $t('common.save') }}</button>
  </div>
</template>

<script setup lang="ts">
const username = 'John'
</script>
```

### 3.2 在 Composition API 中使用

```vue
<script setup lang="ts">
import { useI18n } from 'vue-i18n'

// 获取 i18n 实例
const { t, locale, availableLocales } = useI18n()

// 使用翻译函数
const welcomeMessage = t('message.welcome', { name: 'John' })

// 切换语言
function changeLocale(lang: string) {
  locale.value = lang
  localStorage.setItem('locale', lang)
}

// 获取当前语言
console.log('当前语言:', locale.value)

// 获取所有可用语言
console.log('可用语言:', availableLocales)
</script>

<template>
  <div>
    <p>{{ t('nav.home') }}</p>
    <p>{{ welcomeMessage }}</p>
    
    <select v-model="locale">
      <option v-for="lang in availableLocales" :key="lang" :value="lang">
        {{ lang }}
      </option>
    </select>
  </div>
</template>
```

### 3.3 在 Options API 中使用

```vue
<script>
export default {
  computed: {
    welcomeMessage() {
      return this.$t('message.welcome', { name: 'John' })
    }
  },
  methods: {
    showAlert() {
      alert(this.$t('message.loginSuccess'))
    },
    changeLocale(lang) {
      this.$i18n.locale = lang
    }
  }
}
</script>
```

### 3.4 在 JS/TS 文件中使用

```typescript
// 方式1：导入 i18n 实例
import i18n from '@/i18n'

// 使用全局 t 函数
const message = i18n.global.t('message.welcome', { name: 'John' })

// 获取/设置当前语言
console.log(i18n.global.locale.value)
i18n.global.locale.value = 'en-US'

// 方式2：在 Pinia store 中使用
import { defineStore } from 'pinia'
import i18n from '@/i18n'

export const useUserStore = defineStore('user', {
  actions: {
    login() {
      // 使用翻译
      const successMsg = i18n.global.t('message.loginSuccess')
      console.log(successMsg)
    }
  }
})

// 方式3：在工具函数中使用
export function formatError(code: string): string {
  return i18n.global.t(`errors.${code}`)
}
```


---

## 4. 消息格式化

### 4.1 命名插值

最常用的插值方式，使用 `{name}` 语法。

```typescript
// 语言文件
{
  message: {
    greeting: '你好，{name}！',
    info: '{name} 在 {city} 工作',
    nested: '欢迎 {user.name}，您的邮箱是 {user.email}',
  }
}
```

```vue
<template>
  <!-- 基本使用 -->
  <p>{{ $t('message.greeting', { name: '张三' }) }}</p>
  <!-- 输出：你好，张三！ -->
  
  <!-- 多个参数 -->
  <p>{{ $t('message.info', { name: '李四', city: '北京' }) }}</p>
  <!-- 输出：李四 在 北京 工作 -->
  
  <!-- 嵌套对象 -->
  <p>{{ $t('message.nested', { user: { name: '王五', email: 'wang@example.com' } }) }}</p>
  <!-- 输出：欢迎 王五，您的邮箱是 wang@example.com -->
</template>
```

### 4.2 列表插值

使用数组索引进行插值。

```typescript
// 语言文件
{
  message: {
    items: '{0}、{1} 和 {2}',
    ordered: '第一是 {0}，第二是 {1}',
  }
}
```

```vue
<template>
  <p>{{ $t('message.items', ['苹果', '香蕉', '橙子']) }}</p>
  <!-- 输出：苹果、香蕉 和 橙子 -->
  
  <p>{{ $t('message.ordered', ['张三', '李四']) }}</p>
  <!-- 输出：第一是 张三，第二是 李四 -->
</template>
```

### 4.3 字面量插值

直接在消息中使用字面量。

```typescript
// 语言文件
{
  message: {
    literal: "{'{'} 这是花括号 {'}'}",
    special: "使用 {'@'} 符号和 {'|'} 管道符",
  }
}
```

### 4.4 链接消息（引用其他消息）

使用 `@:key` 语法引用其他翻译。

```typescript
// 语言文件
{
  common: {
    appName: 'MyApp',
    company: 'ABC公司',
  },
  message: {
    // 引用其他消息
    welcome: '欢迎使用 @:common.appName',
    footer: '@:common.appName 由 @:common.company 开发',
    
    // 带修饰符的引用
    upperName: '@.upper:common.appName',  // 转大写
    lowerName: '@.lower:common.appName',  // 转小写
    capitalName: '@.capitalize:common.appName',  // 首字母大写
  }
}
```

```vue
<template>
  <p>{{ $t('message.welcome') }}</p>
  <!-- 输出：欢迎使用 MyApp -->
  
  <p>{{ $t('message.upperName') }}</p>
  <!-- 输出：MYAPP -->
</template>
```

### 4.5 HTML 消息

```typescript
// 语言文件
{
  message: {
    terms: '请阅读我们的<a href="/terms">服务条款</a>',
    highlight: '这是<strong>重要</strong>信息',
  }
}
```

```vue
<template>
  <!-- 使用 v-html 渲染 HTML -->
  <p v-html="$t('message.terms')"></p>
  
  <!-- 或使用 i18n-t 组件（更安全） -->
  <i18n-t keypath="message.highlight" tag="p">
    <template #default="{ message }">
      <span v-html="message"></span>
    </template>
  </i18n-t>
</template>
```

> ⚠️ **安全警告**：使用 `v-html` 时要确保内容是可信的，避免 XSS 攻击。

### 4.6 自定义修饰符

```typescript
// src/i18n/index.ts
const i18n = createI18n({
  // ...其他配置
  modifiers: {
    // 自定义修饰符
    snakeCase: (str: string) => str.replace(/\s+/g, '_').toLowerCase(),
    reverse: (str: string) => str.split('').reverse().join(''),
  }
})
```

```typescript
// 语言文件
{
  message: {
    custom: '@.snakeCase:common.appName',  // 使用自定义修饰符
  }
}
```

---

## 5. 复数处理

不同语言有不同的复数规则。英语有单数和复数，而中文通常不区分，俄语有更复杂的复数形式。

### 5.1 基本复数

使用 `|` 分隔不同的复数形式。

```typescript
// 语言文件 - 英语
{
  message: {
    car: 'no cars | one car | {count} cars',
    apple: 'no apples | one apple | {n} apples',
  }
}

// 语言文件 - 中文（通常不需要复数）
{
  message: {
    car: '没有车 | {count} 辆车',
    apple: '没有苹果 | {n} 个苹果',
  }
}
```

```vue
<template>
  <p>{{ $t('message.car', 0) }}</p>
  <!-- 英语输出：no cars -->
  
  <p>{{ $t('message.car', 1) }}</p>
  <!-- 英语输出：one car -->
  
  <p>{{ $t('message.car', { count: 5 }) }}</p>
  <!-- 英语输出：5 cars -->
  
  <!-- 使用 $tc 函数（Legacy API） -->
  <p>{{ $tc('message.apple', 10) }}</p>
  <!-- 英语输出：10 apples -->
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// Composition API 中使用复数
const carMessage = t('message.car', 3)  // 3 cars
const carMessage2 = t('message.car', { count: 3 }, 3)  // 3 cars
</script>
```

### 5.2 命名复数形式

对于复杂的复数规则，可以使用命名形式。

```typescript
// 语言文件
{
  message: {
    items: {
      zero: '没有项目',
      one: '一个项目',
      two: '两个项目',
      few: '{count} 个项目（少量）',
      many: '{count} 个项目（大量）',
      other: '{count} 个项目',
    }
  }
}
```

### 5.3 自定义复数规则

```typescript
// src/i18n/index.ts
const i18n = createI18n({
  // ...其他配置
  pluralRules: {
    // 俄语复数规则
    'ru-RU': (choice: number, choicesLength: number) => {
      if (choice === 0) return 0
      
      const teen = choice > 10 && choice < 20
      const endsWithOne = choice % 10 === 1
      
      if (!teen && endsWithOne) return 1
      if (!teen && choice % 10 >= 2 && choice % 10 <= 4) return 2
      
      return choicesLength < 4 ? 2 : 3
    },
    
    // 中文（简化处理）
    'zh-CN': (choice: number) => {
      return choice === 0 ? 0 : 1
    }
  }
})
```

---

## 6. 日期时间格式化

### 6.1 配置日期时间格式

```typescript
// src/i18n/index.ts
const i18n = createI18n({
  // ...其他配置
  datetimeFormats: {
    'zh-CN': {
      short: {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
      },
      long: {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        weekday: 'long',
      },
      time: {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      },
      datetime: {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      },
    },
    'en-US': {
      short: {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      },
      long: {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        weekday: 'long',
      },
      time: {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
      },
      datetime: {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      },
    },
  },
})
```

### 6.2 使用日期时间格式化

```vue
<template>
  <div>
    <!-- 使用 $d 函数 -->
    <p>短格式：{{ $d(new Date(), 'short') }}</p>
    <!-- zh-CN: 2024/01/15 -->
    <!-- en-US: Jan 15, 2024 -->
    
    <p>长格式：{{ $d(new Date(), 'long') }}</p>
    <!-- zh-CN: 2024年1月15日星期一 -->
    <!-- en-US: Monday, January 15, 2024 -->
    
    <p>时间：{{ $d(new Date(), 'time') }}</p>
    <!-- zh-CN: 14:30:00 -->
    <!-- en-US: 02:30:00 PM -->
    
    <p>日期时间：{{ $d(new Date(), 'datetime') }}</p>
    <!-- zh-CN: 2024/01/15 14:30 -->
    <!-- en-US: Jan 15, 2024, 02:30 PM -->
    
    <!-- 指定语言 -->
    <p>{{ $d(new Date(), 'short', 'en-US') }}</p>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { d } = useI18n()

// 在脚本中使用
const formattedDate = d(new Date(), 'short')
const formattedTime = d(new Date(), 'time')
</script>
```

### 6.3 相对时间格式化

```typescript
// 使用 Intl.RelativeTimeFormat（原生 API）
function formatRelativeTime(date: Date, locale: string): string {
  const now = new Date()
  const diff = date.getTime() - now.getTime()
  const diffInSeconds = Math.floor(diff / 1000)
  const diffInMinutes = Math.floor(diffInSeconds / 60)
  const diffInHours = Math.floor(diffInMinutes / 60)
  const diffInDays = Math.floor(diffInHours / 24)
  
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  
  if (Math.abs(diffInDays) >= 1) {
    return rtf.format(diffInDays, 'day')
  } else if (Math.abs(diffInHours) >= 1) {
    return rtf.format(diffInHours, 'hour')
  } else if (Math.abs(diffInMinutes) >= 1) {
    return rtf.format(diffInMinutes, 'minute')
  } else {
    return rtf.format(diffInSeconds, 'second')
  }
}

// 使用示例
formatRelativeTime(new Date(Date.now() - 3600000), 'zh-CN')  // "1小时前"
formatRelativeTime(new Date(Date.now() + 86400000), 'zh-CN')  // "明天"
```

---

## 7. 数字格式化

### 7.1 配置数字格式

```typescript
// src/i18n/index.ts
const i18n = createI18n({
  // ...其他配置
  numberFormats: {
    'zh-CN': {
      currency: {
        style: 'currency',
        currency: 'CNY',
        currencyDisplay: 'symbol',
      },
      decimal: {
        style: 'decimal',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      },
      percent: {
        style: 'percent',
        minimumFractionDigits: 1,
      },
      compact: {
        notation: 'compact',
        compactDisplay: 'short',
      },
    },
    'en-US': {
      currency: {
        style: 'currency',
        currency: 'USD',
        currencyDisplay: 'symbol',
      },
      decimal: {
        style: 'decimal',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      },
      percent: {
        style: 'percent',
        minimumFractionDigits: 1,
      },
      compact: {
        notation: 'compact',
        compactDisplay: 'short',
      },
    },
    'ja-JP': {
      currency: {
        style: 'currency',
        currency: 'JPY',
        currencyDisplay: 'symbol',
      },
    },
  },
})
```

### 7.2 使用数字格式化

```vue
<template>
  <div>
    <!-- 使用 $n 函数 -->
    <p>货币：{{ $n(1234.56, 'currency') }}</p>
    <!-- zh-CN: ¥1,234.56 -->
    <!-- en-US: $1,234.56 -->
    <!-- ja-JP: ￥1,235 -->
    
    <p>小数：{{ $n(1234.5, 'decimal') }}</p>
    <!-- zh-CN: 1,234.50 -->
    <!-- en-US: 1,234.50 -->
    
    <p>百分比：{{ $n(0.856, 'percent') }}</p>
    <!-- zh-CN: 85.6% -->
    <!-- en-US: 85.6% -->
    
    <p>紧凑格式：{{ $n(1234567, 'compact') }}</p>
    <!-- zh-CN: 123万 -->
    <!-- en-US: 1.2M -->
    
    <!-- 指定语言 -->
    <p>{{ $n(1234.56, 'currency', 'ja-JP') }}</p>
    <!-- ￥1,235 -->
    
    <!-- 动态货币 -->
    <p>{{ $n(price, { style: 'currency', currency: userCurrency }) }}</p>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { n } = useI18n()

const price = 99.99
const userCurrency = 'EUR'

// 在脚本中使用
const formattedPrice = n(1234.56, 'currency')
const formattedPercent = n(0.5, 'percent')
</script>
```

### 7.3 自定义数字格式

```vue
<template>
  <!-- 内联格式选项 -->
  <p>{{ $n(1234567.89, {
    style: 'currency',
    currency: 'EUR',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }) }}</p>
  <!-- €1,234,568 -->
  
  <!-- 科学计数法 -->
  <p>{{ $n(1234567, { notation: 'scientific' }) }}</p>
  <!-- 1.235E6 -->
  
  <!-- 工程计数法 -->
  <p>{{ $n(1234567, { notation: 'engineering' }) }}</p>
  <!-- 1.235E6 -->
</template>
```

---

## 8. 组件插值

当翻译文本中需要插入 Vue 组件时，使用 `<i18n-t>` 组件。

### 8.1 基本组件插值

```typescript
// 语言文件
{
  message: {
    terms: '我已阅读并同意{terms}和{privacy}',
    greeting: '你好，{name}！欢迎来到{app}',
  }
}
```

```vue
<template>
  <i18n-t keypath="message.terms" tag="p">
    <template #terms>
      <a href="/terms" class="text-blue-500">服务条款</a>
    </template>
    <template #privacy>
      <a href="/privacy" class="text-blue-500">隐私政策</a>
    </template>
  </i18n-t>
  <!-- 输出：我已阅读并同意<a>服务条款</a>和<a>隐私政策</a> -->
  
  <i18n-t keypath="message.greeting" tag="div">
    <template #name>
      <strong>{{ username }}</strong>
    </template>
    <template #app>
      <span class="text-primary">MyApp</span>
    </template>
  </i18n-t>
</template>

<script setup lang="ts">
const username = '张三'
</script>
```

### 8.2 复数与组件插值结合

```typescript
// 语言文件
{
  message: {
    items: '没有项目 | 有 {count} 个项目 | 有 {count} 个项目',
    linkedItems: '没有{item} | 有一个{item} | 有 {count} 个{item}',
  }
}
```

```vue
<template>
  <i18n-t keypath="message.linkedItems" :plural="itemCount" tag="p">
    <template #item>
      <strong>任务</strong>
    </template>
    <template #count>
      <span class="text-red-500">{{ itemCount }}</span>
    </template>
  </i18n-t>
</template>

<script setup lang="ts">
const itemCount = 5
</script>
```

### 8.3 作用域插槽

```vue
<template>
  <i18n-t keypath="message.greeting" tag="p">
    <template #default="{ message }">
      <!-- message 是翻译后的完整文本 -->
      <span class="greeting">{{ message }}</span>
    </template>
  </i18n-t>
</template>
```

---

## 9. 语言切换

### 9.1 基本语言切换

```vue
<template>
  <div class="language-switcher">
    <!-- 下拉选择 -->
    <select v-model="locale" @change="changeLocale">
      <option value="zh-CN">简体中文</option>
      <option value="en-US">English</option>
      <option value="ja-JP">日本語</option>
    </select>
    
    <!-- 或者使用按钮 -->
    <div class="flex space-x-2">
      <button 
        v-for="lang in availableLocales" 
        :key="lang"
        :class="{ 'active': locale === lang }"
        @click="changeLocale(lang)"
      >
        {{ getLanguageName(lang) }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { locale, availableLocales } = useI18n()

// 语言名称映射
const languageNames: Record<string, string> = {
  'zh-CN': '简体中文',
  'en-US': 'English',
  'ja-JP': '日本語',
}

function getLanguageName(code: string): string {
  return languageNames[code] || code
}

function changeLocale(lang: string) {
  locale.value = lang
  
  // 保存到本地存储
  localStorage.setItem('locale', lang)
  
  // 更新 HTML lang 属性
  document.documentElement.lang = lang
  
  // 如果是 RTL 语言，更新方向
  const rtlLanguages = ['ar', 'he', 'fa']
  const isRTL = rtlLanguages.some(l => lang.startsWith(l))
  document.documentElement.dir = isRTL ? 'rtl' : 'ltr'
}
</script>

<style scoped>
.active {
  @apply bg-blue-500 text-white;
}
</style>
```

### 9.2 带图标的语言切换器

```vue
<template>
  <div class="relative">
    <button 
      @click="isOpen = !isOpen"
      class="flex items-center space-x-2 px-3 py-2 rounded-lg hover:bg-gray-100"
    >
      <span class="text-xl">{{ currentFlag }}</span>
      <span>{{ currentLanguageName }}</span>
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
      </svg>
    </button>
    
    <div 
      v-if="isOpen" 
      class="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border z-50"
    >
      <button
        v-for="lang in languages"
        :key="lang.code"
        @click="selectLanguage(lang.code)"
        class="w-full flex items-center space-x-3 px-4 py-2 hover:bg-gray-100 first:rounded-t-lg last:rounded-b-lg"
        :class="{ 'bg-blue-50': locale === lang.code }"
      >
        <span class="text-xl">{{ lang.flag }}</span>
        <span>{{ lang.name }}</span>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { locale } = useI18n()
const isOpen = ref(false)

const languages = [
  { code: 'zh-CN', name: '简体中文', flag: '🇨🇳' },
  { code: 'zh-TW', name: '繁體中文', flag: '🇹🇼' },
  { code: 'en-US', name: 'English', flag: '🇺🇸' },
  { code: 'ja-JP', name: '日本語', flag: '🇯🇵' },
  { code: 'ko-KR', name: '한국어', flag: '🇰🇷' },
]

const currentLanguage = computed(() => 
  languages.find(l => l.code === locale.value) || languages[0]
)

const currentFlag = computed(() => currentLanguage.value.flag)
const currentLanguageName = computed(() => currentLanguage.value.name)

function selectLanguage(code: string) {
  locale.value = code
  localStorage.setItem('locale', code)
  document.documentElement.lang = code
  isOpen.value = false
}
</script>
```


---

## 10. 懒加载与按需加载

对于大型应用，将所有语言包打包在一起会增加初始加载时间。使用懒加载可以按需加载语言包。

### 10.1 基本懒加载

```typescript
// src/i18n/index.ts
import { createI18n } from 'vue-i18n'

// 只加载默认语言
import zhCN from './locales/zh-CN'

const i18n = createI18n({
  legacy: false,
  locale: 'zh-CN',
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': zhCN,
  },
})

// 动态加载语言包
export async function loadLocaleMessages(locale: string) {
  // 如果已加载，直接返回
  if (i18n.global.availableLocales.includes(locale)) {
    return
  }
  
  // 动态导入语言包
  const messages = await import(`./locales/${locale}.ts`)
  
  // 设置语言包
  i18n.global.setLocaleMessage(locale, messages.default)
}

// 切换语言
export async function setLocale(locale: string) {
  // 加载语言包
  await loadLocaleMessages(locale)
  
  // 切换语言
  i18n.global.locale.value = locale
  
  // 保存设置
  localStorage.setItem('locale', locale)
  document.documentElement.lang = locale
}

export default i18n
```

### 10.2 使用 Vite 的动态导入

```typescript
// src/i18n/index.ts
import { createI18n, type I18n } from 'vue-i18n'

// 使用 Vite 的 glob 导入
const localeModules = import.meta.glob('./locales/*.ts')

async function loadLocaleMessages(i18n: I18n, locale: string) {
  const path = `./locales/${locale}.ts`
  
  if (localeModules[path]) {
    const messages = await localeModules[path]()
    i18n.global.setLocaleMessage(locale, (messages as any).default)
  }
}

export async function setupI18n() {
  const defaultLocale = localStorage.getItem('locale') || 'zh-CN'
  
  const i18n = createI18n({
    legacy: false,
    locale: defaultLocale,
    fallbackLocale: 'zh-CN',
    messages: {},
  })
  
  // 加载默认语言
  await loadLocaleMessages(i18n, defaultLocale)
  
  return i18n
}

// 导出切换语言函数
export async function changeLocale(i18n: I18n, locale: string) {
  if (!i18n.global.availableLocales.includes(locale)) {
    await loadLocaleMessages(i18n, locale)
  }
  
  i18n.global.locale.value = locale
  localStorage.setItem('locale', locale)
  document.documentElement.lang = locale
}
```

```typescript
// src/main.ts
import { createApp } from 'vue'
import App from './App.vue'
import { setupI18n } from './i18n'

async function bootstrap() {
  const app = createApp(App)
  
  // 异步设置 i18n
  const i18n = await setupI18n()
  app.use(i18n)
  
  app.mount('#app')
}

bootstrap()
```

### 10.3 按模块拆分语言包

对于大型应用，可以按功能模块拆分语言包。

```
src/i18n/
├── index.ts
└── locales/
    ├── zh-CN/
    │   ├── index.ts      # 汇总导出
    │   ├── common.ts     # 公共翻译
    │   ├── user.ts       # 用户模块
    │   ├── order.ts      # 订单模块
    │   └── product.ts    # 产品模块
    └── en-US/
        ├── index.ts
        ├── common.ts
        ├── user.ts
        ├── order.ts
        └── product.ts
```

```typescript
// src/i18n/locales/zh-CN/index.ts
import common from './common'
import user from './user'
import order from './order'
import product from './product'

export default {
  common,
  user,
  order,
  product,
}
```

```typescript
// src/i18n/locales/zh-CN/user.ts
export default {
  title: '用户管理',
  list: '用户列表',
  create: '创建用户',
  edit: '编辑用户',
  delete: '删除用户',
  fields: {
    username: '用户名',
    email: '邮箱',
    phone: '手机号',
    status: '状态',
  },
  status: {
    active: '启用',
    inactive: '禁用',
  },
}
```

### 10.4 路由级别懒加载

```typescript
// src/router/index.ts
import { createRouter, createWebHistory } from 'vue-router'
import { loadLocaleMessages } from '@/i18n'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/user',
      component: () => import('@/views/user/index.vue'),
      meta: {
        // 标记需要加载的语言模块
        i18nModules: ['user'],
      },
    },
    {
      path: '/order',
      component: () => import('@/views/order/index.vue'),
      meta: {
        i18nModules: ['order'],
      },
    },
  ],
})

// 路由守卫中加载语言模块
router.beforeEach(async (to, from, next) => {
  const modules = to.meta.i18nModules as string[] | undefined
  
  if (modules && modules.length > 0) {
    await Promise.all(modules.map(m => loadLocaleMessages(m)))
  }
  
  next()
})

export default router
```

---

## 11. 与 Vue Router 集成

### 11.1 URL 中包含语言参数

```typescript
// src/router/index.ts
import { createRouter, createWebHistory } from 'vue-router'
import i18n from '@/i18n'

const routes = [
  {
    path: '/:locale',
    children: [
      {
        path: '',
        name: 'home',
        component: () => import('@/views/Home.vue'),
      },
      {
        path: 'about',
        name: 'about',
        component: () => import('@/views/About.vue'),
      },
      {
        path: 'contact',
        name: 'contact',
        component: () => import('@/views/Contact.vue'),
      },
    ],
  },
  {
    // 重定向到默认语言
    path: '/',
    redirect: () => {
      const locale = localStorage.getItem('locale') || 'zh-CN'
      return `/${locale}`
    },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 支持的语言列表
const supportedLocales = ['zh-CN', 'en-US', 'ja-JP']

// 路由守卫：处理语言切换
router.beforeEach((to, from, next) => {
  const locale = to.params.locale as string
  
  // 检查是否是支持的语言
  if (!supportedLocales.includes(locale)) {
    // 重定向到默认语言
    return next(`/zh-CN${to.path}`)
  }
  
  // 切换语言
  if (i18n.global.locale.value !== locale) {
    i18n.global.locale.value = locale
    localStorage.setItem('locale', locale)
    document.documentElement.lang = locale
  }
  
  next()
})

export default router
```

### 11.2 语言切换时更新 URL

```vue
<template>
  <select v-model="currentLocale" @change="changeLocale">
    <option value="zh-CN">简体中文</option>
    <option value="en-US">English</option>
  </select>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

const router = useRouter()
const route = useRoute()
const { locale } = useI18n()

const currentLocale = computed({
  get: () => locale.value,
  set: (value) => {
    locale.value = value
  }
})

function changeLocale() {
  // 替换 URL 中的语言参数
  const newPath = route.fullPath.replace(
    /^\/[a-z]{2}-[A-Z]{2}/,
    `/${currentLocale.value}`
  )
  router.push(newPath)
}
</script>
```

### 11.3 路由元信息中的翻译

```typescript
// src/router/index.ts
const routes = [
  {
    path: '/user',
    name: 'user',
    component: () => import('@/views/User.vue'),
    meta: {
      titleKey: 'nav.user',  // 使用翻译 key
    },
  },
]

// 路由守卫：更新页面标题
router.afterEach((to) => {
  const titleKey = to.meta.titleKey as string
  if (titleKey) {
    document.title = i18n.global.t(titleKey) + ' - MyApp'
  }
})
```

---

## 12. 与 Pinia 集成

### 12.1 在 Store 中使用 i18n

```typescript
// src/stores/user.ts
import { defineStore } from 'pinia'
import { ref } from 'vue'
import i18n from '@/i18n'

export const useUserStore = defineStore('user', () => {
  const user = ref(null)
  const loading = ref(false)
  const error = ref('')
  
  async function login(credentials: { username: string; password: string }) {
    loading.value = true
    error.value = ''
    
    try {
      // 模拟登录请求
      const response = await fetch('/api/login', {
        method: 'POST',
        body: JSON.stringify(credentials),
      })
      
      if (!response.ok) {
        // 使用 i18n 翻译错误消息
        throw new Error(i18n.global.t('message.loginFailed'))
      }
      
      user.value = await response.json()
      
      // 返回成功消息
      return i18n.global.t('message.loginSuccess')
    } catch (e) {
      error.value = (e as Error).message
      throw e
    } finally {
      loading.value = false
    }
  }
  
  function logout() {
    user.value = null
    return i18n.global.t('message.logoutSuccess')
  }
  
  return {
    user,
    loading,
    error,
    login,
    logout,
  }
})
```

### 12.2 语言设置 Store

```typescript
// src/stores/locale.ts
import { defineStore } from 'pinia'
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

export const useLocaleStore = defineStore('locale', () => {
  const { locale, availableLocales } = useI18n()
  
  const currentLocale = ref(locale.value)
  
  // 语言配置
  const localeConfigs = {
    'zh-CN': {
      name: '简体中文',
      flag: '🇨🇳',
      dateFormat: 'YYYY年MM月DD日',
      currency: 'CNY',
    },
    'en-US': {
      name: 'English',
      flag: '🇺🇸',
      dateFormat: 'MM/DD/YYYY',
      currency: 'USD',
    },
    'ja-JP': {
      name: '日本語',
      flag: '🇯🇵',
      dateFormat: 'YYYY年MM月DD日',
      currency: 'JPY',
    },
  }
  
  // 获取当前语言配置
  const currentConfig = computed(() => 
    localeConfigs[currentLocale.value as keyof typeof localeConfigs]
  )
  
  // 切换语言
  function setLocale(newLocale: string) {
    if (availableLocales.includes(newLocale)) {
      currentLocale.value = newLocale
      locale.value = newLocale
      localStorage.setItem('locale', newLocale)
      document.documentElement.lang = newLocale
    }
  }
  
  // 初始化
  function initLocale() {
    const savedLocale = localStorage.getItem('locale')
    const browserLocale = navigator.language
    
    if (savedLocale && availableLocales.includes(savedLocale)) {
      setLocale(savedLocale)
    } else if (availableLocales.includes(browserLocale)) {
      setLocale(browserLocale)
    }
  }
  
  return {
    currentLocale,
    currentConfig,
    availableLocales,
    localeConfigs,
    setLocale,
    initLocale,
  }
})
```


---

## 13. TypeScript 支持

### 13.1 类型定义

```typescript
// src/i18n/types.ts

// 定义消息结构类型
export interface CommonMessages {
  confirm: string
  cancel: string
  save: string
  delete: string
  edit: string
  search: string
  loading: string
  noData: string
}

export interface NavMessages {
  home: string
  about: string
  contact: string
}

export interface UserMessages {
  login: string
  logout: string
  register: string
  username: string
  password: string
  email: string
}

export interface MessageMessages {
  welcome: string
  loginSuccess: string
  loginFailed: string
}

// 完整的消息类型
export interface LocaleMessages {
  common: CommonMessages
  nav: NavMessages
  user: UserMessages
  message: MessageMessages
}

// 支持的语言类型
export type SupportedLocale = 'zh-CN' | 'en-US' | 'ja-JP'
```

### 13.2 配置类型安全的 i18n

```typescript
// src/i18n/index.ts
import { createI18n } from 'vue-i18n'
import type { LocaleMessages, SupportedLocale } from './types'

import zhCN from './locales/zh-CN'
import enUS from './locales/en-US'

// 类型检查语言包
const messages: Record<SupportedLocale, LocaleMessages> = {
  'zh-CN': zhCN,
  'en-US': enUS,
}

const i18n = createI18n<[LocaleMessages], SupportedLocale>({
  legacy: false,
  locale: 'zh-CN',
  fallbackLocale: 'en-US',
  messages,
})

export default i18n
```

### 13.3 全局类型声明

```typescript
// src/vue-i18n.d.ts
import type { LocaleMessages } from '@/i18n/types'

declare module 'vue-i18n' {
  // 定义消息类型
  export interface DefineLocaleMessage extends LocaleMessages {}
  
  // 定义日期时间格式类型
  export interface DefineDateTimeFormat {
    short: {
      year: 'numeric'
      month: '2-digit'
      day: '2-digit'
    }
    long: {
      year: 'numeric'
      month: 'long'
      day: 'numeric'
      weekday: 'long'
    }
  }
  
  // 定义数字格式类型
  export interface DefineNumberFormat {
    currency: {
      style: 'currency'
      currency: string
    }
    decimal: {
      style: 'decimal'
      minimumFractionDigits: number
      maximumFractionDigits: number
    }
    percent: {
      style: 'percent'
    }
  }
}
```

### 13.4 使用类型安全的 useI18n

```vue
<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { LocaleMessages } from '@/i18n/types'

// 带类型的 useI18n
const { t, locale } = useI18n<{ message: LocaleMessages }>()

// t 函数现在有类型提示
const welcomeMsg = t('message.welcome', { name: 'John' })

// 错误：TypeScript 会提示 'message.nonExistent' 不存在
// const errorMsg = t('message.nonExistent')
</script>
```

### 13.5 创建类型安全的翻译 key

```typescript
// src/i18n/keys.ts

// 递归生成所有可能的 key 路径
type PathsToStringProps<T> = T extends string
  ? []
  : {
      [K in Extract<keyof T, string>]: [K, ...PathsToStringProps<T[K]>]
    }[Extract<keyof T, string>]

type Join<T extends string[], D extends string> = T extends []
  ? never
  : T extends [infer F]
  ? F
  : T extends [infer F, ...infer R]
  ? F extends string
    ? `${F}${D}${Join<Extract<R, string[]>, D>}`
    : never
  : string

// 生成翻译 key 类型
export type TranslationKey = Join<PathsToStringProps<LocaleMessages>, '.'>

// 使用示例
function translate(key: TranslationKey): string {
  return i18n.global.t(key)
}

// 正确
translate('common.confirm')
translate('message.welcome')

// 错误：TypeScript 会报错
// translate('invalid.key')
```

---

## 14. 最佳实践

### 14.1 语言文件组织

```
推荐的目录结构：

src/i18n/
├── index.ts              # i18n 实例和配置
├── types.ts              # TypeScript 类型定义
├── utils.ts              # 工具函数
└── locales/
    ├── zh-CN/
    │   ├── index.ts      # 汇总导出
    │   ├── common.ts     # 公共文本
    │   ├── validation.ts # 表单验证消息
    │   ├── error.ts      # 错误消息
    │   └── modules/      # 按功能模块
    │       ├── user.ts
    │       ├── order.ts
    │       └── product.ts
    └── en-US/
        └── ...（相同结构）
```

### 14.2 翻译 Key 命名规范

```typescript
// ✅ 好的命名
{
  // 使用模块.功能.具体描述 的层级结构
  user: {
    list: {
      title: '用户列表',
      empty: '暂无用户',
      loading: '加载用户中...',
    },
    form: {
      username: '用户名',
      usernamePlaceholder: '请输入用户名',
      usernameRequired: '用户名不能为空',
    },
    action: {
      create: '创建用户',
      edit: '编辑用户',
      delete: '删除用户',
      deleteConfirm: '确定要删除该用户吗？',
    },
  },
}

// ❌ 不好的命名
{
  // 太扁平，难以管理
  userListTitle: '用户列表',
  userListEmpty: '暂无用户',
  
  // 命名不一致
  user_name: '用户名',
  userName: '用户名',
  
  // 含义不清
  text1: '确定',
  btn1: '取消',
}
```

### 14.3 处理动态内容

```typescript
// 语言文件
{
  message: {
    // 使用插值而非拼接
    greeting: '你好，{name}！',
    
    // 复数处理
    items: '没有项目 | {count} 个项目',
    
    // 带 HTML 的消息（谨慎使用）
    terms: '请阅读{link}',
  }
}
```

```vue
<template>
  <!-- ✅ 好的做法：使用插值 -->
  <p>{{ $t('message.greeting', { name: username }) }}</p>
  
  <!-- ❌ 不好的做法：字符串拼接 -->
  <p>{{ $t('message.hello') + username }}</p>
  
  <!-- ✅ 好的做法：使用组件插值处理 HTML -->
  <i18n-t keypath="message.terms" tag="p">
    <template #link>
      <a href="/terms">{{ $t('common.termsOfService') }}</a>
    </template>
  </i18n-t>
</template>
```

### 14.4 表单验证消息国际化

```typescript
// src/i18n/locales/zh-CN/validation.ts
export default {
  required: '{field}不能为空',
  email: '请输入有效的邮箱地址',
  minLength: '{field}至少需要{min}个字符',
  maxLength: '{field}不能超过{max}个字符',
  pattern: '{field}格式不正确',
  confirmed: '两次输入不一致',
  numeric: '{field}必须是数字',
  between: '{field}必须在{min}和{max}之间',
}
```

```typescript
// 与 VeeValidate 集成
import { configure } from 'vee-validate'
import i18n from '@/i18n'

configure({
  generateMessage: (context) => {
    const { field, rule } = context
    const fieldName = i18n.global.t(`fields.${field}`)
    
    return i18n.global.t(`validation.${rule?.name}`, {
      field: fieldName,
      ...rule?.params,
    })
  },
})
```

### 14.5 SEO 优化

```vue
<!-- 使用 @vueuse/head 或 vue-meta -->
<script setup lang="ts">
import { useHead } from '@vueuse/head'
import { useI18n } from 'vue-i18n'
import { computed } from 'vue'

const { t, locale } = useI18n()

useHead({
  title: computed(() => t('page.home.title')),
  meta: [
    {
      name: 'description',
      content: computed(() => t('page.home.description')),
    },
  ],
  htmlAttrs: {
    lang: computed(() => locale.value),
  },
  link: [
    // 添加 hreflang 标签
    { rel: 'alternate', hreflang: 'zh-CN', href: 'https://example.com/zh-CN/' },
    { rel: 'alternate', hreflang: 'en-US', href: 'https://example.com/en-US/' },
    { rel: 'alternate', hreflang: 'x-default', href: 'https://example.com/' },
  ],
})
</script>
```

### 14.6 RTL 语言支持

```typescript
// src/i18n/index.ts
const rtlLocales = ['ar-SA', 'he-IL', 'fa-IR']

export function isRTL(locale: string): boolean {
  return rtlLocales.some(l => locale.startsWith(l.split('-')[0]))
}

// 切换语言时更新方向
export function setLocale(locale: string) {
  i18n.global.locale.value = locale
  document.documentElement.lang = locale
  document.documentElement.dir = isRTL(locale) ? 'rtl' : 'ltr'
}
```

```css
/* 支持 RTL 的样式 */
.container {
  /* 使用逻辑属性 */
  margin-inline-start: 1rem;  /* 替代 margin-left */
  margin-inline-end: 1rem;    /* 替代 margin-right */
  padding-inline: 1rem;       /* 替代 padding-left/right */
}

/* 或使用 Tailwind CSS */
/* ms-4 = margin-inline-start, me-4 = margin-inline-end */
```

---

## 15. 常见错误与解决方案

### 15.1 翻译不生效

**问题：使用 `$t()` 但显示的是 key 而非翻译文本**

```vue
<!-- ❌ 问题 -->
<p>{{ $t('message.hello') }}</p>
<!-- 显示：message.hello -->
```

**原因与解决：**

```typescript
// 原因1：key 不存在
// 检查语言文件中是否有对应的 key
{
  message: {
    hello: '你好',  // 确保 key 存在
  }
}

// 原因2：语言包未正确加载
// 检查 i18n 配置
const i18n = createI18n({
  messages: {
    'zh-CN': zhCN,  // 确保语言包已导入
  },
})

// 原因3：使用了错误的 locale
console.log(i18n.global.locale.value)  // 检查当前语言

// 原因4：嵌套 key 路径错误
// 语言文件
{
  user: {
    profile: {
      name: '姓名'
    }
  }
}
// 正确：$t('user.profile.name')
// 错误：$t('user.name')
```

### 15.2 响应式问题

**问题：切换语言后，某些地方的翻译没有更新**

```typescript
// ❌ 问题：在 setup 外部使用 t 函数
const title = i18n.global.t('page.title')  // 非响应式

export default {
  data() {
    return {
      title,  // 切换语言后不会更新
    }
  }
}
```

**解决方案：**

```vue
<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// ✅ 使用 computed 保持响应式
const title = computed(() => t('page.title'))
</script>

<template>
  <!-- ✅ 直接在模板中使用 $t -->
  <h1>{{ $t('page.title') }}</h1>
  
  <!-- ✅ 使用 computed -->
  <h1>{{ title }}</h1>
</template>
```


### 15.3 Legacy API vs Composition API

**问题：混用两种 API 导致错误**

```typescript
// ❌ 错误：legacy: false 时使用 $tc
// $tc 是 Legacy API 的复数函数
<p>{{ $tc('message.items', 5) }}</p>

// ✅ 正确：Composition API 中使用 t 函数处理复数
<p>{{ $t('message.items', 5) }}</p>
<p>{{ $t('message.items', { count: 5 }, 5) }}</p>
```

```typescript
// i18n 配置
const i18n = createI18n({
  legacy: false,  // 使用 Composition API
  // ...
})

// Legacy API (legacy: true) 的函数：
// $t, $tc, $te, $d, $n, $tm

// Composition API (legacy: false) 的函数：
// t, d, n, tm, te (通过 useI18n 获取)
```

### 15.4 TypeScript 类型错误

**问题：`$t` 函数没有类型提示**

```typescript
// ❌ 问题
const msg = this.$t('message.hello')  // 类型为 any
```

**解决方案：**

```typescript
// 1. 创建类型声明文件
// src/shims-vue-i18n.d.ts
import type { LocaleMessages } from '@/i18n/types'

declare module 'vue-i18n' {
  export interface DefineLocaleMessage extends LocaleMessages {}
}

// 2. 在 tsconfig.json 中包含类型文件
{
  "include": [
    "src/**/*.ts",
    "src/**/*.d.ts",
    "src/**/*.vue"
  ]
}

// 3. 使用 useI18n 时指定类型
const { t } = useI18n<{ message: LocaleMessages }>()
```

### 15.5 异步组件中的 i18n

**问题：异步组件中 `useI18n` 报错**

```typescript
// ❌ 问题：在异步组件的顶层使用 useI18n
const AsyncComponent = defineAsyncComponent(async () => {
  const { t } = useI18n()  // 可能报错
  // ...
})
```

**解决方案：**

```vue
<!-- ✅ 在组件内部使用 -->
<script setup lang="ts">
import { useI18n } from 'vue-i18n'

// 在 setup 中使用是安全的
const { t } = useI18n()
</script>
```

```typescript
// 或者使用全局 i18n 实例
import i18n from '@/i18n'

const message = i18n.global.t('message.hello')
```

### 15.6 SSR/SSG 问题

**问题：服务端渲染时语言不正确**

```typescript
// ❌ 问题：服务端无法访问 localStorage
const locale = localStorage.getItem('locale')  // 服务端报错
```

**解决方案：**

```typescript
// src/i18n/index.ts
export function getDefaultLocale(req?: Request): string {
  // 服务端：从请求头获取
  if (typeof window === 'undefined' && req) {
    const acceptLanguage = req.headers.get('accept-language')
    if (acceptLanguage?.startsWith('zh')) return 'zh-CN'
    return 'en-US'
  }
  
  // 客户端：从 localStorage 获取
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem('locale')
    if (saved) return saved
    
    const browserLang = navigator.language
    if (browserLang.startsWith('zh')) return 'zh-CN'
  }
  
  return 'en-US'
}
```

### 15.7 动态 key 问题

**问题：动态拼接的 key 没有类型检查**

```vue
<template>
  <!-- ❌ 动态 key 无法进行类型检查 -->
  <p>{{ $t(`status.${item.status}`) }}</p>
</template>
```

**解决方案：**

```typescript
// 方案1：使用映射对象
const statusMap: Record<string, string> = {
  pending: 'status.pending',
  active: 'status.active',
  completed: 'status.completed',
}

const statusText = computed(() => t(statusMap[item.status]))

// 方案2：使用类型安全的函数
function getStatusText(status: 'pending' | 'active' | 'completed'): string {
  const keys = {
    pending: 'status.pending',
    active: 'status.active',
    completed: 'status.completed',
  } as const
  
  return t(keys[status])
}
```

### 15.8 性能问题

**问题：大量翻译导致性能下降**

```typescript
// ❌ 问题：在循环中频繁调用 t 函数
<template>
  <div v-for="item in largeList" :key="item.id">
    <p>{{ $t('item.name') }}: {{ item.name }}</p>
    <p>{{ $t('item.price') }}: {{ item.price }}</p>
    <p>{{ $t('item.status') }}: {{ $t(`status.${item.status}`) }}</p>
  </div>
</template>
```

**解决方案：**

```vue
<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// ✅ 预先计算静态翻译
const labels = computed(() => ({
  name: t('item.name'),
  price: t('item.price'),
  status: t('item.status'),
}))

// ✅ 预先计算状态映射
const statusTexts = computed(() => ({
  pending: t('status.pending'),
  active: t('status.active'),
  completed: t('status.completed'),
}))
</script>

<template>
  <div v-for="item in largeList" :key="item.id">
    <p>{{ labels.name }}: {{ item.name }}</p>
    <p>{{ labels.price }}: {{ item.price }}</p>
    <p>{{ labels.status }}: {{ statusTexts[item.status] }}</p>
  </div>
</template>
```

### 15.9 缺失翻译处理

**问题：某些 key 没有翻译时显示 key 本身**

```typescript
// 配置缺失翻译处理
const i18n = createI18n({
  // ...
  
  // 方案1：使用回退语言
  fallbackLocale: 'en-US',
  
  // 方案2：自定义缺失处理
  missing: (locale, key, vm, values) => {
    // 开发环境警告
    if (process.env.NODE_ENV === 'development') {
      console.warn(`Missing translation: [${locale}] ${key}`)
    }
    
    // 返回 key 的最后一部分作为默认值
    // 'user.profile.name' -> 'name'
    return key.split('.').pop() || key
  },
  
  // 方案3：静默处理
  silentTranslationWarn: true,
  silentFallbackWarn: true,
})
```

### 15.10 日期时间格式化问题

**问题：日期格式化结果不符合预期**

```typescript
// ❌ 问题：时区问题
const date = new Date('2024-01-15')  // 可能被解析为 UTC
$d(date, 'short')  // 可能显示前一天

// ✅ 解决：明确指定时间
const date = new Date('2024-01-15T00:00:00')  // 本地时间
const date = new Date(2024, 0, 15)  // 使用构造函数

// ✅ 或者使用 dayjs/date-fns 处理
import dayjs from 'dayjs'
const date = dayjs('2024-01-15').toDate()
```

---

## 附录：常用 API 速查

### useI18n 返回值

| 属性/方法 | 说明 |
|----------|------|
| `t(key, values?)` | 翻译函数 |
| `d(value, format?)` | 日期格式化 |
| `n(value, format?)` | 数字格式化 |
| `locale` | 当前语言（ref） |
| `availableLocales` | 可用语言列表 |
| `tm(key)` | 获取翻译消息对象 |
| `te(key)` | 检查 key 是否存在 |

### 模板中的全局函数

| 函数 | 说明 |
|------|------|
| `$t(key, values?)` | 翻译 |
| `$d(value, format?)` | 日期格式化 |
| `$n(value, format?)` | 数字格式化 |
| `$tm(key)` | 获取翻译消息对象 |
| `$te(key)` | 检查 key 是否存在 |

### 指令

| 指令 | 说明 |
|------|------|
| `v-t="'key'"` | 翻译并设置 textContent |
| `v-t="{ path: 'key', args: {} }"` | 带参数的翻译 |

### 组件

| 组件 | 说明 |
|------|------|
| `<i18n-t>` | 组件插值翻译 |
| `<i18n-d>` | 日期格式化组件 |
| `<i18n-n>` | 数字格式化组件 |

---

> 📝 **笔记说明**
> - 本笔记基于 Vue 3 + Vue I18n v9 编写
> - 建议配合官方文档学习：https://vue-i18n.intlify.dev/
> - 推荐使用 VS Code 插件 "i18n Ally" 进行翻译管理

---

*最后更新：2024年*
