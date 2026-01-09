

> Uni-app 是一个使用 Vue.js 开发所有前端应用的框架，一套代码可编译到 iOS、Android、Web、小程序等多个平台
> 本笔记基于 Vue 3 + Composition API + TypeScript

---

## 目录

1. [基础概念](#1-基础概念)
2. [项目搭建](#2-项目搭建)
3. [项目结构](#3-项目结构)
4. [页面与路由](#4-页面与路由)
5. [组件基础](#5-组件基础)
6. [内置组件](#6-内置组件)
7. [样式与布局](#7-样式与布局)
8. [生命周期](#8-生命周期)
9. [数据请求](#9-数据请求)
10. [状态管理](#10-状态管理)
11. [本地存储](#11-本地存储)
12. [条件编译](#12-条件编译)
13. [原生能力](#13-原生能力)
14. [插件与扩展](#14-插件与扩展)
15. [性能优化](#15-性能优化)
16. [打包发布](#16-打包发布)
17. [常见错误与解决方案](#17-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Uni-app？

Uni-app 是 DCloud 公司推出的跨平台开发框架，核心理念是"一次开发，多端发布"：

- **跨平台能力**：一套代码可以编译到 iOS、Android、H5、以及各种小程序（微信/支付宝/百度/字节跳动/QQ/快手/京东/飞书）
- **基于 Vue.js**：使用 Vue 语法开发，学习成本低
- **丰富的生态**：拥有插件市场、云开发等配套服务
- **性能优秀**：App 端使用原生渲染，性能接近原生应用

### 1.2 Uni-app 的优势

```
┌─────────────────────────────────────────────────────────────┐
│                    Uni-app 跨端能力                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│                      一套代码                                │
│                         │                                   │
│         ┌───────────────┼───────────────┐                   │
│         │               │               │                   │
│         ▼               ▼               ▼                   │
│    ┌─────────┐    ┌─────────┐    ┌─────────┐               │
│    │   App   │    │   Web   │    │  小程序  │               │
│    │ iOS/安卓│    │   H5    │    │ 微信/支付宝│              │
│    └─────────┘    └─────────┘    └─────────┘               │
│                                                             │
│  优势：                                                      │
│  ✅ 开发效率高，一套代码多端运行                              │
│  ✅ 学习成本低，Vue 开发者可快速上手                          │
│  ✅ 社区活跃，插件丰富                                       │
│  ✅ 官方维护，持续更新                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 技术架构

Uni-app 在不同平台的渲染方式：

| 平台 | 渲染方式 | 说明 |
|------|---------|------|
| App (iOS/Android) | 原生渲染 + Webview | 使用 weex 改进的原生渲染引擎 |
| H5 | 浏览器渲染 | 标准 Web 技术 |
| 微信小程序 | 小程序渲染 | 编译为微信小程序代码 |
| 其他小程序 | 各平台渲染 | 编译为对应平台代码 |

### 1.4 开发方式选择

Uni-app 支持两种开发方式：

1. **HBuilderX（推荐新手）**
   - DCloud 官方 IDE
   - 内置 uni-app 项目模板
   - 可视化创建项目
   - 真机调试方便

2. **CLI 命令行（推荐团队）**
   - 使用 Vue CLI 或 Vite 创建
   - 更灵活的工程化配置
   - 适合团队协作

---

## 2. 项目搭建

### 2.1 使用 HBuilderX 创建

1. 下载安装 [HBuilderX](https://www.dcloud.io/hbuilderx.html)
2. 文件 → 新建 → 项目
3. 选择 uni-app 项目模板
4. 选择 Vue 3 版本

### 2.2 使用 CLI 创建（Vue 3 + Vite）

```bash
# 使用 npx 创建项目
npx degit dcloudio/uni-preset-vue#vite-ts my-uni-app

# 进入项目目录
cd my-uni-app

# 安装依赖
npm install

# 运行到 H5
npm run dev:h5

# 运行到微信小程序
npm run dev:mp-weixin

# 运行到 App
npm run dev:app
```

### 2.3 项目配置文件

```json
// package.json
{
  "name": "my-uni-app",
  "version": "1.0.0",
  "scripts": {
    "dev:app": "uni -p app",
    "dev:h5": "uni -p h5",
    "dev:mp-weixin": "uni -p mp-weixin",
    "dev:mp-alipay": "uni -p mp-alipay",
    "build:app": "uni build -p app",
    "build:h5": "uni build -p h5",
    "build:mp-weixin": "uni build -p mp-weixin"
  },
  "dependencies": {
    "@dcloudio/uni-app": "3.0.0-alpha-3081220230802001",
    "@dcloudio/uni-components": "3.0.0-alpha-3081220230802001",
    "@dcloudio/uni-h5": "3.0.0-alpha-3081220230802001",
    "vue": "^3.3.4",
    "pinia": "^2.1.6"
  },
  "devDependencies": {
    "@dcloudio/uni-automator": "3.0.0-alpha-3081220230802001",
    "@dcloudio/vite-plugin-uni": "3.0.0-alpha-3081220230802001",
    "typescript": "^5.1.6",
    "vite": "^4.4.9"
  }
}
```

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import uni from '@dcloudio/vite-plugin-uni'

export default defineConfig({
  plugins: [uni()],
  // 自定义配置
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  }
})
```

---

## 3. 项目结构

### 3.1 标准目录结构

```
my-uni-app/
├── src/
│   ├── pages/                    # 页面目录
│   │   ├── index/
│   │   │   └── index.vue         # 首页
│   │   ├── user/
│   │   │   └── index.vue         # 用户页
│   │   └── detail/
│   │       └── index.vue         # 详情页
│   ├── components/               # 组件目录
│   │   ├── NavBar.vue
│   │   └── TabBar.vue
│   ├── static/                   # 静态资源（不会被编译）
│   │   ├── images/
│   │   └── fonts/
│   ├── store/                    # 状态管理
│   │   ├── index.ts
│   │   └── modules/
│   ├── utils/                    # 工具函数
│   │   ├── request.ts
│   │   └── storage.ts
│   ├── api/                      # API 接口
│   │   └── user.ts
│   ├── types/                    # TypeScript 类型
│   │   └── index.d.ts
│   ├── App.vue                   # 应用入口组件
│   ├── main.ts                   # 应用入口文件
│   ├── pages.json                # 页面配置（重要！）
│   ├── manifest.json             # 应用配置
│   └── uni.scss                  # 全局样式变量
├── dist/                         # 编译输出目录
├── node_modules/
├── package.json
├── tsconfig.json
└── vite.config.ts
```

### 3.2 pages.json 配置详解

`pages.json` 是 uni-app 最重要的配置文件，用于配置页面路由、导航栏、tabBar 等：

```json
{
  // 全局配置
  "globalStyle": {
    "navigationBarTextStyle": "black",
    "navigationBarTitleText": "我的应用",
    "navigationBarBackgroundColor": "#F8F8F8",
    "backgroundColor": "#F8F8F8",
    "backgroundTextStyle": "dark",
    "enablePullDownRefresh": false,
    "onReachBottomDistance": 50
  },
  
  // 页面配置（数组第一项为首页）
  "pages": [
    {
      "path": "pages/index/index",
      "style": {
        "navigationBarTitleText": "首页",
        "enablePullDownRefresh": true
      }
    },
    {
      "path": "pages/user/index",
      "style": {
        "navigationBarTitleText": "我的",
        "navigationStyle": "custom"
      }
    },
    {
      "path": "pages/detail/index",
      "style": {
        "navigationBarTitleText": "详情"
      }
    }
  ],
  
  // 分包配置（优化小程序包体积）
  "subPackages": [
    {
      "root": "pages-sub",
      "pages": [
        {
          "path": "order/index",
          "style": {
            "navigationBarTitleText": "订单"
          }
        }
      ]
    }
  ],
  
  // tabBar 配置
  "tabBar": {
    "color": "#999999",
    "selectedColor": "#007AFF",
    "backgroundColor": "#FFFFFF",
    "borderStyle": "black",
    "list": [
      {
        "pagePath": "pages/index/index",
        "text": "首页",
        "iconPath": "static/tab/home.png",
        "selectedIconPath": "static/tab/home-active.png"
      },
      {
        "pagePath": "pages/user/index",
        "text": "我的",
        "iconPath": "static/tab/user.png",
        "selectedIconPath": "static/tab/user-active.png"
      }
    ]
  },
  
  // easycom 组件自动导入
  "easycom": {
    "autoscan": true,
    "custom": {
      "^uni-(.*)": "@dcloudio/uni-ui/lib/uni-$1/uni-$1.vue"
    }
  }
}
```

### 3.3 manifest.json 应用配置

```json
{
  "name": "我的应用",
  "appid": "__UNI__XXXXXX",
  "description": "应用描述",
  "versionName": "1.0.0",
  "versionCode": "100",
  
  // H5 配置
  "h5": {
    "title": "我的应用",
    "router": {
      "mode": "history",
      "base": "/"
    },
    "devServer": {
      "port": 8080,
      "proxy": {
        "/api": {
          "target": "http://localhost:3000",
          "changeOrigin": true
        }
      }
    }
  },
  
  // 微信小程序配置
  "mp-weixin": {
    "appid": "wx1234567890",
    "setting": {
      "urlCheck": false,
      "es6": true,
      "minified": true
    },
    "usingComponents": true
  },
  
  // App 配置
  "app-plus": {
    "distribute": {
      "android": {
        "permissions": [
          "<uses-permission android:name=\"android.permission.CAMERA\"/>",
          "<uses-permission android:name=\"android.permission.READ_EXTERNAL_STORAGE\"/>"
        ]
      },
      "ios": {
        "UIBackgroundModes": ["audio"]
      }
    },
    "modules": {
      "OAuth": {},
      "Payment": {},
      "Push": {}
    }
  }
}
```

---

## 4. 页面与路由

### 4.1 页面文件结构

```vue
<!-- pages/index/index.vue -->
<template>
  <view class="container">
    <text class="title">{{ message }}</text>
    <button @click="goToDetail">跳转详情</button>
  </view>
</template>

<script setup lang="ts">
import { ref } from 'vue'

// 响应式数据
const message = ref('Hello Uni-app!')

// 页面跳转
const goToDetail = () => {
  uni.navigateTo({
    url: '/pages/detail/index?id=123'
  })
}
</script>

<style lang="scss" scoped>
.container {
  padding: 20rpx;
}

.title {
  font-size: 32rpx;
  color: #333;
}
</style>
```

### 4.2 路由跳转方式

```typescript
// 1. navigateTo - 保留当前页面，跳转到新页面（可返回）
uni.navigateTo({
  url: '/pages/detail/index?id=123&name=test',
  success: () => console.log('跳转成功'),
  fail: (err) => console.log('跳转失败', err)
})

// 2. redirectTo - 关闭当前页面，跳转到新页面（不可返回）
uni.redirectTo({
  url: '/pages/login/index'
})

// 3. reLaunch - 关闭所有页面，打开新页面
uni.reLaunch({
  url: '/pages/index/index'
})

// 4. switchTab - 跳转到 tabBar 页面（关闭其他非 tabBar 页面）
uni.switchTab({
  url: '/pages/user/index'
})

// 5. navigateBack - 返回上一页或多级页面
uni.navigateBack({
  delta: 1  // 返回的页面数，默认 1
})

// 6. 使用 EventChannel 传递数据（推荐复杂数据）
uni.navigateTo({
  url: '/pages/detail/index',
  success: (res) => {
    // 向被打开页面传送数据
    res.eventChannel.emit('acceptData', { data: 'test' })
  }
})
```

### 4.3 接收路由参数

```vue
<!-- pages/detail/index.vue -->
<script setup lang="ts">
import { onLoad } from '@dcloudio/uni-app'
import { ref } from 'vue'

const id = ref('')
const name = ref('')

// 方式1：通过 onLoad 获取参数
onLoad((options) => {
  console.log('页面参数:', options)
  id.value = options?.id || ''
  name.value = options?.name || ''
})

// 方式2：通过 EventChannel 接收数据
onLoad(() => {
  const eventChannel = getCurrentPages().pop()?.getOpenerEventChannel?.()
  eventChannel?.on('acceptData', (data: any) => {
    console.log('接收到的数据:', data)
  })
})
</script>
```

### 4.4 页面栈管理

```typescript
// 获取当前页面栈
const pages = getCurrentPages()
console.log('页面栈长度:', pages.length)
console.log('当前页面:', pages[pages.length - 1])

// 获取上一个页面实例（用于修改上一页数据）
const prevPage = pages[pages.length - 2]
if (prevPage) {
  // Vue 3 中需要通过 $vm 访问
  prevPage.$vm?.updateData?.()
}

// 页面间通信 - 使用全局事件
// 发送事件
uni.$emit('refreshList', { type: 'add' })

// 监听事件
uni.$on('refreshList', (data) => {
  console.log('收到刷新事件:', data)
  loadList()
})

// 移除事件监听（页面卸载时）
import { onUnload } from '@dcloudio/uni-app'
onUnload(() => {
  uni.$off('refreshList')
})
```


---

## 5. 组件基础

### 5.1 组件定义与使用

```vue
<!-- components/MyButton.vue -->
<template>
  <button 
    class="my-button" 
    :class="[type, { disabled }]"
    :disabled="disabled"
    @click="handleClick"
  >
    <slot>默认按钮</slot>
  </button>
</template>

<script setup lang="ts">
// 定义 Props
interface Props {
  type?: 'primary' | 'success' | 'warning' | 'danger'
  disabled?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  type: 'primary',
  disabled: false
})

// 定义 Emits
const emit = defineEmits<{
  click: [event: Event]
}>()

const handleClick = (event: Event) => {
  if (!props.disabled) {
    emit('click', event)
  }
}
</script>

<style lang="scss" scoped>
.my-button {
  padding: 20rpx 40rpx;
  border-radius: 8rpx;
  font-size: 28rpx;
  
  &.primary {
    background-color: #007AFF;
    color: #fff;
  }
  
  &.success {
    background-color: #4CD964;
    color: #fff;
  }
  
  &.disabled {
    opacity: 0.5;
  }
}
</style>
```

```vue
<!-- 使用组件 -->
<template>
  <view>
    <MyButton type="primary" @click="handleClick">
      点击我
    </MyButton>
    <MyButton type="success" :disabled="isLoading">
      {{ isLoading ? '加载中...' : '提交' }}
    </MyButton>
  </view>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import MyButton from '@/components/MyButton.vue'

const isLoading = ref(false)

const handleClick = () => {
  console.log('按钮被点击')
}
</script>
```

### 5.2 easycom 自动导入

在 `pages.json` 中配置 easycom 后，组件可以自动导入：

```json
// pages.json
{
  "easycom": {
    "autoscan": true,
    "custom": {
      // 自定义组件匹配规则
      "^my-(.*)": "@/components/my-$1.vue",
      // uni-ui 组件
      "^uni-(.*)": "@dcloudio/uni-ui/lib/uni-$1/uni-$1.vue"
    }
  }
}
```

```vue
<!-- 无需手动 import，直接使用 -->
<template>
  <view>
    <my-button>自动导入的按钮</my-button>
    <uni-icons type="star" size="24"></uni-icons>
  </view>
</template>
```

### 5.3 组件通信

```vue
<!-- 父组件 -->
<template>
  <view>
    <!-- Props 传递 -->
    <ChildComponent 
      :message="parentMessage"
      :list="dataList"
      @update="handleUpdate"
      ref="childRef"
    />
    <button @click="callChildMethod">调用子组件方法</button>
  </view>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import ChildComponent from './ChildComponent.vue'

const parentMessage = ref('来自父组件的消息')
const dataList = ref([1, 2, 3])
const childRef = ref<InstanceType<typeof ChildComponent>>()

const handleUpdate = (value: string) => {
  console.log('子组件传来的值:', value)
}

const callChildMethod = () => {
  childRef.value?.doSomething()
}
</script>
```

```vue
<!-- 子组件 ChildComponent.vue -->
<template>
  <view>
    <text>{{ message }}</text>
    <button @click="sendToParent">发送给父组件</button>
  </view>
</template>

<script setup lang="ts">
interface Props {
  message: string
  list: number[]
}

const props = defineProps<Props>()
const emit = defineEmits<{
  update: [value: string]
}>()

const sendToParent = () => {
  emit('update', '子组件的数据')
}

// 暴露方法给父组件
const doSomething = () => {
  console.log('子组件方法被调用')
}

defineExpose({
  doSomething
})
</script>
```

### 5.4 Provide / Inject

```vue
<!-- 祖先组件 -->
<script setup lang="ts">
import { provide, ref } from 'vue'

const theme = ref('dark')
const updateTheme = (newTheme: string) => {
  theme.value = newTheme
}

// 提供数据和方法
provide('theme', theme)
provide('updateTheme', updateTheme)
</script>
```

```vue
<!-- 后代组件（任意层级） -->
<script setup lang="ts">
import { inject, type Ref } from 'vue'

// 注入数据
const theme = inject<Ref<string>>('theme')
const updateTheme = inject<(theme: string) => void>('updateTheme')

const toggleTheme = () => {
  updateTheme?.(theme?.value === 'dark' ? 'light' : 'dark')
}
</script>
```

---

## 6. 内置组件

### 6.1 视图容器组件

```vue
<template>
  <!-- view - 视图容器，类似 div -->
  <view class="container">
    <text>基础容器</text>
  </view>
  
  <!-- scroll-view - 可滚动视图 -->
  <scroll-view 
    scroll-y 
    class="scroll-container"
    :scroll-top="scrollTop"
    @scroll="onScroll"
    @scrolltolower="loadMore"
    refresher-enabled
    :refresher-triggered="isRefreshing"
    @refresherrefresh="onRefresh"
  >
    <view v-for="item in list" :key="item.id">
      {{ item.name }}
    </view>
  </scroll-view>
  
  <!-- swiper - 轮播图 -->
  <swiper 
    class="banner"
    :indicator-dots="true"
    :autoplay="true"
    :interval="3000"
    :circular="true"
    @change="onSwiperChange"
  >
    <swiper-item v-for="item in banners" :key="item.id">
      <image :src="item.image" mode="aspectFill" />
    </swiper-item>
  </swiper>
  
  <!-- movable-area + movable-view - 可拖动区域 -->
  <movable-area class="movable-area">
    <movable-view 
      class="movable-view"
      direction="all"
      :x="x"
      :y="y"
    >
      拖动我
    </movable-view>
  </movable-area>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const scrollTop = ref(0)
const isRefreshing = ref(false)
const list = ref([])
const banners = ref([])
const x = ref(0)
const y = ref(0)

const onScroll = (e: any) => {
  console.log('滚动位置:', e.detail.scrollTop)
}

const loadMore = () => {
  console.log('触底加载更多')
}

const onRefresh = async () => {
  isRefreshing.value = true
  await fetchData()
  isRefreshing.value = false
}

const onSwiperChange = (e: any) => {
  console.log('当前索引:', e.detail.current)
}
</script>

<style lang="scss" scoped>
.scroll-container {
  height: 600rpx;
}

.banner {
  height: 300rpx;
  
  image {
    width: 100%;
    height: 100%;
  }
}

.movable-area {
  width: 100%;
  height: 400rpx;
  background-color: #f5f5f5;
}

.movable-view {
  width: 100rpx;
  height: 100rpx;
  background-color: #007AFF;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>
```

### 6.2 表单组件

```vue
<template>
  <view class="form">
    <!-- input 输入框 -->
    <input 
      v-model="form.username"
      type="text"
      placeholder="请输入用户名"
      :maxlength="20"
      @input="onInput"
      @focus="onFocus"
      @blur="onBlur"
      @confirm="onConfirm"
    />
    
    <!-- 密码输入 -->
    <input 
      v-model="form.password"
      type="password"
      placeholder="请输入密码"
      password
    />
    
    <!-- 数字键盘 -->
    <input 
      v-model="form.phone"
      type="number"
      placeholder="请输入手机号"
    />
    
    <!-- textarea 多行输入 -->
    <textarea 
      v-model="form.content"
      placeholder="请输入内容"
      :maxlength="200"
      :auto-height="true"
      @linechange="onLineChange"
    />
    
    <!-- picker 选择器 -->
    <picker 
      mode="selector"
      :range="cityList"
      :value="cityIndex"
      @change="onCityChange"
    >
      <view class="picker">
        当前选择：{{ cityList[cityIndex] || '请选择' }}
      </view>
    </picker>
    
    <!-- 日期选择 -->
    <picker 
      mode="date"
      :value="form.date"
      :start="startDate"
      :end="endDate"
      @change="onDateChange"
    >
      <view class="picker">
        日期：{{ form.date || '请选择日期' }}
      </view>
    </picker>
    
    <!-- 时间选择 -->
    <picker 
      mode="time"
      :value="form.time"
      @change="onTimeChange"
    >
      <view class="picker">
        时间：{{ form.time || '请选择时间' }}
      </view>
    </picker>
    
    <!-- 多列选择器 -->
    <picker 
      mode="multiSelector"
      :range="multiArray"
      :value="multiIndex"
      @change="onMultiChange"
      @columnchange="onColumnChange"
    >
      <view class="picker">
        地区：{{ selectedArea }}
      </view>
    </picker>
    
    <!-- switch 开关 -->
    <switch 
      :checked="form.agree"
      @change="onSwitchChange"
      color="#007AFF"
    />
    
    <!-- slider 滑块 -->
    <slider 
      :value="form.volume"
      :min="0"
      :max="100"
      :step="1"
      show-value
      @change="onSliderChange"
    />
    
    <!-- radio 单选 -->
    <radio-group @change="onRadioChange">
      <label v-for="item in genderList" :key="item.value">
        <radio :value="item.value" :checked="form.gender === item.value" />
        {{ item.label }}
      </label>
    </radio-group>
    
    <!-- checkbox 多选 -->
    <checkbox-group @change="onCheckboxChange">
      <label v-for="item in hobbyList" :key="item.value">
        <checkbox :value="item.value" :checked="form.hobbies.includes(item.value)" />
        {{ item.label }}
      </label>
    </checkbox-group>
    
    <!-- button 按钮 -->
    <button type="primary" @click="submitForm">提交</button>
    <button type="default" @click="resetForm">重置</button>
    <button open-type="share">分享</button>
    <button open-type="getUserInfo" @getuserinfo="onGetUserInfo">获取用户信息</button>
  </view>
</template>

<script setup lang="ts">
import { ref, reactive, computed } from 'vue'

const form = reactive({
  username: '',
  password: '',
  phone: '',
  content: '',
  date: '',
  time: '',
  agree: false,
  volume: 50,
  gender: 'male',
  hobbies: [] as string[]
})

const cityList = ['北京', '上海', '广州', '深圳']
const cityIndex = ref(0)
const startDate = '2020-01-01'
const endDate = '2030-12-31'

const genderList = [
  { label: '男', value: 'male' },
  { label: '女', value: 'female' }
]

const hobbyList = [
  { label: '阅读', value: 'reading' },
  { label: '运动', value: 'sports' },
  { label: '音乐', value: 'music' }
]

// 省市区联动数据
const multiArray = ref([
  ['广东省', '湖南省'],
  ['广州市', '深圳市'],
  ['天河区', '越秀区']
])
const multiIndex = ref([0, 0, 0])

const selectedArea = computed(() => {
  return multiArray.value.map((arr, i) => arr[multiIndex.value[i]]).join(' ')
})

const onInput = (e: any) => {
  console.log('输入:', e.detail.value)
}

const onCityChange = (e: any) => {
  cityIndex.value = e.detail.value
}

const onDateChange = (e: any) => {
  form.date = e.detail.value
}

const onTimeChange = (e: any) => {
  form.time = e.detail.value
}

const onMultiChange = (e: any) => {
  multiIndex.value = e.detail.value
}

const onColumnChange = (e: any) => {
  // 联动更新下一列数据
  const { column, value } = e.detail
  console.log(`第${column}列改变，值为${value}`)
}

const onSwitchChange = (e: any) => {
  form.agree = e.detail.value
}

const onSliderChange = (e: any) => {
  form.volume = e.detail.value
}

const onRadioChange = (e: any) => {
  form.gender = e.detail.value
}

const onCheckboxChange = (e: any) => {
  form.hobbies = e.detail.value
}

const submitForm = () => {
  console.log('提交表单:', form)
}

const resetForm = () => {
  Object.assign(form, {
    username: '',
    password: '',
    phone: '',
    content: '',
    date: '',
    time: '',
    agree: false,
    volume: 50,
    gender: 'male',
    hobbies: []
  })
}
</script>
```

### 6.3 媒体组件

```vue
<template>
  <!-- image 图片 -->
  <image 
    :src="imageUrl"
    mode="aspectFill"
    :lazy-load="true"
    @load="onImageLoad"
    @error="onImageError"
  />
  
  <!-- video 视频 -->
  <video 
    id="myVideo"
    :src="videoUrl"
    :poster="posterUrl"
    :controls="true"
    :autoplay="false"
    :loop="false"
    :muted="false"
    @play="onVideoPlay"
    @pause="onVideoPause"
    @ended="onVideoEnded"
    @timeupdate="onTimeUpdate"
  />
  
  <!-- audio 音频（部分平台支持） -->
  <audio 
    :src="audioUrl"
    :poster="audioPoster"
    :name="audioName"
    :author="audioAuthor"
    :controls="true"
  />
  
  <!-- camera 相机（小程序/App） -->
  <camera 
    device-position="back"
    flash="auto"
    @error="onCameraError"
  />
  
  <!-- live-player 直播播放 -->
  <live-player 
    :src="liveUrl"
    mode="live"
    :autoplay="true"
    :muted="false"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'

const imageUrl = ref('/static/images/demo.jpg')
const videoUrl = ref('https://example.com/video.mp4')
const posterUrl = ref('/static/images/poster.jpg')
const audioUrl = ref('https://example.com/audio.mp3')
const audioPoster = ref('/static/images/audio-cover.jpg')
const audioName = ref('歌曲名称')
const audioAuthor = ref('歌手')
const liveUrl = ref('rtmp://example.com/live/stream')

// 图片加载事件
const onImageLoad = (e: any) => {
  console.log('图片加载成功', e.detail)
}

const onImageError = (e: any) => {
  console.log('图片加载失败', e.detail)
  // 设置默认图片
  imageUrl.value = '/static/images/default.jpg'
}

// 视频事件
const onVideoPlay = () => {
  console.log('视频开始播放')
}

const onVideoPause = () => {
  console.log('视频暂停')
}

const onVideoEnded = () => {
  console.log('视频播放结束')
}

const onTimeUpdate = (e: any) => {
  console.log('当前播放时间:', e.detail.currentTime)
}

// 视频控制
const videoContext = ref<UniApp.VideoContext>()

const initVideoContext = () => {
  videoContext.value = uni.createVideoContext('myVideo')
}

const playVideo = () => {
  videoContext.value?.play()
}

const pauseVideo = () => {
  videoContext.value?.pause()
}

const seekVideo = (position: number) => {
  videoContext.value?.seek(position)
}
</script>

<style lang="scss" scoped>
image {
  width: 100%;
  height: 400rpx;
}

video {
  width: 100%;
  height: 450rpx;
}
</style>
```

### 6.4 image 的 mode 属性详解

```vue
<template>
  <!-- 
    mode 属性决定图片的裁剪和缩放模式
    
    缩放模式：
    - scaleToFill: 不保持比例缩放，填满容器（可能变形）
    - aspectFit: 保持比例缩放，完整显示（可能有空白）
    - aspectFill: 保持比例缩放，填满容器（可能裁剪）
    - widthFix: 宽度不变，高度自动变化，保持比例
    - heightFix: 高度不变，宽度自动变化，保持比例
    
    裁剪模式：
    - top, bottom, left, right, center
    - top left, top right, bottom left, bottom right
  -->
  
  <view class="image-demo">
    <text>aspectFill（常用）</text>
    <image src="/static/demo.jpg" mode="aspectFill" />
    
    <text>aspectFit</text>
    <image src="/static/demo.jpg" mode="aspectFit" />
    
    <text>widthFix（宽度固定，高度自适应）</text>
    <image src="/static/demo.jpg" mode="widthFix" />
  </view>
</template>
```


---

## 7. 样式与布局

### 7.1 尺寸单位

Uni-app 推荐使用 `rpx` 作为尺寸单位，它会根据屏幕宽度自动换算：

```scss
// rpx 说明：
// - 以 750rpx 为基准，等于屏幕宽度
// - iPhone 6/7/8: 1rpx = 0.5px
// - 设计稿通常以 750px 宽度为准，直接使用设计稿尺寸即可

.container {
  // 推荐使用 rpx
  width: 750rpx;      // 满屏宽度
  padding: 20rpx;     // 内边距
  font-size: 28rpx;   // 字体大小（约 14px）
  
  // 也可以使用 px（固定尺寸）
  border: 1px solid #eee;
  
  // 百分比
  width: 100%;
  
  // vh/vw（视口单位）
  height: 100vh;
}

// 常用尺寸参考（基于 750rpx 设计稿）
// 12px = 24rpx
// 14px = 28rpx
// 16px = 32rpx
// 18px = 36rpx
// 20px = 40rpx
```

### 7.2 Flex 布局

```vue
<template>
  <view class="flex-demo">
    <!-- 水平排列 -->
    <view class="row">
      <view class="item">1</view>
      <view class="item">2</view>
      <view class="item">3</view>
    </view>
    
    <!-- 垂直排列 -->
    <view class="column">
      <view class="item">1</view>
      <view class="item">2</view>
      <view class="item">3</view>
    </view>
    
    <!-- 两端对齐 -->
    <view class="space-between">
      <view class="item">左</view>
      <view class="item">右</view>
    </view>
    
    <!-- 居中对齐 -->
    <view class="center">
      <view class="item">居中内容</view>
    </view>
    
    <!-- 换行 -->
    <view class="wrap">
      <view class="item" v-for="i in 6" :key="i">{{ i }}</view>
    </view>
  </view>
</template>

<style lang="scss" scoped>
.row {
  display: flex;
  flex-direction: row;  // 默认值，可省略
}

.column {
  display: flex;
  flex-direction: column;
}

.space-between {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.center {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 200rpx;
}

.wrap {
  display: flex;
  flex-wrap: wrap;
  
  .item {
    width: 33.33%;
  }
}

.item {
  padding: 20rpx;
  background-color: #007AFF;
  color: #fff;
  margin: 10rpx;
}
</style>
```

### 7.3 全局样式变量

```scss
// uni.scss - 全局样式变量（无需导入，直接使用）
$primary-color: #007AFF;
$success-color: #4CD964;
$warning-color: #FF9500;
$danger-color: #FF3B30;

$text-color: #333333;
$text-color-secondary: #666666;
$text-color-placeholder: #999999;

$border-color: #E5E5E5;
$background-color: #F5F5F5;

$font-size-sm: 24rpx;
$font-size-base: 28rpx;
$font-size-lg: 32rpx;
$font-size-xl: 36rpx;

$spacing-sm: 10rpx;
$spacing-base: 20rpx;
$spacing-lg: 30rpx;

// 使用变量
.button {
  background-color: $primary-color;
  font-size: $font-size-base;
  padding: $spacing-base $spacing-lg;
}
```

### 7.4 样式注意事项

```vue
<template>
  <view class="container">
    <!-- 1. 不支持 * 选择器 -->
    <!-- 2. 不支持媒体查询（部分平台） -->
    <!-- 3. 小程序不支持 scoped 的 >>> 或 /deep/ -->
    
    <!-- 正确的样式穿透写法 -->
    <uni-popup ref="popup">
      <view class="popup-content">内容</view>
    </uni-popup>
  </view>
</template>

<style lang="scss">
/* 样式穿透 - 不使用 scoped */
.container {
  /* 穿透子组件样式 */
  :deep(.uni-popup) {
    background-color: #fff;
  }
}
</style>

<style lang="scss" scoped>
/* 组件内部样式 */
.container {
  padding: 20rpx;
}

/* 
  注意事项：
  1. 背景图片使用网络地址或 base64
  2. 本地图片需要放在 static 目录
  3. 小程序中 background-image 不支持本地路径
*/
.bg-image {
  /* ❌ 小程序不支持 */
  /* background-image: url('@/static/bg.png'); */
  
  /* ✅ 使用网络图片 */
  background-image: url('https://example.com/bg.png');
  
  /* ✅ 或使用 base64 */
  background-image: url('data:image/png;base64,...');
}
</style>
```

### 7.5 安全区域适配

```vue
<template>
  <view class="page">
    <!-- 顶部安全区域 -->
    <view class="status-bar" :style="{ height: statusBarHeight + 'px' }"></view>
    
    <!-- 内容区域 -->
    <view class="content">
      主要内容
    </view>
    
    <!-- 底部安全区域（iPhone X 等） -->
    <view class="safe-area-bottom"></view>
  </view>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const statusBarHeight = ref(0)

// 获取状态栏高度
uni.getSystemInfo({
  success: (res) => {
    statusBarHeight.value = res.statusBarHeight || 0
  }
})
</script>

<style lang="scss" scoped>
.page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.status-bar {
  background-color: #007AFF;
}

.content {
  flex: 1;
}

/* 底部安全区域 */
.safe-area-bottom {
  padding-bottom: constant(safe-area-inset-bottom); /* iOS < 11.2 */
  padding-bottom: env(safe-area-inset-bottom); /* iOS >= 11.2 */
}

/* 或使用 CSS 变量 */
.fixed-bottom {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  padding-bottom: env(safe-area-inset-bottom);
}
</style>
```

---

## 8. 生命周期

### 8.1 应用生命周期

```typescript
// App.vue
<script setup lang="ts">
import { onLaunch, onShow, onHide, onError } from '@dcloudio/uni-app'

// 应用初始化完成时触发（全局只触发一次）
onLaunch((options) => {
  console.log('App Launch')
  console.log('启动参数:', options)
  
  // 常见操作：
  // 1. 检查登录状态
  // 2. 获取系统信息
  // 3. 初始化第三方 SDK
})

// 应用从后台进入前台时触发
onShow((options) => {
  console.log('App Show')
  console.log('场景值:', options?.scene)
  
  // 常见操作：
  // 1. 刷新数据
  // 2. 恢复音视频播放
})

// 应用从前台进入后台时触发
onHide(() => {
  console.log('App Hide')
  
  // 常见操作：
  // 1. 暂停音视频
  // 2. 保存草稿
})

// 应用发生错误时触发
onError((error) => {
  console.error('App Error:', error)
  
  // 上报错误到服务器
})
</script>
```

### 8.2 页面生命周期

```vue
<script setup lang="ts">
import { ref } from 'vue'
import {
  onLoad,
  onShow,
  onReady,
  onHide,
  onUnload,
  onPullDownRefresh,
  onReachBottom,
  onPageScroll,
  onShareAppMessage,
  onShareTimeline,
  onBackPress,
  onNavigationBarButtonTap,
  onTabItemTap
} from '@dcloudio/uni-app'

const list = ref<any[]>([])
const page = ref(1)

// 页面加载时触发，可获取路由参数
onLoad((options) => {
  console.log('页面加载，参数:', options)
  // 初始化数据
  loadData()
})

// 页面显示时触发（每次显示都会触发）
onShow(() => {
  console.log('页面显示')
  // 刷新数据
})

// 页面初次渲染完成时触发
onReady(() => {
  console.log('页面渲染完成')
  // 可以操作 DOM 或组件
})

// 页面隐藏时触发
onHide(() => {
  console.log('页面隐藏')
})

// 页面卸载时触发
onUnload(() => {
  console.log('页面卸载')
  // 清理定时器、取消订阅等
})

// 下拉刷新（需要在 pages.json 中开启 enablePullDownRefresh）
onPullDownRefresh(async () => {
  console.log('下拉刷新')
  page.value = 1
  await loadData()
  uni.stopPullDownRefresh()
})

// 上拉触底加载更多
onReachBottom(() => {
  console.log('触底加载')
  page.value++
  loadMore()
})

// 页面滚动
onPageScroll((e) => {
  console.log('滚动位置:', e.scrollTop)
})

// 分享给好友
onShareAppMessage((options) => {
  return {
    title: '分享标题',
    path: '/pages/index/index?id=123',
    imageUrl: '/static/share.png'
  }
})

// 分享到朋友圈（微信小程序）
onShareTimeline(() => {
  return {
    title: '分享标题',
    query: 'id=123',
    imageUrl: '/static/share.png'
  }
})

// 返回按钮点击（App 端）
onBackPress((options) => {
  console.log('返回按钮点击', options.from)
  // 返回 true 阻止默认返回行为
  return false
})

// 导航栏按钮点击
onNavigationBarButtonTap((options) => {
  console.log('导航栏按钮点击', options.index)
})

// TabBar 点击
onTabItemTap((options) => {
  console.log('TabBar 点击', options)
})

const loadData = async () => {
  // 加载数据
}

const loadMore = async () => {
  // 加载更多
}
</script>
```

### 8.3 组件生命周期

```vue
<script setup lang="ts">
import { 
  onMounted, 
  onUpdated, 
  onUnmounted,
  onBeforeMount,
  onBeforeUpdate,
  onBeforeUnmount
} from 'vue'

// Vue 3 组件生命周期
onBeforeMount(() => {
  console.log('组件挂载前')
})

onMounted(() => {
  console.log('组件挂载完成')
  // 可以访问 DOM
})

onBeforeUpdate(() => {
  console.log('组件更新前')
})

onUpdated(() => {
  console.log('组件更新完成')
})

onBeforeUnmount(() => {
  console.log('组件卸载前')
})

onUnmounted(() => {
  console.log('组件卸载完成')
  // 清理工作
})
</script>
```

### 8.4 生命周期执行顺序

```
应用启动：
App onLaunch → App onShow → Page onLoad → Page onShow → Page onReady

页面切换（A → B）：
Page A onHide → Page B onLoad → Page B onShow → Page B onReady

页面返回（B → A）：
Page B onUnload → Page A onShow

应用切到后台：
Page onHide → App onHide

应用切回前台：
App onShow → Page onShow
```

---

## 9. 数据请求

### 9.1 基础请求

```typescript
// 基础用法
uni.request({
  url: 'https://api.example.com/users',
  method: 'GET',
  data: {
    page: 1,
    pageSize: 10
  },
  header: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token'
  },
  success: (res) => {
    console.log('请求成功:', res.data)
  },
  fail: (err) => {
    console.error('请求失败:', err)
  },
  complete: () => {
    console.log('请求完成')
  }
})

// Promise 风格
const response = await uni.request({
  url: 'https://api.example.com/users',
  method: 'GET'
})
console.log(response.data)
```

### 9.2 封装请求工具

```typescript
// utils/request.ts
interface RequestConfig {
  url: string
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  data?: any
  header?: Record<string, string>
  showLoading?: boolean
  showError?: boolean
}

interface ResponseData<T = any> {
  code: number
  message: string
  data: T
}

const BASE_URL = 'https://api.example.com'

// 请求拦截
const requestInterceptor = (config: RequestConfig) => {
  // 添加 token
  const token = uni.getStorageSync('token')
  if (token) {
    config.header = {
      ...config.header,
      'Authorization': `Bearer ${token}`
    }
  }
  return config
}

// 响应拦截
const responseInterceptor = <T>(response: UniApp.RequestSuccessCallbackResult): T => {
  const { statusCode, data } = response
  
  if (statusCode === 200) {
    const result = data as ResponseData<T>
    if (result.code === 0) {
      return result.data
    } else if (result.code === 401) {
      // token 过期，跳转登录
      uni.removeStorageSync('token')
      uni.reLaunch({ url: '/pages/login/index' })
      throw new Error('登录已过期')
    } else {
      throw new Error(result.message || '请求失败')
    }
  } else if (statusCode === 401) {
    uni.removeStorageSync('token')
    uni.reLaunch({ url: '/pages/login/index' })
    throw new Error('登录已过期')
  } else {
    throw new Error(`请求失败: ${statusCode}`)
  }
}

// 封装请求函数
export const request = <T = any>(config: RequestConfig): Promise<T> => {
  return new Promise((resolve, reject) => {
    // 显示加载
    if (config.showLoading !== false) {
      uni.showLoading({ title: '加载中...' })
    }
    
    // 请求拦截
    const finalConfig = requestInterceptor(config)
    
    uni.request({
      url: BASE_URL + finalConfig.url,
      method: finalConfig.method || 'GET',
      data: finalConfig.data,
      header: {
        'Content-Type': 'application/json',
        ...finalConfig.header
      },
      success: (res) => {
        try {
          const data = responseInterceptor<T>(res)
          resolve(data)
        } catch (error: any) {
          if (config.showError !== false) {
            uni.showToast({
              title: error.message,
              icon: 'none'
            })
          }
          reject(error)
        }
      },
      fail: (err) => {
        const message = '网络请求失败'
        if (config.showError !== false) {
          uni.showToast({ title: message, icon: 'none' })
        }
        reject(new Error(message))
      },
      complete: () => {
        if (config.showLoading !== false) {
          uni.hideLoading()
        }
      }
    })
  })
}

// 快捷方法
export const get = <T = any>(url: string, data?: any, config?: Partial<RequestConfig>) => {
  return request<T>({ url, method: 'GET', data, ...config })
}

export const post = <T = any>(url: string, data?: any, config?: Partial<RequestConfig>) => {
  return request<T>({ url, method: 'POST', data, ...config })
}

export const put = <T = any>(url: string, data?: any, config?: Partial<RequestConfig>) => {
  return request<T>({ url, method: 'PUT', data, ...config })
}

export const del = <T = any>(url: string, data?: any, config?: Partial<RequestConfig>) => {
  return request<T>({ url, method: 'DELETE', data, ...config })
}
```

### 9.3 API 模块化

```typescript
// api/user.ts
import { get, post } from '@/utils/request'

export interface User {
  id: number
  name: string
  avatar: string
  phone: string
}

export interface LoginParams {
  phone: string
  code: string
}

export interface LoginResult {
  token: string
  user: User
}

// 用户登录
export const login = (data: LoginParams) => {
  return post<LoginResult>('/user/login', data)
}

// 获取用户信息
export const getUserInfo = () => {
  return get<User>('/user/info')
}

// 更新用户信息
export const updateUserInfo = (data: Partial<User>) => {
  return post<User>('/user/update', data)
}

// 获取用户列表
export const getUserList = (params: { page: number; pageSize: number }) => {
  return get<{ list: User[]; total: number }>('/user/list', params)
}
```

### 9.4 在页面中使用

```vue
<script setup lang="ts">
import { ref } from 'vue'
import { onLoad } from '@dcloudio/uni-app'
import { getUserInfo, type User } from '@/api/user'

const userInfo = ref<User | null>(null)
const loading = ref(false)

const fetchUserInfo = async () => {
  loading.value = true
  try {
    userInfo.value = await getUserInfo()
  } catch (error) {
    console.error('获取用户信息失败:', error)
  } finally {
    loading.value = false
  }
}

onLoad(() => {
  fetchUserInfo()
})
</script>
```

### 9.5 文件上传

```typescript
// 上传单个文件
const uploadFile = async (filePath: string) => {
  return new Promise((resolve, reject) => {
    uni.uploadFile({
      url: 'https://api.example.com/upload',
      filePath,
      name: 'file',
      header: {
        'Authorization': `Bearer ${uni.getStorageSync('token')}`
      },
      formData: {
        type: 'image'
      },
      success: (res) => {
        const data = JSON.parse(res.data)
        resolve(data.url)
      },
      fail: reject
    })
  })
}

// 选择并上传图片
const chooseAndUpload = async () => {
  const res = await uni.chooseImage({
    count: 1,
    sizeType: ['compressed'],
    sourceType: ['album', 'camera']
  })
  
  const url = await uploadFile(res.tempFilePaths[0])
  console.log('上传成功:', url)
}
```


---

## 10. 状态管理

### 10.1 使用 Pinia

```bash
npm install pinia
```

```typescript
// store/index.ts
import { createPinia } from 'pinia'

const pinia = createPinia()

export default pinia
```

```typescript
// main.ts
import { createSSRApp } from 'vue'
import App from './App.vue'
import pinia from './store'

export function createApp() {
  const app = createSSRApp(App)
  app.use(pinia)
  return { app }
}
```

### 10.2 定义 Store

```typescript
// store/modules/user.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login, getUserInfo, type User, type LoginParams } from '@/api/user'

export const useUserStore = defineStore('user', () => {
  // 状态
  const token = ref(uni.getStorageSync('token') || '')
  const userInfo = ref<User | null>(null)
  
  // 计算属性
  const isLoggedIn = computed(() => !!token.value)
  const userName = computed(() => userInfo.value?.name || '游客')
  
  // 方法
  const setToken = (newToken: string) => {
    token.value = newToken
    uni.setStorageSync('token', newToken)
  }
  
  const clearToken = () => {
    token.value = ''
    uni.removeStorageSync('token')
  }
  
  const loginAction = async (params: LoginParams) => {
    const result = await login(params)
    setToken(result.token)
    userInfo.value = result.user
    return result
  }
  
  const fetchUserInfo = async () => {
    if (!token.value) return null
    try {
      userInfo.value = await getUserInfo()
      return userInfo.value
    } catch (error) {
      clearToken()
      throw error
    }
  }
  
  const logout = () => {
    clearToken()
    userInfo.value = null
    uni.reLaunch({ url: '/pages/login/index' })
  }
  
  return {
    token,
    userInfo,
    isLoggedIn,
    userName,
    setToken,
    clearToken,
    loginAction,
    fetchUserInfo,
    logout
  }
})
```

```typescript
// store/modules/cart.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

interface CartItem {
  id: number
  name: string
  price: number
  quantity: number
  image: string
  selected: boolean
}

export const useCartStore = defineStore('cart', () => {
  const items = ref<CartItem[]>([])
  
  // 计算属性
  const totalCount = computed(() => 
    items.value.reduce((sum, item) => sum + item.quantity, 0)
  )
  
  const selectedItems = computed(() => 
    items.value.filter(item => item.selected)
  )
  
  const totalPrice = computed(() => 
    selectedItems.value.reduce(
      (sum, item) => sum + item.price * item.quantity, 
      0
    )
  )
  
  const isAllSelected = computed(() => 
    items.value.length > 0 && items.value.every(item => item.selected)
  )
  
  // 方法
  const addItem = (item: Omit<CartItem, 'quantity' | 'selected'>) => {
    const existingItem = items.value.find(i => i.id === item.id)
    if (existingItem) {
      existingItem.quantity++
    } else {
      items.value.push({ ...item, quantity: 1, selected: true })
    }
    saveToStorage()
  }
  
  const removeItem = (id: number) => {
    const index = items.value.findIndex(item => item.id === id)
    if (index > -1) {
      items.value.splice(index, 1)
      saveToStorage()
    }
  }
  
  const updateQuantity = (id: number, quantity: number) => {
    const item = items.value.find(i => i.id === id)
    if (item) {
      item.quantity = Math.max(1, quantity)
      saveToStorage()
    }
  }
  
  const toggleSelect = (id: number) => {
    const item = items.value.find(i => i.id === id)
    if (item) {
      item.selected = !item.selected
      saveToStorage()
    }
  }
  
  const toggleSelectAll = () => {
    const newValue = !isAllSelected.value
    items.value.forEach(item => {
      item.selected = newValue
    })
    saveToStorage()
  }
  
  const clearCart = () => {
    items.value = []
    saveToStorage()
  }
  
  const saveToStorage = () => {
    uni.setStorageSync('cart', JSON.stringify(items.value))
  }
  
  const loadFromStorage = () => {
    const data = uni.getStorageSync('cart')
    if (data) {
      items.value = JSON.parse(data)
    }
  }
  
  // 初始化时加载
  loadFromStorage()
  
  return {
    items,
    totalCount,
    selectedItems,
    totalPrice,
    isAllSelected,
    addItem,
    removeItem,
    updateQuantity,
    toggleSelect,
    toggleSelectAll,
    clearCart
  }
})
```

### 10.3 在组件中使用

```vue
<template>
  <view class="user-info">
    <view v-if="userStore.isLoggedIn">
      <text>欢迎，{{ userStore.userName }}</text>
      <button @click="handleLogout">退出登录</button>
    </view>
    <view v-else>
      <button @click="goLogin">去登录</button>
    </view>
  </view>
  
  <view class="cart">
    <text>购物车 ({{ cartStore.totalCount }})</text>
    <view v-for="item in cartStore.items" :key="item.id">
      <checkbox :checked="item.selected" @tap="cartStore.toggleSelect(item.id)" />
      <text>{{ item.name }}</text>
      <text>¥{{ item.price }}</text>
      <button @click="cartStore.updateQuantity(item.id, item.quantity - 1)">-</button>
      <text>{{ item.quantity }}</text>
      <button @click="cartStore.updateQuantity(item.id, item.quantity + 1)">+</button>
    </view>
    <view class="footer">
      <checkbox :checked="cartStore.isAllSelected" @tap="cartStore.toggleSelectAll" />
      <text>全选</text>
      <text>合计：¥{{ cartStore.totalPrice.toFixed(2) }}</text>
    </view>
  </view>
</template>

<script setup lang="ts">
import { useUserStore } from '@/store/modules/user'
import { useCartStore } from '@/store/modules/cart'

const userStore = useUserStore()
const cartStore = useCartStore()

const handleLogout = () => {
  uni.showModal({
    title: '提示',
    content: '确定要退出登录吗？',
    success: (res) => {
      if (res.confirm) {
        userStore.logout()
      }
    }
  })
}

const goLogin = () => {
  uni.navigateTo({ url: '/pages/login/index' })
}
</script>
```

### 10.4 持久化插件

```typescript
// store/plugins/persist.ts
import type { PiniaPluginContext } from 'pinia'

export const piniaPluginPersist = ({ store }: PiniaPluginContext) => {
  // 从存储中恢复状态
  const savedState = uni.getStorageSync(`pinia-${store.$id}`)
  if (savedState) {
    store.$patch(JSON.parse(savedState))
  }
  
  // 监听状态变化并保存
  store.$subscribe((mutation, state) => {
    uni.setStorageSync(`pinia-${store.$id}`, JSON.stringify(state))
  })
}

// store/index.ts
import { createPinia } from 'pinia'
import { piniaPluginPersist } from './plugins/persist'

const pinia = createPinia()
pinia.use(piniaPluginPersist)

export default pinia
```

---

## 11. 本地存储

### 11.1 同步存储

```typescript
// 存储数据
uni.setStorageSync('key', 'value')
uni.setStorageSync('user', JSON.stringify({ name: '张三', age: 18 }))

// 读取数据
const value = uni.getStorageSync('key')
const user = JSON.parse(uni.getStorageSync('user') || '{}')

// 删除数据
uni.removeStorageSync('key')

// 清空所有数据
uni.clearStorageSync()

// 获取存储信息
const info = uni.getStorageInfoSync()
console.log('当前存储的 key:', info.keys)
console.log('当前占用空间:', info.currentSize, 'KB')
console.log('限制空间:', info.limitSize, 'KB')
```

### 11.2 异步存储

```typescript
// 存储数据
uni.setStorage({
  key: 'user',
  data: { name: '张三', age: 18 },
  success: () => console.log('存储成功'),
  fail: (err) => console.error('存储失败', err)
})

// 读取数据
uni.getStorage({
  key: 'user',
  success: (res) => console.log('数据:', res.data),
  fail: (err) => console.error('读取失败', err)
})

// Promise 风格
const data = await uni.getStorage({ key: 'user' })
```

### 11.3 封装存储工具

```typescript
// utils/storage.ts
const STORAGE_PREFIX = 'myapp_'

export const storage = {
  // 设置
  set<T>(key: string, value: T, expire?: number): void {
    const data = {
      value,
      expire: expire ? Date.now() + expire * 1000 : null
    }
    uni.setStorageSync(STORAGE_PREFIX + key, JSON.stringify(data))
  },
  
  // 获取
  get<T>(key: string, defaultValue?: T): T | undefined {
    const raw = uni.getStorageSync(STORAGE_PREFIX + key)
    if (!raw) return defaultValue
    
    try {
      const data = JSON.parse(raw)
      // 检查是否过期
      if (data.expire && Date.now() > data.expire) {
        this.remove(key)
        return defaultValue
      }
      return data.value as T
    } catch {
      return defaultValue
    }
  },
  
  // 删除
  remove(key: string): void {
    uni.removeStorageSync(STORAGE_PREFIX + key)
  },
  
  // 清空
  clear(): void {
    const info = uni.getStorageInfoSync()
    info.keys.forEach(key => {
      if (key.startsWith(STORAGE_PREFIX)) {
        uni.removeStorageSync(key)
      }
    })
  },
  
  // 检查是否存在
  has(key: string): boolean {
    return !!uni.getStorageSync(STORAGE_PREFIX + key)
  }
}

// 使用示例
storage.set('token', 'abc123', 3600)  // 1小时后过期
storage.set('user', { name: '张三' })
const token = storage.get<string>('token')
const user = storage.get<{ name: string }>('user')
```

---

## 12. 条件编译

### 12.1 基础语法

条件编译是 uni-app 的核心特性，用于在不同平台编写不同代码：

```vue
<template>
  <!-- #ifdef H5 -->
  <view>这段代码只在 H5 平台显示</view>
  <!-- #endif -->
  
  <!-- #ifdef MP-WEIXIN -->
  <view>这段代码只在微信小程序显示</view>
  <!-- #endif -->
  
  <!-- #ifdef APP-PLUS -->
  <view>这段代码只在 App 平台显示</view>
  <!-- #endif -->
  
  <!-- #ifndef H5 -->
  <view>这段代码在除了 H5 以外的平台显示</view>
  <!-- #endif -->
  
  <!-- #ifdef H5 || MP-WEIXIN -->
  <view>这段代码在 H5 或微信小程序显示</view>
  <!-- #endif -->
</template>

<script setup lang="ts">
// #ifdef H5
console.log('H5 平台')
import h5Module from './h5-module'
// #endif

// #ifdef MP-WEIXIN
console.log('微信小程序')
const wx = uni.requireNativePlugin?.('wx')
// #endif

// #ifdef APP-PLUS
console.log('App 平台')
const plus = uni.requireNativePlugin?.('plus')
// #endif

const getPlatformInfo = () => {
  // #ifdef H5
  return { platform: 'h5', ua: navigator.userAgent }
  // #endif
  
  // #ifdef MP-WEIXIN
  return { platform: 'mp-weixin', version: wx.getSystemInfoSync().version }
  // #endif
  
  // #ifdef APP-PLUS
  return { platform: 'app', os: plus.os.name }
  // #endif
}
</script>

<style lang="scss" scoped>
.container {
  /* #ifdef H5 */
  padding-top: 44px;  /* H5 导航栏高度 */
  /* #endif */
  
  /* #ifdef MP-WEIXIN */
  padding-top: 0;  /* 小程序有原生导航栏 */
  /* #endif */
  
  /* #ifdef APP-PLUS */
  padding-top: var(--status-bar-height);
  /* #endif */
}
</style>
```

### 12.2 平台标识符

| 标识符 | 说明 |
|--------|------|
| `H5` | H5 网页 |
| `APP-PLUS` | App（iOS 和 Android） |
| `APP-PLUS-NVUE` | App nvue 页面 |
| `APP-ANDROID` | App Android 平台 |
| `APP-IOS` | App iOS 平台 |
| `MP` | 所有小程序 |
| `MP-WEIXIN` | 微信小程序 |
| `MP-ALIPAY` | 支付宝小程序 |
| `MP-BAIDU` | 百度小程序 |
| `MP-TOUTIAO` | 字节跳动小程序 |
| `MP-QQ` | QQ 小程序 |
| `MP-KUAISHOU` | 快手小程序 |
| `MP-JD` | 京东小程序 |
| `MP-LARK` | 飞书小程序 |

### 12.3 pages.json 条件编译

```json
{
  "pages": [
    {
      "path": "pages/index/index",
      "style": {
        "navigationBarTitleText": "首页",
        // #ifdef H5
        "navigationStyle": "custom"
        // #endif
      }
    }
  ],
  // #ifdef MP-WEIXIN
  "permission": {
    "scope.userLocation": {
      "desc": "你的位置信息将用于小程序位置接口的效果展示"
    }
  },
  // #endif
  "tabBar": {
    "list": [
      {
        "pagePath": "pages/index/index",
        "text": "首页"
      },
      // #ifdef APP-PLUS || H5
      {
        "pagePath": "pages/scan/index",
        "text": "扫码"
      },
      // #endif
      {
        "pagePath": "pages/user/index",
        "text": "我的"
      }
    ]
  }
}
```

### 12.4 实际应用场景

```typescript
// utils/platform.ts
export const platform = {
  // 是否是 H5
  isH5: () => {
    // #ifdef H5
    return true
    // #endif
    // #ifndef H5
    return false
    // #endif
  },
  
  // 是否是小程序
  isMp: () => {
    // #ifdef MP
    return true
    // #endif
    // #ifndef MP
    return false
    // #endif
  },
  
  // 是否是 App
  isApp: () => {
    // #ifdef APP-PLUS
    return true
    // #endif
    // #ifndef APP-PLUS
    return false
    // #endif
  },
  
  // 获取平台名称
  getName: () => {
    // #ifdef H5
    return 'H5'
    // #endif
    // #ifdef MP-WEIXIN
    return '微信小程序'
    // #endif
    // #ifdef MP-ALIPAY
    return '支付宝小程序'
    // #endif
    // #ifdef APP-PLUS
    return 'App'
    // #endif
  }
}

// 分享功能（不同平台实现不同）
export const share = (options: { title: string; path: string; imageUrl?: string }) => {
  // #ifdef MP-WEIXIN
  // 微信小程序使用页面的 onShareAppMessage
  return
  // #endif
  
  // #ifdef H5
  // H5 使用 Web Share API 或自定义分享
  if (navigator.share) {
    navigator.share({
      title: options.title,
      url: window.location.origin + options.path
    })
  } else {
    // 显示分享弹窗
    uni.showModal({
      title: '分享',
      content: '请复制链接分享给好友',
      showCancel: false
    })
  }
  // #endif
  
  // #ifdef APP-PLUS
  // App 使用原生分享
  plus.share.sendWithSystem({
    content: options.title,
    href: options.path
  })
  // #endif
}
```


---

## 13. 原生能力

### 13.1 系统信息

```typescript
// 获取系统信息
const getSystemInfo = () => {
  const info = uni.getSystemInfoSync()
  
  console.log('设备品牌:', info.brand)
  console.log('设备型号:', info.model)
  console.log('操作系统:', info.platform)
  console.log('操作系统版本:', info.system)
  console.log('屏幕宽度:', info.screenWidth)
  console.log('屏幕高度:', info.screenHeight)
  console.log('可用窗口宽度:', info.windowWidth)
  console.log('可用窗口高度:', info.windowHeight)
  console.log('状态栏高度:', info.statusBarHeight)
  console.log('安全区域:', info.safeArea)
  console.log('DPR:', info.pixelRatio)
  
  return info
}

// 获取网络状态
uni.getNetworkType({
  success: (res) => {
    console.log('网络类型:', res.networkType)
    // wifi, 2g, 3g, 4g, 5g, ethernet, unknown, none
  }
})

// 监听网络变化
uni.onNetworkStatusChange((res) => {
  console.log('网络是否连接:', res.isConnected)
  console.log('网络类型:', res.networkType)
})
```

### 13.2 位置服务

```typescript
// 获取当前位置
const getLocation = async () => {
  try {
    const res = await uni.getLocation({
      type: 'gcj02',  // 坐标系类型
      altitude: true,  // 是否获取高度
      isHighAccuracy: true  // 高精度
    })
    
    console.log('纬度:', res.latitude)
    console.log('经度:', res.longitude)
    console.log('速度:', res.speed)
    console.log('精确度:', res.accuracy)
    console.log('高度:', res.altitude)
    
    return res
  } catch (error: any) {
    if (error.errMsg.includes('auth deny')) {
      uni.showModal({
        title: '提示',
        content: '请授权位置权限',
        success: (res) => {
          if (res.confirm) {
            uni.openSetting()
          }
        }
      })
    }
    throw error
  }
}

// 打开地图选择位置
const chooseLocation = async () => {
  const res = await uni.chooseLocation({})
  console.log('选择的位置:', res.name)
  console.log('详细地址:', res.address)
  console.log('纬度:', res.latitude)
  console.log('经度:', res.longitude)
  return res
}

// 打开地图查看位置
const openLocation = (latitude: number, longitude: number) => {
  uni.openLocation({
    latitude,
    longitude,
    name: '目的地',
    address: '详细地址',
    scale: 18
  })
}
```

### 13.3 相机与相册

```typescript
// 选择图片
const chooseImage = async (count = 9) => {
  const res = await uni.chooseImage({
    count,
    sizeType: ['original', 'compressed'],
    sourceType: ['album', 'camera']
  })
  
  console.log('选择的图片:', res.tempFilePaths)
  return res.tempFilePaths
}

// 预览图片
const previewImage = (urls: string[], current = 0) => {
  uni.previewImage({
    urls,
    current: urls[current],
    indicator: 'number',
    loop: true
  })
}

// 保存图片到相册
const saveImage = async (url: string) => {
  // 先下载图片
  const downloadRes = await uni.downloadFile({ url })
  
  // 保存到相册
  await uni.saveImageToPhotosAlbum({
    filePath: downloadRes.tempFilePath
  })
  
  uni.showToast({ title: '保存成功' })
}

// 选择视频
const chooseVideo = async () => {
  const res = await uni.chooseVideo({
    sourceType: ['album', 'camera'],
    maxDuration: 60,
    camera: 'back',
    compressed: true
  })
  
  console.log('视频路径:', res.tempFilePath)
  console.log('视频时长:', res.duration)
  console.log('视频大小:', res.size)
  
  return res
}
```

### 13.4 扫码

```typescript
// 扫码
const scanCode = async () => {
  try {
    const res = await uni.scanCode({
      onlyFromCamera: false,  // 是否只能从相机扫码
      scanType: ['qrCode', 'barCode']  // 扫码类型
    })
    
    console.log('扫码结果:', res.result)
    console.log('码类型:', res.scanType)
    console.log('码内容:', res.charSet)
    
    return res.result
  } catch (error) {
    console.error('扫码失败:', error)
    throw error
  }
}
```

### 13.5 支付

```typescript
// 微信支付
const wxPay = async (orderInfo: any) => {
  // #ifdef MP-WEIXIN
  await uni.requestPayment({
    provider: 'wxpay',
    timeStamp: orderInfo.timeStamp,
    nonceStr: orderInfo.nonceStr,
    package: orderInfo.package,
    signType: orderInfo.signType,
    paySign: orderInfo.paySign
  })
  // #endif
  
  // #ifdef APP-PLUS
  await uni.requestPayment({
    provider: 'wxpay',
    orderInfo: orderInfo  // App 端传完整订单信息
  })
  // #endif
}

// 支付宝支付
const aliPay = async (orderInfo: string) => {
  await uni.requestPayment({
    provider: 'alipay',
    orderInfo: orderInfo  // 支付宝订单字符串
  })
}
```

### 13.6 分享

```typescript
// 页面分享配置
import { onShareAppMessage, onShareTimeline } from '@dcloudio/uni-app'

// 分享给好友
onShareAppMessage((options) => {
  // options.from: 'button' 或 'menu'
  // options.target: 如果 from 是 button，则为触发分享的按钮
  
  return {
    title: '分享标题',
    path: '/pages/index/index?id=123',
    imageUrl: '/static/share.png'
  }
})

// 分享到朋友圈（微信小程序）
onShareTimeline(() => {
  return {
    title: '分享标题',
    query: 'id=123',
    imageUrl: '/static/share.png'
  }
})

// App 端分享
const shareToApp = () => {
  // #ifdef APP-PLUS
  uni.share({
    provider: 'weixin',
    scene: 'WXSceneSession',  // WXSceneSession: 好友, WXSceneTimeline: 朋友圈
    type: 0,  // 0: 图文, 1: 纯文字, 2: 纯图片, 5: 小程序
    title: '分享标题',
    summary: '分享描述',
    href: 'https://example.com',
    imageUrl: '/static/share.png',
    success: () => {
      uni.showToast({ title: '分享成功' })
    },
    fail: (err) => {
      console.error('分享失败:', err)
    }
  })
  // #endif
}
```

### 13.7 推送通知

```typescript
// App 端推送
// #ifdef APP-PLUS
// 获取推送客户端 ID
const getPushClientId = () => {
  return new Promise<string>((resolve, reject) => {
    plus.push.getClientInfo({
      success: (info) => {
        console.log('推送 ID:', info.clientid)
        resolve(info.clientid)
      },
      fail: reject
    })
  })
}

// 监听推送消息
plus.push.addEventListener('receive', (msg) => {
  console.log('收到推送:', msg)
  // 处理推送消息
}, false)

// 监听推送点击
plus.push.addEventListener('click', (msg) => {
  console.log('点击推送:', msg)
  // 跳转到对应页面
  if (msg.payload?.page) {
    uni.navigateTo({ url: msg.payload.page })
  }
}, false)
// #endif
```

### 13.8 生物认证

```typescript
// 检查是否支持生物认证
const checkBiometric = async () => {
  // #ifdef APP-PLUS
  const res = await uni.checkIsSupportSoterAuthentication({})
  console.log('支持的认证方式:', res.supportMode)
  // fingerPrint: 指纹, facial: 人脸, speech: 声纹
  return res.supportMode
  // #endif
  
  // #ifdef MP-WEIXIN
  const res = await uni.checkIsSupportSoterAuthentication({})
  return res.supportMode
  // #endif
}

// 进行生物认证
const startBiometric = async () => {
  try {
    await uni.startSoterAuthentication({
      requestAuthModes: ['fingerPrint', 'facial'],
      challenge: '123456',
      authContent: '请验证身份'
    })
    console.log('认证成功')
    return true
  } catch (error) {
    console.error('认证失败:', error)
    return false
  }
}
```

---

## 14. 插件与扩展

### 14.1 uni-ui 组件库

```bash
# 安装 uni-ui
npm install @dcloudio/uni-ui
```

```json
// pages.json 配置 easycom
{
  "easycom": {
    "autoscan": true,
    "custom": {
      "^uni-(.*)": "@dcloudio/uni-ui/lib/uni-$1/uni-$1.vue"
    }
  }
}
```

```vue
<template>
  <!-- 图标 -->
  <uni-icons type="star-filled" size="24" color="#FFB800"></uni-icons>
  
  <!-- 徽章 -->
  <uni-badge text="99+" type="error"></uni-badge>
  
  <!-- 标签 -->
  <uni-tag text="标签" type="primary"></uni-tag>
  
  <!-- 搜索栏 -->
  <uni-search-bar 
    v-model="keyword"
    placeholder="搜索"
    @confirm="onSearch"
  ></uni-search-bar>
  
  <!-- 折叠面板 -->
  <uni-collapse>
    <uni-collapse-item title="标题1">
      内容1
    </uni-collapse-item>
    <uni-collapse-item title="标题2">
      内容2
    </uni-collapse-item>
  </uni-collapse>
  
  <!-- 弹出层 -->
  <uni-popup ref="popup" type="bottom">
    <view class="popup-content">
      弹出内容
    </view>
  </uni-popup>
  
  <!-- 日历 -->
  <uni-calendar 
    :selected="selectedDates"
    @change="onDateChange"
  ></uni-calendar>
  
  <!-- 表单 -->
  <uni-forms ref="form" :model="formData" :rules="rules">
    <uni-forms-item label="姓名" name="name">
      <uni-easyinput v-model="formData.name" placeholder="请输入姓名" />
    </uni-forms-item>
    <uni-forms-item label="手机号" name="phone">
      <uni-easyinput v-model="formData.phone" placeholder="请输入手机号" />
    </uni-forms-item>
  </uni-forms>
  <button @click="submitForm">提交</button>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'

const keyword = ref('')
const popup = ref()
const form = ref()

const formData = reactive({
  name: '',
  phone: ''
})

const rules = {
  name: {
    rules: [{ required: true, errorMessage: '请输入姓名' }]
  },
  phone: {
    rules: [
      { required: true, errorMessage: '请输入手机号' },
      { pattern: /^1[3-9]\d{9}$/, errorMessage: '手机号格式不正确' }
    ]
  }
}

const onSearch = () => {
  console.log('搜索:', keyword.value)
}

const submitForm = async () => {
  try {
    await form.value.validate()
    console.log('表单数据:', formData)
  } catch (error) {
    console.log('验证失败:', error)
  }
}

const showPopup = () => {
  popup.value.open()
}
</script>
```

### 14.2 uView UI

```bash
# 安装 uView
npm install uview-plus
```

```typescript
// main.ts
import uviewPlus from 'uview-plus'

export function createApp() {
  const app = createSSRApp(App)
  app.use(uviewPlus)
  return { app }
}
```

```vue
<template>
  <!-- 按钮 -->
  <u-button type="primary" text="按钮"></u-button>
  
  <!-- 输入框 -->
  <u-input v-model="value" placeholder="请输入"></u-input>
  
  <!-- 通知栏 -->
  <u-notice-bar :text="noticeText"></u-notice-bar>
  
  <!-- 步骤条 -->
  <u-steps :current="currentStep">
    <u-steps-item title="下单"></u-steps-item>
    <u-steps-item title="付款"></u-steps-item>
    <u-steps-item title="发货"></u-steps-item>
    <u-steps-item title="收货"></u-steps-item>
  </u-steps>
  
  <!-- 上传 -->
  <u-upload
    :fileList="fileList"
    @afterRead="afterRead"
    @delete="deleteFile"
  ></u-upload>
</template>
```

### 14.3 自定义原生插件（App）

```typescript
// 使用原生插件
// #ifdef APP-PLUS
const myPlugin = uni.requireNativePlugin('MyPlugin')

// 调用插件方法
myPlugin.doSomething({
  param1: 'value1',
  param2: 'value2'
}, (result: any) => {
  console.log('插件返回:', result)
})
// #endif
```

### 14.4 小程序插件

```json
// manifest.json
{
  "mp-weixin": {
    "plugins": {
      "myPlugin": {
        "version": "1.0.0",
        "provider": "wx1234567890"
      }
    }
  }
}
```

```vue
<template>
  <!-- 使用小程序插件组件 -->
  <plugin-component></plugin-component>
</template>

<script setup lang="ts">
// 使用小程序插件 API
// #ifdef MP-WEIXIN
const plugin = requirePlugin('myPlugin')
plugin.doSomething()
// #endif
</script>
```


---

## 15. 性能优化

### 15.1 启动优化

```typescript
// 1. 分包加载（减少主包体积）
// pages.json
{
  "pages": [
    // 主包页面（首页等核心页面）
    { "path": "pages/index/index" },
    { "path": "pages/user/index" }
  ],
  "subPackages": [
    {
      "root": "pages-sub-a",
      "pages": [
        { "path": "detail/index" },
        { "path": "list/index" }
      ]
    },
    {
      "root": "pages-sub-b",
      "pages": [
        { "path": "order/index" },
        { "path": "pay/index" }
      ]
    }
  ],
  // 分包预下载
  "preloadRule": {
    "pages/index/index": {
      "network": "all",
      "packages": ["pages-sub-a"]
    }
  }
}

// 2. 延迟加载非关键资源
onLoad(() => {
  // 先加载关键数据
  loadCriticalData()
  
  // 延迟加载非关键数据
  setTimeout(() => {
    loadNonCriticalData()
  }, 1000)
})

// 3. 骨架屏
<template>
  <view v-if="loading" class="skeleton">
    <view class="skeleton-avatar"></view>
    <view class="skeleton-text"></view>
    <view class="skeleton-text short"></view>
  </view>
  <view v-else>
    <!-- 实际内容 -->
  </view>
</template>
```

### 15.2 渲染优化

```vue
<template>
  <!-- 1. 使用 v-show 代替 v-if（频繁切换时） -->
  <view v-show="isVisible">频繁切换的内容</view>
  
  <!-- 2. 列表使用 key -->
  <view v-for="item in list" :key="item.id">
    {{ item.name }}
  </view>
  
  <!-- 3. 长列表使用虚拟列表 -->
  <scroll-view 
    scroll-y 
    class="list"
    @scroll="onScroll"
  >
    <view 
      v-for="item in visibleList" 
      :key="item.id"
      :style="{ transform: `translateY(${item.offset}px)` }"
    >
      {{ item.name }}
    </view>
  </scroll-view>
  
  <!-- 4. 图片懒加载 -->
  <image 
    :src="item.image" 
    lazy-load
    mode="aspectFill"
  />
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

// 虚拟列表实现
const list = ref<any[]>([])
const scrollTop = ref(0)
const itemHeight = 100
const containerHeight = 600

const visibleList = computed(() => {
  const startIndex = Math.floor(scrollTop.value / itemHeight)
  const endIndex = Math.min(
    startIndex + Math.ceil(containerHeight / itemHeight) + 1,
    list.value.length
  )
  
  return list.value.slice(startIndex, endIndex).map((item, index) => ({
    ...item,
    offset: (startIndex + index) * itemHeight
  }))
})

const onScroll = (e: any) => {
  scrollTop.value = e.detail.scrollTop
}
</script>
```

### 15.3 数据优化

```typescript
// 1. 避免频繁 setData
// ❌ 错误
list.value.forEach((item, index) => {
  list.value[index].checked = true  // 每次都触发更新
})

// ✅ 正确
const newList = list.value.map(item => ({ ...item, checked: true }))
list.value = newList  // 只触发一次更新

// 2. 减少数据量
// ❌ 错误：存储完整数据
const fullData = await fetchData()
list.value = fullData

// ✅ 正确：只存储需要的字段
const fullData = await fetchData()
list.value = fullData.map(item => ({
  id: item.id,
  name: item.name,
  image: item.image
}))

// 3. 使用 shallowRef 优化大数据
import { shallowRef } from 'vue'

const bigList = shallowRef<any[]>([])

// 更新时需要替换整个数组
bigList.value = [...bigList.value, newItem]
```

### 15.4 网络优化

```typescript
// 1. 请求合并
const fetchAllData = async () => {
  // ❌ 串行请求
  const users = await getUsers()
  const orders = await getOrders()
  const products = await getProducts()
  
  // ✅ 并行请求
  const [users, orders, products] = await Promise.all([
    getUsers(),
    getOrders(),
    getProducts()
  ])
}

// 2. 请求缓存
const cache = new Map<string, { data: any; timestamp: number }>()
const CACHE_TIME = 5 * 60 * 1000  // 5分钟

const fetchWithCache = async (url: string) => {
  const cached = cache.get(url)
  if (cached && Date.now() - cached.timestamp < CACHE_TIME) {
    return cached.data
  }
  
  const data = await request({ url })
  cache.set(url, { data, timestamp: Date.now() })
  return data
}

// 3. 图片压缩
const compressImage = async (filePath: string) => {
  const res = await uni.compressImage({
    src: filePath,
    quality: 80
  })
  return res.tempFilePath
}
```

### 15.5 内存优化

```typescript
// 1. 及时清理定时器
import { onUnload } from '@dcloudio/uni-app'

let timer: number | null = null

const startTimer = () => {
  timer = setInterval(() => {
    // 定时任务
  }, 1000)
}

onUnload(() => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
})

// 2. 及时取消事件监听
onUnload(() => {
  uni.$off('eventName')
  uni.offNetworkStatusChange()
})

// 3. 大图片及时释放
const imageUrl = ref('')

const loadImage = async () => {
  imageUrl.value = await fetchImage()
}

const clearImage = () => {
  imageUrl.value = ''  // 释放图片内存
}
```

### 15.6 小程序包体积优化

```bash
# 1. 分析包体积
# 微信开发者工具 → 详情 → 本地设置 → 代码依赖分析

# 2. 压缩图片
# 使用 tinypng 等工具压缩图片

# 3. 使用 CDN 加载大资源
# 将大图片、字体等放到 CDN
```

```json
// 4. 配置按需引入
// pages.json
{
  "easycom": {
    "autoscan": true,
    "custom": {
      // 只引入需要的组件
      "^uni-icons": "@dcloudio/uni-ui/lib/uni-icons/uni-icons.vue",
      "^uni-badge": "@dcloudio/uni-ui/lib/uni-badge/uni-badge.vue"
    }
  }
}
```

---

## 16. 打包发布

### 16.1 H5 发布

```bash
# 构建 H5
npm run build:h5

# 输出目录：dist/build/h5
# 将该目录部署到 Web 服务器
```

```typescript
// vite.config.ts - H5 配置
export default defineConfig({
  build: {
    // 输出目录
    outDir: 'dist/build/h5',
    // 资源路径
    assetsDir: 'static',
    // 是否生成 sourcemap
    sourcemap: false,
    // 压缩方式
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

### 16.2 微信小程序发布

```bash
# 构建微信小程序
npm run build:mp-weixin

# 输出目录：dist/build/mp-weixin
# 使用微信开发者工具打开该目录
# 点击上传，提交审核
```

```json
// manifest.json - 微信小程序配置
{
  "mp-weixin": {
    "appid": "wx1234567890",
    "setting": {
      "urlCheck": false,
      "es6": true,
      "enhance": true,
      "minified": true,
      "postcss": true
    },
    "usingComponents": true,
    "optimization": {
      "subPackages": true
    }
  }
}
```

### 16.3 App 发布

```bash
# 构建 App 资源
npm run build:app

# 使用 HBuilderX 打包
# 1. 打开 HBuilderX
# 2. 导入项目
# 3. 发行 → 原生 App-云打包
```

```json
// manifest.json - App 配置
{
  "app-plus": {
    "distribute": {
      "android": {
        "packagename": "com.example.myapp",
        "keystore": "path/to/keystore",
        "password": "keystore_password",
        "aliasname": "alias",
        "schemes": "myapp",
        "permissions": [
          "<uses-permission android:name=\"android.permission.CAMERA\"/>",
          "<uses-permission android:name=\"android.permission.WRITE_EXTERNAL_STORAGE\"/>"
        ]
      },
      "ios": {
        "appid": "com.example.myapp",
        "mobileprovision": "path/to/mobileprovision",
        "p12": "path/to/p12",
        "password": "p12_password",
        "devices": "universal",
        "UIBackgroundModes": ["audio", "location"]
      }
    },
    "splashscreen": {
      "alwaysShowBeforeRender": true,
      "autoclose": true,
      "waiting": true
    },
    "modules": {
      "OAuth": {},
      "Payment": {},
      "Push": {},
      "Share": {}
    }
  }
}
```

### 16.4 多环境配置

```typescript
// env.d.ts
interface ImportMetaEnv {
  VITE_APP_TITLE: string
  VITE_API_BASE_URL: string
  VITE_APP_ENV: 'development' | 'staging' | 'production'
}

// .env.development
VITE_APP_TITLE=我的应用(开发)
VITE_API_BASE_URL=http://localhost:3000
VITE_APP_ENV=development

// .env.staging
VITE_APP_TITLE=我的应用(测试)
VITE_API_BASE_URL=https://staging-api.example.com
VITE_APP_ENV=staging

// .env.production
VITE_APP_TITLE=我的应用
VITE_API_BASE_URL=https://api.example.com
VITE_APP_ENV=production

// 使用环境变量
const apiUrl = import.meta.env.VITE_API_BASE_URL
```

```json
// package.json
{
  "scripts": {
    "dev:h5": "uni -p h5",
    "dev:h5:staging": "uni -p h5 --mode staging",
    "build:h5": "uni build -p h5",
    "build:h5:staging": "uni build -p h5 --mode staging"
  }
}
```

---

## 17. 常见错误与解决方案

### 17.1 页面路由错误

```typescript
// ❌ 错误：跳转 tabBar 页面使用 navigateTo
uni.navigateTo({
  url: '/pages/user/index'  // user 是 tabBar 页面
})
// 报错：can not navigateTo a tabbar page

// ✅ 正确：使用 switchTab
uni.switchTab({
  url: '/pages/user/index'
})

// ❌ 错误：路径不以 / 开头
uni.navigateTo({
  url: 'pages/detail/index'
})

// ✅ 正确：路径以 / 开头
uni.navigateTo({
  url: '/pages/detail/index'
})

// ❌ 错误：页面栈超过限制（最多 10 层）
// 连续多次 navigateTo 会导致页面栈溢出

// ✅ 正确：适时使用 redirectTo 或 reLaunch
uni.redirectTo({
  url: '/pages/result/index'  // 替换当前页面
})
```

### 17.2 数据响应式问题

```typescript
// ❌ 错误：直接修改数组索引
const list = ref([1, 2, 3])
list.value[0] = 10  // 可能不触发更新

// ✅ 正确：使用数组方法或替换整个数组
list.value = [10, ...list.value.slice(1)]
// 或
list.value.splice(0, 1, 10)

// ❌ 错误：给响应式对象添加新属性
const obj = reactive({ name: '张三' })
obj.age = 18  // Vue 3 中这样是可以的，但要注意

// ✅ 推荐：预先定义所有属性
const obj = reactive({ name: '张三', age: 0 })
```

### 17.3 生命周期问题

```typescript
// ❌ 错误：在 setup 外使用生命周期钩子
export default {
  setup() {
    // ...
  },
  onLoad() {  // 这样不会生效
    console.log('onLoad')
  }
}

// ✅ 正确：在 setup 内使用
import { onLoad } from '@dcloudio/uni-app'

// setup 语法糖
onLoad(() => {
  console.log('onLoad')
})

// ❌ 错误：组件中使用页面生命周期
// 组件中 onLoad、onShow 等不会触发

// ✅ 正确：组件使用 Vue 生命周期
import { onMounted } from 'vue'

onMounted(() => {
  console.log('组件挂载')
})
```

### 17.4 样式问题

```scss
// ❌ 错误：使用 * 选择器
* {
  margin: 0;
  padding: 0;
}

// ✅ 正确：具体指定元素
view, text, image {
  margin: 0;
  padding: 0;
}

// ❌ 错误：小程序中使用本地背景图
.bg {
  background-image: url('@/static/bg.png');  // 不生效
}

// ✅ 正确：使用网络图片或 base64
.bg {
  background-image: url('https://example.com/bg.png');
}

// ❌ 错误：rpx 和 px 混用计算
.box {
  width: calc(100% - 20rpx);  // 可能有问题
}

// ✅ 正确：统一单位
.box {
  width: calc(100% - 20px);
  // 或使用 padding
  padding: 0 20rpx;
}
```

### 17.5 API 兼容性问题

```typescript
// ❌ 错误：不检查 API 是否存在
navigator.clipboard.writeText('text')  // 小程序中不存在

// ✅ 正确：使用条件编译或检查
// #ifdef H5
navigator.clipboard?.writeText('text')
// #endif

// #ifdef MP-WEIXIN
uni.setClipboardData({ data: 'text' })
// #endif

// ❌ 错误：使用 DOM API
document.getElementById('myId')  // 小程序中不存在

// ✅ 正确：使用 uni API
uni.createSelectorQuery()
  .select('#myId')
  .boundingClientRect()
  .exec((res) => {
    console.log(res[0])
  })
```

### 17.6 网络请求问题

```typescript
// ❌ 错误：不处理请求失败
const data = await uni.request({ url: '/api/data' })

// ✅ 正确：处理错误
try {
  const [error, res] = await uni.request({ url: '/api/data' })
  if (error) {
    throw error
  }
  console.log(res.data)
} catch (error) {
  uni.showToast({ title: '请求失败', icon: 'none' })
}

// ❌ 错误：小程序未配置合法域名
// 在微信公众平台配置 request 合法域名

// ✅ 开发时可以关闭域名校验
// 微信开发者工具 → 详情 → 本地设置 → 不校验合法域名
```

### 17.7 图片问题

```vue
<!-- ❌ 错误：图片路径错误 -->
<image src="../../static/logo.png" />

<!-- ✅ 正确：使用绝对路径或 @ 别名 -->
<image src="/static/logo.png" />
<image src="@/static/logo.png" />

<!-- ❌ 错误：不设置 mode 导致图片变形 -->
<image src="/static/logo.png" />

<!-- ✅ 正确：设置合适的 mode -->
<image src="/static/logo.png" mode="aspectFill" />

<!-- ❌ 错误：不处理图片加载失败 -->
<image :src="imageUrl" />

<!-- ✅ 正确：处理加载失败 -->
<image 
  :src="imageUrl" 
  @error="onImageError"
/>

<script setup>
const onImageError = () => {
  imageUrl.value = '/static/default.png'
}
</script>
```

### 17.8 小程序审核问题

```typescript
// 1. 用户授权问题
// ❌ 错误：直接调用需要授权的 API
uni.getLocation({})  // 可能被拒绝

// ✅ 正确：先检查授权状态
const checkLocationAuth = async () => {
  const res = await uni.getSetting({})
  if (res.authSetting['scope.userLocation']) {
    // 已授权
    return uni.getLocation({})
  } else {
    // 未授权，引导用户
    uni.showModal({
      title: '提示',
      content: '需要获取您的位置信息',
      success: (res) => {
        if (res.confirm) {
          uni.openSetting({})
        }
      }
    })
  }
}

// 2. 隐私协议问题（微信小程序）
// 需要在小程序后台配置隐私协议
// 并在代码中处理隐私授权
```

### 17.9 TypeScript 类型问题

```typescript
// ❌ 错误：缺少类型定义
const res = await uni.request({ url: '/api/data' })
console.log(res.data.list)  // 类型错误

// ✅ 正确：定义响应类型
interface ApiResponse<T> {
  code: number
  message: string
  data: T
}

interface User {
  id: number
  name: string
}

const res = await uni.request<ApiResponse<User[]>>({ url: '/api/users' })
console.log(res.data.data)  // 正确的类型

// 扩展 uni 类型
// types/uni.d.ts
declare namespace UniApp {
  interface RequestSuccessCallbackResult {
    data: ApiResponse<any>
  }
}
```

### 17.10 调试技巧

```typescript
// 1. 使用 console 调试
console.log('数据:', JSON.stringify(data, null, 2))

// 2. 使用 vconsole（H5）
// #ifdef H5
import VConsole from 'vconsole'
new VConsole()
// #endif

// 3. 真机调试
// HBuilderX → 运行 → 运行到手机或模拟器

// 4. 小程序调试
// 微信开发者工具 → 调试器

// 5. 网络请求调试
// 使用 Charles 或 Fiddler 抓包

// 6. 性能分析
// 微信开发者工具 → 调试器 → Performance
```

---

## 总结

Uni-app 是一个强大的跨平台开发框架，掌握以下核心概念即可高效开发：

1. **项目结构**：理解 pages.json、manifest.json 的配置
2. **页面路由**：掌握各种跳转方式和参数传递
3. **组件开发**：熟悉内置组件和自定义组件
4. **条件编译**：针对不同平台编写差异化代码
5. **数据管理**：使用 Pinia 进行状态管理
6. **网络请求**：封装统一的请求工具
7. **原生能力**：调用设备功能和系统 API
8. **性能优化**：分包、懒加载、虚拟列表等
9. **打包发布**：针对不同平台的发布流程

---

> 📚 参考资源
> - [Uni-app 官方文档](https://uniapp.dcloud.net.cn/)
> - [Uni-app 插件市场](https://ext.dcloud.net.cn/)
> - [DCloud 社区](https://ask.dcloud.net.cn/)
> - [uni-ui 组件库](https://uniapp.dcloud.net.cn/component/uniui/uni-ui.html)
> - [uView UI](https://uviewui.com/)
