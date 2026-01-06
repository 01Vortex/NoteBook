# Tailwind CSS 完全指南

> Tailwind CSS 是一个功能类优先（Utility-First）的 CSS 框架，让你无需离开 HTML 即可快速构建现代网站
> 本笔记基于 Tailwind CSS v3.4+，涵盖从入门到高级的完整知识体系

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [布局系统](#3-布局系统)
4. [Flexbox](#4-flexbox)
5. [Grid 网格](#5-grid-网格)
6. [间距系统](#6-间距系统)
7. [尺寸与大小](#7-尺寸与大小)
8. [排版](#8-排版)
9. [背景与边框](#9-背景与边框)
10. [颜色系统](#10-颜色系统)
11. [效果与滤镜](#11-效果与滤镜)
12. [过渡与动画](#12-过渡与动画)
13. [响应式设计](#13-响应式设计)
14. [状态变体](#14-状态变体)
15. [深色模式](#15-深色模式)
16. [自定义配置](#16-自定义配置)
17. [组件模式](#17-组件模式)
18. [常见错误与解决方案](#18-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Tailwind CSS？

Tailwind CSS 是一个「功能类优先」的 CSS 框架。与 Bootstrap 等传统框架提供预设组件不同，Tailwind 提供的是底层的工具类（Utility Classes），让你像搭积木一样组合出任意设计。

**传统 CSS 写法：**
```html
<div class="chat-notification">
  <p class="chat-notification-title">新消息</p>
  <p class="chat-notification-message">你有一条未读消息</p>
</div>

<style>
.chat-notification {
  display: flex;
  padding: 1rem;
  background-color: #fff;
  border-radius: 0.5rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
.chat-notification-title {
  font-weight: 600;
  color: #1a202c;
}
.chat-notification-message {
  color: #718096;
}
</style>
```

**Tailwind CSS 写法：**
```html
<div class="flex p-4 bg-white rounded-lg shadow">
  <p class="font-semibold text-gray-900">新消息</p>
  <p class="text-gray-500">你有一条未读消息</p>
</div>
```

### 1.2 为什么选择 Tailwind？

| 优势 | 说明 |
|------|------|
| 开发效率高 | 无需在 HTML 和 CSS 文件间切换，直接在 HTML 中编写样式 |
| 无需命名 | 不用再为 class 命名发愁，告别 BEM 等命名规范的心智负担 |
| CSS 体积小 | 生产构建时自动移除未使用的样式，最终 CSS 通常只有几 KB |
| 设计一致性 | 内置设计系统（间距、颜色、字体等），保证视觉统一 |
| 响应式友好 | 通过前缀轻松实现响应式设计，如 `md:flex` |
| 高度可定制 | 通过配置文件自定义一切，适配任何设计规范 |

### 1.3 核心理念

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tailwind CSS 核心理念                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. 功能类优先 (Utility-First)                                       │
│     • 使用小而专一的类名组合样式                                      │
│     • 每个类只做一件事：text-center 只负责文本居中                    │
│                                                                      │
│  2. 约束式设计 (Constrained Design)                                  │
│     • 预设的设计令牌（Design Tokens）                                │
│     • 间距：0, 1, 2, 4, 8, 12, 16...                                │
│     • 颜色：gray-50, gray-100, gray-200...                          │
│                                                                      │
│  3. 响应式优先 (Mobile-First)                                        │
│     • 默认样式应用于所有屏幕                                         │
│     • 使用断点前缀覆盖：sm:, md:, lg:, xl:, 2xl:                    │
│                                                                      │
│  4. 状态变体 (State Variants)                                        │
│     • hover:, focus:, active:, disabled:                            │
│     • dark:, group-hover:, peer-checked:                            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```


---

## 2. 安装与配置

### 2.1 使用 Vite 安装（推荐）

```bash
# 创建 Vite 项目
npm create vite@latest my-project -- --template vue
cd my-project

# 安装 Tailwind CSS
npm install -D tailwindcss postcss autoprefixer

# 初始化配置文件
npx tailwindcss init -p
```

**配置 `tailwind.config.js`：**
```javascript
/** @type {import('tailwindcss').Config} */
export default {
  // 指定要扫描的文件路径
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

**在 CSS 中引入 Tailwind（`src/style.css`）：**
```css
@tailwind base;       /* 基础样式重置 */
@tailwind components; /* 组件类 */
@tailwind utilities;  /* 工具类 */
```

### 2.2 使用 CDN（快速体验）

```html
<!DOCTYPE html>
<html>
<head>
  <!-- 仅用于开发/学习，生产环境请使用构建工具 -->
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body>
  <h1 class="text-3xl font-bold text-blue-600">
    Hello Tailwind!
  </h1>
</body>
</html>
```

> ⚠️ **注意**：CDN 方式不支持自定义配置和 Tree-shaking，仅适合学习和原型开发。

### 2.3 与主流框架集成

**Vue 3 + Vite：**
```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

**React + Vite：**
```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

**Next.js：**
```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

**Nuxt 3：**
```bash
npm install -D @nuxtjs/tailwindcss
```
```javascript
// nuxt.config.ts
export default defineNuxtConfig({
  modules: ['@nuxtjs/tailwindcss']
})
```

### 2.4 编辑器配置

**VS Code 插件（强烈推荐）：**
- **Tailwind CSS IntelliSense**：提供类名自动补全、悬停预览、语法高亮
- **Headwind**：自动排序 Tailwind 类名

**配置 VS Code（`.vscode/settings.json`）：**
```json
{
  "tailwindCSS.includeLanguages": {
    "vue": "html",
    "vue-html": "html"
  },
  "editor.quickSuggestions": {
    "strings": true
  },
  "tailwindCSS.experimental.classRegex": [
    ["clsx\\(([^)]*)\\)", "(?:'|\"|`)([^']*)(?:'|\"|`)"]
  ]
}
```

### 2.5 PostCSS 配置

**`postcss.config.js`：**
```javascript
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
```

---

## 3. 布局系统

### 3.1 容器（Container）

容器用于将内容限制在最大宽度内，并自动居中。

```html
<!-- 基础容器 -->
<div class="container mx-auto">
  <!-- 内容自动居中，宽度随断点变化 -->
</div>

<!-- 带内边距的容器 -->
<div class="container mx-auto px-4">
  <!-- 左右留出间距 -->
</div>
```

**容器断点宽度：**
| 断点 | 最大宽度 |
|------|----------|
| sm (640px) | 640px |
| md (768px) | 768px |
| lg (1024px) | 1024px |
| xl (1280px) | 1280px |
| 2xl (1536px) | 1536px |

**自定义容器配置：**
```javascript
// tailwind.config.js
module.exports = {
  theme: {
    container: {
      center: true,  // 自动居中
      padding: '1rem', // 默认内边距
      screens: {
        sm: '640px',
        md: '768px',
        lg: '1024px',
        xl: '1280px',
        '2xl': '1400px', // 自定义最大宽度
      },
    },
  },
}
```

### 3.2 显示类型（Display）

```html
<!-- 块级元素 -->
<div class="block">Block</div>

<!-- 行内块 -->
<span class="inline-block">Inline Block</span>

<!-- 行内元素 -->
<span class="inline">Inline</span>

<!-- Flex 容器 -->
<div class="flex">Flex Container</div>

<!-- 行内 Flex -->
<div class="inline-flex">Inline Flex</div>

<!-- Grid 容器 -->
<div class="grid">Grid Container</div>

<!-- 隐藏元素 -->
<div class="hidden">Hidden</div>

<!-- 响应式显示/隐藏 -->
<div class="hidden md:block">
  <!-- 移动端隐藏，md 及以上显示 -->
</div>
<div class="block md:hidden">
  <!-- 移动端显示，md 及以上隐藏 -->
</div>
```

### 3.3 定位（Position）

```html
<!-- 定位类型 -->
<div class="static">Static（默认）</div>
<div class="relative">Relative</div>
<div class="absolute">Absolute</div>
<div class="fixed">Fixed</div>
<div class="sticky">Sticky</div>

<!-- 定位偏移 -->
<div class="relative">
  <div class="absolute top-0 left-0">左上角</div>
  <div class="absolute top-0 right-0">右上角</div>
  <div class="absolute bottom-0 left-0">左下角</div>
  <div class="absolute bottom-0 right-0">右下角</div>
  <div class="absolute inset-0">铺满父元素</div>
</div>

<!-- 常用偏移值 -->
<!-- top-0, top-1, top-2, top-4, top-8, top-1/2, top-full -->
<!-- right-0, bottom-0, left-0 同理 -->
<!-- inset-0 = top-0 right-0 bottom-0 left-0 -->
<!-- inset-x-0 = left-0 right-0 -->
<!-- inset-y-0 = top-0 bottom-0 -->

<!-- 实际案例：固定导航栏 -->
<nav class="fixed top-0 left-0 right-0 z-50 bg-white shadow">
  <!-- 导航内容 -->
</nav>

<!-- 实际案例：粘性侧边栏 -->
<aside class="sticky top-4">
  <!-- 滚动时固定在顶部 -->
</aside>

<!-- 实际案例：居中弹窗 -->
<div class="fixed inset-0 flex items-center justify-center bg-black/50">
  <div class="bg-white rounded-lg p-6">
    弹窗内容
  </div>
</div>
```

### 3.4 层叠顺序（Z-Index）

```html
<!-- z-index 值 -->
<div class="z-0">z-index: 0</div>
<div class="z-10">z-index: 10</div>
<div class="z-20">z-index: 20</div>
<div class="z-30">z-index: 30</div>
<div class="z-40">z-index: 40</div>
<div class="z-50">z-index: 50</div>
<div class="z-auto">z-index: auto</div>

<!-- 负值 -->
<div class="-z-10">z-index: -10</div>

<!-- 实际案例：层叠管理 -->
<div class="relative">
  <div class="absolute z-10">底层</div>
  <div class="absolute z-20">中层</div>
  <div class="absolute z-30">顶层</div>
</div>
```

### 3.5 溢出处理（Overflow）

```html
<!-- 溢出行为 -->
<div class="overflow-auto">自动滚动条</div>
<div class="overflow-hidden">隐藏溢出</div>
<div class="overflow-visible">显示溢出（默认）</div>
<div class="overflow-scroll">始终显示滚动条</div>

<!-- 单方向溢出 -->
<div class="overflow-x-auto">水平滚动</div>
<div class="overflow-y-auto">垂直滚动</div>
<div class="overflow-x-hidden overflow-y-auto">
  隐藏水平溢出，垂直可滚动
</div>

<!-- 实际案例：横向滚动列表 -->
<div class="flex overflow-x-auto space-x-4 pb-4">
  <div class="flex-shrink-0 w-64">卡片1</div>
  <div class="flex-shrink-0 w-64">卡片2</div>
  <div class="flex-shrink-0 w-64">卡片3</div>
</div>

<!-- 实际案例：固定高度可滚动区域 -->
<div class="h-64 overflow-y-auto">
  <!-- 长内容 -->
</div>
```

---

## 4. Flexbox

Flexbox 是 Tailwind 中最常用的布局方式，掌握它能解决 90% 的布局需求。

### 4.1 Flex 容器

```html
<!-- 启用 Flex -->
<div class="flex">
  <div>子元素1</div>
  <div>子元素2</div>
</div>

<!-- Flex 方向 -->
<div class="flex flex-row">水平排列（默认）</div>
<div class="flex flex-row-reverse">水平反向</div>
<div class="flex flex-col">垂直排列</div>
<div class="flex flex-col-reverse">垂直反向</div>

<!-- 换行 -->
<div class="flex flex-wrap">允许换行</div>
<div class="flex flex-nowrap">不换行（默认）</div>
<div class="flex flex-wrap-reverse">反向换行</div>
```

### 4.2 主轴对齐（Justify Content）

```html
<!-- 主轴对齐方式 -->
<div class="flex justify-start">起点对齐（默认）</div>
<div class="flex justify-center">居中对齐</div>
<div class="flex justify-end">终点对齐</div>
<div class="flex justify-between">两端对齐</div>
<div class="flex justify-around">均匀分布（两侧有间距）</div>
<div class="flex justify-evenly">完全均匀分布</div>

<!-- 可视化示例 -->
<!-- justify-start:    [1][2][3]          -->
<!-- justify-center:      [1][2][3]       -->
<!-- justify-end:              [1][2][3]  -->
<!-- justify-between:  [1]    [2]    [3]  -->
<!-- justify-around:   [1]  [2]  [3]      -->
<!-- justify-evenly:   [1]   [2]   [3]    -->
```

### 4.3 交叉轴对齐（Align Items）

```html
<!-- 交叉轴对齐方式 -->
<div class="flex items-start">顶部对齐</div>
<div class="flex items-center">垂直居中</div>
<div class="flex items-end">底部对齐</div>
<div class="flex items-baseline">基线对齐</div>
<div class="flex items-stretch">拉伸填充（默认）</div>

<!-- 完美居中（最常用！） -->
<div class="flex items-center justify-center h-screen">
  <div>我在页面正中央</div>
</div>
```

### 4.4 Flex 子元素

```html
<!-- flex-grow: 放大比例 -->
<div class="flex">
  <div class="flex-grow">占据剩余空间</div>
  <div>固定宽度</div>
</div>

<!-- flex-shrink: 缩小比例 -->
<div class="flex">
  <div class="flex-shrink-0">不缩小</div>
  <div class="flex-shrink">可缩小</div>
</div>

<!-- flex 简写 -->
<div class="flex-1">flex: 1 1 0%（等分空间）</div>
<div class="flex-auto">flex: 1 1 auto</div>
<div class="flex-initial">flex: 0 1 auto（默认）</div>
<div class="flex-none">flex: none（不伸缩）</div>

<!-- 单独对齐某个子元素 -->
<div class="flex items-start">
  <div>顶部</div>
  <div class="self-center">我居中</div>
  <div class="self-end">我在底部</div>
</div>

<!-- 排序 -->
<div class="flex">
  <div class="order-3">显示第三</div>
  <div class="order-1">显示第一</div>
  <div class="order-2">显示第二</div>
</div>
```

### 4.5 Flex 实战案例

```html
<!-- 导航栏 -->
<nav class="flex items-center justify-between px-6 py-4">
  <div class="text-xl font-bold">Logo</div>
  <div class="flex space-x-6">
    <a href="#">首页</a>
    <a href="#">产品</a>
    <a href="#">关于</a>
  </div>
  <button class="px-4 py-2 bg-blue-500 text-white rounded">登录</button>
</nav>

<!-- 卡片列表 -->
<div class="flex flex-wrap -mx-2">
  <div class="w-full md:w-1/2 lg:w-1/3 px-2 mb-4">
    <div class="bg-white rounded-lg shadow p-4">卡片1</div>
  </div>
  <div class="w-full md:w-1/2 lg:w-1/3 px-2 mb-4">
    <div class="bg-white rounded-lg shadow p-4">卡片2</div>
  </div>
  <div class="w-full md:w-1/2 lg:w-1/3 px-2 mb-4">
    <div class="bg-white rounded-lg shadow p-4">卡片3</div>
  </div>
</div>

<!-- 页脚固定在底部 -->
<div class="flex flex-col min-h-screen">
  <header>头部</header>
  <main class="flex-grow">主内容区</main>
  <footer>页脚始终在底部</footer>
</div>

<!-- 媒体对象 -->
<div class="flex space-x-4">
  <img class="w-16 h-16 rounded-full flex-shrink-0" src="avatar.jpg" alt="">
  <div>
    <h3 class="font-bold">用户名</h3>
    <p class="text-gray-600">这是一段描述文字...</p>
  </div>
</div>

<!-- 输入框组 -->
<div class="flex">
  <span class="inline-flex items-center px-3 bg-gray-200 border border-r-0 border-gray-300 rounded-l">
    @
  </span>
  <input class="flex-1 px-3 py-2 border border-gray-300 rounded-r focus:outline-none focus:ring-2" 
         type="text" placeholder="用户名">
</div>
```

---

## 5. Grid 网格

Grid 布局适合复杂的二维布局，比 Flexbox 更强大。

### 5.1 Grid 容器

```html
<!-- 基础 Grid -->
<div class="grid grid-cols-3 gap-4">
  <div>1</div>
  <div>2</div>
  <div>3</div>
  <div>4</div>
  <div>5</div>
  <div>6</div>
</div>

<!-- 列数 -->
<div class="grid grid-cols-1">1列</div>
<div class="grid grid-cols-2">2列</div>
<div class="grid grid-cols-3">3列</div>
<div class="grid grid-cols-4">4列</div>
<div class="grid grid-cols-6">6列</div>
<div class="grid grid-cols-12">12列</div>
<div class="grid grid-cols-none">无网格</div>

<!-- 响应式列数 -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
  <!-- 移动端1列，md 2列，lg 3列，xl 4列 -->
</div>

<!-- 行数 -->
<div class="grid grid-rows-3 grid-flow-col">
  <!-- 3行，按列填充 -->
</div>
```

### 5.2 间距（Gap）

```html
<!-- 统一间距 -->
<div class="grid grid-cols-3 gap-4">gap: 1rem</div>
<div class="grid grid-cols-3 gap-8">gap: 2rem</div>

<!-- 分别设置行列间距 -->
<div class="grid grid-cols-3 gap-x-4 gap-y-8">
  <!-- 列间距 1rem，行间距 2rem -->
</div>

<!-- 常用 gap 值 -->
<!-- gap-0, gap-1, gap-2, gap-3, gap-4, gap-5, gap-6, gap-8, gap-10, gap-12 -->
```

### 5.3 跨列跨行

```html
<!-- 跨列 -->
<div class="grid grid-cols-3 gap-4">
  <div class="col-span-2">跨2列</div>
  <div>1列</div>
  <div class="col-span-3">跨3列（整行）</div>
</div>

<!-- 跨行 -->
<div class="grid grid-cols-3 grid-rows-3 gap-4">
  <div class="row-span-2">跨2行</div>
  <div>普通</div>
  <div class="row-span-3">跨3行</div>
</div>

<!-- 起始位置 -->
<div class="grid grid-cols-6 gap-4">
  <div class="col-start-2 col-span-4">从第2列开始，跨4列</div>
  <div class="col-start-1 col-end-3">从第1列到第3列</div>
</div>

<!-- 实际案例：仪表盘布局 -->
<div class="grid grid-cols-4 grid-rows-3 gap-4 h-screen">
  <div class="col-span-4 bg-gray-800">顶部导航</div>
  <div class="row-span-2 bg-gray-200">侧边栏</div>
  <div class="col-span-2 bg-white">主内容区</div>
  <div class="bg-white">小部件1</div>
  <div class="col-span-2 bg-white">底部内容</div>
  <div class="bg-white">小部件2</div>
</div>
```

### 5.4 Grid 对齐

```html
<!-- 内容对齐（整体） -->
<div class="grid justify-items-start">左对齐</div>
<div class="grid justify-items-center">水平居中</div>
<div class="grid justify-items-end">右对齐</div>
<div class="grid justify-items-stretch">拉伸（默认）</div>

<!-- 垂直对齐 -->
<div class="grid items-start">顶部</div>
<div class="grid items-center">垂直居中</div>
<div class="grid items-end">底部</div>

<!-- 同时居中 -->
<div class="grid place-items-center h-screen">
  <div>完美居中</div>
</div>

<!-- 单个元素对齐 -->
<div class="grid grid-cols-3">
  <div class="justify-self-start">左</div>
  <div class="justify-self-center">中</div>
  <div class="justify-self-end">右</div>
</div>
```

### 5.5 自动填充

```html
<!-- 自动填充列 -->
<div class="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-4">
  <!-- 自动计算列数，每列最小200px -->
  <div>卡片</div>
  <div>卡片</div>
  <div>卡片</div>
</div>

<!-- 使用任意值语法 -->
<div class="grid grid-cols-[200px_1fr_200px]">
  <!-- 左侧200px，中间自适应，右侧200px -->
</div>
```

---

## 6. 间距系统

Tailwind 的间距系统是其设计系统的核心，保证了视觉一致性。

### 6.1 间距比例

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tailwind 间距比例表                               │
├─────────────────────────────────────────────────────────────────────┤
│  类名      │  rem    │  px     │  说明                              │
├───────────┼─────────┼─────────┼────────────────────────────────────┤
│  0        │  0      │  0      │  无间距                            │
│  px       │  1px    │  1px    │  1像素                             │
│  0.5      │  0.125  │  2px    │                                    │
│  1        │  0.25   │  4px    │  基础单位                          │
│  1.5      │  0.375  │  6px    │                                    │
│  2        │  0.5    │  8px    │                                    │
│  2.5      │  0.625  │  10px   │                                    │
│  3        │  0.75   │  12px   │                                    │
│  3.5      │  0.875  │  14px   │                                    │
│  4        │  1      │  16px   │  常用                              │
│  5        │  1.25   │  20px   │                                    │
│  6        │  1.5    │  24px   │                                    │
│  7        │  1.75   │  28px   │                                    │
│  8        │  2      │  32px   │  常用                              │
│  9        │  2.25   │  36px   │                                    │
│  10       │  2.5    │  40px   │                                    │
│  11       │  2.75   │  44px   │                                    │
│  12       │  3      │  48px   │                                    │
│  14       │  3.5    │  56px   │                                    │
│  16       │  4      │  64px   │                                    │
│  20       │  5      │  80px   │                                    │
│  24       │  6      │  96px   │                                    │
│  28       │  7      │  112px  │                                    │
│  32       │  8      │  128px  │                                    │
│  36       │  9      │  144px  │                                    │
│  40       │  10     │  160px  │                                    │
│  44       │  11     │  176px  │                                    │
│  48       │  12     │  192px  │                                    │
│  52       │  13     │  208px  │                                    │
│  56       │  14     │  224px  │                                    │
│  60       │  15     │  240px  │                                    │
│  64       │  16     │  256px  │                                    │
│  72       │  18     │  288px  │                                    │
│  80       │  20     │  320px  │                                    │
│  96       │  24     │  384px  │                                    │
└───────────┴─────────┴─────────┴────────────────────────────────────┘
```

### 6.2 内边距（Padding）

```html
<!-- 四周内边距 -->
<div class="p-4">padding: 1rem</div>
<div class="p-8">padding: 2rem</div>

<!-- 单方向内边距 -->
<div class="pt-4">padding-top: 1rem</div>
<div class="pr-4">padding-right: 1rem</div>
<div class="pb-4">padding-bottom: 1rem</div>
<div class="pl-4">padding-left: 1rem</div>

<!-- 水平/垂直内边距 -->
<div class="px-4">padding-left + padding-right: 1rem</div>
<div class="py-4">padding-top + padding-bottom: 1rem</div>

<!-- 组合使用 -->
<div class="px-6 py-4">水平1.5rem，垂直1rem</div>

<!-- 常见按钮内边距 -->
<button class="px-4 py-2">普通按钮</button>
<button class="px-6 py-3">大按钮</button>
<button class="px-3 py-1">小按钮</button>
```

### 6.3 外边距（Margin）

```html
<!-- 四周外边距 -->
<div class="m-4">margin: 1rem</div>

<!-- 单方向外边距 -->
<div class="mt-4">margin-top: 1rem</div>
<div class="mr-4">margin-right: 1rem</div>
<div class="mb-4">margin-bottom: 1rem</div>
<div class="ml-4">margin-left: 1rem</div>

<!-- 水平/垂直外边距 -->
<div class="mx-4">margin-left + margin-right: 1rem</div>
<div class="my-4">margin-top + margin-bottom: 1rem</div>

<!-- 自动外边距（居中） -->
<div class="mx-auto w-1/2">水平居中</div>

<!-- 负外边距 -->
<div class="-mt-4">margin-top: -1rem</div>
<div class="-mx-4">负水平外边距</div>

<!-- 实际案例：卡片列表负边距技巧 -->
<div class="flex flex-wrap -mx-2">
  <div class="w-1/3 px-2 mb-4">
    <div class="bg-white p-4">卡片</div>
  </div>
  <!-- 更多卡片... -->
</div>
```

### 6.4 Space Between（子元素间距）

`space-x` 和 `space-y` 是给子元素之间添加间距的便捷方式。

```html
<!-- 水平间距 -->
<div class="flex space-x-4">
  <div>1</div>
  <div>2</div>
  <div>3</div>
</div>
<!-- 等同于给每个子元素（除第一个）添加 margin-left -->

<!-- 垂直间距 -->
<div class="flex flex-col space-y-4">
  <div>1</div>
  <div>2</div>
  <div>3</div>
</div>

<!-- 反向间距（用于 flex-row-reverse） -->
<div class="flex flex-row-reverse space-x-4 space-x-reverse">
  <div>1</div>
  <div>2</div>
  <div>3</div>
</div>

<!-- 实际案例：表单 -->
<form class="space-y-4">
  <div>
    <label>用户名</label>
    <input type="text" class="w-full">
  </div>
  <div>
    <label>密码</label>
    <input type="password" class="w-full">
  </div>
  <button type="submit">提交</button>
</form>

<!-- 实际案例：按钮组 -->
<div class="flex space-x-2">
  <button class="px-4 py-2 bg-blue-500 text-white rounded">保存</button>
  <button class="px-4 py-2 bg-gray-200 rounded">取消</button>
</div>
```

> ⚠️ **注意**：`space-*` 使用的是相邻兄弟选择器，如果子元素被隐藏或动态添加，可能会出现意外间距。这种情况建议使用 `gap`。

---

## 7. 尺寸与大小

### 7.1 宽度（Width）

```html
<!-- 固定宽度 -->
<div class="w-0">0</div>
<div class="w-1">0.25rem (4px)</div>
<div class="w-4">1rem (16px)</div>
<div class="w-8">2rem (32px)</div>
<div class="w-16">4rem (64px)</div>
<div class="w-32">8rem (128px)</div>
<div class="w-64">16rem (256px)</div>
<div class="w-96">24rem (384px)</div>

<!-- 百分比宽度 -->
<div class="w-1/2">50%</div>
<div class="w-1/3">33.333%</div>
<div class="w-2/3">66.667%</div>
<div class="w-1/4">25%</div>
<div class="w-3/4">75%</div>
<div class="w-1/5">20%</div>
<div class="w-2/5">40%</div>
<div class="w-full">100%</div>

<!-- 视口宽度 -->
<div class="w-screen">100vw</div>

<!-- 内容宽度 -->
<div class="w-auto">auto</div>
<div class="w-fit">fit-content</div>
<div class="w-min">min-content</div>
<div class="w-max">max-content</div>

<!-- 最小/最大宽度 -->
<div class="min-w-0">min-width: 0</div>
<div class="min-w-full">min-width: 100%</div>
<div class="max-w-xs">max-width: 20rem</div>
<div class="max-w-sm">max-width: 24rem</div>
<div class="max-w-md">max-width: 28rem</div>
<div class="max-w-lg">max-width: 32rem</div>
<div class="max-w-xl">max-width: 36rem</div>
<div class="max-w-2xl">max-width: 42rem</div>
<div class="max-w-full">max-width: 100%</div>
<div class="max-w-screen-sm">max-width: 640px</div>
<div class="max-w-screen-md">max-width: 768px</div>
<div class="max-w-screen-lg">max-width: 1024px</div>
<div class="max-w-screen-xl">max-width: 1280px</div>
```

### 7.2 高度（Height）

```html
<!-- 固定高度 -->
<div class="h-4">1rem</div>
<div class="h-8">2rem</div>
<div class="h-16">4rem</div>
<div class="h-32">8rem</div>
<div class="h-64">16rem</div>

<!-- 百分比高度 -->
<div class="h-1/2">50%</div>
<div class="h-full">100%</div>

<!-- 视口高度 -->
<div class="h-screen">100vh</div>
<div class="h-svh">100svh（小视口高度）</div>
<div class="h-lvh">100lvh（大视口高度）</div>
<div class="h-dvh">100dvh（动态视口高度）</div>

<!-- 最小/最大高度 -->
<div class="min-h-0">min-height: 0</div>
<div class="min-h-full">min-height: 100%</div>
<div class="min-h-screen">min-height: 100vh</div>
<div class="max-h-64">max-height: 16rem</div>
<div class="max-h-full">max-height: 100%</div>
<div class="max-h-screen">max-height: 100vh</div>

<!-- 实际案例：全屏布局 -->
<div class="min-h-screen flex flex-col">
  <header class="h-16">导航</header>
  <main class="flex-grow">内容</main>
  <footer class="h-20">页脚</footer>
</div>
```

### 7.3 尺寸（Size）

`size-*` 是同时设置宽高的快捷方式（Tailwind v3.4+）。

```html
<!-- 同时设置宽高 -->
<div class="size-4">16px × 16px</div>
<div class="size-8">32px × 32px</div>
<div class="size-16">64px × 64px</div>
<div class="size-full">100% × 100%</div>

<!-- 实际案例：头像 -->
<img class="size-10 rounded-full" src="avatar.jpg" alt="">
<img class="size-12 rounded-full" src="avatar.jpg" alt="">
<img class="size-16 rounded-full" src="avatar.jpg" alt="">

<!-- 实际案例：图标按钮 -->
<button class="size-10 flex items-center justify-center rounded-full bg-gray-100">
  <svg class="size-5">...</svg>
</button>
```

---

## 8. 排版

### 8.1 字体大小

```html
<!-- 字体大小 -->
<p class="text-xs">12px / 0.75rem</p>
<p class="text-sm">14px / 0.875rem</p>
<p class="text-base">16px / 1rem（默认）</p>
<p class="text-lg">18px / 1.125rem</p>
<p class="text-xl">20px / 1.25rem</p>
<p class="text-2xl">24px / 1.5rem</p>
<p class="text-3xl">30px / 1.875rem</p>
<p class="text-4xl">36px / 2.25rem</p>
<p class="text-5xl">48px / 3rem</p>
<p class="text-6xl">60px / 3.75rem</p>
<p class="text-7xl">72px / 4.5rem</p>
<p class="text-8xl">96px / 6rem</p>
<p class="text-9xl">128px / 8rem</p>

<!-- 响应式字体 -->
<h1 class="text-2xl md:text-4xl lg:text-6xl">
  响应式标题
</h1>
```

### 8.2 字体粗细

```html
<p class="font-thin">100 - Thin</p>
<p class="font-extralight">200 - Extra Light</p>
<p class="font-light">300 - Light</p>
<p class="font-normal">400 - Normal</p>
<p class="font-medium">500 - Medium</p>
<p class="font-semibold">600 - Semi Bold</p>
<p class="font-bold">700 - Bold</p>
<p class="font-extrabold">800 - Extra Bold</p>
<p class="font-black">900 - Black</p>
```

### 8.3 行高

```html
<!-- 固定行高 -->
<p class="leading-3">0.75rem</p>
<p class="leading-4">1rem</p>
<p class="leading-5">1.25rem</p>
<p class="leading-6">1.5rem</p>
<p class="leading-7">1.75rem</p>
<p class="leading-8">2rem</p>
<p class="leading-9">2.25rem</p>
<p class="leading-10">2.5rem</p>

<!-- 相对行高 -->
<p class="leading-none">1（无行高）</p>
<p class="leading-tight">1.25</p>
<p class="leading-snug">1.375</p>
<p class="leading-normal">1.5（默认）</p>
<p class="leading-relaxed">1.625</p>
<p class="leading-loose">2</p>
```

### 8.4 文本对齐

```html
<p class="text-left">左对齐</p>
<p class="text-center">居中</p>
<p class="text-right">右对齐</p>
<p class="text-justify">两端对齐</p>
<p class="text-start">起始对齐（支持 RTL）</p>
<p class="text-end">结束对齐（支持 RTL）</p>
```

### 8.5 文本颜色

```html
<!-- 基础颜色 -->
<p class="text-black">黑色</p>
<p class="text-white">白色</p>
<p class="text-transparent">透明</p>

<!-- 灰度 -->
<p class="text-gray-50">最浅灰</p>
<p class="text-gray-100">...</p>
<p class="text-gray-200">...</p>
<p class="text-gray-300">...</p>
<p class="text-gray-400">...</p>
<p class="text-gray-500">中灰</p>
<p class="text-gray-600">...</p>
<p class="text-gray-700">...</p>
<p class="text-gray-800">...</p>
<p class="text-gray-900">最深灰</p>
<p class="text-gray-950">近黑</p>

<!-- 彩色 -->
<p class="text-red-500">红色</p>
<p class="text-blue-500">蓝色</p>
<p class="text-green-500">绿色</p>
<p class="text-yellow-500">黄色</p>
<p class="text-purple-500">紫色</p>
<p class="text-pink-500">粉色</p>

<!-- 透明度 -->
<p class="text-black/50">50% 透明度黑色</p>
<p class="text-blue-500/75">75% 透明度蓝色</p>
```

### 8.6 文本装饰

```html
<!-- 下划线 -->
<p class="underline">下划线</p>
<p class="overline">上划线</p>
<p class="line-through">删除线</p>
<p class="no-underline">无装饰</p>

<!-- 下划线样式 -->
<p class="underline decoration-solid">实线</p>
<p class="underline decoration-double">双线</p>
<p class="underline decoration-dotted">点线</p>
<p class="underline decoration-dashed">虚线</p>
<p class="underline decoration-wavy">波浪线</p>

<!-- 下划线颜色 -->
<p class="underline decoration-red-500">红色下划线</p>

<!-- 下划线粗细 -->
<p class="underline decoration-1">1px</p>
<p class="underline decoration-2">2px</p>
<p class="underline decoration-4">4px</p>

<!-- 下划线偏移 -->
<p class="underline underline-offset-1">偏移1</p>
<p class="underline underline-offset-2">偏移2</p>
<p class="underline underline-offset-4">偏移4</p>
<p class="underline underline-offset-8">偏移8</p>
```

### 8.7 文本溢出

```html
<!-- 截断单行文本 -->
<p class="truncate">
  这是一段很长的文本，超出部分会被截断并显示省略号...
</p>
<!-- truncate = overflow-hidden + text-overflow: ellipsis + white-space: nowrap -->

<!-- 多行截断 -->
<p class="line-clamp-2">
  这是一段很长的文本，会在第二行末尾截断并显示省略号。
  这是第二行内容。这是第三行内容，会被隐藏。
</p>
<p class="line-clamp-3">限制3行</p>

<!-- 文本换行 -->
<p class="whitespace-normal">正常换行</p>
<p class="whitespace-nowrap">不换行</p>
<p class="whitespace-pre">保留空格和换行</p>
<p class="whitespace-pre-line">保留换行，合并空格</p>
<p class="whitespace-pre-wrap">保留空格和换行，自动换行</p>

<!-- 单词断行 -->
<p class="break-normal">正常断行</p>
<p class="break-words">长单词可断行</p>
<p class="break-all">任意位置断行</p>
```

### 8.8 字体样式

```html
<!-- 字体族 -->
<p class="font-sans">无衬线字体（默认）</p>
<p class="font-serif">衬线字体</p>
<p class="font-mono">等宽字体</p>

<!-- 斜体 -->
<p class="italic">斜体</p>
<p class="not-italic">非斜体</p>

<!-- 字母间距 -->
<p class="tracking-tighter">更紧凑</p>
<p class="tracking-tight">紧凑</p>
<p class="tracking-normal">正常</p>
<p class="tracking-wide">宽松</p>
<p class="tracking-wider">更宽松</p>
<p class="tracking-widest">最宽松</p>

<!-- 大小写转换 -->
<p class="uppercase">UPPERCASE 大写</p>
<p class="lowercase">lowercase 小写</p>
<p class="capitalize">Capitalize 首字母大写</p>
<p class="normal-case">Normal Case 正常</p>
```

---

## 9. 背景与边框

### 9.1 背景颜色

```html
<!-- 背景色 -->
<div class="bg-white">白色背景</div>
<div class="bg-black">黑色背景</div>
<div class="bg-gray-100">浅灰背景</div>
<div class="bg-blue-500">蓝色背景</div>
<div class="bg-red-500">红色背景</div>

<!-- 透明度 -->
<div class="bg-black/50">50% 透明度黑色</div>
<div class="bg-blue-500/25">25% 透明度蓝色</div>

<!-- 渐变背景 -->
<div class="bg-gradient-to-r from-blue-500 to-purple-500">
  从左到右渐变
</div>
<div class="bg-gradient-to-br from-pink-500 via-red-500 to-yellow-500">
  从左上到右下，三色渐变
</div>

<!-- 渐变方向 -->
<!-- bg-gradient-to-t  上 -->
<!-- bg-gradient-to-tr 右上 -->
<!-- bg-gradient-to-r  右 -->
<!-- bg-gradient-to-br 右下 -->
<!-- bg-gradient-to-b  下 -->
<!-- bg-gradient-to-bl 左下 -->
<!-- bg-gradient-to-l  左 -->
<!-- bg-gradient-to-tl 左上 -->
```

### 9.2 背景图片

```html
<!-- 背景图片 -->
<div class="bg-[url('/img/hero.jpg')]">
  使用任意值语法设置背景图
</div>

<!-- 背景大小 -->
<div class="bg-auto">原始大小</div>
<div class="bg-cover">覆盖（可能裁剪）</div>
<div class="bg-contain">包含（完整显示）</div>

<!-- 背景位置 -->
<div class="bg-center">居中</div>
<div class="bg-top">顶部</div>
<div class="bg-bottom">底部</div>
<div class="bg-left">左侧</div>
<div class="bg-right">右侧</div>
<div class="bg-left-top">左上</div>
<div class="bg-right-bottom">右下</div>

<!-- 背景重复 -->
<div class="bg-repeat">重复</div>
<div class="bg-no-repeat">不重复</div>
<div class="bg-repeat-x">水平重复</div>
<div class="bg-repeat-y">垂直重复</div>

<!-- 背景固定 -->
<div class="bg-fixed">固定（视差效果）</div>
<div class="bg-local">随内容滚动</div>
<div class="bg-scroll">随页面滚动</div>

<!-- 实际案例：Hero 区域 -->
<div class="bg-[url('/hero.jpg')] bg-cover bg-center bg-no-repeat h-screen">
  <div class="bg-black/50 h-full flex items-center justify-center">
    <h1 class="text-white text-5xl font-bold">欢迎</h1>
  </div>
</div>
```

### 9.3 边框

```html
<!-- 边框宽度 -->
<div class="border">1px 边框</div>
<div class="border-0">无边框</div>
<div class="border-2">2px 边框</div>
<div class="border-4">4px 边框</div>
<div class="border-8">8px 边框</div>

<!-- 单边边框 -->
<div class="border-t">上边框</div>
<div class="border-r">右边框</div>
<div class="border-b">下边框</div>
<div class="border-l">左边框</div>
<div class="border-x">左右边框</div>
<div class="border-y">上下边框</div>

<!-- 边框颜色 -->
<div class="border border-gray-300">灰色边框</div>
<div class="border border-blue-500">蓝色边框</div>
<div class="border border-transparent">透明边框</div>

<!-- 边框样式 -->
<div class="border border-solid">实线</div>
<div class="border border-dashed">虚线</div>
<div class="border border-dotted">点线</div>
<div class="border border-double">双线</div>
<div class="border-none">无边框</div>

<!-- 实际案例：输入框 -->
<input class="border border-gray-300 rounded px-3 py-2 
              focus:border-blue-500 focus:ring-2 focus:ring-blue-200 
              focus:outline-none" 
       type="text" placeholder="请输入">
```

### 9.4 圆角

```html
<!-- 圆角大小 -->
<div class="rounded-none">无圆角</div>
<div class="rounded-sm">2px</div>
<div class="rounded">4px（默认）</div>
<div class="rounded-md">6px</div>
<div class="rounded-lg">8px</div>
<div class="rounded-xl">12px</div>
<div class="rounded-2xl">16px</div>
<div class="rounded-3xl">24px</div>
<div class="rounded-full">完全圆角（圆形/胶囊形）</div>

<!-- 单角圆角 -->
<div class="rounded-t-lg">上方圆角</div>
<div class="rounded-r-lg">右侧圆角</div>
<div class="rounded-b-lg">下方圆角</div>
<div class="rounded-l-lg">左侧圆角</div>
<div class="rounded-tl-lg">左上圆角</div>
<div class="rounded-tr-lg">右上圆角</div>
<div class="rounded-bl-lg">左下圆角</div>
<div class="rounded-br-lg">右下圆角</div>

<!-- 实际案例：圆形头像 -->
<img class="w-16 h-16 rounded-full" src="avatar.jpg" alt="">

<!-- 实际案例：胶囊按钮 -->
<button class="px-6 py-2 bg-blue-500 text-white rounded-full">
  胶囊按钮
</button>

<!-- 实际案例：卡片 -->
<div class="bg-white rounded-xl shadow-lg overflow-hidden">
  <img class="w-full h-48 object-cover" src="cover.jpg" alt="">
  <div class="p-4">
    <h3 class="font-bold">卡片标题</h3>
  </div>
</div>
```

### 9.5 轮廓（Outline）

```html
<!-- 轮廓宽度 -->
<div class="outline outline-1">1px 轮廓</div>
<div class="outline outline-2">2px 轮廓</div>
<div class="outline outline-4">4px 轮廓</div>

<!-- 轮廓颜色 -->
<div class="outline outline-2 outline-blue-500">蓝色轮廓</div>

<!-- 轮廓样式 -->
<div class="outline outline-dashed">虚线轮廓</div>
<div class="outline outline-dotted">点线轮廓</div>

<!-- 轮廓偏移 -->
<div class="outline outline-2 outline-offset-2">偏移2px</div>
<div class="outline outline-2 outline-offset-4">偏移4px</div>

<!-- 移除轮廓（常用于 focus 状态） -->
<button class="focus:outline-none">无焦点轮廓</button>
```

### 9.6 环形（Ring）

Ring 是 Tailwind 特有的概念，用于创建类似轮廓的效果，常用于焦点状态。

```html
<!-- 环形宽度 -->
<div class="ring">3px 环形（默认）</div>
<div class="ring-0">无环形</div>
<div class="ring-1">1px</div>
<div class="ring-2">2px</div>
<div class="ring-4">4px</div>
<div class="ring-8">8px</div>

<!-- 环形颜色 -->
<div class="ring-2 ring-blue-500">蓝色环形</div>
<div class="ring-2 ring-red-500">红色环形</div>

<!-- 环形偏移 -->
<div class="ring-2 ring-offset-2">偏移2px</div>
<div class="ring-2 ring-offset-4 ring-offset-gray-100">偏移4px，偏移色为灰色</div>

<!-- 内嵌环形 -->
<div class="ring-2 ring-inset ring-blue-500">内嵌环形</div>

<!-- 实际案例：焦点状态 -->
<button class="px-4 py-2 bg-blue-500 text-white rounded
               focus:ring-4 focus:ring-blue-300 focus:outline-none">
  点击我
</button>

<!-- 实际案例：选中状态 -->
<div class="p-4 border rounded cursor-pointer
            hover:border-blue-500
            focus:ring-2 focus:ring-blue-500">
  可选卡片
</div>
```

---

## 10. 颜色系统

### 10.1 默认调色板

Tailwind 提供了一套精心设计的调色板，每种颜色有 11 个深浅级别（50-950）。

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tailwind 默认颜色                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  灰度系列:                                                           │
│  slate    - 蓝灰色（偏冷）                                          │
│  gray     - 纯灰色                                                  │
│  zinc     - 锌灰色                                                  │
│  neutral  - 中性灰                                                  │
│  stone    - 石灰色（偏暖）                                          │
│                                                                      │
│  彩色系列:                                                           │
│  red      - 红色                                                    │
│  orange   - 橙色                                                    │
│  amber    - 琥珀色                                                  │
│  yellow   - 黄色                                                    │
│  lime     - 青柠色                                                  │
│  green    - 绿色                                                    │
│  emerald  - 翡翠绿                                                  │
│  teal     - 青色                                                    │
│  cyan     - 蓝绿色                                                  │
│  sky      - 天蓝色                                                  │
│  blue     - 蓝色                                                    │
│  indigo   - 靛蓝色                                                  │
│  violet   - 紫罗兰                                                  │
│  purple   - 紫色                                                    │
│  fuchsia  - 品红色                                                  │
│  pink     - 粉色                                                    │
│  rose     - 玫瑰色                                                  │
│                                                                      │
│  每种颜色的级别: 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950│
│  数字越小越浅，越大越深                                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 10.2 颜色使用

```html
<!-- 文本颜色 -->
<p class="text-blue-500">蓝色文本</p>
<p class="text-gray-700">深灰文本</p>

<!-- 背景颜色 -->
<div class="bg-blue-500">蓝色背景</div>
<div class="bg-gray-100">浅灰背景</div>

<!-- 边框颜色 -->
<div class="border border-blue-500">蓝色边框</div>

<!-- 环形颜色 -->
<div class="ring-2 ring-blue-500">蓝色环形</div>

<!-- 分割线颜色 -->
<div class="divide-y divide-gray-200">
  <div>项目1</div>
  <div>项目2</div>
</div>

<!-- 占位符颜色 -->
<input class="placeholder-gray-400" placeholder="请输入">

<!-- 透明度 -->
<div class="bg-blue-500/50">50% 透明度</div>
<div class="bg-blue-500/[0.35]">35% 透明度（任意值）</div>
<div class="text-black/75">75% 透明度文本</div>
```

### 10.3 自定义颜色

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        // 添加单个颜色
        'brand': '#FF6B6B',
        
        // 添加颜色系列
        'brand': {
          50: '#FFF5F5',
          100: '#FFE3E3',
          200: '#FFC9C9',
          300: '#FFA8A8',
          400: '#FF8787',
          500: '#FF6B6B',  // 主色
          600: '#FA5252',
          700: '#F03E3E',
          800: '#E03131',
          900: '#C92A2A',
          950: '#A51111',
        },
        
        // 使用 CSS 变量
        'primary': 'var(--color-primary)',
      },
    },
  },
}
```

```html
<!-- 使用自定义颜色 -->
<div class="bg-brand">品牌色背景</div>
<div class="bg-brand-500">品牌色 500</div>
<div class="text-brand-700">品牌色文本</div>
```


---

## 11. 效果与滤镜

### 11.1 阴影

```html
<!-- 盒阴影 -->
<div class="shadow-sm">小阴影</div>
<div class="shadow">默认阴影</div>
<div class="shadow-md">中等阴影</div>
<div class="shadow-lg">大阴影</div>
<div class="shadow-xl">超大阴影</div>
<div class="shadow-2xl">最大阴影</div>
<div class="shadow-inner">内阴影</div>
<div class="shadow-none">无阴影</div>

<!-- 阴影颜色 -->
<div class="shadow-lg shadow-blue-500/50">蓝色阴影</div>
<div class="shadow-lg shadow-red-500/40">红色阴影</div>

<!-- 实际案例：悬浮卡片 -->
<div class="bg-white rounded-lg shadow-md hover:shadow-xl transition-shadow">
  卡片内容
</div>

<!-- 实际案例：按钮阴影 -->
<button class="px-6 py-3 bg-blue-500 text-white rounded-lg
               shadow-lg shadow-blue-500/50
               hover:shadow-xl hover:shadow-blue-500/40
               transition-shadow">
  立体按钮
</button>
```

### 11.2 透明度

```html
<!-- 元素透明度 -->
<div class="opacity-0">完全透明</div>
<div class="opacity-25">25%</div>
<div class="opacity-50">50%</div>
<div class="opacity-75">75%</div>
<div class="opacity-100">完全不透明</div>

<!-- 悬浮时改变透明度 -->
<img class="opacity-75 hover:opacity-100 transition-opacity" src="...">

<!-- 禁用状态 -->
<button class="disabled:opacity-50" disabled>禁用按钮</button>
```

### 11.3 混合模式

```html
<!-- 混合模式 -->
<div class="mix-blend-normal">正常</div>
<div class="mix-blend-multiply">正片叠底</div>
<div class="mix-blend-screen">滤色</div>
<div class="mix-blend-overlay">叠加</div>
<div class="mix-blend-darken">变暗</div>
<div class="mix-blend-lighten">变亮</div>
<div class="mix-blend-color-dodge">颜色减淡</div>
<div class="mix-blend-color-burn">颜色加深</div>
<div class="mix-blend-difference">差值</div>

<!-- 背景混合模式 -->
<div class="bg-blend-multiply">背景正片叠底</div>

<!-- 实际案例：图片叠加效果 -->
<div class="relative">
  <img src="photo.jpg" alt="">
  <div class="absolute inset-0 bg-blue-500 mix-blend-multiply"></div>
</div>
```

### 11.4 滤镜

```html
<!-- 模糊 -->
<div class="blur-none">无模糊</div>
<div class="blur-sm">轻微模糊</div>
<div class="blur">默认模糊</div>
<div class="blur-md">中等模糊</div>
<div class="blur-lg">大模糊</div>
<div class="blur-xl">超大模糊</div>
<div class="blur-2xl">最大模糊</div>
<div class="blur-3xl">极大模糊</div>

<!-- 亮度 -->
<div class="brightness-50">50% 亮度</div>
<div class="brightness-75">75% 亮度</div>
<div class="brightness-100">100% 亮度</div>
<div class="brightness-125">125% 亮度</div>
<div class="brightness-150">150% 亮度</div>

<!-- 对比度 -->
<div class="contrast-50">50% 对比度</div>
<div class="contrast-100">100% 对比度</div>
<div class="contrast-150">150% 对比度</div>

<!-- 灰度 -->
<div class="grayscale">完全灰度</div>
<div class="grayscale-0">无灰度</div>

<!-- 色相旋转 -->
<div class="hue-rotate-90">旋转90度</div>
<div class="hue-rotate-180">旋转180度</div>

<!-- 反色 -->
<div class="invert">反色</div>
<div class="invert-0">无反色</div>

<!-- 饱和度 -->
<div class="saturate-50">50% 饱和度</div>
<div class="saturate-100">100% 饱和度</div>
<div class="saturate-150">150% 饱和度</div>
<div class="saturate-200">200% 饱和度</div>

<!-- 褐色滤镜 -->
<div class="sepia">褐色</div>
<div class="sepia-0">无褐色</div>

<!-- 实际案例：图片悬浮效果 -->
<img class="grayscale hover:grayscale-0 transition-all duration-300" src="...">

<!-- 实际案例：禁用状态 -->
<div class="grayscale opacity-50 pointer-events-none">
  禁用的内容
</div>
```

### 11.5 背景滤镜（毛玻璃效果）

```html
<!-- 背景模糊 -->
<div class="backdrop-blur-sm">轻微背景模糊</div>
<div class="backdrop-blur">默认背景模糊</div>
<div class="backdrop-blur-md">中等背景模糊</div>
<div class="backdrop-blur-lg">大背景模糊</div>
<div class="backdrop-blur-xl">超大背景模糊</div>

<!-- 其他背景滤镜 -->
<div class="backdrop-brightness-50">背景亮度</div>
<div class="backdrop-contrast-125">背景对比度</div>
<div class="backdrop-grayscale">背景灰度</div>
<div class="backdrop-saturate-150">背景饱和度</div>

<!-- 实际案例：毛玻璃导航栏 -->
<nav class="fixed top-0 left-0 right-0 z-50
            bg-white/70 backdrop-blur-lg
            border-b border-gray-200/50">
  <div class="container mx-auto px-4 py-3">
    导航内容
  </div>
</nav>

<!-- 实际案例：毛玻璃卡片 -->
<div class="bg-white/30 backdrop-blur-md rounded-xl p-6 shadow-lg">
  毛玻璃卡片内容
</div>

<!-- 实际案例：模态框背景 -->
<div class="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center">
  <div class="bg-white rounded-lg p-6">
    模态框内容
  </div>
</div>
```

---

## 12. 过渡与动画

### 12.1 过渡

```html
<!-- 过渡属性 -->
<div class="transition-none">无过渡</div>
<div class="transition-all">所有属性过渡</div>
<div class="transition">默认过渡（颜色、背景、边框、阴影、透明度、变换）</div>
<div class="transition-colors">仅颜色过渡</div>
<div class="transition-opacity">仅透明度过渡</div>
<div class="transition-shadow">仅阴影过渡</div>
<div class="transition-transform">仅变换过渡</div>

<!-- 过渡时长 -->
<div class="transition duration-75">75ms</div>
<div class="transition duration-100">100ms</div>
<div class="transition duration-150">150ms（默认）</div>
<div class="transition duration-200">200ms</div>
<div class="transition duration-300">300ms</div>
<div class="transition duration-500">500ms</div>
<div class="transition duration-700">700ms</div>
<div class="transition duration-1000">1000ms</div>

<!-- 过渡时机函数 -->
<div class="transition ease-linear">线性</div>
<div class="transition ease-in">缓入</div>
<div class="transition ease-out">缓出</div>
<div class="transition ease-in-out">缓入缓出</div>

<!-- 过渡延迟 -->
<div class="transition delay-75">延迟75ms</div>
<div class="transition delay-100">延迟100ms</div>
<div class="transition delay-150">延迟150ms</div>
<div class="transition delay-200">延迟200ms</div>
<div class="transition delay-300">延迟300ms</div>
<div class="transition delay-500">延迟500ms</div>

<!-- 实际案例：按钮悬浮效果 -->
<button class="px-4 py-2 bg-blue-500 text-white rounded
               transition duration-300 ease-in-out
               hover:bg-blue-600 hover:scale-105">
  悬浮放大
</button>

<!-- 实际案例：卡片悬浮 -->
<div class="bg-white rounded-lg shadow-md p-4
            transition-all duration-300
            hover:shadow-xl hover:-translate-y-1">
  卡片内容
</div>
```

### 12.2 变换

```html
<!-- 缩放 -->
<div class="scale-0">0%</div>
<div class="scale-50">50%</div>
<div class="scale-75">75%</div>
<div class="scale-90">90%</div>
<div class="scale-95">95%</div>
<div class="scale-100">100%</div>
<div class="scale-105">105%</div>
<div class="scale-110">110%</div>
<div class="scale-125">125%</div>
<div class="scale-150">150%</div>

<!-- 单轴缩放 -->
<div class="scale-x-50">水平缩放50%</div>
<div class="scale-y-150">垂直缩放150%</div>

<!-- 旋转 -->
<div class="rotate-0">0度</div>
<div class="rotate-45">45度</div>
<div class="rotate-90">90度</div>
<div class="rotate-180">180度</div>
<div class="-rotate-45">-45度</div>
<div class="-rotate-90">-90度</div>

<!-- 平移 -->
<div class="translate-x-4">右移1rem</div>
<div class="-translate-x-4">左移1rem</div>
<div class="translate-y-4">下移1rem</div>
<div class="-translate-y-4">上移1rem</div>
<div class="translate-x-1/2">右移50%</div>
<div class="-translate-x-1/2">左移50%</div>

<!-- 倾斜 -->
<div class="skew-x-6">水平倾斜6度</div>
<div class="skew-y-6">垂直倾斜6度</div>
<div class="-skew-x-6">水平倾斜-6度</div>

<!-- 变换原点 -->
<div class="origin-center">中心（默认）</div>
<div class="origin-top">顶部</div>
<div class="origin-top-right">右上</div>
<div class="origin-right">右侧</div>
<div class="origin-bottom-right">右下</div>
<div class="origin-bottom">底部</div>
<div class="origin-bottom-left">左下</div>
<div class="origin-left">左侧</div>
<div class="origin-top-left">左上</div>

<!-- 实际案例：居中定位 -->
<div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2">
  完美居中
</div>

<!-- 实际案例：悬浮旋转 -->
<div class="transition-transform duration-300 hover:rotate-12">
  悬浮旋转
</div>
```

### 12.3 动画

```html
<!-- 内置动画 -->
<div class="animate-spin">旋转（加载图标）</div>
<div class="animate-ping">脉冲（通知点）</div>
<div class="animate-pulse">呼吸（骨架屏）</div>
<div class="animate-bounce">弹跳（提示箭头）</div>
<div class="animate-none">无动画</div>

<!-- 实际案例：加载按钮 -->
<button class="flex items-center px-4 py-2 bg-blue-500 text-white rounded" disabled>
  <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" viewBox="0 0 24 24">
    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
  </svg>
  加载中...
</button>

<!-- 实际案例：通知红点 -->
<div class="relative">
  <button>消息</button>
  <span class="absolute -top-1 -right-1 flex h-3 w-3">
    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
    <span class="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
  </span>
</div>

<!-- 实际案例：骨架屏 -->
<div class="animate-pulse space-y-4">
  <div class="h-4 bg-gray-200 rounded w-3/4"></div>
  <div class="h-4 bg-gray-200 rounded"></div>
  <div class="h-4 bg-gray-200 rounded w-5/6"></div>
</div>
```

### 12.4 自定义动画

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.3s ease-out',
        'scale-in': 'scaleIn 0.2s ease-out',
        'wiggle': 'wiggle 1s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideDown: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        scaleIn: {
          '0%': { transform: 'scale(0.9)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        wiggle: {
          '0%, 100%': { transform: 'rotate(-3deg)' },
          '50%': { transform: 'rotate(3deg)' },
        },
      },
    },
  },
}
```

```html
<!-- 使用自定义动画 -->
<div class="animate-fade-in">淡入</div>
<div class="animate-slide-up">上滑进入</div>
<div class="animate-wiggle">摇摆</div>
```

---

## 13. 响应式设计

### 13.1 断点系统

Tailwind 采用移动优先（Mobile-First）的响应式设计策略。

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tailwind 默认断点                                 │
├─────────────────────────────────────────────────────────────────────┤
│  前缀    │  最小宽度   │  CSS                    │  设备            │
├─────────┼────────────┼─────────────────────────┼──────────────────┤
│  (无)   │  0px       │  默认样式               │  所有设备         │
│  sm     │  640px     │  @media (min-width: 640px)  │  大手机/小平板 │
│  md     │  768px     │  @media (min-width: 768px)  │  平板          │
│  lg     │  1024px    │  @media (min-width: 1024px) │  笔记本        │
│  xl     │  1280px    │  @media (min-width: 1280px) │  桌面显示器    │
│  2xl    │  1536px    │  @media (min-width: 1536px) │  大显示器      │
└─────────┴────────────┴─────────────────────────┴──────────────────┘
```

### 13.2 响应式语法

```html
<!-- 基本用法：前缀:类名 -->
<div class="w-full md:w-1/2 lg:w-1/3">
  <!-- 默认全宽，md 半宽，lg 三分之一宽 -->
</div>

<!-- 响应式显示/隐藏 -->
<div class="hidden md:block">
  <!-- 移动端隐藏，md 及以上显示 -->
</div>
<div class="block md:hidden">
  <!-- 移动端显示，md 及以上隐藏 -->
</div>

<!-- 响应式 Flex 方向 -->
<div class="flex flex-col md:flex-row">
  <!-- 移动端垂直排列，md 及以上水平排列 -->
</div>

<!-- 响应式字体大小 -->
<h1 class="text-2xl sm:text-3xl md:text-4xl lg:text-5xl">
  响应式标题
</h1>

<!-- 响应式间距 -->
<div class="p-4 md:p-6 lg:p-8">
  响应式内边距
</div>

<!-- 响应式 Grid 列数 -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
  <div>卡片1</div>
  <div>卡片2</div>
  <div>卡片3</div>
  <div>卡片4</div>
</div>
```

### 13.3 响应式实战案例

```html
<!-- 响应式导航栏 -->
<nav class="bg-white shadow">
  <div class="container mx-auto px-4">
    <div class="flex items-center justify-between h-16">
      <!-- Logo -->
      <div class="text-xl font-bold">Logo</div>
      
      <!-- 桌面端导航 -->
      <div class="hidden md:flex space-x-8">
        <a href="#" class="text-gray-700 hover:text-blue-500">首页</a>
        <a href="#" class="text-gray-700 hover:text-blue-500">产品</a>
        <a href="#" class="text-gray-700 hover:text-blue-500">关于</a>
        <a href="#" class="text-gray-700 hover:text-blue-500">联系</a>
      </div>
      
      <!-- 移动端菜单按钮 -->
      <button class="md:hidden p-2">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
        </svg>
      </button>
    </div>
  </div>
</nav>

<!-- 响应式卡片布局 -->
<div class="container mx-auto px-4 py-8">
  <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
    <div class="bg-white rounded-lg shadow-md overflow-hidden">
      <img class="w-full h-48 object-cover" src="..." alt="">
      <div class="p-4 sm:p-6">
        <h3 class="text-lg sm:text-xl font-bold mb-2">卡片标题</h3>
        <p class="text-gray-600 text-sm sm:text-base">卡片描述内容...</p>
      </div>
    </div>
    <!-- 更多卡片... -->
  </div>
</div>

<!-- 响应式侧边栏布局 -->
<div class="flex flex-col lg:flex-row min-h-screen">
  <!-- 侧边栏 -->
  <aside class="w-full lg:w-64 bg-gray-800 text-white p-4 lg:min-h-screen">
    <nav class="flex lg:flex-col space-x-4 lg:space-x-0 lg:space-y-2 overflow-x-auto lg:overflow-visible">
      <a href="#" class="whitespace-nowrap px-3 py-2 rounded hover:bg-gray-700">菜单1</a>
      <a href="#" class="whitespace-nowrap px-3 py-2 rounded hover:bg-gray-700">菜单2</a>
      <a href="#" class="whitespace-nowrap px-3 py-2 rounded hover:bg-gray-700">菜单3</a>
    </nav>
  </aside>
  
  <!-- 主内容 -->
  <main class="flex-1 p-4 lg:p-8">
    主内容区域
  </main>
</div>
```

### 13.4 自定义断点

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    // 完全覆盖默认断点
    screens: {
      'sm': '640px',
      'md': '768px',
      'lg': '1024px',
      'xl': '1280px',
      '2xl': '1536px',
    },
    // 或者扩展
    extend: {
      screens: {
        'xs': '475px',      // 添加更小的断点
        '3xl': '1920px',    // 添加更大的断点
      },
    },
  },
}
```

---

## 14. 状态变体

### 14.1 伪类状态

```html
<!-- 悬浮状态 -->
<button class="bg-blue-500 hover:bg-blue-600">悬浮变色</button>

<!-- 焦点状态 -->
<input class="border focus:border-blue-500 focus:ring-2 focus:ring-blue-200">

<!-- 激活状态 -->
<button class="bg-blue-500 active:bg-blue-700">点击变色</button>

<!-- 访问过的链接 -->
<a class="text-blue-500 visited:text-purple-500" href="#">链接</a>

<!-- 焦点可见（键盘焦点） -->
<button class="focus-visible:ring-2 focus-visible:ring-blue-500">
  仅键盘焦点时显示环形
</button>

<!-- 焦点在内部 -->
<div class="focus-within:ring-2 focus-within:ring-blue-500">
  <input type="text">
</div>

<!-- 禁用状态 -->
<button class="bg-blue-500 disabled:bg-gray-300 disabled:cursor-not-allowed" disabled>
  禁用按钮
</button>

<!-- 启用状态 -->
<input class="enabled:border-blue-500">

<!-- 必填状态 -->
<input class="required:border-red-500" required>

<!-- 有效/无效状态 -->
<input class="valid:border-green-500 invalid:border-red-500" type="email">

<!-- 只读状态 -->
<input class="read-only:bg-gray-100" readonly>

<!-- 选中状态（复选框/单选框） -->
<input type="checkbox" class="checked:bg-blue-500">

<!-- 不确定状态 -->
<input type="checkbox" class="indeterminate:bg-gray-300">

<!-- 占位符显示时 -->
<input class="placeholder-shown:border-gray-300">

<!-- 自动填充时 -->
<input class="autofill:bg-yellow-100">
```

### 14.2 伪元素

```html
<!-- before 伪元素 -->
<div class="before:content-['*'] before:text-red-500">
  必填字段
</div>

<!-- after 伪元素 -->
<a class="after:content-['↗'] after:ml-1" href="#">
  外部链接
</a>

<!-- 首字母 -->
<p class="first-letter:text-4xl first-letter:font-bold first-letter:text-blue-500">
  这是一段文字，首字母会被放大。
</p>

<!-- 首行 -->
<p class="first-line:font-bold first-line:text-blue-500">
  这是第一行文字。
  这是第二行文字。
</p>

<!-- 选中文本 -->
<p class="selection:bg-blue-500 selection:text-white">
  选中这段文字试试
</p>

<!-- 文件选择按钮 -->
<input type="file" class="file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 
                          file:bg-blue-500 file:text-white hover:file:bg-blue-600">

<!-- 占位符 -->
<input class="placeholder:text-gray-400 placeholder:italic" placeholder="请输入...">

<!-- 标记（列表项标记） -->
<ul class="marker:text-blue-500">
  <li>项目1</li>
  <li>项目2</li>
</ul>
```

### 14.3 子元素状态

```html
<!-- 第一个子元素 -->
<ul>
  <li class="first:font-bold">第一项（加粗）</li>
  <li>第二项</li>
  <li>第三项</li>
</ul>

<!-- 最后一个子元素 -->
<ul>
  <li>第一项</li>
  <li>第二项</li>
  <li class="last:border-b-0">最后一项（无下边框）</li>
</ul>

<!-- 奇数/偶数子元素 -->
<table>
  <tr class="odd:bg-gray-100 even:bg-white">...</tr>
</table>

<!-- 唯一子元素 -->
<div class="only:p-4">如果是唯一子元素则有内边距</div>

<!-- 空元素 -->
<div class="empty:hidden">如果为空则隐藏</div>

<!-- 第 n 个子元素 -->
<li class="[&:nth-child(3)]:text-red-500">第三项</li>
```

### 14.4 Group 和 Peer

`group` 和 `peer` 用于基于父元素或兄弟元素的状态来设置样式。

```html
<!-- Group：基于父元素状态 -->
<div class="group p-4 bg-white rounded-lg hover:bg-blue-500 transition">
  <h3 class="text-gray-900 group-hover:text-white">标题</h3>
  <p class="text-gray-500 group-hover:text-blue-100">描述文字</p>
</div>

<!-- 嵌套 Group -->
<div class="group/card p-4 bg-white rounded-lg">
  <div class="group/title">
    <h3 class="group-hover/title:text-blue-500">标题</h3>
  </div>
  <p class="group-hover/card:text-gray-700">描述</p>
</div>

<!-- Group 其他状态 -->
<div class="group">
  <button class="group-focus:ring-2">按钮</button>
  <div class="group-active:scale-95">内容</div>
</div>

<!-- Peer：基于兄弟元素状态 -->
<div>
  <input type="checkbox" class="peer" id="toggle">
  <label for="toggle">切换</label>
  <div class="hidden peer-checked:block">
    选中时显示的内容
  </div>
</div>

<!-- 表单验证提示 -->
<div>
  <input type="email" class="peer" placeholder="邮箱" required>
  <p class="hidden peer-invalid:block text-red-500 text-sm">
    请输入有效的邮箱地址
  </p>
</div>

<!-- 自定义下拉菜单 -->
<div class="relative">
  <button class="peer px-4 py-2 bg-gray-100 rounded">菜单</button>
  <div class="absolute hidden peer-focus:block bg-white shadow-lg rounded mt-1">
    <a href="#" class="block px-4 py-2 hover:bg-gray-100">选项1</a>
    <a href="#" class="block px-4 py-2 hover:bg-gray-100">选项2</a>
  </div>
</div>
```

### 14.5 Has 选择器

`has-*` 变体允许基于子元素状态设置父元素样式（CSS :has() 选择器）。

```html
<!-- 包含选中复选框时 -->
<label class="has-[:checked]:bg-blue-100 has-[:checked]:ring-2 has-[:checked]:ring-blue-500 
              p-4 rounded-lg border cursor-pointer block">
  <input type="checkbox" class="mr-2">
  选择此选项
</label>

<!-- 包含焦点元素时 -->
<div class="has-[:focus]:ring-2 has-[:focus]:ring-blue-500 p-4 rounded-lg border">
  <input type="text" class="w-full border rounded px-3 py-2">
</div>

<!-- 包含无效输入时 -->
<form class="has-[:invalid]:border-red-500 border-2 p-4 rounded">
  <input type="email" required>
</form>
```

---

## 15. 深色模式

### 15.1 启用深色模式

```javascript
// tailwind.config.js
module.exports = {
  // 方式1：基于系统偏好（默认）
  darkMode: 'media',
  
  // 方式2：基于 class（推荐，可手动切换）
  darkMode: 'class',
  
  // 方式3：基于选择器（v3.4+）
  darkMode: ['selector', '[data-theme="dark"]'],
}
```

### 15.2 深色模式语法

```html
<!-- 基本用法 -->
<div class="bg-white dark:bg-gray-900">
  <h1 class="text-gray-900 dark:text-white">标题</h1>
  <p class="text-gray-600 dark:text-gray-300">内容</p>
</div>

<!-- 深色模式下的悬浮状态 -->
<button class="bg-blue-500 hover:bg-blue-600 
               dark:bg-blue-600 dark:hover:bg-blue-700">
  按钮
</button>

<!-- 深色模式卡片 -->
<div class="bg-white dark:bg-gray-800 
            border border-gray-200 dark:border-gray-700 
            rounded-lg shadow-md dark:shadow-gray-900/50 
            p-6">
  <h3 class="text-gray-900 dark:text-white font-bold">卡片标题</h3>
  <p class="text-gray-600 dark:text-gray-400 mt-2">卡片内容</p>
</div>
```

### 15.3 深色模式切换实现

```html
<!-- HTML 结构 -->
<html class="dark">
  <!-- 添加 dark 类启用深色模式 -->
</html>

<!-- 切换按钮 -->
<button id="theme-toggle" class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
  <!-- 太阳图标（深色模式下显示） -->
  <svg class="hidden dark:block w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
    <!-- sun icon -->
  </svg>
  <!-- 月亮图标（浅色模式下显示） -->
  <svg class="block dark:hidden w-5 h-5 text-gray-700" fill="currentColor" viewBox="0 0 20 20">
    <!-- moon icon -->
  </svg>
</button>
```

```javascript
// 深色模式切换逻辑
const themeToggle = document.getElementById('theme-toggle');

// 检查系统偏好或本地存储
if (localStorage.theme === 'dark' || 
    (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
  document.documentElement.classList.add('dark');
} else {
  document.documentElement.classList.remove('dark');
}

// 切换主题
themeToggle.addEventListener('click', () => {
  document.documentElement.classList.toggle('dark');
  
  // 保存到本地存储
  if (document.documentElement.classList.contains('dark')) {
    localStorage.theme = 'dark';
  } else {
    localStorage.theme = 'light';
  }
});

// 重置为系统偏好
// localStorage.removeItem('theme');
```

```vue
<!-- Vue 3 组合式 API 实现 -->
<script setup>
import { ref, onMounted, watch } from 'vue'

const isDark = ref(false)

onMounted(() => {
  isDark.value = localStorage.theme === 'dark' ||
    (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)
  updateTheme()
})

watch(isDark, () => {
  updateTheme()
  localStorage.theme = isDark.value ? 'dark' : 'light'
})

function updateTheme() {
  if (isDark.value) {
    document.documentElement.classList.add('dark')
  } else {
    document.documentElement.classList.remove('dark')
  }
}

function toggleTheme() {
  isDark.value = !isDark.value
}
</script>

<template>
  <button @click="toggleTheme" class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
    {{ isDark ? '🌙' : '☀️' }}
  </button>
</template>
```

---

## 16. 自定义配置

### 16.1 配置文件结构

```javascript
// tailwind.config.js
/** @type {import('tailwindcss').Config} */
module.exports = {
  // 内容扫描路径
  content: [
    './index.html',
    './src/**/*.{vue,js,ts,jsx,tsx}',
  ],
  
  // 深色模式
  darkMode: 'class',
  
  // 主题配置
  theme: {
    // 完全覆盖默认值
    colors: {
      // 自定义颜色系统
    },
    
    // 扩展默认值（推荐）
    extend: {
      colors: {},
      spacing: {},
      fontSize: {},
      fontFamily: {},
      borderRadius: {},
      boxShadow: {},
      animation: {},
      keyframes: {},
    },
  },
  
  // 插件
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    require('@tailwindcss/aspect-ratio'),
  ],
}
```

### 16.2 自定义主题

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      // 自定义颜色
      colors: {
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        secondary: '#64748b',
        accent: '#f59e0b',
      },
      
      // 自定义字体
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        serif: ['Georgia', 'serif'],
        mono: ['Fira Code', 'monospace'],
        display: ['Poppins', 'sans-serif'],
      },
      
      // 自定义间距
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      
      // 自定义圆角
      borderRadius: {
        '4xl': '2rem',
      },
      
      // 自定义阴影
      boxShadow: {
        'soft': '0 2px 15px -3px rgba(0, 0, 0, 0.07), 0 10px 20px -2px rgba(0, 0, 0, 0.04)',
        'glow': '0 0 15px rgba(59, 130, 246, 0.5)',
      },
      
      // 自定义断点
      screens: {
        'xs': '475px',
        '3xl': '1920px',
      },
      
      // 自定义 z-index
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
    },
  },
}
```

### 16.3 使用 CSS 变量

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: 'rgb(var(--color-primary) / <alpha-value>)',
        secondary: 'rgb(var(--color-secondary) / <alpha-value>)',
      },
    },
  },
}
```

```css
/* CSS 变量定义 */
:root {
  --color-primary: 59 130 246;    /* blue-500 */
  --color-secondary: 100 116 139; /* slate-500 */
}

.dark {
  --color-primary: 96 165 250;    /* blue-400 */
  --color-secondary: 148 163 184; /* slate-400 */
}
```

```html
<!-- 使用 -->
<div class="bg-primary text-primary/50">
  支持透明度
</div>
```

### 16.4 任意值语法

当预设值不满足需求时，可以使用任意值语法。

```html
<!-- 任意颜色 -->
<div class="bg-[#1da1f2]">Twitter 蓝</div>
<div class="text-[rgb(255,100,50)]">RGB 颜色</div>
<div class="border-[hsl(200,100%,50%)]">HSL 颜色</div>

<!-- 任意尺寸 -->
<div class="w-[137px]">精确宽度</div>
<div class="h-[calc(100vh-80px)]">计算高度</div>
<div class="top-[117px]">精确定位</div>

<!-- 任意字体 -->
<div class="text-[22px]">22px 字体</div>
<div class="leading-[1.7]">1.7 行高</div>
<div class="font-[600]">600 字重</div>

<!-- 任意间距 -->
<div class="p-[13px]">13px 内边距</div>
<div class="m-[5%]">5% 外边距</div>

<!-- 任意网格 -->
<div class="grid grid-cols-[200px_1fr_200px]">三列布局</div>
<div class="grid grid-cols-[repeat(auto-fill,minmax(250px,1fr))]">自动填充</div>

<!-- 任意背景图 -->
<div class="bg-[url('/img/hero.png')]">背景图</div>

<!-- 任意内容 -->
<div class="before:content-['Hello']">伪元素内容</div>

<!-- 任意选择器 -->
<div class="[&>*]:p-4">所有直接子元素</div>
<div class="[&_p]:text-gray-600">所有后代 p 元素</div>
<div class="[&:nth-child(3)]:bg-red-500">第三个子元素</div>

<!-- 任意属性 -->
<div class="[mask-type:luminance]">任意 CSS 属性</div>
```

### 16.5 @apply 指令

`@apply` 用于在 CSS 中复用 Tailwind 类，适合创建可复用组件样式。

```css
/* 在 CSS 文件中使用 */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* 使用 @layer 确保正确的优先级 */
@layer components {
  .btn {
    @apply px-4 py-2 rounded font-medium transition-colors;
  }
  
  .btn-primary {
    @apply btn bg-blue-500 text-white hover:bg-blue-600;
  }
  
  .btn-secondary {
    @apply btn bg-gray-200 text-gray-800 hover:bg-gray-300;
  }
  
  .btn-outline {
    @apply btn border-2 border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white;
  }
  
  .card {
    @apply bg-white rounded-lg shadow-md p-6;
  }
  
  .input {
    @apply w-full px-3 py-2 border border-gray-300 rounded-md
           focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent;
  }
}

@layer utilities {
  .text-shadow {
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
  }
  
  .text-shadow-lg {
    text-shadow: 4px 4px 8px rgba(0, 0, 0, 0.2);
  }
}
```

```html
<!-- 使用自定义组件类 -->
<button class="btn-primary">主要按钮</button>
<button class="btn-secondary">次要按钮</button>
<button class="btn-outline">轮廓按钮</button>

<div class="card">
  <h3>卡片标题</h3>
</div>

<input class="input" type="text" placeholder="请输入">
```

> ⚠️ **注意**：过度使用 `@apply` 会失去 Tailwind 的优势。建议仅在需要复用的组件样式中使用。

---

## 17. 组件模式

### 17.1 常用组件示例

```html
<!-- 按钮组件 -->
<!-- 主要按钮 -->
<button class="px-4 py-2 bg-blue-500 text-white font-medium rounded-lg
               hover:bg-blue-600 active:bg-blue-700
               focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
               transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
  主要按钮
</button>

<!-- 次要按钮 -->
<button class="px-4 py-2 bg-gray-100 text-gray-700 font-medium rounded-lg
               hover:bg-gray-200 active:bg-gray-300
               focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2
               transition-colors">
  次要按钮
</button>

<!-- 轮廓按钮 -->
<button class="px-4 py-2 border-2 border-blue-500 text-blue-500 font-medium rounded-lg
               hover:bg-blue-500 hover:text-white
               focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
               transition-colors">
  轮廓按钮
</button>

<!-- 图标按钮 -->
<button class="p-2 rounded-full bg-gray-100 hover:bg-gray-200 transition-colors">
  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
  </svg>
</button>
```

```html
<!-- 输入框组件 -->
<!-- 基础输入框 -->
<input type="text" 
       class="w-full px-3 py-2 border border-gray-300 rounded-lg
              focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
              placeholder-gray-400"
       placeholder="请输入内容">

<!-- 带图标的输入框 -->
<div class="relative">
  <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
    <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
    </svg>
  </div>
  <input type="text" 
         class="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg
                focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
         placeholder="搜索...">
</div>

<!-- 带验证状态的输入框 -->
<div>
  <input type="email" 
         class="peer w-full px-3 py-2 border rounded-lg
                border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200
                invalid:border-red-500 invalid:focus:border-red-500 invalid:focus:ring-red-200"
         placeholder="邮箱地址" required>
  <p class="hidden peer-invalid:block mt-1 text-sm text-red-500">
    请输入有效的邮箱地址
  </p>
</div>

<!-- 卡片组件 -->
<!-- 基础卡片 -->
<div class="bg-white rounded-xl shadow-md overflow-hidden">
  <img class="w-full h-48 object-cover" src="..." alt="">
  <div class="p-6">
    <div class="text-sm text-blue-500 font-semibold uppercase tracking-wide">分类</div>
    <h3 class="mt-2 text-xl font-bold text-gray-900">卡片标题</h3>
    <p class="mt-2 text-gray-600">卡片描述内容，这里是一些简短的介绍文字。</p>
    <div class="mt-4">
      <button class="text-blue-500 hover:text-blue-600 font-medium">
        了解更多 →
      </button>
    </div>
  </div>
</div>

<!-- 横向卡片 -->
<div class="flex bg-white rounded-xl shadow-md overflow-hidden">
  <img class="w-48 h-full object-cover flex-shrink-0" src="..." alt="">
  <div class="p-6">
    <h3 class="text-xl font-bold text-gray-900">卡片标题</h3>
    <p class="mt-2 text-gray-600">卡片描述内容...</p>
  </div>
</div>

<!-- 徽章组件 -->
<span class="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">默认</span>
<span class="px-2 py-1 text-xs font-medium bg-green-100 text-green-800 rounded-full">成功</span>
<span class="px-2 py-1 text-xs font-medium bg-yellow-100 text-yellow-800 rounded-full">警告</span>
<span class="px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded-full">错误</span>

<!-- 头像组件 -->
<!-- 圆形头像 -->
<img class="w-10 h-10 rounded-full" src="avatar.jpg" alt="">

<!-- 带状态的头像 -->
<div class="relative">
  <img class="w-10 h-10 rounded-full" src="avatar.jpg" alt="">
  <span class="absolute bottom-0 right-0 w-3 h-3 bg-green-500 border-2 border-white rounded-full"></span>
</div>

<!-- 头像组 -->
<div class="flex -space-x-2">
  <img class="w-10 h-10 rounded-full border-2 border-white" src="avatar1.jpg" alt="">
  <img class="w-10 h-10 rounded-full border-2 border-white" src="avatar2.jpg" alt="">
  <img class="w-10 h-10 rounded-full border-2 border-white" src="avatar3.jpg" alt="">
  <span class="flex items-center justify-center w-10 h-10 rounded-full border-2 border-white bg-gray-200 text-sm font-medium">
    +5
  </span>
</div>

<!-- 警告框组件 -->
<!-- 信息 -->
<div class="flex items-start p-4 bg-blue-50 border-l-4 border-blue-500 rounded-r-lg">
  <svg class="w-5 h-5 text-blue-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
  </svg>
  <div class="ml-3">
    <h3 class="text-sm font-medium text-blue-800">提示信息</h3>
    <p class="mt-1 text-sm text-blue-700">这是一条提示信息。</p>
  </div>
</div>

<!-- 成功 -->
<div class="flex items-start p-4 bg-green-50 border-l-4 border-green-500 rounded-r-lg">
  <svg class="w-5 h-5 text-green-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
  </svg>
  <div class="ml-3">
    <h3 class="text-sm font-medium text-green-800">操作成功</h3>
    <p class="mt-1 text-sm text-green-700">您的更改已保存。</p>
  </div>
</div>

<!-- 模态框组件 -->
<div class="fixed inset-0 z-50 flex items-center justify-center">
  <!-- 背景遮罩 -->
  <div class="fixed inset-0 bg-black/50 backdrop-blur-sm"></div>
  
  <!-- 模态框内容 -->
  <div class="relative bg-white rounded-xl shadow-xl max-w-md w-full mx-4 p-6">
    <button class="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
      <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
      </svg>
    </button>
    
    <h2 class="text-xl font-bold text-gray-900">模态框标题</h2>
    <p class="mt-2 text-gray-600">模态框内容...</p>
    
    <div class="mt-6 flex justify-end space-x-3">
      <button class="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200">
        取消
      </button>
      <button class="px-4 py-2 text-white bg-blue-500 rounded-lg hover:bg-blue-600">
        确认
      </button>
    </div>
  </div>
</div>

<!-- 下拉菜单组件 -->
<div class="relative inline-block">
  <button class="px-4 py-2 bg-white border border-gray-300 rounded-lg 
                 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500">
    选项
    <svg class="inline-block w-4 h-4 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
    </svg>
  </button>
  
  <div class="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-100 py-1 z-10">
    <a href="#" class="block px-4 py-2 text-gray-700 hover:bg-gray-100">选项一</a>
    <a href="#" class="block px-4 py-2 text-gray-700 hover:bg-gray-100">选项二</a>
    <a href="#" class="block px-4 py-2 text-gray-700 hover:bg-gray-100">选项三</a>
    <hr class="my-1 border-gray-100">
    <a href="#" class="block px-4 py-2 text-red-600 hover:bg-gray-100">删除</a>
  </div>
</div>
```

---

## 18. 常见错误与解决方案

### 18.1 样式不生效

**问题：添加的 Tailwind 类没有效果**

```html
<!-- ❌ 错误：动态拼接类名 -->
<div :class="`text-${color}-500`">
  <!-- Tailwind 无法检测到这个类 -->
</div>

<!-- ✅ 正确：使用完整类名 -->
<div :class="{
  'text-red-500': color === 'red',
  'text-blue-500': color === 'blue',
  'text-green-500': color === 'green',
}">
</div>

<!-- ✅ 或者使用对象映射 -->
<script>
const colorMap = {
  red: 'text-red-500',
  blue: 'text-blue-500',
  green: 'text-green-500',
}
</script>
<div :class="colorMap[color]"></div>
```

**原因**：Tailwind 在构建时扫描文件中的完整类名，动态拼接的类名无法被检测到。

**解决方案**：
1. 使用完整的类名
2. 在 `safelist` 中添加需要的类
3. 使用任意值语法 `text-[var(--color)]`

```javascript
// tailwind.config.js
module.exports = {
  safelist: [
    'text-red-500',
    'text-blue-500',
    'text-green-500',
    // 或使用正则
    {
      pattern: /text-(red|blue|green)-(100|500|900)/,
    },
  ],
}
```

### 18.2 样式优先级问题

**问题：自定义样式被 Tailwind 覆盖**

```html
<!-- ❌ 问题：自定义类被覆盖 -->
<style>
.my-button {
  background-color: red;
}
</style>
<button class="my-button bg-blue-500">按钮</button>
<!-- 显示蓝色，因为 Tailwind 工具类优先级更高 -->
```

**解决方案**：

```css
/* 方案1：使用 @layer 确保正确的优先级 */
@layer components {
  .my-button {
    @apply bg-red-500;
  }
}

/* 方案2：提高选择器优先级 */
.my-button.my-button {
  background-color: red;
}

/* 方案3：使用 !important（不推荐） */
.my-button {
  background-color: red !important;
}
```

```html
<!-- 方案4：使用 Tailwind 的 ! 前缀 -->
<button class="!bg-red-500 bg-blue-500">按钮</button>
<!-- !bg-red-500 会添加 !important -->
```

### 18.3 PurgeCSS 误删样式

**问题：生产构建后某些样式丢失**

```javascript
// ❌ 错误：content 路径配置不完整
module.exports = {
  content: [
    './src/**/*.vue',  // 缺少其他文件类型
  ],
}

// ✅ 正确：包含所有可能使用 Tailwind 类的文件
module.exports = {
  content: [
    './index.html',
    './src/**/*.{vue,js,ts,jsx,tsx}',
    './components/**/*.{vue,js,ts}',
    // 如果使用了 UI 库
    './node_modules/@headlessui/vue/**/*.js',
  ],
}
```

### 18.4 响应式断点不生效

**问题：响应式类没有按预期工作**

```html
<!-- ❌ 错误理解：认为 md: 是"仅在 md 屏幕" -->
<div class="md:hidden">
  <!-- 这不是"仅在 md 屏幕隐藏" -->
  <!-- 而是"md 及以上屏幕隐藏" -->
</div>

<!-- ✅ 正确理解：Tailwind 是移动优先 -->
<div class="block md:hidden">
  <!-- 默认显示，md 及以上隐藏 -->
</div>

<div class="hidden md:block">
  <!-- 默认隐藏，md 及以上显示 -->
</div>

<!-- 仅在特定断点范围显示 -->
<div class="hidden md:block lg:hidden">
  <!-- 仅在 md 到 lg 之间显示 -->
</div>
```

### 18.5 Flexbox 子元素溢出

**问题：Flex 子元素内容溢出容器**

```html
<!-- ❌ 问题：长文本导致布局溢出 -->
<div class="flex">
  <div>固定内容</div>
  <div>这是一段非常非常非常非常非常非常长的文本内容会导致溢出</div>
</div>

<!-- ✅ 解决方案1：添加 min-w-0 -->
<div class="flex">
  <div class="flex-shrink-0">固定内容</div>
  <div class="min-w-0 truncate">长文本会被截断...</div>
</div>

<!-- ✅ 解决方案2：添加 overflow-hidden -->
<div class="flex">
  <div class="flex-shrink-0">固定内容</div>
  <div class="overflow-hidden">
    <p class="truncate">长文本会被截断...</p>
  </div>
</div>
```

**原因**：Flex 子元素的默认 `min-width` 是 `auto`，会阻止元素收缩到内容宽度以下。

### 18.6 Grid 子元素溢出

**问题：Grid 子元素内容溢出单元格**

```html
<!-- ❌ 问题 -->
<div class="grid grid-cols-3">
  <div>短内容</div>
  <div>这是一段非常长的内容会溢出网格单元格</div>
  <div>短内容</div>
</div>

<!-- ✅ 解决方案 -->
<div class="grid grid-cols-3">
  <div>短内容</div>
  <div class="min-w-0 truncate">长内容会被截断</div>
  <div>短内容</div>
</div>
```

### 18.7 z-index 不生效

**问题：设置了 z-index 但元素没有在上层**

```html
<!-- ❌ 问题：z-index 需要配合定位使用 -->
<div class="z-50">
  <!-- z-index 对 static 定位的元素无效 -->
</div>

<!-- ✅ 解决方案：添加定位 -->
<div class="relative z-50">
  <!-- 现在 z-index 生效了 -->
</div>
```

### 18.8 过渡动画不流畅

**问题：hover 效果没有过渡动画**

```html
<!-- ❌ 问题：忘记添加 transition -->
<button class="bg-blue-500 hover:bg-blue-600">
  没有过渡效果
</button>

<!-- ✅ 解决方案：添加 transition 类 -->
<button class="bg-blue-500 hover:bg-blue-600 transition-colors duration-200">
  有平滑过渡
</button>

<!-- 常用过渡组合 -->
<div class="transition-all duration-300 ease-in-out">所有属性</div>
<div class="transition-colors duration-200">仅颜色</div>
<div class="transition-transform duration-300">仅变换</div>
<div class="transition-opacity duration-150">仅透明度</div>
```

### 18.9 暗色模式样式冲突

**问题：暗色模式下某些样式不正确**

```html
<!-- ❌ 问题：忘记为暗色模式设置对应样式 -->
<div class="bg-white text-gray-900">
  <!-- 暗色模式下背景还是白色 -->
</div>

<!-- ✅ 解决方案：始终成对设置 -->
<div class="bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
  <!-- 暗色模式下正确显示 -->
</div>

<!-- 使用 CSS 变量简化 -->
<div class="bg-[var(--bg-primary)] text-[var(--text-primary)]">
  <!-- 通过 CSS 变量统一管理 -->
</div>
```

### 18.10 表单元素样式重置

**问题：表单元素有浏览器默认样式**

```html
<!-- ❌ 问题：浏览器默认样式干扰 -->
<input type="text" class="border rounded">
<!-- 可能有意外的内边距、轮廓等 -->

<!-- ✅ 解决方案1：使用 @tailwindcss/forms 插件 -->
<!-- npm install @tailwindcss/forms -->

<!-- ✅ 解决方案2：手动重置 -->
<input type="text" 
       class="appearance-none border rounded px-3 py-2
              focus:outline-none focus:ring-2 focus:ring-blue-500">

<!-- 复选框自定义 -->
<input type="checkbox" 
       class="appearance-none w-5 h-5 border-2 border-gray-300 rounded
              checked:bg-blue-500 checked:border-blue-500
              focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
```

### 18.11 性能优化建议

```javascript
// tailwind.config.js

module.exports = {
  // 1. 精确配置 content，避免扫描不必要的文件
  content: [
    './src/**/*.{vue,js,ts}',
    // 不要使用 './**/*.html' 这样过于宽泛的模式
  ],
  
  // 2. 禁用不需要的核心插件
  corePlugins: {
    float: false,        // 如果不使用 float
    clear: false,
    skew: false,         // 如果不使用 skew
  },
  
  // 3. 限制颜色和间距的变体
  theme: {
    extend: {
      // 只保留需要的颜色
    },
  },
}
```

```html
<!-- 4. 避免过度使用任意值 -->
<!-- ❌ 不好 -->
<div class="w-[137px] h-[89px] mt-[23px] text-[13px]">

<!-- ✅ 更好：使用设计系统中的值 -->
<div class="w-36 h-24 mt-6 text-sm">
```

---

## 附录：常用类速查表

### 布局
| 类名 | 说明 |
|------|------|
| `container` | 响应式容器 |
| `flex` | Flex 容器 |
| `grid` | Grid 容器 |
| `hidden` | 隐藏元素 |
| `block` | 块级元素 |

### Flexbox
| 类名 | 说明 |
|------|------|
| `flex-row` | 水平排列 |
| `flex-col` | 垂直排列 |
| `justify-center` | 主轴居中 |
| `items-center` | 交叉轴居中 |
| `flex-1` | 等分空间 |

### 间距
| 类名 | 说明 |
|------|------|
| `p-4` | 内边距 1rem |
| `m-4` | 外边距 1rem |
| `px-4` | 水平内边距 |
| `py-4` | 垂直内边距 |
| `space-x-4` | 子元素水平间距 |

### 尺寸
| 类名 | 说明 |
|------|------|
| `w-full` | 宽度 100% |
| `h-screen` | 高度 100vh |
| `max-w-md` | 最大宽度 28rem |
| `min-h-screen` | 最小高度 100vh |

### 排版
| 类名 | 说明 |
|------|------|
| `text-lg` | 字体大小 18px |
| `font-bold` | 字重 700 |
| `text-center` | 文本居中 |
| `truncate` | 文本截断 |

### 颜色
| 类名 | 说明 |
|------|------|
| `text-gray-500` | 文本颜色 |
| `bg-blue-500` | 背景颜色 |
| `border-red-500` | 边框颜色 |

### 边框
| 类名 | 说明 |
|------|------|
| `border` | 1px 边框 |
| `rounded-lg` | 圆角 8px |
| `shadow-md` | 中等阴影 |

### 响应式前缀
| 前缀 | 断点 |
|------|------|
| `sm:` | ≥640px |
| `md:` | ≥768px |
| `lg:` | ≥1024px |
| `xl:` | ≥1280px |
| `2xl:` | ≥1536px |

### 状态前缀
| 前缀 | 说明 |
|------|------|
| `hover:` | 悬浮状态 |
| `focus:` | 焦点状态 |
| `active:` | 激活状态 |
| `disabled:` | 禁用状态 |
| `dark:` | 暗色模式 |

---

> 📝 **笔记说明**
> - 本笔记基于 Tailwind CSS v3.4+ 编写
> - 建议配合官方文档学习：https://tailwindcss.com/docs
> - 推荐安装 VS Code 插件 "Tailwind CSS IntelliSense"

---

*最后更新：2024年*
