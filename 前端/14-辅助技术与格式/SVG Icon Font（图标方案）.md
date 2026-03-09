> SVG 和 Icon Font 是前端常用的图标解决方案，各有优劣
> 本笔记涵盖 SVG Sprite、Icon Font、SVG 组件等多种方案

---

## 目录

1. [基础概念](#1-基础概念)
2. [Icon Font 方案](#2-icon-font-方案)
3. [SVG Sprite 方案](#3-svg-sprite-方案)
4. [SVG 组件方案](#4-svg-组件方案)
5. [第三方图标库](#5-第三方图标库)
6. [自动化工具](#6-自动化工具)
7. [性能优化](#7-性能优化)
8. [无障碍访问](#8-无障碍访问)
9. [最佳实践](#9-最佳实践)
10. [常见错误与解决方案](#10-常见错误与解决方案)
11. [方案对比](#11-方案对比)

---

## 1. 基础概念

### 1.1 图标方案对比

| 方案 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| Icon Font | 兼容性好、体积小 | 单色、抗锯齿问题 | 简单图标 |
| SVG Sprite | 多色、可控性强 | 兼容性要求高 | 复杂图标 |
| SVG 组件 | 灵活、可交互 | 打包体积大 | 动态图标 |
| 图片 | 简单直接 | 不可缩放 | 位图图标 |

### 1.2 技术选型建议

```typescript
// 简单单色图标 → Icon Font
// 复杂多色图标 → SVG Sprite
// 需要动画交互 → SVG 组件
// 大量图标 → 按需加载
```

---

## 2. Icon Font 方案

### 2.1 使用 Iconfont

```html
<!-- 1. 引入 CSS -->
<link rel="stylesheet" href="//at.alicdn.com/t/font_xxx.css">

<!-- 2. 使用图标 -->
<i class="iconfont icon-home"></i>
<i class="iconfont icon-user"></i>
```

### 2.2 自定义 Icon Font

```bash
# 安装工具
npm install -D webfont

# 生成字体文件
npx webfont src/icons/*.svg -o dist/fonts
```

### 2.3 Vue 组件封装

```vue
<!-- IconFont.vue -->
<template>
  <i :class="['iconfont', `icon-${name}`]" :style="style"></i>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  name: string
  size?: number | string
  color?: string
}>()

const style = computed(() => ({
  fontSize: typeof props.size === 'number' ? `${props.size}px` : props.size,
  color: props.color
}))
</script>

<style scoped>
@import url('//at.alicdn.com/t/font_xxx.css');
</style>
```

```vue
<!-- 使用 -->
<template>
  <IconFont name="home" :size="24" color="#1890ff" />
  <IconFont name="user" size="2em" />
</template>
```

### 2.4 Symbol 引用方式

```html
<!-- 1. 引入 JS -->
<script src="//at.alicdn.com/t/font_xxx.js"></script>

<!-- 2. 添加通用样式 -->
<style>
.icon {
  width: 1em;
  height: 1em;
  vertical-align: -0.15em;
  fill: currentColor;
  overflow: hidden;
}
</style>

<!-- 3. 使用图标 -->
<svg class="icon" aria-hidden="true">
  <use xlink:href="#icon-home"></use>
</svg>
```

### 2.5 本地化 Icon Font

```typescript
// vite.config.ts
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [
    {
      name: 'iconfont-loader',
      transformIndexHtml(html) {
        // 将 iconfont.js 内联到 HTML
        const iconfontScript = fs.readFileSync('./src/assets/iconfont.js', 'utf-8')
        return html.replace(
          '</head>',
          `<script>${iconfontScript}</script></head>`
        )
      }
    }
  ]
})
```

---

## 3. SVG Sprite 方案

### 3.1 基础 SVG Sprite

```html
<!-- sprite.svg -->
<svg xmlns="http://www.w3.org/2000/svg" style="display: none;">
  <symbol id="icon-home" viewBox="0 0 24 24">
    <path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/>
  </symbol>
  
  <symbol id="icon-user" viewBox="0 0 24 24">
    <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
  </symbol>
</svg>

<!-- 使用 -->
<svg class="icon">
  <use xlink:href="#icon-home"></use>
</svg>
```

### 3.2 自动生成 Sprite

```bash
# 安装工具
npm install -D svg-sprite-loader

# 或使用 vite-plugin-svg-icons
npm install -D vite-plugin-svg-icons
```

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import { createSvgIconsPlugin } from 'vite-plugin-svg-icons'
import path from 'path'

export default defineConfig({
  plugins: [
    createSvgIconsPlugin({
      // 指定图标文件夹
      iconDirs: [path.resolve(process.cwd(), 'src/icons')],
      // 指定 symbolId 格式
      symbolId: 'icon-[dir]-[name]',
      // 注入位置
      inject: 'body-last',
      // 自定义插入位置
      customDomId: '__svg__icons__dom__'
    })
  ]
})
```

### 3.3 Vue 组件封装

```vue
<!-- SvgIcon.vue -->
<template>
  <svg :class="['svg-icon', className]" :style="style" aria-hidden="true">
    <use :xlink:href="symbolId" :fill="color" />
  </svg>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  name: string
  prefix?: string
  color?: string
  size?: number | string
  className?: string
}>()

const symbolId = computed(() => `#${props.prefix || 'icon'}-${props.name}`)

const style = computed(() => {
  const size = typeof props.size === 'number' ? `${props.size}px` : props.size
  return {
    width: size,
    height: size
  }
})
</script>

<style scoped>
.svg-icon {
  display: inline-block;
  vertical-align: -0.15em;
  fill: currentColor;
  overflow: hidden;
}
</style>
```

```vue
<!-- 使用 -->
<template>
  <SvgIcon name="home" :size="24" color="#1890ff" />
  <SvgIcon name="user" size="2em" />
</template>
```

### 3.4 注册全局组件

```typescript
// main.ts
import { createApp } from 'vue'
import App from './App.vue'
import SvgIcon from '@/components/SvgIcon.vue'

// 引入所有 SVG
import 'virtual:svg-icons-register'

const app = createApp(App)

// 全局注册
app.component('SvgIcon', SvgIcon)

app.mount('#app')
```

---

## 4. SVG 组件方案

### 4.1 直接导入 SVG

```vue
<template>
  <img src="@/assets/icons/home.svg" alt="Home" />
</template>
```

### 4.2 SVG 作为组件

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import svgLoader from 'vite-svg-loader'

export default defineConfig({
  plugins: [
    vue(),
    svgLoader({
      svgoConfig: {
        plugins: [
          {
            name: 'removeViewBox',
            active: false
          }
        ]
      }
    })
  ]
})
```

```vue
<script setup lang="ts">
import HomeIcon from '@/assets/icons/home.svg?component'
import UserIcon from '@/assets/icons/user.svg?component'
</script>

<template>
  <HomeIcon class="icon" />
  <UserIcon class="icon" style="color: red;" />
</template>

<style scoped>
.icon {
  width: 24px;
  height: 24px;
  fill: currentColor;
}
</style>
```

### 4.3 动态 SVG 组件

```vue
<script setup lang="ts">
import { defineAsyncComponent } from 'vue'

const props = defineProps<{
  name: string
}>()

const IconComponent = defineAsyncComponent(() => 
  import(`@/assets/icons/${props.name}.svg?component`)
)
</script>

<template>
  <component :is="IconComponent" class="icon" />
</template>
```

### 4.4 SVG 动画

```vue
<template>
  <svg viewBox="0 0 100 100" class="loading-icon">
    <circle 
      cx="50" 
      cy="50" 
      r="40" 
      stroke="currentColor"
      stroke-width="4"
      fill="none"
      stroke-dasharray="251.2"
      stroke-dashoffset="0"
    >
      <animate
        attributeName="stroke-dashoffset"
        from="0"
        to="502.4"
        dur="2s"
        repeatCount="indefinite"
      />
    </circle>
  </svg>
</template>

<style scoped>
.loading-icon {
  width: 50px;
  height: 50px;
  animation: rotate 2s linear infinite;
}

@keyframes rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
```

---

## 5. 第三方图标库

### 5.1 使用 Iconify

```bash
npm install @iconify/vue
```

```vue
<script setup lang="ts">
import { Icon } from '@iconify/vue'
</script>

<template>
  <!-- Material Design Icons -->
  <Icon icon="mdi:home" />
  
  <!-- Font Awesome -->
  <Icon icon="fa:user" />
  
  <!-- 自定义样式 -->
  <Icon 
    icon="mdi:heart" 
    :width="24" 
    :height="24"
    color="red"
  />
</template>
```

### 5.2 使用 Unplugin Icons

```bash
npm install -D unplugin-icons
```

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import Icons from 'unplugin-icons/vite'
import IconsResolver from 'unplugin-icons/resolver'
import Components from 'unplugin-vue-components/vite'

export default defineConfig({
  plugins: [
    Components({
      resolvers: [
        IconsResolver({
          prefix: 'icon'
        })
      ]
    }),
    Icons({
      autoInstall: true
    })
  ]
})
```

```vue
<template>
  <!-- 自动导入 -->
  <icon-mdi-home />
  <icon-fa-user />
  <icon-carbon-logo-github />
</template>
```

### 5.3 Element Plus Icons

```bash
npm install @element-plus/icons-vue
```

```vue
<script setup lang="ts">
import { Edit, Delete, Search } from '@element-plus/icons-vue'
</script>

<template>
  <el-icon :size="20">
    <Edit />
  </el-icon>
  
  <el-icon color="#409EFC">
    <Delete />
  </el-icon>
</template>
```

---

## 6. 自动化工具

### 6.1 SVG 优化

```bash
# 安装 SVGO
npm install -D svgo

# 优化 SVG
npx svgo -f src/icons -o dist/icons
```

```javascript
// svgo.config.js
module.exports = {
  plugins: [
    {
      name: 'preset-default',
      params: {
        overrides: {
          removeViewBox: false,
          cleanupIDs: false
        }
      }
    },
    'removeDimensions',
    'removeStyleElement'
  ]
}
```

### 6.2 批量处理脚本

```javascript
// scripts/process-icons.js
const fs = require('fs')
const path = require('path')
const { optimize } = require('svgo')

const iconsDir = path.resolve(__dirname, '../src/icons')
const outputDir = path.resolve(__dirname, '../src/icons/optimized')

// 确保输出目录存在
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true })
}

// 读取所有 SVG 文件
const files = fs.readdirSync(iconsDir).filter(file => file.endsWith('.svg'))

files.forEach(file => {
  const filePath = path.join(iconsDir, file)
  const svgContent = fs.readFileSync(filePath, 'utf-8')
  
  // 优化 SVG
  const result = optimize(svgContent, {
    path: filePath,
    plugins: [
      {
        name: 'preset-default',
        params: {
          overrides: {
            removeViewBox: false
          }
        }
      }
    ]
  })
  
  // 写入优化后的文件
  const outputPath = path.join(outputDir, file)
  fs.writeFileSync(outputPath, result.data)
  
  console.log(`✓ Optimized: ${file}`)
})

console.log(`\n✓ Total: ${files.length} icons processed`)
```

### 6.3 生成类型定义

```typescript
// scripts/generate-icon-types.ts
import fs from 'fs'
import path from 'path'

const iconsDir = path.resolve(__dirname, '../src/icons')
const outputFile = path.resolve(__dirname, '../src/types/icons.d.ts')

// 读取所有图标文件名
const iconFiles = fs.readdirSync(iconsDir)
  .filter(file => file.endsWith('.svg'))
  .map(file => file.replace('.svg', ''))

// 生成类型定义
const typeDefinition = `
// Auto-generated file. Do not edit manually.
export type IconName = ${iconFiles.map(name => `'${name}'`).join(' | ')}

export const iconNames: IconName[] = [
  ${iconFiles.map(name => `'${name}'`).join(',\n  ')}
]
`

fs.writeFileSync(outputFile, typeDefinition)
console.log(`✓ Generated icon types: ${iconFiles.length} icons`)
```

---

## 7. 性能优化

### 7.1 按需加载

```typescript
// 动态导入图标
const loadIcon = async (name: string) => {
  try {
    const icon = await import(`@/assets/icons/${name}.svg?component`)
    return icon.default
  } catch (error) {
    console.error(`Failed to load icon: ${name}`)
    return null
  }
}
```

### 7.2 图标预加载

```typescript
// 预加载常用图标
const preloadIcons = ['home', 'user', 'search', 'menu']

preloadIcons.forEach(name => {
  import(`@/assets/icons/${name}.svg?component`)
})
```

### 7.3 CDN 加速

```html
<!-- 使用 CDN 加载 iconfont -->
<link 
  rel="stylesheet" 
  href="https://cdn.jsdelivr.net/npm/@icon/font@1.0.0/iconfont.css"
  crossorigin="anonymous"
>
```

### 7.4 缓存策略

```typescript
// 图标缓存
const iconCache = new Map()

async function getIcon(name: string) {
  if (iconCache.has(name)) {
    return iconCache.get(name)
  }
  
  const icon = await import(`@/assets/icons/${name}.svg?component`)
  iconCache.set(name, icon.default)
  
  return icon.default
}
```

---

## 8. 无障碍访问

### 8.1 添加语义化标签

```vue
<template>
  <!-- ✅ 推荐: 添加 aria-label -->
  <button aria-label="关闭">
    <SvgIcon name="close" />
  </button>
  
  <!-- ✅ 推荐: 使用 title -->
  <SvgIcon name="info">
    <title>信息提示</title>
  </SvgIcon>
  
  <!-- ✅ 推荐: 装饰性图标隐藏 -->
  <SvgIcon name="decoration" aria-hidden="true" />
</template>
```

### 8.2 键盘导航支持

```vue
<template>
  <button 
    class="icon-button"
    @click="handleClick"
    @keydown.enter="handleClick"
    @keydown.space.prevent="handleClick"
  >
    <SvgIcon name="action" />
    <span class="sr-only">执行操作</span>
  </button>
</template>

<style scoped>
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
</style>
```

---

## 9. 最佳实践

### 9.1 图标命名规范

```
✅ 推荐命名:
- home.svg
- user-circle.svg
- arrow-right.svg
- check-circle-filled.svg

❌ 不推荐:
- Home.svg (大写)
- user_circle.svg (下划线)
- icon-home.svg (冗余前缀)
- 首页.svg (中文)
```

### 9.2 统一图标尺寸

```vue
<script setup lang="ts">
// 定义标准尺寸
const iconSizes = {
  xs: 12,
  sm: 16,
  md: 20,
  lg: 24,
  xl: 32
}
</script>

<template>
  <SvgIcon name="home" :size="iconSizes.md" />
</template>
```

### 9.3 主题适配

```vue
<template>
  <SvgIcon 
    name="theme" 
    :color="isDark ? '#fff' : '#000'"
  />
</template>

<style>
/* CSS 变量方式 */
.icon {
  color: var(--icon-color, currentColor);
}

/* 暗色模式 */
@media (prefers-color-scheme: dark) {
  .icon {
    --icon-color: #fff;
  }
}
</style>
```

### 9.4 图标组织结构

```
src/
├── assets/
│   └── icons/
│       ├── common/          # 通用图标
│       │   ├── home.svg
│       │   └── user.svg
│       ├── actions/         # 操作图标
│       │   ├── edit.svg
│       │   └── delete.svg
│       └── social/          # 社交图标
│           ├── github.svg
│           └── twitter.svg
└── components/
    └── SvgIcon.vue
```

---

## 10. 常见错误与解决方案

### 10.1 图标不显示

```vue
<!-- ❌ 问题: 路径错误 -->
<use xlink:href="icon-home"></use>

<!-- ✅ 解决: 添加 # 号 -->
<use xlink:href="#icon-home"></use>
```

### 10.2 颜色无法修改

```svg
<!-- ❌ 问题: SVG 内部定义了 fill -->
<svg>
  <path fill="#000" d="..."/>
</svg>

<!-- ✅ 解决: 移除 fill 或使用 currentColor -->
<svg>
  <path fill="currentColor" d="..."/>
</svg>
```

### 10.3 尺寸不正确

```vue
<!-- ❌ 问题: 缺少 viewBox -->
<svg width="24" height="24">
  <path d="..."/>
</svg>

<!-- ✅ 解决: 添加 viewBox -->
<svg viewBox="0 0 24 24">
  <path d="..."/>
</svg>
```

### 10.4 Icon Font 模糊

```css
/* ❌ 问题: 非整数尺寸 */
.icon {
  font-size: 16.5px;
}

/* ✅ 解决: 使用整数尺寸 */
.icon {
  font-size: 16px;
}

/* 或添加抗锯齿 */
.icon {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
```

### 10.5 SVG Sprite 跨域问题

```typescript
// ❌ 问题: 外部 SVG 跨域
<use xlink:href="https://example.com/sprite.svg#icon"></use>

// ✅ 解决方案 1: 内联 SVG
// 将 SVG 内容直接放在 HTML 中

// ✅ 解决方案 2: 使用 CORS
// 服务器设置 Access-Control-Allow-Origin

// ✅ 解决方案 3: 使用 svg4everybody polyfill
import svg4everybody from 'svg4everybody'
svg4everybody()
```

### 10.6 动态导入失败

```typescript
// ❌ 错误: 变量路径
const iconName = 'home'
import(`@/icons/${iconName}.svg`)  // 无法解析

// ✅ 解决: 使用 glob 导入
const icons = import.meta.glob('@/icons/*.svg')
const icon = await icons[`/src/icons/${iconName}.svg`]()
```

### 10.7 TypeScript 类型错误

```typescript
// ❌ 问题: SVG 导入类型错误
import HomeIcon from './home.svg'

// ✅ 解决: 添加类型声明
// vite-env.d.ts
declare module '*.svg' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent
  export default component
}

declare module '*.svg?component' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent
  export default component
}
```

---

## 11. 方案对比

### 11.1 性能对比

```typescript
// Icon Font
// ✅ 体积小 (10-50KB)
// ✅ 加载快
// ❌ 单色限制
// ❌ 抗锯齿问题

// SVG Sprite
// ✅ 多色支持
// ✅ 可缩放
// ❌ 体积较大
// ❌ 兼容性要求

// SVG 组件
// ✅ 最灵活
// ✅ 可交互
// ❌ 打包体积大
// ❌ 按需加载复杂
```

### 11.2 选择建议

```typescript
// 小型项目 (< 50 个图标)
// → Icon Font 或 第三方库

// 中型项目 (50-200 个图标)
// → SVG Sprite + 按需加载

// 大型项目 (> 200 个图标)
// → SVG 组件 + 自动化工具 + CDN

// 需要动画交互
// → SVG 组件

// 需要多色图标
// → SVG Sprite 或 SVG 组件
```

### 11.3 混合方案

```vue
<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  name: string
  type?: 'font' | 'svg' | 'component'
}>()

// 根据类型选择不同方案
const iconType = computed(() => props.type || 'svg')
</script>

<template>
  <!-- Icon Font -->
  <i v-if="iconType === 'font'" :class="`iconfont icon-${name}`"></i>
  
  <!-- SVG Sprite -->
  <svg v-else-if="iconType === 'svg'" class="icon">
    <use :xlink:href="`#icon-${name}`"></use>
  </svg>
  
  <!-- SVG 组件 -->
  <component v-else :is="iconComponent" />
</template>
```

---

## 总结

SVG 和 Icon Font 是前端图标的主流解决方案，掌握它们能够：

**核心优势：**
- ✅ 矢量图形，任意缩放
- ✅ 体积小，加载快
- ✅ 易于维护和更新
- ✅ 支持样式定制
- ✅ 可实现动画效果

**最佳实践要点：**
1. 根据项目规模选择方案
2. 统一图标命名规范
3. 优化 SVG 文件大小
4. 实现按需加载
5. 注意无障碍访问
6. 使用自动化工具
7. 做好缓存策略

**常见陷阱：**
- ❌ 图标路径错误
- ❌ 颜色无法修改
- ❌ 尺寸不正确
- ❌ Icon Font 模糊
- ❌ SVG 跨域问题
- ❌ 动态导入失败
- ❌ TypeScript 类型错误

通过本笔记的学习，你应该能够：
- ✅ 选择合适的图标方案
- ✅ 实现 Icon Font 和 SVG
- ✅ 封装图标组件
- ✅ 使用第三方图标库
- ✅ 优化图标性能
- ✅ 处理常见问题
- ✅ 实现自动化工作流

继续学习建议：
1. 实践不同图标方案
2. 学习 SVG 动画技术
3. 研究图标设计规范
4. 探索图标管理平台

---

> 最后更新: 2024
> 相关工具: Iconfont, SVGO, Iconify, vite-plugin-svg-icons
> 作者: Kiro AI Assistant
```
