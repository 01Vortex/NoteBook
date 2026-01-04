
---

## 目录

1. [简介与环境搭建](#1-简介与环境搭建)
2. [基础组件](#2-基础组件)
3. [表单组件](#3-表单组件)
4. [数据展示组件](#4-数据展示组件)
5. [导航组件](#5-导航组件)
6. [反馈组件](#6-反馈组件)
7. [布局组件](#7-布局组件)
8. [进阶用法](#8-进阶用法)
9. [主题定制](#9-主题定制)
10. [国际化](#10-国际化)
11. [常见错误与解决方案](#11-常见错误与解决方案)
12. [最佳实践](#12-最佳实践)

---

## 1. 简介与环境搭建

### 1.1 什么是 Element Plus？

Element Plus 是一套基于 Vue 3 的桌面端组件库，是 Element UI 的升级版本。它提供了丰富的 UI 组件，帮助开发者快速构建美观、一致的用户界面。

**主要特点：**
- 完全支持 Vue 3 的 Composition API
- 使用 TypeScript 重写，提供完整的类型定义
- 支持按需引入，减小打包体积
- 提供暗黑模式支持
- 国际化支持（i18n）

### 1.2 安装

```bash
# 使用 npm
npm install element-plus

# 使用 yarn
yarn add element-plus

# 使用 pnpm（推荐）
pnpm add element-plus

```

### 1.3 引入方式

#### 完整引入（适合学习和小项目）

完整引入会将所有组件和样式一次性加载，简单方便但会增加打包体积。

```typescript
// main.ts
import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import App from './App.vue'

const app = createApp(App)
app.use(ElementPlus)
app.mount('#app')
```

#### 按需引入（推荐用于生产环境）

按需引入只加载使用到的组件，可以显著减小打包体积。需要配合自动导入插件使用。

```bash
# 安装自动导入插件
npm install -D unplugin-vue-components unplugin-auto-import
```

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

export default defineConfig({
  plugins: [
    vue(),
    AutoImport({
      resolvers: [ElementPlusResolver()],
    }),
    Components({
      resolvers: [ElementPlusResolver()],
    }),
  ],
})
```

配置完成后，可以直接在组件中使用 Element Plus 组件，无需手动导入：

```vue
<template>
  <!-- 无需导入，直接使用 -->
  <el-button type="primary">按钮</el-button>
</template>
```

#### 手动按需引入

如果不想使用自动导入插件，也可以手动引入需要的组件：

```typescript
// main.ts
import { createApp } from 'vue'
import { ElButton, ElInput, ElForm } from 'element-plus'
import 'element-plus/es/components/button/style/css'
import 'element-plus/es/components/input/style/css'
import 'element-plus/es/components/form/style/css'
import App from './App.vue'

const app = createApp(App)
app.component('ElButton', ElButton)
app.component('ElInput', ElInput)
app.component('ElForm', ElForm)
app.mount('#app')
```

---

## 2. 基础组件

### 2.1 Button 按钮

按钮是最常用的组件之一，用于触发操作。Element Plus 提供了多种按钮类型和状态。

#### 基本用法

```vue
<template>
  <div class="button-demo">
    <!-- 默认按钮 -->
    <el-button>默认按钮</el-button>
    
    <!-- 主要按钮：用于主要操作 -->
    <el-button type="primary">主要按钮</el-button>
    
    <!-- 成功按钮：用于成功状态的操作 -->
    <el-button type="success">成功按钮</el-button>
    
    <!-- 信息按钮：用于信息提示类操作 -->
    <el-button type="info">信息按钮</el-button>
    
    <!-- 警告按钮：用于警告类操作 -->
    <el-button type="warning">警告按钮</el-button>
    
    <!-- 危险按钮：用于危险操作，如删除 -->
    <el-button type="danger">危险按钮</el-button>
  </div>
</template>
```


#### 按钮状态

```vue
<template>
  <!-- 朴素按钮：背景透明，只有边框 -->
  <el-button plain>朴素按钮</el-button>
  <el-button type="primary" plain>主要按钮</el-button>
  
  <!-- 圆角按钮 -->
  <el-button round>圆角按钮</el-button>
  <el-button type="primary" round>主要按钮</el-button>
  
  <!-- 圆形按钮：通常配合图标使用 -->
  <el-button :icon="Search" circle />
  <el-button type="primary" :icon="Edit" circle />
  
  <!-- 禁用状态 -->
  <el-button disabled>禁用按钮</el-button>
  <el-button type="primary" disabled>禁用按钮</el-button>
  
  <!-- 加载状态：用于异步操作时显示 -->
  <el-button type="primary" :loading="loading" @click="handleClick">
    {{ loading ? '加载中...' : '点击加载' }}
  </el-button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Search, Edit } from '@element-plus/icons-vue'

const loading = ref(false)

const handleClick = () => {
  loading.value = true
  // 模拟异步操作
  setTimeout(() => {
    loading.value = false
  }, 2000)
}
</script>
```

#### 按钮尺寸

Element Plus 提供了四种尺寸的按钮，可以根据场景选择合适的尺寸。

```vue
<template>
  <el-button size="large">大型按钮</el-button>
  <el-button>默认按钮</el-button>
  <el-button size="small">小型按钮</el-button>
</template>
```

#### 按钮组

当有多个相关操作时，可以使用按钮组将它们组合在一起。

```vue
<template>
  <el-button-group>
    <el-button type="primary" :icon="ArrowLeft">上一页</el-button>
    <el-button type="primary">
      下一页<el-icon class="el-icon--right"><ArrowRight /></el-icon>
    </el-button>
  </el-button-group>
  
  <el-button-group>
    <el-button type="primary" :icon="Edit" />
    <el-button type="primary" :icon="Share" />
    <el-button type="primary" :icon="Delete" />
  </el-button-group>
</template>

<script setup lang="ts">
import { ArrowLeft, ArrowRight, Edit, Share, Delete } from '@element-plus/icons-vue'
</script>
```

### 2.2 Icon 图标

Element Plus 使用 SVG 图标，需要单独安装图标库。

```bash
npm install @element-plus/icons-vue
```

#### 基本用法

```vue
<template>
  <!-- 直接使用图标组件 -->
  <el-icon><Edit /></el-icon>
  <el-icon><Share /></el-icon>
  <el-icon><Delete /></el-icon>
  
  <!-- 设置图标大小和颜色 -->
  <el-icon :size="20" color="#409EFC"><Edit /></el-icon>
  
  <!-- 在按钮中使用图标 -->
  <el-button type="primary" :icon="Search">搜索</el-button>
  
  <!-- 图标在文字后面 -->
  <el-button type="primary">
    上传<el-icon class="el-icon--right"><Upload /></el-icon>
  </el-button>
</template>

<script setup lang="ts">
import { Edit, Share, Delete, Search, Upload } from '@element-plus/icons-vue'
</script>
```

#### 全局注册所有图标

如果项目中大量使用图标，可以全局注册所有图标：

```typescript
// main.ts
import * as ElementPlusIconsVue from '@element-plus/icons-vue'

const app = createApp(App)

// 注册所有图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}
```

### 2.3 Link 链接

文字超链接组件，用于页面内或页面间的跳转。

```vue
<template>
  <div class="link-demo">
    <el-link href="https://element-plus.org" target="_blank">默认链接</el-link>
    <el-link type="primary">主要链接</el-link>
    <el-link type="success">成功链接</el-link>
    <el-link type="warning">警告链接</el-link>
    <el-link type="danger">危险链接</el-link>
    <el-link type="info">信息链接</el-link>
    
    <!-- 禁用状态 -->
    <el-link disabled>禁用链接</el-link>
    
    <!-- 下划线 -->
    <el-link :underline="false">无下划线</el-link>
    
    <!-- 带图标 -->
    <el-link :icon="Edit">编辑</el-link>
  </div>
</template>

<script setup lang="ts">
import { Edit } from '@element-plus/icons-vue'
</script>
```

###
 2.4 Text 文本

用于展示文本内容，支持不同类型和尺寸。

```vue
<template>
  <!-- 不同类型 -->
  <el-text>默认文本</el-text>
  <el-text type="primary">主要文本</el-text>
  <el-text type="success">成功文本</el-text>
  <el-text type="warning">警告文本</el-text>
  <el-text type="danger">危险文本</el-text>
  <el-text type="info">信息文本</el-text>
  
  <!-- 不同尺寸 -->
  <el-text size="large">大号文本</el-text>
  <el-text>默认文本</el-text>
  <el-text size="small">小号文本</el-text>
  
  <!-- 文本省略 -->
  <el-text class="w-150px" truncated>
    这是一段很长的文本，超出部分会被省略显示
  </el-text>
</template>
```

---

## 3. 表单组件

表单是 Web 应用中最常见的交互方式，Element Plus 提供了丰富的表单组件和完善的表单验证机制。

### 3.1 Input 输入框

输入框是最基础的表单组件，用于接收用户输入的文本信息。

#### 基本用法

```vue
<template>
  <div class="input-demo">
    <!-- 基础输入框 -->
    <el-input v-model="input" placeholder="请输入内容" />
    
    <!-- 禁用状态 -->
    <el-input v-model="input" disabled placeholder="禁用状态" />
    
    <!-- 可清空 -->
    <el-input v-model="input" clearable placeholder="可清空" />
    
    <!-- 密码框 -->
    <el-input
      v-model="password"
      type="password"
      placeholder="请输入密码"
      show-password
    />
    
    <!-- 带图标的输入框 -->
    <el-input v-model="input" :prefix-icon="Search" placeholder="搜索" />
    <el-input v-model="input" :suffix-icon="Calendar" placeholder="选择日期" />
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Search, Calendar } from '@element-plus/icons-vue'

const input = ref('')
const password = ref('')
</script>
```

#### 文本域

用于输入多行文本，如评论、描述等。

```vue
<template>
  <!-- 基础文本域 -->
  <el-input
    v-model="textarea"
    type="textarea"
    placeholder="请输入内容"
  />
  
  <!-- 自适应高度 -->
  <el-input
    v-model="textarea"
    type="textarea"
    :autosize="{ minRows: 2, maxRows: 6 }"
    placeholder="自适应高度"
  />
  
  <!-- 显示字数统计 -->
  <el-input
    v-model="textarea"
    type="textarea"
    :rows="4"
    maxlength="200"
    show-word-limit
    placeholder="最多200字"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'
const textarea = ref('')
</script>
```

#### 复合型输入框

可以在输入框前后添加元素，常用于输入网址、金额等场景。

```vue
<template>
  <!-- 前置内容 -->
  <el-input v-model="input" placeholder="请输入网址">
    <template #prepend>https://</template>
  </el-input>
  
  <!-- 后置内容 -->
  <el-input v-model="input" placeholder="请输入域名">
    <template #append>.com</template>
  </el-input>
  
  <!-- 前后都有 -->
  <el-input v-model="input" placeholder="请输入内容">
    <template #prepend>
      <el-select v-model="select" style="width: 100px">
        <el-option label="HTTP" value="1" />
        <el-option label="HTTPS" value="2" />
      </el-select>
    </template>
    <template #append>
      <el-button :icon="Search" />
    </template>
  </el-input>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Search } from '@element-plus/icons-vue'

const input = ref('')
const select = ref('1')
</script>
```

### 3.2 Select 选择器

当选项过多时，使用下拉菜单展示并选择内容。

#### 基本用法

```vue
<template>
  <!-- 基础选择器 -->
  <el-select v-model="value" placeholder="请选择">
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
  
  <!-- 禁用状态 -->
  <el-select v-model="value" disabled placeholder="禁用状态">
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
  
  <!-- 可清空 -->
  <el-select v-model="value" clearable placeholder="可清空">
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const value = ref('')
const options = [
  { value: '1', label: '选项一' },
  { value: '2', label: '选项二' },
  { value: '3', label: '选项三' },
  { value: '4', label: '选项四' },
  { value: '5', label: '选项五' },
]
</script>
```

#
### 多选

```vue
<template>
  <!-- 基础多选 -->
  <el-select v-model="multiValue" multiple placeholder="请选择">
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
  
  <!-- 折叠标签：当选中项过多时，折叠显示 -->
  <el-select
    v-model="multiValue"
    multiple
    collapse-tags
    collapse-tags-tooltip
    placeholder="请选择"
  >
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const multiValue = ref([])
const options = [
  { value: '1', label: '选项一' },
  { value: '2', label: '选项二' },
  { value: '3', label: '选项三' },
  { value: '4', label: '选项四' },
  { value: '5', label: '选项五' },
]
</script>
```

#### 可搜索

当选项较多时，可以使用搜索功能快速定位。

```vue
<template>
  <el-select v-model="value" filterable placeholder="请选择">
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
</template>
```

#### 远程搜索

从服务器搜索数据，常用于数据量大的场景。

```vue
<template>
  <el-select
    v-model="value"
    filterable
    remote
    reserve-keyword
    placeholder="请输入关键词"
    :remote-method="remoteMethod"
    :loading="loading"
  >
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const value = ref('')
const loading = ref(false)
const options = ref([])

const remoteMethod = (query: string) => {
  if (query) {
    loading.value = true
    // 模拟远程请求
    setTimeout(() => {
      loading.value = false
      options.value = [
        { value: '1', label: `${query} - 结果1` },
        { value: '2', label: `${query} - 结果2` },
        { value: '3', label: `${query} - 结果3` },
      ]
    }, 500)
  } else {
    options.value = []
  }
}
</script>
```

### 3.3 Radio 单选框

在一组选项中进行单选。

```vue
<template>
  <!-- 基础用法 -->
  <el-radio-group v-model="radio">
    <el-radio value="1">选项一</el-radio>
    <el-radio value="2">选项二</el-radio>
    <el-radio value="3">选项三</el-radio>
  </el-radio-group>
  
  <!-- 禁用状态 -->
  <el-radio-group v-model="radio">
    <el-radio value="1">选项一</el-radio>
    <el-radio value="2" disabled>选项二（禁用）</el-radio>
    <el-radio value="3">选项三</el-radio>
  </el-radio-group>
  
  <!-- 按钮样式 -->
  <el-radio-group v-model="radio">
    <el-radio-button value="1">选项一</el-radio-button>
    <el-radio-button value="2">选项二</el-radio-button>
    <el-radio-button value="3">选项三</el-radio-button>
  </el-radio-group>
  
  <!-- 带边框 -->
  <el-radio-group v-model="radio">
    <el-radio value="1" border>选项一</el-radio>
    <el-radio value="2" border>选项二</el-radio>
  </el-radio-group>
</template>

<script setup lang="ts">
import { ref } from 'vue'
const radio = ref('1')
</script>
```

### 3.4 Checkbox 多选框

在一组选项中进行多选。

```vue
<template>
  <!-- 基础用法 -->
  <el-checkbox v-model="checked">同意协议</el-checkbox>
  
  <!-- 多选框组 -->
  <el-checkbox-group v-model="checkList">
    <el-checkbox value="A">选项A</el-checkbox>
    <el-checkbox value="B">选项B</el-checkbox>
    <el-checkbox value="C">选项C</el-checkbox>
    <el-checkbox value="D" disabled>选项D（禁用）</el-checkbox>
  </el-checkbox-group>
  
  <!-- 按钮样式 -->
  <el-checkbox-group v-model="checkList">
    <el-checkbox-button value="A">选项A</el-checkbox-button>
    <el-checkbox-button value="B">选项B</el-checkbox-button>
    <el-checkbox-button value="C">选项C</el-checkbox-button>
  </el-checkbox-group>
  
  <!-- 限制选择数量 -->
  <el-checkbox-group v-model="checkList" :min="1" :max="3">
    <el-checkbox value="A">选项A</el-checkbox>
    <el-checkbox value="B">选项B</el-checkbox>
    <el-checkbox value="C">选项C</el-checkbox>
    <el-checkbox value="D">选项D</el-checkbox>
    <el-checkbox value="E">选项E</el-checkbox>
  </el-checkbox-group>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const checked = ref(false)
const checkList = ref(['A', 'B'])
</script>
```

### 3.5 
Switch 开关

表示两种相互对立的状态间的切换，常用于开启/关闭某个功能。

```vue
<template>
  <!-- 基础用法 -->
  <el-switch v-model="value" />
  
  <!-- 文字描述 -->
  <el-switch
    v-model="value"
    active-text="开启"
    inactive-text="关闭"
  />
  
  <!-- 内嵌文字 -->
  <el-switch
    v-model="value"
    inline-prompt
    active-text="是"
    inactive-text="否"
  />
  
  <!-- 自定义颜色 -->
  <el-switch
    v-model="value"
    active-color="#13ce66"
    inactive-color="#ff4949"
  />
  
  <!-- 禁用状态 -->
  <el-switch v-model="value" disabled />
  
  <!-- 加载状态 -->
  <el-switch v-model="value" loading />
</template>

<script setup lang="ts">
import { ref } from 'vue'
const value = ref(true)
</script>
```

### 3.6 DatePicker 日期选择器

用于选择日期或日期范围。

```vue
<template>
  <!-- 选择日期 -->
  <el-date-picker
    v-model="date"
    type="date"
    placeholder="选择日期"
  />
  
  <!-- 选择日期时间 -->
  <el-date-picker
    v-model="datetime"
    type="datetime"
    placeholder="选择日期时间"
  />
  
  <!-- 选择日期范围 -->
  <el-date-picker
    v-model="dateRange"
    type="daterange"
    range-separator="至"
    start-placeholder="开始日期"
    end-placeholder="结束日期"
  />
  
  <!-- 选择月份 -->
  <el-date-picker
    v-model="month"
    type="month"
    placeholder="选择月份"
  />
  
  <!-- 选择年份 -->
  <el-date-picker
    v-model="year"
    type="year"
    placeholder="选择年份"
  />
  
  <!-- 快捷选项 -->
  <el-date-picker
    v-model="date"
    type="date"
    placeholder="选择日期"
    :shortcuts="shortcuts"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'

const date = ref('')
const datetime = ref('')
const dateRange = ref([])
const month = ref('')
const year = ref('')

// 快捷选项配置
const shortcuts = [
  {
    text: '今天',
    value: new Date(),
  },
  {
    text: '昨天',
    value: () => {
      const date = new Date()
      date.setTime(date.getTime() - 3600 * 1000 * 24)
      return date
    },
  },
  {
    text: '一周前',
    value: () => {
      const date = new Date()
      date.setTime(date.getTime() - 3600 * 1000 * 24 * 7)
      return date
    },
  },
]
</script>
```

### 3.7 TimePicker 时间选择器

用于选择时间或时间范围。

```vue
<template>
  <!-- 选择时间 -->
  <el-time-picker
    v-model="time"
    placeholder="选择时间"
  />
  
  <!-- 选择时间范围 -->
  <el-time-picker
    v-model="timeRange"
    is-range
    range-separator="至"
    start-placeholder="开始时间"
    end-placeholder="结束时间"
  />
  
  <!-- 固定时间点 -->
  <el-time-select
    v-model="timeSelect"
    start="08:30"
    step="00:15"
    end="18:30"
    placeholder="选择时间"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'

const time = ref('')
const timeRange = ref([])
const timeSelect = ref('')
</script>
```

### 3.8 Upload 上传

用于文件上传，支持多种上传方式。

```vue
<template>
  <!-- 点击上传 -->
  <el-upload
    action="https://run.mocky.io/v3/9d059bf9-4660-45f2-925d-ce80ad6c4d15"
    :on-success="handleSuccess"
    :on-error="handleError"
  >
    <el-button type="primary">点击上传</el-button>
    <template #tip>
      <div class="el-upload__tip">只能上传 jpg/png 文件，且不超过 500kb</div>
    </template>
  </el-upload>
  
  <!-- 拖拽上传 -->
  <el-upload
    drag
    action="https://run.mocky.io/v3/9d059bf9-4660-45f2-925d-ce80ad6c4d15"
    multiple
  >
    <el-icon class="el-icon--upload"><upload-filled /></el-icon>
    <div class="el-upload__text">
      将文件拖到此处，或<em>点击上传</em>
    </div>
  </el-upload>
  
  <!-- 图片列表 -->
  <el-upload
    action="https://run.mocky.io/v3/9d059bf9-4660-45f2-925d-ce80ad6c4d15"
    list-type="picture-card"
    :on-preview="handlePreview"
    :on-remove="handleRemove"
  >
    <el-icon><Plus /></el-icon>
  </el-upload>
</template>

<script setup lang="ts">
import { UploadFilled, Plus } from '@element-plus/icons-vue'
import type { UploadFile } from 'element-plus'

const handleSuccess = (response: any, file: UploadFile) => {
  console.log('上传成功', response, file)
}

const handleError = (error: Error, file: UploadFile) => {
  console.log('上传失败', error, file)
}

const handlePreview = (file: UploadFile) => {
  console.log('预览', file)
}

const handleRemove = (file: UploadFile) => {
  console.log('删除', file)
}
</script>
```

#
## 3.9 Form 表单

表单组件用于收集、验证和提交数据。这是 Element Plus 中最重要的组件之一。

#### 基本表单

```vue
<template>
  <el-form :model="form" label-width="80px">
    <el-form-item label="用户名">
      <el-input v-model="form.username" />
    </el-form-item>
    <el-form-item label="密码">
      <el-input v-model="form.password" type="password" />
    </el-form-item>
    <el-form-item label="性别">
      <el-radio-group v-model="form.gender">
        <el-radio value="male">男</el-radio>
        <el-radio value="female">女</el-radio>
      </el-radio-group>
    </el-form-item>
    <el-form-item label="爱好">
      <el-checkbox-group v-model="form.hobbies">
        <el-checkbox value="reading">阅读</el-checkbox>
        <el-checkbox value="music">音乐</el-checkbox>
        <el-checkbox value="sports">运动</el-checkbox>
      </el-checkbox-group>
    </el-form-item>
    <el-form-item label="城市">
      <el-select v-model="form.city" placeholder="请选择城市">
        <el-option label="北京" value="beijing" />
        <el-option label="上海" value="shanghai" />
        <el-option label="广州" value="guangzhou" />
      </el-select>
    </el-form-item>
    <el-form-item label="备注">
      <el-input v-model="form.remark" type="textarea" />
    </el-form-item>
    <el-form-item>
      <el-button type="primary" @click="onSubmit">提交</el-button>
      <el-button @click="onReset">重置</el-button>
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
import { reactive } from 'vue'

const form = reactive({
  username: '',
  password: '',
  gender: '',
  hobbies: [],
  city: '',
  remark: '',
})

const onSubmit = () => {
  console.log('提交表单', form)
}

const onReset = () => {
  Object.assign(form, {
    username: '',
    password: '',
    gender: '',
    hobbies: [],
    city: '',
    remark: '',
  })
}
</script>
```

#### 表单验证（重点）

表单验证是实际开发中必不可少的功能。Element Plus 使用 async-validator 进行表单验证。

```vue
<template>
  <el-form
    ref="formRef"
    :model="form"
    :rules="rules"
    label-width="100px"
  >
    <el-form-item label="用户名" prop="username">
      <el-input v-model="form.username" />
    </el-form-item>
    
    <el-form-item label="邮箱" prop="email">
      <el-input v-model="form.email" />
    </el-form-item>
    
    <el-form-item label="密码" prop="password">
      <el-input v-model="form.password" type="password" />
    </el-form-item>
    
    <el-form-item label="确认密码" prop="confirmPassword">
      <el-input v-model="form.confirmPassword" type="password" />
    </el-form-item>
    
    <el-form-item label="年龄" prop="age">
      <el-input-number v-model="form.age" :min="1" :max="120" />
    </el-form-item>
    
    <el-form-item label="手机号" prop="phone">
      <el-input v-model="form.phone" />
    </el-form-item>
    
    <el-form-item>
      <el-button type="primary" @click="submitForm">提交</el-button>
      <el-button @click="resetForm">重置</el-button>
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'

// 表单引用
const formRef = ref<FormInstance>()

// 表单数据
const form = reactive({
  username: '',
  email: '',
  password: '',
  confirmPassword: '',
  age: 18,
  phone: '',
})

// 自定义验证器：验证确认密码
const validateConfirmPassword = (rule: any, value: string, callback: any) => {
  if (value === '') {
    callback(new Error('请再次输入密码'))
  } else if (value !== form.password) {
    callback(new Error('两次输入密码不一致'))
  } else {
    callback()
  }
}

// 自定义验证器：验证手机号
const validatePhone = (rule: any, value: string, callback: any) => {
  const phoneReg = /^1[3-9]\d{9}$/
  if (value === '') {
    callback(new Error('请输入手机号'))
  } else if (!phoneReg.test(value)) {
    callback(new Error('请输入正确的手机号'))
  } else {
    callback()
  }
}

// 验证规则
const rules = reactive<FormRules>({
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, max: 20, message: '长度在 3 到 20 个字符', trigger: 'blur' },
  ],
  email: [
    { required: true, message: '请输入邮箱', trigger: 'blur' },
    { type: 'email', message: '请输入正确的邮箱格式', trigger: 'blur' },
  ],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, max: 20, message: '密码长度在 6 到 20 个字符', trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: '请确认密码', trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' },
  ],
  age: [
    { required: true, message: '请输入年龄', trigger: 'blur' },
    { type: 'number', min: 1, max: 120, message: '年龄必须在 1-120 之间', trigger: 'blur' },
  ],
  phone: [
    { required: true, message: '请输入手机号', trigger: 'blur' },
    { validator: validatePhone, trigger: 'blur' },
  ],
})

// 提交表单
const submitForm = async () => {
  if (!formRef.value) return
  
  try {
    // 验证表单
    await formRef.value.validate()
    console.log('验证通过，提交表单', form)
    // 这里可以调用 API 提交数据
  } catch (error) {
    console.log('验证失败', error)
  }
}

// 重置表单
const resetForm = () => {
  if (!formRef.value) return
  formRef.value.resetFields()
}
</script>
```


#### 动态表单

有时候表单项是动态的，比如添加多个联系人信息。

```vue
<template>
  <el-form ref="formRef" :model="form" label-width="100px">
    <el-form-item
      v-for="(item, index) in form.contacts"
      :key="index"
      :label="'联系人 ' + (index + 1)"
      :prop="'contacts.' + index + '.name'"
      :rules="[{ required: true, message: '请输入联系人姓名', trigger: 'blur' }]"
    >
      <el-row :gutter="20">
        <el-col :span="10">
          <el-input v-model="item.name" placeholder="姓名" />
        </el-col>
        <el-col :span="10">
          <el-input v-model="item.phone" placeholder="电话" />
        </el-col>
        <el-col :span="4">
          <el-button type="danger" @click="removeContact(index)">删除</el-button>
        </el-col>
      </el-row>
    </el-form-item>
    
    <el-form-item>
      <el-button @click="addContact">添加联系人</el-button>
      <el-button type="primary" @click="submitForm">提交</el-button>
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import type { FormInstance } from 'element-plus'

const formRef = ref<FormInstance>()

const form = reactive({
  contacts: [
    { name: '', phone: '' }
  ]
})

const addContact = () => {
  form.contacts.push({ name: '', phone: '' })
}

const removeContact = (index: number) => {
  if (form.contacts.length > 1) {
    form.contacts.splice(index, 1)
  }
}

const submitForm = async () => {
  if (!formRef.value) return
  try {
    await formRef.value.validate()
    console.log('提交', form)
  } catch (error) {
    console.log('验证失败', error)
  }
}
</script>
```

---

## 4. 数据展示组件

### 4.1 Table 表格

表格是展示数据最常用的组件，Element Plus 的表格功能非常强大。

#### 基础表格

```vue
<template>
  <el-table :data="tableData" style="width: 100%">
    <el-table-column prop="date" label="日期" width="180" />
    <el-table-column prop="name" label="姓名" width="180" />
    <el-table-column prop="address" label="地址" />
  </el-table>
</template>

<script setup lang="ts">
const tableData = [
  { date: '2024-01-01', name: '张三', address: '北京市朝阳区' },
  { date: '2024-01-02', name: '李四', address: '上海市浦东新区' },
  { date: '2024-01-03', name: '王五', address: '广州市天河区' },
  { date: '2024-01-04', name: '赵六', address: '深圳市南山区' },
]
</script>
```

#### 带斑马纹和边框

```vue
<template>
  <el-table :data="tableData" stripe border style="width: 100%">
    <el-table-column prop="date" label="日期" width="180" />
    <el-table-column prop="name" label="姓名" width="180" />
    <el-table-column prop="address" label="地址" />
  </el-table>
</template>
```

#### 固定表头和列

当数据量大时，可以固定表头或某些列，方便查看。

```vue
<template>
  <el-table :data="tableData" height="250" style="width: 100%">
    <!-- 固定左侧列 -->
    <el-table-column fixed prop="date" label="日期" width="150" />
    <el-table-column prop="name" label="姓名" width="120" />
    <el-table-column prop="province" label="省份" width="120" />
    <el-table-column prop="city" label="城市" width="120" />
    <el-table-column prop="address" label="地址" width="300" />
    <el-table-column prop="zip" label="邮编" width="120" />
    <!-- 固定右侧列 -->
    <el-table-column fixed="right" label="操作" width="120">
      <template #default="scope">
        <el-button link type="primary" size="small" @click="handleEdit(scope.row)">
          编辑
        </el-button>
        <el-button link type="danger" size="small" @click="handleDelete(scope.row)">
          删除
        </el-button>
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup lang="ts">
const tableData = [
  { date: '2024-01-01', name: '张三', province: '北京', city: '北京', address: '朝阳区xxx街道', zip: '100000' },
  { date: '2024-01-02', name: '李四', province: '上海', city: '上海', address: '浦东新区xxx街道', zip: '200000' },
  // ... 更多数据
]

const handleEdit = (row: any) => {
  console.log('编辑', row)
}

const handleDelete = (row: any) => {
  console.log('删除', row)
}
</script>
```

#### 多选表格

```vue
<template>
  <el-table
    ref="tableRef"
    :data="tableData"
    @selection-change="handleSelectionChange"
  >
    <el-table-column type="selection" width="55" />
    <el-table-column prop="date" label="日期" width="180" />
    <el-table-column prop="name" label="姓名" width="180" />
    <el-table-column prop="address" label="地址" />
  </el-table>
  
  <div style="margin-top: 20px">
    <el-button @click="toggleSelection([tableData[1], tableData[2]])">
      选中第二、三行
    </el-button>
    <el-button @click="toggleSelection()">清除选择</el-button>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { ElTable } from 'element-plus'

const tableRef = ref<InstanceType<typeof ElTable>>()
const multipleSelection = ref([])

const tableData = [
  { date: '2024-01-01', name: '张三', address: '北京市朝阳区' },
  { date: '2024-01-02', name: '李四', address: '上海市浦东新区' },
  { date: '2024-01-03', name: '王五', address: '广州市天河区' },
]

const handleSelectionChange = (val: any[]) => {
  multipleSelection.value = val
  console.log('选中的数据', val)
}

const toggleSelection = (rows?: any[]) => {
  if (rows) {
    rows.forEach((row) => {
      tableRef.value?.toggleRowSelection(row, true)
    })
  } else {
    tableRef.value?.clearSelection()
  }
}
</script>
```

###
# 排序和筛选

```vue
<template>
  <el-table :data="tableData" @sort-change="handleSortChange">
    <el-table-column prop="date" label="日期" sortable width="180" />
    <el-table-column prop="name" label="姓名" width="180" />
    <el-table-column
      prop="status"
      label="状态"
      :filters="[
        { text: '启用', value: 'active' },
        { text: '禁用', value: 'inactive' },
      ]"
      :filter-method="filterStatus"
    />
    <el-table-column prop="address" label="地址" />
  </el-table>
</template>

<script setup lang="ts">
const tableData = [
  { date: '2024-01-01', name: '张三', status: 'active', address: '北京市' },
  { date: '2024-01-02', name: '李四', status: 'inactive', address: '上海市' },
  { date: '2024-01-03', name: '王五', status: 'active', address: '广州市' },
]

const handleSortChange = ({ column, prop, order }: any) => {
  console.log('排序变化', prop, order)
}

const filterStatus = (value: string, row: any) => {
  return row.status === value
}
</script>
```

#### 自定义列模板

使用插槽可以自定义列的显示内容。

```vue
<template>
  <el-table :data="tableData">
    <el-table-column prop="date" label="日期" width="180" />
    <el-table-column prop="name" label="姓名" width="180" />
    
    <!-- 自定义状态列 -->
    <el-table-column prop="status" label="状态" width="100">
      <template #default="scope">
        <el-tag :type="scope.row.status === 'active' ? 'success' : 'danger'">
          {{ scope.row.status === 'active' ? '启用' : '禁用' }}
        </el-tag>
      </template>
    </el-table-column>
    
    <!-- 自定义操作列 -->
    <el-table-column label="操作" width="200">
      <template #default="scope">
        <el-button size="small" @click="handleEdit(scope.$index, scope.row)">
          编辑
        </el-button>
        <el-button size="small" type="danger" @click="handleDelete(scope.$index, scope.row)">
          删除
        </el-button>
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup lang="ts">
const tableData = [
  { date: '2024-01-01', name: '张三', status: 'active' },
  { date: '2024-01-02', name: '李四', status: 'inactive' },
]

const handleEdit = (index: number, row: any) => {
  console.log('编辑', index, row)
}

const handleDelete = (index: number, row: any) => {
  console.log('删除', index, row)
}
</script>
```

### 4.2 Pagination 分页

当数据量过多时，使用分页分解数据。

```vue
<template>
  <div>
    <!-- 基础分页 -->
    <el-pagination
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :page-sizes="[10, 20, 50, 100]"
      :total="total"
      layout="total, sizes, prev, pager, next, jumper"
      @size-change="handleSizeChange"
      @current-change="handleCurrentChange"
    />
    
    <!-- 表格 + 分页完整示例 -->
    <el-table :data="paginatedData" style="margin-top: 20px">
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="name" label="姓名" />
      <el-table-column prop="email" label="邮箱" />
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'

const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(100)

// 模拟数据
const allData = Array.from({ length: 100 }, (_, i) => ({
  id: i + 1,
  name: `用户${i + 1}`,
  email: `user${i + 1}@example.com`,
}))

// 计算当前页数据
const paginatedData = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  return allData.slice(start, end)
})

const handleSizeChange = (val: number) => {
  console.log(`每页 ${val} 条`)
  pageSize.value = val
  currentPage.value = 1 // 切换每页条数时，回到第一页
}

const handleCurrentChange = (val: number) => {
  console.log(`当前页: ${val}`)
  currentPage.value = val
}
</script>
```

### 4.3 Tag 标签

用于标记和选择。

```vue
<template>
  <!-- 基础标签 -->
  <el-tag>标签一</el-tag>
  <el-tag type="success">标签二</el-tag>
  <el-tag type="info">标签三</el-tag>
  <el-tag type="warning">标签四</el-tag>
  <el-tag type="danger">标签五</el-tag>
  
  <!-- 可移除标签 -->
  <el-tag
    v-for="tag in tags"
    :key="tag"
    closable
    @close="handleClose(tag)"
  >
    {{ tag }}
  </el-tag>
  
  <!-- 动态编辑标签 -->
  <el-tag
    v-for="tag in dynamicTags"
    :key="tag"
    closable
    @close="handleTagClose(tag)"
  >
    {{ tag }}
  </el-tag>
  <el-input
    v-if="inputVisible"
    ref="inputRef"
    v-model="inputValue"
    size="small"
    style="width: 100px"
    @keyup.enter="handleInputConfirm"
    @blur="handleInputConfirm"
  />
  <el-button v-else size="small" @click="showInput">+ 新标签</el-button>
</template>

<script setup lang="ts">
import { ref, nextTick } from 'vue'

const tags = ref(['标签一', '标签二', '标签三'])
const dynamicTags = ref(['标签一', '标签二', '标签三'])
const inputVisible = ref(false)
const inputValue = ref('')
const inputRef = ref()

const handleClose = (tag: string) => {
  tags.value.splice(tags.value.indexOf(tag), 1)
}

const handleTagClose = (tag: string) => {
  dynamicTags.value.splice(dynamicTags.value.indexOf(tag), 1)
}

const showInput = () => {
  inputVisible.value = true
  nextTick(() => {
    inputRef.value?.focus()
  })
}

const handleInputConfirm = () => {
  if (inputValue.value) {
    dynamicTags.value.push(inputValue.value)
  }
  inputVisible.value = false
  inputValue.value = ''
}
</script>
```

##
# 4.4 Tree 树形控件

用于展示层级结构的数据。

```vue
<template>
  <!-- 基础树形控件 -->
  <el-tree :data="treeData" :props="defaultProps" @node-click="handleNodeClick" />
  
  <!-- 可选择的树 -->
  <el-tree
    ref="treeRef"
    :data="treeData"
    :props="defaultProps"
    show-checkbox
    node-key="id"
    default-expand-all
    @check-change="handleCheckChange"
  />
  
  <!-- 获取选中节点 -->
  <el-button @click="getCheckedNodes">获取选中节点</el-button>
  <el-button @click="getCheckedKeys">获取选中节点 key</el-button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { ElTree } from 'element-plus'

const treeRef = ref<InstanceType<typeof ElTree>>()

const treeData = [
  {
    id: 1,
    label: '一级 1',
    children: [
      {
        id: 11,
        label: '二级 1-1',
        children: [
          { id: 111, label: '三级 1-1-1' },
          { id: 112, label: '三级 1-1-2' },
        ],
      },
    ],
  },
  {
    id: 2,
    label: '一级 2',
    children: [
      { id: 21, label: '二级 2-1' },
      { id: 22, label: '二级 2-2' },
    ],
  },
  {
    id: 3,
    label: '一级 3',
    children: [
      { id: 31, label: '二级 3-1' },
      { id: 32, label: '二级 3-2' },
    ],
  },
]

const defaultProps = {
  children: 'children',
  label: 'label',
}

const handleNodeClick = (data: any) => {
  console.log('点击节点', data)
}

const handleCheckChange = (data: any, checked: boolean, indeterminate: boolean) => {
  console.log('选中状态变化', data, checked, indeterminate)
}

const getCheckedNodes = () => {
  console.log('选中的节点', treeRef.value?.getCheckedNodes())
}

const getCheckedKeys = () => {
  console.log('选中的节点 key', treeRef.value?.getCheckedKeys())
}
</script>
```

### 4.5 Card 卡片

将信息聚合在卡片容器中展示。

```vue
<template>
  <!-- 基础卡片 -->
  <el-card style="max-width: 480px">
    <template #header>
      <div class="card-header">
        <span>卡片标题</span>
        <el-button type="primary" text>操作按钮</el-button>
      </div>
    </template>
    <p>卡片内容</p>
    <p>卡片内容</p>
  </el-card>
  
  <!-- 简单卡片 -->
  <el-card style="max-width: 480px" shadow="hover">
    <p>鼠标悬停时显示阴影</p>
  </el-card>
  
  <!-- 无阴影卡片 -->
  <el-card style="max-width: 480px" shadow="never">
    <p>无阴影卡片</p>
  </el-card>
</template>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
```

### 4.6 Descriptions 描述列表

用于展示多个字段的详细信息。

```vue
<template>
  <el-descriptions title="用户信息" :column="3" border>
    <el-descriptions-item label="用户名">张三</el-descriptions-item>
    <el-descriptions-item label="手机号">18888888888</el-descriptions-item>
    <el-descriptions-item label="居住地">北京市</el-descriptions-item>
    <el-descriptions-item label="备注">
      <el-tag size="small">学生</el-tag>
    </el-descriptions-item>
    <el-descriptions-item label="联系地址">
      北京市朝阳区xxx街道xxx小区xxx号
    </el-descriptions-item>
  </el-descriptions>
</template>
```

### 4.7 Empty 空状态

空状态时的占位提示。

```vue
<template>
  <!-- 基础用法 -->
  <el-empty description="暂无数据" />
  
  <!-- 自定义图片 -->
  <el-empty image="https://example.com/empty.png" description="暂无数据" />
  
  <!-- 自定义底部内容 -->
  <el-empty description="暂无数据">
    <el-button type="primary">添加数据</el-button>
  </el-empty>
</template>
```

---

## 5. 导航组件

### 5.1 Menu 菜单

为网站提供导航功能的菜单。

#### 顶部导航菜单

```vue
<template>
  <el-menu
    :default-active="activeIndex"
    mode="horizontal"
    @select="handleSelect"
  >
    <el-menu-item index="1">首页</el-menu-item>
    <el-sub-menu index="2">
      <template #title>产品中心</template>
      <el-menu-item index="2-1">产品一</el-menu-item>
      <el-menu-item index="2-2">产品二</el-menu-item>
      <el-sub-menu index="2-3">
        <template #title>更多产品</template>
        <el-menu-item index="2-3-1">产品三</el-menu-item>
        <el-menu-item index="2-3-2">产品四</el-menu-item>
      </el-sub-menu>
    </el-sub-menu>
    <el-menu-item index="3">关于我们</el-menu-item>
    <el-menu-item index="4" disabled>帮助中心</el-menu-item>
  </el-menu>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const activeIndex = ref('1')

const handleSelect = (key: string, keyPath: string[]) => {
  console.log('选中菜单', key, keyPath)
}
</script>
```


#### 侧边栏导航菜单

```vue
<template>
  <el-menu
    :default-active="activeIndex"
    class="el-menu-vertical"
    :collapse="isCollapse"
    @select="handleSelect"
  >
    <el-menu-item index="1">
      <el-icon><House /></el-icon>
      <span>首页</span>
    </el-menu-item>
    
    <el-sub-menu index="2">
      <template #title>
        <el-icon><User /></el-icon>
        <span>用户管理</span>
      </template>
      <el-menu-item index="2-1">用户列表</el-menu-item>
      <el-menu-item index="2-2">角色管理</el-menu-item>
      <el-menu-item index="2-3">权限管理</el-menu-item>
    </el-sub-menu>
    
    <el-sub-menu index="3">
      <template #title>
        <el-icon><Setting /></el-icon>
        <span>系统设置</span>
      </template>
      <el-menu-item index="3-1">基础设置</el-menu-item>
      <el-menu-item index="3-2">安全设置</el-menu-item>
    </el-sub-menu>
  </el-menu>
  
  <el-button @click="isCollapse = !isCollapse">
    {{ isCollapse ? '展开' : '收起' }}
  </el-button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { House, User, Setting } from '@element-plus/icons-vue'

const activeIndex = ref('1')
const isCollapse = ref(false)

const handleSelect = (key: string) => {
  console.log('选中菜单', key)
}
</script>

<style scoped>
.el-menu-vertical {
  width: 200px;
  min-height: 400px;
}
.el-menu-vertical:not(.el-menu--collapse) {
  width: 200px;
}
</style>
```

### 5.2 Tabs 标签页

分隔内容上有关联但属于不同类别的数据集合。

```vue
<template>
  <!-- 基础标签页 -->
  <el-tabs v-model="activeName" @tab-click="handleClick">
    <el-tab-pane label="用户管理" name="first">用户管理内容</el-tab-pane>
    <el-tab-pane label="配置管理" name="second">配置管理内容</el-tab-pane>
    <el-tab-pane label="角色管理" name="third">角色管理内容</el-tab-pane>
    <el-tab-pane label="定时任务" name="fourth">定时任务内容</el-tab-pane>
  </el-tabs>
  
  <!-- 卡片风格 -->
  <el-tabs v-model="activeName" type="card">
    <el-tab-pane label="用户管理" name="first">用户管理内容</el-tab-pane>
    <el-tab-pane label="配置管理" name="second">配置管理内容</el-tab-pane>
  </el-tabs>
  
  <!-- 带边框卡片风格 -->
  <el-tabs v-model="activeName" type="border-card">
    <el-tab-pane label="用户管理" name="first">用户管理内容</el-tab-pane>
    <el-tab-pane label="配置管理" name="second">配置管理内容</el-tab-pane>
  </el-tabs>
  
  <!-- 可关闭标签页 -->
  <el-tabs v-model="editableTabsValue" type="card" closable @tab-remove="removeTab">
    <el-tab-pane
      v-for="item in editableTabs"
      :key="item.name"
      :label="item.title"
      :name="item.name"
    >
      {{ item.content }}
    </el-tab-pane>
  </el-tabs>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { TabsPaneContext } from 'element-plus'

const activeName = ref('first')
const editableTabsValue = ref('1')
const editableTabs = ref([
  { title: '标签 1', name: '1', content: '标签 1 的内容' },
  { title: '标签 2', name: '2', content: '标签 2 的内容' },
])

const handleClick = (tab: TabsPaneContext, event: Event) => {
  console.log('点击标签', tab, event)
}

const removeTab = (targetName: string) => {
  const tabs = editableTabs.value
  let activeName = editableTabsValue.value
  if (activeName === targetName) {
    tabs.forEach((tab, index) => {
      if (tab.name === targetName) {
        const nextTab = tabs[index + 1] || tabs[index - 1]
        if (nextTab) {
          activeName = nextTab.name
        }
      }
    })
  }
  editableTabsValue.value = activeName
  editableTabs.value = tabs.filter((tab) => tab.name !== targetName)
}
</script>
```

### 5.3 Breadcrumb 面包屑

显示当前页面的路径，快速返回之前的任意页面。

```vue
<template>
  <!-- 基础用法 -->
  <el-breadcrumb separator="/">
    <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
    <el-breadcrumb-item :to="{ path: '/user' }">用户管理</el-breadcrumb-item>
    <el-breadcrumb-item>用户列表</el-breadcrumb-item>
  </el-breadcrumb>
  
  <!-- 图标分隔符 -->
  <el-breadcrumb :separator-icon="ArrowRight">
    <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
    <el-breadcrumb-item>用户管理</el-breadcrumb-item>
    <el-breadcrumb-item>用户列表</el-breadcrumb-item>
  </el-breadcrumb>
</template>

<script setup lang="ts">
import { ArrowRight } from '@element-plus/icons-vue'
</script>
```

### 5.4 Dropdown 下拉菜单

将动作或菜单折叠到下拉菜单中。

```vue
<template>
  <!-- 基础用法 -->
  <el-dropdown @command="handleCommand">
    <span class="el-dropdown-link">
      下拉菜单<el-icon class="el-icon--right"><ArrowDown /></el-icon>
    </span>
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item command="a">选项一</el-dropdown-item>
        <el-dropdown-item command="b">选项二</el-dropdown-item>
        <el-dropdown-item command="c" disabled>选项三</el-dropdown-item>
        <el-dropdown-item command="d" divided>选项四</el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
  
  <!-- 按钮触发 -->
  <el-dropdown split-button type="primary" @command="handleCommand">
    更多操作
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item command="edit">编辑</el-dropdown-item>
        <el-dropdown-item command="delete">删除</el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
</template>

<script setup lang="ts">
import { ArrowDown } from '@element-plus/icons-vue'

const handleCommand = (command: string) => {
  console.log('点击了', command)
}
</script>

<style scoped>
.el-dropdown-link {
  cursor: pointer;
  color: var(--el-color-primary);
  display: flex;
  align-items: center;
}
</style>
```

### 
5.5 Steps 步骤条

引导用户按照流程完成任务的分步导航条。

```vue
<template>
  <!-- 基础步骤条 -->
  <el-steps :active="active" finish-status="success">
    <el-step title="步骤 1" description="这是步骤1的描述" />
    <el-step title="步骤 2" description="这是步骤2的描述" />
    <el-step title="步骤 3" description="这是步骤3的描述" />
  </el-steps>
  
  <el-button @click="prev" :disabled="active === 0">上一步</el-button>
  <el-button @click="next" :disabled="active === 3">下一步</el-button>
  
  <!-- 带图标的步骤条 -->
  <el-steps :active="1">
    <el-step title="步骤 1" :icon="Edit" />
    <el-step title="步骤 2" :icon="Upload" />
    <el-step title="步骤 3" :icon="Picture" />
  </el-steps>
  
  <!-- 竖向步骤条 -->
  <el-steps direction="vertical" :active="1">
    <el-step title="步骤 1" description="这是步骤1的描述" />
    <el-step title="步骤 2" description="这是步骤2的描述" />
    <el-step title="步骤 3" description="这是步骤3的描述" />
  </el-steps>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { Edit, Upload, Picture } from '@element-plus/icons-vue'

const active = ref(0)

const next = () => {
  if (active.value < 3) active.value++
}

const prev = () => {
  if (active.value > 0) active.value--
}
</script>
```

---

## 6. 反馈组件

### 6.1 Dialog 对话框

在保留当前页面状态的情况下，告知用户并承载相关操作。

```vue
<template>
  <el-button @click="dialogVisible = true">打开对话框</el-button>
  
  <el-dialog
    v-model="dialogVisible"
    title="提示"
    width="500"
    :before-close="handleClose"
  >
    <span>这是一段信息</span>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleConfirm">确定</el-button>
      </span>
    </template>
  </el-dialog>
  
  <!-- 嵌套表单的对话框 -->
  <el-button @click="formDialogVisible = true">打开表单对话框</el-button>
  
  <el-dialog v-model="formDialogVisible" title="用户信息" width="500">
    <el-form :model="form" label-width="80px">
      <el-form-item label="用户名">
        <el-input v-model="form.name" />
      </el-form-item>
      <el-form-item label="邮箱">
        <el-input v-model="form.email" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="formDialogVisible = false">取消</el-button>
      <el-button type="primary" @click="submitForm">提交</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'
import { ElMessageBox } from 'element-plus'

const dialogVisible = ref(false)
const formDialogVisible = ref(false)

const form = reactive({
  name: '',
  email: '',
})

const handleClose = (done: () => void) => {
  ElMessageBox.confirm('确定要关闭吗？')
    .then(() => {
      done()
    })
    .catch(() => {
      // 取消关闭
    })
}

const handleConfirm = () => {
  console.log('确定')
  dialogVisible.value = false
}

const submitForm = () => {
  console.log('提交表单', form)
  formDialogVisible.value = false
}
</script>
```

### 6.2 Message 消息提示

常用于主动操作后的反馈提示。

```vue
<template>
  <el-button @click="showMessage">显示消息</el-button>
  <el-button @click="showSuccess">成功消息</el-button>
  <el-button @click="showWarning">警告消息</el-button>
  <el-button @click="showError">错误消息</el-button>
  <el-button @click="showClosable">可关闭消息</el-button>
  <el-button @click="showHtml">HTML 消息</el-button>
</template>

<script setup lang="ts">
import { ElMessage } from 'element-plus'

const showMessage = () => {
  ElMessage('这是一条消息提示')
}

const showSuccess = () => {
  ElMessage.success('操作成功')
}

const showWarning = () => {
  ElMessage.warning('警告信息')
}

const showError = () => {
  ElMessage.error('错误信息')
}

const showClosable = () => {
  ElMessage({
    message: '这是一条可关闭的消息',
    showClose: true,
    duration: 0, // 不自动关闭
  })
}

const showHtml = () => {
  ElMessage({
    dangerouslyUseHTMLString: true,
    message: '<strong>这是 <i>HTML</i> 消息</strong>',
  })
}
</script>
```

### 6.3 MessageBox 消息弹框

模拟系统的消息提示框而实现的一套模态对话框组件，用于消息提示、确认消息和提交内容。

```vue
<template>
  <el-button @click="showAlert">Alert</el-button>
  <el-button @click="showConfirm">Confirm</el-button>
  <el-button @click="showPrompt">Prompt</el-button>
</template>

<script setup lang="ts">
import { ElMessageBox, ElMessage } from 'element-plus'

// 消息提示
const showAlert = () => {
  ElMessageBox.alert('这是一段内容', '标题', {
    confirmButtonText: '确定',
    callback: (action: string) => {
      ElMessage.info(`action: ${action}`)
    },
  })
}

// 确认消息
const showConfirm = () => {
  ElMessageBox.confirm(
    '此操作将永久删除该文件, 是否继续?',
    '警告',
    {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning',
    }
  )
    .then(() => {
      ElMessage.success('删除成功!')
    })
    .catch(() => {
      ElMessage.info('已取消删除')
    })
}

// 提交内容
const showPrompt = () => {
  ElMessageBox.prompt('请输入邮箱', '提示', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    inputPattern: /[\w!#$%&'*+/=?^_`{|}~-]+(?:\.[\w!#$%&'*+/=?^_`{|}~-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?/,
    inputErrorMessage: '邮箱格式不正确',
  })
    .then(({ value }) => {
      ElMessage.success(`你的邮箱是: ${value}`)
    })
    .catch(() => {
      ElMessage.info('取消输入')
    })
}
</script>
```

### 6.
4 Notification 通知

悬浮出现在页面角落，显示全局的通知提醒消息。

```vue
<template>
  <el-button @click="showNotification">显示通知</el-button>
  <el-button @click="showSuccess">成功通知</el-button>
  <el-button @click="showWarning">警告通知</el-button>
  <el-button @click="showError">错误通知</el-button>
</template>

<script setup lang="ts">
import { ElNotification } from 'element-plus'

const showNotification = () => {
  ElNotification({
    title: '标题',
    message: '这是一条通知消息',
  })
}

const showSuccess = () => {
  ElNotification({
    title: '成功',
    message: '操作成功',
    type: 'success',
  })
}

const showWarning = () => {
  ElNotification({
    title: '警告',
    message: '这是一条警告通知',
    type: 'warning',
  })
}

const showError = () => {
  ElNotification({
    title: '错误',
    message: '这是一条错误通知',
    type: 'error',
    duration: 0, // 不自动关闭
  })
}
</script>
```

### 6.5 Loading 加载

加载数据时显示动效。

```vue
<template>
  <!-- 区域加载 -->
  <el-table v-loading="loading" :data="tableData">
    <el-table-column prop="name" label="姓名" />
    <el-table-column prop="age" label="年龄" />
  </el-table>
  
  <!-- 自定义加载文案 -->
  <el-table
    v-loading="loading"
    element-loading-text="拼命加载中..."
    element-loading-background="rgba(0, 0, 0, 0.7)"
    :data="tableData"
  >
    <el-table-column prop="name" label="姓名" />
  </el-table>
  
  <el-button @click="toggleLoading">切换加载状态</el-button>
  <el-button @click="fullscreenLoading">全屏加载</el-button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElLoading } from 'element-plus'

const loading = ref(false)
const tableData = [
  { name: '张三', age: 20 },
  { name: '李四', age: 25 },
]

const toggleLoading = () => {
  loading.value = !loading.value
}

// 全屏加载（以服务的方式调用）
const fullscreenLoading = () => {
  const loadingInstance = ElLoading.service({
    lock: true,
    text: '加载中...',
    background: 'rgba(0, 0, 0, 0.7)',
  })
  
  // 模拟异步操作
  setTimeout(() => {
    loadingInstance.close()
  }, 2000)
}
</script>
```

### 6.6 Popconfirm 气泡确认框

点击元素，弹出气泡式的确认框。

```vue
<template>
  <el-popconfirm
    title="确定要删除吗？"
    confirm-button-text="确定"
    cancel-button-text="取消"
    @confirm="handleConfirm"
    @cancel="handleCancel"
  >
    <template #reference>
      <el-button type="danger">删除</el-button>
    </template>
  </el-popconfirm>
</template>

<script setup lang="ts">
import { ElMessage } from 'element-plus'

const handleConfirm = () => {
  ElMessage.success('删除成功')
}

const handleCancel = () => {
  ElMessage.info('取消删除')
}
</script>
```

### 6.7 Tooltip 文字提示

常用于展示鼠标 hover 时的提示信息。

```vue
<template>
  <!-- 基础用法 -->
  <el-tooltip content="这是提示内容" placement="top">
    <el-button>上方提示</el-button>
  </el-tooltip>
  
  <el-tooltip content="这是提示内容" placement="bottom">
    <el-button>下方提示</el-button>
  </el-tooltip>
  
  <el-tooltip content="这是提示内容" placement="left">
    <el-button>左侧提示</el-button>
  </el-tooltip>
  
  <el-tooltip content="这是提示内容" placement="right">
    <el-button>右侧提示</el-button>
  </el-tooltip>
  
  <!-- 自定义内容 -->
  <el-tooltip placement="top">
    <template #content>
      多行信息<br />第二行信息
    </template>
    <el-button>多行提示</el-button>
  </el-tooltip>
</template>
```

---

## 7. 布局组件

### 7.1 Layout 布局

通过基础的 24 分栏，迅速简便地创建布局。

```vue
<template>
  <!-- 基础布局 -->
  <el-row>
    <el-col :span="24"><div class="grid-content">24</div></el-col>
  </el-row>
  <el-row>
    <el-col :span="12"><div class="grid-content">12</div></el-col>
    <el-col :span="12"><div class="grid-content light">12</div></el-col>
  </el-row>
  <el-row>
    <el-col :span="8"><div class="grid-content">8</div></el-col>
    <el-col :span="8"><div class="grid-content light">8</div></el-col>
    <el-col :span="8"><div class="grid-content">8</div></el-col>
  </el-row>
  
  <!-- 分栏间隔 -->
  <el-row :gutter="20">
    <el-col :span="6"><div class="grid-content">6</div></el-col>
    <el-col :span="6"><div class="grid-content">6</div></el-col>
    <el-col :span="6"><div class="grid-content">6</div></el-col>
    <el-col :span="6"><div class="grid-content">6</div></el-col>
  </el-row>
  
  <!-- 分栏偏移 -->
  <el-row>
    <el-col :span="6"><div class="grid-content">6</div></el-col>
    <el-col :span="6" :offset="6"><div class="grid-content">6 offset-6</div></el-col>
  </el-row>
  
  <!-- 对齐方式 -->
  <el-row justify="center">
    <el-col :span="6"><div class="grid-content">居中</div></el-col>
  </el-row>
  <el-row justify="end">
    <el-col :span="6"><div class="grid-content">右对齐</div></el-col>
  </el-row>
  <el-row justify="space-between">
    <el-col :span="6"><div class="grid-content">两端对齐</div></el-col>
    <el-col :span="6"><div class="grid-content">两端对齐</div></el-col>
  </el-row>
  
  <!-- 响应式布局 -->
  <el-row :gutter="10">
    <el-col :xs="24" :sm="12" :md="8" :lg="6" :xl="4">
      <div class="grid-content">响应式</div>
    </el-col>
    <el-col :xs="24" :sm="12" :md="8" :lg="6" :xl="4">
      <div class="grid-content">响应式</div>
    </el-col>
  </el-row>
</template>

<style scoped>
.grid-content {
  background-color: #409eff;
  color: white;
  padding: 10px;
  text-align: center;
  border-radius: 4px;
}
.grid-content.light {
  background-color: #79bbff;
}
.el-row {
  margin-bottom: 20px;
}
</style>
```


### 7.2 Container 布局容器

用于布局的容器组件，方便快速搭建页面的基本结构。

```vue
<template>
  <!-- 常见的后台管理系统布局 -->
  <el-container class="layout-container">
    <!-- 侧边栏 -->
    <el-aside width="200px">
      <el-menu default-active="1" class="el-menu-vertical">
        <el-menu-item index="1">
          <el-icon><House /></el-icon>
          <span>首页</span>
        </el-menu-item>
        <el-menu-item index="2">
          <el-icon><User /></el-icon>
          <span>用户管理</span>
        </el-menu-item>
        <el-menu-item index="3">
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    
    <el-container>
      <!-- 头部 -->
      <el-header>
        <div class="header-content">
          <span>后台管理系统</span>
          <el-dropdown>
            <span class="el-dropdown-link">
              管理员<el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item>个人中心</el-dropdown-item>
                <el-dropdown-item>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      
      <!-- 主内容区 -->
      <el-main>
        <el-breadcrumb separator="/">
          <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
          <el-breadcrumb-item>用户管理</el-breadcrumb-item>
        </el-breadcrumb>
        
        <div class="main-content">
          <!-- 这里放置页面主要内容 -->
          <p>主内容区域</p>
        </div>
      </el-main>
      
      <!-- 底部 -->
      <el-footer>
        <span>© 2024 Your Company. All rights reserved.</span>
      </el-footer>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { House, User, Setting, ArrowDown } from '@element-plus/icons-vue'
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.el-aside {
  background-color: #304156;
}

.el-menu-vertical {
  border-right: none;
  background-color: #304156;
}

.el-menu-vertical .el-menu-item {
  color: #bfcbd9;
}

.el-menu-vertical .el-menu-item:hover,
.el-menu-vertical .el-menu-item.is-active {
  background-color: #263445;
  color: #409eff;
}

.el-header {
  background-color: #fff;
  box-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 100%;
}

.el-main {
  background-color: #f0f2f5;
  padding: 20px;
}

.main-content {
  background-color: #fff;
  padding: 20px;
  margin-top: 20px;
  border-radius: 4px;
}

.el-footer {
  background-color: #fff;
  text-align: center;
  line-height: 60px;
  color: #999;
}

.el-dropdown-link {
  cursor: pointer;
  color: #409eff;
  display: flex;
  align-items: center;
}
</style>
```

### 7.3 Space 间距

设置组件之间的间距。

```vue
<template>
  <!-- 基础用法 -->
  <el-space>
    <el-button>按钮1</el-button>
    <el-button>按钮2</el-button>
    <el-button>按钮3</el-button>
  </el-space>
  
  <!-- 垂直布局 -->
  <el-space direction="vertical">
    <el-card>卡片1</el-card>
    <el-card>卡片2</el-card>
    <el-card>卡片3</el-card>
  </el-space>
  
  <!-- 自定义间距 -->
  <el-space :size="20">
    <el-button>按钮1</el-button>
    <el-button>按钮2</el-button>
    <el-button>按钮3</el-button>
  </el-space>
  
  <!-- 对齐方式 -->
  <el-space alignment="flex-start">
    <el-button>按钮</el-button>
    <div style="height: 100px; background: #f0f0f0; padding: 10px;">高元素</div>
  </el-space>
  
  <!-- 自动换行 -->
  <el-space wrap>
    <el-button v-for="i in 20" :key="i">按钮{{ i }}</el-button>
  </el-space>
</template>
```

### 7.4 Divider 分割线

区隔内容的分割线。

```vue
<template>
  <!-- 基础用法 -->
  <p>段落一</p>
  <el-divider />
  <p>段落二</p>
  
  <!-- 带文字的分割线 -->
  <el-divider content-position="left">左侧文字</el-divider>
  <el-divider>居中文字</el-divider>
  <el-divider content-position="right">右侧文字</el-divider>
  
  <!-- 垂直分割线 -->
  <span>文字</span>
  <el-divider direction="vertical" />
  <span>文字</span>
  <el-divider direction="vertical" />
  <span>文字</span>
  
  <!-- 虚线 -->
  <el-divider border-style="dashed" />
  <el-divider border-style="dotted" />
</template>
```

---

## 8. 进阶用法

### 8.1 组件二次封装

在实际项目中，我们经常需要对 Element Plus 组件进行二次封装，以满足业务需求和统一风格。

#### 封装搜索表单组件

```vue
<!-- components/SearchForm.vue -->
<template>
  <el-form :model="formData" :inline="true" class="search-form">
    <el-form-item
      v-for="item in formItems"
      :key="item.prop"
      :label="item.label"
    >
      <!-- 输入框 -->
      <el-input
        v-if="item.type === 'input'"
        v-model="formData[item.prop]"
        :placeholder="item.placeholder || `请输入${item.label}`"
        clearable
      />
      
      <!-- 选择器 -->
      <el-select
        v-else-if="item.type === 'select'"
        v-model="formData[item.prop]"
        :placeholder="item.placeholder || `请选择${item.label}`"
        clearable
      >
        <el-option
          v-for="opt in item.options"
          :key="opt.value"
          :label="opt.label"
          :value="opt.value"
        />
      </el-select>
      
      <!-- 日期选择器 -->
      <el-date-picker
        v-else-if="item.type === 'date'"
        v-model="formData[item.prop]"
        type="date"
        :placeholder="item.placeholder || `请选择${item.label}`"
      />
      
      <!-- 日期范围选择器 -->
      <el-date-picker
        v-else-if="item.type === 'daterange'"
        v-model="formData[item.prop]"
        type="daterange"
        range-separator="至"
        start-placeholder="开始日期"
        end-placeholder="结束日期"
      />
    </el-form-item>
    
    <el-form-item>
      <el-button type="primary" @click="handleSearch">搜索</el-button>
      <el-button @click="handleReset">重置</el-button>
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
import { reactive, watch } from 'vue'

interface FormItem {
  prop: string
  label: string
  type: 'input' | 'select' | 'date' | 'daterange'
  placeholder?: string
  options?: { label: string; value: any }[]
}

interface Props {
  formItems: FormItem[]
  modelValue?: Record<string, any>
}

const props = defineProps<Props>()
const emit = defineEmits(['update:modelValue', 'search', 'reset'])

// 初始化表单数据
const initFormData = () => {
  const data: Record<string, any> = {}
  props.formItems.forEach((item) => {
    data[item.prop] = props.modelValue?.[item.prop] ?? ''
  })
  return data
}

const formData = reactive(initFormData())

// 监听表单数据变化
watch(
  formData,
  (val) => {
    emit('update:modelValue', { ...val })
  },
  { deep: true }
)

const handleSearch = () => {
  emit('search', { ...formData })
}

const handleReset = () => {
  props.formItems.forEach((item) => {
    formData[item.prop] = ''
  })
  emit('reset')
}
</script>

<style scoped>
.search-form {
  padding: 20px;
  background-color: #fff;
  border-radius: 4px;
}
</style>
```


#### 使用封装的搜索表单

```vue
<template>
  <SearchForm
    v-model="searchParams"
    :form-items="formItems"
    @search="handleSearch"
    @reset="handleReset"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'
import SearchForm from '@/components/SearchForm.vue'

const searchParams = ref({})

const formItems = [
  { prop: 'name', label: '姓名', type: 'input' },
  {
    prop: 'status',
    label: '状态',
    type: 'select',
    options: [
      { label: '启用', value: 1 },
      { label: '禁用', value: 0 },
    ],
  },
  { prop: 'createTime', label: '创建时间', type: 'daterange' },
]

const handleSearch = (params: any) => {
  console.log('搜索参数', params)
  // 调用 API 获取数据
}

const handleReset = () => {
  console.log('重置搜索')
}
</script>
```

#### 封装表格组件

```vue
<!-- components/ProTable.vue -->
<template>
  <div class="pro-table">
    <el-table
      v-loading="loading"
      :data="data"
      :border="border"
      :stripe="stripe"
      @selection-change="handleSelectionChange"
    >
      <!-- 多选列 -->
      <el-table-column v-if="selection" type="selection" width="55" />
      
      <!-- 序号列 -->
      <el-table-column v-if="index" type="index" label="序号" width="60" />
      
      <!-- 动态列 -->
      <el-table-column
        v-for="col in columns"
        :key="col.prop"
        :prop="col.prop"
        :label="col.label"
        :width="col.width"
        :min-width="col.minWidth"
        :sortable="col.sortable"
        :show-overflow-tooltip="col.showOverflowTooltip ?? true"
      >
        <template #default="scope">
          <!-- 自定义插槽 -->
          <slot
            v-if="col.slot"
            :name="col.slot"
            :row="scope.row"
            :index="scope.$index"
          />
          <!-- 默认显示 -->
          <span v-else>{{ scope.row[col.prop] }}</span>
        </template>
      </el-table-column>
      
      <!-- 操作列 -->
      <el-table-column v-if="$slots.operation" label="操作" :width="operationWidth" fixed="right">
        <template #default="scope">
          <slot name="operation" :row="scope.row" :index="scope.$index" />
        </template>
      </el-table-column>
    </el-table>
    
    <!-- 分页 -->
    <el-pagination
      v-if="pagination"
      v-model:current-page="currentPage"
      v-model:page-size="pageSize"
      :page-sizes="pageSizes"
      :total="total"
      layout="total, sizes, prev, pager, next, jumper"
      class="pagination"
      @size-change="handleSizeChange"
      @current-change="handleCurrentChange"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'

interface Column {
  prop: string
  label: string
  width?: number | string
  minWidth?: number | string
  sortable?: boolean
  showOverflowTooltip?: boolean
  slot?: string
}

interface Props {
  data: any[]
  columns: Column[]
  loading?: boolean
  border?: boolean
  stripe?: boolean
  selection?: boolean
  index?: boolean
  pagination?: boolean
  total?: number
  pageSizes?: number[]
  operationWidth?: number | string
}

const props = withDefaults(defineProps<Props>(), {
  loading: false,
  border: true,
  stripe: true,
  selection: false,
  index: false,
  pagination: true,
  total: 0,
  pageSizes: () => [10, 20, 50, 100],
  operationWidth: 150,
})

const emit = defineEmits(['selection-change', 'page-change'])

const currentPage = ref(1)
const pageSize = ref(10)

const handleSelectionChange = (selection: any[]) => {
  emit('selection-change', selection)
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  currentPage.value = 1
  emit('page-change', { page: 1, size: val })
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  emit('page-change', { page: val, size: pageSize.value })
}
</script>

<style scoped>
.pro-table {
  background-color: #fff;
  padding: 20px;
  border-radius: 4px;
}

.pagination {
  margin-top: 20px;
  justify-content: flex-end;
}
</style>
```

### 8.2 表单联动

表单项之间的联动是常见需求，比如省市区三级联动。

```vue
<template>
  <el-form :model="form" label-width="100px">
    <el-form-item label="省份">
      <el-select v-model="form.province" placeholder="请选择省份" @change="handleProvinceChange">
        <el-option
          v-for="item in provinces"
          :key="item.code"
          :label="item.name"
          :value="item.code"
        />
      </el-select>
    </el-form-item>
    
    <el-form-item label="城市">
      <el-select v-model="form.city" placeholder="请选择城市" @change="handleCityChange">
        <el-option
          v-for="item in cities"
          :key="item.code"
          :label="item.name"
          :value="item.code"
        />
      </el-select>
    </el-form-item>
    
    <el-form-item label="区县">
      <el-select v-model="form.district" placeholder="请选择区县">
        <el-option
          v-for="item in districts"
          :key="item.code"
          :label="item.name"
          :value="item.code"
        />
      </el-select>
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
import { ref, reactive } from 'vue'

const form = reactive({
  province: '',
  city: '',
  district: '',
})

// 模拟数据
const provinces = ref([
  { code: '11', name: '北京市' },
  { code: '31', name: '上海市' },
  { code: '44', name: '广东省' },
])

const cities = ref<{ code: string; name: string }[]>([])
const districts = ref<{ code: string; name: string }[]>([])

// 模拟城市数据
const cityData: Record<string, { code: string; name: string }[]> = {
  '11': [{ code: '1101', name: '北京市' }],
  '31': [{ code: '3101', name: '上海市' }],
  '44': [
    { code: '4401', name: '广州市' },
    { code: '4403', name: '深圳市' },
  ],
}

// 模拟区县数据
const districtData: Record<string, { code: string; name: string }[]> = {
  '1101': [
    { code: '110101', name: '东城区' },
    { code: '110102', name: '西城区' },
  ],
  '4401': [
    { code: '440103', name: '荔湾区' },
    { code: '440104', name: '越秀区' },
  ],
  '4403': [
    { code: '440303', name: '罗湖区' },
    { code: '440304', name: '福田区' },
  ],
}

const handleProvinceChange = (value: string) => {
  // 清空下级选择
  form.city = ''
  form.district = ''
  districts.value = []
  
  // 加载城市数据
  cities.value = cityData[value] || []
}

const handleCityChange = (value: string) => {
  // 清空下级选择
  form.district = ''
  
  // 加载区县数据
  districts.value = districtData[value] || []
}
</script>
```


### 8.3 虚拟列表

当数据量很大时，使用虚拟列表可以提高性能。Element Plus 提供了虚拟化表格和虚拟化选择器。

```vue
<template>
  <!-- 虚拟化选择器 -->
  <el-select-v2
    v-model="value"
    :options="options"
    placeholder="请选择"
    style="width: 240px"
  />
  
  <!-- 虚拟化表格 -->
  <el-table-v2
    :columns="columns"
    :data="tableData"
    :width="700"
    :height="400"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'

// 虚拟化选择器数据
const value = ref('')
const options = Array.from({ length: 10000 }, (_, i) => ({
  value: `option_${i}`,
  label: `选项 ${i}`,
}))

// 虚拟化表格数据
const columns = [
  { key: 'id', dataKey: 'id', title: 'ID', width: 100 },
  { key: 'name', dataKey: 'name', title: '姓名', width: 150 },
  { key: 'email', dataKey: 'email', title: '邮箱', width: 250 },
  { key: 'address', dataKey: 'address', title: '地址', width: 200 },
]

const tableData = Array.from({ length: 10000 }, (_, i) => ({
  id: i + 1,
  name: `用户${i + 1}`,
  email: `user${i + 1}@example.com`,
  address: `地址${i + 1}`,
}))
</script>
```

### 8.4 自定义指令配合 Element Plus

创建自定义指令来增强 Element Plus 组件的功能。

```typescript
// directives/permission.ts
// 权限指令：根据权限控制元素显示
import type { Directive } from 'vue'

const permission: Directive = {
  mounted(el, binding) {
    const { value } = binding
    // 假设从 store 获取用户权限
    const permissions = ['user:add', 'user:edit', 'user:delete']
    
    if (value && !permissions.includes(value)) {
      el.parentNode?.removeChild(el)
    }
  },
}

export default permission
```

```typescript
// directives/loading.ts
// 按钮加载指令
import type { Directive } from 'vue'

const loading: Directive = {
  mounted(el, binding) {
    if (binding.value) {
      el.classList.add('is-loading')
      el.disabled = true
    }
  },
  updated(el, binding) {
    if (binding.value !== binding.oldValue) {
      if (binding.value) {
        el.classList.add('is-loading')
        el.disabled = true
      } else {
        el.classList.remove('is-loading')
        el.disabled = false
      }
    }
  },
}

export default loading
```

```typescript
// main.ts
import { createApp } from 'vue'
import App from './App.vue'
import permission from './directives/permission'
import loading from './directives/loading'

const app = createApp(App)
app.directive('permission', permission)
app.directive('loading', loading)
app.mount('#app')
```

```vue
<!-- 使用自定义指令 -->
<template>
  <!-- 权限控制 -->
  <el-button v-permission="'user:add'" type="primary">添加用户</el-button>
  <el-button v-permission="'user:edit'">编辑</el-button>
  <el-button v-permission="'user:delete'" type="danger">删除</el-button>
  
  <!-- 按钮加载 -->
  <el-button v-loading="isLoading" type="primary" @click="handleClick">
    提交
  </el-button>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const isLoading = ref(false)

const handleClick = () => {
  isLoading.value = true
  setTimeout(() => {
    isLoading.value = false
  }, 2000)
}
</script>
```

---

## 9. 主题定制

Element Plus 支持多种方式自定义主题。

### 9.1 使用 CSS 变量

最简单的方式是通过 CSS 变量覆盖默认样式。

```css
/* styles/element-variables.css */
:root {
  /* 主色 */
  --el-color-primary: #409eff;
  --el-color-primary-light-3: #79bbff;
  --el-color-primary-light-5: #a0cfff;
  --el-color-primary-light-7: #c6e2ff;
  --el-color-primary-light-8: #d9ecff;
  --el-color-primary-light-9: #ecf5ff;
  --el-color-primary-dark-2: #337ecc;
  
  /* 成功色 */
  --el-color-success: #67c23a;
  
  /* 警告色 */
  --el-color-warning: #e6a23c;
  
  /* 危险色 */
  --el-color-danger: #f56c6c;
  
  /* 信息色 */
  --el-color-info: #909399;
  
  /* 字体大小 */
  --el-font-size-base: 14px;
  
  /* 边框圆角 */
  --el-border-radius-base: 4px;
}
```

```typescript
// main.ts
import 'element-plus/dist/index.css'
import './styles/element-variables.css' // 引入自定义变量
```

### 9.2 使用 SCSS 变量

如果项目使用 SCSS，可以通过覆盖 SCSS 变量来自定义主题。

```scss
/* styles/element-variables.scss */
@forward 'element-plus/theme-chalk/src/common/var.scss' with (
  $colors: (
    'primary': (
      'base': #409eff,
    ),
    'success': (
      'base': #67c23a,
    ),
    'warning': (
      'base': #e6a23c,
    ),
    'danger': (
      'base': #f56c6c,
    ),
    'info': (
      'base': #909399,
    ),
  ),
  $font-size: (
    'base': 14px,
  ),
  $border-radius: (
    'base': 4px,
  )
);

@use 'element-plus/theme-chalk/src/index.scss' as *;
```

```typescript
// vite.config.ts
import { defineConfig } from 'vite'

export default defineConfig({
  css: {
    preprocessorOptions: {
      scss: {
        additionalData: `@use "@/styles/element-variables.scss" as *;`,
      },
    },
  },
})
```


### 9.3 暗黑模式

Element Plus 内置了暗黑模式支持。

```vue
<template>
  <el-switch
    v-model="isDark"
    inline-prompt
    active-text="暗黑"
    inactive-text="明亮"
    @change="toggleDark"
  />
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useDark, useToggle } from '@vueuse/core'

const isDark = useDark()
const toggleDark = useToggle(isDark)
</script>
```

或者手动切换：

```typescript
// 切换暗黑模式
const toggleDarkMode = (isDark: boolean) => {
  if (isDark) {
    document.documentElement.classList.add('dark')
  } else {
    document.documentElement.classList.remove('dark')
  }
}
```

```css
/* 引入暗黑模式样式 */
@import 'element-plus/theme-chalk/dark/css-vars.css';
```

---

## 10. 国际化

Element Plus 支持多语言，可以轻松实现国际化。

### 10.1 全局配置

```vue
<!-- App.vue -->
<template>
  <el-config-provider :locale="locale">
    <router-view />
  </el-config-provider>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import zhCn from 'element-plus/dist/locale/zh-cn.mjs'
import en from 'element-plus/dist/locale/en.mjs'

const language = ref('zh-cn')

const locale = computed(() => {
  return language.value === 'zh-cn' ? zhCn : en
})

// 切换语言
const changeLanguage = (lang: string) => {
  language.value = lang
}
</script>
```

### 10.2 配合 vue-i18n

```typescript
// i18n/index.ts
import { createI18n } from 'vue-i18n'
import zhCn from './locales/zh-cn'
import en from './locales/en'

const i18n = createI18n({
  legacy: false,
  locale: 'zh-cn',
  fallbackLocale: 'en',
  messages: {
    'zh-cn': zhCn,
    en: en,
  },
})

export default i18n
```

```typescript
// i18n/locales/zh-cn.ts
export default {
  common: {
    confirm: '确定',
    cancel: '取消',
    save: '保存',
    delete: '删除',
    edit: '编辑',
    search: '搜索',
    reset: '重置',
  },
  user: {
    username: '用户名',
    password: '密码',
    email: '邮箱',
  },
}
```

```typescript
// i18n/locales/en.ts
export default {
  common: {
    confirm: 'Confirm',
    cancel: 'Cancel',
    save: 'Save',
    delete: 'Delete',
    edit: 'Edit',
    search: 'Search',
    reset: 'Reset',
  },
  user: {
    username: 'Username',
    password: 'Password',
    email: 'Email',
  },
}
```

```vue
<!-- 使用 -->
<template>
  <el-button>{{ $t('common.confirm') }}</el-button>
  <el-button>{{ $t('common.cancel') }}</el-button>
</template>
```

---

## 11. 常见错误与解决方案

### 11.1 样式丢失问题

**问题描述：** 组件显示但没有样式

**原因：** 没有正确引入 Element Plus 的样式文件

**解决方案：**

```typescript
// 完整引入时
import 'element-plus/dist/index.css'

// 按需引入时，确保配置了自动导入插件
// 或手动引入组件样式
import 'element-plus/es/components/button/style/css'
```

### 11.2 图标不显示

**问题描述：** 使用图标组件但不显示

**原因：** 没有安装或正确引入图标库

**解决方案：**

```bash
# 安装图标库
npm install @element-plus/icons-vue
```

```typescript
// 方式一：按需引入
import { Edit, Delete } from '@element-plus/icons-vue'

// 方式二：全局注册
import * as ElementPlusIconsVue from '@element-plus/icons-vue'

const app = createApp(App)
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}
```

### 11.3 表单验证不生效

**问题描述：** 配置了验证规则但不触发验证

**原因：** 
1. `prop` 属性与 `model` 中的字段名不匹配
2. 没有正确绑定 `rules`
3. 验证触发时机不对

**解决方案：**

```vue
<template>
  <!-- 确保 prop 与 form 中的字段名一致 -->
  <el-form :model="form" :rules="rules" ref="formRef">
    <!-- ❌ 错误：prop 与 form 字段名不匹配 -->
    <el-form-item label="用户名" prop="userName">
      <el-input v-model="form.username" />
    </el-form-item>
    
    <!-- ✅ 正确：prop 与 form 字段名一致 -->
    <el-form-item label="用户名" prop="username">
      <el-input v-model="form.username" />
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
const form = reactive({
  username: '', // 字段名
})

const rules = {
  username: [ // 规则的 key 要与 prop 一致
    { required: true, message: '请输入用户名', trigger: 'blur' }
  ]
}
</script>
```


### 11.4 v-model 双向绑定失效

**问题描述：** 表单组件的值无法双向绑定

**原因：** 
1. 使用了错误的 v-model 语法
2. 响应式数据定义不正确

**解决方案：**

```vue
<script setup lang="ts">
import { ref, reactive } from 'vue'

// ❌ 错误：普通变量不是响应式的
let value = ''

// ✅ 正确：使用 ref
const value = ref('')

// ✅ 正确：使用 reactive
const form = reactive({
  name: '',
  age: 0,
})
</script>

<template>
  <!-- ✅ 正确使用 v-model -->
  <el-input v-model="value" />
  <el-input v-model="form.name" />
</template>
```

### 11.5 Dialog 对话框无法关闭

**问题描述：** 点击关闭按钮或遮罩层，对话框不关闭

**原因：** 没有正确处理 `v-model` 或 `before-close`

**解决方案：**

```vue
<template>
  <!-- ✅ 正确：使用 v-model 控制显示 -->
  <el-dialog v-model="dialogVisible" title="标题">
    内容
  </el-dialog>
  
  <!-- 如果使用 before-close，需要手动调用 done -->
  <el-dialog
    v-model="dialogVisible"
    title="标题"
    :before-close="handleClose"
  >
    内容
  </el-dialog>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const dialogVisible = ref(false)

const handleClose = (done: () => void) => {
  // 执行一些操作后调用 done 关闭对话框
  done()
}
</script>
```

### 11.6 Table 表格数据更新不刷新

**问题描述：** 修改数组数据后，表格不更新

**原因：** Vue 3 的响应式系统对数组的某些操作可能不会触发更新

**解决方案：**

```vue
<script setup lang="ts">
import { ref } from 'vue'

const tableData = ref([
  { id: 1, name: '张三' },
  { id: 2, name: '李四' },
])

// ❌ 错误：直接修改数组元素的属性可能不触发更新
tableData.value[0].name = '王五'

// ✅ 正确：使用 splice 替换元素
tableData.value.splice(0, 1, { id: 1, name: '王五' })

// ✅ 正确：重新赋值整个数组
tableData.value = tableData.value.map(item => {
  if (item.id === 1) {
    return { ...item, name: '王五' }
  }
  return item
})

// ✅ 正确：使用 reactive 定义数组
const tableData2 = reactive([
  { id: 1, name: '张三' },
])
// 直接修改即可触发更新
tableData2[0].name = '王五'
</script>
```

### 11.7 Select 选择器选中值显示 value 而不是 label

**问题描述：** 选择后显示的是 value 值而不是 label 文本

**原因：** `v-model` 绑定的值与 `option` 的 `value` 类型不匹配

**解决方案：**

```vue
<template>
  <el-select v-model="selected">
    <!-- 注意：value 是数字类型 -->
    <el-option
      v-for="item in options"
      :key="item.value"
      :label="item.label"
      :value="item.value"
    />
  </el-select>
</template>

<script setup lang="ts">
import { ref } from 'vue'

// ❌ 错误：selected 是字符串，但 option 的 value 是数字
const selected = ref('1')

// ✅ 正确：类型要匹配
const selected = ref(1)

const options = [
  { value: 1, label: '选项一' },
  { value: 2, label: '选项二' },
]
</script>
```

### 11.8 DatePicker 日期格式问题

**问题描述：** 日期选择器返回的格式不是想要的

**原因：** 没有配置 `value-format`

**解决方案：**

```vue
<template>
  <!-- 默认返回 Date 对象 -->
  <el-date-picker v-model="date1" type="date" />
  
  <!-- 返回格式化的字符串 -->
  <el-date-picker
    v-model="date2"
    type="date"
    value-format="YYYY-MM-DD"
  />
  
  <!-- 返回时间戳 -->
  <el-date-picker
    v-model="date3"
    type="date"
    value-format="x"
  />
</template>

<script setup lang="ts">
import { ref } from 'vue'

const date1 = ref<Date | null>(null) // Date 对象
const date2 = ref('') // 字符串 '2024-01-01'
const date3 = ref<number | null>(null) // 时间戳
</script>
```

### 11.9 Upload 上传组件问题

**问题描述：** 文件上传失败或无法获取上传结果

**常见原因和解决方案：**

```vue
<template>
  <el-upload
    :action="uploadUrl"
    :headers="headers"
    :data="extraData"
    :on-success="handleSuccess"
    :on-error="handleError"
    :before-upload="beforeUpload"
  >
    <el-button type="primary">上传文件</el-button>
  </el-upload>
</template>

<script setup lang="ts">
import { ElMessage } from 'element-plus'
import type { UploadProps, UploadRawFile } from 'element-plus'

// 上传地址
const uploadUrl = '/api/upload'

// 请求头（如需要 token）
const headers = {
  Authorization: 'Bearer your-token',
}

// 额外参数
const extraData = {
  type: 'image',
}

// 上传前验证
const beforeUpload: UploadProps['beforeUpload'] = (rawFile: UploadRawFile) => {
  // 验证文件类型
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif']
  if (!allowedTypes.includes(rawFile.type)) {
    ElMessage.error('只能上传 JPG/PNG/GIF 格式的图片')
    return false
  }
  
  // 验证文件大小（2MB）
  if (rawFile.size / 1024 / 1024 > 2) {
    ElMessage.error('图片大小不能超过 2MB')
    return false
  }
  
  return true
}

// 上传成功
const handleSuccess: UploadProps['onSuccess'] = (response, uploadFile) => {
  console.log('上传成功', response)
  ElMessage.success('上传成功')
}

// 上传失败
const handleError: UploadProps['onError'] = (error, uploadFile) => {
  console.error('上传失败', error)
  ElMessage.error('上传失败')
}
</script>
```

### 11
.10 组件 ref 获取不到实例

**问题描述：** 使用 ref 获取组件实例时为 undefined

**原因：** 
1. 组件还未挂载就访问 ref
2. ref 名称与模板中不匹配
3. 类型定义不正确

**解决方案：**

```vue
<template>
  <el-form ref="formRef" :model="form">
    <!-- ... -->
  </el-form>
  <el-table ref="tableRef" :data="tableData">
    <!-- ... -->
  </el-table>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { FormInstance, TableInstance } from 'element-plus'

// ✅ 正确：使用正确的类型
const formRef = ref<FormInstance>()
const tableRef = ref<TableInstance>()

// ❌ 错误：在 setup 中直接访问（组件还未挂载）
console.log(formRef.value) // undefined

// ✅ 正确：在 onMounted 或事件处理函数中访问
onMounted(() => {
  console.log(formRef.value) // FormInstance
})

const submitForm = async () => {
  // 使用可选链，避免 undefined 错误
  await formRef.value?.validate()
}
</script>
```

### 11.11 ElMessage/ElMessageBox 在 setup 外使用报错

**问题描述：** 在 Pinia store 或工具函数中使用 ElMessage 报错

**原因：** 这些方法依赖 Vue 应用上下文

**解决方案：**

```typescript
// ✅ 正确：直接从 element-plus 导入使用
import { ElMessage, ElMessageBox } from 'element-plus'

// 在任何地方都可以使用
export const showMessage = (message: string) => {
  ElMessage.success(message)
}

export const confirmDelete = async () => {
  try {
    await ElMessageBox.confirm('确定删除吗？', '提示', {
      type: 'warning',
    })
    return true
  } catch {
    return false
  }
}
```

### 11.12 TypeScript 类型错误

**问题描述：** 使用 TypeScript 时出现类型错误

**解决方案：**

```typescript
// 导入 Element Plus 提供的类型
import type {
  FormInstance,
  FormRules,
  TableInstance,
  UploadProps,
  UploadFile,
  UploadRawFile,
  TabsPaneContext,
} from 'element-plus'

// 表单实例
const formRef = ref<FormInstance>()

// 表单规则
const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
}

// 表格实例
const tableRef = ref<TableInstance>()

// 上传相关
const beforeUpload: UploadProps['beforeUpload'] = (file: UploadRawFile) => {
  return true
}

const onSuccess: UploadProps['onSuccess'] = (response, file: UploadFile) => {
  console.log(response)
}
```

---

## 12. 最佳实践

### 12.1 项目结构建议

```
src/
├── components/           # 公共组件
│   ├── ProTable/        # 封装的表格组件
│   ├── SearchForm/      # 封装的搜索表单
│   └── ...
├── composables/         # 组合式函数
│   ├── useTable.ts      # 表格相关逻辑
│   ├── useForm.ts       # 表单相关逻辑
│   └── ...
├── directives/          # 自定义指令
│   ├── permission.ts
│   └── ...
├── styles/              # 样式文件
│   ├── element-variables.scss  # Element Plus 变量覆盖
│   └── ...
├── utils/               # 工具函数
│   ├── validate.ts      # 表单验证规则
│   └── ...
└── ...
```

### 12.2 表单验证规则复用

```typescript
// utils/validate.ts
import type { FormItemRule } from 'element-plus'

// 必填验证
export const required = (message: string): FormItemRule => ({
  required: true,
  message,
  trigger: 'blur',
})

// 邮箱验证
export const email: FormItemRule = {
  type: 'email',
  message: '请输入正确的邮箱格式',
  trigger: 'blur',
}

// 手机号验证
export const phone: FormItemRule = {
  pattern: /^1[3-9]\d{9}$/,
  message: '请输入正确的手机号',
  trigger: 'blur',
}

// 长度验证
export const length = (min: number, max: number): FormItemRule => ({
  min,
  max,
  message: `长度在 ${min} 到 ${max} 个字符`,
  trigger: 'blur',
})

// 数字范围验证
export const numberRange = (min: number, max: number): FormItemRule => ({
  type: 'number',
  min,
  max,
  message: `数值必须在 ${min} 到 ${max} 之间`,
  trigger: 'blur',
})

// URL 验证
export const url: FormItemRule = {
  type: 'url',
  message: '请输入正确的 URL',
  trigger: 'blur',
}
```

```vue
<!-- 使用 -->
<script setup lang="ts">
import { required, email, phone, length } from '@/utils/validate'
import type { FormRules } from 'element-plus'

const rules: FormRules = {
  username: [required('请输入用户名'), length(3, 20)],
  email: [required('请输入邮箱'), email],
  phone: [required('请输入手机号'), phone],
}
</script>
```

### 12.3 组合式函数封装

```typescript
// composables/useTable.ts
import { ref, reactive } from 'vue'
import type { Ref } from 'vue'

interface UseTableOptions<T> {
  api: (params: any) => Promise<{ data: T[]; total: number }>
  immediate?: boolean
}

export function useTable<T = any>(options: UseTableOptions<T>) {
  const { api, immediate = true } = options
  
  const loading = ref(false)
  const tableData: Ref<T[]> = ref([])
  const total = ref(0)
  
  const pagination = reactive({
    currentPage: 1,
    pageSize: 10,
  })
  
  const searchParams = reactive<Record<string, any>>({})
  
  const fetchData = async () => {
    loading.value = true
    try {
      const params = {
        page: pagination.currentPage,
        size: pagination.pageSize,
        ...searchParams,
      }
      const res = await api(params)
      tableData.value = res.data
      total.value = res.total
    } catch (error) {
      console.error('获取数据失败', error)
    } finally {
      loading.value = false
    }
  }
  
  const handleSearch = (params: Record<string, any>) => {
    Object.assign(searchParams, params)
    pagination.currentPage = 1
    fetchData()
  }
  
  const handleReset = () => {
    Object.keys(searchParams).forEach((key) => {
      searchParams[key] = ''
    })
    pagination.currentPage = 1
    fetchData()
  }
  
  const handlePageChange = ({ page, size }: { page: number; size: number }) => {
    pagination.currentPage = page
    pagination.pageSize = size
    fetchData()
  }
  
  // 立即加载数据
  if (immediate) {
    fetchData()
  }
  
  return {
    loading,
    tableData,
    total,
    pagination,
    searchParams,
    fetchData,
    handleSearch,
    handleReset,
    handlePageChange,
  }
}
```

```vue

<!-- 使用 useTable -->
<template>
  <SearchForm :form-items="formItems" @search="handleSearch" @reset="handleReset" />
  
  <ProTable
    :data="tableData"
    :columns="columns"
    :loading="loading"
    :total="total"
    @page-change="handlePageChange"
  >
    <template #operation="{ row }">
      <el-button size="small" @click="handleEdit(row)">编辑</el-button>
      <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
    </template>
  </ProTable>
</template>

<script setup lang="ts">
import { useTable } from '@/composables/useTable'
import { getUserList } from '@/api/user'

const {
  loading,
  tableData,
  total,
  handleSearch,
  handleReset,
  handlePageChange,
} = useTable({
  api: getUserList,
})

const formItems = [
  { prop: 'name', label: '姓名', type: 'input' },
  { prop: 'status', label: '状态', type: 'select', options: [
    { label: '启用', value: 1 },
    { label: '禁用', value: 0 },
  ]},
]

const columns = [
  { prop: 'name', label: '姓名' },
  { prop: 'email', label: '邮箱' },
  { prop: 'status', label: '状态', slot: 'status' },
]

const handleEdit = (row: any) => {
  console.log('编辑', row)
}

const handleDelete = (row: any) => {
  console.log('删除', row)
}
</script>
```

### 12.4 性能优化建议

1. **按需引入组件**：使用自动导入插件，只打包使用到的组件

2. **虚拟列表**：数据量大时使用 `el-select-v2` 和 `el-table-v2`

3. **懒加载**：对于大型表单或复杂组件，使用动态导入

```typescript
// 动态导入组件
const HeavyComponent = defineAsyncComponent(() => 
  import('./HeavyComponent.vue')
)
```

4. **合理使用 v-if 和 v-show**：
   - 频繁切换用 `v-show`
   - 条件很少改变用 `v-if`

5. **表格优化**：
   - 固定列数量不要太多
   - 大数据量使用虚拟滚动
   - 避免在表格列中使用复杂计算

### 12.5 代码规范建议

```vue
<template>
  <!-- 1. 组件属性换行，保持整洁 -->
  <el-form
    ref="formRef"
    :model="form"
    :rules="rules"
    label-width="100px"
    @submit.prevent="handleSubmit"
  >
    <!-- 2. 使用语义化的 prop 名称 -->
    <el-form-item label="用户名" prop="username">
      <el-input
        v-model="form.username"
        placeholder="请输入用户名"
        clearable
      />
    </el-form-item>
  </el-form>
</template>

<script setup lang="ts">
// 3. 导入顺序：Vue -> 第三方库 -> 本地模块
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { useUserStore } from '@/stores/user'
import { required, email } from '@/utils/validate'

// 4. 类型定义
interface FormData {
  username: string
  email: string
}

// 5. 响应式数据
const formRef = ref<FormInstance>()
const form = reactive<FormData>({
  username: '',
  email: '',
})

// 6. 验证规则
const rules: FormRules = {
  username: [required('请输入用户名')],
  email: [required('请输入邮箱'), email],
}

// 7. 方法定义
const handleSubmit = async () => {
  if (!formRef.value) return
  
  try {
    await formRef.value.validate()
    // 提交逻辑
    ElMessage.success('提交成功')
  } catch (error) {
    console.error('验证失败', error)
  }
}

// 8. 生命周期
onMounted(() => {
  // 初始化逻辑
})
</script>

<style scoped>
/* 9. 使用 scoped 避免样式污染 */
/* 10. 使用 CSS 变量保持一致性 */
.form-container {
  padding: var(--el-spacing-large);
}
</style>
```

---

## 总结

Element Plus 是一个功能强大、文档完善的 Vue 3 组件库。通过本笔记的学习，你应该能够：

1. **掌握基础**：了解如何安装、引入和使用 Element Plus 的各种组件
2. **表单开发**：熟练使用表单组件和表单验证
3. **数据展示**：使用表格、分页等组件展示数据
4. **交互反馈**：使用对话框、消息提示等组件与用户交互
5. **布局设计**：使用布局组件构建页面结构
6. **进阶应用**：组件二次封装、主题定制、国际化等
7. **问题排查**：了解常见错误及其解决方案
8. **最佳实践**：遵循代码规范，提高开发效率

建议在实际项目中多加练习，遇到问题时查阅官方文档：https://element-plus.org/zh-CN/