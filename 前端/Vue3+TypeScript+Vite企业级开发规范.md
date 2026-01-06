# Vue3 + TypeScript + Vite 企业级开发规范

> 基于 Vue 3.4+ / TypeScript 5.x / Vite 5.x 的企业级前端开发最佳实践
> 本笔记涵盖项目结构、代码风格、命名规范、组件设计、状态管理、性能优化及企业级开发踩坑经验

---

## 目录

1. [项目初始化与结构](#1-项目初始化与结构)
2. [命名规范](#2-命名规范)
3. [TypeScript 规范](#3-typescript-规范)
4. [Vue 组件规范](#4-vue-组件规范)
5. [Composition API 最佳实践](#5-composition-api-最佳实践)
6. [状态管理 Pinia](#6-状态管理-pinia)
7. [路由管理](#7-路由管理)
8. [API 请求封装](#8-api-请求封装)
9. [样式规范](#9-样式规范)
10. [工程化配置](#10-工程化配置)
11. [性能优化](#11-性能优化)
12. [安全规范](#12-安全规范)
13. [测试规范](#13-测试规范)
14. [Git 规范](#14-git-规范)
15. [企业级开发踩坑与常见错误](#15-企业级开发踩坑与常见错误)

---

## 1. 项目初始化与结构

### 1.1 项目初始化

使用 Vite 创建项目是目前最推荐的方式，它提供了极快的开发服务器启动和热更新。

```bash
# 使用 pnpm（推荐，更快更省空间）
pnpm create vite my-project --template vue-ts

# 或使用 npm
npm create vite@latest my-project -- --template vue-ts

# 或使用 yarn
yarn create vite my-project --template vue-ts

# 进入项目并安装依赖
cd my-project
pnpm install

# 启动开发服务器
pnpm dev
```

**为什么推荐 pnpm？**
- 磁盘空间利用率高（硬链接共享依赖）
- 安装速度快
- 严格的依赖管理，避免幽灵依赖
- 原生支持 monorepo

### 1.2 推荐的项目结构

一个清晰的项目结构是团队协作的基础。以下是企业级项目推荐的目录结构：

```
my-project/
├── .husky/                    # Git hooks 配置
│   ├── pre-commit             # 提交前检查（lint-staged）
│   └── commit-msg             # 提交信息检查（commitlint）
│
├── .vscode/                   # VSCode 配置（团队共享）
│   ├── extensions.json        # 推荐插件
│   ├── settings.json          # 编辑器设置
│   └── launch.json            # 调试配置
│
├── public/                    # 静态资源（不经过构建处理）
│   └── favicon.ico
│
├── src/
│   ├── api/                   # API 接口层
│   │   ├── modules/           # 按模块划分的接口
│   │   │   ├── user/          # 用户域（不再是单个 user.ts）
│   │   │   │   ├── profile.ts # 个人资料
│   │   │   │   ├── auth.ts    # 登录/注册
│   │   │   │   └── index.ts
│   │   │   ├── order/
│   │   │   │   ├── list.ts    # 订单列表
│   │   │   │   ├── detail.ts  # 订单详情
│   │   │   │   ├── refund.ts  # 退款相关
│   │   │   │   └── index.ts
│   │   │   └── common/        # 公共接口（如字典、地区、配置）  
│   │   ├── axios.ts           # Axios 封装
│   │   └── index.ts           # 统一导出
│   │
│   ├── assets/                # 静态资源（经过构建处理）
│   │   ├── images/            # 图片
│   │   ├── fonts/             # 字体
│   │   ├── icons/             # 图标（SVG）
│   │   └── styles/            # 样式文件
│   │       ├── variables.scss # SCSS 变量
│   │       ├── mixins.scss    # SCSS 混入
│   │       ├── reset.scss     # 样式重置
│   │       └── global.scss    # 全局样式
│   │
│   ├── components/            # 公共组件
│   │   ├── ui/                # 更现代的命名
│   │   │   ├── button/
│   │   │   │   ├── BaseButton.vue
│   │   │   │   └── index.ts   # 单组件导出（便于 tree-shaking）
│   │   │   ├── input/
│   │   │   │   ├── BaseInput.vue
│   │   │   │   └── index.ts   # 单组件导出（便于 tree-shaking）
│   │   │   └── index.ts       # 聚合导出所有 UI 组件
│   │   │── layout/            # 布局组件
│   │   │   ├── TheHeader.vue  #导航栏
│   │   │   ├── TheFooter.vue  #页脚
│   │   │   └── index.ts       # 统一导出
│   │   │── shared/            # "Shared" 表示跨页面复用的业务组件
│   │   │   ├── user-card/     # 组件文件夹化(利于扩展)
│   │   │   │   ├── UserCard.vue
│   │   │   │   ├── types.ts   # 组件专属类型
│   │   │   │   └── index.ts
│   │   │   ├── order-summary/
│   │   │   │   ├── OrderSummary.vue
│   │   │   │   └── index.ts
│   │   │   └── index.ts 
│   │   └── index.ts           # 顶层统一导出（可选）
│   │
│   ├── composables/           # 可复用的逻辑
│   │   ├── useLocalStorage.ts # 本地存储封装
│   │   ├── useModal.ts        # 弹窗控制逻辑
│   │   ├── useUser.ts         # 用户相关逻辑（登录状态、权限等）
│   │   └── index.ts
│   │
│   ├── constants/             # 常量定义
│   │   ├── api.ts             # API 相关常量
│   │   ├── storage.ts         # 存储 key 常量
│   │   ├── enum.ts            # 枚举常量
│   │   └── index.ts
│   │
│   ├── directives/            # 自定义指令
│   │   ├── permission.ts      # 权限指令
│   │   ├── loading.ts         # 加载指令
│   │   └── index.ts
│   │
│   ├── layouts/               # 页面布局(路由级别复用（如所有后台页用 DefaultLayout）)
│   │   ├── DefaultLayout.vue  # 默认布局
│   │   └── TwoColLayout.vue   # 双列布局
│   │
│   ├── plugins/               # 插件配置
│   │   ├── element-plus.ts    # Element Plus 配置
│   │   └── index.ts
│   │
│   ├── router/                # 路由配置
│   │   ├── modules/           # 路由模块
│   │   │   ├── user.ts
│   │   │   └── order.ts
│   │   ├── guards.ts          # 路由守卫
│   │   └── index.ts
│   │
│   ├── stores/                # Pinia 状态管理
│   │   ├── modules/
│   │   │   ├── user.ts        # 用户状态
│   │   │   └── app.ts         # 应用状态
│   │   └── index.ts
│   │
│   ├── types/                 # TypeScript 类型定义
│   │   ├── api.d.ts           # API 相关类型
│   │   ├── components.d.ts    # 组件类型
│   │   ├── global.d.ts        # 全局类型扩展
│   │   └── index.ts
│   │
│   ├── utils/                 # 工具函数
│   │   ├── storage.ts         # 本地存储
│   │   ├── validate.ts        # 验证函数
│   │   ├── format.ts          # 格式化函数
│   │   ├── auth.ts            # 认证相关
│   │   └── index.ts
│   │
│   ├── views/                 # 页面
│   │   ├── admin/             # 管理端页面
│   │   │   ├── home/   
│   │   │   │   ├── components/       
│   │   │   │   │   ├── AdminDashboard.vue
│   │   │   │   │   └── index.ts                                
│   │   │   │   └── AdminHome.vue
│   │   │   ├── login/
│   │   │   │   ├── components/
│   │   │   │   └── AdminLogin.vue
│   │   │   └── index.ts    # 管理端页面导出
│   │   └── client/         # 客户端页面 
│   │       ├── home/   
│   │       │   ├── components/       
│   │       │   │   ├── HomeWaterfall.vue
│   │       │   │   ├── HomeSkeleton.vue
│   │       │   │   └── index.ts                                
│   │       │   └── Home.vue   
│   │       ├── login/
│   │       │   ├── components/
│   │       │   └── Login.vue
│   │       ├── error/
│   │       │   ├── 404.vue
│   │       │   └── 500.vue
│   │       └── index.ts      #客户端页面导出    
│   ├── App.vue               # 根组件
│   └── main.ts               # 入口文件
├── .env                      # 环境变量（所有环境）
├── .env.development          # 开发环境变量
├── .env.production           # 生产环境变量
├── .env.staging              # 测试环境变量
├── .eslintrc.cjs             # ESLint 配置
├── .prettierrc               # Prettier 配置
├── .stylelintrc.cjs          # Stylelint 配置
├── .gitignore                # Git 忽略文件
├── index.html                # HTML 模板
├── package.json              # 项目配置
├── pnpm-lock.yaml            # 依赖锁定
├── tsconfig.json             # TypeScript 配置
├── tsconfig.node.json        # Node 环境 TS 配置
└── vite.config.ts            # Vite 配置
```

### 1.3 核心依赖安装

```bash
# 核心依赖
pnpm add vue-router@4 pinia @vueuse/core axios dayjs

# UI 框架（选择其一）
pnpm add element-plus @element-plus/icons-vue
# 或
pnpm add ant-design-vue@4

# 开发依赖
pnpm add -D typescript @types/node
pnpm add -D sass

# 代码规范
pnpm add -D eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin
pnpm add -D eslint-plugin-vue eslint-config-prettier eslint-plugin-prettier
pnpm add -D prettier
pnpm add -D stylelint stylelint-config-standard-scss stylelint-order

# Git 规范
pnpm add -D husky lint-staged @commitlint/cli @commitlint/config-conventional

# 自动导入（强烈推荐）
pnpm add -D unplugin-auto-import unplugin-vue-components
pnpm add -D unplugin-icons @iconify/json

# SVG 图标
pnpm add -D vite-plugin-svg-icons
```

### 1.4 VSCode 配置

为了保证团队开发一致性，建议在项目中添加 VSCode 配置。

**.vscode/extensions.json** - 推荐插件：

```json
{
  "recommendations": [
    "Vue.volar",
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "stylelint.vscode-stylelint",
    "bradlc.vscode-tailwindcss",
    "antfu.iconify",
    "lokalise.i18n-ally",
    "formulahendry.auto-rename-tag",
    "streetsidesoftware.code-spell-checker"
  ]
}
```

**.vscode/settings.json** - 编辑器设置：

```json
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": "explicit",
    "source.fixAll.stylelint": "explicit"
  },
  "[vue]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[scss]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "typescript.tsdk": "node_modules/typescript/lib",
  "vue.inlayHints.missingProps": true,
  "vue.inlayHints.inlineHandlerLeading": true
}
```

---

## 2. 命名规范

命名是代码可读性的基础。好的命名能让代码自解释，减少注释需求。

### 2.1 文件命名

```
┌─────────────────────────────────────────────────────────────────────┐
│ 文件命名规范                                                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ Vue 组件文件:                                                        │
│ • 使用 PascalCase（大驼峰）                                          │
│ • 多单词命名，避免单个单词（防止与 HTML 元素冲突）                   │
│ • 例: UserProfile.vue, SearchInput.vue, TheHeader.vue               │
│                                                                      │
│ TypeScript/JavaScript 文件:                                         │
│ • 使用 camelCase（小驼峰）                                           │
│ • 例: userService.ts, useRequest.ts, formatDate.ts                  │
│                                                                      │
│ 样式文件:                                                            │
│ • 使用 kebab-case（短横线）                                          │
│ • 例: user-profile.scss, global-variables.scss                      │
│                                                                      │
│ 常量/配置文件:                                                       │
│ • 使用 camelCase 或 SCREAMING_SNAKE_CASE                            │
│ • 例: apiConfig.ts, API_CONSTANTS.ts                                │
│                                                                      │
│ 类型定义文件:                                                        │
│ • 使用 .d.ts 后缀表示声明文件                                       │
│ • 例: api.d.ts, global.d.ts, env.d.ts                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 变量命名

```typescript
// ✅ 好的命名 - 清晰表达意图

// 布尔值：使用 is/has/can/should/will 前缀
const isLoading = ref(false)
const hasPermission = ref(true)
const canEdit = computed(() => user.role === 'admin')
const shouldShowModal = ref(false)
const willRedirect = ref(false)

// 数组：使用复数形式
const users = ref<User[]>([])
const selectedIds = ref<number[]>([])
const menuItems = ref<MenuItem[]>([])

// 对象：使用名词，表达清晰
const userInfo = ref<UserInfo | null>(null)
const formData = reactive<FormData>({ name: '', email: '' })
const tableConfig = ref<TableConfig>({})
const currentUser = ref<User | null>(null)

// 函数：使用动词开头，表达行为
const fetchUserList = async () => {}      // 获取
const handleSubmit = () => {}             // 处理
const validateForm = () => {}             // 验证
const formatDate = (date: Date) => {}     // 格式化
const parseJSON = (str: string) => {}     // 解析
const toggleVisible = () => {}            // 切换
const resetForm = () => {}                // 重置

// 常量：使用 SCREAMING_SNAKE_CASE
const MAX_FILE_SIZE = 1024 * 1024 * 5     // 5MB
const API_BASE_URL = '/api/v1'
const STORAGE_TOKEN_KEY = 'access_token'
const DEFAULT_PAGE_SIZE = 20

// 枚举：使用 PascalCase
enum UserStatus {
  Active = 'active',
  Inactive = 'inactive',
  Pending = 'pending',
  Banned = 'banned'
}

enum HttpMethod {
  GET = 'GET',
  POST = 'POST',
  PUT = 'PUT',
  DELETE = 'DELETE'
}

// ❌ 不好的命名 - 含义不清

const data = ref([])           // 太泛泛，什么数据？
const flag = ref(false)        // 什么标志？
const temp = ref('')           // 临时变量不应该存在于正式代码
const arr = ref([])            // 缩写不清晰
const obj = reactive({})       // 不知道是什么对象
const fn = () => {}            // 不知道做什么
const list = ref([])           // 什么列表？
const info = ref({})           // 什么信息？
const str = ''                 // 什么字符串？
const num = 0                  // 什么数字？
```

### 2.3 组件命名

```typescript
// ✅ 组件命名规范

// 基础组件：使用 Base/App 前缀
// 这些是项目中最基础的组件，会被频繁复用
// components/base/BaseButton.vue
// components/base/BaseInput.vue
// components/base/BaseModal.vue
// components/base/AppIcon.vue

// 单例组件：使用 The 前缀
// 整个应用只有一个实例的组件
// components/layout/TheHeader.vue
// components/layout/TheSidebar.vue
// components/layout/TheFooter.vue
// components/layout/TheNavbar.vue

// 紧密耦合的组件：使用父组件名作为前缀
// 这些组件只在特定父组件中使用
// components/TodoList.vue
// components/TodoListItem.vue
// components/TodoListItemButton.vue

// 业务组件：使用业务模块名作为前缀
// components/business/UserCard.vue
// components/business/UserAvatar.vue
// components/business/OrderTable.vue
// components/business/ProductList.vue

// 页面私有组件：放在页面目录下的 components 文件夹
// views/user/components/UserFilter.vue
// views/user/components/UserTable.vue

// 组件注册和使用
import UserProfile from './UserProfile.vue'

// 模板中使用 PascalCase（推荐）或 kebab-case
<template>
  <!-- 推荐：PascalCase，与导入名一致 -->
  <UserProfile :user="user" />
  
  <!-- 也可以：kebab-case -->
  <user-profile :user="user" />
</template>
```

### 2.4 Props 和 Emits 命名

```typescript
// ✅ Props 命名规范
interface Props {
  // 使用 camelCase
  userId: number
  userName: string
  
  // 布尔值使用 is/has/can 前缀
  isDisabled: boolean
  hasError: boolean
  canEdit: boolean
  
  // 数字使用描述性名称
  maxLength: number
  minValue: number
  pageSize: number
  
  // 复杂类型
  userInfo: UserInfo
  menuItems: MenuItem[]
  
  // 回调函数使用 on 前缀
  onSuccess?: () => void
  onError?: (error: Error) => void
  onChange?: (value: string) => void
}

// ✅ Emits 命名规范
const emit = defineEmits<{
  // 使用 kebab-case 事件名
  (e: 'update:modelValue', value: string): void
  (e: 'change', value: string): void
  (e: 'item-click', item: Item): void
  (e: 'page-change', page: number): void
  
  // 状态变化使用过去式
  (e: 'loaded', data: Data): void
  (e: 'submitted', result: Result): void
  (e: 'deleted', id: number): void
  (e: 'closed'): void
}>()

// 在模板中使用
<template>
  <ChildComponent
    :user-id="userId"
    :is-disabled="isDisabled"
    :max-length="100"
    @update:model-value="handleUpdate"
    @item-click="handleItemClick"
    @page-change="handlePageChange"
  />
</template>
```

### 2.5 CSS 类名命名

推荐使用 BEM 命名规范（Block Element Modifier）：

```scss
// BEM 命名规范
// Block: 独立的组件块
// Element: 组件的组成部分，使用 __ 连接
// Modifier: 组件或元素的变体，使用 -- 连接

// ✅ 好的 BEM 命名
.user-card {                    // Block
  padding: 16px;
  
  &__header {                   // Element
    display: flex;
    align-items: center;
  }
  
  &__avatar {                   // Element
    width: 48px;
    height: 48px;
    border-radius: 50%;
  }
  
  &__name {                     // Element
    font-size: 16px;
    font-weight: 500;
  }
  
  &__actions {                  // Element
    margin-top: 12px;
  }
  
  &--large {                    // Modifier
    padding: 24px;
    
    .user-card__avatar {
      width: 64px;
      height: 64px;
    }
  }
  
  &--disabled {                 // Modifier
    opacity: 0.5;
    pointer-events: none;
  }
  
  &--highlighted {              // Modifier
    border: 2px solid var(--primary-color);
  }
}

// 使用示例
<div class="user-card user-card--large user-card--highlighted">
  <div class="user-card__header">
    <img class="user-card__avatar" :src="avatar" />
    <span class="user-card__name">{{ name }}</span>
  </div>
  <div class="user-card__actions">
    <button>编辑</button>
  </div>
</div>

// ❌ 不好的命名
.userCard { }           // 不使用驼峰
.user_card { }          // 不使用下划线
.card1 { }              // 不使用数字
.red-text { }           // 不使用表现性命名
.left-align { }         // 不使用位置性命名
.big-font { }           // 不使用大小性命名
```

---

## 3. TypeScript 规范

TypeScript 是企业级项目的标配，它能在编译时发现错误，提高代码质量和可维护性。

### 3.1 类型定义基础

```typescript
// ✅ 优先使用 interface 定义对象类型
// interface 可以被扩展和合并，更适合定义对象结构
interface User {
  id: number
  name: string
  email: string
  avatar?: string           // 可选属性
  readonly createdAt: Date  // 只读属性
}

// 接口继承
interface AdminUser extends User {
  role: 'admin'
  permissions: string[]
}

// ✅ 使用 type 定义联合类型、交叉类型、工具类型
type Status = 'pending' | 'success' | 'error' | 'warning'
type UserWithRole = User & { role: string }
type PartialUser = Partial<User>
type RequiredUser = Required<User>
type ReadonlyUser = Readonly<User>
type UserKeys = keyof User  // 'id' | 'name' | 'email' | 'avatar' | 'createdAt'

// ✅ 使用泛型提高复用性
interface ApiResponse<T> {
  code: number
  message: string
  data: T
  timestamp: number
}

// 使用示例
type UserResponse = ApiResponse<User>
type UserListResponse = ApiResponse<User[]>
type PageResponse<T> = ApiResponse<{
  list: T[]
  total: number
  page: number
  pageSize: number
}>

// ✅ 使用枚举定义常量集合
enum HttpStatus {
  OK = 200,
  Created = 201,
  BadRequest = 400,
  Unauthorized = 401,
  Forbidden = 403,
  NotFound = 404,
  InternalError = 500
}

// 字符串枚举
enum OrderStatus {
  Pending = 'pending',
  Paid = 'paid',
  Shipped = 'shipped',
  Delivered = 'delivered',
  Cancelled = 'cancelled'
}

// ✅ 使用 const 断言定义字面量类型
const ROLES = ['admin', 'user', 'guest'] as const
type Role = typeof ROLES[number]  // 'admin' | 'user' | 'guest'

const STATUS_MAP = {
  pending: '待处理',
  success: '成功',
  error: '失败'
} as const
type StatusKey = keyof typeof STATUS_MAP  // 'pending' | 'success' | 'error'
```

### 3.2 类型定义文件组织

```typescript
// types/api.d.ts - API 相关类型

/** 分页参数 */
interface PaginationParams {
  page: number
  pageSize: number
  sortField?: string
  sortOrder?: 'asc' | 'desc'
}

/** 分页响应 */
interface PaginationResponse<T> {
  list: T[]
  total: number
  page: number
  pageSize: number
  totalPages: number
}

/** 通用 API 响应 */
interface ApiResponse<T = unknown> {
  code: number
  message: string
  data: T
  timestamp: number
}

/** API 错误响应 */
interface ApiError {
  code: number
  message: string
  details?: Record<string, string[]>
}

// types/user.d.ts - 用户模块类型

/** 用户基本信息 */
interface UserInfo {
  id: number
  username: string
  nickname: string
  avatar: string
  email: string
  phone: string
  roles: string[]
  permissions: string[]
  createdAt: string
  updatedAt: string
}

/** 登录参数 */
interface LoginParams {
  username: string
  password: string
  captcha?: string
  remember?: boolean
}

/** 登录响应 */
interface LoginResponse {
  token: string
  refreshToken: string
  expiresIn: number
  userInfo: UserInfo
}

/** 用户查询参数 */
interface UserQueryParams extends PaginationParams {
  username?: string
  email?: string
  status?: number
  startDate?: string
  endDate?: string
}

// types/global.d.ts - 全局类型扩展

// 扩展 Window 对象
declare interface Window {
  __APP_VERSION__: string
  __APP_BUILD_TIME__: string
  __APP_ENV__: 'development' | 'staging' | 'production'
}

// 扩展 ImportMeta（Vite 环境变量）
declare interface ImportMetaEnv {
  readonly VITE_APP_TITLE: string
  readonly VITE_API_BASE_URL: string
  readonly VITE_UPLOAD_URL: string
  readonly VITE_APP_ENV: string
}

declare interface ImportMeta {
  readonly env: ImportMetaEnv
}

// 声明模块类型
declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

declare module '*.svg' {
  const content: string
  export default content
}

declare module '*.png' {
  const content: string
  export default content
}

// 声明第三方库类型（如果没有 @types）
declare module 'some-untyped-lib' {
  export function someFunction(arg: string): void
  export const someValue: number
}
```

### 3.3 严格类型检查配置

```json
// tsconfig.json 推荐配置
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "module": "ESNext",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "skipLibCheck": true,

    /* 严格类型检查 - 全部开启 */
    "strict": true,                        // 启用所有严格检查
    "noImplicitAny": true,                 // 禁止隐式 any
    "strictNullChecks": true,              // 严格空值检查
    "strictFunctionTypes": true,           // 严格函数类型
    "strictBindCallApply": true,           // 严格 bind/call/apply
    "strictPropertyInitialization": true,  // 严格属性初始化
    "noImplicitThis": true,                // 禁止隐式 this
    "alwaysStrict": true,                  // 始终严格模式

    /* 额外检查 - 推荐开启 */
    "noUnusedLocals": true,                // 未使用的局部变量报错
    "noUnusedParameters": true,            // 未使用的参数报错
    "noImplicitReturns": true,             // 隐式返回报错
    "noFallthroughCasesInSwitch": true,    // switch 穿透报错
    "noUncheckedIndexedAccess": true,      // 索引访问检查
    "exactOptionalPropertyTypes": true,    // 精确可选属性类型

    /* 模块解析 */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "preserve",

    /* 路径别名 */
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@/components/*": ["src/components/*"],
      "@/utils/*": ["src/utils/*"],
      "@/api/*": ["src/api/*"],
      "@/stores/*": ["src/stores/*"],
      "@/types/*": ["src/types/*"]
    }
  },
  "include": ["src/**/*.ts", "src/**/*.tsx", "src/**/*.vue"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

### 3.4 类型体操实用技巧

```typescript
// 1. 从对象中提取类型
const user = {
  id: 1,
  name: 'John',
  age: 25,
  email: 'john@example.com'
}
type User = typeof user  // { id: number; name: string; age: number; email: string }

// 2. 从数组中提取元素类型
const roles = ['admin', 'user', 'guest'] as const
type Role = typeof roles[number]  // 'admin' | 'user' | 'guest'

// 3. 获取函数返回类型
function getUser() {
  return { id: 1, name: 'John' }
}
type UserType = ReturnType<typeof getUser>  // { id: number; name: string }

// 4. 获取函数参数类型
function createUser(name: string, age: number) {}
type CreateUserParams = Parameters<typeof createUser>  // [string, number]

// 5. 获取 Promise 解析类型
type PromiseType<T> = T extends Promise<infer U> ? U : T
type Result = PromiseType<Promise<string>>  // string

// 6. 深度 Partial（递归可选）
type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P]
}

// 7. 深度 Required（递归必填）
type DeepRequired<T> = {
  [P in keyof T]-?: T[P] extends object ? DeepRequired<T[P]> : T[P]
}

// 8. 提取对象的可选属性键
type OptionalKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? K : never
}[keyof T]

// 9. 提取对象的必填属性键
type RequiredKeys<T> = {
  [K in keyof T]-?: {} extends Pick<T, K> ? never : K
}[keyof T]

// 10. 排除 null 和 undefined
type NonNullableDeep<T> = {
  [P in keyof T]: NonNullable<T[P]>
}

// 11. 条件类型
type IsString<T> = T extends string ? true : false
type A = IsString<string>  // true
type B = IsString<number>  // false

// 12. 映射类型 - 将所有属性变为只读
type Readonly<T> = {
  readonly [P in keyof T]: T[P]
}

// 13. 排除某些属性
type OmitUser = Omit<User, 'password' | 'salt'>

// 14. 选取某些属性
type PickUser = Pick<User, 'id' | 'name'>

// 15. 记录类型
type StatusMap = Record<string, { label: string; color: string }>
```

### 3.5 避免 any，使用更精确的类型

```typescript
// ❌ 不好的做法 - 使用 any
function processData(data: any) {
  return data.map((item: any) => item.name)
}

// ✅ 好的做法 - 使用泛型
function processData<T extends { name: string }>(data: T[]): string[] {
  return data.map(item => item.name)
}

// ❌ 不好的做法 - 类型断言滥用
const element = document.getElementById('app') as HTMLDivElement

// ✅ 好的做法 - 类型守卫
const element = document.getElementById('app')
if (element instanceof HTMLDivElement) {
  // 这里 element 类型是 HTMLDivElement
  element.style.display = 'block'
}

// ✅ 使用 unknown 代替 any
function parseJSON(json: string): unknown {
  return JSON.parse(json)
}

// 使用时进行类型检查
const result = parseJSON('{"name": "John"}')
if (isUser(result)) {
  console.log(result.name)  // 类型安全
}

// ✅ 使用类型守卫函数
function isUser(obj: unknown): obj is User {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'id' in obj &&
    'name' in obj &&
    typeof (obj as User).id === 'number' &&
    typeof (obj as User).name === 'string'
  )
}

// ✅ 使用 satisfies 操作符（TypeScript 4.9+）
const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000,
  retries: 3
} satisfies Record<string, string | number>
// config 保持字面量类型，同时确保符合 Record 类型

// ✅ 使用 as const 保持字面量类型
const STATUS = {
  PENDING: 'pending',
  SUCCESS: 'success',
  ERROR: 'error'
} as const
// STATUS.PENDING 的类型是 'pending' 而不是 string
```

---

## 4. Vue 组件规范

### 4.1 单文件组件结构

```vue
<!-- 
  组件文件结构顺序（推荐）：
  1. <script setup> - 逻辑代码（放在最前面，因为是最重要的部分）
  2. <template> - 模板
  3. <style> - 样式
-->

<script setup lang="ts">
/**
 * 用户卡片组件
 * @description 展示用户基本信息的卡片组件
 * @example
 * <UserCard :user="userInfo" @click="handleClick" />
 */

// ============ 1. 类型导入 ============
import type { User, UserRole } from '@/types'

// ============ 2. 组件导入 ============
import { UserAvatar, BaseButton } from '@/components'

// ============ 3. 工具函数导入 ============
import { formatDate, formatMoney } from '@/utils'

// ============ 4. 组合式函数导入 ============
import { useUserStore } from '@/stores'
import { useRequest } from '@/composables'

// ============ 5. Props 定义 ============
interface Props {
  /** 用户信息 */
  user: User
  /** 是否显示操作按钮 */
  showActions?: boolean
  /** 卡片尺寸 */
  size?: 'small' | 'medium' | 'large'
}

const props = withDefaults(defineProps<Props>(), {
  showActions: true,
  size: 'medium'
})

// ============ 6. Emits 定义 ============
const emit = defineEmits<{
  (e: 'click', user: User): void
  (e: 'edit', user: User): void
  (e: 'delete', id: number): void
}>()

// ============ 7. 响应式状态 ============
const isLoading = ref(false)
const isExpanded = ref(false)
const localUser = ref<User | null>(null)

// ============ 8. 计算属性 ============
const fullName = computed(() => {
  return `${props.user.firstName} ${props.user.lastName}`
})

const cardClass = computed(() => ({
  'user-card': true,
  [`user-card--${props.size}`]: true,
  'user-card--expanded': isExpanded.value
}))

// ============ 9. 侦听器 ============
watch(
  () => props.user.id,
  (newId, oldId) => {
    if (newId !== oldId) {
      console.log('User changed:', newId)
      fetchUserDetail()
    }
  }
)

watchEffect(() => {
  // 自动追踪依赖
  console.log('User:', props.user.name)
})

// ============ 10. 生命周期 ============
onMounted(() => {
  console.log('Component mounted')
  fetchUserDetail()
})

onUnmounted(() => {
  console.log('Component unmounted')
})

// ============ 11. 方法 ============
const handleClick = () => {
  emit('click', props.user)
}

const handleEdit = () => {
  emit('edit', props.user)
}

const handleDelete = () => {
  emit('delete', props.user.id)
}

const fetchUserDetail = async () => {
  isLoading.value = true
  try {
    // 获取用户详情
  } finally {
    isLoading.value = false
  }
}

// ============ 12. 暴露给父组件的方法 ============
defineExpose({
  refresh: fetchUserDetail,
  expand: () => { isExpanded.value = true },
  collapse: () => { isExpanded.value = false }
})
</script>

<template>
  <div :class="cardClass" @click="handleClick">
    <div class="user-card__header">
      <UserAvatar :src="user.avatar" :size="size" />
      <div class="user-card__info">
        <h3 class="user-card__name">{{ fullName }}</h3>
        <p class="user-card__email">{{ user.email }}</p>
      </div>
    </div>
    
    <div v-if="showActions" class="user-card__actions">
      <BaseButton size="small" @click.stop="handleEdit">
        编辑
      </BaseButton>
      <BaseButton size="small" type="danger" @click.stop="handleDelete">
        删除
      </BaseButton>
    </div>
    
    <div v-if="isLoading" class="user-card__loading">
      加载中...
    </div>
  </div>
</template>

<style lang="scss" scoped>
.user-card {
  display: flex;
  flex-direction: column;
  padding: 16px;
  border-radius: 8px;
  background: var(--bg-color);
  cursor: pointer;
  transition: all 0.3s ease;

  &:hover {
    box-shadow: 0 2px 12px rgba(0, 0, 0, 0.1);
    transform: translateY(-2px);
  }

  &--small {
    padding: 12px;
  }

  &--large {
    padding: 24px;
  }

  &--expanded {
    // 展开状态样式
  }

  &__header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  &__info {
    flex: 1;
    min-width: 0;  // 防止文字溢出
  }

  &__name {
    margin: 0;
    font-size: 16px;
    font-weight: 500;
    color: var(--text-primary);
    
    // 文字溢出省略
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  &__email {
    margin: 4px 0 0;
    font-size: 14px;
    color: var(--text-secondary);
  }

  &__actions {
    display: flex;
    gap: 8px;
    margin-top: 16px;
    padding-top: 16px;
    border-top: 1px solid var(--border-color);
  }

  &__loading {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(255, 255, 255, 0.8);
  }
}
</style>
```

### 4.2 Props 定义规范

```typescript
// ✅ 推荐：使用 TypeScript 类型定义 Props

// 方式 1：使用 interface（推荐）
interface Props {
  // 必填属性
  id: number
  title: string
  
  // 可选属性（使用 ?）
  description?: string
  
  // 带默认值的属性（需要配合 withDefaults）
  size?: 'small' | 'medium' | 'large'
  disabled?: boolean
  
  // 复杂类型
  user?: User
  items?: Item[]
  config?: Record<string, unknown>
  
  // 函数类型
  formatter?: (value: string) => string
  validator?: (value: unknown) => boolean
  
  // 回调函数使用 on 前缀
  onSuccess?: () => void
  onError?: (error: Error) => void
}

const props = withDefaults(defineProps<Props>(), {
  size: 'medium',
  disabled: false,
  items: () => [],           // 引用类型默认值必须使用工厂函数
  config: () => ({}),        // 对象也需要工厂函数
  formatter: (v) => v,       // 函数默认值
})

// 方式 2：使用 defineProps 的运行时声明
// 适用于需要运行时验证的场景
const props = defineProps({
  id: {
    type: Number,
    required: true
  },
  title: {
    type: String,
    required: true,
    validator: (value: string) => value.length > 0
  },
  size: {
    type: String as PropType<'small' | 'medium' | 'large'>,
    default: 'medium',
    validator: (value: string) => ['small', 'medium', 'large'].includes(value)
  },
  items: {
    type: Array as PropType<Item[]>,
    default: () => []
  }
})

// ❌ 不好的做法

// 1. 不定义类型
const props = defineProps(['id', 'title'])  // 没有类型检查

// 2. 使用 any
interface Props {
  data: any  // 应该定义具体类型
}

// 3. 引用类型默认值不使用工厂函数
const props = withDefaults(defineProps<Props>(), {
  items: []  // ❌ 会导致所有实例共享同一个数组
})

// 4. 可选属性没有默认值但直接使用
const props = defineProps<{ name?: string }>()
console.log(props.name.length)  // ❌ 可能是 undefined
```

### 4.3 Emits 定义规范

```typescript
// ✅ 推荐：使用 TypeScript 类型定义 Emits

// 方式 1：使用泛型（推荐）
const emit = defineEmits<{
  // 无参数事件
  (e: 'close'): void
  (e: 'cancel'): void
  
  // 单参数事件
  (e: 'update:modelValue', value: string): void
  (e: 'change', value: string): void
  (e: 'select', item: Item): void
  
  // 多参数事件
  (e: 'move', from: number, to: number): void
  (e: 'resize', width: number, height: number): void
  
  // 可选参数
  (e: 'error', message?: string): void
  
  // 复杂参数
  (e: 'submit', data: FormData, options?: SubmitOptions): void
}>()

// 方式 2：Vue 3.3+ 简化语法
const emit = defineEmits<{
  close: []                                    // 无参数
  'update:modelValue': [value: string]         // 单参数
  change: [value: string]                      // 单参数
  select: [item: Item, index: number]          // 多参数
  submit: [data: FormData, options?: SubmitOptions]  // 可选参数
}>()

// 使用
emit('close')
emit('update:modelValue', 'new value')
emit('select', item, 0)
emit('submit', formData, { validate: true })

// ✅ v-model 双向绑定实现

// 父组件使用
<ChildComponent v-model="value" />
<ChildComponent v-model:title="title" v-model:content="content" />

// 子组件实现
interface Props {
  modelValue: string
  title?: string
  content?: string
}

const props = defineProps<Props>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'update:title', value: string): void
  (e: 'update:content', value: string): void
}>()

// 使用 computed 实现双向绑定（推荐）
const innerValue = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val)
})

// 在模板中使用
<template>
  <input v-model="innerValue" />
</template>
```

### 4.4 模板规范

```vue
<template>
  <!-- ✅ 好的模板写法 -->
  
  <!-- 1. 使用语义化标签 -->
  <article class="post">
    <header class="post__header">
      <h1 class="post__title">{{ title }}</h1>
      <time class="post__date" :datetime="createdAt">
        {{ formatDate(createdAt) }}
      </time>
    </header>
    <main class="post__content">
      <p>{{ content }}</p>
    </main>
    <footer class="post__footer">
      <span class="post__author">{{ author }}</span>
    </footer>
  </article>

  <!-- 2. 条件渲染：v-if/v-else-if/v-else 保持在一起 -->
  <div v-if="status === 'loading'" class="loading">
    <LoadingSpinner />
  </div>
  <div v-else-if="status === 'error'" class="error">
    <ErrorMessage :message="errorMessage" />
  </div>
  <div v-else-if="status === 'empty'" class="empty">
    <EmptyState />
  </div>
  <div v-else class="content">
    {{ data }}
  </div>

  <!-- 3. 列表渲染：始终使用唯一的 key -->
  <ul class="user-list">
    <li 
      v-for="user in users" 
      :key="user.id"
      class="user-list__item"
    >
      <UserCard :user="user" />
    </li>
  </ul>

  <!-- 4. 事件处理：简单逻辑内联，复杂逻辑使用方法 -->
  <button @click="count++">简单操作</button>
  <button @click="handleSubmit">复杂操作</button>
  
  <!-- 使用事件修饰符 -->
  <form @submit.prevent="handleSubmit">
    <input @keyup.enter="handleSearch" />
    <button @click.stop="handleClick">阻止冒泡</button>
    <a @click.prevent="handleLink">阻止默认</a>
  </form>

  <!-- 5. 属性绑定：多个属性换行，保持整洁 -->
  <MyComponent
    :id="item.id"
    :title="item.title"
    :description="item.description"
    :is-active="item.isActive"
    :config="componentConfig"
    class="my-component"
    @click="handleClick"
    @update="handleUpdate"
    @delete="handleDelete"
  />

  <!-- 6. 插槽使用 -->
  <BaseCard>
    <template #header>
      <h3>卡片标题</h3>
    </template>
    
    <template #default>
      <p>卡片内容</p>
    </template>
    
    <template #footer="{ data }">
      <span>{{ data.count }} 条记录</span>
    </template>
  </BaseCard>

  <!-- 7. 动态组件 -->
  <component :is="currentComponent" v-bind="componentProps" />

  <!-- 8. 异步组件 -->
  <Suspense>
    <template #default>
      <AsyncComponent />
    </template>
    <template #fallback>
      <LoadingSpinner />
    </template>
  </Suspense>
</template>

<template>
  <!-- ❌ 不好的模板写法 -->
  
  <!-- 1. 不要在模板中写复杂逻辑 -->
  <div>
    {{ items.filter(i => i.active).map(i => i.name).join(', ') }}
  </div>
  <!-- ✅ 应该使用计算属性 -->
  <div>{{ activeItemNames }}</div>

  <!-- 2. 不要使用 index 作为 key（除非列表是静态的） -->
  <li v-for="(item, index) in items" :key="index">❌</li>
  <!-- ✅ 使用唯一标识 -->
  <li v-for="item in items" :key="item.id">✅</li>

  <!-- 3. 避免 v-if 和 v-for 同时使用在同一元素 -->
  <li v-for="item in items" v-if="item.active" :key="item.id">❌</li>
  <!-- ✅ 使用计算属性过滤，或用 template 包裹 -->
  <li v-for="item in activeItems" :key="item.id">✅</li>
  <template v-for="item in items" :key="item.id">
    <li v-if="item.active">✅</li>
  </template>

  <!-- 4. 不要在模板中直接修改 props -->
  <input :value="modelValue" @input="modelValue = $event.target.value" />❌
  <!-- ✅ 使用 emit -->
  <input :value="modelValue" @input="emit('update:modelValue', $event.target.value)" />
</template>
```

---

## 5. Composition API 最佳实践

### 5.1 响应式数据

```typescript
import { ref, reactive, computed, watch, watchEffect, toRefs, toRef } from 'vue'

// ============ ref vs reactive 使用场景 ============

// ✅ ref: 用于基本类型和需要整体替换的对象
const count = ref(0)
const message = ref('')
const user = ref<User | null>(null)
const items = ref<Item[]>([])

// 访问和修改（需要 .value）
count.value++
message.value = 'Hello'
user.value = { id: 1, name: 'John' }
items.value = [...items.value, newItem]
items.value.push(newItem)  // 也可以直接修改

// ✅ reactive: 用于复杂对象，不需要整体替换
const form = reactive({
  username: '',
  password: '',
  remember: false
})

const state = reactive({
  loading: false,
  error: null as Error | null,
  data: [] as Item[]
})

// 访问和修改（不需要 .value）
form.username = 'admin'
state.loading = true
state.data.push(newItem)

// ⚠️ reactive 的注意事项

// 1. 不能整体替换（会丢失响应性）
state = { loading: false }  // ❌ 错误！

// 2. 解构会丢失响应性
const { loading } = state  // ❌ loading 不是响应式的
const { loading } = toRefs(state)  // ✅ 使用 toRefs
const loading = toRef(state, 'loading')  // ✅ 使用 toRef

// 3. 传递给函数时要注意
function updateLoading(loading: boolean) {
  state.loading = loading  // ✅ 正确
}
function updateState(s: typeof state) {
  s.loading = true  // ✅ 正确，传递的是响应式对象
}

// ============ 计算属性 ============

// 只读计算属性
const fullName = computed(() => `${user.value?.firstName} ${user.value?.lastName}`)
const isValid = computed(() => form.username.length > 0 && form.password.length >= 6)
const totalPrice = computed(() => items.value.reduce((sum, item) => sum + item.price, 0))

// 可写计算属性
const selectedIds = computed({
  get: () => props.modelValue,
  set: (val) => emit('update:modelValue', val)
})

// 带缓存的计算属性（默认就有缓存）
const expensiveComputed = computed(() => {
  console.log('计算中...')  // 只有依赖变化时才会重新计算
  return items.value.filter(item => item.active).map(item => item.name)
})

// ============ 侦听器 ============

// watch: 侦听特定数据源
watch(
  () => props.userId,
  (newId, oldId) => {
    if (newId !== oldId) {
      fetchUser(newId)
    }
  },
  { immediate: true }  // 立即执行一次
)

// 侦听多个数据源
watch(
  [() => props.userId, () => props.type],
  ([newUserId, newType], [oldUserId, oldType]) => {
    // 任一变化都会触发
  }
)

// 侦听 reactive 对象（需要 deep 选项或使用 getter）
watch(
  () => state.data,
  (newData) => {
    console.log('data changed')
  },
  { deep: true }
)

// watchEffect: 自动追踪依赖
watchEffect(() => {
  // 自动追踪 userId 和 type
  console.log(`User: ${props.userId}, Type: ${props.type}`)
})

// watchEffect 返回停止函数
const stop = watchEffect(() => {
  // ...
})
stop()  // 停止侦听

// 清理副作用
watchEffect((onCleanup) => {
  const timer = setInterval(() => {
    // ...
  }, 1000)
  
  onCleanup(() => {
    clearInterval(timer)
  })
})
```

### 5.2 组合式函数（Composables）

组合式函数是 Vue 3 中复用逻辑的主要方式，类似于 React 的 Hooks。

```typescript
// composables/useRequest.ts
import { ref, type Ref } from 'vue'

interface UseRequestOptions<T> {
  immediate?: boolean
  initialData?: T
  onSuccess?: (data: T) => void
  onError?: (error: Error) => void
}

interface UseRequestReturn<T> {
  data: Ref<T | null>
  loading: Ref<boolean>
  error: Ref<Error | null>
  execute: () => Promise<void>
  refresh: () => Promise<void>
}

export function useRequest<T>(
  fetcher: () => Promise<T>,
  options: UseRequestOptions<T> = {}
): UseRequestReturn<T> {
  const { immediate = true, initialData = null, onSuccess, onError } = options

  const data = ref<T | null>(initialData) as Ref<T | null>
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const execute = async () => {
    loading.value = true
    error.value = null
    
    try {
      const result = await fetcher()
      data.value = result
      onSuccess?.(result)
    } catch (e) {
      error.value = e as Error
      onError?.(e as Error)
    } finally {
      loading.value = false
    }
  }

  const refresh = execute

  if (immediate) {
    execute()
  }

  return {
    data,
    loading,
    error,
    execute,
    refresh
  }
}

// 使用示例
const { data: users, loading, error, refresh } = useRequest(
  () => api.getUsers(),
  {
    onSuccess: (data) => {
      console.log('获取成功', data)
    },
    onError: (error) => {
      console.error('获取失败', error)
    }
  }
)
```

```typescript
// composables/useTable.ts
import { ref, reactive, computed, watch } from 'vue'
import type { Ref } from 'vue'

interface TableParams {
  page: number
  pageSize: number
  sortField?: string
  sortOrder?: 'asc' | 'desc'
  [key: string]: unknown
}

interface UseTableOptions<T, P extends TableParams> {
  fetcher: (params: P) => Promise<{ list: T[]; total: number }>
  defaultParams?: Partial<P>
  immediate?: boolean
}

export function useTable<T, P extends TableParams = TableParams>(
  options: UseTableOptions<T, P>
) {
  const { fetcher, defaultParams = {}, immediate = true } = options

  // 表格数据
  const data = ref<T[]>([]) as Ref<T[]>
  const total = ref(0)
  const loading = ref(false)

  // 分页参数
  const pagination = reactive({
    page: 1,
    pageSize: 10,
    ...defaultParams
  }) as P

  // 查询参数（不包含分页）
  const searchParams = reactive<Record<string, unknown>>({})

  // 合并后的参数
  const params = computed(() => ({
    ...pagination,
    ...searchParams
  }))

  // 获取数据
  const fetchData = async () => {
    loading.value = true
    try {
      const result = await fetcher(params.value as P)
      data.value = result.list
      total.value = result.total
    } catch (error) {
      console.error('获取表格数据失败', error)
      data.value = []
      total.value = 0
    } finally {
      loading.value = false
    }
  }

  // 搜索（重置到第一页）
  const search = (params: Record<string, unknown> = {}) => {
    Object.assign(searchParams, params)
    pagination.page = 1
    fetchData()
  }

  // 重置搜索条件
  const reset = () => {
    Object.keys(searchParams).forEach(key => {
      delete searchParams[key]
    })
    pagination.page = 1
    fetchData()
  }

  // 分页变化
  const handlePageChange = (page: number) => {
    pagination.page = page
    fetchData()
  }

  // 每页条数变化
  const handleSizeChange = (size: number) => {
    pagination.pageSize = size
    pagination.page = 1
    fetchData()
  }

  // 排序变化
  const handleSortChange = (field: string, order: 'asc' | 'desc') => {
    pagination.sortField = field
    pagination.sortOrder = order
    fetchData()
  }

  // 刷新当前页
  const refresh = fetchData

  // 立即执行
  if (immediate) {
    fetchData()
  }

  return {
    data,
    total,
    loading,
    pagination,
    searchParams,
    search,
    reset,
    refresh,
    handlePageChange,
    handleSizeChange,
    handleSortChange
  }
}

// 使用示例
const {
  data: users,
  total,
  loading,
  pagination,
  search,
  reset,
  refresh,
  handlePageChange,
  handleSizeChange
} = useTable({
  fetcher: (params) => api.getUsers(params),
  defaultParams: {
    page: 1,
    pageSize: 20
  }
})
```

```typescript
// composables/useForm.ts
import { reactive, ref, computed } from 'vue'
import type { FormInstance, FormRules } from 'element-plus'

interface UseFormOptions<T extends Record<string, unknown>> {
  initialValues: T
  rules?: FormRules
  onSubmit?: (values: T) => Promise<void>
}

export function useForm<T extends Record<string, unknown>>(
  options: UseFormOptions<T>
) {
  const { initialValues, rules = {}, onSubmit } = options

  // 表单引用
  const formRef = ref<FormInstance>()

  // 表单数据
  const formData = reactive<T>({ ...initialValues })

  // 提交状态
  const submitting = ref(false)

  // 是否有修改
  const isDirty = computed(() => {
    return JSON.stringify(formData) !== JSON.stringify(initialValues)
  })

  // 重置表单
  const resetForm = () => {
    Object.assign(formData, initialValues)
    formRef.value?.resetFields()
  }

  // 验证表单
  const validate = async () => {
    if (!formRef.value) return false
    try {
      await formRef.value.validate()
      return true
    } catch {
      return false
    }
  }

  // 验证单个字段
  const validateField = async (field: keyof T) => {
    if (!formRef.value) return false
    try {
      await formRef.value.validateField(field as string)
      return true
    } catch {
      return false
    }
  }

  // 清除验证
  const clearValidate = (fields?: (keyof T)[]) => {
    formRef.value?.clearValidate(fields as string[])
  }

  // 提交表单
  const submitForm = async () => {
    const valid = await validate()
    if (!valid) return false

    submitting.value = true
    try {
      await onSubmit?.(formData as T)
      return true
    } catch (error) {
      console.error('提交失败', error)
      return false
    } finally {
      submitting.value = false
    }
  }

  // 设置表单值
  const setFieldValue = <K extends keyof T>(field: K, value: T[K]) => {
    (formData as T)[field] = value
  }

  // 设置多个值
  const setFieldsValue = (values: Partial<T>) => {
    Object.assign(formData, values)
  }

  return {
    formRef,
    formData,
    rules,
    submitting,
    isDirty,
    resetForm,
    validate,
    validateField,
    clearValidate,
    submitForm,
    setFieldValue,
    setFieldsValue
  }
}

// 使用示例
const {
  formRef,
  formData,
  rules,
  submitting,
  resetForm,
  submitForm
} = useForm({
  initialValues: {
    username: '',
    email: '',
    phone: ''
  },
  rules: {
    username: [{ required: true, message: '请输入用户名' }],
    email: [
      { required: true, message: '请输入邮箱' },
      { type: 'email', message: '邮箱格式不正确' }
    ]
  },
  onSubmit: async (values) => {
    await api.createUser(values)
  }
})
```

---

## 6. 状态管理 Pinia

Pinia 是 Vue 3 官方推荐的状态管理库，比 Vuex 更简洁、更好用。

### 6.1 Store 定义

```typescript
// stores/modules/user.ts
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { UserInfo, LoginParams, LoginResponse } from '@/types'
import { login, logout, getUserInfo } from '@/api/user'
import { setToken, getToken, removeToken } from '@/utils/auth'

// 推荐：使用 Setup Store 语法（更灵活）
export const useUserStore = defineStore('user', () => {
  // ============ State ============
  const token = ref<string>(getToken() || '')
  const userInfo = ref<UserInfo | null>(null)
  const roles = ref<string[]>([])
  const permissions = ref<string[]>([])

  // ============ Getters ============
  const isLoggedIn = computed(() => !!token.value)
  const isAdmin = computed(() => roles.value.includes('admin'))
  const hasPermission = computed(() => (permission: string) => {
    return permissions.value.includes(permission) || roles.value.includes('admin')
  })
  const username = computed(() => userInfo.value?.username || '')
  const avatar = computed(() => userInfo.value?.avatar || '/default-avatar.png')

  // ============ Actions ============
  
  // 登录
  async function loginAction(params: LoginParams): Promise<LoginResponse> {
    try {
      const res = await login(params)
      token.value = res.token
      setToken(res.token)
      return res
    } catch (error) {
      throw error
    }
  }

  // 获取用户信息
  async function getUserInfoAction(): Promise<UserInfo> {
    try {
      const res = await getUserInfo()
      userInfo.value = res
      roles.value = res.roles
      permissions.value = res.permissions
      return res
    } catch (error) {
      throw error
    }
  }

  // 登出
  async function logoutAction(): Promise<void> {
    try {
      await logout()
    } finally {
      resetState()
    }
  }

  // 重置状态
  function resetState(): void {
    token.value = ''
    userInfo.value = null
    roles.value = []
    permissions.value = []
    removeToken()
  }

  // 设置 Token
  function setTokenAction(newToken: string): void {
    token.value = newToken
    setToken(newToken)
  }

  return {
    // State
    token,
    userInfo,
    roles,
    permissions,
    // Getters
    isLoggedIn,
    isAdmin,
    hasPermission,
    username,
    avatar,
    // Actions
    loginAction,
    getUserInfoAction,
    logoutAction,
    resetState,
    setTokenAction
  }
})
```

```typescript
// stores/modules/app.ts
import { defineStore } from 'pinia'
import { ref, computed, watch } from 'vue'

export const useAppStore = defineStore('app', () => {
  // ============ State ============
  
  // 侧边栏状态
  const sidebarCollapsed = ref(false)
  
  // 主题
  const theme = ref<'light' | 'dark'>('light')
  
  // 语言
  const locale = ref<'zh-CN' | 'en-US'>('zh-CN')
  
  // 全局 Loading
  const globalLoading = ref(false)
  const loadingText = ref('')
  
  // 设备类型
  const device = ref<'desktop' | 'tablet' | 'mobile'>('desktop')
  
  // 页面标题
  const pageTitle = ref('')

  // ============ Getters ============
  
  const isDark = computed(() => theme.value === 'dark')
  const isMobile = computed(() => device.value === 'mobile')
  const isTablet = computed(() => device.value === 'tablet')
  const isDesktop = computed(() => device.value === 'desktop')

  // ============ Actions ============
  
  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }
  
  function setSidebarCollapsed(collapsed: boolean) {
    sidebarCollapsed.value = collapsed
  }
  
  function toggleTheme() {
    theme.value = theme.value === 'light' ? 'dark' : 'light'
  }
  
  function setTheme(newTheme: 'light' | 'dark') {
    theme.value = newTheme
  }
  
  function setLocale(newLocale: 'zh-CN' | 'en-US') {
    locale.value = newLocale
  }
  
  function showLoading(text = '加载中...') {
    globalLoading.value = true
    loadingText.value = text
  }
  
  function hideLoading() {
    globalLoading.value = false
    loadingText.value = ''
  }
  
  function setDevice(newDevice: 'desktop' | 'tablet' | 'mobile') {
    device.value = newDevice
  }
  
  function setPageTitle(title: string) {
    pageTitle.value = title
    document.title = title ? `${title} - 管理系统` : '管理系统'
  }

  // ============ 持久化 ============
  
  // 监听主题变化，同步到 localStorage 和 DOM
  watch(theme, (newTheme) => {
    localStorage.setItem('theme', newTheme)
    document.documentElement.setAttribute('data-theme', newTheme)
  }, { immediate: true })
  
  // 监听语言变化
  watch(locale, (newLocale) => {
    localStorage.setItem('locale', newLocale)
  })

  // 初始化时从 localStorage 读取
  function initFromStorage() {
    const savedTheme = localStorage.getItem('theme') as 'light' | 'dark' | null
    if (savedTheme) {
      theme.value = savedTheme
    }
    
    const savedLocale = localStorage.getItem('locale') as 'zh-CN' | 'en-US' | null
    if (savedLocale) {
      locale.value = savedLocale
    }
  }

  // 初始化
  initFromStorage()

  return {
    // State
    sidebarCollapsed,
    theme,
    locale,
    globalLoading,
    loadingText,
    device,
    pageTitle,
    // Getters
    isDark,
    isMobile,
    isTablet,
    isDesktop,
    // Actions
    toggleSidebar,
    setSidebarCollapsed,
    toggleTheme,
    setTheme,
    setLocale,
    showLoading,
    hideLoading,
    setDevice,
    setPageTitle
  }
})
```

### 6.2 Store 使用

```typescript
// 在组件中使用
<script setup lang="ts">
import { useUserStore, useAppStore } from '@/stores'
import { storeToRefs } from 'pinia'

const userStore = useUserStore()
const appStore = useAppStore()

// ✅ 使用 storeToRefs 解构响应式状态
const { userInfo, isLoggedIn, isAdmin } = storeToRefs(userStore)
const { theme, sidebarCollapsed } = storeToRefs(appStore)

// ✅ 直接解构 actions（不需要 storeToRefs）
const { loginAction, logoutAction } = userStore
const { toggleSidebar, toggleTheme } = appStore

// 使用
const handleLogin = async () => {
  try {
    await loginAction({ username: 'admin', password: '123456' })
    await userStore.getUserInfoAction()
  } catch (error) {
    console.error('登录失败', error)
  }
}

const handleLogout = async () => {
  await logoutAction()
  router.push('/login')
}
</script>

<template>
  <div>
    <p v-if="isLoggedIn">欢迎，{{ userInfo?.username }}</p>
    <button @click="toggleTheme">切换主题</button>
    <button @click="toggleSidebar">切换侧边栏</button>
  </div>
</template>
```

### 6.3 Store 持久化

```typescript
// 使用 pinia-plugin-persistedstate 插件
// pnpm add pinia-plugin-persistedstate

// main.ts
import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'

const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)

app.use(pinia)

// 在 store 中配置持久化
export const useUserStore = defineStore('user', () => {
  // ... state 和 actions
}, {
  persist: {
    key: 'user-store',
    storage: localStorage,
    paths: ['token', 'userInfo'],  // 只持久化指定字段
  }
})

// 或者使用 sessionStorage
export const useAppStore = defineStore('app', () => {
  // ...
}, {
  persist: {
    storage: sessionStorage,
  }
})
```

---

## 7. 路由管理

### 7.1 路由配置

```typescript
// router/index.ts
import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

// 静态路由（不需要权限）
export const constantRoutes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/index.vue'),
    meta: {
      title: '登录',
      hidden: true  // 不在菜单中显示
    }
  },
  {
    path: '/404',
    name: 'NotFound',
    component: () => import('@/views/error/404.vue'),
    meta: {
      title: '404',
      hidden: true
    }
  },
  {
    path: '/',
    component: () => import('@/layouts/DefaultLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/index.vue'),
        meta: {
          title: '仪表盘',
          icon: 'dashboard',
          affix: true  // 固定在标签栏
        }
      }
    ]
  }
]

// 动态路由（需要权限）
export const asyncRoutes: RouteRecordRaw[] = [
  {
    path: '/user',
    component: () => import('@/layouts/DefaultLayout.vue'),
    redirect: '/user/list',
    meta: {
      title: '用户管理',
      icon: 'user',
      roles: ['admin']  // 需要 admin 角色
    },
    children: [
      {
        path: 'list',
        name: 'UserList',
        component: () => import('@/views/user/list.vue'),
        meta: {
          title: '用户列表',
          roles: ['admin']
        }
      },
      {
        path: 'detail/:id',
        name: 'UserDetail',
        component: () => import('@/views/user/detail.vue'),
        meta: {
          title: '用户详情',
          hidden: true,
          activeMenu: '/user/list'  // 高亮的菜单
        }
      }
    ]
  },
  {
    path: '/order',
    component: () => import('@/layouts/DefaultLayout.vue'),
    redirect: '/order/list',
    meta: {
      title: '订单管理',
      icon: 'order',
      permissions: ['order:view']  // 需要特定权限
    },
    children: [
      {
        path: 'list',
        name: 'OrderList',
        component: () => import('@/views/order/list.vue'),
        meta: {
          title: '订单列表',
          permissions: ['order:view']
        }
      }
    ]
  },
  // 404 必须放在最后
  {
    path: '/:pathMatch(.*)*',
    redirect: '/404',
    meta: { hidden: true }
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: constantRoutes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) {
      return savedPosition
    } else {
      return { top: 0 }
    }
  }
})

export default router
```

### 7.2 路由守卫

```typescript
// router/guards.ts
import type { Router } from 'vue-router'
import { useUserStore } from '@/stores'
import { getToken } from '@/utils/auth'
import NProgress from 'nprogress'
import 'nprogress/nprogress.css'

// 白名单路由（不需要登录）
const whiteList = ['/login', '/register', '/forgot-password']

export function setupRouterGuards(router: Router) {
  // 全局前置守卫
  router.beforeEach(async (to, from, next) => {
    // 开始进度条
    NProgress.start()

    // 设置页面标题
    document.title = to.meta.title 
      ? `${to.meta.title} - 管理系统` 
      : '管理系统'

    const token = getToken()
    const userStore = useUserStore()

    if (token) {
      // 已登录
      if (to.path === '/login') {
        // 已登录访问登录页，重定向到首页
        next({ path: '/' })
        NProgress.done()
      } else {
        // 检查是否有用户信息
        if (userStore.userInfo) {
          // 有用户信息，检查权限
          if (hasPermission(to, userStore)) {
            next()
          } else {
            next({ path: '/403' })
          }
        } else {
          // 没有用户信息，获取用户信息
          try {
            await userStore.getUserInfoAction()
            // 动态添加路由
            const accessRoutes = filterAsyncRoutes(asyncRoutes, userStore.roles)
            accessRoutes.forEach(route => {
              router.addRoute(route)
            })
            // 重新导航到目标路由
            next({ ...to, replace: true })
          } catch (error) {
            // 获取用户信息失败，清除 token 并跳转登录页
            userStore.resetState()
            next(`/login?redirect=${to.path}`)
            NProgress.done()
          }
        }
      }
    } else {
      // 未登录
      if (whiteList.includes(to.path)) {
        // 在白名单中，直接进入
        next()
      } else {
        // 不在白名单中，重定向到登录页
        next(`/login?redirect=${to.path}`)
        NProgress.done()
      }
    }
  })

  // 全局后置守卫
  router.afterEach(() => {
    NProgress.done()
  })

  // 全局错误处理
  router.onError((error) => {
    console.error('路由错误:', error)
    NProgress.done()
  })
}

// 检查权限
function hasPermission(to: any, userStore: any): boolean {
  const { roles, permissions } = to.meta || {}
  
  // 没有权限要求，直接通过
  if (!roles && !permissions) {
    return true
  }
  
  // 检查角色
  if (roles && roles.length > 0) {
    if (userStore.roles.some((role: string) => roles.includes(role))) {
      return true
    }
  }
  
  // 检查权限
  if (permissions && permissions.length > 0) {
    if (userStore.permissions.some((p: string) => permissions.includes(p))) {
      return true
    }
  }
  
  return false
}

// 过滤动态路由
function filterAsyncRoutes(routes: any[], roles: string[]): any[] {
  const res: any[] = []
  
  routes.forEach(route => {
    const tmp = { ...route }
    if (hasRoutePermission(tmp, roles)) {
      if (tmp.children) {
        tmp.children = filterAsyncRoutes(tmp.children, roles)
      }
      res.push(tmp)
    }
  })
  
  return res
}

function hasRoutePermission(route: any, roles: string[]): boolean {
  if (route.meta && route.meta.roles) {
    return roles.some(role => route.meta.roles.includes(role))
  }
  return true
}
```

---

## 8. API 请求封装

### 8.1 Axios 封装

```typescript
// api/request.ts
import axios, { type AxiosInstance, type AxiosRequestConfig, type AxiosResponse } from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useUserStore } from '@/stores'
import { getToken, removeToken } from '@/utils/auth'
import router from '@/router'

// 响应数据类型
interface ApiResponse<T = unknown> {
  code: number
  message: string
  data: T
}

// 创建 axios 实例
const service: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// 请求拦截器
service.interceptors.request.use(
  (config) => {
    // 添加 token
    const token = getToken()
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    // 添加时间戳防止缓存
    if (config.method === 'get') {
      config.params = {
        ...config.params,
        _t: Date.now()
      }
    }
    
    return config
  },
  (error) => {
    console.error('请求错误:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器
service.interceptors.response.use(
  (response: AxiosResponse<ApiResponse>) => {
    const { code, message, data } = response.data
    
    // 成功
    if (code === 200 || code === 0) {
      return data as any
    }
    
    // 业务错误
    handleBusinessError(code, message)
    return Promise.reject(new Error(message || '请求失败'))
  },
  (error) => {
    // HTTP 错误
    handleHttpError(error)
    return Promise.reject(error)
  }
)

// 处理业务错误
function handleBusinessError(code: number, message: string) {
  switch (code) {
    case 401:
      // 未登录或 token 过期
      handleUnauthorized()
      break
    case 403:
      // 无权限
      ElMessage.error('没有操作权限')
      break
    case 404:
      ElMessage.error('请求的资源不存在')
      break
    case 500:
      ElMessage.error('服务器内部错误')
      break
    default:
      ElMessage.error(message || '请求失败')
  }
}

// 处理 HTTP 错误
function handleHttpError(error: any) {
  if (error.response) {
    const { status, data } = error.response
    switch (status) {
      case 400:
        ElMessage.error(data?.message || '请求参数错误')
        break
      case 401:
        handleUnauthorized()
        break
      case 403:
        ElMessage.error('没有操作权限')
        break
      case 404:
        ElMessage.error('请求的资源不存在')
        break
      case 500:
        ElMessage.error('服务器内部错误')
        break
      case 502:
        ElMessage.error('网关错误')
        break
      case 503:
        ElMessage.error('服务不可用')
        break
      default:
        ElMessage.error(`请求失败: ${status}`)
    }
  } else if (error.code === 'ECONNABORTED') {
    ElMessage.error('请求超时，请稍后重试')
  } else if (error.message === 'Network Error') {
    ElMessage.error('网络错误，请检查网络连接')
  } else {
    ElMessage.error('请求失败，请稍后重试')
  }
}

// 处理未授权
let isRefreshing = false
function handleUnauthorized() {
  if (isRefreshing) return
  isRefreshing = true
  
  ElMessageBox.confirm(
    '登录状态已过期，请重新登录',
    '提示',
    {
      confirmButtonText: '重新登录',
      cancelButtonText: '取消',
      type: 'warning'
    }
  ).then(() => {
    const userStore = useUserStore()
    userStore.resetState()
    router.push(`/login?redirect=${router.currentRoute.value.fullPath}`)
  }).finally(() => {
    isRefreshing = false
  })
}

// 封装请求方法
export const request = {
  get<T>(url: string, params?: object, config?: AxiosRequestConfig): Promise<T> {
    return service.get(url, { params, ...config })
  },
  
  post<T>(url: string, data?: object, config?: AxiosRequestConfig): Promise<T> {
    return service.post(url, data, config)
  },
  
  put<T>(url: string, data?: object, config?: AxiosRequestConfig): Promise<T> {
    return service.put(url, data, config)
  },
  
  delete<T>(url: string, params?: object, config?: AxiosRequestConfig): Promise<T> {
    return service.delete(url, { params, ...config })
  },
  
  // 上传文件
  upload<T>(url: string, file: File, onProgress?: (percent: number) => void): Promise<T> {
    const formData = new FormData()
    formData.append('file', file)
    
    return service.post(url, formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      onUploadProgress: (progressEvent) => {
        if (progressEvent.total) {
          const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total)
          onProgress?.(percent)
        }
      }
    })
  },
  
  // 下载文件
  download(url: string, params?: object, filename?: string): Promise<void> {
    return service.get(url, {
      params,
      responseType: 'blob'
    }).then((response: any) => {
      const blob = new Blob([response])
      const link = document.createElement('a')
      link.href = URL.createObjectURL(blob)
      link.download = filename || 'download'
      link.click()
      URL.revokeObjectURL(link.href)
    })
  }
}

export default service
```

### 8.2 API 模块化

```typescript
// api/modules/user.ts
import { request } from '../request'
import type { 
  UserInfo, 
  LoginParams, 
  LoginResponse,
  UserQueryParams,
  PaginationResponse 
} from '@/types'

const PREFIX = '/user'

export const userApi = {
  // 登录
  login(params: LoginParams): Promise<LoginResponse> {
    return request.post(`${PREFIX}/login`, params)
  },
  
  // 登出
  logout(): Promise<void> {
    return request.post(`${PREFIX}/logout`)
  },
  
  // 获取当前用户信息
  getCurrentUser(): Promise<UserInfo> {
    return request.get(`${PREFIX}/current`)
  },
  
  // 获取用户列表
  getList(params: UserQueryParams): Promise<PaginationResponse<UserInfo>> {
    return request.get(`${PREFIX}/list`, params)
  },
  
  // 获取用户详情
  getDetail(id: number): Promise<UserInfo> {
    return request.get(`${PREFIX}/${id}`)
  },
  
  // 创建用户
  create(data: Partial<UserInfo>): Promise<UserInfo> {
    return request.post(PREFIX, data)
  },
  
  // 更新用户
  update(id: number, data: Partial<UserInfo>): Promise<UserInfo> {
    return request.put(`${PREFIX}/${id}`, data)
  },
  
  // 删除用户
  delete(id: number): Promise<void> {
    return request.delete(`${PREFIX}/${id}`)
  },
  
  // 批量删除
  batchDelete(ids: number[]): Promise<void> {
    return request.post(`${PREFIX}/batch-delete`, { ids })
  },
  
  // 修改密码
  changePassword(data: { oldPassword: string; newPassword: string }): Promise<void> {
    return request.post(`${PREFIX}/change-password`, data)
  },
  
  // 上传头像
  uploadAvatar(file: File): Promise<{ url: string }> {
    return request.upload(`${PREFIX}/avatar`, file)
  }
}

// api/modules/order.ts
import { request } from '../request'
import type { Order, OrderQueryParams, PaginationResponse } from '@/types'

const PREFIX = '/order'

export const orderApi = {
  getList(params: OrderQueryParams): Promise<PaginationResponse<Order>> {
    return request.get(`${PREFIX}/list`, params)
  },
  
  getDetail(id: number): Promise<Order> {
    return request.get(`${PREFIX}/${id}`)
  },
  
  create(data: Partial<Order>): Promise<Order> {
    return request.post(PREFIX, data)
  },
  
  cancel(id: number, reason: string): Promise<void> {
    return request.post(`${PREFIX}/${id}/cancel`, { reason })
  },
  
  export(params: OrderQueryParams): Promise<void> {
    return request.download(`${PREFIX}/export`, params, 'orders.xlsx')
  }
}

// api/index.ts - 统一导出
export * from './modules/user'
export * from './modules/order'
export { request } from './request'
```

---

## 9. 样式规范

### 9.1 CSS 变量（主题）

```scss
// assets/styles/variables.scss

// ============ 颜色变量 ============
:root {
  // 主色
  --primary-color: #409eff;
  --primary-color-light: #66b1ff;
  --primary-color-dark: #3a8ee6;
  
  // 功能色
  --success-color: #67c23a;
  --warning-color: #e6a23c;
  --danger-color: #f56c6c;
  --info-color: #909399;
  
  // 文字颜色
  --text-primary: #303133;
  --text-regular: #606266;
  --text-secondary: #909399;
  --text-placeholder: #c0c4cc;
  
  // 边框颜色
  --border-color: #dcdfe6;
  --border-color-light: #e4e7ed;
  --border-color-lighter: #ebeef5;
  
  // 背景颜色
  --bg-color: #ffffff;
  --bg-color-page: #f2f3f5;
  --bg-color-overlay: rgba(0, 0, 0, 0.5);
  
  // 阴影
  --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
  
  // 圆角
  --radius-sm: 2px;
  --radius-md: 4px;
  --radius-lg: 8px;
  --radius-full: 9999px;
  
  // 间距
  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 16px;
  --spacing-lg: 24px;
  --spacing-xl: 32px;
  
  // 字体大小
  --font-size-xs: 12px;
  --font-size-sm: 13px;
  --font-size-md: 14px;
  --font-size-lg: 16px;
  --font-size-xl: 18px;
  --font-size-2xl: 20px;
  
  // 行高
  --line-height-tight: 1.25;
  --line-height-normal: 1.5;
  --line-height-relaxed: 1.75;
  
  // 过渡
  --transition-fast: 0.15s ease;
  --transition-normal: 0.3s ease;
  --transition-slow: 0.5s ease;
  
  // z-index
  --z-dropdown: 1000;
  --z-sticky: 1020;
  --z-fixed: 1030;
  --z-modal-backdrop: 1040;
  --z-modal: 1050;
  --z-popover: 1060;
  --z-tooltip: 1070;
}

// 暗色主题
[data-theme='dark'] {
  --text-primary: #e5eaf3;
  --text-regular: #cfd3dc;
  --text-secondary: #a3a6ad;
  --text-placeholder: #8d9095;
  
  --border-color: #4c4d4f;
  --border-color-light: #414243;
  --border-color-lighter: #363637;
  
  --bg-color: #141414;
  --bg-color-page: #0a0a0a;
  --bg-color-overlay: rgba(0, 0, 0, 0.8);
}
```

### 9.2 全局样式

```scss
// assets/styles/global.scss

// 引入变量
@import './variables.scss';
@import './mixins.scss';

// ============ 重置样式 ============
*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  font-size: 16px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: var(--font-size-md);
  line-height: var(--line-height-normal);
  color: var(--text-primary);
  background-color: var(--bg-color-page);
}

a {
  color: var(--primary-color);
  text-decoration: none;
  
  &:hover {
    color: var(--primary-color-light);
  }
}

img {
  max-width: 100%;
  height: auto;
}

// ============ 工具类 ============

// 文字截断
.text-ellipsis {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

// 多行截断
.text-ellipsis-2 {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

// Flex 布局
.flex {
  display: flex;
}

.flex-center {
  display: flex;
  align-items: center;
  justify-content: center;
}

.flex-between {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.flex-col {
  display: flex;
  flex-direction: column;
}

.flex-1 {
  flex: 1;
}

// 间距
.mt-sm { margin-top: var(--spacing-sm); }
.mt-md { margin-top: var(--spacing-md); }
.mt-lg { margin-top: var(--spacing-lg); }
.mb-sm { margin-bottom: var(--spacing-sm); }
.mb-md { margin-bottom: var(--spacing-md); }
.mb-lg { margin-bottom: var(--spacing-lg); }

// 文字对齐
.text-left { text-align: left; }
.text-center { text-align: center; }
.text-right { text-align: right; }

// 文字颜色
.text-primary { color: var(--text-primary); }
.text-secondary { color: var(--text-secondary); }
.text-success { color: var(--success-color); }
.text-warning { color: var(--warning-color); }
.text-danger { color: var(--danger-color); }

// 隐藏
.hidden { display: none !important; }
.invisible { visibility: hidden; }

// 滚动条样式
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-thumb {
  background-color: var(--border-color);
  border-radius: 3px;
  
  &:hover {
    background-color: var(--text-secondary);
  }
}

::-webkit-scrollbar-track {
  background-color: transparent;
}
```

---

## 10. 工程化配置

### 10.1 Vite 配置

```typescript
// vite.config.ts
import { defineConfig, loadEnv, type ConfigEnv, type UserConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueJsx from '@vitejs/plugin-vue-jsx'
import { resolve } from 'path'

// 自动导入
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

// 图标
import Icons from 'unplugin-icons/vite'
import IconsResolver from 'unplugin-icons/resolver'

// SVG
import { createSvgIconsPlugin } from 'vite-plugin-svg-icons'

// 压缩
import viteCompression from 'vite-plugin-compression'

// 分析
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig(({ command, mode }: ConfigEnv): UserConfig => {
  // 加载环境变量
  const env = loadEnv(mode, process.cwd())
  const { VITE_APP_ENV, VITE_API_BASE_URL, VITE_DROP_CONSOLE } = env

  const isBuild = command === 'build'
  const isProduction = mode === 'production'

  return {
    // 基础路径
    base: '/',

    // 路径别名
    resolve: {
      alias: {
        '@': resolve(__dirname, 'src'),
        '@/components': resolve(__dirname, 'src/components'),
        '@/utils': resolve(__dirname, 'src/utils'),
        '@/api': resolve(__dirname, 'src/api'),
        '@/stores': resolve(__dirname, 'src/stores'),
        '@/types': resolve(__dirname, 'src/types')
      }
    },

    // CSS 配置
    css: {
      preprocessorOptions: {
        scss: {
          additionalData: `
            @import "@/assets/styles/variables.scss";
            @import "@/assets/styles/mixins.scss";
          `
        }
      }
    },

    // 插件
    plugins: [
      vue(),
      vueJsx(),

      // 自动导入 API
      AutoImport({
        imports: [
          'vue',
          'vue-router',
          'pinia',
          '@vueuse/core'
        ],
        resolvers: [
          ElementPlusResolver(),
          IconsResolver({ prefix: 'Icon' })
        ],
        dts: 'src/types/auto-imports.d.ts',
        eslintrc: {
          enabled: true
        }
      }),

      // 自动导入组件
      Components({
        resolvers: [
          ElementPlusResolver(),
          IconsResolver({ enabledCollections: ['ep'] })
        ],
        dts: 'src/types/components.d.ts'
      }),

      // 图标
      Icons({
        autoInstall: true
      }),

      // SVG 图标
      createSvgIconsPlugin({
        iconDirs: [resolve(__dirname, 'src/assets/icons')],
        symbolId: 'icon-[dir]-[name]'
      }),

      // 生产环境压缩
      isBuild && viteCompression({
        verbose: true,
        disable: false,
        threshold: 10240,
        algorithm: 'gzip',
        ext: '.gz'
      }),

      // 打包分析
      isProduction && visualizer({
        open: true,
        gzipSize: true,
        brotliSize: true
      })
    ].filter(Boolean),

    // 开发服务器
    server: {
      host: '0.0.0.0',
      port: 3000,
      open: true,
      cors: true,
      proxy: {
        '/api': {
          target: VITE_API_BASE_URL,
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api/, '')
        }
      }
    },

    // 构建配置
    build: {
      target: 'es2015',
      outDir: 'dist',
      assetsDir: 'assets',
      sourcemap: !isProduction,
      minify: 'terser',
      terserOptions: {
        compress: {
          drop_console: VITE_DROP_CONSOLE === 'true',
          drop_debugger: true
        }
      },
      rollupOptions: {
        output: {
          // 分包策略
          manualChunks: {
            'vue-vendor': ['vue', 'vue-router', 'pinia'],
            'element-plus': ['element-plus'],
            'utils': ['axios', 'dayjs', '@vueuse/core']
          },
          // 文件名
          chunkFileNames: 'assets/js/[name]-[hash].js',
          entryFileNames: 'assets/js/[name]-[hash].js',
          assetFileNames: 'assets/[ext]/[name]-[hash].[ext]'
        }
      },
      // 块大小警告限制
      chunkSizeWarningLimit: 1000
    },

    // 优化依赖
    optimizeDeps: {
      include: [
        'vue',
        'vue-router',
        'pinia',
        'axios',
        'element-plus/es',
        '@vueuse/core'
      ]
    }
  }
})
```

### 10.2 ESLint 配置

```javascript
// .eslintrc.cjs
module.exports = {
  root: true,
  env: {
    browser: true,
    node: true,
    es2021: true
  },
  parser: 'vue-eslint-parser',
  parserOptions: {
    parser: '@typescript-eslint/parser',
    ecmaVersion: 'latest',
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true
    }
  },
  extends: [
    'eslint:recommended',
    'plugin:vue/vue3-recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:prettier/recommended'
  ],
  plugins: ['vue', '@typescript-eslint'],
  rules: {
    // Vue 规则
    'vue/multi-word-component-names': 'off',
    'vue/no-v-html': 'off',
    'vue/require-default-prop': 'off',
    'vue/require-explicit-emits': 'error',
    'vue/component-definition-name-casing': ['error', 'PascalCase'],
    'vue/prop-name-casing': ['error', 'camelCase'],
    'vue/v-on-event-hyphenation': ['error', 'always'],
    'vue/attribute-hyphenation': ['error', 'always'],
    
    // TypeScript 规则
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-non-null-assertion': 'off',
    '@typescript-eslint/ban-ts-comment': 'off',
    
    // 通用规则
    'no-console': process.env.NODE_ENV === 'production' ? 'warn' : 'off',
    'no-debugger': process.env.NODE_ENV === 'production' ? 'error' : 'off',
    'prefer-const': 'error',
    'no-var': 'error'
  },
  globals: {
    defineProps: 'readonly',
    defineEmits: 'readonly',
    defineExpose: 'readonly',
    withDefaults: 'readonly'
  }
}
```

### 10.3 Prettier 配置

```json
// .prettierrc
{
  "semi": false,
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "trailingComma": "none",
  "bracketSpacing": true,
  "arrowParens": "avoid",
  "endOfLine": "auto",
  "vueIndentScriptAndStyle": false,
  "htmlWhitespaceSensitivity": "ignore"
}
```

---

## 11. 性能优化

### 11.1 组件优化

```typescript
// ============ 1. 路由懒加载 ============
// ❌ 不好：同步导入
import UserList from '@/views/user/list.vue'

// ✅ 好：懒加载
const UserList = () => import('@/views/user/list.vue')

// ============ 2. 异步组件 ============
import { defineAsyncComponent } from 'vue'

// 基础用法
const AsyncComponent = defineAsyncComponent(() => 
  import('./HeavyComponent.vue')
)

// 带加载和错误状态
const AsyncComponentWithOptions = defineAsyncComponent({
  loader: () => import('./HeavyComponent.vue'),
  loadingComponent: LoadingSpinner,
  errorComponent: ErrorComponent,
  delay: 200,  // 延迟显示 loading
  timeout: 10000  // 超时时间
})

// ============ 3. v-memo 缓存 ============
<template>
  <!-- 只有当 item.id 或 selected 变化时才重新渲染 -->
  <div v-for="item in list" :key="item.id" v-memo="[item.id, selected === item.id]">
    <p>{{ item.name }}</p>
    <p>{{ selected === item.id ? '选中' : '未选中' }}</p>
  </div>
</template>

// ============ 4. v-once 静态内容 ============
<template>
  <!-- 只渲染一次，后续不再更新 -->
  <div v-once>
    <h1>{{ title }}</h1>
    <p>这是静态内容，不会变化</p>
  </div>
</template>

// ============ 5. shallowRef / shallowReactive ============
import { shallowRef, shallowReactive } from 'vue'

// 大型数据使用浅层响应式
const bigList = shallowRef<Item[]>([])

// 更新时需要替换整个数组
bigList.value = [...bigList.value, newItem]

// ============ 6. computed 缓存 ============
// ❌ 不好：在模板中计算
<template>
  <div>{{ items.filter(i => i.active).length }}</div>
</template>

// ✅ 好：使用 computed
const activeCount = computed(() => items.value.filter(i => i.active).length)
<template>
  <div>{{ activeCount }}</div>
</template>

// ============ 7. 虚拟列表 ============
// 使用 vue-virtual-scroller 处理大量数据
import { RecycleScroller } from 'vue-virtual-scroller'
import 'vue-virtual-scroller/dist/vue-virtual-scroller.css'

<template>
  <RecycleScroller
    class="scroller"
    :items="items"
    :item-size="50"
    key-field="id"
    v-slot="{ item }"
  >
    <div class="item">{{ item.name }}</div>
  </RecycleScroller>
</template>

// ============ 8. KeepAlive 缓存 ============
<template>
  <router-view v-slot="{ Component }">
    <keep-alive :include="cachedViews" :max="10">
      <component :is="Component" :key="route.fullPath" />
    </keep-alive>
  </router-view>
</template>

<script setup>
const cachedViews = ref(['UserList', 'OrderList'])
</script>
```

### 11.2 打包优化

```typescript
// vite.config.ts 打包优化

export default defineConfig({
  build: {
    // 分包策略
    rollupOptions: {
      output: {
        manualChunks(id) {
          // node_modules 分包
          if (id.includes('node_modules')) {
            // Vue 相关
            if (id.includes('vue') || id.includes('pinia') || id.includes('vue-router')) {
              return 'vue-vendor'
            }
            // UI 框架
            if (id.includes('element-plus')) {
              return 'element-plus'
            }
            // 工具库
            if (id.includes('lodash') || id.includes('dayjs') || id.includes('axios')) {
              return 'utils'
            }
            // 图表库
            if (id.includes('echarts')) {
              return 'echarts'
            }
            // 其他
            return 'vendor'
          }
        }
      }
    },
    
    // 压缩配置
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
        pure_funcs: ['console.log', 'console.info']
      }
    },
    
    // CSS 代码分割
    cssCodeSplit: true,
    
    // 资源内联阈值
    assetsInlineLimit: 4096
  }
})
```

### 11.3 图片优化

```typescript
// 1. 使用 WebP 格式
<template>
  <picture>
    <source srcset="/image.webp" type="image/webp">
    <img src="/image.jpg" alt="description">
  </picture>
</template>

// 2. 懒加载图片
<template>
  <img v-lazy="imageUrl" alt="description">
</template>

// 3. 响应式图片
<template>
  <img
    :src="image.small"
    :srcset="`${image.small} 400w, ${image.medium} 800w, ${image.large} 1200w`"
    sizes="(max-width: 400px) 400px, (max-width: 800px) 800px, 1200px"
    alt="description"
  >
</template>

// 4. 使用 vite-imagetools 优化
// pnpm add -D vite-imagetools
import { imagetools } from 'vite-imagetools'

export default defineConfig({
  plugins: [
    imagetools()
  ]
})

// 使用
import heroImage from './hero.jpg?w=800&format=webp'
```

---

## 12. 安全规范

### 12.1 XSS 防护

```typescript
// ❌ 危险：直接使用 v-html
<div v-html="userInput"></div>

// ✅ 安全：使用文本插值
<div>{{ userInput }}</div>

// ✅ 如果必须使用 v-html，先进行消毒
import DOMPurify from 'dompurify'

const sanitizedHtml = computed(() => {
  return DOMPurify.sanitize(userInput.value)
})

<div v-html="sanitizedHtml"></div>

// ✅ 使用 CSP（Content Security Policy）
// 在 index.html 中添加
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
```

### 12.2 敏感数据处理

```typescript
// ❌ 不好：在前端存储敏感信息
localStorage.setItem('password', password)
localStorage.setItem('creditCard', cardNumber)

// ✅ 好：只存储 token，敏感操作在后端处理
localStorage.setItem('token', token)

// ✅ 使用 httpOnly cookie 存储 token（更安全）
// 后端设置：Set-Cookie: token=xxx; HttpOnly; Secure; SameSite=Strict

// ✅ 敏感数据脱敏显示
function maskPhone(phone: string): string {
  return phone.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2')
}

function maskEmail(email: string): string {
  const [name, domain] = email.split('@')
  return `${name.slice(0, 2)}***@${domain}`
}

function maskIdCard(idCard: string): string {
  return idCard.replace(/(\d{4})\d{10}(\d{4})/, '$1**********$2')
}
```

### 12.3 请求安全

```typescript
// 1. CSRF 防护
// 在请求头中添加 CSRF Token
service.interceptors.request.use(config => {
  const csrfToken = getCookie('XSRF-TOKEN')
  if (csrfToken) {
    config.headers['X-XSRF-TOKEN'] = csrfToken
  }
  return config
})

// 2. 防止重复提交
const isSubmitting = ref(false)

async function handleSubmit() {
  if (isSubmitting.value) return
  
  isSubmitting.value = true
  try {
    await api.submit(data)
  } finally {
    isSubmitting.value = false
  }
}

// 3. 请求签名（防篡改）
function signRequest(params: Record<string, any>, secret: string): string {
  const sortedKeys = Object.keys(params).sort()
  const str = sortedKeys.map(key => `${key}=${params[key]}`).join('&')
  return md5(str + secret)
}

// 4. 敏感接口限流
import { useDebounceFn, useThrottleFn } from '@vueuse/core'

const debouncedSearch = useDebounceFn(search, 300)
const throttledSubmit = useThrottleFn(submit, 1000)
```

---

## 13. 测试规范

### 13.1 单元测试

```typescript
// 使用 Vitest 进行单元测试
// pnpm add -D vitest @vue/test-utils happy-dom

// vitest.config.ts
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'happy-dom',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html']
    }
  }
})

// 测试工具函数
// utils/__tests__/format.test.ts
import { describe, it, expect } from 'vitest'
import { formatDate, formatMoney } from '../format'

describe('formatDate', () => {
  it('should format date correctly', () => {
    const date = new Date('2024-01-15T10:30:00')
    expect(formatDate(date)).toBe('2024-01-15')
    expect(formatDate(date, 'YYYY-MM-DD HH:mm')).toBe('2024-01-15 10:30')
  })

  it('should return empty string for invalid date', () => {
    expect(formatDate(null)).toBe('')
    expect(formatDate(undefined)).toBe('')
  })
})

describe('formatMoney', () => {
  it('should format money with default options', () => {
    expect(formatMoney(1234.5)).toBe('¥1,234.50')
    expect(formatMoney(1000000)).toBe('¥1,000,000.00')
  })

  it('should handle zero and negative numbers', () => {
    expect(formatMoney(0)).toBe('¥0.00')
    expect(formatMoney(-100)).toBe('-¥100.00')
  })
})

// 测试组件
// components/__tests__/BaseButton.test.ts
import { describe, it, expect, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import BaseButton from '../base/BaseButton.vue'

describe('BaseButton', () => {
  it('renders slot content', () => {
    const wrapper = mount(BaseButton, {
      slots: {
        default: '点击我'
      }
    })
    expect(wrapper.text()).toBe('点击我')
  })

  it('emits click event', async () => {
    const wrapper = mount(BaseButton)
    await wrapper.trigger('click')
    expect(wrapper.emitted('click')).toBeTruthy()
  })

  it('is disabled when disabled prop is true', () => {
    const wrapper = mount(BaseButton, {
      props: { disabled: true }
    })
    expect(wrapper.attributes('disabled')).toBeDefined()
  })

  it('shows loading state', () => {
    const wrapper = mount(BaseButton, {
      props: { loading: true }
    })
    expect(wrapper.find('.loading-icon').exists()).toBe(true)
  })
})

// 测试 Composable
// composables/__tests__/useRequest.test.ts
import { describe, it, expect, vi } from 'vitest'
import { useRequest } from '../useRequest'

describe('useRequest', () => {
  it('should fetch data successfully', async () => {
    const mockData = { id: 1, name: 'Test' }
    const fetcher = vi.fn().mockResolvedValue(mockData)

    const { data, loading, execute } = useRequest(fetcher, { immediate: false })

    expect(loading.value).toBe(false)
    expect(data.value).toBe(null)

    await execute()

    expect(fetcher).toHaveBeenCalled()
    expect(data.value).toEqual(mockData)
    expect(loading.value).toBe(false)
  })

  it('should handle error', async () => {
    const error = new Error('Network error')
    const fetcher = vi.fn().mockRejectedValue(error)

    const { error: errorRef, execute } = useRequest(fetcher, { immediate: false })

    await execute()

    expect(errorRef.value).toEqual(error)
  })
})
```

---

## 14. Git 规范

### 14.1 Commit 规范

```bash
# Commit 格式
<type>(<scope>): <subject>

<body>

<footer>

# type 类型
feat:     新功能
fix:      修复 bug
docs:     文档更新
style:    代码格式（不影响功能）
refactor: 重构（不是新功能也不是修复 bug）
perf:     性能优化
test:     测试相关
build:    构建系统或外部依赖变更
ci:       CI 配置变更
chore:    其他修改
revert:   回滚

# 示例
feat(user): 添加用户登录功能
fix(order): 修复订单金额计算错误
docs(readme): 更新安装说明
style(button): 调整按钮样式
refactor(api): 重构请求封装
perf(list): 优化列表渲染性能
test(utils): 添加工具函数测试
```

### 14.2 Husky + lint-staged 配置

```bash
# 安装
pnpm add -D husky lint-staged @commitlint/cli @commitlint/config-conventional

# 初始化 husky
npx husky install

# 添加 pre-commit hook
npx husky add .husky/pre-commit "npx lint-staged"

# 添加 commit-msg hook
npx husky add .husky/commit-msg "npx --no -- commitlint --edit $1"
```

```json
// package.json
{
  "scripts": {
    "prepare": "husky install"
  },
  "lint-staged": {
    "*.{js,jsx,ts,tsx,vue}": [
      "eslint --fix",
      "prettier --write"
    ],
    "*.{css,scss,less}": [
      "stylelint --fix",
      "prettier --write"
    ],
    "*.{json,md}": [
      "prettier --write"
    ]
  }
}
```

```javascript
// commitlint.config.cjs
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'style', 'refactor', 'perf', 'test', 'build', 'ci', 'chore', 'revert']
    ],
    'subject-case': [0],
    'subject-max-length': [2, 'always', 100]
  }
}
```

### 14.3 分支管理

```
┌─────────────────────────────────────────────────────────────────────┐
│ Git 分支管理规范                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ main/master    - 主分支，生产环境代码                                │
│ develop        - 开发分支，最新开发代码                              │
│ feature/*      - 功能分支，开发新功能                                │
│ bugfix/*       - 修复分支，修复 bug                                  │
│ hotfix/*       - 热修复分支，紧急修复生产问题                        │
│ release/*      - 发布分支，准备发布                                  │
│                                                                      │
│ 分支命名示例:                                                        │
│ feature/user-login                                                  │
│ feature/order-export                                                │
│ bugfix/login-error                                                  │
│ hotfix/payment-crash                                                │
│ release/v1.2.0                                                      │
│                                                                      │
│ 工作流程:                                                            │
│ 1. 从 develop 创建 feature 分支                                     │
│ 2. 开发完成后提交 PR 到 develop                                     │
│ 3. Code Review 通过后合并                                           │
│ 4. 发布时从 develop 创建 release 分支                               │
│ 5. 测试通过后合并到 main 和 develop                                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 15. 企业级开发踩坑与常见错误

### 15.1 响应式相关

```typescript
// ❌ 坑 1：解构 reactive 对象丢失响应性
const state = reactive({ count: 0, name: 'test' })
const { count } = state  // count 不是响应式的！

// ✅ 解决方案
const { count } = toRefs(state)  // 使用 toRefs
const count = toRef(state, 'count')  // 或 toRef

// ❌ 坑 2：直接替换 reactive 对象
let state = reactive({ list: [] })
state = reactive({ list: [1, 2, 3] })  // 丢失响应性！

// ✅ 解决方案
const state = reactive({ list: [] })
state.list = [1, 2, 3]  // 修改属性而不是替换对象
// 或使用 ref
const state = ref({ list: [] })
state.value = { list: [1, 2, 3] }  // ref 可以整体替换

// ❌ 坑 3：在 setup 外部访问响应式数据
const count = ref(0)
console.log(count)  // 输出 RefImpl 对象，不是值

// ✅ 解决方案
console.log(count.value)  // 使用 .value

// ❌ 坑 4：异步操作后响应式丢失
const { data } = await useAsyncData()  // data 可能不是响应式的

// ✅ 解决方案
const result = await useAsyncData()
const data = toRef(result, 'data')

// ❌ 坑 5：watch 监听 reactive 对象的属性
const state = reactive({ user: { name: 'test' } })
watch(state.user, () => {})  // 不会触发！

// ✅ 解决方案
watch(() => state.user, () => {}, { deep: true })  // 使用 getter
watch(() => state.user.name, () => {})  // 监听具体属性
```

### 15.2 组件相关

```typescript
// ❌ 坑 1：v-if 和 v-for 同时使用
<li v-for="item in items" v-if="item.active" :key="item.id">

// ✅ 解决方案
// 方案 1：使用计算属性
const activeItems = computed(() => items.filter(i => i.active))
<li v-for="item in activeItems" :key="item.id">

// 方案 2：使用 template
<template v-for="item in items" :key="item.id">
  <li v-if="item.active">{{ item.name }}</li>
</template>

// ❌ 坑 2：组件 key 使用 index
<Component v-for="(item, index) in items" :key="index" />
// 当列表顺序变化时，组件不会正确更新

// ✅ 解决方案
<Component v-for="item in items" :key="item.id" />

// ❌ 坑 3：修改 props
const props = defineProps<{ value: string }>()
props.value = 'new value'  // 错误！props 是只读的

// ✅ 解决方案
const emit = defineEmits<{ (e: 'update:value', v: string): void }>()
emit('update:value', 'new value')

// ❌ 坑 4：在 v-for 中使用 ref
<div v-for="item in items" :key="item.id" ref="itemRefs">
// itemRefs 会是一个数组，但可能不是你期望的顺序

// ✅ 解决方案
const itemRefs = ref<HTMLElement[]>([])
const setItemRef = (el: HTMLElement | null, index: number) => {
  if (el) itemRefs.value[index] = el
}
<div v-for="(item, index) in items" :key="item.id" :ref="el => setItemRef(el, index)">

// ❌ 坑 5：异步组件错误处理
const AsyncComp = defineAsyncComponent(() => import('./Comp.vue'))
// 如果加载失败，没有错误处理

// ✅ 解决方案
const AsyncComp = defineAsyncComponent({
  loader: () => import('./Comp.vue'),
  loadingComponent: Loading,
  errorComponent: Error,
  delay: 200,
  timeout: 10000,
  onError(error, retry, fail, attempts) {
    if (attempts <= 3) {
      retry()
    } else {
      fail()
    }
  }
})
```

### 15.3 TypeScript 相关

```typescript
// ❌ 坑 1：类型推断失败
const user = ref(null)  // 类型是 Ref<null>
user.value = { name: 'test' }  // 类型错误！

// ✅ 解决方案
const user = ref<User | null>(null)

// ❌ 坑 2：泛型组件类型丢失
// 父组件
<ChildComponent ref="childRef" />
const childRef = ref()  // 类型是 any

// ✅ 解决方案
import type { ComponentExposed } from 'vue-component-type-helpers'
// 或
const childRef = ref<InstanceType<typeof ChildComponent>>()

// ❌ 坑 3：事件处理器类型
<input @input="handleInput" />
const handleInput = (e) => {  // e 是 any
  console.log(e.target.value)
}

// ✅ 解决方案
const handleInput = (e: Event) => {
  const target = e.target as HTMLInputElement
  console.log(target.value)
}

// ❌ 坑 4：可选链和空值合并
const name = user?.name ?? 'default'  // 如果 name 是空字符串，不会使用默认值

// ✅ 解决方案
const name = user?.name || 'default'  // 空字符串也会使用默认值
// 或根据业务需求选择

// ❌ 坑 5：枚举的坑
enum Status {
  Active,   // 0
  Inactive  // 1
}
// 数字枚举可以反向映射，可能导致意外行为

// ✅ 解决方案：使用字符串枚举
enum Status {
  Active = 'active',
  Inactive = 'inactive'
}
// 或使用 const 对象
const Status = {
  Active: 'active',
  Inactive: 'inactive'
} as const
```

### 15.4 路由相关

```typescript
// ❌ 坑 1：路由守卫中的异步操作
router.beforeEach(async (to, from, next) => {
  const user = await fetchUser()  // 如果这里抛错
  next()  // next 不会被调用，导致路由卡住
})

// ✅ 解决方案
router.beforeEach(async (to, from, next) => {
  try {
    const user = await fetchUser()
    next()
  } catch (error) {
    next('/login')  // 确保 next 总是被调用
  }
})

// ❌ 坑 2：动态路由添加后不生效
router.addRoute(newRoute)
router.push('/new-path')  // 可能 404

// ✅ 解决方案
router.addRoute(newRoute)
// 使用 replace 重新导航
router.replace(router.currentRoute.value.fullPath)

// ❌ 坑 3：路由参数类型
// route.params.id 是 string | string[]
const id = route.params.id
const user = await getUser(id)  // 类型错误

// ✅ 解决方案
const id = Array.isArray(route.params.id) 
  ? route.params.id[0] 
  : route.params.id
// 或
const id = route.params.id as string

// ❌ 坑 4：路由 meta 类型
// route.meta 默认是 RouteMeta，没有自定义属性

// ✅ 解决方案：扩展类型
// types/router.d.ts
import 'vue-router'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    icon?: string
    roles?: string[]
    keepAlive?: boolean
  }
}

// ❌ 坑 5：路由组件缓存问题
<keep-alive>
  <router-view />
</keep-alive>
// 所有路由都会被缓存

// ✅ 解决方案
<router-view v-slot="{ Component }">
  <keep-alive :include="cachedViews">
    <component :is="Component" :key="route.fullPath" />
  </keep-alive>
</router-view>
```

### 15.5 状态管理相关

```typescript
// ❌ 坑 1：在 setup 外使用 store
// utils/auth.ts
import { useUserStore } from '@/stores'
const userStore = useUserStore()  // 错误！Pinia 还没初始化

// ✅ 解决方案
export function getToken() {
  const userStore = useUserStore()  // 在函数内部调用
  return userStore.token
}

// ❌ 坑 2：解构 store 丢失响应性
const userStore = useUserStore()
const { username, isLoggedIn } = userStore  // 不是响应式的！

// ✅ 解决方案
const { username, isLoggedIn } = storeToRefs(userStore)
// 注意：actions 不需要 storeToRefs
const { login, logout } = userStore

// ❌ 坑 3：在 action 中使用 this
export const useUserStore = defineStore('user', {
  actions: {
    async login() {
      this.loading = true  // 在 Options API 中可以
    }
  }
})

// ✅ 在 Setup Store 中
export const useUserStore = defineStore('user', () => {
  const loading = ref(false)
  
  async function login() {
    loading.value = true  // 直接使用变量
  }
  
  return { loading, login }
})

// ❌ 坑 4：store 持久化后类型丢失
// 从 localStorage 恢复的数据可能类型不对

// ✅ 解决方案：添加类型转换
persist: {
  afterRestore: (ctx) => {
    // 恢复后进行类型转换
    if (ctx.store.userInfo) {
      ctx.store.userInfo.createdAt = new Date(ctx.store.userInfo.createdAt)
    }
  }
}
```

### 15.6 请求相关

```typescript
// ❌ 坑 1：请求取消不生效
const controller = new AbortController()
axios.get('/api/data', { signal: controller.signal })
controller.abort()  // 可能不生效

// ✅ 解决方案
const controller = new AbortController()
const { signal } = controller

axios.get('/api/data', { signal }).catch(error => {
  if (axios.isCancel(error)) {
    console.log('请求已取消')
  }
})

// 组件卸载时取消
onUnmounted(() => {
  controller.abort()
})

// ❌ 坑 2：并发请求竞态条件
let currentId = 1
async function fetchData(id: number) {
  currentId = id
  const data = await api.getData(id)
  // 如果快速切换 id，可能显示旧数据
  setData(data)
}

// ✅ 解决方案
let currentId = 1
async function fetchData(id: number) {
  currentId = id
  const data = await api.getData(id)
  // 检查是否是最新请求
  if (id === currentId) {
    setData(data)
  }
}

// 或使用 AbortController
let controller: AbortController | null = null
async function fetchData(id: number) {
  controller?.abort()
  controller = new AbortController()
  
  try {
    const data = await api.getData(id, { signal: controller.signal })
    setData(data)
  } catch (error) {
    if (!axios.isCancel(error)) {
      throw error
    }
  }
}

// ❌ 坑 3：Token 刷新竞态
// 多个请求同时发现 token 过期，都去刷新

// ✅ 解决方案：使用锁
let isRefreshing = false
let refreshSubscribers: ((token: string) => void)[] = []

function subscribeTokenRefresh(cb: (token: string) => void) {
  refreshSubscribers.push(cb)
}

function onTokenRefreshed(token: string) {
  refreshSubscribers.forEach(cb => cb(token))
  refreshSubscribers = []
}

axios.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      if (!isRefreshing) {
        isRefreshing = true
        try {
          const { token } = await refreshToken()
          setToken(token)
          onTokenRefreshed(token)
        } finally {
          isRefreshing = false
        }
      }
      
      return new Promise(resolve => {
        subscribeTokenRefresh(token => {
          error.config.headers.Authorization = `Bearer ${token}`
          resolve(axios(error.config))
        })
      })
    }
    return Promise.reject(error)
  }
)
```

### 15.7 性能相关

```typescript
// ❌ 坑 1：大量数据导致页面卡顿
const items = ref<Item[]>([])  // 10000+ 条数据
// 直接渲染会很卡

// ✅ 解决方案
// 1. 使用虚拟列表
import { RecycleScroller } from 'vue-virtual-scroller'

// 2. 使用分页
// 3. 使用 shallowRef
const items = shallowRef<Item[]>([])

// ❌ 坑 2：频繁触发 watch
watch(searchText, async (val) => {
  const result = await search(val)  // 每次输入都请求
})

// ✅ 解决方案：防抖
import { watchDebounced } from '@vueuse/core'

watchDebounced(searchText, async (val) => {
  const result = await search(val)
}, { debounce: 300 })

// ❌ 坑 3：computed 中有副作用
const filteredItems = computed(() => {
  console.log('filtering...')  // 副作用
  api.log('filter')  // 副作用
  return items.value.filter(i => i.active)
})

// ✅ 解决方案：computed 应该是纯函数
const filteredItems = computed(() => {
  return items.value.filter(i => i.active)
})

// 副作用放在 watch 中
watch(filteredItems, (items) => {
  console.log('filtered:', items.length)
})

// ❌ 坑 4：不必要的响应式
const config = reactive({
  apiUrl: 'https://api.example.com',
  timeout: 5000
})  // 这些值永远不会变，不需要响应式

// ✅ 解决方案
const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000
} as const

// ❌ 坑 5：内存泄漏
onMounted(() => {
  window.addEventListener('resize', handleResize)
  setInterval(fetchData, 5000)
})
// 组件卸载后，事件监听和定时器还在

// ✅ 解决方案
onMounted(() => {
  window.addEventListener('resize', handleResize)
  const timer = setInterval(fetchData, 5000)
  
  onUnmounted(() => {
    window.removeEventListener('resize', handleResize)
    clearInterval(timer)
  })
})

// 或使用 @vueuse/core
import { useEventListener, useIntervalFn } from '@vueuse/core'

useEventListener(window, 'resize', handleResize)  // 自动清理
useIntervalFn(fetchData, 5000)  // 自动清理
```

### 15.8 常见错误速查表

```
┌─────────────────────────────────────────────────────────────────────┐
│ Vue3 + TypeScript 常见错误速查表                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ 错误现象                    │ 可能原因                │ 解决方案    │
│─────────────────────────────┼────────────────────────┼─────────────│
│ 数据不更新                  │ 解构丢失响应性         │ toRefs      │
│ 数据不更新                  │ 替换了 reactive 对象   │ 修改属性    │
│ 类型错误                    │ ref 没有指定泛型       │ ref<T>()    │
│ 组件不更新                  │ key 使用 index         │ 使用唯一 ID │
│ 路由卡住                    │ next() 未调用          │ try-catch   │
│ Store 报错                  │ 在 setup 外使用        │ 函数内调用  │
│ 请求重复                    │ 没有取消旧请求         │ AbortController│
│ 内存泄漏                    │ 未清理监听器/定时器    │ onUnmounted │
│ 页面卡顿                    │ 大量数据直接渲染       │ 虚拟列表    │
│ 样式不生效                  │ scoped 样式穿透问题    │ :deep()     │
│ 打包体积大                  │ 没有按需导入           │ 自动导入    │
│ HMR 不生效                  │ 文件路径大小写问题     │ 统一大小写  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 附录

### A. 推荐的 VSCode 插件

```
必装插件:
• Vue - Official (Volar)
• ESLint
• Prettier
• TypeScript Vue Plugin

推荐插件:
• Auto Rename Tag
• Path Intellisense
• GitLens
• Error Lens
• Code Spell Checker
• i18n Ally
• Iconify IntelliSense
```

### B. 常用命令

```bash
# 开发
pnpm dev              # 启动开发服务器
pnpm build            # 构建生产版本
pnpm preview          # 预览构建结果

# 代码检查
pnpm lint             # ESLint 检查
pnpm lint:fix         # ESLint 自动修复
pnpm format           # Prettier 格式化
pnpm type-check       # TypeScript 类型检查

# 测试
pnpm test             # 运行测试
pnpm test:coverage    # 测试覆盖率

# 其他
pnpm deps:update      # 更新依赖
pnpm analyze          # 打包分析
```

### C. 相关资源

```
官方文档:
• Vue 3: https://vuejs.org/
• Vite: https://vitejs.dev/
• Pinia: https://pinia.vuejs.org/
• Vue Router: https://router.vuejs.org/
• VueUse: https://vueuse.org/

UI 框架:
• Element Plus: https://element-plus.org/
• Ant Design Vue: https://antdv.com/
• Naive UI: https://www.naiveui.com/

工具库:
• VueUse: https://vueuse.org/
• unplugin-auto-import: https://github.com/antfu/unplugin-auto-import
• unplugin-vue-components: https://github.com/antfu/unplugin-vue-components
```

---

> 最后更新: 2025年1月
> 
> 这份规范是团队协作的基础，但不是一成不变的。随着项目发展和技术更新，规范也需要不断迭代。最重要的是团队达成共识，保持代码风格一致。祝你的项目开发顺利！
