

> Axios 是一个基于 Promise 的 HTTP 客户端，可用于浏览器和 Node.js
> 本笔记基于 Vue 3 + TypeScript + Vite，从基础到进阶全面讲解 Axios 封装

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与基本使用](#2-安装与基本使用)
3. [创建 Axios 实例](#3-创建-axios-实例)
4. [请求拦截器](#4-请求拦截器)
5. [响应拦截器](#5-响应拦截器)
6. [错误统一处理](#6-错误统一处理)
7. [TypeScript 类型定义](#7-typescript-类型定义)
8. [请求封装与 API 模块化](#8-请求封装与-api-模块化)
9. [高级功能](#9-高级功能)
10. [完整封装示例](#10-完整封装示例)
11. [常见错误与解决方案](#11-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Axios？

Axios 是一个基于 Promise 的 HTTP 客户端，具有以下特点：

- **浏览器和 Node.js 通用**：同一套代码可以在两个环境中运行
- **支持 Promise API**：可以使用 async/await 语法
- **请求和响应拦截**：可以在请求发送前和响应返回后进行统一处理
- **自动转换 JSON 数据**：请求和响应数据自动序列化/反序列化
- **客户端支持防御 XSRF**：内置安全机制
- **取消请求**：支持取消正在进行的请求

### 1.2 为什么要封装 Axios？

直接使用 Axios 存在以下问题：

1. **代码重复**：每次请求都要写相同的配置（baseURL、headers 等）
2. **错误处理分散**：每个请求都要单独处理错误
3. **难以维护**：修改配置需要改动多处代码
4. **缺乏统一规范**：团队成员可能写出风格不一的代码

封装后的好处：

- ✅ 统一配置管理
- ✅ 统一错误处理
- ✅ 统一 loading 状态管理
- ✅ 统一 token 处理
- ✅ 便于维护和扩展


### 1.3 Axios 请求流程

```
发起请求 → 请求拦截器 → 服务器 → 响应拦截器 → 业务代码
                ↓                      ↓
           添加 token              统一错误处理
           添加 loading            数据转换
           参数序列化              取消 loading
```

理解这个流程非常重要，它决定了我们在哪个环节做什么事情。

---

## 2. 安装与基本使用

### 2.1 安装 Axios

```bash
# npm
npm install axios

# yarn
yarn add axios

# pnpm
pnpm add axios
```

### 2.2 最基本的使用方式

在封装之前，先看看 Axios 最原始的用法：

```typescript
import axios from 'axios'

// GET 请求
axios.get('https://api.example.com/users')
  .then(response => {
    console.log(response.data)
  })
  .catch(error => {
    console.error(error)
  })

// POST 请求
axios.post('https://api.example.com/users', {
  name: '张三',
  age: 25
})
  .then(response => {
    console.log(response.data)
  })
  .catch(error => {
    console.error(error)
  })
```

### 2.3 使用 async/await 语法

```typescript
import axios from 'axios'

async function getUsers() {
  try {
    const response = await axios.get('https://api.example.com/users')
    console.log(response.data)
  } catch (error) {
    console.error(error)
  }
}
```

> 💡 **注意**：直接使用 axios 会有很多重复代码，这就是为什么我们需要封装。


---

## 3. 创建 Axios 实例

### 3.1 为什么要创建实例？

使用 `axios.create()` 创建实例的好处：

1. **隔离配置**：不同的 API 可以有不同的配置
2. **避免污染全局**：不会影响其他地方使用的 axios
3. **便于管理**：可以创建多个实例对应不同的后端服务

### 3.2 基础实例创建

在 `src/utils/request.ts` 中创建：

```typescript
import axios, { type AxiosInstance } from 'axios'

// 创建 axios 实例
const service: AxiosInstance = axios.create({
  // 基础 URL，所有请求都会拼接这个前缀
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  
  // 请求超时时间（毫秒）
  timeout: 10000,
  
  // 请求头配置
  headers: {
    'Content-Type': 'application/json;charset=UTF-8'
  }
})

export default service
```

### 3.3 环境变量配置

在项目根目录创建环境变量文件：

`.env.development`（开发环境）：
```bash
VITE_API_BASE_URL=http://localhost:3000/api
```

`.env.production`（生产环境）：
```bash
VITE_API_BASE_URL=https://api.example.com
```

### 3.4 常用配置项详解

```typescript
const service = axios.create({
  // 基础 URL
  baseURL: '/api',
  
  // 超时时间
  timeout: 10000,
  
  // 请求头
  headers: {
    'Content-Type': 'application/json'
  },
  
  // 跨域请求时是否携带 cookie
  withCredentials: true,
  
  // 响应数据类型：'arraybuffer', 'blob', 'document', 'json', 'text', 'stream'
  responseType: 'json',
  
  // 定义对于给定的 HTTP 响应状态码是 resolve 还是 reject
  // 默认情况下，状态码在 2xx 范围内才会 resolve
  validateStatus: function (status) {
    return status >= 200 && status < 300
  }
})
```

> 💡 **提示**：`withCredentials: true` 在跨域请求时非常重要，如果后端需要 cookie 认证，必须开启此选项。


---

## 4. 请求拦截器

### 4.1 什么是请求拦截器？

请求拦截器在请求发送到服务器**之前**执行，常用于：

- 添加 token 到请求头
- 添加全局 loading
- 参数序列化处理
- 请求日志记录

### 4.2 基础请求拦截器

```typescript
import axios from 'axios'

const service = axios.create({
  baseURL: '/api',
  timeout: 10000
})

// 请求拦截器
service.interceptors.request.use(
  (config) => {
    // 在发送请求之前做些什么
    console.log('请求发送前:', config)
    return config
  },
  (error) => {
    // 对请求错误做些什么
    console.error('请求错误:', error)
    return Promise.reject(error)
  }
)
```

### 4.3 添加 Token 认证

```typescript
import { useUserStore } from '@/stores/user'

service.interceptors.request.use(
  (config) => {
    // 从 Pinia store 获取 token
    const userStore = useUserStore()
    const token = userStore.token
    
    // 如果 token 存在，添加到请求头
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)
```

### 4.4 添加全局 Loading

```typescript
import { ElLoading } from 'element-plus'

let loadingInstance: ReturnType<typeof ElLoading.service> | null = null
let requestCount = 0 // 请求计数器，处理并发请求

service.interceptors.request.use(
  (config) => {
    requestCount++
    
    // 只在第一个请求时显示 loading
    if (requestCount === 1) {
      loadingInstance = ElLoading.service({
        lock: true,
        text: '加载中...',
        background: 'rgba(0, 0, 0, 0.7)'
      })
    }
    
    return config
  },
  (error) => {
    requestCount--
    return Promise.reject(error)
  }
)
```

> 💡 **为什么需要请求计数器？** 当同时发起多个请求时，我们只想显示一个 loading，而不是每个请求都显示一个。计数器确保只有所有请求都完成后才关闭 loading。

### 4.5 请求参数处理

```typescript
import qs from 'qs'

service.interceptors.request.use(
  (config) => {
    // GET 请求参数序列化（处理数组参数）
    if (config.method?.toLowerCase() === 'get' && config.params) {
      config.paramsSerializer = {
        serialize: (params) => qs.stringify(params, { arrayFormat: 'repeat' })
      }
    }
    
    // POST 请求：如果是 FormData，修改 Content-Type
    if (config.data instanceof FormData) {
      config.headers['Content-Type'] = 'multipart/form-data'
    }
    
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)
```


---

## 5. 响应拦截器

### 5.1 什么是响应拦截器？

响应拦截器在服务器响应返回**之后**、业务代码处理**之前**执行，常用于：

- 统一处理响应数据格式
- 统一处理错误状态码
- 关闭全局 loading
- Token 过期处理

### 5.2 基础响应拦截器

```typescript
service.interceptors.response.use(
  (response) => {
    // 对响应数据做点什么
    console.log('响应成功:', response)
    return response
  },
  (error) => {
    // 对响应错误做点什么
    console.error('响应错误:', error)
    return Promise.reject(error)
  }
)
```

### 5.3 统一处理响应数据

假设后端返回的数据格式为：

```json
{
  "code": 200,
  "message": "success",
  "data": { ... }
}
```

我们可以在拦截器中统一处理：

```typescript
import { ElMessage } from 'element-plus'

// 定义响应数据接口
interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

service.interceptors.response.use(
  (response) => {
    const res = response.data as ApiResponse
    
    // 根据业务状态码判断请求是否成功
    if (res.code === 200) {
      // 成功：直接返回数据部分
      return res.data
    } else {
      // 业务错误：显示错误信息
      ElMessage.error(res.message || '请求失败')
      return Promise.reject(new Error(res.message || '请求失败'))
    }
  },
  (error) => {
    return Promise.reject(error)
  }
)
```

### 5.4 关闭 Loading

```typescript
service.interceptors.response.use(
  (response) => {
    requestCount--
    
    // 所有请求完成后关闭 loading
    if (requestCount === 0 && loadingInstance) {
      loadingInstance.close()
      loadingInstance = null
    }
    
    return response.data
  },
  (error) => {
    requestCount--
    
    if (requestCount === 0 && loadingInstance) {
      loadingInstance.close()
      loadingInstance = null
    }
    
    return Promise.reject(error)
  }
)
```

### 5.5 Token 过期处理

```typescript
import router from '@/router'
import { useUserStore } from '@/stores/user'

service.interceptors.response.use(
  (response) => {
    const res = response.data
    
    // Token 过期（假设后端返回 401 或特定 code）
    if (res.code === 401 || res.code === 10401) {
      const userStore = useUserStore()
      
      // 清除用户信息
      userStore.logout()
      
      // 提示用户
      ElMessage.error('登录已过期，请重新登录')
      
      // 跳转到登录页
      router.push({
        path: '/login',
        query: { redirect: router.currentRoute.value.fullPath }
      })
      
      return Promise.reject(new Error('Token 过期'))
    }
    
    return res.data
  },
  (error) => {
    // HTTP 状态码 401
    if (error.response?.status === 401) {
      const userStore = useUserStore()
      userStore.logout()
      router.push('/login')
    }
    
    return Promise.reject(error)
  }
)
```


---

## 6. 错误统一处理

### 6.1 错误类型分类

在 Axios 中，错误主要分为以下几类：

| 错误类型 | 说明 | 示例 |
|---------|------|------|
| 网络错误 | 无法连接到服务器 | 断网、服务器宕机 |
| 超时错误 | 请求超过设定时间 | 网络慢、服务器响应慢 |
| HTTP 错误 | 服务器返回错误状态码 | 404、500、403 |
| 业务错误 | 服务器返回的业务错误 | 用户名已存在、余额不足 |
| 取消错误 | 请求被手动取消 | 用户切换页面 |

### 6.2 HTTP 状态码处理

```typescript
// 定义 HTTP 状态码对应的错误信息
const httpErrorMessages: Record<number, string> = {
  400: '请求参数错误',
  401: '未授权，请重新登录',
  403: '拒绝访问',
  404: '请求的资源不存在',
  405: '请求方法不允许',
  408: '请求超时',
  500: '服务器内部错误',
  501: '服务未实现',
  502: '网关错误',
  503: '服务不可用',
  504: '网关超时',
  505: 'HTTP 版本不受支持'
}

// 获取错误信息
function getHttpErrorMessage(status: number): string {
  return httpErrorMessages[status] || `未知错误 (${status})`
}
```

### 6.3 完整的错误处理函数

```typescript
import axios, { type AxiosError } from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'

// 错误处理函数
function handleError(error: AxiosError): void {
  // 1. 请求被取消
  if (axios.isCancel(error)) {
    console.log('请求已取消:', error.message)
    return
  }
  
  // 2. 网络错误（没有响应）
  if (!error.response) {
    if (error.message.includes('timeout')) {
      ElMessage.error('请求超时，请检查网络连接')
    } else if (error.message.includes('Network Error')) {
      ElMessage.error('网络错误，请检查网络连接')
    } else {
      ElMessage.error('请求失败，请稍后重试')
    }
    return
  }
  
  // 3. HTTP 错误（有响应）
  const { status, data } = error.response
  
  switch (status) {
    case 401:
      // 未授权，跳转登录
      ElMessageBox.confirm(
        '登录状态已过期，请重新登录',
        '提示',
        {
          confirmButtonText: '重新登录',
          cancelButtonText: '取消',
          type: 'warning'
        }
      ).then(() => {
        // 清除 token 并跳转
        localStorage.removeItem('token')
        window.location.href = '/login'
      })
      break
      
    case 403:
      ElMessage.error('没有权限访问该资源')
      break
      
    case 404:
      ElMessage.error('请求的资源不存在')
      break
      
    case 500:
      ElMessage.error('服务器错误，请稍后重试')
      break
      
    default:
      ElMessage.error((data as any)?.message || getHttpErrorMessage(status))
  }
}
```

### 6.4 在响应拦截器中使用

```typescript
service.interceptors.response.use(
  (response) => {
    // 成功响应处理...
    return response.data
  },
  (error: AxiosError) => {
    // 调用统一错误处理
    handleError(error)
    return Promise.reject(error)
  }
)
```


---

## 7. TypeScript 类型定义

### 7.1 为什么需要类型定义？

TypeScript 类型定义的好处：

- ✅ 代码提示和自动补全
- ✅ 编译时类型检查
- ✅ 更好的代码可读性
- ✅ 减少运行时错误

### 7.2 基础类型定义

在 `src/types/api.ts` 中定义：

```typescript
// 通用响应结构
export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

// 分页请求参数
export interface PageParams {
  page: number
  pageSize: number
}

// 分页响应数据
export interface PageResult<T> {
  list: T[]
  total: number
  page: number
  pageSize: number
}

// 通用列表响应
export type PageResponse<T> = ApiResponse<PageResult<T>>
```

### 7.3 扩展 Axios 类型

在 `src/types/axios.d.ts` 中扩展：

```typescript
import 'axios'

declare module 'axios' {
  // 扩展 AxiosRequestConfig，添加自定义配置
  export interface AxiosRequestConfig {
    // 是否显示 loading
    showLoading?: boolean
    // 是否显示错误提示
    showError?: boolean
    // 重试次数
    retryCount?: number
    // 重试延迟（毫秒）
    retryDelay?: number
  }
}
```

### 7.4 请求方法类型封装

```typescript
import type { AxiosRequestConfig, AxiosResponse } from 'axios'

// 请求配置类型
export interface RequestConfig extends AxiosRequestConfig {
  showLoading?: boolean
  showError?: boolean
}

// 封装后的请求方法类型
export interface RequestInstance {
  <T = any>(config: RequestConfig): Promise<T>
  get<T = any>(url: string, config?: RequestConfig): Promise<T>
  post<T = any>(url: string, data?: any, config?: RequestConfig): Promise<T>
  put<T = any>(url: string, data?: any, config?: RequestConfig): Promise<T>
  delete<T = any>(url: string, config?: RequestConfig): Promise<T>
}
```

### 7.5 业务接口类型定义示例

```typescript
// src/types/user.ts

// 用户信息
export interface UserInfo {
  id: number
  username: string
  nickname: string
  avatar: string
  email: string
  phone: string
  roles: string[]
  createTime: string
}

// 登录请求参数
export interface LoginParams {
  username: string
  password: string
  captcha?: string
}

// 登录响应数据
export interface LoginResult {
  token: string
  refreshToken: string
  expiresIn: number
  userInfo: UserInfo
}

// 用户列表查询参数
export interface UserQueryParams extends PageParams {
  username?: string
  status?: number
  startTime?: string
  endTime?: string
}
```


---

## 8. 请求封装与 API 模块化

### 8.1 封装通用请求方法

在 `src/utils/request.ts` 中：

```typescript
import axios, {
  type AxiosInstance,
  type AxiosRequestConfig,
  type AxiosResponse,
  type InternalAxiosRequestConfig
} from 'axios'
import { ElMessage, ElLoading } from 'element-plus'

// 自定义配置接口
interface CustomConfig {
  showLoading?: boolean
  showError?: boolean
}

type RequestConfig = AxiosRequestConfig & CustomConfig

// 创建实例
const service: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 10000
})

// Loading 管理
let loadingInstance: ReturnType<typeof ElLoading.service> | null = null
let loadingCount = 0

const showLoading = () => {
  if (loadingCount === 0) {
    loadingInstance = ElLoading.service({
      lock: true,
      text: '加载中...',
      background: 'rgba(0, 0, 0, 0.7)'
    })
  }
  loadingCount++
}

const hideLoading = () => {
  loadingCount--
  if (loadingCount === 0 && loadingInstance) {
    loadingInstance.close()
    loadingInstance = null
  }
}

// 请求拦截器
service.interceptors.request.use(
  (config: InternalAxiosRequestConfig & CustomConfig) => {
    // 显示 loading
    if (config.showLoading !== false) {
      showLoading()
    }
    
    // 添加 token
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    return config
  },
  (error) => {
    hideLoading()
    return Promise.reject(error)
  }
)

// 响应拦截器
service.interceptors.response.use(
  (response: AxiosResponse) => {
    hideLoading()
    
    const { code, message, data } = response.data
    
    if (code === 200) {
      return data
    }
    
    ElMessage.error(message || '请求失败')
    return Promise.reject(new Error(message))
  },
  (error) => {
    hideLoading()
    
    const config = error.config as CustomConfig
    if (config?.showError !== false) {
      ElMessage.error(error.message || '网络错误')
    }
    
    return Promise.reject(error)
  }
)

// 封装请求方法
const request = {
  get<T = any>(url: string, params?: object, config?: RequestConfig): Promise<T> {
    return service.get(url, { params, ...config })
  },
  
  post<T = any>(url: string, data?: object, config?: RequestConfig): Promise<T> {
    return service.post(url, data, config)
  },
  
  put<T = any>(url: string, data?: object, config?: RequestConfig): Promise<T> {
    return service.put(url, data, config)
  },
  
  delete<T = any>(url: string, config?: RequestConfig): Promise<T> {
    return service.delete(url, config)
  },
  
  // 上传文件
  upload<T = any>(url: string, file: File, config?: RequestConfig): Promise<T> {
    const formData = new FormData()
    formData.append('file', file)
    return service.post(url, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      ...config
    })
  }
}

export default request
```

### 8.2 API 模块化组织

推荐的目录结构：

```
src/
├── api/
│   ├── index.ts        # 统一导出
│   ├── user.ts         # 用户相关接口
│   ├── product.ts      # 商品相关接口
│   ├── order.ts        # 订单相关接口
│   └── common.ts       # 公共接口
├── types/
│   ├── api.ts          # 通用类型
│   ├── user.ts         # 用户类型
│   └── product.ts      # 商品类型
└── utils/
    └── request.ts      # axios 封装
```


### 8.3 用户模块 API 示例

`src/api/user.ts`：

```typescript
import request from '@/utils/request'
import type { LoginParams, LoginResult, UserInfo, UserQueryParams } from '@/types/user'
import type { PageResult } from '@/types/api'

// 用户 API
export const userApi = {
  // 登录
  login(data: LoginParams) {
    return request.post<LoginResult>('/auth/login', data)
  },
  
  // 退出登录
  logout() {
    return request.post<void>('/auth/logout')
  },
  
  // 获取当前用户信息
  getCurrentUser() {
    return request.get<UserInfo>('/user/current')
  },
  
  // 获取用户列表
  getUserList(params: UserQueryParams) {
    return request.get<PageResult<UserInfo>>('/user/list', params)
  },
  
  // 获取用户详情
  getUserById(id: number) {
    return request.get<UserInfo>(`/user/${id}`)
  },
  
  // 创建用户
  createUser(data: Partial<UserInfo>) {
    return request.post<UserInfo>('/user', data)
  },
  
  // 更新用户
  updateUser(id: number, data: Partial<UserInfo>) {
    return request.put<UserInfo>(`/user/${id}`, data)
  },
  
  // 删除用户
  deleteUser(id: number) {
    return request.delete<void>(`/user/${id}`)
  },
  
  // 上传头像
  uploadAvatar(file: File) {
    return request.upload<{ url: string }>('/user/avatar', file)
  }
}
```

### 8.4 在组件中使用

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { userApi } from '@/api/user'
import type { UserInfo } from '@/types/user'

const userList = ref<UserInfo[]>([])
const loading = ref(false)
const total = ref(0)

// 查询参数
const queryParams = ref({
  page: 1,
  pageSize: 10,
  username: ''
})

// 获取用户列表
const fetchUserList = async () => {
  loading.value = true
  try {
    const res = await userApi.getUserList(queryParams.value)
    userList.value = res.list
    total.value = res.total
  } catch (error) {
    console.error('获取用户列表失败:', error)
  } finally {
    loading.value = false
  }
}

// 删除用户
const handleDelete = async (id: number) => {
  try {
    await userApi.deleteUser(id)
    ElMessage.success('删除成功')
    fetchUserList() // 刷新列表
  } catch (error) {
    // 错误已在拦截器中处理
  }
}

onMounted(() => {
  fetchUserList()
})
</script>
```

### 8.5 统一导出

`src/api/index.ts`：

```typescript
export * from './user'
export * from './product'
export * from './order'
export * from './common'
```

使用时：

```typescript
import { userApi, productApi, orderApi } from '@/api'

// 调用
const user = await userApi.getCurrentUser()
const products = await productApi.getProductList({ page: 1, pageSize: 10 })
```


---

## 9. 高级功能

### 9.1 请求取消

当用户快速切换页面或重复点击时，需要取消之前的请求：

```typescript
import axios, { type CancelTokenSource } from 'axios'

// 存储取消令牌
const pendingRequests = new Map<string, CancelTokenSource>()

// 生成请求唯一标识
const generateRequestKey = (config: AxiosRequestConfig): string => {
  const { method, url, params, data } = config
  return [method, url, JSON.stringify(params), JSON.stringify(data)].join('&')
}

// 添加请求到 pending
const addPendingRequest = (config: AxiosRequestConfig): void => {
  const requestKey = generateRequestKey(config)
  
  // 如果已存在相同请求，先取消
  if (pendingRequests.has(requestKey)) {
    const source = pendingRequests.get(requestKey)!
    source.cancel('重复请求被取消')
    pendingRequests.delete(requestKey)
  }
  
  // 创建新的取消令牌
  const source = axios.CancelToken.source()
  config.cancelToken = source.token
  pendingRequests.set(requestKey, source)
}

// 移除请求
const removePendingRequest = (config: AxiosRequestConfig): void => {
  const requestKey = generateRequestKey(config)
  pendingRequests.delete(requestKey)
}

// 在拦截器中使用
service.interceptors.request.use((config) => {
  addPendingRequest(config)
  return config
})

service.interceptors.response.use(
  (response) => {
    removePendingRequest(response.config)
    return response
  },
  (error) => {
    if (!axios.isCancel(error)) {
      removePendingRequest(error.config)
    }
    return Promise.reject(error)
  }
)
```

### 9.2 使用 AbortController（推荐）

Axios 0.22.0+ 支持更现代的 AbortController：

```typescript
// 在组件中使用
const controller = new AbortController()

const fetchData = async () => {
  try {
    const response = await request.get('/api/data', {}, {
      signal: controller.signal
    })
    console.log(response)
  } catch (error) {
    if (axios.isCancel(error)) {
      console.log('请求已取消')
    }
  }
}

// 取消请求
const cancelRequest = () => {
  controller.abort()
}

// 组件卸载时取消
onUnmounted(() => {
  controller.abort()
})
```

### 9.3 请求重试

```typescript
import type { AxiosError, InternalAxiosRequestConfig } from 'axios'

interface RetryConfig extends InternalAxiosRequestConfig {
  retryCount?: number
  retryDelay?: number
  __retryCount?: number
}

// 重试拦截器
service.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const config = error.config as RetryConfig
    
    // 如果没有配置重试，直接返回错误
    if (!config || !config.retryCount) {
      return Promise.reject(error)
    }
    
    // 初始化重试计数
    config.__retryCount = config.__retryCount || 0
    
    // 检查是否超过重试次数
    if (config.__retryCount >= config.retryCount) {
      return Promise.reject(error)
    }
    
    // 增加重试计数
    config.__retryCount++
    
    // 延迟重试
    const delay = config.retryDelay || 1000
    await new Promise(resolve => setTimeout(resolve, delay))
    
    console.log(`第 ${config.__retryCount} 次重试...`)
    
    // 重新发起请求
    return service(config)
  }
)

// 使用
request.get('/api/data', {}, {
  retryCount: 3,    // 最多重试 3 次
  retryDelay: 1000  // 每次重试间隔 1 秒
})
```


### 9.4 Token 无感刷新

当 access_token 过期时，自动使用 refresh_token 获取新 token：

```typescript
import axios, { type AxiosError, type InternalAxiosRequestConfig } from 'axios'

// 是否正在刷新 token
let isRefreshing = false
// 等待刷新的请求队列
let refreshSubscribers: ((token: string) => void)[] = []

// 添加到等待队列
const subscribeTokenRefresh = (callback: (token: string) => void) => {
  refreshSubscribers.push(callback)
}

// 通知所有等待的请求
const onTokenRefreshed = (token: string) => {
  refreshSubscribers.forEach(callback => callback(token))
  refreshSubscribers = []
}

// 刷新 token
const refreshToken = async (): Promise<string> => {
  const refreshToken = localStorage.getItem('refreshToken')
  const response = await axios.post('/auth/refresh', { refreshToken })
  const { token } = response.data.data
  localStorage.setItem('token', token)
  return token
}

// 响应拦截器
service.interceptors.response.use(
  (response) => response.data,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean }
    
    // 如果是 401 错误且不是刷新 token 的请求
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      
      if (!isRefreshing) {
        isRefreshing = true
        
        try {
          const newToken = await refreshToken()
          isRefreshing = false
          onTokenRefreshed(newToken)
          
          // 重新发起原请求
          originalRequest.headers.Authorization = `Bearer ${newToken}`
          return service(originalRequest)
        } catch (refreshError) {
          isRefreshing = false
          refreshSubscribers = []
          
          // 刷新失败，跳转登录
          localStorage.removeItem('token')
          localStorage.removeItem('refreshToken')
          window.location.href = '/login'
          
          return Promise.reject(refreshError)
        }
      } else {
        // 正在刷新，将请求加入队列
        return new Promise((resolve) => {
          subscribeTokenRefresh((token: string) => {
            originalRequest.headers.Authorization = `Bearer ${token}`
            resolve(service(originalRequest))
          })
        })
      }
    }
    
    return Promise.reject(error)
  }
)
```

> 💡 **原理说明**：当多个请求同时遇到 401 时，只有第一个请求会去刷新 token，其他请求会被放入队列等待。刷新成功后，队列中的请求会使用新 token 重新发起。

### 9.5 请求缓存

对于不经常变化的数据，可以添加缓存：

```typescript
interface CacheItem {
  data: any
  timestamp: number
  expireTime: number
}

const cache = new Map<string, CacheItem>()

// 生成缓存 key
const generateCacheKey = (url: string, params?: object): string => {
  return `${url}?${JSON.stringify(params || {})}`
}

// 带缓存的 GET 请求
const getWithCache = async <T>(
  url: string,
  params?: object,
  cacheTime: number = 5 * 60 * 1000 // 默认缓存 5 分钟
): Promise<T> => {
  const cacheKey = generateCacheKey(url, params)
  const cached = cache.get(cacheKey)
  
  // 检查缓存是否有效
  if (cached && Date.now() - cached.timestamp < cached.expireTime) {
    console.log('使用缓存数据:', cacheKey)
    return cached.data
  }
  
  // 发起请求
  const data = await request.get<T>(url, params)
  
  // 存入缓存
  cache.set(cacheKey, {
    data,
    timestamp: Date.now(),
    expireTime: cacheTime
  })
  
  return data
}

// 清除缓存
const clearCache = (url?: string) => {
  if (url) {
    // 清除指定 URL 的缓存
    for (const key of cache.keys()) {
      if (key.startsWith(url)) {
        cache.delete(key)
      }
    }
  } else {
    // 清除所有缓存
    cache.clear()
  }
}
```


### 9.6 并发请求控制

限制同时进行的请求数量：

```typescript
class RequestQueue {
  private queue: (() => Promise<any>)[] = []
  private running = 0
  private maxConcurrent: number
  
  constructor(maxConcurrent: number = 5) {
    this.maxConcurrent = maxConcurrent
  }
  
  add<T>(requestFn: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      const task = async () => {
        try {
          const result = await requestFn()
          resolve(result)
        } catch (error) {
          reject(error)
        } finally {
          this.running--
          this.runNext()
        }
      }
      
      this.queue.push(task)
      this.runNext()
    })
  }
  
  private runNext() {
    while (this.running < this.maxConcurrent && this.queue.length > 0) {
      const task = this.queue.shift()!
      this.running++
      task()
    }
  }
}

// 使用
const requestQueue = new RequestQueue(3) // 最多同时 3 个请求

// 批量请求
const ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
const results = await Promise.all(
  ids.map(id => requestQueue.add(() => userApi.getUserById(id)))
)
```

### 9.7 文件下载

```typescript
// 下载文件
const downloadFile = async (url: string, filename: string) => {
  try {
    const response = await service.get(url, {
      responseType: 'blob',
      showLoading: true
    })
    
    // 创建 Blob URL
    const blob = new Blob([response.data])
    const downloadUrl = window.URL.createObjectURL(blob)
    
    // 创建下载链接
    const link = document.createElement('a')
    link.href = downloadUrl
    link.download = filename
    
    // 触发下载
    document.body.appendChild(link)
    link.click()
    
    // 清理
    document.body.removeChild(link)
    window.URL.revokeObjectURL(downloadUrl)
  } catch (error) {
    ElMessage.error('下载失败')
  }
}

// 带进度的下载
const downloadWithProgress = async (
  url: string,
  filename: string,
  onProgress?: (progress: number) => void
) => {
  const response = await service.get(url, {
    responseType: 'blob',
    onDownloadProgress: (progressEvent) => {
      if (progressEvent.total) {
        const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total)
        onProgress?.(progress)
      }
    }
  })
  
  // ... 同上处理下载
}
```


---

## 10. 完整封装示例

### 10.1 完整的 request.ts

`src/utils/request.ts`：

```typescript
import axios, {
  type AxiosInstance,
  type AxiosError,
  type AxiosResponse,
  type InternalAxiosRequestConfig
} from 'axios'
import { ElMessage, ElLoading, ElMessageBox } from 'element-plus'
import router from '@/router'

// ==================== 类型定义 ====================

// 自定义配置
interface CustomConfig {
  showLoading?: boolean
  showError?: boolean
  retryCount?: number
  retryDelay?: number
}

// 扩展请求配置
type RequestConfig = InternalAxiosRequestConfig & CustomConfig & {
  __retryCount?: number
}

// 响应数据结构
interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

// ==================== Loading 管理 ====================

let loadingInstance: ReturnType<typeof ElLoading.service> | null = null
let loadingCount = 0

const showLoading = () => {
  if (loadingCount === 0) {
    loadingInstance = ElLoading.service({
      lock: true,
      text: '加载中...',
      background: 'rgba(0, 0, 0, 0.7)'
    })
  }
  loadingCount++
}

const hideLoading = () => {
  loadingCount--
  if (loadingCount <= 0) {
    loadingCount = 0
    loadingInstance?.close()
    loadingInstance = null
  }
}

// ==================== 错误处理 ====================

const httpErrorMessages: Record<number, string> = {
  400: '请求参数错误',
  401: '未授权，请重新登录',
  403: '拒绝访问',
  404: '请求的资源不存在',
  500: '服务器内部错误',
  502: '网关错误',
  503: '服务不可用',
  504: '网关超时'
}

const handleHttpError = (error: AxiosError, showError: boolean) => {
  if (!showError) return
  
  if (axios.isCancel(error)) {
    console.log('请求已取消')
    return
  }
  
  if (!error.response) {
    if (error.message.includes('timeout')) {
      ElMessage.error('请求超时，请检查网络')
    } else {
      ElMessage.error('网络错误，请检查连接')
    }
    return
  }
  
  const { status } = error.response
  
  if (status === 401) {
    ElMessageBox.confirm('登录已过期，请重新登录', '提示', {
      confirmButtonText: '重新登录',
      cancelButtonText: '取消',
      type: 'warning'
    }).then(() => {
      localStorage.removeItem('token')
      router.push('/login')
    })
    return
  }
  
  ElMessage.error(httpErrorMessages[status] || `请求失败 (${status})`)
}

// ==================== 创建实例 ====================

const service: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json;charset=UTF-8'
  }
})

// ==================== 请求拦截器 ====================

service.interceptors.request.use(
  (config: RequestConfig) => {
    // 显示 Loading
    if (config.showLoading !== false) {
      showLoading()
    }
    
    // 添加 Token
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    
    return config
  },
  (error) => {
    hideLoading()
    return Promise.reject(error)
  }
)

// ==================== 响应拦截器 ====================

service.interceptors.response.use(
  (response: AxiosResponse<ApiResponse>) => {
    hideLoading()
    
    const { code, message, data } = response.data
    
    // 成功
    if (code === 200) {
      return data as any
    }
    
    // 业务错误
    ElMessage.error(message || '请求失败')
    return Promise.reject(new Error(message))
  },
  async (error: AxiosError) => {
    hideLoading()
    
    const config = error.config as RequestConfig
    
    // 重试逻辑
    if (config?.retryCount && config.retryCount > 0) {
      config.__retryCount = config.__retryCount || 0
      
      if (config.__retryCount < config.retryCount) {
        config.__retryCount++
        const delay = config.retryDelay || 1000
        await new Promise(resolve => setTimeout(resolve, delay))
        return service(config)
      }
    }
    
    // 错误处理
    handleHttpError(error, config?.showError !== false)
    
    return Promise.reject(error)
  }
)

// ==================== 导出请求方法 ====================

export interface RequestOptions extends CustomConfig {
  params?: Record<string, any>
  headers?: Record<string, string>
}

const request = {
  get<T = any>(url: string, params?: object, options?: RequestOptions): Promise<T> {
    return service.get(url, { params, ...options })
  },
  
  post<T = any>(url: string, data?: object, options?: RequestOptions): Promise<T> {
    return service.post(url, data, options)
  },
  
  put<T = any>(url: string, data?: object, options?: RequestOptions): Promise<T> {
    return service.put(url, data, options)
  },
  
  delete<T = any>(url: string, options?: RequestOptions): Promise<T> {
    return service.delete(url, options)
  },
  
  upload<T = any>(url: string, file: File, fieldName = 'file', options?: RequestOptions): Promise<T> {
    const formData = new FormData()
    formData.append(fieldName, file)
    return service.post(url, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      ...options
    })
  }
}

export default request
export { service as axiosInstance }
```


### 10.2 类型定义文件

`src/types/api.ts`：

```typescript
// 通用响应结构
export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

// 分页参数
export interface PageParams {
  page: number
  pageSize: number
}

// 分页结果
export interface PageResult<T> {
  list: T[]
  total: number
  page: number
  pageSize: number
}

// 通用 ID 参数
export interface IdParams {
  id: number | string
}

// 通用状态
export type Status = 0 | 1 // 0: 禁用, 1: 启用
```

### 10.3 API 模块示例

`src/api/user.ts`：

```typescript
import request from '@/utils/request'
import type { PageParams, PageResult } from '@/types/api'

// 用户信息类型
export interface UserInfo {
  id: number
  username: string
  nickname: string
  avatar: string
  email: string
  status: number
  createTime: string
}

// 登录参数
export interface LoginParams {
  username: string
  password: string
}

// 登录结果
export interface LoginResult {
  token: string
  userInfo: UserInfo
}

// 用户 API
export const userApi = {
  // 登录
  login: (data: LoginParams) => 
    request.post<LoginResult>('/auth/login', data, { showLoading: true }),
  
  // 获取用户信息
  getUserInfo: () => 
    request.get<UserInfo>('/user/info'),
  
  // 获取用户列表
  getUserList: (params: PageParams & { keyword?: string }) => 
    request.get<PageResult<UserInfo>>('/user/list', params),
  
  // 更新用户
  updateUser: (id: number, data: Partial<UserInfo>) => 
    request.put<void>(`/user/${id}`, data),
  
  // 删除用户
  deleteUser: (id: number) => 
    request.delete<void>(`/user/${id}`)
}
```

### 10.4 在 Vue 组件中使用

```vue
<template>
  <div class="user-list">
    <el-table :data="userList" v-loading="loading">
      <el-table-column prop="username" label="用户名" />
      <el-table-column prop="nickname" label="昵称" />
      <el-table-column prop="email" label="邮箱" />
      <el-table-column label="操作">
        <template #default="{ row }">
          <el-button type="danger" @click="handleDelete(row.id)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>
    
    <el-pagination
      v-model:current-page="params.page"
      v-model:page-size="params.pageSize"
      :total="total"
      @change="fetchList"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { userApi, type UserInfo } from '@/api/user'

const loading = ref(false)
const userList = ref<UserInfo[]>([])
const total = ref(0)

const params = reactive({
  page: 1,
  pageSize: 10,
  keyword: ''
})

// 获取列表
const fetchList = async () => {
  loading.value = true
  try {
    const res = await userApi.getUserList(params)
    userList.value = res.list
    total.value = res.total
  } finally {
    loading.value = false
  }
}

// 删除用户
const handleDelete = async (id: number) => {
  await ElMessageBox.confirm('确定删除该用户吗？', '提示')
  await userApi.deleteUser(id)
  ElMessage.success('删除成功')
  fetchList()
}

onMounted(fetchList)
</script>
```


---

## 11. 常见错误与解决方案

### 11.1 跨域问题 (CORS)

**错误信息**：
```
Access to XMLHttpRequest at 'http://api.example.com' from origin 'http://localhost:5173' 
has been blocked by CORS policy
```

**原因**：浏览器的同源策略限制，前端和后端不在同一个域。

**解决方案**：

方案一：Vite 开发代理（推荐）

`vite.config.ts`：
```typescript
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://api.example.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, '')
      }
    }
  }
})
```

方案二：后端配置 CORS 响应头
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
```

### 11.2 请求超时

**错误信息**：
```
Error: timeout of 10000ms exceeded
```

**解决方案**：

```typescript
// 1. 增加全局超时时间
const service = axios.create({
  timeout: 30000 // 30 秒
})

// 2. 单个请求设置更长超时
request.post('/upload', formData, {
  timeout: 60000 // 上传文件 60 秒
})

// 3. 添加重试机制
request.get('/api/data', {}, {
  retryCount: 3,
  retryDelay: 1000
})
```

### 11.3 Token 相关问题

**问题 1：Token 未携带**

```typescript
// ❌ 错误：直接使用 axios 而不是封装的 service
import axios from 'axios'
axios.get('/api/user') // 不会携带 token

// ✅ 正确：使用封装的 request
import request from '@/utils/request'
request.get('/api/user') // 会自动携带 token
```

**问题 2：Token 格式错误**

```typescript
// ❌ 错误：缺少 Bearer 前缀
config.headers.Authorization = token

// ✅ 正确：添加 Bearer 前缀
config.headers.Authorization = `Bearer ${token}`
```

**问题 3：Token 存储位置不一致**

```typescript
// 确保存取位置一致
// 存储
localStorage.setItem('token', token)

// 读取
const token = localStorage.getItem('token')
```

### 11.4 请求参数问题

**问题 1：GET 请求参数未正确传递**

```typescript
// ❌ 错误：GET 请求使用 data
request.get('/api/users', { data: { page: 1 } })

// ✅ 正确：GET 请求使用 params
request.get('/api/users', { page: 1 })
```

**问题 2：POST 请求 Content-Type 错误**

```typescript
// 发送 JSON（默认）
request.post('/api/user', { name: '张三' })

// 发送 FormData
const formData = new FormData()
formData.append('file', file)
request.post('/api/upload', formData, {
  headers: { 'Content-Type': 'multipart/form-data' }
})

// 发送 URL 编码
import qs from 'qs'
request.post('/api/login', qs.stringify({ username, password }), {
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
})
```

### 11.5 响应数据处理问题

**问题 1：响应数据结构不一致**

```typescript
// 后端返回格式不统一时的处理
service.interceptors.response.use(
  (response) => {
    const res = response.data
    
    // 兼容不同的响应格式
    if (res.code !== undefined) {
      // 格式 1: { code, message, data }
      return res.code === 200 ? res.data : Promise.reject(res)
    } else if (res.success !== undefined) {
      // 格式 2: { success, msg, result }
      return res.success ? res.result : Promise.reject(res)
    } else {
      // 直接返回数据
      return res
    }
  }
)
```

**问题 2：TypeScript 类型推断失败**

```typescript
// ❌ 类型丢失
const data = await request.get('/api/user')
data.name // 类型为 any

// ✅ 指定泛型类型
interface User {
  id: number
  name: string
}
const data = await request.get<User>('/api/user')
data.name // 类型为 string
```


### 11.6 Loading 状态问题

**问题：并发请求导致 Loading 闪烁**

```typescript
// ❌ 错误：每个请求独立控制 loading
const loading = ref(false)

const fetchData = async () => {
  loading.value = true
  await request.get('/api/data1')
  loading.value = false // 第一个请求完成就关闭了
}

// ✅ 正确：使用计数器管理
let loadingCount = 0

const showLoading = () => {
  if (loadingCount === 0) {
    // 显示 loading
  }
  loadingCount++
}

const hideLoading = () => {
  loadingCount--
  if (loadingCount === 0) {
    // 隐藏 loading
  }
}
```

### 11.7 内存泄漏问题

**问题：组件卸载后请求回调仍然执行**

```typescript
// ❌ 错误：组件卸载后仍然更新状态
const fetchData = async () => {
  const data = await request.get('/api/data')
  list.value = data // 组件可能已卸载
}

// ✅ 正确：使用 AbortController 取消请求
const controller = new AbortController()

const fetchData = async () => {
  try {
    const data = await request.get('/api/data', {}, {
      signal: controller.signal
    })
    list.value = data
  } catch (error) {
    if (!axios.isCancel(error)) {
      console.error(error)
    }
  }
}

onUnmounted(() => {
  controller.abort()
})
```

### 11.8 环境变量问题

**问题：环境变量未生效**

```typescript
// ❌ 错误：使用 process.env（Vite 不支持）
const baseURL = process.env.VUE_APP_API_URL

// ✅ 正确：使用 import.meta.env
const baseURL = import.meta.env.VITE_API_BASE_URL

// 注意：Vite 环境变量必须以 VITE_ 开头
```

`.env` 文件示例：
```bash
# ❌ 错误：不会被暴露
API_URL=http://localhost:3000

# ✅ 正确：以 VITE_ 开头
VITE_API_URL=http://localhost:3000
```

### 11.9 循环依赖问题

**问题：request.ts 和 store 循环引用**

```typescript
// ❌ 错误：在模块顶层导入 store
import { useUserStore } from '@/stores/user' // 可能导致循环依赖

const service = axios.create({ ... })

service.interceptors.request.use((config) => {
  const userStore = useUserStore() // 报错
})

// ✅ 正确：在函数内部获取 store
service.interceptors.request.use((config) => {
  // 延迟获取，避免循环依赖
  const token = localStorage.getItem('token')
  // 或者使用 pinia 的 storeToRefs
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})
```

### 11.10 常见 TypeScript 错误

**错误 1：类型 'AxiosResponse' 上不存在属性 'xxx'**

```typescript
// ❌ 错误：直接访问 response.data.xxx
service.interceptors.response.use((response) => {
  return response.data.data // 类型错误
})

// ✅ 正确：定义响应类型
interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

service.interceptors.response.use((response: AxiosResponse<ApiResponse>) => {
  return response.data.data
})
```

**错误 2：参数类型不匹配**

```typescript
// ❌ 错误：config 类型不正确
service.interceptors.request.use((config: AxiosRequestConfig) => {
  // InternalAxiosRequestConfig 才是正确的类型
})

// ✅ 正确
import type { InternalAxiosRequestConfig } from 'axios'

service.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  return config
})
```

---

## 总结

本笔记从基础到进阶，系统地介绍了 Axios 在 Vue 3 + TypeScript 项目中的封装方法：

1. **基础概念**：理解 Axios 的特点和封装的必要性
2. **实例创建**：使用 `axios.create()` 创建独立实例
3. **请求拦截器**：添加 token、loading、参数处理
4. **响应拦截器**：统一处理响应数据和错误
5. **错误处理**：分类处理各种错误类型
6. **TypeScript**：完善的类型定义提升开发体验
7. **API 模块化**：按业务模块组织 API
8. **高级功能**：请求取消、重试、缓存、Token 刷新等
9. **常见错误**：总结开发中常见的问题和解决方案

掌握这些内容，你就能在项目中构建一个健壮、可维护的 HTTP 请求层。
