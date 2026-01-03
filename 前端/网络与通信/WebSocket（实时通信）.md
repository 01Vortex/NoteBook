

> WebSocket 是一种在单个 TCP 连接上进行全双工通信的协议
> 本笔记基于 Vue 3 + TypeScript + Vite，从基础到进阶全面讲解 WebSocket 实时通信

---

## 目录

1. [基础概念](#1-基础概念)
2. [原生 WebSocket API](#2-原生-websocket-api)
3. [Vue 3 中使用 WebSocket](#3-vue-3-中使用-websocket)
4. [封装 WebSocket 类](#4-封装-websocket-类)
5. [心跳检测与断线重连](#5-心跳检测与断线重连)
6. [消息队列与离线缓存](#6-消息队列与离线缓存)
7. [TypeScript 类型定义](#7-typescript-类型定义)
8. [实战：聊天室应用](#8-实战聊天室应用)
9. [实战：实时通知系统](#9-实战实时通知系统)
10. [Socket.IO 集成](#10-socketio-集成)
11. [性能优化与最佳实践](#11-性能优化与最佳实践)
12. [常见错误与解决方案](#12-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 WebSocket？

WebSocket 是 HTML5 提供的一种网络通信协议，它实现了浏览器与服务器之间的**全双工通信**。

**传统 HTTP 请求的问题**：
- 单向通信：只能客户端主动请求，服务器被动响应
- 轮询浪费：为了获取实时数据，需要不断发送请求
- 头部开销：每次请求都要携带完整的 HTTP 头部

**WebSocket 的优势**：
- ✅ 双向通信：服务器可以主动推送数据给客户端
- ✅ 持久连接：一次握手，持续通信
- ✅ 低延迟：无需重复建立连接
- ✅ 轻量级：数据帧头部只有 2-10 字节

### 1.2 WebSocket vs HTTP

| 特性 | HTTP | WebSocket |
|------|------|-----------|
| 通信方式 | 单向（请求-响应） | 双向（全双工） |
| 连接状态 | 短连接 | 长连接 |
| 头部开销 | 大（每次请求都有） | 小（握手后很小） |
| 实时性 | 差（需要轮询） | 好（服务器主动推送） |
| 协议标识 | http:// / https:// | ws:// / wss:// |

### 1.3 WebSocket 连接过程

```
客户端                                    服务器
   |                                        |
   |  1. HTTP 升级请求 (Upgrade: websocket) |
   |--------------------------------------->|
   |                                        |
   |  2. HTTP 101 响应 (Switching Protocols)|
   |<---------------------------------------|
   |                                        |
   |  3. WebSocket 连接建立，双向通信开始    |
   |<======================================>|
   |                                        |
```

握手请求头示例：
```
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```


### 1.4 适用场景

WebSocket 特别适合以下场景：

1. **即时通讯**：聊天应用、客服系统
2. **实时数据**：股票行情、体育比分、在线游戏
3. **协同编辑**：多人文档编辑、白板协作
4. **消息推送**：系统通知、订单状态更新
5. **物联网**：设备状态监控、传感器数据

### 1.5 WebSocket 状态

WebSocket 有四种连接状态：

| 状态 | 值 | 说明 |
|------|---|------|
| CONNECTING | 0 | 正在连接 |
| OPEN | 1 | 连接已建立，可以通信 |
| CLOSING | 2 | 连接正在关闭 |
| CLOSED | 3 | 连接已关闭或无法建立 |

```typescript
const ws = new WebSocket('ws://localhost:3000')

console.log(ws.readyState) // 0 - CONNECTING

ws.onopen = () => {
  console.log(ws.readyState) // 1 - OPEN
}

ws.onclose = () => {
  console.log(ws.readyState) // 3 - CLOSED
}
```

---

## 2. 原生 WebSocket API

### 2.1 创建连接

```typescript
// 创建 WebSocket 连接
const ws = new WebSocket('ws://localhost:3000')

// 带协议的连接（可选）
const wsWithProtocol = new WebSocket('ws://localhost:3000', 'chat-protocol')

// 安全连接（生产环境推荐）
const wss = new WebSocket('wss://api.example.com/ws')
```

> 💡 **提示**：`ws://` 是非加密连接，`wss://` 是加密连接（类似 HTTP 和 HTTPS 的关系）。生产环境务必使用 `wss://`。

### 2.2 事件监听

WebSocket 有四个核心事件：

```typescript
const ws = new WebSocket('ws://localhost:3000')

// 1. 连接建立成功
ws.onopen = (event: Event) => {
  console.log('连接已建立')
  // 连接成功后可以发送消息
  ws.send('Hello Server!')
}

// 2. 收到服务器消息
ws.onmessage = (event: MessageEvent) => {
  console.log('收到消息:', event.data)
  
  // 如果是 JSON 数据
  try {
    const data = JSON.parse(event.data)
    console.log('解析后的数据:', data)
  } catch (e) {
    console.log('纯文本消息:', event.data)
  }
}

// 3. 连接关闭
ws.onclose = (event: CloseEvent) => {
  console.log('连接已关闭')
  console.log('关闭码:', event.code)
  console.log('关闭原因:', event.reason)
  console.log('是否正常关闭:', event.wasClean)
}

// 4. 连接错误
ws.onerror = (event: Event) => {
  console.error('连接错误:', event)
}
```

### 2.3 发送消息

```typescript
const ws = new WebSocket('ws://localhost:3000')

ws.onopen = () => {
  // 发送文本
  ws.send('Hello!')
  
  // 发送 JSON
  ws.send(JSON.stringify({
    type: 'message',
    content: '你好',
    timestamp: Date.now()
  }))
  
  // 发送二进制数据（ArrayBuffer）
  const buffer = new ArrayBuffer(8)
  ws.send(buffer)
  
  // 发送 Blob
  const blob = new Blob(['Hello'], { type: 'text/plain' })
  ws.send(blob)
}
```

### 2.4 关闭连接

```typescript
// 正常关闭
ws.close()

// 带关闭码和原因
ws.close(1000, '正常关闭')

// 常用关闭码
// 1000 - 正常关闭
// 1001 - 终端离开（如页面关闭）
// 1002 - 协议错误
// 1003 - 数据类型错误
// 1006 - 异常关闭（无法发送关闭帧）
// 1011 - 服务器错误
```


### 2.5 完整基础示例

```typescript
class SimpleWebSocket {
  private ws: WebSocket | null = null
  private url: string
  
  constructor(url: string) {
    this.url = url
  }
  
  // 建立连接
  connect(): void {
    this.ws = new WebSocket(this.url)
    
    this.ws.onopen = () => {
      console.log('✅ WebSocket 连接成功')
    }
    
    this.ws.onmessage = (event) => {
      console.log('📩 收到消息:', event.data)
    }
    
    this.ws.onclose = (event) => {
      console.log(`❌ 连接关闭: ${event.code} - ${event.reason}`)
    }
    
    this.ws.onerror = (error) => {
      console.error('⚠️ 连接错误:', error)
    }
  }
  
  // 发送消息
  send(data: string | object): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      const message = typeof data === 'string' ? data : JSON.stringify(data)
      this.ws.send(message)
    } else {
      console.warn('WebSocket 未连接，无法发送消息')
    }
  }
  
  // 关闭连接
  close(): void {
    this.ws?.close(1000, '用户主动关闭')
  }
}

// 使用
const socket = new SimpleWebSocket('ws://localhost:3000')
socket.connect()
socket.send({ type: 'hello', message: '你好' })
```

---

## 3. Vue 3 中使用 WebSocket

### 3.1 组件内直接使用

```vue
<template>
  <div class="websocket-demo">
    <div class="status">
      状态: <span :class="statusClass">{{ statusText }}</span>
    </div>
    
    <div class="messages">
      <div v-for="(msg, index) in messages" :key="index" class="message">
        {{ msg }}
      </div>
    </div>
    
    <div class="input-area">
      <input v-model="inputMessage" @keyup.enter="sendMessage" placeholder="输入消息..." />
      <button @click="sendMessage" :disabled="!isConnected">发送</button>
    </div>
    
    <button @click="toggleConnection">
      {{ isConnected ? '断开连接' : '建立连接' }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'

// 状态
const ws = ref<WebSocket | null>(null)
const messages = ref<string[]>([])
const inputMessage = ref('')
const readyState = ref<number>(WebSocket.CLOSED)

// 计算属性
const isConnected = computed(() => readyState.value === WebSocket.OPEN)

const statusText = computed(() => {
  const statusMap: Record<number, string> = {
    [WebSocket.CONNECTING]: '连接中...',
    [WebSocket.OPEN]: '已连接',
    [WebSocket.CLOSING]: '关闭中...',
    [WebSocket.CLOSED]: '已断开'
  }
  return statusMap[readyState.value]
})

const statusClass = computed(() => ({
  'status-connecting': readyState.value === WebSocket.CONNECTING,
  'status-open': readyState.value === WebSocket.OPEN,
  'status-closing': readyState.value === WebSocket.CLOSING,
  'status-closed': readyState.value === WebSocket.CLOSED
}))

// 建立连接
const connect = () => {
  ws.value = new WebSocket('ws://localhost:3000')
  
  ws.value.onopen = () => {
    readyState.value = WebSocket.OPEN
    messages.value.push('[系统] 连接已建立')
  }
  
  ws.value.onmessage = (event) => {
    messages.value.push(`[服务器] ${event.data}`)
  }
  
  ws.value.onclose = () => {
    readyState.value = WebSocket.CLOSED
    messages.value.push('[系统] 连接已关闭')
  }
  
  ws.value.onerror = () => {
    messages.value.push('[系统] 连接发生错误')
  }
  
  readyState.value = WebSocket.CONNECTING
}

// 断开连接
const disconnect = () => {
  ws.value?.close()
}

// 切换连接状态
const toggleConnection = () => {
  if (isConnected.value) {
    disconnect()
  } else {
    connect()
  }
}

// 发送消息
const sendMessage = () => {
  if (!inputMessage.value.trim() || !isConnected.value) return
  
  ws.value?.send(inputMessage.value)
  messages.value.push(`[我] ${inputMessage.value}`)
  inputMessage.value = ''
}

// 生命周期
onMounted(() => {
  connect()
})

onUnmounted(() => {
  disconnect()
})
</script>

<style scoped>
.status-open { color: green; }
.status-closed { color: red; }
.status-connecting { color: orange; }
</style>
```


### 3.2 封装为 Composable（推荐）

`src/composables/useWebSocket.ts`：

```typescript
import { ref, onUnmounted, type Ref } from 'vue'

export interface UseWebSocketOptions {
  // 自动连接
  autoConnect?: boolean
  // 自动重连
  autoReconnect?: boolean
  // 重连次数
  reconnectLimit?: number
  // 重连间隔（毫秒）
  reconnectInterval?: number
  // 心跳间隔（毫秒）
  heartbeatInterval?: number
  // 心跳消息
  heartbeatMessage?: string
}

export interface UseWebSocketReturn {
  // 状态
  ws: Ref<WebSocket | null>
  readyState: Ref<number>
  isConnected: Ref<boolean>
  // 方法
  connect: () => void
  disconnect: () => void
  send: (data: string | object) => void
  // 数据
  data: Ref<any>
  error: Ref<Event | null>
}

export function useWebSocket(
  url: string,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    autoConnect = true,
    autoReconnect = true,
    reconnectLimit = 3,
    reconnectInterval = 3000,
    heartbeatInterval = 30000,
    heartbeatMessage = 'ping'
  } = options
  
  // 响应式状态
  const ws = ref<WebSocket | null>(null)
  const readyState = ref<number>(WebSocket.CLOSED)
  const isConnected = ref(false)
  const data = ref<any>(null)
  const error = ref<Event | null>(null)
  
  // 内部状态
  let reconnectCount = 0
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let heartbeatTimer: ReturnType<typeof setInterval> | null = null
  
  // 清理定时器
  const clearTimers = () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (heartbeatTimer) {
      clearInterval(heartbeatTimer)
      heartbeatTimer = null
    }
  }
  
  // 开始心跳
  const startHeartbeat = () => {
    if (heartbeatInterval <= 0) return
    
    heartbeatTimer = setInterval(() => {
      if (isConnected.value) {
        send(heartbeatMessage)
      }
    }, heartbeatInterval)
  }
  
  // 建立连接
  const connect = () => {
    if (ws.value?.readyState === WebSocket.OPEN) return
    
    clearTimers()
    
    ws.value = new WebSocket(url)
    readyState.value = WebSocket.CONNECTING
    
    ws.value.onopen = () => {
      readyState.value = WebSocket.OPEN
      isConnected.value = true
      reconnectCount = 0
      error.value = null
      startHeartbeat()
    }
    
    ws.value.onmessage = (event: MessageEvent) => {
      // 忽略心跳响应
      if (event.data === 'pong') return
      
      try {
        data.value = JSON.parse(event.data)
      } catch {
        data.value = event.data
      }
    }
    
    ws.value.onclose = () => {
      readyState.value = WebSocket.CLOSED
      isConnected.value = false
      clearTimers()
      
      // 自动重连
      if (autoReconnect && reconnectCount < reconnectLimit) {
        reconnectCount++
        console.log(`尝试重连 (${reconnectCount}/${reconnectLimit})...`)
        reconnectTimer = setTimeout(connect, reconnectInterval)
      }
    }
    
    ws.value.onerror = (e: Event) => {
      error.value = e
      readyState.value = WebSocket.CLOSED
      isConnected.value = false
    }
  }
  
  // 断开连接
  const disconnect = () => {
    reconnectCount = reconnectLimit // 阻止自动重连
    clearTimers()
    ws.value?.close(1000, '用户主动断开')
    ws.value = null
    isConnected.value = false
    readyState.value = WebSocket.CLOSED
  }
  
  // 发送消息
  const send = (message: string | object) => {
    if (!isConnected.value) {
      console.warn('WebSocket 未连接')
      return
    }
    
    const msg = typeof message === 'string' ? message : JSON.stringify(message)
    ws.value?.send(msg)
  }
  
  // 自动连接
  if (autoConnect) {
    connect()
  }
  
  // 组件卸载时清理
  onUnmounted(() => {
    disconnect()
  })
  
  return {
    ws,
    readyState,
    isConnected,
    data,
    error,
    connect,
    disconnect,
    send
  }
}
```

### 3.3 使用 Composable

```vue
<template>
  <div>
    <p>连接状态: {{ isConnected ? '已连接' : '未连接' }}</p>
    <p>最新消息: {{ data }}</p>
    
    <button @click="send({ type: 'hello' })">发送消息</button>
    <button @click="isConnected ? disconnect() : connect()">
      {{ isConnected ? '断开' : '连接' }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { watch } from 'vue'
import { useWebSocket } from '@/composables/useWebSocket'

const { isConnected, data, send, connect, disconnect } = useWebSocket(
  'ws://localhost:3000',
  {
    autoConnect: true,
    autoReconnect: true,
    reconnectLimit: 5,
    heartbeatInterval: 30000
  }
)

// 监听数据变化
watch(data, (newData) => {
  if (newData) {
    console.log('收到新消息:', newData)
  }
})
</script>
```


---

## 4. 封装 WebSocket 类

### 4.1 完整的 WebSocket 封装类

`src/utils/websocket.ts`：

```typescript
type MessageHandler = (data: any) => void
type EventHandler = (event: Event) => void

export interface WebSocketOptions {
  url: string
  protocols?: string | string[]
  // 自动重连
  autoReconnect?: boolean
  reconnectLimit?: number
  reconnectInterval?: number
  // 心跳
  heartbeat?: boolean
  heartbeatInterval?: number
  heartbeatMessage?: string | (() => string)
  heartbeatTimeout?: number
}

export class WebSocketClient {
  private ws: WebSocket | null = null
  private options: Required<WebSocketOptions>
  private reconnectCount = 0
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private heartbeatTimeoutTimer: ReturnType<typeof setTimeout> | null = null
  private isManualClose = false
  
  // 事件处理器
  private messageHandlers: Map<string, Set<MessageHandler>> = new Map()
  private onOpenHandlers: Set<EventHandler> = new Set()
  private onCloseHandlers: Set<EventHandler> = new Set()
  private onErrorHandlers: Set<EventHandler> = new Set()
  
  constructor(options: WebSocketOptions) {
    this.options = {
      protocols: [],
      autoReconnect: true,
      reconnectLimit: 5,
      reconnectInterval: 3000,
      heartbeat: true,
      heartbeatInterval: 30000,
      heartbeatMessage: 'ping',
      heartbeatTimeout: 5000,
      ...options
    }
  }
  
  // 获取连接状态
  get readyState(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED
  }
  
  get isConnected(): boolean {
    return this.readyState === WebSocket.OPEN
  }
  
  // 建立连接
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.isConnected) {
        resolve()
        return
      }
      
      this.isManualClose = false
      this.clearAllTimers()
      
      try {
        this.ws = new WebSocket(this.options.url, this.options.protocols)
      } catch (error) {
        reject(error)
        return
      }
      
      this.ws.onopen = (event) => {
        console.log('[WebSocket] 连接成功')
        this.reconnectCount = 0
        this.startHeartbeat()
        this.onOpenHandlers.forEach(handler => handler(event))
        resolve()
      }
      
      this.ws.onmessage = (event) => {
        this.handleMessage(event)
      }
      
      this.ws.onclose = (event) => {
        console.log(`[WebSocket] 连接关闭: ${event.code}`)
        this.clearAllTimers()
        this.onCloseHandlers.forEach(handler => handler(event))
        
        // 非手动关闭时尝试重连
        if (!this.isManualClose && this.options.autoReconnect) {
          this.tryReconnect()
        }
      }
      
      this.ws.onerror = (event) => {
        console.error('[WebSocket] 连接错误')
        this.onErrorHandlers.forEach(handler => handler(event))
        reject(event)
      }
    })
  }
  
  // 断开连接
  disconnect(code = 1000, reason = '主动断开'): void {
    this.isManualClose = true
    this.clearAllTimers()
    
    if (this.ws) {
      this.ws.close(code, reason)
      this.ws = null
    }
  }
  
  // 发送消息
  send(data: string | object): boolean {
    if (!this.isConnected) {
      console.warn('[WebSocket] 未连接，无法发送消息')
      return false
    }
    
    const message = typeof data === 'string' ? data : JSON.stringify(data)
    this.ws!.send(message)
    return true
  }
  
  // 发送带类型的消息
  emit(type: string, payload?: any): boolean {
    return this.send({ type, payload, timestamp: Date.now() })
  }
  
  // 监听特定类型的消息
  on(type: string, handler: MessageHandler): () => void {
    if (!this.messageHandlers.has(type)) {
      this.messageHandlers.set(type, new Set())
    }
    this.messageHandlers.get(type)!.add(handler)
    
    // 返回取消监听的函数
    return () => this.off(type, handler)
  }
  
  // 取消监听
  off(type: string, handler?: MessageHandler): void {
    if (!handler) {
      this.messageHandlers.delete(type)
    } else {
      this.messageHandlers.get(type)?.delete(handler)
    }
  }
  
  // 监听连接事件
  onOpen(handler: EventHandler): () => void {
    this.onOpenHandlers.add(handler)
    return () => this.onOpenHandlers.delete(handler)
  }
  
  onClose(handler: EventHandler): () => void {
    this.onCloseHandlers.add(handler)
    return () => this.onCloseHandlers.delete(handler)
  }
  
  onError(handler: EventHandler): () => void {
    this.onErrorHandlers.add(handler)
    return () => this.onErrorHandlers.delete(handler)
  }
  
  // 处理收到的消息
  private handleMessage(event: MessageEvent): void {
    // 重置心跳超时
    this.resetHeartbeatTimeout()
    
    let data: any
    try {
      data = JSON.parse(event.data)
    } catch {
      data = event.data
    }
    
    // 心跳响应
    if (data === 'pong' || data?.type === 'pong') {
      return
    }
    
    // 触发对应类型的处理器
    if (data?.type) {
      const handlers = this.messageHandlers.get(data.type)
      handlers?.forEach(handler => handler(data.payload ?? data))
    }
    
    // 触发通用消息处理器
    const allHandlers = this.messageHandlers.get('*')
    allHandlers?.forEach(handler => handler(data))
  }
  
  // 心跳相关
  private startHeartbeat(): void {
    if (!this.options.heartbeat) return
    
    this.heartbeatTimer = setInterval(() => {
      if (this.isConnected) {
        const message = typeof this.options.heartbeatMessage === 'function'
          ? this.options.heartbeatMessage()
          : this.options.heartbeatMessage
        this.ws!.send(message)
        this.startHeartbeatTimeout()
      }
    }, this.options.heartbeatInterval)
  }
  
  private startHeartbeatTimeout(): void {
    this.heartbeatTimeoutTimer = setTimeout(() => {
      console.warn('[WebSocket] 心跳超时，断开连接')
      this.ws?.close()
    }, this.options.heartbeatTimeout)
  }
  
  private resetHeartbeatTimeout(): void {
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer)
      this.heartbeatTimeoutTimer = null
    }
  }
  
  // 重连相关
  private tryReconnect(): void {
    if (this.reconnectCount >= this.options.reconnectLimit) {
      console.error('[WebSocket] 重连次数已达上限')
      return
    }
    
    this.reconnectCount++
    console.log(`[WebSocket] ${this.options.reconnectInterval}ms 后尝试第 ${this.reconnectCount} 次重连...`)
    
    this.reconnectTimer = setTimeout(() => {
      this.connect().catch(() => {})
    }, this.options.reconnectInterval)
  }
  
  // 清理定时器
  private clearAllTimers(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer)
      this.heartbeatTimeoutTimer = null
    }
  }
  
  // 销毁实例
  destroy(): void {
    this.disconnect()
    this.messageHandlers.clear()
    this.onOpenHandlers.clear()
    this.onCloseHandlers.clear()
    this.onErrorHandlers.clear()
  }
}
```


### 4.2 使用封装类

```typescript
import { WebSocketClient } from '@/utils/websocket'

// 创建实例
const ws = new WebSocketClient({
  url: 'wss://api.example.com/ws',
  autoReconnect: true,
  reconnectLimit: 5,
  heartbeat: true,
  heartbeatInterval: 30000
})

// 监听连接事件
ws.onOpen(() => {
  console.log('连接成功')
})

ws.onClose(() => {
  console.log('连接关闭')
})

ws.onError((error) => {
  console.error('连接错误', error)
})

// 监听特定类型的消息
ws.on('chat', (data) => {
  console.log('收到聊天消息:', data)
})

ws.on('notification', (data) => {
  console.log('收到通知:', data)
})

// 监听所有消息
ws.on('*', (data) => {
  console.log('收到消息:', data)
})

// 建立连接
await ws.connect()

// 发送消息
ws.emit('chat', { content: '你好', to: 'user123' })

// 断开连接
ws.disconnect()

// 销毁实例
ws.destroy()
```

---

## 5. 心跳检测与断线重连

### 5.1 为什么需要心跳检测？

WebSocket 连接可能因为以下原因"假死"：

1. **网络不稳定**：移动网络切换、WiFi 断开
2. **代理/防火墙**：长时间无数据传输被断开
3. **服务器问题**：服务器崩溃但未发送关闭帧
4. **NAT 超时**：路由器/防火墙的 NAT 表项过期

心跳检测可以：
- ✅ 保持连接活跃，防止被中间设备断开
- ✅ 及时发现连接异常
- ✅ 触发重连机制

### 5.2 心跳检测实现原理

```
客户端                                    服务器
   |                                        |
   |  发送心跳 (ping)                        |
   |--------------------------------------->|
   |                                        |
   |  响应心跳 (pong)                        |
   |<---------------------------------------|
   |                                        |
   |  [等待 heartbeatInterval]              |
   |                                        |
   |  发送心跳 (ping)                        |
   |--------------------------------------->|
   |                                        |
   |  [超过 heartbeatTimeout 未收到响应]     |
   |  判定连接异常，触发重连                  |
   |                                        |
```

### 5.3 完整的心跳检测实现

```typescript
class HeartbeatWebSocket {
  private ws: WebSocket | null = null
  private url: string
  
  // 心跳配置
  private heartbeatInterval = 30000  // 心跳间隔
  private heartbeatTimeout = 5000    // 心跳超时时间
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private heartbeatTimeoutTimer: ReturnType<typeof setTimeout> | null = null
  
  // 重连配置
  private reconnectInterval = 3000   // 重连间隔
  private reconnectLimit = 5         // 最大重连次数
  private reconnectCount = 0         // 当前重连次数
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  
  private isManualClose = false      // 是否手动关闭
  
  constructor(url: string) {
    this.url = url
  }
  
  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return
    
    this.isManualClose = false
    this.ws = new WebSocket(this.url)
    
    this.ws.onopen = () => {
      console.log('✅ 连接成功')
      this.reconnectCount = 0
      this.startHeartbeat()
    }
    
    this.ws.onmessage = (event) => {
      // 收到任何消息都重置心跳超时
      this.resetHeartbeatTimeout()
      
      if (event.data === 'pong') {
        console.log('💓 收到心跳响应')
        return
      }
      
      // 处理业务消息
      this.handleMessage(event.data)
    }
    
    this.ws.onclose = () => {
      console.log('❌ 连接关闭')
      this.stopHeartbeat()
      
      if (!this.isManualClose) {
        this.reconnect()
      }
    }
    
    this.ws.onerror = () => {
      console.error('⚠️ 连接错误')
    }
  }
  
  // 开始心跳
  private startHeartbeat(): void {
    this.stopHeartbeat()
    
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        console.log('💓 发送心跳')
        this.ws.send('ping')
        
        // 设置心跳超时检测
        this.heartbeatTimeoutTimer = setTimeout(() => {
          console.warn('💔 心跳超时，关闭连接')
          this.ws?.close()
        }, this.heartbeatTimeout)
      }
    }, this.heartbeatInterval)
  }
  
  // 停止心跳
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
    this.resetHeartbeatTimeout()
  }
  
  // 重置心跳超时
  private resetHeartbeatTimeout(): void {
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer)
      this.heartbeatTimeoutTimer = null
    }
  }
  
  // 重连
  private reconnect(): void {
    if (this.reconnectCount >= this.reconnectLimit) {
      console.error('🚫 重连次数已达上限')
      return
    }
    
    this.reconnectCount++
    console.log(`🔄 ${this.reconnectInterval}ms 后进行第 ${this.reconnectCount} 次重连...`)
    
    this.reconnectTimer = setTimeout(() => {
      this.connect()
    }, this.reconnectInterval)
  }
  
  // 处理消息
  private handleMessage(data: string): void {
    try {
      const message = JSON.parse(data)
      console.log('📩 收到消息:', message)
    } catch {
      console.log('📩 收到消息:', data)
    }
  }
  
  // 发送消息
  send(data: string | object): void {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      console.warn('WebSocket 未连接')
      return
    }
    
    const message = typeof data === 'string' ? data : JSON.stringify(data)
    this.ws.send(message)
  }
  
  // 关闭连接
  close(): void {
    this.isManualClose = true
    this.stopHeartbeat()
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    
    this.ws?.close(1000, '用户主动关闭')
  }
}
```


### 5.4 指数退避重连策略

简单的固定间隔重连可能会在服务器恢复时造成"惊群效应"。使用指数退避可以分散重连请求：

```typescript
class ExponentialBackoffReconnect {
  private baseInterval = 1000      // 基础间隔 1 秒
  private maxInterval = 30000      // 最大间隔 30 秒
  private reconnectCount = 0
  
  // 计算下次重连间隔
  getNextInterval(): number {
    // 指数退避：1s, 2s, 4s, 8s, 16s, 30s, 30s...
    const interval = Math.min(
      this.baseInterval * Math.pow(2, this.reconnectCount),
      this.maxInterval
    )
    
    // 添加随机抖动，避免同时重连
    const jitter = Math.random() * 1000
    
    return interval + jitter
  }
  
  // 重连成功后重置
  reset(): void {
    this.reconnectCount = 0
  }
  
  // 重连失败后增加计数
  increment(): void {
    this.reconnectCount++
  }
}

// 使用
const backoff = new ExponentialBackoffReconnect()

const reconnect = () => {
  const interval = backoff.getNextInterval()
  console.log(`${interval}ms 后重连...`)
  
  setTimeout(() => {
    connect()
      .then(() => backoff.reset())
      .catch(() => {
        backoff.increment()
        reconnect()
      })
  }, interval)
}
```

---

## 6. 消息队列与离线缓存

### 6.1 为什么需要消息队列？

在以下场景中，消息队列非常有用：

1. **连接未建立时发送消息**：将消息缓存，连接后自动发送
2. **断线重连期间**：缓存用户操作，重连后同步
3. **消息确认机制**：确保消息送达

### 6.2 消息队列实现

```typescript
interface QueuedMessage {
  id: string
  data: any
  timestamp: number
  retryCount: number
}

class MessageQueue {
  private queue: QueuedMessage[] = []
  private maxRetry = 3
  private maxQueueSize = 100
  
  // 添加消息到队列
  enqueue(data: any): string {
    const id = this.generateId()
    
    // 队列满时移除最旧的消息
    if (this.queue.length >= this.maxQueueSize) {
      this.queue.shift()
    }
    
    this.queue.push({
      id,
      data,
      timestamp: Date.now(),
      retryCount: 0
    })
    
    return id
  }
  
  // 获取所有待发送消息
  getAll(): QueuedMessage[] {
    return [...this.queue]
  }
  
  // 移除已发送的消息
  remove(id: string): void {
    const index = this.queue.findIndex(msg => msg.id === id)
    if (index > -1) {
      this.queue.splice(index, 1)
    }
  }
  
  // 标记重试
  markRetry(id: string): boolean {
    const message = this.queue.find(msg => msg.id === id)
    if (message) {
      message.retryCount++
      if (message.retryCount >= this.maxRetry) {
        this.remove(id)
        return false // 超过重试次数
      }
      return true
    }
    return false
  }
  
  // 清空队列
  clear(): void {
    this.queue = []
  }
  
  // 获取队列长度
  get length(): number {
    return this.queue.length
  }
  
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }
}
```

### 6.3 带消息队列的 WebSocket

```typescript
class QueuedWebSocket {
  private ws: WebSocket | null = null
  private url: string
  private messageQueue = new MessageQueue()
  private pendingMessages = new Map<string, QueuedMessage>()
  private messageTimeout = 5000 // 消息确认超时
  
  constructor(url: string) {
    this.url = url
  }
  
  connect(): void {
    this.ws = new WebSocket(this.url)
    
    this.ws.onopen = () => {
      console.log('连接成功，发送队列中的消息...')
      this.flushQueue()
    }
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      
      // 处理消息确认
      if (data.type === 'ack') {
        this.handleAck(data.messageId)
        return
      }
      
      // 处理业务消息
      this.handleMessage(data)
    }
    
    this.ws.onclose = () => {
      // 将未确认的消息放回队列
      this.pendingMessages.forEach((msg) => {
        this.messageQueue.enqueue(msg.data)
      })
      this.pendingMessages.clear()
    }
  }
  
  // 发送消息（带队列支持）
  send(data: any): string {
    const messageId = this.messageQueue.enqueue(data)
    
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.sendMessage(messageId, data)
    }
    
    return messageId
  }
  
  // 实际发送消息
  private sendMessage(id: string, data: any): void {
    const message = { id, ...data }
    this.ws!.send(JSON.stringify(message))
    
    // 移到待确认队列
    this.pendingMessages.set(id, {
      id,
      data,
      timestamp: Date.now(),
      retryCount: 0
    })
    
    // 设置超时
    setTimeout(() => {
      if (this.pendingMessages.has(id)) {
        console.warn(`消息 ${id} 超时未确认`)
        this.retryMessage(id)
      }
    }, this.messageTimeout)
  }
  
  // 处理消息确认
  private handleAck(messageId: string): void {
    this.messageQueue.remove(messageId)
    this.pendingMessages.delete(messageId)
    console.log(`消息 ${messageId} 已确认`)
  }
  
  // 重试发送
  private retryMessage(id: string): void {
    const message = this.pendingMessages.get(id)
    if (message && this.messageQueue.markRetry(id)) {
      this.sendMessage(id, message.data)
    }
  }
  
  // 发送队列中的所有消息
  private flushQueue(): void {
    const messages = this.messageQueue.getAll()
    messages.forEach(msg => {
      this.sendMessage(msg.id, msg.data)
    })
  }
  
  private handleMessage(data: any): void {
    console.log('收到消息:', data)
  }
}
```


### 6.4 离线消息存储

使用 localStorage 或 IndexedDB 持久化消息：

```typescript
class PersistentMessageQueue {
  private storageKey = 'ws_message_queue'
  
  // 保存到本地存储
  save(messages: QueuedMessage[]): void {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(messages))
    } catch (e) {
      console.error('保存消息队列失败:', e)
    }
  }
  
  // 从本地存储加载
  load(): QueuedMessage[] {
    try {
      const data = localStorage.getItem(this.storageKey)
      return data ? JSON.parse(data) : []
    } catch {
      return []
    }
  }
  
  // 清除本地存储
  clear(): void {
    localStorage.removeItem(this.storageKey)
  }
}

// 使用 IndexedDB 存储大量消息
class IndexedDBMessageStore {
  private dbName = 'WebSocketMessages'
  private storeName = 'messages'
  private db: IDBDatabase | null = null
  
  async init(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1)
      
      request.onerror = () => reject(request.error)
      request.onsuccess = () => {
        this.db = request.result
        resolve()
      }
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'id' })
        }
      }
    })
  }
  
  async add(message: QueuedMessage): Promise<void> {
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(this.storeName, 'readwrite')
      const store = transaction.objectStore(this.storeName)
      const request = store.add(message)
      
      request.onsuccess = () => resolve()
      request.onerror = () => reject(request.error)
    })
  }
  
  async getAll(): Promise<QueuedMessage[]> {
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(this.storeName, 'readonly')
      const store = transaction.objectStore(this.storeName)
      const request = store.getAll()
      
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
  }
  
  async delete(id: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(this.storeName, 'readwrite')
      const store = transaction.objectStore(this.storeName)
      const request = store.delete(id)
      
      request.onsuccess = () => resolve()
      request.onerror = () => reject(request.error)
    })
  }
  
  async clear(): Promise<void> {
    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(this.storeName, 'readwrite')
      const store = transaction.objectStore(this.storeName)
      const request = store.clear()
      
      request.onsuccess = () => resolve()
      request.onerror = () => reject(request.error)
    })
  }
}
```

---

## 7. TypeScript 类型定义

### 7.1 基础类型定义

`src/types/websocket.ts`：

```typescript
// WebSocket 连接状态
export enum WebSocketState {
  CONNECTING = 0,
  OPEN = 1,
  CLOSING = 2,
  CLOSED = 3
}

// 消息类型枚举
export enum MessageType {
  // 系统消息
  PING = 'ping',
  PONG = 'pong',
  ACK = 'ack',
  ERROR = 'error',
  
  // 业务消息
  CHAT = 'chat',
  NOTIFICATION = 'notification',
  USER_JOIN = 'user_join',
  USER_LEAVE = 'user_leave',
  TYPING = 'typing'
}

// 基础消息结构
export interface BaseMessage<T = any> {
  id: string
  type: MessageType | string
  payload: T
  timestamp: number
}

// 聊天消息
export interface ChatMessage {
  content: string
  from: string
  to: string
  roomId?: string
}

// 通知消息
export interface NotificationMessage {
  title: string
  content: string
  level: 'info' | 'warning' | 'error' | 'success'
}

// 用户状态消息
export interface UserStatusMessage {
  userId: string
  username: string
  status: 'online' | 'offline' | 'away'
}

// 消息处理器类型
export type MessageHandler<T = any> = (message: BaseMessage<T>) => void

// WebSocket 配置
export interface WebSocketConfig {
  url: string
  protocols?: string | string[]
  autoReconnect?: boolean
  reconnectLimit?: number
  reconnectInterval?: number
  heartbeat?: boolean
  heartbeatInterval?: number
  heartbeatTimeout?: number
  debug?: boolean
}

// WebSocket 事件
export interface WebSocketEvents {
  open: () => void
  close: (event: CloseEvent) => void
  error: (event: Event) => void
  message: (data: any) => void
  reconnect: (count: number) => void
  reconnectFailed: () => void
}
```

### 7.2 泛型消息处理

```typescript
// 类型安全的消息发送和接收
class TypedWebSocket {
  private ws: WebSocket | null = null
  private handlers = new Map<string, Set<Function>>()
  
  // 发送类型安全的消息
  send<T extends keyof MessagePayloadMap>(
    type: T,
    payload: MessagePayloadMap[T]
  ): void {
    const message: BaseMessage<MessagePayloadMap[T]> = {
      id: this.generateId(),
      type,
      payload,
      timestamp: Date.now()
    }
    
    this.ws?.send(JSON.stringify(message))
  }
  
  // 监听类型安全的消息
  on<T extends keyof MessagePayloadMap>(
    type: T,
    handler: (payload: MessagePayloadMap[T]) => void
  ): () => void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set())
    }
    this.handlers.get(type)!.add(handler)
    
    return () => this.handlers.get(type)?.delete(handler)
  }
  
  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }
}

// 消息类型映射
interface MessagePayloadMap {
  [MessageType.CHAT]: ChatMessage
  [MessageType.NOTIFICATION]: NotificationMessage
  [MessageType.USER_JOIN]: UserStatusMessage
  [MessageType.USER_LEAVE]: UserStatusMessage
  [MessageType.TYPING]: { userId: string; roomId: string }
}

// 使用
const ws = new TypedWebSocket()

// 类型安全的发送
ws.send(MessageType.CHAT, {
  content: '你好',
  from: 'user1',
  to: 'user2'
})

// 类型安全的监听
ws.on(MessageType.CHAT, (payload) => {
  // payload 自动推断为 ChatMessage 类型
  console.log(payload.content, payload.from)
})
```


---

## 8. 实战：聊天室应用

### 8.1 聊天室 WebSocket 服务

`src/services/chatSocket.ts`：

```typescript
import { WebSocketClient } from '@/utils/websocket'
import type { ChatMessage, UserStatusMessage } from '@/types/websocket'

export interface ChatRoom {
  id: string
  name: string
  members: string[]
}

class ChatSocketService {
  private ws: WebSocketClient | null = null
  private currentRoom: string | null = null
  
  // 事件回调
  private onMessageCallback: ((msg: ChatMessage) => void) | null = null
  private onUserJoinCallback: ((user: UserStatusMessage) => void) | null = null
  private onUserLeaveCallback: ((user: UserStatusMessage) => void) | null = null
  private onTypingCallback: ((userId: string) => void) | null = null
  
  // 初始化连接
  init(token: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocketClient({
        url: `${import.meta.env.VITE_WS_URL}?token=${token}`,
        autoReconnect: true,
        reconnectLimit: 10,
        heartbeat: true,
        heartbeatInterval: 30000
      })
      
      // 监听消息
      this.ws.on('chat', (data: ChatMessage) => {
        this.onMessageCallback?.(data)
      })
      
      this.ws.on('user_join', (data: UserStatusMessage) => {
        this.onUserJoinCallback?.(data)
      })
      
      this.ws.on('user_leave', (data: UserStatusMessage) => {
        this.onUserLeaveCallback?.(data)
      })
      
      this.ws.on('typing', (data: { userId: string }) => {
        this.onTypingCallback?.(data.userId)
      })
      
      this.ws.onOpen(() => resolve())
      this.ws.onError(() => reject(new Error('连接失败')))
      
      this.ws.connect()
    })
  }
  
  // 加入房间
  joinRoom(roomId: string): void {
    this.currentRoom = roomId
    this.ws?.emit('join_room', { roomId })
  }
  
  // 离开房间
  leaveRoom(): void {
    if (this.currentRoom) {
      this.ws?.emit('leave_room', { roomId: this.currentRoom })
      this.currentRoom = null
    }
  }
  
  // 发送消息
  sendMessage(content: string, to?: string): void {
    if (!this.currentRoom) return
    
    this.ws?.emit('chat', {
      content,
      roomId: this.currentRoom,
      to
    })
  }
  
  // 发送正在输入状态
  sendTyping(): void {
    if (!this.currentRoom) return
    this.ws?.emit('typing', { roomId: this.currentRoom })
  }
  
  // 注册回调
  onMessage(callback: (msg: ChatMessage) => void): void {
    this.onMessageCallback = callback
  }
  
  onUserJoin(callback: (user: UserStatusMessage) => void): void {
    this.onUserJoinCallback = callback
  }
  
  onUserLeave(callback: (user: UserStatusMessage) => void): void {
    this.onUserLeaveCallback = callback
  }
  
  onTyping(callback: (userId: string) => void): void {
    this.onTypingCallback = callback
  }
  
  // 断开连接
  disconnect(): void {
    this.leaveRoom()
    this.ws?.disconnect()
    this.ws = null
  }
}

// 导出单例
export const chatSocket = new ChatSocketService()
```

### 8.2 聊天室组件

```vue
<template>
  <div class="chat-room">
    <!-- 用户列表 -->
    <aside class="user-list">
      <h3>在线用户 ({{ onlineUsers.length }})</h3>
      <ul>
        <li v-for="user in onlineUsers" :key="user.userId">
          <span class="status-dot online"></span>
          {{ user.username }}
        </li>
      </ul>
    </aside>
    
    <!-- 消息区域 -->
    <main class="message-area">
      <div class="messages" ref="messagesRef">
        <div
          v-for="msg in messages"
          :key="msg.id"
          :class="['message', { 'own': msg.from === currentUser }]"
        >
          <div class="message-header">
            <span class="username">{{ msg.from }}</span>
            <span class="time">{{ formatTime(msg.timestamp) }}</span>
          </div>
          <div class="message-content">{{ msg.content }}</div>
        </div>
      </div>
      
      <!-- 正在输入提示 -->
      <div v-if="typingUser" class="typing-indicator">
        {{ typingUser }} 正在输入...
      </div>
      
      <!-- 输入框 -->
      <div class="input-area">
        <input
          v-model="inputMessage"
          @input="handleTyping"
          @keyup.enter="sendMessage"
          placeholder="输入消息..."
        />
        <button @click="sendMessage" :disabled="!inputMessage.trim()">
          发送
        </button>
      </div>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { chatSocket } from '@/services/chatSocket'
import type { ChatMessage, UserStatusMessage } from '@/types/websocket'
import { useUserStore } from '@/stores/user'
import { throttle } from 'lodash-es'

const props = defineProps<{
  roomId: string
}>()

const userStore = useUserStore()
const currentUser = userStore.userInfo?.username || ''

// 状态
const messages = ref<(ChatMessage & { id: string; timestamp: number })[]>([])
const onlineUsers = ref<UserStatusMessage[]>([])
const inputMessage = ref('')
const typingUser = ref<string | null>(null)
const messagesRef = ref<HTMLElement | null>(null)

let typingTimer: ReturnType<typeof setTimeout> | null = null

// 格式化时间
const formatTime = (timestamp: number): string => {
  return new Date(timestamp).toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit'
  })
}

// 滚动到底部
const scrollToBottom = () => {
  nextTick(() => {
    if (messagesRef.value) {
      messagesRef.value.scrollTop = messagesRef.value.scrollHeight
    }
  })
}

// 发送消息
const sendMessage = () => {
  if (!inputMessage.value.trim()) return
  
  chatSocket.sendMessage(inputMessage.value)
  
  // 本地添加消息（乐观更新）
  messages.value.push({
    id: Date.now().toString(),
    content: inputMessage.value,
    from: currentUser,
    to: '',
    timestamp: Date.now()
  })
  
  inputMessage.value = ''
  scrollToBottom()
}

// 处理输入（节流发送 typing 状态）
const handleTyping = throttle(() => {
  chatSocket.sendTyping()
}, 1000)

// 初始化
onMounted(async () => {
  try {
    await chatSocket.init(userStore.token!)
    chatSocket.joinRoom(props.roomId)
    
    // 监听消息
    chatSocket.onMessage((msg) => {
      if (msg.from !== currentUser) {
        messages.value.push({
          ...msg,
          id: Date.now().toString(),
          timestamp: Date.now()
        })
        scrollToBottom()
      }
    })
    
    // 监听用户加入
    chatSocket.onUserJoin((user) => {
      onlineUsers.value.push(user)
    })
    
    // 监听用户离开
    chatSocket.onUserLeave((user) => {
      const index = onlineUsers.value.findIndex(u => u.userId === user.userId)
      if (index > -1) {
        onlineUsers.value.splice(index, 1)
      }
    })
    
    // 监听正在输入
    chatSocket.onTyping((userId) => {
      typingUser.value = userId
      
      // 3 秒后清除
      if (typingTimer) clearTimeout(typingTimer)
      typingTimer = setTimeout(() => {
        typingUser.value = null
      }, 3000)
    })
  } catch (error) {
    console.error('连接聊天室失败:', error)
  }
})

// 清理
onUnmounted(() => {
  chatSocket.disconnect()
  if (typingTimer) clearTimeout(typingTimer)
})

// 监听房间变化
watch(() => props.roomId, (newRoomId) => {
  chatSocket.leaveRoom()
  messages.value = []
  chatSocket.joinRoom(newRoomId)
})
</script>

<style scoped>
.chat-room {
  display: flex;
  height: 100%;
}

.user-list {
  width: 200px;
  border-right: 1px solid #eee;
  padding: 16px;
}

.message-area {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.messages {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
}

.message {
  margin-bottom: 16px;
  max-width: 70%;
}

.message.own {
  margin-left: auto;
  text-align: right;
}

.message-content {
  background: #f0f0f0;
  padding: 8px 12px;
  border-radius: 8px;
  display: inline-block;
}

.message.own .message-content {
  background: #1890ff;
  color: white;
}

.typing-indicator {
  padding: 8px 16px;
  color: #999;
  font-size: 12px;
}

.input-area {
  display: flex;
  padding: 16px;
  border-top: 1px solid #eee;
}

.input-area input {
  flex: 1;
  padding: 8px 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  margin-right: 8px;
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 8px;
}

.status-dot.online {
  background: #52c41a;
}
</style>
```


---

## 9. 实战：实时通知系统

### 9.1 通知服务

`src/services/notificationSocket.ts`：

```typescript
import { WebSocketClient } from '@/utils/websocket'
import { ElNotification } from 'element-plus'

export interface Notification {
  id: string
  title: string
  content: string
  type: 'info' | 'success' | 'warning' | 'error'
  read: boolean
  createdAt: string
}

class NotificationService {
  private ws: WebSocketClient | null = null
  private notifications: Notification[] = []
  private listeners: Set<(notifications: Notification[]) => void> = new Set()
  
  // 初始化
  init(token: string): void {
    this.ws = new WebSocketClient({
      url: `${import.meta.env.VITE_WS_URL}/notifications?token=${token}`,
      autoReconnect: true,
      heartbeat: true
    })
    
    this.ws.on('notification', (data: Notification) => {
      this.handleNotification(data)
    })
    
    this.ws.on('notification_batch', (data: Notification[]) => {
      this.notifications = [...data, ...this.notifications]
      this.notifyListeners()
    })
    
    this.ws.connect()
  }
  
  // 处理新通知
  private handleNotification(notification: Notification): void {
    // 添加到列表
    this.notifications.unshift(notification)
    this.notifyListeners()
    
    // 显示桌面通知
    this.showDesktopNotification(notification)
    
    // 显示 UI 通知
    ElNotification({
      title: notification.title,
      message: notification.content,
      type: notification.type,
      duration: 5000
    })
  }
  
  // 显示桌面通知
  private async showDesktopNotification(notification: Notification): Promise<void> {
    // 检查权限
    if (!('Notification' in window)) return
    
    if (Notification.permission === 'default') {
      await Notification.requestPermission()
    }
    
    if (Notification.permission === 'granted') {
      new Notification(notification.title, {
        body: notification.content,
        icon: '/notification-icon.png',
        tag: notification.id
      })
    }
  }
  
  // 获取所有通知
  getNotifications(): Notification[] {
    return this.notifications
  }
  
  // 获取未读数量
  getUnreadCount(): number {
    return this.notifications.filter(n => !n.read).length
  }
  
  // 标记已读
  markAsRead(id: string): void {
    const notification = this.notifications.find(n => n.id === id)
    if (notification) {
      notification.read = true
      this.ws?.emit('mark_read', { id })
      this.notifyListeners()
    }
  }
  
  // 标记全部已读
  markAllAsRead(): void {
    this.notifications.forEach(n => n.read = true)
    this.ws?.emit('mark_all_read', {})
    this.notifyListeners()
  }
  
  // 订阅通知变化
  subscribe(callback: (notifications: Notification[]) => void): () => void {
    this.listeners.add(callback)
    return () => this.listeners.delete(callback)
  }
  
  // 通知所有监听者
  private notifyListeners(): void {
    this.listeners.forEach(callback => callback(this.notifications))
  }
  
  // 断开连接
  disconnect(): void {
    this.ws?.disconnect()
    this.ws = null
  }
}

export const notificationService = new NotificationService()
```

### 9.2 通知组件

```vue
<template>
  <el-popover placement="bottom" :width="360" trigger="click">
    <template #reference>
      <el-badge :value="unreadCount" :hidden="unreadCount === 0">
        <el-button :icon="Bell" circle />
      </el-badge>
    </template>
    
    <div class="notification-panel">
      <div class="notification-header">
        <span>通知</span>
        <el-button link @click="markAllAsRead" :disabled="unreadCount === 0">
          全部已读
        </el-button>
      </div>
      
      <el-scrollbar max-height="400px">
        <div v-if="notifications.length === 0" class="empty">
          暂无通知
        </div>
        
        <div
          v-for="item in notifications"
          :key="item.id"
          :class="['notification-item', { unread: !item.read }]"
          @click="handleClick(item)"
        >
          <div class="notification-icon">
            <el-icon :color="getIconColor(item.type)">
              <component :is="getIcon(item.type)" />
            </el-icon>
          </div>
          <div class="notification-content">
            <div class="notification-title">{{ item.title }}</div>
            <div class="notification-text">{{ item.content }}</div>
            <div class="notification-time">{{ formatTime(item.createdAt) }}</div>
          </div>
        </div>
      </el-scrollbar>
    </div>
  </el-popover>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { Bell, InfoFilled, SuccessFilled, WarningFilled, CircleCloseFilled } from '@element-plus/icons-vue'
import { notificationService, type Notification } from '@/services/notificationSocket'
import { formatDistanceToNow } from 'date-fns'
import { zhCN } from 'date-fns/locale'

const notifications = ref<Notification[]>([])
const unreadCount = ref(0)

// 获取图标
const getIcon = (type: string) => {
  const icons: Record<string, any> = {
    info: InfoFilled,
    success: SuccessFilled,
    warning: WarningFilled,
    error: CircleCloseFilled
  }
  return icons[type] || InfoFilled
}

// 获取图标颜色
const getIconColor = (type: string) => {
  const colors: Record<string, string> = {
    info: '#409eff',
    success: '#67c23a',
    warning: '#e6a23c',
    error: '#f56c6c'
  }
  return colors[type] || '#409eff'
}

// 格式化时间
const formatTime = (time: string) => {
  return formatDistanceToNow(new Date(time), { addSuffix: true, locale: zhCN })
}

// 点击通知
const handleClick = (item: Notification) => {
  if (!item.read) {
    notificationService.markAsRead(item.id)
  }
}

// 全部已读
const markAllAsRead = () => {
  notificationService.markAllAsRead()
}

// 更新通知列表
const updateNotifications = (list: Notification[]) => {
  notifications.value = list
  unreadCount.value = notificationService.getUnreadCount()
}

onMounted(() => {
  // 订阅通知变化
  const unsubscribe = notificationService.subscribe(updateNotifications)
  
  // 初始化数据
  notifications.value = notificationService.getNotifications()
  unreadCount.value = notificationService.getUnreadCount()
  
  onUnmounted(unsubscribe)
})
</script>

<style scoped>
.notification-panel {
  margin: -12px;
}

.notification-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid #eee;
  font-weight: 500;
}

.notification-item {
  display: flex;
  padding: 12px 16px;
  cursor: pointer;
  transition: background 0.2s;
}

.notification-item:hover {
  background: #f5f5f5;
}

.notification-item.unread {
  background: #f0f7ff;
}

.notification-icon {
  margin-right: 12px;
  font-size: 20px;
}

.notification-content {
  flex: 1;
  min-width: 0;
}

.notification-title {
  font-weight: 500;
  margin-bottom: 4px;
}

.notification-text {
  color: #666;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.notification-time {
  color: #999;
  font-size: 12px;
  margin-top: 4px;
}

.empty {
  padding: 40px;
  text-align: center;
  color: #999;
}
</style>
```

### 9.3 在 App 中初始化

```typescript
// src/App.vue 或 main.ts
import { notificationService } from '@/services/notificationSocket'
import { useUserStore } from '@/stores/user'

const userStore = useUserStore()

// 用户登录后初始化通知服务
watch(
  () => userStore.token,
  (token) => {
    if (token) {
      notificationService.init(token)
    } else {
      notificationService.disconnect()
    }
  },
  { immediate: true }
)
```


---

## 10. Socket.IO 集成

### 10.1 什么是 Socket.IO？

Socket.IO 是一个基于 WebSocket 的实时通信库，提供了更多高级功能：

- ✅ 自动重连
- ✅ 房间和命名空间
- ✅ 广播
- ✅ 二进制数据支持
- ✅ 降级支持（WebSocket 不可用时使用轮询）
- ✅ 消息确认

### 10.2 安装 Socket.IO 客户端

```bash
npm install socket.io-client
```

### 10.3 基础使用

```typescript
import { io, Socket } from 'socket.io-client'

// 创建连接
const socket: Socket = io('http://localhost:3000', {
  // 连接选项
  autoConnect: true,           // 自动连接
  reconnection: true,          // 自动重连
  reconnectionAttempts: 5,     // 重连次数
  reconnectionDelay: 1000,     // 重连延迟
  reconnectionDelayMax: 5000,  // 最大重连延迟
  timeout: 20000,              // 连接超时
  
  // 认证
  auth: {
    token: 'your-jwt-token'
  },
  
  // 查询参数
  query: {
    userId: '123'
  }
})

// 连接事件
socket.on('connect', () => {
  console.log('连接成功，ID:', socket.id)
})

socket.on('disconnect', (reason) => {
  console.log('断开连接:', reason)
})

socket.on('connect_error', (error) => {
  console.error('连接错误:', error)
})

// 发送消息
socket.emit('chat', { message: '你好' })

// 带回调的发送（消息确认）
socket.emit('chat', { message: '你好' }, (response: any) => {
  console.log('服务器确认:', response)
})

// 监听消息
socket.on('chat', (data) => {
  console.log('收到消息:', data)
})

// 断开连接
socket.disconnect()
```

### 10.4 封装 Socket.IO 服务

`src/services/socketio.ts`：

```typescript
import { io, Socket } from 'socket.io-client'
import { ref, type Ref } from 'vue'

export interface SocketIOOptions {
  url: string
  token?: string
  autoConnect?: boolean
}

class SocketIOService {
  private socket: Socket | null = null
  private _isConnected: Ref<boolean> = ref(false)
  
  get isConnected(): Ref<boolean> {
    return this._isConnected
  }
  
  // 初始化连接
  connect(options: SocketIOOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = io(options.url, {
        autoConnect: options.autoConnect ?? true,
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 1000,
        auth: options.token ? { token: options.token } : undefined
      })
      
      this.socket.on('connect', () => {
        this._isConnected.value = true
        console.log('[Socket.IO] 连接成功')
        resolve()
      })
      
      this.socket.on('disconnect', (reason) => {
        this._isConnected.value = false
        console.log('[Socket.IO] 断开连接:', reason)
      })
      
      this.socket.on('connect_error', (error) => {
        console.error('[Socket.IO] 连接错误:', error)
        reject(error)
      })
    })
  }
  
  // 发送消息
  emit<T = any>(event: string, data?: any): Promise<T> {
    return new Promise((resolve, reject) => {
      if (!this.socket?.connected) {
        reject(new Error('Socket 未连接'))
        return
      }
      
      this.socket.emit(event, data, (response: T) => {
        resolve(response)
      })
    })
  }
  
  // 监听事件
  on<T = any>(event: string, callback: (data: T) => void): () => void {
    this.socket?.on(event, callback)
    return () => this.socket?.off(event, callback)
  }
  
  // 监听一次
  once<T = any>(event: string, callback: (data: T) => void): void {
    this.socket?.once(event, callback)
  }
  
  // 取消监听
  off(event: string, callback?: Function): void {
    if (callback) {
      this.socket?.off(event, callback as any)
    } else {
      this.socket?.off(event)
    }
  }
  
  // 加入房间
  joinRoom(room: string): Promise<void> {
    return this.emit('join', { room })
  }
  
  // 离开房间
  leaveRoom(room: string): Promise<void> {
    return this.emit('leave', { room })
  }
  
  // 断开连接
  disconnect(): void {
    this.socket?.disconnect()
    this.socket = null
    this._isConnected.value = false
  }
}

export const socketIO = new SocketIOService()
```

### 10.5 Vue Composable 封装

```typescript
// src/composables/useSocketIO.ts
import { onMounted, onUnmounted, ref } from 'vue'
import { io, Socket } from 'socket.io-client'

export function useSocketIO(url: string, options?: any) {
  const socket = ref<Socket | null>(null)
  const isConnected = ref(false)
  const error = ref<Error | null>(null)
  
  const connect = () => {
    socket.value = io(url, {
      ...options,
      autoConnect: false
    })
    
    socket.value.on('connect', () => {
      isConnected.value = true
      error.value = null
    })
    
    socket.value.on('disconnect', () => {
      isConnected.value = false
    })
    
    socket.value.on('connect_error', (err) => {
      error.value = err
    })
    
    socket.value.connect()
  }
  
  const disconnect = () => {
    socket.value?.disconnect()
  }
  
  const emit = (event: string, data?: any) => {
    socket.value?.emit(event, data)
  }
  
  const on = (event: string, callback: Function) => {
    socket.value?.on(event, callback as any)
  }
  
  const off = (event: string, callback?: Function) => {
    socket.value?.off(event, callback as any)
  }
  
  onMounted(connect)
  onUnmounted(disconnect)
  
  return {
    socket,
    isConnected,
    error,
    connect,
    disconnect,
    emit,
    on,
    off
  }
}
```

### 10.6 命名空间使用

```typescript
import { io } from 'socket.io-client'

// 连接到不同的命名空间
const chatSocket = io('http://localhost:3000/chat')
const notificationSocket = io('http://localhost:3000/notifications')

// 每个命名空间独立管理
chatSocket.on('message', (data) => {
  console.log('聊天消息:', data)
})

notificationSocket.on('notification', (data) => {
  console.log('通知:', data)
})
```


---

## 11. 性能优化与最佳实践

### 11.1 消息压缩

对于大量数据传输，可以使用压缩减少带宽：

```typescript
// 使用 pako 进行 gzip 压缩
import pako from 'pako'

class CompressedWebSocket {
  private ws: WebSocket
  
  constructor(url: string) {
    this.ws = new WebSocket(url)
    this.ws.binaryType = 'arraybuffer'
  }
  
  // 发送压缩消息
  send(data: object): void {
    const json = JSON.stringify(data)
    const compressed = pako.gzip(json)
    this.ws.send(compressed)
  }
  
  // 接收并解压消息
  onMessage(callback: (data: any) => void): void {
    this.ws.onmessage = (event) => {
      try {
        const decompressed = pako.ungzip(new Uint8Array(event.data), { to: 'string' })
        const data = JSON.parse(decompressed)
        callback(data)
      } catch {
        // 非压缩消息，直接解析
        callback(JSON.parse(event.data))
      }
    }
  }
}
```

### 11.2 消息批处理

减少消息发送频率，批量发送：

```typescript
class BatchedWebSocket {
  private ws: WebSocket
  private messageBuffer: any[] = []
  private batchInterval = 100 // 100ms 批处理一次
  private batchTimer: ReturnType<typeof setTimeout> | null = null
  
  constructor(url: string) {
    this.ws = new WebSocket(url)
  }
  
  // 添加消息到缓冲区
  send(data: any): void {
    this.messageBuffer.push(data)
    this.scheduleBatch()
  }
  
  // 调度批处理
  private scheduleBatch(): void {
    if (this.batchTimer) return
    
    this.batchTimer = setTimeout(() => {
      this.flush()
      this.batchTimer = null
    }, this.batchInterval)
  }
  
  // 发送缓冲区中的所有消息
  private flush(): void {
    if (this.messageBuffer.length === 0) return
    
    const batch = {
      type: 'batch',
      messages: this.messageBuffer
    }
    
    this.ws.send(JSON.stringify(batch))
    this.messageBuffer = []
  }
  
  // 立即发送（不等待批处理）
  sendImmediate(data: any): void {
    this.ws.send(JSON.stringify(data))
  }
}
```

### 11.3 消息节流与防抖

```typescript
import { throttle, debounce } from 'lodash-es'

class ThrottledWebSocket {
  private ws: WebSocket
  
  // 节流发送（如鼠标位置同步）
  sendThrottled = throttle((data: any) => {
    this.ws.send(JSON.stringify(data))
  }, 50) // 每 50ms 最多发送一次
  
  // 防抖发送（如输入状态）
  sendDebounced = debounce((data: any) => {
    this.ws.send(JSON.stringify(data))
  }, 300) // 停止输入 300ms 后发送
  
  constructor(url: string) {
    this.ws = new WebSocket(url)
  }
}
```

### 11.4 连接池管理

对于需要多个 WebSocket 连接的场景：

```typescript
class WebSocketPool {
  private pool: Map<string, WebSocket> = new Map()
  private maxConnections = 5
  
  // 获取或创建连接
  getConnection(url: string): WebSocket {
    if (this.pool.has(url)) {
      const ws = this.pool.get(url)!
      if (ws.readyState === WebSocket.OPEN) {
        return ws
      }
      // 连接已关闭，移除并重新创建
      this.pool.delete(url)
    }
    
    // 检查连接数限制
    if (this.pool.size >= this.maxConnections) {
      // 关闭最旧的连接
      const oldestUrl = this.pool.keys().next().value
      this.closeConnection(oldestUrl)
    }
    
    const ws = new WebSocket(url)
    this.pool.set(url, ws)
    return ws
  }
  
  // 关闭指定连接
  closeConnection(url: string): void {
    const ws = this.pool.get(url)
    if (ws) {
      ws.close()
      this.pool.delete(url)
    }
  }
  
  // 关闭所有连接
  closeAll(): void {
    this.pool.forEach(ws => ws.close())
    this.pool.clear()
  }
}
```

### 11.5 最佳实践总结

1. **安全性**
   - 生产环境使用 `wss://` 加密连接
   - 验证所有接收的消息
   - 使用 token 认证

2. **可靠性**
   - 实现心跳检测
   - 实现断线重连（使用指数退避）
   - 消息确认机制

3. **性能**
   - 大数据使用压缩
   - 高频消息使用节流/防抖
   - 批量发送减少请求次数

4. **用户体验**
   - 显示连接状态
   - 离线时缓存消息
   - 重连时恢复状态

5. **代码组织**
   - 封装为独立服务
   - 使用 TypeScript 类型
   - 事件驱动架构


---

## 12. 常见错误与解决方案

### 12.1 连接失败

**错误信息**：
```
WebSocket connection to 'ws://...' failed
```

**可能原因及解决方案**：

```typescript
// 1. URL 格式错误
// ❌ 错误
new WebSocket('http://localhost:3000')  // 应该用 ws:// 或 wss://

// ✅ 正确
new WebSocket('ws://localhost:3000')
new WebSocket('wss://api.example.com')

// 2. 跨域问题 - 服务器需要配置 CORS
// Node.js 示例
const WebSocket = require('ws')
const wss = new WebSocket.Server({
  port: 3000,
  // 允许跨域
  verifyClient: (info, callback) => {
    callback(true)
  }
})

// 3. 端口被占用或服务未启动
// 检查服务器是否正常运行

// 4. 防火墙/代理阻止
// 检查网络配置，确保 WebSocket 端口开放
```

### 12.2 连接被关闭

**错误信息**：
```
WebSocket is closed before the connection is established
```

**解决方案**：

```typescript
// 1. 确保在连接建立后再发送消息
const ws = new WebSocket('ws://localhost:3000')

// ❌ 错误：连接未建立就发送
ws.send('hello')

// ✅ 正确：等待连接建立
ws.onopen = () => {
  ws.send('hello')
}

// 2. 使用 Promise 封装
function createWebSocket(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url)
    
    ws.onopen = () => resolve(ws)
    ws.onerror = (error) => reject(error)
    
    // 超时处理
    setTimeout(() => {
      if (ws.readyState !== WebSocket.OPEN) {
        ws.close()
        reject(new Error('连接超时'))
      }
    }, 10000)
  })
}

// 使用
const ws = await createWebSocket('ws://localhost:3000')
ws.send('hello')
```

### 12.3 消息发送失败

**错误信息**：
```
Failed to execute 'send' on 'WebSocket': Still in CONNECTING state
```

**解决方案**：

```typescript
// 封装安全的发送方法
class SafeWebSocket {
  private ws: WebSocket
  private messageQueue: string[] = []
  
  constructor(url: string) {
    this.ws = new WebSocket(url)
    
    this.ws.onopen = () => {
      // 连接成功后发送队列中的消息
      this.flushQueue()
    }
  }
  
  send(data: any): void {
    const message = typeof data === 'string' ? data : JSON.stringify(data)
    
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(message)
    } else if (this.ws.readyState === WebSocket.CONNECTING) {
      // 连接中，加入队列
      this.messageQueue.push(message)
    } else {
      console.error('WebSocket 未连接，无法发送消息')
    }
  }
  
  private flushQueue(): void {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift()!
      this.ws.send(message)
    }
  }
}
```

### 12.4 内存泄漏

**问题**：组件卸载后 WebSocket 仍在运行

```typescript
// ❌ 错误：未清理 WebSocket
export default {
  mounted() {
    this.ws = new WebSocket('ws://localhost:3000')
    this.ws.onmessage = (event) => {
      this.messages.push(event.data) // 组件卸载后仍会执行
    }
  }
}

// ✅ 正确：组件卸载时清理
import { onMounted, onUnmounted, ref } from 'vue'

const ws = ref<WebSocket | null>(null)
const messages = ref<string[]>([])

onMounted(() => {
  ws.value = new WebSocket('ws://localhost:3000')
  ws.value.onmessage = (event) => {
    messages.value.push(event.data)
  }
})

onUnmounted(() => {
  ws.value?.close()
  ws.value = null
})
```

### 12.5 JSON 解析错误

**错误信息**：
```
SyntaxError: Unexpected token in JSON
```

**解决方案**：

```typescript
ws.onmessage = (event) => {
  // ❌ 错误：直接解析可能失败
  const data = JSON.parse(event.data)
  
  // ✅ 正确：安全解析
  let data: any
  try {
    data = JSON.parse(event.data)
  } catch (error) {
    // 可能是纯文本消息
    console.log('收到非 JSON 消息:', event.data)
    data = event.data
  }
  
  // 处理数据
  handleMessage(data)
}

// 更完善的处理
function parseMessage(raw: string | ArrayBuffer): any {
  // 处理二进制数据
  if (raw instanceof ArrayBuffer) {
    const decoder = new TextDecoder()
    raw = decoder.decode(raw)
  }
  
  // 尝试 JSON 解析
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}
```

### 12.6 心跳超时误判

**问题**：网络延迟导致心跳超时

```typescript
// ❌ 错误：超时时间太短
const heartbeatTimeout = 1000 // 1 秒太短

// ✅ 正确：合理的超时时间
const heartbeatTimeout = 5000 // 5 秒

// 更好的方案：动态调整超时时间
class AdaptiveHeartbeat {
  private latencies: number[] = []
  private baseTimeout = 5000
  
  // 记录延迟
  recordLatency(latency: number): void {
    this.latencies.push(latency)
    // 只保留最近 10 次
    if (this.latencies.length > 10) {
      this.latencies.shift()
    }
  }
  
  // 计算自适应超时时间
  getTimeout(): number {
    if (this.latencies.length === 0) {
      return this.baseTimeout
    }
    
    // 平均延迟 + 2 倍标准差
    const avg = this.latencies.reduce((a, b) => a + b, 0) / this.latencies.length
    const variance = this.latencies.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / this.latencies.length
    const stdDev = Math.sqrt(variance)
    
    return Math.max(this.baseTimeout, avg + 2 * stdDev)
  }
}
```

### 12.7 重连风暴

**问题**：服务器重启时所有客户端同时重连

```typescript
// ❌ 错误：固定间隔重连
const reconnect = () => {
  setTimeout(() => {
    connect()
  }, 3000) // 所有客户端同时重连
}

// ✅ 正确：随机延迟 + 指数退避
const reconnect = (attempt: number) => {
  const baseDelay = 1000
  const maxDelay = 30000
  
  // 指数退避
  let delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay)
  
  // 添加随机抖动（±50%）
  const jitter = delay * 0.5 * (Math.random() - 0.5)
  delay += jitter
  
  console.log(`${delay}ms 后重连...`)
  
  setTimeout(() => {
    connect()
  }, delay)
}
```

### 12.8 消息顺序问题

**问题**：消息到达顺序与发送顺序不一致

```typescript
// 解决方案：消息序号
interface OrderedMessage {
  seq: number
  data: any
}

class OrderedWebSocket {
  private ws: WebSocket
  private sendSeq = 0
  private receiveSeq = 0
  private messageBuffer: Map<number, any> = new Map()
  
  constructor(url: string) {
    this.ws = new WebSocket(url)
    this.ws.onmessage = this.handleMessage.bind(this)
  }
  
  send(data: any): void {
    const message: OrderedMessage = {
      seq: this.sendSeq++,
      data
    }
    this.ws.send(JSON.stringify(message))
  }
  
  private handleMessage(event: MessageEvent): void {
    const message: OrderedMessage = JSON.parse(event.data)
    
    if (message.seq === this.receiveSeq) {
      // 顺序正确，直接处理
      this.processMessage(message.data)
      this.receiveSeq++
      
      // 检查缓冲区中是否有后续消息
      while (this.messageBuffer.has(this.receiveSeq)) {
        this.processMessage(this.messageBuffer.get(this.receiveSeq))
        this.messageBuffer.delete(this.receiveSeq)
        this.receiveSeq++
      }
    } else if (message.seq > this.receiveSeq) {
      // 消息提前到达，缓存
      this.messageBuffer.set(message.seq, message.data)
    }
    // 忽略重复消息（seq < receiveSeq）
  }
  
  private processMessage(data: any): void {
    console.log('处理消息:', data)
  }
}
```

### 12.9 大消息处理

**问题**：发送/接收大文件导致内存问题

```typescript
// 解决方案：分片传输
class ChunkedWebSocket {
  private ws: WebSocket
  private chunkSize = 64 * 1024 // 64KB
  private receivingChunks: Map<string, ArrayBuffer[]> = new Map()
  
  constructor(url: string) {
    this.ws = new WebSocket(url)
    this.ws.binaryType = 'arraybuffer'
  }
  
  // 分片发送大数据
  async sendLargeData(id: string, data: ArrayBuffer): Promise<void> {
    const totalChunks = Math.ceil(data.byteLength / this.chunkSize)
    
    for (let i = 0; i < totalChunks; i++) {
      const start = i * this.chunkSize
      const end = Math.min(start + this.chunkSize, data.byteLength)
      const chunk = data.slice(start, end)
      
      // 发送分片
      this.ws.send(JSON.stringify({
        type: 'chunk',
        id,
        index: i,
        total: totalChunks,
        data: this.arrayBufferToBase64(chunk)
      }))
      
      // 控制发送速率
      await new Promise(resolve => setTimeout(resolve, 10))
    }
  }
  
  // 处理接收的分片
  handleChunk(message: any): ArrayBuffer | null {
    const { id, index, total, data } = message
    
    if (!this.receivingChunks.has(id)) {
      this.receivingChunks.set(id, new Array(total))
    }
    
    const chunks = this.receivingChunks.get(id)!
    chunks[index] = this.base64ToArrayBuffer(data)
    
    // 检查是否接收完成
    if (chunks.every(chunk => chunk !== undefined)) {
      this.receivingChunks.delete(id)
      return this.mergeArrayBuffers(chunks)
    }
    
    return null
  }
  
  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary)
  }
  
  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    return bytes.buffer
  }
  
  private mergeArrayBuffers(buffers: ArrayBuffer[]): ArrayBuffer {
    const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0)
    const result = new Uint8Array(totalLength)
    let offset = 0
    for (const buffer of buffers) {
      result.set(new Uint8Array(buffer), offset)
      offset += buffer.byteLength
    }
    return result.buffer
  }
}
```

### 12.10 TypeScript 类型错误

```typescript
// ❌ 错误：事件类型不正确
ws.onmessage = (event) => {
  // event 类型为 Event，没有 data 属性
}

// ✅ 正确：使用正确的事件类型
ws.onmessage = (event: MessageEvent) => {
  console.log(event.data)
}

// ❌ 错误：CloseEvent 类型
ws.onclose = (event) => {
  console.log(event.code) // 类型错误
}

// ✅ 正确
ws.onclose = (event: CloseEvent) => {
  console.log(event.code)
  console.log(event.reason)
  console.log(event.wasClean)
}
```

---

## 总结

本笔记从基础到进阶，系统地介绍了 WebSocket 在 Vue 3 + TypeScript 项目中的使用：

1. **基础概念**：理解 WebSocket 协议和适用场景
2. **原生 API**：掌握 WebSocket 的基本操作
3. **Vue 集成**：组件内使用和 Composable 封装
4. **完整封装**：构建可复用的 WebSocket 类
5. **可靠性**：心跳检测、断线重连、消息队列
6. **类型安全**：TypeScript 类型定义
7. **实战应用**：聊天室和通知系统
8. **Socket.IO**：更强大的实时通信库
9. **性能优化**：压缩、批处理、节流
10. **错误处理**：常见问题和解决方案

掌握这些内容，你就能在项目中构建稳定、高效的实时通信功能。
