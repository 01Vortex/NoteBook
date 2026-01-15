> SSE（Server-Sent Events）是一种服务器向客户端推送数据的技术
> 本笔记从基础到进阶，全面覆盖 SSE 的使用场景、实现方式和最佳实践

---

## 目录

1. [基础概念](#1-基础概念)
2. [EventSource API](#2-eventsource-api)
3. [服务端实现](#3-服务端实现)
4. [消息格式详解](#4-消息格式详解)
5. [连接管理](#5-连接管理)
6. [错误处理与重连](#6-错误处理与重连)
7. [身份认证](#7-身份认证)
8. [实战案例](#8-实战案例)
9. [SSE vs WebSocket](#9-sse-vs-websocket)
10. [性能优化](#10-性能优化)
11. [框架集成](#11-框架集成)
12. [常见错误与解决方案](#12-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 SSE？

SSE（Server-Sent Events，服务器推送事件）是一种允许服务器主动向客户端推送数据的技术。它基于 HTTP 协议，使用长连接实现服务器到客户端的单向通信。

**SSE 的特点**：
- **单向通信**：只能服务器向客户端推送，客户端不能通过同一连接发送数据
- **基于 HTTP**：使用标准 HTTP 协议，无需特殊协议支持
- **自动重连**：浏览器内置断线重连机制
- **文本协议**：传输的是文本数据（通常是 UTF-8 编码）
- **轻量级**：相比 WebSocket 更简单，适合单向数据流场景

### 1.2 SSE 工作原理

```
1. 客户端发起请求
   浏览器 ──────────────────────────────> 服务器
          GET /events HTTP/1.1
          Accept: text/event-stream

2. 服务器保持连接并推送数据
   浏览器 <────────────────────────────── 服务器
          HTTP/1.1 200 OK
          Content-Type: text/event-stream
          
          data: {"message": "Hello"}
          
          data: {"message": "World"}
          
          ...（连接保持打开）

3. 连接断开时，浏览器自动重连
   浏览器 ──────────────────────────────> 服务器
          GET /events HTTP/1.1
          Last-Event-ID: 123
```

### 1.3 适用场景

| 场景 | 说明 |
|------|------|
| 实时通知 | 系统消息、提醒、告警 |
| 实时数据更新 | 股票行情、体育比分、天气更新 |
| 进度推送 | 文件上传/下载进度、任务执行进度 |
| 日志流 | 实时日志查看、构建日志 |
| AI 流式响应 | ChatGPT 等 AI 对话的流式输出 |
| 社交动态 | 新消息提醒、点赞通知 |

### 1.4 浏览器支持

| 浏览器 | 支持情况 |
|--------|----------|
| Chrome | ✅ 6+ |
| Firefox | ✅ 6+ |
| Safari | ✅ 5+ |
| Edge | ✅ 79+ |
| IE | ❌ 不支持 |
| Opera | ✅ 11+ |

```javascript
// 检测浏览器是否支持 SSE
if (typeof EventSource !== 'undefined') {
  console.log('SSE is supported');
} else {
  console.log('SSE is not supported, use polyfill');
}
```

---

## 2. EventSource API

### 2.1 基本使用

```javascript
// 创建 EventSource 连接
const eventSource = new EventSource('/api/events');

// 监听消息（默认事件类型为 message）
eventSource.onmessage = (event) => {
  console.log('Received:', event.data);
};

// 监听连接打开
eventSource.onopen = (event) => {
  console.log('Connection opened');
};

// 监听错误
eventSource.onerror = (event) => {
  console.error('Error occurred');
  if (eventSource.readyState === EventSource.CLOSED) {
    console.log('Connection was closed');
  }
};

// 关闭连接
eventSource.close();
```

### 2.2 EventSource 属性

```javascript
const eventSource = new EventSource('/api/events');

// readyState: 连接状态
// 0 - CONNECTING: 正在连接
// 1 - OPEN: 已连接
// 2 - CLOSED: 已关闭
console.log(eventSource.readyState);
console.log(EventSource.CONNECTING); // 0
console.log(EventSource.OPEN);       // 1
console.log(EventSource.CLOSED);     // 2

// url: 连接的 URL
console.log(eventSource.url);

// withCredentials: 是否携带凭证
console.log(eventSource.withCredentials);
```

### 2.3 监听自定义事件

```javascript
const eventSource = new EventSource('/api/events');

// 监听自定义事件类型
eventSource.addEventListener('notification', (event) => {
  const data = JSON.parse(event.data);
  console.log('Notification:', data);
});

eventSource.addEventListener('update', (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
});

eventSource.addEventListener('error', (event) => {
  // 注意：这是自定义的 error 事件，不是连接错误
  const data = JSON.parse(event.data);
  console.log('Server error:', data);
});

// 默认 message 事件
eventSource.addEventListener('message', (event) => {
  console.log('Message:', event.data);
});
```

### 2.4 Event 对象属性

```javascript
eventSource.onmessage = (event) => {
  // data: 服务器发送的数据
  console.log('Data:', event.data);
  
  // type: 事件类型（默认为 'message'）
  console.log('Type:', event.type);
  
  // lastEventId: 最后一个事件 ID
  console.log('Last Event ID:', event.lastEventId);
  
  // origin: 事件源的 origin
  console.log('Origin:', event.origin);
};
```

### 2.5 携带凭证（跨域）

```javascript
// 跨域请求时携带 Cookie
const eventSource = new EventSource('https://api.example.com/events', {
  withCredentials: true
});

// 服务端需要设置 CORS 头
// Access-Control-Allow-Origin: https://your-domain.com
// Access-Control-Allow-Credentials: true
```

### 2.6 TypeScript 类型定义

```typescript
interface SSEMessage {
  id: string;
  type: string;
  data: unknown;
  timestamp: number;
}

class SSEClient {
  private eventSource: EventSource | null = null;
  private url: string;
  private options: EventSourceInit;
  
  constructor(url: string, options: EventSourceInit = {}) {
    this.url = url;
    this.options = options;
  }
  
  connect(): void {
    this.eventSource = new EventSource(this.url, this.options);
  }
  
  on<T = unknown>(
    event: string, 
    callback: (data: T, event: MessageEvent) => void
  ): void {
    this.eventSource?.addEventListener(event, (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as T;
        callback(data, e);
      } catch {
        callback(e.data as T, e);
      }
    });
  }
  
  close(): void {
    this.eventSource?.close();
    this.eventSource = null;
  }
  
  get readyState(): number {
    return this.eventSource?.readyState ?? EventSource.CLOSED;
  }
}

// 使用
const client = new SSEClient('/api/events');
client.connect();

client.on<{ message: string }>('notification', (data) => {
  console.log(data.message);
});
```

---

## 3. 服务端实现

### 3.1 Node.js (Express)

```javascript
const express = require('express');
const app = express();

// SSE 端点
app.get('/api/events', (req, res) => {
  // 设置 SSE 必需的响应头
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  // 禁用 Nginx 缓冲（如果使用 Nginx 代理）
  res.setHeader('X-Accel-Buffering', 'no');
  
  // 发送初始消息
  res.write('data: Connected\n\n');
  
  // 定时发送消息
  const intervalId = setInterval(() => {
    const data = {
      time: new Date().toISOString(),
      message: 'Hello from server'
    };
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  }, 1000);
  
  // 客户端断开连接时清理
  req.on('close', () => {
    clearInterval(intervalId);
    console.log('Client disconnected');
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### 3.2 Node.js (原生 HTTP)

```javascript
const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/events') {
    // SSE 响应头
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });
    
    // 发送消息的辅助函数
    const sendEvent = (event, data, id) => {
      if (id) res.write(`id: ${id}\n`);
      if (event) res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };
    
    // 发送心跳
    const heartbeat = setInterval(() => {
      res.write(': heartbeat\n\n');
    }, 30000);
    
    // 发送数据
    let eventId = 0;
    const dataInterval = setInterval(() => {
      sendEvent('update', { count: ++eventId }, eventId);
    }, 1000);
    
    // 清理
    req.on('close', () => {
      clearInterval(heartbeat);
      clearInterval(dataInterval);
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.listen(3000);
```

### 3.3 Python (Flask)

```python
from flask import Flask, Response
import json
import time

app = Flask(__name__)

def generate_events():
    """生成 SSE 事件流"""
    event_id = 0
    while True:
        event_id += 1
        data = {
            'id': event_id,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'message': 'Hello from Python'
        }
        
        # SSE 格式：id, event, data
        yield f"id: {event_id}\n"
        yield f"event: update\n"
        yield f"data: {json.dumps(data)}\n\n"
        
        time.sleep(1)

@app.route('/events')
def events():
    return Response(
        generate_events(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
```

### 3.4 Python (FastAPI)

```python
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse
import asyncio
import json

app = FastAPI()

async def event_generator():
    """异步事件生成器"""
    event_id = 0
    while True:
        event_id += 1
        data = {
            'id': event_id,
            'message': 'Hello from FastAPI'
        }
        yield {
            'event': 'update',
            'id': str(event_id),
            'data': json.dumps(data)
        }
        await asyncio.sleep(1)

@app.get('/events')
async def events():
    return EventSourceResponse(event_generator())

# 或使用原生 StreamingResponse
async def raw_event_generator():
    event_id = 0
    while True:
        event_id += 1
        data = json.dumps({'id': event_id})
        yield f"id: {event_id}\nevent: update\ndata: {data}\n\n"
        await asyncio.sleep(1)

@app.get('/events-raw')
async def events_raw():
    return StreamingResponse(
        raw_event_generator(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )
```

### 3.5 Go (Gin)

```go
package main

import (
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/gin-gonic/gin"
)

type Event struct {
    ID      int    `json:"id"`
    Message string `json:"message"`
    Time    string `json:"time"`
}

func main() {
    r := gin.Default()
    
    r.GET("/events", func(c *gin.Context) {
        // 设置 SSE 响应头
        c.Header("Content-Type", "text/event-stream")
        c.Header("Cache-Control", "no-cache")
        c.Header("Connection", "keep-alive")
        c.Header("X-Accel-Buffering", "no")
        
        // 获取客户端断开通知
        clientGone := c.Request.Context().Done()
        
        eventID := 0
        ticker := time.NewTicker(time.Second)
        defer ticker.Stop()
        
        for {
            select {
            case <-clientGone:
                fmt.Println("Client disconnected")
                return
            case <-ticker.C:
                eventID++
                event := Event{
                    ID:      eventID,
                    Message: "Hello from Go",
                    Time:    time.Now().Format(time.RFC3339),
                }
                data, _ := json.Marshal(event)
                
                c.SSEvent("update", string(data))
                c.Writer.Flush()
            }
        }
    })
    
    r.Run(":3000")
}
```

### 3.6 Java (Spring Boot)

```java
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RestController
public class SSEController {
    
    private final ExecutorService executor = Executors.newCachedThreadPool();
    
    @GetMapping(value = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter events() {
        SseEmitter emitter = new SseEmitter(0L); // 0 表示无超时
        
        executor.execute(() -> {
            try {
                int eventId = 0;
                while (true) {
                    eventId++;
                    
                    SseEmitter.SseEventBuilder event = SseEmitter.event()
                        .id(String.valueOf(eventId))
                        .name("update")
                        .data(new EventData(eventId, "Hello from Spring"));
                    
                    emitter.send(event);
                    Thread.sleep(1000);
                }
            } catch (IOException | InterruptedException e) {
                emitter.completeWithError(e);
            }
        });
        
        emitter.onCompletion(() -> System.out.println("Client disconnected"));
        emitter.onTimeout(() -> System.out.println("Connection timeout"));
        
        return emitter;
    }
}

record EventData(int id, String message) {}
```

---

## 4. 消息格式详解

### 4.1 SSE 消息结构

SSE 消息由多个字段组成，每个字段占一行，字段之间用换行符分隔，消息之间用空行分隔：

```
field: value\n
field: value\n
\n
```

### 4.2 字段类型

| 字段 | 说明 | 示例 |
|------|------|------|
| `data` | 消息数据（必需） | `data: Hello World` |
| `event` | 事件类型 | `event: notification` |
| `id` | 事件 ID | `id: 123` |
| `retry` | 重连时间（毫秒） | `retry: 5000` |
| `:` | 注释（被忽略） | `: this is a comment` |

### 4.3 消息示例

```
# 简单消息
data: Hello World

# 带事件类型的消息
event: notification
data: {"title": "New Message", "body": "You have a new message"}

# 带 ID 的消息（用于断线重连）
id: 123
event: update
data: {"count": 42}

# 多行数据
data: Line 1
data: Line 2
data: Line 3

# 设置重连时间
retry: 5000

# 注释（心跳保活）
: heartbeat

# 完整示例
id: 456
event: user-joined
retry: 3000
data: {"userId": "u123", "username": "John"}

```

### 4.4 服务端发送消息的辅助函数

```javascript
// Node.js 辅助函数
class SSEWriter {
  constructor(res) {
    this.res = res;
  }
  
  // 发送数据
  send(data, options = {}) {
    const { event, id, retry } = options;
    
    if (id !== undefined) {
      this.res.write(`id: ${id}\n`);
    }
    
    if (event) {
      this.res.write(`event: ${event}\n`);
    }
    
    if (retry !== undefined) {
      this.res.write(`retry: ${retry}\n`);
    }
    
    // 处理多行数据
    const lines = String(data).split('\n');
    lines.forEach(line => {
      this.res.write(`data: ${line}\n`);
    });
    
    this.res.write('\n');
  }
  
  // 发送 JSON 数据
  sendJSON(data, options = {}) {
    this.send(JSON.stringify(data), options);
  }
  
  // 发送注释（心跳）
  comment(text = 'heartbeat') {
    this.res.write(`: ${text}\n\n`);
  }
  
  // 设置重连时间
  setRetry(ms) {
    this.res.write(`retry: ${ms}\n\n`);
  }
}

// 使用
app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  const sse = new SSEWriter(res);
  
  // 设置重连时间为 3 秒
  sse.setRetry(3000);
  
  // 发送消息
  sse.sendJSON({ message: 'Connected' }, { event: 'connected' });
  
  let id = 0;
  const interval = setInterval(() => {
    sse.sendJSON(
      { count: ++id, time: Date.now() },
      { event: 'update', id }
    );
  }, 1000);
  
  // 心跳
  const heartbeat = setInterval(() => {
    sse.comment();
  }, 30000);
  
  req.on('close', () => {
    clearInterval(interval);
    clearInterval(heartbeat);
  });
});
```

---

## 5. 连接管理

### 5.1 连接池管理

```javascript
// 服务端：管理多个客户端连接
class SSEConnectionManager {
  constructor() {
    this.connections = new Map();
  }
  
  // 添加连接
  add(clientId, res) {
    // 设置 SSE 响应头
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    this.connections.set(clientId, res);
    console.log(`Client ${clientId} connected. Total: ${this.connections.size}`);
    
    return () => this.remove(clientId);
  }
  
  // 移除连接
  remove(clientId) {
    this.connections.delete(clientId);
    console.log(`Client ${clientId} disconnected. Total: ${this.connections.size}`);
  }
  
  // 向单个客户端发送
  sendTo(clientId, event, data) {
    const res = this.connections.get(clientId);
    if (res) {
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    }
  }
  
  // 广播给所有客户端
  broadcast(event, data) {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    this.connections.forEach((res, clientId) => {
      try {
        res.write(message);
      } catch (error) {
        this.remove(clientId);
      }
    });
  }
  
  // 广播给指定客户端组
  broadcastTo(clientIds, event, data) {
    clientIds.forEach(clientId => {
      this.sendTo(clientId, event, data);
    });
  }
  
  // 获取连接数
  get size() {
    return this.connections.size;
  }
}

// 使用
const sseManager = new SSEConnectionManager();

app.get('/events', (req, res) => {
  const clientId = req.query.clientId || Date.now().toString();
  const cleanup = sseManager.add(clientId, res);
  
  req.on('close', cleanup);
});

// 在其他地方广播消息
app.post('/notify', (req, res) => {
  sseManager.broadcast('notification', req.body);
  res.json({ success: true, clients: sseManager.size });
});
```

### 5.2 房间/频道管理

```javascript
class SSERoomManager {
  constructor() {
    this.rooms = new Map(); // roomId -> Set<clientId>
    this.clients = new Map(); // clientId -> { res, rooms: Set }
  }
  
  // 添加客户端
  addClient(clientId, res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    this.clients.set(clientId, { res, rooms: new Set() });
  }
  
  // 移除客户端
  removeClient(clientId) {
    const client = this.clients.get(clientId);
    if (client) {
      // 从所有房间中移除
      client.rooms.forEach(roomId => {
        this.leaveRoom(clientId, roomId);
      });
      this.clients.delete(clientId);
    }
  }
  
  // 加入房间
  joinRoom(clientId, roomId) {
    const client = this.clients.get(clientId);
    if (!client) return;
    
    if (!this.rooms.has(roomId)) {
      this.rooms.set(roomId, new Set());
    }
    
    this.rooms.get(roomId).add(clientId);
    client.rooms.add(roomId);
  }
  
  // 离开房间
  leaveRoom(clientId, roomId) {
    const room = this.rooms.get(roomId);
    if (room) {
      room.delete(clientId);
      if (room.size === 0) {
        this.rooms.delete(roomId);
      }
    }
    
    const client = this.clients.get(clientId);
    if (client) {
      client.rooms.delete(roomId);
    }
  }
  
  // 向房间广播
  broadcastToRoom(roomId, event, data) {
    const room = this.rooms.get(roomId);
    if (!room) return;
    
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    room.forEach(clientId => {
      const client = this.clients.get(clientId);
      if (client) {
        try {
          client.res.write(message);
        } catch {
          this.removeClient(clientId);
        }
      }
    });
  }
}
```

### 5.3 客户端连接状态管理

```javascript
class SSEClient {
  constructor(url, options = {}) {
    this.url = url;
    this.options = options;
    this.eventSource = null;
    this.listeners = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = options.maxReconnectAttempts || 10;
    this.reconnectDelay = options.reconnectDelay || 1000;
  }
  
  connect() {
    if (this.eventSource) {
      this.close();
    }
    
    this.eventSource = new EventSource(this.url, {
      withCredentials: this.options.withCredentials
    });
    
    this.eventSource.onopen = () => {
      console.log('SSE connected');
      this.reconnectAttempts = 0;
      this.emit('connected');
    };
    
    this.eventSource.onerror = (error) => {
      console.error('SSE error:', error);
      this.emit('error', error);
      
      if (this.eventSource.readyState === EventSource.CLOSED) {
        this.handleDisconnect();
      }
    };
    
    // 重新绑定所有监听器
    this.listeners.forEach((callbacks, event) => {
      callbacks.forEach(callback => {
        this.eventSource.addEventListener(event, callback);
      });
    });
  }
  
  handleDisconnect() {
    this.emit('disconnected');
    
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
      console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => this.connect(), delay);
    } else {
      console.error('Max reconnect attempts reached');
      this.emit('maxReconnectReached');
    }
  }
  
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    
    if (this.eventSource) {
      this.eventSource.addEventListener(event, callback);
    }
    
    return () => this.off(event, callback);
  }
  
  off(event, callback) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.delete(callback);
      if (this.eventSource) {
        this.eventSource.removeEventListener(event, callback);
      }
    }
  }
  
  emit(event, data) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }
  
  close() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }
  
  get readyState() {
    return this.eventSource?.readyState ?? EventSource.CLOSED;
  }
  
  get isConnected() {
    return this.readyState === EventSource.OPEN;
  }
}

// 使用
const client = new SSEClient('/api/events', {
  withCredentials: true,
  maxReconnectAttempts: 5,
  reconnectDelay: 2000
});

client.on('connected', () => {
  console.log('Connected to server');
});

client.on('disconnected', () => {
  console.log('Disconnected from server');
});

client.on('update', (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
});

client.connect();
```

---

## 6. 错误处理与重连

### 6.1 自动重连机制

```javascript
// EventSource 内置自动重连
// 服务端可以通过 retry 字段控制重连间隔

// 服务端设置重连时间
res.write('retry: 5000\n\n'); // 5秒后重连

// 客户端处理重连
const eventSource = new EventSource('/events');

eventSource.onerror = (event) => {
  switch (eventSource.readyState) {
    case EventSource.CONNECTING:
      console.log('Reconnecting...');
      break;
    case EventSource.CLOSED:
      console.log('Connection closed, will not reconnect');
      break;
  }
};
```

### 6.2 断点续传（Last-Event-ID）

```javascript
// 服务端：处理 Last-Event-ID
app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  
  // 获取客户端发送的最后事件 ID
  const lastEventId = req.headers['last-event-id'];
  let currentId = lastEventId ? parseInt(lastEventId) : 0;
  
  console.log(`Client reconnected, last event ID: ${lastEventId}`);
  
  // 如果有遗漏的消息，先发送遗漏的消息
  if (lastEventId) {
    const missedEvents = getMissedEvents(parseInt(lastEventId));
    missedEvents.forEach(event => {
      res.write(`id: ${event.id}\n`);
      res.write(`event: ${event.type}\n`);
      res.write(`data: ${JSON.stringify(event.data)}\n\n`);
    });
  }
  
  // 继续发送新消息
  const interval = setInterval(() => {
    currentId++;
    res.write(`id: ${currentId}\n`);
    res.write(`event: update\n`);
    res.write(`data: ${JSON.stringify({ id: currentId })}\n\n`);
  }, 1000);
  
  req.on('close', () => clearInterval(interval));
});

// 消息存储（简单示例）
const eventStore = [];
const MAX_EVENTS = 1000;

function storeEvent(event) {
  eventStore.push(event);
  if (eventStore.length > MAX_EVENTS) {
    eventStore.shift();
  }
}

function getMissedEvents(lastId) {
  return eventStore.filter(e => e.id > lastId);
}
```

### 6.3 心跳保活

```javascript
// 服务端：发送心跳
app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  // 心跳间隔（防止连接被代理服务器关闭）
  const heartbeatInterval = setInterval(() => {
    // 使用注释作为心跳，不会触发客户端事件
    res.write(': heartbeat\n\n');
  }, 30000); // 每30秒发送一次
  
  // 业务消息
  const messageInterval = setInterval(() => {
    res.write(`data: ${JSON.stringify({ time: Date.now() })}\n\n`);
  }, 5000);
  
  req.on('close', () => {
    clearInterval(heartbeatInterval);
    clearInterval(messageInterval);
  });
});

// 客户端：检测心跳超时
class SSEClientWithHeartbeat {
  constructor(url, heartbeatTimeout = 60000) {
    this.url = url;
    this.heartbeatTimeout = heartbeatTimeout;
    this.lastHeartbeat = Date.now();
    this.eventSource = null;
    this.heartbeatChecker = null;
  }
  
  connect() {
    this.eventSource = new EventSource(this.url);
    
    // 任何消息都重置心跳计时
    this.eventSource.onmessage = (event) => {
      this.lastHeartbeat = Date.now();
      this.handleMessage(event);
    };
    
    this.eventSource.onopen = () => {
      this.lastHeartbeat = Date.now();
      this.startHeartbeatChecker();
    };
    
    this.eventSource.onerror = () => {
      this.stopHeartbeatChecker();
    };
  }
  
  startHeartbeatChecker() {
    this.heartbeatChecker = setInterval(() => {
      const timeSinceLastHeartbeat = Date.now() - this.lastHeartbeat;
      if (timeSinceLastHeartbeat > this.heartbeatTimeout) {
        console.log('Heartbeat timeout, reconnecting...');
        this.reconnect();
      }
    }, 10000);
  }
  
  stopHeartbeatChecker() {
    if (this.heartbeatChecker) {
      clearInterval(this.heartbeatChecker);
      this.heartbeatChecker = null;
    }
  }
  
  reconnect() {
    this.close();
    setTimeout(() => this.connect(), 1000);
  }
  
  close() {
    this.stopHeartbeatChecker();
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }
  
  handleMessage(event) {
    console.log('Message:', event.data);
  }
}
```

---

## 7. 身份认证

### 7.1 Cookie 认证

```javascript
// 客户端：使用 withCredentials
const eventSource = new EventSource('/api/events', {
  withCredentials: true
});

// 服务端：验证 Cookie
app.get('/api/events', (req, res) => {
  // 验证 session
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  
  // 发送用户特定的消息
  const userId = req.session.userId;
  // ...
});
```

### 7.2 URL 参数认证

```javascript
// 客户端：在 URL 中传递 token
const token = 'your-auth-token';
const eventSource = new EventSource(`/api/events?token=${token}`);

// 服务端：验证 token
app.get('/api/events', async (req, res) => {
  const token = req.query.token;
  
  try {
    const user = await verifyToken(token);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    
    // 发送消息...
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});
```

### 7.3 使用 Fetch API 替代 EventSource

EventSource 不支持自定义请求头，如果需要使用 Authorization 头，可以使用 Fetch API：

```javascript
class FetchEventSource {
  constructor(url, options = {}) {
    this.url = url;
    this.options = options;
    this.controller = null;
    this.listeners = new Map();
  }
  
  async connect() {
    this.controller = new AbortController();
    
    try {
      const response = await fetch(this.url, {
        method: 'GET',
        headers: {
          'Accept': 'text/event-stream',
          'Authorization': `Bearer ${this.options.token}`,
          ...this.options.headers
        },
        signal: this.controller.signal
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      
      while (true) {
        const { done, value } = await reader.read();
        
        if (done) {
          this.emit('close');
          break;
        }
        
        buffer += decoder.decode(value, { stream: true });
        const events = this.parseEvents(buffer);
        buffer = events.remaining;
        
        events.parsed.forEach(event => {
          this.emit(event.type || 'message', event);
        });
      }
    } catch (error) {
      if (error.name !== 'AbortError') {
        this.emit('error', error);
      }
    }
  }
  
  parseEvents(buffer) {
    const events = [];
    const lines = buffer.split('\n');
    let currentEvent = {};
    let remaining = '';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      if (line === '') {
        if (Object.keys(currentEvent).length > 0) {
          events.push(currentEvent);
          currentEvent = {};
        }
      } else if (line.startsWith('data:')) {
        currentEvent.data = (currentEvent.data || '') + line.slice(5).trim();
      } else if (line.startsWith('event:')) {
        currentEvent.type = line.slice(6).trim();
      } else if (line.startsWith('id:')) {
        currentEvent.id = line.slice(3).trim();
      } else if (line.startsWith('retry:')) {
        currentEvent.retry = parseInt(line.slice(6).trim());
      } else if (!line.startsWith(':')) {
        // 可能是不完整的行，保留到下次处理
        remaining = lines.slice(i).join('\n');
        break;
      }
    }
    
    return { parsed: events, remaining };
  }
  
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
  }
  
  emit(event, data) {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach(cb => cb(data));
    }
  }
  
  close() {
    if (this.controller) {
      this.controller.abort();
    }
  }
}

// 使用
const sse = new FetchEventSource('/api/events', {
  token: 'your-jwt-token'
});

sse.on('message', (event) => {
  console.log('Message:', event.data);
});

sse.on('error', (error) => {
  console.error('Error:', error);
});

sse.connect();
```

---

## 8. 实战案例

### 8.1 AI 流式对话（类 ChatGPT）

```javascript
// 服务端：流式返回 AI 响应
app.post('/api/chat', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  
  const { message } = req.body;
  
  try {
    // 调用 AI API（以 OpenAI 为例）
    const stream = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: message }],
      stream: true
    });
    
    for await (const chunk of stream) {
      const content = chunk.choices[0]?.delta?.content || '';
      if (content) {
        res.write(`data: ${JSON.stringify({ content })}\n\n`);
      }
    }
    
    res.write('data: [DONE]\n\n');
    res.end();
  } catch (error) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: error.message })}\n\n`);
    res.end();
  }
});

// 客户端：显示流式响应
async function sendMessage(message) {
  const responseDiv = document.getElementById('response');
  responseDiv.textContent = '';
  
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });
  
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    const text = decoder.decode(value);
    const lines = text.split('\n');
    
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        if (data === '[DONE]') {
          console.log('Stream completed');
        } else {
          try {
            const { content } = JSON.parse(data);
            responseDiv.textContent += content;
          } catch (e) {
            // 忽略解析错误
          }
        }
      }
    }
  }
}
```

### 8.2 实时通知系统

```javascript
// 服务端：通知管理器
class NotificationManager {
  constructor() {
    this.clients = new Map(); // userId -> response
  }
  
  addClient(userId, res) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    // 发送连接成功消息
    res.write(`event: connected\ndata: ${JSON.stringify({ userId })}\n\n`);
    
    this.clients.set(userId, res);
    
    return () => this.clients.delete(userId);
  }
  
  notify(userId, notification) {
    const res = this.clients.get(userId);
    if (res) {
      res.write(`event: notification\ndata: ${JSON.stringify(notification)}\n\n`);
      return true;
    }
    return false;
  }
  
  broadcast(notification) {
    const message = `event: notification\ndata: ${JSON.stringify(notification)}\n\n`;
    this.clients.forEach(res => res.write(message));
  }
}

const notificationManager = new NotificationManager();

// SSE 端点
app.get('/api/notifications', authenticateUser, (req, res) => {
  const userId = req.user.id;
  const cleanup = notificationManager.addClient(userId, res);
  
  req.on('close', cleanup);
});

// 发送通知的 API
app.post('/api/notifications', async (req, res) => {
  const { userId, title, message, type } = req.body;
  
  const notification = {
    id: Date.now(),
    title,
    message,
    type,
    timestamp: new Date().toISOString()
  };
  
  // 保存到数据库
  await saveNotification(userId, notification);
  
  // 实时推送
  const sent = notificationManager.notify(userId, notification);
  
  res.json({ success: true, delivered: sent });
});

// 客户端
function setupNotifications() {
  const eventSource = new EventSource('/api/notifications', {
    withCredentials: true
  });
  
  eventSource.addEventListener('notification', (event) => {
    const notification = JSON.parse(event.data);
    showNotification(notification);
  });
  
  eventSource.addEventListener('connected', (event) => {
    console.log('Notification service connected');
  });
  
  return eventSource;
}

function showNotification({ title, message, type }) {
  // 浏览器通知
  if (Notification.permission === 'granted') {
    new Notification(title, { body: message });
  }
  
  // 页面内通知
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<strong>${title}</strong><p>${message}</p>`;
  document.body.appendChild(toast);
  
  setTimeout(() => toast.remove(), 5000);
}
```

### 8.3 实时日志查看器

```javascript
// 服务端：日志流
const { spawn } = require('child_process');

app.get('/api/logs/:service', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  
  const { service } = req.params;
  const { lines = 100 } = req.query;
  
  // 使用 tail 命令读取日志
  const tail = spawn('tail', ['-f', '-n', lines, `/var/log/${service}.log`]);
  
  tail.stdout.on('data', (data) => {
    const logLines = data.toString().split('\n').filter(Boolean);
    logLines.forEach(line => {
      const logEntry = parseLogLine(line);
      res.write(`event: log\ndata: ${JSON.stringify(logEntry)}\n\n`);
    });
  });
  
  tail.stderr.on('data', (data) => {
    res.write(`event: error\ndata: ${JSON.stringify({ error: data.toString() })}\n\n`);
  });
  
  req.on('close', () => {
    tail.kill();
  });
});

function parseLogLine(line) {
  // 解析日志格式：[2024-01-15 10:30:00] [INFO] Message
  const match = line.match(/\[(.+?)\] \[(\w+)\] (.+)/);
  if (match) {
    return {
      timestamp: match[1],
      level: match[2],
      message: match[3]
    };
  }
  return { message: line };
}

// 客户端：日志查看器
class LogViewer {
  constructor(container, service) {
    this.container = container;
    this.service = service;
    this.eventSource = null;
    this.autoScroll = true;
  }
  
  connect() {
    this.eventSource = new EventSource(`/api/logs/${this.service}?lines=100`);
    
    this.eventSource.addEventListener('log', (event) => {
      const log = JSON.parse(event.data);
      this.appendLog(log);
    });
    
    this.eventSource.addEventListener('error', (event) => {
      const error = JSON.parse(event.data);
      this.appendError(error);
    });
  }
  
  appendLog({ timestamp, level, message }) {
    const div = document.createElement('div');
    div.className = `log-entry log-${level?.toLowerCase() || 'info'}`;
    div.innerHTML = `
      <span class="timestamp">${timestamp || new Date().toISOString()}</span>
      <span class="level">${level || 'INFO'}</span>
      <span class="message">${this.escapeHtml(message)}</span>
    `;
    this.container.appendChild(div);
    
    if (this.autoScroll) {
      this.container.scrollTop = this.container.scrollHeight;
    }
  }
  
  appendError({ error }) {
    const div = document.createElement('div');
    div.className = 'log-entry log-error';
    div.textContent = `Error: ${error}`;
    this.container.appendChild(div);
  }
  
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
    }
  }
  
  clear() {
    this.container.innerHTML = '';
  }
}
```

### 8.4 实时数据仪表盘

```javascript
// 服务端：系统监控数据
app.get('/api/metrics', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  
  const sendMetrics = async () => {
    const metrics = {
      cpu: await getCpuUsage(),
      memory: await getMemoryUsage(),
      disk: await getDiskUsage(),
      network: await getNetworkStats(),
      timestamp: Date.now()
    };
    
    res.write(`event: metrics\ndata: ${JSON.stringify(metrics)}\n\n`);
  };
  
  // 立即发送一次
  sendMetrics();
  
  // 每秒更新
  const interval = setInterval(sendMetrics, 1000);
  
  req.on('close', () => clearInterval(interval));
});

// 客户端：仪表盘
class Dashboard {
  constructor() {
    this.charts = {};
    this.eventSource = null;
  }
  
  init() {
    this.initCharts();
    this.connect();
  }
  
  initCharts() {
    // 使用 Chart.js 初始化图表
    this.charts.cpu = new Chart(document.getElementById('cpuChart'), {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'CPU Usage %',
          data: [],
          borderColor: 'rgb(75, 192, 192)',
          tension: 0.1
        }]
      },
      options: {
        scales: {
          y: { min: 0, max: 100 }
        },
        animation: false
      }
    });
    
    // 类似地初始化其他图表...
  }
  
  connect() {
    this.eventSource = new EventSource('/api/metrics');
    
    this.eventSource.addEventListener('metrics', (event) => {
      const metrics = JSON.parse(event.data);
      this.updateCharts(metrics);
      this.updateStats(metrics);
    });
  }
  
  updateCharts(metrics) {
    const time = new Date(metrics.timestamp).toLocaleTimeString();
    
    // 更新 CPU 图表
    const cpuChart = this.charts.cpu;
    cpuChart.data.labels.push(time);
    cpuChart.data.datasets[0].data.push(metrics.cpu);
    
    // 保持最近 60 个数据点
    if (cpuChart.data.labels.length > 60) {
      cpuChart.data.labels.shift();
      cpuChart.data.datasets[0].data.shift();
    }
    
    cpuChart.update('none');
  }
  
  updateStats(metrics) {
    document.getElementById('cpuValue').textContent = `${metrics.cpu.toFixed(1)}%`;
    document.getElementById('memoryValue').textContent = `${metrics.memory.toFixed(1)}%`;
    document.getElementById('diskValue').textContent = `${metrics.disk.toFixed(1)}%`;
  }
  
  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
    }
  }
}
```

---

## 9. SSE vs WebSocket

### 9.1 对比表

| 特性 | SSE | WebSocket |
|------|-----|-----------|
| 通信方向 | 单向（服务器→客户端） | 双向 |
| 协议 | HTTP | WS/WSS |
| 数据格式 | 文本 | 文本/二进制 |
| 自动重连 | ✅ 内置 | ❌ 需手动实现 |
| 浏览器支持 | 较好（除 IE） | 很好 |
| 代理兼容性 | 好（标准 HTTP） | 一般 |
| 复杂度 | 简单 | 较复杂 |
| 连接数限制 | 每域名 6 个 | 无限制 |
| 适用场景 | 服务器推送 | 实时双向通信 |

### 9.2 选择建议

**选择 SSE**：
- 只需要服务器向客户端推送数据
- 需要自动重连和断点续传
- 希望使用简单的 HTTP 基础设施
- 数据是文本格式
- 示例：通知、实时更新、日志流、AI 流式响应

**选择 WebSocket**：
- 需要双向实时通信
- 需要传输二进制数据
- 需要高频率的消息交换
- 需要突破浏览器连接数限制
- 示例：聊天应用、在线游戏、协作编辑

### 9.3 混合使用

```javascript
// 使用 SSE 接收服务器推送，使用 HTTP 发送客户端消息
class HybridClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.eventSource = null;
  }
  
  // 使用 SSE 接收消息
  connect() {
    this.eventSource = new EventSource(`${this.baseUrl}/events`);
    
    this.eventSource.addEventListener('message', (event) => {
      this.handleMessage(JSON.parse(event.data));
    });
  }
  
  // 使用 HTTP POST 发送消息
  async send(message) {
    const response = await fetch(`${this.baseUrl}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });
    return response.json();
  }
  
  handleMessage(data) {
    console.log('Received:', data);
  }
  
  disconnect() {
    if (this.eventSource) {
      this.eventSource.close();
    }
  }
}
```

---

## 10. 性能优化

### 10.1 连接数优化

```javascript
// 浏览器对同一域名的 SSE 连接数有限制（通常 6 个）
// 解决方案：使用单一连接 + 消息路由

// 服务端：统一的事件流
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  
  // 订阅多个频道
  const channels = req.query.channels?.split(',') || ['default'];
  
  const subscriptions = channels.map(channel => {
    return eventEmitter.on(channel, (data) => {
      res.write(`event: ${channel}\ndata: ${JSON.stringify(data)}\n\n`);
    });
  });
  
  req.on('close', () => {
    subscriptions.forEach(unsub => unsub());
  });
});

// 客户端：单一连接，多事件监听
const eventSource = new EventSource('/api/events?channels=notifications,updates,chat');

eventSource.addEventListener('notifications', handleNotification);
eventSource.addEventListener('updates', handleUpdate);
eventSource.addEventListener('chat', handleChat);
```

### 10.2 消息压缩

```javascript
// 服务端：启用 gzip 压缩
const compression = require('compression');

// 注意：SSE 通常不建议使用压缩，因为会导致缓冲
// 如果必须使用，确保设置 flush
app.use(compression({
  filter: (req, res) => {
    // SSE 不压缩
    if (req.headers.accept === 'text/event-stream') {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// 替代方案：在应用层压缩数据
const zlib = require('zlib');

function compressData(data) {
  return zlib.gzipSync(JSON.stringify(data)).toString('base64');
}

// 客户端解压
function decompressData(compressed) {
  const buffer = Uint8Array.from(atob(compressed), c => c.charCodeAt(0));
  const decompressed = pako.ungzip(buffer, { to: 'string' });
  return JSON.parse(decompressed);
}
```

### 10.3 消息批处理

```javascript
// 服务端：批量发送消息
class BatchedSSE {
  constructor(res, batchInterval = 100) {
    this.res = res;
    this.batchInterval = batchInterval;
    this.messageQueue = [];
    this.timer = null;
  }
  
  send(event, data) {
    this.messageQueue.push({ event, data });
    
    if (!this.timer) {
      this.timer = setTimeout(() => this.flush(), this.batchInterval);
    }
  }
  
  flush() {
    if (this.messageQueue.length === 0) return;
    
    // 批量发送
    const batch = this.messageQueue;
    this.messageQueue = [];
    this.timer = null;
    
    this.res.write(`event: batch\ndata: ${JSON.stringify(batch)}\n\n`);
  }
  
  close() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.flush();
    }
  }
}

// 客户端：处理批量消息
eventSource.addEventListener('batch', (event) => {
  const messages = JSON.parse(event.data);
  messages.forEach(({ event, data }) => {
    handleMessage(event, data);
  });
});
```

### 10.4 内存管理

```javascript
// 服务端：限制连接数和消息队列
class SSEManager {
  constructor(options = {}) {
    this.maxConnections = options.maxConnections || 10000;
    this.maxQueueSize = options.maxQueueSize || 100;
    this.connections = new Map();
  }
  
  addConnection(id, res) {
    // 检查连接数限制
    if (this.connections.size >= this.maxConnections) {
      res.status(503).json({ error: 'Too many connections' });
      return false;
    }
    
    this.connections.set(id, {
      res,
      queue: [],
      lastActivity: Date.now()
    });
    
    return true;
  }
  
  // 定期清理不活跃的连接
  startCleanup(interval = 60000) {
    setInterval(() => {
      const now = Date.now();
      const timeout = 5 * 60 * 1000; // 5分钟无活动
      
      this.connections.forEach((conn, id) => {
        if (now - conn.lastActivity > timeout) {
          this.removeConnection(id);
        }
      });
    }, interval);
  }
  
  removeConnection(id) {
    const conn = this.connections.get(id);
    if (conn) {
      try {
        conn.res.end();
      } catch (e) {
        // 忽略
      }
      this.connections.delete(id);
    }
  }
}
```

---

## 11. 框架集成

### 11.1 React Hook

```tsx
import { useState, useEffect, useCallback, useRef } from 'react';

interface UseSSEOptions {
  withCredentials?: boolean;
  onOpen?: () => void;
  onError?: (error: Event) => void;
}

function useSSE<T = unknown>(
  url: string,
  eventName: string = 'message',
  options: UseSSEOptions = {}
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  
  const connect = useCallback(() => {
    const eventSource = new EventSource(url, {
      withCredentials: options.withCredentials
    });
    
    eventSource.onopen = () => {
      setIsConnected(true);
      setError(null);
      options.onOpen?.();
    };
    
    eventSource.onerror = (e) => {
      setError(new Error('SSE connection error'));
      setIsConnected(false);
      options.onError?.(e);
    };
    
    eventSource.addEventListener(eventName, (event: MessageEvent) => {
      try {
        const parsedData = JSON.parse(event.data) as T;
        setData(parsedData);
      } catch {
        setData(event.data as T);
      }
    });
    
    eventSourceRef.current = eventSource;
  }, [url, eventName, options]);
  
  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
      setIsConnected(false);
    }
  }, []);
  
  useEffect(() => {
    connect();
    return disconnect;
  }, [connect, disconnect]);
  
  return { data, error, isConnected, reconnect: connect, disconnect };
}

// 使用示例
function NotificationList() {
  const { data, isConnected, error } = useSSE<Notification>(
    '/api/notifications',
    'notification'
  );
  
  const [notifications, setNotifications] = useState<Notification[]>([]);
  
  useEffect(() => {
    if (data) {
      setNotifications(prev => [data, ...prev].slice(0, 50));
    }
  }, [data]);
  
  if (error) return <div>Error: {error.message}</div>;
  
  return (
    <div>
      <div className={`status ${isConnected ? 'connected' : 'disconnected'}`}>
        {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
      </div>
      <ul>
        {notifications.map(n => (
          <li key={n.id}>{n.message}</li>
        ))}
      </ul>
    </div>
  );
}
```

### 11.2 Vue Composable

```typescript
import { ref, onMounted, onUnmounted, Ref } from 'vue';

interface UseSSEReturn<T> {
  data: Ref<T | null>;
  error: Ref<Error | null>;
  isConnected: Ref<boolean>;
  connect: () => void;
  disconnect: () => void;
}

export function useSSE<T = unknown>(
  url: string,
  eventName: string = 'message'
): UseSSEReturn<T> {
  const data = ref<T | null>(null) as Ref<T | null>;
  const error = ref<Error | null>(null);
  const isConnected = ref(false);
  let eventSource: EventSource | null = null;
  
  const connect = () => {
    if (eventSource) {
      eventSource.close();
    }
    
    eventSource = new EventSource(url);
    
    eventSource.onopen = () => {
      isConnected.value = true;
      error.value = null;
    };
    
    eventSource.onerror = () => {
      error.value = new Error('SSE connection error');
      isConnected.value = false;
    };
    
    eventSource.addEventListener(eventName, (event: MessageEvent) => {
      try {
        data.value = JSON.parse(event.data);
      } catch {
        data.value = event.data as T;
      }
    });
  };
  
  const disconnect = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
      isConnected.value = false;
    }
  };
  
  onMounted(connect);
  onUnmounted(disconnect);
  
  return { data, error, isConnected, connect, disconnect };
}

// 使用示例
<script setup lang="ts">
import { watch } from 'vue';
import { useSSE } from '@/composables/useSSE';

interface StockPrice {
  symbol: string;
  price: number;
  change: number;
}

const { data, isConnected, error } = useSSE<StockPrice>(
  '/api/stocks',
  'price-update'
);

const prices = ref<Map<string, StockPrice>>(new Map());

watch(data, (newData) => {
  if (newData) {
    prices.value.set(newData.symbol, newData);
  }
});
</script>

<template>
  <div>
    <div :class="['status', isConnected ? 'connected' : 'disconnected']">
      {{ isConnected ? '🟢 Connected' : '🔴 Disconnected' }}
    </div>
    <div v-if="error" class="error">{{ error.message }}</div>
    <table>
      <tr v-for="[symbol, price] in prices" :key="symbol">
        <td>{{ symbol }}</td>
        <td>{{ price.price.toFixed(2) }}</td>
        <td :class="price.change >= 0 ? 'up' : 'down'">
          {{ price.change >= 0 ? '+' : '' }}{{ price.change.toFixed(2) }}%
        </td>
      </tr>
    </table>
  </div>
</template>
```

### 11.3 Angular Service

```typescript
import { Injectable, OnDestroy } from '@angular/core';
import { Observable, Subject, BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class SSEService implements OnDestroy {
  private eventSource: EventSource | null = null;
  private messageSubject = new Subject<any>();
  private connectionStatus = new BehaviorSubject<boolean>(false);
  
  connect(url: string): Observable<any> {
    this.disconnect();
    
    this.eventSource = new EventSource(url);
    
    this.eventSource.onopen = () => {
      this.connectionStatus.next(true);
    };
    
    this.eventSource.onerror = () => {
      this.connectionStatus.next(false);
    };
    
    this.eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.messageSubject.next(data);
      } catch {
        this.messageSubject.next(event.data);
      }
    };
    
    return this.messageSubject.asObservable();
  }
  
  addEventListener(eventName: string): Observable<any> {
    return new Observable(observer => {
      if (!this.eventSource) {
        observer.error(new Error('Not connected'));
        return;
      }
      
      const handler = (event: MessageEvent) => {
        try {
          observer.next(JSON.parse(event.data));
        } catch {
          observer.next(event.data);
        }
      };
      
      this.eventSource.addEventListener(eventName, handler);
      
      return () => {
        this.eventSource?.removeEventListener(eventName, handler);
      };
    });
  }
  
  get isConnected$(): Observable<boolean> {
    return this.connectionStatus.asObservable();
  }
  
  disconnect(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
      this.connectionStatus.next(false);
    }
  }
  
  ngOnDestroy(): void {
    this.disconnect();
    this.messageSubject.complete();
    this.connectionStatus.complete();
  }
}

// 使用示例
@Component({
  selector: 'app-notifications',
  template: `
    <div [class.connected]="isConnected$ | async">
      {{ (isConnected$ | async) ? 'Connected' : 'Disconnected' }}
    </div>
    <ul>
      <li *ngFor="let notification of notifications">
        {{ notification.message }}
      </li>
    </ul>
  `
})
export class NotificationsComponent implements OnInit, OnDestroy {
  notifications: Notification[] = [];
  isConnected$ = this.sseService.isConnected$;
  private subscription?: Subscription;
  
  constructor(private sseService: SSEService) {}
  
  ngOnInit(): void {
    this.sseService.connect('/api/events');
    this.subscription = this.sseService
      .addEventListener('notification')
      .subscribe(notification => {
        this.notifications.unshift(notification);
      });
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
    this.sseService.disconnect();
  }
}
```

---

## 12. 常见错误与解决方案

### 12.1 连接立即关闭

**问题**：EventSource 连接后立即关闭

**原因与解决方案**：

```javascript
// 1. Content-Type 错误
// ❌ 错误
res.setHeader('Content-Type', 'application/json');
// ✅ 正确
res.setHeader('Content-Type', 'text/event-stream');

// 2. 响应被缓冲
// ❌ 没有禁用缓冲
// ✅ 添加必要的头
res.setHeader('Cache-Control', 'no-cache');
res.setHeader('Connection', 'keep-alive');
res.setHeader('X-Accel-Buffering', 'no'); // Nginx

// 3. 响应过早结束
// ❌ 错误：使用 res.send() 或 res.json()
res.send('data');
// ✅ 正确：使用 res.write()
res.write('data: message\n\n');

// 4. 没有发送初始数据
// 某些代理需要收到数据才会保持连接
res.write(': connected\n\n');
```

### 12.2 消息格式错误

**问题**：客户端收不到消息或消息解析错误

```javascript
// 1. 缺少换行符
// ❌ 错误
res.write('data: hello');
// ✅ 正确：每条消息后需要两个换行符
res.write('data: hello\n\n');

// 2. 多行数据格式错误
// ❌ 错误
res.write('data: line1\nline2\n\n');
// ✅ 正确：每行都需要 data: 前缀
res.write('data: line1\ndata: line2\n\n');

// 3. JSON 数据换行问题
// ❌ 错误：JSON 中包含换行符
const data = { message: 'hello\nworld' };
res.write(`data: ${JSON.stringify(data)}\n\n`);
// ✅ 正确：JSON.stringify 会转义换行符，这是安全的
// 或者分行发送
res.write('data: {"message": "hello\\nworld"}\n\n');

// 4. 事件类型拼写错误
// ❌ 错误
res.write('Event: update\n'); // 大写 E
// ✅ 正确
res.write('event: update\n');
```

### 12.3 跨域问题

**问题**：CORS 错误

```javascript
// 服务端：设置 CORS 头
app.get('/api/events', (req, res) => {
  // 设置 CORS 头
  res.setHeader('Access-Control-Allow-Origin', 'https://your-domain.com');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  // SSE 头
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  
  // ...
});

// 客户端：启用凭证
const eventSource = new EventSource('https://api.example.com/events', {
  withCredentials: true
});

// 注意：使用 withCredentials 时，服务端不能设置
// Access-Control-Allow-Origin: *
// 必须指定具体的域名
```

### 12.4 Nginx 代理问题

**问题**：通过 Nginx 代理时连接不稳定或消息延迟

```nginx
# Nginx 配置
location /api/events {
    proxy_pass http://backend;
    
    # 禁用缓冲
    proxy_buffering off;
    proxy_cache off;
    
    # SSE 特定设置
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    
    # 超时设置
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    
    # 禁用 gzip（可选）
    gzip off;
    
    # 传递客户端信息
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### 12.5 连接数限制

**问题**：浏览器限制同一域名的 SSE 连接数（通常 6 个）

```javascript
// 解决方案 1：使用单一连接 + 消息路由
const eventSource = new EventSource('/api/events?channels=a,b,c');

// 解决方案 2：使用不同的子域名
const eventSource1 = new EventSource('https://sse1.example.com/events');
const eventSource2 = new EventSource('https://sse2.example.com/events');

// 解决方案 3：使用 HTTP/2（支持多路复用）
// 需要服务器支持 HTTP/2

// 解决方案 4：页面卸载时关闭连接
window.addEventListener('beforeunload', () => {
  eventSource.close();
});
```

### 12.6 内存泄漏

**问题**：长时间运行后内存持续增长

```javascript
// 服务端：清理断开的连接
const connections = new Map();

app.get('/events', (req, res) => {
  const id = Date.now();
  connections.set(id, res);
  
  // 监听连接关闭
  req.on('close', () => {
    connections.delete(id);
    console.log(`Connection ${id} closed, total: ${connections.size}`);
  });
  
  // 设置超时
  req.setTimeout(0); // 禁用超时
});

// 客户端：正确清理事件监听器
class SSEClient {
  constructor(url) {
    this.url = url;
    this.eventSource = null;
    this.handlers = [];
  }
  
  on(event, handler) {
    this.handlers.push({ event, handler });
    if (this.eventSource) {
      this.eventSource.addEventListener(event, handler);
    }
  }
  
  close() {
    if (this.eventSource) {
      // 移除所有监听器
      this.handlers.forEach(({ event, handler }) => {
        this.eventSource.removeEventListener(event, handler);
      });
      this.eventSource.close();
      this.eventSource = null;
    }
    this.handlers = [];
  }
}
```

### 12.7 重连风暴

**问题**：服务器重启时所有客户端同时重连

```javascript
// 服务端：设置随机重连时间
app.get('/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  
  // 设置随机重连时间（3-10秒）
  const retryTime = 3000 + Math.random() * 7000;
  res.write(`retry: ${Math.floor(retryTime)}\n\n`);
  
  // ...
});

// 客户端：指数退避重连
class SSEClientWithBackoff {
  constructor(url) {
    this.url = url;
    this.reconnectDelay = 1000;
    this.maxDelay = 30000;
    this.eventSource = null;
  }
  
  connect() {
    this.eventSource = new EventSource(this.url);
    
    this.eventSource.onopen = () => {
      // 连接成功，重置延迟
      this.reconnectDelay = 1000;
    };
    
    this.eventSource.onerror = () => {
      if (this.eventSource.readyState === EventSource.CLOSED) {
        // 使用指数退避 + 随机抖动
        const jitter = Math.random() * 1000;
        const delay = Math.min(this.reconnectDelay + jitter, this.maxDelay);
        
        console.log(`Reconnecting in ${delay}ms`);
        
        setTimeout(() => {
          this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay);
          this.connect();
        }, delay);
      }
    };
  }
}
```

---

## 快速参考

### SSE 消息格式

```
id: 123
event: update
retry: 5000
data: {"message": "Hello"}

```

### 服务端响应头

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

### EventSource 状态

| 常量 | 值 | 说明 |
|------|---|------|
| CONNECTING | 0 | 正在连接 |
| OPEN | 1 | 已连接 |
| CLOSED | 2 | 已关闭 |

---

> 💡 **小贴士**：SSE 是实现服务器推送的简单有效方案，特别适合单向数据流场景。对于需要双向通信的场景，考虑使用 WebSocket。在生产环境中，注意配置 Nginx 等代理服务器以支持长连接。
