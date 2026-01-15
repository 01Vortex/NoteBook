

> Nest.js 是一个用于构建高效、可扩展的 Node.js 服务端应用的渐进式框架
> 本笔记基于 Nest.js 10.x + TypeScript + TypeORM/Prisma

---

## 目录

1. [基础概念](#1-基础概念)
2. [项目搭建](#2-项目搭建)
3. [控制器 Controller](#3-控制器-controller)
4. [服务与依赖注入](#4-服务与依赖注入)
5. [模块系统](#5-模块系统)
6. [中间件与拦截器](#6-中间件与拦截器)
7. [管道与数据验证](#7-管道与数据验证)
8. [异常处理](#8-异常处理)
9. [守卫与认证](#9-守卫与认证)
10. [数据库集成](#10-数据库集成)
11. [配置管理](#11-配置管理)
12. [文件上传](#12-文件上传)
13. [WebSocket](#13-websocket)
14. [微服务](#14-微服务)
15. [测试](#15-测试)
16. [常见错误与解决方案](#16-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Nest.js？

Nest.js 是一个用于构建高效、可靠、可扩展的服务端应用程序的框架。它使用 TypeScript 构建（也支持纯 JavaScript），结合了面向对象编程（OOP）、函数式编程（FP）和函数响应式编程（FRP）的元素。

**Nest.js 的核心特点**：
- **TypeScript 优先**：完全支持 TypeScript，提供类型安全和更好的开发体验
- **模块化架构**：采用模块化设计，便于代码组织和复用
- **依赖注入**：内置强大的依赖注入容器，实现松耦合
- **装饰器驱动**：大量使用装饰器，代码简洁优雅
- **平台无关**：底层可以使用 Express 或 Fastify
- **微服务支持**：原生支持微服务架构
- **丰富的生态**：官方提供大量模块（数据库、认证、缓存等）

### 1.2 架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│                      Nest.js 架构                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   请求 ──→ 中间件 ──→ 守卫 ──→ 拦截器(前) ──→ 管道 ──→ 控制器    │
│                                                                  │
│                              │                                   │
│                              ▼                                   │
│                           服务层                                 │
│                              │                                   │
│                              ▼                                   │
│                          数据访问层                              │
│                              │                                   │
│                              ▼                                   │
│   响应 ←── 异常过滤器 ←── 拦截器(后) ←── 控制器返回              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 核心概念

| 概念 | 说明 | 装饰器 |
|------|------|--------|
| Module（模块） | 组织代码的基本单元 | `@Module()` |
| Controller（控制器） | 处理 HTTP 请求 | `@Controller()` |
| Provider（提供者） | 可注入的服务、仓库等 | `@Injectable()` |
| Middleware（中间件） | 请求预处理 | - |
| Guard（守卫） | 权限验证 | `@UseGuards()` |
| Interceptor（拦截器） | 请求/响应转换 | `@UseInterceptors()` |
| Pipe（管道） | 数据转换和验证 | `@UsePipes()` |
| Filter（过滤器） | 异常处理 | `@UseFilters()` |

### 1.4 请求生命周期

```
1. 收到请求
2. 全局中间件
3. 模块中间件
4. 全局守卫
5. 控制器守卫
6. 路由守卫
7. 全局拦截器（前）
8. 控制器拦截器（前）
9. 路由拦截器（前）
10. 全局管道
11. 控制器管道
12. 路由管道
13. 路由参数管道
14. 控制器方法（处理程序）
15. 服务
16. 路由拦截器（后）
17. 控制器拦截器（后）
18. 全局拦截器（后）
19. 异常过滤器（如果有异常）
20. 返回响应
```


---

## 2. 项目搭建

### 2.1 安装与创建项目

```bash
# 全局安装 Nest CLI
npm install -g @nestjs/cli

# 创建新项目
nest new my-project

# 选择包管理器（npm/yarn/pnpm）
# 项目创建完成后进入目录
cd my-project

# 启动开发服务器
npm run start:dev

# 访问 http://localhost:3000
```

### 2.2 项目结构

```
my-project/
├── src/
│   ├── app.controller.ts      # 根控制器
│   ├── app.controller.spec.ts # 控制器测试
│   ├── app.module.ts          # 根模块
│   ├── app.service.ts         # 根服务
│   └── main.ts                # 应用入口
├── test/
│   ├── app.e2e-spec.ts        # 端到端测试
│   └── jest-e2e.json          # E2E 测试配置
├── nest-cli.json              # Nest CLI 配置
├── package.json
├── tsconfig.json              # TypeScript 配置
└── tsconfig.build.json        # 构建配置
```

### 2.3 推荐项目结构（大型项目）

```
src/
├── common/                    # 公共模块
│   ├── decorators/            # 自定义装饰器
│   ├── filters/               # 异常过滤器
│   ├── guards/                # 守卫
│   ├── interceptors/          # 拦截器
│   ├── pipes/                 # 管道
│   ├── middleware/            # 中间件
│   └── dto/                   # 公共 DTO
├── config/                    # 配置模块
│   ├── config.module.ts
│   └── configuration.ts
├── modules/                   # 业务模块
│   ├── users/
│   │   ├── dto/
│   │   │   ├── create-user.dto.ts
│   │   │   └── update-user.dto.ts
│   │   ├── entities/
│   │   │   └── user.entity.ts
│   │   ├── users.controller.ts
│   │   ├── users.service.ts
│   │   ├── users.module.ts
│   │   └── users.repository.ts
│   ├── auth/
│   └── posts/
├── database/                  # 数据库相关
│   ├── migrations/
│   └── seeds/
├── app.module.ts
└── main.ts
```

### 2.4 入口文件配置

```typescript
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  // 全局前缀
  app.setGlobalPrefix('api');

  // API 版本控制
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // 全局验证管道
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,           // 自动剥离非白名单属性
      forbidNonWhitelisted: true, // 非白名单属性抛出错误
      transform: true,           // 自动类型转换
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // CORS 配置
  app.enableCors({
    origin: ['http://localhost:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  });

  // Swagger 文档
  const config = new DocumentBuilder()
    .setTitle('API 文档')
    .setDescription('API 接口文档')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  // 启动服务
  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}`);
}
bootstrap();
```

### 2.5 CLI 常用命令

```bash
# 生成模块
nest g module users
nest g mo users  # 简写

# 生成控制器
nest g controller users
nest g co users

# 生成服务
nest g service users
nest g s users

# 生成完整资源（CRUD）
nest g resource users
# 选择 REST API / GraphQL / Microservice / WebSockets

# 生成其他
nest g guard auth                    # 守卫
nest g interceptor logging           # 拦截器
nest g pipe validation               # 管道
nest g filter http-exception         # 过滤器
nest g middleware logger             # 中间件
nest g decorator roles               # 装饰器
nest g class user.entity             # 类
nest g interface user                # 接口

# 构建项目
nest build

# 查看项目信息
nest info
```


---

## 3. 控制器 Controller

控制器负责处理传入的 HTTP 请求并返回响应。它是应用程序的入口点，定义了路由和请求处理逻辑。

### 3.1 基础控制器

```typescript
// src/modules/users/users.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  Headers,
  Ip,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  Redirect,
  Header,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Controller('users')  // 路由前缀 /users
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // GET /users
  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  // GET /users/:id
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(+id);
  }

  // POST /users
  @Post()
  @HttpCode(HttpStatus.CREATED)  // 设置状态码
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  // PUT /users/:id
  @Put(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  // PATCH /users/:id
  @Patch(':id')
  partialUpdate(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  // DELETE /users/:id
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  remove(@Param('id') id: string) {
    return this.usersService.remove(+id);
  }
}
```

### 3.2 请求参数装饰器

```typescript
@Controller('users')
export class UsersController {
  // 路径参数
  @Get(':id')
  findOne(@Param('id') id: string) {
    return `User ${id}`;
  }

  // 多个路径参数
  @Get(':userId/posts/:postId')
  findUserPost(
    @Param('userId') userId: string,
    @Param('postId') postId: string,
  ) {
    return `User ${userId}, Post ${postId}`;
  }

  // 查询参数 GET /users?page=1&limit=10&sort=name
  @Get()
  findAll(
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
    @Query('sort') sort?: string,
    @Query() query?: any,  // 获取所有查询参数
  ) {
    return { page, limit, sort, query };
  }

  // 请求体
  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return createUserDto;
  }

  // 部分请求体
  @Post()
  createPartial(@Body('name') name: string) {
    return { name };
  }

  // 请求头
  @Get('headers')
  getHeaders(
    @Headers('authorization') auth: string,
    @Headers() headers: any,
  ) {
    return { auth, headers };
  }

  // 客户端 IP
  @Get('ip')
  getIp(@Ip() ip: string) {
    return { ip };
  }

  // 原始请求/响应对象
  @Get('raw')
  getRaw(@Req() req: Request, @Res() res: Response) {
    res.status(200).json({ message: 'Hello' });
  }

  // 使用 @Res() 但不发送响应（passthrough）
  @Get('passthrough')
  getPassthrough(@Res({ passthrough: true }) res: Response) {
    res.header('X-Custom-Header', 'value');
    return { message: 'Hello' };  // 仍然可以返回值
  }
}
```

### 3.3 路由配置

```typescript
// 路由通配符
@Controller('users')
export class UsersController {
  // 匹配 /users/ab*cd（如 /users/abcd, /users/ab123cd）
  @Get('ab*cd')
  findWildcard() {
    return 'Wildcard route';
  }

  // 可选参数
  @Get(':id?')
  findOptional(@Param('id') id?: string) {
    return id ? `User ${id}` : 'All users';
  }
}

// 子路由
@Controller('users/:userId/posts')
export class UserPostsController {
  @Get()
  findAll(@Param('userId') userId: string) {
    return `All posts of user ${userId}`;
  }

  @Get(':postId')
  findOne(
    @Param('userId') userId: string,
    @Param('postId') postId: string,
  ) {
    return `Post ${postId} of user ${userId}`;
  }
}

// API 版本控制
@Controller({
  path: 'users',
  version: '1',  // /v1/users
})
export class UsersV1Controller {
  @Get()
  findAll() {
    return 'V1 users';
  }
}

@Controller({
  path: 'users',
  version: '2',  // /v2/users
})
export class UsersV2Controller {
  @Get()
  findAll() {
    return 'V2 users with new features';
  }
}
```

### 3.4 响应处理

```typescript
@Controller('users')
export class UsersController {
  // 重定向
  @Get('old-route')
  @Redirect('https://example.com', 301)
  redirect() {
    // 可以动态修改重定向
    return { url: 'https://new-url.com', statusCode: 302 };
  }

  // 设置响应头
  @Get('custom-header')
  @Header('Cache-Control', 'none')
  @Header('X-Custom-Header', 'value')
  customHeader() {
    return { message: 'With custom headers' };
  }

  // 异步响应
  @Get('async')
  async findAllAsync(): Promise<User[]> {
    return await this.usersService.findAll();
  }

  // Observable 响应
  @Get('observable')
  findAllObservable(): Observable<User[]> {
    return of(this.usersService.findAll());
  }

  // 流式响应
  @Get('stream')
  getStream(@Res() res: Response) {
    const stream = createReadStream(join(process.cwd(), 'file.txt'));
    stream.pipe(res);
  }
}
```


---

## 4. 服务与依赖注入

服务（Service）是 Nest.js 中处理业务逻辑的核心组件。通过依赖注入（DI），可以实现松耦合和更好的可测试性。

### 4.1 基础服务

```typescript
// src/modules/users/users.service.ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()  // 标记为可注入的提供者
export class UsersService {
  private users = [
    { id: 1, name: 'John', email: 'john@example.com' },
    { id: 2, name: 'Jane', email: 'jane@example.com' },
  ];

  findAll() {
    return this.users;
  }

  findOne(id: number) {
    const user = this.users.find(u => u.id === id);
    if (!user) {
      throw new NotFoundException(`User #${id} not found`);
    }
    return user;
  }

  create(createUserDto: CreateUserDto) {
    const newUser = {
      id: this.users.length + 1,
      ...createUserDto,
    };
    this.users.push(newUser);
    return newUser;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new NotFoundException(`User #${id} not found`);
    }
    this.users[userIndex] = {
      ...this.users[userIndex],
      ...updateUserDto,
    };
    return this.users[userIndex];
  }

  remove(id: number) {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new NotFoundException(`User #${id} not found`);
    }
    this.users.splice(userIndex, 1);
  }
}
```

### 4.2 依赖注入

```typescript
// 构造函数注入（推荐）
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly loggerService: LoggerService,
  ) {}
}

// 属性注入
@Controller('users')
export class UsersController {
  @Inject(UsersService)
  private readonly usersService: UsersService;
}

// 使用自定义令牌注入
// 定义令牌
export const CONFIG_OPTIONS = 'CONFIG_OPTIONS';

// 注册提供者
@Module({
  providers: [
    {
      provide: CONFIG_OPTIONS,
      useValue: { apiKey: 'xxx' },
    },
  ],
})
export class AppModule {}

// 注入
@Injectable()
export class ApiService {
  constructor(
    @Inject(CONFIG_OPTIONS) private options: ConfigOptions,
  ) {}
}
```

### 4.3 提供者类型

```typescript
// 1. 类提供者（标准）
@Module({
  providers: [UsersService],
  // 等同于
  // providers: [{ provide: UsersService, useClass: UsersService }],
})

// 2. 值提供者
@Module({
  providers: [
    {
      provide: 'API_KEY',
      useValue: 'my-api-key',
    },
    {
      provide: 'CONFIG',
      useValue: {
        database: 'mongodb://localhost',
        port: 3000,
      },
    },
  ],
})

// 3. 工厂提供者
@Module({
  providers: [
    {
      provide: 'ASYNC_CONNECTION',
      useFactory: async (configService: ConfigService) => {
        const connection = await createConnection(configService.get('DATABASE_URL'));
        return connection;
      },
      inject: [ConfigService],  // 注入依赖
    },
  ],
})

// 4. 别名提供者
@Module({
  providers: [
    UsersService,
    {
      provide: 'AliasedUsersService',
      useExisting: UsersService,
    },
  ],
})

// 5. 异步提供者
@Module({
  providers: [
    {
      provide: 'ASYNC_PROVIDER',
      useFactory: async () => {
        const data = await fetchSomeData();
        return data;
      },
    },
  ],
})
```

### 4.4 作用域

```typescript
// 默认作用域：单例（SINGLETON）
// 整个应用共享一个实例
@Injectable()
export class SingletonService {}

// 请求作用域（REQUEST）
// 每个请求创建新实例
@Injectable({ scope: Scope.REQUEST })
export class RequestScopedService {
  constructor(@Inject(REQUEST) private request: Request) {}
}

// 瞬态作用域（TRANSIENT）
// 每次注入创建新实例
@Injectable({ scope: Scope.TRANSIENT })
export class TransientService {}

// 控制器也可以设置作用域
@Controller({
  path: 'users',
  scope: Scope.REQUEST,
})
export class UsersController {}
```

### 4.5 循环依赖处理

```typescript
// 使用 forwardRef 解决循环依赖
// users.service.ts
@Injectable()
export class UsersService {
  constructor(
    @Inject(forwardRef(() => PostsService))
    private postsService: PostsService,
  ) {}
}

// posts.service.ts
@Injectable()
export class PostsService {
  constructor(
    @Inject(forwardRef(() => UsersService))
    private usersService: UsersService,
  ) {}
}

// 模块级别的循环依赖
@Module({
  imports: [forwardRef(() => PostsModule)],
})
export class UsersModule {}
```


---

## 5. 模块系统

模块是 Nest.js 组织代码的基本单元。每个应用至少有一个根模块，大型应用通常由多个功能模块组成。

### 5.1 模块基础

```typescript
// src/modules/users/users.module.ts
import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

@Module({
  imports: [],           // 导入其他模块
  controllers: [UsersController],  // 控制器
  providers: [UsersService],       // 提供者
  exports: [UsersService],         // 导出供其他模块使用
})
export class UsersModule {}
```

### 5.2 模块导入导出

```typescript
// 功能模块
@Module({
  providers: [DatabaseService],
  exports: [DatabaseService],  // 导出服务
})
export class DatabaseModule {}

// 使用模块
@Module({
  imports: [DatabaseModule],  // 导入模块
  providers: [UsersService],
})
export class UsersModule {}

// UsersService 现在可以注入 DatabaseService
@Injectable()
export class UsersService {
  constructor(private databaseService: DatabaseService) {}
}

// 重新导出模块
@Module({
  imports: [DatabaseModule],
  exports: [DatabaseModule],  // 重新导出，使用 CommonModule 的模块也能访问 DatabaseModule
})
export class CommonModule {}
```

### 5.3 全局模块

```typescript
// 全局模块 - 只需导入一次，全局可用
@Global()
@Module({
  providers: [ConfigService, LoggerService],
  exports: [ConfigService, LoggerService],
})
export class GlobalModule {}

// 在根模块导入
@Module({
  imports: [GlobalModule],
})
export class AppModule {}

// 其他模块无需导入即可使用
@Injectable()
export class UsersService {
  constructor(
    private configService: ConfigService,  // 直接可用
    private loggerService: LoggerService,
  ) {}
}
```

### 5.4 动态模块

```typescript
// 动态模块允许在导入时传入配置
// database.module.ts
import { Module, DynamicModule } from '@nestjs/common';

interface DatabaseModuleOptions {
  host: string;
  port: number;
  username: string;
  password: string;
  database: string;
}

@Module({})
export class DatabaseModule {
  static forRoot(options: DatabaseModuleOptions): DynamicModule {
    return {
      module: DatabaseModule,
      global: true,  // 可选：设为全局模块
      providers: [
        {
          provide: 'DATABASE_OPTIONS',
          useValue: options,
        },
        {
          provide: 'DATABASE_CONNECTION',
          useFactory: async (options: DatabaseModuleOptions) => {
            const connection = await createConnection(options);
            return connection;
          },
          inject: ['DATABASE_OPTIONS'],
        },
        DatabaseService,
      ],
      exports: ['DATABASE_CONNECTION', DatabaseService],
    };
  }

  // 异步配置
  static forRootAsync(options: {
    imports?: any[];
    useFactory: (...args: any[]) => Promise<DatabaseModuleOptions> | DatabaseModuleOptions;
    inject?: any[];
  }): DynamicModule {
    return {
      module: DatabaseModule,
      imports: options.imports || [],
      providers: [
        {
          provide: 'DATABASE_OPTIONS',
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        {
          provide: 'DATABASE_CONNECTION',
          useFactory: async (options: DatabaseModuleOptions) => {
            return await createConnection(options);
          },
          inject: ['DATABASE_OPTIONS'],
        },
        DatabaseService,
      ],
      exports: ['DATABASE_CONNECTION', DatabaseService],
    };
  }
}

// 使用动态模块
@Module({
  imports: [
    DatabaseModule.forRoot({
      host: 'localhost',
      port: 5432,
      username: 'admin',
      password: 'password',
      database: 'mydb',
    }),
  ],
})
export class AppModule {}

// 异步配置（从 ConfigService 获取）
@Module({
  imports: [
    DatabaseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        host: configService.get('DB_HOST'),
        port: configService.get('DB_PORT'),
        username: configService.get('DB_USER'),
        password: configService.get('DB_PASS'),
        database: configService.get('DB_NAME'),
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

### 5.5 模块引用

```typescript
// 获取模块引用，用于动态获取提供者
import { ModuleRef } from '@nestjs/core';

@Injectable()
export class UsersService {
  private service: SomeService;

  constructor(private moduleRef: ModuleRef) {}

  async onModuleInit() {
    // 获取提供者实例
    this.service = await this.moduleRef.get(SomeService);
    
    // 获取请求作用域的提供者
    this.service = await this.moduleRef.resolve(SomeService);
    
    // 创建新的瞬态实例
    this.service = await this.moduleRef.create(SomeService);
  }
}
```


---

## 6. 中间件与拦截器

### 6.1 中间件

中间件在路由处理程序之前执行，可以访问请求和响应对象，常用于日志、认证、请求转换等。

```typescript
// src/common/middleware/logger.middleware.ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

// 类中间件
@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const { method, originalUrl } = req;
    const startTime = Date.now();

    res.on('finish', () => {
      const { statusCode } = res;
      const duration = Date.now() - startTime;
      console.log(`${method} ${originalUrl} ${statusCode} - ${duration}ms`);
    });

    next();
  }
}

// 函数中间件
export function loggerMiddleware(req: Request, res: Response, next: NextFunction) {
  console.log(`Request: ${req.method} ${req.url}`);
  next();
}
```

```typescript
// 应用中间件
// app.module.ts
import { Module, NestModule, MiddlewareConsumer, RequestMethod } from '@nestjs/common';

@Module({
  imports: [UsersModule],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      // 应用到所有路由
      .forRoutes('*');

    consumer
      .apply(AuthMiddleware)
      // 应用到特定路由
      .forRoutes('users');

    consumer
      .apply(CorsMiddleware)
      // 应用到特定方法和路由
      .forRoutes({ path: 'users', method: RequestMethod.POST });

    consumer
      .apply(ValidationMiddleware)
      // 应用到控制器
      .forRoutes(UsersController);

    consumer
      .apply(LoggerMiddleware, AuthMiddleware)  // 多个中间件
      .exclude(
        { path: 'users', method: RequestMethod.GET },  // 排除特定路由
        { path: 'health', method: RequestMethod.ALL },
      )
      .forRoutes(UsersController);
  }
}

// 全局中间件（在 main.ts 中）
app.use(loggerMiddleware);
```

### 6.2 拦截器

拦截器可以在方法执行前后添加额外逻辑，常用于日志、缓存、响应转换、异常映射等。

```typescript
// src/common/interceptors/logging.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, map, catchError } from 'rxjs/operators';

// 日志拦截器
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const now = Date.now();

    console.log(`Before: ${method} ${url}`);

    return next.handle().pipe(
      tap(() => {
        console.log(`After: ${method} ${url} - ${Date.now() - now}ms`);
      }),
    );
  }
}

// 响应转换拦截器
@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    return next.handle().pipe(
      map(data => ({
        code: 200,
        message: 'success',
        data,
        timestamp: new Date().toISOString(),
      })),
    );
  }
}

// 缓存拦截器
@Injectable()
export class CacheInterceptor implements NestInterceptor {
  private cache = new Map<string, any>();

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const key = request.url;

    if (this.cache.has(key)) {
      return of(this.cache.get(key));
    }

    return next.handle().pipe(
      tap(response => {
        this.cache.set(key, response);
      }),
    );
  }
}

// 超时拦截器
@Injectable()
export class TimeoutInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      timeout(5000),
      catchError(err => {
        if (err instanceof TimeoutError) {
          throw new RequestTimeoutException();
        }
        throw err;
      }),
    );
  }
}

// 错误映射拦截器
@Injectable()
export class ErrorsInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError(err => {
        if (err instanceof SomeSpecificError) {
          throw new BadRequestException(err.message);
        }
        throw err;
      }),
    );
  }
}
```

```typescript
// 应用拦截器

// 1. 控制器级别
@Controller('users')
@UseInterceptors(LoggingInterceptor)
export class UsersController {}

// 2. 方法级别
@Get()
@UseInterceptors(CacheInterceptor)
findAll() {}

// 3. 全局级别（在 main.ts）
app.useGlobalInterceptors(new TransformInterceptor());

// 4. 全局级别（通过模块，支持依赖注入）
@Module({
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
  ],
})
export class AppModule {}
```


---

## 7. 管道与数据验证

管道用于数据转换和验证，在控制器方法执行之前处理输入数据。

### 7.1 内置管道

```typescript
import {
  ParseIntPipe,
  ParseFloatPipe,
  ParseBoolPipe,
  ParseArrayPipe,
  ParseUUIDPipe,
  ParseEnumPipe,
  DefaultValuePipe,
  ValidationPipe,
} from '@nestjs/common';

@Controller('users')
export class UsersController {
  // ParseIntPipe - 转换为整数
  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.findOne(id);
  }

  // 自定义错误状态码
  @Get(':id')
  findOne(
    @Param('id', new ParseIntPipe({ errorHttpStatusCode: HttpStatus.NOT_ACCEPTABLE }))
    id: number,
  ) {
    return this.usersService.findOne(id);
  }

  // ParseUUIDPipe - 验证 UUID
  @Get(':uuid')
  findByUuid(@Param('uuid', ParseUUIDPipe) uuid: string) {
    return this.usersService.findByUuid(uuid);
  }

  // ParseEnumPipe - 验证枚举
  @Get('status/:status')
  findByStatus(
    @Param('status', new ParseEnumPipe(UserStatus))
    status: UserStatus,
  ) {
    return this.usersService.findByStatus(status);
  }

  // DefaultValuePipe - 默认值
  @Get()
  findAll(
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number,
  ) {
    return this.usersService.findAll({ page, limit });
  }

  // ParseArrayPipe - 解析数组
  @Get()
  findByIds(
    @Query('ids', new ParseArrayPipe({ items: Number, separator: ',' }))
    ids: number[],
  ) {
    return this.usersService.findByIds(ids);
  }
}
```

### 7.2 数据验证（class-validator）

```bash
# 安装依赖
npm install class-validator class-transformer
```

```typescript
// src/modules/users/dto/create-user.dto.ts
import {
  IsString,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsInt,
  IsEnum,
  IsArray,
  IsBoolean,
  IsDate,
  IsUrl,
  IsPhoneNumber,
  MinLength,
  MaxLength,
  Min,
  Max,
  Matches,
  ValidateNested,
  ArrayMinSize,
  ArrayMaxSize,
  IsUUID,
} from 'class-validator';
import { Type, Transform } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
  GUEST = 'guest',
}

export class AddressDto {
  @IsString()
  @IsNotEmpty()
  street: string;

  @IsString()
  @IsNotEmpty()
  city: string;

  @IsString()
  @IsOptional()
  zipCode?: string;
}

export class CreateUserDto {
  @ApiProperty({ description: '用户名', example: 'john_doe' })
  @IsString({ message: '用户名必须是字符串' })
  @IsNotEmpty({ message: '用户名不能为空' })
  @MinLength(3, { message: '用户名至少3个字符' })
  @MaxLength(20, { message: '用户名最多20个字符' })
  @Matches(/^[a-zA-Z0-9_]+$/, { message: '用户名只能包含字母、数字和下划线' })
  username: string;

  @ApiProperty({ description: '邮箱', example: 'john@example.com' })
  @IsEmail({}, { message: '邮箱格式不正确' })
  @IsNotEmpty({ message: '邮箱不能为空' })
  email: string;

  @ApiProperty({ description: '密码', minLength: 6 })
  @IsString()
  @MinLength(6, { message: '密码至少6个字符' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: '密码必须包含大小写字母和数字',
  })
  password: string;

  @ApiPropertyOptional({ description: '年龄', minimum: 0, maximum: 150 })
  @IsOptional()
  @IsInt({ message: '年龄必须是整数' })
  @Min(0, { message: '年龄不能小于0' })
  @Max(150, { message: '年龄不能大于150' })
  @Type(() => Number)  // 自动转换类型
  age?: number;

  @ApiPropertyOptional({ description: '角色', enum: UserRole })
  @IsOptional()
  @IsEnum(UserRole, { message: '角色必须是 admin、user 或 guest' })
  role?: UserRole;

  @ApiPropertyOptional({ description: '标签' })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })  // 数组中每个元素都是字符串
  @ArrayMinSize(1)
  @ArrayMaxSize(10)
  tags?: string[];

  @ApiPropertyOptional({ description: '地址' })
  @IsOptional()
  @ValidateNested()  // 验证嵌套对象
  @Type(() => AddressDto)
  address?: AddressDto;

  @ApiPropertyOptional({ description: '是否激活' })
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value === 'true' || value === true)
  isActive?: boolean;

  @ApiPropertyOptional({ description: '生日' })
  @IsOptional()
  @IsDate()
  @Type(() => Date)
  birthday?: Date;

  @ApiPropertyOptional({ description: '个人网站' })
  @IsOptional()
  @IsUrl({}, { message: '网站地址格式不正确' })
  website?: string;

  @ApiPropertyOptional({ description: '手机号' })
  @IsOptional()
  @IsPhoneNumber('CN', { message: '手机号格式不正确' })
  phone?: string;
}
```

```typescript
// src/modules/users/dto/update-user.dto.ts
import { PartialType, PickType, OmitType, IntersectionType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';

// PartialType - 所有字段变为可选
export class UpdateUserDto extends PartialType(CreateUserDto) {}

// PickType - 只选择部分字段
export class UpdateEmailDto extends PickType(CreateUserDto, ['email'] as const) {}

// OmitType - 排除部分字段
export class CreateUserWithoutPasswordDto extends OmitType(CreateUserDto, ['password'] as const) {}

// IntersectionType - 合并多个 DTO
export class ExtendedUserDto extends IntersectionType(CreateUserDto, AdditionalInfoDto) {}
```

### 7.3 自定义管道

```typescript
// src/common/pipes/parse-int.pipe.ts
import { PipeTransform, Injectable, ArgumentMetadata, BadRequestException } from '@nestjs/common';

@Injectable()
export class CustomParseIntPipe implements PipeTransform<string, number> {
  transform(value: string, metadata: ArgumentMetadata): number {
    const val = parseInt(value, 10);
    if (isNaN(val)) {
      throw new BadRequestException(`${metadata.data} must be a number`);
    }
    return val;
  }
}

// 自定义验证管道
@Injectable()
export class JoiValidationPipe implements PipeTransform {
  constructor(private schema: Joi.Schema) {}

  transform(value: any, metadata: ArgumentMetadata) {
    const { error } = this.schema.validate(value);
    if (error) {
      throw new BadRequestException('Validation failed: ' + error.message);
    }
    return value;
  }
}

// 使用
@Post()
@UsePipes(new JoiValidationPipe(createUserSchema))
create(@Body() createUserDto: CreateUserDto) {}
```

### 7.4 全局验证管道配置

```typescript
// main.ts
app.useGlobalPipes(
  new ValidationPipe({
    whitelist: true,              // 剥离非 DTO 定义的属性
    forbidNonWhitelisted: true,   // 非白名单属性抛出错误
    transform: true,              // 自动类型转换
    transformOptions: {
      enableImplicitConversion: true,  // 隐式类型转换
    },
    disableErrorMessages: false,  // 生产环境可设为 true
    validationError: {
      target: false,              // 不在错误中暴露目标对象
      value: false,               // 不在错误中暴露值
    },
    exceptionFactory: (errors) => {
      // 自定义错误格式
      const messages = errors.map(error => ({
        field: error.property,
        errors: Object.values(error.constraints || {}),
      }));
      return new BadRequestException({
        statusCode: 400,
        message: 'Validation failed',
        errors: messages,
      });
    },
  }),
);
```


---

## 8. 异常处理

Nest.js 提供了完善的异常处理机制，包括内置异常类和自定义异常过滤器。

### 8.1 内置异常

```typescript
import {
  BadRequestException,           // 400
  UnauthorizedException,         // 401
  ForbiddenException,            // 403
  NotFoundException,             // 404
  MethodNotAllowedException,     // 405
  NotAcceptableException,        // 406
  RequestTimeoutException,       // 408
  ConflictException,             // 409
  GoneException,                 // 410
  PayloadTooLargeException,      // 413
  UnsupportedMediaTypeException, // 415
  UnprocessableEntityException,  // 422
  InternalServerErrorException,  // 500
  NotImplementedException,       // 501
  BadGatewayException,           // 502
  ServiceUnavailableException,   // 503
  GatewayTimeoutException,       // 504
  HttpException,                 // 自定义状态码
} from '@nestjs/common';

@Injectable()
export class UsersService {
  findOne(id: number) {
    const user = this.users.find(u => u.id === id);
    if (!user) {
      // 简单用法
      throw new NotFoundException(`User #${id} not found`);
      
      // 带详细信息
      throw new NotFoundException({
        statusCode: 404,
        message: `User #${id} not found`,
        error: 'Not Found',
      });
    }
    return user;
  }

  create(createUserDto: CreateUserDto) {
    const exists = this.users.find(u => u.email === createUserDto.email);
    if (exists) {
      throw new ConflictException('Email already exists');
    }
    // ...
  }

  // 自定义状态码
  customError() {
    throw new HttpException('Custom error message', HttpStatus.FORBIDDEN);
    
    // 带详细响应
    throw new HttpException(
      {
        status: HttpStatus.FORBIDDEN,
        error: 'This is a custom message',
        details: { reason: 'Some reason' },
      },
      HttpStatus.FORBIDDEN,
    );
  }
}
```

### 8.2 自定义异常

```typescript
// src/common/exceptions/business.exception.ts
import { HttpException, HttpStatus } from '@nestjs/common';

// 业务异常基类
export class BusinessException extends HttpException {
  constructor(
    public readonly code: string,
    message: string,
    status: HttpStatus = HttpStatus.BAD_REQUEST,
  ) {
    super(
      {
        code,
        message,
        timestamp: new Date().toISOString(),
      },
      status,
    );
  }
}

// 具体业务异常
export class UserNotFoundException extends BusinessException {
  constructor(userId: number) {
    super('USER_NOT_FOUND', `User #${userId} not found`, HttpStatus.NOT_FOUND);
  }
}

export class EmailAlreadyExistsException extends BusinessException {
  constructor(email: string) {
    super('EMAIL_EXISTS', `Email ${email} already exists`, HttpStatus.CONFLICT);
  }
}

export class InsufficientBalanceException extends BusinessException {
  constructor() {
    super('INSUFFICIENT_BALANCE', 'Insufficient balance', HttpStatus.BAD_REQUEST);
  }
}
```

### 8.3 异常过滤器

```typescript
// src/common/filters/http-exception.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

// 捕获所有 HttpException
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message:
        typeof exceptionResponse === 'string'
          ? exceptionResponse
          : (exceptionResponse as any).message || 'Error',
      ...(typeof exceptionResponse === 'object' ? exceptionResponse : {}),
    };

    this.logger.error(
      `${request.method} ${request.url} ${status} - ${JSON.stringify(errorResponse)}`,
    );

    response.status(status).json(errorResponse);
  }
}

// 捕获所有异常（包括非 HTTP 异常）
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.message
        : 'Internal server error';

    this.logger.error(
      `${request.method} ${request.url}`,
      exception instanceof Error ? exception.stack : String(exception),
    );

    response.status(status).json({
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
    });
  }
}

// 捕获特定异常
@Catch(QueryFailedError)
export class QueryFailedExceptionFilter implements ExceptionFilter {
  catch(exception: QueryFailedError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    // 处理数据库唯一约束错误
    if (exception.message.includes('duplicate key')) {
      response.status(HttpStatus.CONFLICT).json({
        statusCode: HttpStatus.CONFLICT,
        message: 'Resource already exists',
      });
      return;
    }

    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'Database error',
    });
  }
}
```

```typescript
// 应用异常过滤器

// 1. 方法级别
@Get(':id')
@UseFilters(HttpExceptionFilter)
findOne(@Param('id') id: string) {}

// 2. 控制器级别
@Controller('users')
@UseFilters(HttpExceptionFilter)
export class UsersController {}

// 3. 全局级别（main.ts）
app.useGlobalFilters(new AllExceptionsFilter());

// 4. 全局级别（通过模块，支持依赖注入）
@Module({
  providers: [
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
  ],
})
export class AppModule {}
```


---

## 9. 守卫与认证

守卫用于实现权限控制，决定请求是否应该被处理。常用于身份验证和授权。

### 9.1 基础守卫

```typescript
// src/common/guards/auth.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Token not found');
    }

    // 验证 token
    try {
      const payload = this.validateToken(token);
      request.user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  private validateToken(token: string): any {
    // 实际项目中使用 JWT 验证
    return { userId: 1, username: 'john' };
  }
}
```

### 9.2 JWT 认证（Passport）

```bash
# 安装依赖
npm install @nestjs/passport passport passport-jwt @nestjs/jwt
npm install -D @types/passport-jwt
```

```typescript
// src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'your-secret-key',
      signOptions: { expiresIn: '1d' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, LocalStrategy],
  exports: [AuthService],
})
export class AuthModule {}
```

```typescript
// src/modules/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private usersService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key',
    });
  }

  async validate(payload: any) {
    const user = await this.usersService.findOne(payload.sub);
    if (!user) {
      throw new UnauthorizedException();
    }
    return { userId: payload.sub, username: payload.username, roles: payload.roles };
  }
}

// src/modules/auth/strategies/local.strategy.ts
import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',  // 使用 email 作为用户名字段
    });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authService.validateUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return user;
  }
}
```

```typescript
// src/modules/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);
    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.id, roles: user.roles };
    return {
      access_token: this.jwtService.sign(payload),
      refresh_token: this.jwtService.sign(payload, { expiresIn: '7d' }),
    };
  }

  async register(createUserDto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = await this.usersService.create({
      ...createUserDto,
      password: hashedPassword,
    });
    return this.login(user);
  }

  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken);
      const user = await this.usersService.findOne(payload.sub);
      return this.login(user);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
```

```typescript
// src/modules/auth/auth.controller.ts
import { Controller, Post, Body, UseGuards, Request, Get } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  @UseGuards(AuthGuard('local'))
  @Post('login')
  login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @Post('refresh')
  refreshToken(@Body('refresh_token') refreshToken: string) {
    return this.authService.refreshToken(refreshToken);
  }
}
```

### 9.3 角色守卫

```typescript
// src/common/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

// src/common/guards/roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some(role => user.roles?.includes(role));
  }
}

// 使用
@Controller('admin')
@UseGuards(AuthGuard('jwt'), RolesGuard)
export class AdminController {
  @Get('dashboard')
  @Roles('admin')
  getDashboard() {
    return 'Admin dashboard';
  }

  @Get('users')
  @Roles('admin', 'moderator')
  getUsers() {
    return 'User list';
  }
}
```

### 9.4 自定义装饰器

```typescript
// src/common/decorators/current-user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    return data ? user?.[data] : user;
  },
);

// 使用
@Get('profile')
@UseGuards(AuthGuard('jwt'))
getProfile(@CurrentUser() user: User) {
  return user;
}

@Get('profile')
@UseGuards(AuthGuard('jwt'))
getUsername(@CurrentUser('username') username: string) {
  return { username };
}

// 公开路由装饰器
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

// 在全局守卫中检查
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    return super.canActivate(context);
  }
}
```


---

## 10. 数据库集成

### 10.1 TypeORM 集成

```bash
# 安装依赖
npm install @nestjs/typeorm typeorm pg  # PostgreSQL
npm install @nestjs/typeorm typeorm mysql2  # MySQL
```

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'postgres',
      password: 'password',
      database: 'mydb',
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true,  // 开发环境使用，生产环境禁用
      logging: true,
    }),
  ],
})
export class AppModule {}

// 异步配置
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DB_HOST'),
        port: configService.get('DB_PORT'),
        username: configService.get('DB_USER'),
        password: configService.get('DB_PASS'),
        database: configService.get('DB_NAME'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: configService.get('NODE_ENV') !== 'production',
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
```

```typescript
// src/modules/users/entities/user.entity.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  OneToMany,
  ManyToOne,
  ManyToMany,
  JoinTable,
  Index,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import * as bcrypt from 'bcrypt';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ length: 50, unique: true })
  @Index()
  username: string;

  @Column({ unique: true })
  @Index()
  email: string;

  @Column()
  @Exclude()  // 序列化时排除
  password: string;

  @Column({ nullable: true })
  avatar: string;

  @Column({ type: 'enum', enum: ['admin', 'user', 'guest'], default: 'user' })
  role: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date;  // 软删除

  // 一对多关系
  @OneToMany(() => Post, post => post.author)
  posts: Post[];

  // 多对多关系
  @ManyToMany(() => Role)
  @JoinTable({
    name: 'user_roles',
    joinColumn: { name: 'user_id' },
    inverseJoinColumn: { name: 'role_id' },
  })
  roles: Role[];

  // 钩子
  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (this.password) {
      this.password = await bcrypt.hash(this.password, 10);
    }
  }
}
```

```typescript
// src/modules/users/users.service.ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Like, Between, In } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  // 基础 CRUD
  async findAll(query: QueryUserDto) {
    const { page = 1, limit = 10, search, role } = query;

    const queryBuilder = this.usersRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.posts', 'posts')
      .where('user.isActive = :isActive', { isActive: true });

    if (search) {
      queryBuilder.andWhere(
        '(user.username LIKE :search OR user.email LIKE :search)',
        { search: `%${search}%` },
      );
    }

    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }

    const [items, total] = await queryBuilder
      .skip((page - 1) * limit)
      .take(limit)
      .orderBy('user.createdAt', 'DESC')
      .getManyAndCount();

    return {
      items,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    };
  }

  async findOne(id: number) {
    const user = await this.usersRepository.findOne({
      where: { id },
      relations: ['posts', 'roles'],
    });
    if (!user) {
      throw new NotFoundException(`User #${id} not found`);
    }
    return user;
  }

  async findByEmail(email: string) {
    return this.usersRepository.findOne({ where: { email } });
  }

  async create(createUserDto: CreateUserDto) {
    const user = this.usersRepository.create(createUserDto);
    return this.usersRepository.save(user);
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    const user = await this.findOne(id);
    Object.assign(user, updateUserDto);
    return this.usersRepository.save(user);
  }

  async remove(id: number) {
    const user = await this.findOne(id);
    // 软删除
    return this.usersRepository.softRemove(user);
    // 硬删除
    // return this.usersRepository.remove(user);
  }

  // 事务
  async transferCredits(fromId: number, toId: number, amount: number) {
    return this.usersRepository.manager.transaction(async manager => {
      const fromUser = await manager.findOne(User, { where: { id: fromId } });
      const toUser = await manager.findOne(User, { where: { id: toId } });

      if (fromUser.credits < amount) {
        throw new Error('Insufficient credits');
      }

      fromUser.credits -= amount;
      toUser.credits += amount;

      await manager.save([fromUser, toUser]);
    });
  }
}
```

### 10.2 Prisma 集成

```bash
# 安装依赖
npm install prisma @prisma/client
npx prisma init
```

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  username  String   @unique
  password  String
  role      Role     @default(USER)
  isActive  Boolean  @default(true)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  posts     Post[]
  profile   Profile?

  @@index([email])
  @@map("users")
}

model Profile {
  id     Int     @id @default(autoincrement())
  bio    String?
  avatar String?
  userId Int     @unique
  user   User    @relation(fields: [userId], references: [id])

  @@map("profiles")
}

model Post {
  id        Int      @id @default(autoincrement())
  title     String
  content   String?
  published Boolean  @default(false)
  authorId  Int
  author    User     @relation(fields: [authorId], references: [id])
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@map("posts")
}

enum Role {
  USER
  ADMIN
}
```

```typescript
// src/prisma/prisma.service.ts
import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}

// src/modules/users/users.service.ts
@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findAll(params: {
    skip?: number;
    take?: number;
    where?: Prisma.UserWhereInput;
    orderBy?: Prisma.UserOrderByWithRelationInput;
  }) {
    const { skip, take, where, orderBy } = params;
    return this.prisma.user.findMany({
      skip,
      take,
      where,
      orderBy,
      include: { posts: true, profile: true },
    });
  }

  async findOne(id: number) {
    return this.prisma.user.findUnique({
      where: { id },
      include: { posts: true, profile: true },
    });
  }

  async create(data: Prisma.UserCreateInput) {
    return this.prisma.user.create({ data });
  }

  async update(id: number, data: Prisma.UserUpdateInput) {
    return this.prisma.user.update({
      where: { id },
      data,
    });
  }

  async remove(id: number) {
    return this.prisma.user.delete({ where: { id } });
  }

  // 事务
  async createUserWithProfile(userData: any, profileData: any) {
    return this.prisma.$transaction(async (prisma) => {
      const user = await prisma.user.create({ data: userData });
      const profile = await prisma.profile.create({
        data: { ...profileData, userId: user.id },
      });
      return { user, profile };
    });
  }
}
```

```bash
# Prisma 常用命令
npx prisma generate          # 生成客户端
npx prisma migrate dev       # 开发环境迁移
npx prisma migrate deploy    # 生产环境迁移
npx prisma db push           # 同步 schema（不生成迁移）
npx prisma studio            # 打开数据库管理界面
npx prisma db seed           # 运行种子数据
```


---

## 11. 配置管理

### 11.1 @nestjs/config

```bash
npm install @nestjs/config
```

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,              // 全局可用
      envFilePath: ['.env.local', '.env'],  // 环境文件
      expandVariables: true,       // 支持变量展开
      cache: true,                 // 缓存配置
      validationSchema: Joi.object({  // 验证
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
        PORT: Joi.number().default(3000),
        DATABASE_URL: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}
```

```typescript
// src/config/configuration.ts
export default () => ({
  port: parseInt(process.env.PORT, 10) || 3000,
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    username: process.env.DB_USER,
    password: process.env.DB_PASS,
    name: process.env.DB_NAME,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
  },
});

// app.module.ts
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
  ],
})
export class AppModule {}
```

```typescript
// 使用配置
@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {}

  getDatabaseConfig() {
    // 获取单个值
    const port = this.configService.get<number>('port');
    
    // 获取嵌套值
    const dbHost = this.configService.get<string>('database.host');
    
    // 带默认值
    const timeout = this.configService.get<number>('timeout', 5000);
    
    // 获取整个配置对象
    const dbConfig = this.configService.get('database');
    
    return dbConfig;
  }
}

// 在 main.ts 中使用
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get<number>('port');
  await app.listen(port);
}
```

### 11.2 命名空间配置

```typescript
// src/config/database.config.ts
import { registerAs } from '@nestjs/config';

export default registerAs('database', () => ({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  username: process.env.DB_USER,
  password: process.env.DB_PASS,
  name: process.env.DB_NAME,
}));

// src/config/jwt.config.ts
export default registerAs('jwt', () => ({
  secret: process.env.JWT_SECRET,
  expiresIn: process.env.JWT_EXPIRES_IN || '1d',
}));

// app.module.ts
import databaseConfig from './config/database.config';
import jwtConfig from './config/jwt.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, jwtConfig],
    }),
  ],
})
export class AppModule {}

// 使用
@Injectable()
export class DatabaseService {
  constructor(
    @Inject(databaseConfig.KEY)
    private dbConfig: ConfigType<typeof databaseConfig>,
  ) {
    console.log(this.dbConfig.host);  // 类型安全
  }
}
```

### 11.3 环境文件示例

```env
# .env
NODE_ENV=development
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASS=password
DB_NAME=mydb

# JWT
JWT_SECRET=your-super-secret-key
JWT_EXPIRES_IN=1d

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# AWS
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx
AWS_REGION=us-east-1
AWS_S3_BUCKET=my-bucket
```


---

## 12. 文件上传

### 12.1 基础文件上传

```bash
npm install @nestjs/platform-express multer
npm install -D @types/multer
```

```typescript
// src/modules/upload/upload.controller.ts
import {
  Controller,
  Post,
  UseInterceptors,
  UploadedFile,
  UploadedFiles,
  ParseFilePipe,
  MaxFileSizeValidator,
  FileTypeValidator,
  BadRequestException,
} from '@nestjs/common';
import { FileInterceptor, FilesInterceptor, FileFieldsInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';

@Controller('upload')
export class UploadController {
  // 单文件上传
  @Post('single')
  @UseInterceptors(FileInterceptor('file'))
  uploadSingle(@UploadedFile() file: Express.Multer.File) {
    return {
      originalName: file.originalname,
      filename: file.filename,
      size: file.size,
      mimetype: file.mimetype,
    };
  }

  // 带验证的文件上传
  @Post('validated')
  @UseInterceptors(FileInterceptor('file'))
  uploadValidated(
    @UploadedFile(
      new ParseFilePipe({
        validators: [
          new MaxFileSizeValidator({ maxSize: 5 * 1024 * 1024 }),  // 5MB
          new FileTypeValidator({ fileType: /(jpg|jpeg|png|gif)$/ }),
        ],
      }),
    )
    file: Express.Multer.File,
  ) {
    return { filename: file.filename };
  }

  // 多文件上传（同一字段）
  @Post('multiple')
  @UseInterceptors(FilesInterceptor('files', 10))  // 最多 10 个文件
  uploadMultiple(@UploadedFiles() files: Express.Multer.File[]) {
    return files.map(file => ({
      originalName: file.originalname,
      filename: file.filename,
    }));
  }

  // 多字段文件上传
  @Post('fields')
  @UseInterceptors(
    FileFieldsInterceptor([
      { name: 'avatar', maxCount: 1 },
      { name: 'documents', maxCount: 5 },
    ]),
  )
  uploadFields(
    @UploadedFiles()
    files: {
      avatar?: Express.Multer.File[];
      documents?: Express.Multer.File[];
    },
  ) {
    return {
      avatar: files.avatar?.[0]?.filename,
      documents: files.documents?.map(f => f.filename),
    };
  }
}
```

```typescript
// src/modules/upload/upload.module.ts
import { Module } from '@nestjs/common';
import { MulterModule } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { v4 as uuid } from 'uuid';

@Module({
  imports: [
    MulterModule.register({
      storage: diskStorage({
        destination: './uploads',
        filename: (req, file, callback) => {
          const uniqueName = `${uuid()}${extname(file.originalname)}`;
          callback(null, uniqueName);
        },
      }),
      limits: {
        fileSize: 10 * 1024 * 1024,  // 10MB
      },
      fileFilter: (req, file, callback) => {
        if (!file.mimetype.match(/\/(jpg|jpeg|png|gif|pdf)$/)) {
          return callback(new BadRequestException('Unsupported file type'), false);
        }
        callback(null, true);
      },
    }),
  ],
  controllers: [UploadController],
})
export class UploadModule {}
```

### 12.2 云存储（AWS S3）

```bash
npm install @aws-sdk/client-s3 @aws-sdk/s3-request-presigner
```

```typescript
// src/modules/upload/s3.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuid } from 'uuid';

@Injectable()
export class S3Service {
  private s3Client: S3Client;
  private bucket: string;

  constructor(private configService: ConfigService) {
    this.s3Client = new S3Client({
      region: this.configService.get('AWS_REGION'),
      credentials: {
        accessKeyId: this.configService.get('AWS_ACCESS_KEY_ID'),
        secretAccessKey: this.configService.get('AWS_SECRET_ACCESS_KEY'),
      },
    });
    this.bucket = this.configService.get('AWS_S3_BUCKET');
  }

  async uploadFile(file: Express.Multer.File, folder: string = 'uploads') {
    const key = `${folder}/${uuid()}-${file.originalname}`;

    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: file.buffer,
        ContentType: file.mimetype,
      }),
    );

    return {
      key,
      url: `https://${this.bucket}.s3.amazonaws.com/${key}`,
    };
  }

  async getSignedUrl(key: string, expiresIn: number = 3600) {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });
    return getSignedUrl(this.s3Client, command, { expiresIn });
  }

  async deleteFile(key: string) {
    await this.s3Client.send(
      new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: key,
      }),
    );
  }
}
```


---

## 13. WebSocket

### 13.1 基础 WebSocket

```bash
npm install @nestjs/websockets @nestjs/platform-socket.io socket.io
```

```typescript
// src/modules/chat/chat.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayInit,
  OnGatewayConnection,
  OnGatewayDisconnect,
  WsException,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger, UseGuards, UsePipes, ValidationPipe } from '@nestjs/common';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
  namespace: '/chat',
})
export class ChatGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server: Server;

  private logger = new Logger('ChatGateway');

  afterInit(server: Server) {
    this.logger.log('WebSocket Gateway initialized');
  }

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  // 处理消息
  @SubscribeMessage('message')
  handleMessage(
    @MessageBody() data: { room: string; message: string },
    @ConnectedSocket() client: Socket,
  ) {
    // 广播到房间
    this.server.to(data.room).emit('message', {
      sender: client.id,
      message: data.message,
      timestamp: new Date(),
    });

    return { event: 'message', data: 'Message sent' };
  }

  // 加入房间
  @SubscribeMessage('joinRoom')
  handleJoinRoom(
    @MessageBody() room: string,
    @ConnectedSocket() client: Socket,
  ) {
    client.join(room);
    this.server.to(room).emit('userJoined', {
      userId: client.id,
      room,
    });
    return { event: 'joinRoom', data: `Joined room: ${room}` };
  }

  // 离开房间
  @SubscribeMessage('leaveRoom')
  handleLeaveRoom(
    @MessageBody() room: string,
    @ConnectedSocket() client: Socket,
  ) {
    client.leave(room);
    this.server.to(room).emit('userLeft', {
      userId: client.id,
      room,
    });
  }

  // 私聊
  @SubscribeMessage('privateMessage')
  handlePrivateMessage(
    @MessageBody() data: { to: string; message: string },
    @ConnectedSocket() client: Socket,
  ) {
    this.server.to(data.to).emit('privateMessage', {
      from: client.id,
      message: data.message,
    });
  }

  // 广播给所有客户端
  broadcastToAll(event: string, data: any) {
    this.server.emit(event, data);
  }
}
```

### 13.2 WebSocket 认证

```typescript
// src/common/guards/ws-auth.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { WsException } from '@nestjs/websockets';
import { JwtService } from '@nestjs/jwt';
import { Socket } from 'socket.io';

@Injectable()
export class WsAuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient();
    const token = client.handshake.auth.token || client.handshake.headers.authorization?.split(' ')[1];

    if (!token) {
      throw new WsException('Unauthorized');
    }

    try {
      const payload = this.jwtService.verify(token);
      client.data.user = payload;
      return true;
    } catch {
      throw new WsException('Invalid token');
    }
  }
}

// 使用守卫
@WebSocketGateway()
@UseGuards(WsAuthGuard)
export class ChatGateway {
  @SubscribeMessage('message')
  handleMessage(
    @MessageBody() data: any,
    @ConnectedSocket() client: Socket,
  ) {
    const user = client.data.user;  // 获取认证用户
    // ...
  }
}
```

```typescript
// 客户端连接示例
import { io } from 'socket.io-client';

const socket = io('http://localhost:3000/chat', {
  auth: {
    token: 'your-jwt-token',
  },
});

socket.on('connect', () => {
  console.log('Connected');
  socket.emit('joinRoom', 'general');
});

socket.on('message', (data) => {
  console.log('Received:', data);
});

socket.emit('message', { room: 'general', message: 'Hello!' });
```


---

## 14. 微服务

Nest.js 原生支持微服务架构，提供多种传输层选项。

### 14.1 TCP 微服务

```typescript
// 微服务端 (user-service)
// main.ts
import { NestFactory } from '@nestjs/core';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    {
      transport: Transport.TCP,
      options: {
        host: '127.0.0.1',
        port: 3001,
      },
    },
  );
  await app.listen();
  console.log('User microservice is running on port 3001');
}
bootstrap();

// user.controller.ts
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload, EventPattern } from '@nestjs/microservices';

@Controller()
export class UserController {
  // 请求-响应模式
  @MessagePattern({ cmd: 'get_user' })
  getUser(@Payload() data: { id: number }) {
    return { id: data.id, name: 'John', email: 'john@example.com' };
  }

  @MessagePattern({ cmd: 'get_users' })
  getUsers() {
    return [
      { id: 1, name: 'John' },
      { id: 2, name: 'Jane' },
    ];
  }

  // 事件模式（不需要响应）
  @EventPattern('user_created')
  handleUserCreated(@Payload() data: any) {
    console.log('User created:', data);
    // 处理事件，不返回响应
  }
}
```

```typescript
// API 网关 (gateway)
// app.module.ts
import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: 'USER_SERVICE',
        transport: Transport.TCP,
        options: {
          host: '127.0.0.1',
          port: 3001,
        },
      },
    ]),
  ],
})
export class AppModule {}

// gateway.controller.ts
import { Controller, Get, Param, Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';

@Controller('users')
export class GatewayController {
  constructor(
    @Inject('USER_SERVICE') private userClient: ClientProxy,
  ) {}

  @Get()
  async getUsers() {
    // 发送请求并等待响应
    return firstValueFrom(
      this.userClient.send({ cmd: 'get_users' }, {}),
    );
  }

  @Get(':id')
  async getUser(@Param('id') id: string) {
    return firstValueFrom(
      this.userClient.send({ cmd: 'get_user' }, { id: +id }),
    );
  }

  @Post()
  async createUser(@Body() createUserDto: CreateUserDto) {
    const user = await this.userService.create(createUserDto);
    // 发送事件（不等待响应）
    this.userClient.emit('user_created', user);
    return user;
  }
}
```

### 14.2 Redis 微服务

```typescript
// 微服务配置
const app = await NestFactory.createMicroservice<MicroserviceOptions>(
  AppModule,
  {
    transport: Transport.REDIS,
    options: {
      host: 'localhost',
      port: 6379,
    },
  },
);

// 客户端配置
ClientsModule.register([
  {
    name: 'REDIS_SERVICE',
    transport: Transport.REDIS,
    options: {
      host: 'localhost',
      port: 6379,
    },
  },
]),
```

### 14.3 RabbitMQ 微服务

```bash
npm install amqplib amqp-connection-manager
```

```typescript
// 微服务配置
const app = await NestFactory.createMicroservice<MicroserviceOptions>(
  AppModule,
  {
    transport: Transport.RMQ,
    options: {
      urls: ['amqp://localhost:5672'],
      queue: 'users_queue',
      queueOptions: {
        durable: true,
      },
    },
  },
);

// 客户端配置
ClientsModule.register([
  {
    name: 'RABBITMQ_SERVICE',
    transport: Transport.RMQ,
    options: {
      urls: ['amqp://localhost:5672'],
      queue: 'users_queue',
      queueOptions: {
        durable: true,
      },
    },
  },
]),
```

### 14.4 混合应用（HTTP + 微服务）

```typescript
// main.ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 连接微服务
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.TCP,
    options: { port: 3001 },
  });

  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.REDIS,
    options: { host: 'localhost', port: 6379 },
  });

  // 启动所有微服务
  await app.startAllMicroservices();

  // 启动 HTTP 服务
  await app.listen(3000);
}
```


---

## 15. 测试

### 15.1 单元测试

```typescript
// src/modules/users/users.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { NotFoundException } from '@nestjs/common';

describe('UsersService', () => {
  let service: UsersService;
  let repository: Repository<User>;

  const mockUser = {
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
  };

  const mockRepository = {
    find: jest.fn(),
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    repository = module.get<Repository<User>>(getRepositoryToken(User));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findAll', () => {
    it('should return an array of users', async () => {
      mockRepository.find.mockResolvedValue([mockUser]);

      const result = await service.findAll();

      expect(result).toEqual([mockUser]);
      expect(mockRepository.find).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a user', async () => {
      mockRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.findOne(1);

      expect(result).toEqual(mockUser);
      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { id: 1 },
      });
    });

    it('should throw NotFoundException if user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      await expect(service.findOne(999)).rejects.toThrow(NotFoundException);
    });
  });

  describe('create', () => {
    it('should create a user', async () => {
      const createUserDto = { username: 'newuser', email: 'new@example.com', password: 'password' };
      mockRepository.create.mockReturnValue(mockUser);
      mockRepository.save.mockResolvedValue(mockUser);

      const result = await service.create(createUserDto);

      expect(result).toEqual(mockUser);
      expect(mockRepository.create).toHaveBeenCalledWith(createUserDto);
      expect(mockRepository.save).toHaveBeenCalled();
    });
  });
});
```

### 15.2 控制器测试

```typescript
// src/modules/users/users.controller.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

describe('UsersController', () => {
  let controller: UsersController;
  let service: UsersService;

  const mockUser = {
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
  };

  const mockUsersService = {
    findAll: jest.fn().mockResolvedValue([mockUser]),
    findOne: jest.fn().mockResolvedValue(mockUser),
    create: jest.fn().mockResolvedValue(mockUser),
    update: jest.fn().mockResolvedValue(mockUser),
    remove: jest.fn().mockResolvedValue(undefined),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
    service = module.get<UsersService>(UsersService);
  });

  describe('findAll', () => {
    it('should return an array of users', async () => {
      const result = await controller.findAll();
      expect(result).toEqual([mockUser]);
      expect(service.findAll).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a user', async () => {
      const result = await controller.findOne('1');
      expect(result).toEqual(mockUser);
      expect(service.findOne).toHaveBeenCalledWith(1);
    });
  });

  describe('create', () => {
    it('should create a user', async () => {
      const createUserDto = { username: 'newuser', email: 'new@example.com', password: 'password' };
      const result = await controller.create(createUserDto);
      expect(result).toEqual(mockUser);
      expect(service.create).toHaveBeenCalledWith(createUserDto);
    });
  });
});
```

### 15.3 E2E 测试

```typescript
// test/users.e2e-spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('UsersController (e2e)', () => {
  let app: INestApplication;
  let authToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();

    // 获取认证 token
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'test@example.com', password: 'password' });
    authToken = loginResponse.body.access_token;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('/users (GET)', () => {
    it('should return users', () => {
      return request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
        });
    });

    it('should return 401 without token', () => {
      return request(app.getHttpServer())
        .get('/users')
        .expect(401);
    });
  });

  describe('/users (POST)', () => {
    it('should create a user', () => {
      return request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          username: 'newuser',
          email: 'newuser@example.com',
          password: 'Password123',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body.username).toBe('newuser');
          expect(res.body.email).toBe('newuser@example.com');
        });
    });

    it('should return 400 for invalid data', () => {
      return request(app.getHttpServer())
        .post('/users')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          username: 'ab',  // 太短
          email: 'invalid-email',
        })
        .expect(400);
    });
  });

  describe('/users/:id (GET)', () => {
    it('should return a user', () => {
      return request(app.getHttpServer())
        .get('/users/1')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.id).toBe(1);
        });
    });

    it('should return 404 for non-existent user', () => {
      return request(app.getHttpServer())
        .get('/users/99999')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });
});
```

```bash
# 运行测试
npm run test              # 单元测试
npm run test:watch        # 监听模式
npm run test:cov          # 覆盖率报告
npm run test:e2e          # E2E 测试
```


---

## 16. 常见错误与解决方案

### 16.1 依赖注入错误

```typescript
// ❌ 错误：Nest can't resolve dependencies of the XXXService
// 原因：依赖未正确注入或模块未导入

// 错误示例
@Injectable()
export class UsersService {
  constructor(private postsService: PostsService) {}  // PostsService 未导入
}

// ✅ 解决方案 1：在模块中导入
@Module({
  imports: [PostsModule],  // 导入 PostsModule
  providers: [UsersService],
})
export class UsersModule {}

// ✅ 解决方案 2：确保 PostsModule 导出了 PostsService
@Module({
  providers: [PostsService],
  exports: [PostsService],  // 必须导出
})
export class PostsModule {}


// ❌ 错误：循环依赖
// Nest cannot create the XXX instance. The module at index [x] of the XXX "imports" array is undefined.

// ✅ 解决方案：使用 forwardRef
@Module({
  imports: [forwardRef(() => PostsModule)],
})
export class UsersModule {}

@Injectable()
export class UsersService {
  constructor(
    @Inject(forwardRef(() => PostsService))
    private postsService: PostsService,
  ) {}
}
```

### 16.2 验证错误

```typescript
// ❌ 错误：验证不生效
// 原因：未启用 ValidationPipe 或未安装依赖

// ✅ 解决方案 1：全局启用
// main.ts
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  transform: true,
}));

// ✅ 解决方案 2：确保安装了依赖
// npm install class-validator class-transformer


// ❌ 错误：类型转换不生效
// Query 参数始终是字符串

// ✅ 解决方案：启用隐式转换
app.useGlobalPipes(new ValidationPipe({
  transform: true,
  transformOptions: {
    enableImplicitConversion: true,
  },
}));

// 或使用 @Type 装饰器
@IsInt()
@Type(() => Number)
page: number;


// ❌ 错误：嵌套对象验证不生效
// ✅ 解决方案：使用 @ValidateNested 和 @Type
class CreateUserDto {
  @ValidateNested()
  @Type(() => AddressDto)
  address: AddressDto;
}
```

### 16.3 数据库错误

```typescript
// ❌ 错误：EntityMetadataNotFoundError: No metadata for "XXX" was found
// 原因：实体未注册

// ✅ 解决方案 1：在模块中注册
@Module({
  imports: [TypeOrmModule.forFeature([User, Post])],
})
export class UsersModule {}

// ✅ 解决方案 2：检查 entities 配置
TypeOrmModule.forRoot({
  entities: [__dirname + '/**/*.entity{.ts,.js}'],
  // 或
  autoLoadEntities: true,
})


// ❌ 错误：QueryFailedError: duplicate key value violates unique constraint
// 原因：违反唯一约束

// ✅ 解决方案：捕获并处理
async create(createUserDto: CreateUserDto) {
  try {
    return await this.usersRepository.save(createUserDto);
  } catch (error) {
    if (error.code === '23505') {  // PostgreSQL 唯一约束错误码
      throw new ConflictException('Email already exists');
    }
    throw error;
  }
}


// ❌ 错误：Cannot query across one-to-many for property XXX
// 原因：关系未正确加载

// ✅ 解决方案：使用 relations 或 QueryBuilder
// 方法 1
const user = await this.usersRepository.findOne({
  where: { id },
  relations: ['posts'],
});

// 方法 2
const user = await this.usersRepository
  .createQueryBuilder('user')
  .leftJoinAndSelect('user.posts', 'posts')
  .where('user.id = :id', { id })
  .getOne();
```

### 16.4 认证错误

```typescript
// ❌ 错误：Unauthorized - 401
// 原因：Token 无效或过期

// ✅ 解决方案：检查 JWT 配置
JwtModule.register({
  secret: process.env.JWT_SECRET,  // 确保 secret 一致
  signOptions: { expiresIn: '1d' },
})

// 检查 token 格式
// Authorization: Bearer <token>


// ❌ 错误：Cannot read property 'user' of undefined
// 原因：守卫未正确设置 user

// ✅ 解决方案：确保在 validate 方法中返回用户
async validate(payload: any) {
  const user = await this.usersService.findOne(payload.sub);
  if (!user) {
    throw new UnauthorizedException();
  }
  return user;  // 这个值会被设置到 request.user
}
```

### 16.5 性能问题

```typescript
// ❌ 问题：N+1 查询问题
// 原因：循环中查询关联数据

// ✅ 解决方案：使用 eager loading
const users = await this.usersRepository.find({
  relations: ['posts', 'profile'],
});

// 或使用 QueryBuilder
const users = await this.usersRepository
  .createQueryBuilder('user')
  .leftJoinAndSelect('user.posts', 'posts')
  .leftJoinAndSelect('user.profile', 'profile')
  .getMany();


// ❌ 问题：响应数据过大
// ✅ 解决方案：使用序列化排除敏感字段
import { Exclude, Expose } from 'class-transformer';

@Entity()
export class User {
  @Exclude()
  password: string;

  @Expose()
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }
}

// 在控制器中使用 ClassSerializerInterceptor
@UseInterceptors(ClassSerializerInterceptor)
@Get(':id')
findOne(@Param('id') id: string) {
  return this.usersService.findOne(+id);
}
```

### 16.6 其他常见错误

```typescript
// ❌ 错误：Cannot read properties of undefined (reading 'prototype')
// 原因：循环导入或导入顺序问题
// ✅ 解决方案：检查导入，使用 forwardRef


// ❌ 错误：Maximum call stack size exceeded
// 原因：无限递归，通常是序列化时的循环引用
// ✅ 解决方案：使用 @Exclude() 或自定义序列化
@Entity()
export class User {
  @OneToMany(() => Post, post => post.author)
  @Exclude()  // 排除以避免循环
  posts: Post[];
}


// ❌ 错误：CORS 错误
// ✅ 解决方案：正确配置 CORS
app.enableCors({
  origin: ['http://localhost:3000', 'https://yourdomain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  credentials: true,
});


// ❌ 错误：文件上传失败 - Unexpected field
// 原因：字段名不匹配
// ✅ 解决方案：确保前端字段名与 @FileInterceptor 参数一致
@UseInterceptors(FileInterceptor('file'))  // 字段名必须是 'file'
uploadFile(@UploadedFile() file: Express.Multer.File) {}

// 前端
formData.append('file', selectedFile);  // 必须是 'file'
```

---

## 附录：常用命令速查

```bash
# 项目管理
nest new project-name          # 创建项目
nest g resource users          # 生成完整 CRUD 资源
nest g module users            # 生成模块
nest g controller users        # 生成控制器
nest g service users           # 生成服务
nest g guard auth              # 生成守卫
nest g interceptor logging     # 生成拦截器
nest g pipe validation         # 生成管道
nest g filter http-exception   # 生成过滤器
nest g middleware logger       # 生成中间件

# 运行
npm run start                  # 启动
npm run start:dev              # 开发模式（热重载）
npm run start:debug            # 调试模式
npm run start:prod             # 生产模式

# 构建
npm run build                  # 构建项目

# 测试
npm run test                   # 单元测试
npm run test:watch             # 监听模式
npm run test:cov               # 覆盖率
npm run test:e2e               # E2E 测试

# 数据库（TypeORM）
npm run typeorm migration:generate -- -n MigrationName
npm run typeorm migration:run
npm run typeorm migration:revert

# 数据库（Prisma）
npx prisma generate            # 生成客户端
npx prisma migrate dev         # 开发迁移
npx prisma migrate deploy      # 生产迁移
npx prisma studio              # 数据库管理界面
```

---

> 本笔记涵盖了 Nest.js 从入门到进阶的核心知识点，建议结合官方文档和实际项目进行学习。
> 官方文档：https://docs.nestjs.com/
> 中文文档：https://docs.nestjs.cn/
