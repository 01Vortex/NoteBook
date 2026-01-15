> npm、pnpm、yarn 是 Node.js 生态中最主流的三大包管理工具
> 本笔记从基础到进阶，全面覆盖日常开发中的使用场景

---

## 目录

1. [基础概念](#1-基础概念)
2. [安装与配置](#2-安装与配置)
3. [包管理基础操作](#3-包管理基础操作)
4. [依赖类型详解](#4-依赖类型详解)
5. [版本管理](#5-版本管理)
6. [锁文件机制](#6-锁文件机制)
7. [脚本与生命周期](#7-脚本与生命周期)
8. [工作区（Monorepo）](#8-工作区monorepo)
9. [私有仓库与镜像源](#9-私有仓库与镜像源)
10. [缓存管理](#10-缓存管理)
11. [安全与审计](#11-安全与审计)
12. [性能对比与选型](#12-性能对比与选型)
13. [高级技巧](#13-高级技巧)
14. [常见错误与解决方案](#14-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是包管理器？

包管理器是用于自动化安装、升级、配置和移除软件包的工具。在 Node.js 生态中，包管理器负责：

- **依赖管理**：自动下载项目所需的第三方库
- **版本控制**：确保团队成员使用相同版本的依赖
- **脚本执行**：运行项目定义的各种命令（构建、测试、部署等）
- **发布管理**：将自己的包发布到公共或私有仓库

### 1.2 三大包管理器简介

| 特性 | npm | yarn | pnpm |
|------|-----|------|------|
| 发布时间 | 2010 | 2016 | 2017 |
| 开发者 | npm, Inc | Facebook | Zoltan Kochan |
| 默认安装 | Node.js 自带 | 需单独安装 | 需单独安装 |
| 存储方式 | 扁平化 node_modules | 扁平化 node_modules | 硬链接 + 符号链接 |
| 磁盘占用 | 较大 | 较大 | 最小 |
| 安装速度 | 一般 | 较快 | 最快 |

### 1.3 核心概念

#### package.json
`package.json` 是项目的"身份证"，记录了项目的元信息和依赖关系：

```json
{
  "name": "my-project",           // 项目名称（必须小写，可用连字符）
  "version": "1.0.0",             // 版本号（遵循 semver 规范）
  "description": "项目描述",
  "main": "index.js",             // 入口文件
  "scripts": {                    // 可执行脚本
    "start": "node index.js",
    "build": "webpack --mode production",
    "test": "jest"
  },
  "dependencies": {},             // 生产依赖
  "devDependencies": {},          // 开发依赖
  "peerDependencies": {},         // 同伴依赖
  "optionalDependencies": {},     // 可选依赖
  "engines": {                    // 运行环境要求
    "node": ">=16.0.0"
  },
  "license": "MIT"
}
```

#### node_modules
`node_modules` 是存放所有依赖包的目录。不同包管理器的存储策略不同：

- **npm/yarn**：扁平化结构，所有依赖尽可能提升到顶层
- **pnpm**：使用硬链接指向全局存储，节省磁盘空间

---

## 2. 安装与配置

### 2.1 npm 安装

npm 随 Node.js 一起安装，无需单独安装：

```bash
# 检查 npm 版本
npm -v

# 升级 npm 到最新版本
npm install -g npm@latest

# 查看 npm 配置
npm config list
```

### 2.2 yarn 安装

```bash
# 方式一：通过 npm 安装（推荐）
npm install -g yarn

# 方式二：通过 corepack 启用（Node.js 16.10+）
corepack enable
corepack prepare yarn@stable --activate

# 检查版本
yarn -v
```

> **Corepack 说明**：Corepack 是 Node.js 内置的包管理器管理工具，可以让你在不同项目中使用不同版本的 yarn/pnpm。

### 2.3 pnpm 安装

```bash
# 方式一：通过 npm 安装
npm install -g pnpm

# 方式二：通过 corepack 启用
corepack enable
corepack prepare pnpm@latest --activate

# 方式三：独立安装脚本（Windows PowerShell）
iwr https://get.pnpm.io/install.ps1 -useb | iex

# 方式四：独立安装脚本（Linux/macOS）
curl -fsSL https://get.pnpm.io/install.sh | sh -

# 检查版本
pnpm -v
```

### 2.4 配置文件

#### .npmrc 配置文件

`.npmrc` 文件用于配置包管理器的行为，可以放在以下位置：

- **项目级**：`项目根目录/.npmrc`（优先级最高）
- **用户级**：`~/.npmrc`
- **全局级**：`$PREFIX/etc/npmrc`

```ini
# .npmrc 示例配置

# 设置镜像源
registry=https://registry.npmmirror.com

# 设置特定 scope 的镜像源
@mycompany:registry=https://npm.mycompany.com

# 代理设置
proxy=http://proxy.company.com:8080
https-proxy=http://proxy.company.com:8080

# 忽略 SSL 证书错误（不推荐在生产环境使用）
strict-ssl=false

# 设置缓存目录
cache=/path/to/cache

# 安装时不生成 package-lock.json
package-lock=false

# 设置默认的 save-exact
save-exact=true
```

#### pnpm 特有配置

pnpm 除了支持 `.npmrc`，还有一些特有配置：

```ini
# .npmrc (pnpm 特有配置)

# 提升所有依赖到 node_modules 根目录（模拟 npm 行为）
shamefully-hoist=true

# 只提升特定包
public-hoist-pattern[]=*eslint*
public-hoist-pattern[]=*prettier*

# 严格模式：禁止访问未声明的依赖
strict-peer-dependencies=true

# 设置全局存储目录
store-dir=/path/to/pnpm-store
```

---

## 3. 包管理基础操作

### 3.1 初始化项目

```bash
# npm
npm init              # 交互式创建 package.json
npm init -y           # 使用默认值快速创建

# yarn
yarn init
yarn init -y

# pnpm
pnpm init
```

### 3.2 安装依赖

#### 安装所有依赖

```bash
# 根据 package.json 安装所有依赖
npm install           # 或 npm i
yarn install          # 或 yarn
pnpm install          # 或 pnpm i
```

#### 安装指定包

```bash
# 安装生产依赖
npm install lodash
yarn add lodash
pnpm add lodash

# 安装开发依赖
npm install -D typescript    # 或 --save-dev
yarn add -D typescript
pnpm add -D typescript

# 安装全局包
npm install -g nodemon
yarn global add nodemon
pnpm add -g nodemon

# 安装指定版本
npm install lodash@4.17.21
yarn add lodash@4.17.21
pnpm add lodash@4.17.21

# 安装最新版本
npm install lodash@latest
yarn add lodash@latest
pnpm add lodash@latest
```

### 3.3 卸载依赖

```bash
# 卸载包
npm uninstall lodash      # 或 npm remove, npm rm
yarn remove lodash
pnpm remove lodash        # 或 pnpm rm

# 卸载全局包
npm uninstall -g nodemon
yarn global remove nodemon
pnpm remove -g nodemon
```

### 3.4 更新依赖

```bash
# 查看过时的包
npm outdated
yarn outdated
pnpm outdated

# 更新所有包（在 semver 范围内）
npm update
yarn upgrade
pnpm update

# 更新指定包
npm update lodash
yarn upgrade lodash
pnpm update lodash

# 更新到最新版本（忽略 semver 范围）
npm install lodash@latest
yarn upgrade lodash --latest
pnpm update lodash --latest

# 交互式更新（推荐）
npx npm-check-updates -i   # npm
yarn upgrade-interactive   # yarn
pnpm update -i             # pnpm
```

### 3.5 查看包信息

```bash
# 查看已安装的包
npm list                  # 或 npm ls
yarn list
pnpm list                 # 或 pnpm ls

# 只查看顶层依赖
npm list --depth=0
yarn list --depth=0
pnpm list --depth=0

# 查看全局安装的包
npm list -g --depth=0
yarn global list
pnpm list -g

# 查看包的详细信息
npm info lodash
yarn info lodash
pnpm info lodash

# 查看包的所有版本
npm view lodash versions
yarn info lodash versions
pnpm view lodash versions
```

### 3.6 执行脚本

```bash
# 执行 package.json 中定义的脚本
npm run build
yarn build              # yarn 可以省略 run
pnpm build              # pnpm 也可以省略 run

# 执行 start 脚本（特殊，可省略 run）
npm start
yarn start
pnpm start

# 执行 test 脚本
npm test                # 或 npm t
yarn test
pnpm test

# 传递参数给脚本
npm run build -- --watch
yarn build --watch
pnpm build --watch
```

---

## 4. 依赖类型详解

### 4.1 dependencies（生产依赖）

项目运行时必需的依赖，会被打包到最终产物中：

```bash
npm install express
yarn add express
pnpm add express
```

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}
```

**适用场景**：
- Web 框架（express, koa, fastify）
- 工具库（lodash, axios, dayjs）
- UI 组件库（antd, element-plus）

### 4.2 devDependencies（开发依赖）

仅在开发阶段需要的依赖，不会被打包到生产环境：

```bash
npm install -D typescript
yarn add -D typescript
pnpm add -D typescript
```

```json
{
  "devDependencies": {
    "typescript": "^5.0.0",
    "eslint": "^8.0.0",
    "jest": "^29.0.0",
    "webpack": "^5.0.0"
  }
}
```

**适用场景**：
- 构建工具（webpack, vite, rollup）
- 编译器（typescript, babel）
- 测试框架（jest, vitest, mocha）
- 代码检查（eslint, prettier）

### 4.3 peerDependencies（同伴依赖）

声明当前包需要宿主环境提供的依赖，常用于插件开发：

```json
{
  "name": "eslint-plugin-my-rules",
  "peerDependencies": {
    "eslint": ">=7.0.0"
  }
}
```

**工作原理**：
- npm 7+ 会自动安装 peerDependencies
- 如果版本冲突，会给出警告
- 插件不会自己安装 eslint，而是使用项目中已有的 eslint

**适用场景**：
- ESLint/Prettier 插件
- Babel 插件
- Webpack loader/plugin
- React/Vue 组件库

### 4.4 optionalDependencies（可选依赖）

安装失败不会导致整体安装失败的依赖：

```json
{
  "optionalDependencies": {
    "fsevents": "^2.3.2"
  }
}
```

**适用场景**：
- 平台特定的依赖（如 fsevents 只在 macOS 上有效）
- 性能优化包（有则更好，没有也能运行）

### 4.5 bundledDependencies（打包依赖）

在发布包时一起打包的依赖：

```json
{
  "bundledDependencies": [
    "internal-package"
  ]
}
```

**适用场景**：
- 私有包不想发布到 npm
- 确保特定版本的依赖被包含

---

## 5. 版本管理

### 5.1 语义化版本（Semver）

版本号格式：`主版本.次版本.修订版本`（MAJOR.MINOR.PATCH）

```
1.2.3
│ │ │
│ │ └── PATCH: 向后兼容的 bug 修复
│ └──── MINOR: 向后兼容的新功能
└────── MAJOR: 不兼容的 API 变更
```

**预发布版本**：
- `1.0.0-alpha.1`：内部测试版
- `1.0.0-beta.1`：公开测试版
- `1.0.0-rc.1`：发布候选版

### 5.2 版本范围符号

```json
{
  "dependencies": {
    // 精确版本
    "lodash": "4.17.21",
    
    // 波浪号：允许修订版本更新
    "express": "~4.18.2",    // >=4.18.2 <4.19.0
    
    // 插入号：允许次版本更新（默认）
    "axios": "^1.4.0",       // >=1.4.0 <2.0.0
    
    // 大于等于
    "node": ">=16.0.0",
    
    // 范围
    "react": ">=17.0.0 <19.0.0",
    
    // 或
    "typescript": "^4.0.0 || ^5.0.0",
    
    // 任意版本
    "debug": "*",
    
    // x 占位符
    "chalk": "5.x",          // >=5.0.0 <6.0.0
    
    // 最新版本
    "vite": "latest"
  }
}
```

### 5.3 版本锁定策略

| 符号 | 示例 | 含义 | 风险等级 |
|------|------|------|----------|
| 无符号 | `4.17.21` | 精确版本 | 最低 |
| `~` | `~4.17.21` | 允许 patch 更新 | 低 |
| `^` | `^4.17.21` | 允许 minor 更新 | 中 |
| `*` | `*` | 任意版本 | 最高 |

**最佳实践**：
- 生产项目使用 `^` 或精确版本
- 始终提交锁文件（package-lock.json / yarn.lock / pnpm-lock.yaml）
- 定期更新依赖并测试

---

## 6. 锁文件机制

### 6.1 锁文件的作用

锁文件记录了依赖树的精确版本，确保团队成员和 CI/CD 环境安装完全相同的依赖：

| 包管理器 | 锁文件名 |
|----------|----------|
| npm | package-lock.json |
| yarn | yarn.lock |
| pnpm | pnpm-lock.yaml |

### 6.2 锁文件示例

**package-lock.json (npm)**：
```json
{
  "name": "my-project",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    }
  }
}
```

**pnpm-lock.yaml (pnpm)**：
```yaml
lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-v2kDE...}
    dev: false
```

### 6.3 锁文件最佳实践

```bash
# ✅ 正确做法
git add package-lock.json   # 始终提交锁文件
npm ci                      # CI 环境使用 ci 命令（更快、更严格）

# ❌ 错误做法
echo "package-lock.json" >> .gitignore  # 不要忽略锁文件
```

**npm ci vs npm install**：

| 特性 | npm install | npm ci |
|------|-------------|--------|
| 读取 | package.json | package-lock.json |
| 更新锁文件 | 可能更新 | 不更新 |
| node_modules | 增量更新 | 删除后重装 |
| 速度 | 较慢 | 较快 |
| 适用场景 | 开发环境 | CI/CD 环境 |

```bash
# yarn 等效命令
yarn install --frozen-lockfile

# pnpm 等效命令
pnpm install --frozen-lockfile
```

---

## 7. 脚本与生命周期

### 7.1 npm scripts

在 `package.json` 的 `scripts` 字段定义可执行命令：

```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "build": "webpack --mode production",
    "test": "jest",
    "lint": "eslint src/",
    "lint:fix": "eslint src/ --fix",
    "format": "prettier --write .",
    "prepare": "husky install"
  }
}
```

### 7.2 生命周期钩子

npm 提供了一系列生命周期钩子，在特定时机自动执行：

```json
{
  "scripts": {
    // 安装前后
    "preinstall": "echo '安装前执行'",
    "install": "echo '安装时执行'",
    "postinstall": "echo '安装后执行'",
    
    // 发布前后
    "prepublishOnly": "npm run build",
    "prepublish": "echo '发布前执行'",
    "postpublish": "echo '发布后执行'",
    
    // 自定义脚本的前后钩子
    "prebuild": "rimraf dist",
    "build": "webpack",
    "postbuild": "echo '构建完成'",
    
    // 特殊钩子
    "prepare": "husky install"  // install 后、publish 前执行
  }
}
```

**执行顺序示例**：
```bash
npm run build
# 1. prebuild
# 2. build
# 3. postbuild
```

### 7.3 脚本技巧

#### 串行执行
```json
{
  "scripts": {
    "build": "npm run clean && npm run compile && npm run bundle"
  }
}
```

#### 并行执行
```json
{
  "scripts": {
    // 使用 npm-run-all
    "dev": "npm-run-all --parallel dev:*",
    "dev:server": "nodemon server.js",
    "dev:client": "vite",
    
    // 使用 concurrently
    "start": "concurrently \"npm run server\" \"npm run client\""
  }
}
```

#### 跨平台兼容
```json
{
  "scripts": {
    // ❌ 不跨平台
    "clean": "rm -rf dist",
    
    // ✅ 使用 rimraf（跨平台）
    "clean": "rimraf dist",
    
    // ✅ 使用 cross-env 设置环境变量
    "build": "cross-env NODE_ENV=production webpack"
  }
}
```

#### 传递参数
```bash
# 传递参数给脚本
npm run test -- --coverage
yarn test --coverage
pnpm test --coverage
```

---

## 8. 工作区（Monorepo）

### 8.1 什么是 Monorepo？

Monorepo 是将多个项目放在同一个代码仓库中管理的策略。包管理器的工作区功能可以：

- 在一个仓库中管理多个包
- 共享依赖，减少重复安装
- 方便包之间的相互引用

### 8.2 npm workspaces

**目录结构**：
```
my-monorepo/
├── package.json
├── packages/
│   ├── core/
│   │   └── package.json
│   ├── utils/
│   │   └── package.json
│   └── cli/
│       └── package.json
```

**根目录 package.json**：
```json
{
  "name": "my-monorepo",
  "private": true,
  "workspaces": [
    "packages/*"
  ]
}
```

**常用命令**：
```bash
# 安装所有工作区的依赖
npm install

# 在指定工作区执行命令
npm run build -w packages/core
npm run build --workspace=packages/core

# 在所有工作区执行命令
npm run build --workspaces
npm run build -ws

# 为指定工作区添加依赖
npm install lodash -w packages/core

# 工作区之间相互引用
npm install @my-monorepo/utils -w packages/core
```

### 8.3 yarn workspaces

**配置方式**：
```json
{
  "name": "my-monorepo",
  "private": true,
  "workspaces": [
    "packages/*",
    "apps/*"
  ]
}
```

**常用命令**：
```bash
# 安装所有依赖
yarn install

# 在指定工作区执行命令
yarn workspace @my-monorepo/core build

# 在所有工作区执行命令
yarn workspaces run build

# 为指定工作区添加依赖
yarn workspace @my-monorepo/core add lodash

# 查看工作区信息
yarn workspaces info
```

### 8.4 pnpm workspaces

pnpm 使用 `pnpm-workspace.yaml` 配置工作区：

**pnpm-workspace.yaml**：
```yaml
packages:
  - 'packages/*'
  - 'apps/*'
  - '!**/test/**'  # 排除 test 目录
```

**常用命令**：
```bash
# 安装所有依赖
pnpm install

# 在指定工作区执行命令
pnpm --filter @my-monorepo/core build
pnpm -F @my-monorepo/core build

# 在所有工作区执行命令
pnpm -r build
pnpm --recursive build

# 为指定工作区添加依赖
pnpm --filter @my-monorepo/core add lodash

# 过滤器高级用法
pnpm --filter "./packages/**" build    # 匹配路径
pnpm --filter "...@my-monorepo/core"   # 包含依赖
pnpm --filter "@my-monorepo/core..."   # 包含被依赖者
```

### 8.5 工作区内部引用

在 Monorepo 中，包之间可以相互引用：

```json
// packages/cli/package.json
{
  "name": "@my-monorepo/cli",
  "dependencies": {
    "@my-monorepo/core": "workspace:*",    // pnpm 语法
    "@my-monorepo/utils": "workspace:^"    // 发布时转换为实际版本
  }
}
```

**workspace 协议（pnpm）**：
- `workspace:*`：任意版本，发布时替换为实际版本
- `workspace:^`：发布时替换为 `^x.x.x`
- `workspace:~`：发布时替换为 `~x.x.x`

---

## 9. 私有仓库与镜像源

### 9.1 配置镜像源

由于网络原因，国内访问 npm 官方源较慢，可以使用镜像源：

```bash
# 查看当前源
npm config get registry

# 设置淘宝镜像源
npm config set registry https://registry.npmmirror.com
yarn config set registry https://registry.npmmirror.com
pnpm config set registry https://registry.npmmirror.com

# 恢复官方源
npm config set registry https://registry.npmjs.org

# 临时使用指定源
npm install lodash --registry https://registry.npmmirror.com
```

### 9.2 使用 nrm 管理源

```bash
# 安装 nrm
npm install -g nrm

# 查看可用源
nrm ls

# 切换源
nrm use taobao
nrm use npm

# 添加自定义源
nrm add company https://npm.company.com

# 测试源速度
nrm test
```

### 9.3 私有仓库配置

#### 使用 .npmrc 配置

```ini
# .npmrc

# 默认源
registry=https://registry.npmmirror.com

# 特定 scope 使用私有源
@mycompany:registry=https://npm.mycompany.com

# 私有源认证
//npm.mycompany.com/:_authToken=${NPM_TOKEN}
//npm.mycompany.com/:always-auth=true
```

#### 使用 Verdaccio 搭建私有仓库

```bash
# 安装 Verdaccio
npm install -g verdaccio

# 启动服务
verdaccio

# 配置客户端使用私有仓库
npm set registry http://localhost:4873

# 发布包到私有仓库
npm publish --registry http://localhost:4873
```

### 9.4 发布包到 npm

```bash
# 登录 npm
npm login

# 查看当前登录用户
npm whoami

# 发布包
npm publish

# 发布 scoped 包（公开）
npm publish --access public

# 发布 beta 版本
npm publish --tag beta

# 撤销发布（24小时内）
npm unpublish package-name@1.0.0

# 废弃版本（推荐替代 unpublish）
npm deprecate package-name@1.0.0 "此版本有严重 bug，请升级"
```

---

## 10. 缓存管理

### 10.1 npm 缓存

```bash
# 查看缓存目录
npm config get cache

# 查看缓存内容
npm cache ls

# 清理缓存
npm cache clean --force

# 验证缓存完整性
npm cache verify
```

### 10.2 yarn 缓存

```bash
# 查看缓存目录
yarn cache dir

# 查看缓存列表
yarn cache list

# 清理缓存
yarn cache clean

# 清理指定包的缓存
yarn cache clean lodash
```

### 10.3 pnpm 缓存与存储

pnpm 使用全局存储（store）来节省磁盘空间：

```bash
# 查看存储目录
pnpm store path

# 查看存储状态
pnpm store status

# 清理未被引用的包
pnpm store prune

# 从存储中删除指定包
pnpm store remove lodash
```

**pnpm 存储原理**：
1. 所有包都下载到全局存储目录
2. 项目的 node_modules 通过硬链接指向存储
3. 多个项目共享同一份包文件，大幅节省磁盘空间

---

## 11. 安全与审计

### 11.1 安全审计

```bash
# 检查依赖中的安全漏洞
npm audit
yarn audit
pnpm audit

# 查看详细报告
npm audit --json

# 只检查生产依赖
npm audit --production
```

### 11.2 修复漏洞

```bash
# 自动修复漏洞
npm audit fix

# 强制修复（可能有破坏性更新）
npm audit fix --force

# 只更新 package-lock.json
npm audit fix --package-lock-only
```

### 11.3 安全最佳实践

```bash
# 1. 定期更新依赖
npm outdated
npm update

# 2. 使用 npm-check-updates 检查更新
npx npm-check-updates

# 3. 锁定依赖版本
npm config set save-exact true

# 4. 检查包的下载量和维护状态
npm info lodash

# 5. 使用 npx 前检查包名
npx --yes package-name  # 确认后执行
```

### 11.4 .npmignore 与 files

控制发布到 npm 的文件：

```ini
# .npmignore - 排除不需要发布的文件
node_modules/
src/
test/
*.test.js
.eslintrc
.prettierrc
```

```json
// package.json - 使用 files 字段（白名单，推荐）
{
  "files": [
    "dist/",
    "lib/",
    "README.md"
  ]
}
```

---

## 12. 性能对比与选型

### 12.1 安装速度对比

| 场景 | npm | yarn | pnpm |
|------|-----|------|------|
| 首次安装（无缓存） | 慢 | 中 | 快 |
| 重复安装（有缓存） | 中 | 快 | 最快 |
| CI 环境 | 中 | 快 | 最快 |

### 12.2 磁盘占用对比

```
项目 A: 100 个依赖
项目 B: 80 个依赖（与 A 有 60 个相同）

npm/yarn:
├── 项目 A: 200MB
└── 项目 B: 180MB
总计: 380MB

pnpm:
├── 全局存储: 250MB
├── 项目 A: ~0MB（硬链接）
└── 项目 B: ~0MB（硬链接）
总计: 250MB
```

### 12.3 功能对比

| 功能 | npm | yarn | pnpm |
|------|-----|------|------|
| 工作区 | ✅ v7+ | ✅ | ✅ |
| 即插即用（PnP） | ❌ | ✅ | ❌ |
| 严格依赖 | ❌ | ❌ | ✅ |
| 内容寻址存储 | ❌ | ❌ | ✅ |
| 并行安装 | ✅ | ✅ | ✅ |
| 离线模式 | ✅ | ✅ | ✅ |

### 12.4 选型建议

**选择 npm**：
- 小型项目或个人项目
- 不想安装额外工具
- 需要最广泛的兼容性

**选择 yarn**：
- 需要 Plug'n'Play 特性
- 已有 yarn 使用经验的团队
- 需要更好的 monorepo 支持

**选择 pnpm**：
- 磁盘空间有限
- 大型 monorepo 项目
- 需要严格的依赖隔离
- 追求最快的安装速度

---

## 13. 高级技巧

### 13.1 npx 使用

npx 是 npm 5.2+ 自带的包执行工具：

```bash
# 执行本地安装的包
npx eslint .

# 执行远程包（不安装）
npx create-react-app my-app
npx degit user/repo my-project

# 指定包版本
npx typescript@4.9.5 --version

# 执行 GitHub gist
npx https://gist.github.com/xxx

# 强制使用最新版本
npx --yes create-vite@latest
```

### 13.2 pnpm dlx

pnpm 的 npx 等效命令：

```bash
# 执行远程包
pnpm dlx create-vite my-app

# 等同于
pnpm exec create-vite my-app
```

### 13.3 包别名

```bash
# npm/yarn
npm install lodash-es@npm:lodash@4

# pnpm
pnpm add lodash-es@npm:lodash@4
```

```json
{
  "dependencies": {
    "lodash-es": "npm:lodash@4"
  }
}
```

### 13.4 覆盖依赖版本

当依赖的依赖有问题时，可以强制覆盖版本：

**npm (overrides)**：
```json
{
  "overrides": {
    "lodash": "4.17.21",
    "foo": {
      "bar": "1.0.0"
    }
  }
}
```

**yarn (resolutions)**：
```json
{
  "resolutions": {
    "lodash": "4.17.21",
    "**/lodash": "4.17.21"
  }
}
```

**pnpm (overrides)**：
```json
{
  "pnpm": {
    "overrides": {
      "lodash": "4.17.21",
      "foo>bar": "1.0.0"
    }
  }
}
```

### 13.5 补丁包

当需要修改 node_modules 中的包时：

```bash
# 使用 patch-package
npm install patch-package postinstall-postinstall -D

# 修改 node_modules 中的文件后，创建补丁
npx patch-package lodash

# 补丁会保存在 patches/lodash+4.17.21.patch
```

```json
{
  "scripts": {
    "postinstall": "patch-package"
  }
}
```

**pnpm 内置补丁功能**：
```bash
# 创建补丁
pnpm patch lodash@4.17.21

# 编辑后提交补丁
pnpm patch-commit /path/to/temp/lodash
```

### 13.6 链接本地包

开发时调试本地包：

```bash
# 在包目录创建全局链接
cd my-package
npm link

# 在项目中使用链接
cd my-project
npm link my-package

# 取消链接
npm unlink my-package

# pnpm 方式
pnpm link --global
pnpm link --global my-package
```

---

## 14. 常见错误与解决方案

### 14.1 EACCES 权限错误

**错误信息**：
```
npm ERR! Error: EACCES: permission denied
```

**原因**：全局安装时没有写入权限

**解决方案**：
```bash
# 方案一：修改 npm 全局目录（推荐）
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
# 添加到 PATH: export PATH=~/.npm-global/bin:$PATH

# 方案二：使用 nvm 管理 Node.js
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install node

# 方案三：使用 sudo（不推荐）
sudo npm install -g package-name
```

### 14.2 ERESOLVE 依赖冲突

**错误信息**：
```
npm ERR! ERESOLVE unable to resolve dependency tree
npm ERR! peer dep missing: react@^17.0.0
```

**原因**：依赖版本冲突，通常是 peerDependencies 不满足

**解决方案**：
```bash
# 方案一：使用 --legacy-peer-deps 忽略 peer 依赖检查
npm install --legacy-peer-deps

# 方案二：使用 --force 强制安装
npm install --force

# 方案三：手动解决冲突
# 1. 查看冲突详情
npm ls react
# 2. 安装兼容版本
npm install react@17.0.2

# 方案四：使用 overrides 覆盖版本
{
  "overrides": {
    "react": "17.0.2"
  }
}
```

### 14.3 ENOENT 文件不存在

**错误信息**：
```
npm ERR! enoent ENOENT: no such file or directory
```

**原因**：package.json 不存在或路径错误

**解决方案**：
```bash
# 确认当前目录
pwd
ls package.json

# 初始化项目
npm init -y

# 或检查路径是否正确
cd correct-directory
npm install
```

### 14.4 网络超时错误

**错误信息**：
```
npm ERR! network timeout
npm ERR! ETIMEDOUT
npm ERR! ECONNREFUSED
```

**原因**：网络问题或镜像源不可用

**解决方案**：
```bash
# 方案一：切换镜像源
npm config set registry https://registry.npmmirror.com

# 方案二：设置超时时间
npm config set timeout 60000

# 方案三：设置代理
npm config set proxy http://proxy.company.com:8080
npm config set https-proxy http://proxy.company.com:8080

# 方案四：清理缓存后重试
npm cache clean --force
npm install
```

### 14.5 node-gyp 编译错误

**错误信息**：
```
gyp ERR! build error
gyp ERR! stack Error: `make` failed
```

**原因**：缺少编译原生模块所需的工具

**解决方案**：

**Windows**：
```bash
# 安装 windows-build-tools
npm install -g windows-build-tools

# 或手动安装
# 1. 安装 Visual Studio Build Tools
# 2. 安装 Python 2.7 或 3.x
```

**macOS**：
```bash
# 安装 Xcode Command Line Tools
xcode-select --install
```

**Linux**：
```bash
# Ubuntu/Debian
sudo apt-get install build-essential python3

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install python3
```

### 14.6 EPERM 操作不允许

**错误信息**：
```
npm ERR! Error: EPERM: operation not permitted
```

**原因**：文件被占用或权限问题

**解决方案**：
```bash
# 方案一：关闭占用文件的程序（IDE、终端等）

# 方案二：删除 node_modules 后重装
rm -rf node_modules
rm package-lock.json
npm install

# 方案三：Windows 下以管理员身份运行

# 方案四：检查文件是否只读
attrib -r node_modules /s /d  # Windows
chmod -R 755 node_modules     # Linux/macOS
```

### 14.7 幽灵依赖问题（Phantom Dependencies）

**问题描述**：
代码中引用了未在 package.json 中声明的包，但因为扁平化安装而意外可用。

```javascript
// package.json 只声明了 express
// 但 express 依赖 debug，所以 debug 也被安装了
import debug from 'debug';  // 危险！未声明的依赖
```

**风险**：
- 其他项目可能没有这个"幽灵依赖"
- 依赖升级后可能消失

**解决方案**：
```bash
# 方案一：使用 pnpm（默认严格模式）
pnpm install

# 方案二：显式声明所有使用的依赖
npm install debug

# 方案三：使用 eslint-plugin-import 检测
{
  "rules": {
    "import/no-extraneous-dependencies": "error"
  }
}
```

### 14.8 版本不一致问题

**问题描述**：
团队成员安装的依赖版本不同，导致"在我电脑上能跑"的问题。

**解决方案**：
```bash
# 1. 始终提交锁文件
git add package-lock.json

# 2. CI 环境使用 ci 命令
npm ci

# 3. 使用 engines 字段限制 Node.js 版本
{
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}

# 4. 使用 .nvmrc 文件
echo "18.17.0" > .nvmrc
nvm use
```

### 14.9 pnpm 特有问题

#### 依赖无法访问

**错误信息**：
```
Error: Cannot find module 'xxx'
```

**原因**：pnpm 的严格模式阻止访问未声明的依赖

**解决方案**：
```ini
# .npmrc
# 方案一：提升特定包
public-hoist-pattern[]=*eslint*

# 方案二：提升所有包（不推荐）
shamefully-hoist=true

# 方案三：正确声明依赖（推荐）
pnpm add xxx
```

#### 符号链接问题

某些工具不支持符号链接：

```ini
# .npmrc
node-linker=hoisted  # 使用传统的 node_modules 结构
```

### 14.10 常见警告处理

#### deprecated 警告

```
npm WARN deprecated request@2.88.2: request has been deprecated
```

**处理方式**：
```bash
# 查看是哪个包依赖了废弃包
npm ls request

# 更新依赖或寻找替代方案
npm update
```

#### peer dependency 警告

```
npm WARN peer dep missing: react@^17.0.0
```

**处理方式**：
```bash
# 安装缺失的 peer 依赖
npm install react@17

# 或忽略警告（如果确定不影响）
npm install --legacy-peer-deps
```

---

## 快速参考表

### 命令对照表

| 操作 | npm | yarn | pnpm |
|------|-----|------|------|
| 初始化 | `npm init` | `yarn init` | `pnpm init` |
| 安装所有依赖 | `npm install` | `yarn` | `pnpm install` |
| 添加依赖 | `npm install pkg` | `yarn add pkg` | `pnpm add pkg` |
| 添加开发依赖 | `npm install -D pkg` | `yarn add -D pkg` | `pnpm add -D pkg` |
| 全局安装 | `npm install -g pkg` | `yarn global add pkg` | `pnpm add -g pkg` |
| 卸载 | `npm uninstall pkg` | `yarn remove pkg` | `pnpm remove pkg` |
| 更新 | `npm update` | `yarn upgrade` | `pnpm update` |
| 运行脚本 | `npm run script` | `yarn script` | `pnpm script` |
| 执行包 | `npx pkg` | `yarn dlx pkg` | `pnpm dlx pkg` |
| 清理缓存 | `npm cache clean` | `yarn cache clean` | `pnpm store prune` |
| 查看过时包 | `npm outdated` | `yarn outdated` | `pnpm outdated` |
| 安全审计 | `npm audit` | `yarn audit` | `pnpm audit` |

---

> 💡 **小贴士**：选择哪个包管理器取决于项目需求和团队习惯。对于新项目，推荐尝试 pnpm，它在性能和磁盘占用方面都有明显优势。
