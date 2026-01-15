> CI/CD 是现代软件开发中实现自动化构建、测试和部署的核心实践
> 本笔记涵盖 GitHub Actions / GitLab CI / Jenkins / Docker / Kubernetes

---

## 目录

1. [基础概念](#1-基础概念)
2. [GitHub Actions](#2-github-actions)
3. [GitLab CI/CD](#3-gitlab-cicd)
4. [Jenkins](#4-jenkins)
5. [Docker 容器化](#5-docker-容器化)
6. [Kubernetes 部署](#6-kubernetes-部署)
7. [部署策略](#7-部署策略)
8. [环境管理](#8-环境管理)
9. [安全最佳实践](#9-安全最佳实践)
10. [监控与回滚](#10-监控与回滚)
11. [常见错误与解决方案](#11-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 CI/CD？

**CI（Continuous Integration，持续集成）**：
开发人员频繁地将代码合并到主分支，每次合并都会触发自动化构建和测试，尽早发现集成问题。

**CD（Continuous Delivery/Deployment，持续交付/部署）**：
- **持续交付**：代码通过所有测试后，自动准备好可部署的版本，但需要手动触发部署
- **持续部署**：代码通过所有测试后，自动部署到生产环境

```
代码提交 → 构建 → 单元测试 → 集成测试 → 部署到测试环境 → 部署到生产环境
   │         │        │           │              │                │
   └─────────┴────────┴───────────┴──────────────┴────────────────┘
                              CI/CD Pipeline
```

### 1.2 CI/CD 的价值

| 传统开发 | CI/CD |
|----------|-------|
| 手动构建，容易出错 | 自动化构建，一致性高 |
| 集成周期长，问题难定位 | 频繁集成，问题早发现 |
| 手动测试，覆盖率低 | 自动化测试，覆盖率高 |
| 部署耗时，风险高 | 快速部署，可回滚 |
| 发布周期长 | 可以每天多次发布 |

### 1.3 CI/CD 工具对比

| 工具 | 类型 | 特点 | 适用场景 |
|------|------|------|----------|
| GitHub Actions | 云托管 | 与 GitHub 深度集成，免费额度充足 | GitHub 项目 |
| GitLab CI | 云托管/自托管 | 功能全面，内置容器注册表 | GitLab 项目 |
| Jenkins | 自托管 | 插件丰富，高度可定制 | 企业级复杂流程 |
| CircleCI | 云托管 | 配置简单，并行执行 | 中小型项目 |
| Travis CI | 云托管 | 开源项目友好 | 开源项目 |
| Azure DevOps | 云托管 | 微软生态集成 | .NET 项目 |

### 1.4 Pipeline 基本概念

```yaml
# Pipeline 结构示意
Pipeline（流水线）
├── Stage（阶段）
│   ├── Job（作业）
│   │   ├── Step（步骤）
│   │   └── Step
│   └── Job
├── Stage
│   └── Job
└── Stage
    └── Job
```

**核心概念**：
- **Pipeline**：整个 CI/CD 流程
- **Stage**：流水线的阶段（如 build、test、deploy）
- **Job**：在某个阶段执行的具体任务
- **Step**：Job 中的单个命令或操作
- **Runner/Agent**：执行 Job 的机器或容器
- **Artifact**：构建产物，可在 Job 间传递
- **Cache**：缓存依赖，加速构建

---

## 2. GitHub Actions

### 2.1 基础配置

GitHub Actions 的配置文件位于 `.github/workflows/` 目录下：

```yaml
# .github/workflows/ci.yml
name: CI Pipeline

# 触发条件
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  # 定时触发
  schedule:
    - cron: '0 2 * * *'  # 每天凌晨 2 点
  # 手动触发
  workflow_dispatch:
    inputs:
      environment:
        description: '部署环境'
        required: true
        default: 'staging'
        type: choice
        options:
          - staging
          - production

# 环境变量
env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # 构建任务
  build:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build
        run: npm run build
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/
          retention-days: 7

  # 测试任务
  test:
    runs-on: ubuntu-latest
    needs: build  # 依赖 build 任务
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests
        run: npm test -- --coverage
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
```

### 2.2 矩阵构建

同时在多个环境下测试：

```yaml
jobs:
  test:
    runs-on: ${{ matrix.os }}
    
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node-version: [16, 18, 20]
        exclude:
          - os: windows-latest
            node-version: 16
      fail-fast: false  # 一个失败不影响其他
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Use Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
      
      - run: npm ci
      - run: npm test
```

### 2.3 Docker 构建与推送

```yaml
jobs:
  docker:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=sha,prefix=
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

### 2.4 部署到云服务

**部署到 AWS**：
```yaml
jobs:
  deploy-aws:
    runs-on: ubuntu-latest
    environment: production
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ap-northeast-1
      
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2
      
      - name: Build and push to ECR
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: my-app
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
      
      - name: Deploy to ECS
        run: |
          aws ecs update-service \
            --cluster my-cluster \
            --service my-service \
            --force-new-deployment
```

**部署到 Kubernetes**：
```yaml
jobs:
  deploy-k8s:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up kubectl
        uses: azure/setup-kubectl@v3
      
      - name: Configure kubeconfig
        run: |
          mkdir -p ~/.kube
          echo "${{ secrets.KUBE_CONFIG }}" | base64 -d > ~/.kube/config
      
      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/my-app \
            my-app=ghcr.io/${{ github.repository }}:${{ github.sha }} \
            -n production
          kubectl rollout status deployment/my-app -n production
```

### 2.5 可复用工作流

**定义可复用工作流**：
```yaml
# .github/workflows/reusable-deploy.yml
name: Reusable Deploy

on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string
      image-tag:
        required: true
        type: string
    secrets:
      DEPLOY_KEY:
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    
    steps:
      - name: Deploy
        run: |
          echo "Deploying ${{ inputs.image-tag }} to ${{ inputs.environment }}"
          # 部署逻辑
```

**调用可复用工作流**：
```yaml
# .github/workflows/main.yml
jobs:
  build:
    # ... 构建任务

  deploy-staging:
    needs: build
    uses: ./.github/workflows/reusable-deploy.yml
    with:
      environment: staging
      image-tag: ${{ github.sha }}
    secrets:
      DEPLOY_KEY: ${{ secrets.STAGING_DEPLOY_KEY }}

  deploy-production:
    needs: deploy-staging
    uses: ./.github/workflows/reusable-deploy.yml
    with:
      environment: production
      image-tag: ${{ github.sha }}
    secrets:
      DEPLOY_KEY: ${{ secrets.PROD_DEPLOY_KEY }}
```

### 2.6 自定义 Action

```yaml
# action.yml
name: 'My Custom Action'
description: '自定义 Action 示例'
inputs:
  name:
    description: '名称'
    required: true
    default: 'World'
outputs:
  result:
    description: '结果'
    value: ${{ steps.run.outputs.result }}

runs:
  using: 'composite'
  steps:
    - name: Run script
      id: run
      shell: bash
      run: |
        echo "Hello, ${{ inputs.name }}!"
        echo "result=success" >> $GITHUB_OUTPUT
```

---

## 3. GitLab CI/CD

### 3.1 基础配置

GitLab CI 配置文件为 `.gitlab-ci.yml`：

```yaml
# .gitlab-ci.yml

# 定义阶段
stages:
  - build
  - test
  - deploy

# 全局变量
variables:
  NODE_VERSION: "18"
  DOCKER_DRIVER: overlay2

# 全局缓存
cache:
  key: ${CI_COMMIT_REF_SLUG}
  paths:
    - node_modules/
    - .npm/

# 默认配置
default:
  image: node:${NODE_VERSION}
  before_script:
    - npm ci --cache .npm --prefer-offline

# 构建任务
build:
  stage: build
  script:
    - npm run build
  artifacts:
    paths:
      - dist/
    expire_in: 1 week
  only:
    - main
    - merge_requests

# 单元测试
unit-test:
  stage: test
  script:
    - npm run test:unit -- --coverage
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
  artifacts:
    reports:
      junit: junit.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

# 集成测试
integration-test:
  stage: test
  services:
    - postgres:14
    - redis:7
  variables:
    POSTGRES_DB: test_db
    POSTGRES_USER: test_user
    POSTGRES_PASSWORD: test_pass
    DATABASE_URL: "postgresql://test_user:test_pass@postgres:5432/test_db"
  script:
    - npm run test:integration

# 部署到测试环境
deploy-staging:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache openssh-client
    - eval $(ssh-agent -s)
    - echo "$SSH_PRIVATE_KEY" | ssh-add -
  script:
    - ssh -o StrictHostKeyChecking=no $STAGING_USER@$STAGING_HOST "cd /app && ./deploy.sh"
  environment:
    name: staging
    url: https://staging.example.com
  only:
    - develop

# 部署到生产环境
deploy-production:
  stage: deploy
  script:
    - ./deploy-production.sh
  environment:
    name: production
    url: https://example.com
  when: manual  # 手动触发
  only:
    - main
```

### 3.2 Docker 构建

```yaml
# Docker 构建与推送
docker-build:
  stage: build
  image: docker:24
  services:
    - docker:24-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - |
      if [ "$CI_COMMIT_BRANCH" == "main" ]; then
        docker tag $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE:latest
        docker push $CI_REGISTRY_IMAGE:latest
      fi
  only:
    - main
    - develop
```

### 3.3 多环境部署

```yaml
# 使用 extends 复用配置
.deploy-template:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - kubectl config set-cluster k8s --server="$KUBE_URL" --insecure-skip-tls-verify=true
    - kubectl config set-credentials admin --token="$KUBE_TOKEN"
    - kubectl config set-context default --cluster=k8s --user=admin
    - kubectl config use-context default
    - envsubst < k8s/deployment.yaml | kubectl apply -f -
    - kubectl rollout status deployment/$APP_NAME -n $NAMESPACE

deploy-dev:
  extends: .deploy-template
  variables:
    NAMESPACE: development
    APP_NAME: my-app-dev
  environment:
    name: development
  only:
    - develop

deploy-staging:
  extends: .deploy-template
  variables:
    NAMESPACE: staging
    APP_NAME: my-app-staging
  environment:
    name: staging
  only:
    - main
  when: manual

deploy-production:
  extends: .deploy-template
  variables:
    NAMESPACE: production
    APP_NAME: my-app
  environment:
    name: production
  only:
    - tags
  when: manual
```

### 3.4 动态环境

```yaml
# 为每个 MR 创建动态环境
review:
  stage: deploy
  script:
    - kubectl apply -f k8s/review-app.yaml
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    url: https://$CI_COMMIT_REF_SLUG.review.example.com
    on_stop: stop-review
    auto_stop_in: 1 week
  only:
    - merge_requests

stop-review:
  stage: deploy
  script:
    - kubectl delete -f k8s/review-app.yaml
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    action: stop
  when: manual
  only:
    - merge_requests
```

---

## 4. Jenkins

### 4.1 Jenkinsfile（声明式）

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'registry.example.com'
        IMAGE_NAME = 'my-app'
        KUBECONFIG = credentials('kubeconfig')
    }
    
    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }
    
    parameters {
        choice(name: 'ENVIRONMENT', choices: ['dev', 'staging', 'production'], description: '部署环境')
        booleanParam(name: 'SKIP_TESTS', defaultValue: false, description: '跳过测试')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build') {
            steps {
                sh 'npm ci'
                sh 'npm run build'
            }
        }
        
        stage('Test') {
            when {
                expression { !params.SKIP_TESTS }
            }
            parallel {
                stage('Unit Tests') {
                    steps {
                        sh 'npm run test:unit'
                    }
                }
                stage('Integration Tests') {
                    steps {
                        sh 'npm run test:integration'
                    }
                }
            }
            post {
                always {
                    junit 'test-results/**/*.xml'
                    publishHTML([
                        reportDir: 'coverage',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
            }
        }
        
        stage('Docker Build') {
            steps {
                script {
                    docker.withRegistry("https://${DOCKER_REGISTRY}", 'docker-credentials') {
                        def image = docker.build("${IMAGE_NAME}:${BUILD_NUMBER}")
                        image.push()
                        image.push('latest')
                    }
                }
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                script {
                    withKubeConfig([credentialsId: 'kubeconfig']) {
                        sh """
                            kubectl set image deployment/${IMAGE_NAME} \
                                ${IMAGE_NAME}=${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} \
                                -n ${params.ENVIRONMENT}
                            kubectl rollout status deployment/${IMAGE_NAME} -n ${params.ENVIRONMENT}
                        """
                    }
                }
            }
        }
    }
    
    post {
        success {
            slackSend(
                color: 'good',
                message: "构建成功: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
            )
        }
        failure {
            slackSend(
                color: 'danger',
                message: "构建失败: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
            )
        }
        always {
            cleanWs()
        }
    }
}
```

### 4.2 共享库

```groovy
// vars/standardPipeline.groovy
def call(Map config) {
    pipeline {
        agent any
        
        stages {
            stage('Build') {
                steps {
                    script {
                        if (config.buildCommand) {
                            sh config.buildCommand
                        } else {
                            sh 'npm ci && npm run build'
                        }
                    }
                }
            }
            
            stage('Test') {
                steps {
                    sh config.testCommand ?: 'npm test'
                }
            }
            
            stage('Deploy') {
                when {
                    branch 'main'
                }
                steps {
                    script {
                        deploy(config.deployConfig)
                    }
                }
            }
        }
    }
}

// 使用共享库
// Jenkinsfile
@Library('my-shared-library') _

standardPipeline(
    buildCommand: 'mvn clean package',
    testCommand: 'mvn test',
    deployConfig: [
        environment: 'production',
        namespace: 'default'
    ]
)
```

---

## 5. Docker 容器化

### 5.1 Dockerfile 最佳实践

**Node.js 应用**：
```dockerfile
# 多阶段构建
# 阶段1：构建
FROM node:18-alpine AS builder

WORKDIR /app

# 先复制依赖文件，利用缓存
COPY package*.json ./
RUN npm ci --only=production

# 复制源代码并构建
COPY . .
RUN npm run build

# 阶段2：运行
FROM node:18-alpine AS runner

WORKDIR /app

# 创建非 root 用户
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 appuser

# 只复制必要文件
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# 设置环境变量
ENV NODE_ENV=production
ENV PORT=3000

# 切换用户
USER appuser

EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "dist/main.js"]
```

**Java Spring Boot 应用**：
```dockerfile
# 多阶段构建
FROM eclipse-temurin:17-jdk-alpine AS builder

WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY build.gradle.kts settings.gradle.kts ./
COPY src src

RUN chmod +x ./gradlew && ./gradlew bootJar --no-daemon

# 运行阶段
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# 创建用户
RUN addgroup -S spring && adduser -S spring -G spring

# 复制 JAR
COPY --from=builder /app/build/libs/*.jar app.jar

USER spring

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
```

**Python 应用**：
```dockerfile
FROM python:3.11-slim AS builder

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# 运行阶段
FROM python:3.11-slim

WORKDIR /app

# 复制依赖
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# 复制应用
COPY . .

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
```

### 5.2 Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - NODE_ENV=production
    image: my-app:latest
    container_name: my-app
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  db:
    image: postgres:15-alpine
    container_name: my-app-db
    restart: unless-stopped
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=myapp
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: my-app-redis
    restart: unless-stopped
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - app-network

  nginx:
    image: nginx:alpine
    container_name: my-app-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    networks:
      - app-network

volumes:
  postgres-data:
  redis-data:

networks:
  app-network:
    driver: bridge
```

### 5.3 镜像优化

```dockerfile
# 1. 使用 .dockerignore
# .dockerignore
node_modules
npm-debug.log
.git
.gitignore
*.md
.env*
coverage
.nyc_output
dist

# 2. 合并 RUN 命令减少层数
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 3. 使用特定版本标签
FROM node:18.19.0-alpine3.19

# 4. 清理缓存
RUN npm ci --only=production && npm cache clean --force
```

---

## 6. Kubernetes 部署

### 6.1 基础资源配置

**Deployment**：
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
  labels:
    app: my-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: my-app
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "3000"
    spec:
      serviceAccountName: my-app
      containers:
        - name: my-app
          image: ghcr.io/myorg/my-app:latest
          imagePullPolicy: Always
          ports:
            - containerPort: 3000
              name: http
          env:
            - name: NODE_ENV
              value: "production"
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: my-app-secrets
                  key: database-url
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 3
          volumeMounts:
            - name: config
              mountPath: /app/config
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: my-app-config
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: my-app
                topologyKey: kubernetes.io/hostname
```

**Service**：
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: my-app
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: my-app
  ports:
    - port: 80
      targetPort: 3000
      protocol: TCP
      name: http
```

**Ingress**：
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  namespace: production
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: my-app-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-app
                port:
                  number: 80
```

**ConfigMap 和 Secret**：
```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-app-config
  namespace: production
data:
  config.json: |
    {
      "logLevel": "info",
      "features": {
        "newFeature": true
      }
    }

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app-secrets
  namespace: production
type: Opaque
stringData:
  database-url: "postgresql://user:pass@host:5432/db"
  api-key: "your-api-key"
```

### 6.2 Helm Chart

```yaml
# charts/my-app/Chart.yaml
apiVersion: v2
name: my-app
description: My Application Helm Chart
type: application
version: 1.0.0
appVersion: "1.0.0"

# charts/my-app/values.yaml
replicaCount: 3

image:
  repository: ghcr.io/myorg/my-app
  tag: latest
  pullPolicy: Always

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: my-app-tls
      hosts:
        - api.example.com

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

env:
  NODE_ENV: production

secrets:
  databaseUrl: ""
```

```yaml
# charts/my-app/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "my-app.fullname" . }}
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicaCount }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "my-app.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "my-app.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 3000
          env:
            - name: NODE_ENV
              value: {{ .Values.env.NODE_ENV | quote }}
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ include "my-app.fullname" . }}-secrets
                  key: database-url
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
```

**Helm 命令**：
```bash
# 安装
helm install my-app ./charts/my-app -n production -f values-prod.yaml

# 升级
helm upgrade my-app ./charts/my-app -n production -f values-prod.yaml

# 回滚
helm rollback my-app 1 -n production

# 查看历史
helm history my-app -n production

# 卸载
helm uninstall my-app -n production
```

### 6.3 Kustomize

```yaml
# base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - deployment.yaml
  - service.yaml
  - ingress.yaml

commonLabels:
  app: my-app

# overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: production

resources:
  - ../../base

images:
  - name: my-app
    newName: ghcr.io/myorg/my-app
    newTag: v1.0.0

replicas:
  - name: my-app
    count: 5

patches:
  - patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources/limits/memory
        value: 1Gi
    target:
      kind: Deployment
      name: my-app

configMapGenerator:
  - name: my-app-config
    literals:
      - LOG_LEVEL=info

secretGenerator:
  - name: my-app-secrets
    literals:
      - DATABASE_URL=postgresql://prod-db:5432/myapp
```

```bash
# 应用 Kustomize
kubectl apply -k overlays/production/

# 预览生成的 YAML
kubectl kustomize overlays/production/
```

---

## 7. 部署策略

### 7.1 滚动更新（Rolling Update）

默认策略，逐步替换旧版本：

```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 25%        # 最多超出期望副本数的比例
      maxUnavailable: 25%  # 最多不可用副本数的比例
```

**优点**：零停机、可回滚
**缺点**：新旧版本共存期间可能有兼容性问题

### 7.2 蓝绿部署（Blue-Green）

同时运行两个完整环境，通过切换流量实现部署：

```yaml
# blue-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
      version: blue
  template:
    metadata:
      labels:
        app: my-app
        version: blue
    spec:
      containers:
        - name: my-app
          image: my-app:v1

---
# green-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-green
spec:
  replicas: 3
  selector:
    matchLabels:
      app: my-app
      version: green
  template:
    metadata:
      labels:
        app: my-app
        version: green
    spec:
      containers:
        - name: my-app
          image: my-app:v2

---
# service.yaml - 切换 selector 实现流量切换
apiVersion: v1
kind: Service
metadata:
  name: my-app
spec:
  selector:
    app: my-app
    version: green  # 切换到 green
  ports:
    - port: 80
      targetPort: 3000
```

**优点**：快速回滚、测试方便
**缺点**：需要双倍资源

### 7.3 金丝雀部署（Canary）

先将新版本部署给小部分用户，验证后再全量发布：

```yaml
# 使用 Istio 实现金丝雀部署
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: my-app
spec:
  hosts:
    - my-app
  http:
    - match:
        - headers:
            x-canary:
              exact: "true"
      route:
        - destination:
            host: my-app
            subset: canary
    - route:
        - destination:
            host: my-app
            subset: stable
          weight: 90
        - destination:
            host: my-app
            subset: canary
          weight: 10

---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: my-app
spec:
  host: my-app
  subsets:
    - name: stable
      labels:
        version: v1
    - name: canary
      labels:
        version: v2
```

**使用 Argo Rollouts**：
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: my-app
spec:
  replicas: 5
  strategy:
    canary:
      steps:
        - setWeight: 10
        - pause: {duration: 5m}
        - setWeight: 30
        - pause: {duration: 5m}
        - setWeight: 50
        - pause: {duration: 5m}
        - setWeight: 100
      canaryService: my-app-canary
      stableService: my-app-stable
      trafficRouting:
        nginx:
          stableIngress: my-app-ingress
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
        - name: my-app
          image: my-app:v2
```

### 7.4 A/B 测试

基于用户特征分流：

```yaml
# Istio VirtualService
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: my-app
spec:
  hosts:
    - my-app
  http:
    # 特定用户使用新版本
    - match:
        - headers:
            user-id:
              regex: "^[0-4].*"  # 用户 ID 以 0-4 开头
      route:
        - destination:
            host: my-app
            subset: v2
    # 其他用户使用旧版本
    - route:
        - destination:
            host: my-app
            subset: v1
```

---

## 8. 环境管理

### 8.1 多环境配置

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches:
      - develop
      - main
  release:
    types: [published]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set environment
        id: env
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/develop" ]]; then
            echo "environment=development" >> $GITHUB_OUTPUT
            echo "url=https://dev.example.com" >> $GITHUB_OUTPUT
          elif [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "environment=staging" >> $GITHUB_OUTPUT
            echo "url=https://staging.example.com" >> $GITHUB_OUTPUT
          elif [[ "${{ github.event_name }}" == "release" ]]; then
            echo "environment=production" >> $GITHUB_OUTPUT
            echo "url=https://example.com" >> $GITHUB_OUTPUT
          fi
      
      - name: Deploy
        uses: ./.github/actions/deploy
        with:
          environment: ${{ steps.env.outputs.environment }}
        env:
          DEPLOY_URL: ${{ steps.env.outputs.url }}
```

### 8.2 环境变量管理

**使用 GitHub Environments**：
```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://example.com
    
    steps:
      - name: Deploy
        env:
          # 从 Environment secrets 获取
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          API_KEY: ${{ secrets.API_KEY }}
        run: ./deploy.sh
```

**使用 Vault**：
```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Import secrets from Vault
        uses: hashicorp/vault-action@v2
        with:
          url: https://vault.example.com
          method: jwt
          role: github-actions
          secrets: |
            secret/data/production/database url | DATABASE_URL ;
            secret/data/production/api key | API_KEY
      
      - name: Deploy
        run: ./deploy.sh
```

### 8.3 配置文件管理

```yaml
# config/base.yaml
app:
  name: my-app
  port: 3000

logging:
  level: info
  format: json

# config/development.yaml
database:
  host: localhost
  port: 5432
  name: myapp_dev

redis:
  host: localhost
  port: 6379

# config/production.yaml
database:
  host: ${DATABASE_HOST}
  port: 5432
  name: myapp_prod
  ssl: true

redis:
  host: ${REDIS_HOST}
  port: 6379
  tls: true
```

```javascript
// config/index.js
const config = require('config');

module.exports = {
  database: {
    host: config.get('database.host'),
    port: config.get('database.port'),
    name: config.get('database.name'),
  },
  redis: {
    host: config.get('redis.host'),
    port: config.get('redis.port'),
  },
};
```

---

## 9. 安全最佳实践

### 9.1 密钥管理

```yaml
# 不要在代码中硬编码密钥
# ❌ 错误
env:
  DATABASE_URL: "postgresql://user:password@host:5432/db"

# ✅ 使用 Secrets
env:
  DATABASE_URL: ${{ secrets.DATABASE_URL }}

# ✅ 使用 Kubernetes Secrets
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: app-secrets
        key: database-url
```

### 9.2 镜像安全扫描

```yaml
# GitHub Actions
jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: my-app:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      
      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

### 9.3 代码安全扫描

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # 依赖漏洞扫描
      - name: Run npm audit
        run: npm audit --audit-level=high
      
      # SAST 扫描
      - name: Run CodeQL
        uses: github/codeql-action/analyze@v2
        with:
          languages: javascript
      
      # 密钥泄露检测
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 9.4 最小权限原则

```yaml
# GitHub Actions - 最小权限
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # OIDC
    
    steps:
      # 使用 OIDC 而非长期凭证
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/github-actions
          aws-region: us-east-1
```

```yaml
# Kubernetes - ServiceAccount 最小权限
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["my-app-secrets"]
    verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: my-app-rolebinding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: my-app
    namespace: production
roleRef:
  kind: Role
  name: my-app-role
  apiGroup: rbac.authorization.k8s.io
```

---

## 10. 监控与回滚

### 10.1 部署监控

```yaml
# 部署后验证
jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Deploy
        run: kubectl apply -f k8s/
      
      - name: Wait for rollout
        run: |
          kubectl rollout status deployment/my-app -n production --timeout=300s
      
      - name: Verify deployment
        run: |
          # 检查 Pod 状态
          kubectl get pods -n production -l app=my-app
          
          # 健康检查
          for i in {1..10}; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://api.example.com/health)
            if [ "$STATUS" == "200" ]; then
              echo "Health check passed"
              exit 0
            fi
            echo "Attempt $i: Status $STATUS"
            sleep 10
          done
          echo "Health check failed"
          exit 1
      
      - name: Rollback on failure
        if: failure()
        run: |
          kubectl rollout undo deployment/my-app -n production
```

### 10.2 自动回滚

```yaml
# Argo Rollouts 自动回滚
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: my-app
spec:
  strategy:
    canary:
      steps:
        - setWeight: 10
        - pause: {duration: 5m}
        - analysis:
            templates:
              - templateName: success-rate
            args:
              - name: service-name
                value: my-app
        - setWeight: 50
        - pause: {duration: 5m}
        - setWeight: 100

---
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: success-rate
spec:
  args:
    - name: service-name
  metrics:
    - name: success-rate
      interval: 1m
      successCondition: result[0] >= 0.95
      failureLimit: 3
      provider:
        prometheus:
          address: http://prometheus:9090
          query: |
            sum(rate(http_requests_total{service="{{args.service-name}}",status=~"2.."}[5m])) /
            sum(rate(http_requests_total{service="{{args.service-name}}"}[5m]))
```

### 10.3 通知集成

```yaml
# Slack 通知
jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Deploy
        id: deploy
        run: ./deploy.sh
      
      - name: Notify Slack on success
        if: success()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ 部署成功",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*部署成功* :white_check_mark:\n*仓库:* ${{ github.repository }}\n*分支:* ${{ github.ref_name }}\n*提交:* ${{ github.sha }}"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
      
      - name: Notify Slack on failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "❌ 部署失败",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*部署失败* :x:\n*仓库:* ${{ github.repository }}\n*分支:* ${{ github.ref_name }}\n*查看日志:* ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### 10.4 手动回滚

```bash
# Kubernetes 回滚
kubectl rollout undo deployment/my-app -n production

# 回滚到特定版本
kubectl rollout undo deployment/my-app -n production --to-revision=2

# 查看历史
kubectl rollout history deployment/my-app -n production

# Helm 回滚
helm rollback my-app 1 -n production

# 查看历史
helm history my-app -n production
```

---

## 11. 常见错误与解决方案

### 11.1 GitHub Actions 错误

#### Permission denied

**错误信息**：
```
Error: Process completed with exit code 126.
/home/runner/work/_temp/xxx.sh: Permission denied
```

**解决方案**：
```yaml
steps:
  - name: Make script executable
    run: chmod +x ./scripts/deploy.sh
  
  - name: Run script
    run: ./scripts/deploy.sh
```

#### Resource not accessible by integration

**错误信息**：
```
Error: Resource not accessible by integration
```

**解决方案**：
```yaml
# 添加必要的权限
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      pull-requests: write
```

#### Context deadline exceeded

**错误信息**：
```
Error: Context deadline exceeded
```

**解决方案**：
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30  # 增加超时时间
    
    steps:
      - name: Long running task
        timeout-minutes: 15  # 单步超时
        run: ./long-task.sh
```

### 11.2 Docker 构建错误

#### COPY failed: file not found

**错误信息**：
```
COPY failed: file not found in build context
```

**解决方案**：
```dockerfile
# 检查 .dockerignore 是否排除了需要的文件
# 确保文件路径正确

# 使用相对于构建上下文的路径
COPY ./src ./src

# 检查构建上下文
docker build -t my-app . --progress=plain
```

#### npm install 失败

**错误信息**：
```
npm ERR! network timeout
```

**解决方案**：
```dockerfile
# 使用国内镜像
RUN npm config set registry https://registry.npmmirror.com && \
    npm ci

# 或增加超时时间
RUN npm ci --fetch-timeout=600000
```

#### 镜像体积过大

**解决方案**：
```dockerfile
# 1. 使用多阶段构建
FROM node:18 AS builder
# 构建阶段

FROM node:18-alpine AS runner
# 只复制必要文件

# 2. 使用 alpine 基础镜像
FROM node:18-alpine

# 3. 清理缓存
RUN npm ci --only=production && npm cache clean --force

# 4. 使用 .dockerignore
# .dockerignore
node_modules
.git
*.md
test
coverage
```

### 11.3 Kubernetes 部署错误

#### ImagePullBackOff

**错误信息**：
```
Failed to pull image: rpc error: code = Unknown desc = Error response from daemon
```

**解决方案**：
```yaml
# 1. 检查镜像名称和标签
kubectl describe pod <pod-name>

# 2. 创建镜像拉取密钥
kubectl create secret docker-registry regcred \
  --docker-server=ghcr.io \
  --docker-username=<username> \
  --docker-password=<token>

# 3. 在 Deployment 中使用
spec:
  template:
    spec:
      imagePullSecrets:
        - name: regcred
```

#### CrashLoopBackOff

**错误信息**：
```
CrashLoopBackOff
```

**排查步骤**：
```bash
# 1. 查看 Pod 日志
kubectl logs <pod-name> -n <namespace>
kubectl logs <pod-name> -n <namespace> --previous

# 2. 查看 Pod 事件
kubectl describe pod <pod-name> -n <namespace>

# 3. 进入容器调试
kubectl exec -it <pod-name> -n <namespace> -- /bin/sh

# 常见原因：
# - 应用启动失败
# - 健康检查配置错误
# - 资源限制过低
# - 配置文件缺失
```

#### OOMKilled

**错误信息**：
```
Last State: Terminated
Reason: OOMKilled
```

**解决方案**：
```yaml
# 增加内存限制
resources:
  requests:
    memory: "256Mi"
  limits:
    memory: "512Mi"  # 增加限制

# 或优化应用内存使用
# Node.js 示例
CMD ["node", "--max-old-space-size=400", "dist/main.js"]
```

#### Pending 状态

**排查步骤**：
```bash
# 查看原因
kubectl describe pod <pod-name>

# 常见原因：
# 1. 资源不足
kubectl describe nodes | grep -A 5 "Allocated resources"

# 2. PVC 未绑定
kubectl get pvc

# 3. 节点选择器不匹配
kubectl get nodes --show-labels
```

### 11.4 网络错误

#### Connection refused

**解决方案**：
```yaml
# 1. 检查 Service 配置
kubectl get svc
kubectl describe svc <service-name>

# 2. 检查 Endpoints
kubectl get endpoints <service-name>

# 3. 检查 Pod 端口
kubectl get pods -o wide
kubectl exec -it <pod-name> -- netstat -tlnp

# 4. 测试连接
kubectl run test --rm -it --image=busybox -- wget -qO- http://<service-name>:<port>
```

#### DNS 解析失败

**解决方案**：
```bash
# 1. 检查 CoreDNS
kubectl get pods -n kube-system -l k8s-app=kube-dns

# 2. 测试 DNS
kubectl run test --rm -it --image=busybox -- nslookup <service-name>

# 3. 检查 DNS 配置
kubectl exec -it <pod-name> -- cat /etc/resolv.conf
```

### 11.5 CI/CD 流程问题

#### 缓存失效

**GitHub Actions**：
```yaml
- name: Cache node modules
  uses: actions/cache@v3
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-node-
```

**GitLab CI**：
```yaml
cache:
  key:
    files:
      - package-lock.json
  paths:
    - node_modules/
  policy: pull-push
```

#### 并发部署冲突

**解决方案**：
```yaml
# GitHub Actions
concurrency:
  group: deploy-${{ github.ref }}
  cancel-in-progress: true

# GitLab CI
deploy:
  resource_group: production  # 同一资源组串行执行
```

#### 环境变量未生效

**排查步骤**：
```yaml
# 1. 打印环境变量（调试用）
- name: Debug
  run: |
    echo "MY_VAR: $MY_VAR"
    env | grep MY_VAR

# 2. 检查变量作用域
env:
  GLOBAL_VAR: "global"  # 全局

jobs:
  build:
    env:
      JOB_VAR: "job"  # Job 级别
    steps:
      - name: Step
        env:
          STEP_VAR: "step"  # Step 级别
```

---

## 快速参考

### GitHub Actions 常用语法

```yaml
# 条件执行
if: github.event_name == 'push' && github.ref == 'refs/heads/main'
if: contains(github.event.head_commit.message, '[skip ci]') == false
if: success() || failure()

# 输出变量
- run: echo "version=1.0.0" >> $GITHUB_OUTPUT
  id: vars
- run: echo ${{ steps.vars.outputs.version }}

# 矩阵
strategy:
  matrix:
    node: [16, 18, 20]
    os: [ubuntu-latest, windows-latest]
    exclude:
      - node: 16
        os: windows-latest
```

### kubectl 常用命令

| 命令 | 说明 |
|------|------|
| `kubectl apply -f file.yaml` | 应用配置 |
| `kubectl get pods -n namespace` | 查看 Pod |
| `kubectl logs pod-name` | 查看日志 |
| `kubectl describe pod pod-name` | 查看详情 |
| `kubectl exec -it pod-name -- sh` | 进入容器 |
| `kubectl rollout status deployment/name` | 查看部署状态 |
| `kubectl rollout undo deployment/name` | 回滚部署 |
| `kubectl port-forward pod-name 8080:80` | 端口转发 |

### Docker 常用命令

| 命令 | 说明 |
|------|------|
| `docker build -t name:tag .` | 构建镜像 |
| `docker push name:tag` | 推送镜像 |
| `docker run -d -p 8080:80 name` | 运行容器 |
| `docker logs container-id` | 查看日志 |
| `docker exec -it container-id sh` | 进入容器 |
| `docker system prune -a` | 清理资源 |

---

> 💡 **小贴士**：CI/CD 是一个持续改进的过程，建议从简单的流水线开始，逐步添加测试、安全扫描、多环境部署等功能。保持流水线的可维护性比追求复杂功能更重要。
