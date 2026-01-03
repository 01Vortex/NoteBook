

> Kubernetes（K8s）是一个开源的容器编排平台，用于自动化部署、扩展和管理容器化应用
> 本笔记从零开始，涵盖核心概念、实战配置、常见问题及最佳实践

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [核心资源对象](#3-核心资源对象)
4. [Pod 详解](#4-pod-详解)
5. [工作负载控制器](#5-工作负载控制器)
6. [服务发现与负载均衡](#6-服务发现与负载均衡)
7. [配置管理](#7-配置管理)
8. [存储管理](#8-存储管理)
9. [网络策略](#9-网络策略)
10. [资源调度](#10-资源调度)
11. [自动伸缩](#11-自动伸缩)
12. [安全管理](#12-安全管理)
13. [监控与日志](#13-监控与日志)
14. [Helm 包管理](#14-helm-包管理)
15. [常见错误与解决方案](#15-常见错误与解决方案)
16. [最佳实践总结](#16-最佳实践总结)

---

## 1. 基础概念

### 1.1 什么是 Kubernetes？

Kubernetes（希腊语"舵手"的意思）是 Google 开源的容器编排系统，简称 K8s（K 和 s 之间有 8 个字母）。

**为什么需要 K8s？**

想象你有一个电商网站：
- 双11流量暴增 → 需要快速扩容
- 某台服务器挂了 → 需要自动恢复
- 新版本上线 → 需要平滑升级
- 多个服务通信 → 需要服务发现

手动管理这些太痛苦了，K8s 就是来解决这些问题的！

### 1.2 核心架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Master Node（控制平面）                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │  API Server  │ │  Scheduler   │ │  Controller  │            │
│  │  (入口大门)   │ │  (调度员)    │ │  Manager     │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│  ┌──────────────┐                                              │
│  │    etcd      │  ← 分布式键值存储，保存集群所有数据             │
│  │  (数据库)    │                                              │
│  └──────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ↓                   ↓                   ↓
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Worker Node   │ │   Worker Node   │ │   Worker Node   │
│  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
│  │  kubelet  │  │ │  │  kubelet  │  │ │  │  kubelet  │  │
│  │ (节点代理) │  │ │  │ (节点代理) │  │ │  │ (节点代理) │  │
│  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
│  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
│  │kube-proxy │  │ │  │kube-proxy │  │ │  │kube-proxy │  │
│  │ (网络代理) │  │ │  │ (网络代理) │  │ │  │ (网络代理) │  │
│  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
│  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
│  │ Container │  │ │  │ Container │  │ │  │ Container │  │
│  │  Runtime  │  │ │  │  Runtime  │  │ │  │  Runtime  │  │
│  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 1.3 核心组件说明

| 组件 | 作用 | 类比 |
|------|------|------|
| API Server | 集群的统一入口，所有操作都通过它 | 公司前台 |
| etcd | 存储集群所有配置和状态数据 | 公司档案室 |
| Scheduler | 决定 Pod 运行在哪个节点 | HR分配工位 |
| Controller Manager | 确保集群状态符合预期 | 监工 |
| kubelet | 管理节点上的容器 | 车间主任 |
| kube-proxy | 处理网络规则和负载均衡 | 网管 |

### 1.4 核心概念速览

| 概念 | 说明 | 类比 |
|------|------|------|
| Cluster | 一组节点组成的集群 | 整个公司 |
| Node | 集群中的一台机器 | 一栋办公楼 |
| Pod | 最小部署单元，包含一个或多个容器 | 一个工位 |
| Deployment | 管理 Pod 的副本和更新 | 部门 |
| Service | 为 Pod 提供稳定的访问入口 | 总机号码 |
| Namespace | 资源隔离的虚拟集群 | 不同楼层 |
| ConfigMap | 存储配置信息 | 配置文件柜 |
| Secret | 存储敏感信息 | 保险箱 |
| Volume | 持久化存储 | 文件服务器 |


---

## 2. 环境搭建

### 2.1 本地开发环境选择

| 工具 | 特点 | 适用场景 |
|------|------|----------|
| Minikube | 单节点，功能完整 | 学习、开发 |
| Kind | 用 Docker 容器模拟节点 | CI/CD、测试 |
| Docker Desktop | 内置 K8s，一键启用 | Mac/Windows 开发 |
| k3s | 轻量级，资源占用少 | 边缘计算、IoT |
| MicroK8s | Ubuntu 官方，snap 安装 | Ubuntu 用户 |

### 2.2 Minikube 安装（推荐学习用）

```bash
# Windows (PowerShell 管理员)
choco install minikube

# macOS
brew install minikube

# Linux
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# 启动集群
minikube start --driver=docker --memory=4096 --cpus=2

# 验证安装
minikube status
kubectl cluster-info
```

### 2.3 kubectl 安装与配置

kubectl 是 K8s 的命令行工具，所有操作都通过它完成。

```bash
# Windows
choco install kubernetes-cli

# macOS
brew install kubectl

# Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# 验证
kubectl version --client

# 配置自动补全（强烈推荐）
# Bash
echo 'source <(kubectl completion bash)' >> ~/.bashrc
echo 'alias k=kubectl' >> ~/.bashrc
echo 'complete -o default -F __start_kubectl k' >> ~/.bashrc

# Zsh
echo 'source <(kubectl completion zsh)' >> ~/.zshrc
echo 'alias k=kubectl' >> ~/.zshrc
```

### 2.4 kubectl 常用命令速查

```bash
# 集群信息
kubectl cluster-info                    # 集群信息
kubectl get nodes                       # 查看节点
kubectl get nodes -o wide               # 详细信息

# 资源操作（CRUD）
kubectl create -f xxx.yaml              # 创建资源
kubectl apply -f xxx.yaml               # 创建或更新（推荐）
kubectl get pods                        # 查看 Pod
kubectl get pods -n kube-system         # 指定命名空间
kubectl get all                         # 查看所有资源
kubectl describe pod <pod-name>         # 查看详情
kubectl delete pod <pod-name>           # 删除资源
kubectl delete -f xxx.yaml              # 根据文件删除

# 调试命令
kubectl logs <pod-name>                 # 查看日志
kubectl logs -f <pod-name>              # 实时日志
kubectl logs <pod-name> -c <container>  # 多容器 Pod
kubectl exec -it <pod-name> -- /bin/sh  # 进入容器
kubectl port-forward <pod-name> 8080:80 # 端口转发

# 资源管理
kubectl top nodes                       # 节点资源使用
kubectl top pods                        # Pod 资源使用
kubectl get events                      # 查看事件
kubectl get events --sort-by='.lastTimestamp'  # 按时间排序
```

### 2.5 生产环境部署方式

| 方式 | 说明 | 适用场景 |
|------|------|----------|
| kubeadm | 官方工具，手动部署 | 自建集群 |
| Rancher | 图形化管理平台 | 企业多集群 |
| 云厂商托管 | EKS/AKS/GKE/ACK | 生产环境首选 |

```bash
# kubeadm 初始化集群（Master 节点）
kubeadm init --pod-network-cidr=10.244.0.0/16

# Worker 节点加入集群
kubeadm join <master-ip>:6443 --token <token> --discovery-token-ca-cert-hash <hash>
```

---

## 3. 核心资源对象

### 3.1 资源对象分类

```
┌─────────────────────────────────────────────────────────────┐
│                      K8s 资源对象                            │
├─────────────────────────────────────────────────────────────┤
│  工作负载                                                    │
│  ├── Pod          最小部署单元                               │
│  ├── Deployment   无状态应用部署                             │
│  ├── StatefulSet  有状态应用部署                             │
│  ├── DaemonSet    每个节点运行一个 Pod                       │
│  ├── Job          一次性任务                                 │
│  └── CronJob      定时任务                                   │
├─────────────────────────────────────────────────────────────┤
│  服务发现与负载均衡                                          │
│  ├── Service      服务抽象，提供稳定访问入口                  │
│  ├── Ingress      HTTP/HTTPS 路由                           │
│  └── Endpoints    Service 后端 Pod 列表                      │
├─────────────────────────────────────────────────────────────┤
│  配置与存储                                                  │
│  ├── ConfigMap    配置信息                                   │
│  ├── Secret       敏感信息                                   │
│  ├── PV           持久卷                                     │
│  └── PVC          持久卷声明                                 │
├─────────────────────────────────────────────────────────────┤
│  集群管理                                                    │
│  ├── Namespace    命名空间                                   │
│  ├── Node         节点                                       │
│  ├── ServiceAccount  服务账号                                │
│  ├── Role/ClusterRole  角色                                  │
│  └── RoleBinding/ClusterRoleBinding  角色绑定                │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 YAML 文件基本结构

所有 K8s 资源都用 YAML 文件描述，结构如下：

```yaml
# 必需字段
apiVersion: v1              # API 版本
kind: Pod                   # 资源类型
metadata:                   # 元数据
  name: my-pod              # 资源名称（必需）
  namespace: default        # 命名空间（可选）
  labels:                   # 标签（可选，但强烈推荐）
    app: my-app
    env: production
  annotations:              # 注解（可选）
    description: "这是一个示例 Pod"
spec:                       # 规格（资源的具体配置）
  # 具体内容因资源类型而异
```

### 3.3 Namespace 命名空间

命名空间用于资源隔离，类似于文件夹。

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: development
  labels:
    env: dev
---
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    env: prod
```

```bash
# 创建命名空间
kubectl create namespace development
kubectl apply -f namespace.yaml

# 查看命名空间
kubectl get namespaces
kubectl get ns  # 简写

# 在指定命名空间操作
kubectl get pods -n development
kubectl get pods --all-namespaces  # 所有命名空间
kubectl get pods -A                 # 简写

# 设置默认命名空间
kubectl config set-context --current --namespace=development
```

**默认命名空间**：
- `default`：默认命名空间
- `kube-system`：K8s 系统组件
- `kube-public`：公开资源
- `kube-node-lease`：节点心跳

---

## 4. Pod 详解

### 4.1 什么是 Pod？

Pod 是 K8s 最小的部署单元，可以包含一个或多个容器。同一个 Pod 中的容器：
- 共享网络（可以用 localhost 通信）
- 共享存储卷
- 共享 IPC 命名空间

**什么时候用多容器 Pod？**
- Sidecar 模式：日志收集、代理
- Ambassador 模式：代理外部服务
- Adapter 模式：数据格式转换

### 4.2 Pod 基础配置

```yaml
# pod-basic.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  labels:
    app: nginx
    tier: frontend
spec:
  containers:
  - name: nginx
    image: nginx:1.21
    ports:
    - containerPort: 80
      name: http
    # 资源限制（生产环境必须配置！）
    resources:
      requests:           # 最小需求
        memory: "64Mi"
        cpu: "250m"       # 0.25 核
      limits:             # 最大限制
        memory: "128Mi"
        cpu: "500m"       # 0.5 核
```

```bash
# 创建 Pod
kubectl apply -f pod-basic.yaml

# 查看 Pod
kubectl get pods
kubectl get pods -o wide  # 显示 IP 和节点

# 查看 Pod 详情
kubectl describe pod nginx-pod

# 查看日志
kubectl logs nginx-pod

# 进入容器
kubectl exec -it nginx-pod -- /bin/bash

# 删除 Pod
kubectl delete pod nginx-pod
```


### 4.3 Pod 生命周期

```
┌─────────────────────────────────────────────────────────────┐
│                      Pod 生命周期                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Pending → Running → Succeeded/Failed                       │
│     ↓         ↓                                             │
│  (调度中)  (运行中)                                          │
│                                                             │
│  状态说明：                                                  │
│  - Pending:   等待调度或拉取镜像                             │
│  - Running:   至少一个容器在运行                             │
│  - Succeeded: 所有容器成功终止（Job）                        │
│  - Failed:    至少一个容器失败终止                           │
│  - Unknown:   无法获取状态（通常是节点问题）                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.4 容器探针（健康检查）

探针是 K8s 检查容器健康状态的机制，非常重要！

```yaml
# pod-probes.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-probes
spec:
  containers:
  - name: app
    image: my-app:1.0
    ports:
    - containerPort: 8080
    
    # 存活探针：检查容器是否存活，失败则重启容器
    livenessProbe:
      httpGet:
        path: /health/live
        port: 8080
      initialDelaySeconds: 30    # 容器启动后等待时间
      periodSeconds: 10          # 检查间隔
      timeoutSeconds: 5          # 超时时间
      failureThreshold: 3        # 失败几次后重启
      successThreshold: 1        # 成功几次后认为健康
    
    # 就绪探针：检查容器是否准备好接收流量
    readinessProbe:
      httpGet:
        path: /health/ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
      failureThreshold: 3
    
    # 启动探针：检查容器是否启动完成（K8s 1.16+）
    # 启动探针成功前，存活和就绪探针不会执行
    startupProbe:
      httpGet:
        path: /health/startup
        port: 8080
      initialDelaySeconds: 0
      periodSeconds: 10
      failureThreshold: 30       # 最多等待 300 秒启动
```

**探针类型**：

```yaml
# 1. HTTP 探针（最常用）
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
    httpHeaders:
    - name: Custom-Header
      value: Awesome

# 2. TCP 探针（检查端口是否可连接）
livenessProbe:
  tcpSocket:
    port: 3306

# 3. 命令探针（执行命令，返回 0 表示健康）
livenessProbe:
  exec:
    command:
    - cat
    - /tmp/healthy

# 4. gRPC 探针（K8s 1.24+）
livenessProbe:
  grpc:
    port: 50051
```

### 4.5 Init 容器

Init 容器在主容器启动前运行，用于初始化工作。

```yaml
# pod-init.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-init
spec:
  # Init 容器按顺序执行，全部成功后才启动主容器
  initContainers:
  - name: init-db
    image: busybox:1.28
    command: ['sh', '-c', 'until nc -z mysql-service 3306; do echo waiting for mysql; sleep 2; done']
  
  - name: init-config
    image: busybox:1.28
    command: ['sh', '-c', 'wget -O /config/app.conf http://config-server/app.conf']
    volumeMounts:
    - name: config-volume
      mountPath: /config
  
  containers:
  - name: app
    image: my-app:1.0
    volumeMounts:
    - name: config-volume
      mountPath: /app/config
  
  volumes:
  - name: config-volume
    emptyDir: {}
```

### 4.6 多容器 Pod 模式

```yaml
# pod-sidecar.yaml - Sidecar 模式示例
apiVersion: v1
kind: Pod
metadata:
  name: app-with-sidecar
spec:
  containers:
  # 主容器
  - name: app
    image: my-app:1.0
    volumeMounts:
    - name: logs
      mountPath: /var/log/app
  
  # Sidecar 容器：收集日志
  - name: log-collector
    image: fluentd:latest
    volumeMounts:
    - name: logs
      mountPath: /var/log/app
      readOnly: true
  
  volumes:
  - name: logs
    emptyDir: {}
```

### 4.7 Pod 重启策略

```yaml
spec:
  restartPolicy: Always    # 默认值，总是重启
  # restartPolicy: OnFailure  # 失败时重启（适合 Job）
  # restartPolicy: Never      # 从不重启
```

---

## 5. 工作负载控制器

直接创建 Pod 有个问题：Pod 挂了不会自动恢复。所以我们需要控制器来管理 Pod。

### 5.1 Deployment（最常用）

Deployment 用于管理无状态应用，支持滚动更新、回滚等功能。

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3                    # 副本数
  selector:                      # 选择器，匹配 Pod
    matchLabels:
      app: nginx
  
  # 更新策略
  strategy:
    type: RollingUpdate          # 滚动更新（默认）
    rollingUpdate:
      maxSurge: 1                # 更新时最多多出 1 个 Pod
      maxUnavailable: 0          # 更新时最少可用 Pod 数
  
  # Pod 模板
  template:
    metadata:
      labels:
        app: nginx               # 必须与 selector 匹配
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 10
          periodSeconds: 5
        readinessProbe:
          httpGet:
            path: /
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 3
```

```bash
# 创建 Deployment
kubectl apply -f deployment.yaml

# 查看 Deployment
kubectl get deployments
kubectl get deploy  # 简写

# 查看 ReplicaSet（Deployment 创建的）
kubectl get replicasets
kubectl get rs

# 查看 Pod
kubectl get pods -l app=nginx

# 扩缩容
kubectl scale deployment nginx-deployment --replicas=5

# 更新镜像（触发滚动更新）
kubectl set image deployment/nginx-deployment nginx=nginx:1.22

# 查看更新状态
kubectl rollout status deployment/nginx-deployment

# 查看更新历史
kubectl rollout history deployment/nginx-deployment

# 回滚到上一版本
kubectl rollout undo deployment/nginx-deployment

# 回滚到指定版本
kubectl rollout undo deployment/nginx-deployment --to-revision=2

# 暂停/恢复更新
kubectl rollout pause deployment/nginx-deployment
kubectl rollout resume deployment/nginx-deployment
```

### 5.2 StatefulSet（有状态应用）

StatefulSet 用于管理有状态应用，如数据库、消息队列等。

**特点**：
- Pod 有固定的名称（pod-0, pod-1, pod-2）
- 有序部署和删除
- 稳定的网络标识
- 稳定的持久化存储

```yaml
# statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql
spec:
  serviceName: mysql-headless    # 必须关联 Headless Service
  replicas: 3
  selector:
    matchLabels:
      app: mysql
  
  template:
    metadata:
      labels:
        app: mysql
    spec:
      containers:
      - name: mysql
        image: mysql:8.0
        ports:
        - containerPort: 3306
        env:
        - name: MYSQL_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mysql-secret
              key: password
        volumeMounts:
        - name: data
          mountPath: /var/lib/mysql
  
  # 卷声明模板（每个 Pod 自动创建 PVC）
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: standard
      resources:
        requests:
          storage: 10Gi

---
# Headless Service（无 ClusterIP）
apiVersion: v1
kind: Service
metadata:
  name: mysql-headless
spec:
  clusterIP: None              # Headless Service
  selector:
    app: mysql
  ports:
  - port: 3306
```

```bash
# Pod 名称固定
mysql-0, mysql-1, mysql-2

# DNS 名称
mysql-0.mysql-headless.default.svc.cluster.local
mysql-1.mysql-headless.default.svc.cluster.local
```


### 5.3 DaemonSet（每个节点一个）

DaemonSet 确保每个节点运行一个 Pod 副本，常用于：
- 日志收集（Fluentd、Filebeat）
- 监控代理（Prometheus Node Exporter）
- 网络插件（Calico、Flannel）

```yaml
# daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: fluentd
  template:
    metadata:
      labels:
        app: fluentd
    spec:
      tolerations:                    # 容忍污点，可以调度到 Master 节点
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: fluentd
        image: fluentd:v1.14
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: containers
          mountPath: /var/lib/docker/containers
          readOnly: true
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: containers
        hostPath:
          path: /var/lib/docker/containers
```

### 5.4 Job（一次性任务）

```yaml
# job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: data-migration
spec:
  completions: 1              # 需要成功完成的 Pod 数
  parallelism: 1              # 并行运行的 Pod 数
  backoffLimit: 3             # 失败重试次数
  activeDeadlineSeconds: 600  # 超时时间（秒）
  ttlSecondsAfterFinished: 100  # 完成后自动删除
  
  template:
    spec:
      restartPolicy: Never    # Job 必须是 Never 或 OnFailure
      containers:
      - name: migration
        image: my-migration:1.0
        command: ["python", "migrate.py"]
        env:
        - name: DB_HOST
          value: "mysql-service"
```

```bash
# 查看 Job
kubectl get jobs

# 查看 Job 的 Pod
kubectl get pods -l job-name=data-migration

# 查看日志
kubectl logs job/data-migration
```

### 5.5 CronJob（定时任务）

```yaml
# cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-job
spec:
  schedule: "0 2 * * *"       # Cron 表达式：每天凌晨 2 点
  concurrencyPolicy: Forbid   # 禁止并发执行
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  startingDeadlineSeconds: 200  # 错过调度的截止时间
  
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: backup
            image: backup-tool:1.0
            command: ["/bin/sh", "-c", "backup.sh"]
```

**Cron 表达式**：
```
┌───────────── 分钟 (0 - 59)
│ ┌───────────── 小时 (0 - 23)
│ │ ┌───────────── 日 (1 - 31)
│ │ │ ┌───────────── 月 (1 - 12)
│ │ │ │ ┌───────────── 星期 (0 - 6)
│ │ │ │ │
* * * * *

示例：
"0 * * * *"      每小时
"0 0 * * *"      每天午夜
"0 0 * * 0"      每周日午夜
"0 0 1 * *"      每月 1 号
"*/15 * * * *"   每 15 分钟
```

---

## 6. 服务发现与负载均衡

### 6.1 Service 概述

Pod 的 IP 是不固定的，重启后会变化。Service 提供稳定的访问入口。

```
┌─────────────────────────────────────────────────────────────┐
│                      Service 类型                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ClusterIP (默认)                                           │
│  └── 集群内部访问，分配虚拟 IP                               │
│                                                             │
│  NodePort                                                   │
│  └── 在每个节点开放端口，外部可访问                          │
│                                                             │
│  LoadBalancer                                               │
│  └── 云厂商负载均衡器，自动分配外部 IP                       │
│                                                             │
│  ExternalName                                               │
│  └── 映射到外部 DNS 名称                                    │
│                                                             │
│  Headless (clusterIP: None)                                 │
│  └── 不分配 IP，直接返回 Pod IP 列表                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 ClusterIP Service

```yaml
# service-clusterip.yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP              # 默认类型
  selector:
    app: my-app                # 选择后端 Pod
  ports:
  - name: http
    port: 80                   # Service 端口
    targetPort: 8080           # Pod 端口
    protocol: TCP
  - name: https
    port: 443
    targetPort: 8443
```

```bash
# 集群内访问方式
# 1. Service 名称（同命名空间）
curl http://my-service

# 2. 完整 DNS 名称
curl http://my-service.default.svc.cluster.local

# 3. ClusterIP
curl http://10.96.0.100
```

### 6.3 NodePort Service

```yaml
# service-nodeport.yaml
apiVersion: v1
kind: Service
metadata:
  name: my-nodeport-service
spec:
  type: NodePort
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 30080            # 节点端口（30000-32767）
```

```bash
# 外部访问
curl http://<node-ip>:30080
```

### 6.4 LoadBalancer Service

```yaml
# service-loadbalancer.yaml
apiVersion: v1
kind: Service
metadata:
  name: my-lb-service
  annotations:
    # 云厂商特定注解
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
spec:
  type: LoadBalancer
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 8080
  # 可选：指定负载均衡器 IP
  # loadBalancerIP: 1.2.3.4
```

### 6.5 Headless Service

```yaml
# service-headless.yaml
apiVersion: v1
kind: Service
metadata:
  name: my-headless-service
spec:
  clusterIP: None              # Headless
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 8080
```

```bash
# DNS 查询返回所有 Pod IP
nslookup my-headless-service
# 返回：
# 10.244.1.10
# 10.244.2.11
# 10.244.3.12
```

### 6.6 Ingress（HTTP 路由）

Ingress 是 K8s 的 HTTP/HTTPS 路由规则，需要 Ingress Controller 支持。

```bash
# 安装 Nginx Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.0/deploy/static/provider/cloud/deploy.yaml
```

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  
  # TLS 配置
  tls:
  - hosts:
    - example.com
    - api.example.com
    secretName: tls-secret
  
  rules:
  # 基于域名路由
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: backend-service
            port:
              number: 8080
  
  # 另一个域名
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-service
            port:
              number: 80
```

**pathType 说明**：
- `Exact`：精确匹配
- `Prefix`：前缀匹配
- `ImplementationSpecific`：由 Ingress Controller 决定


---

## 7. 配置管理

### 7.1 ConfigMap

ConfigMap 用于存储非敏感配置信息。

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  # 简单键值对
  DATABASE_HOST: "mysql-service"
  DATABASE_PORT: "3306"
  LOG_LEVEL: "INFO"
  
  # 配置文件内容
  application.properties: |
    server.port=8080
    spring.datasource.url=jdbc:mysql://mysql-service:3306/mydb
    spring.datasource.username=root
    logging.level.root=INFO
  
  nginx.conf: |
    server {
        listen 80;
        server_name localhost;
        location / {
            proxy_pass http://backend:8080;
        }
    }
```

```bash
# 从命令行创建
kubectl create configmap app-config \
  --from-literal=DATABASE_HOST=mysql-service \
  --from-literal=DATABASE_PORT=3306

# 从文件创建
kubectl create configmap app-config \
  --from-file=application.properties \
  --from-file=nginx.conf

# 从目录创建
kubectl create configmap app-config --from-file=./config/
```

**使用 ConfigMap**：

```yaml
# pod-with-configmap.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
  - name: app
    image: my-app:1.0
    
    # 方式1：环境变量（单个值）
    env:
    - name: DB_HOST
      valueFrom:
        configMapKeyRef:
          name: app-config
          key: DATABASE_HOST
    
    # 方式2：环境变量（所有值）
    envFrom:
    - configMapRef:
        name: app-config
    
    # 方式3：挂载为文件
    volumeMounts:
    - name: config-volume
      mountPath: /etc/config
      readOnly: true
    
    # 方式4：挂载单个文件
    - name: nginx-config
      mountPath: /etc/nginx/nginx.conf
      subPath: nginx.conf
  
  volumes:
  - name: config-volume
    configMap:
      name: app-config
  - name: nginx-config
    configMap:
      name: app-config
      items:
      - key: nginx.conf
        path: nginx.conf
```

### 7.2 Secret

Secret 用于存储敏感信息，如密码、Token、证书等。

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
type: Opaque                   # 通用类型
data:
  # 值必须是 Base64 编码
  username: YWRtaW4=           # echo -n 'admin' | base64
  password: cGFzc3dvcmQxMjM=   # echo -n 'password123' | base64

---
# 使用 stringData 可以直接写明文（K8s 会自动编码）
apiVersion: v1
kind: Secret
metadata:
  name: db-secret-plain
type: Opaque
stringData:
  username: admin
  password: password123
```

**Secret 类型**：

```yaml
# 1. Opaque（通用）
type: Opaque

# 2. Docker 镜像仓库凭证
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded-docker-config>

# 3. TLS 证书
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>

# 4. Basic Auth
type: kubernetes.io/basic-auth
stringData:
  username: admin
  password: password123

# 5. SSH 密钥
type: kubernetes.io/ssh-auth
data:
  ssh-privatekey: <base64-encoded-key>
```

```bash
# 创建 Docker 镜像仓库凭证
kubectl create secret docker-registry my-registry \
  --docker-server=registry.example.com \
  --docker-username=user \
  --docker-password=password \
  --docker-email=user@example.com

# 创建 TLS 证书
kubectl create secret tls tls-secret \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key

# 创建通用 Secret
kubectl create secret generic db-secret \
  --from-literal=username=admin \
  --from-literal=password=password123
```

**使用 Secret**：

```yaml
# pod-with-secret.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
  - name: app
    image: my-app:1.0
    
    # 环境变量
    env:
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: username
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
    
    # 挂载为文件
    volumeMounts:
    - name: secret-volume
      mountPath: /etc/secrets
      readOnly: true
  
  # 使用镜像仓库凭证
  imagePullSecrets:
  - name: my-registry
  
  volumes:
  - name: secret-volume
    secret:
      secretName: db-secret
      defaultMode: 0400        # 文件权限
```

### 7.3 配置热更新

ConfigMap 和 Secret 更新后，挂载为文件的方式会自动更新（有延迟），但环境变量不会自动更新。

```yaml
# 使用 Reloader 实现自动重启
# 安装：kubectl apply -f https://raw.githubusercontent.com/stakater/Reloader/master/deployments/kubernetes/reloader.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  annotations:
    # 当 ConfigMap 变化时自动重启
    configmap.reloader.stakater.com/reload: "app-config"
    # 当 Secret 变化时自动重启
    secret.reloader.stakater.com/reload: "db-secret"
spec:
  # ...
```

---

## 8. 存储管理

### 8.1 Volume 类型概览

```
┌─────────────────────────────────────────────────────────────┐
│                      Volume 类型                             │
├─────────────────────────────────────────────────────────────┤
│  临时存储                                                    │
│  ├── emptyDir      Pod 生命周期内的临时存储                  │
│  └── configMap/secret  配置数据                             │
├─────────────────────────────────────────────────────────────┤
│  节点存储                                                    │
│  ├── hostPath      节点本地路径（不推荐生产使用）            │
│  └── local         本地持久卷                               │
├─────────────────────────────────────────────────────────────┤
│  网络存储                                                    │
│  ├── nfs           NFS 共享存储                             │
│  ├── cephfs        Ceph 文件系统                            │
│  ├── glusterfs     GlusterFS                                │
│  └── iscsi         iSCSI 存储                               │
├─────────────────────────────────────────────────────────────┤
│  云存储                                                      │
│  ├── awsElasticBlockStore  AWS EBS                          │
│  ├── azureDisk     Azure Disk                               │
│  ├── gcePersistentDisk  GCE PD                              │
│  └── csi           容器存储接口（推荐）                      │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 emptyDir（临时存储）

```yaml
# pod-emptydir.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-cache
spec:
  containers:
  - name: app
    image: my-app:1.0
    volumeMounts:
    - name: cache-volume
      mountPath: /cache
    - name: shared-data
      mountPath: /data
  
  - name: sidecar
    image: sidecar:1.0
    volumeMounts:
    - name: shared-data
      mountPath: /data
  
  volumes:
  - name: cache-volume
    emptyDir:
      sizeLimit: 500Mi         # 大小限制
  - name: shared-data
    emptyDir: {}               # 默认使用节点磁盘
  - name: memory-volume
    emptyDir:
      medium: Memory           # 使用内存（tmpfs）
      sizeLimit: 100Mi
```

### 8.3 hostPath（节点路径）

```yaml
# pod-hostpath.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-hostpath
spec:
  containers:
  - name: app
    image: my-app:1.0
    volumeMounts:
    - name: host-data
      mountPath: /data
  
  volumes:
  - name: host-data
    hostPath:
      path: /data/app          # 节点路径
      type: DirectoryOrCreate  # 类型
      # type 可选值：
      # DirectoryOrCreate - 目录不存在则创建
      # Directory - 必须存在的目录
      # FileOrCreate - 文件不存在则创建
      # File - 必须存在的文件
      # Socket - Unix Socket
      # CharDevice - 字符设备
      # BlockDevice - 块设备
```

**⚠️ 警告**：hostPath 有安全风险，不推荐在生产环境使用！


### 8.4 PV 和 PVC（持久化存储）

PV（PersistentVolume）是集群级别的存储资源，PVC（PersistentVolumeClaim）是用户对存储的请求。

```
用户 → PVC（我需要 10G 存储）→ K8s 匹配 → PV（实际存储）→ 底层存储
```

```yaml
# pv.yaml - 管理员创建
apiVersion: v1
kind: PersistentVolume
metadata:
  name: pv-nfs-01
  labels:
    type: nfs
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteMany           # 多节点读写
  persistentVolumeReclaimPolicy: Retain  # 回收策略
  storageClassName: nfs-storage
  nfs:
    server: 192.168.1.100
    path: /data/k8s/pv01

---
# pvc.yaml - 用户创建
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-pvc
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 5Gi
  storageClassName: nfs-storage
  selector:                    # 可选：选择特定 PV
    matchLabels:
      type: nfs
```

**访问模式**：
- `ReadWriteOnce (RWO)`：单节点读写
- `ReadOnlyMany (ROX)`：多节点只读
- `ReadWriteMany (RWX)`：多节点读写
- `ReadWriteOncePod (RWOP)`：单 Pod 读写（K8s 1.22+）

**回收策略**：
- `Retain`：保留数据，手动清理
- `Delete`：自动删除底层存储
- `Recycle`：已废弃

```yaml
# 在 Pod 中使用 PVC
apiVersion: v1
kind: Pod
metadata:
  name: app-with-pvc
spec:
  containers:
  - name: app
    image: my-app:1.0
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: my-pvc
```

### 8.5 StorageClass（动态存储）

StorageClass 实现动态创建 PV，无需管理员手动创建。

```yaml
# storageclass.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-storage
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"  # 设为默认
provisioner: kubernetes.io/aws-ebs    # 存储提供者
parameters:
  type: gp3
  iopsPerGB: "10"
  fsType: ext4
reclaimPolicy: Delete
allowVolumeExpansion: true            # 允许扩容
volumeBindingMode: WaitForFirstConsumer  # 延迟绑定

---
# 使用 StorageClass 的 PVC
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: dynamic-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-storage      # 指定 StorageClass
  resources:
    requests:
      storage: 20Gi
```

### 8.6 常用存储方案

```yaml
# NFS StorageClass（需要 NFS Provisioner）
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-storage
provisioner: nfs-subdir-external-provisioner
parameters:
  archiveOnDelete: "false"

---
# 本地存储 StorageClass
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: local-storage
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer

---
# 本地 PV
apiVersion: v1
kind: PersistentVolume
metadata:
  name: local-pv
spec:
  capacity:
    storage: 100Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: local-storage
  local:
    path: /mnt/disks/ssd1
  nodeAffinity:                       # 必须指定节点
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: kubernetes.io/hostname
          operator: In
          values:
          - node-1
```

---

## 9. 网络策略

NetworkPolicy 用于控制 Pod 之间的网络流量，实现网络隔离。

### 9.1 默认策略

```yaml
# 默认拒绝所有入站流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}              # 选择所有 Pod
  policyTypes:
  - Ingress                    # 只限制入站

---
# 默认拒绝所有出站流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress

---
# 默认拒绝所有流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### 9.2 允许特定流量

```yaml
# networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-network-policy
  namespace: production
spec:
  # 应用到哪些 Pod
  podSelector:
    matchLabels:
      app: api-server
  
  policyTypes:
  - Ingress
  - Egress
  
  # 入站规则
  ingress:
  # 规则1：允许来自 frontend 的流量
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  
  # 规则2：允许来自特定命名空间的流量
  - from:
    - namespaceSelector:
        matchLabels:
          env: production
      podSelector:
        matchLabels:
          app: monitoring
    ports:
    - protocol: TCP
      port: 9090
  
  # 规则3：允许来自特定 IP 段的流量
  - from:
    - ipBlock:
        cidr: 10.0.0.0/8
        except:
        - 10.0.1.0/24
    ports:
    - protocol: TCP
      port: 443
  
  # 出站规则
  egress:
  # 允许访问数据库
  - to:
    - podSelector:
        matchLabels:
          app: mysql
    ports:
    - protocol: TCP
      port: 3306
  
  # 允许 DNS 查询
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  
  # 允许访问外部 API
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443
```

---

## 10. 资源调度

### 10.1 节点选择器

```yaml
# 简单节点选择
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod
spec:
  nodeSelector:
    gpu: "true"                # 选择有 gpu=true 标签的节点
    disktype: ssd
  containers:
  - name: gpu-app
    image: gpu-app:1.0
```

```bash
# 给节点添加标签
kubectl label nodes node-1 gpu=true
kubectl label nodes node-1 disktype=ssd

# 查看节点标签
kubectl get nodes --show-labels
```

### 10.2 节点亲和性（Node Affinity）

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-affinity
spec:
  affinity:
    nodeAffinity:
      # 硬性要求（必须满足）
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: kubernetes.io/os
            operator: In
            values:
            - linux
          - key: node-type
            operator: In
            values:
            - compute
            - gpu
      
      # 软性偏好（尽量满足）
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 80              # 权重 1-100
        preference:
          matchExpressions:
          - key: zone
            operator: In
            values:
            - zone-a
      - weight: 20
        preference:
          matchExpressions:
          - key: zone
            operator: In
            values:
            - zone-b
  
  containers:
  - name: app
    image: my-app:1.0
```

**操作符**：
- `In`：值在列表中
- `NotIn`：值不在列表中
- `Exists`：标签存在
- `DoesNotExist`：标签不存在
- `Gt`：大于
- `Lt`：小于


### 10.3 Pod 亲和性与反亲和性

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      affinity:
        # Pod 亲和性：希望和某些 Pod 在一起
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - cache
            topologyKey: kubernetes.io/hostname  # 同一节点
        
        # Pod 反亲和性：不希望和某些 Pod 在一起
        podAntiAffinity:
          # 硬性要求：同一应用的 Pod 分散到不同节点
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - web
            topologyKey: kubernetes.io/hostname
          
          # 软性偏好：尽量分散到不同可用区
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - web
              topologyKey: topology.kubernetes.io/zone
      
      containers:
      - name: web
        image: nginx:1.21
```

### 10.4 污点和容忍（Taints & Tolerations）

污点用于排斥 Pod，容忍用于允许 Pod 调度到有污点的节点。

```bash
# 给节点添加污点
kubectl taint nodes node-1 key=value:NoSchedule
kubectl taint nodes node-1 dedicated=gpu:NoExecute

# 查看节点污点
kubectl describe node node-1 | grep Taints

# 删除污点
kubectl taint nodes node-1 key:NoSchedule-
```

**污点效果**：
- `NoSchedule`：不调度新 Pod
- `PreferNoSchedule`：尽量不调度
- `NoExecute`：不调度且驱逐现有 Pod

```yaml
# Pod 容忍污点
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod
spec:
  tolerations:
  # 容忍特定污点
  - key: "dedicated"
    operator: "Equal"
    value: "gpu"
    effect: "NoSchedule"
  
  # 容忍所有 NoExecute 污点（300秒后被驱逐）
  - key: "node.kubernetes.io/not-ready"
    operator: "Exists"
    effect: "NoExecute"
    tolerationSeconds: 300
  
  # 容忍所有污点（慎用！）
  # - operator: "Exists"
  
  containers:
  - name: gpu-app
    image: gpu-app:1.0
```

### 10.5 资源配额（ResourceQuota）

```yaml
# resourcequota.yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: development
spec:
  hard:
    # 计算资源
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    
    # 对象数量
    pods: "50"
    services: "10"
    secrets: "20"
    configmaps: "20"
    persistentvolumeclaims: "10"
    
    # 存储
    requests.storage: 100Gi

---
# LimitRange：设置默认资源限制
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: development
spec:
  limits:
  - type: Container
    default:              # 默认 limits
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:       # 默认 requests
      cpu: "100m"
      memory: "128Mi"
    max:                  # 最大值
      cpu: "2"
      memory: "4Gi"
    min:                  # 最小值
      cpu: "50m"
      memory: "64Mi"
  - type: PersistentVolumeClaim
    max:
      storage: 50Gi
    min:
      storage: 1Gi
```

---

## 11. 自动伸缩

### 11.1 HPA（水平 Pod 自动伸缩）

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-deployment
  
  minReplicas: 2
  maxReplicas: 10
  
  metrics:
  # CPU 使用率
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  
  # 内存使用率
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  
  # 自定义指标（需要 Prometheus Adapter）
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: 1000
  
  # 外部指标
  - type: External
    external:
      metric:
        name: queue_messages_ready
        selector:
          matchLabels:
            queue: worker-queue
      target:
        type: AverageValue
        averageValue: 30
  
  # 伸缩行为
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300  # 缩容稳定窗口
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

```bash
# 命令行创建 HPA
kubectl autoscale deployment web-deployment \
  --cpu-percent=70 \
  --min=2 \
  --max=10

# 查看 HPA
kubectl get hpa
kubectl describe hpa web-hpa

# 查看 HPA 事件
kubectl get events --field-selector involvedObject.name=web-hpa
```

### 11.2 VPA（垂直 Pod 自动伸缩）

VPA 自动调整 Pod 的资源请求和限制。

```yaml
# vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: web-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-deployment
  
  updatePolicy:
    updateMode: "Auto"         # Auto/Off/Initial
  
  resourcePolicy:
    containerPolicies:
    - containerName: web
      minAllowed:
        cpu: 100m
        memory: 128Mi
      maxAllowed:
        cpu: 2
        memory: 4Gi
      controlledResources: ["cpu", "memory"]
```

### 11.3 Cluster Autoscaler（集群自动伸缩）

Cluster Autoscaler 自动调整集群节点数量。

```yaml
# 云厂商配置示例（AWS）
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-autoscaler
  template:
    metadata:
      labels:
        app: cluster-autoscaler
    spec:
      serviceAccountName: cluster-autoscaler
      containers:
      - name: cluster-autoscaler
        image: k8s.gcr.io/autoscaling/cluster-autoscaler:v1.26.0
        command:
        - ./cluster-autoscaler
        - --v=4
        - --cloud-provider=aws
        - --skip-nodes-with-local-storage=false
        - --expander=least-waste
        - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/my-cluster
        - --balance-similar-node-groups
        - --scale-down-enabled=true
        - --scale-down-delay-after-add=10m
        - --scale-down-unneeded-time=10m
```

---

## 12. 安全管理

### 12.1 RBAC（基于角色的访问控制）

```yaml
# 1. ServiceAccount - 服务账号
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: production

---
# 2. Role - 命名空间级别角色
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: production
rules:
- apiGroups: [""]              # 核心 API 组
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]

---
# 3. RoleBinding - 绑定角色到用户/服务账号
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-service-account
  namespace: production
- kind: User
  name: developer
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: dev-team
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io

---
# 4. ClusterRole - 集群级别角色
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list"]

---
# 5. ClusterRoleBinding - 集群级别绑定
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-secrets-global
subjects:
- kind: ServiceAccount
  name: monitoring-sa
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

**常用 verbs**：
- `get`：获取单个资源
- `list`：列出资源
- `watch`：监听变化
- `create`：创建
- `update`：更新
- `patch`：部分更新
- `delete`：删除
- `deletecollection`：批量删除


### 12.2 Pod 安全策略

```yaml
# pod-security.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  # Pod 级别安全上下文
  securityContext:
    runAsUser: 1000              # 运行用户 ID
    runAsGroup: 3000             # 运行组 ID
    fsGroup: 2000                # 文件系统组
    runAsNonRoot: true           # 禁止 root 运行
    seccompProfile:
      type: RuntimeDefault
  
  containers:
  - name: app
    image: my-app:1.0
    
    # 容器级别安全上下文
    securityContext:
      allowPrivilegeEscalation: false  # 禁止提权
      readOnlyRootFilesystem: true     # 只读根文件系统
      capabilities:
        drop:
        - ALL                          # 删除所有能力
        add:
        - NET_BIND_SERVICE             # 只添加需要的
      privileged: false                # 非特权模式
    
    # 只读文件系统需要挂载可写目录
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /var/cache
  
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

### 12.3 Pod Security Standards（K8s 1.25+）

```yaml
# 命名空间级别的安全策略
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    # 强制执行 restricted 策略
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    
    # 警告 baseline 违规
    pod-security.kubernetes.io/warn: baseline
    pod-security.kubernetes.io/warn-version: latest
    
    # 审计 privileged 违规
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/audit-version: latest
```

**安全级别**：
- `privileged`：无限制
- `baseline`：最小限制，防止已知提权
- `restricted`：严格限制，最佳实践

### 12.4 网络安全

```yaml
# 限制 Pod 只能访问特定外部服务
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-external
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  # 允许 DNS
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  # 允许访问特定外部 IP
  - to:
    - ipBlock:
        cidr: 203.0.113.0/24
    ports:
    - protocol: TCP
      port: 443
```

---

## 13. 监控与日志

### 13.1 Metrics Server

```bash
# 安装 Metrics Server
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# 查看资源使用
kubectl top nodes
kubectl top pods
kubectl top pods --containers
```

### 13.2 Prometheus + Grafana

```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    
    scrape_configs:
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
```

```yaml
# 应用添加 Prometheus 注解
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    metadata:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: app
        image: my-app:1.0
        ports:
        - containerPort: 8080
```

### 13.3 日志收集（EFK Stack）

```yaml
# fluentd-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: logging
spec:
  selector:
    matchLabels:
      app: fluentd
  template:
    metadata:
      labels:
        app: fluentd
    spec:
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1.14-debian-elasticsearch7-1
        env:
        - name: FLUENT_ELASTICSEARCH_HOST
          value: "elasticsearch.logging.svc.cluster.local"
        - name: FLUENT_ELASTICSEARCH_PORT
          value: "9200"
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: containers
          mountPath: /var/lib/docker/containers
          readOnly: true
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: containers
        hostPath:
          path: /var/lib/docker/containers
```

### 13.4 应用日志最佳实践

```yaml
# 日志输出到 stdout/stderr
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: my-app:1.0
        # 应用日志输出到 stdout
        command: ["/bin/sh", "-c"]
        args:
        - |
          # 将日志文件软链接到 stdout
          ln -sf /dev/stdout /var/log/app/access.log
          ln -sf /dev/stderr /var/log/app/error.log
          exec /app/start.sh
```

---

## 14. Helm 包管理

Helm 是 K8s 的包管理工具，类似于 apt/yum。

### 14.1 安装 Helm

```bash
# Windows
choco install kubernetes-helm

# macOS
brew install helm

# Linux
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# 验证
helm version
```

### 14.2 基本使用

```bash
# 添加仓库
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add stable https://charts.helm.sh/stable
helm repo update

# 搜索 Chart
helm search repo nginx
helm search hub wordpress

# 安装 Chart
helm install my-nginx bitnami/nginx
helm install my-nginx bitnami/nginx -n production --create-namespace

# 自定义配置安装
helm install my-nginx bitnami/nginx -f values.yaml
helm install my-nginx bitnami/nginx --set service.type=NodePort

# 查看已安装
helm list
helm list -A  # 所有命名空间

# 查看状态
helm status my-nginx

# 升级
helm upgrade my-nginx bitnami/nginx --set replicaCount=3

# 回滚
helm rollback my-nginx 1

# 卸载
helm uninstall my-nginx
```

### 14.3 创建自己的 Chart

```bash
# 创建 Chart
helm create my-app

# 目录结构
my-app/
├── Chart.yaml          # Chart 元信息
├── values.yaml         # 默认配置值
├── charts/             # 依赖的 Chart
├── templates/          # 模板文件
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   ├── _helpers.tpl    # 模板助手函数
│   └── NOTES.txt       # 安装后提示
└── .helmignore         # 忽略文件
```

```yaml
# Chart.yaml
apiVersion: v2
name: my-app
description: My Application Helm Chart
type: application
version: 0.1.0
appVersion: "1.0.0"
dependencies:
- name: mysql
  version: "9.x.x"
  repository: https://charts.bitnami.com/bitnami
  condition: mysql.enabled
```

```yaml
# values.yaml
replicaCount: 2

image:
  repository: my-app
  tag: "1.0.0"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  className: nginx
  hosts:
  - host: my-app.example.com
    paths:
    - path: /
      pathType: Prefix

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

mysql:
  enabled: true
  auth:
    rootPassword: "secret"
    database: "myapp"
```

```yaml
# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "my-app.fullname" . }}
  labels:
    {{- include "my-app.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
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
        - containerPort: 8080
        resources:
          {{- toYaml .Values.resources | nindent 12 }}
```

```bash
# 验证 Chart
helm lint my-app

# 渲染模板（不安装）
helm template my-app ./my-app

# 打包
helm package my-app

# 安装本地 Chart
helm install my-release ./my-app
```


---

## 15. 常见错误与解决方案

### 15.1 Pod 状态异常

#### ImagePullBackOff / ErrImagePull

```bash
# 错误现象
kubectl get pods
# NAME       READY   STATUS             RESTARTS   AGE
# my-pod     0/1     ImagePullBackOff   0          5m

# 排查步骤
kubectl describe pod my-pod | grep -A 10 Events

# 常见原因及解决
# 1. 镜像名称错误
# 检查 image 字段拼写

# 2. 镜像不存在
docker pull <image-name>  # 本地测试

# 3. 私有仓库认证失败
kubectl create secret docker-registry my-registry \
  --docker-server=registry.example.com \
  --docker-username=user \
  --docker-password=password

# Pod 中使用
spec:
  imagePullSecrets:
  - name: my-registry

# 4. 网络问题
# 检查节点是否能访问镜像仓库
```

#### CrashLoopBackOff

```bash
# 错误现象
kubectl get pods
# NAME       READY   STATUS             RESTARTS   AGE
# my-pod     0/1     CrashLoopBackOff   5          10m

# 排查步骤
# 1. 查看日志
kubectl logs my-pod
kubectl logs my-pod --previous  # 上一次崩溃的日志

# 2. 查看事件
kubectl describe pod my-pod

# 常见原因
# 1. 应用启动失败（配置错误、依赖缺失）
# 2. 健康检查失败
# 3. 资源不足（OOMKilled）
# 4. 命令或参数错误

# 解决：进入容器调试
kubectl run debug --image=<same-image> --rm -it -- /bin/sh
```

#### Pending

```bash
# 错误现象
kubectl get pods
# NAME       READY   STATUS    RESTARTS   AGE
# my-pod     0/1     Pending   0          10m

# 排查
kubectl describe pod my-pod | grep -A 20 Events

# 常见原因
# 1. 资源不足
# Events: 0/3 nodes are available: 3 Insufficient cpu

# 解决：检查资源请求，或扩容节点
kubectl top nodes
kubectl describe node <node-name> | grep -A 10 Allocated

# 2. 节点选择器/亲和性无法满足
# Events: 0/3 nodes are available: 3 node(s) didn't match node selector

# 解决：检查 nodeSelector 和 affinity 配置

# 3. PVC 未绑定
# Events: pod has unbound immediate PersistentVolumeClaims

# 解决：检查 PVC 状态
kubectl get pvc
kubectl describe pvc <pvc-name>

# 4. 污点无法容忍
# Events: 0/3 nodes are available: 3 node(s) had taints that the pod didn't tolerate

# 解决：添加 tolerations 或移除节点污点
```

#### OOMKilled

```bash
# 错误现象
kubectl describe pod my-pod
# Last State: Terminated
# Reason: OOMKilled

# 解决
# 1. 增加内存限制
resources:
  limits:
    memory: "512Mi"  # 增加到合适值
  requests:
    memory: "256Mi"

# 2. 优化应用内存使用
# Java 应用设置堆内存
env:
- name: JAVA_OPTS
  value: "-Xmx384m -Xms256m"
```

### 15.2 Service 访问问题

#### Service 无法访问

```bash
# 排查步骤
# 1. 检查 Service
kubectl get svc my-service
kubectl describe svc my-service

# 2. 检查 Endpoints（是否有后端 Pod）
kubectl get endpoints my-service
# 如果 ENDPOINTS 为空，说明没有匹配的 Pod

# 3. 检查 Pod 标签是否匹配
kubectl get pods --show-labels
kubectl get pods -l app=my-app

# 4. 检查 Pod 是否 Ready
kubectl get pods
# READY 列应该是 1/1

# 5. 测试 Pod 内部访问
kubectl run test --image=busybox --rm -it -- wget -qO- http://my-service

# 常见原因
# 1. selector 与 Pod 标签不匹配
# 2. targetPort 与容器端口不匹配
# 3. Pod 未通过 readinessProbe
```

#### NodePort 无法从外部访问

```bash
# 检查
kubectl get svc my-service
# 确认 TYPE 是 NodePort，记录 NodePort 端口

# 排查
# 1. 检查防火墙规则
# 云环境检查安全组是否开放端口

# 2. 检查 kube-proxy
kubectl get pods -n kube-system | grep kube-proxy
kubectl logs -n kube-system kube-proxy-xxxxx

# 3. 检查节点 IP
kubectl get nodes -o wide
# 使用 INTERNAL-IP 或 EXTERNAL-IP
```

### 15.3 存储问题

#### PVC Pending

```bash
# 错误现象
kubectl get pvc
# NAME     STATUS    VOLUME   CAPACITY   ACCESS MODES   STORAGECLASS   AGE
# my-pvc   Pending                                      standard       5m

# 排查
kubectl describe pvc my-pvc

# 常见原因
# 1. 没有匹配的 PV
# 解决：创建 PV 或使用 StorageClass 动态创建

# 2. StorageClass 不存在
kubectl get storageclass
# 解决：创建 StorageClass 或使用已有的

# 3. 存储配额不足
kubectl describe resourcequota -n <namespace>

# 4. 访问模式不匹配
# PVC 请求 ReadWriteMany，但 PV 只支持 ReadWriteOnce
```

#### Pod 挂载卷失败

```bash
# 错误现象
kubectl describe pod my-pod
# Warning  FailedMount  Unable to attach or mount volumes

# 常见原因
# 1. PVC 未绑定
kubectl get pvc

# 2. 节点无法访问存储
# NFS: 检查 NFS 服务器连通性
# 云存储: 检查节点 IAM 权限

# 3. 卷已被其他 Pod 使用（RWO 模式）
kubectl get pods -o wide  # 检查 Pod 所在节点
```

### 15.4 网络问题

#### DNS 解析失败

```bash
# 测试 DNS
kubectl run test --image=busybox --rm -it -- nslookup kubernetes

# 检查 CoreDNS
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl logs -n kube-system -l k8s-app=kube-dns

# 检查 CoreDNS 配置
kubectl get configmap coredns -n kube-system -o yaml

# 常见原因
# 1. CoreDNS Pod 异常
# 2. 网络策略阻止 DNS 流量
# 3. Pod 的 dnsPolicy 配置错误
```

#### Pod 之间无法通信

```bash
# 测试连通性
kubectl exec -it pod-a -- ping <pod-b-ip>
kubectl exec -it pod-a -- wget -qO- http://<pod-b-ip>:8080

# 检查网络插件
kubectl get pods -n kube-system | grep -E "calico|flannel|weave"

# 检查网络策略
kubectl get networkpolicy -A

# 常见原因
# 1. 网络插件问题
# 2. NetworkPolicy 阻止流量
# 3. 节点防火墙规则
```

### 15.5 权限问题

#### RBAC 权限不足

```bash
# 错误现象
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:my-sa" 
cannot list resource "pods" in API group "" in the namespace "default"

# 排查
# 1. 检查 ServiceAccount
kubectl get sa my-sa

# 2. 检查绑定的角色
kubectl get rolebinding,clusterrolebinding -A | grep my-sa

# 3. 检查角色权限
kubectl describe role <role-name>
kubectl describe clusterrole <role-name>

# 解决：创建正确的 Role 和 RoleBinding
```

#### Pod 无法访问 API Server

```bash
# 测试
kubectl exec -it my-pod -- curl -k https://kubernetes.default.svc/api/v1/namespaces

# 检查 ServiceAccount Token 是否挂载
kubectl exec -it my-pod -- ls /var/run/secrets/kubernetes.io/serviceaccount/

# 检查 RBAC 配置
```

### 15.6 资源问题

#### 节点 NotReady

```bash
# 检查节点状态
kubectl get nodes
kubectl describe node <node-name>

# 检查 kubelet
systemctl status kubelet
journalctl -u kubelet -f

# 常见原因
# 1. kubelet 服务停止
# 2. 节点资源耗尽（磁盘、内存）
# 3. 网络问题（无法连接 API Server）
# 4. 证书过期
```

#### 资源配额超限

```bash
# 错误现象
Error from server (Forbidden): pods "my-pod" is forbidden: 
exceeded quota: compute-quota, requested: limits.cpu=2, used: limits.cpu=9, limited: limits.cpu=10

# 检查配额使用
kubectl describe resourcequota -n <namespace>

# 解决
# 1. 减少资源请求
# 2. 增加配额限制
# 3. 删除不需要的资源
```


### 15.7 部署更新问题

#### 滚动更新卡住

```bash
# 检查更新状态
kubectl rollout status deployment/my-deployment

# 查看 ReplicaSet
kubectl get rs

# 查看事件
kubectl describe deployment my-deployment

# 常见原因
# 1. 新 Pod 无法启动（镜像问题、配置错误）
# 2. 新 Pod 未通过健康检查
# 3. 资源不足

# 解决：回滚
kubectl rollout undo deployment/my-deployment
```

#### Deployment 副本数不对

```bash
# 检查 HPA
kubectl get hpa

# 检查 Deployment
kubectl describe deployment my-deployment

# 可能原因
# 1. HPA 自动调整了副本数
# 2. 手动 scale 覆盖了配置
# 3. 资源不足无法调度
```

---

## 16. 最佳实践总结

### 16.1 资源配置清单

```yaml
# 生产环境 Deployment 模板
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    app: my-app
    version: v1
spec:
  replicas: 3
  
  # 更新策略
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  
  selector:
    matchLabels:
      app: my-app
  
  template:
    metadata:
      labels:
        app: my-app
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
    spec:
      # 服务账号
      serviceAccountName: my-app-sa
      
      # 安全上下文
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      
      # 优雅终止
      terminationGracePeriodSeconds: 30
      
      # 反亲和性：分散到不同节点
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: my-app
              topologyKey: kubernetes.io/hostname
      
      containers:
      - name: my-app
        image: my-app:1.0.0
        imagePullPolicy: IfNotPresent
        
        ports:
        - name: http
          containerPort: 8080
        
        # 环境变量
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        
        envFrom:
        - configMapRef:
            name: my-app-config
        - secretRef:
            name: my-app-secret
        
        # 资源限制（必须配置！）
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        
        # 健康检查（必须配置！）
        startupProbe:
          httpGet:
            path: /health/startup
            port: 8080
          initialDelaySeconds: 0
          periodSeconds: 10
          failureThreshold: 30
        
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 0
          periodSeconds: 10
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 0
          periodSeconds: 5
          failureThreshold: 3
        
        # 安全上下文
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        
        # 挂载
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: config
          mountPath: /app/config
          readOnly: true
      
      volumes:
      - name: tmp
        emptyDir: {}
      - name: config
        configMap:
          name: my-app-config
```

### 16.2 命名规范

```
资源命名规范：
- 使用小写字母、数字、连字符
- 不超过 63 个字符
- 以字母开头，以字母或数字结尾

推荐格式：
- Deployment: <app-name>-deployment 或 <app-name>
- Service: <app-name>-service 或 <app-name>-svc
- ConfigMap: <app-name>-config
- Secret: <app-name>-secret
- PVC: <app-name>-data

标签规范：
app.kubernetes.io/name: my-app           # 应用名称
app.kubernetes.io/instance: my-app-prod  # 实例名称
app.kubernetes.io/version: "1.0.0"       # 版本
app.kubernetes.io/component: frontend    # 组件
app.kubernetes.io/part-of: my-system     # 所属系统
app.kubernetes.io/managed-by: helm       # 管理工具
```

### 16.3 安全最佳实践

```yaml
# 安全检查清单
1. Pod 安全
   ✓ runAsNonRoot: true
   ✓ readOnlyRootFilesystem: true
   ✓ allowPrivilegeEscalation: false
   ✓ capabilities.drop: ALL

2. 网络安全
   ✓ 使用 NetworkPolicy 限制流量
   ✓ 使用 TLS 加密通信
   ✓ 限制 Ingress 来源 IP

3. 认证授权
   ✓ 使用 ServiceAccount
   ✓ 最小权限原则
   ✓ 定期轮换 Secret

4. 镜像安全
   ✓ 使用私有镜像仓库
   ✓ 镜像签名验证
   ✓ 定期扫描漏洞
   ✓ 使用固定版本标签，避免 latest

5. 资源限制
   ✓ 配置 ResourceQuota
   ✓ 配置 LimitRange
   ✓ 所有容器设置 resources
```

### 16.4 高可用配置

```yaml
# 高可用检查清单
1. 副本数
   ✓ 生产环境至少 3 个副本
   ✓ 配置 PodDisruptionBudget

2. 反亲和性
   ✓ Pod 分散到不同节点
   ✓ Pod 分散到不同可用区

3. 健康检查
   ✓ 配置 livenessProbe
   ✓ 配置 readinessProbe
   ✓ 配置 startupProbe（启动慢的应用）

4. 优雅终止
   ✓ 配置 terminationGracePeriodSeconds
   ✓ 应用处理 SIGTERM 信号

5. 资源预留
   ✓ 配置合理的 requests
   ✓ 避免资源超卖
```

```yaml
# PodDisruptionBudget 示例
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: my-app-pdb
spec:
  minAvailable: 2              # 最少可用 Pod 数
  # 或 maxUnavailable: 1       # 最多不可用 Pod 数
  selector:
    matchLabels:
      app: my-app
```

### 16.5 监控告警配置

```yaml
# 关键监控指标
1. 节点级别
   - CPU/内存/磁盘使用率
   - 节点状态
   - Pod 数量

2. Pod 级别
   - CPU/内存使用率
   - 重启次数
   - 状态异常

3. 应用级别
   - 请求延迟
   - 错误率
   - QPS

# Prometheus 告警规则示例
groups:
- name: kubernetes
  rules:
  - alert: PodCrashLooping
    expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Pod {{ $labels.pod }} 频繁重启"
  
  - alert: PodNotReady
    expr: kube_pod_status_ready{condition="false"} == 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Pod {{ $labels.pod }} 未就绪"
  
  - alert: NodeNotReady
    expr: kube_node_status_condition{condition="Ready",status="true"} == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "节点 {{ $labels.node }} 不可用"
```

### 16.6 故障排查流程

```
Pod 问题排查流程：
1. kubectl get pods -o wide
   └── 查看状态、重启次数、所在节点

2. kubectl describe pod <pod-name>
   └── 查看事件、状态详情

3. kubectl logs <pod-name>
   └── 查看应用日志
   └── --previous 查看上次崩溃日志

4. kubectl exec -it <pod-name> -- /bin/sh
   └── 进入容器调试

5. kubectl get events --sort-by='.lastTimestamp'
   └── 查看集群事件

Service 问题排查流程：
1. kubectl get svc,endpoints
   └── 检查 Service 和 Endpoints

2. kubectl describe svc <svc-name>
   └── 检查选择器和端口

3. kubectl get pods -l <selector>
   └── 检查匹配的 Pod

4. kubectl exec -it <pod> -- curl <svc-name>
   └── 从 Pod 内部测试访问
```

---

## 参考资料

- [Kubernetes 官方文档](https://kubernetes.io/docs/)
- [Kubernetes GitHub](https://github.com/kubernetes/kubernetes)
- [Helm 官方文档](https://helm.sh/docs/)
- [CNCF 云原生全景图](https://landscape.cncf.io/)
- [Kubernetes Patterns](https://k8spatterns.io/)
