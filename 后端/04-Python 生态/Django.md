> Django 是 Python 最流行的全栈 Web 框架，遵循 MTV 架构模式
> 本笔记基于 Django 4.2 LTS / Python 3.11+ / Django REST Framework

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [项目结构](#3-项目结构)
4. [模型与数据库](#4-模型与数据库)
5. [视图与URL](#5-视图与url)
6. [模板系统](#6-模板系统)
7. [表单处理](#7-表单处理)
8. [用户认证](#8-用户认证)
9. [Django REST Framework](#9-django-rest-framework)
10. [中间件](#10-中间件)
11. [缓存系统](#11-缓存系统)
12. [异步任务](#12-异步任务)
13. [测试](#13-测试)
14. [部署](#14-部署)
15. [常见错误与解决方案](#15-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Django？

Django 是一个高级 Python Web 框架，鼓励快速开发和简洁、实用的设计。它由经验丰富的开发者构建，解决了 Web 开发中的许多麻烦，让你可以专注于编写应用而无需重新发明轮子。

**Django 的特点**：
- **全栈框架**：内置 ORM、模板引擎、表单处理、认证系统等
- **安全性高**：内置防护 SQL 注入、XSS、CSRF 等攻击
- **可扩展性强**：丰富的第三方包生态
- **文档完善**：官方文档详尽，社区活跃
- **DRY 原则**：Don't Repeat Yourself，减少重复代码

### 1.2 MTV 架构

Django 采用 MTV（Model-Template-View）架构，类似于 MVC：

| MTV | MVC | 说明 |
|-----|-----|------|
| Model | Model | 数据模型，与数据库交互 |
| Template | View | 模板，负责展示 |
| View | Controller | 视图，处理业务逻辑 |

```
用户请求 → URL 路由 → View（视图）→ Model（模型）→ 数据库
                         ↓
                    Template（模板）
                         ↓
                      响应用户
```

### 1.3 Django vs Flask vs FastAPI

| 特性 | Django | Flask | FastAPI |
|------|--------|-------|---------|
| 类型 | 全栈框架 | 微框架 | 异步框架 |
| ORM | 内置 | 需要扩展 | 需要扩展 |
| Admin | 内置 | 需要扩展 | 需要扩展 |
| 异步支持 | 4.0+ 支持 | 有限 | 原生支持 |
| 学习曲线 | 较陡 | 平缓 | 中等 |
| 适用场景 | 大型项目 | 小型项目/API | 高性能 API |

---

## 2. 环境搭建

### 2.1 安装 Django

```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# 安装 Django
pip install django

# 验证安装
python -m django --version

# 安装常用依赖
pip install djangorestframework  # REST API
pip install django-cors-headers  # 跨域支持
pip install django-filter        # 过滤器
pip install pillow               # 图片处理
pip install psycopg2-binary      # PostgreSQL 驱动
pip install python-dotenv        # 环境变量
pip install celery               # 异步任务
pip install redis                # Redis 客户端
```

### 2.2 创建项目

```bash
# 创建项目
django-admin startproject myproject

# 进入项目目录
cd myproject

# 创建应用
python manage.py startapp users
python manage.py startapp blog

# 运行开发服务器
python manage.py runserver

# 指定端口
python manage.py runserver 8080

# 允许外部访问
python manage.py runserver 0.0.0.0:8000
```

### 2.3 项目配置

```python
# myproject/settings.py

from pathlib import Path
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# 安全配置
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
DEBUG = os.getenv('DEBUG', 'True') == 'True'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# 应用配置
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # 第三方应用
    'rest_framework',
    'corsheaders',
    'django_filters',
    
    # 本地应用
    'users.apps.UsersConfig',
    'blog.apps.BlogConfig',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # 放在最前面
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# 数据库配置
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME', 'myproject'),
        'USER': os.getenv('DB_USER', 'postgres'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

# 开发环境使用 SQLite
if DEBUG:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# 密码验证
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# 国际化
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_I18N = True
USE_TZ = True

# 静态文件
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

# 媒体文件
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# 默认主键类型
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 自定义用户模型
AUTH_USER_MODEL = 'users.User'

# CORS 配置
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
]

# REST Framework 配置
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}
```

---

## 3. 项目结构

### 3.1 推荐目录结构

```
myproject/
├── myproject/              # 项目配置目录
│   ├── __init__.py
│   ├── settings/           # 分环境配置
│   │   ├── __init__.py
│   │   ├── base.py         # 基础配置
│   │   ├── development.py  # 开发环境
│   │   └── production.py   # 生产环境
│   ├── urls.py             # 主路由
│   ├── wsgi.py             # WSGI 入口
│   └── asgi.py             # ASGI 入口
├── apps/                   # 应用目录
│   ├── users/              # 用户应用
│   │   ├── __init__.py
│   │   ├── admin.py        # Admin 配置
│   │   ├── apps.py         # 应用配置
│   │   ├── models.py       # 数据模型
│   │   ├── views.py        # 视图
│   │   ├── urls.py         # 路由
│   │   ├── serializers.py  # 序列化器
│   │   ├── forms.py        # 表单
│   │   ├── signals.py      # 信号
│   │   ├── tasks.py        # 异步任务
│   │   └── tests/          # 测试
│   │       ├── __init__.py
│   │       ├── test_models.py
│   │       └── test_views.py
│   └── blog/               # 博客应用
├── templates/              # 模板目录
│   ├── base.html
│   └── users/
├── static/                 # 静态文件
│   ├── css/
│   ├── js/
│   └── images/
├── media/                  # 用户上传文件
├── locale/                 # 国际化文件
├── requirements/           # 依赖文件
│   ├── base.txt
│   ├── development.txt
│   └── production.txt
├── manage.py
├── .env                    # 环境变量
├── .gitignore
└── README.md
```

### 3.2 分环境配置

```python
# myproject/settings/base.py
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent.parent

INSTALLED_APPS = [
    # ...
]

# 通用配置
# ...

# myproject/settings/development.py
from .base import *

DEBUG = True
ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# myproject/settings/production.py
from .base import *

DEBUG = False
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}

# 安全配置
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
```

```bash
# 使用不同配置启动
# 开发环境
export DJANGO_SETTINGS_MODULE=myproject.settings.development
python manage.py runserver

# 生产环境
export DJANGO_SETTINGS_MODULE=myproject.settings.production
gunicorn myproject.wsgi:application
```

---

## 4. 模型与数据库

### 4.1 定义模型

```python
# apps/users/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

class User(AbstractUser):
    """自定义用户模型"""
    
    class Gender(models.TextChoices):
        MALE = 'M', '男'
        FEMALE = 'F', '女'
        OTHER = 'O', '其他'
    
    email = models.EmailField('邮箱', unique=True)
    phone = models.CharField('手机号', max_length=11, blank=True)
    avatar = models.ImageField('头像', upload_to='avatars/', blank=True)
    gender = models.CharField('性别', max_length=1, choices=Gender.choices, blank=True)
    bio = models.TextField('简介', max_length=500, blank=True)
    birth_date = models.DateField('生日', null=True, blank=True)
    
    # 时间戳
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)
    
    USERNAME_FIELD = 'email'  # 使用邮箱登录
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        verbose_name = '用户'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']
    
    def __str__(self):
        return self.username


# apps/blog/models.py
from django.db import models
from django.conf import settings
from django.utils.text import slugify

class Category(models.Model):
    """文章分类"""
    name = models.CharField('名称', max_length=100, unique=True)
    slug = models.SlugField('Slug', max_length=100, unique=True)
    description = models.TextField('描述', blank=True)
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='children',
        verbose_name='父分类'
    )
    
    class Meta:
        verbose_name = '分类'
        verbose_name_plural = verbose_name
    
    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name, allow_unicode=True)
        super().save(*args, **kwargs)


class Tag(models.Model):
    """文章标签"""
    name = models.CharField('名称', max_length=50, unique=True)
    slug = models.SlugField('Slug', max_length=50, unique=True)
    
    class Meta:
        verbose_name = '标签'
        verbose_name_plural = verbose_name
    
    def __str__(self):
        return self.name


class Post(models.Model):
    """文章"""
    
    class Status(models.TextChoices):
        DRAFT = 'draft', '草稿'
        PUBLISHED = 'published', '已发布'
        ARCHIVED = 'archived', '已归档'
    
    title = models.CharField('标题', max_length=200)
    slug = models.SlugField('Slug', max_length=200, unique=True)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='posts',
        verbose_name='作者'
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        related_name='posts',
        verbose_name='分类'
    )
    tags = models.ManyToManyField(Tag, related_name='posts', blank=True, verbose_name='标签')
    
    content = models.TextField('内容')
    excerpt = models.TextField('摘要', max_length=500, blank=True)
    cover_image = models.ImageField('封面图', upload_to='posts/covers/', blank=True)
    
    status = models.CharField('状态', max_length=10, choices=Status.choices, default=Status.DRAFT)
    is_featured = models.BooleanField('是否推荐', default=False)
    views_count = models.PositiveIntegerField('浏览量', default=0)
    
    published_at = models.DateTimeField('发布时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)
    
    class Meta:
        verbose_name = '文章'
        verbose_name_plural = verbose_name
        ordering = ['-published_at', '-created_at']
        indexes = [
            models.Index(fields=['status', '-published_at']),
            models.Index(fields=['author', '-created_at']),
        ]
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title, allow_unicode=True)
        if self.status == self.Status.PUBLISHED and not self.published_at:
            self.published_at = timezone.now()
        super().save(*args, **kwargs)
    
    def increase_views(self):
        """增加浏览量"""
        self.views_count += 1
        self.save(update_fields=['views_count'])


class Comment(models.Model):
    """评论"""
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments', verbose_name='文章')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name='作者')
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies', verbose_name='父评论')
    content = models.TextField('内容', max_length=1000)
    is_approved = models.BooleanField('是否审核通过', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    
    class Meta:
        verbose_name = '评论'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']
    
    def __str__(self):
        return f'{self.author.username}: {self.content[:50]}'
```

### 4.2 数据库迁移

```bash
# 创建迁移文件
python manage.py makemigrations

# 创建特定应用的迁移
python manage.py makemigrations users blog

# 查看迁移 SQL
python manage.py sqlmigrate blog 0001

# 执行迁移
python manage.py migrate

# 查看迁移状态
python manage.py showmigrations

# 回滚迁移
python manage.py migrate blog 0001

# 重置迁移（危险操作）
python manage.py migrate blog zero
```

### 4.3 QuerySet API

```python
from apps.blog.models import Post, Category, Tag
from django.db.models import Q, F, Count, Avg, Sum
from django.db.models.functions import TruncMonth

# 基础查询
posts = Post.objects.all()
post = Post.objects.get(id=1)  # 获取单个对象，不存在抛出异常
post = Post.objects.filter(id=1).first()  # 获取单个对象，不存在返回 None

# 过滤查询
published_posts = Post.objects.filter(status='published')
draft_posts = Post.objects.exclude(status='published')

# 字段查找
Post.objects.filter(title__contains='Django')      # 包含
Post.objects.filter(title__icontains='django')     # 包含（不区分大小写）
Post.objects.filter(title__startswith='Django')    # 开头
Post.objects.filter(title__endswith='教程')        # 结尾
Post.objects.filter(views_count__gt=100)           # 大于
Post.objects.filter(views_count__gte=100)          # 大于等于
Post.objects.filter(views_count__lt=100)           # 小于
Post.objects.filter(views_count__lte=100)          # 小于等于
Post.objects.filter(views_count__range=(10, 100))  # 范围
Post.objects.filter(category__isnull=True)         # 为空
Post.objects.filter(status__in=['draft', 'published'])  # 在列表中
Post.objects.filter(created_at__year=2024)         # 年份
Post.objects.filter(created_at__month=1)           # 月份
Post.objects.filter(created_at__date='2024-01-01') # 日期

# Q 对象（复杂查询）
Post.objects.filter(Q(status='published') | Q(author_id=1))  # OR
Post.objects.filter(Q(status='published') & Q(is_featured=True))  # AND
Post.objects.filter(~Q(status='draft'))  # NOT

# F 对象（字段引用）
Post.objects.filter(views_count__gt=F('comments__count'))  # 字段比较
Post.objects.update(views_count=F('views_count') + 1)  # 字段更新

# 排序
Post.objects.order_by('-created_at')  # 降序
Post.objects.order_by('created_at')   # 升序
Post.objects.order_by('-is_featured', '-created_at')  # 多字段排序

# 限制结果
Post.objects.all()[:10]  # 前 10 条
Post.objects.all()[5:10]  # 第 6-10 条

# 去重
Post.objects.values('author').distinct()

# 聚合
from django.db.models import Count, Avg, Sum, Max, Min

Post.objects.count()
Post.objects.aggregate(total_views=Sum('views_count'))
Post.objects.aggregate(avg_views=Avg('views_count'))
Post.objects.aggregate(max_views=Max('views_count'))

# 分组统计
Post.objects.values('category__name').annotate(
    count=Count('id'),
    total_views=Sum('views_count')
)

# 按月统计
Post.objects.annotate(
    month=TruncMonth('created_at')
).values('month').annotate(
    count=Count('id')
).order_by('month')

# 关联查询
post = Post.objects.select_related('author', 'category').get(id=1)  # 一对一/多对一
posts = Post.objects.prefetch_related('tags', 'comments').all()  # 多对多/一对多

# 只获取特定字段
Post.objects.values('id', 'title')  # 返回字典列表
Post.objects.values_list('id', 'title')  # 返回元组列表
Post.objects.values_list('title', flat=True)  # 返回单值列表

# 原生 SQL
Post.objects.raw('SELECT * FROM blog_post WHERE status = %s', ['published'])

# 批量操作
Post.objects.filter(status='draft').update(status='published')  # 批量更新
Post.objects.filter(status='archived').delete()  # 批量删除

# 批量创建
Post.objects.bulk_create([
    Post(title='文章1', content='内容1', author_id=1),
    Post(title='文章2', content='内容2', author_id=1),
])

# 批量更新
posts = Post.objects.filter(author_id=1)
for post in posts:
    post.is_featured = True
Post.objects.bulk_update(posts, ['is_featured'])

# 获取或创建
post, created = Post.objects.get_or_create(
    slug='my-post',
    defaults={'title': 'My Post', 'content': 'Content', 'author_id': 1}
)

# 更新或创建
post, created = Post.objects.update_or_create(
    slug='my-post',
    defaults={'title': 'Updated Title'}
)
```

### 4.4 模型管理器

```python
# apps/blog/models.py
from django.db import models

class PostManager(models.Manager):
    """文章管理器"""
    
    def published(self):
        """获取已发布的文章"""
        return self.filter(status='published')
    
    def featured(self):
        """获取推荐文章"""
        return self.published().filter(is_featured=True)
    
    def by_author(self, author):
        """获取某作者的文章"""
        return self.filter(author=author)
    
    def popular(self, limit=10):
        """获取热门文章"""
        return self.published().order_by('-views_count')[:limit]


class Post(models.Model):
    # ... 字段定义
    
    objects = PostManager()  # 替换默认管理器
    
    # 或添加额外管理器
    # all_objects = models.Manager()  # 默认管理器
    # published_objects = PublishedManager()  # 自定义管理器

# 使用
Post.objects.published()
Post.objects.featured()
Post.objects.popular(5)
```

---

## 5. 视图与URL

### 5.1 函数视图

```python
# apps/blog/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse, Http404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from .models import Post, Category

def post_list(request):
    """文章列表"""
    posts = Post.objects.published().select_related('author', 'category')
    
    # 分类过滤
    category_slug = request.GET.get('category')
    if category_slug:
        posts = posts.filter(category__slug=category_slug)
    
    # 搜索
    query = request.GET.get('q')
    if query:
        posts = posts.filter(title__icontains=query)
    
    # 分页
    paginator = Paginator(posts, 10)
    page = request.GET.get('page', 1)
    posts = paginator.get_page(page)
    
    context = {
        'posts': posts,
        'categories': Category.objects.all(),
    }
    return render(request, 'blog/post_list.html', context)


def post_detail(request, slug):
    """文章详情"""
    post = get_object_or_404(
        Post.objects.select_related('author', 'category').prefetch_related('tags', 'comments'),
        slug=slug,
        status='published'
    )
    post.increase_views()
    
    return render(request, 'blog/post_detail.html', {'post': post})


@login_required
@require_http_methods(['POST'])
def post_like(request, pk):
    """点赞文章"""
    post = get_object_or_404(Post, pk=pk)
    # 处理点赞逻辑
    return JsonResponse({'status': 'ok', 'likes': post.likes_count})


def api_posts(request):
    """API: 获取文章列表"""
    posts = Post.objects.published().values('id', 'title', 'slug', 'created_at')[:20]
    return JsonResponse({'posts': list(posts)})
```

### 5.2 类视图

```python
# apps/blog/views.py
from django.views import View
from django.views.generic import (
    ListView, DetailView, CreateView, UpdateView, DeleteView,
    TemplateView, RedirectView
)
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.urls import reverse_lazy
from .models import Post
from .forms import PostForm


class PostListView(ListView):
    """文章列表视图"""
    model = Post
    template_name = 'blog/post_list.html'
    context_object_name = 'posts'
    paginate_by = 10
    
    def get_queryset(self):
        queryset = Post.objects.published().select_related('author', 'category')
        
        # 分类过滤
        category = self.request.GET.get('category')
        if category:
            queryset = queryset.filter(category__slug=category)
        
        # 搜索
        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(title__icontains=query)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['categories'] = Category.objects.all()
        context['query'] = self.request.GET.get('q', '')
        return context


class PostDetailView(DetailView):
    """文章详情视图"""
    model = Post
    template_name = 'blog/post_detail.html'
    context_object_name = 'post'
    slug_field = 'slug'
    slug_url_kwarg = 'slug'
    
    def get_queryset(self):
        return Post.objects.published().select_related('author', 'category').prefetch_related('tags')
    
    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        obj.increase_views()
        return obj
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['related_posts'] = Post.objects.published().filter(
            category=self.object.category
        ).exclude(id=self.object.id)[:5]
        return context


class PostCreateView(LoginRequiredMixin, CreateView):
    """创建文章视图"""
    model = Post
    form_class = PostForm
    template_name = 'blog/post_form.html'
    success_url = reverse_lazy('blog:post_list')
    
    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)


class PostUpdateView(LoginRequiredMixin, UpdateView):
    """更新文章视图"""
    model = Post
    form_class = PostForm
    template_name = 'blog/post_form.html'
    
    def get_queryset(self):
        # 只能编辑自己的文章
        return Post.objects.filter(author=self.request.user)
    
    def get_success_url(self):
        return reverse_lazy('blog:post_detail', kwargs={'slug': self.object.slug})


class PostDeleteView(LoginRequiredMixin, DeleteView):
    """删除文章视图"""
    model = Post
    template_name = 'blog/post_confirm_delete.html'
    success_url = reverse_lazy('blog:post_list')
    
    def get_queryset(self):
        return Post.objects.filter(author=self.request.user)


# 自定义类视图
class PostArchiveView(View):
    """文章归档视图"""
    
    def get(self, request):
        posts = Post.objects.published().dates('created_at', 'month', order='DESC')
        return render(request, 'blog/post_archive.html', {'dates': posts})
    
    def post(self, request):
        # 处理 POST 请求
        pass
```

### 5.3 URL 配置

```python
# myproject/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('apps.blog.urls', namespace='blog')),
    path('users/', include('apps.users.urls', namespace='users')),
    path('api/', include('apps.api.urls', namespace='api')),
]

# 开发环境提供媒体文件
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


# apps/blog/urls.py
from django.urls import path
from . import views

app_name = 'blog'

urlpatterns = [
    # 函数视图
    path('', views.post_list, name='post_list'),
    path('post/<slug:slug>/', views.post_detail, name='post_detail'),
    path('post/<int:pk>/like/', views.post_like, name='post_like'),
    
    # 类视图
    path('posts/', views.PostListView.as_view(), name='post_list_cbv'),
    path('posts/<slug:slug>/', views.PostDetailView.as_view(), name='post_detail_cbv'),
    path('posts/create/', views.PostCreateView.as_view(), name='post_create'),
    path('posts/<slug:slug>/edit/', views.PostUpdateView.as_view(), name='post_update'),
    path('posts/<slug:slug>/delete/', views.PostDeleteView.as_view(), name='post_delete'),
    
    # 分类
    path('category/<slug:slug>/', views.category_posts, name='category_posts'),
    
    # 标签
    path('tag/<slug:slug>/', views.tag_posts, name='tag_posts'),
]
```

---

## 6. 模板系统

### 6.1 模板基础

```html
<!-- templates/base.html -->
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}我的网站{% endblock %}</title>
    
    {% load static %}
    <link rel="stylesheet" href="{% static 'css/style.css' %}">
    {% block extra_css %}{% endblock %}
</head>
<body>
    <header>
        {% include 'includes/navbar.html' %}
    </header>
    
    <main class="container">
        {% if messages %}
            {% for message in messages %}
                <div class="alert alert-{{ message.tags }}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endif %}
        
        {% block content %}{% endblock %}
    </main>
    
    <footer>
        {% include 'includes/footer.html' %}
    </footer>
    
    <script src="{% static 'js/main.js' %}"></script>
    {% block extra_js %}{% endblock %}
</body>
</html>


<!-- templates/blog/post_list.html -->
{% extends 'base.html' %}
{% load static %}

{% block title %}文章列表 - {{ block.super }}{% endblock %}

{% block content %}
<div class="post-list">
    <h1>文章列表</h1>
    
    <!-- 搜索表单 -->
    <form method="get" class="search-form">
        <input type="text" name="q" value="{{ query }}" placeholder="搜索文章...">
        <button type="submit">搜索</button>
    </form>
    
    <!-- 文章列表 -->
    {% for post in posts %}
        <article class="post-item">
            {% if post.cover_image %}
                <img src="{{ post.cover_image.url }}" alt="{{ post.title }}">
            {% endif %}
            
            <h2>
                <a href="{% url 'blog:post_detail' slug=post.slug %}">
                    {{ post.title }}
                </a>
            </h2>
            
            <div class="post-meta">
                <span>作者: {{ post.author.username }}</span>
                <span>分类: {{ post.category.name|default:"未分类" }}</span>
                <span>发布于: {{ post.published_at|date:"Y-m-d H:i" }}</span>
                <span>浏览: {{ post.views_count }}</span>
            </div>
            
            <p>{{ post.excerpt|truncatewords:50 }}</p>
            
            <div class="post-tags">
                {% for tag in post.tags.all %}
                    <a href="{% url 'blog:tag_posts' slug=tag.slug %}" class="tag">
                        {{ tag.name }}
                    </a>
                {% empty %}
                    <span>无标签</span>
                {% endfor %}
            </div>
        </article>
    {% empty %}
        <p>暂无文章</p>
    {% endfor %}
    
    <!-- 分页 -->
    {% if posts.has_other_pages %}
        <nav class="pagination">
            {% if posts.has_previous %}
                <a href="?page={{ posts.previous_page_number }}">上一页</a>
            {% endif %}
            
            <span>第 {{ posts.number }} 页 / 共 {{ posts.paginator.num_pages }} 页</span>
            
            {% if posts.has_next %}
                <a href="?page={{ posts.next_page_number }}">下一页</a>
            {% endif %}
        </nav>
    {% endif %}
</div>
{% endblock %}
```


### 6.2 模板过滤器

Django 模板过滤器用于对变量进行格式化和转换，使用管道符 `|` 连接。

```html
<!-- 常用内置过滤器 -->

<!-- 字符串处理 -->
{{ name|lower }}                    <!-- 转小写 -->
{{ name|upper }}                    <!-- 转大写 -->
{{ name|title }}                    <!-- 首字母大写 -->
{{ name|capfirst }}                 <!-- 第一个字母大写 -->
{{ text|truncatewords:30 }}         <!-- 截断到30个单词 -->
{{ text|truncatechars:100 }}        <!-- 截断到100个字符 -->
{{ text|wordcount }}                <!-- 单词计数 -->
{{ text|linebreaks }}               <!-- 换行转 <p> 和 <br> -->
{{ text|linebreaksbr }}             <!-- 换行转 <br> -->
{{ text|striptags }}                <!-- 去除 HTML 标签 -->
{{ html|safe }}                     <!-- 标记为安全 HTML，不转义 -->
{{ text|escape }}                   <!-- HTML 转义 -->
{{ text|slugify }}                  <!-- 转为 slug 格式 -->

<!-- 列表处理 -->
{{ list|length }}                   <!-- 列表长度 -->
{{ list|first }}                    <!-- 第一个元素 -->
{{ list|last }}                     <!-- 最后一个元素 -->
{{ list|join:", " }}                <!-- 用逗号连接 -->
{{ list|slice:":5" }}               <!-- 切片，取前5个 -->
{{ list|random }}                   <!-- 随机元素 -->
{{ list|dictsort:"name" }}          <!-- 按字典键排序 -->

<!-- 日期时间 -->
{{ date|date:"Y-m-d" }}             <!-- 格式化日期 -->
{{ date|time:"H:i:s" }}             <!-- 格式化时间 -->
{{ date|timesince }}                <!-- 距今多久（如：3天前） -->
{{ date|timeuntil }}                <!-- 还有多久 -->

<!-- 数字处理 -->
{{ num|add:5 }}                     <!-- 加法 -->
{{ num|floatformat:2 }}             <!-- 保留2位小数 -->
{{ num|filesizeformat }}            <!-- 文件大小格式化 -->
{{ num|intcomma }}                  <!-- 千位分隔符（需要 humanize） -->

<!-- 默认值 -->
{{ value|default:"暂无" }}          <!-- 为空时显示默认值 -->
{{ value|default_if_none:"暂无" }}  <!-- 为 None 时显示默认值 -->

<!-- 条件判断 -->
{{ value|yesno:"是,否,未知" }}      <!-- 布尔值转文字 -->
{{ num|divisibleby:2 }}             <!-- 是否能被整除 -->

<!-- JSON -->
{{ data|json_script:"my-data" }}    <!-- 输出为 JSON script 标签 -->
```


### 6.3 自定义模板标签和过滤器

当内置的过滤器和标签无法满足需求时，可以创建自定义的模板标签和过滤器。

```python
# apps/blog/templatetags/blog_tags.py
# 注意：需要在 templatetags 目录下创建 __init__.py 文件

from django import template
from django.utils.safestring import mark_safe
from django.utils.html import escape
import markdown

register = template.Library()

# ========== 自定义过滤器 ==========

@register.filter(name='markdown')
def markdown_filter(text):
    """将 Markdown 转换为 HTML"""
    return mark_safe(markdown.markdown(text, extensions=['extra', 'codehilite']))


@register.filter
def phone_format(phone):
    """手机号格式化：138****8888"""
    if phone and len(phone) == 11:
        return f"{phone[:3]}****{phone[-4:]}"
    return phone


@register.filter
def percentage(value, total):
    """计算百分比"""
    try:
        return f"{(value / total) * 100:.1f}%"
    except (ValueError, ZeroDivisionError):
        return "0%"


# ========== 简单标签 ==========

@register.simple_tag
def current_time(format_string='%Y-%m-%d %H:%M:%S'):
    """显示当前时间"""
    from datetime import datetime
    return datetime.now().strftime(format_string)


@register.simple_tag(takes_context=True)
def url_replace(context, **kwargs):
    """替换 URL 参数，常用于分页保持其他参数"""
    query = context['request'].GET.copy()
    for key, value in kwargs.items():
        query[key] = value
    return query.urlencode()


# ========== 包含标签 ==========

@register.inclusion_tag('blog/includes/sidebar.html', takes_context=True)
def show_sidebar(context):
    """显示侧边栏"""
    from apps.blog.models import Category, Tag, Post
    return {
        'categories': Category.objects.all(),
        'tags': Tag.objects.all()[:20],
        'popular_posts': Post.objects.published().order_by('-views_count')[:5],
        'request': context['request'],
    }


@register.inclusion_tag('blog/includes/post_card.html')
def post_card(post, show_excerpt=True):
    """文章卡片组件"""
    return {
        'post': post,
        'show_excerpt': show_excerpt,
    }
```

```html
<!-- 使用自定义标签和过滤器 -->
{% load blog_tags %}

<!-- 使用过滤器 -->
{{ post.content|markdown }}
{{ user.phone|phone_format }}
{{ completed|percentage:total }}

<!-- 使用简单标签 -->
<p>当前时间：{% current_time "%Y年%m月%d日" %}</p>

<!-- 分页时保持搜索参数 -->
<a href="?{% url_replace page=posts.next_page_number %}">下一页</a>

<!-- 使用包含标签 -->
{% show_sidebar %}
{% post_card post show_excerpt=False %}
```


---

## 7. 表单处理

表单是 Web 应用中用户输入数据的主要方式。Django 提供了强大的表单处理机制，包括数据验证、错误处理和安全防护。

### 7.1 Django 表单基础

```python
# apps/blog/forms.py
from django import forms
from django.core.validators import MinLengthValidator, RegexValidator
from .models import Post, Comment, Category

# ========== 普通表单 ==========

class ContactForm(forms.Form):
    """联系表单 - 不与模型关联"""
    
    name = forms.CharField(
        label='姓名',
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '请输入姓名'
        })
    )
    
    email = forms.EmailField(
        label='邮箱',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'example@email.com'
        })
    )
    
    phone = forms.CharField(
        label='手机号',
        max_length=11,
        required=False,
        validators=[
            RegexValidator(
                regex=r'^1[3-9]\d{9}$',
                message='请输入有效的手机号'
            )
        ]
    )
    
    subject = forms.ChoiceField(
        label='主题',
        choices=[
            ('', '请选择'),
            ('feedback', '意见反馈'),
            ('bug', 'Bug 报告'),
            ('cooperation', '商务合作'),
        ]
    )
    
    message = forms.CharField(
        label='留言内容',
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 5,
            'placeholder': '请输入留言内容...'
        }),
        validators=[MinLengthValidator(10, '留言内容至少10个字符')]
    )
    
    # 单字段验证
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if '管理员' in name:
            raise forms.ValidationError('名称不能包含"管理员"')
        return name
    
    # 多字段验证
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        phone = cleaned_data.get('phone')
        
        if not email and not phone:
            raise forms.ValidationError('邮箱和手机号至少填写一个')
        
        return cleaned_data
```


### 7.2 模型表单

模型表单（ModelForm）可以自动根据模型生成表单字段，大大减少重复代码。

```python
# apps/blog/forms.py

class PostForm(forms.ModelForm):
    """文章表单 - 与 Post 模型关联"""
    
    class Meta:
        model = Post
        fields = ['title', 'category', 'tags', 'content', 'excerpt', 'cover_image', 'status']
        # exclude = ['author', 'views_count']  # 或者排除某些字段
        
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '请输入文章标题'
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 15,
                'id': 'editor'
            }),
            'excerpt': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '文章摘要，不填则自动截取'
            }),
            'tags': forms.CheckboxSelectMultiple(),
            'status': forms.RadioSelect(),
        }
        
        labels = {
            'title': '标题',
            'content': '内容',
            'excerpt': '摘要',
        }
        
        help_texts = {
            'tags': '可多选',
            'cover_image': '建议尺寸：1200x630',
        }
        
        error_messages = {
            'title': {
                'required': '标题不能为空',
                'max_length': '标题最多200个字符',
            },
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 动态设置字段属性
        self.fields['category'].queryset = Category.objects.filter(parent__isnull=True)
        self.fields['category'].empty_label = '请选择分类'
    
    def clean_title(self):
        title = self.cleaned_data.get('title')
        # 检查标题是否重复（排除当前实例）
        qs = Post.objects.filter(title=title)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('该标题已存在')
        return title
    
    def save(self, commit=True):
        post = super().save(commit=False)
        # 自动生成摘要
        if not post.excerpt:
            post.excerpt = post.content[:200]
        if commit:
            post.save()
            self.save_m2m()  # 保存多对多关系
        return post


class CommentForm(forms.ModelForm):
    """评论表单"""
    
    class Meta:
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '写下你的评论...'
            })
        }
```


### 7.3 表单视图处理

```python
# apps/blog/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from .forms import ContactForm, PostForm, CommentForm
from .models import Post

def contact_view(request):
    """联系表单视图"""
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            # 获取清洗后的数据
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            message = form.cleaned_data['message']
            
            # 发送邮件
            send_mail(
                subject=f'来自 {name} 的留言',
                message=message,
                from_email=email,
                recipient_list=['admin@example.com'],
            )
            
            messages.success(request, '留言已发送，我们会尽快回复！')
            return redirect('contact')
    else:
        form = ContactForm()
    
    return render(request, 'blog/contact.html', {'form': form})


def post_create_view(request):
    """创建文章视图"""
    if request.method == 'POST':
        form = PostForm(request.POST, request.FILES)  # 注意 FILES
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            form.save_m2m()  # 保存标签（多对多）
            messages.success(request, '文章创建成功！')
            return redirect('blog:post_detail', slug=post.slug)
    else:
        form = PostForm()
    
    return render(request, 'blog/post_form.html', {'form': form, 'title': '创建文章'})


def post_update_view(request, slug):
    """更新文章视图"""
    post = get_object_or_404(Post, slug=slug, author=request.user)
    
    if request.method == 'POST':
        form = PostForm(request.POST, request.FILES, instance=post)
        if form.is_valid():
            form.save()
            messages.success(request, '文章更新成功！')
            return redirect('blog:post_detail', slug=post.slug)
    else:
        form = PostForm(instance=post)
    
    return render(request, 'blog/post_form.html', {'form': form, 'title': '编辑文章'})
```

```html
<!-- templates/blog/post_form.html -->
{% extends 'base.html' %}

{% block content %}
<div class="form-container">
    <h1>{{ title }}</h1>
    
    <form method="post" enctype="multipart/form-data" novalidate>
        {% csrf_token %}
        
        <!-- 显示非字段错误 -->
        {% if form.non_field_errors %}
            <div class="alert alert-danger">
                {% for error in form.non_field_errors %}
                    <p>{{ error }}</p>
                {% endfor %}
            </div>
        {% endif %}
        
        <!-- 逐个渲染字段 -->
        {% for field in form %}
            <div class="form-group {% if field.errors %}has-error{% endif %}">
                <label for="{{ field.id_for_label }}">
                    {{ field.label }}
                    {% if field.field.required %}<span class="required">*</span>{% endif %}
                </label>
                
                {{ field }}
                
                {% if field.help_text %}
                    <small class="help-text">{{ field.help_text }}</small>
                {% endif %}
                
                {% if field.errors %}
                    <div class="error-messages">
                        {% for error in field.errors %}
                            <span class="error">{{ error }}</span>
                        {% endfor %}
                    </div>
                {% endif %}
            </div>
        {% endfor %}
        
        <button type="submit" class="btn btn-primary">提交</button>
    </form>
</div>
{% endblock %}
```


---

## 8. 用户认证

Django 内置了完整的用户认证系统，包括用户注册、登录、登出、密码重置等功能。

### 8.1 自定义用户模型

在项目初期就应该创建自定义用户模型，即使暂时不需要额外字段。这样可以避免后期修改的麻烦。

```python
# apps/users/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class UserManager(BaseUserManager):
    """自定义用户管理器"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('邮箱不能为空')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """自定义用户模型"""
    
    email = models.EmailField('邮箱', unique=True)
    phone = models.CharField('手机号', max_length=11, blank=True)
    avatar = models.ImageField('头像', upload_to='avatars/', blank=True)
    bio = models.TextField('简介', max_length=500, blank=True)
    
    # 使用邮箱作为登录字段
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    objects = UserManager()
    
    class Meta:
        verbose_name = '用户'
        verbose_name_plural = verbose_name
    
    def __str__(self):
        return self.username
```

```python
# settings.py
AUTH_USER_MODEL = 'users.User'  # 必须在第一次迁移前设置
```


### 8.2 用户注册与登录

```python
# apps/users/forms.py
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

User = get_user_model()

class RegisterForm(UserCreationForm):
    """用户注册表单"""
    
    email = forms.EmailField(
        label='邮箱',
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs['class'] = 'form-control'
        self.fields['password2'].widget.attrs['class'] = 'form-control'


class LoginForm(AuthenticationForm):
    """用户登录表单"""
    
    username = forms.EmailField(
        label='邮箱',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': '请输入邮箱'
        })
    )
    password = forms.CharField(
        label='密码',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': '请输入密码'
        })
    )
    remember_me = forms.BooleanField(
        label='记住我',
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )


class ProfileForm(forms.ModelForm):
    """用户资料表单"""
    
    class Meta:
        model = User
        fields = ['username', 'avatar', 'phone', 'bio']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'bio': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }
```

```python
# apps/users/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import RegisterForm, LoginForm, ProfileForm

def register_view(request):
    """用户注册"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # 注册后自动登录
            messages.success(request, '注册成功！')
            return redirect('home')
    else:
        form = RegisterForm()
    
    return render(request, 'users/register.html', {'form': form})


def login_view(request):
    """用户登录"""
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            
            # 处理"记住我"
            if not form.cleaned_data.get('remember_me'):
                request.session.set_expiry(0)  # 关闭浏览器后过期
            
            messages.success(request, f'欢迎回来，{user.username}！')
            
            # 重定向到之前的页面
            next_url = request.GET.get('next', 'home')
            return redirect(next_url)
    else:
        form = LoginForm()
    
    return render(request, 'users/login.html', {'form': form})


def logout_view(request):
    """用户登出"""
    logout(request)
    messages.info(request, '您已成功退出登录')
    return redirect('home')


@login_required
def profile_view(request):
    """用户资料"""
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, '资料更新成功！')
            return redirect('users:profile')
    else:
        form = ProfileForm(instance=request.user)
    
    return render(request, 'users/profile.html', {'form': form})
```


### 8.3 权限控制

Django 提供了灵活的权限控制机制，可以在视图级别和对象级别进行权限检查。

```python
# 函数视图装饰器
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test

@login_required(login_url='/users/login/')
def my_view(request):
    """需要登录才能访问"""
    pass

@permission_required('blog.add_post', raise_exception=True)
def create_post(request):
    """需要添加文章权限"""
    pass

@user_passes_test(lambda u: u.is_staff)
def admin_view(request):
    """只有管理员可以访问"""
    pass


# 类视图 Mixin
from django.contrib.auth.mixins import (
    LoginRequiredMixin, 
    PermissionRequiredMixin,
    UserPassesTestMixin
)

class PostCreateView(LoginRequiredMixin, CreateView):
    """需要登录"""
    login_url = '/users/login/'
    redirect_field_name = 'next'


class PostDeleteView(PermissionRequiredMixin, DeleteView):
    """需要特定权限"""
    permission_required = 'blog.delete_post'
    # permission_required = ['blog.delete_post', 'blog.change_post']  # 多个权限


class PostUpdateView(UserPassesTestMixin, UpdateView):
    """自定义权限测试"""
    
    def test_func(self):
        post = self.get_object()
        return self.request.user == post.author or self.request.user.is_staff


# 模板中检查权限
"""
{% if user.is_authenticated %}
    <p>已登录</p>
{% endif %}

{% if perms.blog.add_post %}
    <a href="{% url 'blog:post_create' %}">写文章</a>
{% endif %}

{% if perms.blog %}
    <p>有 blog 应用的某些权限</p>
{% endif %}
"""
```

```python
# 自定义权限
# apps/blog/models.py
class Post(models.Model):
    # ... 字段
    
    class Meta:
        permissions = [
            ('publish_post', '可以发布文章'),
            ('feature_post', '可以推荐文章'),
        ]

# 代码中检查权限
def publish_post(request, pk):
    if not request.user.has_perm('blog.publish_post'):
        raise PermissionDenied
    # ...

# 分配权限
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

content_type = ContentType.objects.get_for_model(Post)
permission = Permission.objects.get(
    codename='publish_post',
    content_type=content_type
)
user.user_permissions.add(permission)
```


---

## 9. Django REST Framework

Django REST Framework (DRF) 是构建 Web API 的强大工具包，提供了序列化、认证、权限、分页等功能。

### 9.1 序列化器

序列化器负责将复杂数据类型（如 QuerySet 和模型实例）转换为 Python 原生数据类型，以便渲染成 JSON 等格式。

```python
# apps/blog/serializers.py
from rest_framework import serializers
from .models import Post, Category, Tag, Comment
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """用户序列化器"""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'avatar']
        read_only_fields = ['id']


class TagSerializer(serializers.ModelSerializer):
    """标签序列化器"""
    
    class Meta:
        model = Tag
        fields = ['id', 'name', 'slug']


class CategorySerializer(serializers.ModelSerializer):
    """分类序列化器"""
    posts_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description', 'posts_count']
    
    def get_posts_count(self, obj):
        return obj.posts.filter(status='published').count()


class PostListSerializer(serializers.ModelSerializer):
    """文章列表序列化器 - 简化版"""
    author = UserSerializer(read_only=True)
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    
    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug', 'author', 'category', 'tags',
            'excerpt', 'cover_image', 'views_count', 'published_at'
        ]


class PostDetailSerializer(serializers.ModelSerializer):
    """文章详情序列化器 - 完整版"""
    author = UserSerializer(read_only=True)
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    comments_count = serializers.SerializerMethodField()
    
    # 写入时使用 ID
    category_id = serializers.PrimaryKeyRelatedField(
        queryset=Category.objects.all(),
        source='category',
        write_only=True
    )
    tag_ids = serializers.PrimaryKeyRelatedField(
        queryset=Tag.objects.all(),
        source='tags',
        many=True,
        write_only=True
    )
    
    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug', 'author', 'category', 'category_id',
            'tags', 'tag_ids', 'content', 'excerpt', 'cover_image',
            'status', 'views_count', 'comments_count',
            'published_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'slug', 'author', 'views_count', 'published_at']
    
    def get_comments_count(self, obj):
        return obj.comments.filter(is_approved=True).count()
    
    def validate_title(self, value):
        """验证标题"""
        if len(value) < 5:
            raise serializers.ValidationError('标题至少5个字符')
        return value
    
    def create(self, validated_data):
        """创建文章"""
        tags = validated_data.pop('tags', [])
        validated_data['author'] = self.context['request'].user
        post = Post.objects.create(**validated_data)
        post.tags.set(tags)
        return post
    
    def update(self, instance, validated_data):
        """更新文章"""
        tags = validated_data.pop('tags', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if tags is not None:
            instance.tags.set(tags)
        return instance


class CommentSerializer(serializers.ModelSerializer):
    """评论序列化器"""
    author = UserSerializer(read_only=True)
    replies = serializers.SerializerMethodField()
    
    class Meta:
        model = Comment
        fields = ['id', 'author', 'content', 'parent', 'replies', 'created_at']
        read_only_fields = ['id', 'author']
    
    def get_replies(self, obj):
        if obj.parent is None:  # 只有顶级评论才获取回复
            replies = obj.replies.filter(is_approved=True)
            return CommentSerializer(replies, many=True).data
        return []
```


### 9.2 视图集与路由

DRF 提供了多种视图类，从简单的 APIView 到功能完整的 ViewSet。

```python
# apps/blog/views.py
from rest_framework import viewsets, generics, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly, AllowAny
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from .models import Post, Category, Tag, Comment
from .serializers import (
    PostListSerializer, PostDetailSerializer,
    CategorySerializer, TagSerializer, CommentSerializer
)

# ========== 分页配置 ==========

class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# ========== 自定义权限 ==========

from rest_framework.permissions import BasePermission

class IsAuthorOrReadOnly(BasePermission):
    """只有作者可以编辑"""
    
    def has_object_permission(self, request, view, obj):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        return obj.author == request.user


# ========== ViewSet ==========

class PostViewSet(viewsets.ModelViewSet):
    """文章视图集"""
    queryset = Post.objects.select_related('author', 'category').prefetch_related('tags')
    permission_classes = [IsAuthenticatedOrReadOnly, IsAuthorOrReadOnly]
    pagination_class = StandardPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'category', 'author']
    search_fields = ['title', 'content']
    ordering_fields = ['created_at', 'views_count']
    ordering = ['-created_at']
    lookup_field = 'slug'
    
    def get_serializer_class(self):
        if self.action == 'list':
            return PostListSerializer
        return PostDetailSerializer
    
    def get_queryset(self):
        queryset = super().get_queryset()
        # 非作者只能看到已发布的文章
        if not self.request.user.is_staff:
            if self.action == 'list':
                queryset = queryset.filter(status='published')
        return queryset
    
    def perform_create(self, serializer):
        serializer.save(author=self.request.user)
    
    @action(detail=True, methods=['post'])
    def publish(self, request, slug=None):
        """发布文章"""
        post = self.get_object()
        if post.author != request.user:
            return Response({'error': '无权操作'}, status=status.HTTP_403_FORBIDDEN)
        post.status = 'published'
        post.save()
        return Response({'status': '已发布'})
    
    @action(detail=True, methods=['get'])
    def comments(self, request, slug=None):
        """获取文章评论"""
        post = self.get_object()
        comments = post.comments.filter(is_approved=True, parent__isnull=True)
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def featured(self, request):
        """获取推荐文章"""
        posts = self.get_queryset().filter(is_featured=True)[:10]
        serializer = PostListSerializer(posts, many=True)
        return Response(serializer.data)


class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    """分类视图集（只读）"""
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]
    lookup_field = 'slug'


# ========== 函数视图 ==========

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def tag_list(request):
    """标签列表"""
    if request.method == 'GET':
        tags = Tag.objects.all()
        serializer = TagSerializer(tags, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = TagSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
```


### 9.3 路由配置

```python
# apps/blog/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register('posts', views.PostViewSet, basename='post')
router.register('categories', views.CategoryViewSet, basename='category')

urlpatterns = [
    path('', include(router.urls)),
    path('tags/', views.tag_list, name='tag-list'),
]

# 生成的 URL：
# GET/POST   /posts/           - 文章列表/创建
# GET        /posts/{slug}/    - 文章详情
# PUT/PATCH  /posts/{slug}/    - 更新文章
# DELETE     /posts/{slug}/    - 删除文章
# POST       /posts/{slug}/publish/   - 发布文章
# GET        /posts/{slug}/comments/  - 文章评论
# GET        /posts/featured/         - 推荐文章
```

### 9.4 JWT 认证

```python
# 安装
# pip install djangorestframework-simplejwt

# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}

from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# urls.py
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]
```

```python
# 自定义 Token 序列化器
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # 添加自定义字段
        token['username'] = user.username
        token['email'] = user.email
        return token
    
    def validate(self, attrs):
        data = super().validate(attrs)
        # 添加额外响应数据
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
        }
        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
```


---

## 10. 中间件

中间件是 Django 请求/响应处理的钩子框架，可以在视图处理之前或之后执行代码。

### 10.1 中间件工作原理

```
请求进入 → Middleware 1 (process_request)
         → Middleware 2 (process_request)
         → Middleware 3 (process_request)
         → View 处理
         → Middleware 3 (process_response)
         → Middleware 2 (process_response)
         → Middleware 1 (process_response)
         → 响应返回
```

### 10.2 自定义中间件

```python
# apps/core/middleware.py
import time
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware:
    """请求日志中间件（新式写法）"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # 请求前处理
        start_time = time.time()
        
        # 记录请求信息
        logger.info(f"Request: {request.method} {request.path}")
        
        # 调用下一个中间件或视图
        response = self.get_response(request)
        
        # 响应后处理
        duration = time.time() - start_time
        logger.info(f"Response: {response.status_code} ({duration:.2f}s)")
        
        # 添加响应头
        response['X-Request-Duration'] = f"{duration:.2f}s"
        
        return response


class IPBlockMiddleware:
    """IP 黑名单中间件"""
    
    BLOCKED_IPS = ['192.168.1.100', '10.0.0.1']
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        ip = self.get_client_ip(request)
        if ip in self.BLOCKED_IPS:
            return JsonResponse({'error': 'IP 已被封禁'}, status=403)
        return self.get_response(request)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class ExceptionHandlerMiddleware:
    """全局异常处理中间件"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        return self.get_response(request)
    
    def process_exception(self, request, exception):
        """处理视图中抛出的异常"""
        logger.error(f"Exception: {exception}", exc_info=True)
        
        if request.path.startswith('/api/'):
            return JsonResponse({
                'error': str(exception),
                'type': exception.__class__.__name__
            }, status=500)
        
        # 返回 None 让 Django 继续处理
        return None


class MaintenanceModeMiddleware(MiddlewareMixin):
    """维护模式中间件（旧式写法，使用 Mixin）"""
    
    def process_request(self, request):
        from django.conf import settings
        if getattr(settings, 'MAINTENANCE_MODE', False):
            if not request.user.is_staff:
                return JsonResponse({'message': '系统维护中，请稍后再试'}, status=503)
    
    def process_response(self, request, response):
        return response
```

```python
# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # 自定义中间件
    'apps.core.middleware.RequestLoggingMiddleware',
    'apps.core.middleware.ExceptionHandlerMiddleware',
]
```


---

## 11. 缓存系统

缓存是提升 Web 应用性能的重要手段。Django 提供了灵活的缓存框架，支持多种缓存后端。

### 11.1 缓存配置

```python
# settings.py

# Redis 缓存（推荐生产环境使用）
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': 'myproject',
        'TIMEOUT': 300,  # 默认过期时间（秒）
    }
}

# 内存缓存（开发环境）
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# 文件缓存
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
    }
}

# 数据库缓存
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'cache_table',
    }
}
# 需要运行: python manage.py createcachetable
```

### 11.2 缓存使用

```python
from django.core.cache import cache
from django.views.decorators.cache import cache_page, cache_control
from django.utils.decorators import method_decorator

# ========== 低级缓存 API ==========

# 设置缓存
cache.set('my_key', 'my_value', timeout=300)  # 5分钟过期
cache.set('my_key', 'my_value', timeout=None)  # 永不过期

# 获取缓存
value = cache.get('my_key')
value = cache.get('my_key', default='default_value')

# 获取或设置
value = cache.get_or_set('my_key', 'default_value', timeout=300)
value = cache.get_or_set('my_key', lambda: expensive_calculation(), timeout=300)

# 删除缓存
cache.delete('my_key')
cache.delete_many(['key1', 'key2', 'key3'])
cache.clear()  # 清空所有缓存

# 自增/自减
cache.incr('counter')
cache.decr('counter')

# 批量操作
cache.set_many({'key1': 'value1', 'key2': 'value2'}, timeout=300)
values = cache.get_many(['key1', 'key2'])


# ========== 视图缓存 ==========

@cache_page(60 * 15)  # 缓存15分钟
def post_list(request):
    posts = Post.objects.published()
    return render(request, 'blog/post_list.html', {'posts': posts})


@cache_page(60 * 15, cache='default', key_prefix='post_list')
def post_list_with_prefix(request):
    pass


# 类视图缓存
@method_decorator(cache_page(60 * 15), name='dispatch')
class PostListView(ListView):
    model = Post


# ========== 模板片段缓存 ==========
"""
{% load cache %}

{% cache 500 sidebar %}
    <!-- 侧边栏内容，缓存500秒 -->
    {% for category in categories %}
        <a href="{{ category.get_absolute_url }}">{{ category.name }}</a>
    {% endfor %}
{% endcache %}

<!-- 带变量的缓存 -->
{% cache 500 sidebar request.user.id %}
    <!-- 每个用户独立缓存 -->
{% endcache %}
"""


# ========== 实际应用示例 ==========

def get_popular_posts():
    """获取热门文章（带缓存）"""
    cache_key = 'popular_posts'
    posts = cache.get(cache_key)
    
    if posts is None:
        posts = list(Post.objects.published().order_by('-views_count')[:10])
        cache.set(cache_key, posts, timeout=60 * 30)  # 缓存30分钟
    
    return posts


def get_post_detail(slug):
    """获取文章详情（带缓存）"""
    cache_key = f'post_detail_{slug}'
    post = cache.get(cache_key)
    
    if post is None:
        post = Post.objects.select_related('author', 'category').get(slug=slug)
        cache.set(cache_key, post, timeout=60 * 60)  # 缓存1小时
    
    return post


# 缓存失效
def invalidate_post_cache(post):
    """文章更新时清除缓存"""
    cache.delete(f'post_detail_{post.slug}')
    cache.delete('popular_posts')
    cache.delete('post_list')


# 使用信号自动清除缓存
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

@receiver([post_save, post_delete], sender=Post)
def clear_post_cache(sender, instance, **kwargs):
    invalidate_post_cache(instance)
```


---

## 12. 异步任务

对于耗时操作（如发送邮件、处理图片、生成报表），应该使用异步任务来避免阻塞请求。Celery 是 Python 最流行的分布式任务队列。

### 12.1 Celery 配置

```python
# 安装
# pip install celery redis

# myproject/celery.py
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myproject.settings')

app = Celery('myproject')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# 可选：配置定时任务
app.conf.beat_schedule = {
    'cleanup-expired-sessions': {
        'task': 'apps.users.tasks.cleanup_expired_sessions',
        'schedule': 60 * 60 * 24,  # 每天执行
    },
    'send-daily-digest': {
        'task': 'apps.blog.tasks.send_daily_digest',
        'schedule': crontab(hour=8, minute=0),  # 每天8点
    },
}


# myproject/__init__.py
from .celery import app as celery_app

__all__ = ('celery_app',)


# settings.py
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Asia/Shanghai'
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 任务超时时间（秒）
```

### 12.2 定义任务

```python
# apps/blog/tasks.py
from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from .models import Post

@shared_task
def send_notification_email(user_id, post_id):
    """发送通知邮件"""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    user = User.objects.get(id=user_id)
    post = Post.objects.get(id=post_id)
    
    html_message = render_to_string('emails/notification.html', {
        'user': user,
        'post': post,
    })
    
    send_mail(
        subject=f'新文章：{post.title}',
        message='',
        from_email='noreply@example.com',
        recipient_list=[user.email],
        html_message=html_message,
    )
    
    return f'Email sent to {user.email}'


@shared_task(bind=True, max_retries=3)
def process_image(self, image_path):
    """处理图片（带重试）"""
    try:
        from PIL import Image
        
        img = Image.open(image_path)
        # 生成缩略图
        img.thumbnail((800, 600))
        img.save(image_path.replace('.', '_thumb.'))
        
        return 'Image processed successfully'
    except Exception as exc:
        # 重试，指数退避
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task
def send_daily_digest():
    """发送每日摘要"""
    from datetime import datetime, timedelta
    from django.contrib.auth import get_user_model
    
    User = get_user_model()
    yesterday = datetime.now() - timedelta(days=1)
    
    posts = Post.objects.filter(
        published_at__date=yesterday.date(),
        status='published'
    )
    
    if posts.exists():
        for user in User.objects.filter(is_active=True):
            send_notification_email.delay(user.id, posts.first().id)
    
    return f'Sent digest for {posts.count()} posts'


# 在视图中调用任务
def create_post(request):
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            
            # 异步发送通知
            send_notification_email.delay(request.user.id, post.id)
            
            return redirect('blog:post_detail', slug=post.slug)
```

```bash
# 启动 Celery Worker
celery -A myproject worker -l info

# 启动 Celery Beat（定时任务调度器）
celery -A myproject beat -l info

# 同时启动（开发环境）
celery -A myproject worker -B -l info
```


---

## 13. 测试

测试是保证代码质量的重要手段。Django 提供了完整的测试框架，支持单元测试、集成测试和功能测试。

### 13.1 模型测试

```python
# apps/blog/tests/test_models.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.blog.models import Post, Category, Tag

User = get_user_model()

class PostModelTest(TestCase):
    """文章模型测试"""
    
    @classmethod
    def setUpTestData(cls):
        """设置测试数据（整个测试类只执行一次）"""
        cls.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        cls.category = Category.objects.create(
            name='技术',
            slug='tech'
        )
    
    def setUp(self):
        """每个测试方法执行前运行"""
        self.post = Post.objects.create(
            title='测试文章',
            content='这是测试内容',
            author=self.user,
            category=self.category,
            status='draft'
        )
    
    def test_post_creation(self):
        """测试文章创建"""
        self.assertEqual(self.post.title, '测试文章')
        self.assertEqual(self.post.author, self.user)
        self.assertEqual(self.post.status, 'draft')
    
    def test_post_str(self):
        """测试 __str__ 方法"""
        self.assertEqual(str(self.post), '测试文章')
    
    def test_post_slug_auto_generation(self):
        """测试 slug 自动生成"""
        self.assertIsNotNone(self.post.slug)
    
    def test_post_publish(self):
        """测试发布文章"""
        self.post.status = 'published'
        self.post.save()
        self.assertIsNotNone(self.post.published_at)
    
    def test_post_increase_views(self):
        """测试增加浏览量"""
        initial_views = self.post.views_count
        self.post.increase_views()
        self.assertEqual(self.post.views_count, initial_views + 1)
    
    def test_post_manager_published(self):
        """测试自定义管理器"""
        self.post.status = 'published'
        self.post.save()
        
        published_posts = Post.objects.published()
        self.assertIn(self.post, published_posts)
```

### 13.2 视图测试

```python
# apps/blog/tests/test_views.py
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.blog.models import Post, Category

User = get_user_model()

class PostViewTest(TestCase):
    """文章视图测试"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.category = Category.objects.create(name='技术', slug='tech')
        self.post = Post.objects.create(
            title='测试文章',
            slug='test-post',
            content='测试内容',
            author=self.user,
            category=self.category,
            status='published'
        )
    
    def test_post_list_view(self):
        """测试文章列表页"""
        response = self.client.get(reverse('blog:post_list'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'blog/post_list.html')
        self.assertContains(response, '测试文章')
    
    def test_post_detail_view(self):
        """测试文章详情页"""
        response = self.client.get(
            reverse('blog:post_detail', kwargs={'slug': self.post.slug})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '测试文章')
        self.assertContains(response, '测试内容')
    
    def test_post_detail_view_404(self):
        """测试不存在的文章"""
        response = self.client.get(
            reverse('blog:post_detail', kwargs={'slug': 'not-exist'})
        )
        self.assertEqual(response.status_code, 404)
    
    def test_post_create_view_login_required(self):
        """测试创建文章需要登录"""
        response = self.client.get(reverse('blog:post_create'))
        self.assertEqual(response.status_code, 302)  # 重定向到登录页
    
    def test_post_create_view(self):
        """测试创建文章"""
        self.client.login(email='test@example.com', password='testpass123')
        
        response = self.client.post(reverse('blog:post_create'), {
            'title': '新文章',
            'content': '新内容',
            'category': self.category.id,
            'status': 'draft',
        })
        
        self.assertEqual(response.status_code, 302)  # 创建成功后重定向
        self.assertTrue(Post.objects.filter(title='新文章').exists())
```


### 13.3 API 测试

```python
# apps/blog/tests/test_api.py
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from apps.blog.models import Post, Category

User = get_user_model()

class PostAPITest(APITestCase):
    """文章 API 测试"""
    
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.category = Category.objects.create(name='技术', slug='tech')
        self.post = Post.objects.create(
            title='测试文章',
            slug='test-post',
            content='测试内容',
            author=self.user,
            category=self.category,
            status='published'
        )
    
    def test_get_post_list(self):
        """测试获取文章列表"""
        url = reverse('post-list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
    
    def test_get_post_detail(self):
        """测试获取文章详情"""
        url = reverse('post-detail', kwargs={'slug': self.post.slug})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], '测试文章')
    
    def test_create_post_unauthorized(self):
        """测试未登录创建文章"""
        url = reverse('post-list')
        data = {'title': '新文章', 'content': '内容'}
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_create_post(self):
        """测试创建文章"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('post-list')
        data = {
            'title': '新文章',
            'content': '新内容',
            'category_id': self.category.id,
            'status': 'draft',
        }
        response = self.client.post(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Post.objects.count(), 2)
    
    def test_update_post(self):
        """测试更新文章"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('post-detail', kwargs={'slug': self.post.slug})
        data = {'title': '更新后的标题'}
        response = self.client.patch(url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.post.refresh_from_db()
        self.assertEqual(self.post.title, '更新后的标题')
    
    def test_delete_post(self):
        """测试删除文章"""
        self.client.force_authenticate(user=self.user)
        
        url = reverse('post-detail', kwargs={'slug': self.post.slug})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Post.objects.count(), 0)
```

```bash
# 运行测试
python manage.py test

# 运行特定应用的测试
python manage.py test apps.blog

# 运行特定测试类
python manage.py test apps.blog.tests.test_models.PostModelTest

# 运行特定测试方法
python manage.py test apps.blog.tests.test_models.PostModelTest.test_post_creation

# 显示详细输出
python manage.py test -v 2

# 生成覆盖率报告
pip install coverage
coverage run --source='.' manage.py test
coverage report
coverage html  # 生成 HTML 报告
```


---

## 14. 部署

将 Django 应用部署到生产环境需要考虑安全性、性能和可维护性。

### 14.1 部署前检查

```bash
# Django 部署检查
python manage.py check --deploy

# 常见检查项：
# - DEBUG = False
# - SECRET_KEY 使用环境变量
# - ALLOWED_HOSTS 配置正确
# - 安全相关设置已启用
```

### 14.2 生产环境配置

```python
# myproject/settings/production.py
from .base import *
import os

DEBUG = False
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

# 安全设置
SECRET_KEY = os.getenv('SECRET_KEY')
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# 数据库
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '5432'),
        'CONN_MAX_AGE': 60,  # 数据库连接池
    }
}

# 缓存
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.getenv('REDIS_URL'),
    }
}

# 静态文件
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# 日志
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/error.log',
            'formatter': 'verbose',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
}
```

### 14.3 Gunicorn + Nginx 部署

```bash
# 安装 Gunicorn
pip install gunicorn

# 启动 Gunicorn
gunicorn myproject.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 2 \
    --timeout 30 \
    --access-logfile /var/log/gunicorn/access.log \
    --error-logfile /var/log/gunicorn/error.log
```

```nginx
# /etc/nginx/sites-available/myproject
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    client_max_body_size 10M;

    location /static/ {
        alias /var/www/myproject/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /media/ {
        alias /var/www/myproject/media/;
        expires 7d;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 14.4 Docker 部署

```dockerfile
# Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖
COPY requirements/production.txt .
RUN pip install --no-cache-dir -r production.txt

# 复制项目文件
COPY . .

# 收集静态文件
RUN python manage.py collectstatic --noinput

# 运行
CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8000"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DJANGO_SETTINGS_MODULE=myproject.settings.production
      - SECRET_KEY=${SECRET_KEY}
      - DB_HOST=db
      - DB_NAME=myproject
      - DB_USER=postgres
      - DB_PASSWORD=${DB_PASSWORD}
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=myproject
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=${DB_PASSWORD}

  redis:
    image: redis:7-alpine

  celery:
    build: .
    command: celery -A myproject worker -l info
    environment:
      - DJANGO_SETTINGS_MODULE=myproject.settings.production
    depends_on:
      - db
      - redis

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./staticfiles:/var/www/static
    depends_on:
      - web

volumes:
  postgres_data:
```


---

## 15. 常见错误与解决方案

### 15.1 数据库相关错误

```python
# ❌ 错误：django.db.utils.OperationalError: no such table: xxx
# 原因：数据库表不存在，通常是忘记执行迁移
# ✅ 解决：
python manage.py makemigrations
python manage.py migrate


# ❌ 错误：django.db.utils.IntegrityError: UNIQUE constraint failed
# 原因：违反唯一约束，插入了重复数据
# ✅ 解决：使用 get_or_create 或 update_or_create
obj, created = Model.objects.get_or_create(
    unique_field=value,
    defaults={'other_field': 'value'}
)


# ❌ 错误：django.db.utils.ProgrammingError: relation "xxx" does not exist
# 原因：PostgreSQL 中表不存在
# ✅ 解决：检查迁移状态，可能需要重新迁移
python manage.py showmigrations
python manage.py migrate --fake-initial  # 如果表已存在但迁移记录丢失


# ❌ 错误：Cannot add foreign key constraint
# 原因：外键引用的表或字段不存在，或数据类型不匹配
# ✅ 解决：确保被引用的模型先迁移，检查字段类型一致性


# ❌ 错误：InconsistentMigrationHistory
# 原因：迁移历史不一致
# ✅ 解决（开发环境）：
# 1. 删除所有迁移文件（保留 __init__.py）
# 2. 删除数据库
# 3. 重新 makemigrations 和 migrate
```

### 15.2 视图与URL错误

```python
# ❌ 错误：NoReverseMatch: Reverse for 'xxx' not found
# 原因：URL 名称不存在或参数不匹配
# ✅ 解决：
# 1. 检查 URL 名称是否正确
# 2. 检查是否使用了 namespace
# 3. 检查参数是否完整
{% url 'blog:post_detail' slug=post.slug %}  # 正确
{% url 'post_detail' slug=post.slug %}       # 如果没有 namespace


# ❌ 错误：AttributeError: 'NoneType' object has no attribute 'xxx'
# 原因：对象为 None，通常是查询没有结果
# ✅ 解决：使用 get_object_or_404 或检查是否为 None
from django.shortcuts import get_object_or_404
post = get_object_or_404(Post, slug=slug)

# 或者
post = Post.objects.filter(slug=slug).first()
if post is None:
    raise Http404("文章不存在")


# ❌ 错误：MultiValueDictKeyError
# 原因：访问不存在的 GET/POST 参数
# ✅ 解决：使用 .get() 方法
value = request.GET.get('key', 'default')  # 正确
value = request.GET['key']                  # 可能报错


# ❌ 错误：CSRF verification failed
# 原因：CSRF token 缺失或无效
# ✅ 解决：
# 1. 表单中添加 {% csrf_token %}
# 2. AJAX 请求添加 CSRF header
# 3. 如果是 API，考虑使用 @csrf_exempt（谨慎使用）
```

### 15.3 模板错误

```python
# ❌ 错误：TemplateDoesNotExist
# 原因：模板文件不存在或路径错误
# ✅ 解决：
# 1. 检查 TEMPLATES 配置中的 DIRS
# 2. 检查应用是否在 INSTALLED_APPS 中
# 3. 检查模板文件路径是否正确

# settings.py
TEMPLATES = [
    {
        'DIRS': [BASE_DIR / 'templates'],  # 项目级模板目录
        'APP_DIRS': True,  # 启用应用级模板目录
    },
]


# ❌ 错误：TemplateSyntaxError: Invalid block tag
# 原因：模板标签语法错误
# ✅ 解决：
# 1. 检查是否加载了自定义标签 {% load xxx %}
# 2. 检查标签名称是否正确
# 3. 检查是否有未闭合的标签


# ❌ 错误：'xxx' is not a valid tag library
# 原因：自定义模板标签库不存在
# ✅ 解决：
# 1. 确保 templatetags 目录下有 __init__.py
# 2. 确保标签文件名正确
# 3. 确保应用在 INSTALLED_APPS 中
```

### 15.4 静态文件与媒体文件错误

```python
# ❌ 错误：静态文件 404
# 原因：静态文件配置错误或未收集
# ✅ 解决：
# 1. 开发环境确保 DEBUG=True
# 2. 生产环境运行 collectstatic
python manage.py collectstatic

# 3. 检查 STATIC_URL 和 STATICFILES_DIRS 配置
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'


# ❌ 错误：媒体文件无法访问
# 原因：开发环境未配置媒体文件 URL
# ✅ 解决：在 urls.py 中添加
from django.conf import settings
from django.conf.urls.static import static

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

### 15.5 认证与权限错误

```python
# ❌ 错误：AUTH_USER_MODEL refers to model 'xxx' that has not been installed
# 原因：自定义用户模型配置错误
# ✅ 解决：
# 1. 确保在第一次迁移前设置 AUTH_USER_MODEL
# 2. 确保用户应用在 INSTALLED_APPS 中
# 3. 如果已有迁移，需要重置数据库


# ❌ 错误：RelatedObjectDoesNotExist: User has no profile
# 原因：一对一关联对象不存在
# ✅ 解决：使用 hasattr 检查或使用信号自动创建
if hasattr(user, 'profile'):
    profile = user.profile
else:
    profile = Profile.objects.create(user=user)

# 或使用信号
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


# ❌ 错误：PermissionDenied
# 原因：用户没有相应权限
# ✅ 解决：检查权限配置，或在视图中处理
from django.core.exceptions import PermissionDenied

def my_view(request):
    if not request.user.has_perm('app.permission_name'):
        raise PermissionDenied
```


### 15.6 性能问题

```python
# ❌ 问题：N+1 查询问题
# 原因：在循环中访问关联对象，导致大量数据库查询
# ✅ 解决：使用 select_related 和 prefetch_related

# 错误示例
posts = Post.objects.all()
for post in posts:
    print(post.author.username)  # 每次循环都查询数据库

# 正确示例
posts = Post.objects.select_related('author').all()  # 一对一/多对一
posts = Post.objects.prefetch_related('tags').all()  # 多对多/一对多


# ❌ 问题：查询过多数据
# 原因：获取了不需要的字段
# ✅ 解决：使用 only/defer 或 values/values_list
Post.objects.only('id', 'title')  # 只获取指定字段
Post.objects.defer('content')     # 延迟加载大字段
Post.objects.values('id', 'title')  # 返回字典


# ❌ 问题：重复查询
# 原因：同一数据多次查询
# ✅ 解决：使用缓存或在视图中预先获取
# 模板中
{% with posts=category.posts.all %}
    {% for post in posts %}...{% endfor %}
    共 {{ posts.count }} 篇
{% endwith %}


# ❌ 问题：大量数据内存溢出
# 原因：一次性加载过多数据
# ✅ 解决：使用 iterator() 或分批处理
for post in Post.objects.iterator(chunk_size=1000):
    process(post)

# 或使用分页
from django.core.paginator import Paginator
paginator = Paginator(Post.objects.all(), 100)
for page_num in paginator.page_range:
    for post in paginator.page(page_num):
        process(post)
```

### 15.7 REST Framework 错误

```python
# ❌ 错误：{"detail": "Authentication credentials were not provided."}
# 原因：API 需要认证但未提供凭证
# ✅ 解决：
# 1. 添加认证头
# Authorization: Token xxx
# Authorization: Bearer xxx

# 2. 或修改权限类
from rest_framework.permissions import AllowAny

class MyView(APIView):
    permission_classes = [AllowAny]


# ❌ 错误：{"detail": "Method \"XXX\" not allowed."}
# 原因：视图不支持该 HTTP 方法
# ✅ 解决：检查视图类或装饰器是否允许该方法
@api_view(['GET', 'POST'])  # 明确允许的方法
def my_view(request):
    pass


# ❌ 错误：序列化器验证失败
# 原因：数据不符合序列化器定义
# ✅ 解决：检查 serializer.errors
serializer = MySerializer(data=request.data)
if not serializer.is_valid():
    print(serializer.errors)  # 查看具体错误
    return Response(serializer.errors, status=400)


# ❌ 错误：Serializer field 'xxx' is not a valid field
# 原因：序列化器字段名与模型字段不匹配
# ✅ 解决：检查 Meta.fields 中的字段名是否正确
```

### 15.8 部署常见问题

```python
# ❌ 错误：DisallowedHost
# 原因：请求的 Host 不在 ALLOWED_HOSTS 中
# ✅ 解决：
ALLOWED_HOSTS = ['example.com', 'www.example.com', 'localhost']


# ❌ 错误：静态文件在生产环境无法加载
# 原因：Django 在 DEBUG=False 时不提供静态文件
# ✅ 解决：
# 1. 使用 WhiteNoise
pip install whitenoise

# settings.py
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # 添加这行
    # ...
]
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# 2. 或配置 Nginx 提供静态文件


# ❌ 错误：数据库连接超时
# 原因：数据库连接数不足或连接未复用
# ✅ 解决：配置连接池
DATABASES = {
    'default': {
        # ...
        'CONN_MAX_AGE': 60,  # 连接保持时间（秒）
        'OPTIONS': {
            'MAX_CONNS': 20,  # 最大连接数
        }
    }
}


# ❌ 错误：Gunicorn worker timeout
# 原因：请求处理时间过长
# ✅ 解决：
# 1. 增加超时时间
gunicorn --timeout 120 myproject.wsgi

# 2. 将耗时操作改为异步任务
# 3. 优化数据库查询
```

### 15.9 调试技巧

```python
# 1. 使用 Django Debug Toolbar
pip install django-debug-toolbar

# settings.py
INSTALLED_APPS = [
    # ...
    'debug_toolbar',
]

MIDDLEWARE = [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    # ...
]

INTERNAL_IPS = ['127.0.0.1']


# 2. 打印 SQL 查询
from django.db import connection
print(connection.queries)

# 或使用 QuerySet.query
print(Post.objects.filter(status='published').query)


# 3. 使用 logging
import logging
logger = logging.getLogger(__name__)

logger.debug('Debug message')
logger.info('Info message')
logger.warning('Warning message')
logger.error('Error message')


# 4. 使用 shell_plus（django-extensions）
pip install django-extensions

# settings.py
INSTALLED_APPS = [
    # ...
    'django_extensions',
]

python manage.py shell_plus  # 自动导入所有模型


# 5. 使用 pdb 调试
import pdb; pdb.set_trace()  # 在代码中设置断点

# 或使用 breakpoint()（Python 3.7+）
breakpoint()
```

---

## 附录：常用命令速查

```bash
# 项目管理
django-admin startproject myproject    # 创建项目
python manage.py startapp myapp        # 创建应用
python manage.py runserver             # 启动开发服务器
python manage.py runserver 0.0.0.0:8000  # 允许外部访问

# 数据库
python manage.py makemigrations        # 创建迁移
python manage.py migrate               # 执行迁移
python manage.py showmigrations        # 查看迁移状态
python manage.py sqlmigrate app 0001   # 查看迁移 SQL
python manage.py dbshell               # 数据库命令行

# 用户管理
python manage.py createsuperuser       # 创建超级用户
python manage.py changepassword user   # 修改密码

# 静态文件
python manage.py collectstatic         # 收集静态文件

# Shell
python manage.py shell                 # Django shell
python manage.py shell_plus            # 增强 shell（需要 django-extensions）

# 测试
python manage.py test                  # 运行测试
python manage.py test --verbosity=2    # 详细输出

# 检查
python manage.py check                 # 检查项目问题
python manage.py check --deploy        # 部署检查

# 清理
python manage.py clearsessions         # 清理过期会话
python manage.py flush                 # 清空数据库（危险）
```

---

> 本笔记涵盖了 Django 从入门到进阶的核心知识点，建议结合官方文档和实际项目进行学习。
> 官方文档：https://docs.djangoproject.com/
> Django REST Framework：https://www.django-rest-framework.org/
