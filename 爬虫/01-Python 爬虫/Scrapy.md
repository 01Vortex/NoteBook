

> Scrapy 是 Python 最强大的爬虫框架，提供了完整的爬虫解决方案
> 适合构建大规模、高性能的数据采集系统

---

## 目录

1. [基础概念](#1-基础概念)
2. [环境搭建](#2-环境搭建)
3. [项目结构](#3-项目结构)
4. [Spider 爬虫](#4-spider-爬虫)
5. [选择器](#5-选择器)
6. [Item 数据项](#6-item-数据项)
7. [Item Pipeline](#7-item-pipeline)
8. [中间件](#8-中间件)
9. [请求与响应](#9-请求与响应)
10. [设置与配置](#10-设置与配置)
11. [反爬应对](#11-反爬应对)
12. [分布式爬虫](#12-分布式爬虫)
13. [数据存储](#13-数据存储)
14. [性能优化](#14-性能优化)
15. [部署与监控](#15-部署与监控)
16. [常见错误与解决方案](#16-常见错误与解决方案)

---

## 1. 基础概念

### 1.1 什么是 Scrapy？

Scrapy 是一个用 Python 编写的开源爬虫框架，专为快速、高效地抓取网站数据而设计。

**通俗理解**：
- 如果说 Requests 是手动挡汽车，Scrapy 就是自动挡
- Scrapy 帮你处理了并发、去重、数据管道等繁琐工作
- 你只需要关注"抓什么"和"怎么解析"

**核心特点**：

1. **异步架构**：基于 Twisted 异步网络框架，高并发性能优异
2. **内置功能丰富**：选择器、中间件、管道、去重、限速等
3. **可扩展性强**：中间件和管道机制支持高度定制
4. **社区活跃**：大量扩展库和文档支持

### 1.2 Scrapy 架构

```
                                        ┌─────────────┐
                                        │   Spider    │
                                        │  (爬虫逻辑)  │
                                        └──────┬──────┘
                                               │
                              ┌────────────────┼────────────────┐
                              │                │                │
                              ▼                │                ▼
                        ┌──────────┐           │          ┌──────────┐
                        │  Items   │           │          │ Requests │
                        │ (数据项) │           │          │  (请求)  │
                        └────┬─────┘           │          └────┬─────┘
                             │                 │               │
                             ▼                 │               ▼
                     ┌───────────────┐         │      ┌─────────────────┐
                     │ Item Pipeline │         │      │ Scheduler       │
                     │  (数据管道)   │         │      │   (调度器)      │
                     └───────────────┘         │      └────────┬────────┘
                                               │               │
                                               │               ▼
                                               │      ┌─────────────────┐
                                               │      │ Downloader      │
                                               │      │ Middlewares     │
                                               │      │  (下载中间件)   │
                                               │      └────────┬────────┘
                                               │               │
                                               │               ▼
                                               │      ┌─────────────────┐
                                               └──────│   Downloader    │
                                                      │   (下载器)      │
                                                      └────────┬────────┘
                                                               │
                                                               ▼
                                                      ┌─────────────────┐
                                                      │    Internet     │
                                                      │    (互联网)     │
                                                      └─────────────────┘
```

**数据流程**：
1. Spider 生成初始 Request
2. Scheduler 调度 Request
3. Downloader 下载页面，返回 Response
4. Spider 解析 Response，提取 Item 或新 Request
5. Item Pipeline 处理数据（清洗、存储）

### 1.3 Scrapy vs 其他方案

| 特性 | Scrapy | Requests + BeautifulSoup | Selenium |
|------|--------|--------------------------|----------|
| 学习曲线 | 中等 | 简单 | 简单 |
| 性能 | 高（异步） | 低（同步） | 很低 |
| JavaScript 渲染 | 需配合 Splash | ❌ | ✅ |
| 适用场景 | 大规模爬取 | 简单爬取 | 动态页面 |
| 内置功能 | 丰富 | 需自己实现 | 浏览器自动化 |

---

## 2. 环境搭建

### 2.1 安装 Scrapy

```bash
# 使用 pip 安装
pip install scrapy

# 推荐使用虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install scrapy

# 验证安装
scrapy version
```

**Windows 常见问题**：
```bash
# 如果安装 Twisted 失败，先安装 wheel
pip install wheel

# 或者使用 conda
conda install -c conda-forge scrapy
```

### 2.2 创建项目

```bash
# 创建项目
scrapy startproject myspider

# 项目结构
myspider/
├── scrapy.cfg              # 部署配置文件
└── myspider/
    ├── __init__.py
    ├── items.py            # 数据项定义
    ├── middlewares.py      # 中间件
    ├── pipelines.py        # 数据管道
    ├── settings.py         # 项目设置
    └── spiders/            # 爬虫目录
        └── __init__.py

# 创建爬虫
cd myspider
scrapy genspider example example.com
```

### 2.3 运行爬虫

```bash
# 运行爬虫
scrapy crawl example

# 输出到文件
scrapy crawl example -o output.json
scrapy crawl example -o output.csv
scrapy crawl example -o output.xml

# 指定日志级别
scrapy crawl example -L INFO

# 在脚本中运行
from scrapy.crawler import CrawlerProcess
from myspider.spiders.example import ExampleSpider

process = CrawlerProcess()
process.crawl(ExampleSpider)
process.start()
```

---

## 3. 项目结构

### 3.1 标准项目结构

```
myspider/
├── scrapy.cfg                  # Scrapy 部署配置
└── myspider/
    ├── __init__.py
    ├── items.py                # 定义数据结构
    ├── middlewares.py          # 自定义中间件
    ├── pipelines.py            # 数据处理管道
    ├── settings.py             # 项目配置
    └── spiders/                # 爬虫文件夹
        ├── __init__.py
        ├── example_spider.py   # 爬虫文件
        └── another_spider.py
```

### 3.2 大型项目结构

```
myspider/
├── scrapy.cfg
├── requirements.txt
├── README.md
└── myspider/
    ├── __init__.py
    ├── items/                  # 多个 Item 定义
    │   ├── __init__.py
    │   ├── product.py
    │   └── user.py
    ├── middlewares/            # 多个中间件
    │   ├── __init__.py
    │   ├── proxy.py
    │   └── useragent.py
    ├── pipelines/              # 多个管道
    │   ├── __init__.py
    │   ├── clean.py
    │   ├── mysql.py
    │   └── mongodb.py
    ├── utils/                  # 工具函数
    │   ├── __init__.py
    │   └── helpers.py
    ├── settings/               # 多环境配置
    │   ├── __init__.py
    │   ├── base.py
    │   ├── dev.py
    │   └── prod.py
    ├── settings.py
    └── spiders/
        ├── __init__.py
        └── ...
```

---

## 4. Spider 爬虫

### 4.1 基础 Spider

```python
# spiders/quotes_spider.py
import scrapy


class QuotesSpider(scrapy.Spider):
    """爬取名言网站的爬虫"""
    
    # 爬虫名称（必须唯一）
    name = 'quotes'
    
    # 允许爬取的域名
    allowed_domains = ['quotes.toscrape.com']
    
    # 起始 URL
    start_urls = [
        'https://quotes.toscrape.com/page/1/',
    ]
    
    def parse(self, response):
        """解析响应，提取数据"""
        # 提取所有名言
        for quote in response.css('div.quote'):
            yield {
                'text': quote.css('span.text::text').get(),
                'author': quote.css('small.author::text').get(),
                'tags': quote.css('div.tags a.tag::text').getall(),
            }
        
        # 提取下一页链接并继续爬取
        next_page = response.css('li.next a::attr(href)').get()
        if next_page:
            yield response.follow(next_page, callback=self.parse)
```

### 4.2 使用 start_requests

```python
import scrapy


class ProductSpider(scrapy.Spider):
    name = 'product'
    
    def start_requests(self):
        """自定义起始请求（更灵活）"""
        # 可以从数据库、文件等读取 URL
        urls = [
            'https://example.com/product/1',
            'https://example.com/product/2',
            'https://example.com/product/3',
        ]
        
        for url in urls:
            yield scrapy.Request(
                url=url,
                callback=self.parse,
                meta={'category': 'electronics'},  # 传递额外数据
                headers={'Referer': 'https://example.com'},
            )
    
    def parse(self, response):
        category = response.meta.get('category')
        yield {
            'url': response.url,
            'category': category,
            'title': response.css('h1::text').get(),
        }
```

### 4.3 CrawlSpider（规则爬虫）

CrawlSpider 适合需要跟踪链接的场景，通过规则自动提取链接。

```python
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor


class NewsSpider(CrawlSpider):
    name = 'news'
    allowed_domains = ['news.example.com']
    start_urls = ['https://news.example.com/']
    
    rules = (
        # 提取分类页面链接，继续跟踪
        Rule(
            LinkExtractor(allow=r'/category/\w+'),
            follow=True
        ),
        # 提取文章链接，调用 parse_article 解析
        Rule(
            LinkExtractor(allow=r'/article/\d+'),
            callback='parse_article',
            follow=False
        ),
    )
    
    def parse_article(self, response):
        yield {
            'title': response.css('h1.title::text').get(),
            'content': response.css('div.content').get(),
            'publish_time': response.css('time::attr(datetime)').get(),
        }
```

### 4.4 XMLFeedSpider 和 CSVFeedSpider

```python
from scrapy.spiders import XMLFeedSpider


class RSSSpider(XMLFeedSpider):
    """爬取 RSS 订阅"""
    name = 'rss'
    start_urls = ['https://example.com/feed.xml']
    iterator = 'iternodes'  # 迭代方式
    itertag = 'item'        # 迭代的标签
    
    def parse_node(self, response, node):
        yield {
            'title': node.xpath('title/text()').get(),
            'link': node.xpath('link/text()').get(),
            'description': node.xpath('description/text()').get(),
        }
```

### 4.5 SitemapSpider

```python
from scrapy.spiders import SitemapSpider


class MySitemapSpider(SitemapSpider):
    """从 sitemap 爬取"""
    name = 'sitemap'
    sitemap_urls = ['https://example.com/sitemap.xml']
    
    # 根据 URL 模式选择不同的解析方法
    sitemap_rules = [
        ('/product/', 'parse_product'),
        ('/category/', 'parse_category'),
    ]
    
    def parse_product(self, response):
        yield {'type': 'product', 'url': response.url}
    
    def parse_category(self, response):
        yield {'type': 'category', 'url': response.url}
```

---

## 5. 选择器

Scrapy 支持 CSS 选择器和 XPath 两种方式提取数据。

### 5.1 CSS 选择器

```python
def parse(self, response):
    # 获取单个元素的文本
    title = response.css('h1::text').get()
    
    # 获取所有匹配元素
    links = response.css('a::attr(href)').getall()
    
    # 获取属性
    image_url = response.css('img::attr(src)').get()
    
    # 嵌套选择
    for item in response.css('div.product'):
        name = item.css('h2.name::text').get()
        price = item.css('span.price::text').get()
    
    # 常用 CSS 选择器
    response.css('div')              # 标签选择器
    response.css('.class')           # 类选择器
    response.css('#id')              # ID 选择器
    response.css('div.class')        # 组合选择器
    response.css('div > p')          # 子元素
    response.css('div p')            # 后代元素
    response.css('div + p')          # 相邻兄弟
    response.css('div ~ p')          # 所有兄弟
    response.css('[attr]')           # 属性存在
    response.css('[attr=value]')     # 属性等于
    response.css('[attr*=value]')    # 属性包含
    response.css('[attr^=value]')    # 属性开头
    response.css('[attr$=value]')    # 属性结尾
    response.css(':nth-child(2)')    # 第 n 个子元素
    response.css(':first-child')     # 第一个子元素
    response.css(':last-child')      # 最后一个子元素
    
    # 伪元素获取文本和属性
    response.css('a::text')          # 获取文本
    response.css('a::attr(href)')    # 获取属性
```

### 5.2 XPath 选择器

```python
def parse(self, response):
    # 获取文本
    title = response.xpath('//h1/text()').get()
    
    # 获取属性
    href = response.xpath('//a/@href').get()
    
    # 获取所有匹配
    items = response.xpath('//div[@class="item"]').getall()
    
    # 常用 XPath 表达式
    response.xpath('//div')                    # 所有 div
    response.xpath('//div[@class="name"]')     # class 属性
    response.xpath('//div[@id="main"]')        # id 属性
    response.xpath('//div/p')                  # 子元素
    response.xpath('//div//p')                 # 后代元素
    response.xpath('//div/p[1]')               # 第一个 p
    response.xpath('//div/p[last()]')          # 最后一个 p
    response.xpath('//div/p[position()<3]')    # 前两个 p
    response.xpath('//a[contains(@href, "page")]')  # 属性包含
    response.xpath('//a[starts-with(@href, "/")]')  # 属性开头
    response.xpath('//div[contains(@class, "item")]')  # class 包含
    response.xpath('//div/text()')             # 直接文本
    response.xpath('//div//text()')            # 所有文本
    response.xpath('string(//div)')            # 合并所有文本
    response.xpath('//div/@*')                 # 所有属性
    
    # XPath 函数
    response.xpath('normalize-space(//p)')     # 去除空白
    response.xpath('count(//div)')             # 计数
    response.xpath('//div[not(@class)]')       # 否定
    response.xpath('//div[@class and @id]')    # 与
    response.xpath('//div[@class or @id]')     # 或
```

### 5.3 选择器进阶

```python
def parse(self, response):
    # 链式调用
    for product in response.css('div.product'):
        name = product.css('h2::text').get()
        # 在子元素中继续使用 XPath
        price = product.xpath('.//span[@class="price"]/text()').get()
    
    # 正则表达式提取
    price = response.css('span.price::text').re_first(r'\d+\.?\d*')
    numbers = response.css('p::text').re(r'\d+')
    
    # 默认值
    title = response.css('h1::text').get(default='无标题')
    
    # 获取 HTML
    html = response.css('div.content').get()  # 包含标签
    
    # 组合使用
    # 先用 CSS 定位，再用 XPath 精确提取
    items = response.css('div.item')
    for item in items:
        text = item.xpath('normalize-space(.)').get()
```

**⚠️ 常见错误**：
```python
# ❌ 错误：忘记 get() 或 getall()
title = response.css('h1::text')  # 返回 SelectorList，不是字符串

# ✅ 正确
title = response.css('h1::text').get()

# ❌ 错误：XPath 相对路径忘记加点
for item in response.css('div.item'):
    name = item.xpath('//h2/text()').get()  # 从根开始找，错误！

# ✅ 正确：使用 .// 表示相对路径
for item in response.css('div.item'):
    name = item.xpath('.//h2/text()').get()

# ❌ 错误：class 属性包含多个值时精确匹配失败
response.xpath('//div[@class="item active"]')  # 可能匹配不到

# ✅ 正确：使用 contains
response.xpath('//div[contains(@class, "item")]')
```

---

## 6. Item 数据项

Item 用于定义爬取数据的结构，类似于数据库的表结构。

### 6.1 定义 Item

```python
# items.py
import scrapy
from scrapy import Field
from itemloaders.processors import TakeFirst, MapCompose, Join


class ProductItem(scrapy.Item):
    """商品数据项"""
    name = scrapy.Field()
    price = scrapy.Field()
    description = scrapy.Field()
    url = scrapy.Field()
    image_urls = scrapy.Field()  # 图片下载用
    images = scrapy.Field()      # 图片下载结果
    category = scrapy.Field()
    stock = scrapy.Field()
    
    
class ArticleItem(scrapy.Item):
    """文章数据项"""
    title = scrapy.Field()
    author = scrapy.Field()
    content = scrapy.Field()
    publish_time = scrapy.Field()
    tags = scrapy.Field()
```

### 6.2 使用 Item

```python
# spiders/product_spider.py
from myspider.items import ProductItem


class ProductSpider(scrapy.Spider):
    name = 'product'
    
    def parse(self, response):
        for product in response.css('div.product'):
            item = ProductItem()
            item['name'] = product.css('h2::text').get()
            item['price'] = product.css('.price::text').get()
            item['url'] = response.url
            yield item
        
        # 或者使用字典方式
        yield ProductItem(
            name=response.css('h2::text').get(),
            price=response.css('.price::text').get(),
        )
```

### 6.3 ItemLoader（推荐）

ItemLoader 提供了更优雅的数据填充和处理方式。

```python
# items.py
import scrapy
from itemloaders.processors import TakeFirst, MapCompose, Join, Compose
from w3lib.html import remove_tags
import re


def clean_price(value):
    """清洗价格"""
    if value:
        match = re.search(r'[\d.]+', value)
        return float(match.group()) if match else None
    return None


def clean_text(value):
    """清洗文本"""
    return value.strip() if value else None


class ProductItem(scrapy.Item):
    name = scrapy.Field(
        input_processor=MapCompose(str.strip),
        output_processor=TakeFirst()
    )
    price = scrapy.Field(
        input_processor=MapCompose(clean_price),
        output_processor=TakeFirst()
    )
    description = scrapy.Field(
        input_processor=MapCompose(remove_tags, clean_text),
        output_processor=Join('\n')
    )
    tags = scrapy.Field(
        input_processor=MapCompose(str.strip, str.lower),
        output_processor=Compose(set, list)  # 去重
    )
```

```python
# spiders/product_spider.py
from scrapy.loader import ItemLoader
from myspider.items import ProductItem


class ProductSpider(scrapy.Spider):
    name = 'product'
    
    def parse(self, response):
        for product in response.css('div.product'):
            loader = ItemLoader(item=ProductItem(), selector=product)
            
            # 使用 CSS 选择器添加值
            loader.add_css('name', 'h2.title::text')
            loader.add_css('price', 'span.price::text')
            loader.add_css('description', 'div.desc')
            loader.add_css('tags', 'a.tag::text')
            
            # 使用 XPath 添加值
            loader.add_xpath('name', './/h2/text()')
            
            # 直接添加值
            loader.add_value('url', response.url)
            
            yield loader.load_item()
```

### 6.4 自定义 ItemLoader

```python
# loaders.py
from scrapy.loader import ItemLoader
from itemloaders.processors import TakeFirst, MapCompose, Join


class ProductLoader(ItemLoader):
    """商品专用 Loader"""
    
    # 默认输出处理器：取第一个值
    default_output_processor = TakeFirst()
    
    # 特定字段的处理器
    description_out = Join('\n')
    tags_out = list  # 保留列表
    
    # 自定义输入处理器
    price_in = MapCompose(
        lambda x: x.replace('¥', '').replace(',', ''),
        float
    )
```

```python
# 使用自定义 Loader
from myspider.loaders import ProductLoader

loader = ProductLoader(item=ProductItem(), response=response)
loader.add_css('name', 'h2::text')
item = loader.load_item()
```

---

## 7. Item Pipeline

Pipeline 用于处理 Spider 提取的数据，如清洗、验证、存储等。

### 7.1 基础 Pipeline

```python
# pipelines.py

class CleanPipeline:
    """数据清洗管道"""
    
    def process_item(self, item, spider):
        # 清洗名称
        if item.get('name'):
            item['name'] = item['name'].strip()
        
        # 清洗价格
        if item.get('price'):
            price = item['price']
            if isinstance(price, str):
                item['price'] = float(price.replace('¥', '').replace(',', ''))
        
        return item


class ValidatePipeline:
    """数据验证管道"""
    
    def process_item(self, item, spider):
        # 验证必填字段
        if not item.get('name'):
            raise DropItem(f"缺少名称: {item}")
        
        if not item.get('price') or item['price'] <= 0:
            raise DropItem(f"价格无效: {item}")
        
        return item


class DuplicatesPipeline:
    """去重管道"""
    
    def __init__(self):
        self.seen = set()
    
    def process_item(self, item, spider):
        # 根据 URL 去重
        url = item.get('url')
        if url in self.seen:
            raise DropItem(f"重复项: {url}")
        
        self.seen.add(url)
        return item
```

### 7.2 Pipeline 生命周期

```python
# pipelines.py
from scrapy.exceptions import DropItem


class MyPipeline:
    """完整的 Pipeline 示例"""
    
    @classmethod
    def from_crawler(cls, crawler):
        """从 crawler 创建实例，可以访问设置"""
        return cls(
            db_uri=crawler.settings.get('MONGO_URI'),
            db_name=crawler.settings.get('MONGO_DATABASE')
        )
    
    def __init__(self, db_uri, db_name):
        self.db_uri = db_uri
        self.db_name = db_name
    
    def open_spider(self, spider):
        """爬虫启动时调用"""
        self.client = pymongo.MongoClient(self.db_uri)
        self.db = self.client[self.db_name]
        spider.logger.info('Pipeline 已启动')
    
    def close_spider(self, spider):
        """爬虫关闭时调用"""
        self.client.close()
        spider.logger.info('Pipeline 已关闭')
    
    def process_item(self, item, spider):
        """处理每个 Item"""
        # 处理逻辑
        self.db[spider.name].insert_one(dict(item))
        return item
```

### 7.3 启用 Pipeline

```python
# settings.py

# 数字表示优先级，越小越先执行
ITEM_PIPELINES = {
    'myspider.pipelines.CleanPipeline': 100,
    'myspider.pipelines.ValidatePipeline': 200,
    'myspider.pipelines.DuplicatesPipeline': 300,
    'myspider.pipelines.MongoPipeline': 400,
}
```

### 7.4 存储到数据库

```python
# pipelines.py
import pymongo
import pymysql
from itemadapter import ItemAdapter


class MongoPipeline:
    """MongoDB 存储管道"""
    
    collection_name = 'items'
    
    def __init__(self, mongo_uri, mongo_db):
        self.mongo_uri = mongo_uri
        self.mongo_db = mongo_db
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            mongo_uri=crawler.settings.get('MONGO_URI', 'mongodb://localhost:27017'),
            mongo_db=crawler.settings.get('MONGO_DATABASE', 'scrapy')
        )
    
    def open_spider(self, spider):
        self.client = pymongo.MongoClient(self.mongo_uri)
        self.db = self.client[self.mongo_db]
    
    def close_spider(self, spider):
        self.client.close()
    
    def process_item(self, item, spider):
        self.db[self.collection_name].insert_one(ItemAdapter(item).asdict())
        return item


class MySQLPipeline:
    """MySQL 存储管道"""
    
    def __init__(self, host, database, user, password):
        self.host = host
        self.database = database
        self.user = user
        self.password = password
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            host=crawler.settings.get('MYSQL_HOST', 'localhost'),
            database=crawler.settings.get('MYSQL_DATABASE'),
            user=crawler.settings.get('MYSQL_USER'),
            password=crawler.settings.get('MYSQL_PASSWORD'),
        )
    
    def open_spider(self, spider):
        self.conn = pymysql.connect(
            host=self.host,
            database=self.database,
            user=self.user,
            password=self.password,
            charset='utf8mb4'
        )
        self.cursor = self.conn.cursor()
    
    def close_spider(self, spider):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()
    
    def process_item(self, item, spider):
        sql = """
            INSERT INTO products (name, price, url)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE price = VALUES(price)
        """
        self.cursor.execute(sql, (
            item.get('name'),
            item.get('price'),
            item.get('url'),
        ))
        self.conn.commit()
        return item
```

---

## 8. 中间件

中间件是 Scrapy 的钩子系统，可以在请求/响应处理过程中插入自定义逻辑。

### 8.1 下载中间件

```python
# middlewares.py
import random
from scrapy import signals
from scrapy.http import HtmlResponse
from scrapy.exceptions import IgnoreRequest


class RandomUserAgentMiddleware:
    """随机 User-Agent 中间件"""
    
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36...',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36...',
    ]
    
    def process_request(self, request, spider):
        """处理请求（发送前）"""
        request.headers['User-Agent'] = random.choice(self.USER_AGENTS)
        return None  # 继续处理
    
    def process_response(self, request, response, spider):
        """处理响应（返回后）"""
        return response  # 必须返回 Response
    
    def process_exception(self, request, exception, spider):
        """处理异常"""
        spider.logger.error(f'请求异常: {exception}')
        return None  # 继续处理异常


class ProxyMiddleware:
    """代理中间件"""
    
    def __init__(self, proxy_list):
        self.proxy_list = proxy_list
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            proxy_list=crawler.settings.getlist('PROXY_LIST')
        )
    
    def process_request(self, request, spider):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            request.meta['proxy'] = proxy
            spider.logger.debug(f'使用代理: {proxy}')


class RetryMiddleware:
    """自定义重试中间件"""
    
    RETRY_CODES = [500, 502, 503, 504, 408, 429]
    
    def __init__(self, max_retry_times):
        self.max_retry_times = max_retry_times
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            max_retry_times=crawler.settings.getint('RETRY_TIMES', 3)
        )
    
    def process_response(self, request, response, spider):
        if response.status in self.RETRY_CODES:
            retry_times = request.meta.get('retry_times', 0)
            
            if retry_times < self.max_retry_times:
                retry_request = request.copy()
                retry_request.meta['retry_times'] = retry_times + 1
                retry_request.dont_filter = True
                spider.logger.warning(
                    f'重试 {retry_times + 1}/{self.max_retry_times}: {request.url}'
                )
                return retry_request
            else:
                spider.logger.error(f'重试次数用尽: {request.url}')
        
        return response
```

### 8.2 Spider 中间件

```python
# middlewares.py

class DepthMiddleware:
    """深度控制中间件"""
    
    def __init__(self, max_depth):
        self.max_depth = max_depth
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            max_depth=crawler.settings.getint('DEPTH_LIMIT', 3)
        )
    
    def process_spider_output(self, response, result, spider):
        """处理 Spider 输出"""
        depth = response.meta.get('depth', 0)
        
        for item in result:
            if isinstance(item, scrapy.Request):
                if depth >= self.max_depth:
                    spider.logger.debug(f'达到最大深度，跳过: {item.url}')
                    continue
                item.meta['depth'] = depth + 1
            yield item
    
    def process_spider_input(self, response, spider):
        """处理 Spider 输入"""
        return None  # 继续处理
    
    def process_spider_exception(self, response, exception, spider):
        """处理 Spider 异常"""
        spider.logger.error(f'Spider 异常: {exception}')
        return None
```

### 8.3 启用中间件

```python
# settings.py

# 下载中间件
DOWNLOADER_MIDDLEWARES = {
    # 禁用默认中间件
    'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': None,
    # 启用自定义中间件
    'myspider.middlewares.RandomUserAgentMiddleware': 400,
    'myspider.middlewares.ProxyMiddleware': 410,
    'myspider.middlewares.RetryMiddleware': 500,
}

# Spider 中间件
SPIDER_MIDDLEWARES = {
    'myspider.middlewares.DepthMiddleware': 100,
}
```

### 8.4 Selenium 中间件

```python
# middlewares.py
from scrapy.http import HtmlResponse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class SeleniumMiddleware:
    """Selenium 渲染中间件"""
    
    def __init__(self):
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        self.driver = webdriver.Chrome(options=chrome_options)
    
    def process_request(self, request, spider):
        # 只处理标记了需要 Selenium 的请求
        if not request.meta.get('selenium'):
            return None
        
        self.driver.get(request.url)
        
        # 等待页面加载
        wait_for = request.meta.get('wait_for')
        if wait_for:
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located(wait_for)
            )
        
        body = self.driver.page_source
        return HtmlResponse(
            url=request.url,
            body=body,
            encoding='utf-8',
            request=request
        )
    
    def spider_closed(self, spider):
        self.driver.quit()
```

```python
# 在 Spider 中使用
def start_requests(self):
    yield scrapy.Request(
        url='https://example.com',
        meta={
            'selenium': True,
            'wait_for': (By.CSS_SELECTOR, 'div.content')
        }
    )
```

---

## 9. 请求与响应

### 9.1 Request 对象

```python
import scrapy
from scrapy import Request


class MySpider(scrapy.Spider):
    name = 'myspider'
    
    def start_requests(self):
        # 基本请求
        yield Request(
            url='https://example.com',
            callback=self.parse
        )
        
        # 完整参数
        yield Request(
            url='https://example.com/api',
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer token123',
            },
            body='{"key": "value"}',
            cookies={'session': 'abc123'},
            meta={
                'item': item,           # 传递数据
                'proxy': 'http://proxy:8080',  # 使用代理
                'download_timeout': 30,  # 超时时间
            },
            callback=self.parse_api,
            errback=self.handle_error,  # 错误回调
            dont_filter=False,          # 是否去重
            priority=10,                # 优先级（越大越优先）
            cb_kwargs={'page': 1},      # 回调参数
        )
    
    def parse(self, response):
        pass
    
    def parse_api(self, response, page):
        # cb_kwargs 中的参数会传递到这里
        print(f'当前页: {page}')
    
    def handle_error(self, failure):
        """处理请求错误"""
        self.logger.error(f'请求失败: {failure.request.url}')
        self.logger.error(f'错误类型: {failure.type}')
```

### 9.2 FormRequest（表单请求）

```python
from scrapy import FormRequest


class LoginSpider(scrapy.Spider):
    name = 'login'
    
    def start_requests(self):
        # 先访问登录页获取 CSRF token
        yield Request(
            url='https://example.com/login',
            callback=self.parse_login_page
        )
    
    def parse_login_page(self, response):
        # 提取 CSRF token
        csrf_token = response.css('input[name="csrf"]::attr(value)').get()
        
        # 提交登录表单
        yield FormRequest(
            url='https://example.com/login',
            formdata={
                'username': 'myuser',
                'password': 'mypass',
                'csrf': csrf_token,
            },
            callback=self.after_login
        )
        
        # 或者使用 from_response 自动填充表单
        yield FormRequest.from_response(
            response,
            formxpath='//form[@id="login"]',
            formdata={
                'username': 'myuser',
                'password': 'mypass',
            },
            callback=self.after_login
        )
    
    def after_login(self, response):
        # 检查是否登录成功
        if 'Welcome' in response.text:
            self.logger.info('登录成功')
            # 继续爬取需要登录的页面
            yield Request(
                url='https://example.com/dashboard',
                callback=self.parse_dashboard
            )
        else:
            self.logger.error('登录失败')
```

### 9.3 JsonRequest

```python
from scrapy.http import JsonRequest


class ApiSpider(scrapy.Spider):
    name = 'api'
    
    def start_requests(self):
        # JSON POST 请求
        yield JsonRequest(
            url='https://api.example.com/data',
            data={
                'page': 1,
                'size': 20,
                'filters': {'category': 'electronics'}
            },
            callback=self.parse_api
        )
    
    def parse_api(self, response):
        data = response.json()  # 直接解析 JSON
        for item in data['items']:
            yield item
        
        # 翻页
        if data['has_next']:
            yield JsonRequest(
                url='https://api.example.com/data',
                data={
                    'page': data['page'] + 1,
                    'size': 20,
                },
                callback=self.parse_api
            )
```

### 9.4 Response 对象

```python
def parse(self, response):
    # 基本属性
    print(response.url)           # 请求 URL
    print(response.status)        # 状态码
    print(response.headers)       # 响应头
    print(response.body)          # 响应体（bytes）
    print(response.text)          # 响应体（str）
    print(response.encoding)      # 编码
    
    # 选择器
    response.css('div')
    response.xpath('//div')
    
    # JSON 响应
    data = response.json()
    
    # 获取请求信息
    print(response.request.url)
    print(response.request.headers)
    print(response.meta)
    
    # 跟踪链接
    yield response.follow('next-page.html', callback=self.parse)
    yield response.follow_all(response.css('a.link'), callback=self.parse)
    
    # 构建绝对 URL
    absolute_url = response.urljoin('/path/to/page')
```

---

## 10. 设置与配置

### 10.1 常用设置

```python
# settings.py

# ==================== 基本设置 ====================
BOT_NAME = 'myspider'
SPIDER_MODULES = ['myspider.spiders']
NEWSPIDER_MODULE = 'myspider.spiders'

# ==================== 爬取行为 ====================
# 是否遵守 robots.txt
ROBOTSTXT_OBEY = False

# 并发请求数
CONCURRENT_REQUESTS = 16

# 同一域名并发数
CONCURRENT_REQUESTS_PER_DOMAIN = 8

# 同一 IP 并发数
CONCURRENT_REQUESTS_PER_IP = 0

# 下载延迟（秒）
DOWNLOAD_DELAY = 1

# 随机延迟（0.5 * DOWNLOAD_DELAY ~ 1.5 * DOWNLOAD_DELAY）
RANDOMIZE_DOWNLOAD_DELAY = True

# 下载超时
DOWNLOAD_TIMEOUT = 30

# ==================== 请求设置 ====================
# 默认请求头
DEFAULT_REQUEST_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
}

# User-Agent
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# Cookies
COOKIES_ENABLED = True
COOKIES_DEBUG = False

# ==================== 重试设置 ====================
RETRY_ENABLED = True
RETRY_TIMES = 3
RETRY_HTTP_CODES = [500, 502, 503, 504, 408, 429]

# ==================== 缓存设置 ====================
HTTPCACHE_ENABLED = True
HTTPCACHE_EXPIRATION_SECS = 86400  # 24 小时
HTTPCACHE_DIR = 'httpcache'
HTTPCACHE_IGNORE_HTTP_CODES = [500, 502, 503, 504]
HTTPCACHE_STORAGE = 'scrapy.extensions.httpcache.FilesystemCacheStorage'

# ==================== 日志设置 ====================
LOG_LEVEL = 'INFO'  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE = 'scrapy.log'
LOG_FORMAT = '%(asctime)s [%(name)s] %(levelname)s: %(message)s'
LOG_DATEFORMAT = '%Y-%m-%d %H:%M:%S'

# ==================== 深度限制 ====================
DEPTH_LIMIT = 3
DEPTH_PRIORITY = 1  # 正数：广度优先，负数：深度优先

# ==================== 去重设置 ====================
DUPEFILTER_CLASS = 'scrapy.dupefilters.RFPDupeFilter'

# ==================== 输出设置 ====================
FEED_EXPORT_ENCODING = 'utf-8'
FEEDS = {
    'output/%(name)s_%(time)s.json': {
        'format': 'json',
        'encoding': 'utf-8',
        'indent': 2,
    },
}

# ==================== 中间件 ====================
DOWNLOADER_MIDDLEWARES = {
    'myspider.middlewares.RandomUserAgentMiddleware': 400,
}

# ==================== 管道 ====================
ITEM_PIPELINES = {
    'myspider.pipelines.CleanPipeline': 100,
    'myspider.pipelines.MongoPipeline': 300,
}

# ==================== 扩展 ====================
EXTENSIONS = {
    'scrapy.extensions.telnet.TelnetConsole': None,  # 禁用
}

# ==================== 自定义设置 ====================
MONGO_URI = 'mongodb://localhost:27017'
MONGO_DATABASE = 'scrapy_data'
PROXY_LIST = [
    'http://proxy1:8080',
    'http://proxy2:8080',
]
```

### 10.2 在 Spider 中覆盖设置

```python
class MySpider(scrapy.Spider):
    name = 'myspider'
    
    # 在 Spider 中覆盖设置
    custom_settings = {
        'DOWNLOAD_DELAY': 2,
        'CONCURRENT_REQUESTS': 8,
        'ITEM_PIPELINES': {
            'myspider.pipelines.SpecialPipeline': 100,
        },
        'LOG_LEVEL': 'DEBUG',
    }
```

### 10.3 命令行覆盖设置

```bash
# 使用 -s 参数
scrapy crawl myspider -s DOWNLOAD_DELAY=2 -s LOG_LEVEL=DEBUG

# 输出到文件
scrapy crawl myspider -o output.json -t json
```

### 10.4 多环境配置

```python
# settings/base.py
BOT_NAME = 'myspider'
SPIDER_MODULES = ['myspider.spiders']

# settings/dev.py
from .base import *

LOG_LEVEL = 'DEBUG'
DOWNLOAD_DELAY = 0
HTTPCACHE_ENABLED = True

# settings/prod.py
from .base import *

LOG_LEVEL = 'INFO'
DOWNLOAD_DELAY = 1
HTTPCACHE_ENABLED = False
CONCURRENT_REQUESTS = 32
```

```bash
# 使用不同环境
scrapy crawl myspider --set SETTINGS_MODULE=myspider.settings.prod
```

---

## 11. 反爬应对

### 11.1 User-Agent 轮换

```python
# middlewares.py
import random


class RandomUserAgentMiddleware:
    """随机 User-Agent"""
    
    USER_AGENTS = [
        # Chrome
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        # Firefox
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        # Safari
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        # Edge
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    ]
    
    def process_request(self, request, spider):
        request.headers['User-Agent'] = random.choice(self.USER_AGENTS)


# 或使用 fake-useragent 库
from fake_useragent import UserAgent


class FakeUserAgentMiddleware:
    def __init__(self):
        self.ua = UserAgent()
    
    def process_request(self, request, spider):
        request.headers['User-Agent'] = self.ua.random
```

### 11.2 代理池

```python
# middlewares.py
import random
import requests


class ProxyPoolMiddleware:
    """代理池中间件"""
    
    def __init__(self, proxy_url):
        self.proxy_url = proxy_url
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            proxy_url=crawler.settings.get('PROXY_POOL_URL')
        )
    
    def get_proxy(self):
        """从代理池获取代理"""
        try:
            response = requests.get(self.proxy_url, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except Exception as e:
            return None
    
    def process_request(self, request, spider):
        proxy = self.get_proxy()
        if proxy:
            request.meta['proxy'] = f'http://{proxy}'
            spider.logger.debug(f'使用代理: {proxy}')
    
    def process_exception(self, request, exception, spider):
        """代理失败时重试"""
        spider.logger.warning(f'代理失败: {request.meta.get("proxy")}')
        # 返回新请求重试
        return request.copy()


class StaticProxyMiddleware:
    """静态代理列表"""
    
    def __init__(self, proxy_list):
        self.proxy_list = proxy_list
        self.proxy_index = 0
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            proxy_list=crawler.settings.getlist('PROXY_LIST')
        )
    
    def process_request(self, request, spider):
        if self.proxy_list:
            # 轮询使用代理
            proxy = self.proxy_list[self.proxy_index % len(self.proxy_list)]
            self.proxy_index += 1
            request.meta['proxy'] = proxy
```

### 11.3 Cookies 处理

```python
# spiders/cookie_spider.py
import scrapy


class CookieSpider(scrapy.Spider):
    name = 'cookie'
    
    def start_requests(self):
        # 方式一：直接设置 Cookies
        yield scrapy.Request(
            url='https://example.com',
            cookies={
                'session_id': 'abc123',
                'user_token': 'xyz789',
            },
            callback=self.parse
        )
        
        # 方式二：从浏览器导出的 Cookies
        cookies = self.load_cookies_from_file('cookies.json')
        yield scrapy.Request(
            url='https://example.com',
            cookies=cookies,
            callback=self.parse
        )
    
    def load_cookies_from_file(self, filename):
        import json
        with open(filename, 'r') as f:
            cookies = json.load(f)
        return {c['name']: c['value'] for c in cookies}
```

### 11.4 验证码处理

```python
# 使用打码平台
import requests


class CaptchaSolver:
    """验证码识别"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.api_url = 'http://api.captcha-service.com/solve'
    
    def solve(self, image_data):
        """识别验证码"""
        response = requests.post(
            self.api_url,
            data={
                'key': self.api_key,
                'method': 'base64',
                'body': image_data,
            }
        )
        result = response.json()
        if result['status'] == 1:
            return result['request']
        return None


# 在 Spider 中使用
class CaptchaSpider(scrapy.Spider):
    name = 'captcha'
    
    def __init__(self):
        self.solver = CaptchaSolver(api_key='your_api_key')
    
    def parse(self, response):
        # 检测是否有验证码
        captcha_img = response.css('img.captcha::attr(src)').get()
        if captcha_img:
            yield scrapy.Request(
                url=response.urljoin(captcha_img),
                callback=self.solve_captcha,
                meta={'original_url': response.url}
            )
        else:
            # 正常解析
            yield from self.parse_content(response)
    
    def solve_captcha(self, response):
        import base64
        image_data = base64.b64encode(response.body).decode()
        captcha_text = self.solver.solve(image_data)
        
        if captcha_text:
            # 提交验证码
            yield scrapy.FormRequest(
                url=response.meta['original_url'],
                formdata={'captcha': captcha_text},
                callback=self.parse_content
            )
```

### 11.5 JavaScript 渲染

```bash
# 安装 Splash
docker run -p 8050:8050 scrapinghub/splash

# 安装 scrapy-splash
pip install scrapy-splash
```

```python
# settings.py
SPLASH_URL = 'http://localhost:8050'

DOWNLOADER_MIDDLEWARES = {
    'scrapy_splash.SplashCookiesMiddleware': 723,
    'scrapy_splash.SplashMiddleware': 725,
    'scrapy.downloadermiddlewares.httpcompression.HttpCompressionMiddleware': 810,
}

SPIDER_MIDDLEWARES = {
    'scrapy_splash.SplashDeduplicateArgsMiddleware': 100,
}

DUPEFILTER_CLASS = 'scrapy_splash.SplashAwareDupeFilter'
HTTPCACHE_STORAGE = 'scrapy_splash.SplashAwareFSCacheStorage'
```

```python
# spiders/splash_spider.py
import scrapy
from scrapy_splash import SplashRequest


class SplashSpider(scrapy.Spider):
    name = 'splash'
    
    def start_requests(self):
        yield SplashRequest(
            url='https://example.com',
            callback=self.parse,
            args={
                'wait': 2,           # 等待时间
                'timeout': 90,       # 超时
                'images': 0,         # 不加载图片
            },
            endpoint='render.html'   # 渲染 HTML
        )
    
    def parse(self, response):
        # response 已经是渲染后的 HTML
        yield {
            'title': response.css('h1::text').get(),
            'content': response.css('div.content::text').getall(),
        }


# 使用 Lua 脚本进行复杂操作
class AdvancedSplashSpider(scrapy.Spider):
    name = 'advanced_splash'
    
    lua_script = """
    function main(splash, args)
        splash:go(args.url)
        splash:wait(2)
        
        -- 点击按钮
        splash:runjs("document.querySelector('.load-more').click()")
        splash:wait(1)
        
        -- 滚动页面
        splash:runjs("window.scrollTo(0, document.body.scrollHeight)")
        splash:wait(1)
        
        return {
            html = splash:html(),
            cookies = splash:get_cookies(),
        }
    end
    """
    
    def start_requests(self):
        yield SplashRequest(
            url='https://example.com',
            callback=self.parse,
            endpoint='execute',
            args={'lua_source': self.lua_script}
        )
```

### 11.6 请求频率控制

```python
# settings.py

# 自动限速扩展
AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_START_DELAY = 1
AUTOTHROTTLE_MAX_DELAY = 10
AUTOTHROTTLE_TARGET_CONCURRENCY = 2.0
AUTOTHROTTLE_DEBUG = True

# 或手动设置
DOWNLOAD_DELAY = 2
RANDOMIZE_DOWNLOAD_DELAY = True
CONCURRENT_REQUESTS_PER_DOMAIN = 4
```

```python
# 在 Spider 中动态调整
class AdaptiveSpider(scrapy.Spider):
    name = 'adaptive'
    
    def parse(self, response):
        # 检测是否被限制
        if response.status == 429 or '访问过于频繁' in response.text:
            # 增加延迟
            self.crawler.engine.downloader.slots['example.com'].delay = 5
            self.logger.warning('检测到限制，增加延迟')
            
            # 重新请求
            yield response.request.copy()
        else:
            # 正常处理
            yield from self.parse_content(response)
```

---

## 12. 分布式爬虫

### 12.1 Scrapy-Redis

```bash
pip install scrapy-redis
```

```python
# settings.py

# 使用 Redis 调度器
SCHEDULER = 'scrapy_redis.scheduler.Scheduler'

# 使用 Redis 去重
DUPEFILTER_CLASS = 'scrapy_redis.dupefilter.RFPDupeFilter'

# 允许暂停/恢复
SCHEDULER_PERSIST = True

# Redis 连接
REDIS_URL = 'redis://localhost:6379/0'
# 或
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_PARAMS = {
    'password': 'your_password',
}

# Item Pipeline
ITEM_PIPELINES = {
    'scrapy_redis.pipelines.RedisPipeline': 300,
}
```

```python
# spiders/redis_spider.py
from scrapy_redis.spiders import RedisSpider


class MyRedisSpider(RedisSpider):
    """分布式爬虫"""
    name = 'redis_spider'
    
    # 从 Redis 读取起始 URL 的 key
    redis_key = 'myspider:start_urls'
    
    def parse(self, response):
        yield {
            'url': response.url,
            'title': response.css('h1::text').get(),
        }
        
        # 提取新链接
        for href in response.css('a::attr(href)').getall():
            yield response.follow(href, callback=self.parse)
```

```bash
# 向 Redis 添加起始 URL
redis-cli lpush myspider:start_urls https://example.com/page1
redis-cli lpush myspider:start_urls https://example.com/page2

# 在多台机器上运行
scrapy crawl redis_spider
```

### 12.2 分布式架构

```
                    ┌─────────────────┐
                    │   Redis Server  │
                    │  (URL 队列/去重) │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   Worker 1      │ │   Worker 2      │ │   Worker 3      │
│  (Scrapy Node)  │ │  (Scrapy Node)  │ │  (Scrapy Node)  │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   MongoDB/MySQL │
                    │   (数据存储)     │
                    └─────────────────┘
```

### 12.3 增量爬取

```python
# spiders/incremental_spider.py
import scrapy
from scrapy_redis.spiders import RedisSpider
import redis


class IncrementalSpider(RedisSpider):
    """增量爬虫"""
    name = 'incremental'
    redis_key = 'incremental:start_urls'
    
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
    
    def parse(self, response):
        for item in response.css('div.item'):
            item_id = item.css('::attr(data-id)').get()
            
            # 检查是否已爬取
            if self.redis_client.sismember('crawled_ids', item_id):
                self.logger.debug(f'跳过已爬取: {item_id}')
                continue
            
            # 标记为已爬取
            self.redis_client.sadd('crawled_ids', item_id)
            
            yield {
                'id': item_id,
                'title': item.css('h2::text').get(),
            }
```

---

## 13. 数据存储

### 13.1 文件存储

```python
# settings.py

# JSON 输出
FEEDS = {
    'output/data.json': {
        'format': 'json',
        'encoding': 'utf-8',
        'indent': 2,
        'overwrite': True,
    },
}

# JSON Lines（每行一个 JSON）
FEEDS = {
    'output/data.jsonl': {
        'format': 'jsonlines',
        'encoding': 'utf-8',
    },
}

# CSV 输出
FEEDS = {
    'output/data.csv': {
        'format': 'csv',
        'encoding': 'utf-8-sig',  # Excel 兼容
        'fields': ['name', 'price', 'url'],  # 指定字段顺序
    },
}

# 多格式输出
FEEDS = {
    'output/%(name)s_%(time)s.json': {'format': 'json'},
    'output/%(name)s_%(time)s.csv': {'format': 'csv'},
}
```

### 13.2 图片下载

```python
# settings.py
ITEM_PIPELINES = {
    'scrapy.pipelines.images.ImagesPipeline': 1,
}

IMAGES_STORE = 'images'
IMAGES_URLS_FIELD = 'image_urls'
IMAGES_RESULT_FIELD = 'images'

# 图片过滤
IMAGES_MIN_HEIGHT = 100
IMAGES_MIN_WIDTH = 100

# 缩略图
IMAGES_THUMBS = {
    'small': (50, 50),
    'big': (200, 200),
}
```

```python
# items.py
class ProductItem(scrapy.Item):
    name = scrapy.Field()
    image_urls = scrapy.Field()  # 图片 URL 列表
    images = scrapy.Field()      # 下载结果


# spiders/image_spider.py
class ImageSpider(scrapy.Spider):
    name = 'image'
    
    def parse(self, response):
        yield {
            'name': response.css('h1::text').get(),
            'image_urls': response.css('img::attr(src)').getall(),
        }


# 自定义图片管道
from scrapy.pipelines.images import ImagesPipeline


class MyImagesPipeline(ImagesPipeline):
    def get_media_requests(self, item, info):
        """生成图片下载请求"""
        for url in item.get('image_urls', []):
            yield scrapy.Request(
                url,
                meta={'item': item}
            )
    
    def file_path(self, request, response=None, info=None, *, item=None):
        """自定义文件路径"""
        image_name = request.url.split('/')[-1]
        return f'full/{item["category"]}/{image_name}'
    
    def item_completed(self, results, item, info):
        """下载完成后处理"""
        image_paths = [x['path'] for ok, x in results if ok]
        item['image_paths'] = image_paths
        return item
```

### 13.3 文件下载

```python
# settings.py
ITEM_PIPELINES = {
    'scrapy.pipelines.files.FilesPipeline': 1,
}

FILES_STORE = 'downloads'
FILES_URLS_FIELD = 'file_urls'
FILES_RESULT_FIELD = 'files'
```

```python
# items.py
class DocumentItem(scrapy.Item):
    title = scrapy.Field()
    file_urls = scrapy.Field()
    files = scrapy.Field()


# spiders/file_spider.py
class FileSpider(scrapy.Spider):
    name = 'file'
    
    def parse(self, response):
        yield {
            'title': response.css('h1::text').get(),
            'file_urls': response.css('a.download::attr(href)').getall(),
        }
```

### 13.4 Elasticsearch 存储

```python
# pipelines.py
from elasticsearch import Elasticsearch


class ElasticsearchPipeline:
    def __init__(self, es_url, index_name):
        self.es_url = es_url
        self.index_name = index_name
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            es_url=crawler.settings.get('ELASTICSEARCH_URL', 'http://localhost:9200'),
            index_name=crawler.settings.get('ELASTICSEARCH_INDEX', 'scrapy')
        )
    
    def open_spider(self, spider):
        self.es = Elasticsearch([self.es_url])
        
        # 创建索引
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(index=self.index_name, body={
                'mappings': {
                    'properties': {
                        'title': {'type': 'text'},
                        'content': {'type': 'text'},
                        'url': {'type': 'keyword'},
                        'timestamp': {'type': 'date'},
                    }
                }
            })
    
    def process_item(self, item, spider):
        self.es.index(
            index=self.index_name,
            body=dict(item)
        )
        return item
```

---

## 14. 性能优化

### 14.1 并发优化

```python
# settings.py

# 增加并发数
CONCURRENT_REQUESTS = 32
CONCURRENT_REQUESTS_PER_DOMAIN = 16
CONCURRENT_REQUESTS_PER_IP = 16

# 减少下载延迟
DOWNLOAD_DELAY = 0

# 禁用不必要的中间件
DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.robotstxt.RobotsTxtMiddleware': None,
}

# 禁用 Cookies（如果不需要）
COOKIES_ENABLED = False

# 禁用重试（如果可以接受丢失）
RETRY_ENABLED = False

# 减少日志
LOG_LEVEL = 'WARNING'
```

### 14.2 内存优化

```python
# settings.py

# 启用 HTTP 缓存
HTTPCACHE_ENABLED = True
HTTPCACHE_EXPIRATION_SECS = 0  # 永不过期
HTTPCACHE_DIR = 'httpcache'

# 限制响应大小
DOWNLOAD_MAXSIZE = 10 * 1024 * 1024  # 10MB
DOWNLOAD_WARNSIZE = 5 * 1024 * 1024   # 5MB

# 使用 LIFO 队列（深度优先，减少内存）
SCHEDULER_DISK_QUEUE = 'scrapy.squeues.PickleLifoDiskQueue'
SCHEDULER_MEMORY_QUEUE = 'scrapy.squeues.LifoMemoryQueue'

# 限制队列大小
SCHEDULER_PRIORITY_QUEUE = 'scrapy.pqueues.DownloaderAwarePriorityQueue'
```

```python
# 在 Spider 中优化
class OptimizedSpider(scrapy.Spider):
    name = 'optimized'
    
    def parse(self, response):
        # 只提取需要的数据，不保存整个响应
        yield {
            'title': response.css('h1::text').get(),
            # 不要这样做：'html': response.text
        }
        
        # 使用生成器而不是列表
        for item in response.css('div.item'):
            yield self.parse_item(item)
    
    def parse_item(self, selector):
        return {
            'name': selector.css('h2::text').get(),
        }
```

### 14.3 请求优化

```python
# 使用 DNS 缓存
DNSCACHE_ENABLED = True
DNSCACHE_SIZE = 10000

# 使用连接池
DOWNLOAD_HANDLERS = {
    'http': 'scrapy.core.downloader.handlers.http.HTTPDownloadHandler',
    'https': 'scrapy.core.downloader.handlers.http.HTTPDownloadHandler',
}

# 禁用不需要的功能
TELNETCONSOLE_ENABLED = False
MEMUSAGE_ENABLED = False
```

### 14.4 异步数据库写入

```python
# pipelines.py
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient


class AsyncMongoPipeline:
    """异步 MongoDB 管道"""
    
    def __init__(self, mongo_uri, mongo_db):
        self.mongo_uri = mongo_uri
        self.mongo_db = mongo_db
        self.buffer = []
        self.buffer_size = 100
    
    @classmethod
    def from_crawler(cls, crawler):
        return cls(
            mongo_uri=crawler.settings.get('MONGO_URI'),
            mongo_db=crawler.settings.get('MONGO_DATABASE')
        )
    
    def open_spider(self, spider):
        self.client = AsyncIOMotorClient(self.mongo_uri)
        self.db = self.client[self.mongo_db]
    
    def close_spider(self, spider):
        # 写入剩余数据
        if self.buffer:
            asyncio.get_event_loop().run_until_complete(
                self.flush_buffer(spider)
            )
        self.client.close()
    
    async def flush_buffer(self, spider):
        if self.buffer:
            await self.db[spider.name].insert_many(self.buffer)
            self.buffer = []
    
    def process_item(self, item, spider):
        self.buffer.append(dict(item))
        
        if len(self.buffer) >= self.buffer_size:
            asyncio.get_event_loop().run_until_complete(
                self.flush_buffer(spider)
            )
        
        return item
```

### 14.5 监控与统计

```python
# 启用统计扩展
STATS_CLASS = 'scrapy.statscollectors.MemoryStatsCollector'

# 在 Spider 中访问统计
class MySpider(scrapy.Spider):
    name = 'myspider'
    
    def closed(self, reason):
        stats = self.crawler.stats.get_stats()
        self.logger.info(f'爬取完成: {stats}')
        self.logger.info(f'请求数: {stats.get("downloader/request_count", 0)}')
        self.logger.info(f'响应数: {stats.get("downloader/response_count", 0)}')
        self.logger.info(f'Item 数: {stats.get("item_scraped_count", 0)}')
```

```python
# 自定义统计扩展
from scrapy import signals


class StatsExtension:
    def __init__(self, stats):
        self.stats = stats
    
    @classmethod
    def from_crawler(cls, crawler):
        ext = cls(crawler.stats)
        crawler.signals.connect(ext.spider_opened, signal=signals.spider_opened)
        crawler.signals.connect(ext.spider_closed, signal=signals.spider_closed)
        crawler.signals.connect(ext.item_scraped, signal=signals.item_scraped)
        return ext
    
    def spider_opened(self, spider):
        self.stats.set_value('custom/start_time', datetime.now())
    
    def spider_closed(self, spider):
        self.stats.set_value('custom/end_time', datetime.now())
    
    def item_scraped(self, item, spider):
        self.stats.inc_value('custom/items_count')
```

---

## 15. 部署与监控

### 15.1 Scrapyd 部署

```bash
# 安装 Scrapyd
pip install scrapyd scrapyd-client

# 启动 Scrapyd 服务
scrapyd
# 默认运行在 http://localhost:6800
```

```ini
# scrapy.cfg
[settings]
default = myspider.settings

[deploy:local]
url = http://localhost:6800/
project = myspider

[deploy:production]
url = http://server:6800/
project = myspider
username = admin
password = secret
```

```bash
# 部署项目
scrapyd-deploy local -p myspider

# 启动爬虫
curl http://localhost:6800/schedule.json -d project=myspider -d spider=example

# 查看状态
curl http://localhost:6800/listjobs.json?project=myspider

# 取消任务
curl http://localhost:6800/cancel.json -d project=myspider -d job=xxx
```

### 15.2 Docker 部署

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目
COPY . .

# 运行爬虫
CMD ["scrapy", "crawl", "myspider"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  scrapy:
    build: .
    volumes:
      - ./output:/app/output
    environment:
      - MONGO_URI=mongodb://mongo:27017
    depends_on:
      - mongo
      - redis
  
  mongo:
    image: mongo:6
    volumes:
      - mongo_data:/data/db
  
  redis:
    image: redis:7
    volumes:
      - redis_data:/data

volumes:
  mongo_data:
  redis_data:
```

### 15.3 定时任务

```python
# 使用 APScheduler
from apscheduler.schedulers.twisted import TwistedScheduler
from scrapy.crawler import CrawlerRunner
from scrapy.utils.log import configure_logging
from twisted.internet import reactor


configure_logging()
runner = CrawlerRunner()

scheduler = TwistedScheduler()

@scheduler.scheduled_job('interval', hours=1)
def crawl_job():
    runner.crawl(MySpider)

scheduler.start()
reactor.run()
```

```bash
# 使用 cron
# crontab -e
0 */2 * * * cd /path/to/project && /path/to/venv/bin/scrapy crawl myspider >> /var/log/scrapy.log 2>&1
```

### 15.4 Gerapy 管理平台

```bash
# 安装 Gerapy
pip install gerapy

# 初始化
gerapy init
cd gerapy
gerapy migrate

# 创建管理员
gerapy createsuperuser

# 启动
gerapy runserver 0.0.0.0:8000
```

### 15.5 监控告警

```python
# extensions.py
from scrapy import signals
import requests


class AlertExtension:
    """告警扩展"""
    
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    @classmethod
    def from_crawler(cls, crawler):
        ext = cls(
            webhook_url=crawler.settings.get('ALERT_WEBHOOK_URL')
        )
        crawler.signals.connect(ext.spider_error, signal=signals.spider_error)
        crawler.signals.connect(ext.spider_closed, signal=signals.spider_closed)
        return ext
    
    def spider_error(self, failure, response, spider):
        self.send_alert(f'爬虫错误: {spider.name}\n{failure}')
    
    def spider_closed(self, spider, reason):
        stats = spider.crawler.stats.get_stats()
        items = stats.get('item_scraped_count', 0)
        
        if items == 0:
            self.send_alert(f'警告: {spider.name} 未抓取到任何数据')
        else:
            self.send_alert(f'{spider.name} 完成，共抓取 {items} 条数据')
    
    def send_alert(self, message):
        try:
            requests.post(self.webhook_url, json={'text': message})
        except Exception as e:
            pass
```

```python
# settings.py
EXTENSIONS = {
    'myspider.extensions.AlertExtension': 500,
}

ALERT_WEBHOOK_URL = 'https://hooks.slack.com/services/xxx'
```

---

## 16. 常见错误与解决方案

### 16.1 安装与环境错误

```bash
# 错误：Twisted 安装失败（Windows）
# error: Microsoft Visual C++ 14.0 or greater is required

# 解决方案 1：安装 Visual C++ Build Tools
# 下载：https://visualstudio.microsoft.com/visual-cpp-build-tools/

# 解决方案 2：使用预编译包
pip install Twisted‑xx.x.x‑cp311‑cp311‑win_amd64.whl

# 解决方案 3：使用 conda
conda install -c conda-forge scrapy
```

```bash
# 错误：No module named 'scrapy'
# 原因：未安装或虚拟环境未激活

# 解决
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install scrapy
```

### 16.2 Spider 错误

```python
# 错误：Spider not found
# scrapy crawl myspider
# Spider not found: myspider

# 原因 1：爬虫名称错误
# 检查 spider 的 name 属性

# 原因 2：Spider 未在正确目录
# 确保在 spiders/ 目录下

# 原因 3：语法错误导致无法加载
# 检查 Spider 文件是否有语法错误
python -c "from myspider.spiders.example import ExampleSpider"
```

```python
# 错误：callback 未定义
# TypeError: parse() missing 1 required positional argument: 'response'

# ❌ 错误写法
yield scrapy.Request(url, self.parse())  # 调用了函数

# ✅ 正确写法
yield scrapy.Request(url, callback=self.parse)  # 传递函数引用
```

```python
# 错误：yield 和 return 混用
# ❌ 错误
def parse(self, response):
    items = []
    for item in response.css('div'):
        items.append({'name': item.css('::text').get()})
    return items  # 应该用 yield

# ✅ 正确
def parse(self, response):
    for item in response.css('div'):
        yield {'name': item.css('::text').get()}
```

### 16.3 选择器错误

```python
# 错误：选择器返回空
# 原因 1：选择器写错
response.css('div.item')  # 检查类名是否正确

# 原因 2：页面是 JavaScript 渲染的
# 解决：使用 Splash 或 Selenium

# 原因 3：页面编码问题
# 检查 response.encoding
response.encoding = 'utf-8'

# 调试技巧
scrapy shell 'https://example.com'
>>> response.css('div.item')
>>> view(response)  # 在浏览器中查看
```

```python
# 错误：XPath 相对路径
# ❌ 错误
for item in response.css('div.item'):
    name = item.xpath('//h2/text()').get()  # 从根开始找

# ✅ 正确
for item in response.css('div.item'):
    name = item.xpath('.//h2/text()').get()  # 相对路径
```

```python
# 错误：忘记 get() 或 getall()
# ❌ 错误
title = response.css('h1::text')  # 返回 SelectorList

# ✅ 正确
title = response.css('h1::text').get()  # 返回字符串
titles = response.css('h1::text').getall()  # 返回列表
```

### 16.4 请求错误

```python
# 错误：请求被过滤（去重）
# DEBUG: Filtered duplicate request

# 解决：设置 dont_filter=True
yield scrapy.Request(url, callback=self.parse, dont_filter=True)
```

```python
# 错误：403 Forbidden
# 原因：缺少请求头或被反爬

# 解决 1：添加 User-Agent
DEFAULT_REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 ...',
}

# 解决 2：添加 Referer
yield scrapy.Request(
    url,
    headers={'Referer': 'https://example.com'}
)

# 解决 3：使用代理
yield scrapy.Request(
    url,
    meta={'proxy': 'http://proxy:8080'}
)
```

```python
# 错误：SSL 证书错误
# twisted.internet.error.SSLError

# 解决：禁用 SSL 验证（不推荐用于生产）
# settings.py
DOWNLOADER_CLIENT_TLS_CIPHERS = 'DEFAULT:!DH'
# 或在请求中
yield scrapy.Request(url, meta={'dont_verify_ssl': True})
```

### 16.5 Pipeline 错误

```python
# 错误：Pipeline 未执行
# 原因 1：未在 settings.py 中启用
ITEM_PIPELINES = {
    'myspider.pipelines.MyPipeline': 300,
}

# 原因 2：process_item 未返回 item
# ❌ 错误
def process_item(self, item, spider):
    # 处理 item
    pass  # 没有返回

# ✅ 正确
def process_item(self, item, spider):
    # 处理 item
    return item  # 必须返回
```

```python
# 错误：DropItem 未导入
# NameError: name 'DropItem' is not defined

from scrapy.exceptions import DropItem

def process_item(self, item, spider):
    if not item.get('name'):
        raise DropItem('缺少名称')
    return item
```

```python
# 错误：数据库连接问题
# 原因：open_spider 中连接失败

def open_spider(self, spider):
    try:
        self.conn = pymysql.connect(...)
    except Exception as e:
        spider.logger.error(f'数据库连接失败: {e}')
        raise  # 抛出异常停止爬虫
```

### 16.6 中间件错误

```python
# 错误：中间件顺序问题
# 数字越小越先执行（请求时）
# 数字越大越先执行（响应时）

DOWNLOADER_MIDDLEWARES = {
    'myspider.middlewares.ProxyMiddleware': 100,      # 先设置代理
    'myspider.middlewares.UserAgentMiddleware': 200,  # 再设置 UA
}
```

```python
# 错误：process_request 返回值错误
def process_request(self, request, spider):
    # 返回 None：继续处理
    # 返回 Request：替换当前请求
    # 返回 Response：跳过下载，直接返回
    # 抛出 IgnoreRequest：丢弃请求
    
    # ❌ 错误：返回其他类型
    return "error"  # 会导致错误
    
    # ✅ 正确
    return None
```

### 16.7 编码错误

```python
# 错误：UnicodeDecodeError
# 原因：响应编码识别错误

def parse(self, response):
    # 方法 1：手动设置编码
    response = response.replace(encoding='gbk')
    
    # 方法 2：使用 body 解码
    text = response.body.decode('gbk')
```

```python
# 错误：JSON 输出乱码
# settings.py
FEED_EXPORT_ENCODING = 'utf-8'

# 或在 FEEDS 中指定
FEEDS = {
    'output.json': {
        'format': 'json',
        'encoding': 'utf-8',
    },
}
```

### 16.8 内存与性能错误

```python
# 错误：内存溢出
# MemoryError 或进程被杀死

# 解决 1：限制并发
CONCURRENT_REQUESTS = 8

# 解决 2：启用深度优先
DEPTH_PRIORITY = 1
SCHEDULER_DISK_QUEUE = 'scrapy.squeues.PickleLifoDiskQueue'

# 解决 3：不要在内存中积累数据
# ❌ 错误
class MySpider(scrapy.Spider):
    all_items = []  # 会越来越大
    
    def parse(self, response):
        self.all_items.append(item)

# ✅ 正确：使用 yield
def parse(self, response):
    yield item
```

```python
# 错误：请求队列过大
# 解决：限制队列大小
SCHEDULER_PRIORITY_QUEUE = 'scrapy.pqueues.DownloaderAwarePriorityQueue'
REACTOR_THREADPOOL_MAXSIZE = 10
```

### 16.9 调试技巧

```bash
# 使用 Scrapy Shell 调试
scrapy shell 'https://example.com'
>>> response.css('h1::text').get()
>>> view(response)  # 在浏览器中打开

# 查看请求/响应
scrapy crawl myspider -L DEBUG

# 只运行一个请求
scrapy crawl myspider -s CLOSESPIDER_ITEMCOUNT=1

# 保存响应到文件
scrapy fetch 'https://example.com' > response.html
```

```python
# 在代码中调试
import logging

class MySpider(scrapy.Spider):
    def parse(self, response):
        self.logger.debug(f'URL: {response.url}')
        self.logger.debug(f'Status: {response.status}')
        self.logger.debug(f'Body length: {len(response.body)}')
        
        # 使用 pdb 断点
        import pdb; pdb.set_trace()
```

---

## 总结

Scrapy 是一个功能强大的爬虫框架，掌握它需要理解：

1. **架构设计**：Spider、Item、Pipeline、Middleware 的协作
2. **选择器**：CSS 和 XPath 的灵活运用
3. **请求处理**：Request、Response、FormRequest 的使用
4. **数据处理**：Item、ItemLoader、Pipeline 的数据流
5. **中间件**：下载中间件和 Spider 中间件的定制
6. **反爬应对**：代理、UA 轮换、验证码、JS 渲染
7. **分布式**：Scrapy-Redis 实现分布式爬取
8. **性能优化**：并发、内存、请求的优化策略
9. **部署监控**：Scrapyd、Docker、定时任务

爬虫开发需要遵守法律法规和网站的 robots.txt 协议，合理控制爬取频率，不要对目标网站造成过大压力。
