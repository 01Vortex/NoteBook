# 基础语法

### 1. 标题

```java
# 一级标题
## 二级标题
### 三级标题
#### 四级标题
##### 五级标题
###### 六级标题
```

### 2. 段落
段落之间使用空行分隔。

```markdown
这是第一段。

这是第二段。
```

### 3. 换行
在行尾使用两个或更多空格，然后回车。

```markdown
这是第一行。  
这是第二行。
```

### 4. 强调
- **加粗**：使用`**`或`__`包裹文本。
- *斜体*：使用`*`或`_`包裹文本。
- ***加粗斜体***：使用`***`包裹文本。

```markdown
**加粗文本**  
__加粗文本__

*斜体文本*  
_斜体文本_

***加粗斜体文本***  
```

### 5. 列表
- **无序列表**：使用`-`、`*`或`+`。
- **有序列表**：使用数字加`.`。

```markdown
- 项目1
- 项目2
  - 子项目1
  - 子项目2

1. 第一项
2. 第二项
   1. 子项1
   2. 子项2
```

### 6. 链接
使用`[文本](链接)`格式。

```markdown
[Google](https://www.google.com)
```

### 7. 图片
使用`![替代文本](图片链接)`格式。

```markdown
![示例图片](https://example.com/image.jpg)
```

### 8. 代码
- **行内代码**：使用`` ` ``包裹文本。
- **代码块**：使用三个` ``` `包裹代码块，并可指定语言。

```markdown
这是一段`行内代码`。

```python
def hello():
    print("Hello, World!")
``` 
```

### 9. 引用
使用`>`符号。

```markdown
> 这是一个引用块。
```

### 10. 水平线
使用三个或更多`*`、`-`或`_`。

```markdown
---
***
___
```

### 11. 表格
使用`|`和`-`来创建表格。

```markdown
| 名称  | 年龄 | 城市    |
|-------|------|---------|
| 张三  | 25   | 北京    |
| 李四  | 30   | 上海    |
```

### 12. 删除线
使用`~~`包裹文本。

```markdown
~~这是删除线文本~~
```

### 13. 任务列表
使用`- [ ]`和`- [x]`。

```markdown
- [x] 完成项目
- [ ] 开始新项目
```

### 14. 脚注
使用`[^1]`和`[^1]: `。

```markdown
这是一个脚注[^1]。

[^1]: 脚注内容。
```

这些是Markdown的基础语法，适用于大多数文档编写和网页编辑场景。


# 链接与图片
## 如何在 Markdown 中添加链接（Link）

### 1. 内联链接（Inline Link）
内联链接是最常见的添加链接方式，使用方括号 `[]` 包裹链接文本，后面紧跟圆括号 `()` 包裹链接地址。

**语法：**
```markdown
[链接文本](链接地址)
```

**示例：**
```markdown
[Google](https://www.google.com)
```

**效果：**
[Google](https://www.google.com)

### 2. 参考链接（Reference Link）
参考链接允许你为链接定义一个标识符，然后在文档的其他位置定义链接地址。这种方法可以使文档更整洁，尤其是在多次使用同一链接时。

**语法：**
```markdown
[链接文本][标识符]

[标识符]: 链接地址
```

**示例：**
```markdown
[Google][1]

[1]: https://www.google.com
```

**效果：**
[Google][1]

[1]: https://www.google.com

## 如何在 Markdown 中添加图片（Image）

### 1. 内联图片（Inline Image）
内联图片的语法与内联链接相似，只是前面多了一个感叹号 `!`。

**语法：**
```markdown
![替代文本](图片链接)
```

**示例：**
```markdown
![示例图片](https://example.com/image.jpg)
```

**效果：**
![示例图片](https://example.com/image.jpg)

### 2. 参考图片（Reference Image）
参考图片与参考链接类似，使用标识符来定义图片链接。

**语法：**
```markdown
![替代文本][标识符]

[标识符]: 图片链接
```

**示例：**
```markdown
![示例图片][1]

[1]: https://example.com/image.jpg
```

**效果：**
![示例图片][1]

[1]: https://example.com/image.jpg

## 如何设置图片的替代文本（Alt Text）

替代文本用于在图片无法显示时提供描述信息。在 Markdown 中，替代文本位于图片语法的方括号 `[]` 内。

**语法：**
```markdown
![替代文本](图片链接)
```

**示例：**
```markdown
![一只猫](https://example.com/cat.jpg)
```

**效果：**
![一只猫](https://example.com/cat.jpg)

## 如何设置图片的大小和样式

Markdown 本身不支持直接设置图片的大小和样式，但可以通过以下几种方法实现：

### 1. 使用 HTML 标签
你可以直接在 Markdown 中使用 HTML 标签来设置图片的大小和样式。

**语法：**
```html
<img src="图片链接" alt="替代文本" width="宽度" height="高度" style="样式">
```

**示例：**
```html
<img src="https://example.com/image.jpg" alt="示例图片" width="300" height="200" style="border: 1px solid black;">
```

**效果：**
<img src="https://example.com/image.jpg" alt="示例图片" width="300" height="200" style="border: 1px solid black;">

### 2. 使用 CSS 类（如果支持）
某些 Markdown 渲染器支持使用 CSS 类来设置样式。

**语法：**
```markdown
![替代文本](图片链接){: class="class-name"}
```

**示例：**
```markdown
![示例图片](https://example.com/image.jpg){: width="300" height="200" style="border: 1px solid black;"}
```

**注意：** 这种方法依赖于具体的 Markdown 渲染器是否支持。

### 3. 使用内联样式
直接在图片链接后添加样式参数。

**语法：**
```markdown
![替代文本](图片链接){: style="width:宽度; height:高度; border:边框样式;"}
```

**示例：**
```markdown
![示例图片](https://example.com/image.jpg){: style="width:300px; height:200px; border:1px solid black;"}
```

**效果：**
![示例图片](https://example.com/image.jpg){: style="width:300px; height:200px; border:1px solid black;"}

## 总结
- **链接**：
  - 内联链接：`[文本](链接)`
  - 参考链接：`[文本][标识符]` 和 `[标识符]: 链接`
- **图片**：
  - 内联图片：`![替代文本](图片链接)`
  - 参考图片：`![替代文本][标识符]` 和 `[标识符]: 图片链接`
- **替代文本**：在方括号 `[]` 内添加描述。
- **设置大小和样式**：使用 HTML 标签或 CSS 类。

这些方法可以帮助你在 Markdown 中更灵活地添加和管理链接和图片。



# 表格

## 1. 创建表格

表格使用竖线 `|` 分隔列，使用短横线 `-` 分隔表头和表体。短横线的数量至少为三个。

**语法：**
```markdown
| 表头1 | 表头2 | 表头3 |
|-------|-------|-------|
| 行1列1 | 行1列2 | 行1列3 |
| 行2列1 | 行2列2 | 行2列3 |
```

**示例：**
```markdown
| 姓名 | 年龄 | 城市    |
|------|------|---------|
| 张三 | 25   | 北京    |
| 李四 | 30   | 上海    |
```

**效果：**

| 姓名 | 年龄 | 城市    |
|------|------|---------|
| 张三 | 25   | 北京    |
| 李四 | 30   | 上海    |

## 2. 添加标题行

表格的标题行可以通过在表头下方添加短横线 `-` 来创建。标题行通常位于表格的第一行。

**语法：**
```markdown
| 表头1 | 表头2 | 表头3 |
|-------|-------|-------|
| 内容1 | 内容2 | 内容3 |
| 内容4 | 内容5 | 内容6 |
```

**示例：**
```markdown
| 姓名 | 年龄 | 城市    |
|------|------|---------|
| 张三 | 25   | 北京    |
| 李四 | 30   | 上海    |
```

**效果：**

| 姓名 | 年龄 | 城市    |
|------|------|---------|
| 张三 | 25   | 北京    |
| 李四 | 30   | 上海    |

## 3. 设置对齐方式

在分隔表头和表体的短横线行中，可以在短横线 `-` 前添加冒号 `:` 来设置对齐方式：

- 左对齐：在短横线左侧添加冒号 `:`
- 右对齐：在短横线右侧添加冒号 `:`
- 居中对齐：在短横线两侧添加冒号 `:`。

**语法：**
```markdown
| 左对齐 | 右对齐 | 居中对齐 |
|:-------|-------:|:-------:|
| 内容1  | 内容2  | 内容3    |
| 内容4  | 内容5  | 内容6    |
```

**示例：**
```markdown
| 左对齐 | 右对齐 | 居中对齐 |
|:-------|-------:|:-------:|
| 张三   | 25     | 北京     |
| 李四   | 30     | 上海     |
```

**效果：**

| 左对齐 | 右对齐 | 居中对齐 |
|:-------|-------:|:-------:|
| 张三   | 25     | 北京     |
| 李四   | 30     | 上海     |

## 4. 在表格中添加链接和图片

在表格的单元格中，你可以使用 Markdown 的链接和图片语法来插入链接和图片。

#### 在表格中添加链接

**语法：**
```markdown
| 名称 | 链接          |
|------|---------------|
| Google | [Google](https://www.google.com) |
| GitHub | [GitHub](https://www.github.com) |
```

**示例：**
```markdown
| 名称   | 链接                       |
|--------|----------------------------|
| Google | [Google](https://www.google.com) |
| GitHub | [GitHub](https://www.github.com) |
```

**效果：**

| 名称   | 链接                       |
|--------|----------------------------|
| Google | [Google](https://www.google.com) |
| GitHub | [GitHub](https://www.github.com) |

#### 在表格中添加图片

**语法：**
```markdown
| 图片名称 | 图片                  |
|----------|-----------------------|
| 示例图片 | ![示例图片](https://example.com/image.jpg) |
```

**示例：**
```markdown
| 图片名称 | 图片                  |
|----------|-----------------------|
| 示例图片 | ![示例图片](https://example.com/image.jpg) |
```

**效果：**

| 图片名称 | 图片                  |
|----------|-----------------------|
| 示例图片 | ![示例图片](https://example.com/image.jpg) |

**注意：** 如果图片链接不正确，图片可能无法显示。

## 5. 综合示例

以下是一个包含标题行、对齐方式、链接和图片的完整表格示例：

```markdown
| 姓名 | 年龄 | 城市    | 个人网站                    | 头像                  |
|------|------|---------|-----------------------------|-----------------------|
| 张三 | 25   | 北京    | [张三的网站](https://zhangsan.com) | ![张三头像](https://example.com/zhangsan.jpg) |
| 李四 | 30   | 上海    | [李四的网站](https://lisi.com)     | ![李四头像](https://example.com/lisi.jpg)   |
```

**效果：**

| 姓名 | 年龄 | 城市    | 个人网站                    | 头像                  |
|------|------|---------|-----------------------------|-----------------------|
| 张三 | 25   | 北京    | [张三的网站](https://zhangsan.com) | ![张三头像](https://example.com/zhangsan.jpg) |
| 李四 | 30   | 上海    | [李四的网站](https://lisi.com)     | ![李四头像](https://example.com/lisi.jpg)   |

## 总结

- **创建表格**：使用 `|` 分隔列，`-` 分隔表头和表体。
- **添加标题行**：在表头下方添加短横线 `-`。
- **设置对齐方式**：
  - 左对齐：`|:-----|`
  - 右对齐：`|-----:|`
  - 居中对齐：`|:-----:|`
- **在表格中添加链接和图片**：在单元格中使用 Markdown 的链接和图片语法。

通过这些方法，你可以在 Markdown 中创建功能丰富、结构清晰的表格。


# 高级语法
## 在 Markdown 中添加脚注（Footnote）

脚注用于在文档中添加注释或参考资料，而不会打断正文的阅读流程。脚注由两个部分组成：脚注引用和脚注定义。

### 1. 添加脚注

**语法：**
```markdown
这是一个脚注[^1]。

[^1]: 脚注内容。
```

**示例：**
```markdown
这是一个带有脚注的句子[^1]。

[^1]: 这是一个脚注的示例。
```

**效果：**

这是一个带有脚注的句子[^1]。

[^1]: 这是一个脚注的示例。

### 2. 脚注的编号

脚注的编号是自动生成的，你不需要手动指定编号。Markdown 会根据脚注引用的顺序自动编号。

**示例：**
```markdown
这是一个带有脚注的句子[^first]。

这是另一个带有脚注的句子[^second]。

[^first]: 第一个脚注的内容。
[^second]: 第二个脚注的内容。
```

**效果：**

这是一个带有脚注的句子[^first]。

这是另一个带有脚注的句子[^second]。

[^first]: 第一个脚注的内容。
[^second]: 第二个脚注的内容。

## 在 Markdown 中使用缩写（Abbreviation）

缩写用于定义文档中使用的缩略词，并在第一次出现时提供全称。缩写不会自动生成脚注，但可以通过样式提示用户。

### 1. 定义缩写

**语法：**
```markdown
The HTML specification is maintained by the W3C.

*[HTML]: Hyper Text Markup Language
*[W3C]: World Wide Web Consortium
```

**示例：**
```markdown
The HTML specification is maintained by the W3C.

*[HTML]: Hyper Text Markup Language
*[W3C]: World Wide Web Consortium
```

**效果：**

The HTML specification is maintained by the W3C.

*[HTML]: Hyper Text Markup Language
*[W3C]: World Wide Web Consortium

**注意：** 缩写定义的效果依赖于 Markdown 渲染器是否支持。

## 在 Markdown 中添加定义列表（Definition List）

定义列表用于列出术语及其定义。Markdown 的标准语法不直接支持定义列表，但一些扩展（如 GitHub Flavored Markdown）支持。

### 1. 使用定义列表

**语法：**
```markdown
术语1
: 定义1

术语2
: 定义2
```

**示例：**
```markdown
Markdown
: 一种轻量级标记语言，用于编写格式化的文档。

HTML
: 超文本标记语言，用于创建网页。
```

**效果：**

Markdown
: 一种轻量级标记语言，用于编写格式化的文档。

HTML
: 超文本标记语言，用于创建网页。

**注意：** 并非所有 Markdown 渲染器都支持定义列表。

## 在 Markdown 中使用任务列表（Task List）

任务列表用于创建带有复选框的列表，用于跟踪任务完成情况。

### 1. 创建任务列表

**语法：**
```markdown
- [ ] 未完成任务
- [x] 已完成任务
```

**示例：**
```markdown
- [ ] 编写文档
- [x] 提交代码
- [ ] 开会
```

**效果：**

- [ ] 编写文档
- [x] 提交代码
- [ ] 开会

## 在 Markdown 中添加数学公式（Math Formula）

Markdown 本身不支持数学公式，但可以通过使用 MathJax 或其他数学渲染库来实现。

### 1. 使用 MathJax

**语法：**
```markdown
$$
E = mc^2
$$
```

**示例：**
```markdown
$$
E = mc^2
$$
```

**效果：**

$$
E = mc^2
$$

**注意：** 使用 MathJax 需要在 Markdown 文件中引入 MathJax 库。

### 2. 行内数学公式

**语法：**
```markdown
这是一个行内数学公式 $E = mc^2$。
```

**示例：**
```markdown
这是一个行内数学公式 $E = mc^2$。
```

**效果：**

这是一个行内数学公式 $E = mc^2$。

**注意：** 行内数学公式需要使用 `$` 包裹。

## 在 Markdown 中使用 Emoji 表情

Markdown 支持使用 Emoji 表情，可以通过 Emoji 代码或直接复制粘贴 Emoji 符号。

### 1. 使用 Emoji 代码

**语法：**
```markdown
:smile: :heart: :+1:
```

**示例：**
```markdown
Hello, world! :smile: :heart: :+1:
```

**效果：**

Hello, world! :smile: :heart: :+1:

### 2. 直接使用 Emoji 符号

**语法：**
```markdown
Hello, world! 😊❤️👍
```

**示例：**
```markdown
Hello, world! 😊❤️👍
```

**效果：**

Hello, world! 😊❤️👍

**注意：** 并非所有平台和渲染器都支持 Emoji 表情。

## 总结

- **脚注**：使用 `[^1]` 引用脚注，并在文档末尾定义 `[^1]: 脚注内容`。
- **缩写**：使用 `*[缩写]: 全称` 定义缩写。
- **定义列表**：使用 `术语` 和 `:` 定义术语和定义。
- **任务列表**：使用 `- [ ]` 和 `- [x]` 创建任务列表。
- **数学公式**：使用 MathJax 或其他数学渲染库，并使用 `$` 或 `$$` 包裹公式。
- **Emoji 表情**：使用 Emoji 代码或直接使用 Emoji 符号。

这些功能可以大大增强 Markdown 文档的表达能力，使其更加丰富和实用。



# 扩展语法与扩展
## GitHub Flavored Markdown (GFM)

**GitHub Flavored Markdown (GFM)** 是 GitHub 使用的 Markdown 扩展版本，旨在增强标准 Markdown 的功能，以更好地支持软件开发者和文档编写者的需求。GFM 在标准 Markdown 的基础上增加了一些有用的特性，使其更适合在 GitHub 平台上使用。

### GFM 的主要特性

#### 1. 表格（Tables）

GFM 支持在 Markdown 中创建表格，这使得在文档中展示结构化数据变得更加方便。

**示例：**
```markdown
| 姓名 | 年龄 | 城市    |
|------|------|---------|
| 张三 | 25   | 北京    |
| 李四 | 30   | 上海    |
```

**效果：**

| 姓名 | 年龄 | 城市    |
|------|------|---------|
| 张三 | 25   | 北京    |
| 李四 | 30   | 上海    |

#### 2. 删除线（Strikethrough）

GFM 支持删除线语法，用于表示被删除或不再有效的文本。

**语法：**
```markdown
~~删除线文本~~
```

**示例：**
```markdown
这是一个~~删除线~~文本。
```

**效果：**

这是一个~~删除线~~文本。

#### 3. 自动链接（Autolinks）

GFM 增强了自动链接的功能，使得 URL 和电子邮件地址在文档中自动转换为可点击的链接，无需使用 Markdown 的链接语法。

**示例：**
```markdown
https://www.github.com
email@example.com
```

**效果：**

https://www.github.com  
email@example.com

#### 4. 任务列表（Task Lists）

GFM 支持任务列表语法，用于创建带有复选框的列表，用于跟踪任务完成情况。

**语法：**
```markdown
- [x] 已完成任务
- [ ] 未完成任务
```

**示例：**
```markdown
- [x] 编写文档
- [ ] 提交代码
- [x] 开会
```

**效果：**

- [x] 编写文档
- [ ] 提交代码
- [x] 开会

### 其他 GFM 特性

- **代码块语法高亮**：GFM 支持代码块语法高亮，使得代码示例更加易读。
- **表格对齐**：GFM 支持在表格中设置文本对齐方式（左右居中对齐）。
- **Emoji 支持**：GFM 支持使用 Emoji 表情。

## 什么是 MultiMarkdown?

**MultiMarkdown** 是一个扩展的 Markdown 解析器，扩展了标准 Markdown 的功能，增加了许多额外的语法特性，适用于更复杂的文档编写需求。

### MultiMarkdown 的主要特性

- **表格**：支持创建复杂的表格。
- **脚注**：支持脚注语法。
- **元数据**：支持在文档中添加元数据，如标题、作者、日期等。
- **交叉引用**：支持在文档中创建交叉引用。
- **数学公式**：支持数学公式的渲染。
- **定义列表**：支持定义列表语法。

## 什么是 Markdown Extra?

**Markdown Extra** 是另一个扩展的 Markdown 版本，扩展了标准 Markdown 的功能，增加了许多额外的语法特性，适用于更复杂的文档编写需求。

### Markdown Extra 的主要特性

- **表格**：支持创建复杂的表格。
- **脚注**：支持脚注语法。
- **缩写**：支持缩写语法。
- **定义列表**：支持定义列表语法。
- **自定义 HTML 属性**：支持在 Markdown 中添加自定义 HTML 属性。
- **增强的代码块**：支持语法高亮和代码行号。

## 什么是 CommonMark?

**CommonMark** 是一个标准化和规范的 Markdown 版本，旨在统一不同 Markdown 实现之间的差异，提供一个标准的 Markdown 规范。

### CommonMark 的主要特性

- **标准化语法**：CommonMark 定义了标准化的 Markdown 语法规范，确保不同实现之间的兼容性。
- **明确的规范**：CommonMark 提供了详细的规范文档，解释了每种语法的使用方法和行为。
- **扩展性**：CommonMark 支持通过扩展机制添加新的语法特性。

## 常见的 Markdown 扩展语法

除了 GFM、MultiMarkdown、Markdown Extra 和 CommonMark 之外，还有一些常见的 Markdown 扩展语法：

### 1. 表格（Tables）

- **GFM**、**MultiMarkdown**、**Markdown Extra** 都支持表格语法。

### 2. 脚注（Footnotes）

- **GFM**、**MultiMarkdown**、**Markdown Extra** 都支持脚注语法。

### 3. 删除线（Strikethrough）

- **GFM** 支持删除线语法。

### 4. 自动链接（Autolinks）

- **GFM** 支持自动链接语法。

### 5. 任务列表（Task Lists）

- **GFM** 支持任务列表语法。

### 6. 数学公式（Math Formulas）

- **MultiMarkdown**、**Markdown Extra** 支持数学公式语法。

### 7. 定义列表（Definition Lists）

- **MultiMarkdown**、**Markdown Extra** 支持定义列表语法。

### 8. 缩写（Abbreviations）

- **Markdown Extra** 支持缩写语法。

### 9. 元数据（Metadata）

- **MultiMarkdown** 支持元数据语法。

### 10. 交叉引用（Cross References）

- **MultiMarkdown** 支持交叉引用语法。

## 总结

- **GFM**：GitHub 使用的 Markdown 扩展，增加了表格、删除线、自动链接、任务列表等特性。
- **MultiMarkdown**：扩展了标准 Markdown，增加了表格、脚注、元数据、交叉引用等特性。
- **Markdown Extra**：扩展了标准 Markdown，增加了表格、脚注、缩写、定义列表等特性。
- **CommonMark**：标准化的 Markdown 规范，旨在统一不同实现之间的差异。
- **常见的扩展语法**：表格、脚注、删除线、自动链接、任务列表、数学公式、定义列表、缩写、元数据、交叉引用。

这些扩展语法和版本使得 Markdown 更加灵活和强大，能够满足不同用户和平台的需求。





# 安全性
## Markdown 中的安全风险

Markdown 是一种轻量级标记语言，广泛用于编写文档、博客、论坛帖子等。然而，尽管 Markdown 相对安全，但在某些情况下，如果不加以适当处理，可能会引发安全风险。以下是 Markdown 中常见的安全风险：

### 1. **Markdown 注入攻击（Markdown Injection）**
Markdown 注入攻击是指攻击者通过恶意输入 Markdown 语法，导致解析后的内容执行未预期的操作。例如，攻击者可以插入恶意脚本或链接，从而实现跨站脚本攻击（XSS）。

**示例：**
```markdown
[a malicious link](javascript:alert('XSS'))
```

如果这个链接被解析并显示给用户，点击后会弹出 JavaScript 警告框，攻击者可以利用这一点执行更复杂的脚本。

### 2. **HTML 标签注入**
Markdown 允许嵌入 HTML 标签，如果不对用户输入进行适当的过滤，攻击者可以插入恶意 HTML 代码，例如 `<script>` 标签，从而实现跨站脚本攻击（XSS）。

**示例：**
```markdown
<script>alert('XSS');</script>
```

### 3. **资源滥用**
攻击者可以通过插入大量图片或视频链接，导致服务器资源被滥用。例如，攻击者可以上传大量图片，导致服务器带宽和存储空间被耗尽。

**示例：**
```markdown
![image](https://example.com/image1.jpg)
![image](https://example.com/image2.jpg)
...
```

### 4. **钓鱼攻击**
攻击者可以利用 Markdown 插入伪装成合法内容的链接，诱使用户点击，从而进行钓鱼攻击。

**示例：**
```markdown
[Click here to login](https://phishing.example.com)
```

## 如何防止 Markdown 注入攻击

### 1. **输入验证和清理（Sanitization）**
对用户输入进行严格的验证和清理，确保只允许安全的 Markdown 语法和必要的 HTML 标签。

- **使用库进行清理**：使用专门的库（如 `DOMPurify`、`sanitize-html`）来清理用户输入的 HTML 和 Markdown。
- **限制 HTML 标签**：只允许特定的 HTML 标签，如 `<a>`、`<strong>`、`<em>` 等，禁止使用 `<script>`、`<iframe>` 等危险标签。

**示例（使用 `sanitize-html` 库）：**
```javascript
const sanitizeHtml = require('sanitize-html');
const dirty = 'XSS <script>alert("XSS")</script>';
const clean = sanitizeHtml(dirty, {
  allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
  allowedAttributes: {
    'a': ['href', 'title']
  }
});
console.log(clean); // 输出: XSS &lt;script&gt;alert("XSS")&lt;/script&gt;
```

### 2. **禁用危险的 Markdown 语法**
禁用某些危险的 Markdown 语法，如自动链接（尤其是 `javascript:` 链接）和 HTML 标签。

**示例：**
```markdown
禁用自动链接：
[a link](https://example.com)  // 允许
[a link](javascript:alert('XSS'))  // 禁止
```

### 3. **使用内容安全策略（Content Security Policy, CSP）**
通过配置 CSP，可以限制浏览器加载和执行的资源类型，从而减少 XSS 攻击的风险。

**示例：**
```http
Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none';
```

### 4. **限制资源上传**
限制用户上传的资源类型和大小，防止资源滥用。例如，只允许上传特定类型的图片文件，并对上传的文件进行扫描。

### 5. **使用沙箱环境**
在某些情况下，可以将用户上传的内容渲染在沙箱环境中，以隔离潜在的攻击。

## 如何处理 Markdown 中的 HTML 标签

### 1. **允许特定标签**
如果需要允许用户使用 HTML 标签，可以通过配置 Markdown 解析器只允许特定的标签和属性。

**示例（使用 `markdown-it` 库）：**
```javascript
const MarkdownIt = require('markdown-it');
const md = new MarkdownIt({
  html: true,
  allowedAttributes: {
    'a': ['href', 'title'],
    'img': ['src', 'alt', 'title']
  }
});
```

### 2. **清理 HTML 标签**
使用 HTML 清理库（如 `DOMPurify`）对用户输入的 HTML 进行清理，去除潜在的恶意代码。

**示例（使用 `DOMPurify`）：**
```javascript
const DOMPurify = require('dompurify');
const cleanHTML = DOMPurify.sanitize(dirtyHTML);
```

### 3. **禁用 HTML 标签**
如果不需要用户使用 HTML 标签，可以在配置 Markdown 解析器时禁用 HTML 解析。

**示例（使用 `markdown-it` 库）：**
```javascript
const md = new MarkdownIt({
  html: false
});
```

## 如何配置 Markdown 解析器以提高安全性

### 1. **选择合适的解析器**
选择功能强大且可配置的 Markdown 解析器，如 `markdown-it`、`marked`、`CommonMark.js` 等。

### 2. **禁用危险的特性**
根据需求，禁用某些危险的 Markdown 特性。例如，禁用 HTML 解析、自动链接等。

**示例（使用 `markdown-it` 禁用 HTML 和自动链接）：**
```javascript
const md = new MarkdownIt({
  html: false,
  linkify: false
});
```

### 3. **使用插件进行扩展**
使用插件来扩展解析器的功能，同时保持安全性。例如，使用 `markdown-it-raw-loader` 来处理原始 HTML，但需要配合清理工具使用。

### 4. **配置清理工具**
结合使用 HTML 清理工具（如 `DOMPurify`）和 Markdown 解析器，确保所有输出的内容都是安全的。

**示例：**
```javascript
const MarkdownIt = require('markdown-it');
const DOMPurify = require('dompurify');
const md = new MarkdownIt();
const dirtyHTML = md.render(markdownInput);
const cleanHTML = DOMPurify.sanitize(dirtyHTML);
```

### 5. **限制资源类型和大小**
配置解析器和服务器，限制用户上传的资源类型和大小，防止资源滥用。

### 6. **使用 CSP**
配置内容安全策略（CSP），限制浏览器加载和执行的资源类型，减少 XSS 攻击的风险。

**示例：**
```http
Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none';
```

## 总结

- **安全风险**：Markdown 注入攻击、HTML 标签注入、资源滥用、钓鱼攻击。
- **防止注入攻击**：
  - 输入验证和清理
  - 禁用危险的 Markdown 语法
  - 使用内容安全策略（CSP）
  - 限制资源上传
  - 使用沙箱环境
- **处理 HTML 标签**：
  - 允许特定标签
  - 清理 HTML 标签
  - 禁用 HTML 标签
- **配置解析器**：
  - 选择合适的解析器
  - 禁用危险的特性
  - 使用插件进行扩展
  - 配置清理工具
  - 限制资源类型和大小
  - 使用 CSP

通过以上措施，可以有效提高 Markdown 应用的安全性，防止潜在的安全风险。






# 好看的 Markdown 模板

Markdown 本身是一种轻量级的标记语言，主要用于格式化文本。然而，通过结合一些 CSS 样式和模板框架，可以为 Markdown 文档添加美观的排版和设计。以下是一些推荐的好看 Markdown 模板和主题，适用于不同的用途，如博客、文档、简历等。

### 1. **GitHub Markdown 主题**

GitHub 提供了多种主题，可以为 Markdown 文档提供简洁且专业的样式。这些主题适用于技术文档、README 文件等。

- **GitHub Light Theme**
  - 简洁、干净，适合技术文档和代码展示。
  - 支持表格、代码块、任务列表等 GFM 特性。
  - [示例](https://github.com/primer/github-markdown-css)

- **GitHub Dark Theme**
  - 深色主题，适合夜间阅读和代码展示。
  - 与 Light Theme 类似，但背景为深色，文字为浅色。
  - [示例](https://github.com/primer/github-markdown-css)

### 2. **Markdown Resume Templates**

这些模板专为简历设计，提供了简洁、现代的排版，适合展示个人技能和工作经验。

- **Markdown CV**
  - 提供多种样式选项，如单栏、双栏布局。
  - 支持自定义颜色和字体。
  - [示例](https://github.com/mwhite/resume)

- **Awesome CV**
  - 基于 LaTeX 的简历模板，但也可以导出为 Markdown。
  - 提供多种主题，如简洁、现代、创意等。
  - [示例](https://github.com/posquit0/Awesome-CV)

### 3. **Hugo Themes**

Hugo 是一个流行的静态网站生成器，支持 Markdown 文档，并提供多种主题，可以为博客、文档、项目网站等提供美观的样式。

- **Ananke Theme**
  - 现代、响应式设计，适合博客和项目网站。
  - 支持多种内容类型，如文章、项目、页面等。
  - [示例](https://themes.gohugo.io/themes/gohugo-theme-ananke/)

- **Casper Theme**
  - 灵感来自 Ghost 博客平台，简洁、优雅。
  - 适合个人博客和作品展示。
  - [示例](https://themes.gohugo.io/themes/casper/)

### 4. **MkDocs Themes**

MkDocs 是一个用于构建项目文档的静态网站生成器，提供多种主题，可以为技术文档提供美观的样式。

- **Material for MkDocs**
  - 现代、响应式设计，基于 Google 的 Material Design。
  - 支持多种插件，如搜索、版本控制等。
  - [示例](https://squidfunk.github.io/mkdocs-material/)

- **Read the Docs Theme**
  - 经典、简洁的设计，适合技术文档。
  - 支持搜索、导航、版本控制等特性。
  - [示例](https://sphinx-rtd-theme.readthedocs.io/en/stable/)

### 5. **Jekyll Themes**

Jekyll 是一个静态网站生成器，支持 Markdown 文档，并提供多种主题，可以为博客、文档、项目网站等提供美观的样式。

- **Minimal Mistakes**
  - 现代、响应式设计，适合博客和个人网站。
  - 提供多种布局和样式选项。
  - [示例](https://mmistakes.github.io/minimal-mistakes/)

- **Lanyon**
  - 灵感来自 Poole，简洁、优雅。
  - 适合个人博客和作品展示。
  - [示例](https://lanyon.getpoole.com/)

### 6. **其他推荐模板**

- **Typora Themes**
  - Typora 是一个流行的 Markdown 编辑器，提供多种主题，可以为文档提供美观的样式。
  - [示例](https://theme.typora.io/)

- **Markdown.css**
  - 一个简单的 CSS 文件，可以为任何 Markdown 文档提供基本样式。
  - [示例](https://github.com/mrcoles/markdown-css)

### 7. **自定义模板**

如果你需要更个性化的设计，可以自己编写 CSS 样式，或者使用模板引擎（如 Jekyll、Hugo）创建自定义主题。

**步骤：**
1. **选择基础模板**：选择一个基础模板或主题作为起点。
2. **编写 CSS**：根据需要编写自定义 CSS，修改颜色、字体、布局等。
3. **集成 Markdown**：使用静态网站生成器（如 Jekyll、Hugo）将 Markdown 文档与自定义 CSS 集成。
4. **预览和发布**：在本地预览效果，满意后发布到服务器或静态网站托管平台。

## 总结

- **GitHub Markdown 主题**：简洁、专业，适合技术文档。
- **Markdown Resume Templates**：简洁、现代，适合简历。
- **Hugo Themes**：多样、现代，适合博客和项目网站。
- **MkDocs Themes**：简洁、响应式，适合技术文档。
- **Jekyll Themes**：多样、优雅，适合博客和个人网站。
- **自定义模板**：根据需要自定义样式和布局。

通过选择合适的模板和主题，可以为 Markdown 文档添加美观的排版和设计，提升文档的可读性和专业性。



