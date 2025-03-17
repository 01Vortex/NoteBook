# 基础知识













# 其他问题
## 插入PDF
在HTML中嵌入PDF文件有几种常用方法，以下是详细说明和示例：

### 1. 使用 `<embed>` 标签
```html
<embed 
  src="your-file.pdf" 
  type="application/pdf" 
  width="100%" 
  height="600px"
  title="PDF文档">
```
**特点**：
- 原生HTML支持
- 自动显示滚动条和工具栏
- 兼容性：现代浏览器基本支持（Chrome/Firefox/Edge）

### 2. 使用 `<object>` 标签
```html
<object 
  data="your-file.pdf" 
  type="application/pdf" 
  width="100%" 
  height="600px">
  <p>您的浏览器不支持PDF显示，请<a href="your-file.pdf">下载查看</a></p>
</object>
```
**特点**：
- 提供备用内容支持
- 更标准的HTML5方式
- 兼容性与`<embed>`类似

### 3. 使用 `<iframe>`（推荐）
```html
<iframe 
  src="your-file.pdf#view=FitH" 
  width="100%" 
  height="600px"
  style="border: none;">
  <p>当前环境不支持，请<a href="your-file.pdf">点击下载</a></p>
</iframe>
```
**特点**：
- 支持PDF参数控制显示（`#view=FitH`表示水平适配）
- 可通过CSS自定义样式
- 移动端友好（多数系统内置PDF查看器）

### 4. 使用PDF.js（高级定制）
```html
<div id="pdf-container"></div>

<!-- 引入PDF.js库 -->
<script src="//mozilla.github.io/pdf.js/build/pdf.js"></script>
<script>
  const url = 'your-file.pdf';
  
  // 初始化
  pdfjsLib.getDocument(url).promise.then(pdf => {
    pdf.getPage(1).then(page => {
      const scale = 1.5;
      const viewport = page.getViewport({ scale });
      
      // 创建canvas
      const canvas = document.createElement('canvas');
      const context = canvas.getContext('2d');
      canvas.height = viewport.height;
      canvas.width = viewport.width;

      // 渲染PDF页面
      page.render({
        canvasContext: context,
        viewport: viewport
      });

      document.getElementById('pdf-container').appendChild(camera);
    });
  });
</script>
```
**特点**：
- 完全自定义渲染
- 支持分页控制、文本选择、搜索等功能
- 需要加载额外资源（约300KB）

### 5. 纯链接方式
```html
<a href="your-file.pdf" target="_blank">在新窗口查看PDF</a>
```
**适用场景**：
- 快速实现
- 移动端优先体验
- 大文件需要避免页面卡顿

---

### 最佳实践建议：
1. **响应式处理**：
   ```css
   iframe {
     width: 100%;
     height: 80vh; /* 视口高度的80% */
     min-height: 600px;
   }
   ```

2. **参数控制**：
   - `#page=3` 直接定位到第3页
   - `#zoom=50` 设置50%缩放
   - `#view=FitV` 垂直适配

3. **性能优化**：
   - 压缩PDF文件（使用工具如Adobe Acrobat的"Reduce File Size"功能）
   - 对于大文件使用分页加载（PDF.js支持）

4. **跨浏览器兼容**：
   ```html
   <iframe>
     <!-- 备用内容 -->
     <embed src="your-file.pdf" width="100%" height="600px">
   </iframe>
   ```

5. **安全防护**：
   ```html
   <!-- 防止嵌套劫持 -->
   <iframe src="your-file.pdf" sandbox="allow-scripts allow-same-origin"></iframe>
   ```

选择方案时需考虑：
- 简单展示 → 使用`<iframe>`
- 需要自定义交互 → PDF.js
- 移动端优先 → 直接链接+服务端PDF优化
- 企业级应用 → 结合CDN分发和PDF预加载

注意：部分浏览器（如Safari）可能需要用户手动允许PDF显示，建议始终提供备用下载链接。