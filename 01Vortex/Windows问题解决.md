### 文件夹权限赋予

1.  以管理员身份打开命令提示符。
2.  **获取所有权（二选一）**：
*   **为单个文件夹**：
```bash
takeown /F "D:\Program Files" /R /D Y
```
*   **为整个D盘根目录**：如果文件夹很多，可以直接对D盘根目录操作：
```bash
takeown /F D:\ /R /D Y
```
3.  **授予管理员完全控制权**：
```bash
icacls "D:\Program Files" /T /grant administrators:F
```
