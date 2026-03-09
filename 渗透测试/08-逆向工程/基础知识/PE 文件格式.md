# PE 文件格式

> PE (Portable Executable) 是 Windows 可执行文件格式

## PE 文件结构

```
┌─────────────────────┐
│   DOS Header        │  DOS 头部
├─────────────────────┤
│   DOS Stub          │  DOS 存根
├─────────────────────┤
│   PE Signature      │  PE 签名 "PE\0\0"
├─────────────────────┤
│   File Header       │  文件头
├─────────────────────┤
│   Optional Header   │  可选头
├─────────────────────┤
│   Section Headers   │  节表
├─────────────────────┤
│   .text Section     │  代码段
├─────────────────────┤
│   .data Section     │  数据段
├─────────────────────┤
│   .rdata Section    │  只读数据段
├─────────────────────┤
│   .idata Section    │  导入表
├─────────────────────┤
│   .edata Section    │  导出表
├─────────────────────┤
│   .rsrc Section     │  资源段
└─────────────────────┘
```

## DOS Header

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;      // 魔数 "MZ" (0x5A4D)
    // ... 其他字段
    LONG e_lfanew;     // PE 头偏移
} IMAGE_DOS_HEADER;
```

## PE Header

```c
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;                    // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;       // 文件头
    IMAGE_OPTIONAL_HEADER OptionalHeader; // 可选头
} IMAGE_NT_HEADERS;
```

## 重要字段

### 入口点 (Entry Point)

```c
// OptionalHeader.AddressOfEntryPoint
// 程序开始执行的地址
DWORD entryPoint = optionalHeader.AddressOfEntryPoint;
```

### 基址 (Image Base)

```c
// OptionalHeader.ImageBase
// 程序加载到内存的首选地址
ULONGLONG imageBase = optionalHeader.ImageBase;
```

### 导入表 (Import Table)

```c
// 记录程序依赖的 DLL 和函数
IMAGE_IMPORT_DESCRIPTOR importDesc;
```

### 导出表 (Export Table)

```c
// DLL 导出的函数列表
IMAGE_EXPORT_DIRECTORY exportDir;
```

## 节区 (Sections)

### .text 节

- 包含可执行代码
- 属性: 可读、可执行

### .data 节

- 包含已初始化的全局变量
- 属性: 可读、可写

### .rdata 节

- 包含只读数据（常量、字符串）
- 属性: 只读

### .idata 节

- 导入地址表 (IAT)
- 导入名称表 (INT)

### .rsrc 节

- 资源数据（图标、对话框等）

## 地址转换

### RVA (相对虚拟地址)

```
RVA = 虚拟地址 - ImageBase
```

### 文件偏移

```
文件偏移 = RVA - 节的 VirtualAddress + 节的 PointerToRawData
```

## 使用 Python 解析 PE

```python
import pefile

# 加载 PE 文件
pe = pefile.PE('example.exe')

# 获取入口点
entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"Entry Point: 0x{entry_point:X}")

# 获取基址
image_base = pe.OPTIONAL_HEADER.ImageBase
print(f"Image Base: 0x{image_base:X}")

# 遍历节
for section in pe.sections:
    print(f"Section: {section.Name.decode().strip()}")
    print(f"  Virtual Address: 0x{section.VirtualAddress:X}")
    print(f"  Size: 0x{section.SizeOfRawData:X}")

# 获取导入表
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"DLL: {entry.dll.decode()}")
    for imp in entry.imports:
        print(f"  {imp.name.decode() if imp.name else 'Ordinal: ' + str(imp.ordinal)}")
```

## 常用工具

- **PE Explorer**: 图形化 PE 查看器
- **CFF Explorer**: 强大的 PE 编辑器
- **PEview**: 轻量级 PE 查看器
- **pefile (Python)**: PE 文件解析库
- **010 Editor**: 十六进制编辑器（带 PE 模板）
