

# 日志
## 安装普罗米修斯
# 数据库问题
## 无法连接本地数据库
- 在MySQL配置文件的[mysqlid]添加，然后重启
```
bind-address = 127.0.0.1
```



## 关于MySQL排序规则的选择
在MySQL中，选择合适的排序规则（Collation）对于确保数据的正确排序、比较和索引至关重要。以下是选择MySQL数据库排序规则时需要考虑的关键因素和具体建议：

### 1. **理解MySQL的排序规则命名规范**
MySQL的排序规则名称通常遵循以下模式：
```
字符集_语言_语种_CI/CS_AI/AS
```
- **字符集（Character Set）**：如`utf8`, `utf8mb4`, `latin1`等。
- **语言（Language）**：如`en`（英语）、`zh`（中文）等。
- **语种（Country/Region）**：如`US`（美国）、`CN`（中国）等。
- **CI/CS（Case Insensitive/Case Sensitive）**：
  - `CI`：不区分大小写。
  - `CS`：区分大小写。
- **AI/AS（Accent Insensitive/Accent Sensitive）**：
  - `AI`：不区分重音。
  - `AS`：区分重音。

### 2. **选择合适的字符集**
- **UTF-8（`utf8mb4`）**：推荐使用`utf8mb4`，因为它支持完整的Unicode字符集，包括表情符号和其他特殊字符。
  ```sql
  CHARACTER SET utf8mb4
  ```
- **其他字符集**：如果你的应用主要使用特定语言的字符，可以选择相应的字符集，如`latin1`（西欧语言）、`gbk`（简体中文）等。

### 3. **选择区分大小写和重音的排序规则**
- **不区分大小写，不区分重音**：
  - `utf8mb4_general_ci`：适用于大多数场景，性能较好，但不严格按照语言规则排序。
  - `utf8mb4_unicode_ci`：更符合Unicode标准，排序更准确，但性能略低于`general_ci`。
  ```sql
  COLLATE utf8mb4_unicode_ci
  ```
- **区分大小写，不区分重音**：
  - `utf8mb4_general_cs` 或 `utf8mb4_unicode_cs`。
- **不区分大小写，区分重音**：
  - MySQL默认不提供这种排序规则，可能需要自定义或使用其他变体。
- **区分大小写，区分重音**：
  - `utf8mb4_bin`：二进制排序，区分大小写和重音。
  ```sql
  COLLATE utf8mb4_bin
  ```

### 4. **具体应用场景的建议**
- **Web应用（多语言支持）**：
  - 如果你的应用需要支持多种语言，建议使用`utf8mb4_unicode_ci`，因为它对各种语言的支持更好。
  ```sql
  CREATE DATABASE my_database CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```
- **中文应用**：
  - 对于简体中文，可以使用`utf8mb4_unicode_ci`或`utf8mb4_zh_0900_as_cs`（如果需要更精确的中文排序）。
  ```sql
  CREATE DATABASE my_chinese_db CHARACTER SET utf8mb4 COLLATE utf8mb4_zh_0900_as_cs;
  ```
- **高性能需求**：
  - 如果对性能有较高要求，并且可以接受不区分大小写和重音，可以使用`utf8mb4_general_ci`。
  ```sql
  CREATE DATABASE high_perf_db CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
  ```
- **二进制排序**：
  - 如果需要严格的二进制比较，可以使用`utf8mb4_bin`。
  ```sql
  CREATE DATABASE binary_db CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
  ```

### 5. **查看可用的排序规则**
你可以通过以下命令查看MySQL中可用的排序规则：
```sql
SHOW COLLATION WHERE Charset = 'utf8mb4';
```

### 6. **示例**
假设你正在创建一个支持多语言的Web应用，并且需要不区分大小写和不区分重音的排序规则，可以这样创建数据库：
```sql
CREATE DATABASE multilingual_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 7. **总结**
选择MySQL的排序规则时，主要考虑以下几点：
- **字符集**：推荐使用`utf8mb4`以支持完整的Unicode。
- **大小写和重音的区分**：根据应用需求选择`CI`或`CS`，`AI`或`AS`。
- **语言支持**：选择适合应用语言的排序规则，如`utf8mb4_unicode_ci`适用于多语言环境，`utf8mb4_zh_0900_as_cs`适用于中文环境。
- **性能**：一般来说，`general_ci`比`unicode_ci`性能更好，但排序准确性稍低。

通过综合考虑这些因素，可以选择最适合你应用的MySQL排序规则。


# 端口
- 22334 ssh
- 2022  blog
- 2023 main
- 2077 nav
- 2076 bt
- 2075 普罗米修斯






