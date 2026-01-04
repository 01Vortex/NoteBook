# 概念讲解
## 数据库参数化查询接口
MySQL数据库提供了参数化查询接口，以增强SQL语句的安全性和性能。以下是主要介绍：

### 接口类型

1.  **预处理语句（Prepared Statements）**
   - **原理**：将SQL语句模板发送给数据库进行预编译，然后绑定参数值执行。
   - **优势**：
     - **防止SQL注入**：参数值经过转义，避免恶意代码注入。
     - **提高性能**：预编译后，重复执行时无需再次编译，提升效率。
   - **使用方法**：
     - **准备语句**：使用`PREPARE`定义带有占位符`?`的SQL模板。
     - **绑定参数**：使用`SET`或`EXECUTE ... USING`设置参数值。
     - **执行语句**：执行`EXECUTE`语句。
     - **示例**：
       ```sql
       PREPARE stmt FROM 'SELECT * FROM users WHERE id = ?';
       SET @user_id = 1;
       EXECUTE stmt USING @user_id;
       DEALLOCATE PREPARE stmt;
       ```

2. **存储过程（Stored Procedures）**
   - **原理**：将SQL语句封装在数据库中，通过调用存储过程执行，可接受参数。
   - **优势**：
     - **代码复用**：减少重复代码，提高可维护性。
     - **安全性**：与预处理语句类似，防止SQL注入。
   - **使用方法**：
     - **创建存储过程**：定义包含参数的SQL逻辑。
     - **调用存储过程**：传递参数执行。
     - **示例**：
       ```sql
       CREATE PROCEDURE get_user(IN user_id INT)
       BEGIN
         SELECT * FROM users WHERE id = user_id;
       END;
       CALL get_user(1);
       ```

### 编程语言支持

- **MySQLi（PHP）**
  - **示例**：
    ```php
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $username = "admin";
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
      // 处理结果
    }
    $stmt->close();
    ```

- **JDBC（Java）**
  - **示例**：
    ```java
    String sql = "SELECT * FROM users WHERE id = ?";
    PreparedStatement pstmt = conn.prepareStatement(sql);
    pstmt.setInt(1, 1);
    ResultSet rs = pstmt.executeQuery();
    while (rs.next()) {
      // 处理结果
    }
    rs.close();
    pstmt.close();
    ```

- **Python（mysql-connector）**
  - **示例**：
    ```python
    cursor = cnx.cursor()
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (1,))
    result = cursor.fetchone()
    print(result)
    cursor.close()
    cnx.close()
    ```

### 注意事项

- **参数类型匹配**：确保绑定的参数类型与SQL语句中占位符的类型一致。
- **资源释放**：及时关闭预处理语句和数据库连接，避免资源泄露。
- **适用场景**：适用于需要动态构建SQL语句、防止SQL注入以及提升性能的场景。

通过使用参数化查询接口，可以有效防止SQL注入攻击，提高应用程序的安全性和数据库性能。建议在开发过程中广泛采用。
# Sql注入案例
## 登录绕过
1. **场景描述**
   登录验证的SQL语句通常为：
   ```sql
   SELECT * FROM users WHERE username='$username' AND password='$password'
   ```
2. **攻击方式**
   - **用户名输入**：`' OR '1'='1' --`
   - **密码输入**：任意值
3. **结果**
   SQL语句变为：
   ```sql
   SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='任意值'
   ```
   由于`'1'='1'`恒为真，且注释符`--`使后面的密码验证失效，攻击者可绕过验证登录系统。

## 数据泄露
1. **场景描述**
   用户信息查询的SQL语句为：
   ```sql
   SELECT * FROM users WHERE id=$_GET['id']
   ```
2. **攻击方式**
   - **URL参数输入**：`1 UNION SELECT username, password FROM users --`
3. **结果**
   SQL语句变为：
   ```sql
   SELECT * FROM users WHERE id=1 UNION SELECT username, password FROM users --'
   ```
   攻击者通过`UNION`查询获取所有用户的用户名和密码。

## 数据篡改或删除
1. **场景描述**
   订单处理的SQL语句为：
   ```sql
   UPDATE orders SET status='shipped' WHERE order_id=$_POST['order_id']
   ```
2. **攻击方式**
   - **订单ID输入**：`1; UPDATE orders SET status='cancelled' --`
3. **结果**
   SQL语句变为：
   ```sql
   UPDATE orders SET status='shipped' WHERE order_id=1; UPDATE orders SET status='cancelled' --'
   ```
   攻击者利用分号`；`执行多个语句，将订单状态更改为“已取消”。

## 盲注
1. **场景描述**
   应用程序不返回详细的错误信息或查询结果。
2. **攻击方式**
   - **布尔盲注**：通过构造使查询结果返回真或假的语句，如`' AND (SELECT COUNT(*) FROM users)=1 --`，根据页面响应判断条件是否成立。
   - **时间盲注**：利用延时函数，如`' AND SLEEP(5) --`，根据页面响应时间判断条件是否成立。
3. **结果**
   攻击者通过逐步猜测，获取数据库中的敏感信息。

## 二次注入
1. **场景描述**
   用户输入的数据存储在数据库中，在后续使用时未进行再次过滤。
2. **攻击方式**
   - **用户注册输入**：`admin'; DROP TABLE users --`（存储在数据库中）
   - **后续使用**：应用程序从数据库中取出该数据并拼接到SQL语句中。
3. **结果**
   执行恶意SQL语句，导致数据表被删除。





# sqlmap说明书


```Python
选项：
  -h, --help            显示基本帮助信息
  -hh                   要查看完整选项列表
  --version             显示程序版本号并退出
  -v VERBOSE            设置详细级别：0-6（默认为1）

目标：
  必须至少提供以下一个选项来定义目标

  -u URL, --url=URL     目标URL（例如 "http://www.site.com/vuln.php?id=1"）
  -g GOOGLEDORK         将Google搜索结果作为目标URL进行处理

请求：
  可以使用以下选项指定如何连接到目标URL

  --data=DATA           要通过POST发送的数据字符串（例如 "id=1"）
  --cookie=COOKIE       HTTP Cookie头值（例如 "PHPSESSID=a8d127e.."）
  --random-agent        使用随机选择的HTTP User-Agent头值
  --proxy=PROXY         使用代理连接到目标URL
  --tor                 使用Tor匿名网络
  --check-tor           检查Tor是否正确使用

注入：
  可以使用以下选项指定要测试的参数、自定义注入负载和可选篡改脚本

  -p TESTPARAMETER      要测试的参数
  --dbms=DBMS           强制后端数据库管理系统为指定值

检测：
  可以使用以下选项自定义检测阶段的行为

  --level=LEVEL         执行测试的级别（1-5，默认为1）
  --risk=RISK           执行测试的风险等级（1-3，默认为1）

技术：
  可以使用以下选项调整特定SQL注入技术的测试行为

  --technique=TECH..    要使用的SQL注入技术（默认为"BEUSTQ"）

枚举：
  可以使用以下选项列举后端数据库管理系统的相关信息、结构以及表中的数据

  -a, --all             检索所有内容
  -b, --banner          检索DBMS横幅信息
  --current-user        检索DBMS当前用户
  --current-db          检索DBMS当前数据库
  --passwords           列举DBMS用户的密码哈希
  --dbs                 列举DBMS数据库
  --tables              列举DBMS数据库表
  --columns             列举DBMS数据库表列
  --schema              列举DBMS模式
  --dump                导出DBMS数据库表条目
  --dump-all            导出所有DBMS数据库表条目
  -D DB                要列举的DBMS数据库
  -T TBL               要列举的DBMS数据库表
  -C COL               要列举的DBMS数据库表列

操作系统访问：
  可以使用以下选项访问后端数据库管理系统所在的底层操作系统

  --os-shell            提示输入交互式操作系统shell
  --os-pwn              提示输入OOB shell、Meterpreter或VNC

通用：
  可以使用以下选项设置一些通用的工作参数

  --batch               从不询问用户输入，使用默认行为
  --flush-session       清除当前目标的会话文件

杂项：
  以下选项不属于任何其他类别

  --wizard              供初学者使用的简单向导界面

```

