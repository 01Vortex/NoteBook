# sqlmap说明书


```
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

