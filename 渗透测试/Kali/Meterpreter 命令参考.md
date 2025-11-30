# 核心命令

- `?` 或 `help`: 显示帮助菜单。
- `background` 或 `bg`: 将当前会话置于后台。
- `bgkill`: 终止后台运行的 Meterpreter 脚本。
- `bglist`: 列出正在运行的后台脚本。
- `bgrun`: 作为后台线程执行 Meterpreter 脚本。
- `channel`: 显示信息或控制活动通道。
- `close`: 关闭一个通道。
- `detach`: 分离 Meterpreter 会话（用于 http/https）。
- `disable_unicode_encoding` / `enable_unicode_encoding`: 禁用/启用 Unicode 字符串编码。
- `exit` 或 `quit`: 终止 Meterpreter 会话。
- `get_timeouts`: 获取当前会话超时值。
- `guid`: 获取会话的 GUID。
- `info`: 显示有关 Post 模块的信息。
- `irb`: 在当前会话上打开交互式 Ruby shell。
- `load`: 加载一个或多个 Meterpreter 扩展。
- `machine_id`: 获取附加到会话的机器的 MSF ID。
- `migrate`: 将服务器迁移到另一个进程。
- `pivot`: 管理 Pivot 监听器。
- `pry`: 在当前会话上打开 Pry 调试器。
- `read`: 从通道读取数据。
- `resource`: 运行存储在文件中的命令。
- `run`: 执行 Meterpreter 脚本或 Post 模块。
- `secure`: 重新协商会话上的 TLV 数据包加密。
- `sessions`: 快速切换到另一个会话。
- `set_timeouts`: 设置当前会话超时值。
- `sleep`: 强制 Meterpreter 进入静默状态，然后重新建立会话。
- `ssl_verify`: 修改 SSL 证书验证设置。
- `transport`: 管理传输机制。
- `use`: 加载命令的已弃用别名。
- `uuid`: 获取当前会话的 UUID。
- `write`: 向通道写入数据。

# 文件系统命令

这些命令用于与目标系统的文件系统交互。

- `cat`: 将文件内容读取到屏幕。
- `cd`: 更改目录。
- `checksum`: 检索文件的校验和。
- `cp`: 复制源到目标。
- `del`: 删除指定的文件。
- `dir`: 列出文件（`ls` 的别名）。
- `download`: 下载文件或目录。
- `edit`: 编辑文件。
- `getlwd` 或 `lpwd`: 打印本地工作目录。
- `getwd` 或 `pwd`: 打印工作目录。
- `ldir` 或 `lls`: 列出本地文件。
- `lmkdir`: 在本地机器上创建新目录。
- `ls`: 列出文件。
- `mkdir`: 创建目录。
- `mv`: 移动源到目标。
- `rm`: 删除指定的文件。
- `rmdir`: 移除目录。
- `search`: 搜索文件。
- `show_mount`: 列出所有挂载点/逻辑驱动器。
- `upload`: 上传文件或目录。

# 网络命令

这些命令用于与目标系统的网络配置交互。

- `arp`: 显示主机 ARP 缓存。
- `getproxy`: 显示当前代理配置。
- `ifconfig` 或 `ipconfig`: 显示接口。
- `netstat`: 显示网络连接。
- `portfwd`: 将本地端口转发到远程服务。
- `resolve`: 解析目标上的一组主机名。
- `route`: 查看和修改路由表。

# 系统命令

这些命令用于与目标系统的操作系统交互。

- `clearev`: 清除事件日志。
- `drop_token`: 放弃任何活动的模拟令牌。
- `execute`: 执行命令。
- `getenv`: 获取一个或多个环境变量值。
- `getpid`: 获取当前进程标识符。
- `getprivs`: 尝试启用当前进程可用的所有权限。
- `getsid`: 获取服务器运行的用户 SID。
- `getuid`: 获取服务器运行的用户。
- `kill`: 终止进程。
- `localtime`: 显示目标系统本地日期和时间。
- `pgrep`: 按名称过滤进程。
- `pkill`: 按名称终止进程。
- `ps`: 列出正在运行的进程。
- `reboot`: 重启远程计算机。
- `reg`: 修改并与远程注册表交互。
- `rev2self`: 在远程机器上调用 RevertToSelf()。
- `shell`: 进入系统命令 shell。
- `shutdown`: 关闭远程计算机。
- `steal_token`: 尝试从目标进程窃取模拟令牌。
- `suspend`: 挂起或恢复进程列表。
- `sysinfo`: 获取有关远程系统的信息，例如操作系统。

# 用户界面命令

这些命令用于与目标系统的用户界面交互。

- `enumdesktops`: 列出所有可访问的桌面和窗口工作站。
- `getdesktop`: 获取当前 Meterpreter 桌面。
- `idletime`: 返回远程用户空闲的秒数。
- `keyboard_send`: 发送按键。
- `keyevent`: 发送键事件。
- `keyscan_dump`: 转储按键缓冲区。
- `keyscan_start`: 开始捕获按键。
- `keyscan_stop`: 停止捕获按键。
- `mouse`: 发送鼠标事件。
- `screenshare`: 实时观看远程用户桌面。
- `screenshot`: 获取交互式桌面的屏幕截图。
- `setdesktop`: 更改 Meterpreters 当前桌面。
- `uictl`: 控制某些用户界面组件。

# 网络摄像头命令

这些命令用于与目标系统的网络摄像头交互。

- `record_mic`: 从默认麦克风录制音频 X 秒。
- `webcam_chat`: 开始视频聊天。
- `webcam_list`: 列出网络摄像头。
- `webcam_snap`: 从指定的网络摄像头拍摄快照。
- `webcam_stream`: 从指定的网络摄像头播放视频流。

# 音频输出命令
- `play`: 在目标系统上播放波形音频文件 (.wav)。

# 特权提升命令

- `getsystem`: 尝试将您的权限提升到本地系统。

# 密码数据库命令

- `hashdump`: 转储 SAM 数据库的内容。

# 时间戳命令

- `timestomp`: 操作文件 MACE 属性。