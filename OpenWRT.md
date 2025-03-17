# OpenWRT简介
OpenWrt是一个为嵌入式设备设计的Linux操作系统，主要用于路由器等网络设备。它提供了丰富的功能和高度的可定制性，允许用户通过安装软件包来扩展设备的功能，而不像传统固件那样受限。

- **灵活性与可扩展性**：OpenWrt基于Linux，提供了一个完全可写的文件系统和软件包管理系统。这使得用户可以根据需要安装、配置和移除软件包，极大地提高了灵活性。
  
- **安全性**：由于其开源性质，OpenWrt的安全补丁更新迅速，社区贡献了大量的安全增强功能。此外，它的默认设置倾向于更高的安全性，比如禁用不必要的服务。

- **开发者友好**：对于开发者而言，OpenWrt提供了一套完整的开发工具链，支持快速原型设计和开发。文档齐全，社区活跃，遇到问题时容易找到解决方案。

- **应用场景广泛**：除了作为家庭路由器使用外，OpenWrt还被用于构建无线接入点、防火墙、VPN网关等多种网络相关应用。

OpenWrt不仅仅是一个路由器固件，它更像是一个小型的Linux发行版，适用于各种嵌入式设备，赋予了这些设备更多的可能性。无论是技术爱好者还是专业网络管理人员，都可以根据自己的需求对OpenWrt进行深度定制。


# 光猫改桥接

- 查看光猫标签获得登录地址(有普通用户账号密码,但是没用)

- 去淘宝找人破解管理员账号和密码,喊他固定管理员密码并改桥接


# 如何刷入OpenWRT
## 主播de设备

 - 路由器-->Xiaomi Mi Router WR30U(咸鱼100多)

 - OpenWrt固件-->ImmortalWrt 23.05.4
## 路由器是否支持OpenWrt固件

 -  [支持的设备](https://openwrt.org/zh/supported_devices)

## OpenWRT各种固件包下载

### ImmortalWrt
- [ImmortalWrt Firmware Selector](https://firmware-selector.immortalwrt.org)
### Kwrt
- [Kwrt(OpenWrt)软路由固件下载与在线定制编译](https://openwrt.ai/)

## 刷入固件
### 用不死后台刷
-  [如何刷不死后台](https://search.bilibili.com/all?keyword=如何刷不死后台&from_source=webtop_search&spm_id_from=333.1007&search_source=5)

### 用路由器刷入
-  系统设置-->在备份与更新选项 直接上传(变砖概率高)




# OpenWRT配置
## 登录
- 登陆地址  http://192.168.1.1
- 账号:root
- 密码:无密码,直接登录
## 使用PPPoE拨号上网

-  在光猫上找到账号(自己手机号)密码(密码通常是6位)

-  网络-->接口-->编辑wan口-->协议PPPoE-->输入宽带账号密码-->保存-->保存并且应用

## 软件包安装
### 安装Argon主题
 - 系统-->软件包-->在过滤器输入Argon-->更新列表-->安装Argon及其依赖

### 软件包推荐
-  luci-app-ttyd 网页版命令行
-  luci-app-wrtbwmon 流量监控
-  luci-app-PassWall 科学上网

### 常用软件包
 [OpenWRT软件包中英文对照表](https://xiangzi.ltd/2023/03/10/openwrt-package/)

## 设置管理员密码
-  系统-->管理权-->路由器密码






# 远程管理路由器
## 通过Web
- 原理: wan口IPv6地址＋4443端口访问  示例:http://[ipv6地址]:4443
### 为后台界面增加端口
- 原因:入站的80/443端口被运营商锁了,外部流量无法访问80/443端口的服务,所以改端口

- 步骤:
   1.打开终端
   2.输入命令 vi etc/config/uhttpd 
   3.复制 list listen_https '[::]:4443'  到 list listen_https '[::]:443'下面一行

### 使用DDNS-Go
- 将wan口ipv6地址固定到你的域名上
- 可获得wan口ipv6地址


## SSH666