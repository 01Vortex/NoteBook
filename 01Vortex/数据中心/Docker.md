## 宝塔
### run命令
```
docker run -d \
  --name baota \
  --restart unless-stopped \
  --dns 223.5.5.5 \
  -p 8888:8888 \
  -p 8800:80 \
  -p 4433:443 \
  -p 2222:22 \
  -p 888:888 \
  -p 3306:3306 \
  -p 2000-2099:2000-2099 \
  -v /mnt/mmcblk0p7/storage/baota:/www \
  -e TZ=Asia/Shanghai \
btpanel/baota:latest
```
### 配置文件yml
```
version: '3.8'

services:
  baota:
    image: btpanel/baota:latest
    container_name: baota
    restart: unless-stopped
    dns:
      - 223.5.5.5
    ports:
      - "8888:8888"
      - "8800:80"
      - "4433:443"
      - "2222:22"
      - "888:888"
      - "3306:3306"
      - "2077:2077"
    volumes:
      - /mnt/mmcblk0p7/storage/baota:/www
    environment:
      - TZ=Asia/Shanghai
```
好的，这是您提供的 `docker run` 命令转换为 `docker-compose.yml` 格式的配置文件。

###  使用方法

1.  **创建目录并保存文件**
    ```bash
    mkdir -p /mnt/mmcblk0p7/docker/baota
    cd /mnt/mmcblk0p7/docker/baota
    vi docker-compose.yml   # 将上述内容粘贴进去
    ```

2.  **启动容器**
    ```bash
    docker-compose up -d
    ```

3.  **其他常用命令**
    - 停止容器：`docker-compose down`
    - 重启容器：`docker-compose restart`
    - 查看日志：`docker-compose logs -f`
    - 进入容器：`docker exec -it baota /bin/bash`

npm install hexo-cli -g

export PATH=$PATH:/www/server/nodejs/v20.20.2/bin














