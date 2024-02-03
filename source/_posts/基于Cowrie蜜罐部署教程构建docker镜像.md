---
title: 基于Cowrie蜜罐部署教程构建docker镜像
date: 2024-02-04 01:32:34
categories: 
    - honeypot
tags: 
    - cowrie
    - Dockerfile
description: 参考Cowrie蜜罐部署教程，构建基于ubuntu的docker镜像
---
<!-- more -->

## 说明

在使用cowrie官网的镜像搭建蜜罐时，无法访问蜜罐容器里的日志文件，所以决定自己构建一个镜像，方便后续的操作。

## Dockerfile

```Dockerfile
# 基于ubuntu22.04构建
FROM ubuntu:jammy

# （root权限下）换源并安装必要的包，否则安装软件包会很慢，甚至超时报错
RUN test ! -f /etc/apt/source.list.save && cp  /etc/apt/sources.list /etc/apt/sources.list.save \
    && sed -i "s@security.ubuntu.com@mirrors.ustc.edu.cn@g" /etc/apt/sources.list \
    && sed -i "s@archive.ubuntu.com@mirrors.ustc.edu.cn@g" /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y wget python3.10-venv python-is-python3 git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv \ 
    && adduser --disabled-password --gecos "" cowrie

# 基于cowrie官网的安装教程，在ubuntu上安装cowrie
RUN su - cowrie \
    && cd /home/cowrie \
    && wget https://github.com/cowrie/cowrie/archive/refs/tags/v2.5.0.tar.gz \
    && tar -zxvf v2.5.0.tar.gz \
    && mv cowrie-2.5.0/ cowrie \
    && cd cowrie \
    && pwd \
    && python -m venv cowrie-env \
    && . cowrie-env/bin/activate \
    && python -m pip install --upgrade pip -i http://pypi.douban.com/simple --trusted-host pypi.douban.com \
    && python -m pip install --upgrade -r requirements.txt -i http://pypi.douban.com/simple --trusted-host pypi.douban.com \
    && chown -R cowrie:cowrie .

# 暴露端口
EXPOSE 2222 2223


# 设置容器的默认用户和工作目录
USER cowrie
WORKDIR /home/cowrie/cowrie

# 启动蜜罐命令
CMD ["bin/cowrie", "start","-n"]
```

## 构建镜像

```bash
docker build -t cowrie_from_ubuntu:20240202 .
```

## 运行方式

```bash
docker run -itd -p 2222:2222 -p 2223:2223 cowrie_from_ubuntu:20240202
```

## 上传镜像

```bash
# 登录到Docker Hub
docker login

# 为镜像添加标签
docker tag cowrie_from_ubuntu:20240202 mollyyuu/cowrie_from_ubuntu:20240202

# 将镜像推送到Docker Hub
docker push mollyyuu/cowrie_from_ubuntu:20240202
```

## 参考

- [Installing Cowrie in seven steps — cowrie 2.5.0 documentation](https://cowrie.readthedocs.io/en/latest/INSTALL.html)
- [alpine、debian、ubuntu brew 常用的换源命令 - jingjingxyk - 博客园](https://www.cnblogs.com/jingjingxyk/p/16825510.html)
