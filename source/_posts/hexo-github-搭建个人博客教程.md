---
title: hexo + github 搭建个人博客教程
date: 2024-01-20 21:10:25
tags:
    - hexo
    - github
categories:
    - 教程
description: hexo + github 搭建个人博客教程
---
<!-- more -->

## 什么是hexo？

hexo是一个基于nodejs的静态博客框架，可以快速搭建个人博客，支持markdown语法，支持自定义主题，支持插件扩展，支持一键部署到github上，支持离线写作，支持多终端同步等等。

## 准备工作

- 安装git，下载地址[https://git-scm.com/downloads](https://git-scm.com/downloads)
- 安装nodejs，下载地址[https://nodejs.cn/download/](https://nodejs.cn/download/)
- 验证nodejs是否安装成功，打开cmd，输入`node -v`，显示版本号则安装成功
- npm换源，打开cmd，输入`npm config set registry https://registry.npm.taobao.org`，换源成功后，输入`npm config get registry`，显示`https://registry.npm.taobao.org/`则换源成功
- 安装hexo，打开cmd，输入`npm install -g hexo-cli`，安装成功后，输入`hexo -v`，显示版本号则安装成功


## 初始化博客

- 新建一个文件夹，例如`Bloggg`
- 打开git命令行，输入`hexo init`，初始化博客
- 执行`npm install`，安装项目依赖
- 执行`hexo s`，启动本地服务，打开浏览器，输入`http://localhost:4000`，显示hexo默认页面，则初始化成功


## 新建文章

- 在博客根目录下执行`hexo new "文章标题"`，会在`source/_posts`目录下生成一个md文件，例如`hello-world.md`
- 编辑博客后，执行`hexo s`，启动本地服务，打开浏览器，输入`http://localhost:4000`，显示博客，则新建文章成功

## 部署到github pages

- 在github上新建一个仓库，必须以`username.github.io`命名，例如本站的仓库名为`yumlii33.github.io`
- 修改博客根目录下的`_config.yml`文件，修改`deploy`配置，例如本站的配置如下：
    ```yml
    deploy:
    type: git
    repo: git@github.com:yumlii33/yumlii33.github.io.git
    branch: gh-pages
    ```
- 安装上传插件，执行`npm install hexo-deployer-git --save`
- 执行`hexo clean`，清除缓存
- 执行`hexo g`，生成静态文件
- 执行`hexo d`，部署到github
- 访问`https://username.github.io`，显示博客，则部署成功

## 源码上传到github

- 在本地hexo根目录下执行`git init`，初始化git仓库
- 执行`git remote add origin git@github.com:username/username.github.io.git`，添加远程仓库
- 创建`.gitignore`文件，添加忽略文件，例如本站的配置如下：
    ```gitignore
    .DS_Store
    Thumbs.db
    db.json
    *.log
    node_modules/
    public/
    .deploy*/
    ```
- 执行`git add .`，添加所有文件到暂存区
- 执行`git commit -m "init"`，提交到本地仓库
- 执行`git push -u origin master`，上传到远程仓库主分支

## 新环境部署

- 在新环境下，执行`git clone`，克隆仓库到本地
- 执行`npm install`，安装项目依赖
- 执行`hexo s`，启动本地服务，打开浏览器，输入`http://localhost:4000`，显示博客，则部署成功

> 注意：因为没有上传`node_modules`文件夹，所以需要执行`npm install`安装项目依赖，如果需要对插件进行自定义修改，需要在新环境中重新配置

## 参考资料

- [【基础篇】hexo博客搭建教程 - huanhao - 博客园](https://www.cnblogs.com/huanhao/p/hexobase.html)
- [使用git分支保存hexo博客源码到github - 知乎](https://zhuanlan.zhihu.com/p/71544809)