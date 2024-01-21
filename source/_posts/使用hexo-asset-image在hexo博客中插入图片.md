---
title: 使用hexo-asset-image在hexo博客中插入图片
date: 2024-01-21 17:07:00
tags:
    - hexo
categories:
    - 教程
---

## 什么是hexo-asset-image？

- Give asset image in hexo a absolutely path automatically.
- [CodeFalling/hexo-asset-image](https://github.com/CodeFalling/hexo-asset-image)

## 安装hexo-asset-image

- `npm install hexo-asset-image --save`

## 修改hexo配置

- 修改hexo根目录下的`_config.yml`文件，添加如下配置：

  ```yml
  post_asset_folder: true
  ```

## 修改hexo-asset-image插件

- 修改`node_modules\hexo-asset-image\index.js`：
  ![](修改hexo-asset-image的index文件.jpg)

## 使用hexo-asset-image插入图片

- 创建新的文章，例如`hexo new "xx"`，会在`source/_posts`目录下生成一个md文件以及同名文件夹
- 示例:
    ```
    MacGesture2-Publish
    ├── apppicker.jpg
    ├── logo.jpg
    └── rules.jpg
    MacGesture2-Publish.md
    ```
- 在md文件中插入图片，例如：`![](appicker.jpg)`，图片名称就是图片路径