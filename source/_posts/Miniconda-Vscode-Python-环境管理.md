---
title: Miniconda+Vscode Python 环境管理
date: 2024-01-07 15:18:24
tags: 
    - Miniconda
    - Vscode 
    - Python环境管理
categories:
---

## 0 Miniconda 安装
* 下载安装，可以安装Miniconda，也可以安装Anaconda，Miniconda轻量级。
* 安装选项：一路next，有一页path处，全选。
## 1 Vscode配置
* 安装Python扩展
* 设置扩展，将conda path添加到设置中
    ![Conda Path](condapath.png)
* 新建终端后，默认Python环境为miniconda的base虚拟环境

<!-- more -->

## 2 VScode中使用conda管理python环境
* 在vscode中使用conda Prompt：[终端]->[新建终端]->[＋]->[command prompt]
	* conda info --envs 查看当前虚拟环境列表
	* conda activate -n envsname 启动虚拟环境（默认为base）
	* 可以看到启动后前面有（envsname）
## 3 常用conda命令
* 查看所有环境	conda info --envs
* 创建新环境	conda create -n env_name python=x.x
* 启动虚拟环境	conda activate env_name
* 退出虚拟环境	conda deactivate
* 删除虚拟环境	conda remove -n env_name  --all



> 本文内容首发于CSDN：[Miniconda+Vscode Python 环境管理](https://blog.csdn.net/weixin_43694227/article/details/124099269)