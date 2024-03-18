---
title: Gitlab Group Runner配置及相关问题记录
date: 2024-02-19 19:35:38
tags:
    - 教程
    - ci/cd
description: Gitlab Group Runner配置使用，以及相关问题记录
---
<!-- more -->

## CI/CD概述

- CI/CD是指持续集成（Continuous Integration）和持续交付（Continuous Delivery）。
- CI/CD是一种持续的软件开发方法，可以在其中持续构建、测试、部署和监视迭代代码更改。
- 这种迭代过程有助于减少基于错误或失败的就版本开发新代码的机会。GitLab CI/CD可以在开发周期的早期捕获bug，并帮助确保部署到生产环境的所有代码都符合自定的代码标准。


## 常用术语

- `.gitlab-ci.yml`：
  - CI/CD配置文件，可以在项目的根目录中创建，用于定义CI/CD流程
  - 此文件遵循`YAML`格式，存在自己的语法规则。
- `Runners`：
  - Runner是执行CI/CD作业的实体。
  - Runner可以是一个虚拟机、容器或者物理机器。Runner可以在GitLab实例中的所有组和项目中使用，也可以在特定组或项目中使用。
- `Pipelines`：Pipelines由jobs和stages组成:
  - `Jobs`：定义了CI/CD流程中的一个任务。每个job都是一个独立的实体，可以在不同的runner上运行。
  - `Stages`：定义了CI/CD流程中的一个阶段。每个stage包含一个或多个job。典型的stages包括`build`、`test`、`deploy`等。
- `CI/CD variables`：可以用于pipeline配置和job配置的环境变量。可以在`.gitlab-ci.yml`文件中定义，也可以在GitLab中的`Settings->CI/CD->Variables`中定义。
- `CI/CD components`


## Runner的类型

- GitLab Runner有以下类型：
  - Instance Runners：适用于GitLab实例中的所有组和项目。
  - Group Runners：可用于组中的所有项目和子组。
  - Project Runners：与具体项目有关。通常`project runner`一次只由一个项目使用。


### Instance Runner

- 当有多个具有类似要求的作业时，可以使用Instance Runner。与其让多个runner为多个项目空闲，不如让几个runner处理多个项目。
- 如果使用的是自管理的GitLab实例，管理员（Administrator）可以：
  - 安装GitLab Runner并注册一个实例运行器。
  - 为每个组配置实例运行程序计算分钟数的最大值。
- 如果使用的是GitLab.com：
  - 可以从GitLab维护的实例运行器列表中进行选择。
  - 实例运行者消耗帐户中包含的计算分钟数。

- 必要条件：
  - 必须是Administrator角色。


### Group Runner

- 当您希望组中的所有项目都可以访问一组runner时，请使用group runner。
- 组运行者使用先进先出队列处理作业。
- 必要条件：
  - 必须是目标组的Owner角色。


### Project Runner

- 当希望将runner用于特定项目时，使用project runner。
- 特定项目一般具有以下特征：
  - 具有特定要求的作业，如需要凭据的部署作业。
  - 具有大量CI活动的项目，可以从与其他跑步者的分离中受益。
- project runner使用先进先出队列处理作业。

- 必要条件：
  - 必须是目标组的Maintainer角色。


## ⭐Group Runner 配置及使用

### 创建group runner


- 首先确认具备目标组的`Owner`权限。
- 在目标组的侧边栏选择`Builds->Runners`。
- 可以看到`Runners`中有`Group Runners`和`Project Runners`，选择`New group runner`。
- 选择安装`GitLab Runner`的操作系统。
- 在`Tags`中输入作业标签，可以指定某些作业只能在带有特定标签的`runner`上运行。
- 勾选`Run untagged jobs`，允许运行没有标签的作业。
- （可选）在`Runner description`中，可以添加一个在`GitLab`中显示的`runner`描述。
- （可选）在`Configuration`部分可以选择其他配置，例如最大作业超时时间。
- 选择`Create runner`
- 注册`runner`(在目标机器上执行)：
  - 首先需要在目标机器上安装`GitLab Runner`，执行`apt install gitlab-runner`。【BUG1】
  - 执行`gitlab-runner register`命令，按照提示输入相关信息，包括`GitLab instance URL`、`Runner token`等。【BUG2】
  - 在选择`executor`时，可以选择`shell`、`docker`、`docker+machine`等，如果不确定要选择哪个执行器，请参阅[Selecting the executor](https://docs.gitlab.com/runner/executors/#selecting-the-executor)。
    - 当选择`shell`时，`runner`会在目标机器上直接执行作业。
    - 当选择`docker`时，`runner`会在`docker`容器中执行作业，因此需要确保目标机器上已经安装了`docker`。【BUG3&BUG4】
- 注册成功后，可以在gitlab平台看到新注册的`Group Runner`。

### 查看/暂停/恢复/删除/清理group runner

- 查看:
  - 必要条件：`Maintainer of the group` / `Owner of the group`
  - 在`Group sidebar->Builds->Runners`中可以看到所有的group runner，在该组的每一个项目的`Settings->CI/CD->Runners`中也可以看到所有的group runner。
- 暂停：
  - 必要条件：`Administrator` / `Owner of the group`
  - 在`Group sidebar->Builds->Runners->Group Runners`中选择要暂停的runner，然后点击`Pause`。
- 恢复：
  - 必要条件：`Administrator` / `Owner of the group`
  - 在`Group sidebar->Builds->Runners->Group Runners`中选择要恢复的runner，然后点击`Resume`。
- 删除：
  - 必要条件：`Administrator` / `Owner of the group`
  - 在`Group sidebar->Builds->Runners->Group Runners`中选择要删除的runner，然后点击`Delete`。
- 清理：
  -  必要条件：`Owner of the group`
  - （？没看到这个）在`Group sidebar->Settings->CI/CD->Runners`，然后点击`Enable stale runner cleanup`。

## Project Runner 配置及使用

- project runner的配置与group runner类似，需要在特定项目的`Settings->CI/CD->Runners`中选择`New project runner`。
- project runner虽然与特定项目相关，但是可以通过手动的方式将其开放非给同组的其他项目。
- 并且，project runner使用docker执行作业没有问题。

## 简单的.gitlab-ci.yml示例

- 示例：
  ```yaml
  stages: # 定义流程阶段, 顺序执行，通常包括build、test、deploy等
    - build # 构建
    - test # 测试
    - deploy # 部署
  
  build-job:   # 定义job
    stage: build  # 指定job所属的stage
    tag: ubuntu-shell # 指定runner的tag
    script: # 定义job的执行脚本
      - echo "Building the app"

  test-job-1: 
    stage: test
    script:
      - echo "Testing the app"

  test-job-2:
    stage: test
    script:
      - echo "Testing the app"

  deploy:
    stage: deploy
    script:
      - echo "Deploying the app"
  ```

## ⭐问题记录

1. BUG1：无法安装`GitLab Runner`
   - 问题描述：
        ```shell
        root@dd-group-runner:~# apt install gitlab-runner
        Reading package lists... Done
        Building dependency tree... Done
        Reading state information... Done
        E: Unable to locate package gitlab-runner
        ```
   - 解决方案：[参考](https://zhuanlan.zhihu.com/p/590406526)，先去官网下载安装密钥，然后安装。
        ```shell
        curl -L "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | bash
        ```
2. BUG2：注册时认证问题
   - 问题描述：x.509证书问题
        ```shell
        root@shell-2:~# gitlab-runner register  --url https://gitee.xxxx.lab  --token glrt-xxxxxGndzm3iDm
        Runtime platform                                    arch=amd64 os=linux pid=31185 revision=782c6ecb version=16.9.1
        Running in system-mode.

        Enter the GitLab instance URL (for example, https://gitlab.com/):
        [https://gitee.xxxxx.lab]: https://gitee.xxxxx.lab
        ERROR: Verifying runner... failed                   runner=zoYseyDEo status=couldn't execute POST against https://gitee.xxxxx.lab/api/v4/runners/verify: Post "https://gitee.xxxxx.lab/api/v4/runners/verify": tls: failed to verify certificate: x509: certificate signed by unknown authority
        PANIC: Failed to verify the runner.
        ```
   - 解决方案：手动添加gitlab证书并更新`ca-certificates`。
     - 首先，获取服务器的证书。可以使用`openssl s_client`命令连接到服务器并输出证书信息:
        ```shell
        openssl s_client -showcerts -connect xxxx:443 </dev/null
        ```
     - 复制输出的证书信息，包括第一个`-----BEGIN CERTIFICATE-----`和最后一个`-----END CERTIFICATE-----`之间的内容。
     - 将证书内容保存到一个文件，例如`server.crt`。
     - 将证书文件复制到`/etc/ssl/certs/`目录下：
        ```shell
        cp server.crt /etc/ssl/certs/
        ```
     - 更新`ca-certificates`:
        ```shell
        update-ca-certificates
        ```
      - 执行完以上步骤后，服务器的证书就会被添加到系统的信任列表中，gitlab-runner应该能够验证服务器证书并连接到指定的git仓库了。
    
3. BUG3：docker 容器内无法获取gitlab 仓库代码
   - 问题描述：
      ```shell
      fatal: unable to access 'https://xxxx/dd/test-cicd.git/': Could not resolve host: xxxx
      ```
   - 解决方案：
     - 方法1：
       - 设置 network_mode 为 host，[参考](https://stackoverflow.com/questions/50325932/gitlab-runner-docker-could-not-resolve-host)
          ```shell
          vi  /etc/gitlab-runner/config.toml
          #    [runners.docker]
          #        network_mode = "host"
          ```
      - 重启`gitlab runner`，执行`gitlab-runner restart`
    - 方法2：
      - 在`/etc/gitlab-runner/config.toml`中`[runners.docker]`下添加`extra_hosts`字段
        ```
        extra_hosts = ["host:ip"]
        ```
      - 重启`gitlab runner`，执行`gitlab-runner restart`

4. BUG4：docker容器无法获取git仓库代码
  - 问题描述：
    ```shell
    Getting source from Git repository
    00:01
    Fetching changes with git depth set to 20...
    Reinitialized existing Git repository in /builds/xxxxx/.git/
    fatal: unable to access 'https://xxxx.git/': HTTP/2 stream 1 was not closed cleanly: PROTOCOL_ERROR (err 1)
    Cleaning up project directory and file based variables
    ```
  - 解决方案：这个报错是由于错误的域名解析导致的，在【BUG3】的解决方案中，之前错误的配置了`192.168.55.1 gitee.xxxx.lab`，通过执行`ping gitee.xxxx.lab`发现实际的ip是`192.168.55.142`。因此正确解决【BUG3】后，这个问题就不存在了。

## 参考资料

- [Manage runners | GitLab](https://docs.gitlab.com/ee/ci/runners/runners_scope.html#group-runners)
- [Executors | GitLab](https://docs.gitlab.com/runner/executors/#selecting-the-executor)