---
title: WriteUp-CTFHub-回转十三位
date: 2024-01-25 21:51:52
categories: 
    - CTF-WriteUp
tags: 
    - Crypto
description: 2016 | 第五届山东省网络安全竞赛 | Crypto | 回转十三位
---
<!--more-->


## 题目考点

- `rot13`
  - 只对字母进行编码，用当前字母往前数的第13个字母替换当前字母，例如当前为A，编码后变成N，当前为B，编码后变成O，以此类推顺序循环。
- `base64`
  - Base64编码要求把3个8位字节（3*8=24）转化为4个6位的字节（4*6=24），之后在6位的前面补两个0，形成8位一个字节的形式。如果剩下的字符不足3个字节，则用0填充，输出字符使用'='，因此编码后输出的文本末尾可能会出现1或2个'='。


## 解题思路

- 下载题目附件，解压后得到一个txt文件，内容为：
  ```plain
    EzkuM0yGAzA2n3WbEaOJEHuOFmuOpN==
    ```
- 直接尝试base64解码，解出来乱码，思路不正确
- 题目提示为回转十三位，猜测为rot13加密，尝试先用rot13解码，解出来的内容为：
  ```plain
  RmxhZ0lTNmN2a3JoRnBWRUhBSzhBcA==
  ```
- 然后再用base64解码，解出来的内容为：
  ```plain
  FlagIS6cvkrhFpVEHAK8Ap
  ```


## FLAG

```plain
flag{6cvkrhFpVEHAK8Ap}
```