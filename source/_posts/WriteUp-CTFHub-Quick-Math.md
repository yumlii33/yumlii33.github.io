---
title: WriteUp-CTFHub-Quick Math
date: 2024-02-04 03:16:33
categories: 
    - CTF-WriteUp
tags: 
    - Crypto
description: 2020-CSICTF-Crypto-Quick Math
---
<!--more-->

## 题目内容

Ben has encrypted a message with the same value of 'e' for 3 public moduli - n1 = 86812553978993 n2 = 81744303091421 n3 = 83695120256591 and got the cipher texts - c1 = 8875674977048 c2 = 70744354709710 c3 = 29146719498409. Find the original message. (Wrap it with csictf{})


## 题目考点

- RSA
- 中国剩余定理

## 解题思路

- 由题目和RSA原理可知：
    ```plain
    c1=m^3 mod n1
    c2=m^3 mod n2
    c3=m^3 mod n3
    👇
    m^3 = c1 mod n1
    m^3 = c2 mod n2
    m^3 = c3 mod n3
    ```
- 根据中国剩余定理，可以求出m^3，然后开立方根即可得到m
- python代码：
    ```python
    # 导入所需的模块和函数
    from sympy.ntheory.modular import crt
    from gmpy2 import iroot

    # RSA加密的指数e
    e = 3
    # 三个不同的模数N和对应的密文C
    N = [86812553978993, 81744303091421, 83695120256591]
    C = [8875674977048, 70744354709710, 29146719498409]

    # 使用中国剩余定理解决模数不同的同余方程组
    resultant, mod = crt(N,C)

    # 计算resultant的e次根，即对resultant进行e次方根运算
    value, is_perfect = iroot(resultant,e)

    # 将计算得到的明文值转换成字节并打印出来
    print(bytes.fromhex(str(value)).decode())
    ```



## FLAG

```plain
csictf{h45t4d}
```


## 参考

- [CTFtime.org / csictf 2020 / Quick Math / Writeup](https://ctftime.org/writeup/22431)
- 中国剩余定理