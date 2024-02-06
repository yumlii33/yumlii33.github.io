---
title: WriteUp-CTFHub-you raise me up
date: 2024-02-06 18:14:46
categories: 
    - CTF-WriteUp
tags: 
    - Crypto
description: 2020-网鼎杯-青龙组-Crypto-you raise me up
---
<!--more-->

## 题目考点

- 离散对数

## 解题思路

- 下载题目附件：
    ```python
    #!/usr/bin/env python
    # -*- coding: utf-8 -*-
    from Crypto.Util.number import *
    import random

    n = 2 ** 512    # 2^512
    m = random.randint(2, n-1) | 1  # 随机生成一个奇数（使用random.randint()函数生成一个大于等于2且小于n-1的随机整数，并通过按位或操作符"| 1"将其转换为奇数）
    c = pow(m, bytes_to_long(flag), n)  # c = m^flag mod n
    print 'm = ' + str(m)
    print 'c = ' + str(c)

    # m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
    # c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
    ```
- 对于`c = m^flag mod n`，已知c，m，n，求flag，这是典型的离散对数问题。
- 使用sympy库进行求解：
    ```python
    from sympy.ntheory import discrete_log  # conda update sympy
    from Crypto.Util.number import long_to_bytes    # pip install pycryptodome
    m = 391190709124527428959489662565274039318305952172936859403855079581402770986890308469084735451207885386318986881041563704825943945069343345307381099559075
    c = 6665851394203214245856789450723658632520816791621796775909766895233000234023642878786025644953797995373211308485605397024123180085924117610802485972584499
    n = 2 ** 512

    flag=discrete_log(n, c, m)  # 求解离散对数

    print long_to_bytes(flag)
    ```



## FLAG

```plain
flag{5f95ca93-1594-762d-ed0b-a9139692cb4a}
```

## 参考链接

- [2020网鼎杯——you_raise_me_up wp_安全_lnjoy-CSDN学习社区](https://geek.csdn.net/65bf0517b8e5f01e1e45ee3d.html?dp_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MTE1MDY0MSwiZXhwIjoxNzA3ODE4ODQwLCJpYXQiOjE3MDcyMTQwNDAsInVzZXJuYW1lIjoid2VpeGluXzQzNjk0MjI3In0.aWF6bJIklpo13OKZ1nCptqIYY6aOcOfjf-FBMc02mr8)
- [使用sagemath的解法](https://blog.csdn.net/qq_40648358/article/details/106045483)
- [Installation - SymPy 1.12 documentation](https://docs.sympy.org/latest/install.html#anaconda)
- [from Crypto.Util.number import * ImportError: No module named Crypto.Util.number-CSDN博客](https://blog.csdn.net/wukai0909/article/details/109772278)