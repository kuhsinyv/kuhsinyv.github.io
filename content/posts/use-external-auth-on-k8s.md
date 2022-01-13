---
title: "在 k8s 上使用外部认证"
description: "使用 ingress-nginx 和 Auth Service 认证请求"
date: "2021-07-29"
lastmod: "2022-01-13"
author: "Hsinyv Ku"
cover: "/images/k8s-ingress-nginx.png"
toc: true
categories: 
  - "随笔"
tags: 
  - "Kubernetes"
  - "ingress-nginx"
  - "JWT"
  - "Go"
  - "Gin"
keywords:
  - "ingress"
  - "nginx"
  - "k8s"
  - "认证"
  - "jwt"
  - "go"
---

## 一、JSON Web Token

### 1. 什么是 JWT ？

- 详细内容请参考 [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)。
- **JWT** 是一个开放标准，它定义了一种用于**将各方之间的信息作为 JSON 对象进行安全地传输**的紧凑且自包含的方式。
- 由于信息被数字签名，因此可以验证和信任。
- 可以使用 HMAC、RSA 或 ECDSA 算法对 **JWT** 进行**签名**。

### 2. 什么时候该用它？

- 请求鉴权
- 信息传输（可以验证内容是否被篡改）

### 3. JWT 的结构

- 三个组成部分

  - Header

    ```json
    {
      "alg": "HS256",
      "typ": "JWT"
    }
    ```

  - Payload

    - Registered claims (非强制性的)，如 `iss`、`exp` 和 `sub` 等。
    - Public claims
    - Private claims

    ```json
    {
      "exp": 1627544720,
      "sub": "1234567890",
      "username": "6109119115",
      "role": "admin"
    }
    ```

  - Signature

    以 HMAC SHA256 算法为例：

    ```
    HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)
    ```

- 一个未经解析的 JWT 看起来像这样：`xxxxx.yyyyy.zzzzz`。

- 在使用 Bearer 模式的 Authorization 请求头中：`Authorization: Bearer xxxxx.yyyyy.zzzzz`。

### 4. 使用 JWT 的应用请求流程

![image-20210729161426928](/images/jwt-request.png) 

## 二、外部认证实践

### 1. 请求流量路径

![image-20210730164202783](/images/request-use-external-auth.png)

### 2. 在 Rancher 上实战

  GitHub 仓库：

  - https://github.com/kuhsinyv/external-auth-server

  - https://github.com/kuhsinyv/external-auth-client

#### (1) 编写 Auth Server

  a. 先看路由定义（使用 `Gin`），其中 `/api/v1/token` 用以获取 token，`/api/v1/auth` 用以验证 token。

  ```go
  package router

  import (
    "eas/internal/api/auth"
    "eas/internal/middlewares/jwt"
    "github.com/gin-gonic/gin"
  )

  var GinRouter *gin.Engine

  func init() {
    GinRouter = gin.Default()

    apiV1 := GinRouter.Group("/api/v1")
    {
      apiV1.GET("/token", auth.GetToken)
      apiV1.Any("/auth", jwt.JWT(), auth.Auth)
    }
  }
  ```

  b. `/api/v1/token` 接口的具体实现。

  ```go
  package auth

  import (
    "eas/tools/jwt"
    "github.com/gin-gonic/gin"
    "log"
    "time"
  )

  func GetToken(c *gin.Context) {
    if !(c.Query("username") == "6109119115" && c.Query("password") == "123") {
      c.JSON(403, gin.H{
        "status":  1,
        "message": "账号或密码错误",
        "data":    nil,
      })

      return
    }

    claims := map[string]interface{}{
      "exp":      time.Now().Add(3 * time.Hour).Unix(),
      "username": "6109119115",
    }

    tokenString, err := jwt.GenerateToken(claims)
    if err != nil {
      c.JSON(500, gin.H{
        "status":  2,
        "message": "生成 token 失败",
        "data":    nil,
      })

      log.Println("api/auth: failed to generate token string: ", err)

      return
    }

    c.JSON(200, gin.H{
      "status":  0,
      "message": "获取 token 成功",
      "data": gin.H{
        "token": tokenString,
      },
    })
  }
  ```

  c. 获取、解析 token 的中间件。

  ```go
  package jwt

  import (
    "eas/tools/jwt"
    "github.com/gin-gonic/gin"
    "net/url"
    "strings"
  )

  // getTokenString 从 Request Header 中的 Authorization 获取 JWT，若没有，则从 Query Params 中获取。
  func getTokenString(c *gin.Context) string {
    tokenString := c.Request.Header.Get("Authorization")
    if tokenString == "" {
      queryParamsToken := c.Query("token")

      var err error

      tokenString, err = url.QueryUnescape(queryParamsToken)
      if err != nil {
        return ""
      }
    }

    return tokenString
  }

  // JWT 认证中间件
  func JWT() gin.HandlerFunc {
    return func(c *gin.Context) {
      tokenString := getTokenString(c)
      if tokenString == "" {
        c.AbortWithStatusJSON(401, gin.H{
          "status":  1,
          "message": "请附带 jwt 在 Request Headers[Authorization] 或 Query Params[token] 内",
          "data":    nil,
        })

        return
      }

      tokenStringSlice := strings.Split(tokenString, " ")
      if len(tokenStringSlice) == 2 {
        tokenString = tokenStringSlice[len(tokenStringSlice)-1]
      }

      claims, err := jwt.ParseTokenWithMapClaims(tokenString)
      if err != nil {
        c.AbortWithStatusJSON(401, gin.H{
          "status":  2,
          "message": "非法的 token",
          "data":    nil,
        })

        return
      }

      username, ok := (*claims)["username"].(string)
      if !ok {
        c.AbortWithStatusJSON(401, gin.H{
          "status":  3,
          "message": "非法的 payload",
          "data":    nil,
        })

        return
      }

      c.Set("username", username)
      c.Next()
    }
  }
  ```

  d. 将解析出来的数据添加到约定的 Response Headers 中。

  ```go
  package auth

  import "github.com/gin-gonic/gin"

  func Auth(c *gin.Context) {
    if username := c.GetString("username"); username == "" {
      c.JSON(401, gin.H{
        "status":  1,
        "message": "用户未认证",
        "data":    nil,
      })
    } else {
      c.Writer.Header().Set("Username", username)
      c.JSON(200, gin.H{
        "status":  0,
        "message": "身份认证成功",
        "data":    nil,
      })
    }
  }
  ```

#### (2) 编写 Auth Client

  a. 先看路由定义（使用 `Gin`），`/api/v1/greeting` 将根据外部认证结果来返回。

  ```go
  package router

  import (
    "eac/internal/api/greeter"
    "github.com/gin-gonic/gin"
  )

  var GinRouter *gin.Engine

  func init() {
    GinRouter = gin.Default()

    apiV1 := GinRouter.Group("/api/v1")
    {
      apiV1.GET("/greeting", greeter.Greeting)
    }
  }
  ```

  b. `/api/v1/greeting` 具体实现。

  ```go
  package greeter

  import (
    "github.com/gin-gonic/gin"
  )

  func Greeting(c *gin.Context) {
    if username := c.GetHeader("Username"); username == "" {
      c.JSON(400, gin.H{
        "status":  1,
        "message": "获取 Request Headers Username 失败",
        "data":    nil,
      })
    } else {
      c.JSON(200, gin.H{
        "status":  0,
        "message": "Welcome, " + username,
        "data":    nil,
      })
    }
  }  
  ```

#### (3) 部署 Rancher 工作负载

  a. Auth Server

  ![Auth Server](/images/eas-workload.png)

  b. Auth Client

  ![Auth Client](/images/eac-workload.png)

#### (4) 配置 Ingress (Rancher 负载均衡)

  a. Auth Server

  ![Auth Server](/images/eas-ingress.png)

  b. Auth Client

  🌟 在 Auth Client 的 Ingress 配置中添加如下注释。

  ```yml
  nginx.ingress.kubernetes.io/auth-response-headers: Username
  nginx.ingress.kubernetes.io/auth-url: https://eas.example.com/api/v1/auth
  ```

  ![Auth Clinet](/images/eac-ingress.png)

#### (5) 测试

  a. 获取 token

  ```shell
  curl --location --request GET \
  'https://eas.example.com/api/v1/token?username=6109119115&password=123'
  ```

  ```json
  {
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2Mjc3NDgxOTQsInVzZXJuYW1lIjoiNjEwOTExOTExNSJ9.zTynNcdUjWnbGXsCs1lZZsVhMpwiUaz6NBYsW9jK41A"
    },
    "message": "获取 token 成功",
    "status": 0
  }
  ```

  b. 验证 Auth Server 作用

  附带 JWT

  ```shell
  curl --location --request GET 'https://eac.example.com/api/v1/greeting' \
  --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2Mjc3NDgxOTQsInVzZXJuYW1lIjoiNjEwOTExOTExNSJ9.zTynNcdUjWnbGXsCs1lZZsVhMpwiUaz6NBYsW9jK41A'
  ```

  ```json
  {
    "data": null,
    "message": "Welcome, 6109119115",
    "status": 0
  }
  ```

  未附带 JWT

  ```shell
  curl --location --request GET 'https://eac.example.com/api/v1/greeting'
  ```

  ```html
  <html>
  
  <head>
    <title>500 Internal Server Error</title>
  </head>

  <body>
    <center>
      <h1>500 Internal Server Error</h1>
    </center>
    <hr>
    <center>nginx</center>
  </body>
  
  </html>
  ```
