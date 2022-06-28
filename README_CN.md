# 具有故障注入API的服务代理

这是客户端服务代理的参考实现。它旨在与系统弹性测试框架Gremlin一起使用。
每个进行出站API调用的微服务实例都需要有一个关联的gremlin代理。
通常，它与调用进程一起在同一个VM或容器中运行，并通过环回接口与调用方通信。

远程服务及其实例必须在配置文件中进行静态配置。
服务代理充当HTTP/HTTPS请求路由器，将到达localhost:port的请求路由到remotehost:port。
它内置了对以循环方式跨远程服务实例的负载平衡请求的支持。
不支持粘性会话或客户端TLS（什么意思？）。
请注意，虽然代理可以连接到HTTPS端点，但调用方必须仅通过HTTP连接到本地主机上的代理。
请参见配置示例。
json提供了一个示例，说明如何支持HTTPS上游端点，同时通过http://localhost:port.

## 故障注入

带有预定义HTTP头的请求会受到各种形式的故障注入。
请求可以中止（调用方返回HTTP 404、HTTP 503等）、延迟或重写。
可以使用REST API远程控制代理。可以通过此API安装各种故障注入操作的规则。
[小精灵恢复能力测试框架](https://github.com/YuSitong1999/gremlinsdk-python)提供一个基于Python的控制平面库，
用于编写高级配方，该配方将自动分解为由gremlin代理执行的低级故障注入命令。

## 配置（示例：[example-config.json](./example-config.json)）

### services

配置文件的 __*services*__ 部分描述了需要代理的远程服务列表。
列表中的每个元素都是一个JSON字典对象，描述单个服务。

每个服务下的 __*proxy*__ 块指定接收远程服务请求的本地端口 __*port*__ 、
要绑定到的IP地址 __*bindhost*__
（默认为localhost）和代理协议 __*protocol*__ 。有效值为“http”或“tcp”。
虽然代理可以使用HTTP/HTTPS和通用TCP端点，
但对TCP端点的故障注入支持仅限于在TCP会话开始时中止/延迟连接。

__*loadbalancer*__ 部分配置提供远程服务的主机集 __*hosts*__
以及负载平衡方法 __*mode*__ （当前支持循环和随机负载平衡模式）。
当代理协议设置为“http”时，可以指定具有或不具有方案前缀（即http/https）的主机。
如果没有方案前缀，则会将“http”添加到主机条目中。
例如，如果主机条目的格式为192.168.0.1:9080，则请求URL的格式为http://192.168.0.1:9080.
如果要将请求代理到HTTPS端点， __*loadbalancer*__ 部分中的主机条目必须以“HTTPS://”
（例如：https://myacc.cloudant.com).

### router

__*router*__ 块配置gremlin代理的REST接口。

__*name*__ 参数表示使用此服务代理的微服务的名称。

__*port*__ 端口9876是服务代理公开REST API的默认端口。

__*trackingheader*__ 参数指定触发故障注入操作的HTTP头。
不包含此标头的请求保持不变。

### 日志

字段 __*loglevel*__ 、 __*logjson*__ 和 __*logstash*__ 配置服务代理的日志方面。

__*loglevel*__ 本地日志级别

__*logjson*__ 本地日志是否输出为json格式

__*logstash*__ 汇总日志的logstash服务器地址和端口

### 总结

服务代理中的日志可以直接发送到logstash服务器，然后通过管道传输到Elasticsearch。
Gremlin框架的断言引擎可以直接与Elasticsearch交互，对gremlinproxy生成的日志执行断言。

示例配置中提供了一个example-config.json。它为客户端微服务配置代理（如路由器块中的name参数所示）。
代理在0.0.0.0:7777侦听对服务器微服务的请求，并将其转发到54.175.222.246:80或https://httpbin.org.
来自客户端微服务（包含HTTP头X-Gremlin-ID）的所有请求都将进行故障注入。

## 构建和运行代理

* 运行代理前，需要先运行logstash服务和elasticsearch，
  执行``docker-compose -f compose-logstash-elasticsearch.yml up -d``
* 设置Go环境和GOPATH环境变量
* 克隆存储库到``$GOPATH/go/src/github.com/gremlin``目录
* 构建``go get && go build``
* 运行``go get && go build``

### 代理 REST 接口
```GET /gremlin/v1```: hello world测试

```POST /gremlin/v1/rules/add```: 增加规则，规则为以下格式的JSON

```javascript
{
  source: <source service name>,
  dest: <destination service name>,
  messagetype: <request|response|publish|subscribe|stream>
  headerpattern: <regex to match against the value of the X-Gremlin-ID trackingheader present in HTTP headers>
  bodypattern: <regex to match against HTTP message body>
  delayprobability: <float, 0.0 to 1.0>
  delaydistribution: <uniform|exponential|normal> probability distribution function

  mangleprobability: <float, 0.0 to 1.0>
  mangledistribution: <uniform|exponential|normal> probability distribution function

  abortprobability: <float, 0.0 to 1.0>
  abortdistribution: <uniform|exponential|normal> probability distribution function

  delaytime: <string> latency to inject into requests <string, e.g., "10ms", "1s", "5m", "3h", "1s500ms">
  errorcode: <Number> HTTP error code or -1 to reset TCP connection
  searchstring: <string> string to replace when Mangle is enabled
  replacestring: <string> string to replace with for Mangle fault
}
```

```POST /gremlin/v1/rules/remove``` : 移除规则（格式同上）

```GET /gremlin/v1/rules/list```: 列出已设置规则

```DELETE /gremlin/v1/rules```: 清除所有规则

```GET /gremlin/v1/proxy/:service/instances```: 列出 ```:service```服务的实例

```PUT /gremlin/v1/proxy/:service/:instances```: 设置 ```:service```服务的实例， ```:instances``` 是逗号分隔列表

```DELETE /gremlin/v1/proxy/:service/instances```: 清除```:service```服务的所有实例

```PUT /gremlin/v1/test/:id```: 设置新测试ID ```:id```, 将在请求/回复日志中同时输出

```DELETE /gremlin/v1/test/:id```: 移除当前设置的测试ID ```:id```

