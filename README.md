## kong-waf
通过正则规则限制请求, 同时支持IP黑名单拦截后端请求. IP黑名单可以是单个IP、IP段或CIDR.

## 术语
- `plugin`: 
- `Service`:
- `Route`:
- `Consumer`:
- `Credential`:
- `upstream service`:

## 配置

### 在某一个service上启用服务
在服务上启用插件
```bash
$ curl -X POST http://kong:8001/services/{service}/plugins \
    --data "name=kong-waf" \
    --data "config.whitelist=10.129.7.236,10.129.7.235" \
    --data "config.rulepath=wafconf" \
    --data "config.attacklog=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.Redirect=on" \
    --data "config.cookiematch=on" \
    --data "config.postmatch=on" \
    --data "config.black_fileExt=php,jsp,asp"
```
- `service`: 服务的名字或id值


### 在某一个route上启用服务
通过下面的请求来实现在服务上启用插件
```bash
$ curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=kong-waf" \
    --data "config.whitelist=10.129.7.236,10.129.7.235" \
    --data "config.rulepath=wafconf" \
    --data "config.attacklog=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.Redirect=on" \
    --data "config.cookiematch=on" \
    --data "config.postmatch=on" \
    --data "config.black_fileExt=php,jsp,asp"
```
- `route_id`: 服务的名字或id值


### 在某一个Consumer上启用服务
在consumer上启用插件
```bash
$ curl -X POST http://kong:8001/plugins \
    --data "name=kong-waf" \
    --data "consumer_id={consumer_id}" \
    --data "config.whitelist=10.129.7.236,10.129.7.235" \
    --data "config.rulepath=wafconf" \
    --data "config.attacklog=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.Redirect=on" \
    --data "config.cookiematch=on" \
    --data "config.postmatch=on" \
    --data "config.black_fileExt=php,jsp,asp"
```
- `consumer_id`: 服务的名字或id值

### 全局插件
全局插件与服务、路由、消费者或API无关, 会对所有请求起作用.
```bash
$ curl -X POST http://kong:8001/plugins \
    --data "name=kong-waf" \
    --data "config.whitelist=10.129.7.236,10.129.7.235" \
    --data "config.rulepath=wafconf" \
    --data "config.attacklog=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.Redirect=on" \
    --data "config.cookiematch=on" \
    --data "config.postmatch=on" \
    --data "config.black_fileExt=php,jsp,asp"
```
