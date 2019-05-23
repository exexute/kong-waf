## kong-waf
通过正则规则限制请求, 同时支持IP黑名单拦截后端请求. IP黑名单可以是单个IP、IP段或CIDR.

## 部署
1. 进入kong源码目录, 一般为`/usr/local/share/lua/5.1/kong/`
2. 修改插件配置文件`constants.lua`, 增加插件`kong-waf`.
3. 进入plugin目录, 下载插件`cd plugins; git clone https://github.com/exexute/kong-waf.git`
4. 重启服务即可.

## 配置

### 术语
- `plugin`:
- `Service`:
- `Route`:
- `Consumer`:
- `Credential`:
- `upstream service`:


### 参数
下面是kong-waf插件需要用到的插件:

| 参数名 | 默认值 | 参数解释 |
| :------| ------: | :------: |
| `name` |  | 要使用的插件名, `kong-waf` |
| `service_id` |  | 调用插件的服务id |
| `route_id` |  | 调用插件的路由id |
| `enabled` | true | 插件是否启用, 默认为启用 |
| `consumer_id` |  | 调用插件的消费者id |
| `config.whitelist` |  | ip白名单, 只允许该部分IP访问后端服务 |
| `config.blacklist` |  | ip黑名单, 该部分IP不允许访问后端服务 |
| `config.openwaf` | on | 是否打开waf功能, `on`-启用waf, `off`-不启用 (打开waf之后会利用下面的waf检测规则对请求做检测, 占用服务器资源情况需自行压测) |
| `config.logdir` | /tmp/ | waf插件记录日志的目录, 必须指定且nobody用户可写 |
| `config.urldeny` | off | 是否拦截攻击, `on`：拦截, `off`：不拦截 |
| `config.urlmatch` | off | 是否检查url, `on`：检查, `off`：不检查 |
| `config.argsmatch` | on | 是否检查url参数, `on`：检查, `off`：不检查 |
| `config.postmatch` | on | 是否检查post参数, `on`：检查, `off`：不检查 |
| `config.uamatch` | on | 是否检查User-Agent, `on`：检查, `off`：不检查 |
| `config.cookiematch` | on | 是否检查cookie, `on`：检查, `off`：不检查 |

### 在某一个service上启用服务
在某一个service上服务上启用插件
```bash
$ curl -X POST http://kong:8001/services/{service}/plugins \
    --data "name=kong-waf" \
    --data "config.blacklist=10.129.7.236,10.129.7.235" \
    --data "config.openwaf=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.urlmatch=off" \
    --data "config.argsmatch=on" \
    --data "config.postmatch=on" \
    --data "config.uamatch=on" \
    --data "config.cookiematch=on"
```
- `service`: 服务的名字或id值


### 在某一个route上启用服务
在某一个route上启用插件
```bash
$ curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=kong-waf" \
    --data "config.blacklist=10.129.7.236,10.129.7.235" \
    --data "config.openwaf=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.urlmatch=off" \
    --data "config.argsmatch=on" \
    --data "config.postmatch=on" \
    --data "config.uamatch=on" \
    --data "config.cookiematch=on"
```
- `route_id`: 服务的名字或id值


### 在某一个Consumer上启用服务
在consumer上启用插件
```bash
$ curl -X POST http://kong:8001/plugins \
    --data "name=kong-waf" \
    --data "consumer_id={consumer_id}" \
    --data "config.blacklist=10.129.7.236,10.129.7.235" \
    --data "config.openwaf=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.urlmatch=off" \
    --data "config.argsmatch=on" \
    --data "config.postmatch=on" \
    --data "config.uamatch=on" \
    --data "config.cookiematch=on"
```
- `consumer_id`: 服务的名字或id值

### 全局插件
全局插件与服务、路由、消费者或API无关, 会对所有请求起作用.
```bash
$ curl -X POST http://kong:8001/plugins \
    --data "name=kong-waf" \
    --data "config.blacklist=10.129.7.236,10.129.7.235" \
    --data "config.openwaf=on" \
    --data "config.logdir=/var/log/kong/waf/" \
    --data "config.urldeny=on" \
    --data "config.urlmatch=off" \
    --data "config.argsmatch=on" \
    --data "config.postmatch=on" \
    --data "config.uamatch=on" \
    --data "config.cookiematch=on"
```

### 仅启用屏蔽IP功能
```bash
$ curl -X POST http://kong:8001/plugins \
    --data "name=kong-waf" \
    --data "config.blacklist=10.129.7.236,10.129.7.235" \
    --data "config.openwaf=off"
```

### 更新插件
更改插件的某一个配置只需要指定插件名(或插件id)和对应的配置即可(修改黑名单)
```bash
$ curl -X PATCH http://kong:8001/routes/{route_id}/plugins \
    --data "name=kong-waf" \
    --data "config.blacklist=10.129.7.2"
```

### 删除某条路由上的插件
```bash
$ curl -X DELETE --url http://kong:9001/plugins/{plugin_id}/
```