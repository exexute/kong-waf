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


### 参数
下面是kong-waf插件需要用到的插件
| 参数名 | 默认值 | 参数解释 |
| :------| ------: | :------: |
| `name` |  | 要使用的插件名, `kong-waf` |
| `service_id` |  | 调用插件的服务id |
| `route_id` |  | 调用插件的路由id |
| `enabled` | true | 插件是否启用, 默认为启用 |
| `consumer_id` |  | 调用插件的消费者id |
| `config.whitelist` |  | ip白名单, 该部分IP不需要经过waf检查 |
| `config.blacklist` |  | ip黑名单, 该部分IP不允许访问后端服务 |
| `config.rulepath` |  | waf规则所在目录, 必须指定 |
| `config.attacklog` |  | 是否记录攻击日志, `on`-记录, 不指定 - 不记录 |
| `config.logdir` |  | 日志的输出位置 |
| `config.urldeny` |  | 是否检查url, `on`-检查, 其他不检查 |
| `config.cookiematch` |  | 是否检查cookie值, `on` - 检查 |
| `config.postmatch` |  | 是否检查post请求, `on` - 检查 |
| `config.black_fileExt` |  | 禁止上传文件的后缀名列表, php,jsp,do |

