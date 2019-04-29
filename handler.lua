local BasePlugin = require "kong.plugins.base_plugin"
local iputils = require "resty.iputils"

local FORBIDDEN = 403

-- cache of parsed CIDR values
local cache = {}


local request = nil -- 定义kong.request局部变量, 用局部变量可以提升30%的速度, 编译之后 局部变量汇编代码1行, 全局变量汇编代码4行
local ngx = ngx
local kong = kong
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri

local table = table
local pairs = pairs
local lower = string.lower
local match = string.match
local sfind = string.find
local ssub = string.sub
local slen = string.len
local s
local open = io.open

local headers = {}
-- 定义waf规则变量
local uarules = nil
local ckrules = nil
local urlrules = nil
local argsrules = nil
local postrules = nil
local rules_array = {}

local logpath = nil
local attacklog = true
local uri = nil


local KongWaf = BasePlugin:extend()


KongWaf.PRIORITY = 990
KongWaf.VERSION = "1.0.0"

local function cidr_cache(cidr_tab)
  local cidr_tab_len = #cidr_tab

  local parsed_cidrs = kong.table.new(cidr_tab_len, 0) -- table of parsed cidrs to return

  -- build a table of parsed cidr blocks based on configured
  -- cidrs, either from cache or via iputils parse
  -- TODO dont build a new table every time, just cache the final result
  -- best way to do this will require a migration (see PR details)
  for i = 1, cidr_tab_len do
    local cidr        = cidr_tab[i]
    local parsed_cidr = cache[cidr]

    if parsed_cidr then
      parsed_cidrs[i] = parsed_cidr

    else
      -- if we dont have this cidr block cached,
      -- parse it and cache the results
      local lower, upper = iputils.parse_cidr(cidr)

      cache[cidr] = { lower, upper }
      parsed_cidrs[i] = cache[cidr]
    end
  end

  return parsed_cidrs
end

-- 定义插件规则读取函数

local optionIsOn = function (options) return options == "on" and true or false end

local function read_waf_rule(var)
  local file = open('/usr/local/share/lua/5.1/kong/plugins/kong-waf/wafconf/'..var,"r")
  if file==nil then
    return
  end
  local i = 1
  local nFindLastIndex = nil
  for line in file:lines() do
    nFindLastIndex = sfind(line, "@@@", 1)
    if nFindLastIndex then
      rules_array[i] = {ssub(line, 1, nFindLastIndex - 1), ssub(line, nFindLastIndex + 3, slen(line))}
      i = i + 1
    end
  end
  file:close()
end

-- 定义插件配置set函数
local function waf_conf_set( list )
  -- body
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end
-- waf插件相关函数

local function waf_log_write( logfile, msg )
  local fd = io.open(logfile,"ab")
  if fd == nil then return end
  kong.log.err(msg)
  fd:write(msg)
  fd:flush()
  fd:close()
end

local function waf_log(method, url, data, ruletag)
	-- body
	if attacklog then
    local realIp = ngx.var.binary_remote_addr
    local ua = ngx.var.http_user_agent
    local servername = ngx.var.server_name
    local cookie = ngx.var.http_cookie
    local time = ngx.localtime()
    local line = nil

    if ua  then
      line = { realIp, " [", time, "] \"", method, " ", servername, url, "\" \"", data, "\"  \"", ua, "\" \"", ruletag, "\" \"", cookie, "\"\n"}
    else
      line = { realIp, " [", time, "] \"", method, " ", servername, url, "\" \"", data, "\"  \"", ruletag, "\"  \"", cookie, "\"\n"}
    end
    kong.log.err( table.concat(line, " ") )
    local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
    waf_log_write( filename, table.concat(line, " ") )
  end
end

-- 定义waf插件url检测函数
local function waf_url_check( urlmatch )
  if optionIsOn(urlmatch) then
    for i = 2, #rules_array do
      if rule ~="" and ngxmatch(uri,rules_array[1][2],"isjo") then
        waf_log('UA',uri,"-",rules_array[i][1])
        return true
      end
    end
  end
  return false
end

-- 定义waf插件user-agent检测函数
local function waf_ua_check( uamatch )
	-- body
  if optionIsOn(uamatch) then
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
      for i = 2, #rules_array do
        if rule ~="" and ngxmatch(ua,rules_array[i][2],"isjo") then
          waf_log('UA',uri,"-",rules_array[i][1])
          return true
        end
      end
    end
  end
  return false
end

-- 定义waf插件get参数检测函数
local function waf_args_check( argsmatch )
	-- body
  if optionIsOn(argsmatch) then
  	for i = 2, #rules_array do
      local args = request.get_query()
      for key, val in pairs(args) do
        if type(val)=='table' then
          local t={}
          for k,v in pairs(val) do
            if v == true then
              v=""
            end
            table.insert(t,v)
          end
          data=table.concat(t, " ")
        else
          data=val
        end
        if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(ngx.unescape_uri(data),rules_array[i][2],"isjo") then
          waf_log('GET',uri,"-",rules_array[i][1])
          return true
        end
      end
    end
  end
  return false
end

-- 定义waf插件cookie参数检测函数
local function waf_cookie_check( cookie_check )
	-- body
  if optionIsOn(cookie_check) then
    local ck = ngx.var.http_cookie
    if ck then
      for i = 2, #rules_array do
        if rule ~="" and ngxmatch(ck,rules_array[i][2],"isjo") then
          waf_log('Cookie',uri,"-",rules_array[i][1])
          return true
        end
      end
    end
  end
  return false
end

local function waf_body_check( data )
	-- body
	for i = 2, #rules_array do
		if rule ~= "" and data ~= "" and ngxmatch(ngx.unescape_uri(data),rules_array[i][2],"isjo") then
			waf_log( 'POST', uri, data, rules_array[i][1] )
			return true
    end
  end
  return false
end

-- 定义waf插件post请求检测函数
local function waf_post_check( check_post )
  -- body
  local post_status = nil
  if optionIsOn(check_post) then
    local content_length = tonumber(headers['content-length'])
    local method = request.get_method()
    if method == "POST" then
      body_raw = request.get_raw_body()
      if body_raw then
        local form = ngx.decode_args(body_raw)
        if type(form) == "table" and next(form) then
          for name, value in pairs(form) do
            post_status = waf_body_check(value)
            if post_status then
              return true
            end
          end
        end
      end
    end
  end
  return false
end

-- 定义waf检测入口函数
local function waf( conf )
	-- body
	if ngx.var.http_Acunetix_Aspect then
    ngx.exit(444)
  elseif ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
  elseif waf_url_check(conf.urlmatch) then
    return true
  elseif waf_args_check(conf.argsmatch) then
    return true
  elseif waf_post_check(conf.postmatch) then
    return true
  elseif waf_ua_check(conf.uamatch) then
    return true
  elseif waf_cookie_check(conf.cookiematch) then
    return true
  else
    return false
  end
end

-- 定义插件构造函数
function KongWaf:new()
  KongWaf.super.new(self, "KongWaf")
end

-- 构造插件初始化函数, 在每个Nginx Worker启动时执行
function KongWaf:init_worker()
  KongWaf.super.init_worker(self)
  local ok, err = iputils.enable_lrucache()
  if not ok then
    kong.log.err("could not enable lrucache: ", err)
  end
  read_waf_rule('args')
end

-- 构造插件访问逻辑, 判断黑白名单, WAF判断在这里实现
function KongWaf:access(conf)
  KongWaf.super.access(self)
  local block = false
  local binary_remote_addr = ngx.var.binary_remote_addr-- 获取客户端真实IP地址

  if not binary_remote_addr then
    return kong.response.exit(FORBIDDEN, { message = "Cannot identify the client IP address, unix domain sockets are not supported." })
  end

  if conf.blacklist and #conf.blacklist > 0 then
    block = iputils.binip_in_cidrs(binary_remote_addr, cidr_cache(conf.blacklist))
  end

  if conf.whitelist and #conf.whitelist > 0 then
    block = not iputils.binip_in_cidrs(binary_remote_addr, cidr_cache(conf.whitelist))
  end

  if block then
    return kong.response.exit(FORBIDDEN, { message = "Your IP address is not allowed" })
  end

  if optionIsOn(conf.openwaf) then
    uri = unescape(unescape(ngx.var.request_uri))
    request = kong.request
    headers = request.get_headers()
    logpath = conf.logdir
    attacked = waf(conf)
    if optionIsOn(conf.urldeny) and attacked then
      return kong.response.exit(FORBIDDEN, { message = "Your request has attack data." })
    end
  end
end

return KongWaf