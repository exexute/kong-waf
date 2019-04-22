local BasePlugin = require "kong.plugins.base_plugin"
local iputils = require "resty.iputils"

local FORBIDDEN = 403

-- cache of parsed CIDR values
local cache = {}


local ngxmatch=ngx.re.match
-- 定义waf规则变量
local uarules = ""
local ckrules = ""
local urlrules = ""
local argsrules = ""
local postrules = ""

local attacklog = true
local black_fileExt = {}


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
    file = io.open('/usr/local/share/lua/5.1/kong/plugins/kong-waf/wafconf/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

-- 定义插件规则拆分函数
local function split_waf_rule(rule_string, rule_separator)
  local nFindStartIndex = 1
  local nSplitIndex = 1
  local nSplitArray = {}
  while true do
    local nFindLastIndex = string.find(rule_string, rule_separator, nFindStartIndex)
    if not nFindLastIndex then
      nSplitArray[nSplitIndex] = string.sub(rule_string, nFindStartIndex, string.len(rule_string))
      break
    end
    nSplitArray[nSplitIndex] = string.sub(rule_string, nFindStartIndex, nFindLastIndex - 1)
    nFindStartIndex = nFindLastIndex + string.len(rule_separator)
    nSplitIndex = nSplitIndex + 1
  end
  return nSplitArray
end

-- 定义插件配置set函数
local function waf_conf_set( list )
  -- body
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end
-- waf插件相关函数

local function waf_log_write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

local function waf_log(method, url, data, ruletag)
	-- body
	if attacklog then
    	local realIp = ngx.var.binary_remote_addr
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        waf_log_write(filename,line)
    end
end

-- 定义插件后缀检测函数
local function waf_ext_check(ext)
  local items = waf_conf_set(black_fileExt)
  ext=string.lower(ext)
  if ext then
    for rule in pairs(items) do
      if ngx.re.find(ext,rule,"isjo") then
      waf_log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
        say_html()
      end
    end
  end
  return false
end


local function waf_get_boundary( ... )
	-- body
	local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

-- 定义waf插件url检测函数
local function waf_url_check(urldeny)
  if optionIsOn(urldeny) then
    for _,rule in pairs(urlrules) do
      tb_rules = split_waf_rule(rule, '@@@')
      if rule ~="" and ngxmatch(ngx.var.request_uri,tb_rules[2],"isjo") then
        waf_log('GET',ngx.var.request_uri,"-",tb_rules[1])
        return true
      end
    end
  end
  return false
end

-- 定义waf插件user-agent检测函数
local function waf_ua_check( ... )
	-- body
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                waf_log('UA',ngx.var.request_uri,"-",rule)
                return true
            end
        end
    end
    return false
end

-- 定义waf插件get参数检测函数
local function waf_args_check( ... )
	-- body
	for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
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
            tb_rules = split_waf_rule(rule, '@@@')
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),tb_rules[2],"isjo") then
                waf_log('GET',ngx.var.request_uri,"-",tb_rules[1])
                return true
            end
        end
    end
    return false
end

-- 定义waf插件cookie参数检测函数
local function waf_cookie_check( cookie_check )
	-- body
	local ck = ngx.var.http_cookie
    if optionIsOn(cookie_check) and ck then
        for _,rule in pairs(ckrules) do
            tb_rules = split_waf_rule(rule, '@@@')
            if rule ~="" and ngxmatch(ck,tb_rules[2],"isjo") then
                waf_log('Cookie',ngx.var.request_uri,"-",tb_rules[1])
            	return true
            end
        end
    end
    return false
end

local function waf_body_check( ... )
	-- body
	for _,rule in pairs(postrules) do
		tb_rules = split_waf_rule(rule, '@@@')
		if rule ~="" and data~="" and ngxmatch(unescape(data),tb_rules[2],"isjo") then
			waf_log('POST',ngx.var.request_uri,data,tb_rules[1])
			return true
        end
    end
    return false
end

-- 定义waf插件post请求检测函数
local function waf_post_check( check_post )
	-- body
	if optionIsOn(check_post) == false then
		return false
	end

	local content_length=tonumber(ngx.req.get_headers()['content-length'])
	local method=ngx.req.get_method()
    if method=="POST" then
        local boundary = waf_get_boundary()
        if boundary then
        	local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                return
            end
        ngx.req.init_body(128 * 1024)
        sock:settimeout(0)
        local content_length = nil
        content_length=tonumber(ngx.req.get_headers()['content-length'])
        local chunk_size = 4096
        if content_length < chunk_size then
            chunk_size = content_length
        end
        local size = 0
        while size < content_length do
        	local data, err, partial = sock:receive(chunk_size)
            data = data or partial

            if not data then
                return
            end

            ngx.req.append_body(data)
            if waf_body_check(data) then
                return true
            end

            size = size + len(data)
            local m = ngxmatch(data,[[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]],'ijo')
            if m then
                waf_ext_check(m[3])
                filetranslate = true
            else
                if ngxmatch(data,"Content-Disposition:",'isjo') then
                    filetranslate = false
                end

                if filetranslate==false then
                    if waf_body_check(data) then
                        return true
                    end
                end
            end

            local less = content_length - size
            if less < chunk_size then
                chunk_size = less
            end
         end
         ngx.req.finish_body()
        else
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if not args then
                return
            end

            for key, val in pairs(args) do
                if type(val) == "table" then
                    if type(val[1]) == "boolean" then
                        return
                    end
                    data=table.concat(val, ", ")
                else
                    data=val
                end

                if data and type(data) ~= "boolean" and waf_body_check(data) then
                    waf_body_check(key)
                end
            end
        end
    end
end

-- 定义waf检测入口函数
local function waf( conf )
	-- body
	if ngx.var.http_Acunetix_Aspect then
        ngx.exit(444)
    elseif ngx.var.http_X_Scan_Memo then
        ngx.exit(444)
    elseif waf_ua_check() then
    	return true
    elseif waf_url_check(conf.urldeny) then
    	return true
    elseif waf_args_check() then
    	return true
    elseif waf_cookie_check(conf.cookiematch) then
    	return true
    elseif waf_post_check(conf.postmatch) then
    	return true
    else
    	return
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
  urlrules=read_waf_rule('url')
  argsrules=read_waf_rule('args')
  uarules=read_waf_rule('user-agent')
  postrules=read_waf_rule('post')
  ckrules=read_waf_rule('cookie')
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

  attacklog=optionIsOn(conf.attacklog)
  black_fileExt=waf_conf_set(conf.black_fileExt)
  attacked=waf(conf)
  if conf.urldeny and attacked then
  	return kong.response.exit(FORBIDDEN, { message = "Your request has attack data." })
  end
end

return KongWaf