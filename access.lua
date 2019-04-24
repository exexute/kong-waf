local ngx = ngx
local kong = kong
local pairs = pairs
local match = string.match
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local request = kong.request
local headers = request.get_headers()
-- 定义waf规则变量
local urlrules=read_waf_rule('url')
local argsrules=read_waf_rule('args')
local uarules=read_waf_rule('user-agent')
local postrules=read_waf_rule('post')
local ckrules=read_waf_rule('cookie')

local logpath=""
local attacklog = true
local black_fileExt = {}


local _M = {}


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
  local fd = io.open("/usr/local/kong/logs/sec_kong_2019_04_24.log","ab")
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
    print(filename)
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
      return true
      end
    end
  end
  return false
end


local function waf_get_boundary( ... )
	-- body
	local header = headers["content-type"]
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
      kong.log.err(ngx.var.request_uri)
      if rule ~="" and ngx.re.match(ngx.var.request_uri,tb_rules[2],"isjo") then
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
      tb_rules = split_waf_rule(rule, '@@@')
      if rule ~="" and ngx.re.match(ua,tb_rules[2],"isjo") then
        waf_log('UA',ngx.var.request_uri,"-",tb_rules[1])
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
    local args = request.get_query()
    for key, val in pairs(args) do
      kong.log.err(key)
      kong.log.err(val)
      if type(val)=='table' then
        local t={}
        for k,v in pairs(val) do
          print(v)
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
      if data and type(data) ~= "boolean" and rule ~="" and ngx.re.match(ngx.unescape_uri(data),tb_rules[2],"isjo") then
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
  local var = ngx.var
	local ck = var.http_cookie
  if optionIsOn(cookie_check) and ck then
    for _,rule in pairs(ckrules) do
      tb_rules = split_waf_rule(rule, '@@@')
      if rule ~="" and ngx.re.match(ck,tb_rules[2],"isjo") then
        waf_log('Cookie',ngx.var.request_uri,"-",tb_rules[1])
        return true
      end
    end
  end
  return false
end

local function waf_body_check( data )
	-- body
	for _,rule in pairs(postrules) do
		tb_rules = split_waf_rule(rule, '@@@')
		if rule ~= "" and data ~= "" and ngx.re.match(ngx.unescape_uri(data),tb_rules[2],"isjo") then
			waf_log( 'POST', ngx.var.request_uri, data, tb_rules[1] )
			return true
    end
  end
  return false
end

-- 定义waf插件post请求检测函数
local function waf_post_check( check_post )
  -- body
  if optionIsOn(check_post) then
    local content_length = tonumber(headers['content-length'])
    local method = request.get_method()
    if method == "POST" then
      body_raw = kong.request.get_raw_body()
      kong.log.err(body_raw)
      if body_raw then
        local form = ngx.decode_args(body_raw)
        if type(form) == "table" and next(form) then
          for name, value in pairs(form) do
            waf_body_check(value)
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
  elseif waf_url_check(conf.urldeny) then
    return true
  elseif waf_args_check() then
    return true
  elseif waf_post_check(conf.postmatch) then
    return true
  elseif waf_ua_check() then
    return true
  elseif waf_cookie_check(conf.cookiematch) then
    return true
  else
    return false
  end
end

function _M.execute(conf)
  waf(conf)
end


return _M