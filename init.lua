require 'config'
local match = string.match
local ngxmatch=ngx.re.find
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir 
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect=optionIsOn(Redirect)

function Split(szFullString, szSeparator)  
local nFindStartIndex = 1  
local nSplitIndex = 1  
local nSplitArray = {}  
while true do  
   local nFindLastIndex = string.find(szFullString, szSeparator, nFindStartIndex)  
   if not nFindLastIndex then  
    nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, string.len(szFullString))  
    break  
   end  
   nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, nFindLastIndex - 1)  
   nFindStartIndex = nFindLastIndex + string.len(szSeparator)  
   nSplitIndex = nSplitIndex + 1  
end  
return nSplitArray  
end

function getClientIp()
        IP  = ngx.var.remote_addr 
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
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

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')


function Split(szFullString, szSeparator)  
local nFindStartIndex = 1  
local nSplitIndex = 1  
local nSplitArray = {}  
while true do  
   local nFindLastIndex = string.find(szFullString, szSeparator, nFindStartIndex)  
   if not nFindLastIndex then  
    nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, string.len(szFullString))  
    break  
   end  
   nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, nFindLastIndex - 1)  
   nFindStartIndex = nFindLastIndex + string.len(szSeparator)  
   nSplitIndex = nSplitIndex + 1  
end  
return nSplitArray  
end

function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end
function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.find(ext,rule,"isjo") then
	        log('POST',ngx.var.request_uri,"-","file attack with ext "..ext)
            say_html()
            end
        end
    end
    return false
end
function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end
function args()
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
            tb_rules = Split(rule, '@@@')
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),tb_rules[2],"isjo") then
                log('GET',ngx.var.request_uri,"-",tb_rules[1])
                say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            tb_rules = Split(rule, '@@@')
            if rule ~="" and ngxmatch(ngx.var.request_uri,tb_rules[2],"isjo") then
                log('GET',ngx.var.request_uri,"-",tb_rules[1])
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end
function body(data)
    for _,rule in pairs(postrules) do
        tb_rules = Split(rule, '@@@')
        if rule ~="" and data~="" and ngxmatch(unescape(data),tb_rules[2],"isjo") then
            log('POST',ngx.var.request_uri,data,tb_rules[1])
            say_html()
            return true
        end
    end
    return false
end
function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            tb_rules = Split(rule, '@@@')
            if rule ~="" and ngxmatch(ck,tb_rules[2],"isjo") then
                log('Cookie',ngx.var.request_uri,"-",tb_rules[1])
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 ngx.exit(503)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
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

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end


function waf( ... )
    local content_length=tonumber(ngx.req.get_headers()['content-length'])
    local method=ngx.req.get_method()
    local ngxmatch=ngx.re.find
    if whiteip() then
    elseif blockip() then
    elseif denycc() then
    elseif ngx.var.http_Acunetix_Aspect then
        ngx.exit(444)
    elseif ngx.var.http_X_Scan_Memo then
        ngx.exit(444)
    elseif whiteurl() then
    elseif ua() then
    elseif url() then
    elseif args() then
    elseif cookie() then
    elseif PostCheck then
        if method=="POST" then
                local boundary = get_boundary()
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
                if body(data) then
                    return true
                    end
            size = size + len(data)
            local m = ngxmatch(data,[[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]],'ijo')
                if m then
                        fileExtCheck(m[3])
                        filetranslate = true
                else
                        if ngxmatch(data,"Content-Disposition:",'isjo') then
                            filetranslate = false
                        end
                        if filetranslate==false then
                            if body(data) then
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
                    if data and type(data) ~= "boolean" and body(data) then
                                body(key)
                    end
                end
            end
        end
    else
        return
    end
end
