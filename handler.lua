local BasePlugin = require "kong.plugins.base_plugin"
local iputils = require "resty.iputils"
local access = require "kong.plugins.kong-waf.access"

local FORBIDDEN = 403

-- cache of parsed CIDR values
local cache = {}

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

function KongWaf:new()
  KongWaf.super.new(self, "KongWaf")
end

function KongWaf:init_worker()
  KongWaf.super.init_worker(self)
  local ok, err = iputils.enable_lrucache()
  if not ok then
    kong.log.err("could not enable lrucache: ", err)
  end
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

  attacked = access.exexute(conf)
  if optionIsOn(conf.urldeny) and attacked then
  	return kong.response.exit(FORBIDDEN, { message = "Your request has attack data." })
  end
end

return KongWaf