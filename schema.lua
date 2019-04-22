local typedefs = require "kong.db.schema.typedefs"


return {
  name = "KongWaf",
  fields = {
    { run_on = typedefs.run_on_first },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { whitelist = { type = "array", elements = typedefs.cidr, }, },
          { blacklist = { type = "array", elements = typedefs.cidr, }, },
          { rulepath = { type = "path", required = true, }, },
          { attacklog = { type = "string", required = true, }, },
          { logdir = { type = "path", required = true, }, },
          { urldeny = { type = "string", required = true, }, },
          { Redirect = { type = "string", required = true, }, },
          { cookiematch = { type = "string", required = true, }, },
          { postmatch = { type = "string", required = true, }, },
          { black_fileExt = { type = "array", elements = typedefs.string, }, },
          { attacklog = { type = "string", required = true, }, },
        },
      },
    },
  },
  entity_checks = {
    { only_one_of = { "config.whitelist", "config.blacklist" }, },
    { at_least_one_of = { "config.whitelist", "config.blacklist" }, },
  },
}