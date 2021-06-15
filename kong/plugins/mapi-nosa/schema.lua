local typedefs = require "kong.db.schema.typedefs"

-- Grab pluginname from module name
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local schema = {
  name = plugin_name,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },  -- this plugin cannot be configured on a consumer (typical for auth plugins)
    { protocols = typedefs.protocols_http },
    { config = {
        -- The 'config' record is the custom part of the plugin schema
        type = "record",
        fields = {
          -- a standard defined field (typedef), with some customizations
          { region = { -- self defined field
              type = "string",
              default = "us-west-2", -- specifies the value of region
              required = true,}},
          { mandatoryclaims = { -- self defined custom field to check mandatory claims
              type = "string",
              required = false,
              default = "brandID,shopperID"
              }},
              { token_ttl = { -- self defined custom field to check incoming value specified by customer for Token TTL
              type = "number",
              required = true,
              default = 7200
              }},
        },
      },
    },
  },
}

return schema
