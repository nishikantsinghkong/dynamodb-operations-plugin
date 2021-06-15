local plugin = {
  PRIORITY = 1002, -- set the plugin priority lower than api key validation to ensure incoming request apikey is validated before this
  VERSION = "0.1",
}

local base64 = require "ngx.base64"
local sha = require "resty.sha256"
local cjson = require "cjson"
local http = require "resty.http" 
local kong_utils = require "kong.tools.utils"  
local uuid = kong_utils.uuid
local random_string = kong_utils.random_string
local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local pl_string = require "pl.stringx"
local timestamp = require "kong.tools.timestamp"
local lrucache = require "resty.lrucache"   -- to introduce LRU lua memory caching 
--local kong = kong     -- this will allow us to use kong var for caching like kong.cache
-- we need to initialize the cache on the lua module level so that 
-- it can be shared by all the requests served by each nginx worker process:

local c, err = lrucache.new(1000)  -- allow up to 1000 items in the cache
if not c then
    error("failed to create the cache: " .. (err or "unknown"))
end

local AWS = require("resty.aws")
local aws = AWS()
-- or similarly
local aws = AWS:new()


local function connect_to_dynamodb(region) 
  -- instantiate a service (optionally overriding the global config)
   return aws:DynamoDB {
    region = region,
   }

end


-- Dump function allows us to look at the value of any objet, field or results
local dump = function(...)
  local info = debug.getinfo(2) or {}
  local input = { n = select("#", ...), ...}
  local write = require("pl.pretty").write
  local serialized
  if input.n == 1 and type(input[1]) == "table" then
    serialized = "(" .. type(input[1]) .. "): " .. write(input[1])
  elseif input.n == 1 then
    serialized = "(" .. type(input[1]) .. "): " .. tostring(input[1]) .. "\n"
  else
    local n
    n, input.n = input.n, nil
    serialized = "(list, #" .. n .. "): " .. write(input)
  end

  print(ngx.WARN,
          "\027[31m\n",
          "function '", tostring(info.name), ":" , tostring(info.currentline),
          "' in '", tostring(info.short_src), "' wants you to know:\n",
          serialized,
          "\027[0m")
end

local digest_final      -- this variable will store the hased valued from incoming jwt
-- check if value if present in cache. create new function load_Hash 
local function load_hash_from_dynamodb (dynamodb,digest_final)
  
  local hashlookup = {
    ExpressionAttributeValues = {
      [":a"] = {
        S = digest_final
      }
    },
    FilterExpression = "hashedvalue = :a",
    TableName = "hashtable"
  }
  kong.log.inspect(hashlookup)
  
  result,err = dynamodb:scan(hashlookup)  -- to check if the hashedvalue records already exist
  kong.log.inspect(result)
  kong.log.inspect(err)
  return result
end

local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local kong_utils = require ("kong.tools.utils")  -- added to use the random_string function
local random_string = kong_utils.random_string   -- random_string function defined here will be used for opaque tokens


function plugin:access(plugin_conf)

  
  local requestpath = kong.request.get_path()  -- get the path on which request is sent
    kong.log.inspect(requestpath)                      

      -- if the route on which plugin applies is /refreshtoken then code will refresh the incoming token
      -- if the route on which plugin is applied is /nosa/token then code will exchange incoming JWT for opaque token

  if requestpath == "/v1/nosa/refreshtoken" then
    local contenttype =   kong.request.get_header("Content-Type") -- to check and ensure correct Content-Type is passed
    kong.log.inspect(contenttype)
      if contenttype ~= "application/x-www-form-urlencoded" then          -- Validate Content Type for mapi-nosa token exchange and refresh token flow
          kong.response.exit(400, {message = "Invalid or empty content-type passed. Please validate the Content-Type and retry!"})
      end
    local body, err = kong.request.get_body()   -- to get the incoming body
    kong.log.inspect(body) 
    kong.log.inspect(err)
    if not body then                          -- Validate that incoming request has a body for token exchange and refresh token flow
      kong.response.exit(400, {message = "No input body passed. Please pass a valid request!"})
    end 
    local refreshtoken = body.refresh_token   -- to get assertion from form param body 
    local appiid = body.appiid
      kong.log.inspect(appiid)
      kong.log.inspect(refreshtoken)
    local grant_type = body.grant_type  -- to get the right grant type from body in the incoming request
      kong.log.inspect(grant_type)  
          if (not grant_type) or (grant_type ~= "refresh_token") then   -- check if the incoming request has right grant type
            kong.response.exit(400, {
              error = {
                code = 400.02,
                message = "Invalid grant type.",
                detail = {
                  message = "GrantType should be refresh_token"
                  }
              }
            })
          elseif not appiid then
            print("appiid is not present in the incoming request body as User")
              kong.response.exit(400, {
                fault = {
                  faultstring = "Unauthorized user",
                  detail = { errorcode = "proxy.authorization.unauthorized_user"}}})
          end

        if not refreshtoken or refreshtoken == "" then      -- check if the incoming request has a refresh token in the body
          kong.response.exit(400.01, {
            fault = {
              faultstring = "Failed to resolve refresh token variable request.formparam.refresh_token",
              detail = {
                errorcode = "FailedToResolveRefreshToken"
              }
            }
          })
        end
        local dynamodb,err = connect_to_dynamodb(plugin_conf.region) 

        if not dynamodb then
        print("failed to connect to dynamodb")
        kong.log.inspect(err)
        kong.response.exit(500,err)
        else
          kong.log.inspect("Connected to dynamoDB successfully")
        end

       local getCurrentToken = {      -- create sample request body that will Scan dynamodb Tokens table for entry
          ExpressionAttributeValues = {
            [":a"] = {
              S = refreshtoken
            }
          },
          FilterExpression = "refresh_token = :a",
          TableName = "Token"
        }
        kong.log.inspect(getCurrentToken)
        local currentTokenResponse,err = dynamodb:scan(getCurrentToken)  -- to check if the hashedvalue records already exist
        kong.log.inspect(currentTokenResponse)
        kong.log.inspect(err)

          if (not currentTokenResponse) or (currentTokenResponse == nil) then
            kong.response.exit(500, {err})
          end

          if currentTokenResponse.body.Count == 0 then       -- this means that provided refresh token in the request doesnt exist in Tokens table
              kong.response.exit(400, {message = "The incoming refresh_token is either invalid or expired. Please pass a correct refresh token!"})
          elseif (not currentTokenResponse.body.Items[1].appiid) or (currentTokenResponse.body.Items[1].appiid.S ~= appiid)then 
            print("refresh token flow comes to appiid match condition and it doesn not pass the appiid check")
            kong.response.exit(401, {
              fault = {
                faultstring = "Unauthorized user",
                detail = {
                  errorcode = "proxy.authorization.unauthorized_user"
                }
              }
            })
          else
              print("invoking token refreshing activity!")
              local new_access_token = random_string()   -- create new opaque access token
              local new_refresh_token = random_string()   -- create new opaque refresh token
              local seconds_now = ngx.now()   -- to get the current timestamp
              local milliseconds = seconds_now*1000
              kong.log.inspect(seconds_now)
              kong.log.inspect(milliseconds)          -- display time in millis
              local ttl
              if not plugin_conf.token_ttl then
                ttl = 7200
              else
                ttl = plugin_conf.token_ttl
              end

              local expiration_in_millis = milliseconds + ttl*1000
              kong.log.inspect(expiration_in_millis)
              local expiration_in_seconds = (math.floor(expiration_in_millis/1000))
              kong.log.inspect(expiration_in_seconds)
              local issued_at_formatted = os.date("%Y-%b-%dT%H-%M-%S+00:00", seconds_now)  -- to create human-readable format of time to send back as part of response
              local expiration_formatted = os.date("%Y-%b-%dT%H-%M-%S+00:00", expiration_in_millis/1000) -- to create human-readable format of time to send back as part of response
              local id = currentTokenResponse.body.Items[1].id.S   -- this will capture the primary key of the entry that needs to be updated
              local PutItem_body = {
                Key = {
                  id = {
                    S = id
                  }
                },
                UpdateExpression = "SET access_token = :val1,refresh_token = :val2, expires_at = :val3, issued_at = :val4, refresh_token_issued_at = :val5, refresh_token_expires_at = :val6",
                ExpressionAttributeValues = {
                  [":val1"] = {
                    S = new_access_token
                  },
                  [":val2"] = {
                    S = new_refresh_token
                  },
                  [":val3"] = {
                    N = tostring(expiration_in_seconds)
                  },
                  [":val4"] = {
                    S = tostring(issued_at_formatted)
                  },
                  [":val5"] = {
                    S = tostring(issued_at_formatted)
                  },
                  [":val6"] = {
                    S = tostring(expiration_formatted)
                  },
                },
                TableName = "Token",
                ReturnValues = "ALL_NEW"
              }    
              kong.log.inspect(PutItem_body)
            local result,err = dynamodb:updateItem(PutItem_body)   -- to create a new entry with new access token in the table
            kong.log.inspect(result)  -- check the value of response from performing update query
            kong.log.inspect(err)

            if (not result) or (result == nil) then
                kong.response.exit(500, {err})
            else   
                local refresh_token_response = {     -- prepare the resposne to be sent back to client
                  expires = result.body.Attributes.issued_at.N,
                  issued_at = result.body.Attributes.issued_at.N,
                  client_id = kong.request.get_header("apikey"),
                  access_token = result.body.Attributes.access_token.S,
                  refresh_token = result.body.Attributes.refresh_token.S,
                  refresh_token_issued_at = tostring(issued_at_formatted),
                  refresh_token_expires_at = tostring(expiration_formatted)
                }

                if result.body.Attributes.brandId then
                  refresh_token_response.brandId = result.body.Attributes.brandId.S
                  refresh_token_response.app_enduser = result.body.Attributes.brandId.S
                end

                if result.body.Attributes.shopperId then
                  refresh_token_response.shopperId = result.body.Attributes.shopperId.S
                end

                if result.body.Attributes.webShopperId then
                  refresh_token_response.webShopperId = result.body.Attributes.webShopperId.S
                end

                if result.body.Attributes.NCOM_ID then
                  refresh_token_response.NCOM_ID = result.body.Attributes.NCOM_ID.S
                end

                kong.log.inspect(refresh_token_response)
              kong.response.exit(200,refresh_token_response)    -- return back the new tokens to the calling application
            end
          end

        -- end of code block where request path is /v1/nosa/refreshtoken

   -- below should only execute when request comes in on /v1/nosa/token request route
  elseif requestpath == "/v1/nosa/token" then
    local contenttype =   kong.request.get_header("Content-Type") -- to check and ensure correct Content-Type is passed

    local invalidRequestJWT = {
      error = {
        code = 400.02,
        message = "that request was invalid.",
        detail = {
          message = "You must pass a JWT as a formparam. It should be signed with your private key using RS256",
          example_claimset = {
            iss = "API_KEY",
            scope = "https://www.example.com/apitechforum.readonly",
            aud = "https://www.cap500.com/apitechform/token",
            exp = 1328554385,
            iat = 1328550785
           }
        }
      }
    }
    kong.log.inspect(contenttype)
      if contenttype ~= "application/x-www-form-urlencoded" then          -- Validate Content Type for mapi-nosa token exchange and refresh token flow
          kong.response.exit(400, {                -- this just lift and shift of error struture from Apigee to be thrown back to calling app
            error = {
              code = 400.02,
              message = "that request was invalid.",
              detail = {
                message = "You must pass a JWT as a formparam. It should be signed with your private key using RS256",
                example_claimset = {
                  iss = "API_KEY",
                  scope = "https://www.example.com/apitechforum.readonly",
                  aud = "https://www.cap500.com/apitechform/token",
                  exp = 1328554385,
                  iat = 1328550785
                }
              }
            }
          })
      end
    local body, err = kong.request.get_body()   -- to get the incoming body
    kong.log.inspect(body) 
    kong.log.inspect(err)
    if not body then                          -- Validate that incoming request has a body for token exchange and refresh token flow
      kong.response.exit(400, {message = "No input body passed. Please pass a valid request!"})
    end
    local assertion = body.assertion   -- to get assertion from form param body  changeme
      kong.log.inspect(assertion)   
    if not assertion or assertion == "" then 
        kong.response.exit(400, {message = "No asertion value found in the request body!"}) 
    end
    local grant_type = body.grant_type   -- to get the right grant type from body in the incoming request
      kong.log.inspect(grant_type)  
    if not grant_type then
      kong.response.exit(400, {
        error = {
          code = 400.02,
          message = "that request was invalid. Missing grant type",
      }})
      elseif grant_type ~= "urn:ietf:params:oauth:grant-type:jwt-bearer" then
        kong.response.exit(400, {message = "invalid grant type passed. Please correct the grant type and retry"})
    end
    local jwt, err = jwt_decoder:new(assertion)   -- check to see if the jwt is valid structure
      if err then
        kong.response.exit(401, {message = "Not a well-formed jwt. Please pass a right JWT token in a proper format!"})
      end

    -- below block is to decode the jwt token and inspect for mandatory claims  #START
    local claims = jwt.claims
    local header = jwt.header
        if not claims or not header then
            badjwtmessage = {
              fault = {
                faultstring = "Execution failed with Error: invalid JWT - incorrect number of parts. Expected 3 parts. Please recheck the JWT ",
                detail = {
                  errorcode = "400"
                }
              }
            }
            kong.response.exit(400, badjwtmessage)
        end

    kong.log.inspect(claims)
    kong.log.inspect(plugin_conf.mandatoryclaims)
    if plugin_conf.mandatoryclaims then
      local splitclaimvalues = pl_string.split(plugin_conf.mandatoryclaims, ",")
      kong.log.inspect(splitclaimvalues)
          for i,v in ipairs(splitclaimvalues) do 
            if not claims[v] then
                kong.log.inspect("missing a mandatory claim "..v)
                kong.response.exit(401, {message = "Invalid JWT passed in the assertion. Mandatory claim(/s) missing!"}) 
              else
              kong.log.inspect("found mandatory claim "..v)
            end
          end

      -- if not claims[plugin_conf.custom_claimName1] then
      --  kong.response.exit(401, {message = "Invalid JWT passed in the request. Mandatory claim(/s) missing"})
      -- end
    end
    -- Above code is to decode the jwt token and inspect for mandatory claims  #END

      -- The code below is to do hashing on the incoming jwt #START

    local hash = sha:new()
    hash:update(assertion)  -- returns true or false
    
    local digest_mid = hash:final()  -- to return the hashed value of assertion
    digest_final = base64.encode_base64url(digest_mid)
    kong.log.inspect(digest_final)    -- check the final hashed value generated

    local dynamodb,err = connect_to_dynamodb(plugin_conf.region) 
    if not dynamodb then
      kong.log.err("failed to connect to dynamodb",err)
    return nil,"Failed to connect to dynamodb. Error: "..err
    else
      print("Connected to dynamoDB successfully!")
    end

    -- TODO need to revisit the implementation of caching to use mlcache instead of LRU Cache
    local cachehit = c:get(digest_final)-- lookup inside of kong cache here
      kong.log.inspect(cachehit)
      if cachehit then
        kong.response.exit(401, {message = "The incoming JWT has already been previously used!"})
      end

  
   --  local hashresponse,err = kong.cache:get(cache_key,nil,load_hash_from_dynamodb,dynamodb,digest_final)
    local seconds_now = ngx.now() 
    kong.log.inspect(seconds_now) 
    local hashexpiration -- TODO - check with Brent if this is a right way to define variable of type numbe?
    if claims.exp and claims.exp ~= nil and claims.exp ~= "" then
      hashexpiration = tonumber(claims.exp)      
    else
      hashexpiration = seconds_now + 300
    end
    kong.log.inspect(hashexpiration)      -- print the values of hash expiration that will be stored in hashtable

    local expiration_in_seconds = (math.floor(hashexpiration))
    kong.log.inspect(expiration_in_seconds)
    local hashlookup = {
      ExpressionAttributeValues = {
        [":a"] = {
          S = digest_final
        }
      },
      FilterExpression = "hashedvalue = :a",
      TableName = "hashtable"
    }
    kong.log.inspect(hashlookup)

    local hashresponse,err = dynamodb:scan(hashlookup)  -- to check if the hashedvalue records already exist
    kong.log.inspect(hashresponse)
    kong.log.inspect(err)

    if (not hashresponse) or (hashresponse == nil) then
      kong.log.inspect("failed to perform operation on dynamodb. Error: ")
      kong.response.exit(500,err)
    end

      
      if hashresponse.body.Count > 0 then
      -- TODO need to revisit based on caching changes from LRUcache to mlcache
        local addtocache = c:set(digest_final, true)
        kong.log.inspect(addtocache)
        kong.response.exit(401, "The incoming JWT has already been previously used!")
      end
    -- hasloopup will check if the currently-passed JWT is already present in hashtable or not
  
     -- create the body structure to push hashvalue into dynamodb table called "hash"
    local puthash_body = {
      Item = {
        hashedvalue = {
          S = digest_final
        },
        expires_at = {
          N = tostring(expiration_in_seconds)
        }
      },
        TableName = "hashtable"
    }
    kong.log.inspect(puthash_body)
    local addtocache = c:set(digest_final, true)    -- add the hashedvalued of incoming JWT to kong's cache
    kong.log.inspect(addtocache)
    local addhash, err = dynamodb:putItem(puthash_body)   -- insert the new hashedkey into hash table 
    kong.log.inspect(addhash)

      if err or (not addhash) or (addhash == nil) then
        kong.response.exit(500, err)
      end
    -- Added the code above to do hashing on the incoming jwt  #END

   -- below is the code to create random string access_token and refresh_token, prepare for adding new entry in Token table
    local opaque_access_token = random_string()   -- generate a new access token value
    local opaque_refresh_token = random_string()  -- generate a new refresh token value
    local unique_key = uuid()   -- to generate a primary key for the Token table 
    local seconds_now = ngx.now()   -- to get the current timestamp
    local milliseconds = seconds_now*1000
    local body = kong.request.get_body()
    local appiid = body.appiid
    kong.log.inspect(appiid)
    kong.log.inspect(seconds_now)
    kong.log.inspect(milliseconds)          -- display time in millis
    local ttl
    if not plugin_conf.token_ttl then
      ttl = 7200
    else
      ttl = plugin_conf.token_ttl
    end

    local expiration_in_millis = milliseconds + ttl*1000
    kong.log.inspect(expiration_in_millis)
    local expiration_in_seconds = (math.floor(expiration_in_millis/1000))
    kong.log.inspect(expiration_in_seconds)
    local issued_at_formatted = os.date("%Y-%b-%dT%H-%M-%S+00:00", seconds_now)  -- to create human-readable format of time to send back as part of response
    local expiration_formatted = os.date("%Y-%b-%dT%H-%M-%S+00:00", expiration_in_seconds) -- to create human-readable format of time to send back as part of response

    local exchange_response = {
        expires_in = tonumber(ttl),
        expires_at = expiration_in_seconds,
        issued_at = milliseconds,
        client_id = kong.request.get_header("apikey"),
        refresh_token_issued = tostring(issued_at_formatted),
        refresh_token_expires = tostring(expiration_formatted),
        access_token = opaque_access_token,
        NCOM_ID = claims.NCOM,      -- TODO. check if NCOM ID is coming directly as a child element of claims, or as part of another claim
        grant_type = passsword,
        refresh_token = opaque_refresh_token
      }

      -- bunch of optionals fields are populated only if they are present in the JWT claims
      if plugin_conf.notes then 
        exchange_response.notes = plugin_conf.notes
      end

      if claims.brandId then 
        exchange_response.brandId = claims.brandId
        exchange_response.app_enduser = claims.brandID
      end

      if claims.shopperID then 
        exchange_response.shopperId = claims.shopperID
      end

      if claims.webShopperID then
        exchange_response.webShopperId = claims.webShopperID
      end

    kong.log.inspect(exchange_response)
      -- TODO only set values for claims if they are NOT NULl. Need to do that condition check here

      local PutItem_body = {     -- prepare body to insert the new record in Token table
              Item = {
                id = {
                  S = unique_key
                  },  
                access_token = {
                        S = opaque_access_token
                  },
                  refresh_token = {
                        S = opaque_refresh_token
                  },
                  expires_at = {
                    N = tostring(expiration_in_seconds)
                  },
                  issued_at = {
                    S = tostring(issued_at_formatted)
                  },
                  refresh_token_issued_at = {
                    S = tostring(issued_at_formatted)
                  },
                  grant_type = {
                    S = "password"     -- hardcoded the grant_type here as password type
                  },
                  refresh_token_expires_at = {
                    S = tostring(expiration_formatted)
                  },
                    },
                    TableName = "Token"
                  }
               
                  if claims.iss then 
                    PutItem_body.Item.issuer_id = {S}
                    PutItem_body.Item.issuer_id.S = claims.iss
                  end

                  if plugin_conf.notes then 
                    PutItem_body.Item.notes = {S}
                    PutItem_body.Item.notes.S = plugin_conf.notes
                  end

                  if claims.brandId then 
                    PutItem_body.Item.brandId = {S}
                    PutItem_body.Item.brandId.S = claims.brandId
                  end

                  if claims.shopperID then 
                    PutItem_body.Item.shopperId = {S} 
                    PutItem_body.Item.shopperId.S = claims.shopperID
                  end

                  if claims.webShopperID then
                    PutItem_body.Item.webShopperId  = {S} 
                    PutItem_body.Item.webShopperId.S = claims.webShopperID
                  end

                  if claims.NCOM_ID then
                    PutItem_body.Item.NCOM_ID = {S}
                    PutItem_body.Item.NCOM_ID.S = claims.NCOM_ID
                  end

                  if appiid then
                    PutItem_body.Item.appiid = {S}
                    PutItem_body.Item.appiid.S = tostring(appiid)
                  end

                  kong.log.inspect(claims.iss)
                  kong.log.inspect(plugin_conf.notes)
                  kong.log.inspect(claims.brandId)
                  kong.log.inspect(claims.webShopperID)
                  kong.log.inspect(claims.shopperID)
                  kong.log.inspect(appiid)

      kong.log.inspect(PutItem_body)
      local result,err = dynamodb:putItem(PutItem_body)
      -- local hashresponse,err = kong.cache:get(cache_key,nil,load_hash_from_dynamodb,dynamodb,digest_final)
      kong.log.inspect(result)
      kong.log.inspect(err)


    -- respond back with the body 
    if (not result) or (result == nil) then
        print("Bad Response from DynamodDB call. Error:")
        kong.log.inspect(err)
        kong.response.exit(500, {err})
    elseif result.status ~= 200 then
        kong.response.exit(result.status, result.body.message)
    else
      kong.response.exit(200, exchange_response)
    end

  elseif requestpath == "/v2/oauth/check_token" then
      -- This block of code will check if the request is coming for opaque token validation
      local Authorization = kong.request.get_header("Authorization")   -- token is passed as Authorization header
      local apikey = kong.request.get_header("x-api-key")
      local user = kong.request.get_header("User")
       kong.log.inspect(apikey)
       kong.log.inspect(user)

        if not Authorization or Authorization == nil then   -- check to see that request has an Authorization header
          kong.response.exit(401, {message = "Authorization header missing. Not a valid request!"})
        end
        
        local access_token = string.sub(Authorization,8)   -- to extract the value of opaque token from header by trimming off "bearer"
        kong.log.inspect(access_token)                     -- print the value of opaque token in logs

        if not access_token or access_token == "" then -- this will check to ensure that Authorization had a valid value for opaque token
          kong.response.exit(401, {message = "Incorrect Authorization value. Please send in a correct value and try again"}) 
        end


        local dynamodb,err = connect_to_dynamodb(plugin_conf.region) 
        kong.log.inspect(err)
        kong.log.inspect(dynamodb)
        if not dynamodb then
        print("Failed to connect to dynamodb")
       
        else
          kong.log.inspect("Connected to dynamoDB successfully")
        end

        -- code snippet below will check if the currently-passed token is present in Token store or not
        local verifytoken = {
          ExpressionAttributeValues = {
            [":a"] = {
              S = access_token
            }
          },
          FilterExpression = "access_token = :a",
          TableName = "Token"
        }
        kong.log.inspect(verifytoken)

        local result,err = dynamodb:scan(verifytoken)  -- to check if the access token already exists in dynamoDB or not
        kong.log.inspect(result)
        kong.log.inspect(err)

        if (not result) or (result == nil) then 
          kong.log.inspect(err)
        kong.response.exit(500,{err})
        end

          if err then
            print(err)
            kong.response.exit(500,err)
          elseif (result.body.Count == 0) then
            kong.log.inspect(result.body)
            print("count of item in tokens table is nil hence throwing error back to the calling app")
            kong.response.exit(401, {  
            error = {
              message = "The incoming access token is either expired or not valid!"}}) 
          
          elseif result.body.Items[1].webShopperId then  -- check if the incoming opaque token has any associated webShopperId
            print("webshopperID not nil")
            local tokenuser = result.body.Items[1].webShopperId.S   -- extract the webShopperId to compare against the value of incoming user. This is another check performed in check token flow
            kong.log.inspect(tokenuser)
                  if tokenuser ~= user then
                    print("users dont match! Throwing error to calling app")
                    kong.response.exit(401, {
                      fault = {
                        faultstring = "Unauthorized user",
                        detail = {
                          errorcode = "proxy.authorization.unauthorized_user"
                        }
                      }
                    })
                  else 
                    print("incoming token is valid and users match is true. Happy path scenario!")
                    kong.response.exit(200)
                  end 
          else 
            print("incoming token is valid and users match is true. Happy path scenario!. No webShoppeId to match against incoming user value")
            kong.response.exit(200)
          end -- End of if condition on line 636
        
  elseif requestpath == "/oauth2/revoke" then  -- this flow will  flush out all the tokens for a specified user
    -- this flow will flush all the opaque tokens for a user from dynamodb Token store
    local shopperId = kong.request.get_header("User") or kong.request.get_header("user")
    kong.log.inspect(shopperId)

    if not shopperId or shopperId == nil then
      kong.response.exit(401, {
        fault = {
          faultstring = "Unauthorized user",
          detail = { errorcode = "proxy.authorization.unauthorized_user"}}})
    end

    local dynamodb,err = connect_to_dynamodb(plugin_conf.region) 
        if not dynamodb then
        print("failed to connect to dynamodb")
        kong.log.inspect(err)
        else
          kong.log.inspect("Connected to dynamoDB successfully")
        end

    local recordstodelete = {      -- create  request body that will Scan dynamodb Tokens table for entries with matching value of shopperId
        ExpressionAttributeValues = {
          [":a"] = {
            S = shopperId
          }
        },
        FilterExpression = "shopperId = :a",
        TableName = "Token"
      }
      kong.log.inspect(recordstodelete)
      local result,err = dynamodb:scan(recordstodelete)  -- get all the records for matching shopperId
      kong.log.inspect(result)
      kong.log.inspect(err)
        if (not result) or (result == nil) then
          kong.response.exit(500, {err})
        elseif result.status ~= 200 then
          kong.response.exit(result.status,result.body.message)
        else
          print("dyanmodb scan operation successful!")
        end
      
      if not result.body or result.body.Count == 0 then
        kong.log.inspect("Scan result is valid but no dynamodb entry in the result. Nothing to delete")
        kong.response.exit(400, {message = "no tokens to delete for the user"})
      elseif result.body.Count >0 then  
        local aaa = {}  -- this will be the Lua table that will have the result of for loop inserted
        local temp      -- will be used to help store and create request body for batch deletion
        for i,v in ipairs(result.body.Items) do
          temp = {
            DeleteRequest = {
              Key = {
                id = {
                  S = tostring(result.body.Items[i].id.S)
                }
              }
            }}
          --table.insert(aaa,DeleteRequest) -- to insert this record in batchdeleterequest
            aaa[i] = temp
        end
        kong.log.inspect(aaa)
        -- setmetatable(aaa, cjson.array_mt)   
        local batchdeleterequest = {
          RequestItems = {
            Token = aaa
          },
          ReturnConsumedCapacity = "TOTAL"
        }

          kong.log.inspect(batchdeleterequest)
          local deleteresult,err = dynamodb:batchWriteItem(batchdeleterequest)
          kong.log.inspect(deleteresult)
          kong.log.inspect(err)
        
          if not deleteresult or deleteresult == nil then
            kong.response.exit(500,err)
          elseif deleteresult.status ~= 200  then
            kong.response.exit(deleteresult.status,deleteresult.body.message)
          else
            kong.response.exit(deleteresult.status,{message= "success"})
          end
      else 
        print("Request to flush tokens has no matching entries in the Token table")
        kong.response.exit(result.status,result.reason)
      end

      
  else      -- in case none of the three specified path matches, it comes to this else condition
    kong.response.exit(400, {message = "mapi-nosa plugin is applied is incorrect API endpoint or route. Please check and retry again!"})
  end -- this is the end of all request path checks

end 

-- return our plugin object
return plugin