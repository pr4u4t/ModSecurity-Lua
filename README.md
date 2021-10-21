### ModSecurity-Lua

This is libmodsecurity binding for lua, created as a replacement for modsecurity nginx connector to be used with 
openresty. The purpose of this binding is to give read access to libmodsecurity variables to openresty.

### To use this binding libmodsecurity must be patched with:
[pull style API](https://github.com/SpiderLabs/ModSecurity/pull/2620)

Simple example:

```lua

local modsec = require "resty.modsec"
local bdy
local inf
local score

if not modsec.init('/etc/libmodsecurity/modsecurity.conf') then
    return false
end

local transaction = modsec.transaction()

if not transaction then
    return false
end

local res, err = transaction:eval_connection(ngx.var.remote_addr,ngx.var.remote_port,ngx.var.http_host,
                                                         ngx.var.server_port,ngx.var.scheme..'://'..ngx.var.vHost..ngx.var.request_uri,
                                                         ngx.var.request_method,ngx.var.server_protocol)
                
if err then
    ngx.log(ngx.ERR,"Failed to evaluate connection: ",err)
end
            
local hdrs, err = ngx.req.get_headers()
            
if err == "truncated" then
    -- here we have more then 100 header fields this is anomaly
end
            
local res, err = transaction:eval_request_headers(hdrs)

if err then
    ngx.log(ngx.ERR,"Failed to evaluate request headers: ",err)
end

if not ngx.req.get_body_file() then
    bdy = ngx.req.get_body_data()
    inf = false
else
    bdy = ngx.req.get_body_file()
    inf = true
end
                    
local res, err = transaction:eval_request_body(bdy,inf)

if err then
    ngx.log(ngx.ERR,"Failed to evaluate request body: ",err)
end

score = transaction:variable("tx:anomaly_score")

-- if score > 5 then
-- Perform some action if score greater then fg. 5
--end

local hdrs, err = ngx.resp.get_headers()
            
if err == "truncated" then
    -- here we have more then 100 header fields this is anomaly
end
            
local res, err = transaction:eval_response_headers(hdrs,ngx.status,ngx.var.server_protocol) 
            
if err then
    ngx.log(ngx.ERR,"Failed to evaluate response headers: ",err)
end

score = transaction:variable("tx:anomaly_score")

-- if score > 5 then
-- Perform some action if score greater then fg. 5
--end

transaction:logging()

```

Real life example:
