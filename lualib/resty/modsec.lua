local ffi               = require "ffi"
local debug             = require "debug"
local base              = require "resty.core.base"

local C                 = ffi.C
local registry          = debug.getregistry()
local new_tab           = base.new_tab
local ref_in_table      = base.ref_in_table
local get_request       = base.get_request
local FFI_NO_REQ_CTX    = base.FFI_NO_REQ_CTX
local FFI_OK            = base.FFI_OK
local error             = error
local setmetatable      = setmetatable
local subsystem         = ngx.config.subsystem

local _M  = {}
local msc = {}
local _DEBUG = false

if subsystem == "http" then
    ffi.cdef[[
        typedef void ModSecurity;
        typedef void Transaction;
        typedef void RulesSet;      
        typedef void (*ModSecLogCb) (void *, const void *);
             
        const char *msc_get_transaction_variable(Transaction *transaction, const char *var_name);
             
        int msc_get_highest_severity(Transaction *transaction);
        
        int msc_process_connection(Transaction *transaction,
                                    const char *client, int cPort, const char *server, int sPort);
        
        int msc_process_request_headers(Transaction *transaction);
             
        int msc_add_request_header(Transaction *transaction, const unsigned char *key,
                                    const unsigned char *value);
             
        int msc_process_request_body(Transaction *transaction);
             
        int msc_append_request_body(Transaction *transaction,
                                    const unsigned char *body, size_t size);
             
        int msc_request_body_from_file(Transaction *transaction, const char *path);
             
        int msc_process_response_headers(Transaction *transaction, int code,
                                            const char* protocol);
             
        int msc_add_response_header(Transaction *transaction,
                                    const unsigned char *key, const unsigned char *value);
             
        int msc_process_response_body(Transaction *transaction);
             
        int msc_append_response_body(Transaction *transaction,
                                        const unsigned char *body, size_t size);
             
        int msc_process_uri(Transaction *transaction, const char *uri,
                                const char *protocol, const char *http_version);
             
        Transaction *msc_new_transaction(ModSecurity *ms,
                                            RulesSet *rules, void *logCbData);
        
        void msc_transaction_cleanup(Transaction *transaction);
             
        ModSecurity *msc_init(void);
             
        void msc_set_connector_info(ModSecurity *msc, const char *connector);
             
        void msc_cleanup(ModSecurity *msc);
             
        RulesSet *msc_create_rules_set(void);
        
        int msc_rules_cleanup(RulesSet *rules);
             
        int msc_rules_add_remote(RulesSet *rules, const char *key, const char *uri,
                                    const char **error);
             
        int msc_rules_add_file(RulesSet *rules, const char *file, const char **error);
        
        int msc_rules_add(RulesSet *rules, const char *plain_rules,
                               const char **error);
             
        void msc_rules_dump(RulesSet *rules);
             
        int msc_process_logging(Transaction *transaction);
             
        void msc_set_log_cb(ModSecurity *msc, ModSecLogCb cb);
    ]]
    
    local ok, clib = pcall(ffi.load,"modsecurity",true)
    
    if not ok then
        ok, clib = pcall(ffi.load,"/usr/local/modsecurity/lib/libmodsecurity.so",true)
        if not ok then
            ngx.log(ngx.ERR,"Failed to open modsecurity library")
            return nil
        end
    end

    msc = {
        transaction_variable                    = C.msc_get_transaction_variable,
        highest_severity                        = C.msc_get_highest_severity,
        process_connection                      = C.msc_process_connection,
        
        process_request_headers                 = C.msc_process_request_headers,
        add_request_header                      = C.msc_add_request_header,
        
        process_request_body                    = C.msc_process_request_body,
        append_request_body                     = C.msc_append_request_body,
        request_body_from_file                  = C.msc_request_body_from_file,
        
        process_response_headers                = C.msc_process_response_headers,
        add_response_header                     = C.msc_add_response_header,
        
        process_response_body                   = C.msc_process_response_body,
        append_response_body                    = C.msc_append_response_body,
        
        process_uri                             = C.msc_process_uri,
        new_transaction                         = C.msc_new_transaction,
        transaction_cleanup                     = C.msc_transaction_cleanup,
        init                                    = C.msc_init,
        set_connector_info                      = C.msc_set_connector_info,
        cleanup                                 = C.msc_cleanup,
        create_rules_set                        = C.msc_create_rules_set,
        rules_cleanup                           = C.msc_rules_cleanup,
        rules_add_remote                        = C.msc_rules_add_remote,
        rules_add_file                          = C.msc_rules_add_file,
        rules_add_inline                        = C.msc_rules_add,
        rules_dump                              = C.msc_rules_dump,
        process_logging                         = C.msc_process_logging,
        msc_set_log_cb                          = C.msc_set_log_cb
    }    
    
elseif subsystem == "stream" then
    -- nothing to be done here
    ngx.log(ngx.ERR, "Currently not supported")
    return nil
end

local modsec    
local rules

local function httpVersion(version)
    if version == "HTTP/1.0" then
        return "1.0"
    elseif version == "HTTP/1.1" then
        return "1.1"
    elseif version == "HTTP/2.0" then
        return "2.0"
    end
    
    return nil
end    

local function transaction_logging(data,msg)
    local str = ffi.string(msg)
    ngx.log(ngx.ERR,str)
end

function _M.transaction()
    local ret = {}
    local _MT = {}
    local data
    
    if ngx.ctx.transaction then
        data = ngx.ctx.transaction
    else
        data = msc.new_transaction(modsec, rules, nil)
        ffi.gc(data,msc.transaction_cleanup)
    end

    if not data then
        return nil
    end

    -- Create methods being closures 
    function _MT.variable(self,var_name)
        if not data then
            return nil, "Transaction not initialized"
        end
        
        if not var_name then
            return nil, "Variable name empty"
        end
        
        local var = msc.transaction_variable(data,var_name)
        
        if var == nil then
            return nil, "Variable does not exists"
        end
        
        return ffi.string(var)
    end
    
    function _MT.eval_connection(self,client_ip,client_port,host,port,url,method,version)
        
        if msc.process_connection(data, client_ip, tonumber(client_port), host, tonumber(port)) ~= 1 then
            return false, "Failed to process connection"
        end
        
        local v = httpVersion(version)
        
        if not v then
            return false, "Invalid version specified"
        end
        
        if msc.process_uri(data,url,method, v) ~= 1 then
            return false, "Failed to process uri"
        end
        
        return true
    end    
    
    function _MT.eval_request_headers(self,headers)
        if type(headers) == "table" then
            for k,v in pairs(headers) do
                if msc.add_request_header(data,k,v) ~= 1 then
                    return false, "Failed to add request header"
                end
            end
        end
        
        if msc.process_request_headers(data) ~= 1 then
            return false, "Failed to process request headers"
        end
        
        return true
    end
    
    function _MT.eval_request_body(self,body,is_file)
        if body then
            if is_file then
                if msc.request_body_from_file(data,body) ~= 1 then
                    return false, "Failed to set request body from file"
                end
            else
                if msc.append_request_body(data,body,#body) ~= 1 then
                    return false, "Failed to set request body"
                end
            end
        end
        
        if msc.process_request_body(data) ~= 1 then
            return false, "Failed to process request body"
        end
        
        return true
    end    
    
    function _MT.eval_response_headers(self,headers,status,version,code)
        if type(status) == "string" and type(version) == "string" and type(code) == "string" then
            msc.add_response_header(data,status,code);
        end
        
        if type(headers) == "table" then
            for k,v in pairs(headers) do
                if type(v) == "table" then
                    for _,cookie in pairs(v) do
                        if msc.add_response_header(data,k,cookie) ~= 1 then
                            return false, "Failed to add response header"
                        end
                    end
                else
                    if msc.add_response_header(data,k,v) ~= 1 then
                        return false, "Failed to add response header"
                    end
                end
            end
        end
        
        if msc.process_response_headers(data, status, 'HTTP '.. httpVersion(version)) ~= 1 then
            return false, "Failed to process response headers"
        end
        
        return true
    end
    
    function _MT.eval_response_body(self,body)
        if body then
            if msc.append_response_body(data,body,#body) ~= 1 then
                return false, "Failed to append response body"
            end
        else
            if msc.process_response_body(data) ~= 1 then
                return false, "Failed to process response body"
            end
        end
        
        return true
    end    
    
    function _MT.store(self)
        ngx.ctx.transaction = data
    end
    
    function _MT.logging(self)
        return msc.process_logging(data)
    end
    
    setmetatable(ret, { __index = _MT } )
    
    -- Create vars access table
    
    ret.var = {
        global      = {},
        ip          = {},
        session     = {},
        user        = {},
        resource    = {},
        tx          = {}
    }   
    
    setmetatable(ret.var.global, { __index = function(t,k) return _MT.variable(nil,'global:'..k) end } )
    setmetatable(ret.var.ip, { __index = function(t,k) return _MT.variable(nil,'ip:'..k) end } )
    setmetatable(ret.var.session, { __index = function(t,k) return _MT.variable(nil,'session:'..k) end } )
    setmetatable(ret.var.user, { __index = function(t,k) return _MT.variable(nil,'user:'..k) end } )
    setmetatable(ret.var.resource, { __index = function(t,k) return _MT.variable(nil,'resource:'..k) end } )
    setmetatable(ret.var.tx, { __index = function(t,k) return _MT.variable(nil,'tx:'..k) end } )
    
    return ret
end    
    
function _M.init(rules_file,rules_remote,rules_inline,remote_key)
    local res
    
    if modsec and rules then
        return true
    end

    if not rules_file and not rules_remote and not rules_inline then
       return false, "Rules file path/url/inline should not be empty"
    end
    
    -- initialize libmodsecurity and set garbage collect function
    modsec = msc.init()
    
    if not modsec then
        return false, "Failed to initialize ModSecurity"
    end

    ffi.gc(modsec,msc.cleanup)
    msc.set_connector_info(modsec, "ModSecurity LUA")
    msc.msc_set_log_cb(modsec,transaction_logging);
    
    -- initialize new rules set and set garbage collect function
    rules = msc.create_rules_set()
    
    if not rules then
        return false, "Failed to create rules set"
    end
    
    ffi.gc(rules,msc.rules_cleanup)
    
    -- 
    local err = ffi.new 'const char *[1]'
    
    if type(rules_file) == "string" then
        res = msc.rules_add_file(rules, rules_file, err)
    
        if res < 0 then
            ngx.log(ngx.ERR,"Failed to load rules", ffi.string(err[0]))
            return false, ffi.string(err[0])
        end
    end
    
    if type(rules_remote) == "string" then
        res = msc.rules_add_remote(rules, remote_key, rules_remote, err)
        
        if res < 0 then
            ngx.log(ngx.ERR,"Failed to load rules", ffi.string(err[0]))
            return false, ffi.string(err[0])
        end
    end
    
    if type(rules_inline) == "string" then
        res = msc.rules_add_inline(rules, rules_inline, err)
        
        if res < 0 then
            ngx.log(ngx.ERR,"Failed to load rules", ffi.string(err[0]))
            return false, ffi.string(err[0])
        end
    end
    
    ngx.log(ngx.ERR,"Loaded #"..res.." rules from file")
    
    if _DEBUG then
        msc.rules_dump(rules)
    end
    
    return true
end    
    
return _M
