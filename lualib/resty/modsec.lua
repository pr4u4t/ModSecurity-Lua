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

--local settings          = require "settings"

--local ngx_lua_ffi_get_ctx_ref

local _M  = {}
local _MT = {}
local msc = {}

if subsystem == "http" then
    ffi.cdef[[
        typedef void ModSecurity;
        typedef void Transaction;
        typedef void RulesSet;      
              
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
             
        void msc_rules_dump(RulesSet *rules);
    ]]
    
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
        rules_dump                              = C.msc_rules_dump
    }    
    
elseif subsystem == "stream" then
    -- nothing to be done here
end

local modesec    
local rules
    
-- Modsecurity is separate ecosystem with it's own variables
-- deduction about blocking a request using HighestSeverity action often results 
-- in false positives. Making a separate function for every variable possible to set 
-- in rules is impossible. To make a proper deduction a gap between modescurity <-> nginx_connector 
-- must be filled. Best solution for that is make transaction export to Lua. This solution is based 
-- on ngx_mod_lua. Of course this needs one extra ModSec nginx connector function.

-- UPDATE: existing nginx connector doesn't give flexibility only solution is to prepare lua
-- bindings to modsecurity functions and decide whether to test request or not
    
function _MT.variable(self,var_name)

    if not self.transaction or not var_name then
       return nil 
    end
            
    local var = msc.transaction_variable(self.transaction,var_name)
        
    if var == nil then
        return nil
    end
        
    return ffi.string(var)
end

function _MT.eval_connection(self,client_ip,client_port,host,port,url,method,version)
    
    if msc.process_connection(self.transaction, client_ip, tonumber(client_port), host, tonumber(port)) ~= 1 then
	return false, "Failed to process connection"
    end
    
    local v = nil
    if version == "HTTP/1.0" then
	v = "1.0"
    elseif version == "HTTP/1.1" then
	v = "1.1"
    elseif version == "HTTP/2.0" then
	v = "2.0"
    end

    if not v then
	return false, "Invalid version specified"
    end

    if msc.process_uri(self.transaction,url,method, v) ~= 1 then
	return false, "Faild to process uri"
    end

    return true
end    

function _MT.eval_request_headers(self,headers)
    if type(headers) ~= "table" then
        return false
    end
    
    for k,v in pairs(headers) do
        if msc.add_request_header(self.transaction,k,v) ~= 1 then
	   return false, "Failed to add request header"
	end
    end
    
    if msc.process_request_headers(self.transaction) ~= 1 then
	return false, "Failed to process request headers"
    end

    return true
end
    
function _MT.eval_request_body(self,body,is_file)
    if is_file then
        if msc.request_body_from_file(self.transaction,body) ~= 1 then
	   return false, "Failed to set request body from file"
	end
    else
        if msc.append_request_body(self,transaction,body,#body) ~= 1 then
	   return false, "Failed to set request body"
	end
    end
    
    if msc.process_request_body(self.transaction) ~= 1 then
	return false, "Failed to process request body"
    end

    return true
end    

function _MT.eval_response_headers(self,headers,status,version)
    if type(headers) ~= "table" then
        return false
    end
    
    for k,v in pairs(headers) do
	if type(v) == "table" then
	   for _,cookie in pairs(v) do
		if msc.add_response_header(self.transaction,k,cookie) ~= 1 then
		   return false, "Failed to add response header"
		end
	   end
	else
	   if msc.add_response_header(self.transaction,k,v) ~= 1 then
		return false, "Failed to add response header"
	   end
	end
    end
    
    if msc.process_response_headers(self.transaction, status, version) ~= 1 then
	return false, "Failed to process response header"
    end

    return true
end

function _MT.eval_response_body(self,body)
    if msc.append_response_body(self.ransaction,body) ~= 1 then
	return false, "Failed to append response body"
    end

    if msc.process_response_body(self.transaction) ~= 1 then
	return false, "Failed to process response body"
    end

    return true
end    
    
--msc.process_logging(transaction)
    
function _M.transaction()
    local ret = {}
    ret.transaction = msc.new_transaction(modsec, rules, nil);
    
    if not ret.transaction then
        return nil
    end
    
    ffi.gc(ret.transaction,msc.transaction_cleanup)
    setmetatable(ret,{ __index = _MT } )

    return ret
end    
    
function _M.init(rules_file)
    if modsec and rules then
	return true
    end

    if not rules_file then
       return false, "Rules file path should not be empty"
    end
    
    -- initialize libmodsecurity and set garbage collect function
    modsec = msc.init()
    
    if not modsec then
        return false, "Failed to initialize ModSecurity"
    end

    ffi.gc(modsec,msc.cleanup)
    msc.set_connector_info(modsec, "ModSecurity LUA")
    
    -- initialize new rules set and set garbage collect function
    rules = msc.create_rules_set()
    
    if not rules then
        return false, "Failed to create rules set"
    end
    
    ffi.gc(rules,msc.rules_cleanup)
    
    -- 
    local err = ffi.new 'const char *[1]'
    local ret = msc.rules_add_file(rules, rules_file, err)
    
    if ret < 0 then
        return false, err[1]
    end
    
    msc.rules_dump(rules)
    
    return true
end    
    
return _M
