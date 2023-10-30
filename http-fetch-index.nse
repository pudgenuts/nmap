local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
        The script is used to fetch just the default index page 
        and compute an MD5 sum for the returned HTML, will also return any URL 
        for a an allowed redirect
]]

---
-- @usage nmap --script http-fetch <target>
--
-- @output
-- | http-fetch-index:
-- |   URL: /
-- |   html: <body returned to GET>
-- |   md5sum: 5db4fa93a1f7b28c117939af8ee91344
-- | 
--

author = "Paul M Johnson inspire by code for http-fetch by Gyanendra Mishra)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}
portrule = shortport.http

local function fetchPage(host, port, url, output)
  local response = http.get(host, port, url, nil)
   if response.location == nil then 
           URL = url 
   else 
           if (response.location[1]) then 
                   URL = response.location[1] 
           else 
                   URL = url 
           end 
   end 
   stdnse.debug3("response: %s",response.status)


  local body = ""
  local LEN = 0
  if response and response.status and response.status == 200 then
        stdnse.debug3("sucess "..response.status);
	LEN = tonumber(response.header["content-length"])
        body = response.body
  elseif response and response.status and response.status == 302 then 
        body = "redirect to " .. URL
  elseif response and response.status and response.status == 404 then
        stdnse.debug1("strong bad says \"404ed!!!\"")
	LEN = tonumber(response.header["content-length"])
  else
        stdnse.debug3("failure:  => ("..LEN..")")
        stdnse.debug3("%s doesn't exist", url)
        body = "no data returned"
  end

 return URL, response.status, body

end

action = function(host, port)

  local url = '/'
  local paths = stdnse.get_script_args(SCRIPT_NAME..'.paths') or nil

  local output = stdnse.output_table()
  local patterns = {}

  local URL, RC, body = fetchPage(host, port, url, output)
  local result = {}
  if RC == 302 then  
        -- local result = {}
        result = stdnse.output_table()
        result["URL"] = body 
  else
        md5 = stdnse.tohex(openssl.md5(body))
        -- local result = {}
        result = stdnse.output_table()
        result["URL"] = URL
        result["html"] = body
        result["md5sum"] = md5
  end 

  return result

end
