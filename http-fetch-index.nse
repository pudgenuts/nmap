local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[The script is used to fetch just the default index page 
and compute an MD5 sum for the returned HTML, will also return any URL 
for a an allowed redirect

]]

---
-- @usage nmap --script http-fetch <target>
--
-- @output
-- | http-fetch-index:
-- |   URL: /
-- |   md5sum: 5db4fa93a1f7b28c117939af8ee91344
-- |   html:
-- | <HTML> ....
-- | </HTML>
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


  local body = ""
  local LEN = 0
  if response and response.status and response.status == 200 then
        print("sucess")
        print(response.status);
	LEN = tonumber(response.header["content-length"])
        body = response.body
  elseif response and response.status and response.status == 404 then
        print("strong bad says \"404ed!!!\"")
	LEN = tonumber(response.header["content-length"])
  else
        print("failure:  => (",LEN,")")
        stdnse.debug3("%s doesn't exist", url)
        body = "no data returned"
  end

 return URL, body


end

action = function(host, port)

  local url = '/'
  local paths = stdnse.get_script_args(SCRIPT_NAME..'.paths') or nil

  local output = stdnse.output_table()
  local patterns = {}

  local URL, body = fetchPage(host, port, url, output)
  md5 = stdnse.tohex(openssl.md5(body))

  local result = {}
  result = stdnse.output_table()
  result["URL"] = URL
  result["md5sum"] = md5
  result["html"] = body

  return result

end
