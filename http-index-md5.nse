local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[The script is used to fetch files from servers.

]]

---
-- @usage nmap --script http-fetch --script-args destination=/tmp/mirror <target>
--
-- @output
-- |_http-index-md5: 35d79a17ffed0b754d8d8282af50a31e
--

author = " Paul M Johnson based on code from Gyanendra Mishra"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe"},{"discovery"} 

portrule = shortport.http




local function fetch2(host, port, url, output)
  local response = http.get(host, port, url, nil)
  if response and response.status and response.status == 200 then
        stdnse.debug3("sucess")
        body = response.body
  else
    stdnse.debug1("HTTP code 403")
    body = "HTTP code "..response.status
    stdnse.debug3(body)
  end

 return body


end

local function fetchPage(host, port, url, output)
  local response = http.get(host, port, url, nil)

  body = "><"
  if response and response.status and response.status == 200 then
        stdnse.debug3("sucess %s",response.status);
        body = response.body
  else
        
        stdnse.debug3("%s doesn't exist", url)
        body = response.header
  end

 return body


end

action = function(host, port)

  local url = '/'
  local paths = stdnse.get_script_args(SCRIPT_NAME..'.paths') or nil

  local output = stdnse.output_table()
  local patterns = {}

  body = fetchPage(host, port, url, output)

  md5 = stdnse.tohex(openssl.md5(body))


  return md5

end

