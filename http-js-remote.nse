local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local lfs = require "lfs"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[The script is used to fetch just the default index file from a server 

]]

---
-- @usage nmap --script http-fetch <target>
--
-- @output
-- | http-fetch-index: <html> ... </html>
--

author = "Paul M Johnson inspire by code for http-fetch by Gyanendra Mishra)"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe"}

portrule = shortport.http


local function fetchPage(host, port, url, output)
  local response = http.get(host, port, url, nil)
   if response.location[1] then 
        URL = response.location[1]
   else 
        URL = url 
   end 

  body = ""
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
  stdnse.debug3("body:", body)
  

 return URL, body


end

action = function(host, port)

  local url = '/'
  local paths = stdnse.get_script_args(SCRIPT_NAME..'.paths') or nil

  local output = stdnse.output_table()
  local patterns = {}
  local URL, body = fetchPage(host, port, url, output)
  javascript = {}

  for line in body:gmatch("([^\n]*)\n?") do
	if ((string.match(line,"<script")) and (string.match(line, "src=\""))) then
		local extracted = string.match(line, "src=\"(.*)\" ")
		if string.match(extracted, "http") then 
			print(extracted)
			table.insert(javascript, extracted)
		end
	end 
   end

  return javascript

end
