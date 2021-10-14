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
   local URL = "/"
      if response.location == nil then
           URL = url
   else
           if (response.location[1]) then
                   URL = response.location[1]
           else
                   URL = url
           end
   end

  body = ""
  local LEN = 0
  if response and response.status and response.status == 200 then
        stdnse.debug3("sucess rc: "..response.status)
	LEN = tonumber(response.header["content-length"])
        body = response.body
  elseif response and response.status and response.status == 404 then
        stdnse.debug3("strong bad says \"404ed!!!\"")
	LEN = tonumber(response.header["content-length"])
  else
        stdnse.debug3("failure:  => (",LEN,")")
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
  local javascript = {}

  if ( string.find(body, "<script") ) then 
          string.gsub(body, "<script", "\n<script") 
  end


  -- for line in modifiedBody:gmatch("([^\n]*)\n?") do
  for line in body:gmatch("([^\n]*)\n?") do
	if ((string.match(line,"<script")) and (string.match(line, "src=\""))) then
		local extracted = string.match(line, 'src="(.*)%"')
		if string.match(extracted, "^http") then 
        		-- stdnse.debug1("before: %s ", extracted)
			extracted = extracted:gsub("\".*", "")
        		-- stdnse.debug1("after: %s ", extracted)
			table.insert(javascript, extracted.." url: "..URL)
		end
	end 
   end

   -- print(#javascript)

  local result = {}
  result = stdnse.output_table()
  result["URL"] = URL

  if #javascript == 0  then
	-- print("no remote javascript found")
	table.insert(javascript, "no remote javascript found")
  else  
  	result["count"] = #javascript
  end 
  result["javascript"] = javascript

  -- local returnValue = "found "..#javascript.." scripts in page "..URL
  --   return result
	
  return result

end
