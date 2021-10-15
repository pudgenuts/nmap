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

function ltrim(s)
  return (s:gsub("^%s*", ""))
end

-- remove trailing whitespace from string.
-- http://en.wikipedia.org/wiki/Trim_(programming)
function rtrim(s)
  local n = #s
  while n > 0 and s:find("^%s", n) do n = n - 1 end
  return s:sub(1, n)
end

function table2String(table)
   local index = 1
   local holder = ""
   while true do
      if type(table[index]) == "function" then
         index = index + 1
      elseif type(table[index]) == "table" then
         holder = holder..compileTable(table[index])
      elseif type(table[index]) == "number" then
         holder = holder..tostring(table[index])
      elseif type(table[index]) == "string" then
         holder = holder..table[index]
      elseif table[index] == nil then
         holder = holder.."nil"
      elseif type(table[index]) == "boolean" then
         holder = holder..(table[index] and "true" or "false")
      end
      if index + 1 > #table then
        break
      end
      holder = holder
      index = index + 1
   end
   return holder
end

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

  body = ""
  local LEN = 0
  if response and response.status and response.status == 200 then
        stdnse.debug3("sucess rc: "..response.status);
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
  local APPEND = 0
  local array = {}
  
  local modifiedBody =  string.gsub(body, "</script>", "</script>\n")
  local modifiedBody =  string.gsub(modifiedBody, "<script>", "\n</script>")
  stdnse.debug3(modifiedBody)

  for line in modifiedBody:gmatch("([^\n]*)\n?") do
        
	line = ltrim(line)
	line = rtrim(line)
	if ( string.match(line,"script")) then 
		stdnse.debug1("debug> %s", line)
        	if ( (string.match(line,"<script"))  and ( string.match(line,"http")  ) ) then
                	APPEND = 0; 
        	elseif ( (string.match(line,"<script"))  and ( string.match(line,"src=/")  ) ) then
                	APPEND = 1; 
        	elseif ((string.match(line,"<script")) and (string.match(line,"</script>")))  then
                	APPEND = 0; 
                	table.insert(array,line)
                	script = table2String(array)
                	table.insert(javascript,script)
        	elseif (string.match(line,"<script"))  then
                	APPEND = 1; 
        	elseif (string.match(line,"</script>")) then
                	APPEND = 0; 
                	table.insert(array,line)
                	script = table2String(array)
                	table.insert(javascript,script)
        	end 
	end
        if APPEND == 1 then 
                table.insert(array,line)
        end
  end

  local result = {}
  result = stdnse.output_table()
  result["URL"] = URL
  result["count"] = #javascript
  result["javascript"] = javascript

  -- local returnValue = "found "..#javascript.." scripts in page "..URL
  return result
  -- return javascript

end
