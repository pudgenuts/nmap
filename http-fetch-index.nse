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

  body = "><"
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

 return body


end

action = function(host, port)

  local url = '/'
  local paths = stdnse.get_script_args(SCRIPT_NAME..'.paths') or nil

  local output = stdnse.output_table()
  local patterns = {}

  -- if paths then
    -- if type(paths) ~= 'table' then
      -- paths = {paths}
    -- end
    -- for _, path in pairs(paths) do
      -- if path:sub(1, 1) == "/" then
        -- fetch(host, port, url, destination, path, output)
      -- else
        -- table.insert(patterns, path)
      -- end
    -- end
    -- if #patterns > 0 then
      -- fetch_recursively(host, port, url, destination, patterns, output)
    -- end
  -- else
    -- fetch_recursively(host, port, url, destination, nil, output)
    body = fetchPage(host, port, url, output)
  -- end



  return body

end
