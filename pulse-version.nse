local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
quick hack to grab the version of Pulse Secure VPN endpoint installed on 
a given host
]]

---
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- |__pulse-version: 9.0.5.64107
--
-- @xmloutput
-- <elem key="version">9.0.5.64107</elem>


author = "Paul M Johnson"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = function(host, port)
  return shortport.http(host, port) and shortport.ssl(host, port)
end

action = function(host, port)
  local resp, redirect_url, title, VERSION

  resp = http.get( host, port, "/dana-na/nc/nc_gina_ver.txt" )

  print(resp.status)
  if resp and resp.status and resp.status == 200 then
  	local text = string.match(resp.body, "<PARAM NAME=\"ProductVersion\" VALUE=\".*")
	if text then 
        	local ProductVersion = string.match(text, "VALUE=.(%d+%.%d+%.%d+%.%d+)")
		if ProductVersion then 
			VERSION = ProductVersion
  			local output_tab = stdnse.output_table()
  			output_tab.version= VERSION 
			print(output_tab)
  			local output_str = VERSION 
  			return output_tab, output_str
		end
	end
   end 
end 


