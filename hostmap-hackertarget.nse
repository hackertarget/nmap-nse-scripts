local http = require "http"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discovers hostnames (DNS A records) that resolve to the target's IP address by querying the online reverse IP lookup at http://hackertarget.com/reverse-ip-lookup/.

Script based on hostmap-robtex.nse by Arturo 'Buanzo' Busleiman.

Nmap 6.47 may error with:
/usr/local/bin/../share/nmap/nselib/shortport.lua:200: attempt to index field 'version' (a nil value)
Fix issue by getting latest shortport.lua from the Nmap svn.

]]

---
-- @usage
-- nmap --script hostmap-hackertarget -p 80 -Pn nmap.org
--
-- @output
-- | hostmap-hackertarget:
-- |   hosts:
-- |     cgi.insecure.org
-- |     download.insecure.org
-- |     images.insecure.org
-- |     insecure.com
-- |     insecure.org
-- |     nmap.com
-- |     nmap.net
-- |     nmap.org
-- |     seclists.org
-- |     sectools.org
-- |     svn.nmap.org
-- |     www.insecure.org
-- |     www.nmap.org
-- |_    www.sectools.org

--
-- @xmloutput
-- <table key="hosts">
--  <elem>nmap.org</elem>
-- </table>
---

author = "Peter Hill"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "discovery",
  "safe",
  "external"
}


-- Scrape domains sharing target host ip from hackertarget.com website
-- @param data string containing the retrieved web page
-- @return table containing the host names sharing host.ip
function parse_hackertarget_response (data)
  local result = {}

  for domain in string.gmatch(data, "([0-9a-z-.]+)") do
    if not stdnse.contains(result, domain) then
      table.insert(result, domain)
    end
  end
  return result
end

hostrule = function (host)
  return not ipOps.isPrivate(host.ip)
end

action = function (host)
  local link = "http://api.hackertarget.com/reverseiplookup/?q=" .. host.ip
  local htmldata = http.get_url(link)
  local domains = parse_hackertarget_response(htmldata.body)
  local output_tab = stdnse.output_table()
  if (#domains > 0) then
    output_tab.hosts = domains
  end
  return output_tab
end
