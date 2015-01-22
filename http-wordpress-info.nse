local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Finds the WordPress version, theme and plugins observed in the page response. 
- Version detection tests for a meta generator html tag, if this is not found an attempt 
is made to access /readme.html a default file in all versions of WordPress.
- Theme is determined by searching HTML resposne for /wp-content/themes/$themename
- Discovered plugins are those that match /wp-content/plugins/$pluginname in the HTML 
response. This will not find all plugins, to find all plugins you will need the 
http-wordpress-plugins nse script to brute force the plugin paths.

Script based on code from Michael Kohl's http-generator.nse
]]

author = "Peter Hill <peter@hackertarget.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @usage
-- nmap --script http-wordpress-info [--script-args http-wordpress-info.path=<path>,http-wordpress-info.redirects=<number>,...] <host>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-wordpress-info: 
-- |   version: WordPress 4.0
-- |   theme: canvas
-- |   plugins: 
-- |     w3-total-cache
-- |_    simple-tooltips

-- @args http-wordpress-info.path Specify the path you want to check for a generator meta tag (default to '/').
-- @args http-wordpress-info.redirects Specify the maximum number of redirects to follow (defaults to 3).


-- helper function
local follow_redirects = function(host, port, path, n)
  local pattern = "^[hH][tT][tT][pP]/1.[01] 30[12]"
  local response = http.get(host, port, path)

  while (response['status-line'] or ""):match(pattern) and n > 0 do
    n = n - 1
    local loc = response.header['location']
    response = http.get_url(loc)
  end

  return response
end


-- find plugins in HTML page source and return table
function parse_plugins_response (data)
  local result = {}
  local pluginmatch = 'wp%-content/plugins/([0-9a-z%-.]+)'

  for plugin in string.gmatch(data, pluginmatch) do
    if not stdnse.contains(result, plugin) then
      table.insert(result, plugin)
    end
  end
  return result
end


portrule = shortport.http

action = function(host, port)
  local response, loc, generator
  local path = stdnse.get_script_args('http-wordpress-info.path') or '/'
  local redirects = tonumber(stdnse.get_script_args('http-wordpress-info.redirects')) or 3
  local output_tab = stdnse.output_table()

  -- Find Version in "meta generator tag"
  local pattern = '<meta name="?generator"? content="WordPress ([.0-9]*)" ?/?>'
  local themematch = 'wp%-content/themes/([0-9a-z]+)'
 
  -- make pattern case-insensitive
  pattern = pattern:gsub("%a", function (c)
      return string.format("[%s%s]", string.lower(c),
        string.upper(c))
      end)

  -- Find version in readme.html file
  local readmepattern = 'Version ([.0-9]*)'
  local wpversion = nil
  local themes = nil
  


  response = follow_redirects(host, port, path, redirects)
  if ( response and response.body ) then
    wpversion = response.body:match(pattern)
    themes = response.body:match(themematch)
    plugins = parse_plugins_response(response.body)
  end

  -- If version not in generator tag, check /readme.html
  if ( not wpversion and response.body:match("wp%-content")) then
    readmepath = path .. '/readme.html'
    readmeresponse = follow_redirects(host, port, readmepath, redirects)
    if ( readmeresponse and readmeresponse.body ) then
      wpversion = readmeresponse.body:match(readmepattern)
    end
  end

  -- Store results in output table
  if wpversion then
    output_tab.version = 'WordPress ' .. wpversion
  end
  if ( themes and #themes > 0 ) then
    output_tab.theme = themes
  end
  if ( plugins and #plugins > 0 ) then
    output_tab.plugins = plugins 
  end
  if ( output_tab.version or output_tab.plugins or output_tab.theme ) then
     return output_tab
  end
end
