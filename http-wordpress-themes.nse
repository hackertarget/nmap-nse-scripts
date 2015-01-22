local coroutine = require "coroutine"
local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Discover a list of installed WordPress themes. Brute force of the theme path 
/wp-content/themes/$themename/ testing for known themes. As seen in the widespread 
timthumb vulnerability themes installed but not activated can still be exploited.

After detection of a valid theme path, the script will attempt to GET the style.css
of the theme. This is a standard file in WordPress themes that contains the theme
version, if found the version will be included in the output.

The theme list has been created and sorted by theme popularity after crawling the 
top 1 million sites. Also includes themes from wordpress.org.  Anything but a 404
means that a given theme directory probably exists, so the theme probably also does. 

The available themes for Wordpress is huge and despite the efforts of Nmap to
parallelize the queries, a whole search could take an hour or so. That's why
the theme list is sorted by popularity and by default the script will only
check the first 100 ones. Users can tweak this with an option (see below).

NSE Script is a clone of the http-wordpress-plugins.nse script by Ange Gutek.
]]

---
-- @args http-wordpress-themes.root If set, points to the blog root directory on the website. If not, the script will try to find a WP directory installation or fall back to root.
-- @args http-wordpress-themes.search As the themes list contains about 3000 themes, this script will only search the 100 most popular ones by default.
-- Use this option with a number or "all" as an argument for a more comprehensive brute force.
--
-- @usage
-- nmap --script=http-wordpress-themes --script-args http-wordpress-themes.root="/blog/",http-wordpress-themes.search=500 <targets>
--
--@output
-- Interesting ports on my.woot.blog (123.123.123.123):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-wordpress-themes:
-- | search amongst the 500 most popular themes 
-- |   twentyfourteen 1.3
-- |   canvas 5.8.7
-- |_  twentytwelve 1.5
--
-- Created 18/10/2014 - v0.1 - created (and themes crawled) by Peter Hill <peter@hackertarget.com>

author = "Peter Hill <peter@hackertarget.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}


local DEFAULT_THEME_SEARCH = 100


portrule = shortport.service("http")

local function read_data_file(file)
  return coroutine.wrap(function()
    for line in file:lines() do
      if not line:match("^%s*#") and not line:match("^%s*$") then
        coroutine.yield(line)
      end
    end
  end)
end

action = function(host, port)

  local result = {}
  local all = {}
  local bfqueries = {}

  --Check if the wp themes list exists
  local wp_themes_file = nmap.fetchfile("nselib/data/wp-themes.lst")
  if not wp_themes_file then
    return false, "Couldn't find wp-themes.lst (should be in nselib/data)"
  end

  local file = io.open(wp_themes_file, "r")
  if not file then
    return false, "Couldn't find wp-themes.lst (should be in nselib/data)"
  end

  local wp_autoroot
  local wp_root = stdnse.get_script_args("http-wordpress-themes.root")
  local themes_search = DEFAULT_THEME_SEARCH
  local themes_search_arg = stdnse.get_script_args("http-wordpress-themes.search")

  if themes_search_arg == "all" then
    themes_search = nil
  elseif themes_search_arg then
    themes_search = tonumber(themes_search_arg)
  end

  stdnse.print_debug(1, "%s themes search range: %s", SCRIPT_NAME, themes_search or "unlimited")


  -- search the website root for evidences of a Wordpress path
  if not wp_root then
    local target_index = http.get(host,port, "/")

    if target_index.status and target_index.body then
      wp_autoroot = string.match(target_index.body, "http://[%w%-%.]-/([%w%-%./]-)wp%-content")
      if wp_autoroot then
        wp_autoroot = "/" .. wp_autoroot
        stdnse.print_debug(1, "%s WP root directory: %s", SCRIPT_NAME, wp_autoroot)
      else
        stdnse.print_debug(1, "%s WP root directory: wp_autoroot was unable to find a WP content dir (root page returns %d).", SCRIPT_NAME, target_index.status)
      end
    end
  end


  --identify the 404
  local status_404, result_404, body_404 = http.identify_404(host, port)
  if not status_404 then
    return stdnse.format_output(false, SCRIPT_NAME .. " unable to handle 404 pages (" .. result_404 .. ")")
  end


  --build a table of both directories to brute force and the corresponding WP themes' name
  local theme_count = 0
  for line in read_data_file(file) do
    if themes_search and theme_count >= themes_search then
      break
    end

    local target
    if wp_root then
      -- Give user-supplied argument the priority
      target = wp_root .. "/wp-content/themes/" .. line .. "/"
    elseif wp_autoroot then
      -- Maybe the script has discovered another Wordpress content directory
      target = wp_autoroot .. "wp-content/themes/" .. line .. "/"
    else
      -- Default WP directory is root
      target = "/wp-content/themes/" .. line .. "/"
    end


    target = string.gsub(target, "//", "/")
    table.insert(bfqueries, {target, line})
    all = http.pipeline_add(target, nil, all, "GET")
    theme_count = theme_count + 1

  end

  -- release hell...
  local pipeline_returns = http.pipeline_go(host, port, all)
  if not pipeline_returns then
    stdnse.print_debug(1, "%s : got no answers from pipelined queries", SCRIPT_NAME)
  end

  for i, data in pairs(pipeline_returns) do
    -- if it's not a four-'o-four, it probably means that the theme is present
    if http.page_exists(data, result_404, body_404, bfqueries[i][1], true) then
      stdnse.print_debug(1, "http-wordpress-themes.nse: Found a theme: %s", bfqueries[i][2])

      -- now try and get the version of the plugin from readme.txt
      stylecsspath = bfqueries[i][1] .. "style.css"
      local themeversion = nil
      themefound = nil 
      stdnse.print_debug(1, "http-wordpress-plugins.nse: Style CSS path: %s", stylecsspath)
      local themeversioncheck = http.get(host, port, stylecsspath)
      local versionpattern = 'Version: ([.0-9]*)' 
      local themeversion = themeversioncheck.body:match(versionpattern)
      if themeversion then
          themefound = bfqueries[i][2] .. " " .. themeversion
      else
          themefound = bfqueries[i][2]
      end

      table.insert(result, themefound)
    end
  end


  if #result > 0 then
    result.name = "search amongst the " .. theme_count .. " most popular themes"
    return stdnse.format_output(true, result)
  else
    return "nothing found amongst the " .. theme_count .. " most popular themes, use --script-args http-wordpress-themes.search=<number|all> for deeper analysis)\n"
  end

end

