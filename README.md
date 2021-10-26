nmap-nse-scripts
----
Nmap NSE scripts that we have created or customised. At this stage these are custom scripts that you will have to copy into your Nmap Scripts directory manually to use them.

Installation of Custom Nmap Scripts
----
Depending on your installation method and distribution the exact location of the Nmap script files could be slightly different. If you have installed from source then copying these into the `/usr/local/share/nmap/scripts/` folder will do the trick.

You will also need to copy the **wp-themes.lst** and **wp-plugins.lst** into the `/usr/local/share/nmap/nselib/data/` folder for the script to access the theme list.

If you have a Windows installation of Nmap or are using a package, then the location of the files could be slightly different (it should not be too hard to find).

http-wordpress-info.nse
----
This script is non-intrusive and parses the source HTML of a WordPress page to find plugins, theme and the version of WordPress.

- Version is detected from the Meta Generator Tag or `/feed/atom/` if not present.
- Plugins are detected from HTML source /wp-content/plugins/**$pluginname**/ in addition a number of known HTML strings for common plugins are checked.
- Theme is detected from HTML source /wp-content/themes/**$themename**/
- PHP Version is shown if present in HTTP Headers (Server or X-Powered-By)
- HTTP Server is shown from HTTP Header (Server)

http-wordpress-plugins.nse 
----
#### Deprecated as http-wordpress-enum.nse has been updated with this functionality
A modified version of the original `http-wordpress-plugins.nse` script that will also attempt to identify the version of the plugins that have been detected following the brute force of the plugin paths.

http-wordpress-themes.nse
----
#### Deprecated as http-wordpress-enum.nse has been updated with this functionality
Another modified version of the `http-wordpress-plugins.nse` script this script will identify themes installed in the **/wp-content/themes/** folder and also attempt to identify the version of the themes from the **style.css** file. The **wp-theme.lst** was created by crawling the Top 1 million WordPress sites and ranking the themes by popularity.

Themes that are installed but not in use by a WordPress installation can still contain vulnerabilities that could lead to the compromise of the WordPress installation and server.

hostmap-hackertarget.nse
----
Similar to the hostmap-robtex.nse this script will attempt to identify hosts sharing the IP address that is being scanned. The hosts are found using the [Reverse IP Lookup API](https://hackertarget.com/reverse-ip-lookup/ "Reverse IP Lookup") that utilises DNS records from the [Scans.IO](https://scans.io) project.

About HackerTarget Pty Ltd
----
- [HackerTarget](https://hackertarget.com) provides hosted open source tools and network intelligence to help organizations with attack surface discovery and identification of security vulnerabilities.
- Expensive appliances with flashing blue lights are not always the best solution. Through promotion of open source security solutions we make organisations big and small better at protecting what matters to them.

