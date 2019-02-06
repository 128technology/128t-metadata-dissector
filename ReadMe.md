# Overview

This plugin will decode the unencrypted metadata information present on SVR packets.
Any packets containing metadata will also be marked as either:
 - 128t_over_tcp 
 - 128t_over_udp

(**Tip**: you can use that as filters on Wireshark and tshark!)

The expected output is a new "128T SVR Metadata" header on SVR packets, displaying original packet's information.

The "protocol" column shoud present "128T" as one of the payloads of the packet.

You can use '128t_over_tcp' or '128t_over_udp' as filters on the GUI or tshark to filter packets containing metadata.

You can also 'right click' on the metadata information and add them as filters on the GUI.

(**Tip**: you can filter by tenant name for example)

You can also use Wireshark's GUI
  ```sh
     View -> Coloring Rules
  ```
To color any SVR packets accordingly.

**Requirements**:

  - Wireshark 2.2.x or greater
  - It should work on any OS (let me know if you find any issues!)
  - 128T version 3.X (older versions should not work due to distinct metadata format)

**Note**: Encrypted packets will be marked but not decrypted at this time!

Please report any issues!

At this point you should find lots of them :-)

## Using the plugin

To enable the plugin on the command line use:
  ```
  wireshark -Xlua_script:<path to the script> <pcap file>
  or
  tshark -Xlua_script:<path to the script> -r <pcap file> [filter]
  ```
ex:
  ```
  wireshark -Xlua_script:./128t_plugin.lua ./128t_udp_cript.pcap
  
  tshark -V -Xlua_script:./128t_plugin.lua -r ./128t_udp_cript.pcap '128t_over_udp'
  
  tshark -V -Xlua_script:./128t_plugin.lua -r ./128t_udp_cript.pcap '128t.src_tenant == "voip1"'
  ```

On tshark we can use "-T fields -e <filed name>" and display only selected 128t fields like:
  ```
tshark -V -r ./128T_newMetaData.pcap -Y 128t.src_peer=="Sumauma" -Tfields -e 128t.src_peer -e 128t.src_tenant -e 128t.src_ipv4 -e 128t.dst_ipv4 -e 128t.service
Wireshark version = 	2.4.6
Lua version = 	Lua 5.2
128T plugin version = 	0.9 (Beta 2)
128T plugin enabled!

Sumauma	tntVlan600	172.31.11.157	172.31.18.20	toCore600
  ```
  
To add the plugin to wireshark's init files so it will be automatically executed:

On **Windows**:
```
Edit the file: 
   /<Program files>/wireshark/init.lua
At the end of the file add the following line:
   dofile(DATA_DIR.."128t_plugin.lua")
Copy the 128t_plugin.lua file to:
   /<Program files>/wireshark/
```

On **OSX**
```
Edit:
   ~/.config/wireshark/init.lua
Add the a line at the end of the file with the full path for the lua script, like:
   dofile("/src/128t_plugin/metadata-dissector/128t_plugin.lua")
```

On **Linux** 
```
Edit:
   ~/.wireshark/init.lua
Add the a line at the end of the file with the full path for the lua script, like:
   dofile("/src/128t_plugin/metadata-dissector/128t_plugin.lua")
```

To disable the plugin, just remove the line from init.lua

## Known issues

+ SVR over TCP is not supported (actually not tested)
+ You might see some "false positives" SVR packets as the verification code is still very simple
+ IPv6 metadata fields are still missing

This release was tested against 128T 3.2.5 metadata, it might also work with older releases..

Please report any issues, false positives or problems you might find!
(If possible also sendme the offending .pcap file.)

## Possible improvements

+ Add wireshark preferences to enable/disable the plugin
+ Lua has a prolem where it is not possible to add multiple heuristic dissectors with the same name, because of that I was forced to create those two protocol names:
   - "128t_over_tcp"
   - "128t_over_udp"

  When I find a way to fix that we will be able to use only "128t" as the filter.

