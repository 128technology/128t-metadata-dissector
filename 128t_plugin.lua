myVersion = "0.9 (Beta 2)"
-----------------------------------------------------------------
-----------------------------------------------------------------
-- Wireshark 128T SVR plugin
--
-- Please report any issues!
--
-- Author: Paulo Machado <pmachado@128technology.com>
--
-----------------------------------------------------------------
-----------------------------------------------------------------
--
-- To enable the plugin on the command line use:
--   wireshark -Xlua_script:<path to the script> <pcap file>
-- ex:
--   wireshark -Xlua_script:./128t_plugin.lua ./128t_udp_cript.pcap
--
-- You can do the same on tshark!
-----------------------------------------------------------------

print("Wireshark version = ", get_version())
print("Lua version = ", _VERSION)
print("128T plugin version = ", myVersion);

local my128t_proto_gen = Proto("__128T","128T SVR Metadata")
local my128t_proto_udp = Proto("128T_over_UDP","128T SVR Metadata (UDP)")
local my128t_proto_tcp = Proto("128T_over_TCP","128T SVR Metadata (TCP)")

local function debug(level, msg)
   print(msg)
end

function my128t_proto_udp.dissector(tvbuf,pktinfo,root)
	dissector(tvbuf,pktinfo,root,my128t_proto_udp)
end

function my128t_proto_tcp.dissector(tvbuf,pktinfo,root)
   	dissector(tvbuf,pktinfo,root,my128t_proto_tcp)
end

local f_dir      = ProtoField.uint16("128t.dir", "Session Key", base.DEC, { [2] ="Forward", [4] = "Reverse"})
local f_proto    = ProtoField.uint8("128t.proto", "Protocol", base.DEC, { [1] ="128t_icmp", [6] = "128t_tcp", [17] = "128t_udp"})
local f_src_ipv4 = ProtoField.ipv4("128t.src_ipv4", "IP")
local f_src_port = ProtoField.uint16("128t.src_port", "Port")
local f_dst_ipv4 = ProtoField.ipv4("128t.dst_ipv4", "IP")
local f_dst_port = ProtoField.uint16("128t.dst_port", "Port")
local f_src_tenant = ProtoField.string("128t.src_tenant", "Src Tenant")
local f_dst_tenant = ProtoField.string("128t.dst_tenant", "Dst Service")
local f_src_peer   = ProtoField.string("128t.src_peer", "Src Peer")
local f_src_peer_sec_name   = ProtoField.string("128t.src_peer_sec_name", "Src Peer")
local f_dst_peer   = ProtoField.string("128t.dst_peer", "Src Peer")
local f_service    = ProtoField.string("128t.service", "Service")
local f_cookie              = ProtoField.bytes("128t.cookie", "cookie")
local f_meta_version        = ProtoField.uint8("128t.meta_version", "Metadata version")
local f_meta_header_length  = ProtoField.uint16("128t.meta_header_length", "Metadata header length", base.UNIT_STRING, {" bytes"})
local f_payload_length      = ProtoField.uint16("128t.payload_length", "Metadata payload length", base.UNIT_STRING, {" bytes"})

-- generic fields
local f_length  = ProtoField.uint16("128t.len", "Length")
local f_bytes   = ProtoField.bytes("128t.bytes", "Bytes")
local f_ipv4    = ProtoField.ipv4("128t.bytes", "IPv4")
local f_string  = ProtoField.string("128t.bytes", "String")

-- Metadata Field types
local f_type    = ProtoField.uint16("128t.type", "Field",  base.DEC, {
  [2] ="Forward",
  [4] = "Reverse",
  [6] = "Session UUID",
  [7] = "Source Tenant",
  [8] = "Global Interface ID",
  [10] = "Service",
  [12] = "TCP Syn packet",
  [13] = "Load Balancer number of sessions",
  [14] = "Source Peer",
  [15] = "Source Peer Security Name",
  [16] = "Security Identifier",
  [17] = "Destination Peer",
})

my128t_proto_gen.fields = { f_dir, f_proto, f_src_tenant, f_dst_tenant, f_src_ipv4, f_dst_ipv4, f_src_port, f_dst_port,
 f_src_peer, f_src_peer_sec_name, f_dst_peer, f_service,
 f_cookie, f_meta_version, f_meta_header_length, f_payload_length,
 f_type, f_length, f_bytes, f_ipv4, f_string,
 }

-- default handler for unknown types
function type_default(pos, subtree, tvbuf, my128t_proto)
   local t = subtree:add(f_type, tvbuf(pos,2))
   t:add(f_length, tvbuf(pos+2,2))
   if (tvbuf(pos+2,2):uint() > 0) then
       t:add(f_bytes, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
   end
end

function type_session_key(pos, subtree, tvbuf, my128t_proto)
   --local original_tree = subtree:add(f_dir,tvbuf(20,2))
   local src = 'Src: '..tostring(tvbuf(pos+4,4):ipv4())..":"..tostring(tvbuf(pos+12,2):uint())
   local dst = 'Dst: '..tostring(tvbuf(pos+8,4):ipv4())..":"..tostring(tvbuf(pos+14,2):uint())
   local original_tree = subtree:add('['..src..'] ['..dst..'] ')
   local t = original_tree:add('Src: '..tostring(tvbuf(pos+4,4):ipv4())..":"..tostring(tvbuf(pos+12,2):uint())):set_generated()
   t:add(f_src_ipv4, tvbuf(pos+4,4))
   t:add(f_src_port, tvbuf(pos+12,2))
   t = original_tree:add('Dst: '..tostring(tvbuf(pos+8,4):ipv4())..":"..tostring(tvbuf(pos+14,2):uint())):set_generated()
   t:add(f_dst_ipv4, tvbuf(pos+8,4))
   t:add(f_dst_port, tvbuf(pos+14,2))
   subtree:add(f_proto, tvbuf(pos+16,1))
   subtree:add(f_dir,tvbuf(20,2))
end

local t_128t_dissect = {
  [2]   = type_session_key,

  [4]   = type_session_key,

  [7]   = function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_src_tenant, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
   end,

  [10]  = function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_service, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
   end,

  [13]  =  function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add('Loadbalance sessions: '..tostring(tvbuf(pos+4,tvbuf(pos+2,2):uint())))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
      if (tvbuf(pos+2,2):uint() > 0) then
         t:add(f_bytes, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      end
   end,

  [14]  =  function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_src_peer, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
   end,

  [15]  =  function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_src_peer_sec_name, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
   end,

  [17]  = function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_dst_peer, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
  end,

  [19]  = function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_string, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
  end,

}

function find_dissect(type)
  if (t_128t_dissect[type]) then
     -- debug(1, 't_128t_dissect found!')
     return t_128t_dissect[type]
  end
  -- debug(1,'type_default!')
  return type_default
end

function dissector(tvbuf,pktinfo,root,my128t_proto)

	-- We are using TLV format for the metadata
	-- in general that means
	-- 2 bytes for type
	-- 2 bytes for length (of the next data field)
	-- x bytes for the actual data

        -- Main metadata header
        local subtree = root:add(my128t_proto,tvbuf(0,16+tvbuf(10,2):uint()+tvbuf(14,2):uint()),"128T SVR Metadata")
        local t = subtree:add(tvbuf(pos,15),"Metadata")
        t:add(f_cookie,tvbuf(0,8))
        t:add(f_meta_version,tvbuf(8,2):bitfield(0,4))        -- 0x1 by default on the first 4 bits
        t:add(f_meta_header_length,tvbuf(8,2):bitfield(4,12)) -- header lenght on the last 12 bits
        local header_length = tvbuf(8,2):bitfield(4,12)
        t:add(f_payload_length,tvbuf(10,2))
        local payload_length = tvbuf(10,2):uint()
        local pos=12
        -- Starting TLV fields
        while (pos < header_length+payload_length)
        do
           local type = tvbuf(pos,2):uint()
	   -- type = 11 indicates payload encrypted!
           -- should stop parsing
           if (type ~= 11) then
              find_dissect(type)(pos, subtree, tvbuf, my128t_proto)
           else
              find_dissect(type)(pos, subtree, tvbuf, my128t_proto)
              subtree:add('Encrypted metadata fields')
              break
           end
           pos=pos+4+tvbuf(pos+2,2):uint()
        end
end

function dissect_underlay(tvbuf,pktinfo,root,src_port,dst_port,proto)
	local bytes = tostring(tvbuf():bytes())

        -- fake UDP header w/correct length
	local fake_udp_hdr = string.format('%04x%04x%04x0000',src_port,dst_port, (bytes:len()/2)+8)
	bytes = fake_udp_hdr .. bytes

	-- pass pseudo UDP packet to dissector, where wireshark
	-- heuristic will hopefully pick it up
	buf = ByteArray.tvb(ByteArray.new(bytes), "[Generated]")

        Dissector.get(string.lower(proto)):call(buf, pktinfo, root)
end

local function heur_dissect_128t_udp(tvbuf,pktinfo,root)
    --debug(1,'heur UDP')
    return heur_dissect_128t(tvbuf,pktinfo,root,'UDP')
end

local function heur_dissect_128t_tcp(tvbuf,pktinfo,root)
    --debug(1,'heur TCP')
    return heur_dissect_128t(tvbuf,pktinfo,root,'TCP')
end

function heur_dissect_128t(tvbuf,pktinfo,root,transport)
    -- tostring(tvbuf():bytes())
    -- debug(1,pktinfo.curr_proto)
    if (tvbuf(0):len() > 8 and tostring(tvbuf(0,8):bytes()) == "4C48DBC6DDF6670C") then
       if (transport=='UDP') then
          my128t_proto_udp.dissector(tvbuf(0):tvb(),pktinfo,root)
       elseif (transport=='TCP') then
          my128t_proto_tcp.dissector(tvbuf(0):tvb(),pktinfo,root)
       end
       return true
    end
    return false
end

--success, eth_dissector = pcall(Dissector.get, "eth_withoutfcs")
--if not success or not eth_dissector then
--    eth_dissector = Dissector.get("eth")
--end

-- verify tshark/wireshark version is new enough - needs to be 2.2+
local major, minor, micro = 0, 0, 0
if get_version then
    major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
    if not major then
        major, minor, micro = 0, 0, 0
    end
end

my_major=2
my_minor=2
if (tonumber(major) < my_major or ((tonumber(major) == my_major) and (tonumber(minor) < my_minor))) then
    local mm=tostring(my_major).."."..tostring(my_minor)
    print("\n\nSorry, but your Wireshark/Tshark version is too old for this script!\n"..
          "This script needs Wireshark/Tshark version "..mm.." or higher.\n" )
    print("128T plugin disabled!");
    error("\n\nSorry, but your Wireshark/Tshark version is too old for this script!\n"..
          "This script needs Wireshark/Tshark version "..mm.." or higher.\n" )
else
  -- now register that heuristic dissector into the udp heuristic list
  --my128t_proto:register_heuristic("udp",heur_dissect_128t)
  my128t_proto_udp:register_heuristic("udp",heur_dissect_128t_udp)
  my128t_proto_tcp:register_heuristic("tcp",heur_dissect_128t_tcp)
  print("128T plugin enabled!");
end
