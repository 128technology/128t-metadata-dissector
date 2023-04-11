myVersion = "1.0.0"
-----------------------------------------------------------------
-----------------------------------------------------------------
-- Wireshark 128T SVR plugin
--
-- Please report any issues!
--
-- Author: Paulo Machado <pmachado@sumaumatelecom.com.br>
--
-----------------------------------------------------------------
-----------------------------------------------------------------
--
-- To enable the plugin on the command line use:
--   wireshark -Xlua_script:<path to the script> <pcap file>
-- ex:
--   wireshark -Xlua_script:./128t_plugin.lua ./128t_udp.pcap 
-- 
-- You can do the same on tshark!
--   -Y will filter for the specific udp or tcp stream
--   -O will expand only the SVR section of the packte
--   -V would expand everything including other layers like TCP/UDP/Ethernet/etc
-- ex:
--   tshark -Xlua_script:./128t_plugin.lua -O "128t_over_tcp" -Y "128t_over_tcp" -r ./128t_tcp.pcap 
--
-----------------------------------------------------------------

print("Wireshark version = ", get_version())
print("Lua version = ", _VERSION)
print("128T plugin version = ", myVersion);
print("LUA MODULES:\n",(package.path:gsub("%;","\n\t")),"\n\nC MODULES:\n",(package.cpath:gsub("%;","\n\t")))

local my_info = {
   version = "1.0.0",
   author = "Paulo Machado <pmachado@sumaumatelecom.com.br>",
   repository = "https://github.com/128technology/128t-metadata-dissector"
}
set_plugin_info(my_info)

local my128t_proto_gen = Proto("__128T","128T SVR Metadata")

local my128t_proto_udp = Proto("128T_over_UDP","128T SVR Metadata (UDP)")
local my128t_proto_tcp = Proto("128T_over_TCP","128T SVR Metadata (TCP)")

local function debug(level, msg)
   print(msg)
end

function my128t_proto_udp.dissector(tvbuf,pktinfo,root)
   pktinfo.cols.protocol = my128t_proto_udp.name
	dissector(tvbuf,pktinfo,root,my128t_proto_udp)
end

function my128t_proto_tcp.dissector(tvbuf,pktinfo,root)
   pktinfo.cols.protocol = my128t_proto_tcp.name
   dissector(tvbuf,pktinfo,root,my128t_proto_tcp)
end

--
-- adding filed name and subtree description text
--
local f_metadata   = ProtoField.bytes("128t.metadata", "Metadata")
local f_dir        = ProtoField.uint16("128t.dir", "Session Key", base.DEC, { [2] ="Forward", [4] = "Reverse"})
local f_proto      = ProtoField.uint8("128t.proto", "Protocol", base.DEC, { [1] ="128t_icmp", [6] = "128t_tcp", [17] = "128t_udp"})
local f_src_ipv4   = ProtoField.ipv4("128t.src_ipv4", "IP")
local f_src_port   = ProtoField.uint16("128t.src_port", "Port")
local f_dst_ipv4   = ProtoField.ipv4("128t.dst_ipv4", "IP")
local f_dst_port   = ProtoField.uint16("128t.dst_port", "Port")
local f_src_tenant = ProtoField.string("128t.src_tenant", "Src Tenant")
local f_dst_tenant = ProtoField.string("128t.dst_tenant", "Dst Service")
local f_src_peer   = ProtoField.string("128t.src_peer", "Src Peer")
local f_src_peer_path_id   = ProtoField.string("128t.src_peer_path_id", "Src Peer Path ID")
local f_src_peer_sec_name  = ProtoField.string("128t.src_peer_sec_name", "Src Peer - Security Name")
local f_dst_peer           = ProtoField.string("128t.dst_peer", "Src Peer")
local f_service            = ProtoField.string("128t.service", "Service")
local f_cookie             = ProtoField.bytes("128t.cookie", "cookie")
local f_meta_version       = ProtoField.new("Metadata version", "128t.meta_version", ftypes.UINT16, {""}, base.UNIT_STRING, 0xF000, "metadata version")
local f_meta_header_length = ProtoField.new("Metadata header length", "128t.meta_header_length", ftypes.UINT16, {" bytes"}, base.UNIT_STRING, 0x0FFF, "metadata header length")
local f_meta_header        = ProtoField.bytes("128t.meta_header", "Metadata header")
local f_payload_length     = ProtoField.uint16("128t.payload_length", "Metadata payload length", base.UNIT_STRING, {" bytes"})
local f_payload_header     = ProtoField.bytes("128t.payload_header", "Payload")
local f_frag_header        = ProtoField.bytes("128t.frag_header", "Fragment Header")
local f_frag_extended_id   = ProtoField.bytes("128t.frag_extended_id", "Fragment Extended ID")
local f_frag_original_id   = ProtoField.bytes("128t.frag_original_id", "Fragment Original ID")
local f_frag_flags_0       = ProtoField.new("Fragment Flags", "128t.frag_flags_0", ftypes.UINT8, {[0]="reserved", [1]="reserved"}, base.DEC, 128, "flags: reserved")
local f_frag_flags_1       = ProtoField.new("Fragment Flags", "128t.frag_flags_1", ftypes.UINT8, {[0]="none", [1]="dont fragment "}, base.DEC, 64, "flags: dont fragment")
local f_frag_flags_2       = ProtoField.new("Fragment Flags", "128t.frag_flags_2", ftypes.UINT8, {[0]="no other fragments", [1]="more fragments"}, base.DEC, 32, "flags: more fragments")
local f_frag_offset        = ProtoField.new("Fragment Offset", "128t.frag_offset", ftypes.UINT16, {{0,0,"none"}, {1,0x1FFF," eight-byte segments in this fragment"}}, base.RANGE_STRING, 0x1FFF, "flags: offset")
local f_frag_large_seen_frag = ProtoField.bytes("128t.frag_large_seen_frag", "Largest Seen Fragment")
local f_service_sessions_number = ProtoField.uint64("128t.service_sessions_number", "Number of Sessions in Service")
local f_modify_req_header = ProtoField.bytes("128t.modify_req_header", "Modify Request Header")
local f_modify_req_f      = ProtoField.new("Modify Request Header F", "128t.modify_req_header_f", ftypes.UINT16, {}, base.DEC, 0x8000)
local f_modify_req_d      = ProtoField.new("Modify Request Header D", "128t.modify_req_header_d", ftypes.UINT16, {}, base.DEC, 0x4000)
local f_modify_req_res    = ProtoField.new("Modify Request Header RES", "128t.modify_req_header_res", ftypes.UINT16, {}, base.DEC, 0x3000)
local f_modify_req_seq    = ProtoField.new("Modify Request Sequence Number", "128t.modify_req_header_seq", ftypes.UINT16, {}, base.DEC, 0xFF)
-- Note any new fields must be added to 'my128t_proto_gen.fields' below!!!!

--
-- generic fields
--
local f_length       = ProtoField.uint16("128t.len", "Length")
local f_bytes        = ProtoField.bytes("128t.bytes", "Bytes")
local f_ipv4         = ProtoField.ipv4("128t.bytes", "IPv4")
local f_string       = ProtoField.string("128t.bytes", "String")
local f_orig_payload = ProtoField.bytes("128t.bytes", "Payload")

--
-- Metadata Field types
-- Text will be used as the filed "Type" inside each field's own subitem
--
local f_type    = ProtoField.uint16("128t.type", "Type",  base.DEC, { 
  [1] ="Fragment", 
  [2] ="Forward", 
  [4] = "Reverse", 
  [6] = "Session UUID", 
  [7] = "Source Tenant", 
  [8] = "Global Interface ID", 
  [10] = "Service", 
  [11] = "Session Encrypted",   
  [12] = "TCP Syn packet", 
  [13] = "Number of sessions", 
  [14] = "Source Peer", 
  [15] = "Source Peer Security Name", 
  [16] = "Security Identifier",
  [17] = "Destination Peer", 
  [19] = "Source Peer Path ID", 
  [28] = "Modify Request"
})

my128t_proto_gen.fields = { 
 f_metadata, f_dir, f_proto, f_src_tenant, f_dst_tenant, f_src_ipv4, f_dst_ipv4, f_src_port, f_dst_port, 
 f_src_peer, f_src_peer_path_id, f_src_peer_sec_name, f_dst_peer, f_service,
 f_cookie, f_meta_version, f_meta_header_length, f_meta_header, f_payload_length, f_payload_header, 
 f_frag_header, f_frag_extended_id, f_frag_original_id, f_frag_flags_0, f_frag_flags_1, f_frag_flags_2, f_frag_offset, f_frag_large_seen_frag, 
 f_type, f_length, f_bytes, f_ipv4, f_string, 
 f_service_sessions_number,
 f_modify_req_header, f_modify_req_f, f_modify_req_d, f_modify_req_res, f_modify_req_seq,
 } 

function type_default(pos, subtree, tvbuf, my128t_proto)
   -- Default handler for unknown types
   -- will take the name from f_type when available and will display the content as "bytes"
   -- this assumes that the TLV is a basic one: 
   -- Type 2bytes | Length 2bytes | Value xbytes
   -- anything other than that will probably generate an error, in that case we need to add the new type

   local t = subtree:add(f_type, tvbuf(pos,2))
   t:add(f_length, tvbuf(pos+2,2))
   if (tvbuf(pos+2,2):uint() > 0) then
       t:add(f_bytes, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
   end
end

function type_session_key(pos, subtree, tvbuf, my128t_proto)
   subtree:add(f_dir,tvbuf(pos,2))
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
end

function basic_tlv(field_type)
  	-- We are using TLV format for the metadata
	-- in general that means
	-- 2 bytes for type
	-- 2 bytes for length (of the next data field)
	-- x bytes for the actual data

   return function(pos, subtree, tvbuf, my128t_proto)
     local t = subtree:add(field_type, tvbuf(pos+4,tvbuf(pos+2,2):uint()))
     t:add(f_type, tvbuf(pos,2))
     t:add(f_length, tvbuf(pos+2,2))
   end

end

--
-- These functions are used to dissect specialized fields
-- avoiding the default handler that will display "bytes" 
-- This will also use correct types like strings or ipv4, etc.
--
local t_128t_dissect = {
  [1]  = function (pos, subtree, tvbuf, my128t_proto)
      local t = subtree:add(f_frag_header, tvbuf(pos,14),"Fragment")
      t:add(f_type, tvbuf(pos,2))
      t:add(f_length, tvbuf(pos+2,2))
      t:add(f_frag_extended_id, tvbuf(pos+4,4)) -- Extended ID
      t:add(f_frag_original_id, tvbuf(pos+8,2)) -- Original ID
      t:add(f_frag_flags_0, tvbuf(pos+10,1)) -- Flags bit 0
      t:add(f_frag_flags_1, tvbuf(pos+10,1)) -- Flags bit 1
      t:add(f_frag_flags_2, tvbuf(pos+10,1)) -- Flags bit 2
      t:add(f_frag_offset, tvbuf(pos+10,2)) -- Fragment Offset
      t:add(f_frag_large_seen_frag, tvbuf(pos+12,2)) -- Largest Seen Fragment
  end,

  [2]   = type_session_key, 
  [4]   = type_session_key, 

  [7]   = basic_tlv(f_src_tenant), 
  [10]  = basic_tlv(f_service), 
  [13]  = basic_tlv(f_service_sessions_number),
  [14]  = basic_tlv(f_src_peer),
  [15]  = basic_tlv(f_src_peer_sec_name),
  [17]  = basic_tlv(f_dst_peer),
  [19]  = basic_tlv(f_src_peer_path_id),

  [28]  = function (pos, subtree, tvbuf, my128t_proto)
   local t = subtree:add(f_modify_req_header, tvbuf(pos,2),"Modify Request Header")
   t:add(f_type, tvbuf(pos,2))
   t:add(f_length, tvbuf(pos+2,2))
   t:add(f_modify_req_f, tvbuf(pos+4,2)) -- bit 0
   t:add(f_modify_req_d, tvbuf(pos+4,2)) -- bit 1
   t:add(f_modify_req_res, tvbuf(pos+4,2)) -- Flags bit 2,3
   t:add(f_modify_req_seq, tvbuf(pos+4,2), tvbuf(pos+4,2):bitfield(4,12)) -- sequence number in the last 12 bits
end,

}

function find_dissect(type)
  if (t_128t_dissect[type]) then
      return t_128t_dissect[type]
  end
  return type_default
end

--
-- This is the actual dissector function in charge of
-- generating the information displayed in wireshark
--
function dissector(tvbuf,pktinfo,root,my128t_proto)
   -- Main metadata header
   local header_length = tvbuf(8,2):bitfield(4,12) -- header length on the last 12 bits
   local payload_length = tvbuf(10,2):uint()
   local subtree = root:add(my128t_proto,tvbuf(0,header_length+payload_length),"128T SVR Metadata")
   local t = subtree:add("Metadata header length: ",tvbuf(8,2),header_length,"bytes"):set_generated()
   t:add(f_meta_header,tvbuf(0,header_length))
   t:add(f_cookie,tvbuf(0,8))
   t:add(f_meta_version,tvbuf(8,2))  -- 0x1 by default on the first 4 bits
   t:add(f_meta_header_length,tvbuf(8,2))
   local t = subtree:add(f_payload_length,tvbuf(10,2))
   if (payload_length > 0) then
     t:add(f_payload_header,tvbuf(header_length,payload_length))
   end

   local pos=12
   local type
   local length = header_length

   --
   -- starting guaranteed unencrypted section of metadata
   --
   while (pos < length)
   do
     type = tvbuf(pos,2):uint()
     find_dissect(type)(pos, subtree, tvbuf, my128t_proto)
     pos=pos+4+tvbuf(pos+2,2):uint()
   end

   --
   -- starting possibly encrypted section of metadata
   --
   type = tvbuf(pos,2):uint()
   if (payload_length>0 and (type == 0 or type > 50)) then 
      -- If type is outside the known range than we are seeing encrypted TLV or 
      -- we hit the packet payload, in this case we ignore everything from here.
      -- This is not perfect but I don't know a better way to detect encryption yet.
      -- This is just a guess (we will have some false negatives!)
      local t = root:add(f_bytes, 
                         tvbuf(pos,payload_length),
                         "",
                         "Possibly encrypted metadata: "..payload_length.." bytes")
      t:add(f_bytes, tvbuf(pos,payload_length))
      pos = pos + payload_length
   end

   length = header_length+payload_length
   while (pos < length)
   do
      type = tvbuf(pos,2):uint()
      find_dissect(type)(pos, subtree, tvbuf, my128t_proto)
      pos=pos+4+tvbuf(pos+2,2):uint()
   end

   --
   -- marking the orignal packet payload being transported
   --
   local t = root:add(f_orig_payload, 
                      tvbuf(header_length+payload_length,tvbuf:len()-(header_length+payload_length)),
                      "Original Payload",
                      tvbuf:len()-(header_length+payload_length),
                      "bytes")
   t:add(f_length, tvbuf:len()-(header_length+payload_length)):set_generated()
   t:add(f_bytes, tvbuf(header_length+payload_length,tvbuf:len()-(header_length+payload_length)))
   return true
end

local function heur_dissect_128t_udp(tvbuf,pktinfo,root)
   return heur_dissect_128t(tvbuf,pktinfo,root,'UDP')
end

local function heur_dissect_128t_tcp(tvbuf,pktinfo,root)
   return heur_dissect_128t(tvbuf,pktinfo,root,'TCP')
end

--- 
-- NOTE: Some TCP packets might not be dissected when marked as 'error' by wireshark like 
--       out-of-order packets for instance.
--
--       In that case, to allow them to be dissected go to:
--       Edit >> Preferences >> Protocols >> TCP and uncheck:
--       "Do not call subdissectors for error packets"
--       Also uncheck:
--       "Allow subdissector to reassemble TCP stream"
--
function heur_dissect_128t(tvbuf,pktinfo,root,transport)
   --debug(1,pktinfo.number)
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

-- verify tshark/wireshark version is good enough - needs to be 2.2+
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
   -- Console error
   print("\n\nSorry, but your Wireshark/Tshark version is too old for this script!\n"..
         "This script needs Wireshark/Tshark version "..mm.." or higher.\n" )
   print("128T plugin disabled!");
   -- GUI alert
   error("\n\nSorry, but your Wireshark/Tshark version is too old for this script!\n"..
         "This script needs Wireshark/Tshark version "..mm.." or higher.\n" )
else

   -- now register that heuristic dissector into the udp heuristic list
   my128t_proto_udp:register_heuristic("udp",heur_dissect_128t_udp)
   my128t_proto_tcp:register_heuristic("tcp",heur_dissect_128t_tcp)

   local tcp_table = DissectorTable.get("tcp.port")
   tcp_table:add_for_decode_as(my128t_proto_tcp)
   local udp_table = DissectorTable.get("udp.port")
   udp_table:add_for_decode_as(my128t_proto_udp)

   print("128T plugin enabled!");
end
