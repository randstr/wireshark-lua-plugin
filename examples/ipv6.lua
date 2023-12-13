
local ws = require("wireshark")

-- Optional script information
local script_info = {
    version = "1.2.3",
    spdx_id = "Your-SPDX-ID-Here",
    home_url = "Your-URL-Here",
    blurb = "Short description for this dissector module",
}

local log = ws.util.new_log_domain("IPv6-Lua")

local ipv6 = {}

ipv6.hf = {
    version = {"Version", "ipv6_.version",
                ws.FT_UINT8, ws.BASE_DEC, nil, 0xF0},
    tclass = {"Traffic Class", "ipv6_.tclass",
                ws.FT_UINT32, ws.BASE_HEX, nil,0x0FF00000},
    flow = {"Flow Label", "ipv6_.flow",
                ws.FT_UINT32, ws.BASE_HEX, nil, 0x000FFFFF},
    plen = {"Payload Length", "ipv6_.plen",
                ws.FT_UINT16, ws.BASE_DEC},
    nxt = {"Next Header", "ipv6_.nxt",
                ws.FT_UINT8, ws.BASE_DEC},
    hlim = {"Hop Limit", "ipv6_.hlim",
                ws.FT_UINT8, ws.BASE_DEC},
    src = {"Source", "ipv6_.src",
                ws.FT_IPv6, ws.BASE_NONE, nil, 0,
                "Source IPv6 Address"},
    dst = {"Destination", "ipv6_.dst",
                ws.FT_IPv6, ws.BASE_NONE, nil, 0,
                "Destination IPv6 Address"},
    addr = {"Source or Destination Address", "ipv6_.addr",
                ws.FT_IPv6}
}

ipv6.ett = {
    proto = true,
    tclass = true,
}

ipv6.ei = {
    bogus_version = {"ipv6_.bogus_ip_version",
                        ws.PI_MALFORMED, ws.PI_ERROR, "Bogus IP version"},
}

-- 'pinfo' reference is valid with packet scope
local function dissect_ipv6(tvb, pinfo, tree, cinfo)
    local hf = ipv6.hf
    local ett = ipv6.ett
    local ei = ipv6.ei
    local pi, ti
    local nxt, src, dst

    cinfo:set_protocol("IPv6")
    cinfo:clear_info()

    local offset = ws.Offset.new()

    pi = tree:add_protocol(ipv6.proto, tvb, offset, 40)
    ti = pi:add_subtree(ett.proto)

    -- version / traffic class / flow label
    local version, item = ti:add_item_ret(hf.version, tvb, offset, 1)
    if version ~= 6 then
        ws.expert.add_info(pinfo, item, ei.bogus_version)
    end
    ti:add_item(hf.tclass, tvb, offset, 4)
    ti:add_item(hf.flow, tvb, offset, 4)
    offset:next()
    -- payload length
    ti:add_item(hf.plen, tvb, offset, 2)
    offset:next()
    -- next header
    nxt = ti:add_item_ret(hf.nxt, tvb, offset, 1)
    offset:next()
    -- hop limit
    ti:add_item(hf.hlim, tvb, offset, 1)
    offset:next()
    -- source address
    src = ti:add_item_ret(hf.src, tvb, offset, 16)
    ti:add_item(hf.addr, tvb, offset, 16, nil,
                    {hidden = true, generated = true})
    offset:next()
    -- destination address
    dst = ti:add_item_ret(hf.dst, tvb, offset, 16)
    ti:add_item(hf.addr, tvb, offset, 16, nil,
                    {hidden = true, generated = true})
    offset:next()

    pinfo:set_net_addr(src, dst)

    if (ipv6.prefs.summary_in_tree()) then
        pi:append_text(string.format(", Src: %s, Dst: %s", src, dst))
    end

    ws.dissector_try_uint("ip.proto", nxt,
                            tvb:new_subset_remaining(offset), pinfo, tree)

    log:debug("Finished dissecting %d bytes", tvb:captured_length())

    return tvb:captured_length()
end

local function register_ipv6()
    ipv6.proto = ws.proto_register_protocol(
                            "Internet Protocol Version 6 (Lua)",
                            "IPv6 (Lua)", "ipv6_")

    ws.proto_register_field_array(ipv6.proto, ipv6.hf)
    ws.proto_register_subtree_array(ipv6.ett)

    ipv6.expert = ws.expert_register_protocol(ipv6.proto)
    ws.expert_register_field_array(ipv6.expert, ipv6.ei)

    ipv6.handle = ws.register_dissector(ipv6.proto, "ipv6_", dissect_ipv6)

    ipv6.prefs = ws.prefs.register_protocol(ipv6.proto)
    ws.prefs.register_bool_preference(ipv6.prefs,
                "summary_in_tree", "Show IPv6 summary in protocol tree",
                "Whether the IPv6 summary line should be shown in \z
                the protocol tree", true)
end

local function handoff_ipv6()
    ws.dissector_add_uint("ethertype", 0x86DD, ipv6.handle)
end

local M = {}

M.register_protocol = register_ipv6
M.register_handoff = handoff_ipv6
M.script_info = script_info

return M
