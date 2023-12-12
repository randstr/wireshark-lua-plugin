
local ws = require("wireshark")

-- Optional script information
local script_info = {
    version = "1.2.3",
    spdx_id = "Your-SPDX-ID-Here",
    home_url = "Your-URL-Here",
    blurb = "Short description for this dissector module",
}

local proto
local handle

local ICMP6_ECHO_REQUEST = 128
local ICMP6_ECHO_REPLY = 129

local type_vals = ws.vals{
    {ICMP6_ECHO_REQUEST, "Echo (ping) request"},
    {ICMP6_ECHO_REPLY, "Echo (ping) reply"},
}

local hf = {
    type = {"Type", "icmpv6_.type",
                ws.FT_UINT8, ws.BASE_DEC, type_vals, 0,
                "Indicates the type of message"},
    code = {"Code", "icmpv6_.code",
                ws.FT_UINT8, ws.BASE_DEC, nil, 0,
                "Aditional level of granularity for type"},
    cksum = {"Checksum", "icmpv6_.checksum",
                ws.FT_UINT16, ws.BASE_HEX, nil, 0,
                "Used to detect data corruption in the ICMPv6 message and \z
                parts of the IPv6 header"},
    cksum_status = {"Checksum Status", "icmpv6_.checksum.status",
                ws.FT_UINT8, ws.BASE_NONE, ws.cksum_vals },
    echo_id = {"Identifier", "icmpv6_.echo.identifier",
                ws.FT_UINT16, ws.BASE_HEX, nil, 0,
                "An identifier to aid in matching with Request and Reply"},
    echo_seq_number = {"Sequence", "icmpv6_.echo.sequence_number",
                ws.FT_UINT16, ws.BASE_DEC, nil, 0,
                "A sequence number to aid in matching Echo Replies to this \z
                Echo Request"},
}

local ett = {
    proto = true,
}

local ei = {
    cksum = {"icmpv6_.checksum_bad",
                ws.PI_CHECKSUM, ws.PI_WARN, "Bad checksum"},
}

local function cksum_icmpv6(src, dst, reported_length, payload)
    return ws.in_cksum(src:pack(), dst:pack(),
                        string.pack(">I4I4", reported_length, 58),
                        payload)
end

local function dissect_icmpv6(tvb, pinfo, tree, cinfo)
    local pi
    local ti, item
    local offset = ws.Offset.new()
    local typ
    local nxt, nxt_tvb

    cinfo:set_protocol("ICMPv6")
    cinfo:clear_info()

    pi = tree:add_protocol(proto, tvb, offset, -1)
    ti = pi:add_subtree(ett.proto)

    typ = ti:add_item_ret(hf.type, tvb, offset, 1)
    offset:next()

    cinfo:add_str(ws.COL_INFO, ws.val_to_str(typ, type_vals, "Unknown (%d)"))

    ti:add_item(hf.code, tvb, offset, 1)
    offset:next()

    local length = tvb:captured_length()
    local reported_length = tvb:reported_length()
    if not pinfo.fragmented and length >= reported_length and
                                            not pinfo.in_error_pkt then
        local computed_cksum = cksum_icmpv6(pinfo.src, pinfo.dst,
                        reported_length, tvb:get_bytes(0, reported_length))
        ti:add_checksum(tvb, offset, hf.cksum, hf.cksum_status, ei.cksum,
                        pinfo, computed_cksum, ws.ENC_BIG_ENDIAN,
                        ws.PROTO_CHECKSUM_VERIFY|ws.PROTO_CHECKSUM_IN_CKSUM) 
    else
        item = ti:add_checksum(tvb, offset, hf.cksum, hf.cksum_status,
                        ei.cksum, pinfo, 0, ws.ENC_BIG_ENDIAN,
                        ws.PROTO_CHECKSUM_NO_FLAGS);
        if pinfo.in_error_pkt then
            item:append_text(" [in ICMP error packet]")
        else
            item:append_text(" [fragmented datagram]")
        end
    end
    offset:next()

    if typ == ICMP6_ECHO_REQUEST or typ == ICMP6_ECHO_REPLY then
        local identifier, sequence

        identifier = ti:add_item_ret(hf.echo_id, tvb, offset, 2)
        offset:next()
        sequence = ti:add_item_ret(hf.echo_seq_number, tvb, offset, 2)
        offset:next()

        cinfo:append_fstr(ws.COL_INFO, " id=0x%04x, seq=%u",
                            identifier, sequence)
    end

    ws.call_data_dissector(tvb:new_subset_remaining(offset), pinfo, ti);

    return tvb:reported_length()
end

local function register_icmpv6()
    proto = ws.proto_register_protocol(
                            "Internet Control Message Protocol (Lua)",
                            "ICMPv6 (Lua)", "icmpv6_")

    ws.proto_register_field_array(proto, hf)
    ws.proto_register_subtree_array(ett)

    local expert = ws.expert_register_protocol(proto)
    ws.expert_register_field_array(expert, ei)

    handle = ws.register_dissector(proto, "icmpv6_", dissect_icmpv6)
end

local function handoff_icmpv6()
    ws.dissector_add_uint("ip.proto", 58, handle)
end

local M = {}

M.register_protocol = register_icmpv6
M.register_handoff = handoff_icmpv6
M.script_info = script_info

return M
