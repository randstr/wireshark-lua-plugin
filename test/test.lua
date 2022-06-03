
lu = require('luaunit')
ws = require('wireshark')

function testVals()
    local vals = ws.vals{
        {1, "first value"},
        {2, "second (last) value"},
    }
    lu.assertEquals(ws.val_to_str(1, vals, "Unknown (%d)"), "first value")
    lu.assertEquals(ws.val_to_str(2, vals, "Unknown (%d)"), "second (last) value")
    lu.assertEquals(ws.val_to_str(3, vals, "Unknown (%d)"), "Unknown (3)")
end

function testTvb()
    local b = "123456789"
    local l = 100
    local tvb = ws.tvb_new_from_data(b, l)

    lu.assertEquals(tvb:get_bytes(1, 1), "2")
    lu.assertEquals(tvb:get_bytes(0, -1), b)
    lu.assertEquals(tvb:get_bytes(1, -1), string.sub(b, 2))
    lu.assertEquals(tvb:captured_length(), string.len(b))
    lu.assertEquals(tvb:reported_length(), l)
end

function testAddr()
    local ipv4 = ws.Address.ipv4("192.168.1.2")
    local ipv6 = ws.Address.ipv6("2001::2")
    local addr

    addr = ws.Address.new(ipv4)
    lu.assertEquals(tostring(addr), "192.168.1.2")
    addr = ws.Address.new(ipv6)
    lu.assertEquals(tostring(addr), "2001::2")
    addr = ws.Address.new(ws.AT_IPv4, "1.1.1.1")
    lu.assertEquals(tostring(addr), "1.1.1.1")
end

function testPreference()
    local proto = ws.proto_register_protocol("Wslua2 Test Preference", "Wslua2 Pref", "wslua2")
    local prefs = ws.prefs.register_protocol(proto)
    ws.prefs.register_bool_preference(prefs, "test_wslua", "title", "Wslua2 test suite", true)

    lu.assertTrue(prefs.test_wslua())
end

function testPinfo()
    local pinfo = ws.pinfo.new()

    pinfo.fragmented = true
    lu.assertEquals(pinfo.fragmented, true)
end

return lu.LuaUnit.run()
