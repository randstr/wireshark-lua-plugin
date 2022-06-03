/*
 * Copyright 2017-2022, João Valverde <j@v6e.pt>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wslua-int.h"

/***
 * @module wireshark
 */

guint32 luaW_check_ipv4(lua_State *L, int arg)
{
    guint32 *ptr = luaL_checkudata(L, arg, "wslua.IPv4");
    return *ptr;
}

struct e_in6_addr *luaW_check_ipv6(lua_State *L, int arg)
{
    struct e_in6_addr *ptr = luaL_checkudata(L, arg, "wslua.IPv6");
    return ptr;
}

address *luaW_check_addr(lua_State *L, int arg)
{
    address *ptr = luaL_checkudata(L, arg, "wslua.Address");
    return ptr;
}

void luaW_push_ipv4(lua_State *L, guint32 ip4)
{
    guint32 *ptr = NEWUSERDATA(L, guint32, "wslua.IPv4");
    *ptr = ip4;
}

void luaW_push_ipv6(lua_State *L, const struct e_in6_addr *ip6)
{
    struct e_in6_addr *ptr = NEWUSERDATA(L, struct e_in6_addr, "wslua.IPv6");
    memcpy(ptr, ip6, sizeof(struct e_in6_addr));
}

void luaW_push_addr(lua_State *L, address *addr)
{
    address *ptr = NEWUSERDATA(L, address, "wslua.Address");
    copy_address(ptr, addr);
}

address_type ftenum_to_addr_type(enum ftenum ft)
{
    switch (ft) {
        case FT_IPv4:
            return AT_IPv4;
        case FT_IPv6:
            return AT_IPv6;
        default:
            break;
    }
    return AT_NONE;
}

/***
 * IPv4 address class.
 * @type IPv4
 */

/***
 * IPv4 string representation
 * @function __tostring
 */
static int wl_ipv4_tostring(lua_State *L)
{
    guint32 ip4 = luaW_check_ipv4(L, 1);
    gchar buf[32];
    ws_inet_ntop4(&ip4, buf, sizeof(buf));
    lua_pushstring(L, buf);
    return 1;
}

/***
 * IPv6 address class.
 * @type IPv6
 */

/***
 * IPv6 string representation
 * @function __tostring
 */
static int wl_ipv6_tostring(lua_State *L)
{
    const struct e_in6_addr *ip6 = luaW_check_ipv6(L, 1);
    gchar buf[WS_INET6_ADDRSTRLEN];
    ws_inet_ntop4(ip6, buf, sizeof(buf));
    lua_pushstring(L, buf);
    return 1;
}

/***
 * Generic address class.
 * @type Address
 */

/***
 * Address string representation
 * @function __tostring
 */
static int wl_addr_tostring(lua_State *L)
{
    address *addr = luaW_check_addr(L, 1);
    gchar buf[64];
    address_to_str_buf(addr, buf, sizeof(buf));
    lua_pushstring(L, buf);
    return 1;
}

static int wl_addr_gc(lua_State *L)
{
    address *addr = luaW_check_addr(L, 1);
    free_address(addr);
    return 0;
}

static int wl_addr_ipv4(lua_State *L)
{
    const char *str = luaL_checkstring(L, 1);
    ws_in4_addr addr;
    errno = 0;
    if (!ws_inet_pton4(str, &addr)){
        luaL_error(L, "error converting IPv4 string '%s': $s", str, strerror(errno));
    }
    luaW_push_ipv4(L, addr);
    return 1;
}

static int wl_addr_ipv6(lua_State *L)
{
    const char *str = luaL_checkstring(L, 1);
    ws_in6_addr addr;
    errno = 0;
    if (!ws_inet_pton6(str, &addr)){
        luaL_error(L, "error converting IPv6 string '%s': $s", str, strerror(errno));
    }
    luaW_push_ipv6(L, &addr);
    return 1;
}

/***
 * Create a new Address
 * @function Address.new
 * @param type the address type
 * @param data the address data
 */
static int wl_addr_new(lua_State *L)
{
    address_type addr_type;
    gsize addr_size;
    union {
        guint32 ip4;
        struct e_in6_addr ip6;
    } addr_data;
    address *addr;

    /* first see if we were passed the tuple (AT_type, "string address")
     * and convert that to an address */
    if (lua_isinteger(L, 1)) {
        addr_type = luaL_checkinteger(L, 1);
        switch (addr_type) {
            case AT_IPv4:
                lua_pushcfunction(L, wl_addr_ipv4);
                break;
            case AT_IPv6:
                lua_pushcfunction(L, wl_addr_ipv6);
                break;
            default:
                return luaL_error(L, "Unknown address type %d", addr_type);
        }
        lua_insert(L, -2);
        luaW_call(L, 1, 1);
    }

    if (luaL_testudata(L, -1, "wslua.IPv4")) {
        addr_type = AT_IPv4;
        addr_size = sizeof(guint32);
        guint32 ip4 = luaW_check_ipv4(L, -1);
        memcpy(&addr_data.ip4, &ip4, addr_size);
    }
    else if (luaL_testudata(L, -1, "wslua.IPv6")) {
        addr_type = AT_IPv6;
        addr_size = sizeof(struct e_in6_addr);
        struct e_in6_addr *ip6 = luaW_check_ipv6(L, -1);
        memcpy(&addr_data.ip6, ip6, addr_size);
    }
    else {
        const char *badarg = luaL_tolstring(L, -1, NULL);
        return luaL_error(L, "Unknown address value %s", badarg);
    }

    addr = g_new(address, 1);
    alloc_address_wmem(NULL, addr, addr_type, addr_size, &addr_data);
    luaW_push_addr(L, addr);
    return 1;
}

static int wl_addr_pack(lua_State *L)
{
    address *addr = luaW_check_addr(L, 1);
    lua_pushlstring(L, addr->data, addr->len);
    return 1;
}

static const struct luaL_Reg wl_ipv4_m[] = {
    { "__tostring", wl_ipv4_tostring },
    { NULL, NULL }
};

static const struct luaL_Reg wl_ipv6_m[] = {
    { "__tostring", wl_ipv6_tostring },
    { NULL, NULL }
};

static const struct luaL_Reg wl_addr_m[] = {
    { "pack", wl_addr_pack },
    { "__tostring", wl_addr_tostring },
    { "__gc", wl_addr_gc },
    { NULL, NULL }
};

static const struct luaL_Reg wl_addr_f[] = {
    { "new", wl_addr_new },
    { "ipv4", wl_addr_ipv4 },
    { "ipv6", wl_addr_ipv6 },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_addr(lua_State *L)
{
    luaW_newmetatable(L, "wslua.IPv4", wl_ipv4_m);
    luaW_newmetatable(L, "wslua.IPv6", wl_ipv6_m);
    luaW_newmetatable(L, "wslua.Address", wl_addr_m);
    luaL_newlib(L, wl_addr_f);
    lua_setfield(L, -2, "Address");
}
