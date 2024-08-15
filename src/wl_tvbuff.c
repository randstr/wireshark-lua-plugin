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

tvbuff_t *luaW_check_tvbuff(lua_State *L, int arg)
{
    tvbuff_t **ptr = luaL_checkudata(L, arg, "wslua.TVBuff");
    return *ptr;
}

void luaW_push_tvbuff(lua_State *L, tvbuff_t *tvb)
{
    tvbuff_t **ptr = NEWUSERDATA(L, tvbuff_t *, "wslua.TVBuff");
    *ptr = tvb;
}

/***
 * A TVBuff class.
 * @type TVBuff
 */

/***
 * Get a uint8_t from a tvbuff
 * @function uint8
 * @int offset the offset
 * @treturn int a uint8_t
 */
static int wl_tvb_get_guint8(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    int offset = luaW_check_offset_toint(L, 2);
    uint8_t val = tvb_get_guint8(tvb, offset);
    lua_pushinteger(L, val);
    return 1;
}

static int wl_tvb_get_ntohs(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    int offset = luaW_check_offset_toint(L, 2);
    uint16_t val = tvb_get_ntohs(tvb, offset);
    lua_pushinteger(L, val);
    return 1;
}

static int wl_tvb_get_bytes(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    lua_Integer offset = luaW_check_offset_toint(L, 2);
    lua_Integer length = luaL_checkinteger(L, 3);
    if (length == -1) {
        length = tvb_captured_length_remaining(tvb, offset);
    }
    else if (length < 0) {
        luaL_error(L, "length must be positive or -1, was %d", length);
    }
    const uint8_t *ptr = tvb_get_ptr(tvb, offset, length);
    lua_pushlstring(L, (const char *)ptr, length);
    return 1;
}

/***
 * Get an IPv4 address from a tvbuff
 * @function get_ipv4
 * @int offset the offset
 * @treturn int an ip address
 */
static int wl_tvb_get_ipv4(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    int offset = luaW_check_offset_toint(L, 2);
    uint32_t val = tvb_get_ipv4(tvb, offset);
    luaW_push_ipv4(L, val);
    return 1;
}

/***
 * Get an IPv6 address from a tvbuff
 * @function get_ipv6
 * @int offset the offset
 * @treturn bytes a bytes string
 */
static int wl_tvb_get_ipv6(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    int offset = luaW_check_offset_toint(L, 2);
    struct e_in6_addr val;
    tvb_get_ipv6(tvb, offset, &val);
    luaW_push_ipv6(L, &val);
    return 1;
}

/***
 * Return captured length
 * @function captured_length
 * @treturn int the length
 */
static int wl_tvb_captured_length(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    unsigned length = tvb_captured_length(tvb);
    lua_pushinteger(L, length);
    return 1;
}

/***
 * Return reported length
 * @function reported_length
 * @treturn int the length
 */
static int wl_tvb_reported_length(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    unsigned length = tvb_reported_length(tvb);
    lua_pushinteger(L, length);
    return 1;
}

/***
 * Create a tvbuff subset from an existing tvbuff
 * @function new_subset_remaining
 * @int offset the offset
 * @treturn TVBuff the new tvbuff
 */
static int wl_tvb_new_subset_remaining(lua_State *L)
{
    tvbuff_t *backing = luaW_check_tvbuff(L, 1);
    int backing_offset = luaW_check_offset_toint(L, 2);
    tvbuff_t *tvb = tvb_new_subset_remaining(backing, backing_offset);
    luaW_push_tvbuff(L, tvb);
    return 1;
}

static int wl_tvb_new_real_data(lua_State *L)
{
    size_t length;
    const char *data = lua_tolstring(L, 1, &length);
    lua_Integer reported_length = lua_tointeger(L, 2);

    /* removes terminating null from data */
    tvbuff_t *tvb = tvb_new_real_data((uint8_t *)data, length, reported_length);
    luaW_push_tvbuff(L, tvb);
    return 1; 
}

static const struct luaL_Reg wl_tvbuff_f[] = {
    { "tvb_new_from_data", wl_tvb_new_real_data },
    { NULL, NULL }
};

static const struct luaL_Reg wl_tvbuff_m[] = {
    { "uint8", wl_tvb_get_guint8 },
    { "ntohs", wl_tvb_get_ntohs },
    { "get_bytes", wl_tvb_get_bytes },
    { "get_ipv4", wl_tvb_get_ipv4 },
    { "get_ipv6", wl_tvb_get_ipv6 },
    { "captured_length", wl_tvb_captured_length },
    { "reported_length", wl_tvb_reported_length },
    { "new_subset_remaining", wl_tvb_new_subset_remaining },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_tvbuff(lua_State *L)
{
    luaW_newmetatable(L, "wslua.TVBuff", wl_tvbuff_m);
    luaL_setfuncs(L, wl_tvbuff_f, 0);
}
