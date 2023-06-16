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

packet_info *luaW_check_pinfo(lua_State *L, int arg)
{
    packet_info **ptr = luaL_checkudata(L, arg, "wslua.PacketInfo");
    return *ptr;
}

column_info *luaW_check_cinfo(lua_State *L, int arg)
{
    column_info **ptr = luaL_checkudata(L, arg, "wslua.ColumnInfo");
    return *ptr;
}

void luaW_push_pinfo(lua_State *L, packet_info *pinfo)
{
    lua_pushlightuserdata(L, pinfo);
    lua_rawget(L, LUA_REGISTRYINDEX);
}

void luaW_push_cinfo(lua_State *L, column_info *cinfo)
{
    column_info **ptr = NEWUSERDATA(L, column_info *, "wslua.ColumnInfo");
    *ptr = cinfo;
}

/***
 * A PacketInfo class.
 * @type PacketInfo
 */

static int wl_pinfo_set_net_addr(lua_State *L)
{
    packet_info *pinfo = luaW_check_pinfo(L, 1);
    address *src = luaW_check_addr(L, 2);
    address *dst = luaW_check_addr(L, 3);

    copy_address_wmem(pinfo->pool, &pinfo->src, src);
    copy_address_shallow(&pinfo->net_src, &pinfo->src);
    copy_address_wmem(pinfo->pool, &pinfo->dst, dst);
    copy_address_shallow(&pinfo->net_dst, &pinfo->dst);
    return 0;
}
static void l_pinfo_copy_address(lua_State *L,
                            wmem_allocator_t *scope, address *to, int arg)
{
    address *from = luaW_check_addr(L, arg);
    copy_address_wmem(scope, to, from);
}

static int wl_pinfo_index(lua_State *L)
{
    packet_info *pinfo = luaW_check_pinfo(L, 1);
    const char *key = luaL_checkstring(L, 2);

    if (luaL_getmetafield(L, 1, key) == LUA_TNIL) {
        if (strcmp(key, "in_error_pkt") == 0)
            lua_pushboolean(L, pinfo->flags.in_error_pkt);
        else if (strcmp(key, "in_gre_pkt") == 0)
            lua_pushboolean(L, pinfo->flags.in_gre_pkt);
        else if (strcmp(key, "fragmented") == 0)
            lua_pushboolean(L, pinfo->fragmented);
        else if (strcmp(key, "src_port") == 0)
            lua_pushinteger(L, pinfo->srcport);
        else if (strcmp(key, "dst_port") == 0)
            lua_pushinteger(L, pinfo->destport);
        else if (strcmp(key, "src") == 0)
            luaW_push_addr(L, &pinfo->src);
        else if (strcmp(key, "dst") == 0)
            luaW_push_addr(L, &pinfo->dst);
        else if (strcmp(key, "net_src") == 0)
            luaW_push_addr(L, &pinfo->net_src);
        else if (strcmp(key, "net_dst") == 0)
            luaW_push_addr(L, &pinfo->net_dst);
        else if (strcmp(key, "dl_src") == 0)
            luaW_push_addr(L, &pinfo->dl_src);
        else if (strcmp(key, "dl_dst") == 0)
            luaW_push_addr(L, &pinfo->dl_dst);
        else 
            lua_pushnil(L);
    }
    return 1;
}

static int wl_pinfo_newindex(lua_State *L)
{
    packet_info *pinfo = luaW_check_pinfo(L, 1);
    const char *key = luaL_checkstring(L, 2);
    luaL_checkany(L, 3);

    if (strcmp(key, "in_error_pkt") == 0)
        pinfo->flags.in_error_pkt = lua_toboolean(L, -1);
    else if (strcmp(key, "in_gre_pkt") == 0)
        pinfo->flags.in_gre_pkt = lua_toboolean(L, -1);
    else if (strcmp(key, "fragmented") == 0)
        pinfo->fragmented = lua_toboolean(L, -1);
    else if (strcmp(key, "src") == 0)
        l_pinfo_copy_address(L, pinfo->pool, &pinfo->src, -1);
    else if (strcmp(key, "dst") == 0)
        l_pinfo_copy_address(L, pinfo->pool, &pinfo->dst, -1);
    else if (strcmp(key, "net_src") == 0)
        l_pinfo_copy_address(L, pinfo->pool, &pinfo->net_src, -1);
    else if (strcmp(key, "net_dst") == 0)
        l_pinfo_copy_address(L, pinfo->pool, &pinfo->net_dst, -1);
    else if (strcmp(key, "dl_src") == 0)
        l_pinfo_copy_address(L, pinfo->pool, &pinfo->dl_src, -1);
    else if (strcmp(key, "dl_dst") == 0)
        l_pinfo_copy_address(L, pinfo->pool, &pinfo->dl_dst, -1);
    else 
        return luaL_error(L, "wslua.Pinfo does not support setting field %s", key);

    return 0;
}

/***
 * @section end
 */

/***
 * A ColumnInfo class.
 * @type ColumnInfo
 */

static int wl_col_add_string(lua_State *L)
{
    column_info *cinfo = luaW_check_cinfo(L, 1);
    int col = luaL_checkinteger(L, 2);
    const char *str = luaL_checkstring(L, 3);
    col_add_str(cinfo, col, str);
    return 0;
}

static int wl_col_append_fstring(lua_State *L)
{
    column_info *cinfo = luaW_check_cinfo(L, 1);
    int col = luaL_checkinteger(L, 2);
    luaW_string_format_pos(L, 3, lua_gettop(L) - 3);
    const char *str = luaL_checkstring(L, 3);
    col_append_str(cinfo, col, str);
    return 0;
}

/***
 * Set the COL_PROTOCOL string
 * @function set_protocol
 * @string protocol the protocol string
 */
static int wl_col_set_protocol(lua_State *L)
{
    column_info *cinfo = luaW_check_cinfo(L, 1);
    const char *str = luaL_checkstring(L, 2);
    col_set_str(cinfo, COL_PROTOCOL, str);
    return 0;
}

/***
 * Clear the COL_INFO column
 * @function clear_info
 */
static int wl_col_clear_info(lua_State *L)
{
    column_info *cinfo = luaW_check_cinfo(L, 1);
    col_clear(cinfo, COL_INFO);
    return 0;
}

/***
 * @section end
 */

static int wl_pinfo_new(lua_State *L)
{
    packet_info *pinfo = wmem_new0(wmem_epan_scope(), packet_info);
    packet_info **ptr = NEWUSERDATA(L, packet_info *, "wslua.PacketInfo");
    *ptr = pinfo;
    return 1;
}

static const struct luaL_Reg wl_pinfo_m[] = {
    { "set_net_addr", wl_pinfo_set_net_addr },
    { "__index", wl_pinfo_index },
    { "__newindex", wl_pinfo_newindex },
    { NULL, NULL }
};

static const struct luaL_Reg wl_cinfo_m[] = {
    { "add_str", wl_col_add_string },
    { "append_fstr", wl_col_append_fstring },
    { "set_protocol", wl_col_set_protocol },
    { "clear_info", wl_col_clear_info },
    { NULL, NULL }
};

static const struct luaL_Reg wl_pinfo_f[] = {
    { "new", wl_pinfo_new },
    { NULL, NULL }
};
  
/* Receives module on the stack */
void wl_open_pinfo(lua_State *L)
{
    luaW_newmetatable(L, "wslua.PacketInfo", wl_pinfo_m);
    luaW_newmetatable(L, "wslua.ColumnInfo", wl_cinfo_m);
    luaL_newlib(L, wl_pinfo_f);
    lua_setfield(L, -2, "pinfo");
}
