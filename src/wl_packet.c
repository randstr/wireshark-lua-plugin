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

struct wl_dissector_data {
    lua_State *L;
    int lua_dissector_ref;
};

dissector_handle_t luaW_check_dissector_handle(lua_State *L, int arg)
{
    dissector_handle_t *ptr = luaL_checkudata(L, arg, "wslua.DissectorHandle");
    return *ptr;
}

void luaW_push_dissector_handle(lua_State *L, dissector_handle_t handle)
{
    dissector_handle_t *ptr = NEWUSERDATA(L, dissector_handle_t, "wslua.DissectorHandle");
    *ptr = handle;
}

static int wslua2_call_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, void *dissector_data)
{
    lua_State *L;
    int offset, err, exc;
    const char *msg;

    struct wl_dissector_data *ldata = dissector_data;
    
    L = ldata->L;
    lua_rawgeti(L, LUA_REGISTRYINDEX, ldata->lua_dissector_ref);
    luaW_push_tvbuff(L, tvb);
    luaW_push_pinfo(L, pinfo);
    luaW_push_proto_tree(L, tree);
    luaW_push_cinfo(L, pinfo->cinfo);
    err = lua_pcall(L, 4, 1, 0);
    if (err != LUA_OK) {
        if (lua_isinteger(L, -1)) {
            exc = (int)lua_tointeger(L, -1);
            THROW(exc);
        }
        else if (lua_isstring(L, -1)) {
            msg = lua_tostring(L, -1);
            THROW_MESSAGE(DissectorError, msg);
        }
        else {
            THROW(DissectorError);
        }
        ws_assert_not_reached();
    }
    offset = (int)lua_tointeger(L, -1);
    return offset;
}

/***
 * Register a dissector
 * @function register_dissector
 * @tparam Protocol proto a protocol
 * @string name dissector name
 * @func dissector dissector function
 * @treturn DissectorHandle a dissector handle
 */
static int wl_register_dissector(lua_State *L)
{
    dissector_handle_t handle;

    int proto = luaW_check_protocol(L, 1);
    const char *name = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    struct wl_dissector_data *ldata = wmem_new(wmem_epan_scope(), struct wl_dissector_data);
    ldata->L = L;
    ldata->lua_dissector_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    handle = register_dissector_with_data(name, wslua2_call_dissector, proto, ldata);
    luaW_push_dissector_handle(L, handle);
    return 1;
}

/***
 * Try to dissector a uint value
 * @function dissector_try_uint
 * @string table dissector table name
 * @int value pattern to match
 * @tparam TVBuff tvb tvb to dissect
 * @tparam PacketInfo pinfo a packet info
 * @tparam ProtoTree tree a proto tree
 * @treturn int length of dissected tvbuff
 */
static int wl_dissector_try_uint(lua_State *L)
{
    dissector_table_t dt;
    gint len;

    const char *table = luaL_checkstring(L, 1);
    guint32 val = luaL_checkinteger(L, 2);
    tvbuff_t *tvb = luaW_check_tvbuff(L, 3);
    packet_info *pinfo = luaW_check_pinfo(L, 4);
    proto_tree *tree = luaW_check_proto_tree(L, 5);

    dt = find_dissector_table(table);
    len = dissector_try_uint(dt, val, tvb, pinfo, tree);
    lua_pushinteger(L, len);
    return 1;
}

static int wl_call_data_dissector(lua_State *L)
{
    tvbuff_t *tvb = luaW_check_tvbuff(L, 1);
    packet_info *pinfo = luaW_check_pinfo(L, 2);
    proto_tree *tree = luaW_check_proto_tree(L, 3);
    call_data_dissector(tvb, pinfo, tree);
    return 0;
}

/***
 * Add a dissector handle to a table
 * @function dissector_add_uint
 * @string table dissector table name
 * @int pattern pattern to match
 * @tparam DissectorHandle handle dissector handle
 */
static int wl_dissector_add_uint(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    guint32 pattern = (guint32)luaL_checkinteger(L, 2);
    dissector_handle_t handle = luaW_check_dissector_handle(L, 3);

    dissector_add_uint(name, pattern, handle);
    return 0;
}

static const struct luaL_Reg wl_packet_f[] = {
    { "register_dissector", wl_register_dissector },
    { "dissector_add_uint", wl_dissector_add_uint },
    { "dissector_try_uint", wl_dissector_try_uint },
    { "call_data_dissector", wl_call_data_dissector },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_packet(lua_State *L)
{
    luaW_newmetatable(L, "wslua.DissectorHandle", NULL);
    luaL_setfuncs(L, wl_packet_f, 0);
}
