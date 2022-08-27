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

expert_module_t *luaW_check_expert_module(lua_State *L, int arg)
{
    expert_module_t **ptr = luaL_checkudata(L, arg, "wslua.ExpertModule");
    return *ptr;
}

ei_register_info *luaW_check_expert_register_info(lua_State *L, int arg)
{
    ei_register_info **ptr = luaL_checkudata(L, arg, "wslua.ExpertRegisterInfo");
    return *ptr;
}

void luaW_push_expert_module(lua_State *L, expert_module_t *module)
{
    expert_module_t **ptr = NEWUSERDATA(L, expert_module_t *, "wslua.ExpertModule");
    *ptr = module;
}

void luaW_push_expert_register_info(lua_State *L, ei_register_info *ei)
{
    ei_register_info **ptr = NEWUSERDATA(L, ei_register_info *, "wslua.ExpertRegisterInfo");
    *ptr = ei;
}

/***
 * An ExpertModule class.
 * @type ExpertModule
 */

/***
 * @section end
 */

/***
 * An ExpertRegisterInfo class.
 * @type ExpertRegisterInfo
 */

/***
 * @section end
 */

/***
 * Create a new ExpertRegisterInfo
 * @function new_expert_register_info
 * @tparam tab array the expert info value to register
 * @treturn ExpertRegisterInfo the expert register info object
 */
/* receives array on top of stack (-1, +1) */
static int  wl_new_expert_register_info(lua_State *L)
{
    const char *name;
    int group;
    int severity;
    const char *summary;

    /* name */
    lua_geti(L, -1, 1);
    name = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    /* group */
    lua_geti(L, -1, 2);
    group = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    /* severity */
    lua_geti(L, -1, 3);
    severity = luaL_checkinteger(L, -1);
    lua_pop(L, 1);

    /* summary */
    lua_geti(L, -1, 4);
    summary = luaL_checkstring(L, -1);
    lua_pop(L, 1);

    ei_register_info *ei = wmem_new(wmem_epan_scope(), ei_register_info);
    ei->ids = wmem_new(wmem_epan_scope(), expert_field);
    ei->ids->ei = -1;
    ei->ids->hf = -1;
    ei->eiinfo.name = wmem_strdup(wmem_epan_scope(), name);
    ei->eiinfo.group = group;
    ei->eiinfo.severity = severity;
    ei->eiinfo.summary = wmem_strdup(wmem_epan_scope(), summary);
    ei->eiinfo.id = 0;
    ei->eiinfo.protocol = NULL;
    ei->eiinfo.orig_severity = 0;
    ei->eiinfo.hf_info.p_id = 0;
    ei->eiinfo.hf_info.hfinfo.name = "Expert Info";
    ei->eiinfo.hf_info.hfinfo.abbrev = NULL;
    ei->eiinfo.hf_info.hfinfo.type = FT_NONE;
    ei->eiinfo.hf_info.hfinfo.display = BASE_NONE;
    ei->eiinfo.hf_info.hfinfo.strings = NULL;
    ei->eiinfo.hf_info.hfinfo.bitmask = 0;
    ei->eiinfo.hf_info.hfinfo.blurb = NULL;
    ei->eiinfo.hf_info.hfinfo.id = -1;
    ei->eiinfo.hf_info.hfinfo.parent = 0;
    ei->eiinfo.hf_info.hfinfo.ref_type = HF_REF_TYPE_NONE;
    ei->eiinfo.hf_info.hfinfo.same_name_prev_id = -1;
    ei->eiinfo.hf_info.hfinfo.same_name_next = NULL;

    ei_register_info **ptr = NEWUSERDATA(L, ei_register_info *, "wslua.ExpertRegisterInfo");
    *ptr = ei;
    return 1;
}

/***
 * Register an expert info module associated with proto
 * @function register_protocol
 * @tparam Protocol proto the protocol to register
 * @treturn ExpertModule the expert module object
 */
static int wl_expert_register_protocol(lua_State *L)
{
    int proto = luaW_check_protocol(L, 1);

    expert_module_t **ptr = NEWUSERDATA(L, expert_module_t *, "wslua.ExpertModule");
    *ptr = expert_register_protocol(proto);
    return 1;
}

/***
 * Register a expert info array. The table passed can contain RegisterExpertInfo
 * objects or plain Lua arrays. Array elements are converted into ExpertRegisterInfo *inplace*.
 * @function register_field_array
 * @tparam {[string]=ExpertRegisterInfo,...} fields table with ExpertRegisterInfo objects
 */
static int wl_expert_register_field_array(lua_State *L)
{
    expert_module_t *module = *(expert_module_t **)luaL_checkudata(L, 1, "wslua.ExpertModule");
    luaL_checktype(L, 2, LUA_TTABLE);

    ei_register_info *reg;
    int value_type;

    BEGIN_STACK_DEBUG(L);
    /* iterate table and replace each array value with an ExpertRegisterInfo userdata */
    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
        luaL_checktype(L, -2, LUA_TSTRING);
        value_type = lua_type(L, -1);
        if (value_type == LUA_TTABLE) {
            /* Convert array to ExpertRegisterInfo */
            lua_pushcfunction(L, wl_new_expert_register_info);
            lua_insert(L, -2);
            lua_call(L, 1, 1);
        }
        reg = *(ei_register_info **)luaL_checkudata(L, -1, "wslua.ExpertRegisterInfo");
        expert_register_field_array(module, reg, 1);
        /* stack: key(string), value(ExpertRegisterInfo) */
        if (value_type == LUA_TTABLE) {
            /* need to push key duplicate on stack to preserve iteration */
            lua_pushvalue(L, -2);
            lua_insert(L, -2);
            /* stack: key, key, value */
            lua_settable(L, 2);
        }
    }
    END_STACK_DEBUG(L, 0);
    return 0;
}

/***
 * Add an expert info
 * @function add_info
 * @tparam ProtoInfo pinfo the pinfo object
 * @tparam ProtoItem pi the proto_item object
 * @tparam ExpertRegisterInfo ei the expert info object
 */
static int wl_expert_add_info(lua_State *L)
{
    packet_info *pinfo = luaW_check_pinfo(L, 1);
    proto_item *pi = luaW_check_proto_item(L, 2);
    ei_register_info *ei = luaW_check_expert_register_info(L, 3);

    expert_add_info(pinfo, pi, ei->ids);
    return 0;
}

/***
 * Add an expert info with a format string
 * @function add_info_format
 * @tparam ProtoInfo pinfo the pinfo object
 * @tparam ProtoItem pi the proto_item object
 * @tparam EiRegisterInfo ei the expert info object
 * @string format the format string
 * @param ... variable arguments
 */
static int wl_expert_add_info_format(lua_State *L)
{
    packet_info *pinfo = luaW_check_pinfo(L, 1);
    proto_item *pi = luaW_check_proto_item(L, 2);
    ei_register_info *ei = luaW_check_expert_register_info(L, 3);
    const char *fmt = luaL_optstring(L, 4, NULL);

    const char *str = NULL;
    if (fmt != NULL) {
        luaW_string_format(L, lua_gettop(L) - 3);
        str = lua_tostring(L, -1);
    }

    expert_add_info_format(pinfo, pi, ei->ids, "%s", str);
    return 0;
}

static const struct luaL_Reg wl_expert_module_m[] = {
    { NULL, NULL }
};

static const struct luaL_Reg wl_expert_register_info_m[] = {
    { NULL, NULL }
};

static const struct luaL_Reg wl_expert_f[] = {
    { "new_expert_register_info", wl_new_expert_register_info },
    { "expert_register_protocol", wl_expert_register_protocol },
    { "expert_register_field_array", wl_expert_register_field_array },
    { "expert_add_info", wl_expert_add_info },
    { "expert_add_info_format", wl_expert_add_info_format },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_expert(lua_State *L)
{
    luaW_newmetatable(L, "wslua.ExpertModule", wl_expert_module_m);
    luaW_newmetatable(L, "wslua.ExpertRegisterInfo", wl_expert_register_info_m);
    luaL_setfuncs(L, wl_expert_f, 0);
}
