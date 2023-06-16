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

struct wl_value_string *luaW_check_value_string(lua_State *L, int arg)
{
    struct wl_value_string **ptr = luaL_checkudata(L, arg, "wslua.ValueString");
    return *ptr;
}

void luaW_push_value_string(lua_State *L, struct wl_value_string *str)
{
    struct wl_value_string **ptr = NEWUSERDATA(L, struct wl_value_string *, "wslua.ValueString");
    *ptr = str;
}

struct wl_value_string *luaW_opt_value_string(lua_State *L, int idx)
{
    if (lua_isnoneornil(L, idx))
        return NULL;
    return luaW_check_value_string(L, idx);
}

static int wl_val_to_str(lua_State *L)
{
    lua_Integer value = luaL_checkinteger(L, 1);
    struct wl_value_string *vs = luaW_check_value_string(L, 2);
    const char *fmt = luaL_checkstring(L, 3);
    char *str = val_to_str_wmem(NULL, value, vs->data.vals, fmt);
    lua_pushstring(L, str);
    wmem_free(NULL, str);
    return 1;
}

static int wl_value_string_new(lua_State *L)
{
    value_string vs;
    lua_Integer value;
    const gchar *strptr;

    luaL_checktype(L, 1, LUA_TTABLE);
    int len = luaL_len(L, 1);
    value_string *vs_array = wmem_alloc0_array(NULL, value_string, len + 1);

    lua_pushnil(L);
    for (int i = 0; lua_next(L, 1) != 0 && i < len; i++) {
        luaL_checktype(L, -1, LUA_TTABLE);
        lua_geti(L, -1, 1);
        value = lua_tointeger(L, -1);
        lua_geti(L, -2, 2);
        strptr = lua_tostring(L, -1);

        vs.value = value;
        vs.strptr = wmem_strdup(NULL, strptr);
        vs_array[i] = vs;
        lua_pop(L, 3);
    }

    struct wl_value_string *lvalstr = wmem_new(NULL, struct wl_value_string);
    lvalstr->type = WL_VALS;
    lvalstr->data.vals = vs_array;
    luaW_push_value_string(L, lvalstr);
    return 1;
}

static int wl_value_string_gc(lua_State *L)
{
    struct wl_value_string *ptr = luaW_check_value_string(L, 1);

    for (value_string *vs = ptr->data.vals; vs->strptr != NULL; vs++)
        wmem_free(NULL, (char *)vs->strptr);
    wmem_free(NULL, ptr);
    return 0;
}

void luaW_push_vals(lua_State *L, const value_string *ptr)
{
    int n;

    lua_pushcfunction(L, wl_value_string_new);
    lua_newtable(L);
    for(n = 0; ptr && ptr->strptr != NULL; n++, ptr++) {
        lua_newtable(L);
        lua_pushinteger(L, ptr->value);
        lua_seti(L, -2, 1);
        lua_pushstring(L, ptr->strptr);
        lua_seti(L, -2, 2);
        lua_seti(L, -2, n);
    }
    lua_call(L, 1, 1);
}

static const value_string _proto_checksum_vals[] = {
    { PROTO_CHECKSUM_E_BAD,        "Bad"  },
    { PROTO_CHECKSUM_E_GOOD,       "Good" },
    { PROTO_CHECKSUM_E_UNVERIFIED, "Unverified" },
    { PROTO_CHECKSUM_E_NOT_PRESENT, "Not present" },
    { 0,        NULL }
};

static const struct luaL_Reg wl_value_string_m[] = {
    { "__gc", wl_value_string_gc },
    { NULL, NULL }
};

static const struct luaL_Reg wl_value_string_f[] = {
    { "vals", wl_value_string_new },
    { "val_to_str", wl_val_to_str },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_value_string(lua_State *L)
{
    luaW_newmetatable(L, "wslua.ValueString", wl_value_string_m);
    luaL_setfuncs(L, wl_value_string_f, 0);

    luaW_push_vals(L, _proto_checksum_vals);
    lua_setfield(L, -2, "cksum_vals");
}
