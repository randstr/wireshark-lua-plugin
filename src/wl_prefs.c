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
 * @module wireshark.prefs
 */

struct wl_preference {
    char *name;
    char *title;
    char *description;
    unsigned type;
    union {
        gboolean boolean;
    } value;
};

module_t *luaW_check_pref_module(lua_State *L, int arg)
{
    module_t **ptr = luaL_checkudata(L, arg, "wslua.PrefModule");
    return *ptr;
}

void luaW_push_pref_module(lua_State *L, module_t *module)
{
    module_t **ptr = NEWUSERDATA(L, module_t *, "wslua.PrefModule");
    *ptr = module;
}

struct wl_preference *luaW_check_preference(lua_State *L, int arg)
{
    struct wl_preference **ptr = luaL_checkudata(L, arg, "wslua.Preference");
    return *ptr;
}

void luaW_push_preference(lua_State *L, struct wl_preference *pref)
{
    struct wl_preference **ptr = NEWUSERDATA(L, struct wl_preference *, "wslua.Preference");
    *ptr = pref;
}

/***
 * A Preference class.
 * @type Preference
 */

/***
 * Get a boolean from a preference
 * @function get
 * @return value the preference value
 */
static int wl_preference_call(lua_State *L)
{
    struct wl_preference *pref = luaW_check_preference(L, 1);
    switch (pref->type) {
        case LUA_TBOOLEAN:
            lua_pushboolean(L, pref->value.boolean);
            break;
        default:
            ws_assert_not_reached();
    }
    return 1;
}

/***
 * String representation
 * @function __tostring
 */
static int wl_preference_tostring(lua_State *L)
{
    struct wl_preference *pref = luaW_check_preference(L, 1);
    switch (pref->type) {
        case LUA_TBOOLEAN:
            if (pref->value.boolean)
                lua_pushliteral(L, "wslua.Preference: true");
            else
                lua_pushliteral(L, "wslua.Preference: false");
            break;
        default:
            ws_assert_not_reached();
    }
    return 1;
}

/***
 * @section end
 */

/***
 * A Preference module class.
 * @type PrefModule
 */
 
static int wl_pref_module_index(lua_State *L)
{
    luaL_checkudata(L, 1, "wslua.PrefModule");
    const char *key = luaL_checkstring(L, 2);

    lua_getuservalue(L, 1);
    lua_getfield(L, -1, key);
    return 1;
}

/***
 * @section end
 */


static int wl_prefs_register_protocol(lua_State *L)
{
    int proto = luaW_check_protocol(L, 1);
    module_t *module = prefs_register_protocol(proto, NULL);
    luaW_push_pref_module(L, module);
    lua_newtable(L);
    lua_setuservalue(L, -2);
    return 1;
}

/***
 * Create a new boolean preference
 * @function bool
 * @string name the name
 * @string title the title
 * @string description the description
 * @bool value the preference default value
 */
static int wl_prefs_register_bool_preference(lua_State *L)
{
    module_t *module = luaW_check_pref_module(L, 1);
    const char *name = luaL_checkstring(L, 2);
    const char *title = luaL_checkstring(L, 3);
    const char *description = luaL_checkstring(L, 4);
    bool value = lua_toboolean(L, 5);

    lua_getuservalue(L, 1);

    struct wl_preference *pref = wmem_new(wmem_epan_scope(), struct wl_preference);
    pref->name = wmem_strdup(wmem_epan_scope(), name);
    pref->title = wmem_strdup(wmem_epan_scope(), title);
    pref->description = wmem_strdup(wmem_epan_scope(), description);
    pref->type = LUA_TBOOLEAN;
    pref->value.boolean = value;
    prefs_register_bool_preference(module, pref->name, pref->title, pref->description, &pref->value.boolean);
    luaW_push_preference(L, pref);
    lua_setfield(L, -2, name);
    return 0;
}

static const struct luaL_Reg wl_preference_m[] = {
    { "__call", wl_preference_call },
    { "__tostring", wl_preference_tostring },
    { NULL, NULL }
};

static const struct luaL_Reg wl_pref_module_m[] = {
    { "__index", wl_pref_module_index },
    { NULL, NULL }
};

static const struct luaL_Reg wl_prefs_f[] = {
    { "register_protocol", wl_prefs_register_protocol },
    { "register_bool_preference", wl_prefs_register_bool_preference },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_prefs(lua_State *L)
{
    luaW_newmetatable(L, "wslua.PrefModule", wl_pref_module_m);
    luaW_newmetatable(L, "wslua.Preference", wl_preference_m);
    luaL_newlib(L, wl_prefs_f);
    lua_setfield(L, -2, "prefs");
}
