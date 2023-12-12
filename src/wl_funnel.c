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

#include "wl_funnel.h"

#include <epan/funnel.h>

/***
 * @module wireshark
 */

static int g_lua_print_ref = LUA_NOREF;

static const char *l_error_msg(int code)
{
    switch (code) {
        case LUA_ERRSYNTAX: return "syntax error during precompilation";
        case LUA_ERRMEM:    return "memory allocation error";
        case LUA_ERRRUN:    return "runtime error";
        case LUA_ERRERR:    return "error while running the message handler";
        default:            break; /* Should not happen. */
    }
    return "unknown error";
}

static int wl_funnel_console_eval(const char *console_input,
                                        char **error_ptr,
                                        char **error_hint,
                                        void *callback_data)
{
    ws_noisy("Console input: %s", console_input);
    lua_State *_L = callback_data;
    int lcode;

    lcode = luaL_loadstring(_L, console_input);
    if (lcode != LUA_OK) {
        ws_debug("luaL_loadstring(): %s (%d)", l_error_msg(lcode), lcode);
        if (error_hint) {
            *error_hint = xstrdup(l_error_msg(lcode));
        }
        return -1;
    }

    lcode = lua_pcall(_L, 0, LUA_MULTRET, 0);
    if (lcode != LUA_OK) {
        ws_debug("lua_pcall(): %s (%d)", l_error_msg(lcode), lcode);
        if (error_hint) {
            *error_hint = xstrdup(l_error_msg(lcode));
        }
        /* If we have an error message return it. */
        if (error_ptr && !lua_isnil(_L, -1)) {
            *error_ptr = xstrdup(lua_tostring(_L, -1));
        }
        return 1;
    }

    ws_noisy("Success");
    return 0;
}

/* Receives C print function pointer as first upvalue. */
/* Receives C print function data pointer as second upvalue. */
static int wl_console_print(lua_State *_L)
{
    void (*gui_print_func)(const char *, void *) = lua_touserdata(_L, lua_upvalueindex(1));
    void *gui_print_ptr = lua_touserdata(_L, lua_upvalueindex(2));

    wmem_strbuf_t *strbuf = wmem_strbuf_create(NULL);
    const char *repr;

    /* Print arguments. */
    for (int i = 1; i <= lua_gettop(_L); i++) {
            repr = luaL_tolstring(_L, i, NULL);
            if (i > 1)
                wmem_strbuf_append_c(strbuf, '\t');
            wmem_strbuf_append(strbuf, repr);
            lua_pop(_L, 1);
    }
    wmem_strbuf_append_c(strbuf, '\n');
    gui_print_func(strbuf->str, gui_print_ptr);
    wmem_strbuf_destroy(strbuf);
    return 0;
}

// Replace lua print function with a custom print function.
// We will place the original function in the Lua registry and return the reference.
static void wl_funnel_console_open(void (*gui_print_func)(const char *, void *),
                                        void *gui_print_ptr,
                                        void *callback_data)
{
    lua_State *L = callback_data;

    /* Store original print value in the registry (even if it is nil). */
    lua_getglobal(L, "print");
    g_lua_print_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    /* Set new "print" function (to output to the GUI) */
    /* Push upvalues */
    lua_pushlightuserdata(L, gui_print_func);
    lua_pushlightuserdata(L, gui_print_ptr);
    // Push closure
    lua_pushcclosure(L, wl_console_print, 2);
    lua_setglobal(L, "print");
}

// Restore original Lua print function. Clean state.
static void wl_funnel_console_close(void *callback_data)
{
    lua_State *L = callback_data;

    /* Restore the original print function. */
    lua_rawgeti(L, LUA_REGISTRYINDEX, g_lua_print_ref);
    lua_setglobal(L, "print");
    /* Release reference */
    luaL_unref(L, LUA_REGISTRYINDEX, g_lua_print_ref);
    g_lua_print_ref = LUA_NOREF;
}

void wl_funnel_init(void)
{
    /* Register Lua's console menu (in the GUI) */
    funnel_register_console_menu(LUA_VERSION,
                                    wl_funnel_console_eval,
                                    wl_funnel_console_open,
                                    wl_funnel_console_close,
                                    g_lua, NULL);
}
