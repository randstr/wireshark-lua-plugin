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

#include "wauxlib.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static int l_msghandler(lua_State *L)
{
    const char *msg = lua_tostring(L, 1);
    luaL_traceback(L, L, msg, 1);
    return 1;
}

void luaW_call(lua_State *L, int nargs, int nres)
{
    int status, base;

    base = lua_gettop(L) - nargs;
    lua_pushcfunction(L, l_msghandler);
    lua_insert(L, base);
    status = lua_pcall(L, nargs, nres, base);
    lua_remove(L, base);  /* remove message handler from the stack */
    if (status != LUA_OK) {
        lua_error(L);
    }
}

void *luaW_newuserdata(lua_State *L, size_t size, const char *meta) {
    void *p = lua_newuserdata(L, size);
    luaL_setmetatable(L, meta);
    return p;
}

void luaW_argerrorf(lua_State *L, int arg, const char *fmt, ...)
{
    va_list args;
    char buf[64];

    va_start(args, fmt);
    vsnprintf(buf, 64, fmt, args);
    va_end(args);
    luaL_argerror(L, arg, buf);
    abort(); //not reached
}

void luaW_newmetatable(lua_State *L, const char *tname, const luaL_Reg *lreg)
{
    luaL_newmetatable(L, tname);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    if (lreg != NULL) {
        luaL_setfuncs(L, lreg, 0);
    }
    lua_pop(L, 1);
}

int luaW_getsubtable(lua_State *L, int idx, const char *fname, int narr, int nrec)
{
    int t = lua_getfield(L, idx, fname);
    if (t == LUA_TTABLE)
        return 1;
    lua_pop(L, 1);
    lua_createtable(L, narr, nrec);
    lua_pushvalue(L, -1);
    lua_setfield(L, idx, fname);
    return 0;
}

int luaW_string_format(lua_State *L, int nargs)
{
    lua_getglobal(L, "string");
    lua_getfield(L, -1, "format");
    lua_remove(L, -2);
    lua_rotate(L, 1, -nargs);
    lua_call(L, nargs, 1);
    return 1;
}

int luaW_string_format_pos(lua_State *L, int idx, int nargs)
{
    lua_getglobal(L, "string");
    lua_getfield(L, -1, "format");
    lua_remove(L, -2);
    lua_insert(L, idx);
    lua_call(L, nargs + 1, 1); /* include format string */
    return 1;
}

/* append value at the top of the stack to the array at idx */
int luaW_insert(lua_State *L, int idx)
{
    int len = luaL_len(L, idx);
    lua_seti(L, idx, len + 1);
    return len + 1;
}
