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

#ifndef __WAUXLIB_H__
#define __WAUXLIB_H__

#include <glib.h>

#include "../lua/src/lua.h"
#include "../lua/src/lualib.h"
#include "../lua/src/lauxlib.h"

#define NEWUSERDATA(L, type, meta) \
    ((type *)luaW_newuserdata(L, sizeof(type), meta))

void luaW_call(lua_State *L, int nargs, int nresults);

void *luaW_newuserdata(lua_State *L, size_t size, const char *meta);

void luaW_argerrorf(lua_State *L, int arg, const char *fmt, ...);

void luaW_newmetatable(lua_State *L, const char *tname, const luaL_Reg *lreg);

int luaW_getsubtable(lua_State *L, int idx, const char *fname, int narr, int nrec);

int luaW_string_format(lua_State *L, int nargs);

int luaW_string_format_pos(lua_State *L, int idx, int nargs);

int luaW_insert(lua_State *L, int idx);

#endif /* __WL_AUXLIB_H__ */
