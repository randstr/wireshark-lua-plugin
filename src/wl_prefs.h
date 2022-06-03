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

#ifndef _WL_PREFS_H_
#define _WL_PREFS_H_

module_t *luaW_check_pref_module(lua_State *L, int arg);

void luaW_push_pref_module(lua_State *L, module_t *module);

struct wl_preference *luaW_check_preference(lua_State *L, int arg);

void luaW_push_preference(lua_State *L, struct wl_preference *pref);

void wl_open_prefs(lua_State *L);

#endif
