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


#ifndef _WL_VALUE_STRING_H_
#define _WL_VALUE_STRING_H_

enum wl_value_string_e {
    WL_VALS,
    WL_RVALS,
};

struct wl_value_string {
    enum wl_value_string_e type;
    union {
        value_string *vals;
    } data;
};

struct wl_value_string *luaW_check_value_string(lua_State *L, int arg);

void luaW_push_value_string(lua_State *L, struct wl_value_string *str);

struct wl_value_string *luaW_opt_value_string(lua_State *L, int idx);

void luaW_push_vals(lua_State *L, const value_string *ptr);

void wl_open_value_string(lua_State *L);

#endif
