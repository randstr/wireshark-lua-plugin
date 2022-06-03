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

#ifndef _WL_PINFO_H_
#define _WL_PINFO_H_

#include <epan/packet_info.h>

packet_info *luaW_check_pinfo(lua_State *L, int arg);

column_info *luaW_check_cinfo(lua_State *L, int arg);

int luaW_check_column(lua_State *L, int idx);

void luaW_push_pinfo(lua_State *L, packet_info *pinfo);

void luaW_push_cinfo(lua_State *L, column_info *cinfo);
  
void wl_open_pinfo(lua_State *L);

#endif
