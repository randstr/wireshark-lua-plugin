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

#ifndef _WL_PROTO_H_
#define _WL_PROTO_H_

proto_tree *luaW_check_proto_tree(lua_State *L, int arg);

proto_item *luaW_check_proto_item(lua_State *L, int arg);

int luaW_check_protocol(lua_State *L, int arg);

hf_register_info *luaW_check_hf_register_info(lua_State *L, int arg);

void luaW_push_hf_register_info(lua_State *L, hf_register_info *hf);

void luaW_push_proto_tree(lua_State *L, proto_tree *tree);

void luaW_push_proto_item(lua_State *L, proto_item *item);

lua_Integer luaW_check_offset_toint(lua_State *L, int arg);

void wl_open_proto(lua_State *L);

#endif
