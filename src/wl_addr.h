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

#ifndef _WL_ADDR_H_
#define _WL_ADDR_H_

#include <epan/address.h>
#include <epan/ftypes/ftypes.h>

uint32_t luaW_check_ipv4(lua_State *L, int arg);

struct e_in6_addr *luaW_check_ipv6(lua_State *L, int arg);

address *luaW_check_addr(lua_State *L, int arg);

address_type luaW_check_address_type(lua_State *L, int arg);

void luaW_push_ipv4(lua_State *L, uint32_t ip4);

void luaW_push_ipv6(lua_State *L, const struct e_in6_addr *ip6);

void luaW_push_addr(lua_State *L, address *addr);

address_type ftenum_to_addr_type(enum ftenum ft);

void wl_open_addr(lua_State *L);

#endif
