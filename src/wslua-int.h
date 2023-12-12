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

#ifndef _WSLUA2_INT_H_
#define _WSLUA2_INT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define WS_LOG_DOMAIN "wslua2"

#include <errno.h>
#include <string.h>

#include <wireshark.h>

#include "../lua/src/lua.h"
#include "../lua/src/lualib.h"
#include "../lua/src/lauxlib.h"

#include "enums.h"
#include "wauxlib.h"

#include <epan/exceptions.h>
#include <epan/to_str.h>
#include <epan/prefs.h>

#include "wl_addr.h"
#include "wl_expert.h"
#include "wl_packet.h"
#include "wl_pinfo.h"
#include "wl_prefs.h"
#include "wl_proto.h"
#include "wl_tvbuff.h"
#include "wl_value_string.h"
#include "wl_funnel.h"

#define BEGIN_STACK_DEBUG(L) \
    int __top; do {__top = lua_gettop(L); } while(0)

#define END_STACK_DEBUG(L, n) \
    do {ws_assert(lua_gettop(L) == __top + n); } while(0)

extern lua_State *g_lua;

void *xmalloc(size_t size);

#endif
