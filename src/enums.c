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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "enums.h"

#include <epan/introspection.h>

/* Receives module on the stack */
void load_enums(lua_State *L)
{
    const ws_enum_t *all_enums = epan_inspect_enums();

    for (const ws_enum_t *p = all_enums; p->symbol != NULL; p++) {
            lua_pushstring(L, p->symbol);
            lua_pushinteger(L, p->value);
            lua_settable(L, -3);
    }
}
