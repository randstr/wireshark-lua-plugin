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

#ifndef _WSLUA2_H_
#define _WSLUA2_H_

#include <epan/register.h>
#include <epan/epan_dissect.h>

void wslua2_register_all_protocols(register_cb cb, gpointer client_data);

void wslua2_register_all_handoffs(register_cb cb, gpointer client_data);

void wslua2_init(void);

void wslua2_post_init(void);

void wslua2_dissect_init(epan_dissect_t *);

void wslua2_dissect_cleanup(epan_dissect_t *);

void wslua2_cleanup(void);

void wslua2_get_descriptons(plugin_description_callback callback, void *user_data);

#endif
