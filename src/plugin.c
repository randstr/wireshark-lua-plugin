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

#include <epan/epan.h>
#include <ws_version.h>
#include "wslua.h"

#define DLL_PUBLIC __attribute__((visibility ("default")))


DLL_PUBLIC
const gchar plugin_version[] = PLUGIN_VERSION;

DLL_PUBLIC
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;

DLL_PUBLIC
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

DLL_PUBLIC
void plugin_register(void)
{
    static epan_plugin plug;

    plug.init = wslua2_init;
    plug.post_init = wslua2_post_init;
    plug.dissect_init = wslua2_dissect_init;
    plug.dissect_cleanup = wslua2_dissect_cleanup;
    plug.cleanup = wslua2_cleanup;
    plug.register_all_protocols = wslua2_register_all_protocols;
    plug.register_all_handoffs = wslua2_register_all_handoffs;
    epan_register_plugin(&plug);
}
