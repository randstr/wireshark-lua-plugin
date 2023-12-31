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
#include <wsutil/plugins.h>
#include "wslua.h"

static void plugin_register(void)
{
    static epan_plugin plug = {
        .init = wslua2_init,
        .post_init = wslua2_post_init,
        .dissect_init = wslua2_dissect_init,
        .dissect_cleanup = wslua2_dissect_cleanup,
        .cleanup = wslua2_cleanup,
        .register_all_protocols = wslua2_register_all_protocols,
        .register_all_handoffs = wslua2_register_all_handoffs,
        .get_descriptions = wslua2_get_descriptons,
    };
    epan_register_plugin(&plug);
}

static struct ws_module module = {
    .flags = WS_PLUGIN_DESC_EPAN,
    .version = PLUGIN_VERSION,
    .spdx_id = "GPL-2.0-or-later",
    .home_url = "https://gitlab.com/jvalverde/wireshark-lua-plugin",
    .blurb = "Allows writing Wireshark dissectors in Lua 5.4 instead of C.",
    .register_cb = &plugin_register,
};

WIRESHARK_PLUGIN_REGISTER_EPAN(&module, 0)
