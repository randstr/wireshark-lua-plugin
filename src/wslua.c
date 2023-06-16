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

#include "wslua-int.h"
#include "wslua.h"

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include <epan/exceptions.h>
#include <epan/ex-opt.h>
#include <epan/register.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>

/***
 * @module wireshark
 */
#define MODULE_NAME     "wireshark"
#define REX_MODULE_NAME "rex_pcre2"

#define TABLE_REGISTER_PROTOCOL "_PROTOCOLS"
#define TABLE_REGISTER_HANDOFF  "_HANDOFFS"

/***
 * Folder where wireshark runs init.lua and loads dissectors.
 * @field DATAPATH path to load lua code
 */

lua_State *g_lua = NULL;

static gchar *data_path = NULL;

#ifdef HAVE_PCRE2
int luaopen_rex_pcre2(lua_State *L);
#endif

static bool str_has_suffix(const char *str, const char *suffix)
{
    size_t l1 = strlen(str);
    size_t l2 = strlen(suffix);
    if (l1 < l2)
        return false;
    while (l2 > 0) {
        if (suffix[--l2] != str[--l1]) {
            return false;
        }
    }
    return true;
}

static void *l_alloc (void *ud _U_, void *ptr, size_t osize _U_, size_t nsize)
{
    if (nsize == 0) {
        free(ptr);
        return NULL;
    }
    void *p = realloc(ptr, nsize);
    if (!p) {
        fprintf(stderr, "Out of memory error\n");
        abort();
    }
    return p;
}

static int l_panic(lua_State *L)
{
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL)
        msg = "unknown lua failure";
    fprintf(stderr, "%s\n", msg);
    THROW_MESSAGE(DissectorError, msg);
    abort(); // not reached
    return 0;
}

static void l_dofile(lua_State *L, const char *file,
                        gboolean use_datapath, gboolean ignore_missing)
{
    const char *path;
    char path_buf[1024];
    int err;
    gboolean skip = FALSE;

    if (use_datapath) {
        snprintf(path_buf, sizeof(path_buf), "%s/%s", data_path, file);
        path = path_buf;
    }
    else {
        path = file;
    }
    if (ignore_missing && access(path, F_OK) != 0)
        skip = TRUE;
    else
        err = luaL_loadfilex(L, path, "t");

    if (!skip) {
        if (err != LUA_OK) {
            lua_error(L);
            abort(); /* not reached */
        }
        luaW_call(L, 0, LUA_MULTRET);
    }
}

/***
 * Execute a file as a Lua chunk.
 * Opens the named file and executes its contents as a Lua chunk. The file
 * is opened in ws.DATAPATH.
 * @function dofile
 * @string name the file name
 */
static int wl_dofile(lua_State *L)
{
    const char *file = luaL_checkstring(L, 1);
    l_dofile(L, file, TRUE, FALSE);
    return lua_gettop(L) - 1; /* ignore string argument */
}

static int wl_in_cksum(lua_State *L)
{
    int nargs = lua_gettop(L);
    vec_t *p = malloc(nargs * sizeof(vec_t));
    const char *s;
    size_t len;

    for (int i = 0; i < nargs; i++) {
        s = lua_tolstring(L, i+1, &len);
        p[i].ptr = (const guint8 *)s;
        p[i].len = len;
    }
    int result = in_cksum(p, nargs);
    free(p);
    lua_pushinteger(L, result);
    return 1;
}

static const struct luaL_Reg wireshark_f[] = {
    { "dofile", wl_dofile },
    { "in_cksum", wl_in_cksum },
    { NULL, NULL }
};

static int l_luaopen_wireshark(lua_State *L)
{
    luaL_newlib(L, wireshark_f);

    lua_newtable(L);
    lua_setfield(L, 2, TABLE_REGISTER_PROTOCOL);
    lua_newtable(L);
    lua_setfield(L, 2, TABLE_REGISTER_HANDOFF);

    data_path = get_persconffile_path("wslua2", FALSE);
    lua_pushstring(L, data_path);
    lua_setfield(L, 2, "DATAPATH");

    lua_pushstring(L, PLUGIN_VERSION);
    lua_setfield(L, 2, "VERSION");
    lua_pushstring(L, epan_get_version());
    lua_setfield(L, 2, "EPAN_VERSION");

    load_enums(L);
    wl_open_proto(L);
    wl_open_tvbuff(L);
    wl_open_pinfo(L);
    wl_open_prefs(L);
    wl_open_addr(L);
    wl_open_expert(L);
    wl_open_packet(L);
    wl_open_value_string(L);

    return 1;
}

void wslua2_register_all_protocols(register_cb cb, gpointer client_data)
{
    lua_State *L = g_lua;

    ws_info("Registering all Lua protocols");
    BEGIN_STACK_DEBUG(L);
    lua_getglobal(L, MODULE_NAME);
    luaL_getsubtable(L, -1, TABLE_REGISTER_PROTOCOL);
    lua_pushnil(L);
    while (lua_next(L, 2)) {
        if (cb)
            cb(RA_PLUGIN_REGISTER, NULL, client_data);
        lua_call(L, 0, 0);
    }
    lua_pop(L, 2); // pop tables
    END_STACK_DEBUG(L, 0);
}

void wslua2_register_all_handoffs(register_cb cb, gpointer client_data)
{
    lua_State *L = g_lua;

    ws_info("Registering all Lua handoffs");
    BEGIN_STACK_DEBUG(L);
    lua_getglobal(L, MODULE_NAME);
    luaL_getsubtable(L, -1, TABLE_REGISTER_HANDOFF);
    lua_pushnil(L);
    while (lua_next(L, 2)) {
        if (cb)
            cb(RA_PLUGIN_HANDOFF, NULL, client_data);
        lua_call(L, 0, 0);
    }
    lua_pop(L, 2); // pop tables
    END_STACK_DEBUG(L, 0);
}

/* receives function on stack */
static void insert_lua_entry_point(lua_State *L, const char *table_name)
{
    BEGIN_STACK_DEBUG(L);
    luaL_checktype(L, -1, LUA_TFUNCTION);
    int idx = lua_gettop(L);
    lua_getglobal(L, MODULE_NAME);
    luaL_getsubtable(L, -1, table_name);
    lua_pushvalue(L, idx);
    luaW_insert(L, -2);
    lua_pop(L, 3);
    END_STACK_DEBUG(L, -1);
}


void load_lua_module(lua_State *L, const char *name)
{
    int type;

    BEGIN_STACK_DEBUG(L);
    l_dofile(L, name, TRUE, FALSE); /* pushes module on stack */
    luaL_checktype(L, -1, LUA_TTABLE);
    type = lua_getfield(L, -1, "register_protocol");
    if (type == LUA_TFUNCTION)
        insert_lua_entry_point(L, TABLE_REGISTER_PROTOCOL);
    else
        lua_pop(L, 1);
    type = lua_getfield(L, -1, "register_handoff");
    if (type == LUA_TFUNCTION)
        insert_lua_entry_point(L, TABLE_REGISTER_HANDOFF);
    else
        lua_pop(L, 1);
    lua_pop(L, 1);
    END_STACK_DEBUG(L, 0);
}

void wslua2_init(void)
{
    lua_State *L;
    DIR *dir;
    struct dirent *entry;
    const char *name;

    L = g_lua = lua_newstate(l_alloc, NULL);
    lua_atpanic(L, l_panic);
    luaL_openlibs(L);

    luaL_requiref(L, MODULE_NAME, l_luaopen_wireshark, TRUE);
    lua_pop(L, 1);
#ifdef HAVE_PCRE2
    luaL_requiref(L, REX_MODULE_NAME, luaopen_rex_pcre2, TRUE);
    lua_pop(L, 1);
#endif

    /* Lua has no granularity for file errors. We want to be quiet if
     * 'init.lua' doesn't exist (and only then) */
    l_dofile(L, "init.lua", TRUE, TRUE);
    dir = opendir(data_path);
    if (dir == NULL) {
        /* should not happen */
        return;
    }
    while((entry = readdir(dir)) != NULL) {
        name = entry->d_name;
        if (str_has_suffix(name, ".lua") && strcmp(name, "init.lua") != 0) {
            load_lua_module(L, name);
        }
    }
    closedir(dir);
}

void wslua2_post_init(void)
{
    lua_State *L = g_lua;
    const gchar *opt;

    while ((opt = ex_opt_get_next("wslua2")) != NULL) {
        l_dofile(L, opt, FALSE, FALSE);
    }
}

void wslua2_dissect_init(epan_dissect_t *edt)
{
    lua_State *L = g_lua;
    packet_info *pinfo = &edt->pi;

    lua_pushlightuserdata(L, pinfo); /* key */
    packet_info **ptr = NEWUSERDATA(L, packet_info *, "wslua.PacketInfo"); /* value */
    *ptr = pinfo;
    lua_rawset(L, LUA_REGISTRYINDEX);
}

void wslua2_dissect_cleanup(epan_dissect_t *edt)
{
    lua_State *L = g_lua;
    packet_info *pinfo = &edt->pi;

    lua_pushlightuserdata(L, pinfo); /* key */
    lua_pushnil(L); /* value */
    lua_rawset(L, LUA_REGISTRYINDEX);
}

void wslua2_cleanup(void)
{
    if (g_lua)
        lua_close(g_lua);
    g_lua = NULL;
    if (data_path)
        wmem_free(NULL, data_path);
    data_path = NULL;
}
