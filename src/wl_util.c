/*
 * Copyright 2017-2023, João Valverde <j@v6e.pt>
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

/***
 * @module wireshark.util
 */

// The index must match enum ws_log_level in ws_log_defs.h.
static const char *const wl_log_level[] = {
    "none",
    "noisy",
    "debug",
    "info",
    "message",
    "warning",
    "critical",
    "error",
    "echo",
    NULL
};

enum ws_log_level luaW_check_log_level(lua_State *L, int idx)
{
    enum ws_log_level level = luaL_checkoption(L, idx, "none", wl_log_level);
    // Lua code should never crash, reject these for now.
    if (level >= LOG_LEVEL_CRITICAL && level <= LOG_LEVEL_ERROR) {
        luaL_error(L, "Level \"%s\" is not a valid Lua log level", ws_log_level_to_string(level));
    }
    return level;
}

static int l_log_full(lua_State *L, const char *domain, enum ws_log_level log_level,
                        int format_idx, int stack_level)
{
    const char *format _U_ = luaL_checkstring(L, format_idx);
    // Folowed by variadic arguments

    // First call string.format() on the format + arguments
    // Pops the format + arguments and push the result on the stack.
    luaW_string_format_pos(L, format_idx, lua_gettop(L) - format_idx);
    const char *message = luaL_checkstring(L, format_idx);

    const char *file = NULL;
    long line = -1;
    const char *func = NULL;
    lua_Debug ar;

    // Get file/line/func using the debug module
    if (stack_level >= 0) {
        memset(&ar, 0, sizeof(ar));
        lua_getstack(L, stack_level, &ar);
        lua_getinfo(L, "lnS", &ar);
        /*
         * https://www.lua.org/manual/5.4/manual.html#lua_Debug
         *
         *   source: the source of the chunk that created the function. If
         *   source starts with a '@', it means that the function was defined
         *   in a file where the file name follows the '@'. If source starts
         *   with a '=', the remainder of its contents describes the source
         *   in a user-dependent manner. Otherwise, the function was defined
         *   in a string where source is that string.
         *
         *   currentline: the current line where the given function is
         *   executing. When no line information is available, currentline
         *   is set to -1. 
         *
         *   name: a reasonable name for the given function. Because functions
         *   in Lua are first-class values, they do not have a fixed name: some
         *   functions can be the value of multiple global variables, while
         *   others can be stored only in a table field. The lua_getinfo
         *   function checks how the function was called to find a suitable
         *   name. If it cannot find a name, then name is set to NULL. 
         */
        file = ar.source;
        line = ar.currentline;
        func = ar.name;
    }

    ws_log_full(domain, log_level, file, line, func, "%s", message);
    return 0;
}

/***
 * This function is called to output a message to the log.
 * @function log
 * @string domain the log domain
 * @string level the log level
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);
    enum ws_log_level level = luaW_check_log_level(L, 2);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, level))
        return 0;

    return l_log_full(L, domain, level, 3, -1);
}

/***
 * This function is called to output a message to the log.
 * In addition to the message this function provides file/line/function
 * information.
 * @function logf
 * @string domain the log domain
 * @string level the log level
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_full(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);
    enum ws_log_level level = luaW_check_log_level(L, 2);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, level))
        return 0;

    // stack level 1 = above the logf() call
    return l_log_full(L, domain, level, 3, 1);
}

/***
 * This function is used for debugging only. It always prints the message
 * regardless of the log level.
 * In addition to the message this function provides file/line/function
 * information.
 * @function DEBUG_HERE
 * @string domain the log domain
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_debug_here(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);
    // stack level above the DEBUG_HERE() call
    return l_log_full(L, domain, LOG_LEVEL_ECHO, 2, 1);
}

static const struct luaL_Reg wl_util_f[] = {
    { "log", wl_log },
    { "logf", wl_log_full },
    { "DEBUG_HERE", wl_log_debug_here },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_util(lua_State *L)
{
    luaL_newlib(L, wl_util_f);
    lua_setfield(L, -2, "util");
}
