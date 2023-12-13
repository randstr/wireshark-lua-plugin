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

static void luaW_push_log_domain(lua_State *L, const char *domain)
{
    char **ptr = NEWUSERDATA(L, char *, "wslua.LogDomain");
    *ptr = xstrdup(domain);
}

static char **luaW_check_log_domain(lua_State *L, int arg)
{
    return luaL_checkudata(L, arg, "wslua.LogDomain");
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
 * A Logger class with an associated domain name.
 * @type LogDomain
 */

/***
 * Log a message
 * @function log
 * @string level the log level
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_log(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);
    enum ws_log_level log_level = luaW_check_log_level(L, 2);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, log_level))
        return 0;

    l_log_full(L, domain, log_level, 3, -1);
    return 0;
}

/***
 * Log a message with file/line/func
 * @function logf
 * @string level the log level
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_log_full(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);
    enum ws_log_level log_level = luaW_check_log_level(L, 2);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, log_level))
        return 0;

    l_log_full(L, domain, log_level, 3, 1);
    return 0;
}

/***
 * Log a message with "noisy" level
 * @function noisy
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_noisy(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_NOISY))
        return 0;

    l_log_full(L, domain, LOG_LEVEL_NOISY, 2, 1);
    return 0;
}

/***
 * Log a message with "debug" level
 * @function debug
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_debug(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_DEBUG))
        return 0;

    l_log_full(L, domain, LOG_LEVEL_DEBUG, 2, 1);
    return 0;
}

/***
 * Log a message with "info" level
 * @function info
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_info(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_INFO))
        return 0;

    l_log_full(L, domain, LOG_LEVEL_INFO, 2, -1);
    return 0;
}

/***
 * Log a message with "message" level
 * @function message
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_message(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_MESSAGE))
        return 0;

    l_log_full(L, domain, LOG_LEVEL_MESSAGE, 2, -1);
    return 0;
}

/***
 * Log a message with "warning" level
 * @function warning
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_warning(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_WARNING))
        return 0;

    l_log_full(L, domain, LOG_LEVEL_WARNING, 2, 1);
    return 0;
}

/***
 * Log a message with "echo" level
 * @function DEBUG_HERE
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_domain_debug_here(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);
    l_log_full(L, domain, LOG_LEVEL_ECHO, 2, 1);
    return 0;
}

/***
 * String representation
 * @function __tostring
 */
static int wl_log_domain_tostring(lua_State *L)
{
    char *domain = *luaW_check_log_domain(L, 1);
    lua_pushfstring(L, "wslua.LogDomain: %s", domain);
    return 1;
}

/***
 * @section end
 */

/***
 * Create a new log domain logger
 * @function new_log_domain
 * @string domain the domain name
 */
static int wl_new_log_domain(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);
    luaW_push_log_domain(L, domain);
    return 1;
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
 * This function is called to output a "noisy" level messag to the log.
 * @function noisy
 * @string domain the log domain
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_noisy(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_NOISY))
        return 0;

    // stack level 1 = above the logf() call
    return l_log_full(L, domain, LOG_LEVEL_NOISY, 3, 1);
}

/***
 * This function is called to output a "debug" level messag to the log.
 * @function debug
 * @string domain the log domain
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_debug(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_DEBUG))
        return 0;

    // stack level 1 = above the logf() call
    return l_log_full(L, domain, LOG_LEVEL_DEBUG, 3, 1);
}

/***
 * This function is called to output a "info" level messag to the log.
 * @function info
 * @string domain the log domain
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_info(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_INFO))
        return 0;

    return l_log_full(L, domain, LOG_LEVEL_INFO, 3, -1);
}

/***
 * This function is called to output a "message" level messag to the log.
 * @function message
 * @string domain the log domain
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_message(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_MESSAGE))
        return 0;

    return l_log_full(L, domain, LOG_LEVEL_MESSAGE, 3, -1);
}

/***
 * This function is called to output a "warning" level messag to the log.
 * @function warning
 * @string domain the log domain
 * @string format the message string format
 * @string[opt] params followed by the format arguments 
 */
static int wl_log_warning(lua_State *L)
{
    const char *domain = luaL_checkstring(L, 1);

    // First check if the message should be printed.
    if (!ws_log_msg_is_active(domain, LOG_LEVEL_WARNING))
        return 0;

    // stack level 1 = above the logf() call
    return l_log_full(L, domain, LOG_LEVEL_WARNING, 3, 1);
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

static const struct luaL_Reg wl_log_domain_m[] = {
    { "log", wl_log_domain_log },
    { "logf", wl_log_domain_log_full },
    { "noisy", wl_log_domain_noisy },
    { "debug", wl_log_domain_debug },
    { "info", wl_log_domain_info },
    { "message", wl_log_domain_message },
    { "warning", wl_log_domain_warning },
    { "DEBUG_HERE", wl_log_domain_debug_here },
    { "__tostring", wl_log_domain_tostring },
    { NULL, NULL }
};

static const struct luaL_Reg wl_util_f[] = {
    { "log", wl_log },
    { "logf", wl_log_full },
    { "noisy", wl_log_noisy },
    { "debug", wl_log_debug },
    { "info", wl_log_info },
    { "message", wl_log_message },
    { "warning", wl_log_warning },
    { "DEBUG_HERE", wl_log_debug_here },
    { "new_log_domain", wl_new_log_domain },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_util(lua_State *L)
{
    luaW_newmetatable(L, "wslua.LogDomain", wl_log_domain_m);
    luaL_newlib(L, wl_util_f);
    lua_setfield(L, -2, "util");
}
