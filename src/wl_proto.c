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

#define PROTO_PREFS_FIELD "prefs"

/***
 * @module wireshark
 */

struct wl_offset {
    lua_Integer curr, step;
};

/*
 * Only increment if we have not been incremented before, to allow
 * multiple invocations of proto_tree_add_*() without multiple increments.
 */
#define NEXT(off, len)  \
    do {                                \
        if (len > 0) \
            ((off)->step = (len));     \
    } while (0)

int luaW_check_protocol(lua_State *L, int arg)
{
    int proto = *(int *)luaL_checkudata(L, arg, "wslua.Protocol");
    return proto;
}

proto_item *luaW_check_proto_item(lua_State *L, int arg)
{
    proto_item **ptr = luaL_checkudata(L, arg, "wslua.ProtoItem");
    return *ptr;
}

proto_tree *luaW_check_proto_tree(lua_State *L, int arg)
{
    proto_tree **ptr = luaL_checkudata(L, arg, "wslua.ProtoTree");
    return *ptr;
}

hf_register_info *luaW_check_hf_register_info(lua_State *L, int arg)
{
    hf_register_info **ptr = luaL_checkudata(L, arg, "wslua.HfRegisterInfo");
    return *ptr;
}

void luaW_push_proto_item(lua_State *L, proto_item *item)
{
    proto_item **ptr = NEWUSERDATA(L, proto_item *, "wslua.ProtoItem");
    *ptr = item;
}

void luaW_push_proto_tree(lua_State *L, proto_tree *tree)
{
    proto_tree **ptr = NEWUSERDATA(L, proto_tree *, "wslua.ProtoTree");
    *ptr = tree;
}

void luaW_push_hf_register_info(lua_State *L, hf_register_info *hf)
{
    hf_register_info **ptr = NEWUSERDATA(L, hf_register_info *, "wslua.HfRegisterInfo");
    *ptr = hf;
}

unsigned luaW_opt_encoding(lua_State *L, int arg)
{
    unsigned encoding = luaL_optinteger(L, arg, ENC_BIG_ENDIAN); /* XXX: Use ENC_NA instead */
    return encoding;
}

struct wl_offset *luaW_check_offset(lua_State *L, int arg)
{
    struct wl_offset **ptr = luaL_checkudata(L, arg, "wslua.Offset");
    return *ptr;
}

void luaW_push_offset(lua_State *L, struct wl_offset *off)
{
    struct wl_offset **ptr = NEWUSERDATA(L, struct wl_offset *, "wslua.Offset");
    *ptr = off;
}

lua_Integer luaW_check_offset_toint(lua_State *L, int arg)
{
    luaL_checkany(L, arg);
    int t = lua_type(L, arg);
    if (t == LUA_TUSERDATA) {
        struct wl_offset *off = luaW_check_offset(L, arg);
        return off->curr;
    }
    lua_Integer off = luaL_checkinteger(L, arg);
    return off;
}

/*
 * Create a header field info
 * @function hfinfo
 * @string name field name
 * @string abbrev field abbrev
 * @string ftype field type
 * @param[opt] strings VALS value or nil
 * @string[optchain] display display base
 * @int[optchain] bitmask field bitmask
 * @string[optchain] blurb field blurb
 * @treturn HFInfo header field info
 */
static int wl_hf_register_info_new(lua_State *L)
{
    lua_geti(L, 1, 1);
    const char *name = luaL_checkstring(L, -1);

    lua_geti(L, 1, 2);
    const char *abbrev = luaL_checkstring(L, -1);

    lua_geti(L, 1, 3);
    enum ftenum type = luaL_checkinteger(L, -1);

    lua_geti(L, 1, 4);
    field_display_e display = luaL_optinteger(L, -1, BASE_NONE);

    lua_geti(L, 1, 5);
    struct wl_value_string *strings = luaW_opt_value_string(L, -1);
    if (strings) {
        switch (strings->type) {
            case WL_VALS:
                break;
            case WL_RVALS:
                display |= BASE_RANGE_STRING;
                break;
            default:
                ws_assert_not_reached();
        }
    }

    lua_geti(L, 1, 6);
    lua_Integer bitmask = luaL_optinteger(L, -1, 0);

    lua_geti(L, 1, 7);
    const char *blurb = luaL_optstring(L, -1, NULL);

    hf_register_info *hf = wmem_new(wmem_epan_scope(), hf_register_info);
    hf->p_id = wmem_new(wmem_epan_scope(), int);
    *(hf->p_id) = -1;
    hf->hfinfo.name = wmem_strdup(wmem_epan_scope(), name);
    hf->hfinfo.abbrev = wmem_strdup(wmem_epan_scope(), abbrev);
    hf->hfinfo.type = type;
    hf->hfinfo.display = display;
    hf->hfinfo.strings = strings ? strings->data.vals : NULL;
    hf->hfinfo.bitmask = bitmask;
    hf->hfinfo.blurb = wmem_strdup(wmem_epan_scope(), blurb);
    hf->hfinfo.id = -1;
    hf->hfinfo.parent = 0;
    hf->hfinfo.ref_type = HF_REF_TYPE_NONE;
    hf->hfinfo.same_name_prev_id = -1;
    hf->hfinfo.same_name_next = NULL;
    luaW_push_hf_register_info(L, hf);
    return 1;
}

/***
 * @section end
 */

/***
 * A ProtoItem class.
 * @type ProtoItem
 */

/***
 * Add a subtree item to the ProtoItem
 * @function add_subtree
 * @int idx the subtree index
 * @treturn ProtoTree
 */
static int wl_protoitem_add_subtree(lua_State *L)
{
    proto_item *item = luaW_check_proto_item(L, 1);
    int idx = luaL_checkinteger(L, 2);
    proto_tree *tree = proto_item_add_subtree(item, idx);
    luaW_push_proto_tree(L, tree);
    return 1;
}

/***
 * Add an expert info item to the ProtoItem
 * @function add_expert
 * @tparam ExpertField exp the expert info field object
 * @tparam PacketInfo pinfo the packet info object
 * @string[opt] msg optional display string
 */
static int wl_protoitem_add_expert(lua_State *L)
{
    proto_item *pi = luaW_check_proto_item(L, 1);
    ei_register_info *ei = luaW_check_expert_register_info(L, 2);
    packet_info *pinfo = luaW_check_pinfo(L, 3);
    const char *msg = luaL_optstring(L, 4, NULL);

    if (msg)
        expert_add_info_format(pinfo, pi, ei->ids, "%s", msg);
    else
        expert_add_info(pinfo, pi, ei->ids);
    return 0;
}

/***
 * Append string to the ProtoItem
 * @function append_text
 * @string format the string format
 * @param[opt] ... the optional arguments
 */
static int wl_protoitem_append_text(lua_State *L)
{
    proto_item *pi = luaW_check_proto_item(L, 1);
    luaL_checkstring(L, 2);
    lua_remove(L, 1);
    luaW_string_format(L, lua_gettop(L));
    const char *text = lua_tostring(L, -1);
    proto_item_append_text(pi, "%s", text);
    return 0;
}

/***
 * Mark packet field as generated
 * @function set_generated
 */
static int wl_protoitem_set_generated(lua_State *L)
{
    proto_item *pi = luaW_check_proto_item(L, 1);
    PROTO_ITEM_SET_GENERATED(pi);
    return 0;
}

/***
 * Mark packet field as hidden
 * @function set_hidden
 */
static int wl_protoitem_set_hidden(lua_State *L)
{
    proto_item *pi = luaW_check_proto_item(L, 1);
    PROTO_ITEM_SET_HIDDEN(pi);
    return 0;
}

/***
 * @section end
 */

/***
 * A ProtoTree class.
 * @type ProtoTree
 */

#define WL_ITEM_FLAG_HIDDEN    0x01
#define WL_ITEM_FLAG_GENERATED 0x02

static int check_item_flags(lua_State *L, int arg)
{
    int flags = 0;

    luaL_argcheck(L, lua_istable(L, arg), arg, "must be a table");
        
    lua_getfield(L, arg, "hidden");
    if (lua_toboolean(L, -1))
        flags |= WL_ITEM_FLAG_HIDDEN;
    lua_pop(L, 1);
    
    lua_getfield(L, arg, "generated");
    if (lua_toboolean(L, -1))
        flags |= WL_ITEM_FLAG_GENERATED;
    lua_pop(L, 1);

    return flags;
}

/***
 * Add a proto item to the tree
 * @function add_item
 * @int idx the hf index
 * @tparam TVBuff tvb the tvbuff
 * @int start the start offset
 * @int length the item length
 * @string[opt] encoding the encoding
 * @tab[opt] options field properties (hidden/generated)
 * @treturn ProtoItem
 */
static int wl_prototree_add_item(lua_State *L)
{
    proto_tree *tree = luaW_check_proto_tree(L, 1);
    hf_register_info *hf = luaW_check_hf_register_info(L, 2);
    tvbuff_t *tvb = luaW_check_tvbuff(L, 3);
    struct wl_offset *off = luaW_check_offset(L, 4);
    int length = luaL_checkinteger(L, 5);
    unsigned encoding = luaW_opt_encoding(L, 6);
    int flags = luaL_opt(L, check_item_flags, 7, 0);

    proto_item *item = proto_tree_add_item_new(tree, &hf->hfinfo, tvb, off->curr, length, encoding);
    if (flags & WL_ITEM_FLAG_HIDDEN)
        PROTO_ITEM_SET_HIDDEN(item);
    if (flags & WL_ITEM_FLAG_GENERATED)
        PROTO_ITEM_SET_GENERATED(item);
    luaW_push_proto_item(L, item);
    NEXT(off, length);
    return 1;
}

/***
 * Add a proto item to the tree
 * @function add_item_ret
 * @int idx the hf index
 * @tparam TVBuff tvb the tvbuff
 * @int start the start offset
 * @int length the item length
 * @string[opt] encoding the encoding
 * @return lua return value according to field type
 * @treturn ProtoItem
 */
 
static int wl_prototree_add_item_ret(lua_State *L)
{
    proto_tree *tree = luaW_check_proto_tree(L, 1);
    hf_register_info *hf = luaW_check_hf_register_info(L, 2);
    tvbuff_t *tvb = luaW_check_tvbuff(L, 3);
    struct wl_offset *off = luaW_check_offset(L, 4);
    int length = luaL_checkinteger(L, 5);
    unsigned encoding = luaW_opt_encoding(L, 6);

    proto_item *item;
    enum ftenum type = hf->hfinfo.type;

    if (type == FT_BOOLEAN) { 
        gboolean retval;
        item = proto_tree_add_item_ret_boolean(tree, *(hf->p_id), tvb, off->curr, length, encoding, &retval);
        lua_pushboolean(L, retval);
    }
    else if (FT_IS_INT32(type)){
        int32_t retval;
        item = proto_tree_add_item_ret_int(tree, *(hf->p_id), tvb, off->curr, length, encoding, &retval);
        lua_pushinteger(L, retval);
    }
    else if (FT_IS_UINT32(type)){
        uint32_t retval;
        item = proto_tree_add_item_ret_uint(tree, *(hf->p_id), tvb, off->curr, length, encoding, &retval);
        lua_pushinteger(L, retval);
    }
    else if (FT_IS_UINT64(type)){
        uint64_t retval;
        item = proto_tree_add_item_ret_uint64(tree, *(hf->p_id), tvb, off->curr, length, encoding, &retval);
        lua_pushinteger(L, retval);
    }
    else if (FT_IS_STRING(type)) {
        uint8_t *retval;
        item = proto_tree_add_item_ret_string(tree, *(hf->p_id), tvb, off->curr, length, encoding, NULL, (const uint8_t **)&retval);
        lua_pushstring(L, (char *)retval);
        wmem_free(NULL, retval);
    }
    else if (type == FT_IPv4 || type == FT_IPv6) {
        item = proto_tree_add_item(tree, *(hf->p_id), tvb, off->curr, length, ENC_NA);
        address addr;
        alloc_address_tvb(wmem_epan_scope(), &addr, ftenum_to_addr_type(type), length, tvb, off->curr);
        luaW_push_addr(L, &addr);
    }
    else {
        return luaL_error(L, "Unsupported field type %s", ftype_name(hf->hfinfo.type));
    }
    luaW_push_proto_item(L, item);
    NEXT(off, length);
    return 2;
}

/***
 *  Add a checksum to a proto_tree.
 * @function add_checksum
 * @tparam TVBuff tvb the tvbuff
 * @int start the start offset
 * @int hf_checksum checksum field index
 * @int hf_checksum_status optional checksum status field index.  If none
 * exists, just pass nil
 * @tparam ExpertRegisterInfo ei optional expert info for a bad checksum.  If
 * none exists, just pass nil
 * @tparam PacketInfo Packet pinfo info used for optional expert info.  If unused, nil can
 * be passed
 * @int computed_checksum Checksum to verify against
 * @int encoding data encoding of checksum from tvb
 * @int flags bitmask field of PROTO_CHECKSUM_ options
 * @treturn ProtoItem
 */
 
static int wl_prototree_add_checksum(lua_State *L)
{
    proto_tree *tree = luaW_check_proto_tree(L, 1);
    tvbuff_t *tvb = luaW_check_tvbuff(L, 2);
    struct wl_offset *off = luaW_check_offset(L, 3);
    hf_register_info *hf = luaW_check_hf_register_info(L, 4);
    hf_register_info *hf_status = luaW_check_hf_register_info(L, 5);
    ei_register_info *ei = luaW_check_expert_register_info(L, 6);
    packet_info *pinfo = luaW_check_pinfo(L, 7);
    lua_Integer computed_cksum = luaL_checkinteger(L, 8);
    lua_Integer encoding = luaL_checkinteger(L, 9);
    lua_Integer flags = luaL_checkinteger(L, 10);
    proto_item *item = proto_tree_add_checksum(tree, tvb, off->curr, *(hf->p_id), *(hf_status->p_id), ei->ids, pinfo, computed_cksum, encoding, flags);
    luaW_push_proto_item(L, item);
    NEXT(off, 2);
    return 1;
}

/***
 * Add a protocol item to the tree
 * @function add_protocol
 * @tparam Protocol proto the protocol
 * @tparam TVBuff tvb the tvbuff
 * @int start the start offset
 * @int length the item length
 * @string[opt] encoding the encoding
 * @treturn ProtoItem
 */
static int wl_prototree_add_protocol(lua_State *L)
{
    proto_tree *tree = luaW_check_proto_tree(L, 1);
    int hfindex = luaW_check_protocol(L, 2);
    tvbuff_t *tvb = luaW_check_tvbuff(L, 3);
    struct wl_offset *off = luaW_check_offset(L, 4);
    int length = luaL_checkinteger(L, 5);
    unsigned encoding = luaW_opt_encoding(L, 6);
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, off->curr, length, encoding);
    luaW_push_proto_item(L, item);
    NEXT(off, length);
    return 1;
}

/***
 * @section end
 */

/***
 * An Offset class.
 * @type Offset
 */

/***
 * Increments current offset to next offset
 * @function next
 * @int[opt] offset The incremental offset to use
 * @treturn int the new offset
 */
static int wl_offset_next(lua_State *L)
{
    struct wl_offset *off = luaW_check_offset(L, 1);
    lua_Integer length = luaL_optinteger(L, 2, 0);

    if (length != 0) {
        off->curr += length;
    }
    else {
        off->curr += off->step;
    }
    off->step = 0;

    lua_pushinteger(L, off->curr);
    return 1;
}

/***
 * @function __index
 */
static int wl_offset_index(lua_State *L)
{
    struct wl_offset *off = luaW_check_offset(L, 1);
    const char *key = luaL_checkstring(L, 2);

    if (strcmp(key, "curr") == 0)
        lua_pushinteger(L, off->curr);
    else if (strcmp(key, "step") == 0)
        lua_pushinteger(L, off->step);
    else {
        luaL_getmetatable(L, "wslua.Offset");
        lua_pushstring(L, key);
        lua_rawget(L, -2);
    }
    return 1;
}

/***
 * @function __newindex
 */
static int wl_offset_newindex(lua_State *L)
{
    struct wl_offset *off = luaW_check_offset(L, 1);
    const char *key = luaL_checkstring(L, 2);
    lua_Integer val = luaL_checkinteger(L, 3);

    if (strcmp(key, "curr") == 0)
        off->curr = val;
    else if (strcmp(key, "step") == 0)
        off->step = val;
    else
        luaL_error(L, "Offset: invalid assignment with key %s", key);
    return 0;
}

/***
 * Offset string representation
 * @function __tostring
 * @treturn string The string representation
 */
static int wl_offset_tostring(lua_State *L)
{
    struct wl_offset *off = luaW_check_offset(L, 1);
    lua_pushfstring(L, "Offset: curr = %I, step = %I", off->curr, off->step);
    return 1;
}

static int wl_offset_gc(lua_State *L)
{
    struct wl_offset *off = luaW_check_offset(L, 1);
    free(off);
    return 0;
}

/***
 * Create a new Offset
 * @function Offset.new
 * @param start the offset start value
 * @treturn Offset The new Offset object
 */
static int wl_offset_new(lua_State *L)
{
    lua_Integer start = luaL_optinteger(L, 1, 0);
    struct wl_offset *off = xmalloc(sizeof(struct wl_offset));
    off->curr = start;
    off->step = 0;
    luaW_push_offset(L, off);
    return 1;
}

/***
 * @section end
 */
 
/***
 * Register a protocol
 * @function proto_register_protocol
 * @string name protocol name
 * @string short_name short protocol name
 * @string filter_name filter protocol name
 * @treturn Protocol a new protocol
 */
static int wl_proto_register_protocol(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    const char *short_name = luaL_checkstring(L, 2);
    const char *filter_name = luaL_checkstring(L, 3);

    int *ptr = NEWUSERDATA(L, int, "wslua.Protocol");
    *ptr = proto_register_protocol(name, short_name, filter_name);

    return 1;
}

/***
 * Register a field array
 * @function proto_register_field_array
 * @tparam {[string]=HFInfo,...} fields array of header field infos
 */
static int wl_proto_register_field_array(lua_State *L)
{
    int proto = *(int *)luaL_checkudata(L, 1, "wslua.Protocol");
    luaL_checktype(L, 2, LUA_TTABLE);

    hf_register_info *hf;

    lua_pushnil(L);
    while (lua_next(L, 2) != 0) {
        luaL_checktype(L, -2, LUA_TSTRING);
        luaL_checktype(L, -1, LUA_TTABLE);
        /* uses 'key' (at index -2) and 'value' (at index -1) */
        lua_pushcfunction(L, wl_hf_register_info_new);
        lua_insert(L, -2);
        /* call function on table value */
        luaW_call(L, 1, 1);
        hf = luaW_check_hf_register_info(L, -1);
        proto_register_field_array(proto, hf, 1);
        /* hf.name = <hfi>; pops value and key duplicate */
        lua_pushvalue(L, -2);
        lua_insert(L, -2);
        lua_settable(L, 2);
    }

    return 1;
}

/***
 * Register a subtree array
 * @function proto_register_subtree_array
 * @tparam {[string]=true,...} fields map of names to true
 */
static int wl_proto_register_subtree_array(lua_State *L)
{
    luaL_checktype(L, 1, LUA_TTABLE);

    int *index = xmalloc(sizeof(int));

    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        *index = -1;
        proto_register_subtree_array(&index, 1);
        /* removes 'value'; it's not used */
        lua_pop(L, 1);
        /* uses 'key' (at index -1) */
        lua_pushvalue(L, -1);
        lua_pushinteger(L, *index);
        lua_settable(L, 1); /* ett.name = id */
    }

    free(index);
    return 1;
}

static const struct luaL_Reg wl_protocol_m[] = {
    { NULL, NULL }
};

static const struct luaL_Reg wl_protoitem_m[] = {
    { "add_subtree", wl_protoitem_add_subtree },
    { "add_expert", wl_protoitem_add_expert },
    { "set_generated", wl_protoitem_set_generated },
    { "set_hidden", wl_protoitem_set_hidden },
    { "append_text", wl_protoitem_append_text },
    { NULL, NULL }
};

static const struct luaL_Reg wl_prototree_m[] = {
    { "add_item", wl_prototree_add_item },
    { "add_item_ret", wl_prototree_add_item_ret },
    { "add_checksum", wl_prototree_add_checksum },
    { "add_protocol", wl_prototree_add_protocol },
    { NULL, NULL }
};

static const struct luaL_Reg wl_offset_m[] = {
    { "next", wl_offset_next },
    { "__index", wl_offset_index },
    { "__newindex", wl_offset_newindex },
    { "__tostring", wl_offset_tostring },
    { "__gc", wl_offset_gc },
    { NULL, NULL }
};

static const struct luaL_Reg wl_offset_f[] = {
    { "new", wl_offset_new },
    { NULL, NULL }
};

static const struct luaL_Reg wl_proto_f[] = {
    { "proto_register_protocol", wl_proto_register_protocol },
    { "proto_register_field_array", wl_proto_register_field_array },
    { "proto_register_subtree_array", wl_proto_register_subtree_array },
    { NULL, NULL }
};

/* Receives module on the stack */
void wl_open_proto(lua_State *L)
{
    luaW_newmetatable(L, "wslua.Protocol", wl_protocol_m);
    luaW_newmetatable(L, "wslua.ProtoItem", wl_protoitem_m);
    luaW_newmetatable(L, "wslua.ProtoTree", wl_prototree_m);
    luaW_newmetatable(L, "wslua.HfRegisterInfo", NULL);
    luaW_newmetatable(L, "wslua.Offset", wl_offset_m);
    luaL_newlib(L, wl_offset_f);
    lua_setfield(L, -2, "Offset");
    luaL_setfuncs(L, wl_proto_f, 0);
}
