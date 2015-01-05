#include "lua.h"


//#define LUA_DEBUG

static const struct luaL_Reg lbapTrace_lib_f [] = {
    {"open",         lbapTrace_open},
    {NULL, NULL}
};

static const struct luaL_Reg lbapTrace_TCR_m [] = {
    {"__gc",         lbapTrace_gc},
    {"end_of_trace", lbapTrace_end_of_trace},
    {"get_frame",    lbapTrace_get_frame},
    {NULL, NULL}
};


LUALIB_API int luaopen_lbapTrace (lua_State * L) {
    luaL_newmetatable(L, "lbapTrace.TCR");
    luaL_setfuncs(L, lbapTrace_TCR_m, 0);
    lua_pushstring(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);

    luaL_newlib(L, lbapTrace_lib_f);

    return 1;
}


int lbapTrace_open (lua_State * L) {
    const char * filename = luaL_checkstring(L, 1);

    TCR * tcr = new TCR(filename);

    TCR ** luaTcr = (TCR **) lua_newuserdata(L, sizeof(TCR **));
    luaL_getmetatable(L, "lbapTrace.TCR");
    lua_setmetatable(L, -2);

    *luaTcr = tcr;

    return 1;
}


TCR * lbapTrace_check (lua_State * L, int position) {
    TCR * tcr;
    void ** userdata = (void **) luaL_checkudata(L, position, "lbapTrace.TCR");
    luaL_argcheck(L, userdata != NULL, position, "lbapTrace.TCR expected");
    tcr = (TCR *) *userdata;
    return tcr;
}


int lbapTrace_gc (lua_State * L) {
    TCR * tcr = lbapTrace_check(L, -1);

    delete tcr;

    return 0;
}


int lbapTrace_end_of_trace (lua_State * L) {
    TCR * tcr = lbapTrace_check(L, -1);

    if (tcr->end_of_trace())
        lua_pushboolean(L, 1);
    else
        lua_pushboolean(L, 0);

    return 1;
}


void lbapTrace_push_operand_value_list_table (lua_State * L, const operand_value_list & op_list) {
    lua_newtable(L);

    for (int i = 0; i < op_list.elem_size(); i++) {
        const operand_info & op_info = op_list.elem(i);

        lua_pushinteger(L, i + 1);
        lua_newtable(L);

        lua_pushstring(L, "read");
        if (op_info.operand_usage().read())
            lua_pushboolean(L, 1);
        else
            lua_pushboolean(L, 0);
        lua_settable(L, -3);

        lua_pushstring(L, "written");
        if (op_info.operand_usage().written())
            lua_pushboolean(L, 1);
        else
            lua_pushboolean(L, 0);
        lua_settable(L, -3);

        lua_pushstring(L, "index");
        if (op_info.operand_usage().index())
            lua_pushboolean(L, 1);
        else
            lua_pushboolean(L, 0);
        lua_settable(L, -3);

        lua_pushstring(L, "base");
        if (op_info.operand_usage().base())
            lua_pushboolean(L, 1);
        else
            lua_pushboolean(L, 0);
        lua_settable(L, -3);

        lua_pushstring(L, "bit_length");
        lua_pushinteger(L, op_info.bit_length());
        lua_settable(L, -3);

        if (op_info.operand_info_specific().has_mem_operand()) {
            lua_pushstring(L, "type");
            lua_pushstring(L, "mem");
            lua_settable(L, -3);

            lua_pushstring(L, "address");
            lua_pushinteger(L, op_info.operand_info_specific().mem_operand().address());
            lua_settable(L, -3);
        }
        else if (op_info.operand_info_specific().has_reg_operand()) {
            lua_pushstring(L, "type");
            lua_pushstring(L, "reg");
            lua_settable(L, -3);

            lua_pushstring(L, "name");
            lua_pushstring(L, op_info.operand_info_specific().reg_operand().name().c_str());
            lua_settable(L, -3);
        }

        if (op_info.taint_info().has_taint_id()) {
            lua_pushstring(L, "taint");
            lua_pushinteger(L, op_info.taint_info().taint_id());
            lua_settable(L, -3);
        }
        else if (    (op_info.taint_info().has_taint_multiple())
                  && (op_info.taint_info().taint_multiple())) {
            lua_pushstring(L, "taint");
            lua_pushstring(L, "multiple");
            lua_settable(L, -3);
        }
        lua_settable(L, -3);
    }
}


void lbapTrace_push_taint_intro_list_table (lua_State * L, const taint_intro_list & taint_intro_list) {
    lua_newtable(L);
    for (int i = 0; i < taint_intro_list.elem_size(); i++) {
        const taint_intro & taint_i = taint_intro_list.elem(i);

        lua_pushinteger(L, i + 1);
        lua_newtable(L);

        lua_pushstring(L, "address");
        lua_pushinteger(L, taint_i.addr());
        lua_settable(L, -3);

        lua_pushstring(L, "taint_id");
        lua_pushinteger(L, taint_i.taint_id());
        lua_settable(L, -3);

        if (taint_i.has_value()) {
            lua_pushstring(L, "value");
            lua_pushlstring(L, taint_i.value().data(), taint_i.value().size());
            lua_settable(L, -3);
        }

        if (taint_i.has_source_name()) {
            lua_pushstring(L, "offset");
            lua_pushinteger(L, taint_i.offset());
            lua_settable(L, -3);
        }

        if (taint_i.has_offset()) {
            lua_pushstring(L, "source_name");
            lua_pushlstring(L, taint_i.source_name().data(), taint_i.source_name().size());
            lua_settable(L, -3);
        }

        lua_settable(L, -3);
    }
}


int lbapTrace_get_frame (lua_State * L) {
    TCR * tcr = lbapTrace_check(L, -1);

    if (tcr->end_of_trace()) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    const std::auto_ptr<frame> & f = tcr->get_frame();

    if (f->has_std_frame()) {
        lua_pushstring(L, "type");
        lua_pushstring(L, "std_frame");
        lua_settable(L, -3);

        const std_frame & std_f = f->std_frame();

        lua_pushstring(L, "rawbytes");
        lua_pushlstring(L, std_f.rawbytes().data(), std_f.rawbytes().size());
        lua_settable(L, -3);

        lua_pushstring(L, "address");
        lua_pushinteger(L, std_f.address());
        lua_settable(L, -3);

        lua_pushstring(L, "thread_id");
        lua_pushinteger(L, std_f.thread_id());
        lua_settable(L, -3);

        lua_pushstring(L, "operand_pre_list");
        lbapTrace_push_operand_value_list_table(L, std_f.operand_pre_list());
        lua_settable(L, -3);

        lua_pushstring(L, "operand_post_list");
        lbapTrace_push_operand_value_list_table(L, std_f.operand_post_list());
        lua_settable(L, -3);
    }

    else if (f->has_syscall_frame()) {
        lua_pushstring(L, "type");
        lua_pushstring(L, "syscall_frame");
        lua_settable(L, -3);

        const syscall_frame & syscall_f = f->syscall_frame();

        lua_pushstring(L, "address");
        lua_pushinteger(L, syscall_f.address());
        lua_settable(L, -3);

        lua_pushstring(L, "thread_id");
        lua_pushinteger(L, syscall_f.thread_id());
        lua_settable(L, -3);

        lua_pushstring(L, "number");
        lua_pushinteger(L, syscall_f.number());
        lua_settable(L, -3);

        /* a bit incomplete but meh */
    }

    else if (f->has_exception_frame()) {
        lua_pushstring(L, "type");
        lua_pushstring(L, "exception_frame");
        lua_settable(L, -3);
    }

    else if (f->has_taint_intro_frame()) {
        lua_pushstring(L, "type");
        lua_pushstring(L, "taint_intro_frame");
        lua_settable(L, -3);

        lua_pushstring(L, "taint_intro_list");
        lbapTrace_push_taint_intro_list_table(L, f->taint_intro_frame().taint_intro_list());
        lua_settable(L, -3);
    }

    else if (f->has_modload_frame()) {
        lua_pushstring(L, "type");
        lua_pushstring(L, "modload_frame");
        lua_settable(L, -3);

        const modload_frame & modload_f = f->modload_frame();

        lua_pushstring(L, "low_address");
        lua_pushinteger(L, modload_f.low_address());
        lua_settable(L, -3);

        lua_pushstring(L, "high_address");
        lua_pushinteger(L, modload_f.high_address());
        lua_settable(L, -3);

        lua_pushstring(L, "module_name");
        lua_pushlstring(L, modload_f.module_name().data(), modload_f.module_name().size());
        lua_settable(L, -3);
    }
    else if (f->has_key_frame()) {
        lua_pushstring(L, "type");
        lua_pushstring(L, "key_frame");
        lua_settable(L, -3);
    }

    return 1;
}
