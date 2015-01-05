#ifndef lua_HEADER
#define lua_HEADER

extern "C" {
#include <lua5.2/lua.h>
#include <lua5.2/lualib.h>
#include <lua5.2/lauxlib.h>
}

#include "trace.container.hpp"

typedef SerializedTrace::TraceContainerReader TCR;

extern "C" {

LUALIB_API int luaopen_lbapTrace (lua_State * L);

int lbapTrace_open (lua_State * L);

TCR * lbapTrace_check (lua_State * L, int position);

int lbapTrace_gc           (lua_State * L);
int lbapTrace_end_of_trace (lua_State * L);
int lbapTrace_get_frame    (lua_State * L);

}

#endif