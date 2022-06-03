
set(LUA_SRC
	src/lapi.c
	src/lauxlib.c
	src/lbaselib.c
	src/lbitlib.c
	src/lcode.c
	src/lcorolib.c
	src/lctype.c
	src/ldblib.c
	src/ldebug.c
	src/ldo.c
	src/ldump.c
	src/lfunc.c
	src/lgc.c
	src/linit.c
	src/liolib.c
	src/llex.c
	src/lmathlib.c
	src/lmem.c
	src/loadlib.c
	src/lobject.c
	src/lopcodes.c
	src/loslib.c
	src/lparser.c
	src/lstate.c
	src/lstring.c
	src/lstrlib.c
	src/ltable.c
	src/ltablib.c
	src/ltm.c
	src/lundump.c
	src/lutf8lib.c
	src/lvm.c
	src/lzio.c
)

set(LUA_DEFINITIONS)
set(LUA_LINK_FLAGS)
set(USE_READLINE False)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	list(APPEND LUA_DEFINITIONS LUA_USE_LINUX)
	list(APPEND LUA_LINK_FLAGS -ldl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	list(APPEND LUA_DEFINITIONS LUA_USE_MACOSX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	list(APPEND LUA_DEFINITIONS LUA_USE_WINDOWS)
elseif(UNIX)
	list(APPEND LUA_DEFINITIONS LUA_USE_POSIX)
#	list(APPEND LUA_DEFINITIONS LUA_USE_DLOPEN)
#	list(APPEND LUA_LINK_FLAGS -ldl)
endif()

if(UNIX)
	set(USE_READLINE True)
endif()

add_library(lua STATIC ${LUA_SRC})

target_compile_definitions(lua PUBLIC
	${LUA_DEFINITIONS}
	$<$<BOOL:USE_READLINE>:LUA_USE_READLINE>
	LUA_ROOT=\"${Wireshark_INSTALL_PREFIX}/\"
)

target_include_directories(lua INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)

target_link_libraries(lua PUBLIC
	${LUA_LINK_FLAGS}
	$<$<BOOL:UNIX>:m>
	$<$<BOOL:USE_READLINE>:-lreadline>
)
