
set(REX_SRC
	common.c
	pcre2/lpcre2.c
	pcre2/lpcre2_f.c
)

add_library(lrexlib STATIC ${REX_SRC})

target_link_libraries(lrexlib PRIVATE ${PCRE2_LIBRARIES})
target_include_directories(lrexlib SYSTEM PRIVATE ${PCRE2_INCLUDE_DIRS})
target_compile_definitions(lrexlib PRIVATE
	${PCRE2_DEFINITIONS}
	VERSION=\"2.9.2\"
	PCRE2_CODE_UNIT_WIDTH=8
)
