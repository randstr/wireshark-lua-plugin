
set(WSLUA2_SRC
	enums.c
	wauxlib.c
	wl_addr.c
	wl_expert.c
	wl_funnel.c
	wl_packet.c
	wl_pinfo.c
	wl_prefs.c
	wl_proto.c
	wl_value_string.c
	wl_tvbuff.c
	wslua.c
)

add_library(wslua2 STATIC ${WSLUA2_SRC})

target_link_libraries(wslua2 lua epan $<$<BOOL:ENABLE_REGEX>:lrexlib>)

target_include_directories(wslua2
	INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

add_library(plugin MODULE plugin.c)

target_link_libraries(plugin wslua2)

set_target_properties(plugin PROPERTIES
	OUTPUT_NAME "wslua2"
	PREFIX ""
	DEFINE_SYMBOL ""
	LINK_FLAGS "-Wl,--no-undefined"
)

install(TARGETS plugin
	LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin> ${Wireshark_PLUGIN_INSTALL_DIR}
	COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}"
)

string(TOLOWER "wireshark-lua-plugin-${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}-${PROJECT_VERSION}-x64-${CMAKE_SYSTEM_NAME}" _pkgname)

add_custom_target(package_prep
	COMMAND ${CMAKE_COMMAND} -E make_directory  ${CMAKE_BINARY_DIR}/${_pkgname}
	COMMAND ${CMAKE_COMMAND} -E copy
			${CMAKE_SOURCE_DIR}/README.md
			${CMAKE_SOURCE_DIR}/COPYING
			$<TARGET_FILE:plugin>
			${CMAKE_BINARY_DIR}/${_pkgname}
)

add_custom_target(package
	COMMAND ${CMAKE_COMMAND} -E tar czf ${_pkgname}.tar.gz --format=gnutar -- ${_pkgname}
	COMMAND ${CMAKE_COMMAND} -E sha256sum ${_pkgname}.tar.gz > ${_pkgname}.tar.gz.sha256sum.txt
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
add_dependencies(package package_prep)

add_custom_target(package_zip
	COMMAND ${CMAKE_COMMAND} -E tar cf ${_pkgname}.zip --format=zip -- ${_pkgname}
	COMMAND ${CMAKE_COMMAND} -E sha256sum ${_pkgname}.zip > ${_pkgname}.zip.sha256sum.txt
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
add_dependencies(package_zip package_prep)
