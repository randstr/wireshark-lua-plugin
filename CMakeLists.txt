
cmake_minimum_required(VERSION 3.12)

project(wireshark-lua-plugin VERSION 0.3.2 DESCRIPTION "Wireshark Lua 5.4 Plugin" LANGUAGES C)

option(ENABLE_REGEX "Build with lrexlib-pcre2" ON)

include(FeatureSummary)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(Wireshark CONFIG REQUIRED)
if(ENABLE_REGEX)
	find_package(PCRE2 REQUIRED)
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

add_compile_options(-Wall -Wextra)
add_compile_definitions(
	PLUGIN_VERSION=\"${PROJECT_VERSION}\"
	$<$<CONFIG:Debug>:WS_DEBUG>
)
if(ENABLE_REGEX)
	add_compile_definitions(
		HAVE_PCRE2
	)
endif()

add_subdirectory(lua)
add_subdirectory(src)
if(ENABLE_REGEX)
	add_subdirectory(lrexlib)
endif()

find_program(TSHARK_EXECUTABLE tshark
	HINTS "${Wireshark_INSTALL_PREFIX}/bin"
)
add_feature_info(TShark TSHARK_EXECUTABLE "executable to run tests")

if(TSHARK_EXECUTABLE)
	message(STATUS "Found tshark: ${TSHARK_EXECUTABLE}")
	cmake_path(CONVERT  "${CMAKE_BINARY_DIR}/_config" TO_NATIVE_PATH_LIST  _config_dir)
	cmake_path(CONVERT  "${CMAKE_BINARY_DIR}/_plugins" TO_NATIVE_PATH_LIST  _plugin_dir)
	cmake_path(CONVERT  "${_plugin_dir}/${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}/epan" TO_NATIVE_PATH_LIST  _target_dir)

	# Change Wireshark environment to load plugins from the build directory.
	# XXX Is there a way to avoid all the repetitive environment configuration for each tshark command?
	add_custom_target(test
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test
		COMMAND ${CMAKE_COMMAND} -E make_directory ${_config_dir}
		COMMAND ${CMAKE_COMMAND} -E make_directory ${_target_dir}
		COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:plugin> ${_target_dir}
		COMMAND ${CMAKE_COMMAND} -E echo "### Version ###"
		COMMAND ${CMAKE_COMMAND} -E env
			HOME="/nonexistant"
			WIRESHARK_CONFIG_DIR=${_config_dir}
			WIRESHARK_PLUGIN_DIR=${_plugin_dir}
			${TSHARK_EXECUTABLE} --version
			COMMAND ${CMAKE_COMMAND} -E echo "### Folders ###"
		COMMAND ${CMAKE_COMMAND} -E env
			HOME="/nonexistant"
			WIRESHARK_CONFIG_DIR=${_config_dir}
			WIRESHARK_PLUGIN_DIR=${_plugin_dir}
			${TSHARK_EXECUTABLE} -G folders
			COMMAND ${CMAKE_COMMAND} -E echo "### Plugins ###"
		COMMAND ${CMAKE_COMMAND} -E env
			HOME="/nonexistant"
			WIRESHARK_CONFIG_DIR=${_config_dir}
			WIRESHARK_PLUGIN_DIR=${_plugin_dir}
			${TSHARK_EXECUTABLE} -G plugins
		COMMAND ${CMAKE_COMMAND} -E echo ""
		COMMAND ${CMAKE_COMMAND} -E env
			HOME="/nonexistant"
			WIRESHARK_CONFIG_DIR=${_config_dir}
			WIRESHARK_PLUGIN_DIR=${_plugin_dir}
			${TSHARK_EXECUTABLE} -Xwslua2:test.lua -r empty.pcap
	)
endif()

find_program(LDOC_EXECUTABLE ldoc)
add_feature_info(LDoc LDOC_EXECUTABLE "required to build the documentation")

if(LDOC_EXECUTABLE)
	message(STATUS "Found ldoc: ${LDOC_EXECUTABLE}")

	add_custom_target(docs
		COMMAND ${LDOC_EXECUTABLE} -d "${CMAKE_BINARY_DIR}/doc" .
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		COMMENT "Generating documentation"
		VERBATIM
	)
endif()

feature_summary(WHAT ALL)
