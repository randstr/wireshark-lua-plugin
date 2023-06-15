#
# - Find PCRE2 libraries
#
#  PCRE2_INCLUDE_DIRS - where to find PCRE2 headers.
#  PCRE2_LIBRARIES    - List of libraries when using PCRE2.
#  PCRE2_FOUND        - True if PCRE2 is found.

find_package(PkgConfig QUIET)
pkg_search_module(PC_PCRE2 QUIET "libpcre2-8")

find_path(PCRE2_INCLUDE_DIR
	NAMES
		pcre2.h
	HINTS
		${PC_PCRE2_INCLUDE_DIRS}
)

find_library(PCRE2_STATIC_LIBRARY
	NAMES
		"libpcre2-8.a"
	HINTS
		${PC_PCRE2_STATIC_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2
	REQUIRED_VARS   PCRE2_STATIC_LIBRARY PCRE2_INCLUDE_DIR
	VERSION_VAR     PC_PCRE2_VERSION
)

if(PCRE2_FOUND)
	set(PCRE2_LIBRARIES ${PCRE2_STATIC_LIBRARY})
	set(PCRE2_INCLUDE_DIRS ${PCRE2_INCLUDE_DIR})
	set(PCRE2_DEFINITIONS "PCRE2_STATIC")
    else()
	set(PCRE2_LIBRARIES)
	set(PCRE2_INCLUDE_DIRS)
	set(PCRE2_DEFINITIONS)
endif()

mark_as_advanced(PCRE2_LIBRARIES PCRE2_INCLUDE_DIRS PCRE2_DEFINITIONS)
