# This CMake script wants to use libnfc functionality, therefore it looks 
# for libnfc include files and libraries. 
#
# Operating Systems Supported:
# - Unix (requires pkg-config)
#   Tested with Ubuntu 9.04 and Fedora 11
# - Windows (requires MinGW)
#   Tested with Windows XP/Windows 7
#
# This should work for both 32 bit and 64 bit systems.
#
# Author: F. Kooman <fkooman@tuxed.net>
#

IF(NOT LIBNFC_FOUND)
  IF(WIN32)
	  FIND_PATH(LIBNFC_INCLUDE_DIRS nfc.h "$ENV{ProgramFiles}/Libnfc/include" NO_SYSTEM_ENVIRONMENT_PATH)
	  FIND_LIBRARY(LIBNFC_LIBRARIES NAMES libnfc PATHS "$ENV{ProgramFiles}/Libnfc/lib")
    SET(LIBNFC_LIBRARY_DIR "$ENV{ProgramFiles}/Libnfc/bin/")
  ELSE(WIN32)
    # If not under Windows we use PkgConfig
    FIND_PACKAGE (PkgConfig)
    IF(PKG_CONFIG_FOUND)
		PKG_CHECK_MODULES(LIBNFC REQUIRED libnfc)
    ELSE(PKG_CONFIG_FOUND)
      MESSAGE(FATAL_ERROR "Could not find PkgConfig")
    ENDIF(PKG_CONFIG_FOUND)
  ENDIF(WIN32)
  
  IF(LIBNFC_INCLUDE_DIRS AND LIBNFC_LIBRARIES)
	  SET(LIBNFC_FOUND TRUE)
  ENDIF(LIBNFC_INCLUDE_DIRS AND LIBNFC_LIBRARIES)
ENDIF(NOT LIBNFC_FOUND)

IF(LIBNFC_FOUND)
  IF(NOT LIBNFC_FIND_QUIETLY)
	  MESSAGE(STATUS "Found LIBNFC: ${LIBNFC_LIBRARIES} ${LIBNFC_INCLUDE_DIRS}")
  ENDIF (NOT LIBNFC_FIND_QUIETLY)
ELSE(LIBNFC_FOUND)
  IF(LIBNFC_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find libnfc")
  ENDIF(LIBNFC_FIND_REQUIRED)
ENDIF(LIBNFC_FOUND)
