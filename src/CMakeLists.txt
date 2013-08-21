SET(FOO-SOURCES
  nfc-cpupwd
  nfc-mfclassic-ex
  nfc-mftry2
)

ADD_LIBRARY(nfcutils STATIC 
  nfc-utils.c
)
TARGET_LINK_LIBRARIES(nfcutils nfc)


FOREACH(source ${FOO-SOURCES})
  SET (TARGETS ${source}.c)

  IF(WIN32)
    SET(RC_COMMENT "${PACKAGE_NAME} utility")
    SET(RC_INTERNAL_NAME ${source})
    SET(RC_ORIGINAL_NAME ${source}.exe)
    SET(RC_FILE_TYPE VFT_APP)
	#CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/../contrib/win32/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/../windows/${source}.rc @ONLY)
	#LIST(APPEND TARGETS ${CMAKE_CURRENT_BINARY_DIR}/../windows/${source}.rc)
  ENDIF(WIN32)

  IF((${source} MATCHES "nfc-mfclassic-ex") OR (${source} MATCHES "nfc-mftry2"))
    LIST(APPEND TARGETS mifare)
  ENDIF((${source} MATCHES "nfc-mfclassic-ex") OR (${source} MATCHES "nfc-mftry2")) 

  IF(${source} MATCHES "nfc-cpupwd")
	  LIST(APPEND TARGETS crapto1 crypto1)
  ENDIF(${source} MATCHES "nfc-cpupwd")

  ADD_EXECUTABLE(${source} ${TARGETS})

  TARGET_LINK_LIBRARIES(${source} nfc)
  TARGET_LINK_LIBRARIES(${source} nfcutils)

  INSTALL(TARGETS ${source} RUNTIME DESTINATION bin COMPONENT utils)
ENDFOREACH(source)


#install required libraries
IF(WIN32)
  INCLUDE(InstallRequiredSystemLibraries)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/cmake/FixBundle.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/FixBundle.cmake @ONLY)
  INSTALL(SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/FixBundle.cmake)
ENDIF(WIN32)

