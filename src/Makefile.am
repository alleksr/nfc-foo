bin_PROGRAMS = \
		nfc-cpupwd \
		nfc-mftry2 \
		nfc-mfclassic-ex

# set the include path found by configure
AM_CPPFLAGS = $(all_includes) $(LIBNFC_CFLAGS)

AM_CFLAGS = -I$(top_srcdir)/libnfc -I$(top_srcdir)

noinst_LTLIBRARIES = libnfcutils.la

libnfcutils_la_SOURCES = nfc-utils.c

nfc_cpupwd_SOURCES = nfc-cpupwd.c crapto1.c crypo1.c
nfc_cpupwd_LDADD = $(top_builddir)/libnfc/libnfc.la \
		 $(top_builddir)/utils/libnfcutils.la

nfc_mftry2_SOURCES = nfc-mftry2.c mifare.c
nfc_mftry2_LDADD = $(top_builddir)/libnfc/libnfc.la \
		 $(top_builddir)/utils/libnfcutils.la

nfc_mfclassic_ex_SOURCES = nfc-mfclassic-ex.c mifare.c 
nfc_mfclassic_ex_LDADD = $(top_builddir)/libnfc/libnfc.la \
		 $(top_builddir)/utils/libnfcutils.la


EXTRA_DIST = CMakeLists.txt
