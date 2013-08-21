AM_CFLAGS = @libnfc_CFLAGS@

bin_PROGRAMS = \
		nfc-cpupwd \
		nfc-mftry2 \
		nfc-mfclassic-ex

nfc_cpupwd_SOURCES = nfc-cpupwd.c crapto1.c crypto1.c nfc-utils.c
nfc_cpupwd_LDADD =  @libnfc_LIBS@

nfc_mftry2_SOURCES = nfc-mftry2.c mifare.c nfc-utils.c
nfc_mftry2_LDADD = @libnfc_LIBS@

nfc_mfclassic_ex_SOURCES = nfc-mfclassic-ex.c mifare.c nfc-utils.c
nfc_mfclassic_ex_LDADD =  @libnfc_LIBS@
