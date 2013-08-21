/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2011      Adam Laurie
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/**
 * @file nfc-mfcpupwd.c
 * @brief do CPU pwd card related commands
 */

/**
 * based on nfc-anticol.c
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <nfc/nfc.h>

#include "nfc-utils.h"
#include "crapto1.h"

#define SAK_FLAG_ATS_SUPPORTED 0x20

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static uint8_t abtRawUid[12];
static uint8_t abtAtqa[2];
static uint8_t abtSak;
static uint8_t abtAts[MAX_FRAME_LEN];
static uint8_t szAts = 0;
static size_t szCL = 1;//Always start with Cascade Level 1 (CL1)
static nfc_device *pnd;

bool    quiet_output = true;
bool    iso_ats_supported = false;

uint8_t zero_one_switch = 1;

// ISO14443A Anti-Collision Commands
uint8_t  abtReqa[1] = { 0x26 };
uint8_t  abtSelectAll[2] = { 0x93, 0x20 };
uint8_t  abtSelectTag[9] = { 0x93, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t  abtRats[4] = { 0xe0, 0x50, 0x00, 0x00 };
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };
#define CASCADE_BIT 0x04

// special unlock command
uint8_t  abtUnlock1[1] = { 0x40 };
uint8_t  abtUnlock2[1] = { 0x43 };
uint8_t  abtWipe[1] = { 0x41 };
uint8_t abtWrite[4] = { 0xa0,  0x00,  0x5f,  0xb1 };
uint8_t abtData[18] = { 0x01,  0x23,  0x45,  0x67,  0x00,  0x08,  0x04,  0x00,  0x46,  0x59,  0x25,  0x58,  0x49,  0x10,  0x23,  0x02,  0x23,  0xeb };
uint8_t abtBlank[18] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x36, 0xCC };


static  bool
transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex_bits(pbtTx, szTxBits);
  }
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
    return false;

  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex_bits(abtRx, szRxBits);printf(" ATS: ");
  }
  // Succesful transfer
  return true;
}

static  bool
transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  // Show transmitted command
  if (!quiet_output) {
    printf("Sent bits:     ");
    print_hex(pbtTx, szTx);
  }
  int res;
  // Transmit the command bytes
  if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
    return false;

  // Show received answer
  if (!quiet_output) {
    printf("Received bits: ");
    print_hex(abtRx, res);
  }
  // Succesful transfer
  return true;
}

void auto_switch(uint8_t *pbtTx)
{
  if(pbtTx[0] == 0x0a){
    zero_one_switch = (zero_one_switch == 0)?1:0;
    if(zero_one_switch == 1){
        pbtTx[0] = 0x0b;
    }
  }
}

uint32_t prepare_uint32(uint8_t* value) {
	uint8_t temp[4] = {0x00, 0x00, 0x00, 0x00};
	uint32_t result = 0x0;
	temp[0] = value[3];
	temp[1] = value[2];
	temp[2] = value[1];
	temp[3] = value[0];

	result = *(uint32_t*)&temp;
	//printf("%x\n", result);
	return result;
}

static void
print_usage(char *argv[])
{
  printf("Usage: %s [OPTIONS] [UID]\n", argv[0]);
  printf("Options:\n");
  printf("\t-h\tHelp. Print this message.\n");
  //printf("\t-f\tFormat. Delete all data (set to 0xFF) and reset ACLs to default.\n");
  //printf("\t-q\tQuiet mode. Suppress output of READER and CARD data (improves timing).\n");
  //printf("\n\tSpecify UID (4 HEX bytes) to set UID, or leave blank for default '01234567'.\n");
  //printf("\tThis utility can be used to recover cards that have been damaged by writing bad\n");
  //printf("\tdata (e.g. wrong BCC), thus making them non-selectable by most tools/readers.\n");
  //printf("\n\t*** Note: this utility only works with special Mifare 1K cards (Chinese clones).\n\n");
  printf("\t-d\tDebug mode. show output of READER and CARD data.\n");
  printf("\t-w\tWrite UID to the card, [UID] is mandatory if this option set.\n");
  printf("\t-i\tReset read count.\n");
  printf("\t-r\tRead scan result.\n");
  printf("\n\tSpecify UID (4 HEX bytes) to set UID, or leave blank for default 'FFFFFFFF'.\n");
}



int
main(int argc, char *argv[])
{
  int      arg, i;
  //bool     format = false;
  unsigned int c;
  char     tmp[3] = { 0x00, 0x00, 0x00 };
  bool     writeUid = false;
  bool     resetCount = false;
  bool     readData = false;
  uint8_t  read_uid[4] = {0x00, 0x00, 0x00, 0x00};
  uint8_t  card_uid[4] = {0x00, 0x00, 0x00, 0x00};


  // Get commandline options
  for (arg = 1; arg < argc; arg++) {
    if (0 == strcmp(argv[arg], "-h")) {
      print_usage(argv);
      exit(EXIT_SUCCESS);
    } else if (0 == strcmp(argv[arg], "-w")) {
      writeUid = true;
    } else if (0 == strcmp(argv[arg], "-i")) {
      resetCount = true;
    } else if (0 == strcmp(argv[arg], "-r")) {
	  readData = true;	
	} else if (0 == strcmp(argv[arg], "-d")) {
	  quiet_output = false;	
	} else if (strlen(argv[arg]) == 8) {
      for (i = 0 ; i < 4 ; ++i) {
        memcpy(tmp, argv[arg] + i * 2, 2);
        sscanf(tmp, "%02x", &c);
        //abtData[i] = (char) c;
		card_uid[i] = (char) c;
      }
      //abtData[4] = abtData[0] ^ abtData[1] ^ abtData[2] ^ abtData[3];
      //iso14443a_crc_append(abtData, 16);
    } else {
      ERR("%s is not supported option.", argv[arg]);
      print_usage(argv);
      exit(EXIT_FAILURE);
    }
  }

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);

  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Initialise NFC device as "initiator"
  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Disable 14443-4 autoswitching
  //if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
  //  nfc_perror(pnd, "nfc_device_set_property_bool");
  //  nfc_close(pnd);
  //  nfc_exit(context);
  //  exit(EXIT_FAILURE);
  //}

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

  // Send the 7 bits request command specified in ISO 14443A (0x26)
  if (!transmit_bits(abtReqa, 7)) {
    printf("Error: No tag available\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  memcpy(abtAtqa, abtRx, 2);

  // Anti-collision
  transmit_bytes(abtSelectAll, 2);

  // Check answer
  if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
    printf("WARNING: BCC check failed!\n");
  }

  // Save the UID CL1
  memcpy(abtRawUid, abtRx, 4);

  //Prepare and send CL1 Select-Command
  memcpy(abtSelectTag + 2, abtRx, 5);
  iso14443a_crc_append(abtSelectTag, 7);
  transmit_bytes(abtSelectTag, 9);
  abtSak = abtRx[0];

  // Test if we are dealing with a CL2
  if (abtSak & CASCADE_BIT) {
    szCL = 2;//or more
    // Check answer
    if (abtRawUid[0] != 0x88) {
      printf("WARNING: Cascade bit set but CT != 0x88!\n");
    }
  }

  if (szCL == 2) {
    // We have to do the anti-collision for cascade level 2

    // Prepare CL2 commands
    abtSelectAll[0] = 0x95;

    // Anti-collision
    transmit_bytes(abtSelectAll, 2);

    // Check answer
    if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
      printf("WARNING: BCC check failed!\n");
    }

    // Save UID CL2
    memcpy(abtRawUid + 4, abtRx, 4);

    // Selection
    abtSelectTag[0] = 0x95;
    memcpy(abtSelectTag + 2, abtRx, 5);
    iso14443a_crc_append(abtSelectTag, 7);
    transmit_bytes(abtSelectTag, 9);
    abtSak = abtRx[0];

    // Test if we are dealing with a CL3
    if (abtSak & CASCADE_BIT) {
      szCL = 3;
      // Check answer
      if (abtRawUid[0] != 0x88) {
        printf("WARNING: Cascade bit set but CT != 0x88!\n");
      }
    }

    if (szCL == 3) {
      // We have to do the anti-collision for cascade level 3

      // Prepare and send CL3 AC-Command
      abtSelectAll[0] = 0x97;
      transmit_bytes(abtSelectAll, 2);

      // Check answer
      if ((abtRx[0] ^ abtRx[1] ^ abtRx[2] ^ abtRx[3] ^ abtRx[4]) != 0) {
        printf("WARNING: BCC check failed!\n");
      }

      // Save UID CL3
      memcpy(abtRawUid + 8, abtRx, 4);

      // Prepare and send final Select-Command
      abtSelectTag[0] = 0x97;
      memcpy(abtSelectTag + 2, abtRx, 5);
      iso14443a_crc_append(abtSelectTag, 7);
      transmit_bytes(abtSelectTag, 9);
      abtSak = abtRx[0];
    }
  }

  // Request ATS, this only applies to tags that support ISO 14443A-4
  if (abtRx[0] & SAK_FLAG_ATS_SUPPORTED) {
    iso_ats_supported = true;
  }

  printf("\nFound tag with\n UID: ");
  switch (szCL) {
    case 1:
      printf("%02x%02x%02x%02x", abtRawUid[0], abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      break;
    case 2:
      printf("%02x%02x%02x", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      printf("%02x%02x%02x%02x", abtRawUid[4], abtRawUid[5], abtRawUid[6], abtRawUid[7]);
      break;
    case 3:
      printf("%02x%02x%02x", abtRawUid[1], abtRawUid[2], abtRawUid[3]);
      printf("%02x%02x%02x", abtRawUid[5], abtRawUid[6], abtRawUid[7]);
      printf("%02x%02x%02x%02x", abtRawUid[8], abtRawUid[9], abtRawUid[10], abtRawUid[11]);
      break;
  }
  printf("\n");
  printf("ATQA: %02x%02x\n SAK: %02x\n", abtAtqa[1], abtAtqa[0], abtSak);
  if (szAts > 1) { // if = 1, it's not actual ATS but error code
    printf(" ATS: ");
    print_hex(abtAts, szAts);
  }
  printf("\n");



  // now reset UID
  //iso14443a_crc_append(abtHalt, 2);
  //transmit_bytes(abtHalt, 4);
  //transmit_bits(abtUnlock1, 7);
  //if (format) {
  //  transmit_bytes(abtWipe, 1);
  //  transmit_bytes(abtHalt, 4);
  //  transmit_bits(abtUnlock1, 7);
  //}
  //transmit_bytes(abtUnlock2, 1);
  //transmit_bytes(abtWrite, 4);
  //transmit_bytes(abtData, 18);
  //if (format) {
  //  for (i = 3 ; i < 64 ; i += 4) {
  //    abtWrite[1] = (char) i;
  //    iso14443a_crc_append(abtWrite, 2);
  //    transmit_bytes(abtWrite, 4);
  //    transmit_bytes(abtBlank, 18);
  //  }
  //}


  //uint8_t abtNeverUse = {0x0a, 0x00, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t abtReadData00[9]  = {0x0a, 0x00, 0x00, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t abtReadData01[9]  = {0x0a, 0x00, 0x00, 0xae, 0x00, 0x01, 0x00, 0x00, 0x00};
  uint8_t abtReadUid[9]     = {0x0a, 0x00, 0x00, 0xae, 0x00, 0x02, 0x00, 0x00, 0x00};
  uint8_t abtWriteUid[14]   = {0x0a, 0x00, 0x00, 0xae, 0x01, 0x02, 0x05, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00};
  uint8_t abtReadCount[9]   = {0x0a, 0x00, 0x00, 0xae, 0x00, 0x03, 0x00, 0x00, 0x00};
  uint8_t abtWriteCount[10] = {0x0a, 0x00, 0x00, 0xae, 0x01, 0x03, 0x01, 0x00, 0x00, 0x00};

  // send rats to enable CPU card
  printf("Sending RATS... ");
  iso14443a_crc_append(abtRats, 2);
  if(transmit_bytes(abtRats, 4)){
	  printf("\tDone! \n");
  }


  // read uid
  printf("Reading uid: ");
  auto_switch(abtReadUid);
  iso14443a_crc_append(abtReadUid, 7);
  if(transmit_bytes(abtReadUid, 9)){
      printf("%02x%02x%02x%02x", abtRx[2], abtRx[3], abtRx[4], abtRx[5]);
	  printf("\tDone! \n");
	  read_uid[0] = abtRx[2];
	  read_uid[1] = abtRx[3];
	  read_uid[2] = abtRx[4];
	  read_uid[3] = abtRx[5];	  
  }

  // write uid
  if(writeUid) {
	  printf("Writing uid: ");
	  printf("%02x%02x%02x%02x", card_uid[0], card_uid[1], card_uid[2], card_uid[3]);
	  abtWriteUid[7] = card_uid[0];
	  abtWriteUid[8] = card_uid[1];
	  abtWriteUid[9] = card_uid[2];
	  abtWriteUid[10] = card_uid[3];
      auto_switch(abtWriteUid);
	  iso14443a_crc_append(abtWriteUid, 12);
	  if(transmit_bytes(abtWriteUid, 14)){
		  printf("\tDone! \n");
	  }
  }

  // reset count
  if(resetCount) {
	  printf("Resetting count... ");
      auto_switch(abtWriteCount);
	  iso14443a_crc_append(abtWriteCount, 8);
	  if(transmit_bytes(abtWriteCount, 10)){
		  printf("\tDone! \n");
	  }
  }

  // read data
  if(readData) {
	  printf("Reading data: ");
      auto_switch(abtReadCount);
	  iso14443a_crc_append(abtReadCount, 7);
	  if(transmit_bytes(abtReadCount, 9)){
		  printf("\tRead count:%d\tDone!\n", abtRx[2]);
	  }

	  if(abtRx[2] == 2) {
		  auto_switch(abtReadData00);
		  iso14443a_crc_append(abtReadData00, 7);
		  transmit_bytes(abtReadData00, 9);
		  printf("  Count:0, Key:%02x, Block:%02x\tDone!\n", abtRx[2], abtRx[3]);
		  /*printf("\tData:0, Key:%02x, Block:%02x, Reader challenge:%02x%02x%02x%02x, Reader Response:%02x%02x%02x%02x\tDone!\n",
				  abtRx[2], abtRx[3],
				  abtRx[4], abtRx[5], abtRx[6], abtRx[7],
				  abtRx[8], abtRx[9], abtRx[10], abtRx[11]);*/
		  
		  uint32_t uid = prepare_uint32(read_uid);
		  uint32_t chal = 0x00000000;
		  uint32_t rchal = prepare_uint32(&abtRx[4]);
		  uint32_t rresp = prepare_uint32(&abtRx[8]);
		  
		  auto_switch(abtReadData01);
		  iso14443a_crc_append(abtReadData01, 7);
		  transmit_bytes(abtReadData01, 9);
		  printf("  Count:1, Key:%02x, Block:%02x\tDone!\n", abtRx[2], abtRx[3]);
		  /*printf("\tData:1, Key:%02x, Block:%02x, Reader challenge:%02x%02x%02x%02x, Reader Response:%02x%02x%02x%02x\tDone!\n",
				  abtRx[2], abtRx[3],
				  abtRx[4], abtRx[5], abtRx[6], abtRx[7],
				  abtRx[8], abtRx[9], abtRx[10], abtRx[11]);*/

		  uint32_t chal2 = 0x00000000;
		  uint32_t rchal2 = prepare_uint32(&abtRx[4]);
		  uint32_t rresp2 = prepare_uint32(&abtRx[8]);
		  uint64_t key;

		struct Crypto1State *s = lfsr_recovery32(rresp ^ prng_successor(chal, 64), 0), *t;
		for(t = s; t->odd | t->even; ++t) {
			lfsr_rollback_word(t, 0, 0);
			lfsr_rollback_word(t, rchal, 1);
			lfsr_rollback_word(t, uid ^ chal, 0);
			crypto1_get_lfsr(t, &key);
			crypto1_word(t, uid ^ chal2, 0);
			crypto1_word(t, rchal2, 1);
			if (rresp2 == (crypto1_word(t, 0, 0) ^ prng_successor(chal2, 64))) {
				printf("\nKey found: %llx\n", key);
				break;
			}
		}
	  }
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
