/**
 * File name: smllib_test.c
 *
 * @author Christian Reimann <cybernico@gmx.de>
 * @author Tobias Jeske <tobias.jeske@tu-harburg.de>
 * @remark Supported by the Institute for Security in Distributed Applications (http://www.sva.tu-harburg.de)
 * @see The GNU Public License (GPL)
 */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>

#include "smllib_test.h"
#include "smllib_types.h"
#include "smllib_encode.h"
#include "smllib_parse.h"
#include "smllib_tools.h"

int sml_encode_parse_msg_test(SML_Message* message) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result refResult;
	SML_Message refMessage;

	int retValue = 1;
	uint32_t offset = 0;
	result = sml_encode_message_binary(message);
	if(result.resultCode == SML_ENCODE_OK) {
		if(sml_parse_message_binary(result.resultBinary, &offset, &refMessage) == SML_PARSE_OK) {
			refResult = sml_encode_message_binary(&refMessage);
			if(refResult.resultCode == SML_ENCODE_OK) {
				if(result.length == refResult.length && memcmp(result.resultBinary, refResult.resultBinary, result.length) == 0) {
					retValue = 0;
				}
				free(refResult.resultBinary);
			}
		}
		sml_parser_free();
		free(result.resultBinary);
	}

	return retValue;
}

int sml_encode_parse_file_test(SML_File* file) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result refResult;
	SML_File refFile;

	int retValue = 1;
	result = sml_encode_file_binary(file);
	if(result.resultCode == SML_ENCODE_OK) {
		if(sml_parse_file_binary(result.resultBinary, file->msgCount, &refFile) == SML_PARSE_OK) {
			refResult = sml_encode_file_binary(&refFile);
			if(refResult.resultCode == SML_ENCODE_OK) {
				if(result.length == refResult.length && memcmp(result.resultBinary, refResult.resultBinary, result.length) == 0) {
					retValue = 0;
				}
				free(refResult.resultBinary);
			}
		}
		sml_parser_free();
		free(result.resultBinary);
	}

	return retValue;
}

int sml_transport_msg_test(SML_Message* message) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result refResult;
	SML_Message refMessage;

	int retValue = 1;
	uint32_t offset = 0;
	result = sml_transport_encode_message(message);
	if(result.resultCode == SML_ENCODE_OK) {
		if(sml_transport_parse_message(result.resultBinary, &offset, &refMessage) == SML_PARSE_OK) {
			refResult = sml_transport_encode_message(&refMessage);
			if(refResult.resultCode == SML_ENCODE_OK) {
				if(result.length == refResult.length && memcmp(result.resultBinary, refResult.resultBinary, result.length) == 0) {
					retValue = 0;
				}
				free(refResult.resultBinary);
			}
		}
		sml_parser_free();
		free(result.resultBinary);
	}

	return retValue;
}

int sml_transport_file_test(SML_File* file) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result refResult;
	SML_File refFile;

	int retValue = 1;
	result = sml_transport_encode_file(file);
	if(result.resultCode == SML_ENCODE_OK) {
		if(sml_transport_parse_file(result.resultBinary, file->msgCount, &refFile) == SML_PARSE_OK) {
			refResult = sml_transport_encode_file(&refFile);
			if(refResult.resultCode == SML_ENCODE_OK) {
				if(result.length == refResult.length && memcmp(result.resultBinary, refResult.resultBinary, result.length) == 0) {
					retValue = 0;
				}
				free(refResult.resultBinary);
			}
		}
		sml_parser_free();
		free(result.resultBinary);
	}

	return retValue;
}
