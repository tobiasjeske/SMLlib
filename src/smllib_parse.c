/**
 * File name: smllib_parse.c
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

#include "smllib_parse.h"
#include "smllib_tools.h"

#ifdef SMLLIB_DEBUG
	#include <stdio.h>
#endif

uint8_t sml_parse_file_binary(const unsigned char* smlBinary, uint32_t msgCount, SML_File* smlFile) {
	uint32_t i;
	uint32_t offset = 0;
	smlFile->msgCount = msgCount;
	smlFile->messages = (SML_Message**)calloc(msgCount, sizeof(SML_Message*));
	p_sml_add_pointer(smlFile->messages);

	for(i=0; i<msgCount; i++) {
		smlFile->messages[i] = (SML_Message*)calloc(1, sizeof(SML_Message));
		p_sml_add_pointer(smlFile->messages[i]);
		if(sml_parse_message_binary(smlBinary, &offset, smlFile->messages[i]) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t sml_parse_message_binary(const unsigned char* smlBinary, uint32_t* offset, SML_Message* smlMessage) {
	uint16_t crc16;
	uint32_t offsetPrev = *offset;

	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 6) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &smlMessage->transactionId) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &smlMessage->groupNo) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &smlMessage->abortOnError) ||
		SML_PARSE_ERROR == p_sml_parse_messagebody(smlBinary, offset, &smlMessage->messageBody)) {
		return SML_PARSE_ERROR;
	}

	#ifdef SMLLIB_DEBUG
		printf("transactionId: %s\n", smlMessage->transactionId);
		printf("groupNo: %02X\n", smlMessage->groupNo);
		printf("abortOnError: %02X\n", smlMessage->abortOnError);
		printf("messageBodyTag: %08X\n", (unsigned int)smlMessage->messageBody.choiceTag);
		printf("========= endOfParserOutput =========\n");
		printf("\n");
	#endif

	/* Calculate and compare crc16 */
	crc16 = crc16_ccitt(smlBinary+offsetPrev, (*offset)-offsetPrev);

	if(p_sml_parse_unsigned16(smlBinary, offset, &smlMessage->crc16) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	else if(smlMessage->crc16 != crc16) {
		return SML_PARSE_ERROR;
	}
	/* Check last byte */
	else if(smlBinary[*offset] != 0x00) {
		return SML_PARSE_ERROR;
	}
	else {
		(*offset)++;
		return SML_PARSE_OK;
	}
}

uint8_t sml_transport_parse_file(const unsigned char* smlBinary, uint32_t msgCount, SML_File* file) {
	uint32_t i;
	uint32_t offset = 0;
	file->msgCount = msgCount;
	file->messages = (SML_Message**)calloc(msgCount, sizeof(SML_Message*));
	p_sml_add_pointer(file->messages);
	for(i=0; i<msgCount; i++) {
		file->messages[i] = (SML_Message*)calloc(1, sizeof(SML_Message));
		p_sml_add_pointer(file->messages[i]);
		if(sml_transport_parse_message(smlBinary, &offset, file->messages[i]) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t sml_transport_parse_message(const unsigned char* smlBinary, uint32_t* offset, SML_Message* message) {
	unsigned char* smlMessageBinary;
	unsigned char* inPtr;
	unsigned char* outPtr;
	uint64_t buffer = 0;
	uint32_t zeroOffset = 0;
	uint32_t msgSpace = 256;
	uint16_t bufferSize = 0;
	uint16_t crc16;

	if(*((uint32_t*)(smlBinary + *offset)) != 0x1B1B1B1B) {
		return SML_PARSE_ERROR;
	}
	if(*((uint32_t*)(smlBinary + *offset + 4)) != 0x01010101) {
		return SML_PARSE_ERROR;
	}

	smlMessageBinary = (unsigned char*)calloc(msgSpace, sizeof(unsigned char*));
	p_sml_add_pointer(smlMessageBinary);

	outPtr = smlMessageBinary;
	inPtr  = (unsigned char*)(smlBinary + *offset + 8);
	for(;;) {
		buffer = (buffer << 8) | *inPtr;
		bufferSize++;

		if((uint32_t)(outPtr - smlMessageBinary + 64) > msgSpace) {
			smlMessageBinary = (unsigned char*)realloc(smlMessageBinary, msgSpace + 64);
			msgSpace += 64;
		}

		if(buffer == 0x1B1B1B1B1B1B1B1B) {
			memmove(outPtr, &buffer, 4);
			outPtr += 4;
			buffer = 0;
			bufferSize = 0;
		}
		else if((buffer & 0xFFFFFFFFFF) == 0x1B1B1B1B1A) {
			if(bigendian_check() == FALSE) {
				endian_swap64(&buffer);
			}
			memmove(outPtr, ((unsigned char*)(&buffer))+5, (uint16_t)(bufferSize-5));
			outPtr += (bufferSize-5);
			inPtr++;
			break;
		}
		else if(bufferSize % 8 == 0 || (*inPtr != 0x1B && *(inPtr+1) == 0x1B)) {
			if(bigendian_check() == FALSE) {
				endian_swap64(&buffer);
			}
			memmove(outPtr, ((unsigned char*)(&buffer)) + (8 - bufferSize), bufferSize);
			outPtr += bufferSize;
			buffer = 0;
			bufferSize = 0;
		}
		inPtr++;
	}

	crc16 = crc16_ccitt(smlBinary + *offset, (uint32_t)((inPtr + 1) - (smlBinary + *offset)));
	if(bigendian_check() == FALSE) {
		endian_swap16(&crc16);
	}
	if(*((uint16_t*)(inPtr + 1)) != crc16) {
		return SML_PARSE_ERROR;
	}

	if(sml_parse_message_binary(smlMessageBinary, &zeroOffset, message) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}

	*offset += ((uint32_t)((inPtr + 3) - (smlBinary + *offset)));
	return SML_PARSE_OK;
}

void sml_parser_free(void) {
	uint32_t i;
	if(p_sml_pointer_list != NULL && p_sml_pointer_count > 0) {
		for(i=0; i<p_sml_pointer_count; i++) {
			free(p_sml_pointer_list[i]);
		}
	}
	free(p_sml_pointer_list);
	p_sml_pointer_list  = NULL;
	p_sml_pointer_count = 0;
}

uint8_t p_sml_parse_open_request(const unsigned char* smlBinary, uint32_t* offset, SML_PublicOpen_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 7) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->codepage) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->clientId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->reqFileId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->username) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->password) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8_optional(smlBinary, offset, &request->smlVersion)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_open_response(const unsigned char* smlBinary, uint32_t* offset, SML_PublicOpen_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 6) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->codepage) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->clientId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->reqFileId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &response->refTime) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8_optional(smlBinary, offset, &response->smlVersion)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_close_request(const unsigned char* smlBinary, uint32_t* offset, SML_PublicClose_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 1) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->globalSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getprofilelist_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfileList_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 9) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->username) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->password) ||
		SML_PARSE_ERROR == p_sml_parse_boolean_optional(smlBinary, offset, &request->withRawdata) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &request->beginTime) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &request->endTime) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &request->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_objreqentry_optional(smlBinary, offset, &request->object_List) ||
		SML_PARSE_ERROR == p_sml_parse_tree_optional(smlBinary, offset, &request->dasDetails)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getprofilelist_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfileList_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 9) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_time(smlBinary, offset, &response->actTime) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned32(smlBinary, offset, &response->regPeriod) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &response->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_time(smlBinary, offset, &response->valTime) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned64(smlBinary, offset, &response->status) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_periodentry(smlBinary, offset, &response->period_List) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->rawdata) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->periodSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getprofilepack_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfilePack_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 9) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->username) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->password) ||
		SML_PARSE_ERROR == p_sml_parse_boolean_optional(smlBinary, offset, &request->withRawdata) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &request->beginTime) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &request->endTime) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &request->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_objreqentry_optional(smlBinary, offset, &request->object_List) ||
		SML_PARSE_ERROR == p_sml_parse_tree_optional(smlBinary, offset, &request->dasDetails)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getprofilepack_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfilePack_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 8) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_time(smlBinary, offset, &response->actTime) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned32(smlBinary, offset, &response->regPeriod) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &response->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_objheaderentry(smlBinary, offset, &response->header_List) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_objperiodentry(smlBinary, offset, &response->period_List) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->rawdata) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->profileSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_close_response(const unsigned char* smlBinary, uint32_t* offset, SML_PublicClose_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 1) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->globalSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getlist_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetList_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 5) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->clientId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->username) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->password) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->listName)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getlist_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetList_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 7) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->clientId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->listName) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &response->actSensorTime) ||
		SML_PARSE_ERROR == p_sml_parse_list(smlBinary, offset, &response->valList) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->listSignature) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &response->actGatewayTime)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getprocparameter_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetProcParameter_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 5) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->username) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->password) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &request->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->attribute)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_getprocparameter_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetProcParameter_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 3) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &response->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_tree(smlBinary, offset, &response->parameterTree)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_setprocparameter_request(const unsigned char* smlBinary, uint32_t* offset, SML_SetProcParameter_Req* request) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 5) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->username) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &request->password) ||
		SML_PARSE_ERROR == p_sml_parse_treepath(smlBinary, offset, &request->parameterTreePath) ||
		SML_PARSE_ERROR == p_sml_parse_tree(smlBinary, offset, &request->parameterTree)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_attention_response(const unsigned char* smlBinary, uint32_t* offset, SML_Attention_Res* response) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 4) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->attentionNo) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &response->attentionMsg) ||
		SML_PARSE_ERROR == p_sml_parse_tree_optional(smlBinary, offset, &response->attentionDetails)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}


uint8_t p_sml_parse_messagebody(const unsigned char* smlBinary, uint32_t* offset, SML_MessageBody* messageBody) {
	uint8_t retValue;

	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 2) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned32(smlBinary, offset, &messageBody->choiceTag)) {
		return SML_PARSE_ERROR;
	}

	switch(messageBody->choiceTag) {
		case SML_MESSAGEBODY_OPEN_REQUEST:
			messageBody->choiceValue.openRequest = (SML_PublicOpen_Req*)calloc(1, sizeof(SML_PublicOpen_Req));
			p_sml_add_pointer(messageBody->choiceValue.openRequest);
			retValue = p_sml_parse_open_request(
				smlBinary, offset, messageBody->choiceValue.openRequest
			);
		break;
		case SML_MESSAGEBODY_OPEN_RESPONSE:
			messageBody->choiceValue.openResponse = (SML_PublicOpen_Res*)calloc(1, sizeof(SML_PublicOpen_Res));
			p_sml_add_pointer(messageBody->choiceValue.openResponse);
			retValue = p_sml_parse_open_response(
				smlBinary, offset, messageBody->choiceValue.openResponse
			);
		break;
		case SML_MESSAGEBODY_CLOSE_REQUEST:
			messageBody->choiceValue.closeRequest = (SML_PublicClose_Req*)calloc(1, sizeof(SML_PublicClose_Req));
			p_sml_add_pointer(messageBody->choiceValue.closeRequest);
			retValue = p_sml_parse_close_request(
				smlBinary, offset, messageBody->choiceValue.closeRequest
			);
		break;
		case SML_MESSAGEBODY_CLOSE_RESPONSE:
			messageBody->choiceValue.closeResponse = (SML_PublicClose_Res*)calloc(1, sizeof(SML_PublicClose_Res));
			p_sml_add_pointer(messageBody->choiceValue.closeResponse);
			retValue = p_sml_parse_close_response(
				smlBinary, offset, messageBody->choiceValue.closeResponse
			);
		break;
		case SML_MESSAGEBODY_GETPROFILEPACK_REQUEST:
			messageBody->choiceValue.getProfilePackRequest = (SML_GetProfilePack_Req*)calloc(1, sizeof(SML_GetProfilePack_Req));
			p_sml_add_pointer(messageBody->choiceValue.getProfilePackRequest);
			retValue = p_sml_parse_getprofilepack_request(
				smlBinary, offset, messageBody->choiceValue.getProfilePackRequest
			);
		break;
		case SML_MESSAGEBODY_GETPROFILEPACK_RESPONSE:
			messageBody->choiceValue.getProfilePackResponse = (SML_GetProfilePack_Res*)calloc(1, sizeof(SML_GetProfilePack_Res));
			p_sml_add_pointer(messageBody->choiceValue.getProfilePackResponse);
			retValue = p_sml_parse_getprofilepack_response(
				smlBinary, offset, messageBody->choiceValue.getProfilePackResponse
			);
		break;
		case SML_MESSAGEBODY_GETPROFILELIST_REQUEST:
			messageBody->choiceValue.getProfileListRequest = (SML_GetProfileList_Req*)calloc(1, sizeof(SML_GetProfileList_Req));
			p_sml_add_pointer(messageBody->choiceValue.getProfileListRequest);
			retValue = p_sml_parse_getprofilelist_request(
				smlBinary, offset, messageBody->choiceValue.getProfileListRequest
			);
		break;
		case SML_MESSAGEBODY_GETPROFILELIST_RESPONSE:
			messageBody->choiceValue.getProfileListResponse = (SML_GetProfileList_Res*)calloc(1, sizeof(SML_GetProfileList_Res));
			p_sml_add_pointer(messageBody->choiceValue.getProfileListResponse);
			retValue = p_sml_parse_getprofilelist_response(
				smlBinary, offset, messageBody->choiceValue.getProfileListResponse
			);
		break;
		case SML_MESSAGEBODY_GETPROCPARAMETER_REQUEST:
			messageBody->choiceValue.getProcParameterRequest = (SML_GetProcParameter_Req*)calloc(1, sizeof(SML_GetProcParameter_Req));
			p_sml_add_pointer(messageBody->choiceValue.getProcParameterRequest);
			retValue = p_sml_parse_getprocparameter_request(
				smlBinary, offset, messageBody->choiceValue.getProcParameterRequest
			);
		break;
		case SML_MESSAGEBODY_GETPROCPARAMETER_RESPONSE:
			messageBody->choiceValue.getProcParameterResponse = (SML_GetProcParameter_Res*)calloc(1, sizeof(SML_GetProcParameter_Res));
			p_sml_add_pointer(messageBody->choiceValue.getProcParameterResponse);
			retValue = p_sml_parse_getprocparameter_response(
				smlBinary, offset, messageBody->choiceValue.getProcParameterResponse
			);
		break;
		case SML_MESSAGEBODY_SETPROCPARAMETER_REQUEST:
			messageBody->choiceValue.setProcParameterRequest = (SML_SetProcParameter_Req*)calloc(1, sizeof(SML_SetProcParameter_Req));
			p_sml_add_pointer(messageBody->choiceValue.setProcParameterRequest);
			retValue = p_sml_parse_setprocparameter_request(
				smlBinary, offset, messageBody->choiceValue.setProcParameterRequest
			);
		break;
		case SML_MESSAGEBODY_GETLIST_REQUEST:
			messageBody->choiceValue.getListRequest = (SML_GetList_Req*)calloc(1, sizeof(SML_GetList_Req));
			p_sml_add_pointer(messageBody->choiceValue.getListRequest);
			retValue = p_sml_parse_getlist_request(
				smlBinary, offset, messageBody->choiceValue.getListRequest
			);
		break;
		case SML_MESSAGEBODY_GETLIST_RESPONSE:
			messageBody->choiceValue.getListResponse = (SML_GetList_Res*)calloc(1, sizeof(SML_GetList_Res));
			p_sml_add_pointer(messageBody->choiceValue.getListResponse);
			retValue = p_sml_parse_getlist_response(
				smlBinary, offset, messageBody->choiceValue.getListResponse
			);
		break;
		case SML_MESSAGEBODY_ATTENTION_RESPONSE:
			messageBody->choiceValue.attentionResponse = (SML_Attention_Res*)calloc(1, sizeof(SML_Attention_Res));
			p_sml_add_pointer(messageBody->choiceValue.attentionResponse);
			retValue = p_sml_parse_attention_response(
				smlBinary, offset, messageBody->choiceValue.attentionResponse
			);
		break;

		default:
			return SML_PARSE_ERROR;
		break;
	}

	return retValue;
}

uint8_t p_sml_parse_treepath(const unsigned char* smlBinary, uint32_t* offset, SML_TreePath* treepath) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}
	treepath->listSize = tl_value;
	treepath->path_Entry = (char**)calloc(tl_value, sizeof(char*));
	p_sml_add_pointer(treepath->path_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_string(smlBinary, offset, treepath->path_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_tree(const unsigned char* smlBinary, uint32_t* offset, SML_Tree* tree) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 3) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &tree->parameterName) ||
		SML_PARSE_ERROR == p_sml_parse_procparvalue_optional(smlBinary, offset, &tree->parameterValue) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_tree_optional(smlBinary, offset, &tree->child_List)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_tree_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Tree** tree) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*tree = NULL;
		return SML_PARSE_OK;
	}
	if(tl_type != LIST || tl_value != 3) {
		return SML_PARSE_ERROR;
	}

	*tree = (SML_Tree*)calloc(1, sizeof(SML_Tree));
	p_sml_add_pointer(*tree);

	if(	SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &((*tree)->parameterName)) ||
		SML_PARSE_ERROR == p_sml_parse_procparvalue_optional(smlBinary, offset, &((*tree)->parameterValue)) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_tree_optional(smlBinary, offset, &((*tree)->child_List))) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list_of_tree_optional(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_Tree** list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*list = NULL;
		return SML_PARSE_OK;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}

	*list = (List_of_SML_Tree*)calloc(1, sizeof(List_of_SML_Tree));
	p_sml_add_pointer(*list);

	(*list)->listSize = tl_value;
	(*list)->tree_Entry = (SML_Tree*)calloc(tl_value, sizeof(SML_Tree));
	p_sml_add_pointer((*list)->tree_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_tree(smlBinary, offset, (*list)->tree_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list_of_objreqentry_optional(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ObjReqEntry** list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*list = NULL;
		return SML_PARSE_OK;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}

	*list = (List_of_SML_ObjReqEntry*)calloc(1, sizeof(List_of_SML_ObjReqEntry));
	p_sml_add_pointer(*list);

	(*list)->listSize = tl_value;
	(*list)->object_List_Entry = (SML_ObjReqEntry*)calloc(tl_value, sizeof(SML_ObjReqEntry));
	p_sml_add_pointer((*list)->object_List_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_string(smlBinary, offset, (*list)->object_List_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list_of_periodentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_PeriodEntry* list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}
	list->listSize = tl_value;
	list->period_List_Entry = (SML_PeriodEntry*)calloc(tl_value, sizeof(SML_PeriodEntry));
	p_sml_add_pointer(list->period_List_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_periodentry(smlBinary, offset, list->period_List_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list_of_objheaderentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ProfObjHeaderEntry* list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}
	list->listSize = tl_value;
	list->header_List_Entry = (SML_ProfObjHeaderEntry*)calloc(tl_value, sizeof(SML_ProfObjHeaderEntry));
	p_sml_add_pointer(list->header_List_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_objheaderentry(smlBinary, offset, list->header_List_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list_of_objperiodentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ProfObjPeriodEntry* list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}
	list->listSize = tl_value;
	list->period_List_Entry = (SML_ProfObjPeriodEntry*)calloc(tl_value, sizeof(SML_ProfObjPeriodEntry));
	p_sml_add_pointer(list->period_List_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_objperiodentry(smlBinary, offset, list->period_List_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list_of_valueentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ValueEntry* list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}
	list->listSize = tl_value;
	list->value_List_Entry = (SML_ValueEntry*)calloc(tl_value, sizeof(SML_ValueEntry));
	p_sml_add_pointer(list->value_List_Entry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_valueentry(smlBinary, offset, list->value_List_Entry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_valueentry(const unsigned char* smlBinary, uint32_t* offset, SML_ValueEntry* entry) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 2) ||
		SML_PARSE_ERROR == p_sml_parse_value(smlBinary, offset, &entry->value) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->valueSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_objheaderentry(const unsigned char* smlBinary, uint32_t* offset, SML_ProfObjHeaderEntry* entry) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 3) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->objName) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_objperiodentry(const unsigned char* smlBinary, uint32_t* offset, SML_ProfObjPeriodEntry* entry) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 4) ||
		SML_PARSE_ERROR == p_sml_parse_time(smlBinary, offset, &entry->valTime) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned64(smlBinary, offset, &entry->status) ||
		SML_PARSE_ERROR == p_sml_parse_list_of_valueentry(smlBinary, offset, &entry->value_List) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->periodSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_procparvalue_optional(const unsigned char* smlBinary, uint32_t* offset, SML_ProcParValue** value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*value = NULL;
		return SML_PARSE_OK;
	}
	if(tl_type != LIST || tl_value != 2) {
		return SML_PARSE_ERROR;
	}

	*value = (SML_ProcParValue*)calloc(1, sizeof(SML_ProcParValue));
	p_sml_add_pointer(*value);

	if(p_sml_parse_unsigned8(smlBinary, offset, &((*value)->choiceTag)) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}

	switch((*value)->choiceTag) {
		case SML_PROCPAR_VALUE:
			(*value)->choiceValue.smlValue = (SML_Value*)calloc(1, sizeof(SML_Value));
			p_sml_add_pointer((*value)->choiceValue.smlValue);
		return p_sml_parse_value(smlBinary, offset, (*value)->choiceValue.smlValue);

		case SML_PROCPAR_PERIOD:
			(*value)->choiceValue.smlPeriodEntry = (SML_PeriodEntry*)calloc(1, sizeof(SML_PeriodEntry));
			p_sml_add_pointer((*value)->choiceValue.smlPeriodEntry);
		return p_sml_parse_periodentry(smlBinary, offset, (*value)->choiceValue.smlPeriodEntry);

		case SML_PROCPAR_TUPEL:
			(*value)->choiceValue.smlTupelEntry = (SML_TupelEntry*)calloc(1, sizeof(SML_TupelEntry));
			p_sml_add_pointer((*value)->choiceValue.smlTupelEntry);
		return p_sml_parse_tupelentry(smlBinary, offset, (*value)->choiceValue.smlTupelEntry);

		case SML_PROCPAR_TIME:
			(*value)->choiceValue.smlTime = (SML_Time*)calloc(1, sizeof(SML_Time));
			p_sml_add_pointer((*value)->choiceValue.smlTime);
		return p_sml_parse_time(smlBinary, offset, (*value)->choiceValue.smlTime);

		default: return SML_PARSE_ERROR;
	}
}

uint8_t p_sml_parse_periodentry(const unsigned char* smlBinary, uint32_t* offset, SML_PeriodEntry* entry) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 5) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->objName) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler) ||
		SML_PARSE_ERROR == p_sml_parse_value(smlBinary, offset, &entry->value) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->valueSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_tupelentry(const unsigned char* smlBinary, uint32_t* offset, SML_TupelEntry* entry) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 23) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->serverId) ||
		SML_PARSE_ERROR == p_sml_parse_time(smlBinary, offset, &entry->secIndex) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned64(smlBinary, offset, &entry->status) ||

		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit_pA) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler_pA) ||
		SML_PARSE_ERROR == p_sml_parse_integer64(smlBinary, offset, &entry->value_pA) ||

		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit_R1) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler_R1) ||
		SML_PARSE_ERROR == p_sml_parse_integer64(smlBinary, offset, &entry->value_R1) ||

		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit_R4) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler_R4) ||
		SML_PARSE_ERROR == p_sml_parse_integer64(smlBinary, offset, &entry->value_R4) ||

		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit_mA) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler_mA) ||
		SML_PARSE_ERROR == p_sml_parse_integer64(smlBinary, offset, &entry->value_mA) ||

		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit_R2) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler_R2) ||
		SML_PARSE_ERROR == p_sml_parse_integer64(smlBinary, offset, &entry->value_R2) ||

		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &entry->unit_R3) ||
		SML_PARSE_ERROR == p_sml_parse_integer8(smlBinary, offset, &entry->scaler_R3) ||
		SML_PARSE_ERROR == p_sml_parse_integer64(smlBinary, offset, &entry->value_R3) ||

		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->signature_pA_R1_R4) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->signature_mA_R2_R3)
	) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_list(const unsigned char* smlBinary, uint32_t* offset, SML_List* list) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t i;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type != LIST || tl_value == 0) {
		return SML_PARSE_ERROR;
	}
	list->listSize = tl_value;
	list->valListEntry = (SML_ListEntry*)calloc(tl_value, sizeof(SML_ListEntry));
	p_sml_add_pointer(list->valListEntry);
	for(i=0; i<tl_value; i++) {
		if(p_sml_parse_listentry(smlBinary, offset, list->valListEntry+i) == SML_PARSE_ERROR) {
			return SML_PARSE_ERROR;
		}
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_listentry(const unsigned char* smlBinary, uint32_t* offset, SML_ListEntry* entry) {
	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 7) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->objName) ||
		SML_PARSE_ERROR == p_sml_parse_status_optional(smlBinary, offset, &entry->status) ||
		SML_PARSE_ERROR == p_sml_parse_time_optional(smlBinary, offset, &entry->valTime) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8_optional(smlBinary, offset, &entry->unit) ||
		SML_PARSE_ERROR == p_sml_parse_integer8_optional(smlBinary, offset, &entry->scaler) ||
		SML_PARSE_ERROR == p_sml_parse_value(smlBinary, offset, &entry->value) ||
		SML_PARSE_ERROR == p_sml_parse_string(smlBinary, offset, &entry->valueSignature)) {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_value(const unsigned char* smlBinary, uint32_t* offset, SML_Value* value) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t offsetRef = *offset;

	/*if(p_sml_parse_listsize(smlBinary, offset, 2) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}*/
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	*offset = offsetRef;
	if(tl_type == STRING) {
		value->choiceTag = SML_VALUE_STRING;
		return p_sml_parse_string(smlBinary, offset, &value->choiceValue.string);
	}
	else if(tl_type == BOOLEAN) {
		value->choiceTag = SML_VALUE_BOOLEAN;
		return p_sml_parse_boolean(smlBinary, offset, &value->choiceValue.boolean);
	}
	else if(tl_type == INTEGER) {
		if(tl_value == 1) {
			value->choiceTag = SML_VALUE_INT8;
			return p_sml_parse_integer8(smlBinary, offset, &value->choiceValue.int8);
		}
		else if(tl_value == 2) {
			value->choiceTag = SML_VALUE_INT16;
			return p_sml_parse_integer16(smlBinary, offset, &value->choiceValue.int16);
		}
		else if(tl_value == 4) {
			value->choiceTag = SML_VALUE_INT32;
			return p_sml_parse_integer32(smlBinary, offset, &value->choiceValue.int32);
		}
		else if(tl_value == 8) {
			value->choiceTag = SML_VALUE_INT64;
			return p_sml_parse_integer64(smlBinary, offset, &value->choiceValue.int64);
		}
		else {
			return SML_PARSE_ERROR;
		}
	}
	else if(tl_type == UNSIGNED) {
		if(tl_value == 1) {
			value->choiceTag = SML_VALUE_UINT8;
			return p_sml_parse_unsigned8(smlBinary, offset, &value->choiceValue.uint8);
		}
		else if(tl_value == 2) {
			value->choiceTag = SML_VALUE_UINT16;
			return p_sml_parse_unsigned16(smlBinary, offset, &value->choiceValue.uint16);
		}
		else if(tl_value == 4) {
			value->choiceTag = SML_VALUE_UINT32;
			return p_sml_parse_unsigned32(smlBinary, offset, &value->choiceValue.uint32);
		}
		else if(tl_value == 8) {
			value->choiceTag = SML_VALUE_UINT64;
			return p_sml_parse_unsigned64(smlBinary, offset, &value->choiceValue.uint64);
		}
		else {
			return SML_PARSE_ERROR;
		}
	}
	else {
		return SML_PARSE_ERROR;
	}
}

uint8_t p_sml_parse_status_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Status** status) {
	TL_FieldType tl_type;
	uint32_t tl_value;
	uint32_t offsetRef = *offset;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*status = NULL;
		return SML_PARSE_OK;
	}
	if(tl_type != UNSIGNED) {
		return SML_PARSE_ERROR;
	}
	*offset = offsetRef;
	*status = (SML_Status*)calloc(1, sizeof(SML_Status));
	p_sml_add_pointer(*status);
	if(tl_value == 1) {
		(*status)->choiceTag = SML_STATUS_UINT8;
		return p_sml_parse_unsigned8(smlBinary, offset, &((*status)->choiceValue.uint8));
	}
	else if(tl_value == 2) {
		(*status)->choiceTag = SML_STATUS_UINT16;
		return p_sml_parse_unsigned16(smlBinary, offset, &((*status)->choiceValue.uint16));
	}
	else if(tl_value == 4) {
		(*status)->choiceTag = SML_STATUS_UINT32;
		return p_sml_parse_unsigned32(smlBinary, offset, &((*status)->choiceValue.uint32));
	}
	else if(tl_value == 8) {
		(*status)->choiceTag = SML_STATUS_UINT64;
		return p_sml_parse_unsigned64(smlBinary, offset, &((*status)->choiceValue.uint64));
	}
	else {
		return SML_PARSE_ERROR;
	}
}

uint8_t p_sml_parse_time(const unsigned char* smlBinary, uint32_t* offset, SML_Time* time) {
	uint8_t retValue;

	if(	SML_PARSE_ERROR == p_sml_parse_listsize(smlBinary, offset, 2) ||
		SML_PARSE_ERROR == p_sml_parse_unsigned8(smlBinary, offset, &time->choiceTag)) {
		return SML_PARSE_ERROR;
	}
	switch(time->choiceTag) {
		case SML_TIME_SECINDEX: retValue = p_sml_parse_unsigned32(smlBinary, offset, &time->choiceValue.secIndex); break;
		case SML_TIME_TIMESTAMP: retValue = p_sml_parse_unsigned32(smlBinary, offset, &time->choiceValue.timestamp); break;
		default: return SML_PARSE_ERROR;
	}

	return retValue;
}

uint8_t p_sml_parse_time_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Time** time) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*time = NULL;
		return SML_PARSE_OK;
	}
	if(tl_type != LIST || tl_value != 2) {
		return SML_PARSE_ERROR;
	}

	*time = (SML_Time*)calloc(1, sizeof(SML_Time));
	p_sml_add_pointer(*time);

	if(p_sml_parse_unsigned8(smlBinary, offset, &((*time)->choiceTag)) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	switch((*time)->choiceTag) {
		case SML_TIME_SECINDEX: return p_sml_parse_unsigned32(smlBinary, offset, &((*time)->choiceValue.secIndex));
		case SML_TIME_TIMESTAMP: return p_sml_parse_unsigned32(smlBinary, offset, &((*time)->choiceValue.timestamp));
		default: return SML_PARSE_ERROR;
	}
	return SML_PARSE_OK;
}

uint8_t p_sml_parse_string(const unsigned char* smlBinary, uint32_t* offset, char** value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*value = NULL;
		return SML_PARSE_OK;
	}
	/*if(tl_type != LIST || tl_value != 2) {
		return SML_PARSE_ERROR;
	}
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}*/
	if(tl_type != STRING) {
		return SML_PARSE_ERROR;
	}
	/* Allocate memory */
	*value = (char*)calloc(tl_value+1, sizeof(char));
	p_sml_add_pointer(*value);
	/* Read value */
	memmove(
		*value,
		((char*)(smlBinary+*offset)),
		tl_value
	);
	*(*value+tl_value) = '\0';
	*offset += tl_value;

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_boolean(const unsigned char* smlBinary, uint32_t* offset, SML_Boolean* value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	/*if(p_sml_parse_listsize(smlBinary, offset, 2) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}*/
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	/* Read value */
	if(tl_type == BOOLEAN && tl_value == 1) {
		*value = *((SML_Boolean*)(smlBinary+*offset));
		*offset += 1;
	}
	else {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_boolean_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Boolean** value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*value = NULL;
		return SML_PARSE_OK;
	}
	/*if(tl_type != LIST || tl_value != 2) {
		return SML_PARSE_ERROR;
	}
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	*/
	if(tl_type != BOOLEAN || tl_value != 1) {
		return SML_PARSE_ERROR;
	}
	/* Read value */
	*value = (SML_Boolean*)calloc(1, sizeof(SML_Boolean));
	p_sml_add_pointer(*value);
	**value = *((SML_Boolean*)(smlBinary+*offset));
	*offset += 1;

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_integer(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void* value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	/*if(p_sml_parse_listsize(smlBinary, offset, 2) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}*/
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	/* Read value */
	if(tl_type == INTEGER && tl_value <= size) {
		if(tl_value == 1) {
			*((int8_t*)value) = *((int8_t*)(smlBinary+*offset));
		}
		else if(tl_value == 2) {
			*((int16_t*)value) = *((int16_t*)(smlBinary+*offset));
			if(bigendian_check() == FALSE) {
				endian_swap16((uint16_t*)value);
			}
		}
		else if(tl_value == 4) {
			*((int32_t*)value) = *((int32_t*)(smlBinary+*offset));
			if(bigendian_check() == FALSE) {
				endian_swap32((uint32_t*)value);
			}
		}
		else if(tl_value == 8) {
			*((int64_t*)value) = *((int64_t*)(smlBinary+*offset));
			if(bigendian_check() == FALSE) {
				endian_swap64((uint64_t*)value);
			}
		}
		*offset += tl_value;
	}
	else {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_integer8(const unsigned char* smlBinary, uint32_t* offset, int8_t* value) {
	return p_sml_parse_integer(smlBinary, sizeof(int8_t), offset, value);
}

uint8_t p_sml_parse_integer16(const unsigned char* smlBinary, uint32_t* offset, int16_t* value) {
	return p_sml_parse_integer(smlBinary, sizeof(int16_t), offset, value);
}

uint8_t p_sml_parse_integer32(const unsigned char* smlBinary, uint32_t* offset, int32_t* value) {
	return p_sml_parse_integer(smlBinary, sizeof(int32_t), offset, value);
}

uint8_t p_sml_parse_integer64(const unsigned char* smlBinary, uint32_t* offset, int64_t* value) {
	return p_sml_parse_integer(smlBinary, sizeof(int64_t), offset, value);
}

uint8_t p_sml_parse_unsigned(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void* value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	/*if(p_sml_parse_listsize(smlBinary, offset, 2) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}*/
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	/* Read value */
	if(tl_type == UNSIGNED && tl_value <= size) {
		if(tl_value == 1) {
			*((uint8_t*)value) = *((uint8_t*)(smlBinary+*offset));
		}
		else if(tl_value == 2) {
			*((uint16_t*)value) = *((uint16_t*)(smlBinary+*offset));
			if(bigendian_check() == FALSE) {
				endian_swap16((uint16_t*)value);
			}
		}
		else if(tl_value == 4) {
			*((uint32_t*)value) = *((uint32_t*)(smlBinary+*offset));
			if(bigendian_check() == FALSE) {
				endian_swap32((uint32_t*)value);
			}
		}
		else if(tl_value == 8) {
			*((uint64_t*)value) = *((uint64_t*)(smlBinary+*offset));
			if(bigendian_check() == FALSE) {
				endian_swap64((uint64_t*)value);
			}
		}
		*offset += tl_value;
	}
	else {
		return SML_PARSE_ERROR;
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_unsigned8(const unsigned char* smlBinary, uint32_t* offset, uint8_t* value) {
	return p_sml_parse_unsigned(smlBinary, sizeof(uint8_t), offset, value);
}

uint8_t p_sml_parse_unsigned16(const unsigned char* smlBinary, uint32_t* offset, uint16_t* value) {
	return p_sml_parse_unsigned(smlBinary, sizeof(uint16_t), offset, value);
}

uint8_t p_sml_parse_unsigned32(const unsigned char* smlBinary, uint32_t* offset, uint32_t* value) {
	return p_sml_parse_unsigned(smlBinary, sizeof(uint32_t), offset, value);
}

uint8_t p_sml_parse_unsigned64(const unsigned char* smlBinary, uint32_t* offset, uint64_t* value) {
	return p_sml_parse_unsigned(smlBinary, sizeof(uint64_t), offset, value);
}

uint8_t p_sml_parse_integer_optional(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void** value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*value = NULL;
		return SML_PARSE_OK;
	}
	/*if(tl_type != LIST || tl_value != 2) {
		return SML_PARSE_ERROR;
	}
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	*/
	if(tl_type != INTEGER || tl_value > size) {
		return SML_PARSE_ERROR;
	}
	/* Read value */
	*value = calloc(size, sizeof(int8_t));
	p_sml_add_pointer(*value);
	if(tl_value == 1) {
		**((int8_t**)value) = *((int8_t*)(smlBinary+*offset));
	}
	else if(tl_value == 2) {
		**((int16_t**)value) = *((int16_t*)(smlBinary+*offset));
		if(bigendian_check() == FALSE) {
			endian_swap16(*((uint16_t**)value));
		}
	}
	else if(tl_value == 4) {
		**((int32_t**)value) = *((int32_t*)(smlBinary+*offset));
		if(bigendian_check() == FALSE) {
			endian_swap32(*((uint32_t**)value));
		}
	}
	else if(tl_value == 8) {
		**((int64_t**)value) = *((int64_t*)(smlBinary+*offset));
		if(bigendian_check() == FALSE) {
			endian_swap64(*((uint64_t**)value));
		}
	}
	*offset += tl_value;

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_integer8_optional(const unsigned char* smlBinary, uint32_t* offset, int8_t** value) {
	return p_sml_parse_integer_optional(smlBinary, sizeof(int8_t), offset, (void**)value);
}

uint8_t p_sml_parse_integer16_optional(const unsigned char* smlBinary, uint32_t* offset, int16_t** value) {
	return p_sml_parse_integer_optional(smlBinary, sizeof(int16_t), offset, (void**)value);
}

uint8_t p_sml_parse_integer32_optional(const unsigned char* smlBinary, uint32_t* offset, int32_t** value) {
	return p_sml_parse_integer_optional(smlBinary, sizeof(int32_t), offset, (void**)value);
}

uint8_t p_sml_parse_integer64_optional(const unsigned char* smlBinary, uint32_t* offset, int64_t** value) {
	return p_sml_parse_integer_optional(smlBinary, sizeof(int64_t), offset, (void**)value);
}

uint8_t p_sml_parse_unsigned_optional(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void** value) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	if(tl_type == STRING && tl_value == 0) {
		*value = NULL;
		return SML_PARSE_OK;
	}
	/*if(tl_type != LIST || tl_value != 2) {
		return SML_PARSE_ERROR;
	}
	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}*/
	if(tl_type != UNSIGNED || tl_value > size) {
		return SML_PARSE_ERROR;
	}
	/* Read value */
	*value = calloc(size, sizeof(uint8_t));
	p_sml_add_pointer(*value);
	if(tl_value == 1) {
		**((uint8_t**)value) = *((uint8_t*)(smlBinary+*offset));
	}
	else if(tl_value == 2) {
		**((uint16_t**)value) = *((uint16_t*)(smlBinary+*offset));
		if(bigendian_check() == FALSE) {
			endian_swap16(*((uint16_t**)value));
		}
	}
	else if(tl_value == 4) {
		**((uint32_t**)value) = *((uint32_t*)(smlBinary+*offset));
		if(bigendian_check() == FALSE) {
			endian_swap32(*((uint32_t**)value));
		}
	}
	else if(tl_value == 8) {
		**((uint64_t**)value) = *((uint64_t*)(smlBinary+*offset));
		if(bigendian_check() == FALSE) {
			endian_swap64(*((uint64_t**)value));
		}
	}
	*offset += tl_value;

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_unsigned8_optional(const unsigned char* smlBinary, uint32_t* offset, uint8_t** value) {
	return p_sml_parse_unsigned_optional(smlBinary, sizeof(uint8_t), offset, (void**)value);
}

uint8_t p_sml_parse_unsigned16_optional(const unsigned char* smlBinary, uint32_t* offset, uint16_t** value) {
	return p_sml_parse_unsigned_optional(smlBinary, sizeof(uint16_t), offset, (void**)value);
}

uint8_t p_sml_parse_unsigned32_optional(const unsigned char* smlBinary, uint32_t* offset, uint32_t** value) {
	return p_sml_parse_unsigned_optional(smlBinary, sizeof(uint32_t), offset, (void**)value);
}

uint8_t p_sml_parse_unsigned64_optional(const unsigned char* smlBinary, uint32_t* offset, uint64_t** value) {
	return p_sml_parse_unsigned_optional(smlBinary, sizeof(uint64_t), offset, (void**)value);
}

uint8_t p_sml_parse_tlfield(const unsigned char* smlBinary, uint32_t* offset, TL_FieldType* tl_type, uint32_t* tl_value) {
	char typeBits = (smlBinary[*offset] & 0x70);
	uint32_t i = 0;

	/* check tl-field type */
	if(typeBits == 0x00) {
		*tl_type = STRING;
	}
	else if(typeBits == 0x40) {
		*tl_type = BOOLEAN;
	}
	else if(typeBits == 0x50) {
		*tl_type = INTEGER;
	}
	else if(typeBits == 0x60) {
		*tl_type = UNSIGNED;
	}
	else if(typeBits == 0x70) {
		*tl_type = LIST;
	}
	else {
		return SML_PARSE_ERROR;
	}

	/* Set length of first tl-field */
	*tl_value = (smlBinary[*offset] & 0x0F);

	/* Analyze further fields if necessary */
	if((smlBinary[*offset] & 0x80) == 0x80) {
		for(;;) {
			i++;
			*tl_value = (*tl_value << 4) | (smlBinary[(*offset)+i] & 0x0F);
			if((smlBinary[(*offset)+i] & 0x80) == 0) {
				break;
			}
		}
	}

	*offset += (i+1);
	if(*tl_type != LIST) {
		*tl_value -= (i+1);
	}

	return SML_PARSE_OK;
}

uint8_t p_sml_parse_listsize(const unsigned char* smlBinary, uint32_t* offset, uint32_t listSize) {
	TL_FieldType tl_type;
	uint32_t tl_value;

	if(p_sml_parse_tlfield(smlBinary, offset, &tl_type, &tl_value) == SML_PARSE_ERROR) {
		return SML_PARSE_ERROR;
	}
	else if(tl_type != LIST || tl_value != listSize) {
		return SML_PARSE_ERROR;
	}
	else {
		return SML_PARSE_OK;
	}
}

void p_sml_add_pointer(void* ptr) {
	if(p_sml_pointer_list == NULL) {
		p_sml_pointer_list = (void**)calloc(20, sizeof(void*));
		p_sml_pointer_max  = 20;
	}
	if((p_sml_pointer_count+1) > p_sml_pointer_max) {
		p_sml_pointer_list = (void**)realloc(p_sml_pointer_list, (p_sml_pointer_count+5)*sizeof(void*));
		p_sml_pointer_max  = p_sml_pointer_count+5;
	}
	p_sml_pointer_list[p_sml_pointer_count] = ptr;
	p_sml_pointer_count++;
}

uint32_t p_sml_pointer_max = 0;
uint32_t p_sml_pointer_count = 0;
void** p_sml_pointer_list = NULL;
