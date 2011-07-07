/**
 * File name: smllib_encode.c
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

#include "smllib_encode.h"
#include "smllib_tools.h"

#ifdef SMLLIB_DEBUG
	#include <stdio.h>
#endif

SML_Encode_Binary_Result sml_encode_file_binary(SML_File* smlFile) {
	SML_Encode_Binary_Result* smlMessage;
	SML_Encode_Binary_Result result;
	uint32_t i;

	/* Assume encoding error on default */
	result.resultCode = SML_ENCODE_ERROR;

	/* Check if messages pointer is available */
	if(smlFile->messages == NULL) {
		p_set_encode_error(&result, "SML_File message list must not be null.");
		return result;
	}

	/* Check if messages are available */
	if(smlFile->msgCount == 0) {
		p_set_encode_error(&result, "SML_File does not contain any messages.");
		return result;
	}

	/* Check for existing open message */
	if( smlFile->messages[0]->messageBody.choiceTag != SML_MESSAGEBODY_OPEN_REQUEST &&
		smlFile->messages[0]->messageBody.choiceTag != SML_MESSAGEBODY_OPEN_RESPONSE
	) {
		p_set_encode_error(&result, "SML_File must start with an OpenRequest/OpenResponse message.");
		return result;
	}

	/* Check for existing close message */
	if( smlFile->messages[smlFile->msgCount-1]->messageBody.choiceTag != SML_MESSAGEBODY_CLOSE_REQUEST &&
		smlFile->messages[smlFile->msgCount-1]->messageBody.choiceTag != SML_MESSAGEBODY_CLOSE_RESPONSE
	) {
		p_set_encode_error(&result, "SML_File must end with a CloseRequest/CloseResponse message.");
		return result;
	}

	/* Allocate & encode messages */
	smlMessage = (SML_Encode_Binary_Result*)calloc(smlFile->msgCount, sizeof(SML_Encode_Binary_Result));
	for(i=0; i < smlFile->msgCount; i++) {
		smlMessage[i] = sml_encode_message_binary(smlFile->messages[i]);
	}

	/* Concat partial message encodings to result */
	p_allocate_concat_free(&result, smlMessage, smlFile->msgCount);

	/* Free space from encode parts */
	free(smlMessage);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result sml_encode_message_binary(SML_Message* message) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[6];

	uint32_t totalLength;
	SML_Encode_Binary_Result crc16;
	SML_Encode_Binary_Result messageBody;
	SML_Encode_Binary_Result listWrapper	   	= p_sml_encode_tlfield(LIST, 6);
	SML_Encode_Binary_Result transactionId  	= p_sml_encode_string(message->transactionId);
	SML_Encode_Binary_Result groupNo		   	= p_sml_encode_unsigned(message->groupNo, sizeof(uint8_t));
	SML_Encode_Binary_Result abortOnError   	= p_sml_encode_unsigned(message->abortOnError, sizeof(uint8_t));

	printBinaryResult("listWrapper", &listWrapper);
	printBinaryResult("transactionId", &transactionId);
	printBinaryResult("abortOnError", &abortOnError);
	printBinaryResult("groupNo", &groupNo);

	messageBody	= p_sml_encode_messagebody(&message->messageBody);
	totalLength = (
		listWrapper.length
		+ transactionId.length
		+ groupNo.length
		+ abortOnError.length
		+ messageBody.length
		+ (uint32_t)(sizeof(uint16_t) + 1) /* CRC16 + TL */
		+ 1 /* endOfSmlMessage */
	);

	result.length = 0;
	result.resultBinary = (unsigned char*)calloc(totalLength, sizeof(unsigned char));

	/* add encoded parts */
	listPtr[0] = &listWrapper;
	listPtr[1] = &transactionId;
	listPtr[2] = &groupNo;
	listPtr[3] = &abortOnError;
	listPtr[4] = &messageBody;
	p_concat_binary_results_dynamic(&result, listPtr, 5);

	/* add crc16 */
	crc16 = p_sml_encode_unsigned(
		crc16_ccitt(result.resultBinary, result.length), sizeof(uint16_t)
	);

	printBinaryResult("crc16", &crc16);

	listPtr[5] = &crc16;
	p_concat_binary_results_dynamic(&result, listPtr+5, 1);

	/* add endOfSmlMessage */
	result.resultBinary[totalLength-1] = 0x00;
	result.length++;

	printBinaryResult("msgComplete", &result);
	#ifdef SMLLIB_DEBUG
		printf("msgLength: %u bytes\n", (unsigned int)result.length);
		printf("%s", "========= endOfSmlMessage =========\n\n");
	#endif

	free(listWrapper.resultBinary);
	free(transactionId.resultBinary);
	free(groupNo.resultBinary);
	free(abortOnError.resultBinary);
	free(messageBody.resultBinary);
	free(crc16.resultBinary);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result sml_transport_encode_file(SML_File* file) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* messageList;
	uint32_t i;

	messageList = (SML_Encode_Binary_Result*)calloc(file->msgCount, sizeof(SML_Encode_Binary_Result));
	for(i=0; i < file->msgCount; i++) {
		messageList[i] = sml_transport_encode_message(file->messages[i]);
	}

	p_allocate_concat_free(&result, messageList, file->msgCount);

	free(messageList);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result sml_transport_encode_message(SML_Message* message) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result messageBin;
	SML_Encode_Binary_Result messageBinEnc;
	unsigned char* offset;

	uint8_t i;
	uint8_t paddingBytes;
	uint16_t crc;
	uint32_t totalLength;

	messageBin = sml_encode_message_binary(message);
	paddingBytes = (uint8_t)(messageBin.length % 4 != 0 ? (4 - messageBin.length % 4) : 0);

	messageBinEnc = p_sml_transport_escape_message(&messageBin);
	totalLength = (messageBinEnc.length + paddingBytes + 16);
	result.resultBinary = (unsigned char*)calloc(totalLength, sizeof(unsigned char));
	result.length = totalLength;

	/* Start of msg */
	*((uint32_t*)result.resultBinary) = 0x1B1B1B1B;
	*((uint32_t*)(result.resultBinary + 4)) = 0x01010101;
	memmove(
		result.resultBinary + 8,
		messageBinEnc.resultBinary,
		messageBinEnc.length
	);

	/* Padding bytes */
	offset = (unsigned char*)(result.resultBinary + 8 + messageBinEnc.length);
	for(i=0; i<paddingBytes; i++) {
		offset[i] = 0;
	}
	offset += paddingBytes;

	/* End of msg */
	*((uint32_t*)offset) = 0x1B1B1B1B;
	offset += 4;

	offset[0] = 0x1A;
	offset[1] = paddingBytes;

	crc = crc16_ccitt(result.resultBinary, totalLength-2);
	offset[2] = (unsigned char)(crc >> 8);
	offset[3] = (unsigned char)(crc & 0xFF);

	free(messageBin.resultBinary);
	free(messageBinEnc.resultBinary);

	printBinaryResult("transportMsg", &result);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_open_request(SML_PublicOpen_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[8];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 7);
	SML_Encode_Binary_Result codepage  		= request->codepage != NULL ? p_sml_encode_string(request->codepage) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result clientId		= p_sml_encode_string(request->clientId);
	SML_Encode_Binary_Result reqFileId   	= p_sml_encode_string(request->reqFileId);
	SML_Encode_Binary_Result serverId		= request->serverId != NULL ? p_sml_encode_string(request->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result username		= request->username != NULL ? p_sml_encode_string(request->username) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result password		= request->password != NULL ? p_sml_encode_string(request->password) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result smlVersion		= request->smlVersion != NULL ? p_sml_encode_unsigned(*request->smlVersion, sizeof(uint8_t)) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &codepage;
	listPtr[2] = &clientId;
	listPtr[3] = &reqFileId;
	listPtr[4] = &serverId;
	listPtr[5] = &username;
	listPtr[6] = &password;
	listPtr[7] = &smlVersion;
	p_allocate_concat_free_dynamic(&result, listPtr, 8);

	result.resultCode = SML_ENCODE_OK;
	return result;
}


SML_Encode_Binary_Result p_sml_encode_open_response(SML_PublicOpen_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[7];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 6);
	SML_Encode_Binary_Result codepage  		= response->codepage != NULL ? p_sml_encode_string(response->codepage) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result clientId		= p_sml_encode_string(response->clientId);
	SML_Encode_Binary_Result reqFileId   	= p_sml_encode_string(response->reqFileId);
	SML_Encode_Binary_Result serverId		= response->serverId != NULL ? p_sml_encode_string(response->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result refTime		= response->refTime != NULL ? p_sml_encode_time(response->refTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result smlVersion		= response->smlVersion != NULL ? p_sml_encode_unsigned(*response->smlVersion, sizeof(uint8_t)) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &codepage;
	listPtr[2] = &clientId;
	listPtr[3] = &reqFileId;
	listPtr[4] = &serverId;
	listPtr[5] = &refTime;
	listPtr[6] = &smlVersion;
	p_allocate_concat_free_dynamic(&result, listPtr, 7);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_close_request(SML_PublicClose_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[2];

	SML_Encode_Binary_Result listWrapper	 = p_sml_encode_tlfield(LIST, 1);
	SML_Encode_Binary_Result globalSignature = request->globalSignature != NULL ? p_sml_encode_string(request->globalSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &globalSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 2);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_close_response(SML_PublicClose_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[2];

	SML_Encode_Binary_Result listWrapper	 = p_sml_encode_tlfield(LIST, 1);
	SML_Encode_Binary_Result globalSignature = response->globalSignature != NULL ? p_sml_encode_string(response->globalSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &globalSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 2);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getprofilepack_request(SML_GetProfilePack_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[10];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 9);
	SML_Encode_Binary_Result serverId 			= request->serverId != NULL ? p_sml_encode_string(request->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result username 			= request->username != NULL ? p_sml_encode_string(request->username) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result password 			= request->password != NULL ? p_sml_encode_string(request->password) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result withRawdata 		= request->withRawdata != NULL ? p_sml_encode_boolean(*request->withRawdata) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result beginTime 			= request->beginTime != NULL ? p_sml_encode_time(request->beginTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result endTime 			= request->endTime != NULL ? p_sml_encode_time(request->endTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&request->parameterTreePath);
	SML_Encode_Binary_Result object_List 		= request->object_List != NULL ? p_sml_encode_list_of_objreqentry(request->object_List) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result dasDetails 		= request->dasDetails != NULL ? p_sml_encode_tree(request->dasDetails) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &username;
	listPtr[3] = &password;
	listPtr[4] = &withRawdata;
	listPtr[5] = &beginTime;
	listPtr[6] = &endTime;
	listPtr[7] = &parameterTreePath;
	listPtr[8] = &object_List;
	listPtr[9] = &dasDetails;
	p_allocate_concat_free_dynamic(&result, listPtr, 10);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getprofilepack_response(SML_GetProfilePack_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[9];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 8);
	SML_Encode_Binary_Result serverId			= p_sml_encode_string(response->serverId);
	SML_Encode_Binary_Result actTime			= p_sml_encode_time(&response->actTime);
	SML_Encode_Binary_Result regPeriod 			= p_sml_encode_unsigned(response->regPeriod, sizeof(uint32_t));
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&response->parameterTreePath);
	SML_Encode_Binary_Result header_List		= p_sml_encode_list_of_objheaderentry(&response->header_List);
	SML_Encode_Binary_Result period_List	 	= p_sml_encode_list_of_objperiodentry(&response->period_List);
	SML_Encode_Binary_Result rawdata 		 	= response->rawdata != NULL ? p_sml_encode_string(response->rawdata) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result profileSignature 	= response->profileSignature != NULL ? p_sml_encode_string(response->profileSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &actTime;
	listPtr[3] = &regPeriod;
	listPtr[4] = &parameterTreePath;
	listPtr[5] = &header_List;
	listPtr[6] = &period_List;
	listPtr[7] = &rawdata;
	listPtr[8] = &profileSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 9);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getprofilelist_request(SML_GetProfileList_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[10];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 9);
	SML_Encode_Binary_Result serverId 			= request->serverId != NULL ? p_sml_encode_string(request->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result username 			= request->username != NULL ? p_sml_encode_string(request->username) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result password 			= request->password != NULL ? p_sml_encode_string(request->password) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result withRawdata 		= request->withRawdata != NULL ? p_sml_encode_boolean(*request->withRawdata) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result beginTime 			= request->beginTime != NULL ? p_sml_encode_time(request->beginTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result endTime 			= request->endTime != NULL ? p_sml_encode_time(request->endTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&request->parameterTreePath);
	SML_Encode_Binary_Result object_List 		= request->object_List != NULL ? p_sml_encode_list_of_objreqentry(request->object_List) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result dasDetails 		= request->dasDetails != NULL ? p_sml_encode_tree(request->dasDetails) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &username;
	listPtr[3] = &password;
	listPtr[4] = &withRawdata;
	listPtr[5] = &beginTime;
	listPtr[6] = &endTime;
	listPtr[7] = &parameterTreePath;
	listPtr[8] = &object_List;
	listPtr[9] = &dasDetails;
	p_allocate_concat_free_dynamic(&result, listPtr, 10);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getprofilelist_response(SML_GetProfileList_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[10];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 9);
	SML_Encode_Binary_Result serverId			= p_sml_encode_string(response->serverId);
	SML_Encode_Binary_Result actTime			= p_sml_encode_time(&response->actTime);
	SML_Encode_Binary_Result regPeriod 			= p_sml_encode_unsigned(response->regPeriod, sizeof(uint32_t));
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&response->parameterTreePath);
	SML_Encode_Binary_Result valTime 			= p_sml_encode_time(&response->valTime);
	SML_Encode_Binary_Result status 		 	= p_sml_encode_unsigned(response->status, sizeof(uint64_t));
	SML_Encode_Binary_Result period_List 	 	= p_sml_encode_list_of_periodentry(&response->period_List);
	SML_Encode_Binary_Result rawdata 		 	= response->rawdata != NULL ? p_sml_encode_string(response->rawdata) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result periodSignature 	= response->periodSignature != NULL ? p_sml_encode_string(response->periodSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &actTime;
	listPtr[3] = &regPeriod;
	listPtr[4] = &parameterTreePath;
	listPtr[5] = &valTime;
	listPtr[6] = &status;
	listPtr[7] = &period_List;
	listPtr[8] = &rawdata;
	listPtr[9] = &periodSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 10);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getlist_request(SML_GetList_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[6];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 5);
	SML_Encode_Binary_Result clientId 		= p_sml_encode_string(request->clientId);
	SML_Encode_Binary_Result serverId 		= request->serverId != NULL ? p_sml_encode_string(request->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result username 		= request->username != NULL ? p_sml_encode_string(request->username) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result password 		= request->password != NULL ? p_sml_encode_string(request->password) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result listName 		= request->listName != NULL ? p_sml_encode_string(request->listName) : p_sml_encode_tlfield(STRING, 0);

	printBinaryResult("listWrapper", &listWrapper);
	printBinaryResult("clientId", &clientId);
	printBinaryResult("serverId", &serverId);
	printBinaryResult("username", &username);
	printBinaryResult("password", &password);
	printBinaryResult("listName", &listName);

	listPtr[0] = &listWrapper;
	listPtr[1] = &clientId;
	listPtr[2] = &serverId;
	listPtr[3] = &username;
	listPtr[4] = &password;
	listPtr[5] = &listName;
	p_allocate_concat_free_dynamic(&result, listPtr, 6);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getlist_response(SML_GetList_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[8];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 7);
	SML_Encode_Binary_Result clientId		= response->clientId != NULL ? p_sml_encode_string(response->clientId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result serverId		= p_sml_encode_string(response->serverId);
	SML_Encode_Binary_Result listName 		= response->listName != NULL ? p_sml_encode_string(response->listName) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result actSensorTime 	= response->actSensorTime != NULL ? p_sml_encode_time(response->actSensorTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result valList 		= p_sml_encode_list(&response->valList);
	SML_Encode_Binary_Result listSignature 	= response->listSignature != NULL ? p_sml_encode_string(response->listSignature) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result actGatewayTime = response->actGatewayTime != NULL ? p_sml_encode_time(response->actGatewayTime) : p_sml_encode_tlfield(STRING, 0);

	printBinaryResult("listWrapper", &listWrapper);
	printBinaryResult("clientId", &clientId);
	printBinaryResult("serverId", &serverId);
	printBinaryResult("listName", &listName);
	printBinaryResult("actSensorTime", &actSensorTime);
	printBinaryResult("valList", &valList);
	printBinaryResult("listSignature", &listSignature);
	printBinaryResult("actGatewayTime", &actGatewayTime);

	listPtr[0] = &listWrapper;
	listPtr[1] = &clientId;
	listPtr[2] = &serverId;
	listPtr[3] = &listName;
	listPtr[4] = &actSensorTime;
	listPtr[5] = &valList;
	listPtr[6] = &listSignature;
	listPtr[7] = &actGatewayTime;
	p_allocate_concat_free_dynamic(&result, listPtr, 8);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getprocparameter_request(SML_GetProcParameter_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[6];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 5);
	SML_Encode_Binary_Result serverId 			= request->serverId != NULL ? p_sml_encode_string(request->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result username 			= request->username != NULL ? p_sml_encode_string(request->username) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result password 			= request->password != NULL ? p_sml_encode_string(request->password) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&request->parameterTreePath);
	SML_Encode_Binary_Result attribute 			= request->attribute != NULL ? p_sml_encode_string(request->attribute) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &username;
	listPtr[3] = &password;
	listPtr[4] = &parameterTreePath;
	listPtr[5] = &attribute;
	p_allocate_concat_free_dynamic(&result, listPtr, 6);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_getprocparameter_response(SML_GetProcParameter_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[4];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 3);
	SML_Encode_Binary_Result serverId 			= p_sml_encode_string(response->serverId);
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&response->parameterTreePath);
	SML_Encode_Binary_Result parameterTree		= p_sml_encode_tree(&response->parameterTree);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &parameterTreePath;
	listPtr[3] = &parameterTree;
	p_allocate_concat_free_dynamic(&result, listPtr, 4);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_setprocparameter_request(SML_SetProcParameter_Req* request) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[6];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 5);
	SML_Encode_Binary_Result serverId 			= request->serverId != NULL ? p_sml_encode_string(request->serverId) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result username 			= request->username != NULL ? p_sml_encode_string(request->username) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result password 			= request->password != NULL ? p_sml_encode_string(request->password) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result parameterTreePath 	= p_sml_encode_treepath(&request->parameterTreePath);
	SML_Encode_Binary_Result parameterTree 		= p_sml_encode_tree(&request->parameterTree);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &username;
	listPtr[3] = &password;
	listPtr[4] = &parameterTreePath;
	listPtr[5] = &parameterTree;
	p_allocate_concat_free_dynamic(&result, listPtr, 6);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_attention_response(SML_Attention_Res* response) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[5];

	SML_Encode_Binary_Result listWrapper		= p_sml_encode_tlfield(LIST, 4);
	SML_Encode_Binary_Result serverId 			= p_sml_encode_string(response->serverId);
	SML_Encode_Binary_Result attentionNo 		= p_sml_encode_string(response->attentionNo);
	SML_Encode_Binary_Result attentionMsg 		= response->attentionMsg != NULL ? p_sml_encode_string(response->attentionMsg) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result attentionDetails 	= response->attentionDetails != NULL ? p_sml_encode_tree(response->attentionDetails) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &attentionNo;
	listPtr[3] = &attentionMsg;
	listPtr[4] = &attentionDetails;
	p_allocate_concat_free_dynamic(&result, listPtr, 5);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_messagebody(SML_MessageBody* messageBody) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[3];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 2);
	SML_Encode_Binary_Result messageBodyTag = p_sml_encode_unsigned(messageBody->choiceTag, sizeof(uint32_t));
	SML_Encode_Binary_Result messageBodyValue;

	printBinaryResult("listWrapper", &listWrapper);
	printBinaryResult("messageBodyTag", &messageBodyTag);

	switch(messageBody->choiceTag) {
		case SML_MESSAGEBODY_OPEN_REQUEST:
			messageBodyValue = p_sml_encode_open_request(messageBody->choiceValue.openRequest);
		break;
		case SML_MESSAGEBODY_OPEN_RESPONSE:
			messageBodyValue = p_sml_encode_open_response(messageBody->choiceValue.openResponse);
		break;
		case SML_MESSAGEBODY_CLOSE_REQUEST:
			messageBodyValue = p_sml_encode_close_request(messageBody->choiceValue.closeRequest);
		break;
		case SML_MESSAGEBODY_CLOSE_RESPONSE:
			messageBodyValue = p_sml_encode_close_response(messageBody->choiceValue.closeResponse);
		break;
		case SML_MESSAGEBODY_GETPROFILEPACK_REQUEST:
			messageBodyValue = p_sml_encode_getprofilepack_request(messageBody->choiceValue.getProfilePackRequest);
		break;
		case SML_MESSAGEBODY_GETPROFILEPACK_RESPONSE:
			messageBodyValue = p_sml_encode_getprofilepack_response(messageBody->choiceValue.getProfilePackResponse);
		break;
		case SML_MESSAGEBODY_GETPROFILELIST_REQUEST:
			messageBodyValue = p_sml_encode_getprofilelist_request(messageBody->choiceValue.getProfileListRequest);
		break;
		case SML_MESSAGEBODY_GETPROFILELIST_RESPONSE:
			messageBodyValue = p_sml_encode_getprofilelist_response(messageBody->choiceValue.getProfileListResponse);
		break;
		case SML_MESSAGEBODY_GETPROCPARAMETER_REQUEST:
			messageBodyValue = p_sml_encode_getprocparameter_request(messageBody->choiceValue.getProcParameterRequest);
		break;
		case SML_MESSAGEBODY_GETPROCPARAMETER_RESPONSE:
			messageBodyValue = p_sml_encode_getprocparameter_response(messageBody->choiceValue.getProcParameterResponse);
		break;
		case SML_MESSAGEBODY_SETPROCPARAMETER_REQUEST:
			messageBodyValue = p_sml_encode_setprocparameter_request(messageBody->choiceValue.setProcParameterRequest);
		break;
		case SML_MESSAGEBODY_GETLIST_REQUEST:
			messageBodyValue = p_sml_encode_getlist_request(messageBody->choiceValue.getListRequest);
		break;
		case SML_MESSAGEBODY_GETLIST_RESPONSE:
			messageBodyValue = p_sml_encode_getlist_response(messageBody->choiceValue.getListResponse);
		break;
		case SML_MESSAGEBODY_ATTENTION_RESPONSE:
			messageBodyValue = p_sml_encode_attention_response(messageBody->choiceValue.attentionResponse);
		break;
	}

	listPtr[0] = &listWrapper;
	listPtr[1] = &messageBodyTag;
	listPtr[2] = &messageBodyValue;
	p_allocate_concat_free_dynamic(&result, listPtr, 3);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_treepath(SML_TreePath* treePath) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* smlPathEntry = (SML_Encode_Binary_Result*)calloc(treePath->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	smlPathEntry[0] = p_sml_encode_tlfield(LIST, treePath->listSize);
	for(i=0; i < treePath->listSize; i++) {
		smlPathEntry[i+1] = p_sml_encode_string(treePath->path_Entry[i]);
	}

	p_allocate_concat_free(&result, smlPathEntry, treePath->listSize+1);

	free(smlPathEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list_of_tree(List_of_SML_Tree* list) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* smlTree = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	smlTree[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		smlTree[i+1] = p_sml_encode_tree(list->tree_Entry+i);
	}

	p_allocate_concat_free(&result, smlTree, list->listSize+1);

	free(smlTree);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_tree(SML_Tree* tree) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[4];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 3);
	SML_Encode_Binary_Result parameterName 	= p_sml_encode_string(tree->parameterName);
	SML_Encode_Binary_Result parameterValue = tree->parameterValue != NULL ? p_sml_encode_procparvalue(tree->parameterValue) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result child_List 	= tree->child_List != NULL ? p_sml_encode_list_of_tree(tree->child_List) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &parameterName;
	listPtr[2] = &parameterValue;
	listPtr[3] = &child_List;
	p_allocate_concat_free_dynamic(&result, listPtr, 4);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list_of_objreqentry(List_of_SML_ObjReqEntry* list) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* objReqEntry = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	objReqEntry[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		objReqEntry[i+1] = p_sml_encode_string(list->object_List_Entry[i]);
	}

	p_allocate_concat_free(&result, objReqEntry, list->listSize+1);

	free(objReqEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list_of_periodentry(List_of_SML_PeriodEntry* list) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* periodEntry = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	periodEntry[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		periodEntry[i+1] = p_sml_encode_periodentry(list->period_List_Entry+i);
	}

	p_allocate_concat_free(&result, periodEntry, list->listSize+1);

	free(periodEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list_of_objheaderentry(List_of_SML_ProfObjHeaderEntry* list) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* objHeaderEntry = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	objHeaderEntry[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		objHeaderEntry[i+1] = p_sml_encode_objheaderentry(list->header_List_Entry+i);
	}

	p_allocate_concat_free(&result, objHeaderEntry, list->listSize+1);

	free(objHeaderEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list_of_objperiodentry(List_of_SML_ProfObjPeriodEntry* list) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* objPeriodEntry = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	objPeriodEntry[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		objPeriodEntry[i+1] = p_sml_encode_objperiodentry(list->period_List_Entry+i);
	}

	p_allocate_concat_free(&result, objPeriodEntry, list->listSize+1);

	free(objPeriodEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list_of_valueentry(List_of_SML_ValueEntry* list) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* valueEntry = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	valueEntry[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		valueEntry[i+1] = p_sml_encode_valueentry(list->value_List_Entry+i);
	}

	p_allocate_concat_free(&result, valueEntry, list->listSize+1);

	free(valueEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_objheaderentry(SML_ProfObjHeaderEntry* entry) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[4];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 3);
	SML_Encode_Binary_Result objName 		= p_sml_encode_string(entry->objName);
	SML_Encode_Binary_Result unit 			= p_sml_encode_unsigned(entry->unit, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler 		= p_sml_encode_integer(entry->scaler, sizeof(int8_t));

	listPtr[0] = &listWrapper;
	listPtr[1] = &objName;
	listPtr[2] = &unit;
	listPtr[3] = &scaler;
	p_allocate_concat_free_dynamic(&result, listPtr, 4);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_objperiodentry(SML_ProfObjPeriodEntry* entry) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[5];

	SML_Encode_Binary_Result listWrapper	 = p_sml_encode_tlfield(LIST, 4);
	SML_Encode_Binary_Result valTime 		 = p_sml_encode_time(&entry->valTime);
	SML_Encode_Binary_Result status 		 = p_sml_encode_unsigned(entry->status, sizeof(uint64_t));
	SML_Encode_Binary_Result value_List 	 = p_sml_encode_list_of_valueentry(&entry->value_List);
	SML_Encode_Binary_Result periodSignature = entry->periodSignature != NULL ? p_sml_encode_string(entry->periodSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &valTime;
	listPtr[2] = &status;
	listPtr[3] = &value_List;
	listPtr[4] = &periodSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 5);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_valueentry(SML_ValueEntry* entry) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[3];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 2);
	SML_Encode_Binary_Result value 		 	= p_sml_encode_value(&entry->value);
	SML_Encode_Binary_Result valueSignature = entry->valueSignature != NULL ? p_sml_encode_string(entry->valueSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &value;
	listPtr[2] = &valueSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 3);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_procparvalue(SML_ProcParValue* value) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[3];

	SML_Encode_Binary_Result listWrapper = p_sml_encode_tlfield(LIST, 2);
	SML_Encode_Binary_Result smlProcParTag = p_sml_encode_unsigned(value->choiceTag, sizeof(uint8_t));
	SML_Encode_Binary_Result smlProcParValue;

	switch(value->choiceTag) {
		case SML_PROCPAR_VALUE:
			smlProcParValue = p_sml_encode_value(value->choiceValue.smlValue);
		break;
		case SML_PROCPAR_PERIOD:
			smlProcParValue = p_sml_encode_periodentry(value->choiceValue.smlPeriodEntry);
		break;
		case SML_PROCPAR_TUPEL:
			smlProcParValue = p_sml_encode_tupelentry(value->choiceValue.smlTupelEntry);
		break;
		case SML_PROCPAR_TIME:
			smlProcParValue = p_sml_encode_time(value->choiceValue.smlTime);
		break;
	}

	listPtr[0] = &listWrapper;
	listPtr[1] = &smlProcParTag;
	listPtr[2] = &smlProcParValue;
	p_allocate_concat_free_dynamic(&result, listPtr, 3);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_periodentry(SML_PeriodEntry* entry) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[6];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 5);
	SML_Encode_Binary_Result objName 		= p_sml_encode_string(entry->objName);
	SML_Encode_Binary_Result unit 			= p_sml_encode_unsigned(entry->unit, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler 		= p_sml_encode_integer(entry->scaler, sizeof(int8_t));
	SML_Encode_Binary_Result value 			= p_sml_encode_value(&entry->value);
	SML_Encode_Binary_Result valueSignature	= entry->valueSignature != NULL ? p_sml_encode_string(entry->valueSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &objName;
	listPtr[2] = &unit;
	listPtr[3] = &scaler;
	listPtr[4] = &value;
	listPtr[5] = &valueSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 6);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_tupelentry(SML_TupelEntry* entry) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[24];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 23);
	SML_Encode_Binary_Result serverId 		= p_sml_encode_string(entry->serverId);
	SML_Encode_Binary_Result secIndex 		= p_sml_encode_time(&entry->secIndex);
	SML_Encode_Binary_Result status 		= p_sml_encode_unsigned(entry->status, sizeof(uint64_t));

	SML_Encode_Binary_Result unit_pA 		= p_sml_encode_unsigned(entry->unit_pA, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler_pA 		= p_sml_encode_integer(entry->scaler_pA, sizeof(int8_t));
	SML_Encode_Binary_Result value_pA 		= p_sml_encode_integer(entry->value_pA, sizeof(int64_t));

	SML_Encode_Binary_Result unit_R1 		= p_sml_encode_unsigned(entry->unit_R1, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler_R1 		= p_sml_encode_integer(entry->scaler_R1, sizeof(int8_t));
	SML_Encode_Binary_Result value_R1 		= p_sml_encode_integer(entry->value_R1, sizeof(int64_t));

	SML_Encode_Binary_Result unit_R4 		= p_sml_encode_unsigned(entry->unit_R4, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler_R4 		= p_sml_encode_integer(entry->scaler_R4, sizeof(int8_t));
	SML_Encode_Binary_Result value_R4 		= p_sml_encode_integer(entry->value_R4, sizeof(int64_t));

	SML_Encode_Binary_Result unit_mA 		= p_sml_encode_unsigned(entry->unit_mA, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler_mA 		= p_sml_encode_integer(entry->scaler_mA, sizeof(int8_t));
	SML_Encode_Binary_Result value_mA 		= p_sml_encode_integer(entry->value_mA, sizeof(int64_t));

	SML_Encode_Binary_Result unit_R2 		= p_sml_encode_unsigned(entry->unit_R2, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler_R2 		= p_sml_encode_integer(entry->scaler_R2, sizeof(int8_t));
	SML_Encode_Binary_Result value_R2 		= p_sml_encode_integer(entry->value_R2, sizeof(int64_t));

	SML_Encode_Binary_Result unit_R3 		= p_sml_encode_unsigned(entry->unit_R3, sizeof(SML_Unit));
	SML_Encode_Binary_Result scaler_R3 		= p_sml_encode_integer(entry->scaler_R3, sizeof(int8_t));
	SML_Encode_Binary_Result value_R3 		= p_sml_encode_integer(entry->value_R3, sizeof(int64_t));

	SML_Encode_Binary_Result signature_pA_R1_R4 = p_sml_encode_string(entry->signature_pA_R1_R4);
	SML_Encode_Binary_Result signature_mA_R2_R3 = p_sml_encode_string(entry->signature_mA_R2_R3);

	listPtr[0] = &listWrapper;
	listPtr[1] = &serverId;
	listPtr[2] = &secIndex;
	listPtr[3] = &status;

	listPtr[4] = &unit_pA;
	listPtr[5] = &scaler_pA;
	listPtr[6] = &value_pA;

	listPtr[7] = &unit_R1;
	listPtr[8] = &scaler_R1;
	listPtr[9] = &value_R1;

	listPtr[10] = &unit_R4;
	listPtr[11] = &scaler_R4;
	listPtr[12] = &value_R4;

	listPtr[13] = &signature_pA_R1_R4;

	listPtr[14] = &unit_mA;
	listPtr[15] = &scaler_mA;
	listPtr[16] = &value_mA;

	listPtr[17] = &unit_R2;
	listPtr[18] = &scaler_R2;
	listPtr[19] = &value_R2;

	listPtr[20] = &unit_R3;
	listPtr[21] = &scaler_R3;
	listPtr[22] = &value_R3;

	listPtr[23] = &signature_mA_R2_R3;

	p_allocate_concat_free_dynamic(&result, listPtr, 24);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_value(SML_Value* value) {
	SML_Encode_Binary_Result result;

	switch(value->choiceTag) {
		case SML_VALUE_BOOLEAN:
			result = p_sml_encode_boolean(value->choiceValue.boolean);
		break;
		case SML_VALUE_STRING:
			result = p_sml_encode_string(value->choiceValue.string);
		break;
		case SML_VALUE_UINT8:
			result = p_sml_encode_unsigned(value->choiceValue.uint8, sizeof(uint8_t));
		break;
		case SML_VALUE_UINT16:
			result = p_sml_encode_unsigned(value->choiceValue.uint16, sizeof(uint16_t));
		break;
		case SML_VALUE_UINT32:
			result = p_sml_encode_unsigned(value->choiceValue.uint32, sizeof(uint32_t));
		break;
		case SML_VALUE_UINT64:
			result = p_sml_encode_unsigned(value->choiceValue.uint64, sizeof(uint64_t));
		break;
		case SML_VALUE_INT8:
			result = p_sml_encode_integer(value->choiceValue.int8, sizeof(int8_t));
		break;
		case SML_VALUE_INT16:
			result = p_sml_encode_integer(value->choiceValue.int16, sizeof(int16_t));
		break;
		case SML_VALUE_INT32:
			result = p_sml_encode_integer(value->choiceValue.int32, sizeof(int32_t));
		break;
		case SML_VALUE_INT64:
			result = p_sml_encode_integer(value->choiceValue.int64, sizeof(int64_t));
		break;
	}

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_status(SML_Status* status) {
	SML_Encode_Binary_Result result;

	switch(status->choiceTag) {
		case SML_STATUS_UINT8:
			result = p_sml_encode_unsigned(status->choiceValue.uint8, sizeof(uint8_t));
		break;
		case SML_STATUS_UINT16:
			result = p_sml_encode_unsigned(status->choiceValue.uint16, sizeof(uint16_t));
		break;
		case SML_STATUS_UINT32:
			result = p_sml_encode_unsigned(status->choiceValue.uint32, sizeof(uint32_t));
		break;
		case SML_STATUS_UINT64:
			result = p_sml_encode_unsigned(status->choiceValue.uint64, sizeof(uint64_t));
		break;
	}

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_list(SML_List* list) {
	SML_Encode_Binary_Result result;

	SML_Encode_Binary_Result* smlListEntry = (SML_Encode_Binary_Result*)calloc(list->listSize+1, sizeof(SML_Encode_Binary_Result));

	uint32_t i = 0;
	smlListEntry[0] = p_sml_encode_tlfield(LIST, list->listSize);
	for(i=0; i < list->listSize; i++) {
		smlListEntry[i+1] = p_sml_encode_listentry(list->valListEntry+i);
	}

	p_allocate_concat_free(&result, smlListEntry, list->listSize+1);

	free(smlListEntry);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_listentry(SML_ListEntry* entry) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[8];

	SML_Encode_Binary_Result listWrapper	= p_sml_encode_tlfield(LIST, 7);
	SML_Encode_Binary_Result objName 		= p_sml_encode_string(entry->objName);
	SML_Encode_Binary_Result status 		= entry->status != NULL ? p_sml_encode_status(entry->status) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result valTime 		= entry->valTime != NULL ? p_sml_encode_time(entry->valTime) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result unit 			= entry->unit != NULL ? p_sml_encode_unsigned(*entry->unit, sizeof(SML_Unit)) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result scaler 		= entry->scaler != NULL ? p_sml_encode_integer(*entry->scaler, sizeof(int8_t)) : p_sml_encode_tlfield(STRING, 0);
	SML_Encode_Binary_Result value 			= p_sml_encode_value(&entry->value);
	SML_Encode_Binary_Result valueSignature = entry->valueSignature != NULL ? p_sml_encode_string(entry->valueSignature) : p_sml_encode_tlfield(STRING, 0);

	listPtr[0] = &listWrapper;
	listPtr[1] = &objName;
	listPtr[2] = &status;
	listPtr[3] = &valTime;
	listPtr[4] = &unit;
	listPtr[5] = &scaler;
	listPtr[6] = &value;
	listPtr[7] = &valueSignature;
	p_allocate_concat_free_dynamic(&result, listPtr, 8);

	result.resultCode = SML_ENCODE_OK;
	return result;
}


SML_Encode_Binary_Result p_sml_encode_time(SML_Time* time) {
	SML_Encode_Binary_Result result;
	SML_Encode_Binary_Result* listPtr[3];

	SML_Encode_Binary_Result listWrapper = p_sml_encode_tlfield(LIST, 2);
	SML_Encode_Binary_Result smlTimeTag	 = p_sml_encode_unsigned(time->choiceTag, sizeof(uint8_t));
	SML_Encode_Binary_Result smlTimeValue;

	switch(time->choiceTag) {
		case SML_TIME_SECINDEX:
			smlTimeValue = p_sml_encode_unsigned(time->choiceValue.secIndex, sizeof(uint32_t));
		break;
		case SML_TIME_TIMESTAMP:
			smlTimeValue = p_sml_encode_unsigned(time->choiceValue.timestamp, sizeof(SML_Timestamp));
		break;
	}

	listPtr[0] = &listWrapper;
	listPtr[1] = &smlTimeTag;
	listPtr[2] = &smlTimeValue;
	p_allocate_concat_free_dynamic(&result, listPtr, 3);

	result.resultCode = SML_ENCODE_OK;
	return result;
}

SML_Encode_Binary_Result p_sml_encode_string(char* in) {
	return p_sml_encode_primitive_type(in, STRING, (uint32_t)strlen(in));
}

SML_Encode_Binary_Result p_sml_encode_boolean(SML_Boolean in) {
	return p_sml_encode_primitive_type(&in, BOOLEAN, 1);
}

SML_Encode_Binary_Result p_sml_encode_integer(int64_t in, uint32_t length) {
	return p_sml_encode_primitive_type(&in, INTEGER, length);
}

SML_Encode_Binary_Result p_sml_encode_unsigned(uint64_t in, uint32_t length) {
	return p_sml_encode_primitive_type(&in, UNSIGNED, length);
}

SML_Encode_Binary_Result p_sml_encode_primitive_type(void* in_ptr, TL_FieldType type, uint32_t length) {
	SML_Encode_Binary_Result result;
	/*SML_Encode_Binary_Result tl_List  = p_sml_encode_tlfield(LIST, 2);*/
	SML_Encode_Binary_Result tl_Value = p_sml_encode_tlfield(type, length);

	result.length = /*tl_List.length + */tl_Value.length + length;
	result.resultBinary = (unsigned char*)calloc(result.length, sizeof(unsigned char));
	result.errorMessage = NULL;
	result.resultCode = SML_ENCODE_OK;

	/*memmove(
		result.resultBinary,
		tl_List.resultBinary,
		tl_List.length
	);*/
	memmove(
		result.resultBinary,/*+tl_List.length*/
		tl_Value.resultBinary,
		tl_Value.length
	);
	memmove(
		result.resultBinary+/*tl_List.length+*/tl_Value.length,
		(char*)in_ptr,
		length
	);
	if((type == INTEGER || type == UNSIGNED) && length > 1 && bigendian_check() == FALSE) {
		if(length == sizeof(uint16_t)) {
			endian_swap16((uint16_t*)(result.resultBinary+tl_Value.length));
		}
		else if(length == sizeof(uint32_t)) {
			endian_swap32((uint32_t*)(result.resultBinary+tl_Value.length));
		}
		else if(length == sizeof(uint64_t)) {
			endian_swap64((uint64_t*)(result.resultBinary+tl_Value.length));
		}
	}

	/*free(tl_List.resultBinary);*/
	free(tl_Value.resultBinary);

	return result;
}

SML_Encode_Binary_Result p_sml_encode_tlfield(TL_FieldType type, uint32_t length) {
	SML_Encode_Binary_Result result;
	uint32_t baseValue;
	uint32_t tlCount;
	uint32_t i;

	baseValue = 0x00;
	result.errorMessage = NULL;
	result.resultBinary = NULL;
	result.length = 0;

	switch(type) {
		case BOOLEAN:
		case INTEGER:
		case UNSIGNED:
			if(type == BOOLEAN) {
				baseValue = 0x40; /* 0b01000000 */
			}
			else if(type == INTEGER) {
				baseValue = 0x50; /* 0b01010000 */
			}
			else if(type == UNSIGNED) {
				baseValue = 0x60; /* 0b01100000 */
			}

			result.resultBinary = (unsigned char*)calloc(1, sizeof(unsigned char));
			*(result.resultBinary) = (unsigned char)(baseValue + length + 1); /* assume length < 15 bytes */
			result.length = 1;
		break;
		case STRING:
			tlCount=1;
			for(;;) {
				if((length+tlCount) < (uint32_t)(1 << 4*tlCount)) {
					break;
				}
				tlCount++;
			}
			result.resultBinary = (unsigned char*)calloc(tlCount, sizeof(unsigned char));
			result.length = tlCount;

			length = (length + tlCount);
			for(i=tlCount; i > 0; i--) {
				if(i == 1) {
					result.resultBinary[i-1] = (unsigned char)((tlCount > 1 ? 0x80 : 0x00) + (length & 0xF));
				}
				else {
					result.resultBinary[i-1] = (unsigned char)((tlCount != i ? 0x80 : 0x00) + (length & 0xF));
				}
				length = length >> 4;
			}
		break;
		case LIST:
			tlCount=1;
			for(;;) {
				if(length < (uint32_t)(1 << 4*tlCount)) {
					break;
				}
				tlCount++;
			}
			result.resultBinary = (unsigned char*)calloc(tlCount, sizeof(unsigned char));
			result.length = tlCount;

			for(i=tlCount; i > 0; i--) {
				if(i == 1) {
					result.resultBinary[i-1] = (unsigned char)((tlCount > 1 ? 0xF0 : 0x70) + (length & 0xF));
				}
				else {
					result.resultBinary[i-1] = (unsigned char)((tlCount != i ? 0x80 : 0x00) + (length & 0xF));
				}
				length = length >> 4;
			}
		break;
	}

	result.resultCode = SML_ENCODE_OK;
	return result;
}

void p_concat_binary_results(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result* src, uint32_t count) {
	uint32_t i;
	for(i=0; i < count; i++) {
		memmove(
			target->resultBinary + target->length,
			src[i].resultBinary,
			src[i].length
		);
		target->length += src[i].length;
	}
}

void p_concat_binary_results_dynamic(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result** src, uint32_t count) {
	uint32_t i;
	for(i=0; i < count; i++) {
		memmove(
			target->resultBinary + target->length,
			src[i]->resultBinary,
			src[i]->length
		);
		target->length += src[i]->length;
	}
}

void p_allocate_concat_free(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result* src, uint32_t count) {
	uint32_t totalLength;
	uint32_t i;

	/* Collect sizes */
	for(totalLength=0, i=0; i < count; totalLength += src[i].length, i++);

	/* Allocate space for merged binary data */
	target->length = 0;
	target->resultBinary = (unsigned char*)calloc(totalLength, sizeof(unsigned char));

	/* Merge structures & free old ones */
	for(i=0; i < count; i++) {
		memmove(
			target->resultBinary + target->length,
			src[i].resultBinary,
			src[i].length
		);
		target->length += src[i].length;
		free(src[i].resultBinary);
	}
}

void p_allocate_concat_free_dynamic(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result** src, uint32_t count) {
	uint32_t totalLength;
	uint32_t i;

	/* Collect sizes */
	for(totalLength=0, i=0; i < count; totalLength += src[i]->length, i++);

	/* Allocate space for merged binary data */
	target->length = 0;
	target->resultBinary = (unsigned char*)calloc(totalLength, sizeof(unsigned char));

	/* Merge structures & free old ones */
	for(i=0; i < count; i++) {
		memmove(
			target->resultBinary + target->length,
			src[i]->resultBinary,
			src[i]->length
		);
		target->length += src[i]->length;
		free(src[i]->resultBinary);
	}
}

void p_set_encode_error(SML_Encode_Binary_Result* result, const char* errmsg) {
	result->errorMessage = (char*)calloc(strlen(errmsg)+1, sizeof(char));
	strcpy(result->errorMessage, errmsg);
}

SML_Encode_Binary_Result p_sml_transport_escape_message(SML_Encode_Binary_Result* message) {
	SML_Encode_Binary_Result out;
	uint32_t i;
	uint32_t buffer = 0;
	uint32_t escapeCount = 0;
	unsigned char* outPtr;

	out.resultBinary = (unsigned char*)calloc(message->length, sizeof(unsigned char));

	outPtr  = (out.resultBinary);
	for(i=0; i<message->length; i++) {
		buffer  = (buffer << 8) | (message->resultBinary[i]);
		*outPtr = message->resultBinary[i];
		outPtr++;
		if(buffer == 0x1B1B1B1B) {
			escapeCount++;
			out.resultBinary = (unsigned char*)realloc(out.resultBinary, message->length+escapeCount*4);
			outPtr = (out.resultBinary + (i+1) + (escapeCount-1)*4);
			*(uint32_t*)outPtr = 0x1B1B1B1B;
			buffer = 0;
			outPtr += 4;
		}
	}

	out.length = (message->length + escapeCount*4);
	out.errorMessage = NULL;
	out.resultCode = SML_ENCODE_OK;
	return out;
}
