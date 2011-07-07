/**
 * File name: smllib_types.h
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
#ifndef SMLLIB_TYPES_H_
#define SMLLIB_TYPES_H_

#include <stdint.h>

/*** Integer & Pointer types ***/
/*
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef int64_t intptr_t;
typedef uint64_t uintptr_t;
*/

/* Debug output */
#define SMLLIB_DEBUG

/*** Return codes ***/
#define SML_ENCODE_ERROR 1
#define SML_ENCODE_OK 0
#define SML_PARSE_ERROR 1
#define SML_PARSE_OK 0

/*** MessageBody codes ***/
#define SML_MESSAGEBODY_OPEN_REQUEST 0x00000100
#define SML_MESSAGEBODY_OPEN_RESPONSE 0x00000101
#define SML_MESSAGEBODY_CLOSE_REQUEST 0x00000200
#define SML_MESSAGEBODY_CLOSE_RESPONSE 0x00000201
#define SML_MESSAGEBODY_GETPROFILEPACK_REQUEST 0x00000300
#define SML_MESSAGEBODY_GETPROFILEPACK_RESPONSE 0x00000301
#define SML_MESSAGEBODY_GETPROFILELIST_REQUEST 0x00000400
#define SML_MESSAGEBODY_GETPROFILELIST_RESPONSE 0x00000401
#define SML_MESSAGEBODY_GETPROCPARAMETER_REQUEST 0x00000500
#define SML_MESSAGEBODY_GETPROCPARAMETER_RESPONSE 0x00000501
#define SML_MESSAGEBODY_SETPROCPARAMETER_REQUEST 0x00000600
#define SML_MESSAGEBODY_SETPROCPARAMETER_RESPONSE 0x00000601
#define SML_MESSAGEBODY_GETLIST_REQUEST 0x00000700
#define SML_MESSAGEBODY_GETLIST_RESPONSE 0x00000701
#define SML_MESSAGEBODY_ATTENTION_RESPONSE 0x0000FF01

/*** SML_Time codes ***/
#define SML_TIME_SECINDEX 0x01
#define SML_TIME_TIMESTAMP 0x02

/*** SML_ProcParValue codes ***/
#define SML_PROCPAR_VALUE 0x01
#define SML_PROCPAR_PERIOD 0x02
#define SML_PROCPAR_TUPEL 0x03
#define SML_PROCPAR_TIME 0x04

/*** SML_Value codes ***/
#define SML_VALUE_BOOLEAN 0x01
#define SML_VALUE_STRING 0x02
#define SML_VALUE_UINT8 0x03
#define SML_VALUE_UINT16 0x04
#define SML_VALUE_UINT32 0x05
#define SML_VALUE_UINT64 0x06
#define SML_VALUE_INT8 0x07
#define SML_VALUE_INT16 0x08
#define SML_VALUE_INT32 0x09
#define SML_VALUE_INT64 0x0A

/*** SML_Status codes ***/
#define SML_STATUS_UINT8 0x01
#define SML_STATUS_UINT16 0x02
#define SML_STATUS_UINT32 0x03
#define SML_STATUS_UINT64 0x04

/*** Misc ***/
#define TRUE 0x01
#define FALSE 0x00

/*** SML typedefs ***/
typedef enum TL_FieldType { BOOLEAN, INTEGER, UNSIGNED, STRING, LIST } TL_FieldType;
typedef uint8_t SML_Boolean;
typedef uint8_t SML_Unit;
typedef char* SML_Signature;
typedef char* SML_ObjReqEntry;
typedef uint32_t SML_Timestamp;

/*** Basic SML structures ***/

typedef struct SML_Time {
	uint8_t choiceTag;
	union {
		uint32_t secIndex;
		SML_Timestamp timestamp;
	} choiceValue;
} SML_Time;

typedef struct SML_MessageBody {
	uint32_t choiceTag;
	union {
		struct SML_PublicOpen_Req* openRequest;
		struct SML_PublicOpen_Res* openResponse;
		struct SML_PublicClose_Req* closeRequest;
		struct SML_PublicClose_Res* closeResponse;

		struct SML_GetProfilePack_Req* getProfilePackRequest;
		struct SML_GetProfilePack_Res* getProfilePackResponse;
		struct SML_GetProfileList_Req* getProfileListRequest;
		struct SML_GetProfileList_Res* getProfileListResponse;
		struct SML_GetList_Req* getListRequest;
		struct SML_GetList_Res* getListResponse;

		struct SML_GetProcParameter_Req* getProcParameterRequest;
		struct SML_GetProcParameter_Res* getProcParameterResponse;
		struct SML_SetProcParameter_Req* setProcParameterRequest;
		struct SML_Attention_Res* attentionResponse;
	} choiceValue;
} SML_MessageBody;

typedef struct SML_Message SML_Message;
struct SML_Message {
	char* transactionId;
	uint8_t groupNo;
	uint8_t abortOnError;
	uint16_t crc16;
	SML_MessageBody messageBody;
};

typedef struct SML_File {
	SML_Message** messages;
	uint32_t msgCount;
	uint16_t crc16;
	uint8_t version;
} SML_File;

/************* Containers and list structures *************/

/* Entries */

typedef struct SML_Value {
	uint8_t choiceTag;
	union {
		SML_Boolean boolean;
		char* string;
		uint8_t uint8;
		uint16_t uint16;
		uint32_t uint32;
		uint64_t uint64;
		int8_t int8;
		int16_t int16;
		int32_t int32;
		int64_t int64;
	} choiceValue;
} SML_Value;

typedef struct SML_Status {
	uint8_t choiceTag;
	union {
		uint8_t uint8;
		uint16_t uint16;
		uint32_t uint32;
		uint64_t uint64;
	} choiceValue;
} SML_Status;

typedef struct SML_ListEntry {
	char* objName;
	SML_Status* status; 				/* optional */
	SML_Time* valTime; 				/* optional */
	SML_Unit* unit; 					/* optional */
	int8_t* scaler; 						/* optional */
	SML_Value value;
	SML_Signature valueSignature; 	/* optional */
} SML_ListEntry;

typedef struct SML_ValueEntry {
	SML_Value value;
	SML_Signature valueSignature; /* optional */
} SML_ValueEntry;


typedef struct List_of_SML_ValueEntry {
	uint32_t listSize;
	SML_ValueEntry* value_List_Entry;
} List_of_SML_ValueEntry;

typedef struct SML_ProfObjPeriodEntry {
	SML_Time valTime;
	uint64_t status;
	List_of_SML_ValueEntry value_List;
	SML_Signature periodSignature; /* optional */
} SML_ProfObjPeriodEntry;

typedef struct SML_ProfObjHeaderEntry {
	char* objName;
	SML_Unit unit;
	int8_t scaler;
} SML_ProfObjHeaderEntry;

typedef struct SML_PeriodEntry {
	char* objName;
	SML_Unit unit;
	int8_t scaler;
	SML_Value value;
	SML_Signature valueSignature; /* optional */
} SML_PeriodEntry;

typedef struct SML_TupelEntry {
	char* serverId;
	SML_Time secIndex;
	uint64_t status;

	SML_Unit unit_pA;
	int8_t scaler_pA;
	int64_t value_pA;

	SML_Unit unit_R1;
	int8_t scaler_R1;
	int64_t value_R1;

	SML_Unit unit_R4;
	int8_t scaler_R4;
	int64_t value_R4;

	char* signature_pA_R1_R4;

	SML_Unit unit_mA;
	int8_t scaler_mA;
	int64_t value_mA;

	SML_Unit unit_R2;
	int8_t scaler_R2;
	int64_t value_R2;

	SML_Unit unit_R3;
	int8_t scaler_R3;
	int64_t value_R3;

	char* signature_mA_R2_R3;
} SML_TupelEntry;

typedef struct SML_ProcParValue {
	uint8_t choiceTag;
	union {
		SML_Value* smlValue;
		SML_PeriodEntry* smlPeriodEntry;
		SML_TupelEntry* smlTupelEntry;
		SML_Time* smlTime;
	} choiceValue;
} SML_ProcParValue;

typedef struct List_of_SML_Tree List_of_SML_Tree;
typedef struct SML_Tree {
	char* parameterName;
	SML_ProcParValue* parameterValue; /* optional */
	List_of_SML_Tree* child_List; /* optional */
} SML_Tree;

/* Lists */

typedef struct SML_TreePath {
	uint32_t listSize;
	char** path_Entry;
} SML_TreePath;


struct List_of_SML_Tree {
	uint32_t listSize;
	SML_Tree* tree_Entry;
};

typedef struct SML_List {
	uint32_t listSize;
	SML_ListEntry* valListEntry;
} SML_List;

typedef struct List_of_SML_ObjReqEntry {
	uint32_t listSize;
	SML_ObjReqEntry* object_List_Entry;
} List_of_SML_ObjReqEntry;

typedef struct List_of_SML_ProfObjPeriodEntry {
	uint32_t listSize;
	SML_ProfObjPeriodEntry* period_List_Entry;
} List_of_SML_ProfObjPeriodEntry;

typedef struct List_of_SML_ProfObjHeaderEntry {
	uint32_t listSize;
	SML_ProfObjHeaderEntry* header_List_Entry;
} List_of_SML_ProfObjHeaderEntry;

typedef struct List_of_SML_PeriodEntry {
	uint32_t listSize;
	SML_PeriodEntry* period_List_Entry;
} List_of_SML_PeriodEntry;

/************* MessageBody structures *************/

typedef struct SML_PublicOpen_Req {
	char* codepage; 	/* optional */
	char* clientId;
	char* reqFileId;
	char* serverId; 	/* optional */
	char* username; 	/* optional */
	char* password; 	/* optional */
	uint8_t* smlVersion; /* optional */
} SML_PublicOpen_Req;

typedef struct SML_PublicOpen_Res {
	char* codepage; 			/* optional */
	char* clientId; 			/* optional */
	char* reqFileId;
	char* serverId;
	SML_Time* refTime; 	/* optional */
	uint8_t* smlVersion; 		/* optional */
} SML_PublicOpen_Res;

typedef struct SML_PublicClose_Req {
	SML_Signature globalSignature; /* optional */
} SML_PublicClose_Req;

typedef struct SML_PublicClose_Res {
	SML_Signature globalSignature; /* optional */
} SML_PublicClose_Res;

typedef struct SML_GetProfilePack_Req {
	char* serverId; 				/* optional */
	char* username;					/* optional */
	char* password; 				/* optional */
	SML_Boolean* withRawdata; 		/* optional */
	SML_Time* beginTime; 			/* optional */
	SML_Time* endTime; 				/* optional */
	SML_TreePath parameterTreePath;
	List_of_SML_ObjReqEntry* object_List;	/* optional */
	SML_Tree* dasDetails;				/* optional */
} SML_GetProfilePack_Req;

typedef struct SML_GetProfilePack_Res {
	char* serverId;
	SML_Time actTime;
	uint32_t regPeriod;
	SML_TreePath parameterTreePath;
	List_of_SML_ProfObjHeaderEntry header_List;
	List_of_SML_ProfObjPeriodEntry period_List;
	char* rawdata; /* optional */
	SML_Signature profileSignature; /* optional */
} SML_GetProfilePack_Res;

typedef struct SML_GetProfileList_Req {
	char* serverId; 				/* optional */
	char* username;					/* optional */
	char* password; 				/* optional */
	SML_Boolean* withRawdata; 		/* optional */
	SML_Time* beginTime; 			/* optional */
	SML_Time* endTime; 				/* optional */
	SML_TreePath parameterTreePath;
	List_of_SML_ObjReqEntry* object_List;	/* optional */
	SML_Tree* dasDetails;				/* optional */
} SML_GetProfileList_Req;

typedef struct SML_GetProfileList_Res {
	char* serverId;
	SML_Time actTime;
	uint32_t regPeriod;
	SML_TreePath parameterTreePath;
	SML_Time valTime;
	uint64_t status;
	List_of_SML_PeriodEntry period_List;
	char* rawdata; /* optional */
	SML_Signature periodSignature; /* optional */
} SML_GetProfileList_Res;

typedef struct SML_GetList_Req {
	char* clientId;
	char* serverId; /* optional */
	char* username; /* optional */
	char* password; /* optional */
	char* listName; /* optional */
} SML_GetList_Req;

typedef struct SML_GetList_Res {
	char* clientId; /* optional */
	char* serverId;
	char* listName; /* optional */
	SML_Time* actSensorTime; /* optional */
	SML_List valList;
	SML_Signature listSignature; /* optional */
	SML_Time* actGatewayTime; /* optional */
} SML_GetList_Res;

typedef struct SML_GetProcParameter_Req {
	char* serverId; 	/* optional */
	char* username;		/* optional */
	char* password;		/* optional */
	SML_TreePath parameterTreePath;
	char* attribute;	/* optional */
} SML_GetProcParameter_Req;

typedef struct SML_GetProcParameter_Res {
	char* serverId;
	SML_TreePath parameterTreePath;
	SML_Tree parameterTree;
} SML_GetProcParameter_Res;

typedef struct SML_SetProcParameter_Req {
	char* serverId; 	/* optional */
	char* username;		/* optional */
	char* password;		/* optional */
	SML_TreePath parameterTreePath;
	SML_Tree parameterTree;
} SML_SetProcParameter_Req;

typedef struct SML_Attention_Res {
	char* serverId;
	char* attentionNo;
	char* attentionMsg; /* optional */
	SML_Tree* attentionDetails; /* optional */
} SML_Attention_Res;

typedef struct SML_Encode_Binary_Result {
	int resultCode;
	char* errorMessage;
	unsigned char* resultBinary;
	uint32_t length;
} SML_Encode_Binary_Result;

#endif /* SMLLIB_TYPES_H_ */
