/**
 * File name: smllib_parse.h
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

#ifndef SMLLIB_PARSE_H_
#define SMLLIB_PARSE_H_

#include <stdlib.h>
#include "smllib_types.h"

/* Public methods */

uint8_t sml_parse_file_binary(const unsigned char* smlBinary, uint32_t msgCount, SML_File* smlFile);

uint8_t sml_parse_message_binary(const unsigned char* smlBinary, uint32_t* offset, SML_Message* smlMessage);

uint8_t sml_transport_parse_file(const unsigned char* smlBinary, uint32_t msgCount, SML_File* file);

uint8_t sml_transport_parse_message(const unsigned char* smlBinary, uint32_t* offset, SML_Message* message);

void sml_parser_free(void);

/* Private methods */

uint8_t p_sml_parse_open_request(const unsigned char* smlBinary, uint32_t* offset, SML_PublicOpen_Req* request);

uint8_t p_sml_parse_open_response(const unsigned char* smlBinary, uint32_t* offset, SML_PublicOpen_Res* response);

uint8_t p_sml_parse_close_request(const unsigned char* smlBinary, uint32_t* offset, SML_PublicClose_Req* request);

uint8_t p_sml_parse_close_response(const unsigned char* smlBinary, uint32_t* offset, SML_PublicClose_Res* response);

uint8_t p_sml_parse_getprofilelist_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfileList_Req* request);

uint8_t p_sml_parse_getprofilelist_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfileList_Res* response);

uint8_t p_sml_parse_getprofilepack_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfilePack_Req* request);

uint8_t p_sml_parse_getprofilepack_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetProfilePack_Res* response);

uint8_t p_sml_parse_getlist_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetList_Req* request);

uint8_t p_sml_parse_getlist_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetList_Res* response);

uint8_t p_sml_parse_getprocparameter_request(const unsigned char* smlBinary, uint32_t* offset, SML_GetProcParameter_Req* request);

uint8_t p_sml_parse_getprocparameter_response(const unsigned char* smlBinary, uint32_t* offset, SML_GetProcParameter_Res* response);

uint8_t p_sml_parse_setprocparameter_request(const unsigned char* smlBinary, uint32_t* offset, SML_SetProcParameter_Req* request);

uint8_t p_sml_parse_attention_response(const unsigned char* smlBinary, uint32_t* offset, SML_Attention_Res* response);

uint8_t p_sml_parse_messagebody(const unsigned char* smlBinary, uint32_t* offset, SML_MessageBody* messageBody);

uint8_t p_sml_parse_treepath(const unsigned char* smlBinary, uint32_t* offset, SML_TreePath* treepath);

uint8_t p_sml_parse_tree(const unsigned char* smlBinary, uint32_t* offset, SML_Tree* tree);

uint8_t p_sml_parse_tree_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Tree** tree);

uint8_t p_sml_parse_list_of_tree_optional(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_Tree** list);

uint8_t p_sml_parse_list_of_objreqentry_optional(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ObjReqEntry** list);

uint8_t p_sml_parse_list_of_periodentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_PeriodEntry* list);

uint8_t p_sml_parse_list_of_objheaderentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ProfObjHeaderEntry* list);

uint8_t p_sml_parse_list_of_objperiodentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ProfObjPeriodEntry* list);

uint8_t p_sml_parse_list_of_valueentry(const unsigned char* smlBinary, uint32_t* offset, List_of_SML_ValueEntry* list);

uint8_t p_sml_parse_valueentry(const unsigned char* smlBinary, uint32_t* offset, SML_ValueEntry* entry);

uint8_t p_sml_parse_objheaderentry(const unsigned char* smlBinary, uint32_t* offset, SML_ProfObjHeaderEntry* entry);

uint8_t p_sml_parse_objperiodentry(const unsigned char* smlBinary, uint32_t* offset, SML_ProfObjPeriodEntry* entry);

uint8_t p_sml_parse_procparvalue_optional(const unsigned char* smlBinary, uint32_t* offset, SML_ProcParValue** value);

uint8_t p_sml_parse_periodentry(const unsigned char* smlBinary, uint32_t* offset, SML_PeriodEntry* entry);

uint8_t p_sml_parse_tupelentry(const unsigned char* smlBinary, uint32_t* offset, SML_TupelEntry* entry);

uint8_t p_sml_parse_list(const unsigned char* smlBinary, uint32_t* offset, SML_List* list);

uint8_t p_sml_parse_listentry(const unsigned char* smlBinary, uint32_t* offset, SML_ListEntry* entry);

uint8_t p_sml_parse_value(const unsigned char* smlBinary, uint32_t* offset, SML_Value* value);

uint8_t p_sml_parse_status_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Status** status);

uint8_t p_sml_parse_time(const unsigned char* smlBinary, uint32_t* offset, SML_Time* time);
uint8_t p_sml_parse_time_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Time** time);

uint8_t p_sml_parse_string(const unsigned char* smlBinary, uint32_t* offset, char** value);

uint8_t p_sml_parse_boolean(const unsigned char* smlBinary, uint32_t* offset, SML_Boolean* value);
uint8_t p_sml_parse_boolean_optional(const unsigned char* smlBinary, uint32_t* offset, SML_Boolean** value);

uint8_t p_sml_parse_integer(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void* value);
uint8_t p_sml_parse_integer8(const unsigned char* smlBinary, uint32_t* offset, int8_t* value);
uint8_t p_sml_parse_integer16(const unsigned char* smlBinary, uint32_t* offset, int16_t* value);
uint8_t p_sml_parse_integer32(const unsigned char* smlBinary, uint32_t* offset, int32_t* value);
uint8_t p_sml_parse_integer64(const unsigned char* smlBinary, uint32_t* offset, int64_t* value);

uint8_t p_sml_parse_unsigned(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void* value);
uint8_t p_sml_parse_unsigned8(const unsigned char* smlBinary, uint32_t* offset, uint8_t* value);
uint8_t p_sml_parse_unsigned16(const unsigned char* smlBinary, uint32_t* offset, uint16_t* value);
uint8_t p_sml_parse_unsigned32(const unsigned char* smlBinary, uint32_t* offset, uint32_t* value);
uint8_t p_sml_parse_unsigned64(const unsigned char* smlBinary, uint32_t* offset, uint64_t* value);

uint8_t p_sml_parse_integer_optional(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void** value);
uint8_t p_sml_parse_integer8_optional(const unsigned char* smlBinary, uint32_t* offset, int8_t** value);
uint8_t p_sml_parse_integer16_optional(const unsigned char* smlBinary, uint32_t* offset, int16_t** value);
uint8_t p_sml_parse_integer32_optional(const unsigned char* smlBinary, uint32_t* offset, int32_t** value);
uint8_t p_sml_parse_integer64_optional(const unsigned char* smlBinary, uint32_t* offset, int64_t** value);

uint8_t p_sml_parse_unsigned_optional(const unsigned char* smlBinary, uint32_t size, uint32_t* offset, void** value);
uint8_t p_sml_parse_unsigned8_optional(const unsigned char* smlBinary, uint32_t* offset, uint8_t** value);
uint8_t p_sml_parse_unsigned16_optional(const unsigned char* smlBinary, uint32_t* offset, uint16_t** value);
uint8_t p_sml_parse_unsigned32_optional(const unsigned char* smlBinary, uint32_t* offset, uint32_t** value);
uint8_t p_sml_parse_unsigned64_optional(const unsigned char* smlBinary, uint32_t* offset, uint64_t** value);

uint8_t p_sml_parse_tlfield(const unsigned char* smlBinary, uint32_t* offset, TL_FieldType* tl_type, uint32_t* tl_value);

uint8_t p_sml_parse_listsize(const unsigned char* smlBinary, uint32_t* offset, uint32_t listSize);

void p_sml_add_pointer(void* ptr);

/* Private fields */

extern uint32_t p_sml_pointer_max;
extern uint32_t p_sml_pointer_count;
extern void** p_sml_pointer_list;

#endif /* SMLLIB_PARSE_H_ */
