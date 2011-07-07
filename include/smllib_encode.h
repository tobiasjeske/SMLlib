/**
 * File name: smllib_encode.h
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

#ifndef SMLLIB_ENCODE_H_
#define SMLLIB_ENCODE_H_

#include "smllib_types.h"

/* Public methods */

SML_Encode_Binary_Result sml_encode_file_binary(SML_File* smlFile);

SML_Encode_Binary_Result sml_encode_message_binary(SML_Message* message);

SML_Encode_Binary_Result sml_transport_encode_file(SML_File* file);

SML_Encode_Binary_Result sml_transport_encode_message(SML_Message* message);


/* Private methods */

SML_Encode_Binary_Result p_sml_encode_open_request(SML_PublicOpen_Req* request);

SML_Encode_Binary_Result p_sml_encode_open_response(SML_PublicOpen_Res* response);

SML_Encode_Binary_Result p_sml_encode_close_request(SML_PublicClose_Req* request);

SML_Encode_Binary_Result p_sml_encode_close_response(SML_PublicClose_Res* response);

SML_Encode_Binary_Result p_sml_encode_getprofilepack_request(SML_GetProfilePack_Req* request);

SML_Encode_Binary_Result p_sml_encode_getprofilepack_response(SML_GetProfilePack_Res* response);

SML_Encode_Binary_Result p_sml_encode_getprofilelist_request(SML_GetProfileList_Req* request);

SML_Encode_Binary_Result p_sml_encode_getprofilelist_response(SML_GetProfileList_Res* response);

SML_Encode_Binary_Result p_sml_encode_getlist_request(SML_GetList_Req* request);

SML_Encode_Binary_Result p_sml_encode_getlist_response(SML_GetList_Res* response);

SML_Encode_Binary_Result p_sml_encode_getprocparameter_request(SML_GetProcParameter_Req* request);

SML_Encode_Binary_Result p_sml_encode_getprocparameter_response(SML_GetProcParameter_Res* response);

SML_Encode_Binary_Result p_sml_encode_setprocparameter_request(SML_SetProcParameter_Req* request);

SML_Encode_Binary_Result p_sml_encode_attention_response(SML_Attention_Res* response);

SML_Encode_Binary_Result p_sml_encode_messagebody(SML_MessageBody* messageBody);

SML_Encode_Binary_Result p_sml_encode_treepath(SML_TreePath* treePath);

SML_Encode_Binary_Result p_sml_encode_list_of_tree(List_of_SML_Tree* list);

SML_Encode_Binary_Result p_sml_encode_tree(SML_Tree* tree);

SML_Encode_Binary_Result p_sml_encode_list_of_objreqentry(List_of_SML_ObjReqEntry* list);

SML_Encode_Binary_Result p_sml_encode_list_of_periodentry(List_of_SML_PeriodEntry* list);

SML_Encode_Binary_Result p_sml_encode_list_of_objheaderentry(List_of_SML_ProfObjHeaderEntry* list);

SML_Encode_Binary_Result p_sml_encode_list_of_objperiodentry(List_of_SML_ProfObjPeriodEntry* list);

SML_Encode_Binary_Result p_sml_encode_list_of_valueentry(List_of_SML_ValueEntry* list);

SML_Encode_Binary_Result p_sml_encode_objheaderentry(SML_ProfObjHeaderEntry* entry);

SML_Encode_Binary_Result p_sml_encode_objperiodentry(SML_ProfObjPeriodEntry* entry);

SML_Encode_Binary_Result p_sml_encode_valueentry(SML_ValueEntry* entry);

SML_Encode_Binary_Result p_sml_encode_procparvalue(SML_ProcParValue* value);

SML_Encode_Binary_Result p_sml_encode_periodentry(SML_PeriodEntry* entry);

SML_Encode_Binary_Result p_sml_encode_tupelentry(SML_TupelEntry* entry);

SML_Encode_Binary_Result p_sml_encode_value(SML_Value* value);

SML_Encode_Binary_Result p_sml_encode_status(SML_Status* status);

SML_Encode_Binary_Result p_sml_encode_list(SML_List* list);

SML_Encode_Binary_Result p_sml_encode_listentry(SML_ListEntry* entry);

SML_Encode_Binary_Result p_sml_encode_time(SML_Time* time);

SML_Encode_Binary_Result p_sml_encode_string(char* in);

SML_Encode_Binary_Result p_sml_encode_boolean(SML_Boolean in);

SML_Encode_Binary_Result p_sml_encode_integer(int64_t in, uint32_t length);

SML_Encode_Binary_Result p_sml_encode_unsigned(uint64_t in, uint32_t length);

SML_Encode_Binary_Result p_sml_encode_primitive_type(void* in_ptr, TL_FieldType type, uint32_t length);

SML_Encode_Binary_Result p_sml_encode_tlfield(TL_FieldType type, uint32_t length);

void p_concat_binary_results(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result* src, uint32_t count);

void p_concat_binary_results_dynamic(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result** src, uint32_t count);

void p_allocate_concat_free(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result* src, uint32_t count);

void p_allocate_concat_free_dynamic(SML_Encode_Binary_Result* target, SML_Encode_Binary_Result** src, uint32_t count);

void p_set_encode_error(SML_Encode_Binary_Result* result, const char* errmsg);

SML_Encode_Binary_Result p_sml_transport_escape_message(SML_Encode_Binary_Result* message);

#endif /* SMLLIB_ENCODE_H_ */
