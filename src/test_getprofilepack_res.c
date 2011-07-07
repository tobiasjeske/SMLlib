/**
 * File name: test_getprofilepack_res.c
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

#include "smllib_types.h"
#include "smllib_test.h"

int main(void) {
	SML_Message message;
	SML_GetProfilePack_Res getProfilePackRes;
	SML_ProfObjPeriodEntry periodEntry;
	SML_ProfObjHeaderEntry headerEntry;
	SML_ValueEntry valueEntry;
	char* entries[1];

	char* entry = {"MyTreePathEntry"};
	char transactionId[] = {"GetProfilePack_TransactionId"};
	char serverId[] = {"MyServer"};
	char objName[] = {"MyObjName"};
	entries[0] = entry;

	valueEntry.value.choiceTag = SML_VALUE_BOOLEAN;
	valueEntry.value.choiceValue.boolean = TRUE;
	valueEntry.valueSignature = NULL;

	periodEntry.status = 2;
	periodEntry.valTime.choiceTag = SML_TIME_SECINDEX;
	periodEntry.valTime.choiceValue.secIndex = 12;
	periodEntry.value_List.listSize = 1;
	periodEntry.value_List.value_List_Entry = &valueEntry;
	periodEntry.periodSignature = NULL;

	headerEntry.objName = objName;
	headerEntry.scaler = 1;
	headerEntry.unit = 1;

	getProfilePackRes.serverId = serverId;
	getProfilePackRes.actTime.choiceTag = SML_TIME_SECINDEX;
	getProfilePackRes.actTime.choiceValue.secIndex = 12;
	getProfilePackRes.regPeriod = 123456;
	getProfilePackRes.parameterTreePath.listSize = 1;
	getProfilePackRes.parameterTreePath.path_Entry = entries;
	getProfilePackRes.header_List.listSize = 1;
	getProfilePackRes.header_List.header_List_Entry = &headerEntry;
	getProfilePackRes.period_List.listSize = 1;
	getProfilePackRes.period_List.period_List_Entry = &periodEntry;
	getProfilePackRes.rawdata = NULL;
	getProfilePackRes.profileSignature = NULL;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_GETPROFILEPACK_RESPONSE;
	message.messageBody.choiceValue.getProfilePackResponse = &getProfilePackRes;

	return sml_encode_parse_msg_test(&message);
}
