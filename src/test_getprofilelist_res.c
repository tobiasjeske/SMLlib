/**
 * File name: test_getprofilelist_res.c
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
	SML_GetProfileList_Res getProfileListRes;
	SML_PeriodEntry periodEntry;
	char* entries[1];

	char* entry = {"MyTreePathEntry"};
	char transactionId[] = {"GetProfileList_TransactionId"};
	char serverId[] = {"MyServer"};
	char rawdata[] = {"MyRawData"};
	char signature[] = {"MySignature"};
	char objName[] = {"MyObjName"};
	entries[0] = entry;

	periodEntry.objName = objName;
	periodEntry.scaler = 1;
	periodEntry.unit = 2;
	periodEntry.value.choiceTag = SML_VALUE_BOOLEAN;
	periodEntry.value.choiceValue.boolean = TRUE;
	periodEntry.valueSignature = signature;

	getProfileListRes.serverId = serverId;
	getProfileListRes.actTime.choiceTag = SML_TIME_SECINDEX;
	getProfileListRes.actTime.choiceValue.secIndex = 12;
	getProfileListRes.regPeriod = 123456;
	getProfileListRes.parameterTreePath.listSize = 1;
	getProfileListRes.parameterTreePath.path_Entry = entries;
	getProfileListRes.valTime.choiceTag = SML_TIME_SECINDEX;
	getProfileListRes.valTime.choiceValue.secIndex = 12;
	getProfileListRes.status = 1;
	getProfileListRes.period_List.listSize = 1;
	getProfileListRes.period_List.period_List_Entry = &periodEntry;
	getProfileListRes.rawdata = rawdata;
	getProfileListRes.periodSignature = signature;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_GETPROFILELIST_RESPONSE;
	message.messageBody.choiceValue.getProfileListResponse = &getProfileListRes;

	return sml_encode_parse_msg_test(&message);
}
