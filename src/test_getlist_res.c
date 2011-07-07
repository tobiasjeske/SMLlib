/**
 * File name: test_getlist_res.c
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
	SML_GetList_Res getListRes;
	SML_Time actSensorTime;
	SML_Time actGatewayTime;
	SML_ListEntry entry1;
	SML_ListEntry entry2;
	SML_Status status;

	uint8_t unit = 20;
	int8_t scaler = 30;
	char objName[] = {"MyObjectName"};
	char valueSignature[] = {"MyValueSignature"};

	char transactionId[] = {"GetListResponse_TransactionId"};
	char clientId[] = {"MyClient"};
	char serverId[] = {"MyServer"};
	char listName[] = {"MyList"};
	char listSignature[] = {"MyListSignature"};

	status.choiceTag = SML_STATUS_UINT16;
	status.choiceValue.uint16 = 10;
	actSensorTime.choiceTag = SML_TIME_SECINDEX;
	actSensorTime.choiceValue.secIndex = 2048;
	actGatewayTime.choiceTag = SML_TIME_TIMESTAMP;
	actGatewayTime.choiceValue.timestamp = 1234567890;

	entry1.objName = objName;
	entry1.status = &status;
	entry1.valTime = &actSensorTime;
	entry1.unit = &unit;
	entry1.scaler = &scaler;
	entry1.valueSignature = valueSignature;
	entry1.value.choiceTag = SML_VALUE_BOOLEAN;
	entry1.value.choiceValue.boolean = TRUE;
	entry2 = entry1;

	getListRes.clientId = clientId;
	getListRes.serverId = serverId;
	getListRes.listName = listName;
	getListRes.actSensorTime = &actSensorTime;
	getListRes.actGatewayTime = &actGatewayTime;
	getListRes.listSignature = listSignature;
	getListRes.valList.listSize = 1;
	getListRes.valList.valListEntry = &entry1;

	message.transactionId = transactionId;
	message.groupNo = 3;
	message.abortOnError = 3;
	message.messageBody.choiceTag = SML_MESSAGEBODY_GETLIST_RESPONSE;
	message.messageBody.choiceValue.getListResponse = &getListRes;

	return sml_encode_parse_msg_test(&message);
}
