/**
 * File name: test_sml_transport_file.c
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
	SML_Message message1;
	SML_Message message2;
	SML_Message message3;
	SML_PublicOpen_Req openReq;
	SML_PublicClose_Req closeReq;
	SML_GetList_Req getListReq;
	SML_File smlFile;
	SML_Message* msgList[3];

	char globalSignature[] = {"MySignature"};
	char transactionId[] = {"SML_File_Test"};
	char clientId[] = {"MyClient"};
	char serverId[] = {"MyServer"};
	char listName[] = {"MyList"};
	char username[] = {"MyUser"};
	char password[] = {"MyPassword"};
	char codepage[] = {"MyCodepage"};
	char reqFileId[] = {"MyReqFileId"};
	uint8_t smlVersion = 1;

	openReq.clientId = clientId;
	openReq.serverId = serverId;
	openReq.codepage = codepage;
	openReq.username = username;
	openReq.password = password;
	openReq.reqFileId = reqFileId;
	openReq.smlVersion = &smlVersion;

	clientId[0] = 0x1B;
	clientId[1] = 0x1B;
	clientId[2] = 0x1B;
	clientId[3] = 0x1B;

	getListReq.clientId = clientId;
	getListReq.serverId = serverId;
	getListReq.listName = listName;
	getListReq.username = username;
	getListReq.password = password;

	closeReq.globalSignature = globalSignature;

	message1.abortOnError = 3;
	message1.groupNo = 3;
	message1.transactionId = transactionId;
	message1.messageBody.choiceTag = SML_MESSAGEBODY_OPEN_REQUEST;
	message1.messageBody.choiceValue.openRequest = &openReq;
	msgList[0] = &message1;

	message2.abortOnError = 3;
	message2.groupNo = 3;
	message2.transactionId = transactionId;
	message2.messageBody.choiceTag = SML_MESSAGEBODY_GETLIST_REQUEST;
	message2.messageBody.choiceValue.getListRequest = &getListReq;
	msgList[1] = &message2;

	message3.abortOnError = 3;
	message3.groupNo = 3;
	message3.transactionId = transactionId;
	message3.messageBody.choiceTag = SML_MESSAGEBODY_CLOSE_REQUEST;
	message3.messageBody.choiceValue.closeRequest = &closeReq;
	msgList[2] = &message3;

	smlFile.messages = msgList;
	smlFile.msgCount = 3;
	smlFile.version = smlVersion;

	closeReq.globalSignature = globalSignature;

	return sml_transport_file_test(&smlFile);
}
