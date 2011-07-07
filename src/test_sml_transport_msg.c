/**
 * File name: test_sml_transport_msg.c
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
	SML_GetList_Req getListReq;

	char transactionId[] = {"SML_Transport_Test"};
	char clientId[] = {"MyClient"};
	char serverId[] = {"MyServer"};
	char listName[] = {"MyList"};
	char username[] = {"MyUser"};
	char password[] = {"MyPassword"};

	clientId[0] = 0x1B;
	clientId[1] = 0x1B;
	clientId[2] = 0x1B;
	clientId[3] = 0x1B;

	getListReq.clientId = clientId;
	getListReq.serverId = serverId;
	getListReq.listName = listName;
	getListReq.username = username;
	getListReq.password = password;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_GETLIST_REQUEST;
	message.messageBody.choiceValue.getListRequest = &getListReq;

	return sml_transport_msg_test(&message);
}
