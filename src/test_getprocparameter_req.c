/**
 * File name: test_getprocparameter_req.c
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
	SML_GetProcParameter_Req getProcParameterReq;
	char* entries[1];

	char* entry = {"MyTreePathEntry"};
	char transactionId[] = {"GetProcParameter_TransactionId"};
	char serverId[] = {"MyServer"};
	char username[] = {"MyUser"};
	char password[] = {"MyPassword"};
	char attribute[] = {"MyAttribute"};
	entries[0] = entry;

	getProcParameterReq.parameterTreePath.listSize = 1;
	getProcParameterReq.parameterTreePath.path_Entry = entries;
	getProcParameterReq.serverId = serverId;
	getProcParameterReq.username = username;
	getProcParameterReq.password = password;
	getProcParameterReq.attribute = attribute;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_GETPROCPARAMETER_REQUEST;
	message.messageBody.choiceValue.getProcParameterRequest = &getProcParameterReq;

	return sml_encode_parse_msg_test(&message);
}
