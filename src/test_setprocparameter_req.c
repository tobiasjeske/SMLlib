/**
 * File name: test_setprocparameter_req.c
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
	SML_SetProcParameter_Req setProcParameterReq;
	List_of_SML_Tree childList;
	SML_Tree parameterTree;
	SML_ProcParValue ppv;
	SML_Value value;

	char* entries[1];
	char* entry = {"MyTreePathEntry"};

	char transactionId[] = {"SetProcParameter_TransactionId"};
	char serverId[] = {"MyServer"};
	char username[] = {"MyUser"};
	char password[] = {"MyPassword"};
	char parameterName[] = {"MyParameterName"};

	value.choiceTag = SML_VALUE_INT8;
	value.choiceValue.int8 = 10;

	ppv.choiceTag = SML_PROCPAR_VALUE;
	ppv.choiceValue.smlValue = &value;

	parameterTree.child_List = NULL;
	parameterTree.parameterName = parameterName;
	parameterTree.parameterValue = &ppv;
	childList.listSize = 1;
	childList.tree_Entry = &parameterTree;

	setProcParameterReq.parameterTree.child_List = &childList;
	setProcParameterReq.parameterTree.parameterName = parameterName;
	setProcParameterReq.parameterTree.parameterValue = &ppv;

	entries[0] = entry;
	setProcParameterReq.parameterTreePath.listSize = 1;
	setProcParameterReq.parameterTreePath.path_Entry = entries;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_SETPROCPARAMETER_REQUEST;
	message.messageBody.choiceValue.setProcParameterRequest = &setProcParameterReq;

	setProcParameterReq.serverId = serverId;
	setProcParameterReq.username = username;
	setProcParameterReq.password = password;

	return sml_encode_parse_msg_test(&message);
}
