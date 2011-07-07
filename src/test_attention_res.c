/**
 * File name: test_attention_res.c
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
	SML_Attention_Res attentionResponse;
	SML_Tree tree;
	SML_ProcParValue ppv;
	SML_Value value;

	char transactionId[] = {"AttentionResponse_TransactionId"};
	char serverId[] = {"MyServer"};
	char attentionNo[] = {"AttentionNo"};
	char attentionMsg[] = {"AttentionMsg"};
	char parameterName[] = {"ParameterName"};
	char valueString[] = {"MyValue"};

	value.choiceTag = SML_VALUE_STRING;
	value.choiceValue.string = valueString;

	ppv.choiceTag = SML_PROCPAR_VALUE;
	ppv.choiceValue.smlValue = &value;

	tree.child_List = NULL;
	tree.parameterName = parameterName;
	tree.parameterValue = &ppv;

	attentionResponse.serverId = serverId;
	attentionResponse.attentionNo = attentionNo;
	attentionResponse.attentionMsg = attentionMsg;
	attentionResponse.attentionDetails = &tree;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_ATTENTION_RESPONSE;
	message.messageBody.choiceValue.attentionResponse = &attentionResponse;

	return sml_encode_parse_msg_test(&message);
}
