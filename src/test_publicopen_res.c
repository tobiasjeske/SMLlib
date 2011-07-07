/**
 * File name: test_publicopen_res.c
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
	SML_PublicOpen_Res openRes;
	SML_Time refTime;
	char transactionId[] = {"OpenResponse_TransactionId"};
	char clientId[] = {"MyClient"};
	char serverId[] = {"MyServer"};
	char codepage[] = {"MyCodepage"};
	char reqFileId[] = {"MyReqFileId"};
	uint8_t smlVersion = 1;

	refTime.choiceTag = SML_TIME_SECINDEX;
	refTime.choiceValue.secIndex = 2048;

	message.abortOnError = 3;
	message.groupNo = 3;
	message.transactionId = transactionId;
	message.messageBody.choiceTag = SML_MESSAGEBODY_OPEN_RESPONSE;
	message.messageBody.choiceValue.openResponse = &openRes;

	openRes.clientId = clientId;
	openRes.serverId = serverId;
	openRes.codepage = codepage;
	openRes.reqFileId = reqFileId;
	openRes.smlVersion = &smlVersion;
	openRes.refTime = &refTime;

	return sml_encode_parse_msg_test(&message);
}
