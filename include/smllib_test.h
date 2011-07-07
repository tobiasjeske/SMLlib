/**
 * File name: smllib_test.h
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
#ifndef SMLLIB_TEST_H_
#define SMLLIB_TEST_H_

#include "smllib_types.h"

int sml_encode_parse_msg_test(SML_Message* message);

int sml_encode_parse_file_test(SML_File* file);

int sml_transport_msg_test(SML_Message* message);

int sml_transport_file_test(SML_File* file);

#endif /* SMLLIB_TEST_H_ */
