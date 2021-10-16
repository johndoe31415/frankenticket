#!/usr/bin/python3
#	frankenticket - Illustrating the importance of proper authentication
#	Copyright (C) 2021-2021 Johannes Bauer
#
#	This file is part of frankenticket.
#
#	frankenticket is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	frankenticket is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with frankenticket; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import sys
import json
import os
import datetime
import base64
import binascii
from BrokenFeistelCipher import BrokenFeistelCipher

def lambda_handler(event, context):
	# TODO: Change this to a random key.
	cipher = BrokenFeistelCipher(key = bytes.fromhex("700e262e085f16db8e970db29a6143a2"))

	def emit_error(status, msg):
		return {
			"statusCode": status,
			"body": json.dumps({ "status": "error", "text": msg }),
		}


	if "requestContext" not in event:
		return emit_error(200, "No requestContext request data present.")
	if "http" not in event["requestContext"]:
		return emit_error(200, "No http request data present.")
	if "method" not in event["requestContext"]["http"]:
		return emit_error(200, "No method request data present.")

	if event["requestContext"]["http"]["method"].lower() != "post":
		return emit_error(200, "Not submitted via POST, no content returned.")

	if event["isBase64Encoded"]:
		try:
			event["body"] = base64.b64decode(event["body"])
		except binascii.Error as e:
			return emit_error(400, "Unable to decode base64: invalid data (%s)" % (str(e)))

	try:
		json_data = json.loads(event["body"])
	except json.decoder.JSONDecodeError as e:
		return emit_error(400, "Unable to parse JSON: %s" % (str(e)))

	if not isinstance(json_data, dict):
		return emit_error(400, "Unable to interpret JSON: Expected dict data type")
	if not "action" in json_data:
		return emit_error(400, "Unable to interpret JSON: No 'action' field present")

	if json_data["action"] == "login":
		if not "info" in json_data:
			info_dict = None
		else:
			info_dict = json_data["info"]

		def filter_dict(element):
			if isinstance(element, dict):
				for forbidden_key in [ "privs", "username", "info", "timestamp" ]:
					if forbidden_key in element:
						return emit_error(400, "Security alert: The '%s' key is disallowed in the 'info' dictionary." % (forbidden_key))
				for value in element.values():
					filter_dict(value)
		filter_dict(info_dict)

		ticket = {
			"username": "John Doe",
			"info": info_dict,
			"privs": [ "read" ],
			"timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
		}
		ticket_bin = json.dumps(ticket, sort_keys = True).encode("ascii")
		if (len(ticket_bin) % 16) != 0:
			ticket_bin += b" " * (16 - 	(len(ticket_bin) % 16))
		encrypted_ticket = cipher.encrypt(ticket_bin)

		return {
			"statusCode": 200,
			"body": json.dumps({ "status": "ok", "ticket": encrypted_ticket.hex(), "decrypted_ticket": ticket_bin.decode("ascii") }),
		}
	elif json_data["action"] == "auth":
		if not "ticket" in json_data:
			return emit_error(400, "Unable to interpret JSON: No 'ticket' field present")
		try:
			ticket = bytes.fromhex(json_data["ticket"])
		except ValueError as e:
			return emit_error(400, "Unable to parse ticket as hex: %s" % (str(e)))

		if (len(ticket) % 16) != 0:
			return emit_error(400, "Binary ticket length is not a multiple of 16 bytes (found %d bytes)." % (len(ticket)))

		decrypted_ticket = cipher.decrypt(ticket)
		try:
			decrypted_ticket_text = decrypted_ticket.decode("ascii")
		except UnicodeDecodeError:
			return emit_error(400, "Binary ticket is corrupt, cannot decrypt to pure text.")

		try:
			ticket_data = json.loads(decrypted_ticket_text)
			ticket_err = None
		except json.decoder.JSONDecodeError as e:
			ticket_data = None
			ticket_err = "Cannot decode JSON: %s" % (str(e))

		while ticket_data is not None:
			if ticket_data is None:
				ticket_err = "Ticket data was null"
				break

			if not isinstance(ticket_data, dict):
				ticket_err = "Ticket data was not a dictionary"
				break

			if "privs" not in ticket_data:
				ticket_err = "Ticket does not contain a 'privs' key"
				break

			if not isinstance(ticket_data["privs"], list):
				ticket_err = "Ticket 'privs' is not a list"
				break

			if "read" not in ticket_data["privs"]:
				ticket_err = "Ticket does not have the 'read' permission"
				break

			if "write" not in ticket_data["privs"]:
				ticket_err = "Ticket does not have the 'write' permission"
				break

			if "execute" not in ticket_data["privs"]:
				ticket_err = "Ticket does not have the 'execute' permission"
				break
			break

		return {
			"statusCode": 200,
			"body": json.dumps({
				"status": "ok" if (ticket_err is None) else "failed",
				"ticket_text": decrypted_ticket_text,
				"ticket_data": ticket_data,
				"text": ticket_err,
			}),
		}
	else:
		return emit_error(400, "Unknown JSON action: %s" % (json_data["action"]))

if __name__ == "__main__":
	print(lambda_handler({
		"requestContext": { "http": { "method": "POST" } },
		"body": "{\"action\": \"login\"}",
		"isBase64Encoded": False,
	}, None))

	print(lambda_handler({
		"requestContext": { "http": { "method": "POST" } },
		"body": "{\"action\": \"auth\", \"ticket\": \"eee09539a710755eec60199ee7c1dcdb0c587d0fc042c159d8b04dfdf604607c76330f87f6fc95d5cc18461b9af2d570876ca59eb571c65b5dd50c9dc1911fd9abb9fabff7477155aa5781ea6023538a315095339e6e08e3901f936c831bc7fb0b7c4926f573305ec914deafe6af1d73\"}",
		"isBase64Encoded": False,
	}, None))
