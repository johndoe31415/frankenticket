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

import cgi
import sys
import json
import os
import subprocess
import sqlite3
import datetime
import contextlib
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes

config = {
	# TODO: Change this to a random key.
	"key": bytes.fromhex("700e262e085f16db8e970db29a6143a2"),
}

def print_headers(status, text, headers = None):
	print("Status: %d %s" % (status, text))
	print("Access-Control-Allow-Origin: *")
	print("Access-Control-Allow-Methods: POST")
	print("Access-Control-Allow-Headers: Content-Type")
	if headers is not None:
		for (key, value) in headers.items():
			print("%s: %s" % (key, value))
	print()
if os.environ["REQUEST_METHOD"] == "GET":
	print_headers(200, "OK", { "Content-Type": "application/json" })
	print(json.dumps({ "text": "No content." }))
	sys.exit(0)
elif os.environ["REQUEST_METHOD"] == "OPTIONS":
	# Preflight. Just return a 200.
	print_headers(200, "OK")
	sys.exit(0)

def return_error(status, msg):
	print_headers(status, {
		400: "Bad Request",
		500: "Internal Server Error",
	}[status], { "Content-Type": "application/json" })
	print(json.dumps({ "status": "error", "text": msg }))
	sys.exit(0)

try:
	json_data = json.load(sys.stdin)
except json.decoder.JSONDecodeError as e:
	return_error(400, "Unable to parse JSON: %s" % (str(e)))

if not isinstance(json_data, dict):
	return_error(400, "Unable to interpret JSON: Expected dict data type")
if not "action" in json_data:
	return_error(400, "Unable to interpret JSON: No 'action' field present")


if json_data["action"] == "login":
	if not "info" in json_data:
		info_dict = None
	else:
		info_dict = json_data["info"]

	def filter_dict(element):
		if isinstance(element, dict):
			for forbidden_key in [ "privs", "username", "info", "timestamp" ]:
				if forbidden_key in element:
					return_error(400, "Security alert: The '%s' key is disallowed in the 'info' dictionary." % (forbidden_key))
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

	cipher = cryptography.hazmat.primitives.ciphers.Cipher(cryptography.hazmat.primitives.ciphers.algorithms.AES(config["key"]), cryptography.hazmat.primitives.ciphers.modes.ECB(), backend = cryptography.hazmat.backends.default_backend())
	encryptor = cipher.encryptor()
	encrypted_ticket = encryptor.update(ticket_bin) + encryptor.finalize()

	print_headers(200, "OK", { "Content-Type": "application/json" })
	print(json.dumps({ "status": "ok", "ticket": encrypted_ticket.hex(), "decrypted_ticket": ticket_bin.decode("ascii") }))
elif json_data["action"] == "auth":
	if not "ticket" in json_data:
		return_error(400, "Unable to interpret JSON: No 'ticket' field present")
	try:
		ticket = bytes.fromhex(json_data["ticket"])
	except ValueError as e:
		return_error(400, "Unable to parse ticket as hex: %s" % (str(e)))

	if (len(ticket) % 16) != 0:
		return_error(400, "Binary ticket length is not a multiple of 16 bytes (found %d bytes)." % (len(ticket)))

	cipher = cryptography.hazmat.primitives.ciphers.Cipher(cryptography.hazmat.primitives.ciphers.algorithms.AES(config["key"]), cryptography.hazmat.primitives.ciphers.modes.ECB(), backend = cryptography.hazmat.backends.default_backend())
	decryptor = cipher.decryptor()
	decrypted_ticket = decryptor.update(ticket) + decryptor.finalize()

	try:
		decrypted_ticket_text = decrypted_ticket.decode("ascii")
	except UnicodeDecodeError:
		return_error(400, "Binary ticket is corrupt, cannot decrypt to pure text.")

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

	print_headers(200, "OK", { "Content-Type": "application/json" })
	print(json.dumps({
		"status": "ok" if (ticket_err is None) else "failed",
		"ticket_text": decrypted_ticket_text,
		"ticket_data": ticket_data,
		"text": ticket_err,
	}))
else:
	return_error(400, "Unknown JSON action: %s" % (json_data["action"]))
