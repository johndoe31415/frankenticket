/*
	frankenticket - Illustrating the importance of proper authentication
	Copyright (C) 2021-2021 Johannes Bauer

	This file is part of frankenticket.

	frankenticket is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	frankenticket is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with frankenticket; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

export class FrankenTicket {
	constructor(endpoint, ui_elements) {
		this._endpoint = endpoint;
		this._ui_elements = ui_elements;
	}

	_split_text(text, splitlen) {
		let split_text = "";
		for (let i = 0; i < text.length; i += splitlen) {
			split_text += text.substr(i, splitlen) + "\n";
		}
		return split_text;
	}

	_set_message_class(element, classname) {
		element.className = "message " + classname;
	}

	login() {
		this._ui_elements.msg_login.innerHTML = "";
		this._set_message_class(this._ui_elements.msg_login, "idle");
		const info_text = this._ui_elements.info.value;

		let payload = null;
		/* We deliberately do *not* JSON.stringify here because we want to keep
		 * the input exactly as the user has written it */
		if (info_text == "") {
			payload = "{ \"action\": \"login\" }";
		} else {
			payload = "{ \"action\": \"login\", \"info\": " + info_text + " }";
		}

		console.log("Login with payload: ", payload);
		fetch(this._endpoint, {
			"method":	"POST",
			"headers": {
				"Content-Type": "application/json",
			},
			"body": payload,
		}).then(response => response.json())
		.then(data => {
			if (data["status"] == "ok") {
				this._ui_elements.msg_login.innerHTML = "Login successful.";
				this._set_message_class(this._ui_elements.msg_login, "success");
				this._ui_elements.login_ciphertext.value = this._split_text(data["ticket"], 32);
				this._ui_elements.login_plaintext.value = this._split_text(data["decrypted_ticket"], 16);
				this._ui_elements.login_plaintext_pretty.value = JSON.stringify(JSON.parse(data["decrypted_ticket"]), null, 4);
			} else {
				this._ui_elements.msg_login.innerHTML = "Login failed: " + data["text"];
				this._set_message_class(this._ui_elements.msg_login, "error");
				this._ui_elements.login_ciphertext.value = "";
				this._ui_elements.login_plaintext.value = "";
				this._ui_elements.login_plaintext_pretty.value = "";
			}
			this._ui_elements.msg_login.style.display = "";
		});
	}

	auth() {
		this._ui_elements.msg_auth.innerHTML = "";
		this._set_message_class(this._ui_elements.msg_auth, "idle");
		const payload = JSON.stringify({
			"action": "auth",
			"ticket": this._ui_elements.auth_ciphertext.value,
		});

		fetch(this._endpoint, {
			"method":	"POST",
			"headers": {
				"Content-Type": "application/json",
			},
			"body": payload,
		}).then(response => response.json())
		.then(data => {
			if (data["status"] == "ok") {
				this._ui_elements.msg_auth.innerHTML = "Attack successful!";
				this._set_message_class(this._ui_elements.msg_auth, "success");
				this._ui_elements.auth_plaintext.value = this._split_text(data["ticket_text"], 16);
				this._ui_elements.auth_plaintext_pretty.value = JSON.stringify(data["ticket_data"], null, 4);
			} else if (data["status"] == "failed") {
				this._ui_elements.msg_auth.innerHTML = "Attack failed: " + data["text"];
				this._set_message_class(this._ui_elements.msg_auth, "failed");
				this._ui_elements.auth_plaintext.value = this._split_text(data["ticket_text"], 16);
				this._ui_elements.auth_plaintext_pretty.value = JSON.stringify(data["ticket_data"], null, 4);
			} else {
				this._ui_elements.msg_auth.innerHTML = "Login failed: " + data["text"];
				this._set_message_class(this._ui_elements.msg_auth, "error");
				this._ui_elements.auth_plaintext.value = "";
				this._ui_elements.auth_plaintext_pretty.value = "";
			}
			this._ui_elements.msg_auth.style.display = "";
		});
	}
}
