"use strict";

const ae=new AllEars();

document.getElementById("txt_skey").onkeyup = function(e) {
	if (e.key === "Enter") document.getElementById("btn_signin").click();
}

document.getElementById("btn_signin").onclick = function() {
	const txtSkey = document.getElementById('txt_skey');
	if (!(txtSkey.reportValidity())) return;

	ae.SetKeys(txtSkey.value, function(success) {
		if (success) {
			ae.Login(function(success) {
				if (success) {
					txtSkey.value = "";
					loginSuccess();
				} else {
					console.log("Failed to log in");
				}
			});
		} else {
			console.log("Invalid format for key");
		}
	});
};

function addAddress(num) {
	const addrTable = document.getElementById("tbody_opt_addr");
	const row = addrTable.insertRow(-1);
	const cellAddr = row.insertCell(-1);
	const cellChk1 = row.insertCell(-1);
	const cellChk2 = row.insertCell(-1);
	const cellChk3 = row.insertCell(-1);
	const cellChk4 = row.insertCell(-1);
	const cellBtnD = row.insertCell(-1);

	cellAddr.textContent=ae.GetAddress(num);
	if (ae.IsAddressShield(num)) cellAddr.className="mono";

	cellChk1.innerHTML = ae.IsAddressAcceptIntMsg(num) ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk2.innerHTML = ae.IsAddressSharePk(num)      ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk3.innerHTML = ae.IsAddressAcceptExtMsg(num) ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk4.innerHTML = ae.IsAddressGatekeeper(num)   ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";

	cellChk1.onchange = function() {document.getElementById("btn_saveaddrdata").hidden=false;};
	cellChk2.onchange = function() {document.getElementById("btn_saveaddrdata").hidden=false;};
	cellChk3.onchange = function() {document.getElementById("btn_saveaddrdata").hidden=false;};
	cellChk4.onchange = function() {document.getElementById("btn_saveaddrdata").hidden=false;};

	cellBtnD.innerHTML = "<button type=\"button\">X</button>";
	cellBtnD.onclick = function() {deleteAddress(cellAddr.textContent);};

	const opt = document.createElement("option");
	opt.value = cellAddr.textContent;
	opt.textContent = cellAddr.textContent + "@allears.test";
	document.getElementById("send_from").appendChild(opt);
}

function deleteAddress(addr) {
	const btns = document.getElementById("tbody_opt_addr").getElementsByTagName("button");
	for (let i = 0; i < btns.length; i++) btns[i].disabled=true;

	let addressToDelete = -1;

	for (let i = 0; i < ae.GetAddressCount(); i++) {
		if (addr == ae.GetAddress(i)) {
			addressToDelete = i;
			break;
		}
	}

	if (addressToDelete == -1) return;

	ae.DeleteAddress(addressToDelete, function(success) {
		if (success) {
			console.log("Address #" + addressToDelete + " deleted.");
			document.getElementById("tbody_opt_addr").deleteRow(addressToDelete);
			document.getElementById("send_from").remove(addressToDelete);

			document.getElementById("addr_use_normal").textContent = ae.GetAddressCountNormal();
			document.getElementById("addr_use_shield").textContent = ae.GetAddressCountShield();
		} else {
			console.log("Address failed to delete.");
		}

		const btns = document.getElementById("tbody_opt_addr").getElementsByTagName("button");
		for (let i = 0; i < btns.length; i++) btns[i].disabled=false;

	});
}

function deleteContact(email) {
	const tbl = document.getElementById("tbody_notes_contact");
	const rows = tbl.rows;

	for (let i = 0; i < rows.length; i++) {
		if (email == rows[i].cells[0].textContent) {
			ae.DeleteContact(i);
			tbl.deleteRow(i);
			break;
		}
	}

	document.getElementById("btn_savenotes").hidden=false;
}

function addContactToTable(mail, name, note) {
	const contactTable = document.getElementById("tbody_notes_contact");
	const row = contactTable.insertRow(-1);
	const cellMail = row.insertCell(-1);
	const cellName = row.insertCell(-1);
	const cellNote = row.insertCell(-1);
	const cellBtnD = row.insertCell(-1);

	cellMail.className = "left";
	cellName.className = "left";
	cellNote.className = "left";

	cellMail.textContent = mail;
	cellName.textContent = name;
	cellNote.textContent = note;
	cellBtnD.innerHTML = "<button type=\"button\">X</button>";

	cellBtnD.onclick = function() {deleteContact(mail)};
}

function addRowAdmin(num) {
	const table = document.getElementById("tbody_admin");

	const row = table.insertRow(-1);
	const cellPk = row.insertCell(-1);
	const cellMb = row.insertCell(-1);
	const cellLv = row.insertCell(-1);
	const cellBtnPl = row.insertCell(-1);
	const cellBtnMn = row.insertCell(-1);
	const cellBtnDe = row.insertCell(-1);

	cellPk.textContent = ae.Admin_GetUserPkHex(num);
	cellMb.textContent = ae.Admin_GetUserSpace(num);
	cellLv.textContent = ae.Admin_GetUserLevel(num);
	cellBtnPl.innerHTML = "<button type=\"button\">+</button>";
	cellBtnMn.innerHTML = "<button type=\"button\">-</button>";
	cellBtnDe.innerHTML = "<button type=\"button\">X</button>";

	cellPk.className = "mono";
	if (ae.Admin_GetUserLevel(num) == ae.GetLevelMax()) cellBtnPl.children[0].disabled = "disabled";
	if (ae.Admin_GetUserLevel(num) == 0) cellBtnMn.children[0].disabled = "disabled";

	const pkHex = ae.Admin_GetUserPkHex(num);
	const currentLevel = ae.Admin_GetUserLevel(num);
	cellBtnPl.children[0].onclick = function() {setAccountLevel(pkHex, currentLevel + 1)};
	cellBtnMn.children[0].onclick = function() {setAccountLevel(pkHex, currentLevel - 1)};
	cellBtnDe.children[0].onclick = function() {destroyAccount(pkHex)};
}

document.getElementById("btn_contact_add").onclick = function() {
	const txtMail = document.getElementById("txt_newcontact_mail");
	const txtName = document.getElementById("txt_newcontact_name");
	const txtNote = document.getElementById("txt_newcontact_note");

	addContactToTable(txtMail.value, txtName.value, txtNote.value);
	ae.AddContact(txtMail.value, txtName.value, txtNote.value);

	txtMail.value = "";
	txtName.value = "";
	txtNote.value = "";

	document.getElementById("btn_savenotes").hidden=false;
};

document.getElementById("btn_savenotes").onclick = function() {
	ae.SaveNoteData(function(success) {
		if (success) {
			console.log("Note data saved successfully");
			document.getElementById("btn_savenotes").hidden=true;
		} else {
			console.log("Note data failed to save");
		}
	});
};

function destroyAccount(upk_hex) {
	const tbl = document.getElementById("tbody_admin")

	let rowid = -1;

	for (let i = 0; i < tbl.rows.length; i++) {
		if (upk_hex == tbl.rows[i].cells[0].textContent) {
			rowid = i;
			break;
		}
	}

	if (rowid == -1) return;

	ae.DestroyAccount(rowid, function(success) {
		if (success) {
			tbl.deleteRow(rowid);
		} else {
			console.log("Failed to destroy account");
		}
	});
}

function setAccountLevel(upk_hex, level) {
	const tbl = document.getElementById("tbody_admin")

	let rowid = -1;

	for (let i = 0; i < tbl.rows.length; i++) {
		if (tbl.rows[i].cells[0].textContent == upk_hex) {
			rowid = i;
			break;
		}
	}

	if (rowid == -1) return;

	ae.SetAccountLevel(rowid, level, function(success) {
		if (!success) {
			console.log("Failed to set account level");
			return;
		}

		tbl.rows[rowid].cells[2].textContent = level;

		if (level == 0) {
			tbl.rows[rowid].cells[4].children[0].disabled = "disabled";
			tbl.rows[rowid].cells[3].children[0].disabled = "";
		} else if (level == ae.GetLevelMax()) {
			tbl.rows[rowid].cells[3].children[0].disabled = "disabled";
			tbl.rows[rowid].cells[4].children[0].disabled = "";
		} else {
			tbl.rows[rowid].cells[3].children[0].disabled = "";
			tbl.rows[rowid].cells[4].children[0].disabled = "";
		}

		const pkHex = ae.Admin_GetUserPkHex(rowid);
		const currentLevel = ae.Admin_GetUserLevel(rowid);
		tbl.rows[rowid].cells[3].children[0].onclick = function() {setAccountLevel(pkHex, currentLevel + 1)};
		tbl.rows[rowid].cells[4].children[0].onclick = function() {setAccountLevel(pkHex, currentLevel - 1)};
	});
}

function clearMessages() {
	const tblInbox = document.getElementById("tbody_inbox");
	const tblSent = document.getElementById("tbody_sentbox");

	while (tblInbox.rows.length > 0) tblInbox.deleteRow(0);
	while (tblSent.rows.length > 0) tblSent.deleteRow(0);
}

function addIntMessages() {
	const tblInbox = document.getElementById("tbody_inbox");
	const tblSent = document.getElementById("tbody_sentbox");

	while (tblInbox.rows.length > 0) tblInbox.deleteRow(0);
	while (tblSent.rows.length > 0) tblSent.deleteRow(0);

	for (let i = 0; i < ae.GetIntMsgCount(); i++) {
		const isSent = ae.GetIntMsgIsSent(i);
		const table = isSent? tblSent : tblInbox;

		const row = table.insertRow(-1);
		const cellTime  = row.insertCell(-1);
		const cellTitle = row.insertCell(-1);
		const cellFrom  = row.insertCell(-1);
		const cellTo    = row.insertCell(-1);
		const cellDel   = row.insertCell(-1);

		cellTime.textContent = new Date(ae.GetIntMsgTime(i) * 1000).toLocaleString();
		cellTitle.textContent = ae.GetIntMsgTitle(i);

		if (ae.GetIntMsgTo(i).length == 36) {
			cellTo.textContent = ae.GetIntMsgTo(i).substr(0, 24);
			cellTo.className = "mono";
		} else {
			cellTo.textContent = ae.GetIntMsgTo(i);
		}

		if (ae.GetIntMsgShield(i)) {
			cellFrom.textContent = ae.GetIntMsgFrom(i).substr(0, 24);
			cellFrom.className = "mono";
		} else {
			cellFrom.textContent = ae.GetIntMsgFrom(i);
		}

		cellDel.innerHTML = "<input type=\"checkbox\" data-id=\"" + ae.GetIntMsgId(i) + "\">"

		cellTitle.onclick = function() {
			navMenu(-1);
			document.getElementById("div_readmsg").hidden=false;
			document.getElementById("readmsg_levelinfo").hidden = false;
			document.getElementById("readmsg_greetinfo").hidden = true;

			document.getElementById("readmsg_title").textContent = ae.GetIntMsgTitle(i);
			document.getElementById("readmsg_from").textContent = ae.GetIntMsgFrom(i);
			document.getElementById("readmsg_to").textContent = ae.GetIntMsgTo(i);
			document.getElementById("readmsg_body").textContent = ae.GetIntMsgBody(i);
			document.getElementById("readmsg_level").textContent = ae.GetIntMsgLevel(i);

			document.getElementById("readmsg_from").className = (ae.GetIntMsgShield(i)) ? "mono" : "";
			document.getElementById("readmsg_to").className = (ae.GetIntMsgTo(i).length == 36) ? "mono" : "";
		};

		cellDel.children[0].onchange = function() {
			if (!cellDel.children[0].checked) {
				let checked = false;
				for (let i = 0; i < table.rows.length; i++) {
					if (table.rows[i].cells[4].children[0].checked) {
						checked = true;
						break;
					}
				}

				if (!checked) {
					document.getElementById(isSent? "btn_sentdel" : "btn_msgdel").hidden=true;
					return;
				}
			}

			document.getElementById(isSent? "btn_sentdel" : "btn_msgdel").hidden=false;
		}
	}
}

function addExtMessages() {
	const tblInbox = document.getElementById("tbody_inbox");
	const tblSent = document.getElementById("tbody_sentbox");

	for (let i = 0; i < ae.GetExtMsgCount(); i++) {
		const table = tblInbox;

		const row = table.insertRow(-1);
		const cellTime  = row.insertCell(-1);
		const cellTitle = row.insertCell(-1);
		const cellFrom  = row.insertCell(-1);
		const cellTo    = row.insertCell(-1);
		const cellDel   = row.insertCell(-1);

		cellTime.textContent = new Date(ae.GetExtMsgTime(i) * 1000).toLocaleString();
		cellTitle.textContent = ae.GetExtMsgTitle(i);
		cellFrom.textContent = ae.GetExtMsgFrom(i);

		if (ae.GetExtMsgTo(i).length == 36) {
			cellTo.textContent = ae.GetExtMsgTo(i).substr(0, 24);
			cellTo.className = "mono";
		} else {
			cellTo.textContent = ae.GetExtMsgTo(i);
		}

		cellDel.innerHTML = "<input type=\"checkbox\" data-id=\"" + ae.GetExtMsgId(i) + "\">"

		cellTitle.onclick = function() {
			navMenu(-1);
			document.getElementById("div_readmsg").hidden = false;

			document.getElementById("readmsg_levelinfo").hidden = true;
			document.getElementById("readmsg_extmsg").hidden = false;
			document.getElementById("readmsg_greet").textContent = ae.GetExtMsgGreet(i);
			document.getElementById("readmsg_cs").textContent = ae.GetExtMsgCipher(i);
			document.getElementById("readmsg_ip").textContent = ae.GetExtMsgIp(i);
			document.getElementById("readmsg_country").textContent = ae.GetExtMsgCountry(i);

			let flagText = "";
			if (ae.GetExtMsgFlagPExt(i)) flagText += "ESMTP ";
			if (ae.GetExtMsgFlagQuit(i)) flagText += "QUIT ";
			if (ae.GetExtMsgFlagRare(i)) flagText += "RARE ";
			if (ae.GetExtMsgFlagFail(i)) flagText += "FAIL ";
			if (ae.GetExtMsgFlagPErr(i)) flagText += "PERR ";
			document.getElementById("readmsg_flags").textContent = flagText.trim();

			document.getElementById("readmsg_title").textContent = ae.GetExtMsgTitle(i);
			document.getElementById("readmsg_from").textContent = ae.GetExtMsgFrom(i);
			document.getElementById("readmsg_to").textContent = ae.GetExtMsgTo(i);
			document.getElementById("readmsg_body").textContent = ae.GetExtMsgBody(i);
			document.getElementById("readmsg_headers").textContent = ae.GetExtMsgHeaders(i);

			document.getElementById("readmsg_to").className = (ae.GetExtMsgTo(i).length == 36) ? "mono" : "";
		};

		cellDel.children[0].onchange = function() {
			if (!cellDel.children[0].checked) {
				let checked = false;
				for (let i = 0; i < table.rows.length; i++) {
					if (table.rows[i].cells[4].children[0].checked) {
						checked = true;
						break;
					}
				}

				if (!checked) {
					document.getElementById(isSent? "btn_sentdel" : "btn_msgdel").hidden=true;
					return;
				}
			}

			document.getElementById(isSent? "btn_sentdel" : "btn_msgdel").hidden=false;
		}
	}
}

function loginSuccess() {
	if (!ae.IsUserAdmin()) document.getElementById("btn_toadmin").hidden=true;
	document.getElementById("div_login").hidden=true;
	document.getElementById("div_loggedin").hidden=false;

	// Contacts
	for (let i = 0; i < ae.GetContactCount(); i++) {
		addContactToTable(
			ae.GetContactMail(i),
			ae.GetContactName(i),
			ae.GetContactNote(i)
		);
	}

	// Addresses
	const select=document.getElementById("send_from");
	for (let i = 0; i < ae.GetAddressCount(); i++) {
		addAddress(i);
	}

	document.getElementById("addr_use_normal").textContent = ae.GetAddressCountNormal();
	document.getElementById("addr_use_shield").textContent = ae.GetAddressCountShield();
	document.getElementById("addr_max_normal").textContent = ae.GetAddressLimitNormal();
	document.getElementById("addr_max_shield").textContent = ae.GetAddressLimitShield();

	// Gatekeeper data
	let gkList = ae.GetGatekeeperAddress();
	for (let i = 0; i < gkList.length; i++) addOpt(document.getElementById("gatekeeper_addr"), gkList[i]);

	gkList = ae.GetGatekeeperDomain();
	for (let i = 0; i < gkList.length; i++) addOpt(document.getElementById("gatekeeper_domain"), gkList[i]);

	gkList = ae.GetGatekeeperCountry();
	for (let i = 0; i < gkList.length; i++) {
		const opts = document.getElementById("gatekeeper_country");

		for (let j = 0; j < opts.length; j++) {
			if (opts[j].value == gkList[i]) {
				opts[j].selected="selected";
				break;
			}
		}
	}

	// Messages
	addIntMessages();
	addExtMessages();

	// Notes
	for (let i = 0; i < ae.GetNoteCount(); i++) {
		const table = document.getElementById("tbody_textnotes");

		const row = table.insertRow(-1);
		const cellTime = row.insertCell(-1);
		const cellTitle = row.insertCell(-1);
		const cellBtnDe = row.insertCell(-1);

		cellTime.textContent = new Date(ae.GetNoteTime(i) * 1000).toLocaleString();
		cellTitle.textContent = ae.GetNoteTitle(i);
		cellBtnDe.innerHTML = "<button type=\"button\">X</button>";

		cellBtnDe.children[0].onclick = function() {
			const parentRow = this.parentElement.parentElement;
			ae.DeleteMessages([ae.GetNoteId(parentRow.rowIndex - 1)], function(success) {
				if (success) {
					table.deleteRow(parentRow.rowIndex - 1);
				} else {
					console.log("Failed to delete note");
				}
			});
		}
	}

	if (ae.IsUserAdmin()) {
		for (let i = 0; i < ae.Admin_GetUserCount(); i++) {
			addRowAdmin(i);
		}
	}
}

function delMsgs(tblName, btnName) {
	const tbl = document.getElementById(tblName);
	let ids = [];

	for (let i = 0; i < tbl.rows.length; i++) {
		const checkbox = tbl.rows[i].cells[4].children[0];
		if (checkbox.checked) ids.push(checkbox.getAttribute("data-id"));
	}

	if (ids.length > 0) ae.DeleteMessages(ids, function(success) {
		if (success) {
			clearMessages();
			addIntMessages();
			addExtMessages();
			document.getElementById(btnName).hidden=true;
		} else {
			console.log("Failed to delete messages");
		}
	});
}

document.getElementById("btn_msgdel").onclick = function() {
	delMsgs("tbody_inbox", "btn_msgdel");
};

document.getElementById("btn_sentdel").onclick = function() {
	delMsgs("tbody_sentbox", "btn_sentdel");
};

document.getElementById("btn_send").onclick = function() {
	const scopy=document.getElementById("send_copy");
	const sfrom=document.getElementById("send_from");
	const stitle=document.getElementById("send_title");
	const sto=document.getElementById("send_to")
	const sbody=document.getElementById("send_body")

	if (!(stitle.reportValidity()) || !(sto.reportValidity()) || !(sbody.reportValidity())) return;

	ae.Send(scopy.checked, sfrom.value, sto.value, stitle.value, sbody.value, function(success) {
		if (success) {
			stitle.value="";
			sto.value="";
			sbody.value="";
		} else {
			console.log("Failed to send message");
		}
	});
};

document.getElementById("btn_notenew").onclick = function() {
	document.getElementById("div_notes_texts").hidden=true;
	document.getElementById("div_newtextnote").hidden=false;
}

document.getElementById("btn_newnote_cancel").onclick = function() {
	document.getElementById("txt_newnote_title").value = "";
	document.getElementById("txt_newnote_body").value = "";
	document.getElementById("div_notes_texts").hidden=false;
	document.getElementById("div_newtextnote").hidden=true;
}

document.getElementById("btn_newnote_save").onclick = function() {
	const txtTitle = document.getElementById("txt_newnote_title");
	const txtBody = document.getElementById("txt_newnote_body");

	if (!(txtTitle.reportValidity()) || !(txtBody.reportValidity())) return;

	ae.SaveNote(txtTitle.value, txtBody.value, function(success) {
		if (success) {
			const table = document.getElementById("tbody_textnotes");
			const row = table.insertRow(0);
			const cellTime = row.insertCell(-1);
			const cellTitle = row.insertCell(-1);
			const cellBtnDe = row.insertCell(-1);

			cellTime.textContent = "new";
			cellTitle.textContent = txtTitle.value;
			cellBtnDe.innerHTML = "<button type=\"button\" disabled=\"disabled\" title=\"Reload page to delete\">X</button>";

			document.getElementById("txt_newnote_title").value = "";
			document.getElementById("txt_newnote_body").value = "";
			document.getElementById("div_notes_texts").hidden=false;
			document.getElementById("div_newtextnote").hidden=true;
		} else {
			console.log("Failed to save note");
		}
	});
}

document.getElementById("btn_newaddress").onclick = function() {
	if (ae.GetAddressCountNormal() >= ae.GetAddressLimitNormal()) {
		console.log("Address limit reached");
		return;
	}

	const txtNewAddr = document.getElementById("txt_newaddress");
	if (!(txtNewAddr.reportValidity())) return;

	document.getElementById("btn_newaddress").disabled=true;
	document.getElementById("btn_newshieldaddress").disabled=true;

	ae.AddAddress(txtNewAddr.value, function(success) {
		document.getElementById("btn_newaddress").disabled=false;
		document.getElementById("btn_newshieldaddress").disabled=false;

		if (success) {
			document.getElementById("addr_use_normal").textContent = ae.GetAddressCountNormal();
			addAddress(ae.GetAddressCount() - 1);
			txtNewAddr.value = "";
		} else {
			console.log("Failed to add address");
		}
	});
};

document.getElementById("btn_newshieldaddress").onclick = function() {
	if (ae.GetAddressCountShield() >= ae.GetAddressLimitShield()) {
		console.log("Shield address limit reached");
		return;
	}

	document.getElementById("btn_newaddress").disabled=true;
	document.getElementById("btn_newshieldaddress").disabled=true;

	ae.AddShieldAddress(function(success) {
		document.getElementById("btn_newaddress").disabled=false;
		document.getElementById("btn_newshieldaddress").disabled=false;

		if (success) {
			document.getElementById("addr_use_shield").textContent = ae.GetAddressCountShield();
			addAddress(ae.GetAddressCount() - 1);
		} else {
			console.log("Failed to add Shield address")
		}
	});
};

document.getElementById("btn_saveaddrdata").onclick = function() {
	const tbl = document.getElementById("tbody_opt_addr")

	for (let i = 0; i < tbl.rows.length; i++) {
		ae.SetAddressAcceptIntMsg(i, tbl.rows[i].cells[1].firstChild.checked);
		ae.SetAddressSharePk     (i, tbl.rows[i].cells[2].firstChild.checked);
		ae.SetAddressAcceptExtMsg(i, tbl.rows[i].cells[3].firstChild.checked);
		ae.SetAddressGatekeeper  (i, tbl.rows[i].cells[4].firstChild.checked);
	}

	ae.SaveAddressData(function(success) {
		if (success) {
			console.log("Address data saved");
			document.getElementById("btn_saveaddrdata").hidden=true;
		} else {
			console.log("Address data failed to save");
		}
	});
};

function addOpt(select, val) {
	const opt = document.createElement("option");
	opt.value = val;
	opt.textContent = val;
	select.appendChild(opt);
}

document.getElementById("btn_gkdomain_add").onclick = function() {
	const select = document.getElementById("gatekeeper_domain");
	const txt = document.getElementById("txt_gkdomain");

	if (!(txt.reportValidity())) return;

	addOpt(select, txt.value);
	txt.value = "";
	document.getElementById("btn_savegkdata").hidden=false;
};

document.getElementById("btn_gkaddr_add").onclick = function() {
	const select = document.getElementById("gatekeeper_addr");
	const txt = document.getElementById("txt_gkaddr");

	if (!(txt.reportValidity())) return;

	addOpt(select, txt.value);
	txt.value = "";
	document.getElementById("btn_savegkdata").hidden=false;
};

document.getElementById("btn_gkdomain_del").onclick = function() {
	const select = document.getElementById("gatekeeper_domain");
	if (select.selectedIndex >= 0) select.remove(select.selectedIndex);
	document.getElementById("btn_savegkdata").hidden=false;
};

document.getElementById("btn_gkaddr_del").onclick = function() {
	const select = document.getElementById("gatekeeper_addr");
	if (select.selectedIndex >= 0) select.remove(select.selectedIndex);
	document.getElementById("btn_savegkdata").hidden=false;
};

document.getElementById("btn_savegkdata").onclick = function() {
	let blocklist = [];

	let opts = document.getElementById("gatekeeper_country").selectedOptions;
	for (let i = 0; i < opts.length; i++) blocklist.push(opts[i].value);

	opts = document.getElementById("gatekeeper_domain").options;
	for (let i = 0; i < opts.length; i++) blocklist.push(opts[i].value);

	opts = document.getElementById("gatekeeper_addr").options;
	for (let i = 0; i < opts.length; i++) blocklist.push(opts[i].value);

	ae.SaveGatekeeperData(blocklist, function(success) {
		if (success) {
			console.log("Gatekeeper update succeeded");
			document.getElementById("btn_savegkdata").hidden=true;
		} else {
			console.log("Gatekeeper update failed;")
		}
	});
};

document.getElementById("btn_admin_addaccount").onclick = function() {
	const txtPkey = document.getElementById("txt_newacc_pkey");

	if (!(txtPkey.reportValidity())) return;

	const btn = document.getElementById("btn_admin_addaccount");
	btn.disabled = "disabled";

	ae.AddAccount(txtPkey.value, function(success) {
		if (success) {
			addRowAdmin(ae.Admin_GetUserCount() - 1);
			txtPkey.value = "";
		} else {
			console.log("Failed to add account");
		}
	});

	btn.disabled = "";
};

function genKeys() {
	ae.NewKeys(function(pk, sk) {
		console.log("Public=" + pk);
		console.log("Secret=" + sk);
	});
}

// Menu
// Main Menu
function navMenu(num) {
	document.getElementById("div_readmsg").hidden=true;

	const b = document.getElementsByTagName("nav")[0].getElementsByTagName("button");
	const d = document.getElementsByClassName("maindiv");

	for (let i = 0; i < 5; i++) {
		if (i == num) {
			b[i].disabled=true;
			d[i].hidden=false;
		} else {
			b[i].disabled=false;
			d[i].hidden=true;
		}
	}
}

navMenu(0);

// Notes Menu
function navNotesMenu(num) {
	const b = document.getElementById("div_notes").getElementsByTagName("button");
	const d = document.getElementById("div_notes").getElementsByTagName("div");

	for (let i = 0; i < 4; i++) {
		if (i == num) {
			b[i].disabled=true;
			d[i].hidden=false;
		} else {
			b[i].disabled=false;
			d[i].hidden=true;
		}
	}
}

// Prefs menu
document.getElementById("btn_prefs_gatekeeper").onclick = function() {
	document.getElementById("btn_prefs_addresses").disabled=false;
	document.getElementById("btn_prefs_gatekeeper").disabled=true;
	document.getElementById("div_prefs_gatekeeper").hidden=false;
	document.getElementById("div_prefs_addresses").hidden=true;

	document.getElementById("div_prefs_gatekeeper").style.width = getComputedStyle(document.getElementById("gatekeeper_country")).width;
};

document.getElementById("btn_prefs_addresses").onclick = function() {
	document.getElementById("btn_prefs_addresses").disabled=true;
	document.getElementById("btn_prefs_gatekeeper").disabled=false;
	document.getElementById("div_prefs_gatekeeper").hidden=true;
	document.getElementById("div_prefs_addresses").hidden=false;
};

let b = document.getElementsByTagName("nav")[0].getElementsByTagName("button");
b[0].onclick = function() {navMenu(0);};
b[1].onclick = function() {navMenu(1);};
b[2].onclick = function() {navMenu(2);};
b[3].onclick = function() {navMenu(3);};
b[4].onclick = function() {navMenu(4);};

b = document.getElementById("div_notes").getElementsByTagName("button");
b[0].onclick = function() {navNotesMenu(0);};
b[1].onclick = function() {navNotesMenu(1);};
b[2].onclick = function() {navNotesMenu(2);};
b[3].onclick = function() {navNotesMenu(3);};

gatekeeper_country.onchange = function() {
	document.getElementById("btn_savegkdata").hidden=false;
};
