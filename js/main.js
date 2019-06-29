ae=new AllEars();

document.getElementById("btn_signin").onclick = function() {
	// All-Ears needs to be provided with the user's secret key in order to log in
	ae.SetKeys(document.getElementById('txt_skey').value);

	ae.Login(function(success) {
		if (success) {
			loginSuccess();
		} else {
			console.log("Failed to log in");
		}
	});
};

function tsToISO8601(ts){
	const dt = new Date(ts * 1000);
	const dt_Y = dt.getUTCFullYear();
	const dt_m = dt.getUTCMonth()   < 10 ? '0' + dt.getUTCMonth()   : dt.getUTCMonth();
	const dt_d = dt.getUTCDate()    < 10 ? '0' + dt.getUTCDate()    : dt.getUTCDate();
	const dt_H = dt.getUTCHours()   < 10 ? '0' + dt.getUTCHours()   : dt.getUTCHours();
	const dt_M = dt.getUTCMinutes() < 10 ? '0' + dt.getUTCMinutes() : dt.getUTCMinutes();
	const dt_S = dt.getUTCSeconds() < 10 ? '0' + dt.getUTCSeconds() : dt.getUTCSeconds();
	return dt_Y + '-' + dt_m + '-' + dt_d + 'T' + dt_H + ':' + dt_M + ':' + dt_S + 'Z';
}

function addOptAddr(num) {
	const addrTable = document.getElementById("tbody_opt_addr");
	let row = addrTable.insertRow(-1);
	let cellAddr = row.insertCell(-1);
	let cellChk1 = row.insertCell(-1);
	let cellChk2 = row.insertCell(-1);
	let cellChk3 = row.insertCell(-1);
	let cellChk4 = row.insertCell(-1);
	let cellBtnD = row.insertCell(-1);

	cellAddr.textContent=ae.GetAddress(num);
	if (ae.IsAddressShield(num)) cellAddr.className="mono";

	cellChk1.innerHTML = ae.IsAddressAcceptIntMsg(num) ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk2.innerHTML = ae.IsAddressSharePk(num)      ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk3.innerHTML = ae.IsAddressAcceptExtMsg(num) ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk4.innerHTML = ae.IsAddressGatekeeper(num)   ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";

	cellChk1.onchange = function() {document.getElementById("btn_saveaddrdata").style.display="inline";};
	cellChk2.onchange = function() {document.getElementById("btn_saveaddrdata").style.display="inline";};
	cellChk3.onchange = function() {document.getElementById("btn_saveaddrdata").style.display="inline";};
	cellChk4.onchange = function() {document.getElementById("btn_saveaddrdata").style.display="inline";};

	cellBtnD.innerHTML = "<button>&#128473;</button>";
	cellBtnD.onclick = function() {deleteAddress(cellAddr.textContent);};
}

function deleteAddress(addr) {
	let btns = document.getElementById("tbody_opt_addr").getElementsByTagName("button");
	for (i = 0; i < btns.length; i++) btns[i].disabled="disabled";

	let addressToDelete = -1;

	for (i = 0; i < ae.GetAddressCount(); i++) {
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
			document.getElementById("addr_use_normal").textContent = ae.GetAddressCountNormal();
			document.getElementById("addr_use_shield").textContent = ae.GetAddressCountShield();
		} else {
			console.log("Address failed to delete.");
		}

		let btns = document.getElementById("tbody_opt_addr").getElementsByTagName("button");
		for (i = 0; i < btns.length; i++) btns[i].disabled="";

	});
}

function deleteContact(email) {
	const tbl = document.getElementById("tbody_notes_contact");
	const rows = tbl.rows;

	for (i = 0; i < rows.length; i++) {
		if (email == rows[i].cells[0].textContent) {
			ae.DeleteContact(i);
			tbl.deleteRow(i);
			break;
		}
	}

	document.getElementById("btn_savenotes").style.display = "inline";
}

function addContactToTable(mail, name, note) {
	const contactTable = document.getElementById("tbody_notes_contact");
	let row = contactTable.insertRow(-1);
	let cellMail = row.insertCell(-1);
	let cellName = row.insertCell(-1);
	let cellNote = row.insertCell(-1);
	let cellBtnD = row.insertCell(-1);

	cellMail.className = "left";
	cellName.className = "left";
	cellNote.className = "left";

	cellMail.textContent = mail;
	cellName.textContent = name;
	cellNote.textContent = note;
	cellBtnD.innerHTML = "<button>X</button>";

	cellBtnD.onclick = function() {deleteContact(mail)};
}

function addRowAdmin(num) {
	const table = document.getElementById("tbody_admin");

	let row = table.insertRow(-1);
	let cellPk = row.insertCell(-1);
	let cellMb = row.insertCell(-1);
	let cellLv = row.insertCell(-1);
	let cellBtnPl = row.insertCell(-1);
	let cellBtnMn = row.insertCell(-1);
	let cellBtnDe = row.insertCell(-1);

	cellPk.textContent = ae.Admin_GetUserPkHex(num);
	cellMb.textContent = ae.Admin_GetUserSpace(num);
	cellLv.textContent = ae.Admin_GetUserLevel(num);
	cellBtnPl.innerHTML = "<button>+</button>";
	cellBtnMn.innerHTML = "<button>-</button>";
	cellBtnDe.innerHTML = "<button>X</button>";

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
	txtMail = document.getElementById("txt_newcontact_mail");
	txtName = document.getElementById("txt_newcontact_name");
	txtNote = document.getElementById("txt_newcontact_note");

	addContactToTable(txtMail.value, txtName.value, txtNote.value);
	ae.AddContact(txtMail.value, txtName.value, txtNote.value);

	txtMail.value = "";
	txtName.value = "";
	txtNote.value = "";

	document.getElementById("btn_savenotes").style.display = "inline";
};

document.getElementById("btn_savenotes").onclick = function() {
	ae.SaveNoteData(function(success) {
		if (success) {
			console.log("Note data saved successfully");
			document.getElementById("btn_savenotes").style.display = "none";
		} else {
			console.log("Note data failed to save");
		}
	});
};

function destroyAccount(upk_hex) {
	let tbl = document.getElementById("tbody_admin")

	let rowid = -1;

	for (i = 0; i < tbl.rows.length; i++) {
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
	let tbl = document.getElementById("tbody_admin")

	let rowid = -1;

	for (i = 0; i < tbl.rows.length; i++) {
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

function loginSuccess() {
	if (!ae.IsUserAdmin()) document.getElementById("btn_toadmin").style.display="none";
	document.getElementById("div_login").style.display="none";
	document.getElementById("div_loggedin").style.display="inline";

	// Contacts
	for (let i = 0; i < ae.GetContactCount(); i++) {
		addContactToTable(
			ae.GetContactMail(i),
			ae.GetContactName(i),
			ae.GetContactNote(i)
		);
	}

	// Addresses
	let select=document.getElementById("send_from");
	for (let i = 0; i < ae.GetAddressCount(); i++) {
		let opt = document.createElement("option");
		opt.value = ae.GetAddress(i);
		opt.textContent = ae.GetAddress(i) + "@allears.test";
		select.appendChild(opt);

		addOptAddr(i);
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
		opts = document.getElementById("gatekeeper_country");

		for (let j = 0; j < opts.length; j++) {
			if (opts[j].value == gkList[i]) {
				opts[j].selected="selected";
				break;
			}
		}
	}

	// Messages
	for (let i = 0; i < ae.GetIntMsgCount(); i++) {
		const table = document.getElementById("tbody_inbox");

		let row = table.insertRow(-1);
		let cellTime  = row.insertCell(-1);
		let cellTitle = row.insertCell(-1);
		let cellFrom  = row.insertCell(-1);
		let cellTo    = row.insertCell(-1);
		let cellDel   = row.insertCell(-1);

		cellTime.textContent = tsToISO8601(ae.GetIntMsgTime(i));
		cellTitle.textContent = ae.GetIntMsgTitle(i);
		cellFrom.textContent = ae.GetIntMsgFrom(i);
		cellTo.textContent = ae.GetIntMsgTo(i);
		cellFrom.className = ae.GetIntMsgShield(i) ? "mono" : "";
		cellDel.innerHTML = "<input type=\"checkbox\">"

		cellTitle.onclick = function() {
			navMenu(-1);
			document.getElementById("div_readmsg").style.display="inline";

			document.getElementById("readmsg_title").textContent = ae.GetIntMsgTitle(i);
			document.getElementById("readmsg_from").textContent = ae.GetIntMsgFrom(i);
			document.getElementById("readmsg_to").textContent = ae.GetIntMsgTo(i);
			document.getElementById("readmsg_body").textContent = ae.GetIntMsgBody(i);
			document.getElementById("readmsg_level").textContent = ae.GetIntMsgLevel(i);
			document.getElementById("readmsg_from").className = ae.GetIntMsgShield(i) ? "mono" : "";
		};

		cellDel.onchange = function() {
			document.getElementById("btn_msgdel").style.display="inline";
		}
	}

	if (ae.IsUserAdmin()) {
		for (let i = 0; i < ae.Admin_GetUserCount(); i++) {
			addRowAdmin(i);
		}
	}
}

document.getElementById("btn_msgdel").onclick = function() {
	const tbl = document.getElementById("tbody_inbox");
	let ids = [];

	for (let i = 0; i < tbl.rows.length; i++) {
		if (tbl.rows[i].cells[4].children[0].checked) {
			ids.push(i);
		}
	}

	if (ids.length > 0) ae.DeleteMessages(ids, function(success) {
		if (success) {
			let rowsDeleted = 0;
			for (let i = 0; i < ids.length; i++) {
				tbl.deleteRow(ids[i] - rowsDeleted);
				rowsDeleted++;
			}

			document.getElementById("btn_msgdel").style.display="none";
		} else {
			console.log("Failed to delete messages");
		}
	});

};

document.getElementById("btn_send").onclick = function() {
	sfrom=document.getElementById("send_from");
	stitle=document.getElementById("send_title");
	sto=document.getElementById("send_to")
	sbody=document.getElementById("send_body")

	ae.Send(sfrom.value, sto.value, stitle.value, sbody.value, function(success) {
		if (success) {
			stitle.value="";
			sto.value="";
			sbody.value="";
		} else {
			console.log("Failed to send message");
		}
	});
};

document.getElementById("btn_newaddress").onclick = function() {
	if (ae.GetAddressCountNormal() >= ae.GetAddressLimitNormal()) {
		console.log("Address limit reached");
		return;
	}

	document.getElementById("btn_newaddress").disabled="disabled";
	document.getElementById("btn_newshieldaddress").disabled="disabled";

	ae.AddAddress(document.getElementById("txt_newaddress").value, function(success) {
		document.getElementById("btn_newaddress").disabled="";
		document.getElementById("btn_newshieldaddress").disabled="";

		if (success) {
			document.getElementById("addr_use_normal").textContent = ae.GetAddressCountNormal();
			addOptAddr(ae.GetAddressCount() - 1);
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

	document.getElementById("btn_newaddress").disabled="disabled";
	document.getElementById("btn_newshieldaddress").disabled="disabled";

	ae.AddShieldAddress(function(success) {
		document.getElementById("btn_newaddress").disabled="";
		document.getElementById("btn_newshieldaddress").disabled="";

		if (success) {
			document.getElementById("addr_use_shield").textContent = ae.GetAddressCountShield();
			addOptAddr(ae.GetAddressCount() - 1);
		} else {
			console.log("Failed to add Shield address")
		}
	});
};

document.getElementById("btn_saveaddrdata").onclick = function() {
	let tbl = document.getElementById("tbody_opt_addr")

	for (let i = 0; i < tbl.rows.length; i++) {
		ae.SetAddressAcceptIntMsg(i, tbl.rows[i].cells[1].firstChild.checked);
		ae.SetAddressSharePk     (i, tbl.rows[i].cells[2].firstChild.checked);
		ae.SetAddressAcceptExtMsg(i, tbl.rows[i].cells[3].firstChild.checked);
		ae.SetAddressGatekeeper  (i, tbl.rows[i].cells[4].firstChild.checked);
	}

	ae.SaveAddressData(function(success) {
		if (success) {
			console.log("Address data saved");
			document.getElementById("btn_saveaddrdata").style.display="none";
		} else {
			console.log("Address data failed to save");
		}
	});
};

function addOpt(select, val) {
	let opt = document.createElement("option");
	opt.value = val;
	opt.textContent = val;
	select.appendChild(opt);
}

document.getElementById("btn_gkdomain_add").onclick = function() {
	let select = document.getElementById("gatekeeper_domain");
	let txt = document.getElementById("txt_gkdomain");

	if (!(txt.reportValidity())) return;

	addOpt(select, txt.value);
	txt.value = "";
	document.getElementById("btn_savegkdata").style.display="inline";
};

document.getElementById("btn_gkaddr_add").onclick = function() {
	let select = document.getElementById("gatekeeper_addr");
	let txt = document.getElementById("txt_gkaddr");

	if (!(txt.reportValidity())) return;

	addOpt(select, txt.value);
	txt.value = "";
	document.getElementById("btn_savegkdata").style.display="inline";
};

document.getElementById("btn_gkdomain_del").onclick = function() {
	let select = document.getElementById("gatekeeper_domain");
	if (select.selectedIndex >= 0) select.remove(select.selectedIndex);
	document.getElementById("btn_savegkdata").style.display="inline";
};

document.getElementById("btn_gkaddr_del").onclick = function() {
	let select = document.getElementById("gatekeeper_addr");
	if (select.selectedIndex >= 0) select.remove(select.selectedIndex);
	document.getElementById("btn_savegkdata").style.display="inline";
};

document.getElementById("btn_savegkdata").onclick = function() {
	let blocklist = [];

	let opts = document.getElementById("gatekeeper_country").options;
	for (let i = 0; i < opts.length; i++) if (opts[i].selected) blocklist.push(opts[i].value);

	opts = document.getElementById("gatekeeper_domain").options;
	for (let i = 0; i < opts.length; i++) blocklist.push(opts[i].value);

	opts = document.getElementById("gatekeeper_addr").options;
	for (let i = 0; i < opts.length; i++) blocklist.push(opts[i].value);

	ae.SaveGatekeeperData(blocklist, function(success) {
		if (success) {
			console.log("Gatekeeper update succeeded");
			document.getElementById("btn_savegkdata").style.display="none";
		} else {
			console.log("Gatekeeper update failed;")
		}
	});
};

document.getElementById("btn_admin_addaccount").onclick = function() {
	txtPkey = document.getElementById("txt_newacc_pkey");
	btn = document.getElementById("btn_admin_addaccount");
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
	document.getElementById("div_readmsg").style.display="none";

	let b = document.getElementsByTagName("nav")[0].getElementsByTagName("button");
	let d = document.getElementsByClassName("maindiv");

	for (let i = 0; i < 5; i++) {
		if (i == num) {
			b[i].disabled="disabled";
			d[i].style.display="inline";
		} else {
			b[i].disabled="";
			d[i].style.display="none";
		}
	}
}

navMenu(0);

// Notes Menu
function navNotesMenu(num) {
	let b = document.getElementById("div_notes").getElementsByTagName("button");
	let d = document.getElementById("div_notes").getElementsByTagName("div");

	for (let i = 0; i < 4; i++) {
		if (i == num) {
			b[i].disabled="disabled";
			d[i].style.display="inline";
		} else {
			b[i].disabled="";
			d[i].style.display="none";
		}
	}
}

// Prefs menu
document.getElementById("btn_prefs_gatekeeper").onclick = function() {
	document.getElementById("btn_prefs_addresses").disabled="";
	document.getElementById("btn_prefs_gatekeeper").disabled="disabled";
	document.getElementById("div_prefs_gatekeeper").style.display="block";
	document.getElementById("div_prefs_addresses").style.display="none";

	document.getElementById("div_prefs_gatekeeper").style.width = getComputedStyle(document.getElementById("gatekeeper_country")).width;
};

document.getElementById("btn_prefs_addresses").onclick = function() {
	document.getElementById("btn_prefs_addresses").disabled="disabled";
	document.getElementById("btn_prefs_gatekeeper").disabled="";
	document.getElementById("div_prefs_gatekeeper").style.display="none";
	document.getElementById("div_prefs_addresses").style.display="inline";
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
	document.getElementById("btn_savegkdata").style.display="inline";
};
