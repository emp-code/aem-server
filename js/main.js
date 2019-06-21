ae=new AllEars();

document.getElementById("btn_signin").addEventListener("click", function(){
	// All-Ears needs to be provided with the user's secret key in order to log in
	ae.SetKeys(document.getElementById('txt_skey').value);

	ae.Login(function(success) {
		if (success) {
			loginSuccess();
		} else {
			console.log("Failed to log in");
		}
	});
});

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

	cellChk1.addEventListener("change", function() {document.getElementById("btn_saveaddrdata").style.display="inline";});
	cellChk2.addEventListener("change", function() {document.getElementById("btn_saveaddrdata").style.display="inline";});
	cellChk3.addEventListener("change", function() {document.getElementById("btn_saveaddrdata").style.display="inline";});
	cellChk4.addEventListener("change", function() {document.getElementById("btn_saveaddrdata").style.display="inline";});

	cellBtnD.innerHTML = "<button>&#128473;</button>";
	cellBtnD.addEventListener("click", function() {deleteAddress(cellAddr.textContent);});
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

function loginSuccess() {
	console.log("Logged in successfully. Our level: " + ae.GetUserLevel());

	document.getElementById("div_login").style.display="none";
	document.getElementById("div_loggedin").style.display="inline";

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

	// Messages
	for (let i = 0; i < ae.GetIntMsgCount(); i++) {
		const table = document.getElementById("tbody_inbox");

		let row = table.insertRow(-1);
		let cellTime  = row.insertCell(-1);
		let cellTitle = row.insertCell(-1);
		let cellFrom  = row.insertCell(-1);
		let cellTo    = row.insertCell(-1);

		cellTime.textContent = tsToISO8601(ae.GetIntMsgTime(i));
		cellTitle.textContent = ae.GetIntMsgTitle(i);
		cellFrom.textContent = ae.GetIntMsgFrom(i);
		cellTo.textContent = ae.GetIntMsgTo(i);
		cellFrom.className = ae.GetIntMsgShield(i) ? "mono" : "";

		row.addEventListener("click", function(){
			document.getElementById("btn_toinbox").disabled="";
			document.getElementById("btn_towrite").disabled="";
			document.getElementById("btn_tosettings").disabled="";

			document.getElementById("div_inbox").style.display="none";
			document.getElementById("div_write").style.display="none";
			document.getElementById("div_settings").style.display="none";
			document.getElementById("div_readmsg").style.display="inline";

			document.getElementById("readmsg_title").textContent = ae.GetIntMsgTitle(i);
			document.getElementById("readmsg_from").textContent = ae.GetIntMsgFrom(i);
			document.getElementById("readmsg_to").textContent = ae.GetIntMsgTo(i);
			document.getElementById("readmsg_body").textContent = ae.GetIntMsgBody(i);
			document.getElementById("readmsg_level").textContent = ae.GetIntMsgLevel(i);
			document.getElementById("readmsg_from").className = ae.GetIntMsgShield(i) ? "mono" : "";
		});
	}
}

document.getElementById("btn_send").addEventListener("click", function(){
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
});

document.getElementById("btn_newaddress").addEventListener("click", function(){
	if (ae.GetAddressCountNormal() >= ae.GetAddressLimitNormal()) {
		console.log("Address limit reached");
		return;
	}

	ae.AddAddress(document.getElementById("txt_newaddress").value, function(success) {
		if (success) {
			document.getElementById("addr_use_normal").textContent = ae.GetAddressCountNormal();
			addOptAddr(ae.GetAddressCount() - 1);
		} else {
			console.log("Failed to add address");
		}
	});
});

document.getElementById("btn_newshieldaddress").addEventListener("click", function(){
	if (ae.GetAddressCountShield() >= ae.GetAddressLimitShield()) {
		console.log("Shield address limit reached");
		return;
	}

	ae.AddShieldAddress(function(success) {
		if (success) {
			document.getElementById("addr_use_shield").textContent = ae.GetAddressCountShield();
			addOptAddr(ae.GetAddressCount() - 1);
		} else {
			console.log("Failed to add Shield address")
		}
	});
});

document.getElementById("btn_saveaddrdata").addEventListener("click", function(){
	let tbl = document.getElementById("tbody_opt_addr")

	for (let i = 0; i < tbl.rows.length; i++) {
		ae.SetAddressAcceptIntMsg(i, tbl.rows[i].cells[1].firstChild.checked);
		ae.SetAddressSharePk     (i, tbl.rows[i].cells[2].firstChild.checked);
		ae.SetAddressAcceptExtMsg(i, tbl.rows[i].cells[3].firstChild.checked);
		ae.SetAddressGatekeeper  (i, tbl.rows[i].cells[4].firstChild.checked);
	}

	ae.SaveAddressData(function(success) {
		if (success)
			console.log("Address data saved");
		else
			console.log("Address data failed to save");
	});

	document.getElementById("btn_saveaddrdata").style.display="none";
});

// Menu
document.getElementById("btn_toinbox").addEventListener("click", function(){
	document.getElementById("btn_toinbox").disabled="disabled";
	document.getElementById("btn_towrite").disabled="";
	document.getElementById("btn_tosettings").disabled="";

	document.getElementById("div_readmsg").style.display="none";
	document.getElementById("div_settings").style.display="none";
	document.getElementById("div_write").style.display="none";
	document.getElementById("div_inbox").style.display="inline";
});

document.getElementById("btn_towrite").addEventListener("click", function(){
	document.getElementById("btn_toinbox").disabled="";
	document.getElementById("btn_towrite").disabled="disabled";
	document.getElementById("btn_tosettings").disabled="";

	document.getElementById("div_readmsg").style.display="none";
	document.getElementById("div_inbox").style.display="none";
	document.getElementById("div_settings").style.display="none";
	document.getElementById("div_write").style.display="inline";
});

document.getElementById("btn_tosettings").addEventListener("click", function(){
	document.getElementById("btn_toinbox").disabled="";
	document.getElementById("btn_towrite").disabled="";
	document.getElementById("btn_tosettings").disabled="disabled";

	document.getElementById("div_readmsg").style.display="none";
	document.getElementById("div_inbox").style.display="none";
	document.getElementById("div_write").style.display="none";
	document.getElementById("div_settings").style.display="inline";
});
