ae=new AllEars();

document.getElementById("btn_signin").addEventListener("click", function(){
	// All-Ears needs to be provided with the user's secret key in order to log in
	ae.SetKeys(document.getElementById('txt_skey').value);

	ae.Login();

	// Continue in functions named allears_onLoginSuccess() and allears_onLoginFailure()
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
	if (ae.isAddressShield(num)) cellAddr.className="mono";

	cellChk1.innerHTML = ae.isAddressAcceptIntMsg(num) ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk2.innerHTML = ae.isAddressSharePk(num)      ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk3.innerHTML = ae.isAddressAcceptExtMsg(num) ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellChk4.innerHTML = ae.isAddressGatekeeper(num)   ? "<input type=\"checkbox\" checked=\"checked\">" : "<input type=\"checkbox\">";
	cellBtnD.innerHTML = "<button>&#128473;</button>";
}

// Called on a successful login
function allears_onLoginSuccess() {
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
		});
	}
}

// Called on a failed login
function allears_onLoginFailure() {
	console.log("Failed to log in");
}

document.getElementById("btn_send").addEventListener("click", function(){
	ae.Send(document.getElementById("send_from").value, document.getElementById("send_to").value, document.getElementById("send_title").value, document.getElementById("send_body").value);

	// Continue in functions named allears_onSendSuccess() and allears_onSendFailure()
});

function allears_onSendSuccess() {
	console.log("Message sent");
}

function allears_onSendFailure() {
	console.log("Failed to send message");
}

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
