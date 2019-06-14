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

// Called on a successful login
function allears_onLoginSuccess() {
	console.log("Logged in successfully");

	document.getElementById("div_login").style.display="none";
	document.getElementById("div_loggedin").style.display="inline";

	console.log("User has " + ae.GetAddressCountNormal() + " normal addresses and " + ae.GetAddressCountShield() + " Shield addresses");

	console.log("Normal addresses:");
	for (var i = 0; i < ae.GetAddressCountNormal(); i++) {
		console.log(ae.GetAddressNormal(i) + "@allears.test");
	}

	console.log("Shield addresses:");
	for (var i = 0; i < ae.GetAddressCountNormal(); i++) {
		console.log(ae.GetAddressShield(i) + "@allears.test");
	}

	for (var i = 0; i < ae.GetIntMsgCount(); i++) {
		const table = document.getElementById("table_inbox");

		let row = table.insertRow(i + 1);
		let cellTime  = row.insertCell(0);
		let cellTitle = row.insertCell(1);
		let cellFrom  = row.insertCell(2);
		let cellTo    = row.insertCell(3);

		cellTime.innerHTML = tsToISO8601(ae.GetIntMsgTime(i));
		cellTitle.innerHTML = ae.GetIntMsgTitle(i);
		cellFrom.innerHTML = ae.GetIntMsgFrom(i);
		cellTo.innerHTML = ae.GetIntMsgTo(i);

		// Unused elements
//		ae.GetIntMsgLevel(i);
//		ae.GetIntMsgBody(i);
	}
}

// Called on a failed login
function allears_onLoginFailure() {
	console.log("Failed to log in");
}

document.getElementById("btn_send").addEventListener("click", function(){
	ae.Send("tester@allears.test||", document.getElementById("txt_to").value, document.getElementById("txt_title").value, document.getElementById("txt_body").value);

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

	document.getElementById("div_settings").style.display="none";
	document.getElementById("div_write").style.display="none";
	document.getElementById("div_inbox").style.display="inline";
});

document.getElementById("btn_towrite").addEventListener("click", function(){
	document.getElementById("btn_toinbox").disabled="";
	document.getElementById("btn_towrite").disabled="disabled";
	document.getElementById("btn_tosettings").disabled="";

	document.getElementById("div_inbox").style.display="none";
	document.getElementById("div_settings").style.display="none";
	document.getElementById("div_write").style.display="inline";
});

document.getElementById("btn_tosettings").addEventListener("click", function(){
	document.getElementById("btn_toinbox").disabled="";
	document.getElementById("btn_towrite").disabled="";
	document.getElementById("btn_tosettings").disabled="disabled";

	document.getElementById("div_inbox").style.display="none";
	document.getElementById("div_write").style.display="none";
	document.getElementById("div_settings").style.display="inline";
});
