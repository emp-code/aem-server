ae=new AllEars();

document.getElementById("btn_signin").addEventListener("click", function(){
	// All-Ears needs to be provided with the user's secret key in order to log in
	ae.SetKeys(document.getElementById('txt_skey').value);

	ae.Login();

	// Continue in functions named allears_onLoginSuccess() and allears_onLoginFailure()
});

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

		cellTime.innerHTML = ae.GetIntMsgTime(i);
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
