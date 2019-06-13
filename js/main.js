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

	console.log("User has " + ae.GetAddressCountNormal() + " normal addresses and " + ae.GetAddressCountShield() + " Shield addresses");

	console.log("Normal addresses:");
	for (var i = 0; i < ae.GetAddressCountNormal(); i++) {
		console.log(ae.GetAddressNormal(i) + "@allears.test");
	}

	console.log("Shield addresses:");
	for (var i = 0; i < ae.GetAddressCountNormal(); i++) {
		console.log(ae.GetAddressShield(i) + "@allears.test");
	}

	console.log("Internal Messages:");
	for (var i = 0; i < ae.GetIntMsgCount(); i++) {
		console.log("Message #" + i + ":");
		console.log("SenderMemberLevel=" + ae.GetIntMsgLevel(i));
		console.log("Time=" + ae.GetIntMsgTime(i));
		console.log("To=" + ae.GetIntMsgFrom(i));
		console.log("From=" + ae.GetIntMsgTo(i));
		console.log("Title=" + ae.GetIntMsgTitle(i));
		console.log("Body:");
		console.log(ae.GetIntMsgBody(i));
	}
}

// Called on a failed login
function allears_onLoginFailure() {
	console.log("Failed to log in");
}
