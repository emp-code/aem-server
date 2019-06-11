ae=new AllEars();

document.getElementById("btn_genkeys").addEventListener("click", function(){
	console.log("Generating keys");
	var keys = ae.NewKeys();

	// Generate Base64 from keys
	var b64_key_public = btoa(String.fromCharCode.apply(null, keys.publicKey));
	var b64_key_secret = btoa(String.fromCharCode.apply(null, keys.secretKey));

	console.log("Public: " + b64_key_public);
	console.log("Secret: " + b64_key_secret);
});

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
}

// Called on a failed login
function allears_onLoginFailure() {
	console.log("Failed to log in");
}
