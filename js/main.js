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
	ae.SetKeys(document.getElementById('txt_skey').value);
	ae.Login();
});
