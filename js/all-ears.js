// Server keypair for testing (base64 encoded):
// Public: zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=
// Secret: WEPFgMoessUEVWiXJ0RUX0EjpKVmN9nNBvWIKLO2+/4=

// Base64 encoded server public key for NaCl Box
const AllEars_serverPublicKey = b64ToBin("zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=");

var AllEars_userKeys;

function AEM_fetch(url, cb) {
	var r=new XMLHttpRequest();

	r.onreadystatechange=function(){
		if (r.readyState == 4 && typeof(cb) === "function") {
			cb(r.status, r.responseText);
		}
	}

	r.open("GET", url);
	r.send();
}

// Set user's keys from a Base64-encoded secret key
function AllEars_SetKeys(skey_b64) {
	AllEars_userKeys=nacl.box.keyPair.fromSecretKey(b64ToBin(skey_b64));
}

// Generates a new set of keys to use
function AllEars_NewKeys() {
	AllEars_userKeys=nacl.box.keyPair();
	return AllEars_userKeys;
}

function AllEars_Login() {
	const plaintext = new TextEncoder().encode("AllEars:Web.Login");
	var b64_key_public = btoa(String.fromCharCode.apply(null, AllEars_userKeys.publicKey));

	AEM_fetch("https://allears.test:60443/web/nonce/" + b64_key_public, function(httpStatus, b64_login_nonce) {
		if (httpStatus != 200) {
			console.log("Failed to get nonce from server");
			return;
		}

		var login_nonce = b64ToBin(b64_login_nonce);
		var box_login = nacl.box(plaintext, login_nonce, AllEars_serverPublicKey, AllEars_userKeys.secretKey);
		var b64_box_login = btoa(String.fromCharCode.apply(null, box_login));

		AEM_fetch("https://allears.test:60443/web/login/" + b64_key_public + "." + b64_box_login, function(httpStatus, response) {
			if (httpStatus == 200) {
				console.log("Login: Success");
			} else {
				console.log("Login: Failure");
			}
		});
	});
}
