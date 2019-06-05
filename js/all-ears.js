// Server keypair for testing (base64 encoded):
// Public: zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=
// Secret: WEPFgMoessUEVWiXJ0RUX0EjpKVmN9nNBvWIKLO2+/4=

// Base64 encoded server public key for NaCl Box
const AllEars_serverPublicKey = b64ToBin("zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=");

var AllEars_userKeys;

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
	//TODO: Get login nonce from server (24 bytes binary)
	var login_nonce_b64 = "1rE+qiwudzOo5HWHyff+0S6QgbjqekCP";
	var login_nonce = b64ToBin(login_nonce_b64);
	var plaintext = new TextEncoder().encode("AllEars:Web.Login");

	var box_login = nacl.box(plaintext, login_nonce, AllEars_serverPublicKey, AllEars_userKeys.secretKey);

	var b64_key_public = btoa(String.fromCharCode.apply(null, AllEars_userKeys.publicKey));
	var b64_box_login = btoa(String.fromCharCode.apply(null, box_login));

	r=new XMLHttpRequest();
	r.open("GET", "https://allears.test:60443/web/login/" + b64_key_public + "." + b64_box_login);
	r.send();
	r.onreadystatechange = function() {
		if (r.readyState == 4) {
			if (r.status == 200) {
				console.log("Login: Success");
			} else {
				console.log("Login: Failure");
			}
		}
	};
}
