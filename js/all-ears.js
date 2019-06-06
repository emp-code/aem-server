// Server keypair for testing (base64 encoded):
// Public: zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=
// Secret: WEPFgMoessUEVWiXJ0RUX0EjpKVmN9nNBvWIKLO2+/4=

function AllEars() {
// Private
	// Base64 encoded server public key for NaCl Box
	const _serverPublicKey = b64ToBin("zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=");

	var _userKeys;

	var _Fetch = function(url, cb) {
		var r=new XMLHttpRequest();

		r.onreadystatechange=function(){
			if (r.readyState == 4 && typeof(cb) === "function") {
				cb(r.status, r.responseText);
			}
		}

		r.open("GET", url);
		r.send();
	}

// Public
	this.SetKeys = function(skey_b64) {
		_userKeys=nacl.box.keyPair.fromSecretKey(b64ToBin(skey_b64));
	}

	this.NewKeys = function() {
		_userKeys=nacl.box.keyPair();
		return _userKeys;
	}

	this.Login = function() {
		var b64_key_public = btoa(String.fromCharCode.apply(null, _userKeys.publicKey));

		_Fetch("/web/nonce/" + b64_key_public, function(httpStatus, b64_login_nonce) {
			if (httpStatus != 200) {
				console.log("Failed to get nonce from server");
				return;
			}

			var login_nonce = b64ToBin(b64_login_nonce);
			const plaintext = new TextEncoder().encode("AllEars:Web.Login");
			var box_login = nacl.box(plaintext, login_nonce, _serverPublicKey, _userKeys.secretKey);

			var b64_box_login = btoa(String.fromCharCode.apply(null, box_login));

			_Fetch("/web/login/" + b64_key_public + "." + b64_box_login, function(httpStatus, response) {
				if (httpStatus == 200) {
					console.log("Login: Success");
				} else {
					console.log("Login: Failure");
				}
			});
		});
	}
}
