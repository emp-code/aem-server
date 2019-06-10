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

	var _FetchBinary = function(url, cb) {
		var r=new XMLHttpRequest();
		r.responseType = "arraybuffer";

		r.onreadystatechange=function(){
			if (r.readyState == 4 && typeof(cb) === "function") {
				var arrayBuffer = r.response;
				if (arrayBuffer) {
					var byteArray = new Uint8Array(arrayBuffer);
					cb(r.status, byteArray);
				}
			}
		}

		r.open("GET", url);
		r.send();
	}

	var _BitTest = function(num, bit) {
		return ((num>>bit) % 2 != 0);
	}

	var _GetBit = function(byteArray, bitNum) {
		const skipBytes = Math.floor(bitNum / 8.0);
		const skipBits = bitNum % 8;

		return _BitTest(byteArray[skipBytes], skipBits);
	}

	// TODO make this a universal sixBitToText
	var _DecodeAddress = function(byteArray, start) {
		const sixBitTable = "0123456789abcdefghijklmnopqrstuvwxyz.-@???????????????????????|!";
		const skip = start * 8;

		var decoded = "";

		for (var i = 0; i < 21; i++) {
			var num = 0;

			if (_GetBit(byteArray, skip + i*6 + 0)) num +=  1;
			if (_GetBit(byteArray, skip + i*6 + 1)) num +=  2;
			if (_GetBit(byteArray, skip + i*6 + 2)) num +=  4;
			if (_GetBit(byteArray, skip + i*6 + 3)) num +=  8;
			if (_GetBit(byteArray, skip + i*6 + 4)) num += 16;
			if (_GetBit(byteArray, skip + i*6 + 5)) num += 32;

			decoded = decoded + sixBitTable[num];
		}

		return decoded;
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

		// TODO make this use binary directly instead of base64
		_Fetch("/web/nonce/" + b64_key_public, function(httpStatus, b64_login_nonce) {
			if (httpStatus != 200) {
				console.log("Failed to get nonce from server");
				return;
			}

			var login_nonce = b64ToBin(b64_login_nonce);
			const plaintext = new TextEncoder().encode("AllEars:Web.Login");
			var box_login = nacl.box(plaintext, login_nonce, _serverPublicKey, _userKeys.secretKey);

			var b64_box_login = btoa(String.fromCharCode.apply(null, box_login));

			_FetchBinary("/web/login/" + b64_key_public + "." + b64_box_login, function(httpStatus, byteArray) {
				if (httpStatus == 200) {
					console.log("Login: Success");

					var addressCountNormal = byteArray[0];
					var addressCountShield = byteArray[1];
					var msgBoxCount = byteArray[2];

					console.log("Received " + addressCountNormal + " normal addresses and " + addressCountShield + " Shield addresses; and " + msgBoxCount + " Message Boxes");

					console.log("Our normal addresses:");
					for (var i = 0; i < addressCountNormal; i++) {
						var addr = _DecodeAddress(byteArray, 3 + (i * 16));
						console.log(addr + "@allears.test");
					}

					console.log("Our Shield addresses:");
					for (var i = 0; i < addressCountShield; i++) {
						var addr = _DecodeAddress(byteArray, 3 + (addressCountNormal * 16) + (i * 16));
						console.log(addr + "@allears.test");
					}

					// TODO: Message Boxes
				} else {
					console.log("Login: Failure");
				}
			});
		});
	}
}
