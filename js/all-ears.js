// Server keypair for testing (base64 encoded):
// Public: zUv7tx3dQU8vSq93dGOl6RSDv0N+6PDZbhOesYkx2zo=
// Secret: WEPFgMoessUEVWiXJ0RUX0EjpKVmN9nNBvWIKLO2+/4=

function AllEars() {
// Private
	const _serverPublicKey = b64ToBin("D00Yi5zQuaZ12UfTTu6N0RlSJzb0mP3BN91wzslJTVo="); // Seed: TestServer0123456789012345678901

	var _userSeed;

	var _userAddrNormal = [];
	var _userAddrShield = [];

	var _intMsg = [];

	function _NewIntMsg(sml, ts, from, to, title, body) {
		this.senderMemberLevel = sml;
		this.timestamp = ts;
		this.from = from;
		this.to = to;
		this.title = title;
		this.body = body;
	}

	var _Fetch = function(url, cb) {
		let r=new XMLHttpRequest();

		r.onreadystatechange=function(){
			if (r.readyState == 4 && typeof(cb) === "function") {
				cb(r.status, r.responseText);
			}
		}

		r.open("GET", url);
		r.send();
	}

	var _FetchBinary = function(url, cb) {
		let r=new XMLHttpRequest();
		r.responseType = "arraybuffer";

		r.onreadystatechange=function(){
			if (r.readyState == 4 && typeof(cb) === "function") {
				const arrayBuffer = r.response;
				if (arrayBuffer) {
					const byteArray = new Uint8Array(arrayBuffer);
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

		let decoded = "";

		for (let i = 0; i < 21; i++) {
			let num = 0;

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
	this.GetAddressNormal = function(num) {return _userAddrNormal[num];}
	this.GetAddressShield = function(num) {return _userAddrShield[num];}
	this.GetAddressCountNormal = function() {return _userAddrNormal.length;}
	this.GetAddressCountShield = function() {return _userAddrShield.length;}

	this.GetIntMsgCount = function() {return _intMsg.length;}
	this.GetIntMsgLevel = function(num) {return _intMsg[num].senderMemberLevel;}
	this.GetIntMsgTime  = function(num) {return _intMsg[num].timestamp;}
	this.GetIntMsgFrom  = function(num) {return _intMsg[num].from;}
	this.GetIntMsgTo    = function(num) {return _intMsg[num].to;}
	this.GetIntMsgTitle = function(num) {return _intMsg[num].title;}
	this.GetIntMsgBody  = function(num) {return _intMsg[num].body;}

	this.SetKeys = function(seed_b64) {
		_userSeed=b64ToBin(seed_b64);
	}

	this.RandomSeed = function() {
		// TODO
//		_userKeys=nacl.box.keyPair();
//		return _userKeys;
	}

	this.Login = function() { nacl_factory.instantiate(function (nacl) {
		const userKeys = nacl.crypto_box_seed_keypair(_userSeed);

		const b64_key_public = btoa(String.fromCharCode.apply(null, userKeys.boxPk));

		_FetchBinary("/web/nonce/" + b64_key_public, function(httpStatus, login_nonce) {
			if (httpStatus != 200) {allears_onLoginFailure(); return;}

			const plaintext = nacl.encode_utf8("AllEars:Web.Login");
			const box_login = nacl.crypto_box(plaintext, login_nonce, _serverPublicKey, userKeys.boxSk);

			const b64_box_login = btoa(String.fromCharCode.apply(null, box_login));

			_FetchBinary("/web/login/" + b64_key_public + "." + b64_box_login, function(httpStatus, byteArray) {
				if (httpStatus != 200) {allears_onLoginFailure(); return;}

				const addressCountNormal = byteArray[0];
				const addressCountShield = byteArray[1];
				const msgBoxCount = byteArray[2];

				// Empty the arrays
				while (_userAddrNormal.length > 0) _userAddrNormal.pop();
				while (_userAddrShield.length > 0) _userAddrShield.pop();

				for (let i = 0; i < addressCountNormal; i++) {
					_userAddrNormal[i] = _DecodeAddress(byteArray, 3 + (i * 16));
				}

				for (let i = 0; i < addressCountShield; i++) {
					_userAddrShield[i] = _DecodeAddress(byteArray, 3 + (addressCountNormal * 16) + (i * 16));
				}

				// Messages
				// TODO: Support multiple messages; detect type and support extMsg
				const msgStart = 3 + (addressCountNormal * 16) + (addressCountShield * 16);
				const msgKilos = byteArray[msgStart] + 1;

				// HeadBox
				const msgHeadBox = byteArray.slice(msgStart + 1, msgStart + 86); // 37 + 48
				const msgHead = nacl.crypto_box_seal_open(msgHeadBox, userKeys.boxPk, userKeys.boxSk);

				const im_sml = msgHead[0];

				const u32bytes = msgHead.slice(1, 5).buffer;
				const im_ts = new Uint32Array(u32bytes)[0];

				const im_from = _DecodeAddress(msgHead, 5);
				const im_to   = _DecodeAddress(msgHead, 21); // 5 + 16

				// BodyBox
				const msgBodyBox = byteArray.slice(msgStart + 86);
				const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, userKeys.boxPk, userKeys.boxSk);

				const u16bytes = msgBodyFull.slice(0, 2).buffer;
				const padAmount = new Uint16Array(u16bytes)[0];
				const msgBody = msgBodyFull.slice(2, msgBodyFull.length - padAmount);

				const msgBodyUtf8 = nacl.decode_utf8(msgBody);
				const firstLf = msgBodyUtf8.indexOf('\n');
				const im_title=msgBodyUtf8.slice(0, firstLf);
				const im_body=msgBodyUtf8.slice(firstLf + 1);

				_intMsg[0] = new _NewIntMsg(im_sml, im_ts, im_from, im_to, im_title, im_body);

				allears_onLoginSuccess();
			});
		});
	}); }
}
