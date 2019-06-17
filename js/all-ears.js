function AllEars() {
// Private
	const _serverPkHex = "0f4d188b9cd0b9a675d947d34eee8dd119522736f498fdc137dd70cec9494d5a"; // Server public key in hex

	var _userKeys;

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

	var _FetchBinary = function(url, postData, cb) {
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

		r.open("POST", url);
		r.send(postData);
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

	this.SetKeys = function(skey_hex) { nacl_factory.instantiate(function (nacl) {
		_userKeys=nacl.crypto_box_keypair_from_raw_sk(nacl.from_hex(skey_hex));
	}); }

	this.Login = function() { nacl_factory.instantiate(function (nacl) {
		_FetchBinary("/web/nonce", _userKeys.boxPk, function(httpStatus, login_nonce) {
			if (httpStatus != 200) {allears_onLoginFailure(); return;}

			const plaintext = nacl.encode_utf8("AllEars:Web.Login");
			const box_login = nacl.crypto_box(plaintext, login_nonce, nacl.from_hex(_serverPkHex), _userKeys.boxSk);

			let postMsg = new Uint8Array(_userKeys.boxPk.length + box_login.length);
			postMsg.set(_userKeys.boxPk);
			postMsg.set(box_login, _userKeys.boxPk.length);

			_FetchBinary("/web/login", postMsg, function(httpStatus, byteArray) {
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
					const start = 3 + (addressCountNormal * 16) + (i * 16);
					_userAddrShield[i] = nacl.to_hex(byteArray.slice(start, start + 16));
				}

				// Messages
				let msgStart = 3 + (addressCountNormal * 16) + (addressCountShield * 16);
				for (let i = 0; i < msgBoxCount; i++) {
					// TODO: Detect message type and support extMsg
					const msgKilos = byteArray[msgStart] + 1;

					// HeadBox
					const msgHeadBox = byteArray.slice(msgStart + 1, msgStart + 86); // 37 + 48
					const msgHead = nacl.crypto_box_seal_open(msgHeadBox, _userKeys.boxPk, _userKeys.boxSk);

					const im_sml = msgHead[0];

					const u32bytes = msgHead.slice(1, 5).buffer;
					const im_ts = new Uint32Array(u32bytes)[0];

					const im_from = _DecodeAddress(msgHead, 5);
					const im_to   = _DecodeAddress(msgHead, 21); // 5 + 16

					// BodyBox
					const bbSize = msgKilos * 1024 + 50;
					const bbStart = msgStart + 86;

					const msgBodyBox = byteArray.slice(bbStart, bbStart + bbSize);
					const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, _userKeys.boxPk, _userKeys.boxSk);

					const u16bytes = msgBodyFull.slice(0, 2).buffer;
					const padAmount = new Uint16Array(u16bytes)[0];
					const msgBody = msgBodyFull.slice(2, msgBodyFull.length - padAmount);

					const msgBodyUtf8 = nacl.decode_utf8(msgBody);
					const firstLf = msgBodyUtf8.indexOf('\n');
					const im_title=msgBodyUtf8.slice(0, firstLf);
					const im_body=msgBodyUtf8.slice(firstLf + 1);

					_intMsg[i] = new _NewIntMsg(im_sml, im_ts, im_from, im_to, im_title, im_body);
					msgStart += (msgKilos * 1024) + 136; // 48*2+37+2+1=136
				}

				allears_onLoginSuccess();
			});
		});
	}); }

	this.Send = function(msgFrom, msgTo, msgTitle, msgBody) { nacl_factory.instantiate(function (nacl) {
		_FetchBinary("/web/nonce", _userKeys.boxPk, function(httpStatus, nonce) {
			if (httpStatus != 200) {allears_onSendFailure(); return;}

			const plaintext = nacl.encode_utf8(msgFrom + '\n' + msgTo + '\n' + msgTitle + '\n' + msgBody);
			const boxSend = nacl.crypto_box(plaintext, nonce, nacl.from_hex(_serverPkHex), _userKeys.boxSk);

			let postMsg = new Uint8Array(_userKeys.boxPk.length + boxSend.length);
			postMsg.set(_userKeys.boxPk);
			postMsg.set(boxSend, _userKeys.boxPk.length);

			_FetchBinary("/web/send", postMsg, function(httpStatus, byteArray) {
				if (httpStatus == 204)
					allears_onSendSuccess();
				else
					allears_onSendFailure();

				return;
			});
		});
	}); }
}
