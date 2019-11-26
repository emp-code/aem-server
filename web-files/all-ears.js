"use strict";

function AllEars(domain, readyCallback) {
	try {
		if (!window.isSecureContext
		|| window.self !== window.top
		|| document.compatMode == "BackCompat"
		|| document.characterSet !== "UTF-8"
		) return readyCallback(false);
	} catch(e) {return readyCallback(false);}

	if (!domain || typeof(domain) !== "string")
		domain = document.location.hostname;

	let _serverPk;

	fetch("https://" + domain + ":7850/api/pubkey", {
		method: "GET",
		cache: "no-store",
		credentials: "omit",
		redirect: "error",
		referrer: "no-referrer",
	}).then(function(response) {
		return response.ok ? response.arrayBuffer() : false;
	}).then(function(ab) {
		if (ab === false) return readyCallback(false);

		_serverPk = new Uint8Array(ab);
		return readyCallback((_serverPk.length === 32));
	});

// Private Variables
	const _lenPost = 8192; // 8 KiB
	const _lenNoteData_unsealed = 5122;
	const _lenNoteData = _lenNoteData_unsealed + 48;
	const _lenAdminData = 11264; // 11 KiB, space for 1024 users' data
	const _maxLevel = 3;

	const _maxStorage = [];
	const _maxAddressNormal = [];
	const _maxAddressShield = [];

	let _userKeys;

	let _userLevel = 0;
	const _userAddress = [];
	const _intMsg = [];
	const _extMsg = [];
	const _textNote = [];
	const _fileNote = [];

	const _gkCountry = [];
	const _gkDomain  = [];
	const _gkAddress = [];

	const _contactMail = [];
	const _contactName = [];
	const _contactNote = [];

	const _admin_userPkHex = [];
	const _admin_userSpace = [];
	const _admin_userNaddr = [];
	const _admin_userSaddr = [];
	const _admin_userLevel = [];

// Private Functions
	function _NewIntMsg(id, isSent, sml, ts, from, to, title, body) {
		this.id = id;
		this.isSent = isSent;
		this.senderMemberLevel = sml;
		this.ts = ts;
		this.from = from;
		this.to = to;
		this.title = title;
		this.body = body;
	}

	function _NewExtMsg(id, ts, ip, cs, tlsver, greet, infobyte, countrycode, from, to, title, headers, body) {
		this.id = id;
		this.ts = ts;
		this.ip = ip;
		this.cs = cs;
		this.tlsver = tlsver;
		this.greet = greet;
		this.info = infobyte;
		this.countrycode = countrycode;
		this.from = from;
		this.to = to;
		this.title = title;
		this.headers = headers;
		this.body = body;
	}

	function _NewTextNote(id, ts, title, body) {
		this.id = id;
		this.timestamp = ts;
		this.title = title;
		this.body = body;
	}

	function _NewFileNote(id, ts, fileData, fileSize, fileName, fileType) {
		this.id = id;
		this.timestamp = ts;
		this.fileData = fileData;
		this.fileSize = fileSize;
		this.fileName = fileName;
		this.fileType = fileType;
	}

	function _NewAddress(addr, hash, decoded, accInt, spk, accExt, gk) {
		this.address = addr;
		this.hash = hash;
		this.decoded = decoded;
		this.acceptIntMsg = accInt;
		this.sharePk = spk;
		this.acceptExtMsg = accExt;
		this.useGatekeeper = gk;
	}

	const _FetchBinary = function(url, postData, callback) {
		fetch(url, {
			method: "POST",
			cache: "no-store",
			credentials: "omit",
			redirect: "error",
			referrer: "no-referrer",
			body: postData
		}).then(function(response) {
			return response.ok ? response.arrayBuffer() : false;
		}).then(function(ab) {
			if (ab === false) {callback(false); return;}
			callback(true, new Uint8Array(ab));
		}).catch(() => {
			callback(false);
		});
	};

	const _FetchEncrypted = function(url, cleartext, nacl, callback) {
		if (cleartext.length > _lenPost - 2) {callback(false); return;}

		// Cleartext is padded to _lenPost bytes
		const clearU8 = new Uint8Array(_lenPost);
		window.crypto.getRandomValues(clearU8);
		clearU8.set(cleartext);

		// Last two bytes store the length
		const u16len = new Uint16Array([cleartext.length]);
		const u8len = new Uint8Array(u16len.buffer);
		clearU8.set(u8len, _lenPost - 2);

		const nonce = nacl.crypto_box_random_nonce();

		// postBox: the encrypted data to be sent
		const postBox = nacl.crypto_box(clearU8, nonce, _serverPk, _userKeys.boxSk);

		// postMsg: Nonce + User Public Key + postBox
		const postMsg = new Uint8Array(24 + _userKeys.boxPk.length + postBox.length);
		postMsg.set(nonce);
		postMsg.set(_userKeys.boxPk, 24);
		postMsg.set(postBox, 24 + _userKeys.boxPk.length);

		_FetchBinary("https://" + domain + ":7850/api/" + url, postMsg, callback);
	};

	const _GetBit = function(src, bitNum) {
		const bit = bitNum % 8;
		const byte = (bitNum - bit) / 8;

		return ((1 & (src[byte] >> (7 - bit))) === 1);
	}

	const _DecodeShieldAddress = function(byteArray) {
		const shld32_chars = "567890abcdefghijklmnopqrstuvwxyz";

		let decoded = "";

		for (let i = 0; i < 24; i++) {
			let num = 0;
			const skipBits = i * 5;

			if (_GetBit(byteArray, skipBits + 0)) num += 16;
			if (_GetBit(byteArray, skipBits + 1)) num +=  8;
			if (_GetBit(byteArray, skipBits + 2)) num +=  4;
			if (_GetBit(byteArray, skipBits + 3)) num +=  2;
			if (_GetBit(byteArray, skipBits + 4)) num +=  1;

			decoded += shld32_chars[num];
		}

		return decoded;
	};

	const _DecodeAddress = function(byteArray) {
		if (byteArray.length != 15) return "(Error: wrong length)";

		const addr32_chars = "#0123456789abcdefghkmnpqrstuwxyz";

		let decoded = "";

		for (let i = 0; i < 24; i++) {
			let num = 0;
			const skipBits = i * 5;

			if (_GetBit(byteArray, skipBits + 0)) num += 16;
			if (_GetBit(byteArray, skipBits + 1)) num +=  8;
			if (_GetBit(byteArray, skipBits + 2)) num +=  4;
			if (_GetBit(byteArray, skipBits + 3)) num +=  2;
			if (_GetBit(byteArray, skipBits + 4)) num +=  1;

			if (addr32_chars[num] === '#') {
				return (i === 0) ? _DecodeShieldAddress(byteArray) : decoded;
			}

			decoded += addr32_chars[num];
		}

		return decoded;
	};

	const _GetAddressCount = function(isShield) {
		let count = 0;

		for (let i = 0; i < _userAddress.length; i++) {
			if (isShield && _userAddress[i].decoded.length === 24 && _userAddress[i].decoded[0] === '5') count++;
			else if (!isShield && (_userAddress[i].decoded.length < 24 || _userAddress[i].decoded[0] !== '5')) count++;
		}

		return count;
	};

	const _MakeAddrData = function() {
		const addrData = new Uint8Array(_userAddress.length * 24);

		for (let i = 0; i < _userAddress.length; i++) {
			const pos = i * 24;
			addrData[pos] = 0;

			if (_userAddress[i].useGatekeeper) addrData[pos] |= 2;
			if (_userAddress[i].acceptIntMsg)  addrData[pos] |= 4;
			if (_userAddress[i].acceptExtMsg)  addrData[pos] |= 8;
			if (_userAddress[i].sharePk)       addrData[pos] |= 16;

			addrData.set(_userAddress[i].address, pos + 1);
			addrData.set(_userAddress[i].hash, pos + 16);
		}

		return addrData;
	};

	const _MakeAddrData_Server = function() {
		const addrData = new Uint8Array(_userAddress.length * 9);

		for (let i = 0; i < _userAddress.length; i++) {
			const pos = i * 9;
			addrData[pos] = 0;

			if (_userAddress[i].useGatekeeper) addrData[pos] |= 2;
			if (_userAddress[i].acceptIntMsg)  addrData[pos] |= 4;
			if (_userAddress[i].acceptExtMsg)  addrData[pos] |= 8;
			if (_userAddress[i].sharePk)       addrData[pos] |= 16;

			addrData.set(_userAddress[i].hash, pos + 1);
		}

		return addrData;
	};

	const _IsOwnAddress = function(addr) {
		for (let i = 0; i < _userAddress.length; i++) {
			let isOwn = true;

			for (let j = 0; j < 15; j++) {
				if (addr[j] != _userAddress[i].address[j]) {
					isOwn = false;
					break;
				}
			}

			if (isOwn) return true;
		}

		return false;
	};

	const _GetCiphersuite = function(cs) {
		if (typeof(cs) !== "number") return "(Error reading ciphersuite value)";

		switch(cs) {
			case 0: return "";
			case 1: return "(Error saving ciphersuite value)";
			case 0x67:   return "DHE_RSA_WITH_AES_128_CBC_SHA256";
			case 0xC09E: return "DHE_RSA_WITH_AES_128_CCM";
			case 0xC0A2: return "DHE_RSA_WITH_AES_128_CCM_8";
			case 0x9E:   return "DHE_RSA_WITH_AES_128_GCM_SHA256";
			case 0x6B:   return "DHE_RSA_WITH_AES_256_CBC_SHA256";
			case 0xC09F: return "DHE_RSA_WITH_AES_256_CCM";
			case 0xC0A3: return "DHE_RSA_WITH_AES_256_CCM_8";
			case 0x9F:   return "DHE_RSA_WITH_AES_256_GCM_SHA384";
			case 0xC044: return "DHE_RSA_WITH_ARIA_128_CBC_SHA256";
			case 0xC052: return "DHE_RSA_WITH_ARIA_128_GCM_SHA256";
			case 0xC045: return "DHE_RSA_WITH_ARIA_256_CBC_SHA384";
			case 0xC053: return "DHE_RSA_WITH_ARIA_256_GCM_SHA384";
			case 0xBE:   return "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
			case 0xC07C: return "DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
			case 0xC4:   return "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
			case 0xC07D: return "DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
			case 0xCCAA: return "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
			case 0xC023: return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
			case 0xC0AC: return "ECDHE_ECDSA_WITH_AES_128_CCM";
			case 0xC0AE: return "ECDHE_ECDSA_WITH_AES_128_CCM_8";
			case 0xC02B: return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
			case 0xC024: return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
			case 0xC0AD: return "ECDHE_ECDSA_WITH_AES_256_CCM";
			case 0xC0AF: return "ECDHE_ECDSA_WITH_AES_256_CCM_8";
			case 0xC02C: return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
			case 0xC048: return "ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256";
			case 0xC05C: return "ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256";
			case 0xC049: return "ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384";
			case 0xC05D: return "ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384";
			case 0xC072: return "ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
			case 0xC086: return "ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
			case 0xC073: return "ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
			case 0xC087: return "ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
			case 0xCCA9: return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
			case 0xC027: return "ECDHE_RSA_WITH_AES_128_CBC_SHA256";
			case 0xC02F: return "ECDHE_RSA_WITH_AES_128_GCM_SHA256";
			case 0xC028: return "ECDHE_RSA_WITH_AES_256_CBC_SHA384";
			case 0xC030: return "ECDHE_RSA_WITH_AES_256_GCM_SHA384";
			case 0xC04C: return "ECDHE_RSA_WITH_ARIA_128_CBC_SHA256";
			case 0xC060: return "ECDHE_RSA_WITH_ARIA_128_GCM_SHA256";
			case 0xC04D: return "ECDHE_RSA_WITH_ARIA_256_CBC_SHA384";
			case 0xC061: return "ECDHE_RSA_WITH_ARIA_256_GCM_SHA384";
			case 0xC076: return "ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
			case 0xC08A: return "ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256";
			case 0xC077: return "ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
			case 0xC08B: return "ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384";
			case 0xCCA8: return "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
			case 0xC025: return "ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
			case 0xC02D: return "ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
			case 0xC026: return "ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
			case 0xC02E: return "ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
			case 0xC04A: return "ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256";
			case 0xC05E: return "ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
			case 0xC04B: return "ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384";
			case 0xC05F: return "ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
			case 0xC074: return "ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
			case 0xC088: return "ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
			case 0xC075: return "ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
			case 0xC089: return "ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
			case 0xC029: return "ECDH_RSA_WITH_AES_128_CBC_SHA256";
			case 0xC031: return "ECDH_RSA_WITH_AES_128_GCM_SHA256";
			case 0xC02A: return "ECDH_RSA_WITH_AES_256_CBC_SHA384";
			case 0xC032: return "ECDH_RSA_WITH_AES_256_GCM_SHA384";
			case 0xC04E: return "ECDH_RSA_WITH_ARIA_128_CBC_SHA256";
			case 0xC062: return "ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
			case 0xC04F: return "ECDH_RSA_WITH_ARIA_256_CBC_SHA384";
			case 0xC063: return "ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
			case 0xC078: return "ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
			case 0xC08C: return "ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
			case 0xC079: return "ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
			case 0xC08D: return "ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
			case 0x3C:   return "RSA_WITH_AES_128_CBC_SHA256";
			case 0xC09C: return "RSA_WITH_AES_128_CCM";
			case 0xC0A0: return "RSA_WITH_AES_128_CCM_8";
			case 0x9C:   return "RSA_WITH_AES_128_GCM_SHA256";
			case 0x3D:   return "RSA_WITH_AES_256_CBC_SHA256";
			case 0xC09D: return "RSA_WITH_AES_256_CCM";
			case 0xC0A1: return "RSA_WITH_AES_256_CCM_8";
			case 0x9D:   return "RSA_WITH_AES_256_GCM_SHA384";
			case 0xC03C: return "RSA_WITH_ARIA_128_CBC_SHA256";
			case 0xC050: return "RSA_WITH_ARIA_128_GCM_SHA256";
			case 0xC03D: return "RSA_WITH_ARIA_256_CBC_SHA384";
			case 0xC051: return "RSA_WITH_ARIA_256_GCM_SHA384";
			case 0xBA:   return "RSA_WITH_CAMELLIA_128_CBC_SHA256";
			case 0xC07A: return "RSA_WITH_CAMELLIA_128_GCM_SHA256";
			case 0xC0:   return "RSA_WITH_CAMELLIA_256_CBC_SHA256";
			case 0xC07B: return "RSA_WITH_CAMELLIA_256_GCM_SHA384";
			case 0xC00A: return "ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
			case 0x39:   return "DHE_RSA_WITH_AES_256_CBC_SHA";
			case 0xC014: return "ECDHE_RSA_WITH_AES_256_CBC_SHA";
			case 0x88:   return "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
			case 0xC009: return "ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
			case 0xC013: return "ECDHE_RSA_WITH_AES_128_CBC_SHA";
			case 0x33:   return "DHE_RSA_WITH_AES_128_CBC_SHA";
			case 0x45:   return "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
			case 0xC005: return "ECDH_ECDSA_WITH_AES_256_CBC_SHA";
			case 0xC00F: return "ECDH_RSA_WITH_AES_256_CBC_SHA";
			case 0xC004: return "ECDH_ECDSA_WITH_AES_128_CBC_SHA";
			case 0xC00E: return "ECDH_RSA_WITH_AES_128_CBC_SHA";
			case 0x35:   return "RSA_WITH_AES_256_CBC_SHA";
			case 0x84:   return "RSA_WITH_CAMELLIA_256_CBC_SHA";
			case 0x2F:   return "RSA_WITH_AES_128_CBC_SHA";
			case 0x41:   return "RSA_WITH_CAMELLIA_128_CBC_SHA";
			case 0xC007: return "ECDHE_ECDSA_WITH_RC4_128_SHA";
			case 0xC011: return "ECDHE_RSA_WITH_RC4_128_SHA";
			case 0xC008: return "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
			case 0xC012: return "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
			case 0x16:   return "DHE_RSA_WITH_3DES_EDE_CBC_SHA";
			case 0xC002: return "ECDH_ECDSA_WITH_RC4_128_SHA";
			case 0xC00C: return "ECDH_RSA_WITH_RC4_128_SHA";
			case 0xC003: return "ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
			case 0xC00D: return "ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
			case 0x0A:   return "RSA_WITH_3DES_EDE_CBC_SHA";
			case 0x05:   return "RSA_WITH_RC4_128_SHA";
			case 0x04:   return "RSA_WITH_RC4_128_MD5";
			default: return "(Unknown ciphersuite value: " + cs + ")";
		}
	};

	const _GetTlsVersion = function(tlsver) {
		switch (tlsver) {
			case 0: return "(No TLS)";
			case 1: return "TLSv1.0";
			case 2: return "TLSv1.1";
			case 3: return "TLSv1.2";
			case 4: return "TLSv1.3";
		}
	};

// Public
	this.Reset = function() {
		_maxStorage.splice(0);
		_maxAddressNormal.splice(0);
		_maxAddressShield.splice(0);
		_userLevel = 0;
		_userAddress.splice(0);
		_intMsg.splice(0);
		_extMsg.splice(0);
		_textNote.splice(0);
		_fileNote.splice(0);

		_gkCountry.splice(0);
		_gkDomain .splice(0);
		_gkAddress.splice(0);

		_contactMail.splice(0);
		_contactName.splice(0);
		_contactNote.splice(0);

		_admin_userPkHex.splice(0);
		_admin_userSpace.splice(0);
		_admin_userNaddr.splice(0);
		_admin_userSaddr.splice(0);
		_admin_userLevel.splice(0);
	}

	this.GetLevelMax = function() {return _maxLevel;};

	this.GetAddress = function(num) {return _userAddress[num].decoded;};
	this.IsAddressAcceptIntMsg = function(num) {return _userAddress[num].acceptIntMsg;};
	this.IsAddressAcceptExtMsg = function(num) {return _userAddress[num].acceptExtMsg;};
	this.IsAddressSharePk      = function(num) {return _userAddress[num].sharePk;};
	this.IsAddressGatekeeper   = function(num) {return _userAddress[num].useGatekeeper;};

	this.SetAddressAcceptIntMsg = function(num, val) {_userAddress[num].acceptIntMsg = val;};
	this.SetAddressAcceptExtMsg = function(num, val) {_userAddress[num].acceptExtMsg = val;};
	this.SetAddressSharePk      = function(num, val) {_userAddress[num].sharePk = val;};
	this.SetAddressGatekeeper   = function(num, val) {_userAddress[num].useGatekeeper = val;};

	this.GetAddressCount = function() {return _userAddress.length;};
	this.GetAddressCountNormal = function() {return _GetAddressCount(false);};
	this.GetAddressCountShield = function() {return _GetAddressCount(true);};

	this.IsUserAdmin = function() {return (_userLevel === _maxLevel);};
	this.GetUserLevel = function() {return _userLevel;};
	this.GetStorageLimit = function(lvl) {return _maxStorage[lvl];};
	this.GetAddressLimitNormal = function(lvl) {return _maxAddressNormal[lvl];};
	this.GetAddressLimitShield = function(lvl) {return _maxAddressShield[lvl];};

	this.GetIntMsgCount = function() {return _intMsg.length;};
	this.GetIntMsgId     = function(num) {return _intMsg[num].id;};
	this.GetIntMsgLevel  = function(num) {return _intMsg[num].senderMemberLevel;};
	this.GetIntMsgTime   = function(num) {return _intMsg[num].ts;};
	this.GetIntMsgFrom   = function(num) {return _intMsg[num].from;};
	this.GetIntMsgIsSent = function(num) {return _intMsg[num].isSent;};
	this.GetIntMsgTo     = function(num) {return _intMsg[num].to;};
	this.GetIntMsgTitle  = function(num) {return _intMsg[num].title;};
	this.GetIntMsgBody   = function(num) {return _intMsg[num].body;};

	this.GetExtMsgCount = function() {return _extMsg.length;};
	this.GetExtMsgId      = function(num) {return _extMsg[num].id;};
	this.GetExtMsgTime    = function(num) {return _extMsg[num].ts;};
	this.GetExtMsgTLS     = function(num) {return _GetTlsVersion(_extMsg[num].tlsver) + " " + _GetCiphersuite(_extMsg[num].cs);};
	this.GetExtMsgGreet   = function(num) {return _extMsg[num].greet;};
	this.GetExtMsgIp      = function(num) {return "" + _extMsg[num].ip[0] + "." + _extMsg[num].ip[1] + "." + _extMsg[num].ip[2] + "." + _extMsg[num].ip[3];};
	this.GetExtMsgCountry = function(num) {return _extMsg[num].countrycode;};
	this.GetExtMsgFrom    = function(num) {return _extMsg[num].from;};
	this.GetExtMsgTo      = function(num) {return _extMsg[num].to;};
	this.GetExtMsgTitle   = function(num) {return _extMsg[num].title;};
	this.GetExtMsgHeaders = function(num) {return _extMsg[num].headers;};
	this.GetExtMsgBody    = function(num) {return _extMsg[num].body;};

	this.GetExtMsgFlagPErr = function(num) {return _extMsg[num].info &   8;}; // Protocol Error
	this.GetExtMsgFlagFail = function(num) {return _extMsg[num].info &  16;}; // Invalid command used
	this.GetExtMsgFlagRare = function(num) {return _extMsg[num].info &  32;}; // Rare/unusual command used
	this.GetExtMsgFlagQuit = function(num) {return _extMsg[num].info &  64;}; // QUIT command issued
	this.GetExtMsgFlagPExt = function(num) {return _extMsg[num].info & 128;}; // Protocol Extended (ESMTP)

	this.GetNoteCount = function() {return _textNote.length;};
	this.GetNoteId = function(num) {return _textNote[num].id;};
	this.GetNoteTime = function(num) {return _textNote[num].timestamp;};
	this.GetNoteTitle = function(num) {return _textNote[num].title;};
	this.GetNoteBody = function(num) {return _textNote[num].body;};

	this.GetFileCount = function() {return _fileNote.length;};
	this.GetFileId   = function(num) {return _fileNote[num].id;};
	this.GetFileTime = function(num) {return _fileNote[num].timestamp;};
	this.GetFileName = function(num) {return _fileNote[num].fileName;};
	this.GetFileType = function(num) {return _fileNote[num].fileType;};
	this.GetFileSize = function(num) {return _fileNote[num].fileSize;};
	this.GetFileBlob = function(num) {return new Blob([_fileNote[num].fileData.buffer], {type : _fileNote[num].fileType});};

	this.GetGatekeeperCountry = function() {return _gkCountry;};
	this.GetGatekeeperDomain  = function() {return _gkDomain;};
	this.GetGatekeeperAddress = function() {return _gkAddress;};

	this.Admin_GetUserCount = function() {return _admin_userPkHex.length;};
	this.Admin_GetUserPkHex = function(num) {return _admin_userPkHex[num];};
	this.Admin_GetUserSpace = function(num) {return _admin_userSpace[num];};
	this.Admin_GetUserNAddr = function(num) {return _admin_userNaddr[num];};
	this.Admin_GetUserSAddr = function(num) {return _admin_userSaddr[num];};
	this.Admin_GetUserLevel = function(num) {return _admin_userLevel[num];};

	this.GetContactCount = function() {return _contactMail.length;};
	this.GetContactMail = function(num) {return _contactMail[num];};
	this.GetContactName = function(num) {return _contactName[num];};
	this.GetContactNote = function(num) {return _contactNote[num];};
	this.AddContact = function(mail, name, note) {
		_contactMail.push(mail);
		_contactName.push(name);
		_contactNote.push(note);
	};
	this.DeleteContact = function(index) {
		_contactMail.splice(index, 1);
		_contactName.splice(index, 1);
		_contactNote.splice(index, 1);
	};

	this.SetKeys = function(skey_hex, callback) { nacl_factory.instantiate(function (nacl) {
		if (typeof(skey_hex) !== "string" || skey_hex.length !== 64) {
			_userKeys = null;
			callback(false);
			return;
		}

		_userKeys = nacl.crypto_box_keypair_from_raw_sk(nacl.from_hex(skey_hex));
		callback(true);
	}); };

	this.Browse = function(page, callback) { nacl_factory.instantiate(function (nacl) {
		if (typeof(page) !== "number" || page < 0 || page > 255) {callback(false); return;}

		_FetchEncrypted("account/browse", new Uint8Array([page]), nacl, function(fetchOk, loginData) {
			if (!fetchOk) {callback(false); return;}

			for (let i = 0; i < 4; i++) {
				_maxStorage.push(loginData[(i * 3) + 0]);
				_maxAddressNormal.push(loginData[(i * 3) + 1]);
				_maxAddressShield.push(loginData[(i * 3) + 2]);
			}

			_userLevel = loginData[12];
			const msgCount = loginData[13];
			const addrDataSize = new Uint16Array(loginData.slice(14, 16).buffer)[0];
			const gkDataSize   = new Uint16Array(loginData.slice(16, 18).buffer)[0];

			// Note Data
			const noteDataStart = 18;
			const noteData = nacl.crypto_box_seal_open(loginData.slice(noteDataStart, noteDataStart + _lenNoteData), _userKeys.boxPk, _userKeys.boxSk);
			const noteDataSize = new Uint16Array(noteData.slice(0, 2).buffer)[0];

			const contactSet = new TextDecoder("utf-8").decode(noteData.slice(2)).split('\n');
			for (let i = 0; i < (contactSet.length - 1); i += 3) {
				_contactMail.push(contactSet[i]);
				_contactName.push(contactSet[i + 1]);
				_contactNote.push(contactSet[i + 2]);
			}

			// Address data
			const addrDataStart = 18 + _lenNoteData;
			const addrData = nacl.crypto_box_seal_open(loginData.slice(addrDataStart, addrDataStart + addrDataSize), _userKeys.boxPk, _userKeys.boxSk);

			for (let i = 0; i < (addrData.length / 24); i++) {
				const start = i * 24;
				const useGatekeeper = addrData[start] & 2;
				const acceptIntMsg  = addrData[start] & 4;
				const acceptExtMsg  = addrData[start] & 8;
				const sharePk       = addrData[start] & 16;
				const addr = addrData.slice(start + 1, start + 16);
				const hash = addrData.slice(start + 16, start + 24);
				const decoded = _DecodeAddress(addr);

				_userAddress.push(new _NewAddress(addr, hash, decoded, acceptIntMsg, sharePk, acceptExtMsg, useGatekeeper));
			}

			// Gatekeeper data
			const gkDataStart = 18 + _lenNoteData + addrDataSize;
			const gkData = new TextDecoder("utf-8").decode(nacl.crypto_box_seal_open(loginData.slice(gkDataStart, gkDataStart + gkDataSize), _userKeys.boxPk, _userKeys.boxSk));
			const gkSet = gkData.split('\n');
			let gkCountCountry = 0;
			let gkCountDomain = 0;
			let gkCountAddress = 0;

			for (let i = 0; i < gkSet.length; i++) {
				if (gkSet[i].indexOf('@') != -1) {
					_gkAddress[gkCountAddress] = gkSet[i];
					gkCountAddress++;
				} else if (gkSet[i].indexOf('.') != -1) {
					_gkDomain[gkCountDomain] = gkSet[i];
					gkCountDomain++;
				} else {
					_gkCountry[gkCountCountry] = gkSet[i];
					gkCountCountry++;
				}
			}

			// Admin data
			const lenAdmin = (_userLevel === _maxLevel) ? _lenAdminData : 0;
			if (_userLevel === _maxLevel) {
				const adminDataStart = 18 + _lenNoteData + addrDataSize + gkDataSize;

				for (let i = 0; i < (_lenAdminData / 11); i++) {
					const pos = (adminDataStart + i * 11);
					const newPk = loginData.slice(pos, pos + 8);

					if (newPk[0] == 0 && newPk[1] == 0 && newPk[2] == 0 && newPk[3] == 0
					&& newPk[4] == 0 && newPk[5] == 0 && newPk[6] == 0 && newPk[7] == 0) break;

					const newLevel = loginData[pos + 8] & 3;
					const newSpace = loginData[pos + 8] >>> 2;
					const newNaddr = loginData[pos + 9];
					const newSaddr = loginData[pos + 10];

					_admin_userPkHex.push(nacl.to_hex(newPk));
					_admin_userSpace.push(newSpace);
					_admin_userNaddr.push(newNaddr);
					_admin_userSaddr.push(newSaddr);
					_admin_userLevel.push(newLevel);
				}
			}

			// Message data
			let msgStart = 18 + _lenNoteData + addrDataSize + gkDataSize + lenAdmin;
			for (let i = 0; i < msgCount; i++) {
				const msgId = loginData[msgStart];
				const msgKilos = loginData[msgStart + 1] + 1;

				// HeadBox
				const msgHeadBox = loginData.slice(msgStart + 2, msgStart + 85); // 85 = 2 + 35 + crypto_box_SEALBYTES (48)
				const msgHead = nacl.crypto_box_seal_open(msgHeadBox, _userKeys.boxPk, _userKeys.boxSk);

				// BodyBox
				const lenBody = msgKilos * 1024;
				const bbStart = msgStart + 85;
				const msgBodyBox = loginData.slice(bbStart, bbStart + lenBody + 50); // 50 = 2 + crypto_box_SEALBYTES (48)
				const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, _userKeys.boxPk, _userKeys.boxSk);
				const padAmount = new Uint16Array(msgBodyFull.slice(lenBody, lenBody + 2).buffer)[0];
				const msgBody = msgBodyFull.slice(0, lenBody - padAmount);

				if ((msgHead[0] & 3) === 3) { // xxxxxx11 FileNote
					const note_ts = new Uint32Array(msgHead.slice(1, 5).buffer)[0];
					const lenFn = msgBody[0];
					const fileName = new TextDecoder("utf-8").decode(msgBody.slice(1, 1 + lenFn));
					const lenFt = msgBody[1 + lenFn];
					const fileType = new TextDecoder("utf-8").decode(msgBody.slice(2 + lenFn, 2 + lenFn + lenFt));
					const fileData = msgBody.slice(2 + lenFn + lenFt);

					_fileNote.push(new _NewFileNote(msgId, note_ts, fileData, fileData.length, fileName, fileType));
				} else if ((msgHead[0] & 2) === 2) { // xxxxxx10 TextNote
					const note_ts = new Uint32Array(msgHead.slice(1, 5).buffer)[0];
					const msgBodyUtf8 = new TextDecoder("utf-8").decode(msgBody);

					const ln = msgBodyUtf8.indexOf('\n');
					if (ln > 0)
						_textNote.push(new _NewTextNote(msgId, note_ts, msgBodyUtf8.substr(0, ln), msgBodyUtf8.substr(ln + 1)));
					else
						console.log("Received corrupted TextNote");
				} else if ((msgHead[0] & 1) === 1) { // xxxxxx01 ExtMsg
					const em_infobyte = msgHead[0];
					const em_ts = new Uint32Array(msgHead.slice(1, 5).buffer)[0];
					const em_ip = msgHead.slice(5, 9);
					const em_cs = new Uint16Array(msgHead.slice(9, 11).buffer)[0];
					const em_tlsver = msgHead[11];
					// msgHead[12] = SpamByte
					const em_countrycode = new TextDecoder("utf-8").decode(msgHead.slice(13, 15));
					// 16-19 unused
					const em_to = _DecodeAddress(msgHead.slice(20));

					// Bodybox
					const msgBodyBrI8 = new Int8Array(msgBody);
					const msgBodyText = new Uint8Array(window.BrotliDecode(msgBodyBrI8));
					const msgBodyUtf8 = new TextDecoder("utf-8").decode(msgBodyText);

					const firstLf = msgBodyUtf8.indexOf('\n');
					const em_greet = msgBodyUtf8.slice(0, firstLf);
					const secondLf = msgBodyUtf8.slice(firstLf + 1).indexOf('\n') + firstLf + 1;
					const em_from = msgBodyUtf8.slice(firstLf + 1, secondLf);
					const body = msgBodyUtf8.slice(secondLf + 1);

					const titleStart = body.indexOf("\nSubject: ");
					const titleEnd = (titleStart < 1) ? -1 : body.slice(titleStart + 10).indexOf("\n");
					const em_title = (titleStart < 1) ? "(Missing title)" : body.substr(titleStart + 10, titleEnd);

					const headersEnd = body.indexOf("\r\n\r\n");
					const em_headers = body.slice(0, headersEnd);
					const em_body = body.slice(headersEnd + 4);

					_extMsg.push(new _NewExtMsg(msgId, em_ts, em_ip, em_cs, em_tlsver, em_greet, em_infobyte, em_countrycode, em_from, em_to, em_title, em_headers, em_body));
				} else { // xxxxxx00 IntMsg
					const im_sml = (msgHead[0] >>> 4) & 3;
					const im_ts = new Uint32Array(msgHead.slice(1, 5).buffer)[0];
					const im_from_bin = msgHead.slice(5, 20);
					const im_from = _DecodeAddress(im_from_bin);
					const im_isSent = _IsOwnAddress(im_from_bin);
					const im_to = _DecodeAddress(msgHead.slice(20));

					// BodyBox
					const msgBodyUtf8 = new TextDecoder("utf-8").decode(msgBody);
					const firstLf = msgBodyUtf8.indexOf('\n');
					const im_title = msgBodyUtf8.slice(0, firstLf);
					const im_body = msgBodyUtf8.slice(firstLf + 1);

					_intMsg.push(new _NewIntMsg(msgId, im_isSent, im_sml, im_ts, im_from, im_to, im_title, im_body));
				}

				msgStart += (msgKilos * 1024) + 135; // 135 = 48 * 2 + 35 + 2 + 2
			}

			callback(true);
		});
	}); };

	this.Send = function(senderCopy, msgFrom, msgTo, msgTitle, msgBody, callback) { nacl_factory.instantiate(function (nacl) {
		const sc = senderCopy? "Y" : "N";
		const cleartext = nacl.encode_utf8(sc + msgFrom + '\n' + msgTo + '\n' + msgTitle + '\n' + msgBody);

		_FetchEncrypted("message/create", cleartext, nacl, function(fetchOk) {callback(fetchOk);});
	}); };

	// Notes are padded to the nearest 1024 bytes and encrypted into a sealed box before sending
	this.SaveNote = function(title, body, callback) { nacl_factory.instantiate(function (nacl) {
		const txt = title + '\n' + body;
		const lenTxt = new Blob([txt]).size;
		if (lenTxt > _lenPost) {callback(false); return;}

		const lenPad = (lenTxt % 1024 == 0) ? 0 : 1024 - (lenTxt % 1024);
		const paddedLen = lenTxt + lenPad;

		const u8data = new Uint8Array(paddedLen + 2);
		u8data.set(nacl.encode_utf8(txt));

		// Last two bytes store the padding length
		const u16pad = new Uint16Array([lenPad]);
		const u8pad = new Uint8Array(u16pad.buffer);
		u8data.set(u8pad, paddedLen);

		const sealbox = nacl.crypto_box_seal(u8data, _userKeys.boxPk);

		const finalData = new Uint8Array(sealbox.length + 1);
		finalData.set(nacl.encode_utf8("T"));
		finalData.set(sealbox, 1);

		_FetchEncrypted("message/assign", finalData, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_textNote.push(new _NewTextNote(-1, Date.now() / 1000, title, body));
			callback(true);
		});
	}); };

	// Files are padded to the nearest 1024 bytes and encrypted into a sealed box before sending
	this.SaveFile = function(fileData, fileName, fileType, fileSize, callback) { nacl_factory.instantiate(function (nacl) {
		const lenFn = (new Blob([fileName]).size);
		const lenFt = (new Blob([fileType]).size);
		if (lenFn > 255 || lenFt > 255) {callback(false); return;}

		fileSize += lenFn + lenFt + 2;
		if (fileSize > _lenPost) {callback(false); return;}

		const lenPad = (fileSize % 1024 == 0) ? 0 : 1024 - (fileSize % 1024);
		const paddedLen = fileSize + lenPad;

		const u8data = new Uint8Array(paddedLen + 2);
		u8data[0] = lenFn;
		u8data.set(nacl.encode_utf8(fileName), 1);

		u8data[1 + lenFn] = lenFt;
		u8data.set(nacl.encode_utf8(fileType), 2 + lenFn);

		u8data.set(fileData, 2 + lenFn + lenFt);

		// Last two bytes store the padding length
		const u16pad = new Uint16Array([paddedLen - fileSize]);
		const u8pad = new Uint8Array(u16pad.buffer);
		u8data.set(u8pad, paddedLen);

		const sealbox = nacl.crypto_box_seal(u8data, _userKeys.boxPk);

		const finalData = new Uint8Array(sealbox.length + 1);
		finalData.set(nacl.encode_utf8("F"));
		finalData.set(sealbox, 1);

		_FetchEncrypted("message/assign", finalData, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_fileNote.push(new _NewFileNote(-1, Date.now() / 1000, fileData, fileData.length, fileName, fileType));
			callback(true);
		});
	}); };

	this.DeleteAddress = function(num, callback) { nacl_factory.instantiate(function (nacl) {
		const shieldByte = (_userAddress[num].decoded.length === 24 && _userAddress[num].decoded[0] === '5') ? nacl.encode_utf8("S") : nacl.encode_utf8("N");
		const hash = _userAddress[num].hash;
		_userAddress.splice(num, 1);

		const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);
		const postData = new Uint8Array(9 + boxAddrData.length);
		postData.set(hash);
		postData.set(shieldByte, 8);
		postData.set(boxAddrData, 9);

		_FetchEncrypted("address/delete", postData, nacl, function(fetchOk) {callback(fetchOk);});
	}); };

	this.AddAddress = function(addr, callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("address/create", nacl.encode_utf8(addr), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_userAddress.push(new _NewAddress(byteArray.slice(8), byteArray.slice(0, 8), addr, false, false, false, true));

			const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);
			_FetchEncrypted("storage/enaddr", boxAddrData, nacl, function(fetchOk) {callback(fetchOk);});
		});
	}); };

	this.AddShieldAddress = function(callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("address/create", nacl.encode_utf8("SHIELD"), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_userAddress.push(new _NewAddress(byteArray.slice(8), byteArray.slice(0, 8), _DecodeAddress(byteArray.slice(8)), false, false, false, true));

			const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);
			_FetchEncrypted("storage/enaddr", boxAddrData, nacl, function(fetchOk) {callback(fetchOk);});
		});
	}); };

	this.SaveAddressData = function(callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("address/update", _MakeAddrData_Server(), nacl, function(fetchOk) {
			if (!fetchOk) {callback(false); return;}

			const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);
			_FetchEncrypted("storage/enaddr", boxAddrData, nacl, function(fetchOk) {callback(fetchOk);});
		});
	}); };

	this.SaveGatekeeperData = function(lst, callback) { nacl_factory.instantiate(function (nacl) {
		let gkText = "";
		for (let i = 0; i < lst.length; i++) gkText += lst[i] + '\n';

		_FetchEncrypted("storage/engate", nacl.encode_utf8(gkText), nacl, function(fetchOk) {callback(fetchOk);});
	}); };

	this.SaveNoteData = function(callback) { nacl_factory.instantiate(function (nacl) {
		let noteText = "";

		for (let i = 0; i < _contactMail.length; i++) {
			noteText += _contactMail[i] + '\n';
			noteText += _contactName[i] + '\n';
			noteText += _contactNote[i] + '\n';
		}

		const noteData = new Uint8Array(_lenNoteData_unsealed);
		const noteUtf8 = nacl.encode_utf8(noteText);
		noteData.set(noteUtf8, 2);

		const n = noteUtf8.length;
		noteData[0] = n & 0xFF;
		noteData[1] = n >> 8 & 0xFF;

		_FetchEncrypted("storage/ennote", nacl.crypto_box_seal(noteData, _userKeys.boxPk), nacl, function(fetchOk) {callback(fetchOk);});
	}); };

	this.DeleteMessages = function(ids, callback) { nacl_factory.instantiate(function (nacl) {
		const delCount = ids.length;

		const data = new Uint8Array(delCount);
		for (let i = 0; i < ids.length; i++) {
			if (ids[i] > 254) return;
			data[i] = ids[i];
		}

		_FetchEncrypted("message/delete", data, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			for (let i = 0; i < delCount; i++) {
				for (let j = 0; j < _intMsg.length; j++) {
					if (_intMsg[j].id == ids[i]) _intMsg.splice(j, 1);
					else if (_intMsg[j].id > ids[i]) _intMsg[j].id -= 1;
				}

				for (let j = 0; j < _extMsg.length; j++) {
					if (_extMsg[j].id == ids[i]) _extMsg.splice(j, 1);
					else if (_extMsg[j].id > ids[i]) _extMsg[j].id -= 1;
				}

				for (let j = 0; j < _textNote.length; j++) {
					if (ids[i] == _textNote[j].id) _textNote.splice(j, 1);
					else if (ids[i] < _textNote[j].id) _textNote[j].id -= 1;
				}

				for (let j = 0; j < _fileNote.length; j++) {
					if (ids[i] == _fileNote[j].id) _fileNote.splice(j, 1);
					else if (ids[i] < _fileNote[j].id) _fileNote[j].id -= 1;
				}
			}

			callback(true);
		});
	}); };

	this.AddAccount = function(pk_hex, callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("account/create", nacl.from_hex(pk_hex), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userPkHex.push(pk_hex.substr(0, 16));
			_admin_userLevel.push(0);
			_admin_userSpace.push(0);
			callback(true);
		});
	}); };

	this.DestroyAccount = function(num, callback) { nacl_factory.instantiate(function (nacl) {
		if (num >= _admin_userPkHex.length) {callback(false); return;}

		_FetchEncrypted("account/delete", nacl.from_hex(_admin_userPkHex[num]), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userPkHex.splice(num, 1);
			_admin_userLevel.splice(num, 1);
			_admin_userSpace.splice(num, 1);
			callback(true);
		});
	}); };

	this.SetAccountLevel = function(num, level, callback) { nacl_factory.instantiate(function (nacl) {
		if (num >= _admin_userPkHex.length || level < 0 || level > _maxLevel) {callback(false); return;}

		const upData = new Uint8Array(9);
		upData.set(nacl.from_hex(_admin_userPkHex[num]));
		upData[8] = level;

		_FetchEncrypted("account/update", upData, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userLevel[num] = level;
			callback(true);
		});
	}); };

	this.SetLimits = function(storage, addrNrm, addrShd, callback) { nacl_factory.instantiate(function (nacl) {
		if (storage.length !== 4 || addrNrm.length !== 4 || addrShd.length !== 4) {callback(false); return;}

		const newLimits = new Uint8Array(12);
		for (let i = 0; i < 4; i++) {
			newLimits[(i * 3) + 0] = storage[i];
			newLimits[(i * 3) + 1] = addrNrm[i];
			newLimits[(i * 3) + 2] = addrShd[i];
		}

		_FetchEncrypted("setting/limits", newLimits, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			for (let i = 0; i < 4; i++) {
				_maxStorage[i] = storage[i];
				_maxAddressNormal[i] = addrNrm[i];
				_maxAddressShield[i] = addrShd[i];
			}

			callback(true);
		});
	}); };

	this.NewKeys = function(callback) { nacl_factory.instantiate(function (nacl) {
		const newKeys = nacl.crypto_box_keypair();
		callback(nacl.to_hex(newKeys.boxPk), nacl.to_hex(newKeys.boxSk));
	}); };
}
