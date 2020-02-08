"use strict";

function AllEars(domain, serverPkHex, saltNormalHex, readyCallback) {
	try {
		if (!window.isSecureContext
		|| window.self !== window.top
		|| document.compatMode == "BackCompat"
		|| document.characterSet !== "UTF-8"
		) return readyCallback(false);
	} catch(e) {return readyCallback(false);}

	if (!domain || typeof(domain) !== "string")
		domain = document.location.hostname;

// Private constants - must match server
	const _AEM_ADDR_FLAG_EXTMSG = 128;
	const _AEM_ADDR_FLAG_INTMSG = 64;
	const _AEM_ADDR_FLAG_SHR_PK = 16;
	const _AEM_ADDR_FLAG_USE_GK = 32;
	const _AEM_ADDR_FLAGS_DEFAULT = _AEM_ADDR_FLAG_EXTMSG;

	const _AEM_BYTES_HEADBOX = 35;
	const _AEM_BYTES_POST = 8192;
	const _AEM_BYTES_PRIVATE = 4096 - sodium.crypto_box_PUBLICKEYBYTES - 5;

	const _AEM_ARGON2_MEMLIMIT = 67108864;
	const _AEM_ARGON2_OPSLIMIT = 3;

	const _AEM_ADDR32_CHARS = "0123456789abcdefghjkmnpqrstuwxyz";
	const _AEM_ADMINDATA_USERS = 1024;
	const _AEM_PUBKEY_SERVER = sodium.from_hex(serverPkHex);
	const _AEM_SALT_NORMAL = sodium.from_hex(saltNormalHex);
	const _AEM_USER_MAXLEVEL = 3;

// Private variables
	const _maxStorage = [];
	const _maxAddressNormal = [];
	const _maxAddressShield = [];

	let _userKeyPublic;
	let _userKeySecret;

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

// Private functions
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

	function _NewAddress(hash, addr32, decoded, accExt, accInt, gk, spk) {
		this.hash = hash;
		this.addr32 = addr32;
		this.decoded = decoded;
		this.acceptExtMsg = accExt;
		this.acceptIntMsg = accInt;
		this.useGatekeeper = gk;
		this.sharePk = spk;
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

	const _FetchEncrypted = function(url, cleartext, callback) {
		if (cleartext.length > _AEM_BYTES_POST - 2) {callback(false); return;}

		// Cleartext is padded to _AEM_BYTES_POST bytes
		const clearU8 = new Uint8Array(_AEM_BYTES_POST);
		window.crypto.getRandomValues(clearU8);
		clearU8.set(cleartext);

		// Last two bytes store the length
		const u16len = new Uint16Array([cleartext.length]);
		const u8len = new Uint8Array(u16len.buffer);
		clearU8.set(u8len, _AEM_BYTES_POST - 2);

		const nonce = new Uint8Array(sodium.crypto_box_NONCEBYTES);
		window.crypto.getRandomValues(nonce);

		// postBox: the encrypted data to be sent
		const postBox = sodium.crypto_box_easy(clearU8, nonce, _AEM_PUBKEY_SERVER, _userKeySecret);

		// postMsg: Nonce + User Public Key + postBox
		const postMsg = new Uint8Array(sodium.crypto_box_NONCEBYTES + sodium.crypto_box_PUBLICKEYBYTES + postBox.length);
		postMsg.set(nonce);
		postMsg.set(_userKeyPublic, sodium.crypto_box_NONCEBYTES);
		postMsg.set(postBox, sodium.crypto_box_NONCEBYTES + sodium.crypto_box_PUBLICKEYBYTES);

		_FetchBinary("https://" + domain + ":302/api/" + url, postMsg, callback);
	};

	const _GetBit = function(src, bitNum) {
		const bit = bitNum % 8;
		const byte = (bitNum - bit) / 8;

		return ((1 & (src[byte] >> (7 - bit))) === 1);
	}

	const _SetBit = function(src, bitNum) {
		const bit = bitNum % 8;
		const byte = (bitNum - bit) / 8;

		src[byte] |= 1 << (7 - bit);
	}

	const _addr32_decode = function(byteArray) {
		if (byteArray.length != 15) return "addr32:BadLen";

		const len = (byteArray[0] & 248) >> 3; // First five bits (128+64+32+16+8=248) store length; 0 = Shield

		let decoded = "";

		for (let i = 0; i < ((len === 0) ? 23 : len); i++) {
			let num = 0;
			const skipBits = (i + 1) * 5;

			if (_GetBit(byteArray, skipBits + 0)) num += 16;
			if (_GetBit(byteArray, skipBits + 1)) num +=  8;
			if (_GetBit(byteArray, skipBits + 2)) num +=  4;
			if (_GetBit(byteArray, skipBits + 3)) num +=  2;
			if (_GetBit(byteArray, skipBits + 4)) num +=  1;

			decoded += _AEM_ADDR32_CHARS[num];
		}

		return (len === 0) ? decoded + '5' : decoded;
	};

	const _addr32_charToUint5 = function(c) {
		for (let i = 0; i < 32; i++) {
			if (c == _AEM_ADDR32_CHARS[i]) return i;
		}

		if (c == 'o') return 0; // '0'
		if (c == 'i' || c == 'l') return 1; // '1'
		if (c == 'v') return 28; // 'w'

		return -1;
	}

	// Only for Normal, not Shield addresses
	const _addr32_encode = function(source) {
		if (source.length < 1 || source.length > 23) return null;

		let encoded = new Uint8Array(15);
		encoded[0] = source.length << 3; // First five bits store length

		for (let i = 0; i < source.length; i++) {
			const skipBits = (i + 1) * 5;

			let num = _addr32_charToUint5(source[i]);
			if (num < 0) return null;
			if (num >= 16) {_SetBit(encoded, skipBits + 0); num -= 16;}
			if (num >=  8) {_SetBit(encoded, skipBits + 1); num -=  8;}
			if (num >=  4) {_SetBit(encoded, skipBits + 2); num -=  4;}
			if (num >=  2) {_SetBit(encoded, skipBits + 3); num -=  2;}
			if (num >=  1) {_SetBit(encoded, skipBits + 4); num -=  1;}
		}

		return encoded;
	};

	const _GetAddressCount = function(isShield) {
		let count = 0;

		for (let i = 0; i < _userAddress.length; i++) {
			if (isShield && _userAddress[i].decoded.length === 24) count++;
			else if (!isShield && (_userAddress[i].decoded.length < 24)) count++;
		}

		return count;
	};

	const _IsOwnAddress = function(addr) {
		for (let i = 0; i < _userAddress.length; i++) {
			let isOwn = true;

			for (let j = 0; j < 15; j++) {
				if (addr[j] != _userAddress[i].addr32[j]) {
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

	this.GetLevelMax = function() {return _AEM_USER_MAXLEVEL;};

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

	this.IsUserAdmin = function() {return (_userLevel === _AEM_USER_MAXLEVEL);};
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

	this.SetKeys = function(skey_hex, callback) {
		if (typeof(skey_hex) !== "string" || skey_hex.length !== 64) {
			_userKeySecret = null;
			_userKeyPublic = null;
			callback(false);
			return;
		}

		_userKeySecret = sodium.from_hex(skey_hex);
		_userKeyPublic = sodium.crypto_scalarmult_base(_userKeySecret);
		callback(true);
	};

	this.Account_Browse = function(page, callback) {
		if (typeof(page) !== "number" || page < 0 || page > 255) {callback(false); return;}

		_FetchEncrypted("account/browse", new Uint8Array([page]), function(fetchOk, browseData) {
			if (!fetchOk) {callback(false); return;}

			for (let i = 0; i < 4; i++) {
				_maxStorage.push(browseData[(i * 3) + 0]);
				_maxAddressNormal.push(browseData[(i * 3) + 1]);
				_maxAddressShield.push(browseData[(i * 3) + 2]);
			}

			_userLevel = browseData[12];

			// Private field
			const privData = sodium.crypto_box_seal_open(browseData.slice(13, 13 + _AEM_BYTES_PRIVATE), _userKeyPublic, _userKeySecret);

			for (let i = 0; i < privData[0]; i++) {
				const start = (i * 29) + 1;
				const hash = privData.slice(start, start + 13);
				const addr32 = privData.slice(start + 13, start + 28);
				const accExt = (privData[start + 28] & _AEM_ADDR_FLAG_EXTMSG > 0) ? true : false;
				const accInt = (privData[start + 28] & _AEM_ADDR_FLAG_INTMSG > 0) ? true : false;
				const use_gk = (privData[start + 28] & _AEM_ADDR_FLAG_USE_GK > 0) ? true : false;
				const shr_pk = (privData[start + 28] & _AEM_ADDR_FLAG_SHR_PK > 0) ? true : false;

				_userAddress.push(new _NewAddress(hash, addr32, _addr32_decode(addr32), accExt, accInt, use_gk, shr_pk));
			}

			// Admin Data
			if (_userLevel == _AEM_USER_MAXLEVEL) {
				const adminData = browseData.slice(13 + _AEM_BYTES_PRIVATE, 13 + _AEM_BYTES_PRIVATE + 35 * _AEM_ADMINDATA_USERS);
				for (let i = 0; i < _AEM_ADMINDATA_USERS; i++) {
					const s = adminData.slice(i * 35, (i + 1) * 35);

					const pk_hex = sodium.to_hex(s.slice(3));
					if (pk_hex == "0000000000000000000000000000000000000000000000000000000000000000") break;

					const newLevel = s[0] & 3;
					const newSpace = s[0] >>> 2;
					const newNaddr = s[1];
					const newSaddr = s[2];

					_admin_userPkHex.push(pk_hex);
					_admin_userLevel.push(newLevel);
					_admin_userSpace.push(newSpace);
					_admin_userNaddr.push(newNaddr);
					_admin_userSaddr.push(newSaddr);
				}
			}

			// Messages
			let msgStart = 13 + _AEM_BYTES_PRIVATE;
			if (_userLevel == _AEM_USER_MAXLEVEL) msgStart += (35 * _AEM_ADMINDATA_USERS);

			while (msgStart < browseData.length) {
				const kib = browseData[msgStart];
				if (kib == 0) break;
				msgStart++;

				const msgData = browseData.slice(msgStart, msgStart + (kib * 1024));

				// Message ID: Every 64th byte of first kilo of encrypted data
				const msgId = new Uint8Array(16);
				for (let i = 0; i < 16; i++) msgId[i] = msgData[i * 64];

				const msgHeadBox = msgData.slice(0, _AEM_BYTES_HEADBOX + sodium.crypto_box_SEALBYTES);
				const msgHead = sodium.crypto_box_seal_open(msgHeadBox, _userKeyPublic, _userKeySecret);

				// BodyBox
				const msgBodyBox = msgData.slice(_AEM_BYTES_HEADBOX + sodium.crypto_box_SEALBYTES, 1024 * kib);
				const msgBodyFull = sodium.crypto_box_seal_open(msgBodyBox, _userKeyPublic, _userKeySecret);
				const lenBody = (1024 * kib) - _AEM_BYTES_HEADBOX - sodium.crypto_box_SEALBYTES - sodium.crypto_box_SEALBYTES;
				const padAmount = new Uint16Array(msgBodyFull.slice(lenBody - 2, lenBody).buffer)[0];
				const msgBody = msgBodyFull.slice(0, lenBody - padAmount - 2);

				if ((msgHead[0] & 1) === 1) { // xxxxxx01 ExtMsg
					const em_infobyte = msgHead[0];
					const em_ts = new Uint32Array(msgHead.slice(1, 5).buffer)[0];
					const em_ip = msgHead.slice(5, 9);
					const em_cs = new Uint16Array(msgHead.slice(9, 11).buffer)[0];
					const em_tlsver = msgHead[11];
					// msgHead[12] = SpamByte
					const em_countrycode = new TextDecoder("utf-8").decode(msgHead.slice(13, 15));
					// 16-19 unused
					const em_to = _addr32_decode(msgHead.slice(20));

					// Bodybox
					const msgBodyBrI8 = new Int8Array(msgBody);
					const msgBodyText = new Uint8Array(window.BrotliDecode(msgBodyBrI8));
					const msgBodyUtf8 = new TextDecoder("utf-8").decode(msgBodyText);

					const firstLf = msgBodyUtf8.indexOf('\n');
					const em_greet = msgBodyUtf8.slice(0, firstLf);
					const secondLf = msgBodyUtf8.slice(firstLf + 1).indexOf('\n') + firstLf + 1;
					const em_from = msgBodyUtf8.slice(firstLf + 1, secondLf);
					const body = msgBodyUtf8.slice(secondLf);

					const titleStart = body.indexOf("\nSubject: ");
					const titleEnd = (titleStart < 0) ? -1 : body.slice(titleStart + 10).indexOf("\n");
					const em_title = (titleStart < 0) ? "(Missing title)" : body.substr(titleStart + 10, titleEnd);

					const headersEnd = body.indexOf("\n\n");
					const em_headers = body.slice(1, headersEnd);
					const em_body = body.slice(headersEnd + 2);

					_extMsg.push(new _NewExtMsg(msgId, em_ts, em_ip, em_cs, em_tlsver, em_greet, em_infobyte, em_countrycode, em_from, em_to, em_title, em_headers, em_body));
				} else console.log("not-extmsg");

				msgStart += (kib * 1024);
			}

			callback(true);
		});
	};

	this.Account_Create = function(pk_hex, callback) {
		_FetchEncrypted("account/create", sodium.from_hex(pk_hex), function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userPkHex.push(pk_hex);
			_admin_userLevel.push(0);
			_admin_userSpace.push(0);
			_admin_userNaddr.push(0);
			_admin_userSaddr.push(0);
			callback(true);
		});
	};

	this.Account_Delete = function(pk_hex, callback) {
		_FetchEncrypted("account/delete", sodium.from_hex(pk_hex), function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			let num = -1;
			for (let i = 0; i < _admin_userPkHex.length; i++) {
				if (pk_hex === _admin_userPkHex[i]) {
					num = i;
					break;
				}
			}

			if (num >= 0) {
				_admin_userPkHex.splice(num, 1);
				_admin_userLevel.splice(num, 1);
				_admin_userSpace.splice(num, 1);
				_admin_userNaddr.splice(num, 1);
				_admin_userSaddr.splice(num, 1);
			}

			callback(true);
		});
	};

	this.Account_Update = function(pk_hex, level, callback) {
		if (level < 0 || level > _AEM_USER_MAXLEVEL) {callback(false); return;}

		const upData = new Uint8Array(33);
		upData[0] = level;
		upData.set(sodium.from_hex(pk_hex), 1);

		_FetchEncrypted("account/update", upData, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			let num = -1;
			for (let i = 0; i < _admin_userPkHex.length; i++) {
				if (pk_hex === _admin_userPkHex[i]) {
					num = i;
					break;
				}
			}

			if (num >= 0)
				_admin_userLevel[num] = level;

			callback(true);
		});
	};

	this.Address_Create = function(addr, callback) {
		if (addr == "SHIELD") {
			_FetchEncrypted("address/create", sodium.from_string("SHIELD"), function(fetchOk, byteArray) {
				if (!fetchOk) {callback(false); return;}

				_userAddress.push(new _NewAddress(byteArray.slice(0, 13), byteArray.slice(13, 28), _addr32_decode(byteArray.slice(13, 28)), true, false, false, false));
				callback(true);
			});
		} else {
			const addr32 = _addr32_encode(addr);
			const hash = sodium.crypto_pwhash(16, addr32, _AEM_SALT_NORMAL, _AEM_ARGON2_OPSLIMIT, _AEM_ARGON2_MEMLIMIT, sodium.crypto_pwhash_ALG_ARGON2ID13).slice(0, 13);

			_FetchEncrypted("address/create", hash, function(fetchOk, byteArray) {
				if (!fetchOk) {callback(false); return;}

				_userAddress.push(new _NewAddress(hash, addr32, _addr32_decode(addr32), true, false, false, false));
				callback(true);
			});
		}
	};

	this.Address_Delete = function(num, callback) {
		_FetchEncrypted("address/delete", _userAddress[num].hash, function(fetchOk) {
			if (!fetchOk) {
				callback(false);
				return;
			}

			_userAddress.splice(num, 1);
			callback(true);
		});
	};

	this.Private_Update = function(callback) {
		const privData = new Uint8Array(_AEM_BYTES_PRIVATE - sodium.crypto_box_SEALBYTES);
		privData[0] = _userAddress.length;
		for (let i = 0; i < _userAddress.length; i++) {
			privData.set(_userAddress[i].hash, (i * 29) + 1);
			privData.set(_userAddress[i].addr32, (i * 29) + 14);
			privData[(i * 29) + 29] = _AEM_ADDR_FLAGS_DEFAULT;
		}

		_FetchEncrypted("private/update", sodium.crypto_box_seal(privData, _userKeyPublic), function(fetchOk) {callback(fetchOk);});
	};

	this.NewKeys = function(callback) {
		const newKeys = sodium.crypto_box_keypair();
		callback(sodium.to_hex(newKeys.publicKey), sodium.to_hex(newKeys.privateKey));
	};

	return readyCallback(true);
}
