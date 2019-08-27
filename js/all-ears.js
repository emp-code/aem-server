"use strict";

function AllEars() {
	try {
		if (!window.isSecureContext) return;
		if (window.self !== window.top) return;
		if (document.compatMode == "BackCompat") return;
		if (document.characterSet != "UTF-8") return;
	} catch(e) {return;}

// Private
	const _serverPkHex = "_PLACEHOLDER_FOR_ALL-EARS_MAIL_SERVER_PUBLIC_KEY_DO_NOT_MODIFY._"; // Automatically replaced by the server
	const _lenNoteData_unsealed = 5122;
	const _lenNoteData = _lenNoteData_unsealed + 48;
	const _lenAdminData = 9216 // 9 KiB, space for 1024 users' data
	const _maxLevel = 3;

	// These are just informational, the server enforces the real limits
	// [Level0Limit, Level1Limit, ...]
	const _maxAddressNormal = [0, 0, 3, 30, 250];
	const _maxAddressShield = [0, 5, 25, 125, 250];

	let _userKeys;

	let _userLevel = 0;
	let _userAddress = [];
	let _intMsg = [];
	let _extMsg = [];
	let _textNote = [];
	let _fileNote = [];

	let _gkCountry = [];
	let _gkDomain  = [];
	let _gkAddress = [];

	let _contactMail = [];
	let _contactName = [];
	let _contactNote = [];

	let _admin_userPkHex = [];
	let _admin_userSpace = [];
	let _admin_userLevel = [];

	function _NewIntMsg(id, isSent, sml, ts, from, shield, to, title, body) {
		this.id = id;
		this.isSent = isSent;
		this.senderMemberLevel = sml;
		this.ts = ts;
		this.from = from;
		this.shield = shield;
		this.to = to;
		this.title = title;
		this.body = body;
	}

	function _NewExtMsg(id, ts, ip, cs, greet, infobyte, countrycode, from, to, title, headers, body) {
		this.id = id;
		this.ts = ts;
		this.ip = ip;
		this.cs = cs;
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

	function _NewAddress(addr, hash, decoded, isShield, accInt, spk, accExt, gk) {
		this.address = addr;
		this.hash = hash;
		this.decoded = decoded;
		this.isShield = isShield;
		this.acceptIntMsg = accInt;
		this.sharePk = spk;
		this.acceptExtMsg = accExt;
		this.useGatekeeper = gk;
	}

	const _FetchBinary = function(url, postData, callback) {
		fetch(url, {
			method: "POST",
			cache: "no-cache",
			credentials: "omit",
			mode: "same-origin",
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
		})
	}

	const _FetchEncrypted = function(url, cleartext, nacl, callback) {
		let nonce = new Uint8Array(24);
		window.crypto.getRandomValues(nonce);

		// postBox: the encrypted data to be sent
		const postBox = nacl.crypto_box(cleartext, nonce, nacl.from_hex(_serverPkHex), _userKeys.boxSk);

		// postMsg: Nonce + User Public Key + postBox
		const postMsg = new Uint8Array(24 + _userKeys.boxPk.length + postBox.length);
		postMsg.set(nonce);
		postMsg.set(_userKeys.boxPk, 24);
		postMsg.set(postBox, 24 + _userKeys.boxPk.length);

		_FetchBinary(url, postMsg, callback);
	}

	const _BitSet = function(num, bit) {
		return num | 1<<bit;
	}

	const _BitClear = function(num, bit) {
		return num & ~(1<<bit);
	}

	const _BitTest = function(num, bit) {
		return ((num>>bit) % 2 != 0);
	}

	const _GetBit = function(byteArray, bitNum) {
		const skipBytes = Math.floor(bitNum / 8.0);
		const skipBits = bitNum % 8;

		return _BitTest(byteArray[skipBytes], skipBits);
	}

	const _DecodeAddress = function(byteArray, start, nacl) {
		const sixBitTable = "|0123456789abcdefghijklmnopqrstuvwxyz.-@????????????????????????";
		const skip = start * 8;

		let decoded = "";

		for (let i = 0; i < 24; i++) {
			let num = 0;

			if (_GetBit(byteArray, skip + i*6 + 0)) num +=  1;
			if (_GetBit(byteArray, skip + i*6 + 1)) num +=  2;
			if (_GetBit(byteArray, skip + i*6 + 2)) num +=  4;
			if (_GetBit(byteArray, skip + i*6 + 3)) num +=  8;
			if (_GetBit(byteArray, skip + i*6 + 4)) num += 16;
			if (_GetBit(byteArray, skip + i*6 + 5)) num += 32;

			if (nacl != null && sixBitTable[num] == '?') return nacl.to_hex(byteArray.slice(start, start + 18));

			decoded = decoded + sixBitTable[num];
		}

		const end = decoded.indexOf('|');
		if (end == -1) return decoded;

		return decoded.substring(0, end);
	}

	const _DecodeOwnAddress = function(byteArray, start, nacl) {
		const decoded = _DecodeAddress(byteArray, start, null);

		for (let i = 0; i < _userAddress.length; i++) {
			if (_userAddress[i].isShield) continue;

			if (decoded == _DecodeAddress(_userAddress[i].address, 0, null)) return decoded;
		}

		return nacl.to_hex(byteArray.slice(start, start + 18));
	}

	const _GetAddressCount = function(isShield) {
		let count = 0;

		for (let i = 0; i < _userAddress.length; i++) {
			if (_userAddress[i].isShield == isShield) count++;
		}

		return count;
	}

	const _MakeAddrData = function() {
		const addrData = new Uint8Array(_userAddress.length * 27);

		for (let i = 0; i < _userAddress.length; i++) {
			addrData[i*27] = _userAddress[i].isShield      ? _BitSet(addrData[i*27], 0) : _BitClear(addrData[i*27], 0);
			addrData[i*27] = _userAddress[i].acceptIntMsg  ? _BitSet(addrData[i*27], 1) : _BitClear(addrData[i*27], 1);
			addrData[i*27] = _userAddress[i].sharePk       ? _BitSet(addrData[i*27], 2) : _BitClear(addrData[i*27], 2);
			addrData[i*27] = _userAddress[i].acceptExtMsg  ? _BitSet(addrData[i*27], 3) : _BitClear(addrData[i*27], 3);
			addrData[i*27] = _userAddress[i].useGatekeeper ? _BitSet(addrData[i*27], 4) : _BitClear(addrData[i*27], 4);
			addrData[i*27] = _BitClear(addrData[i*27], 5);
			addrData[i*27] = _BitClear(addrData[i*27], 6);
			addrData[i*27] = _BitClear(addrData[i*27], 7);

			addrData.set(_userAddress[i].address, i * 27 + 1);
			addrData.set(_userAddress[i].hash, i * 27 + 19);
		}

		return addrData;
	}

	const _GetCiphersuite = function(cs) {
		if (typeof(cs) !== "number") return "(error)";

		switch(cs) {
			case 0: return "TLS not used"
			case 49196: return "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
			case 49200: return "ECDHE_RSA_WITH_AES_256_GCM_SHA384";
			case 49195: return "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
			case 49199: return "ECDHE_RSA_WITH_AES_128_GCM_SHA256";
			case 52393: return "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
			case 52392: return "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
			default: return "(Unknown ciphersuite value)";
		}
	}

// Public
	this.GetLevelMax = function() {return _maxLevel;}

	this.GetAddress = function(num) {return _userAddress[num].decoded;}
	this.IsAddressShield = function(num) {return _userAddress[num].isShield;}
	this.IsAddressAcceptIntMsg = function(num) {return _userAddress[num].acceptIntMsg;}
	this.IsAddressAcceptExtMsg = function(num) {return _userAddress[num].acceptExtMsg;}
	this.IsAddressSharePk      = function(num) {return _userAddress[num].sharePk;}
	this.IsAddressGatekeeper   = function(num) {return _userAddress[num].useGatekeeper;}

	this.SetAddressAcceptIntMsg = function(num, val) {_userAddress[num].acceptIntMsg = val;}
	this.SetAddressAcceptExtMsg = function(num, val) {_userAddress[num].acceptExtMsg = val;}
	this.SetAddressSharePk      = function(num, val) {_userAddress[num].sharePk = val;}
	this.SetAddressGatekeeper   = function(num, val) {_userAddress[num].useGatekeeper = val;}

	this.GetAddressCount = function() {return _userAddress.length;}
	this.GetAddressCountNormal = function() {return _GetAddressCount(false);}
	this.GetAddressCountShield = function() {return _GetAddressCount(true);}

	this.IsUserAdmin = function() {return (_userLevel == _maxLevel);}
	this.GetUserLevel = function() {return _userLevel;}
	this.GetAddressLimitNormal = function() {return _maxAddressNormal[_userLevel];}
	this.GetAddressLimitShield = function() {return _maxAddressShield[_userLevel];}

	this.GetIntMsgCount = function() {return _intMsg.length;}
	this.GetIntMsgId     = function(num) {return _intMsg[num].id;}
	this.GetIntMsgLevel  = function(num) {return _intMsg[num].senderMemberLevel;}
	this.GetIntMsgTime   = function(num) {return _intMsg[num].ts;}
	this.GetIntMsgFrom   = function(num) {return _intMsg[num].from;}
	this.GetIntMsgShield = function(num) {return _intMsg[num].shield;}
	this.GetIntMsgIsSent = function(num) {return _intMsg[num].isSent;}
	this.GetIntMsgTo     = function(num) {return _intMsg[num].to;}
	this.GetIntMsgTitle  = function(num) {return _intMsg[num].title;}
	this.GetIntMsgBody   = function(num) {return _intMsg[num].body;}

	this.GetExtMsgCount = function() {return _extMsg.length;}
	this.GetExtMsgId      = function(num) {return _extMsg[num].id;}
	this.GetExtMsgTime    = function(num) {return _extMsg[num].ts;}
	this.GetExtMsgCipher  = function(num) {return _GetCiphersuite(_extMsg[num].cs);}
	this.GetExtMsgGreet   = function(num) {return _extMsg[num].greet;}
	this.GetExtMsgIp      = function(num) {return "" + _extMsg[num].ip[0] + "." + _extMsg[num].ip[1] + "." + _extMsg[num].ip[2] + "." + _extMsg[num].ip[3];}
	this.GetExtMsgCountry = function(num) {return _extMsg[num].countrycode;}
	this.GetExtMsgFrom    = function(num) {return _extMsg[num].from;}
	this.GetExtMsgTo      = function(num) {return _extMsg[num].to;}
	this.GetExtMsgTitle   = function(num) {return _extMsg[num].title;}
	this.GetExtMsgHeaders = function(num) {return _extMsg[num].headers;}
	this.GetExtMsgBody    = function(num) {return _extMsg[num].body;}

	this.GetExtMsgFlagPErr = function(num) {return _BitTest(_extMsg[num].info, 3);} // Protocol Error
	this.GetExtMsgFlagFail = function(num) {return _BitTest(_extMsg[num].info, 4);} // Invalid command used
	this.GetExtMsgFlagRare = function(num) {return _BitTest(_extMsg[num].info, 5);} // Rare/unusual command used
	this.GetExtMsgFlagQuit = function(num) {return _BitTest(_extMsg[num].info, 6);} // QUIT command issued
	this.GetExtMsgFlagPExt = function(num) {return _BitTest(_extMsg[num].info, 7);} // Protocol Extended (ESMTP)

	this.GetNoteCount = function() {return _textNote.length;}
	this.GetNoteId = function(num) {return _textNote[num].id;}
	this.GetNoteTime = function(num) {return _textNote[num].timestamp;}
	this.GetNoteTitle = function(num) {return _textNote[num].title;}
	this.GetNoteBody = function(num) {return _textNote[num].body;}

	this.GetFileCount = function() {return _fileNote.length;}
	this.GetFileId   = function(num) {return _fileNote[num].id;}
	this.GetFileTime = function(num) {return _fileNote[num].timestamp;}
	this.GetFileName = function(num) {return _fileNote[num].fileName;}
	this.GetFileType = function(num) {return _fileNote[num].fileType;}
	this.GetFileSize = function(num) {return _fileNote[num].fileSize;}
	this.GetFileBlob = function(num) {return new Blob([_fileNote[num].fileData.buffer], {type : _fileNote[num].fileType});}

	this.GetGatekeeperCountry = function() {return _gkCountry;}
	this.GetGatekeeperDomain  = function() {return _gkDomain;}
	this.GetGatekeeperAddress = function() {return _gkAddress;}

	this.Admin_GetUserCount = function() {return _admin_userPkHex.length;}
	this.Admin_GetUserPkHex = function(num) {return _admin_userPkHex[num];}
	this.Admin_GetUserSpace = function(num) {return _admin_userSpace[num];}
	this.Admin_GetUserLevel = function(num) {return _admin_userLevel[num];}

	this.GetContactCount = function() {return _contactMail.length;}
	this.GetContactMail = function(num) {return _contactMail[num];}
	this.GetContactName = function(num) {return _contactName[num];}
	this.GetContactNote = function(num) {return _contactNote[num];}
	this.AddContact = function(mail, name, note) {
		_contactMail.push(mail);
		_contactName.push(name);
		_contactNote.push(note);
	};
	this.DeleteContact = function(index) {
		_contactMail.splice(index, 1);
		_contactName.splice(index, 1);
		_contactNote.splice(index, 1);
	}

	this.SetKeys = function(skey_hex, callback) { nacl_factory.instantiate(function (nacl) {
		if (typeof(skey_hex) !== "string" || skey_hex.length != 64) {
			_userKeys = null;
			callback(false);
			return;
		}

		_userKeys=nacl.crypto_box_keypair_from_raw_sk(nacl.from_hex(skey_hex));
		callback(true);
	}); }

	this.Login = function(callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("/web/login", nacl.encode_utf8("AllEars:Web.Login"), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_userLevel = byteArray[0];
			const msgCount = byteArray[1];
			const addrDataSize = new Uint16Array(byteArray.slice(2, 4).buffer)[0];
			const gkDataSize   = new Uint16Array(byteArray.slice(4, 6).buffer)[0];

			// Note Data
			const noteData = nacl.crypto_box_seal_open(byteArray.slice(6, 6 + _lenNoteData), _userKeys.boxPk, _userKeys.boxSk);
			const noteDataSize = new Uint16Array(noteData.slice(0, 2).buffer)[0];
			const contactSet = nacl.decode_utf8(noteData.slice(2)).split('\n');

			for (let i = 0; i < (contactSet.length - 1); i += 3) {
				_contactMail.push(contactSet[i]);
				_contactName.push(contactSet[i + 1]);
				_contactNote.push(contactSet[i + 2]);
			}

			// Address data
			const addrData = nacl.crypto_box_seal_open(byteArray.slice(6 + _lenNoteData, 6 + _lenNoteData + addrDataSize), _userKeys.boxPk, _userKeys.boxSk);

			while (_userAddress.length > 0) _userAddress.pop();

			for (let i = 0; i < (addrData.length / 27); i++) {
				const isShield      = _BitTest(addrData[i * 27], 0);
				const acceptIntMsg  = _BitTest(addrData[i * 27], 1);
				const sharePk       = _BitTest(addrData[i * 27], 2);
				const acceptExtMsg  = _BitTest(addrData[i * 27], 3);
				const useGatekeeper = _BitTest(addrData[i * 27], 4);
				const addr = addrData.slice(i * 27 + 1, i * 27 + 19); // Address, 18 bytes
				const hash = addrData.slice(i * 27 + 19, i * 27 + 27); // Hash, 8 bytes
				const decoded = isShield ? nacl.to_hex(addr) : _DecodeAddress(addr, 0, null);

				_userAddress.push(new _NewAddress(addr, hash, decoded, isShield, acceptIntMsg, sharePk, acceptExtMsg, useGatekeeper));
			}

			// Gatekeeper data
			const gkData = nacl.decode_utf8(nacl.crypto_box_seal_open(byteArray.slice(6 + _lenNoteData + addrDataSize, 6 + _lenNoteData + addrDataSize + gkDataSize), _userKeys.boxPk, _userKeys.boxSk));
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
			const lenAdmin = (_userLevel == _maxLevel) ? _lenAdminData : 0;
			if (_userLevel == _maxLevel) {
				const adminStart = 6 + _lenNoteData + addrDataSize + gkDataSize;

				for (let i = 0; i < (_lenAdminData / 9); i++) {
					const pos = (adminStart + i * 9);
					const newPk = byteArray.slice(pos, pos + 8);

					if (newPk[0] == 0 && newPk[1] == 0 && newPk[2] == 0 && newPk[3] == 0
					&& newPk[4] == 0 && newPk[5] == 0 && newPk[6] == 0 && newPk[7] == 0) break;

					let newLevel = 0;
					if (_BitTest(byteArray[pos + 8], 0)) newLevel += 1;
					if (_BitTest(byteArray[pos + 8], 1)) newLevel += 2;

					let newSpace = 0;
					if (_BitTest(byteArray[pos + 8], 2)) newLevel += 1;
					if (_BitTest(byteArray[pos + 8], 3)) newLevel += 2;
					if (_BitTest(byteArray[pos + 8], 4)) newLevel += 4;
					if (_BitTest(byteArray[pos + 8], 5)) newLevel += 8;
					if (_BitTest(byteArray[pos + 8], 6)) newLevel += 16;
					if (_BitTest(byteArray[pos + 8], 7)) newLevel += 32;

					_admin_userPkHex.push(nacl.to_hex(newPk));
					_admin_userSpace.push(newSpace);
					_admin_userLevel.push(newLevel);
				}
			}

			// Message data
			let msgStart = 6 + _lenNoteData + addrDataSize + gkDataSize + lenAdmin;
			for (let i = 0; i < msgCount; i++) {
				const msgId = byteArray[msgStart];
				const msgKilos = byteArray[msgStart + 1] + 1;

				// HeadBox
				const msgHeadBox = byteArray.slice(msgStart + 2, msgStart + 91); // 2 + 41 + 48
				const msgHead = nacl.crypto_box_seal_open(msgHeadBox, _userKeys.boxPk, _userKeys.boxSk);

				if (!_BitTest(msgHead[0], 0) && !_BitTest(msgHead[0], 1)) { // 0,0 IntMsg
					let im_sml = 0;
					if (_BitTest(msgHead[0], 4)) im_sml++;
					if (_BitTest(msgHead[0], 5)) im_sml += 2;

					const u32bytes = msgHead.slice(1, 5).buffer;
					const im_ts = new Uint32Array(u32bytes)[0];

					const im_shield = _BitTest(msgHead[0], 7);
					const im_from_raw = msgHead.slice(5, 23);
					const im_from = im_shield? nacl.to_hex(im_from_raw) : _DecodeAddress(msgHead, 5, null);

					let im_isSent;
					for (let j = 0; j < _userAddress.length; j++) {
						im_isSent = true;

						for (let k = 0; k < 18; k++) {
							if (im_from_raw[k] != _userAddress[j].address[k]) {
								im_isSent = false;
								break;
							}
						}

						if (im_isSent) break;
					}

					const im_to = im_isSent? _DecodeAddress(msgHead, 23, nacl) : _DecodeOwnAddress(msgHead, 23, nacl); //nacl.to_hex(msgHead.slice(23, 41))

					// BodyBox
					const bbSize = msgKilos * 1024 + 50;
					const bbStart = msgStart + 91;

					const msgBodyBox = byteArray.slice(bbStart, bbStart + bbSize);
					const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, _userKeys.boxPk, _userKeys.boxSk);

					const u16bytes = msgBodyFull.slice(0, 2).buffer;
					const padAmount = new Uint16Array(u16bytes)[0];
					const msgBody = msgBodyFull.slice(2, msgBodyFull.length - padAmount);

					const msgBodyUtf8 = nacl.decode_utf8(msgBody);
					const firstLf = msgBodyUtf8.indexOf('\n');
					const im_title = msgBodyUtf8.slice(0, firstLf);
					const im_body = msgBodyUtf8.slice(firstLf + 1);

					_intMsg.push(new _NewIntMsg(msgId, im_isSent, im_sml, im_ts, im_from, im_shield, im_to, im_title, im_body));
				} else if (_BitTest(msgHead[0], 0) && !_BitTest(msgHead[0], 1)) { // 1,0 ExtMsg
					const em_infobyte = msgHead[0];

					let u32bytes = msgHead.slice(1, 5).buffer;
					const em_ts = new Uint32Array(u32bytes)[0];

					const em_ip = msgHead.slice(5, 9);

					u32bytes = msgHead.slice(9, 13).buffer;
					const em_cs = new Uint32Array(u32bytes)[0];

					const em_countrycode = nacl.decode_utf8(msgHead.slice(19, 21));

					const em_to = _DecodeOwnAddress(msgHead, 23, nacl);

					// BodyBox
					const bbSize = msgKilos * 1024 + 50;
					const bbStart = msgStart + 91;

					const msgBodyBox = byteArray.slice(bbStart, bbStart + bbSize);
					const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, _userKeys.boxPk, _userKeys.boxSk);

					const u16bytes = msgBodyFull.slice(0, 2).buffer;
					const padAmount = new Uint16Array(u16bytes)[0];

					const msgBodyBrU8 = msgBodyFull.slice(2, msgBodyFull.length - padAmount);
					const msgBodyBrI8 = new Int8Array(msgBodyBrU8);
					const msgBody = new Uint8Array(window.BrotliDecode(msgBodyBrI8));

					const msgBodyUtf8 = nacl.decode_utf8(msgBody);
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

					_extMsg.push(new _NewExtMsg(msgId, em_ts, em_ip, em_cs, em_greet, em_infobyte, em_countrycode, em_from, em_to, em_title, em_headers, em_body));
				} else if (!_BitTest(msgHead[0], 0) && _BitTest(msgHead[0], 1)) {  // 0,1 TextNote
					const u32bytes = msgHead.slice(1, 5).buffer;
					const note_ts = new Uint32Array(u32bytes)[0];

					const bbSize = msgKilos * 1024 + 50;
					const bbStart = msgStart + 91;

					const msgBodyBox = byteArray.slice(bbStart, bbStart + bbSize);
					const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, _userKeys.boxPk, _userKeys.boxSk);

					const u16bytes = msgBodyFull.slice(0, 2).buffer;
					const padAmount = new Uint16Array(u16bytes)[0];
					const msgBody = nacl.decode_utf8(msgBodyFull.slice(2, msgBodyFull.length - padAmount));

					const ln = msgBody.indexOf('\n');
					if (ln > 0)
						_textNote.push(new _NewTextNote(msgId, note_ts, msgBody.substr(0, ln), msgBody.substr(ln + 1)));
					else
						console.log("Received corrupted TextNote");
				} else { // 1,1 FileNote
					const u32bytes = msgHead.slice(1, 5).buffer;
					const note_ts = new Uint32Array(u32bytes)[0];

					const bbSize = msgKilos * 1024 + 50;
					const bbStart = msgStart + 91;

					const msgBodyBox = byteArray.slice(bbStart, bbStart + bbSize);
					const msgBodyFull = nacl.crypto_box_seal_open(msgBodyBox, _userKeys.boxPk, _userKeys.boxSk);

					const u16bytes = msgBodyFull.slice(0, 2).buffer;
					const padAmount = new Uint16Array(u16bytes)[0];
					const msgBody = msgBodyFull.slice(2, msgBodyFull.length - padAmount);

					const lenFn = msgBody[0];
					const fileName = nacl.decode_utf8(msgBody.slice(1, 1 + lenFn));

					const lenFt = msgBody[1 + lenFn];
					const fileType = nacl.decode_utf8(msgBody.slice(2 + lenFn, 2 + lenFn + lenFt));

					const fileData = msgBody.slice(2 + lenFn + lenFt);

					_fileNote.push(new _NewFileNote(msgId, note_ts, fileData, fileData.length, fileName, fileType));
				}

				msgStart += (msgKilos * 1024) + 141; // 48*2+41+2+2=141
			}

			callback(true);
		});
	}); }

	this.Send = function(senderCopy, msgFrom, msgTo, msgTitle, msgBody, callback) { nacl_factory.instantiate(function (nacl) {
		const sc = senderCopy? "Y" : "N";
		const cleartext = nacl.encode_utf8(sc + msgFrom + '\n' + msgTo + '\n' + msgTitle + '\n' + msgBody);

		_FetchEncrypted("/web/send", cleartext, nacl, function(fetchOk) {callback(fetchOk);});
	}); }

	// Notes are padded to the nearest 1024 bytes and encrypted into a sealed box before sending
	this.SaveNote = function(title, body, callback) { nacl_factory.instantiate(function (nacl) {
		const txt = title + '\n' + body;
		const lenTxt = new Blob([txt]).size;
		if (lenTxt > (256 * 1024)) {callback(false); return;}

		// First two bytes store the padding length
		const paddedLen = Math.ceil(lenTxt / 1024.0) * 1024;
		const u16pad = new Uint16Array([paddedLen - lenTxt]);
		const u8pad = new Uint8Array(u16pad.buffer);

		const u8data = new Uint8Array(paddedLen + 2);
		u8data.set(u8pad);
		u8data.set(nacl.encode_utf8(txt), 2);

		const sealbox = nacl.crypto_box_seal(u8data, _userKeys.boxPk);

		_FetchEncrypted("/web/textnote", sealbox, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_textNote.push(new _NewTextNote(-1, Date.now() / 1000, title, body));
			callback(true);
		});
	}); }

	// Files are padded to the nearest 1024 bytes and encrypted into a sealed box before sending
	this.SaveFile = function(fileData, fileName, fileType, fileSize, callback) { nacl_factory.instantiate(function (nacl) {
		const lenFn = (new Blob([fileName]).size);
		const lenFt = (new Blob([fileType]).size);
		if (lenFn > 255 || lenFt > 255) {callback(false); return;}

		fileSize += lenFn + lenFt + 2;
		if (fileSize > (256 * 1024)) {callback(false); return;}

		// First two bytes store the padding length
		const paddedLen = Math.ceil(fileSize / 1024.0) * 1024;
		const u16pad = new Uint16Array([paddedLen - fileSize]);
		const u8pad = new Uint8Array(u16pad.buffer);

		const u8data = new Uint8Array(paddedLen + 2);
		u8data.set(u8pad);

		u8data[2] = lenFn;
		u8data.set(nacl.encode_utf8(fileName), 3);

		u8data[3 + lenFn] = lenFt;
		u8data.set(nacl.encode_utf8(fileType), 4 + lenFn);

		u8data.set(fileData, 4 + lenFn + lenFt);

		const sealbox = nacl.crypto_box_seal(u8data, _userKeys.boxPk);

		_FetchEncrypted("/web/filenote", sealbox, nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_fileNote.push(new _NewFileNote(-1, Date.now() / 1000, fileData, fileName, fileType));
			callback(true);
		});
	}); }

	this.DeleteAddress = function(num, callback) { nacl_factory.instantiate(function (nacl) {
		const hash = _userAddress[num].hash;
		_userAddress.splice(num, 1);

		const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);
		const postData = new Uint8Array(8 + boxAddrData.length);
		postData.set(hash);
		postData.set(boxAddrData, 8);

		_FetchEncrypted("/web/addr/del", postData, nacl, function(fetchOk) {callback(fetchOk);});
	}); }

	this.AddAddress = function(addr, callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("/web/addr/add", nacl.encode_utf8(addr), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_userAddress.push(new _NewAddress(byteArray.slice(8), byteArray.slice(0, 8), addr, false, false, false, false, true));
			const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);

			_FetchEncrypted("/web/addr/upd", boxAddrData, nacl, function(fetchOk) {callback(fetchOk);});
		});
	}); }

	this.AddShieldAddress = function(callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("/web/addr/add", nacl.encode_utf8("SHIELD"), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_userAddress.push(new _NewAddress(byteArray.slice(8), byteArray.slice(0, 8), nacl.to_hex(byteArray.slice(8)), true, false, false, false, true));
			const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);

			_FetchEncrypted("/web/addr/upd", boxAddrData, nacl, function(fetchOk) {callback(fetchOk);});
		});
	}); }

	this.SaveAddressData = function(callback) { nacl_factory.instantiate(function (nacl) {
		const boxAddrData = nacl.crypto_box_seal(_MakeAddrData(), _userKeys.boxPk);

		_FetchEncrypted("/web/addr/upd", boxAddrData, nacl, function(fetchOk) {callback(fetchOk);});
	}); }

	this.SaveGatekeeperData = function(lst, callback) { nacl_factory.instantiate(function (nacl) {
		let gkText = "";
		for (let i = 0; i < lst.length; i++) gkText += lst[i] + '\n';

		_FetchEncrypted("/web/gatekeeper", nacl.encode_utf8(gkText), nacl, function(fetchOk) {callback(fetchOk);});
	}); }

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
		noteData[0] = n & 0xff;
		noteData[1] = n >> 8 & 0xff;

		_FetchEncrypted("/web/notedata", nacl.crypto_box_seal(noteData, _userKeys.boxPk), nacl, function(fetchOk) {callback(fetchOk);});
	}); }

	this.DeleteMessages = function(ids, callback) { nacl_factory.instantiate(function (nacl) {
		const delCount = ids.length;

		const data = new Uint8Array(delCount);
		for (let i = 0; i < ids.length; i++) {
			if (ids[i] > 254) return;
			data[i] = ids[i];
		}

		_FetchEncrypted("/web/delmsg", data, nacl, function(fetchOk, byteArray) {
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
	}); }

	this.AddAccount = function(pk_hex, callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("/web/addaccount", nacl.from_hex(pk_hex), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userPkHex.push(pk_hex.substr(0, 16));
			_admin_userLevel.push(0);
			_admin_userSpace.push(0);
			callback(true);
		});
	}); }

	this.DestroyAccount = function(num, callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("/web/destroyaccount", nacl.encode_utf8(_admin_userPkHex[num]), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userPkHex.splice(num, 1);
			_admin_userLevel.splice(num, 1);
			_admin_userSpace.splice(num, 1);
			callback(true);
		});
	}); }

	this.SetAccountLevel = function(num, level, callback) { nacl_factory.instantiate(function (nacl) {
		_FetchEncrypted("/web/accountlevel", nacl.encode_utf8(_admin_userPkHex[num] + level), nacl, function(fetchOk, byteArray) {
			if (!fetchOk) {callback(false); return;}

			_admin_userLevel[num] = level;
			callback(true);
		});
	}); }

	this.NewKeys = function(callback) { nacl_factory.instantiate(function (nacl) {
		const newKeys = nacl.crypto_box_keypair();
		callback(nacl.to_hex(newKeys.boxPk), nacl.to_hex(newKeys.boxSk));
	}); }
}
