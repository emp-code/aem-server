function b64ToBin(input) {
	const b64Char="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

	if (b64Char.indexOf(input.charAt(input.length - 1)) == 64) input=input.substring(0,input.length - 1);
	if (b64Char.indexOf(input.charAt(input.length - 1)) == 64) input=input.substring(0,input.length - 1);

	var bytes = parseInt((input.length / 4) * 3, 10);
	
	input = input.replace(/[^0-9A-Za-z\+\/\=]/g, "");

	var u8 = new Uint8Array(bytes);
	var j = 0;

	for (var i=0; i < bytes; i += 3) {
		//get the 3 octects in 4 ascii chars
		var enc1 = b64Char.indexOf(input.charAt(j++));
		var enc2 = b64Char.indexOf(input.charAt(j++));
		var enc3 = b64Char.indexOf(input.charAt(j++));
		var enc4 = b64Char.indexOf(input.charAt(j++));

		var chr1 = (enc1 << 2) | (enc2 >> 4);
		var chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
		var chr3 = ((enc3 & 3) << 6) | enc4;

		u8[i] = chr1;
		if (enc3 != 64) u8[i+1] = chr2;
		if (enc4 != 64) u8[i+2] = chr3;
	}

	return u8;	
}
