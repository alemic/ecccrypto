/*
 * Copyright 2013 mobileapart. All Rights Reserved.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * Example:
 *
 * e = new ECCCrypto();
 * encrypted = e.encrypt("Hello World", true);
 * e.decrypt(encrypted, true);
 *
 * export Keys:
 *
 * e.keys.toHEX();
 *
 */

/**
 * HEX encode/decode
 *
 */
var HEX = function() {
}
HEX.prototype.d2h = function(d) {
    return d.toString(16);
}
HEX.prototype.h2d = function(h) {
    return parseInt(h, 16);
}
HEX.prototype.stringToHex = function(tmp) {
    var str = '',
        i = 0,
        tmp_len = tmp.length,
        c;
    for (; i < tmp_len; i += 1) {
        c = tmp.charCodeAt(i);
        str += this.d2h(c) + '';
    }
    return str;
}
HEX.prototype.hexToString = function(tmp) {
    var arr = tmp.match(/.{1,2}/g),
        str = '',
        i = 0,
        arr_len = arr.length,
        c;
    for (; i < arr_len; i += 1) {
        c = String.fromCharCode( this.h2d( arr[i] ) );
        str += c;
    }
    return str;
}

/**
 * Key Tools
 *
 */
var ECCKeys = function(privKey, pubKey) {
	var that = this;
	this.hex = new HEX();
	if (typeof(privKey) == "string") {
		this.privKey = JSON.parse(this.hex.hexToString(privKey));
	} else {
		this.privKey = privKey;
	}
	if (typeof(pubKey) == "string") {
		this.pubKey = JSON.parse(this.hex.hexToString(pubKey));
	} else {
		this.pubKey = pubKey;
	}
}

ECCKeys.prototype.toHEX = function() {
	return {
		"privKey" : this.hex.stringToHex(JSON.stringify(this.privKey)),
		"pubKey" : this.hex.stringToHex(JSON.stringify(this.pubKey))
	};
}

/**
 * Constructor
 *
 * @param {String} privateKeyHEX  private Key HEX encoded
 * @param {String} publicKeyHEX public Key HEX encoded
 */
var ECCCrypto = function(privateKeyHEX, publicKeyHEX) {
	var that = this;
	this.hex = new HEX();
	if ((privateKeyHEX) && (publicKeyHEX)) {
		this.keys = new ECCKeys(privateKeyHEX, publicKeyHEX);
	} else {
		this.privateKey = this.generatePrivKey();
		this.publicKey = this.generatePubKey();
		this.keys = new ECCKeys(this.privateKey.sec.serialize(), this.generatePubKey());
	}
	// generate privatekey_obj for decryption
	var secjson = this.keys.privKey,
		ex = sjcl.bn.fromBits(secjson.exponent);
	this.privatekey_obj = new sjcl.ecc.elGamal.secretKey(secjson.curve, sjcl.ecc.curves["c" +secjson.curve], ex);
}

/**
 * generate Public Key
 *
 */
ECCCrypto.prototype.generatePubKey = function() {
	var pubjson = this.privateKey.pub.serialize(),
		point = sjcl.ecc.curves["c" + pubjson.curve].fromBits(pubjson.point),
		publicKey = new sjcl.ecc.elGamal.publicKey(pubjson.curve, point.curve, point);
	return publicKey.kem(0);
}

/**
 * generate a new private ecc key
 *
 * @param {number} curve  curve parameter e.g. 384
 */
ECCCrypto.prototype.generatePrivKey = function(curve) {
	curve = curve || 384; // defaults to 384
	return sjcl.ecc.elGamal.generateKeys(curve, 1);
}

/**
 * encrypt message
 *
 * @param {String}  message message to be encrypted
 * @param {Boolean} exportHEX type of message (hex encoded)
 * @param {String}  pubKey public key used to encrypt
 */
ECCCrypto.prototype.encrypt = function(message, exportHEX, pubKey) {
	var exportHEX = exportHEX || false,
		pubKey = pubKey || this.keys.pubKey,
		ciphertext = sjcl.encrypt(pubKey.key, message),
		json = JSON.stringify({ 'ciphertext': ciphertext, 'encrypted_key': pubKey.tag });
	if (exportHEX) {
		var hex = new HEX();
		return hex.stringToHex(json);
	}
	return json;
}

/**
 * decrypt message
 *
 * @param {String}  message message to be decrypted
 * @param {Boolean} importHEX type of message (hex encoded)
 */
ECCCrypto.prototype.decrypt = function(message, importHEX) {
	var importHEX = importHEX || false;
	if (importHEX) {
		var hex = new HEX(),
			cipherMessage = JSON.parse(hex.hexToString(message));
	} else {
		var cipherMessage = JSON.parse(message);
	}
	var symkey = this.privatekey_obj.unkem(cipherMessage.encrypted_key);
	return sjcl.decrypt(symkey, cipherMessage.ciphertext);
}