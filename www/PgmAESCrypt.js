var exec = require('cordova/exec');

var PgmAESCrypt = {
	decrypt: function(base64EncodedData, secureKey, successCallback, errorCallback) {
		exec(successCallback, errorCallback, "PgmAESCrypt", "decrypt", [base64EncodedData, secureKey]);
	},

	encrypt: function(plainText, secureKey, successCallback, errorCallback) {
		exec(successCallback, errorCallback, "PgmAESCrypt", "encrypt", [plainText, secureKey]);
	}
};

module.exports = PgmAESCrypt;
