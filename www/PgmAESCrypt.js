var exec = require('cordova/exec');
var PgmAESCrypt = {
    decrypt: function(base64EncodedData, secureKey, successCallback, errorCallback) {
        exec(successCallback, errorCallback, "PgmAESCrypt", "decrypt", [base64EncodedData, secureKey]);
    }
};
module.exports = PgmAESCrypt;
