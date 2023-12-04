var exec = require('cordova/exec');

var AESCrypt = {
    decrypt: function(base64EncodedData, secureKey, successCallback, errorCallback) {
        exec(successCallback, errorCallback, "AESCrypt", "decrypt", [base64EncodedData, secureKey]);
    }
};

module.exports = AESCrypt;