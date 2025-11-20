#import <Cordova/CDV.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>

@interface PgmAESCrypt : CDVPlugin

- (void)decrypt:(CDVInvokedUrlCommand*)command;
- (void)encrypt:(CDVInvokedUrlCommand*)command;

@end

@implementation PgmAESCrypt

- (void)decrypt:(CDVInvokedUrlCommand*)command {
	NSString *base64EncodedData = [command.arguments objectAtIndex:0];
	NSString *secureKey = [command.arguments objectAtIndex:1];

	// Check if the data and key are not nil
	if (!base64EncodedData || !secureKey) {
		[self sendError:@"Invalid arguments" toCommand:command];
		return;
	}

	NSData *dataToDecrypt = [[NSData alloc] initWithBase64EncodedString:base64EncodedData options:0];
	NSData *keyData = [secureKey dataUsingEncoding:NSUTF8StringEncoding];

	// Validate key size
	if ([keyData length] != kCCKeySizeAES256) {
		[self sendError:@"Key size must be 256 bits" toCommand:command];
		return;
	}

	// Validate data size (should be at least 16 bytes for IV + data)
	if ([dataToDecrypt length] <= kCCBlockSizeAES128) {
		[self sendError:@"Encrypted data is too short" toCommand:command];
		return;
	}

	// Extract the first 16 bytes for the IV
	NSData *ivData = [dataToDecrypt subdataWithRange:NSMakeRange(0, kCCBlockSizeAES128)];
	NSData *encryptedData = [dataToDecrypt subdataWithRange:NSMakeRange(kCCBlockSizeAES128, [dataToDecrypt length] - kCCBlockSizeAES128)];

	NSMutableData *decryptedData = [NSMutableData dataWithLength:encryptedData.length + kCCBlockSizeAES128];
	size_t outLength;
	CCCryptorStatus result = CCCrypt(kCCDecrypt,
									 kCCAlgorithmAES,
									 kCCOptionPKCS7Padding,
									 [keyData bytes],
									 kCCKeySizeAES256,
									 [ivData bytes],
									 [encryptedData bytes],
									 encryptedData.length,
									 decryptedData.mutableBytes,
									 decryptedData.length,
									 &outLength);

	if (result == kCCSuccess) {
		decryptedData.length = outLength;
		NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
		CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:decryptedString];
		[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
	} else {
		[self sendError:@"Decryption failed" toCommand:command];
	}
}

- (void)encrypt:(CDVInvokedUrlCommand*)command {
	NSString *plainText = [command.arguments objectAtIndex:0];
	NSString *secureKey = [command.arguments objectAtIndex:1];

	// Check if the data and key are not nil
	if (!plainText || !secureKey) {
		[self sendError:@"Invalid arguments" toCommand:command];
		return;
	}

	NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
	NSData *keyData = [secureKey dataUsingEncoding:NSUTF8StringEncoding];

	// Validate key size
	if ([keyData length] != kCCKeySizeAES256) {
		[self sendError:@"Key size must be 256 bits" toCommand:command];
		return;
	}

	// Generate random IV (16 bytes)
	NSMutableData *ivData = [NSMutableData dataWithLength:kCCBlockSizeAES128];
	int ivResult = SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, ivData.mutableBytes);
	if (ivResult != errSecSuccess) {
		[self sendError:@"Failed to generate IV" toCommand:command];
		return;
	}

	// Encrypt
	size_t outLength;
	NSMutableData *encryptedData = [NSMutableData dataWithLength:plainData.length + kCCBlockSizeAES128];
	CCCryptorStatus status = CCCrypt(kCCEncrypt,
									 kCCAlgorithmAES,
									 kCCOptionPKCS7Padding,
									 [keyData bytes],
									 kCCKeySizeAES256,
									 [ivData bytes],
									 [plainData bytes],
									 plainData.length,
									 encryptedData.mutableBytes,
									 encryptedData.length,
									 &outLength);

	if (status != kCCSuccess) {
		[self sendError:@"Encryption failed" toCommand:command];
		return;
	}

	encryptedData.length = outLength;

	// Prepend IV to ciphertext (IV || CIPHERTEXT)
	NSMutableData *combinedData = [NSMutableData dataWithData:ivData];
	[combinedData appendData:encryptedData];

	// Base64 encode
	NSString *base64String = [combinedData base64EncodedStringWithOptions:0];

	CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:base64String];
	[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)sendError:(NSString *)errorMessage toCommand:(CDVInvokedUrlCommand *)command {
	CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
	[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
