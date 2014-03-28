//
//  Created by Michael Hohl
//  http://www.michaelhohl.net
//
//
//  Documentation
//  http://cocoadocs.org/docsets/PKCS-Universal
//
//
//  The MIT License
//  Copyright (c) 2014 Michael Hohl
//  http://opensource.org/licenses/MIT
//

/**
 * Encrypt the passed plain text message.
 * 
 * @param plainTextString Message to encrypt.
 * @param publicKey SecKeyRef to the public key.
 * @return The created chiper string.
 */
NSString* PKCSEncryptRSA(NSString* plainTextString, SecKeyRef publicKey);

/**
 * Decrypt the passed encrypted message.
 *
 * @param chiperString Message to decrypt.
 * @param privateKey SecKeyRef to the private key.
 * @return The created plain text message.
 */
NSString* PKCSDecryptRSA(NSString* cipherString, SecKeyRef privateKey);

/**
 * Creates the signature for the passed plain data.
 * Signature is created by encrypting the SHA256 hash value of the plain data.
 *
 * @param plainData Any raw data of which the signature should get created.
 * @param privateKey The private key used to encrypt the data.
 * @return Create signature bytes.
 */
NSData* PKCSSignBytesSHA256withRSA(NSData* plainData, SecKeyRef privateKey);

/**
 * Verfies the passed signature bytes with the passed plain data.
 * If the signature is valid for the passed data and the public key YES is returned.
 * @param plainData Any raw data which has been used to create the signature.
 * @param signature The signature to verify.
 * @param publicKey Public Key used to check the signature.
 * @return YES if the public key, signature and plain data fit together.
 */
BOOL PKCSVerifyBytesSHA256withRSA(NSData* plainData, NSData* signature, SecKeyRef publicKey);

/**
 * Generates a new RSA private and public key with the passed key size and stores it into the Apple Keychain.
 *
 * @param publicTagString Tag used to store the created public key.
 * @param privateTagString Tag used to store the created private key.
 * @param keySize Size of the key to create. (Valid numbers are 256, 512, 1024 and 2048)
 * @param isPermanent If set to NO the generates keys are  only stored in memory, otherwise they are written to disk.
 * @return YES if the create has been successfully created.
 */
BOOL PKCSGenerateKeyPair(NSString* publicTagString, NSString* privateTagString, NSNumber* keySize, BOOL isPermanent);

/**
 * Stores a private or public RSA key in the Apple Keychain.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get saved.
 * @param keyData The raw data of the key.
 * @param keyTagString tag used to store and retrieve keys.
 * @param overwrite If set to YES and the key already exists, PKCSUpdateRSAKey will automatically get called.
 * @return YES if completed successfully.
 */
BOOL PKCSSaveRSAKey(CFTypeRef keyClass, NSData* keyData, NSString* keyTagString, BOOL overwrite);

/**
 * Updates an existing private or public RSA key in the Apple Keychain.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get updated.
 * @param keyData The raw data of the key.
 * @param keyTagString tag used to store and retrieve keys.
 * @param overwrite If set to YES and the key already exists, PKCSUpdateRSAKey will automatically get called.
 * @return YES if completed successfully.
 */
BOOL PKCSUpdateRSAKey(CFTypeRef keyClass, NSData* keyData, NSString* keyTagString);

/**
 * Loads a RSA key from Apple Keychain.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get loaded.
 * @param keyTagString tag used to store and retrieve keys.
 * @return NULL or the loaded SecKeyRef.
 * @discussion Attention! The returned key must be manually released with CFRelease.
 */
SecKeyRef PKCSLoadRSAKey(CFTypeRef keyClass, NSString* keyTagString);

/**
 * Loads the bytes of the key instead of a SecKeyRef.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get loaded.
 * @param keyTagString tag used to store and retrieve keys.
 * @return NULL or the loaded key as NSData representation.
 */
NSData* PKCSLoadRSAKeyData(CFTypeRef keyClass, NSString* keyTagString);

/**
 * Deletes the RSA key with the passed tag.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get deleted.
 * @param keyTagString Tag of the key which should get deleted.
 * @return YES if the key has been successfully deleted.
 */
BOOL PKCSDeleteRSAKey(CFTypeRef keyClass, NSString *keyTagString);
