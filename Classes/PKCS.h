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

#import <Foundation/Foundation.h>

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
 * Generates a new RSA private and public key with the passed key size and stores it into the Apple Keychain.
 *
 * @param publicTagString Tag used to store the created public key.
 * @param privateTagString Tag used to store the created private key.
 * @param keySize Size of the key to create. (Valid numbers are 256, 512, 1024 and 2048)
 * @return YES if the create has been successfully created.
 */
BOOL PCKSGenerateKeyPair(NSString* publicTagString, NSString* privateTagString, NSNumber* keySize);

/**
 * Stores a private or public RSA key in the Apple Keychain.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get saved.
 * @param keyData The raw data of the key.
 * @param keyTagString tag used to store and retrive keys.
 * @param overwrite If set to YES and the key already exists, PKCSUpdateRSAKey will automatically get called.
 * @return YES if completed successfully.
 */
BOOL PKCSSaveRSAKey(CFTypeRef keyClass, NSData* keyData, NSString* keyTagString, BOOL overwrite);

/**
 * Updates an existing private or public RSA key in the Apple Keychain.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get updated.
 * @param keyData The raw data of the key.
 * @param keyTagString tag used to store and retrive keys.
 * @param overwrite If set to YES and the key already exists, PKCSUpdateRSAKey will automatically get called.
 * @return YES if completed successfully.
 */
BOOL PKCSUpdateRSAKey(CFTypeRef keyClass, NSData* keyData, NSString* keyTagString);

/**
 * Loads a RSA key from Apple Keychain.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get loaded.
 * @param keyTagString tag used to store and retrive keys.
 * @return NULL or the loaded key.
 * @discussion Attention! The returned key must be manually released with CFRelease.
 */
SecKeyRef PKCSLoadRSAKey(CFTypeRef keyClass, NSString* keyTagString);

/**
 * Deletes the RSA key with the passed tag.
 *
 * @param keyClass May either be kSecAttrKeyClassPublic or kSecAttrKeyClassPrivate and defines if the private or public key should get deleted.
 * @param keyTagString Tag of the key which should get deleted.
 * @return YES if the key has been successfully deleted.
 */
BOOL PKCSDeleteRSAKey(CFTypeRef keyClass, NSString *keyTagString);
