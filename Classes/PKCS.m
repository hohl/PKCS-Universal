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

#import "PKCS.h"
#import <CommonCrypto/CommonCrypto.h>

NSString* PKCSEncryptRSA(NSString* plainTextString, SecKeyRef publicKey)
{
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t* cipherBuffer = malloc(cipherBufferSize);
    uint8_t* nonce = (uint8_t*)[plainTextString UTF8String];
    SecKeyEncrypt(publicKey,
                  kSecPaddingOAEP,
                  nonce,
                  strlen((char*)nonce),
                  &cipherBuffer[0],
                  &cipherBufferSize);
    NSData* encryptedData = [NSData dataWithBytes:cipherBuffer
                                           length:cipherBufferSize];
    return [encryptedData base64EncodedStringWithOptions:0];
}

NSString* PKCSDecryptRSA(NSString* cipherString, SecKeyRef privateKey)
{
    size_t plainBufferSize = SecKeyGetBlockSize(privateKey);
    uint8_t* plainBuffer = malloc(plainBufferSize);
    NSData* incomingData = [[NSData alloc] initWithBase64EncodedString:cipherString
                                                               options:0];
    uint8_t* cipherBuffer = (uint8_t*)[incomingData bytes];
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
    SecKeyDecrypt(privateKey,
                  kSecPaddingOAEP,
                  cipherBuffer,
                  cipherBufferSize,
                  plainBuffer,
                  &plainBufferSize);
    NSData* decryptedData = [NSData dataWithBytes:plainBuffer
                                           length:plainBufferSize];
    NSString* decryptedString = [[NSString alloc] initWithData:decryptedData
                                                      encoding:NSUTF8StringEncoding];
    return decryptedString;
}

BOOL PCKSGenerateKeyPair(NSString* publicTagString, NSString* privateTagString, NSNumber* keySize)
{
    NSData* publicTag = [publicTagString dataUsingEncoding:NSUTF8StringEncoding];
    NSData* privateTag = [privateTagString dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary* keyPairAttr = @{
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits : keySize,
        (__bridge id)kSecPrivateKeyAttrs : @{
            (__bridge id)kSecAttrIsPermanent : @YES,
            (__bridge id)kSecAttrApplicationTag : privateTag
        },
        (__bridge id)kSecPublicKeyAttrs : @{
            (__bridge id)kSecAttrIsPermanent : @YES,
            (__bridge id)kSecAttrApplicationTag : publicTag
        }
    };

    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);

    if (publicKey)
        CFRelease(publicKey);
    if (privateKey)
        CFRelease(privateKey);

    if (status == noErr)
        return YES;

    return NO;
}

BOOL PKCSSaveRSAKey(CFTypeRef keyClass, NSData* keyData, NSString* keyTagString, BOOL overwrite)
{
    CFDataRef ref;

    NSDictionary* attr = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass : (__bridge id)keyClass,
        (__bridge id)kSecAttrIsPermanent : @YES,
        (__bridge id)kSecAttrApplicationTag : [keyTagString dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecValueData : keyData,
        (__bridge id)kSecReturnPersistentRef : @YES
    };

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attr, (CFTypeRef*)&ref);

    if (status == noErr)
        return YES;
    else if (status == errSecDuplicateItem && overwrite == YES)
        return PKCSUpdateRSAKey(keyClass, keyData, keyTagString);

    return NO;
}

BOOL PKCSUpdateRSAKey(CFTypeRef keyClass, NSData* keyData, NSString* keyTagString)
{
    NSDictionary* matchingAttr = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass : (__bridge id)keyClass,
        (__bridge id)kSecAttrApplicationTag : [keyTagString dataUsingEncoding:NSUTF8StringEncoding]
    };
    OSStatus matchingStatus = SecItemCopyMatching((__bridge CFDictionaryRef)matchingAttr, NULL);

    if (matchingStatus == noErr) {
        NSDictionary* updateAttr = @{
            (__bridge id)kSecClass : (__bridge id)kSecClassKey,
            (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPublic,
            (__bridge id)kSecAttrApplicationTag : [keyTagString dataUsingEncoding:NSUTF8StringEncoding]
        };
        NSDictionary* update = @{
            (__bridge id)kSecValueData : keyData
        };
        OSStatus updateStatus = SecItemUpdate((__bridge CFDictionaryRef)updateAttr, (__bridge CFDictionaryRef)update);
        return updateStatus == noErr;
    }
    return NO;
}

SecKeyRef PKCSLoadRSAKey(CFTypeRef keyClass, NSString* keyTagString)
{
    NSDictionary* attr = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass : (__bridge id)keyClass,
        (__bridge id)kSecAttrApplicationTag : [keyTagString dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecReturnRef : @YES
    };

    SecKeyRef keyRef;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)attr, (CFTypeRef*)&keyRef);

    if (status == noErr)
        return keyRef;
    else
        return NULL;
}

NSData* PKCSLoadRSAKeyData(CFTypeRef keyClass, NSString* keyTagString)
{
    NSDictionary* attr = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass : (__bridge id)keyClass,
        (__bridge id)kSecAttrApplicationTag : [keyTagString dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecReturnData : @YES
    };

    CFTypeRef result;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)attr, (CFTypeRef*)&result);

    if (status == noErr && result)
        return (NSData*)CFBridgingRelease(result);
    else if (result)
        CFRelease(result);

    return nil;
}

BOOL PKCSDeleteRSAKey(CFTypeRef keyClass, NSString* keyTagString)
{
    NSDictionary* attr = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass : (__bridge id)keyClass,
        (__bridge id)kSecAttrApplicationTag : [keyTagString dataUsingEncoding:NSUTF8StringEncoding]
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)attr);

    return status == noErr;
}