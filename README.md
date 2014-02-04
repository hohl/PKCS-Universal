PKCS-Universal
==============

Obj-C helper for working with [PKCS/RSA][pkcsWiki], Keychain and CommonCrypto for iOS.

## Installation

#### From [CocoaPods](http://www.cocoapods.org)

`pod 'PKCS-Universal'`

#### From source

* Drag the `PKCS.h` and `PKCS.m` files to your project
* Link the `libcommonCrypto.dylib` to your project

#### Too cool for [ARC](https://developer.apple.com/library/mac/releasenotes/ObjectiveC/RN-TransitioningToARC/Introduction/Introduction.html)?

* Add the `-fobjc-arc` compiler flag to all source files in your project in Target Settings > Build Phases > Compile Sources.

## Getting Started

1. Use `PCKSGenerateKeyPair(...)` and `SecKeyRef keyRef = PKCSLoadRSAKey(...)` to generate and load a private and public key to/from Apple Keychain.
2. Use `NSString *chiperString = PKCSEncryptRSA(plainTextString, publicKeyRef)` to encrypt your plain text string.
3. Use `NSString *plainTextString = PKCSDecryptRSA(chiperString, privateKeyRef` to decrypt your chiper string again.
4. Don't forget to `CFRelease(keyRef)` to release all your keychain references (since they are Core Foundation references and not Objective-C object instances. Even when using ARC!)

That's it. The helper also provides functions for storing and deleting keys in the keychain if you want to import a key from somewhere else.

Working with PKCS/RSA can't be easier!

## ToDo

- OS X support (Common Crypto has almost same API on OS X, but since I don't need it myself it has not been ported yet.)

## [MIT License][mitLink]

You are free to use this as you please. **No attribution necessary, but much appreciated.**

Copyright &copy; 2014 Michael Hohl

>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

[mitLink]:http://opensource.org/licenses/MIT
[pkcsWiki]:http://en.wikipedia.org/wiki/PKCS
