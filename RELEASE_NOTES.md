### 0.3-dev - Unreleased
* Refactored validation logic
* Hashing
* getLibsodiumVersion
* Changed stream encryption functions to take actual streams

### 0.2 - 2019/07/30
* Switched to using Milekic.YoLo library
* PublicKeyEncryption.encrypt now returns nonce in addition to cipher text to simplify interface usage
* Added Random
* Added PasswordHashing
* Added Secret
* Added StreamEncryption
* Added 'public key from secret key' computation for both public key authentication and encryption
* Updated FSharp.Core references as per guidelines

### 0.1.1 - 2018/04/25
* Moved YoLo to FsSodium namespace

### 0.1 - 2018/04/22
* Added PublicKeyAuthentication and PublicKeyEncryption
