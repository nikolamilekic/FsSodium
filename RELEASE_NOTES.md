## 0.4 (Released 2022/02/19)
* Update to .NET 6

## 0.3 (Released 2020/09/14)
* Hashing (both generic and SHA512)
* Common.getSodiumVersion
* SecretKeyAuthentication
* The library now initializes libsodium automatically
* Refactorying and API cleanup
* XSalsa20
* Key derivation

## New in 0.2 (Released 2019/07/30)
* Switched to using Milekic.YoLo library
* PublicKeyEncryption.encrypt now returns nonce in addition to cipher text to simplify interface usage
* Added Random
* Added PasswordHashing
* Added Secret
* Added StreamEncryption
* Added 'public key from secret key' computation for both public key authentication and encryption
* Updated FSharp.Core references as per guidelines

## New in 0.1.1 (Released 2018/04/25)
* Moved YoLo to FsSodium namespace

## New in 0.1 (Released 2018/04/22)
* Added PublicKeyAuthentication and PublicKeyEncryption
