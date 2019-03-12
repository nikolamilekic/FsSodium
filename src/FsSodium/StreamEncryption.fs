module FsSodium.StreamEncryption

open System
open System.Security.Cryptography
open Milekic.YoLo

let private additionalBytes =
    Interop.crypto_secretstream_xchacha20poly1305_abytes()
let private keyLength = Interop.crypto_secretstream_xchacha20poly1305_keybytes()
let private headerLength = Interop.crypto_secretstream_xchacha20poly1305_headerbytes()
let private notLastTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_message()
let private lastTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_final()

type StreamEncryptionState =
    private State of Interop.crypto_secretstream_xchacha20poly1305_state
type MessageType = NotLast | Last
type CipherText = CipherTextBytes of byte[]

let encryptPart (State state) ((PlainText plainText), messageType) =
    let plainTextLength = Array.length plainText
    let cipherTextLength = plainTextLength + additionalBytes
    let cipherText = Array.zeroCreate cipherTextLength
    let mutable s = state
    let tag = match messageType with
              | NotLast -> notLastTag
              | Last -> lastTag

    let result =
        Interop.crypto_secretstream_xchacha20poly1305_push(
            &s,
            cipherText,
            IntPtr.Zero,
            plainText,
            uint64 plainTextLength,
            null,
            0UL,
            byte tag)

    if result = 0
    then CipherTextBytes cipherText, State s
    else CryptographicException("Encryption failed. This should not happen. Please report this error.")
         |> raise

let decryptPart (State state) (CipherTextBytes cipherText) =
    let cipherTextLength = Array.length cipherText
    let plainTextLength = cipherTextLength - additionalBytes
    let plainText = Array.zeroCreate plainTextLength
    let mutable s = state
    let mutable tag = 0uy

    let result =
        Interop.crypto_secretstream_xchacha20poly1305_pull(
            &s,
            plainText,
            IntPtr.Zero,
            &tag,
            cipherText,
            uint64 cipherTextLength,
            null,
            0UL)

    if result = 0 then
        let tag = match tag with
                  | x when x = notLastTag -> NotLast
                  | x when x = lastTag -> Last
                  | _ -> CryptographicException("Received an unexpected tag")
                         |> raise
        Ok <| (PlainText plainText, tag, State s)
    else Error()

type Key = private KeySecret of Secret
type Header = HeaderBytes of byte[]

let makeEncryptionState (KeySecret key) =
    let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
    let header = Array.zeroCreate headerLength
    let result =
        Interop.crypto_secretstream_xchacha20poly1305_init_push(
            &s,
            header,
            key.Secret)
    if result = 0
    then HeaderBytes header, State s
    else CryptographicException("Making encryption state failed. This should not happen. Please report this error.")
         |> raise
let makeDecryptionState (KeySecret key) (HeaderBytes header) =
    let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
    let result =
        Interop.crypto_secretstream_xchacha20poly1305_init_pull(
            &s,
            header,
            key.Secret)
    if result = 0 then Ok <| State s else Error ()
let generateKey() =
    let key = Array.zeroCreate keyLength
    let secret = new Secret(key)
    Interop.crypto_secretstream_xchacha20poly1305_keygen(key)
    KeySecret secret
// let generateKeyFromPassword =
//     uncurry (PasswordHashing.hashPassword keyLength)
//     >> Result.map KeySecret
//     |> curry
