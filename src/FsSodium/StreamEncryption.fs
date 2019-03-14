module FsSodium.StreamEncryption

open System
open Milekic.YoLo
open Milekic.YoLo.Result.Operators

let private macLength =
    Interop.crypto_secretstream_xchacha20poly1305_abytes()
let private keyLength = Interop.crypto_secretstream_xchacha20poly1305_keybytes()
let private headerLength = Interop.crypto_secretstream_xchacha20poly1305_headerbytes()
let private messageTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_message()
let private finalTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_final()
let private rekeyTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_rekey()
let private pushTag =
    byte <| Interop.crypto_secretstream_xchacha20poly1305_tag_push()

type KeyGenerationFromPasswordError =
    | WrongKeyLength of ValidateRangeError
    | HashPasswordError of PasswordHashing.HashPasswordError
type Key private (key) =
    inherit Secret(key)
    static member GenerateDisposable() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretstream_xchacha20poly1305_keygen(key.Secret)
        key
    static member FromPasswordDisposable(parameters, password) = result {
        let! keyLength =
            PasswordHashing.KeyLength.Create keyLength >>-! WrongKeyLength
        let! key =
            PasswordHashing.hashPassword keyLength parameters password
            >>-! HashPasswordError
        return new Key(key)
    }
type Header = private Header of byte[]
type EncryptionStateGenerationError = SodiumError of int
type DecryptionStateGenerationError = SodiumError of int
type State =
    private State of Interop.crypto_secretstream_xchacha20poly1305_state
    with
        static member MakeDecryptionState(key : Key, Header header) =
            let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
            let result =
                Interop.crypto_secretstream_xchacha20poly1305_init_pull(
                    &s,
                    header,
                    key.Secret)
            if result = 0 then Ok <| State s else Error <| SodiumError result
        static member MakeEncryptionState(key : Key) =
            let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
            let header = Array.zeroCreate headerLength
            let result =
                Interop.crypto_secretstream_xchacha20poly1305_init_push(
                    &s,
                    header,
                    key.Secret)
            if result = 0 then Ok (Header header, State s)
            else Error <| EncryptionStateGenerationError.SodiumError result

type MessageType = Message | Final | Push | Rekey
let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength

type EncryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let encryptPartTo (State state) messageType plainText plainTextLength cipherText =
    if Array.length cipherText < getCipherTextLength plainTextLength
    then Error CipherTextBufferIsNotBigEnough else

    if Array.length plainText < plainTextLength
    then Error PlainTextBufferIsNotBigEnough else

    let mutable s = state
    let tag = match messageType with
              | Message -> messageTag
              | Final -> finalTag
              | Push -> pushTag
              | Rekey -> rekeyTag

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

    if result = 0 then Ok <| State s else Error <| SodiumError result
let encryptPart state (plainText, messageType)  =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    let nextState =
        encryptPartTo state messageType plainText plainTextLength cipherText
    nextState >>- fun x -> (cipherText, x)

type DecryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | ReceivedAnUnexpectedMessageTag of byte
    | SodiumError of int
let decryptPartTo (State state) cipherText cipherTextLength plainText =
    if Array.length plainText < getPlainTextLength cipherTextLength
    then Error PlainTextBufferIsNotBigEnough else

    if Array.length cipherText < cipherTextLength
    then Error CipherTextBufferIsNotBigEnough else

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
        match tag with
        | x when x = finalTag -> Ok (Final, State s)
        | x when x = messageTag -> Ok (Message, State s)
        | x when x = pushTag -> Ok (Push, State s)
        | x when x = rekeyTag -> Ok (Rekey, State s)
        | _ -> Error <| ReceivedAnUnexpectedMessageTag tag
    else Error <| SodiumError result
let decryptPart state cipherText =  result {
    let cipherTextLength = Array.length cipherText
    let plainTextLength = getPlainTextLength cipherTextLength
    let plainText = Array.zeroCreate plainTextLength
    let! messageType, nextState =
        decryptPartTo state cipherText cipherTextLength plainText
    return plainText, messageType, nextState
}
