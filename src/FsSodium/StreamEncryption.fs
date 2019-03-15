module FsSodium.StreamEncryption

open System
open System.IO
open Milekic.YoLo
open Milekic.YoLo.Validation
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
type Header = Header of byte[]
type EncryptionStateGenerationError = SodiumError of int
type DecryptionStateGenerationError = SodiumError of int
type State internal (state) =
    static member MakeDecryptionState(key : Key, Header header) =
        let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
        let result =
            Interop.crypto_secretstream_xchacha20poly1305_init_pull(
                &s,
                header,
                key.Secret)
        if result = 0 then Ok <| new State(s) else Error <| SodiumError result
    static member MakeEncryptionState(key : Key) =
        let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
        let header = Array.zeroCreate headerLength
        let result =
            Interop.crypto_secretstream_xchacha20poly1305_init_push(
                &s,
                header,
                key.Secret)
        if result = 0 then Ok (Header header, new State(s))
        else Error <| EncryptionStateGenerationError.SodiumError result
    member internal __.State = state
    member __.Dispose() =
        let clear x =
            if x <> null then Interop.sodium_memzero(x, Array.length x)
        clear state.k
        clear state.nonce
        clear state._pad
    override this.Finalize() = this.Dispose()
    interface IDisposable with member this.Dispose() = this.Dispose()

type MessageType = Message | Final | Push | Rekey
let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength

type PartEncryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let encryptPartTo (state : State) messageType plainText plainTextLength cipherText =
    if Array.length cipherText < getCipherTextLength plainTextLength
    then Error CipherTextBufferIsNotBigEnough else

    if Array.length plainText < plainTextLength
    then Error PlainTextBufferIsNotBigEnough else

    let mutable s = state.State
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

    if result = 0 then Ok <| new State(s) else Error <| SodiumError result
let encryptPart state (plainText, messageType)  =
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    let nextState =
        encryptPartTo state messageType plainText plainTextLength cipherText
    nextState >>- fun x -> (cipherText, x)

type PartDecryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | ReceivedAnUnexpectedMessageTag of byte
    | SodiumError of int
let decryptPartTo (state : State) cipherText cipherTextLength plainText =
    if Array.length plainText < getPlainTextLength cipherTextLength
    then Error PlainTextBufferIsNotBigEnough else

    if Array.length cipherText < cipherTextLength
    then Error CipherTextBufferIsNotBigEnough else

    let mutable s = state.State
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
        | x when x = finalTag -> Ok (Final, new State(s))
        | x when x = messageTag -> Ok (Message, new State(s))
        | x when x = pushTag -> Ok (Push, new State(s))
        | x when x = rekeyTag -> Ok (Rekey, new State(s))
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

type StreamEncryptionError =
    | StateGenerationError of EncryptionStateGenerationError
    | InputStreamError of IOException
    | OutputStreamError of IOException
    | EncryptionError of PartEncryptionError
let encryptStream
    (chunkSize : int) key (inputStream : Stream) (outputStream : Stream) =

    let cipherTextLength = getCipherTextLength chunkSize
    let cipherBuffer = Array.zeroCreate cipherTextLength
    let plainBuffer = Array.zeroCreate chunkSize
    use __ = new Secret(plainBuffer)
    let write buffer count =
        try Ok <| outputStream.Write(buffer, 0, count)
        with | :? IOException as exn -> Error <| OutputStreamError exn
    let inputStreamLength = inputStream.Length |> int
    let rec go count state = result {
        let! readBytes =
            try Ok <| inputStream.Read(plainBuffer, 0, chunkSize)
            with | :? IOException as exn -> Error <| InputStreamError exn
        let cipherTextLength = getCipherTextLength readBytes
        let messageType =
            if count + readBytes < inputStreamLength then Message else Final
        let! nextState =
            encryptPartTo state messageType plainBuffer readBytes cipherBuffer
            >>-! EncryptionError
        state.Dispose()
        do! write cipherBuffer cipherTextLength
        match messageType with
        | Final -> nextState.Dispose()
        | _ -> return! go (count + readBytes) nextState
    }

    result {
        let! (Header h), state =
            State.MakeEncryptionState key >>-! StateGenerationError
        do! write h (Array.length h)
        let! encryptedChunkSize, state =
            use state = state
            BitConverter.GetBytes(chunkSize)
            |> fun chunkSize -> encryptPart state (chunkSize, Message)
            >>-! EncryptionError
        do! write encryptedChunkSize (Array.length encryptedChunkSize)
        return! go 0 state
    }

type StreamDecryptionError =
    | StateGenerationError of DecryptionStateGenerationError
    | InputStreamError of IOException
    | OutputStreamError of IOException
    | ChunkSizeDecryptionError of PartDecryptionError
    | ChunkDecryptionError of PartDecryptionError
let decryptStream key (inputStream : Stream) (outputStream : Stream) = result {
    let read buffer =
        try Ok <| inputStream.Read(buffer, 0, (Array.length buffer))
        with | :? IOException as exn -> Error <| InputStreamError exn
    let! state = result {
        let h = Array.zeroCreate (headerLength)
        do! read h >>- ignore
        return!
            State.MakeDecryptionState(key, Header h) >>-! StateGenerationError
    }
    let! chunkSize, state = result {
        let b = Array.zeroCreate (getCipherTextLength 4)
        do! read b >>- ignore
        let! b, _, s = decryptPart state b >>-! ChunkSizeDecryptionError
        state.Dispose()
        return BitConverter.ToInt32(b, 0), s
    }
    let cipherTextLength = getCipherTextLength chunkSize
    let cipherBuffer = Array.zeroCreate cipherTextLength
    let plainBuffer = Array.zeroCreate chunkSize
    use __ = new Secret(plainBuffer)
    let rec go state = result {
        let! readBytes = read cipherBuffer
        let plainTextLength = getPlainTextLength readBytes
        let! messageType, nextState =
            decryptPartTo state cipherBuffer readBytes plainBuffer
            >>-! ChunkDecryptionError
        state.Dispose()

        do!
            try Ok <| outputStream.Write(plainBuffer, 0, plainTextLength)
            with | :? IOException as exn -> Error <| OutputStreamError exn

        match messageType with
        | Final -> nextState.Dispose(); return ()
        | _ -> return! go nextState
    }
    return! go state
}
