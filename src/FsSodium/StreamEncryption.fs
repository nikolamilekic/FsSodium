module FsSodium.StreamEncryption

open System
open System.IO
open Milekic.YoLo
open Milekic.YoLo.Validation
open Milekic.YoLo.Update
open Milekic.YoLo.UpdateResult
open Milekic.YoLo.UpdateResult.Operators

let private macLength =
    Interop.crypto_secretstream_xchacha20poly1305_abytes()
let private keyLength = Interop.crypto_secretstream_xchacha20poly1305_keybytes()
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
            PasswordHashing.KeyLength.Create keyLength
            |> Result.mapError WrongKeyLength
        let! key =
            PasswordHashing.hashPassword keyLength parameters password
            |> Result.mapError HashPasswordError
        return new Key(key)
    }
module Header =
    let length = Interop.crypto_secretstream_xchacha20poly1305_headerbytes()
type Header = private Header of byte[]
    with
        static member FromBytes x =
            if Array.length x = Header.length then Header x |> Some else None
        member this.Bytes = let (Header x) = this in x
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
        let header = Array.zeroCreate Header.length
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

[<NoComparison; NoEquality>]
type StateUpdate =
    | DoNothing
    | SetNew of State
    static member Apply (s : State, u) = match u with
                                         | DoNothing -> s
                                         | SetNew s1 -> s.Dispose(); s1
    static member Unit = DoNothing
    static member Combine(a, b) = match (a, b) with | x, DoNothing -> x
                                                    | _, x -> x
let setNewState x = (fun _ -> SetNew x, ()) |> Update |> liftUpdate

type MessageType = Message | Final | Push | Rekey
let getCipherTextLength plainTextLength = plainTextLength + macLength
let getPlainTextLength cipherTextLength = cipherTextLength - macLength

type PartEncryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | SodiumError of int
let encryptPartTo messageType plainText plainTextLength cipherText = updateResult {
    if Array.length cipherText < getCipherTextLength plainTextLength
    then return! Error CipherTextBufferIsNotBigEnough |> liftResult else

    if Array.length plainText < plainTextLength
    then return! Error PlainTextBufferIsNotBigEnough |> liftResult else

    let! (state : State) = getState |> liftUpdate
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
    if result = 0 then return! setNewState <| new State(s)
    else return! Error <| SodiumError result |> liftResult
}
let encryptPart (plainText, messageType) = UpdateResult.delay <| fun () ->
    let plainTextLength = Array.length plainText
    let cipherText = getCipherTextLength plainTextLength |> Array.zeroCreate
    encryptPartTo messageType plainText plainTextLength cipherText
    |> UpdateResult.map (fun _ -> cipherText)

type PartDecryptionError =
    | CipherTextBufferIsNotBigEnough
    | PlainTextBufferIsNotBigEnough
    | ReceivedAnUnexpectedMessageTag of byte
    | SodiumError of int
let decryptPartTo cipherText cipherTextLength plainText = updateResult {
    if Array.length plainText < getPlainTextLength cipherTextLength
    then return! Error PlainTextBufferIsNotBigEnough |> liftResult else

    if Array.length cipherText < cipherTextLength
    then return! Error CipherTextBufferIsNotBigEnough |> liftResult else

    let! (state : State) = getState |> liftUpdate
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
        do! setNewState <| new State(s)
        match tag with
        | x when x = finalTag -> return Final
        | x when x = messageTag -> return Message
        | x when x = pushTag -> return Push
        | x when x = rekeyTag -> return Rekey
        | _ -> return! Error <| ReceivedAnUnexpectedMessageTag tag |> liftResult
    else return! Error <| SodiumError result |> liftResult
}
let decryptPart cipherText = UpdateResult.delay <| fun () ->
    let cipherTextLength = Array.length cipherText
    let plainTextLength = getPlainTextLength cipherTextLength
    let plainText = Array.zeroCreate plainTextLength
    decryptPartTo cipherText cipherTextLength plainText
    |> flip UpdateResult.map <| fun messageType -> plainText, messageType

type StreamEncryptionError =
    | InputStreamError of IOException
    | OutputStreamError of IOException
    | EncryptionError of PartEncryptionError
let encryptStream
    chunkSize (inputStream : Stream) (outputStream : Stream) = updateResult {

    let read buffer count =
        try Ok <| inputStream.Read(buffer, 0, count)
        with | :? IOException as exn -> Error <| InputStreamError exn
        |> liftResult
    let write buffer count =
        try Ok <| outputStream.Write(buffer, 0, count)
        with | :? IOException as exn -> Error <| OutputStreamError exn
        |> liftResult
    let cipherTextLength = getCipherTextLength chunkSize
    let cipherBuffer = Array.zeroCreate cipherTextLength
    let plainBuffer = Array.zeroCreate chunkSize
    use __ = new Secret(plainBuffer)
    let inputStreamLength = inputStream.Length |> int

    let rec inner count = updateResult {
        let! readBytes = read plainBuffer chunkSize
        let cipherTextLength = getCipherTextLength readBytes
        let messageType =
            if count + readBytes < inputStreamLength then Message else Final
        do! encryptPartTo messageType plainBuffer readBytes cipherBuffer
            >>-! EncryptionError
        do! write cipherBuffer cipherTextLength
        match messageType with
        | Final -> return ()
        | _ -> return! inner (count + readBytes)
    }

    let! encryptedChunkSize =
        BitConverter.GetBytes(chunkSize)
        |> fun chunkSize -> encryptPart (chunkSize, Message)
        >>-! EncryptionError
    do! write encryptedChunkSize (Array.length encryptedChunkSize)
    return! inner 0
}

type StreamDecryptionError =
    | InputStreamError of IOException
    | OutputStreamError of IOException
    | ChunkSizeDecryptionError of PartDecryptionError
    | ChunkDecryptionError of PartDecryptionError
let decryptStream
    (inputStream : Stream) (outputStream : Stream) = updateResult {

    let read buffer count =
        try Ok <| inputStream.Read(buffer, 0, count)
        with | :? IOException as exn -> Error <| InputStreamError exn
        |> liftResult
    let write buffer count =
        try Ok <| outputStream.Write(buffer, 0, count)
        with | :? IOException as exn -> Error <| OutputStreamError exn
        |> liftResult
    let! chunkSize = updateResult {
        let cipher = Array.zeroCreate (getCipherTextLength 4)
        do! read cipher (Array.length cipher) >>- ignore
        let! plain, _ = decryptPart cipher >>-! ChunkSizeDecryptionError
        return BitConverter.ToInt32(plain, 0)
    }
    let cipherTextLength = getCipherTextLength chunkSize
    let cipherBuffer = Array.zeroCreate cipherTextLength
    let plainBuffer = Array.zeroCreate chunkSize
    use __ = new Secret(plainBuffer)

    let rec inner () = updateResult {
        let! readBytes = read cipherBuffer cipherTextLength
        let plainTextLength = getPlainTextLength readBytes
        let! messageType =
            decryptPartTo cipherBuffer readBytes plainBuffer
            >>-! ChunkDecryptionError
        do! write plainBuffer plainTextLength
        match messageType with
        | Final -> return ()
        | _ -> return! inner()
    }
    return! inner ()
}
