module FsSodium.StreamEncryption

open System
open System.IO
open Milekic.YoLo
open Milekic.YoLo.Update
open Milekic.YoLo.UpdateResult
open Milekic.YoLo.UpdateResult.Operators
open Extensions

let internal macLength =
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

let private passwordHashingKeyLength =
    PasswordHashing.KeyLength.Validate keyLength
    |> Result.failOnError "Key length is not supported."
type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretstream_xchacha20poly1305_keygen(key.Secret)
        key
    static member FromPassword(parameters, password) =
        PasswordHashing.hashPassword passwordHashingKeyLength parameters password
        |> Result.map (fun x -> new Key(x))
    static member Length = keyLength
    static member Validate x =
        validateArrayLength keyLength (fun x -> new Key(x)) x
module Header =
    let length = Interop.crypto_secretstream_xchacha20poly1305_headerbytes()
type Header =
    private | Header of byte[]
    static member Length = Header.length
    static member Validate x = validateArrayLength Header.length Header x
    member this.Value = let (Header x) = this in x
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
        else Error <| SodiumError result
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
let getCipherTextLength plainTextLength =
    if plainTextLength <= 0 then 0 else plainTextLength + macLength
let getPlainTextLength cipherTextLength =
    if cipherTextLength <= macLength then 0 else cipherTextLength - macLength

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

type ChunkLength =
    private | ChunkLength of int
    static member Validate x =
        validateRange 1 (Int32.MaxValue - macLength) ChunkLength x
    member this.Value = let (ChunkLength x) = this in x

let getCipherTextStreamLength (ChunkLength chunkLength) plainTextStreamLength =
    if plainTextStreamLength <= 0 then 0 else
    plainTextStreamLength / chunkLength * getCipherTextLength chunkLength +
    getCipherTextLength (plainTextStreamLength % chunkLength)
let getPlainTextStreamLength (ChunkLength chunkLength) cipherTextStreamLength =
    if cipherTextStreamLength <= 0 then 0 else
    let encryptedChunkLength = getCipherTextLength chunkLength
    cipherTextStreamLength / encryptedChunkLength * chunkLength +
    getPlainTextLength (cipherTextStreamLength % encryptedChunkLength)

type ReaderState = NotDone | Done

let readFromStream (inputStream : Stream) buffer =
    try
        let readBytes = inputStream.Read(buffer, 0, Array.length buffer)
        let state = if inputStream.Position < inputStream.Length
                    then NotDone else Done
        Ok (readBytes, state)
    with | :? IOException as exn -> Error exn

let writeToStream (outputStream : Stream) (buffer, count) =
    try outputStream.Write(buffer, 0, count) |> Ok
    with | :? IOException as exn -> Error exn

type StreamEncryptionError<'a, 'b> =
    | ReadError of 'a
    | WriteError of 'b
    | EncryptionError of PartEncryptionError
let encryptStream (ChunkLength chunkLength) read write = updateResult {
    let read = read >> Result.mapError ReadError >> liftResult
    let write = write >> Result.mapError WriteError >> liftResult

    let cipherTextLength = getCipherTextLength chunkLength
    let cipherBuffer = Array.zeroCreate cipherTextLength
    let plainBuffer = Array.zeroCreate chunkLength
    use __ = new Secret(plainBuffer)

    let rec inner count = updateResult {
        let! readBytes, state = read plainBuffer
        let messageType = match state with NotDone -> Message | Done -> Final
        let cipherTextLength = getCipherTextLength readBytes
        do! encryptPartTo messageType plainBuffer readBytes cipherBuffer
            >>-! EncryptionError
        do! write (cipherBuffer, cipherTextLength)
        match messageType with
        | Final -> return ()
        | _ -> return! inner (count + readBytes)
    }

    return! inner 0
}

type StreamDecryptionError<'a, 'b> =
    | ReadError of 'a
    | WriteError of 'b
    | IncompleteStream
    | StreamIsTooLong
    | DecryptionError of PartDecryptionError
let decryptStream (ChunkLength chunkLength) read write = updateResult {
    let read = read >> Result.mapError ReadError >> liftResult
    let write = write >> Result.mapError WriteError >> liftResult

    let cipherTextLength = getCipherTextLength chunkLength
    let cipherBuffer = Array.zeroCreate cipherTextLength
    let plainBuffer = Array.zeroCreate chunkLength
    use __ = new Secret(plainBuffer)

    let rec inner () = updateResult {
        let! readBytes, state = read cipherBuffer
        let plainTextLength = getPlainTextLength readBytes
        let! messageType =
            decryptPartTo cipherBuffer readBytes plainBuffer
            >>-! DecryptionError
        do! write(plainBuffer, plainTextLength)
        match messageType, state with
        | Final, Done -> return ()
        | _, Done -> return! Error IncompleteStream |> liftResult
        | Final, NotDone -> return! Error StreamIsTooLong |> liftResult
        | _, NotDone -> return! inner()
    }
    return! inner ()
}
