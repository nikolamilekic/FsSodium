[<RequireQualifiedAccess>]
module FsSodium.StreamEncryption

open System
open System.IO
open FSharpPlus
open FSharpPlus.Data

let internal macLength =
    Interop.crypto_secretstream_xchacha20poly1305_abytes() |> int
let private keyLength =
    Interop.crypto_secretstream_xchacha20poly1305_keybytes() |> int
let private headerLength =
    Interop.crypto_secretstream_xchacha20poly1305_headerbytes() |> int
let private messageTag = Interop.crypto_secretstream_xchacha20poly1305_tag_message()
let private finalTag = Interop.crypto_secretstream_xchacha20poly1305_tag_final()
let private rekeyTag = Interop.crypto_secretstream_xchacha20poly1305_tag_rekey()
let private pushTag = Interop.crypto_secretstream_xchacha20poly1305_tag_push()

type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        let key = new Key(Array.zeroCreate keyLength)
        Interop.crypto_secretstream_xchacha20poly1305_keygen(key.Get)
        key
    static member Import x =
        if Array.length x <> keyLength then Error () else Ok <| new Key(x)
type Header = private | Header of byte[] with
    static member Validate x =
        if Array.length x <> headerLength then Error () else Ok <| Header x
    member this.Get = let (Header x) = this in x

type State internal (state : Interop.crypto_secretstream_xchacha20poly1305_state) =
    member internal __.State = state
    member __.Dispose() =
        let clear x =
            if not (isNull x) then
                Interop.sodium_memzero(x, Array.length x |> uint32)
        clear state.k
        clear state.nonce
        clear state._pad
    override this.Finalize() = this.Dispose()
    interface IDisposable with member this.Dispose() = this.Dispose()

let createEncryptionState(key : Key) =
    let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
    let header = Array.zeroCreate headerLength
    let result =
        Interop.crypto_secretstream_xchacha20poly1305_init_push(
            &s,
            header,
            key.Get)
    if result = 0
    then Ok (Header header, new State(s))
    else Error <| SodiumError result
let createDecryptionState(key : Key, Header header) =
    let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
    let result =
        Interop.crypto_secretstream_xchacha20poly1305_init_pull(
            &s,
            header,
            key.Get)
    if result = 0
    then Ok <| new State(s)
    else Error <| SodiumError result

type MessageType = Message | Final | Push | Rekey
type ChunkLength = private | ChunkLength of int with
    static member Validate x =
        if x < 1 || x > (Int32.MaxValue - macLength)
        then Error ()
        else Ok <| ChunkLength x
    member this.Value = let (ChunkLength x) = this in x
type StreamEncryptionError =
    | ReadError of IOException
    | WriteError of IOException
    | StateInitializationError of SodiumError
    | EncryptionError of SodiumError
type StreamDecryptionError =
    | ReadError of IOException
    | WriteError of IOException
    | IncompleteStream
    | StateInitializationError of SodiumError
    | DecryptionError of SodiumError

let buffersFactory = BuffersFactory(macLength)

let setNewState newState = monad {
    let! (oldState : State) = State.get |> StateT.hoist
    oldState.Dispose()
    do! (State.put newState) |> StateT.hoist
}
let encryptPartTo
    (encryptionBuffers : Buffers)
    messageType
    plainTextLength = monad {

    let plainText = encryptionBuffers.PlainText
    if Array.length plainText < plainTextLength then
        invalidArg "plainTextLength" "Provided plain text buffer is too small"

    let! (state : State) = State.get |> StateT.hoist
    let mutable s = state.State
    let tag =
        match messageType with
        | Message -> messageTag
        | Final -> finalTag
        | Push -> pushTag
        | Rekey -> rekeyTag
    let result =
        Interop.crypto_secretstream_xchacha20poly1305_push(
            &s,
            encryptionBuffers.CipherText,
            IntPtr.Zero,
            plainText,
            uint64 plainTextLength,
            null,
            0UL,
            byte tag)
    if result = 0
    then
        do! setNewState (new State(s))
        return ()
    else return! SodiumError result |> Error |> StateT.lift
}
let encryptPart (messageType, plainText) = monad {
    let buffers = buffersFactory.FromPlainText plainText
    let plainTextLength = Array.length plainText
    do! encryptPartTo buffers messageType plainTextLength
    return buffers.CipherText
}
let decryptPartTo
    (decryptionBuffers : Buffers)
    cipherTextLength = monad {

    let cipherText = decryptionBuffers.CipherText
    if Array.length cipherText < cipherTextLength then
        invalidArg "cipherTextLength" "Provided cipher text buffer too small"

    let! (state : State) = State.get |> StateT.hoist
    let mutable s = state.State
    let mutable tag = 0uy

    let result =
        Interop.crypto_secretstream_xchacha20poly1305_pull(
            &s,
            decryptionBuffers.PlainText,
            IntPtr.Zero,
            &tag,
            cipherText,
            uint64 cipherTextLength,
            null,
            0UL)

    if result = 0 then
        do! setNewState (new State(s))
        match tag with
        | x when x = finalTag -> return Final
        | x when x = messageTag -> return Message
        | x when x = pushTag -> return Push
        | x when x = rekeyTag -> return Rekey
        | _ -> return failwith "Received an unexpected message tag from libsodium"
    else return! (SodiumError result) |> Error |> StateT.lift
}
let decryptPart cipherText = monad {
    let buffers = buffersFactory.FromCipherText cipherText
    GC.SuppressFinalize buffers
    let cipherTextLength = Array.length cipherText
    let! messageType = decryptPartTo buffers cipherTextLength
    return messageType, buffers.PlainText
}
let getCipherTextStreamLength (ChunkLength chunkLength) plainTextStreamLength =
    let cipherLength = buffersFactory.GetCipherTextLength
    if plainTextStreamLength <= 0 then 0 else
    plainTextStreamLength / chunkLength * cipherLength chunkLength +
    cipherLength (plainTextStreamLength % chunkLength)
let getPlainTextStreamLength (ChunkLength chunkLength) cipherTextStreamLength =
    if cipherTextStreamLength <= 0 then 0 else
    let encryptedChunkLength =
        buffersFactory.GetCipherTextLength chunkLength
    cipherTextStreamLength / encryptedChunkLength * chunkLength +
    buffersFactory.GetPlainTextLength
        (cipherTextStreamLength % encryptedChunkLength)

type private ReaderState = NotDone | Done
let private readFromStream (inputStream : Stream) buffer =
    try
        let readBytes = inputStream.Read(buffer, 0, Array.length buffer)
        let state = if inputStream.Position < inputStream.Length
                    then NotDone else Done
        Ok (readBytes, state)
    with | :? IOException as exn -> Error exn
let private writeToStream (outputStream : Stream) (buffer, count) =
    try outputStream.Write(buffer, 0, count) |> Ok
    with | :? IOException as exn -> Error exn

let encryptStream key (ChunkLength chunkLength) input output = monad.strict {
    let encryptionBuffers = buffersFactory.FromPlainTextLength(chunkLength)
    use _ = new Secret (encryptionBuffers.PlainText)
    let read () =
        readFromStream input encryptionBuffers.PlainText
        |> first StreamEncryptionError.ReadError
        |> StateT.lift

    let write cipherTextLength =
        writeToStream output (encryptionBuffers.CipherText, cipherTextLength)
        |> first StreamEncryptionError.WriteError
        |> StateT.lift

    let! header, state =
        createEncryptionState key
        |> first StreamEncryptionError.StateInitializationError

    let encrypt =
        uncurry (encryptPartTo encryptionBuffers)
        >> fun state ->
            StateT.run state
            >> first StreamEncryptionError.EncryptionError
            |> StateT
        |> curry

    let rec inner count = monad {
        let! readBytes, state = read ()
        let messageType =
            match state with
            | NotDone -> Message
            | Done -> Final
        let cipherTextLength = buffersFactory.GetCipherTextLength readBytes
        do! encrypt messageType readBytes
        do! write cipherTextLength
        match messageType with
        | Final -> return ()
        | _ -> return! inner (count + readBytes)
    }

    do! StateT.run (inner 0) state |>> fst

    return header
}

let decryptStream settings (ChunkLength chunkLength) input output = monad.strict {
    let decryptionBuffers = buffersFactory.FromPlainTextLength(chunkLength)
    use _ = new Secret (decryptionBuffers.PlainText)

    let read () =
        readFromStream input decryptionBuffers.CipherText
        |> first StreamDecryptionError.ReadError
        |> StateT.lift

    let write plainTextLength =
        writeToStream output (decryptionBuffers.PlainText, plainTextLength)
        |> first StreamDecryptionError.WriteError
        |> StateT.lift

    let! state =
        createDecryptionState settings
        |> first StreamDecryptionError.StateInitializationError

    let decrypt =
        decryptPartTo decryptionBuffers
        >> fun state ->
            StateT.run state
            >> first StreamDecryptionError.DecryptionError
            |> StateT

    let rec inner () = monad {
        let! readBytes, state = read ()
        let plainTextLength = buffersFactory.GetPlainTextLength readBytes
        let! messageType = decrypt readBytes
        do! write plainTextLength
        match messageType, state with
        | Final, _ -> return ()
        | _, Done -> return! Error IncompleteStream |> StateT.lift
        | _, NotDone -> return! inner ()
    }

    do! StateT.run (inner ()) state |>> fst
}
