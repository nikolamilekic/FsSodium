[<RequireQualifiedAccess>]
module FsSodium.StreamEncryption

open System
open FSharpPlus
open FSharpPlus.Data

let internal macLength =
    lazy (Interop.crypto_secretstream_xchacha20poly1305_abytes() |> int)
let private keyLength =
    lazy (Interop.crypto_secretstream_xchacha20poly1305_keybytes() |> int)
let private headerLength =
    lazy (Interop.crypto_secretstream_xchacha20poly1305_headerbytes() |> int)
let private messageTag = lazy Interop.crypto_secretstream_xchacha20poly1305_tag_message()
let private finalTag = lazy Interop.crypto_secretstream_xchacha20poly1305_tag_final()
let private rekeyTag = lazy Interop.crypto_secretstream_xchacha20poly1305_tag_rekey()
let private pushTag = lazy Interop.crypto_secretstream_xchacha20poly1305_tag_push()

type Key private (key) =
    inherit Secret(key)
    static member Generate() =
        Sodium.initialize ()
        let key = new Key(Array.zeroCreate keyLength.Value)
        Interop.crypto_secretstream_xchacha20poly1305_keygen(key.Get)
        key
    static member Import x =
        Sodium.initialize ()
        if Array.length x <> keyLength.Value then Error () else Ok <| new Key(x)
type Header = private | Header of byte[] with
    static member Validate x =
        Sodium.initialize ()
        if Array.length x <> headerLength.Value then Error () else Ok <| Header x
    member this.Get = let (Header x) = this in x

type State internal (state : Interop.crypto_secretstream_xchacha20poly1305_state) =
    member internal __.State = state
    member __.Dispose() =
        Sodium.initialize ()
        let clear x =
            if not (isNull x) then
                Interop.sodium_memzero(x, Array.length x |> uint32)
        clear state.k
        clear state.nonce
        clear state._pad
    override this.Finalize() = this.Dispose()
    interface IDisposable with member this.Dispose() = this.Dispose()

let createEncryptionState(key : Key) =
    Sodium.initialize ()
    let mutable s = Interop.crypto_secretstream_xchacha20poly1305_state()
    let header = Array.zeroCreate headerLength.Value
    let result =
        Interop.crypto_secretstream_xchacha20poly1305_init_push(
            &s,
            header,
            key.Get)
    if result = 0
    then Ok (Header header, new State(s))
    else Error <| SodiumError result
let createDecryptionState(key : Key, Header header) =
    Sodium.initialize ()
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

let makeBuffersFactory () =
    Sodium.initialize ()
    BuffersFactory(macLength.Value)

let setNewState newState = monad {
    let! (oldState : State) = State.get |> StateT.hoist
    oldState.Dispose()
    do! (State.put newState) |> StateT.hoist
}
let encryptPartTo
    (encryptionBuffers : Buffers)
    messageType
    plainTextLength = monad {

    Sodium.initialize ()

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
        |> fun x -> x.Force()
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
let encryptPart messageType plainText = monad {
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromPlainText plainText
    let plainTextLength = Array.length plainText
    do! encryptPartTo buffers messageType plainTextLength
    return buffers.CipherText
}
let decryptPartTo
    (decryptionBuffers : Buffers)
    cipherTextLength = monad {

    Sodium.initialize ()

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
        | x when x = finalTag.Value -> return Final
        | x when x = messageTag.Value -> return Message
        | x when x = pushTag.Value -> return Push
        | x when x = rekeyTag.Value -> return Rekey
        | _ -> return failwith "Received an unexpected message tag from libsodium"
    else return! (SodiumError result) |> Error |> StateT.lift
}
let decryptPart cipherText = monad {
    let buffersFactory = makeBuffersFactory ()
    let buffers = buffersFactory.FromCipherText cipherText
    GC.SuppressFinalize buffers
    let cipherTextLength = Array.length cipherText
    let! messageType = decryptPartTo buffers cipherTextLength
    return messageType, buffers.PlainText
}
