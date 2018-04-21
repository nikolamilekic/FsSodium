namespace FsSodium

type PlainText = PlainTextBytes of byte[]
type CipherText = CipherTextBytes of byte[]
type SignedText = SignedTextBytes of byte[]

module Sodium =
    let initialize() =
        if Interop.sodium_init() = -1
        then failwith "Could not initialize Sodium"