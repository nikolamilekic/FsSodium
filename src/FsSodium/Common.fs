namespace FsSodium

type PlainText = PlainText of byte[]

module Sodium =
    let initialize() =
        if Interop.sodium_init() = -1
        then failwith "Could not initialize Sodium"
