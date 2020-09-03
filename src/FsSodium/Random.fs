module FsSodium.Random

let bytes count =
    Sodium.initialize ()
    let result = Array.zeroCreate count
    Interop.randombytes_buf (result, uint32 count)
    result
