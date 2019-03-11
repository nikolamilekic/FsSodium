module FsSodium.Random

let bytes count =
    let result = Array.zeroCreate count
    Interop.randombytes_buf (result, uint64 count)
    result
