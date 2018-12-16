module FsSodium.Random

let bytes count =
    let result = Array.zeroCreate count
    Interop.randombytes_buf (result, int64 count)
    result
