module internal FsSodium.Interop

open System
open System.Runtime.InteropServices

[<StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)>]
type crypto_secretstream_xchacha20poly1305_state =
    struct
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)>]
        val k : byte[]

        [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)>]
        val nonce : byte[]

        [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)>]
        val _pad : byte[]
    end

[<Literal>]
let Name = "libsodium"

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_init()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_sign_publickeybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_sign_secretkeybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_sign_bytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_detached(
    byte[] tag,
    IntPtr tagLength,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_verify_detached(
    byte[] tag,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] publicKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_keypair(byte[] publicKey, byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_sign_ed25519_sk_to_pk(byte[] publicKey, byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_box_publickeybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_box_secretkeybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_box_macbytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_box_noncebytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_easy(
    byte[] cipherText,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] nonce,
    byte[] publicKey,
    byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_open_easy(
    byte[] plainText,
    byte[] cipherText,
    uint64 cipherTextLength,
    byte[] nonce,
    byte[] publicKey,
    byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_keypair(byte[] publicKey, byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_scalarmult_base(byte[] publicKey, byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern void randombytes_buf(byte[] buffer, uint32 bufferLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_mlock(
    byte[] array,
    uint32 length)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int sodium_munlock(
    byte[] array,
    uint32 length)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
    extern void sodium_memzero(byte[] array, uint32 length)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_pwhash_alg_default()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_saltbytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]

extern uint64 crypto_pwhash_opslimit_min()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint64 crypto_pwhash_opslimit_max()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint64 crypto_pwhash_opslimit_interactive()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint64 crypto_pwhash_opslimit_moderate()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint64 crypto_pwhash_opslimit_sensitive()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_memlimit_max()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_memlimit_min()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_memlimit_interactive()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_memlimit_moderate()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_memlimit_sensitive()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_bytes_min()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_bytes_max()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_passwd_min()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_pwhash_passwd_max()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_pwhash(
    byte[] key,
    uint64 keyLength,
    byte[] password,
    uint64 passwordLength,
    byte[] salt,
    uint64 maxNumberOfOperations,
    uint32 maxAmountOfMemoryToUse,
    int algorithm)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_secretbox_keybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_secretbox_macbytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_secretbox_noncebytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_easy(
    byte[] cipherText,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] nonce,
    byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretbox_open_easy(
    byte[] plainText,
    byte[] cipherText,
    uint64 cipherTextLength,
    byte[] nonce,
    byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern void crypto_secretbox_keygen(byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_secretstream_xchacha20poly1305_keybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_secretstream_xchacha20poly1305_headerbytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_secretstream_xchacha20poly1305_abytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern byte crypto_secretstream_xchacha20poly1305_tag_message()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern byte crypto_secretstream_xchacha20poly1305_tag_final()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern byte crypto_secretstream_xchacha20poly1305_tag_rekey()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern byte crypto_secretstream_xchacha20poly1305_tag_push()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretstream_xchacha20poly1305_push(
    crypto_secretstream_xchacha20poly1305_state& state,
    byte[] cipherText,
    IntPtr cipherTextLength,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] additionalData,
    uint64 additionalDataLength,
    byte tag)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretstream_xchacha20poly1305_pull(
    crypto_secretstream_xchacha20poly1305_state& state,
    byte[] plainText,
    IntPtr plainTextLength,
    byte& tag,
    byte[] cipherText,
    uint64 cipherTextLength,
    byte[] additionalData,
    uint64 additionalDataLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretstream_xchacha20poly1305_init_pull(
    crypto_secretstream_xchacha20poly1305_state& state,
    byte[] header,
    byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_secretstream_xchacha20poly1305_init_push(
    crypto_secretstream_xchacha20poly1305_state& state,
    byte[] header,
    byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern void crypto_secretstream_xchacha20poly1305_keygen(byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_generichash(
    byte[] hash,
    uint32 hashLength,
    byte[] input,
    uint64 inputLength,
    byte[] key,
    uint32 keyLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_keybytes_min()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_bytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_bytes_min()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_bytes_max()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_keybytes_max()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_keybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_generichash_statebytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_generichash_init(
    byte[] state,
    byte[] key,
    uint32 keyLength,
    uint32 hashLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_generichash_update(
    byte[] state,
    byte[] input,
    uint64 inputLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_generichash_final(
    byte[] state,
    byte[] output,
    uint32 outputLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern IntPtr sodium_version_string()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_hash_sha512_bytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_hash_sha512_statebytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_hash_sha512(byte[] output, byte[] input, uint64 inputLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_hash_sha512_init(byte[] state)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_hash_sha512_update(
    byte[] state, byte[] input, uint64 inputLength)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_hash_sha512_final(byte[] state, byte[] output)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_box_beforenmbytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_beforenm(
    byte[] sharedKey, byte[] publicKey, byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_open_easy_afternm(
    byte[] plainText,
    byte[] cipherText,
    uint64 cipherTextLength,
    byte[] nonce,
    byte[] sharedKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_box_easy_afternm(
    byte[] cipherText,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] nonce,
    byte[] sharedKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_auth_keybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_auth_bytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_auth(
    byte[] tag,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_auth_verify(
    byte[] tag,
    byte[] plainText,
    uint64 plainTextLength,
    byte[] secretKey)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern int crypto_stream_xor(
    byte[] output, byte[] input, uint64 length, byte[] nonce, byte[] key)

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_stream_keybytes()

[<DllImport(Name, CallingConvention = CallingConvention.Cdecl)>]
extern uint32 crypto_stream_noncebytes()
