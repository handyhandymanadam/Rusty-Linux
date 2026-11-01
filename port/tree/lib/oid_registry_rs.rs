// SPDX-License-Identifier: GPL-2.0-or-later

//! ASN.1 Object Identifier (OID) registry -- the Rust behind
//! `lib/oid_registry.c`.
//!
//! Ported from `lib/oid_registry.c` (6.18.49), Copyright (C) 2012 Red Hat,
//! Inc. Written by David Howells.
//!
//! Replaces: lib/oid_registry.c
//!
//! # The tables are generated from the same generator upstream uses, not
//! # transcribed from its output by hand
//!
//! `lib/oid_registry_data.c` is itself machine-generated at build time
//! (`lib/build_OID_registry`, from `include/linux/oid_registry.h`) -- it
//! is not shipped in the tarball, matching `logs/porting-hazards.md`'s
//! "header the tarball doesn't ship" hazard class. `OID_INDEX`/`OID_DATA`/
//! `OID_SEARCH_TABLE` and the `Oid` enum below were produced by parsing
//! the ALREADY-GENERATED `oid_registry_data.c` (a build artifact, not
//! upstream source) and the compiled object's own captured DWARF enum
//! listing (`logs/pins/oid_registry.pins`) with a script, then emitting
//! Rust array/enum literals directly -- the same discipline as
//! `errname_rs.rs`'s tables, extended to a generated-data source instead
//! of a header. Transcribing ~100 enum variants and a 735-byte data table
//! by hand invites exactly the kind of one-character slip this project's
//! whole `//! sourced from headers, not the C literal` convention exists
//! to avoid.
//!
//! # `oid_search_table`'s hash+size+reverse-byte binary search is a
//! # structural translation, not a rewrite
//!
//! `look_up_oid()` reproduces the C's control flow exactly, including its
//! `goto next` exits from three-way comparisons -- each one is a `continue`
//! back to the `while` condition in both languages, so no restructuring
//! was needed beyond replacing labelled `goto`s with ordinary loop
//! `continue`s.
//!
//! # `hash = datasize - 1` wraps on an empty input, and that's kept
//!
//! With `datasize == 0` the C computes `(size_t)0 - 1` (a well-defined
//! wraparound to `SIZE_MAX`) and truncates it into a 32-bit `unsigned`
//! when stored into `hash`. `datasize.wrapping_sub(1) as u32` reproduces
//! precisely that: wrap first at full width, then truncate -- not
//! `checked_sub` or a bounds check, since the C has neither and an OID
//! lookup on zero bytes is a real, valid call this function must not
//! panic on.
//!
//! # `sprint_oid()`'s formatting is hand-written, not a `snprintf` FFI call
//!
//! The C builds its output with the kernel's own `snprintf()`. Rather than
//! declare a variadic FFI binding (a new, untested pattern in this port)
//! for two format strings, decimal formatting is done directly with a
//! small fixed-size scratch buffer and manual division-by-10, and
//! `snprintf_str()` below reproduces just the two properties callers
//! depend on: truncate to `bufsize - 1` content bytes plus a NUL, but
//! always return the FULL untruncated length (so a caller sizing a buffer
//! from the return value gets the right answer even after a truncated
//! first call) -- exactly `snprintf`'s contract, no more of it.
//!
//! # `rig/uaccess-panic-check.sh`: every `+`/`-` here is `wrapping_*`
//!
//! All are `size_t`-or-narrower unsigned in the pristine C. One
//! `panic_bounds_check` remains, investigated rather than silenced:
//! `look_up_oid()`'s binary search (`OID_SEARCH_TABLE[j]`,
//! `OID_DATA[base + l]`) is the standard `lo <= j < hi` binary-search
//! invariant (`j = (i + k) / 2` with `i < k` maintained as the loop
//! condition), and `OID_INDEX[oid_val + 1]` relies on the generated
//! `OID_INDEX` table having exactly `OID__NR + 1` entries for this exact
//! purpose (`include/generated/oid_registry_data.h`, upstream's own
//! generator, unmodified). `data[l]` is safe because the search only
//! reaches that comparison after `len == datasize` is already confirmed
//! (the `len != datasize` cases both `continue` first). Standard,
//! provably-in-range indexing rustc cannot prove across the loop, not a
//! defect -- and reproducing it with a wrapping cast instead would trade
//! a panic for a silent wrong OID match, strictly worse.

use core::ffi::c_int;

const ASN1_OID: u8 = 6;
/// `-EBADMSG`.
const EBADMSG: c_int = 74;
/// `-ENOBUFS`.
const ENOBUFS: c_int = 105;

// Each variant's name IS its documentation -- e.g. `OID_sha256` needs no
// comment repeating "the sha256 OID" -- so missing_docs is allowed here
// rather than adding 104 one-line restatements of the identifier.
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Oid {
    OID_id_dsa_with_sha1 = 0,
    OID_id_dsa = 1,
    OID_id_ecPublicKey = 2,
    OID_id_prime192v1 = 3,
    OID_id_prime256v1 = 4,
    OID_id_ecdsa_with_sha1 = 5,
    OID_id_ecdsa_with_sha224 = 6,
    OID_id_ecdsa_with_sha256 = 7,
    OID_id_ecdsa_with_sha384 = 8,
    OID_id_ecdsa_with_sha512 = 9,
    OID_rsaEncryption = 10,
    OID_sha1WithRSAEncryption = 11,
    OID_sha256WithRSAEncryption = 12,
    OID_sha384WithRSAEncryption = 13,
    OID_sha512WithRSAEncryption = 14,
    OID_sha224WithRSAEncryption = 15,
    OID_data = 16,
    OID_signed_data = 17,
    OID_email_address = 18,
    OID_contentType = 19,
    OID_messageDigest = 20,
    OID_signingTime = 21,
    OID_smimeCapabilites = 22,
    OID_smimeAuthenticatedAttrs = 23,
    OID_mskrb5 = 24,
    OID_krb5 = 25,
    OID_krb5u2u = 26,
    OID_msIndirectData = 27,
    OID_msStatementType = 28,
    OID_msSpOpusInfo = 29,
    OID_msPeImageDataObjId = 30,
    OID_msIndividualSPKeyPurpose = 31,
    OID_msOutlookExpress = 32,
    OID_ntlmssp = 33,
    OID_negoex = 34,
    OID_spnego = 35,
    OID_IAKerb = 36,
    OID_PKU2U = 37,
    OID_Scram = 38,
    OID_certAuthInfoAccess = 39,
    OID_sha1 = 40,
    OID_id_ansip384r1 = 41,
    OID_id_ansip521r1 = 42,
    OID_sha256 = 43,
    OID_sha384 = 44,
    OID_sha512 = 45,
    OID_sha224 = 46,
    OID_commonName = 47,
    OID_surname = 48,
    OID_countryName = 49,
    OID_locality = 50,
    OID_stateOrProvinceName = 51,
    OID_organizationName = 52,
    OID_organizationUnitName = 53,
    OID_title = 54,
    OID_description = 55,
    OID_name = 56,
    OID_givenName = 57,
    OID_initials = 58,
    OID_generationalQualifier = 59,
    OID_subjectKeyIdentifier = 60,
    OID_keyUsage = 61,
    OID_subjectAltName = 62,
    OID_issuerAltName = 63,
    OID_basicConstraints = 64,
    OID_crlDistributionPoints = 65,
    OID_certPolicies = 66,
    OID_authorityKeyIdentifier = 67,
    OID_extKeyUsage = 68,
    OID_NetlogonMechanism = 69,
    OID_appleLocalKdcSupported = 70,
    OID_gostCPSignA = 71,
    OID_gostCPSignB = 72,
    OID_gostCPSignC = 73,
    OID_gost2012PKey256 = 74,
    OID_gost2012PKey512 = 75,
    OID_gost2012Digest256 = 76,
    OID_gost2012Digest512 = 77,
    OID_gost2012Signature256 = 78,
    OID_gost2012Signature512 = 79,
    OID_gostTC26Sign256A = 80,
    OID_gostTC26Sign256B = 81,
    OID_gostTC26Sign256C = 82,
    OID_gostTC26Sign256D = 83,
    OID_gostTC26Sign512A = 84,
    OID_gostTC26Sign512B = 85,
    OID_gostTC26Sign512C = 86,
    OID_sm2 = 87,
    OID_sm3 = 88,
    OID_SM2_with_SM3 = 89,
    OID_sm3WithRSAEncryption = 90,
    OID_TPMLoadableKey = 91,
    OID_TPMImportableKey = 92,
    OID_TPMSealedData = 93,
    OID_sha3_256 = 94,
    OID_sha3_384 = 95,
    OID_sha3_512 = 96,
    OID_id_ecdsa_with_sha3_256 = 97,
    OID_id_ecdsa_with_sha3_384 = 98,
    OID_id_ecdsa_with_sha3_512 = 99,
    OID_id_rsassa_pkcs1_v1_5_with_sha3_256 = 100,
    OID_id_rsassa_pkcs1_v1_5_with_sha3_384 = 101,
    OID_id_rsassa_pkcs1_v1_5_with_sha3_512 = 102,
    OID__NR = 103,
}

const OID_INDEX: [u16; 104] = [
    0, // OID_id_dsa_with_sha1
    7, // OID_id_dsa
    14, // OID_id_ecPublicKey
    21, // OID_id_prime192v1
    29, // OID_id_prime256v1
    37, // OID_id_ecdsa_with_sha1
    44, // OID_id_ecdsa_with_sha224
    52, // OID_id_ecdsa_with_sha256
    60, // OID_id_ecdsa_with_sha384
    68, // OID_id_ecdsa_with_sha512
    76, // OID_rsaEncryption
    85, // OID_sha1WithRSAEncryption
    94, // OID_sha256WithRSAEncryption
    103, // OID_sha384WithRSAEncryption
    112, // OID_sha512WithRSAEncryption
    121, // OID_sha224WithRSAEncryption
    130, // OID_data
    139, // OID_signed_data
    148, // OID_email_address
    157, // OID_contentType
    166, // OID_messageDigest
    175, // OID_signingTime
    184, // OID_smimeCapabilites
    193, // OID_smimeAuthenticatedAttrs
    204, // OID_mskrb5
    213, // OID_krb5
    222, // OID_krb5u2u
    232, // OID_msIndirectData
    242, // OID_msStatementType
    252, // OID_msSpOpusInfo
    262, // OID_msPeImageDataObjId
    272, // OID_msIndividualSPKeyPurpose
    282, // OID_msOutlookExpress
    291, // OID_ntlmssp
    301, // OID_negoex
    311, // OID_spnego
    317, // OID_IAKerb
    323, // OID_PKU2U
    329, // OID_Scram
    335, // OID_certAuthInfoAccess
    343, // OID_sha1
    348, // OID_id_ansip384r1
    353, // OID_id_ansip521r1
    358, // OID_sha256
    367, // OID_sha384
    376, // OID_sha512
    385, // OID_sha224
    394, // OID_commonName
    397, // OID_surname
    400, // OID_countryName
    403, // OID_locality
    406, // OID_stateOrProvinceName
    409, // OID_organizationName
    412, // OID_organizationUnitName
    415, // OID_title
    418, // OID_description
    421, // OID_name
    424, // OID_givenName
    427, // OID_initials
    430, // OID_generationalQualifier
    433, // OID_subjectKeyIdentifier
    436, // OID_keyUsage
    439, // OID_subjectAltName
    442, // OID_issuerAltName
    445, // OID_basicConstraints
    448, // OID_crlDistributionPoints
    451, // OID_certPolicies
    454, // OID_authorityKeyIdentifier
    457, // OID_extKeyUsage
    460, // OID_NetlogonMechanism
    466, // OID_appleLocalKdcSupported
    472, // OID_gostCPSignA
    479, // OID_gostCPSignB
    486, // OID_gostCPSignC
    493, // OID_gost2012PKey256
    501, // OID_gost2012PKey512
    509, // OID_gost2012Digest256
    517, // OID_gost2012Digest512
    525, // OID_gost2012Signature256
    533, // OID_gost2012Signature512
    541, // OID_gostTC26Sign256A
    550, // OID_gostTC26Sign256B
    559, // OID_gostTC26Sign256C
    568, // OID_gostTC26Sign256D
    577, // OID_gostTC26Sign512A
    586, // OID_gostTC26Sign512B
    595, // OID_gostTC26Sign512C
    604, // OID_sm2
    612, // OID_sm3
    620, // OID_SM2_with_SM3
    628, // OID_sm3WithRSAEncryption
    636, // OID_TPMLoadableKey
    642, // OID_TPMImportableKey
    648, // OID_TPMSealedData
    654, // OID_sha3_256
    663, // OID_sha3_384
    672, // OID_sha3_512
    681, // OID_id_ecdsa_with_sha3_256
    690, // OID_id_ecdsa_with_sha3_384
    699, // OID_id_ecdsa_with_sha3_512
    708, // OID_id_rsassa_pkcs1_v1_5_with_sha3_256
    717, // OID_id_rsassa_pkcs1_v1_5_with_sha3_384
    726, // OID_id_rsassa_pkcs1_v1_5_with_sha3_512
    735, // OID__NR
];

const OID_DATA: [u8; 735] = [
    42, 134, 72, 206, 46, 4, 3, 42, 134, 72, 206, 56, 4, 1, 42, 134,
    72, 206, 61, 2, 1, 42, 134, 72, 206, 61, 3, 1, 1, 42, 134, 72,
    206, 61, 3, 1, 7, 42, 134, 72, 206, 61, 4, 1, 42, 134, 72, 206,
    61, 4, 3, 1, 42, 134, 72, 206, 61, 4, 3, 2, 42, 134, 72, 206,
    61, 4, 3, 3, 42, 134, 72, 206, 61, 4, 3, 4, 42, 134, 72, 134,
    247, 13, 1, 1, 1, 42, 134, 72, 134, 247, 13, 1, 1, 5, 42, 134,
    72, 134, 247, 13, 1, 1, 11, 42, 134, 72, 134, 247, 13, 1, 1, 12,
    42, 134, 72, 134, 247, 13, 1, 1, 13, 42, 134, 72, 134, 247, 13, 1,
    1, 14, 42, 134, 72, 134, 247, 13, 1, 7, 1, 42, 134, 72, 134, 247,
    13, 1, 7, 2, 42, 134, 72, 134, 247, 13, 1, 9, 1, 42, 134, 72,
    134, 247, 13, 1, 9, 3, 42, 134, 72, 134, 247, 13, 1, 9, 4, 42,
    134, 72, 134, 247, 13, 1, 9, 5, 42, 134, 72, 134, 247, 13, 1, 9,
    15, 42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 11, 42, 134, 72, 130,
    247, 18, 1, 2, 2, 42, 134, 72, 134, 247, 18, 1, 2, 2, 42, 134,
    72, 134, 247, 18, 1, 2, 2, 3, 43, 6, 1, 4, 1, 130, 55, 2,
    1, 4, 43, 6, 1, 4, 1, 130, 55, 2, 1, 11, 43, 6, 1, 4,
    1, 130, 55, 2, 1, 12, 43, 6, 1, 4, 1, 130, 55, 2, 1, 15,
    43, 6, 1, 4, 1, 130, 55, 2, 1, 21, 43, 6, 1, 4, 1, 130,
    55, 16, 4, 43, 6, 1, 4, 1, 130, 55, 2, 2, 10, 43, 6, 1,
    4, 1, 130, 55, 2, 2, 30, 43, 6, 1, 5, 5, 2, 43, 6, 1,
    5, 2, 5, 43, 5, 1, 5, 2, 7, 43, 6, 1, 5, 5, 14, 43,
    6, 1, 5, 5, 7, 1, 1, 43, 14, 3, 2, 26, 43, 129, 4, 0,
    34, 43, 129, 4, 0, 35, 96, 134, 72, 1, 101, 3, 4, 2, 1, 96,
    134, 72, 1, 101, 3, 4, 2, 2, 96, 134, 72, 1, 101, 3, 4, 2,
    3, 96, 134, 72, 1, 101, 3, 4, 2, 4, 85, 4, 3, 85, 4, 4,
    85, 4, 6, 85, 4, 7, 85, 4, 8, 85, 4, 10, 85, 4, 11, 85,
    4, 12, 85, 4, 13, 85, 4, 41, 85, 4, 42, 85, 4, 43, 85, 4,
    44, 85, 29, 14, 85, 29, 15, 85, 29, 17, 85, 29, 18, 85, 29, 19,
    85, 29, 31, 85, 29, 32, 85, 29, 35, 85, 29, 37, 42, 133, 112, 43,
    14, 2, 42, 133, 112, 43, 14, 3, 42, 133, 3, 2, 2, 35, 1, 42,
    133, 3, 2, 2, 35, 2, 42, 133, 3, 2, 2, 35, 3, 42, 133, 3,
    7, 1, 1, 1, 1, 42, 133, 3, 7, 1, 1, 1, 2, 42, 133, 3,
    7, 1, 1, 2, 2, 42, 133, 3, 7, 1, 1, 2, 3, 42, 133, 3,
    7, 1, 1, 3, 2, 42, 133, 3, 7, 1, 1, 3, 3, 42, 133, 3,
    7, 1, 2, 1, 1, 1, 42, 133, 3, 7, 1, 2, 1, 1, 2, 42,
    133, 3, 7, 1, 2, 1, 1, 3, 42, 133, 3, 7, 1, 2, 1, 1,
    4, 42, 133, 3, 7, 1, 2, 1, 2, 1, 42, 133, 3, 7, 1, 2,
    1, 2, 2, 42, 133, 3, 7, 1, 2, 1, 2, 3, 42, 129, 28, 207,
    85, 1, 130, 45, 42, 129, 28, 207, 85, 1, 131, 17, 42, 129, 28, 207,
    85, 1, 131, 117, 42, 129, 28, 207, 85, 1, 131, 120, 103, 129, 5, 10,
    1, 3, 103, 129, 5, 10, 1, 4, 103, 129, 5, 10, 1, 5, 96, 134,
    72, 1, 101, 3, 4, 2, 8, 96, 134, 72, 1, 101, 3, 4, 2, 9,
    96, 134, 72, 1, 101, 3, 4, 2, 10, 96, 134, 72, 1, 101, 3, 4,
    3, 10, 96, 134, 72, 1, 101, 3, 4, 3, 11, 96, 134, 72, 1, 101,
    3, 4, 3, 12, 96, 134, 72, 1, 101, 3, 4, 3, 14, 96, 134, 72,
    1, 101, 3, 4, 3, 15, 96, 134, 72, 1, 101, 3, 4, 3, 16,
];

const OID_SEARCH_TABLE: [(u8, Oid); 103] = [
    (3, Oid::OID_id_rsassa_pkcs1_v1_5_with_sha3_256),
    (10, Oid::OID_title),
    (11, Oid::OID_spnego),
    (11, Oid::OID_IAKerb),
    (13, Oid::OID_id_ansip384r1),
    (19, Oid::OID_gostTC26Sign512C),
    (19, Oid::OID_gostTC26Sign256D),
    (23, Oid::OID_issuerAltName),
    (23, Oid::OID_initials),
    (32, Oid::OID_id_dsa_with_sha1),
    (35, Oid::OID_contentType),
    (35, Oid::OID_sha256WithRSAEncryption),
    (36, Oid::OID_authorityKeyIdentifier),
    (37, Oid::OID_description),
    (43, Oid::OID_id_dsa),
    (44, Oid::OID_id_ansip521r1),
    (44, Oid::OID_PKU2U),
    (44, Oid::OID_krb5u2u),
    (49, Oid::OID_id_ecdsa_with_sha224),
    (51, Oid::OID_msIndividualSPKeyPurpose),
    (52, Oid::OID_SM2_with_SM3),
    (54, Oid::OID_basicConstraints),
    (54, Oid::OID_generationalQualifier),
    (60, Oid::OID_gostCPSignA),
    (64, Oid::OID_TPMLoadableKey),
    (64, Oid::OID_krb5),
    (64, Oid::OID_signed_data),
    (65, Oid::OID_id_rsassa_pkcs1_v1_5_with_sha3_512),
    (76, Oid::OID_id_prime192v1),
    (77, Oid::OID_countryName),
    (77, Oid::OID_id_ecdsa_with_sha1),
    (83, Oid::OID_sha256),
    (84, Oid::OID_sm2),
    (85, Oid::OID_smimeCapabilites),
    (87, Oid::OID_sha1),
    (88, Oid::OID_sha3_384),
    (93, Oid::OID_gostCPSignB),
    (97, Oid::OID_email_address),
    (98, Oid::OID_id_rsassa_pkcs1_v1_5_with_sha3_384),
    (106, Oid::OID_extKeyUsage),
    (106, Oid::OID_msPeImageDataObjId),
    (110, Oid::OID_locality),
    (120, Oid::OID_negoex),
    (123, Oid::OID_sha3_256),
    (124, Oid::OID_gost2012PKey256),
    (126, Oid::OID_gostCPSignC),
    (126, Oid::OID_rsaEncryption),
    (130, Oid::OID_TPMSealedData),
    (132, Oid::OID_smimeAuthenticatedAttrs),
    (134, Oid::OID_Scram),
    (134, Oid::OID_id_ecdsa_with_sha3_256),
    (142, Oid::OID_id_ecPublicKey),
    (142, Oid::OID_sha224WithRSAEncryption),
    (143, Oid::OID_stateOrProvinceName),
    (145, Oid::OID_sm3WithRSAEncryption),
    (146, Oid::OID_subjectKeyIdentifier),
    (150, Oid::OID_id_ecdsa_with_sha512),
    (150, Oid::OID_id_prime256v1),
    (157, Oid::OID_gost2012PKey512),
    (157, Oid::OID_sha512),
    (160, Oid::OID_data),
    (161, Oid::OID_crlDistributionPoints),
    (161, Oid::OID_TPMImportableKey),
    (173, Oid::OID_msOutlookExpress),
    (178, Oid::OID_sha384),
    (179, Oid::OID_keyUsage),
    (179, Oid::OID_NetlogonMechanism),
    (185, Oid::OID_sha3_512),
    (190, Oid::OID_gost2012Digest256),
    (191, Oid::OID_gostTC26Sign256A),
    (195, Oid::OID_mskrb5),
    (196, Oid::OID_id_ecdsa_with_sha3_512),
    (198, Oid::OID_certPolicies),
    (200, Oid::OID_msSpOpusInfo),
    (201, Oid::OID_organizationName),
    (204, Oid::OID_messageDigest),
    (204, Oid::OID_sha384WithRSAEncryption),
    (208, Oid::OID_id_ecdsa_with_sha256),
    (208, Oid::OID_gostTC26Sign512A),
    (208, Oid::OID_gostTC26Sign256B),
    (212, Oid::OID_name),
    (213, Oid::OID_commonName),
    (213, Oid::OID_sm3),
    (223, Oid::OID_gost2012Signature256),
    (223, Oid::OID_gost2012Digest512),
    (226, Oid::OID_sha1WithRSAEncryption),
    (228, Oid::OID_certAuthInfoAccess),
    (231, Oid::OID_id_ecdsa_with_sha3_384),
    (231, Oid::OID_ntlmssp),
    (231, Oid::OID_msStatementType),
    (234, Oid::OID_organizationUnitName),
    (236, Oid::OID_appleLocalKdcSupported),
    (237, Oid::OID_signingTime),
    (237, Oid::OID_sha512WithRSAEncryption),
    (240, Oid::OID_gost2012Signature512),
    (241, Oid::OID_gostTC26Sign512B),
    (241, Oid::OID_gostTC26Sign256C),
    (244, Oid::OID_surname),
    (245, Oid::OID_subjectAltName),
    (245, Oid::OID_givenName),
    (247, Oid::OID_id_ecdsa_with_sha384),
    (252, Oid::OID_sha224),
    (255, Oid::OID_msIndirectData),
];

/// Format `n` as decimal ASCII digits into the END of `out`, returning how
/// many bytes were written (the digits occupy `out[out.len() - n..]`).
fn fmt_decimal(mut n: u64, out: &mut [u8]) -> usize {
    let mut i = out.len();
    loop {
        i = i.wrapping_sub(1);
        out[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 || i == 0 {
            break;
        }
    }
    out.len().wrapping_sub(i)
}

/// Writes `text` into `buf[..bufsize]` the way `snprintf` does: at most
/// `bufsize - 1` content bytes plus a NUL (nothing at all if `bufsize ==
/// 0`), returning the full length `text` would need with no size limit.
///
/// # Safety
/// `buf` must be valid and writable for `bufsize` bytes.
unsafe fn snprintf_str(buf: *mut u8, bufsize: usize, text: &[u8]) -> usize {
    if bufsize > 0 {
        let n = core::cmp::min(text.len(), bufsize.wrapping_sub(1));
        // SAFETY: `n < bufsize`, and the caller guarantees `buf` writable
        // for `bufsize` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(text.as_ptr(), buf, n);
            *buf.add(n) = 0;
        }
    }
    text.len()
}

/// `look_up_OID()`: hash the OID data, then binary-search
/// `OID_SEARCH_TABLE` by (hash, size, reverse-byte-order) as the C does.
fn look_up_oid(data: &[u8]) -> Oid {
    let datasize = data.len();
    let mut hash: u32 = (datasize.wrapping_sub(1)) as u32;
    for &b in data {
        hash = hash.wrapping_add((b as u32).wrapping_mul(33));
    }
    hash = (hash >> 24) ^ (hash >> 16) ^ (hash >> 8) ^ hash;
    hash &= 0xff;

    let mut i: usize = 0;
    let mut k: usize = OID_SEARCH_TABLE.len();
    while i < k {
        let j = i.wrapping_add(k) / 2;
        let (xhash, oid) = OID_SEARCH_TABLE[j];
        let xhash = xhash as u32;
        if xhash > hash {
            k = j;
            continue;
        }
        if xhash < hash {
            i = j.wrapping_add(1);
            continue;
        }

        let oid_val = oid as usize;
        let len = OID_INDEX[oid_val.wrapping_add(1)].wrapping_sub(OID_INDEX[oid_val]) as usize;
        if len > datasize {
            k = j;
            continue;
        }
        if len < datasize {
            i = j.wrapping_add(1);
            continue;
        }

        let base = OID_INDEX[oid_val] as usize;
        let mut l = len;
        let mut next_i = None;
        let mut next_k = None;
        while l > 0 {
            l = l.wrapping_sub(1);
            let a = OID_DATA[base.wrapping_add(l)];
            let b = data[l];
            if a > b {
                next_k = Some(j);
                break;
            }
            if a < b {
                next_i = Some(j.wrapping_add(1));
                break;
            }
        }
        match (next_i, next_k) {
            (None, None) => return oid,
            (Some(ni), _) => i = ni,
            (_, Some(nk)) => k = nk,
        }
    }
    Oid::OID__NR
}

kernel::kabi_export! {
    look_up_OID,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t datasize ) -> e#OID",
}

/// # Safety
/// `data` must be readable for `datasize` bytes.
#[no_mangle]
pub unsafe extern "C" fn look_up_OID(data: *const core::ffi::c_void, datasize: usize) -> Oid {
    // SAFETY: the caller guarantees `data` readable for `datasize` bytes.
    // `(NULL, 0)` is legal C and `from_raw_parts` forbids a null pointer.
    let slice: &[u8] = if datasize == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), datasize) }
    };
    look_up_oid(slice)
}

kernel::kabi_export! {
    parse_OID,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t datasize , formal_parameter pointer_type { e#OID } oid ) -> base_type int byte_size(4) encoding(5)",
}

/// `parse_OID()`: parse an OID from an ASN1_OID | length | oid bytestream.
///
/// # Safety
/// `data` must be readable for `datasize` bytes; `oid` must be valid and
/// writable.
#[no_mangle]
pub unsafe extern "C" fn parse_OID(
    data: *const core::ffi::c_void,
    datasize: usize,
    oid: *mut Oid,
) -> c_int {
    if datasize < 3 {
        return -EBADMSG;
    }
    let v = data.cast::<u8>();
    // SAFETY: `datasize >= 3`, so both bytes are within the caller's
    // guaranteed readable range.
    let (v0, v1) = unsafe { (*v, *v.add(1)) };
    if v0 != ASN1_OID || (v1 as usize) != datasize.wrapping_sub(2) {
        return -EBADMSG;
    }
    // SAFETY: `datasize >= 3`, so `datasize - 2` bytes starting at `v + 2`
    // are within the caller's guaranteed readable range.
    let slice = unsafe { core::slice::from_raw_parts(v.add(2), datasize.wrapping_sub(2)) };
    // SAFETY: the caller guarantees `oid` valid and writable.
    unsafe { *oid = look_up_oid(slice) };
    0
}

kernel::kabi_export! {
    sprint_oid,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { base_type void } } data , formal_parameter t#size_t datasize , formal_parameter pointer_type { base_type char byte_size(1) encoding(8) } buffer , formal_parameter t#size_t bufsize ) -> base_type int byte_size(4) encoding(5)",
}

/// `sprint_oid()`: render an encoded OID into `buffer` as "a.b.c.d".
///
/// # Safety
/// `data` must be readable for `datasize` bytes; `buffer` must be valid
/// and writable for `bufsize` bytes.
#[no_mangle]
pub unsafe extern "C" fn sprint_oid(
    data: *const core::ffi::c_void,
    datasize: usize,
    buffer: *mut core::ffi::c_char,
    bufsize: usize,
) -> c_int {
    let buffer = buffer.cast::<u8>();
    if datasize == 0 {
        // SAFETY: the caller guarantees `buffer` writable for `bufsize`.
        unsafe { snprintf_str(buffer, bufsize, b"(bad)") };
        return -EBADMSG;
    }

    let v = data.cast::<u8>();
    // SAFETY: the caller guarantees `data` readable for `datasize` bytes,
    // and `datasize > 0` here.
    let bytes = unsafe { core::slice::from_raw_parts(v, datasize) };
    let mut pos = 0usize;
    let mut buf = buffer;
    let mut bsz = bufsize;
    let mut total: usize = 0;

    let n0 = bytes[pos];
    pos = pos.wrapping_add(1);
    let mut scratch = [0u8; 24];
    let mut tmp = [0u8; 12];
    let mut len = fmt_decimal((n0 / 40) as u64, &mut tmp);
    scratch[..len].copy_from_slice(&tmp[(12usize).wrapping_sub(len)..]);
    scratch[len] = b'.';
    len = len.wrapping_add(1);
    let n = fmt_decimal((n0 % 40) as u64, &mut tmp);
    scratch[len..len.wrapping_add(n)].copy_from_slice(&tmp[(12usize).wrapping_sub(n)..]);
    len = len.wrapping_add(n);

    // SAFETY: `buf` is valid and writable for `bsz` (== `bufsize`) bytes.
    let count = unsafe { snprintf_str(buf, bsz, &scratch[..len]) };
    total = total.wrapping_add(count);
    if count >= bsz {
        return -ENOBUFS;
    }
    // SAFETY: `count < bsz`, so this stays within the original buffer.
    buf = unsafe { buf.add(count) };
    bsz = bsz.wrapping_sub(count);

    while pos < bytes.len() {
        let mut n = bytes[pos];
        pos = pos.wrapping_add(1);
        let num: u64;
        if n & 0x80 == 0 {
            num = n as u64;
        } else {
            let mut acc: u64 = (n & 0x7f) as u64;
            loop {
                if pos >= bytes.len() {
                    // Matches the C exactly: `goto bad` there writes
                    // through the LOCAL `buffer`/`bufsize`, already
                    // advanced past whatever components were written
                    // before this one -- not the original start of the
                    // caller's buffer. `buf`/`bsz` are that same
                    // advancing cursor here.
                    //
                    // SAFETY: `buf` is valid and writable for `bsz`
                    // bytes (a suffix of the caller-guaranteed `buffer`).
                    unsafe { snprintf_str(buf, bsz, b"(bad)") };
                    return -EBADMSG;
                }
                n = bytes[pos];
                pos = pos.wrapping_add(1);
                acc = (acc << 7) | (n & 0x7f) as u64;
                if n & 0x80 == 0 {
                    break;
                }
            }
            num = acc;
        }

        let mut tmp20 = [0u8; 20];
        let n_digits = fmt_decimal(num, &mut tmp20);
        scratch[0] = b'.';
        scratch[1..1usize.wrapping_add(n_digits)].copy_from_slice(&tmp20[(20usize).wrapping_sub(n_digits)..]);
        let seg_len = 1usize.wrapping_add(n_digits);

        // SAFETY: `buf` is valid and writable for `bsz` bytes.
        let count = unsafe { snprintf_str(buf, bsz, &scratch[..seg_len]) };
        total = total.wrapping_add(count);
        if count >= bsz {
            return -ENOBUFS;
        }
        // SAFETY: `count < bsz`, so this stays within the original buffer.
        buf = unsafe { buf.add(count) };
        bsz = bsz.wrapping_sub(count);
    }

    total as c_int
}

// The C types these contracts name.
// Generated by rig/kabi-pin.sh --capture; do not hand-edit.
kernel::kabi_rule!("type_string", "e#OID",
    "enumeration_type OID { enumerator OID_id_dsa_with_sha1 = 0 , enumerator OID_id_dsa = 1 , enumerator OID_id_ecPublicKey = 2 , enumerator OID_id_prime192v1 = 3 , enumerator OID_id_prime256v1 = 4 , enumerator OID_id_ecdsa_with_sha1 = 5 , enumerator OID_id_ecdsa_with_sha224 = 6 , enumerator OID_id_ecdsa_with_sha256 = 7 , enumerator OID_id_ecdsa_with_sha384 = 8 , enumerator OID_id_ecdsa_with_sha512 = 9 , enumerator OID_rsaEncryption = 10 , enumerator OID_sha1WithRSAEncryption = 11 , enumerator OID_sha256WithRSAEncryption = 12 , enumerator OID_sha384WithRSAEncryption = 13 , enumerator OID_sha512WithRSAEncryption = 14 , enumerator OID_sha224WithRSAEncryption = 15 , enumerator OID_data = 16 , enumerator OID_signed_data = 17 , enumerator OID_email_address = 18 , enumerator OID_contentType = 19 , enumerator OID_messageDigest = 20 , enumerator OID_signingTime = 21 , enumerator OID_smimeCapabilites = 22 , enumerator OID_smimeAuthenticatedAttrs = 23 , enumerator OID_mskrb5 = 24 , enumerator OID_krb5 = 25 , enumerator OID_krb5u2u = 26 , enumerator OID_msIndirectData = 27 , enumerator OID_msStatementType = 28 , enumerator OID_msSpOpusInfo = 29 , enumerator OID_msPeImageDataObjId = 30 , enumerator OID_msIndividualSPKeyPurpose = 31 , enumerator OID_msOutlookExpress = 32 , enumerator OID_ntlmssp = 33 , enumerator OID_negoex = 34 , enumerator OID_spnego = 35 , enumerator OID_IAKerb = 36 , enumerator OID_PKU2U = 37 , enumerator OID_Scram = 38 , enumerator OID_certAuthInfoAccess = 39 , enumerator OID_sha1 = 40 , enumerator OID_id_ansip384r1 = 41 , enumerator OID_id_ansip521r1 = 42 , enumerator OID_sha256 = 43 , enumerator OID_sha384 = 44 , enumerator OID_sha512 = 45 , enumerator OID_sha224 = 46 , enumerator OID_commonName = 47 , enumerator OID_surname = 48 , enumerator OID_countryName = 49 , enumerator OID_locality = 50 , enumerator OID_stateOrProvinceName = 51 , enumerator OID_organizationName = 52 , enumerator OID_organizationUnitName = 53 , enumerator OID_title = 54 , enumerator OID_description = 55 , enumerator OID_name = 56 , enumerator OID_givenName = 57 , enumerator OID_initials = 58 , enumerator OID_generationalQualifier = 59 , enumerator OID_subjectKeyIdentifier = 60 , enumerator OID_keyUsage = 61 , enumerator OID_subjectAltName = 62 , enumerator OID_issuerAltName = 63 , enumerator OID_basicConstraints = 64 , enumerator OID_crlDistributionPoints = 65 , enumerator OID_certPolicies = 66 , enumerator OID_authorityKeyIdentifier = 67 , enumerator OID_extKeyUsage = 68 , enumerator OID_NetlogonMechanism = 69 , enumerator OID_appleLocalKdcSupported = 70 , enumerator OID_gostCPSignA = 71 , enumerator OID_gostCPSignB = 72 , enumerator OID_gostCPSignC = 73 , enumerator OID_gost2012PKey256 = 74 , enumerator OID_gost2012PKey512 = 75 , enumerator OID_gost2012Digest256 = 76 , enumerator OID_gost2012Digest512 = 77 , enumerator OID_gost2012Signature256 = 78 , enumerator OID_gost2012Signature512 = 79 , enumerator OID_gostTC26Sign256A = 80 , enumerator OID_gostTC26Sign256B = 81 , enumerator OID_gostTC26Sign256C = 82 , enumerator OID_gostTC26Sign256D = 83 , enumerator OID_gostTC26Sign512A = 84 , enumerator OID_gostTC26Sign512B = 85 , enumerator OID_gostTC26Sign512C = 86 , enumerator OID_sm2 = 87 , enumerator OID_sm3 = 88 , enumerator OID_SM2_with_SM3 = 89 , enumerator OID_sm3WithRSAEncryption = 90 , enumerator OID_TPMLoadableKey = 91 , enumerator OID_TPMImportableKey = 92 , enumerator OID_TPMSealedData = 93 , enumerator OID_sha3_256 = 94 , enumerator OID_sha3_384 = 95 , enumerator OID_sha3_512 = 96 , enumerator OID_id_ecdsa_with_sha3_256 = 97 , enumerator OID_id_ecdsa_with_sha3_384 = 98 , enumerator OID_id_ecdsa_with_sha3_512 = 99 , enumerator OID_id_rsassa_pkcs1_v1_5_with_sha3_256 = 100 , enumerator OID_id_rsassa_pkcs1_v1_5_with_sha3_384 = 101 , enumerator OID_id_rsassa_pkcs1_v1_5_with_sha3_512 = 102 , enumerator OID__NR = 103 } byte_size(4)");
kernel::kabi_rule!("type_string", "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }");
kernel::kabi_rule!("type_string", "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }");
kernel::kabi_rule!("type_string", "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }");

// Module build (logs/riscv64.md failure 3; riscv defconfig has this library =m): the C's
// MODULE_DESCRIPTION()/MODULE_LICENSE() went away with the C file, and modpost refuses a module
// without a license. UNPREFIXED tags, as md5_rs.rs. Built-in (=y, every x86 config) emits
// nothing here, unchanged.
#[cfg(MODULE)]
core::arch::global_asm!(
    ".section \".modinfo\",\"a\"",
    ".asciz \"description=OID Registry\"",
    ".asciz \"license=GPL\"",
    ".previous",
);
