// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// AES-256-GCM for the Apple e2ee backend.
//
// CryptoKit is Swift-only, so these two thin wrappers are the C entry points that
// e2ee_aes_gcm_apple.c calls. They exist so the backend does not have to declare
// Apple's undocumented CCCryptorGCMOneshot* SPI: everything used here is public API.
//
// @_cdecl is an underscored attribute, but it is the only way to give a Swift function
// C linkage in the shipping toolchain (the evolution-approved @cdecl is not yet in
// Apple's Swift 6.3). Both functions are leaf, allocation-light and re-entrant: they hold
// no state between calls, so they are safe to call from any thread.

import Foundation
import CryptoKit

/// AES-256-GCM seal. `ciphertext` receives `ptLen` bytes, `tag` receives 16.
/// Returns 0 on success, -1 on failure.
@_cdecl("ziti_cryptokit_aes_gcm_seal")
func zitiCryptoKitAesGcmSeal(_ key: UnsafePointer<UInt8>, _ keyLen: Int,
                             _ nonce: UnsafePointer<UInt8>, _ nonceLen: Int,
                             _ plaintext: UnsafePointer<UInt8>?, _ ptLen: Int,
                             _ ciphertext: UnsafeMutablePointer<UInt8>,
                             _ tag: UnsafeMutablePointer<UInt8>,
                             _ tagLen: Int) -> Int32 {
    let key = SymmetricKey(data: UnsafeRawBufferPointer(start: key, count: keyLen))
    guard let nonce = try? AES.GCM.Nonce(data: UnsafeRawBufferPointer(start: nonce, count: nonceLen)) else {
        return -1
    }

    // an empty payload is legal and arrives as (NULL, 0); CryptoKit traps on a null base
    // pointer even at zero length, so it gets an empty Data instead of a raw buffer
    let sealed: AES.GCM.SealedBox?
    if let plaintext, ptLen > 0 {
        sealed = try? AES.GCM.seal(UnsafeRawBufferPointer(start: plaintext, count: ptLen),
                                   using: key, nonce: nonce)
    } else {
        sealed = try? AES.GCM.seal(Data(), using: key, nonce: nonce)
    }
    guard let sealed, sealed.tag.count == tagLen else {
        return -1
    }

    if ptLen > 0 {
        sealed.ciphertext.copyBytes(to: UnsafeMutableRawBufferPointer(start: ciphertext, count: ptLen))
    }
    sealed.tag.copyBytes(to: UnsafeMutableRawBufferPointer(start: tag, count: tagLen))
    return 0
}

/// AES-256-GCM open. `plaintext` receives `ctLen` bytes on success.
/// Returns 0 on success, -1 if the tag does not verify or any input is malformed.
@_cdecl("ziti_cryptokit_aes_gcm_open")
func zitiCryptoKitAesGcmOpen(_ key: UnsafePointer<UInt8>, _ keyLen: Int,
                             _ nonce: UnsafePointer<UInt8>, _ nonceLen: Int,
                             _ ciphertext: UnsafePointer<UInt8>?, _ ctLen: Int,
                             _ tag: UnsafePointer<UInt8>, _ tagLen: Int,
                             _ plaintext: UnsafeMutablePointer<UInt8>) -> Int32 {
    let key = SymmetricKey(data: UnsafeRawBufferPointer(start: key, count: keyLen))
    guard let nonce = try? AES.GCM.Nonce(data: UnsafeRawBufferPointer(start: nonce, count: nonceLen)) else {
        return -1
    }

    // see the note in seal: (NULL, 0) must not reach CryptoKit as a null base pointer
    let tagBuffer = UnsafeRawBufferPointer(start: tag, count: tagLen)
    let sealed: AES.GCM.SealedBox?
    if let ciphertext, ctLen > 0 {
        sealed = try? AES.GCM.SealedBox(nonce: nonce,
                                        ciphertext: UnsafeRawBufferPointer(start: ciphertext, count: ctLen),
                                        tag: tagBuffer)
    } else {
        sealed = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: Data(), tag: tagBuffer)
    }

    // open throws on tag mismatch, which is the authentication check
    guard let sealed, let opened = try? AES.GCM.open(sealed, using: key) else {
        return -1
    }

    if ctLen > 0 {
        opened.copyBytes(to: UnsafeMutableRawBufferPointer(start: plaintext, count: ctLen))
    }
    return 0
}
