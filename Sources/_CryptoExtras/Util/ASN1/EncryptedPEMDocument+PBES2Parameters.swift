//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

extension EncryptedPEMDocument {
    struct PBES2Parameters: DERParseable {
        static var defaultIdentifier: ASN1Identifier { .sequence }
        
        let keyDerivationFunction: PBKDF2
        let encryptionScheme: EncryptionScheme
        
        init(keyDerivationFunction: PBKDF2, encryptionScheme: EncryptionScheme) {
            self.keyDerivationFunction = keyDerivationFunction
            self.encryptionScheme = encryptionScheme
        }
        
        init(derEncoded node: ASN1Node) throws {
            self = try DER.sequence(node, identifier: .sequence) { nodes in
                let keyDerivationFunction = try PBKDF2(derEncoded: &nodes)
                let encryptionScheme = try EncryptionScheme(derEncoded: &nodes)
                
                return .init(keyDerivationFunction: keyDerivationFunction, encryptionScheme: encryptionScheme)
            }
        }
    }
}
