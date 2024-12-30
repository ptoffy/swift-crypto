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
    protocol KeyDerivationFunction: DERParseable {
        associatedtype Parameters: KeyDerivationFunctionParameters
        
        var algorithm: ASN1ObjectIdentifier { get }
        var parameters: Parameters { get }
        
        init(derEncoded node: ASN1Node) throws
        
        init(parameters: Parameters)
    }
    
    protocol KeyDerivationFunctionParameters: DERParseable {}
}

extension EncryptedPEMDocument.KeyDerivationFunction {
    init(derEncoded node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: .sequence) { nodes in
            let parameters = try Parameters(derEncoded: &nodes)
            
            return .init(parameters: parameters)
        }
    }
}

extension EncryptedPEMDocument {
    struct PBKDF2: KeyDerivationFunction {
        var algorithm: ASN1ObjectIdentifier { .pkcs5PBKDF2 }
        let parameters: EncryptedPEMDocument.PBKDF2Parameters
    }
}
    

extension EncryptedPEMDocument {
    // PBKDF2-params ::= SEQUENCE {
    //   salt CHOICE {
    //     specified       OCTET STRING,
    //     otherSource     AlgorithmIdentifier {{PBKDF2-SaltSources}}
    //   },
    //   iterationCount    INTEGER (1..MAX),
    //   keyLength         INTEGER (1..MAX) OPTIONAL,
    //   prf               AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
    // }
    struct PBKDF2Parameters: KeyDerivationFunctionParameters {
        let salt: ASN1OctetString
        let iterationCount: Int
        let hashFunction: HashFunction
        
        init(salt: ASN1OctetString, iterationCount: Int, hashFunction: HashFunction) {
            self.salt = salt
            self.iterationCount = iterationCount
            self.hashFunction = hashFunction
        }
        
        init(derEncoded node: ASN1Node) throws {
            self = try DER.sequence(node, identifier: .sequence) { nodes in
                let salt = try ASN1OctetString(derEncoded: &nodes)
                let iterationCount = try Int(derEncoded: &nodes)
                let hashFunction = try HashFunction(derEncoded: &nodes)
                
                return .init(salt: salt, iterationCount: iterationCount, hashFunction: hashFunction)
            }
        }
    }
}

extension EncryptedPEMDocument.PBKDF2Parameters {
    struct HashFunction: DERParseable {
        static var defaultIdentifier: ASN1Identifier { .sequence }
        
        let objectIdentifer: ASN1ObjectIdentifier
        let null: ASN1Null
        
        init(objectIdentifer: ASN1ObjectIdentifier, null: ASN1Null) {
            self.objectIdentifer = objectIdentifer
            self.null = null
        }
        
        init(derEncoded node: ASN1Node) throws {
            self = try DER.sequence(node, identifier: .sequence) { nodes in
                let objectIdentifer = try ASN1ObjectIdentifier(derEncoded: &nodes)
                let null = try ASN1Null(derEncoded: &nodes)
                
                return .init(objectIdentifer: objectIdentifer, null: null)
            }
        }
    }
}

extension KDF.Insecure.PBKDF2.HashFunction {
    static func from(objectIdentifier: ASN1ObjectIdentifier) -> Self? {
        switch objectIdentifier.oidComponents {
        case [2, 16, 840, 1, 101, 3, 4, 2, 1],
            [1, 2, 840, 113549, 2, 9]: // hmacWithSHA256
            .sha256
        case [2, 16, 840, 1, 101, 3, 4, 2, 2]:
            .sha384
        case [2, 16, 840, 1, 101, 3, 4, 2, 3]:
            .sha512
        default: nil
        }
    }
}
