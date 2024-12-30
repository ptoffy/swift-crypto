import SwiftASN1

extension EncryptedPEMDocument {
    protocol EncryptionAlgorithm: DERParseable {
        associatedtype Parameters: DERParseable
        
        static var algorithmIdentifier: ASN1ObjectIdentifier { get }
        var parameters: Parameters { get }
        
        init(parameters: Parameters)
    }
}

extension EncryptedPEMDocument.EncryptionAlgorithm {
    static var defaultIdentifier: SwiftASN1.ASN1Identifier { .sequence }
    
    init(derEncoded node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: Self.defaultIdentifier) { nodes in
            let parameters = try Parameters(derEncoded: &nodes)
            
            return .init(parameters: parameters)
        }
    }
}

extension EncryptedPEMDocument {
    struct PBES2: EncryptionAlgorithm {
        static var algorithmIdentifier: ASN1ObjectIdentifier { .pkcs5PBES2 }
        
        let parameters: EncryptedPEMDocument.PBES2Parameters
    }
}
