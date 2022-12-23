//
//  CryptoManager.swift
//  tedee example
//
//  Created by Mateusz Samosij on 21/12/2022.
//

import Foundation

public enum CryptoManagerError: Error {
    case keysAlreadyExists
}

final class CryptoManager {
    func generateMobileKeys() throws {
        var error: Unmanaged<CFError>?
        
        guard SecKeyCreateRandomKey(SecKey.newKeysAttributes(with: "mobileKey"), &error) != nil else {
            let e = (error?.takeRetainedValue() as Error?) ?? NSError(domain: "Something went wrong", code: 0)
            throw e
        }
    }
    
    func generateECDHKey() -> SecKey? {
        guard let key = SecKeyCreateRandomKey(SecKey.ecdhKeyAttributes, nil) else {
            return nil
        }
        
        return key
    }
    
    private func getKeys(for tag: String) -> SecKey? {
        var retrivedItem: AnyObject?
        
        let status = SecItemCopyMatching(SecKey.retriveKeysAttributes(with: tag), &retrivedItem)
        
        guard status == errSecSuccess else {
            return nil
        }
        
        return retrivedItem as! SecKey?
    }
    
    func getMobilePublicKey() -> SecKey? {
        guard let keyPair = getKeys(for: "mobileKey"),
              let publicKey = SecKeyCopyPublicKey(keyPair) else {
            return nil
        }
        return publicKey
    }
    
    func getMobileKey() -> SecKey? {
        guard let key = getKeys(for: "mobileKey") else {
            return nil
        }
        return key
    }
}

extension SecKey {
    static func retriveKeysAttributes(with tag: String) -> CFDictionary {
        let attributes: [NSString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true]
        
        return attributes as CFDictionary
    }
    
    static func newKeysAttributes(with tag: String) -> CFDictionary {
        let attributes: [NSString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag],
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock]
        
        return attributes as CFDictionary
    }
    
    static var ecdhKeyAttributes: CFDictionary {
        let attributes: [String: Any] = [
            kSecAttrType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        
        return attributes as CFDictionary
    }
    
    func base64String() -> String {
        var error: Unmanaged<CFError>?
        guard let cfData = SecKeyCopyExternalRepresentation(self, &error) else {
            fatalError("Cannot convert SecKey to base64 string")
        }
        
        return (cfData as Data).base64EncodedString()
    }
}
