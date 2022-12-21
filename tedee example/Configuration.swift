//
//  Configuration.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CoreBluetooth

enum Configuration {
    static let SerialNumber = "19500203-000011"
    static let CertificateString = "Your certificate"
    static let DevicePublicKeyString = "Your device public key"
    static let MobilePublicKeyString = "Your mobile public key"
}

extension Configuration {
    static var deviceService: CBUUID = {
        let serialNumber = SerialNumber.replacingOccurrences(of: "-", with: "")
        return CBUUID(string: serialNumber.serviceString())
    }()
    
    static var DevicePublicKey: SecKey = {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = Data(base64Encoded: Self.DevicePublicKeyString),
              let publicKey = SecKeyCreateWithData(publicKeyData as CFData, SecKey.devicePublicKeyAttributes as CFDictionary, &error) else {
            fatalError(error.debugDescription)
        }
        
        return publicKey
    }()
    
    static var MobilePublicKey: SecKey = {
        var error: Unmanaged<CFError>?
        guard let publicKeyData = Data(base64Encoded: Self.MobilePublicKeyString),
              let publicKey = SecKeyCreateWithData(publicKeyData as CFData, SecKey.devicePublicKeyAttributes as CFDictionary, &error) else {
            fatalError(error.debugDescription)
        }
        
        return publicKey
    }()
}

extension String {
    func insert(string: String, ind: Int) -> String {
        return String(prefix(ind)) + string + String(suffix(count - ind))
    }
    
    func serviceString() -> String {
        let serviceString = "\(self)".insert(string: "0000", ind: 4) + String(repeating: "0", count: 14)
        return serviceString.insert(string: "-", ind: 20).insert(string: "-", ind: 16).insert(string: "-", ind: 12).insert(string: "-", ind: 8).uppercased()
    }
}

extension SecKey {
    static var devicePublicKeyAttributes: CFDictionary {
        let attributes: [String: Any] = [
            kSecAttrType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        
        return attributes as CFDictionary
    }
}
