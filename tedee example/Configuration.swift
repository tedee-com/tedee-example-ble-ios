//
//  Configuration.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CoreBluetooth

enum Configuration {
    static let SerialNumber = ""
    static let CertificateString = ""
    static let DevicePublicKeyString = ""
    static let MobilePublicKeyString = ""
}

extension Configuration {
    static var deviceService: CBUUID = {
        guard !SerialNumber.isEmpty else {
            print("ERROR: Serial number is missing! Update `SerialNumber` with valid lock serial number!");
            exit(1)
        }
        
        let serialNumber = SerialNumber.replacingOccurrences(of: "-", with: "")
        return CBUUID(string: serialNumber.serviceString())
    }()
    
    static var DevicePublicKey: SecKey = {
        guard !DevicePublicKeyString.isEmpty else {
            print("ERROR: Mobile public key is missing! Update `DevicePublicKeyString` with one from Tedee API!")
            exit(1)
        }
        
        var error: Unmanaged<CFError>?
        guard let publicKeyData = Data(base64Encoded: Self.DevicePublicKeyString),
              let publicKey = SecKeyCreateWithData(publicKeyData as CFData, SecKey.devicePublicKeyAttributes as CFDictionary, &error) else {
            fatalError(error.debugDescription)
        }
        
        return publicKey
    }()
    
    static var MobilePublicKey: SecKey = {
        guard !MobilePublicKeyString.isEmpty else {
            print("ERROR: Device public key is missing! Update `MobilePublicKeyString` with one from console!")
            exit(1)
        }
        
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
