//
//  MessageCipher.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CryptoSwift

public final class MessageCipher {
    enum Mode {
        case encrypt
        case decrypt
    }
    
    let secretKey: [UInt8]
    var iv: [UInt8]
    var ivCounterBase: [UInt8]
    let mode: Mode
    var counter: Int
    
    init(sharedSecret: [UInt8], label: [UInt8], data: [UInt8], mode: Mode) throws {
        let mac = HMAC(key: sharedSecret, variant: .sha2(.sha256))
        let key = try mac.authenticate(label + data)
        self.secretKey = [UInt8](key[0..<16])
        self.iv = [UInt8]()
        self.iv.reserveCapacity(12)
        self.iv.append(contentsOf: key[16..<28])
        self.ivCounterBase = [UInt8](repeating: 0, count: 2)
        self.ivCounterBase[0] = iv[10]
        self.ivCounterBase[1] = iv[11]
        self.counter = 0
        self.mode = mode
    }
    
    init(sharedSecret: [UInt8], label: [UInt8], data: [UInt8], mode: Mode, cipherData: CipherData) throws {
        let mac = HMAC(key: sharedSecret, variant: .sha2(.sha256))
        let key = try mac.authenticate(label + data)
        self.secretKey = [UInt8](key[0..<16])
        self.iv = cipherData.iv
        self.ivCounterBase = cipherData.ivCounterBase
        self.counter = cipherData.counter
        self.mode = mode
    }
    
    func transform(message: [UInt8], offset: Int, len: Int) throws -> [UInt8] {
        if counter > 0xffff {
            throw SecurityErrors.invalidAlgorithmParameter
        }
        
        iv[10] = ivCounterBase[0]
        iv[11] = ivCounterBase[1]
        iv[10] ^= (UInt8)((counter >> 8) & 0xff)
        iv[11] ^= (UInt8)(counter & 0xff)
        var result = [UInt8]()
        
        do {
            let gcm = GCM(iv: iv, tagLength: SecurityProtocol.lenAuthTag, mode: .combined)
            let aes = try AES(key: secretKey, blockMode: gcm, padding: .noPadding)
            
            let msg = message[(offset)..<(len + offset)]
            
            switch mode {
                case .encrypt:
                    result = try aes.encrypt(msg)
                case .decrypt:
                    result = try aes.decrypt(msg)
            }
            counter += 1
            return result
        } catch let error {
            throw error
        }
    }
}

public struct CipherData: Codable {
    public var counter: Int
    public let iv: [UInt8]
    public let ivCounterBase: [UInt8]
}

