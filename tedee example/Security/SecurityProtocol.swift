//
//  SecurityProtocol.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CryptoSwift

public class SecurityProtocol {
    // protocol version
    static let version: UInt8 = 0x02
    
    // types of protocol messages
    static let messageHello: UInt8 = 0x00
    static let messageVerify: UInt8 = 0x01
    static let messageData: UInt8 = 0x02
    static let messageAlert: UInt8 = 0x07
    
    // protocol
    static let sideClient: UInt8 = 0x00
    static let sideServer: UInt8 = 0x01
    
    // alert types
    static let alertClose: UInt8 = 0x00
    static let alertFail: UInt8 = 0xff
    
    // protocol record
    static let lenHeader = 3
    static let lenLength = 2
    static let lenAuthTag = 16
    static let lenRandom = 32
    static let lenAlert = 1
    static let offsetRandomData = lenHeader
    static let offsetECDHPublic = lenRandom + lenHeader
    static let offsetEncryptedRandom = offsetECDHPublic + ECDHPublicLen
    static let encryptedRandomLen = 48
    static let sessionIdLen = 4
    static let ECDHPublicLen = 65
    
    // side of protocol
    let side: UInt8
    let peerSide: UInt8
    
    // authentication data
    var authData: [UInt8]
    var peerAuthData: [UInt8]?
    var verifyBytes: [UInt8]?
    var peerVerifyBytes: [UInt8]?
    
    // key exchange object
    let ecdhKeyPair: SecKey
    var ecdhPublicKeyBytes: [UInt8]?
    var peerEcdhPublicKey: SecKey?
    var peerEcdhPublicKeyBytes: [UInt8]?
    var header: [UInt8] = [version, 0x0, 0x0] // version number, mtu size, unused
    var peerHeader: [UInt8]
    var randomData: [UInt8]
    var peerRandomData: [UInt8]
    
    // data encryption obje
    var sharedSecret: [UInt8]?
    static var clientHSTraffic: [UInt8] {
        guard let data = "ptlsc hs traffic".data(using: .utf8) else { return [] }
        return [UInt8](data)
    }
    static var serverHSTraffic: [UInt8] {
        guard let data = "ptlss hs traffic".data(using: .utf8) else { return [] }
        return [UInt8](data)
    }
    static var clientAPTraffic: [UInt8] {
        guard let data = "ptlsc ap traffic".data(using: .utf8) else { return [] }
        return [UInt8](data)
    }
    static var serverAPTraffic: [UInt8] {
        guard let data = "ptlss ap traffic".data(using: .utf8) else { return [] }
        return [UInt8](data)
    }
    
    var protector: MessageCipher?
    var peerProtector: MessageCipher?
    
    // handshake digest
    var hsDigest: [UInt8] = []
    var helloHash: [UInt8]?
    var helloVerifyHash: [UInt8]?
    var hsHash: [UInt8]?
    
    // sign/verify objects
    var privateKey: SecKey
    
    // protocol status
    var hsFinished: Bool
    
    init(authData: [UInt8], privateKey: SecKey, ecdhKeyPair: SecKey) {
        self.side = Self.sideClient
        self.peerSide = Self.sideServer
        self.randomData = [UInt8]()
        self.randomData.reserveCapacity(Self.lenRandom)
        self.peerHeader = [UInt8]()
        self.peerRandomData = [UInt8]()
        self.peerRandomData.reserveCapacity(Self.lenRandom)
        self.authData = authData
        self.privateKey = privateKey
        self.ecdhKeyPair = ecdhKeyPair
        self.hsFinished = false
    }
    
    public func hello(pfs: Bool) throws -> [UInt8] {
        try prepareSession()
        return try buildHello()
    }
    
    public func serverHello(serverHello: [UInt8]) throws {
        try parseHello(message: serverHello)
        try hsStartEncryption(label: Self.clientHSTraffic, peerLabel: Self.serverHSTraffic)
    }
    
    public func serverVerifyInit() -> [UInt8] {
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000)
        
        return timestamp.bytes.reversed()
    }
    
    public func serverVerify(serverVerify: [UInt8]) throws {
        try parseVerify(message: serverVerify)
    }
    
    public func verify() throws -> [UInt8] {
        let verify = try buildVerify()
        try apStartEncryption(label: Self.clientAPTraffic, peerLabel: Self.serverAPTraffic)
        return verify
    }
    
    func clearSession() {
        randomData.removeAll()
        peerRandomData.removeAll()
        peerHeader.removeAll()
        sharedSecret = nil
        protector = nil
        peerProtector = nil
        hsDigest.removeAll()
        peerAuthData?.removeAll()
        peerVerifyBytes = nil
        helloHash = nil
        helloVerifyHash = nil
        hsHash = nil
        hsFinished = false
    }
    
    func prepareSession() throws {
        guard let publicKey = SecKeyCopyPublicKey(ecdhKeyPair),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) else {
            throw SecurityErrors.invalidKey
        }
        
        ecdhPublicKeyBytes = [UInt8](publicKeyData as Data)
        clearSession()
    }
    
    func getLength(message: [UInt8], offset: Int) throws -> Int {
        let x = message[offset]
        let y = message[offset + 1]
        
        let length = Int(((Int(x) & 0xff) << 8) | (Int(y) & 0xff))
        
        guard message.count > (length + offset) else {
            throw SecurityErrors.invalidData
        }
        return length
    }
    
    func setLength(message: inout [UInt8], offset: Int, len: Int) {
        message[offset] = UInt8(((len >> 8) & 0xff))
        message[offset + 1] = (UInt8(len & 0xff))
    }

    func buildHello() throws -> [UInt8] {
        guard let ecdhPublicKeyBytes = ecdhPublicKeyBytes else {
            throw SecurityErrors.invalidKey
        }
        randomData = Data.random(Self.lenRandom)
        var message: [UInt8] = [UInt8]()
        message.append(contentsOf: header)
        message.append(contentsOf: randomData)
        message.append(contentsOf: ecdhPublicKeyBytes)
        message.append(contentsOf: [UInt8](repeating: 0, count: 48))
        message.append(contentsOf: [0, 0, 0, 0])
        hsDigest.append(contentsOf: message)
        return message
    }
    
    func parseHello(message: [UInt8]) throws {
        guard message.count > Self.offsetECDHPublic else {
            throw SecurityErrors.invalidData
        }
        peerHeader = Array(message[0..<Self.lenHeader])
        peerRandomData = Array(message[Self.offsetRandomData..<Self.lenRandom + Self.lenHeader])
        peerEcdhPublicKeyBytes = Array(message[Self.offsetECDHPublic..<message.count])
        let attributes: [String: Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        guard let keyBytes = peerEcdhPublicKeyBytes,
              let key = SecKeyCreateWithData(Data(keyBytes) as CFData, attributes as CFDictionary, nil) else {
            throw SecurityErrors.invalidKey
        }
        peerEcdhPublicKey = key
        hsDigest.append(contentsOf: message)
    }
    
    func buildVerify(message dateMessage: [UInt8]? = nil) throws -> [UInt8] {
        guard let protector = protector else {
            throw SecurityErrors.invalidData
        }
        
        if side == Self.sideServer, let dateMessage = dateMessage {
            self.authData = dateMessage
        }
        var dataToSign = [UInt8]()
        
        guard let ecdhPublicKeyBytes = ecdhPublicKeyBytes,
              let peerEcdhPublicKeyBytes = peerEcdhPublicKeyBytes,
              let peerAuthData = peerAuthData,
              let peerVerifyBytes = peerVerifyBytes,
              let helloHash = helloHash else {
            throw SecurityErrors.invalidData
        }
        dataToSign.append(contentsOf: header)
        dataToSign.append(contentsOf: randomData)
        dataToSign.append(contentsOf: ecdhPublicKeyBytes)
        dataToSign.append(contentsOf: [UInt8](repeating: 0, count: 48))
        dataToSign.append(contentsOf: [0, 0, 0, 0])
        dataToSign.append(contentsOf: peerHeader)
        dataToSign.append(contentsOf: peerRandomData)
        dataToSign.append(contentsOf: peerEcdhPublicKeyBytes)
        var dataLen = [UInt8](repeating: 0, count: 2)
        setLength(message: &dataLen, offset: 0, len: peerAuthData.count)
        dataToSign.append(contentsOf: dataLen)
        dataToSign.append(contentsOf: peerAuthData)
        setLength(message: &dataLen, offset: 0, len: peerVerifyBytes.count)
        dataToSign.append(contentsOf: dataLen)
        dataToSign.append(contentsOf: peerVerifyBytes)
        setLength(message: &dataLen, offset: 0, len: helloHash.count)
        dataToSign.append(contentsOf: dataLen)
        dataToSign.append(contentsOf: helloHash)
        
        var authDataLen = [UInt8](repeating: 0, count: 2)
        setLength(message: &authDataLen, offset: 0, len: authData.count)
        dataToSign.append(contentsOf: authDataLen)
        dataToSign.append(contentsOf: authData)
        
        var error: Unmanaged<CFError>?
        
        guard let verifyData = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, Data(dataToSign) as CFData, &error) else {
            throw SecurityErrors.error(error?.takeRetainedValue() as Any)
        }
        let verifyBytesArray = [UInt8](verifyData as Data)
        verifyBytes = verifyBytesArray
        
        var message = [UInt8]()
        var offset = 0
        
        message.append(contentsOf: [0, 0])
        setLength(message: &message, offset: offset, len: authData.count)
        offset += Self.lenLength
        message.append(contentsOf: authData)
        offset += authData.count
        message.append(contentsOf: [0, 0])
        setLength(message: &message, offset: offset, len: verifyBytesArray.count)
        offset += Self.lenLength
        message.append(contentsOf: verifyBytesArray)
        offset += verifyBytesArray.count
        
        guard let helloVerifyHash = helloVerifyHash else {
            throw SecurityErrors.invalidData
        }
        
        message.append(contentsOf: [0, 0])
        setLength(message: &message, offset: offset, len: helloVerifyHash.count)
        offset += Self.lenLength
        message.append(contentsOf: helloVerifyHash)
        offset += helloVerifyHash.count

        hsDigest.append(contentsOf: message[0..<(offset)])
        
        return try protector.transform(message: message, offset: 0, len: message.count)
    }
    
    func parseVerify(message: [UInt8]) throws {
        guard let peerProtector = peerProtector,
              let helloHash = helloHash else {
            throw SecurityErrors.invalidData
        }
        
        var message = message
        let decryptedMessage = try peerProtector.transform(message: message, offset: 0, len: message.count)
        message = decryptedMessage
        var offset = 0
        
        var len = try getLength(message: message, offset: offset)
        offset += Self.lenLength
        peerAuthData = Array(message[offset..<(len + offset)])
        offset += peerAuthData?.count ?? 0
        len = try getLength(message: message, offset: offset)
        offset += Self.lenLength
        peerVerifyBytes = Array(message[offset..<(len + offset)])
        offset += peerVerifyBytes?.count ?? 0
        len = try getLength(message: message, offset: offset)
        offset += Self.lenLength
        if len != 32 {
            throw SecurityErrors.error(Self.alertFail)
        }
        
        for i in 0..<len where i < helloHash.count &&
        offset + i < message.count &&
        helloHash[i] != message[offset + i] {
            throw SecurityErrors.error(Self.alertFail)
        }
        
        offset += helloHash.count
        
        hsDigest.append(contentsOf: message[0..<offset])
        if side == Self.sideClient {
            self.helloVerifyHash = SHA2(variant: .sha256).calculate(for: hsDigest)
        }
        
        hsFinished = true
    }
    
    public func write(data: [UInt8]) throws -> [UInt8] {
        guard let protector = protector else {
            throw SecurityErrors.invalidData
        }
        
        if !hsFinished {
            throw SecurityErrors.error(Self.alertFail)
        }
        
        return try protector.transform(message: data, offset: 0, len: data.count)
    }
    
    public func read(message: [UInt8]) throws -> [UInt8] {
        guard let peerProtector = peerProtector else {
            throw SecurityErrors.invalidData
        }
        
        if !hsFinished {
            throw SecurityErrors.error(Self.alertFail)
        }
        
        return try peerProtector.transform(message: message, offset: 0, len: message.count)
    }
    
    func hsStartEncryption(label: [UInt8], peerLabel: [UInt8]) throws {
        let dict: [String: Any] = [String: Any]()
        var error: Unmanaged<CFError>?
        
        guard let keyBytes = peerEcdhPublicKey,
              let sharedSecretData = SecKeyCopyKeyExchangeResult(ecdhKeyPair, .ecdhKeyExchangeStandard, keyBytes, dict as CFDictionary, &error) else {
            throw SecurityErrors.error(error?.takeRetainedValue() as Any)
        }
        
        let sharedSecretKey = Array(sharedSecretData as Data)
        sharedSecret = sharedSecretKey
        
        let hash = SHA2(variant: .sha256).calculate(for: hsDigest)
        helloHash = hash
        protector = try MessageCipher(sharedSecret: sharedSecretKey, label: label, data: hash, mode: .encrypt)
        peerProtector = try MessageCipher(sharedSecret: sharedSecretKey, label: peerLabel, data: hash, mode: .decrypt)
    }
    
    func apStartEncryption(label: [UInt8], peerLabel: [UInt8]) throws {
        guard let sharedSecret = sharedSecret else {
            throw SecurityErrors.invalidData
        }
        
        let hash = SHA2(variant: .sha256).calculate(for: hsDigest)
        hsHash = hash
        protector = try MessageCipher(sharedSecret: sharedSecret, label: label, data: hash, mode: .encrypt)
        peerProtector = try MessageCipher(sharedSecret: sharedSecret, label: peerLabel, data: hash, mode: .decrypt)
    }
    
    func alert(code: UInt8) -> [UInt8] {
        return [code]
    }
    
    public func close() {
        clearSession()
    }
    
    public func peerVerify(publicKey: SecKey) throws -> Bool {
        guard let peerVerifyBytes = peerVerifyBytes else {
            throw SecurityErrors.invalidData
        }
        
        var dataToVerify = [UInt8]()
        
        guard let ecdhPublicKeyBytes = ecdhPublicKeyBytes,
              let peerEcdhPublicKeyBytes = peerEcdhPublicKeyBytes,
              let peerAuthData = peerAuthData else {
            throw SecurityErrors.invalidData
        }
        
        dataToVerify.append(contentsOf: header)
        dataToVerify.append(contentsOf: randomData)
        dataToVerify.append(contentsOf: ecdhPublicKeyBytes)
        dataToVerify.append(contentsOf: [UInt8](repeating: 0, count: 48))
        dataToVerify.append(contentsOf: [0, 0, 0, 0])
        dataToVerify.append(contentsOf: peerHeader)
        dataToVerify.append(contentsOf: peerRandomData)
        dataToVerify.append(contentsOf: peerEcdhPublicKeyBytes)
        var dataLen = [UInt8](repeating: 0, count: 2)
        setLength(message: &dataLen, offset: 0, len: peerAuthData.count)
        dataToVerify.append(contentsOf: dataLen)
        dataToVerify.append(contentsOf: peerAuthData)
        
        let digest = SHA2(variant: .sha256).calculate(for: dataToVerify)
        let result = SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256, Data(digest) as CFData, Data(peerVerifyBytes) as CFData, nil)
        
        return result
    }
}

extension Data {
    static func random(_ length: Int) -> [UInt8] {
        var keyData = [UInt8](repeating: 0, count: length)
        let result = SecRandomCopyBytes(kSecRandomDefault, length, &keyData)
        if result == errSecSuccess {
            return keyData
        } else {
            fatalError("Cannot generate random data")
        }
    }
}

extension FixedWidthInteger {
    var bytes: [UInt8] {
        let size = MemoryLayout<Self>.size
        var value = self
        
        return withUnsafePointer(to: &value) { (pointer: UnsafePointer<Self>) in
            pointer.withMemoryRebound(to: UInt8.self, capacity: size) {
                Array(UnsafeBufferPointer(start: $0, count: size))
            }
        }
    }
}
