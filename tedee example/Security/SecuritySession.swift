//
//  SecuritySession.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CoreBluetooth

public final class SecuritySession {
    let peripheral: CBPeripheral
    let centralManager: CBCentralManager
    
//    private let cryptoManager: CryptoManager
//    private let devicesAdapter: DevicesAdapter
//    private let certificatesManager: CertificatesManager
//    private let bleNotificationHandler: BleNotificationHandler
    private var bleNotificationHandlerRegistered = false
    private var client: SecurityProtocol
    private var completion: (Result<Void, Error>) -> Void

    public var mtuSize: UInt8 = 0
    
    private var certificate: [UInt8]
    private let privateKey: SecKey
    private let ecdhKeyPair: SecKey
    private let devicePublicKey: SecKey
    
    public init(peripheral: CBPeripheral,
                centralManager: CBCentralManager,
                completion: @escaping (Result<Void, Error>) -> Void) throws {
        self.peripheral = peripheral
        self.centralManager = centralManager
        
        let cryptoManager = CryptoManager()
        guard let privateKey = cryptoManager.getMobileKey(),
              let ecdhKeyPair = cryptoManager.generateECDHKey(),
              let publicKey = cryptoManager.getMobilePublicKey() else {
            throw SecurityErrors.missingKeys
        }
        
        self.privateKey = privateKey
        self.ecdhKeyPair = ecdhKeyPair

        guard let certificateData = Data(base64Encoded: Configuration.CertificateString) else {
            throw SecurityErrors.missingCertificate
        }
        
        let devicePublicKey = Configuration.DevicePublicKey
        let mobilePublicKey = Configuration.MobilePublicKey

        guard publicKey == mobilePublicKey else {
            throw SecurityErrors.invalidCertificate
        }
        
        self.certificate = [UInt8](certificateData)
        self.devicePublicKey = devicePublicKey
        
        self.completion = completion
        client = SecurityProtocol(authData: certificate, privateKey: privateKey, ecdhKeyPair: ecdhKeyPair)
        
        sendHelloMessage()
    }
    
    private func disconnect() {
        centralManager.cancelPeripheralConnection(peripheral)
    }
    
    private func sendHelloMessage() {
        guard let parameters = try? client.hello(pfs: true) else {
            disconnect()
            return
        }
        
        var request: [UInt8] = [0]
        request.append(contentsOf: parameters)
        guard let characteristic = peripheral.service?.secureSessionCharacteristic else {
            disconnect()
            return
        }
        peripheral.writeValue(Data(request), for: characteristic, type: .withResponse)
    }
}

// MARK: Encrypt & Decrypt

public extension SecuritySession {
    func encrypt(message: [UInt8]) throws -> [UInt8] {
        do {
            return try client.write(data: message)
        } catch {
            disconnect()
            throw error
        }
    }
    
    func decrypt(message: [UInt8]) throws -> [UInt8] {
        
        do {
            return try client.read(message: message)
        } catch {
            disconnect()
            throw error
        }
    }
}

extension SecuritySession {
    private func handleResponse(response: [UInt8], removeCertificates: Bool = false) {
        switch response.first {
            case 3:
                handleHelloResponse(response)
            case 5:
                handleServerVerifyResponse(response)
            case 8:
                handleInitializedResponse()
            case 4:
                handleAlertResponse()
            default:
                return
        }
    }
    
    private func handleHelloResponse(_ response: [UInt8]) {
        let params = Array(response.dropFirst())
        guard let mtu = self.extractMtu(from: Data(params)),
              mtu >= 1 else {
            disconnect()
            completion(.failure(SecurityErrors.parseError))
            return
        }
        
        self.mtuSize = mtu - 1
        do {
            try client.serverHello(serverHello: [UInt8](params))
        } catch {
            disconnect()
            completion(.failure(SecurityErrors.parseError))
        }
        sendServerVerify()
    }
    
    private func sendServerVerify() {
        var request: [UInt8] = [5]
        request.append(contentsOf: client.serverVerifyInit())
        guard let characteristic = peripheral.service?.secureSessionCharacteristic else {
            disconnect()
            return
        }
        peripheral.writeValue(Data(request), for: characteristic, type: .withResponse)
    }
    
    private func handleServerVerifyResponse(_ response: [UInt8]) {
        let params = Array(response.dropFirst())
        
        do {
            try client.serverVerify(serverVerify: [UInt8](params))
            if try !client.peerVerify(publicKey: self.devicePublicKey) {
                completion(.failure(SecurityErrors.parseError))
                disconnect()
            } else {
                sendClientVerify()
            }
        } catch {
            disconnect()
            completion(.failure(SecurityErrors.parseError))
            
        }
    }
    
    private func sendClientVerify() {
        guard mtuSize != 0 else { return }
        var verifyMessage: [UInt8] = []
        
        do {
            verifyMessage = try client.verify()
        } catch {
            disconnect()
            completion(.failure(SecurityErrors.parseError))
        }
        
        var index = 0
        
        while index < verifyMessage.count {
            if index + Int(self.mtuSize) >= verifyMessage.count {
                var request: [UInt8] = [7]
                request.append(contentsOf: [UInt8](verifyMessage[index..<verifyMessage.count]))
                guard let characteristic = peripheral.service?.secureSessionCharacteristic else {
                    disconnect()
                    return
                }
                peripheral.writeValue(Data(request), for: characteristic, type: .withResponse)
            } else {
                var request: [UInt8] = [6]
                request.append(contentsOf: [UInt8](verifyMessage[index..<index + Int(self.mtuSize)]))
                guard let characteristic = peripheral.service?.secureSessionCharacteristic else {
                    disconnect()
                    return
                }
                peripheral.writeValue(Data(request), for: characteristic, type: .withResponse)
            }
            
            index += Int(mtuSize)
        }
    }
    
    private func handleInitializedResponse() {
        completion(.success(()))
    }
    
    private func handleAlertResponse() {
        completion(.failure(SecurityErrors.parseError))
        disconnect()
    }
}

extension SecuritySession {
    func extractMtu(from data: Data) -> UInt8? {
        if data.count > 2 {
            return data[1]
        } else {
            return nil
        }
    }
}
