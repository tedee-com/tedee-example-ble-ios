//
//  tedee_exampleApp.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import SwiftUI
import CoreBluetooth

@main
struct tedee_exampleApp: App {
    let centralManager: CBCentralManager
    let centralManagerDelegate: CentralManagerDelegate
    
    init() {
        centralManagerDelegate = CentralManagerDelegate()
        centralManager = CBCentralManager(delegate: centralManagerDelegate, queue: .main)
        let cryptoManager = CryptoManager()
        if let key = cryptoManager.getMobilePublicKey()?.base64String(),
           !key.isEmpty {
            print("Public key to register in api: \(key)")
        } else {
            do {
                try cryptoManager.generateMobileKeys()
                guard let key = cryptoManager.getMobilePublicKey()?.base64String(),
                !key.isEmpty else { return }
                print("Public key to register in api: \(key)")
            } catch {
                print(error)
            }
        }
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
