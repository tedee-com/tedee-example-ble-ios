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
    private let centralManager: CBCentralManager
    private let centralManagerDelegate: CentralManagerDelegate
    
    init() {
        centralManagerDelegate = CentralManagerDelegate()
        centralManager = CBCentralManager(delegate: centralManagerDelegate, queue: .main)
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
