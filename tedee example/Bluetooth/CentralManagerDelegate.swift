//
//  CentralManagerDelegate.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CoreBluetooth

final class CentralManagerDelegate: NSObject, CBCentralManagerDelegate, ObservableObject {
    var connectedPeripheral: CBPeripheral?
    var connectedPeripheralDelegate = PeriperalDelegate()
    @Published var peripheralState = "Scanning for device"
    
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            central.scanForPeripherals(withServices: [Configuration.deviceService])
        }
    }
    
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        connectedPeripheralDelegate.centralManager = central
        peripheral.delegate = connectedPeripheralDelegate
        connectedPeripheral = peripheral
        peripheralState = "Device discovered"
        central.connect(peripheral)
    }
    
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        peripheralState = "Device connected"
        peripheral.discoverServices(nil)
    }
}
