//
//  PeripheralDelegate.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CoreBluetooth

final class PeriperalDelegate: NSObject, CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let services = peripheral.services else { return }
        for service in services {
            peripheral.discoverCharacteristics(nil, for: service)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        print("Did discover characteristics")
    }
}
