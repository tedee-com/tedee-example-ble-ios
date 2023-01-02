//
//  PeripheralDelegate.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation
import CoreBluetooth

final class PeriperalDelegate: NSObject, CBPeripheralDelegate {
    var centralManager: CBCentralManager?
    var session: SecuritySession?
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let services = peripheral.services else { return }
        
        for service in services {
            peripheral.discoverCharacteristics(nil, for: service)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let service = peripheral.service else { return }
        if let api = service.apiCharacteristic {
            peripheral.setNotifyValue(true, for: api)
        }
        if let security = service.secureSessionCharacteristic {
            peripheral.setNotifyValue(true, for: security)
        }
        if let receiveSecurity = service.receiveSecureSessionCharacteristic {
            peripheral.setNotifyValue(true, for: receiveSecurity)
        }
        if let notification = service.notificationsCharacteristic {
            peripheral.setNotifyValue(true, for: notification)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == peripheral.service?.receiveSecureSessionCharacteristic?.uuid,
           let response = characteristic.value?.bytes {
            session?.handleResponse(response: response)
        }
    }
    
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if characteristic.uuid == peripheral.service?.receiveSecureSessionCharacteristic?.uuid {
            guard session == nil,
                  let centralManager = centralManager else { return }
            do {
                (centralManager.delegate as? CentralManagerDelegate)?.peripheralState = "Establishing secure connection"
                session = try SecuritySession(peripheral: peripheral, centralManager: centralManager, completion: { result in
                    switch result {
                        case .success:
                            print("Secure session established")
                            (centralManager.delegate as? CentralManagerDelegate)?.peripheralState = "Device ready"
                        case.failure(let error):
                            print(error)
                    }
                })
            } catch {
                print(error)
            }
        }
    }
}
