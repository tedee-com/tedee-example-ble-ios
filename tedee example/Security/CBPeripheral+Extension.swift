//
//  CBPeripheral+Extension.swift
//  tedee example
//
//  Created by Mateusz Samosij on 21/12/2022.
//

import Foundation
import CoreBluetooth

extension CBPeripheral {
    var service: CBService? {
        return services?.first { $0.uuid == CBUUID(string: "00000002-4899-489F-A301-FBEE544B1DB0") }
    }
}
