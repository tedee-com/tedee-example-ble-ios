//
//  CBService+Extension.swift
//  tedee example
//
//  Created by Mateusz Samosij on 21/12/2022.
//

import Foundation
import CoreBluetooth

extension CBService {
    var secureSessionCharacteristic: CBCharacteristic? {
        return characteristics?.first { $0.uuid == CBUUID(string: "00000401-4899-489F-A301-FBEE544B1DB0") }
    }
}
