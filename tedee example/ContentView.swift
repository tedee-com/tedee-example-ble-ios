//
//  ContentView.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import SwiftUI
import CoreBluetooth

struct ContentView: View {
    let centralManager: CBCentralManager?
    @ObservedObject var centralManagerDelegate: CentralManagerDelegate
    
    init(centralManagerDelegate: CentralManagerDelegate = CentralManagerDelegate()) {
        self.centralManagerDelegate = centralManagerDelegate
        centralManager = CBCentralManager(delegate: centralManagerDelegate, queue: .main)
    }
    
    var body: some View {
        VStack {
            Text(centralManagerDelegate.peripheralState)
            Button {
                let encryptedMessage = try? centralManagerDelegate.connectedPeripheralDelegate.session?.encrypt(message: [0x51])
                guard let peripheral = centralManagerDelegate.connectedPeripheral,
                      let message = encryptedMessage,
                      let characteristic = peripheral.service?.apiCharacteristic else {
                    return
                }
                peripheral.writeValue(Data([0x1] + message), for: characteristic, type: .withResponse)
            } label: {
                Text("Unlock")
            }
            .padding(.top, 20)
            .disabled(centralManagerDelegate.peripheralState != "Device ready")
        }
        .padding()
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
