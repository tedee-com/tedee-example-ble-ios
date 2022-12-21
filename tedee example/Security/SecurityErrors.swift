//
//  SecurityErrors.swift
//  tedee example
//
//  Created by Mateusz Samosij on 20/12/2022.
//

import Foundation

enum SecurityErrors: Error {
    case invalidAlgorithmParameter
    case invalidKey
    case invalidData
    case error(Any)
    case parseError
    case missingKeys
    case missingCertificate
    case invalidCertificate
}
