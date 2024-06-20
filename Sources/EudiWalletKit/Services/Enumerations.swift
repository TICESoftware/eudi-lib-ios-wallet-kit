/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//  TransferStatus.swift

import Foundation

/// Data exchange flow type
public enum FlowType: Codable, Hashable {
	
    case bleMdoc
	case openID4VPOverHTTP
    case openID4VPOverBLE
    case other
	
	/// Is the flow based on proximity (currently over BLE)
    public var isProximity: Bool {
        switch self {
        case .bleMdoc: true
        case .openID4VPOverBLE: true
        case .openID4VPOverHTTP: false
        case .other: false
        }
    }
    
    public var dataFormat: DataFormat {
        switch self {
        case .bleMdoc: return .cbor
        case .openID4VPOverHTTP: return .sdjwt
        case .openID4VPOverBLE: return .cbor
        case .other: return .sdjwt
        }
    }
}

/// Data format of the exchanged data
/// TODO: Get rid of "DataFormat". It is in case of CBOR an encoding and in case of SD-JWT a document format, thus it does not make sense. Use ClaimFormat (defined in PresentationExchange).
public enum DataFormat: String {
	case cbor = "cbor"
	case sdjwt = "sdjwt"
}

public enum StorageType {
	case keyChain
}


