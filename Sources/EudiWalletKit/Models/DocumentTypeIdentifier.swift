import MdocDataModel18013

public enum DocumentTypeIdentifier: Equatable {
    
    case EuPidDocType
    case IsoMdlModel
    case genericDocument(docType: String)
    case eid
    
    public var localizedTitle: String {
        return switch self {
        case .EuPidDocType:
            "National ID"
        case .IsoMdlModel:
            "Driving License"
        case .eid:
            "Personalausweis(EID)"
        case .genericDocument(let docType):
            "\(docType)"
        }
    }
    
    public var mdocValue: String {
        return switch self {
        case .EuPidDocType:
            MdocDataModel18013.EuPidModel.euPidDocType
        case .IsoMdlModel:
            MdocDataModel18013.IsoMdlModel.isoDocType
        case .genericDocument(let docType):
            docType
        case .eid:
            "eid"
        }
    }
    
    public var sdjwtValue: String {
        return switch self {
        case .EuPidDocType:
            //https://example.bmi.bund.de/credential/pid/1.0
            "urn:eu.europa.ec.eudi:pid:1"
        case .IsoMdlModel:
            "urn:eu.europa.ec.eudi:pid:1"
        case .genericDocument(let docType):
            docType
        case .eid:
            "eid"
        }
    }
    
    public init(rawValue: String) {
        switch rawValue {
        case MdocDataModel18013.EuPidModel.euPidDocType:
            self = .EuPidDocType
        case MdocDataModel18013.IsoMdlModel.isoDocType:
            self = .IsoMdlModel
        case "eid":
            self = .eid
        default:
            self = .genericDocument(docType: rawValue)
        }
    }
}
