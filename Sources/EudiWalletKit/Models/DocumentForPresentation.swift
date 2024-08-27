import Foundation
import MdocDataModel18013
import MdocSecurity18013
//import PresentationExchange
import SwiftCBOR
import SiopOpenID4VP
import eudi_lib_sdjwt_swift
import WalletStorage
import JOSESwift
import SwiftyJSON
import CryptoKit
import ZKP_Swift

/// A single mdoc document paired with its requested input descriptor and the selected items of this document
struct MDocDocumentForPresentation {
    
    /// ID of document, referred to by the input descriptor id
    let docId: String
    
    /// Issuer signed document containing i.a. the mso and the signature
    let doc: IssuerSigned
    
    /// Input descriptor for the document retrieved by the auth request. Includes the requests for the claims.
    let inputDescriptor: InputDescriptor
    
    /// The claims that were selected by the user to disclose
    let selectedItems: NamespaceToItems
    
    /// Public key of the eReader. Used together with the `devicePrivateKey` for a key agreement
    let eReaderKey: CoseKey?
    
    /// Private key for the device. Used together with the `eReaderKey` for a key agreement
    let devicePrivateKey: CoseKeyPrivate
    
    /// Session transcript for this document
    let sessionTranscript: SessionTranscript?
    
    /// Device auth method (Signature or MAC)
    let dauthMethod: DeviceAuthMethod
    
    /// MDoc generated nonce
    let mdocGeneratedNonce: String
    
    func encode(requestID: String? = nil) async throws -> EncodedDocumentWithDescriptorMap {
        // TODO: Third parameter contains invalid requested documents. Should be checked and handled.
        guard let (deviceResponse, _, _) = try MdocHelpers.getDeviceResponseToSend(
            deviceRequest: nil,
            issuerSigned: [docId: doc],
            selectedItems: [docId: selectedItems],
            eReaderKey: eReaderKey,
            devicePrivateKeys: [docId: devicePrivateKey],
            sessionTranscript: sessionTranscript,
            dauthMethod: .deviceSignature)
        else {
            throw PresentationSession.makeError(str: "DOCUMENT_ERROR")
        }
        guard let fc = inputDescriptor.formatContainer, let format = fc.formats.first?["designation"].string?.lowercased() else {
            throw PresentationSession.makeError(str: "Failed to encode MDocDocumentForPresentation: No format found in descriptor map")
        }
        let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
        var zkpMdoc: String?
        switch format {
        case "mso_mdoc":
            break
        case "mso_mdoc+zkp":
            guard let requestID else {
                throw PresentationSession.makeError(str: "No requestID for mdoc + zkp encode")
            }
            let zkpKey = try getECPublicKey(ZKP_ISSUER_PUBLIC_KEY)
            let generator = ZKPGenerator(issuerPublicKey: zkpKey)
            let prover = ZKPProverMDOC(zkpGenerator: generator)
            let requestData = try prover.createChallengeRequestData(mdoc: vpTokenStr)
            let challenges = try await ZKPClient().getChallenges(zkpRequestId: requestID, requestData: [(inputDescriptor.id, requestData)])
            guard let ecPublicKey = challenges.first?.1 else {
                throw PresentationSession.makeError(str: "No public key from challenge")
            }
            zkpMdoc = try prover.answerChallenge(ephemeralPublicKey: ecPublicKey, mdoc: vpTokenStr)
        default:
            throw PresentationSession.makeError(str: "Failed to encode MDocDocumentForPresentation: Unexpected format")
        }
        
        
        let singleDescriptorMap = DescriptorMapEntry(id: inputDescriptor.id, format: "mso_mdoc", path: "$") // $ will be later replaced by $[index] if multiple documents are submitted
        return EncodedDocumentWithDescriptorMap(encodedDocument: .msoMdoc(zkpMdoc != nil ? zkpMdoc! : vpTokenStr, apu: mdocGeneratedNonce.base64urlEncode), descriptorMapEntry: singleDescriptorMap)
    }
}


struct SDJWTDocumentForPresentation {
    let itemsToSend: RequestItems
    let signedSdjwt: SignedSDJWT
    let privateKey: Data
    let inputDescriptor: InputDescriptor
    let audience: String
    let nonce: String
    
    func encode(requestID: String? = nil) async throws -> EncodedDocumentWithDescriptorMap {
        let nameSpaceToItems = itemsToSend.first?.value
        let paths: [String] = nameSpaceToItems!.values.flatMap { $0 }
        let disclosureSelector = DisclosureSelector(signedSDJWT: signedSdjwt)
        let disclosures = try disclosureSelector.selectDisclosures(paths: paths)
        let alg = signedSdjwt.jwt.header.algorithm ?? .ES256
        let kbJWTProperties = KBJWTProperties(alg: alg, iat: Date(), aud: audience, nonce: nonce)
        guard let fc = inputDescriptor.formatContainer, let format = fc.formats.first?["designation"].string?.lowercased() else {
            throw PresentationSession.makeError(str: "Failed to encode SDJWTDocumentForPresentation: No format found in descriptor map")
        }
        var zkpSdjwt: SignedSDJWT?
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey.init(dataRepresentation: self.privateKey).toSecKey()
        switch format {
        case "vc+sd-jwt":
            break
        case "vc+sd-jwt+zkp":
            if let requestID {
                let zkpKey = try getECPublicKey(ZKP_ISSUER_PUBLIC_KEY)
                let generator = ZKPGenerator(issuerPublicKey: zkpKey)
                let prover = ZKPProverSDJWT(zkpGenerator: generator)
                let request = try prover.createChallengeRequestData(jwt: signedSdjwt.jwt.compactSerializedString)
                let challenges = try await ZKPClient().getChallenges(zkpRequestId: requestID, requestData: [(inputDescriptor.id,request)])
                if let firstChallenge = challenges.first {
                    let finalSdjwtZkp = try prover.answerChallenge(ephemeralPublicKey: firstChallenge.1, jwt: signedSdjwt.jwt.compactSerializedString)
                    zkpSdjwt = try SignedSDJWT(serializedJwt: finalSdjwtZkp, disclosures: disclosures, serializedKbJwt: nil)
                   
                }
            }

        default:
            throw PresentationSession.makeError(str: "Failed to encode SDJWTDocumentForPresentation: Unexpected format")
        }
        
        let holderSDJWTRepresentation = try SDJWTIssuer
        .presentation(holdersPrivateKey: privateKey,
                       signedSDJWT: zkpSdjwt != nil ? zkpSdjwt! : signedSdjwt,
                          disclosuresToPresent: disclosures,
                          keyBindingJWTProperties: kbJWTProperties)
        
        var serialisedSdjwt = CompactSerialiser(signedSDJWT: holderSDJWTRepresentation).serialised
        let singleDescriptorMap = DescriptorMapEntry(id: inputDescriptor.id, format: format, path: "$") // $ will be later replaced by $[index] if multiple documents are submitted
        return EncodedDocumentWithDescriptorMap(encodedDocument: .generic(serialisedSdjwt), descriptorMapEntry: singleDescriptorMap)
    }
}

struct EncodedDocumentWithDescriptorMap {
    let encodedDocument: VpToken
    let descriptorMapEntry: DescriptorMapEntry
}

enum DocumentForPresentation {
    case mdoc(MDocDocumentForPresentation)
    case sd_jwt(SDJWTDocumentForPresentation)
    
    func encode(requestID: String? = nil) async throws -> EncodedDocumentWithDescriptorMap {
        switch self {
        case .mdoc(let mDocDocumentForPresentation): return try await mDocDocumentForPresentation.encode(requestID: requestID)
        case .sd_jwt(let sdJWTDocumentForPresentation): return try await sdJWTDocumentForPresentation.encode(requestID: requestID)
        }
    }
}

public struct SdjwtData {
    public let id: String
    public let sdjwt: SignedSDJWT
    public let documentPrivateKey: Data
}

public struct SdjwtModel {
    public let id: String
    public let docType: String
    public let sdjwt: SignedSDJWT
    public let documentPrivateKey: Data?
}

extension WalletStorage.Document {
    func getSdjwtData() throws -> SdjwtData? {
        guard docDataType == .sjwt else {
            logger.warning("Tried to model to sdjwt: \(self)")
            return nil
        }
        let randomId = UUID().uuidString
        let sdjwtString = String(decoding: data, as: UTF8.self)
        let parser = CompactParser(serialisedString: sdjwtString)
        let sdjwt = try parser.getSignedSdJwt()
        guard let privateKey else {
            throw PresentationSession.makeError(str: "Failed to create mdocDocumentForPresentation")
        }
        return .init(id: randomId, sdjwt: sdjwt, documentPrivateKey: privateKey)
    }
}
