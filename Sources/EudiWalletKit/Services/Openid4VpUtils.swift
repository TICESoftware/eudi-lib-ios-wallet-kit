/*
 *  Copyright (c) 2023-2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import Foundation
import SwiftCBOR
import CryptoKit
import Logging
import PresentationExchange
import MdocDataModel18013
import MdocSecurity18013
/**
 *  Utility class to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = nil,
 *  EReaderKeyBytes = nil
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = Data
 *  responseUriHash = Data
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = String
 *  clientId = String
 *  responseUri = String
 *  nonce = String
 *
 */

class Openid4VpUtils {
	
	static func generateSessionTranscript(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> SessionTranscript {
		let openID4VPHandover = generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri,	nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce)
		return SessionTranscript(handOver: openID4VPHandover)
	}
	
	static func generateOpenId4VpHandover(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> CBOR {
		let clientIdToHash = CBOR.encodeArray([clientId, mdocGeneratedNonce])
		let responseUriToHash = CBOR.encodeArray([responseUri, mdocGeneratedNonce])
		
		let clientIdHash = [UInt8](SHA256.hash(data: clientIdToHash))
		let responseUriHash = [UInt8](SHA256.hash(data: responseUriToHash))
		
		return CBOR.array([.byteString(clientIdHash), .byteString(responseUriHash), .utf8String(nonce)])
	}
	
    static func generateMdocGeneratedNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if result != errSecSuccess {
            logger.warning("Problem generating random bytes with SecRandomCopyBytes")
            bytes = (0 ..< 16).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) }
        }
        return Data(bytes).base64URLEncodedString()
    }
    
    /// Parse mDoc request from presentation definition (Presentation Exchange 2.0.0 protocol)
    static func parsePresentationDefinition(_ presentationDefinition: PresentationDefinition, logger: Logger? = nil) throws -> RequestItems? {
        // TODO: Use SiopOpenID4VP.match(presentationDefinition:)
        
        var res = RequestItems()
        for inputDescriptor in presentationDefinition.inputDescriptors {
            guard let fc = inputDescriptor.formatContainer else { logger?.warning("Input descriptor with id \(inputDescriptor.id) is invalid "); continue }
            // TODO: Support vc+sd-jwt here. Or actually, allow all formats here.
            let format = fc.formats.first?["designation"].string?.lowercased()
            switch format {
            case "vc+sd-jwt":
                let pathRx = try NSRegularExpression(pattern: "\\[\"\\$\\.(.*?)\"\\]", options: .caseInsensitive)
                let inputDescriptorId = inputDescriptor.id.trimmingCharacters(in: .whitespacesAndNewlines)
                let kvs: [String] = inputDescriptor.constraints.fields.compactMap(\.paths.first).compactMap { Self.parsePathSdjwt($0, pathRx: pathRx) }
                let namespace = inputDescriptor.id
                let nsItems = [namespace : kvs]
                if !nsItems.isEmpty { res[inputDescriptorId] = nsItems }
            case "mso_mdoc":
                let pathRx = try NSRegularExpression(pattern: "\\$\\['([^']+)'\\]\\['([^']+)'\\]", options: .caseInsensitive)
                let inputDescriptorId = inputDescriptor.id.trimmingCharacters(in: .whitespacesAndNewlines)
                let kvs: [(String, String)] = inputDescriptor.constraints.fields.compactMap(\.paths.first).compactMap { Self.parsePath($0, pathRx: pathRx) }
                let nsItems = Dictionary(grouping: kvs, by: \.0).mapValues { $0.map(\.1) }
                if !nsItems.isEmpty { res[inputDescriptorId] = nsItems }
            default:
                logger?.warning("Input descriptor with id \(inputDescriptor.id) does not contain format mso_mdoc or vc+sd-jwt")
            }
        }
        return res
    }
    
    static func parsePathSdjwt(_ path: String, pathRx: NSRegularExpression) -> String? {
        guard let match = pathRx.firstMatch(in: path, options: [], range: NSRange(location: 0, length: path.utf16.count)) else {
            return nil
        }
        let r1 = match.range(at: 1)
        let r1l = path.index(path.startIndex, offsetBy: r1.location)
        let r1r = path.index(r1l, offsetBy: r1.length)
        return String(path[r1l..<r1r])
    }
    
    static func parsePath(_ path: String, pathRx: NSRegularExpression) -> (String, String)? {
        guard let match = pathRx.firstMatch(in: path, options: [], range: NSRange(location: 0, length: path.utf16.count)) else { return nil }
        let r1 = match.range(at:1);
        let r1l = path.index(path.startIndex, offsetBy: r1.location)
        let r1r = path.index(r1l, offsetBy: r1.length)
        let r2 = match.range(at: 2)
        let r2l = path.index(path.startIndex, offsetBy: r2.location)
        let r2r = path.index(r2l, offsetBy: r2.length)
        return (String(path[r1l..<r1r]), String(path[r2l..<r2r]))
    }
    
    static func parseFormatContainer(_ formatContainer: FormatContainer) -> Set<ClaimFormat> {
        let formats = formatContainer.formats.compactMap { json -> ClaimFormat? in
            guard let designation = json["designation"].string else { return nil }
            return ClaimFormat(formatIdentifier: designation.lowercased())
        }
        return Set(formats)
    }
    
    // TODO: What format should the VP be in? The verifier is required (https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-9.1-2.2) to provide metadata about their supported `vp_formats`. We now base the format of the input descriptor based on code from the wallet kit
    static func determineVerfiablePresentationFormat(availableDocumentFormats: Set<ClaimFormat>, supportedDataFormatsByVerifier: Set<ClaimFormat>, walletSupportedDataFormats: Set<ClaimFormat>, presentationDefinition: PresentationDefinition, inputDescriptor: InputDescriptor) throws -> ClaimFormat {
        
        let usableDataFormats = supportedDataFormatsByVerifier.intersection(walletSupportedDataFormats)
        guard !usableDataFormats.isEmpty else { throw PresentationSession.makeError(str: "No common data formats") }
        
        let requestedFormats: Set<ClaimFormat>
        if let inputDescriptorFormat = inputDescriptor.formatContainer {
            requestedFormats = parseFormatContainer(inputDescriptorFormat)
        } else if let presentationDefinitionFormat = presentationDefinition.formatContainer {
            requestedFormats = parseFormatContainer(presentationDefinitionFormat)
        } else {
            requestedFormats = []
        }
        
        guard supportedDataFormatsByVerifier.isSuperset(of: requestedFormats) else {
            throw PresentationSession.makeError(str: "Verifier requested formats it does not support itself")
        }
        
        if requestedFormats.isEmpty {
            let availableSupportedFormats = availableDocumentFormats.intersection(supportedDataFormatsByVerifier)
            guard !availableSupportedFormats.isEmpty else {
                throw PresentationSession.makeError(str: "Verifier does not support any of the formats we have")
            }
            return availableSupportedFormats.first!
        } else {
            let availableRequestedFormats = availableDocumentFormats.intersection(requestedFormats)
            guard !availableDocumentFormats.isEmpty else {
                throw PresentationSession.makeError(str: "Verifier requested a format we do not have")
            }
            return availableRequestedFormats.first!
        }
    }
}

extension ECCurveType {
	init?(crvName: String) {
		switch crvName {
		case "P-256": self = .p256
		case "P-384": self = .p384
		case "P-512": self = .p521
		default: return nil
		}
	}
}
