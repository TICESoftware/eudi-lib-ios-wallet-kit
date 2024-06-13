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

Created on 04/10/2023 
*/

import Foundation
import SwiftCBOR
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SiopOpenID4VP
import JOSESwift
import Logging
import X509
/// Implements remote attestation presentation to online verifier

/// Implementation is based on the OpenID4VP – Draft 18 specification

// TODO: The parameters only work with mdoc. Find out, what data is used for sd-jwt and merge them. OR: Make it an OpenID4VPMdocService
public class OpenId4VpService: PresentationService {
	public var status: TransferStatus = .initialized
    public var flow: FlowType
    
    // TODO: Refactor usage of those two to work with SD-JWT
    var state: MDocPresentationState // TODO: Find out which data we need for SD-JWT
    var mdocGeneratedNonce: String!
    var sessionTranscript: SessionTranscript!
    var eReaderPub: CoseKey? // Abstract to use any key (CoseKey or JSONWebKey)
    
    var openId4VpVerifierApiUri: String?
	var openId4VpVerifierLegalName: String?
    
	// map of document id to data
	var logger = Logger(label: "OpenId4VpService")
	var presentationDefinition: PresentationDefinition?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var readerAuthValidated: Bool = false
	var readerCertificateIssuer: String?
	var readerCertificateValidationMessage: String?
    
    init(state: MDocPresentationState, openId4VpVerifierApiUri: String?, openId4VpVerifierLegalName: String?) throws {
        self.state = state
        self.flow = .openID4VPOverHTTP
        self.openId4VpVerifierApiUri = openId4VpVerifierApiUri
		self.openId4VpVerifierLegalName = openId4VpVerifierLegalName
    }
	
	public func startQrEngagement() async throws -> String? { nil }
	
    private func receiveRequest(_ authorizationRequest: AuthorizationRequest) async throws -> [String: Any] {
        switch authorizationRequest {
        case .notSecured(data: _):
            throw PresentationSession.makeError(str: "Not secure request received.")
        case let .jwt(request: resolvedRequestData):
            self.resolvedRequestData = resolvedRequestData
            switch resolvedRequestData {
            case let .vpToken(vp):
                if let key = vp.clientMetaData?.jwkSet?.keys.first(where: { $0.use == "enc"}), let x = key.x, let xd = Data(base64URLEncoded: x), let y = key.y, let yd = Data(base64URLEncoded: y), let crv = key.crv, let crvType = MdocDataModel18013.ECCurveType(crvName: crv)  {
                    logger.info("Found jwks public key with curve \(crv)")
                    eReaderPub = CoseKey(x: [UInt8](xd), y: [UInt8](yd), crv: crvType)
                }
                let responseUri = if case .directPostJWT(let uri) = vp.responseMode { uri.absoluteString } else { "" }
                mdocGeneratedNonce = Openid4VpUtils.generateMdocGeneratedNonce()
                sessionTranscript = Openid4VpUtils.generateSessionTranscript(clientId: vp.client.id,
                                                                             responseUri: responseUri, nonce: vp.nonce, mdocGeneratedNonce: mdocGeneratedNonce)
                logger.info("Session Transcript: \(sessionTranscript.encode().toHexString()), for clientId: \(vp.client.id), responseUri: \(responseUri), nonce: \(vp.nonce), mdocGeneratedNonce: \(mdocGeneratedNonce!)")
                self.presentationDefinition = vp.presentationDefinition
                let items = try Openid4VpUtils.parsePresentationDefinition(vp.presentationDefinition, logger: logger)
                guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
                var result: [String: Any] = [UserRequestKeys.valid_items_requested.rawValue: items]
                if let readerCertificateIssuer {
                    result[UserRequestKeys.reader_auth_validated.rawValue] = readerAuthValidated
                    result[UserRequestKeys.reader_certificate_issuer.rawValue] = MdocHelpers.getCN(from: readerCertificateIssuer)
                    result[UserRequestKeys.reader_certificate_validation_message.rawValue] = readerCertificateValidationMessage
                }
                return result
            default: throw PresentationSession.makeError(str: "SiopAuthentication request received, not supported yet.")
            }
        }
    }
    
	///  Receive request from an openid4vp URL
	///
	/// - Returns: The requested items.
    public func receiveRequest(uri: URL) async throws -> [String: Any] {
        guard status != .error else { throw PresentationSession.makeError(str: "Can not receive request due to error state") }
        siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri, verifierLegalName: openId4VpVerifierLegalName))
        let authorizationRequest = try await siopOpenId4Vp.authorize(url: uri)
        return try await receiveRequest(authorizationRequest)
	}
	
	/// Send response via openid4vp
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ((URL?) -> Void)?) async throws {
		guard let pd = presentationDefinition, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await sendVpToken(nil, pd, resolved, onSuccess)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend)")
        guard let (deviceResponse, _, _) = try MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, issuerSigned: state.docs, selectedItems: itemsToSend, eReaderKey: eReaderPub, devicePrivateKeys: state.devicePrivateKeys, sessionTranscript: sessionTranscript, dauthMethod: .deviceSignature) else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		// Obtain consent
		let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
		try await sendVpToken(vpTokenStr, pd, resolved, onSuccess)
	}
	
	fileprivate func sendVpToken(_ vpTokenStr: String?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData, _ onSuccess: ((URL?) -> Void)?) async throws {
		let consent: ClientConsent = if let vpTokenStr {
			.vpToken(vpToken: .msoMdoc(vpTokenStr, apu: mdocGeneratedNonce.base64urlEncode), presentationSubmission: .init(id: UUID().uuidString, definitionID: pd.id, descriptorMap: pd.inputDescriptors.filter { $0.formatContainer?.formats.contains(where: { $0["designation"].string?.lowercased() == "mso_mdoc" }) ?? false }.map { DescriptorMap(id: $0.id, format: "mso_mdoc", path: "$")} ))
		} else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: getWalletConf(verifierApiUrl: openId4VpVerifierApiUri, verifierLegalName: openId4VpVerifierLegalName))
		let result: DispatchOutcome = try await siopOpenId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
			onSuccess?(url)
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
	}
	
	lazy var chainVerifier: CertificateTrust = { [weak self] certificates in
		let chainVerifier = X509CertificateChainVerifier()
		let verified = try? chainVerifier.verifyCertificateChain(base64Certificates: certificates)
		var result = chainVerifier.isChainTrustResultSuccesful(verified ?? .failure)
		guard let self, let b64cert = certificates.first, let data = Data(base64Encoded: b64cert), let cert = SecCertificateCreateWithData(nil, data as CFData), let x509 = try? X509.Certificate(derEncoded: [UInt8](data)) else { return result }
		self.readerCertificateIssuer = x509.subject.description
		let (isValid, validationMessages, _) = SecurityHelpers.isMdocCertificateValid(secCert: cert, usage: .mdocReaderAuth, rootCerts: state.iaca)
		self.readerAuthValidated = isValid
		self.readerCertificateValidationMessage = validationMessages.joined(separator: "\n")
		return result
	}
	
	/// OpenId4VP wallet configuration
	func getWalletConf(verifierApiUrl: String?, verifierLegalName: String?) -> WalletOpenId4VPConfiguration? {
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
					let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
		var supportedClientIdSchemes: [SupportedClientIdScheme] = [.x509SanUri(trust: chainVerifier), .x509SanDns(trust: chainVerifier)]
		if let verifierApiUrl, let verifierLegalName {
			let verifierMetaData = PreregisteredClient(clientId: "Verifier", legalName: verifierLegalName, jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(verifierApiUrl)/wallet/public-keys.json")!))
			supportedClientIdSchemes += [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])]
	  }
		let res = WalletOpenId4VPConfiguration(subjectSyntaxTypesSupported: [.decentralizedIdentifier, .jwkThumbprint], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: supportedClientIdSchemes, vpFormatsSupported: [])
		return res
	}
	
}

