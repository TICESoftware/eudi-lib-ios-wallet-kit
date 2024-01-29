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

import Foundation
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import WalletStorage
import LocalAuthentication
import CryptoKit

/// User wallet implementation
public final class EudiWallet: ObservableObject {
	/// Storage manager instance
	public private(set) var storage: StorageManager
	var storageService: any WalletStorage.DataStorageService { storage.storageService }
	/// Instance of the wallet initialized with default parameters
	public static private(set) var standard: EudiWallet = EudiWallet()
	/// Whether user authentication via biometrics or passcode is required before sending user data
	public var userAuthenticationRequired: Bool
	/// Trusted root certificates to validate the reader authentication certificate included in the proximity request
	public var trustedReaderCertificates: [Data]?
	/// Method to perform mdoc authentication (MAC or signature). Defaults to device MAC
	public var deviceAuthMethod: DeviceAuthMethod = .deviceMac
	/// OpenID4VP verifier api URL (used for preregistered clients)
	public var verifierApiUri: String?
	/// OpenID4VCI issuer url
	public var openID4VciIssuerUrl: String?
	/// OpenID4VCI client id
	public var openID4VciClientId: String?
	var vciRedirectUri: String = "eudi-openid4ci://authorize/"
	/// Use iPhone Secure Enclave to protect keys and perform cryptographic operations. Defaults to true (if available)
	public var useSecureEnclave: Bool { didSet { if !SecureEnclave.isAvailable { useSecureEnclave = false } } }
	
	/// Initialize a wallet instance. All parameters are optional.
	public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, verifierApiUri: String? = nil, openID4VciIssuerUrl: String? = nil, openID4VciClientId: String? = nil) {
		let keyChainObj = KeyChainStorageService(serviceName: serviceName, accessGroup: accessGroup)
		let storageService = switch storageType { case .keyChain:keyChainObj }
		storage = StorageManager(storageService: storageService)
		self.trustedReaderCertificates = trustedReaderCertificates
		self.userAuthenticationRequired = userAuthenticationRequired
		self.verifierApiUri	= verifierApiUri
		self.openID4VciIssuerUrl = openID4VciIssuerUrl
		self.openID4VciClientId = openID4VciClientId
		useSecureEnclave = SecureEnclave.isAvailable
	}
	
	/// Issue a document with the given docType using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	///  - Parameters:
	///   - docType: Document type
	///   - format: Optional format type. Defaults to cbor
	/// - Returns: The document issued. It is saved in storage.
   @discardableResult public func issueDocument(docType: String, format: DataFormat = .cbor) async throws -> WalletStorage.Document {
		guard let openID4VciIssuerUrl else { throw WalletError(description: "issuer Url not defined")}
		guard let openID4VciClientId else { throw WalletError(description: "clientId not defined")}
		let id: String = UUID().uuidString
	   try await Self.authorizedAction(action: {
		   _ = try await beginIssueDocument(id: id, privateKeyType: useSecureEnclave ? .secureEnclaveP256 : .x963EncodedP256)
	   }, disabled: !userAuthenticationRequired, dismiss: {}, localizedReason: NSLocalizedString("issue_document", comment: "").replacingOccurrences(of: "{docType}", with: NSLocalizedString(docType, comment: "")))
	   guard let issueReq = try IssueRequest(storageService, id: id) else { throw WalletError(description: "Cannot store private key") }
	   let openId4VCIService = OpenId4VCIService(issueRequest: issueReq, credentialIssuerURL: openID4VciIssuerUrl, clientId: openID4VciClientId, callbackScheme: vciRedirectUri)
		let data = try await openId4VCIService.issueDocument(docType: docType, format: format, useSecureEnclave: useSecureEnclave)
		guard let ddt = DocDataType(rawValue: format.rawValue) else { throw WalletError(description: "Invalid format \(format.rawValue)") }
		 var issued: WalletStorage.Document
		 if !openId4VCIService.usedSecureEnclave {
			 issued = WalletStorage.Document(id: id, docType: docType, docDataType: ddt, data: data, privateKeyType: .x963EncodedP256, privateKey: issueReq.keyData, createdAt: Date())
		 } else {
			 issued = WalletStorage.Document(id: id, docType: docType, docDataType: ddt, data: data, privateKeyType: .secureEnclaveP256, privateKey: issueReq.keyData, createdAt: Date())
		 }
		try endIssueDocument(issued)
		await storage.appendDocModel(issued)
		await storage.refreshPublishedVars()
		return issued
	}
		
	/// Begin issuing a document by generating an issue request
	///
	/// - Parameters:
	///   - id: Document identifier
	///   - issuer: Issuer function
	public func beginIssueDocument(id: String, privateKeyType: PrivateKeyType = .secureEnclaveP256) async throws -> IssueRequest {
		let request = try IssueRequest(id: id, privateKeyType: privateKeyType)
		try request.saveToStorage(storage.storageService)
		return request
	}
	
	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document) throws {
		try storage.storageService.saveDocumentData(issued, dataToSaveType: .doc, dataType: issued.docDataType.rawValue, allowOverwrite: true)
		try storage.storageService.saveDocumentData(issued, dataToSaveType: .key, dataType: issued.privateKeyType!.rawValue, allowOverwrite: true)
	}
	
	/// Load documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]? {
		return try await storage.loadDocuments()
	}

	/// Delete all documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	public func deleteDocuments() async throws  {
		return try await storage.deleteDocuments()
	}
	
	/// Load sample data from json files
	///
	/// The mdoc data are stored in wallet storage as documents
	/// - Parameter sampleDataFiles: Names of sample files provided in the app bundle
	public func loadSampleData(sampleDataFiles: [String]? = nil) async throws {
		try? storageService.deleteDocuments()
		let docSamples = (sampleDataFiles ?? ["EUDI_sample_data"]).compactMap { Data(name:$0) }
			.compactMap(SignUpResponse.decomposeCBORSignupResponse(data:)).flatMap {$0}
			.map { Document(docType: $0.docType, docDataType: .cbor, data: $0.drData, privateKeyType: .x963EncodedP256, privateKey: $0.pkData, createdAt: Date.distantPast, modifiedAt: nil) }
		do {
		for docSample in docSamples {
			try storageService.saveDocument(docSample, allowOverwrite: true)
		}
		try await storage.loadDocuments()
		} catch {
			await storage.setError(error)
			throw WalletError(description: error.localizedDescription, code: (error as NSError).code)
		}
	}
	
	/// Prepare Service Data Parameters
	/// - Parameters:
	///   - docType: docType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A data dictionary that can be used to initialize a presentation service
	public func prepareServiceDataParameters(docType: String? = nil, dataFormat: DataFormat = .cbor ) throws -> [String : Any] {
		var parameters: [String: Any]
		switch dataFormat {
		case .cbor:
			guard var docs = try storageService.loadDocuments(), docs.count > 0 else { throw WalletError(description: "No documents found") }
			if let docType { docs = docs.filter { $0.docType == docType} }
			if let docType { guard docs.count > 0 else { throw WalletError(description: "No documents of type \(docType) found") } }
			let cborsWithKeys = docs.compactMap { $0.getCborData() }
			guard cborsWithKeys.count > 0 else { throw WalletError(description: "Documents decode error") }
			parameters = [InitializeKeys.document_signup_response_obj.rawValue: cborsWithKeys.map(\.dr), InitializeKeys.device_private_key_obj.rawValue: cborsWithKeys.first!.dpk]
			if let trustedReaderCertificates { parameters[InitializeKeys.trusted_certificates.rawValue] = trustedReaderCertificates }
			parameters[InitializeKeys.device_auth_method.rawValue] = deviceAuthMethod.rawValue
		default:
			fatalError("jwt format not implemented")
		}
		return parameters
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - docType: DocType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(flow: FlowType, docType: String? = nil, dataFormat: DataFormat = .cbor) -> PresentationSession {
		do {
			let parameters = try prepareServiceDataParameters(docType: docType, dataFormat: dataFormat)
			switch flow {
			case .ble:
				let bleSvc = try BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc, userAuthenticationRequired: userAuthenticationRequired)
			case .openid4vp(let qrCode):
				let openIdSvc = try OpenId4VpService(parameters: parameters, qrCode: qrCode, openId4VpVerifierApiUri: self.verifierApiUri)
				return PresentationSession(presentationService: openIdSvc, userAuthenticationRequired: userAuthenticationRequired)
			default:
				return PresentationSession(presentationService: FaultPresentationService(error: PresentationSession.makeError(str: "Use beginPresentation(service:)")), userAuthenticationRequired: false)
			}
		} catch {
			return PresentationSession(presentationService: FaultPresentationService(error: error), userAuthenticationRequired: false)
		}
	}
	
	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - service: A ``PresentationService`` instance
	///   - docType: DocType of documents to present (optional)
	///   - dataFormat: Exchanged data ``Format`` type
	/// - Returns: A presentation session instance,
	public func beginPresentation(service: any PresentationService) -> PresentationSession {
		PresentationSession(presentationService: service, userAuthenticationRequired: userAuthenticationRequired)
	}
	
	@MainActor
	/// Perform an action after user authorization via TouchID/FaceID/Passcode
	/// - Parameters:
	///   - dismiss: Action to perform if the user cancels authorization
	///   - action: Action to perform after user authorization
	public static func authorizedAction(action: () async throws -> Void, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws {
		try await authorizedAction(isFallBack: false, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
	}
	
	/// Wrap an action with TouchID or FaceID authentication
	/// - Parameters:
	///   - isFallBack: true if fallback (ask for pin code)
	///   - dismiss: action to dismiss current page
	///   - action: action to perform after authentication
	static func authorizedAction(isFallBack: Bool = false, action: () async throws -> Void, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws {
		guard !disabled else {
			try await action()
			return
		}
		let context = LAContext()
		var error: NSError?
		let policy: LAPolicy = .deviceOwnerAuthentication
		if context.canEvaluatePolicy(policy, error: &error) {
			do {
				let success = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
				if success {
					try await action()
				}
				else { dismiss()}
			} catch let laError as LAError {
				if !isFallBack, laError.code == .userFallback {
					try await authorizedAction(isFallBack: true, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
				} else { dismiss() }
			}
		} else if let error {
			throw WalletError(description: error.localizedDescription, code: error.code)
		}
	}
}
