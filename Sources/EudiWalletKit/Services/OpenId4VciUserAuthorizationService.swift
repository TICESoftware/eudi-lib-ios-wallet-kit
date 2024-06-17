import Foundation
import AuthenticationServices
import Logging
import OpenID4VCI

public protocol OpenId4VciUserAuthorizationService {
    var config: OpenId4VCIConfig { get }
    var logger: Logger { get }
    
    @MainActor
    func getAuthorizationCode(requestURL: URL) async throws -> String?
}

public class OpenId4VciUserAuthorizationServiceDefault: NSObject, OpenId4VciUserAuthorizationService, ASWebAuthenticationPresentationContextProviding {
    public var config: OpenId4VCIConfig
    public var logger: Logging.Logger
    
    public init(config: OpenId4VCIConfig) {
        self.config = config
        self.logger = Logger(label: "OpenId4VCI")
    }
    
    @MainActor
    public func getAuthorizationCode(requestURL: URL) async throws -> String? {
        logger.info("--> [AUTHORIZATION] Retrieving Authorization Code using default AuthorizationService with request URL \(requestURL)")
        return try await withCheckedThrowingContinuation { c in
            let authenticationSession = ASWebAuthenticationSession(url: requestURL, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { optionalUrl, optionalError in
                guard optionalError == nil else { c.resume(throwing: OpenId4VCIError.authRequestFailed(optionalError!)); return }
                guard let url = optionalUrl else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl); return }
                guard let code = url.getQueryStringParameter("code") else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoCode); return }
                c.resume(returning: code)
            }
            authenticationSession.prefersEphemeralWebBrowserSession = true
            authenticationSession.presentationContextProvider = self
            authenticationSession.start()
        }
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession)
    -> ASPresentationAnchor {
#if os(iOS)
        let window = UIApplication.shared.windows.first { $0.isKeyWindow }
        return window ?? ASPresentationAnchor()
#else
        return ASPresentationAnchor()
#endif
    }
}

public class OpenId4VciUserAuthorizationServiceEIDReader: NSObject, OpenId4VciUserAuthorizationService, ASWebAuthenticationPresentationContextProviding {
    public var config: OpenId4VCIConfig
    public var logger: Logging.Logger
    
    public init(config: OpenId4VCIConfig) {
        self.config = config
        self.logger = Logger(label: "OpenId4VCI")
    }
    
    @MainActor
    public func getAuthorizationCode(requestURL: URL) async throws -> String? {
        logger.info("--> [AUTHORIZATION] Starting EID Flow with request URL \(requestURL)")
        
        return try await withCheckedThrowingContinuation { c in
            let authenticationSession = ASWebAuthenticationSession(url: requestURL, callbackURLScheme: config.authFlowRedirectionURI.scheme!) { optionalUrl, optionalError in
                guard optionalError == nil else { c.resume(throwing: OpenId4VCIError.authRequestFailed(optionalError!)); return }
                guard let url = optionalUrl else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoUrl); return }
                guard let code = url.getQueryStringParameter("code") else { c.resume(throwing: OpenId4VCIError.authorizeResponseNoCode); return }
                c.resume(returning: code)
            }
            authenticationSession.prefersEphemeralWebBrowserSession = true
            authenticationSession.presentationContextProvider = self
            authenticationSession.start()
        }
    }
    
    public func presentationAnchor(for session: ASWebAuthenticationSession)
    -> ASPresentationAnchor {
#if os(iOS)
        let window = UIApplication.shared.windows.first { $0.isKeyWindow }
        return window ?? ASPresentationAnchor()
#else
        return ASPresentationAnchor()
#endif
    }
}

fileprivate extension URL {
    func getQueryStringParameter(_ parameter: String) -> String? {
        guard let url = URLComponents(string: self.absoluteString) else { return nil }
        return url.queryItems?.first(where: { $0.name == parameter })?.value
    }
}
