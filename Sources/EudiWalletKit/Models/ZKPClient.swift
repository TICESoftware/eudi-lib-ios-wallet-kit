import Foundation
import CryptoKit
import SiopOpenID4VP
import ZKP_Swift
import SwiftECC

struct ZkpRequest: Codable {
    let id: String
    let digest: String
    let r: String
    let proofType: String
    
    enum CodingKeys: String, CodingKey {
        case id, digest, r, proofType
        //case proofType = "proof_type"
    }
}

struct ZkpResponse: Codable {
    let id: String
    let kid: String
    let kty: String
    let crv: String
    let x: String
    let y: String
}

// ZKPClient class
class ZKPClient {
    private let baseUrl: String
    private let session: Networking
    
    init(baseUrl: String = "https://staging.verifier.wallet.tice.software/wallet/zkp/") {
        self.baseUrl = baseUrl
        self.session = URLSession.shared
    }
    
    func getChallenges(zkpRequestId: String, requestData: [(String, ChallengeRequestData)]) async throws -> [(String, ECPublicKey)] {
        let zkpRequests = requestData.map { ZkpRequest(id: $0.0, digest: $0.1.digest, r: $0.1.r, proofType: "secp256r1-sha256") }
        let endpoint = "\(baseUrl)\(zkpRequestId)/jwks.json"
        
        guard let url = URL(string: endpoint) else {
            throw URLError(.badURL)
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json; charset=UTF-8", forHTTPHeaderField: "Content-Type")
        
        let encoder = JSONEncoder()
        request.httpBody = try encoder.encode(zkpRequests)
        
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
        
        let decoder = JSONDecoder()
        let zkpResponses = try decoder.decode([ZkpResponse].self, from: data)
        
        return try zkpResponses.map { response in
            guard var xData = Data(base64URLEncoded: response.x), let yData = Data(base64URLEncoded: response.y) else {
                throw URLError(.cannotDecodeContentData)
            }
            let w: Point = .init(.init(magnitude: xData.bytes), .init(magnitude: yData.bytes))
            let ecPublicKey = try ECPublicKey(domain: .instance(curve: .EC256r1), w: w)
            return (response.id, ecPublicKey)
        }
    }
}
