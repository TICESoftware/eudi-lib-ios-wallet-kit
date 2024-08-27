import Foundation
import Security
import SwiftECC

let ZKP_ISSUER_PUBLIC_KEY = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOFBq4YMKg4w5fTifsytwBuJf/7E7
VhRPXiNm52S3q1ETIgBdXyDK3kVxGxgeHPivLP3uuMvS6iDEc7qMxmvduA==
-----END PUBLIC KEY-----
"""

func getECPublicKey(_ certString: String) throws -> ECPublicKey {
    return try .init(pem: certString)
}

