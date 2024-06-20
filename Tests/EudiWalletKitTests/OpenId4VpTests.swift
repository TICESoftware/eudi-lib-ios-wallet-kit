/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import XCTest
import SiopOpenID4VP
import SwiftyJSON
@testable import EudiWalletKit

final class OpenId4VpTests: XCTestCase {
    
    static func parsed(_ presentationDefinitionString: String) -> PresentationDefinition {
        let parser = Parser()
        let result: Result<PresentationDefinition, ParserError> = parser.decode(
            json: presentationDefinitionString
        )
        return try! result.get()
    }
    
    func testDetermineVerifiablePresentationFormat_noCommon() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        do {
            _ = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([.jwtType(.jwt_vp)]),
                                                                        supportedDataFormatsByVerifier: Set([.msoMdoc]),
                                                                        walletSupportedDataFormats: Set([.jwtType(.jwt_vp)]),
                                                                        presentationDefinition: presentationDefinition,
                                                                        inputDescriptor: inputDescriptor)
            XCTFail("Should not continue to here")
        } catch {
            
        }
    }
    
    func testDetermineVerifiablePresentationFormat_chooseCommonFromMetadata() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        let format = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([.jwtType(.jwt_vp), .msoMdoc]),
                                                                             supportedDataFormatsByVerifier: Set([.msoMdoc, .jwtType(.jwt)]),
                                                                             walletSupportedDataFormats: Set([.ldpType(.ldp), .msoMdoc]),
                                                                             presentationDefinition: presentationDefinition,
                                                                             inputDescriptor: inputDescriptor)
        
        XCTAssertEqual(format, .msoMdoc)
    }
    
    func testDetermineVerifiablePresentationFormat_chooseAnyCommon() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        let format = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             supportedDataFormatsByVerifier: Set([.msoMdoc, .jwtType(.jwt)]),
                                                                             walletSupportedDataFormats: Set([.ldpType(.ldp), .msoMdoc, .jwtType(.jwt)]),
                                                                             presentationDefinition: presentationDefinition,
                                                                             inputDescriptor: inputDescriptor)
        
        XCTAssertTrue([ClaimFormat.msoMdoc, .jwtType(.jwt)].contains(format))
    }
    
    func testDetermineVerifiablePresentationFormat_chooseAvailableCommon() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        for availableFormat in [ClaimFormat.msoMdoc, .jwtType(.jwt)] {
            let format = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([availableFormat]),
                                                                                 supportedDataFormatsByVerifier: Set([.msoMdoc, .jwtType(.jwt)]),
                                                                                 walletSupportedDataFormats: Set([.ldpType(.ldp), .msoMdoc, .jwtType(.jwt)]),
                                                                                 presentationDefinition: presentationDefinition,
                                                                                 inputDescriptor: inputDescriptor)
            XCTAssertEqual(format, availableFormat)
        }
    }
    
    func testDetermineVerifiablePresentationFormat_chooseDefinedByPresentationDefinition() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "format": {
            "mso_mdoc": {
              "alg": [
                "ES256"
              ]
            }
          },
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        let format = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             supportedDataFormatsByVerifier: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             walletSupportedDataFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             presentationDefinition: presentationDefinition,
                                                                             inputDescriptor: inputDescriptor)
        XCTAssertEqual(.msoMdoc, format)
    }
    
    func testDetermineVerifiablePresentationFormat_chooseDefinedByInputDescriptor() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "format": {
                "mso_mdoc": {
                  "alg": [
                    "ES256"
                  ]
                }
              },
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        let format = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             supportedDataFormatsByVerifier: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             walletSupportedDataFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             presentationDefinition: presentationDefinition,
                                                                             inputDescriptor: inputDescriptor)
        XCTAssertEqual(.msoMdoc, format)
    }
    
    func testDetermineVerifiablePresentationFormat_chooseDefinedByInputDescriptorIgnorePresentationDefinition() throws {
        let presentationDefinitionString = """
        {
          "id": "123",
          "format": {
            "vc+sd-jwt": {
              "sd-jwt_alg_values": [
                "ES256"
              ]
            }
          },
          "input_descriptors": [
            {
              "id": "eu.europa.ec.eudiw.pid.1",
              "format": {
                "mso_mdoc": {
                  "alg": [
                    "ES256"
                  ]
                }
              },
              "constraints": {
                "fields": [
                ]
              }
            }
          ]
        }
        """
        
        let presentationDefinition = Self.parsed(presentationDefinitionString)
        let inputDescriptor = presentationDefinition.inputDescriptors.first!
        
        let format = try Openid4VpUtils.determineVerfiablePresentationFormat(availableDocumentFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             supportedDataFormatsByVerifier: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             walletSupportedDataFormats: Set([.jwtType(.jwt), .msoMdoc]),
                                                                             presentationDefinition: presentationDefinition,
                                                                             inputDescriptor: inputDescriptor)
        XCTAssertEqual(.msoMdoc, format)
    }
}
