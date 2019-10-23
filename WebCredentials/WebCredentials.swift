//
//  WebCredentials.swift
//  WebCredentials
//
//  Created by Jan Nash (resmio) on 20.08.19.
//  Copyright © 2019 Jan Nash (resmio). All rights reserved.
//

import Foundation
import Security


// MARK: // Public
// MARK: Enum Declaration
public enum WebCredentials {
    // Nested Types
    public typealias Credential = (account: String, password: String, server: String, port: Int)
    
    public enum Result {
        case credential(Credential)
        case noCredentialsFound
        case userCancelled
        case error(Error)
    }
    
    // Credential CRUD
    public static func request(fqdn: String? = nil, account: String? = nil, completion: @escaping (Result) -> Void) {
        self._request(fqdn: fqdn, completion: completion)
    }
    
    public static func save(fqdn: String, credential: Credential, completion: @escaping (Error?) -> Void) {
        SecAddSharedWebCredential(fqdn as CFString, credential.account as CFString, credential.password as CFString, completion)
    }
    
    public static func delete(fqdn: String, account: String, completion: @escaping (Error?) -> Void) {
        SecAddSharedWebCredential(fqdn as CFString, account as CFString, nil, completion)
    }
    
    // Password Generation
    public static func generatePassword() -> String? {
        return SecCreateSharedWebCredentialPassword() as String?
    }
}


// MARK: // Private
// MARK: Interface Implementations
private extension WebCredentials {
    static func _request(fqdn: String?, completion: @escaping (Result) -> Void) {
        SecRequestSharedWebCredential(fqdn as CFString?, nil) {
            if let error: CFError = $1 {
                let errorDomain: String = CFErrorGetDomain(error) as String
                let errorCode: Int = CFErrorGetCode(error)
                let noCredentialsFound: Bool = errorDomain == NSOSStatusErrorDomain && errorCode == Int(errSecItemNotFound)
                completion(noCredentialsFound ? .noCredentialsFound : .error(error))
                return
            }
            
            guard let credentials = $0, CFArrayGetCount(credentials) > 0 else {
                completion(.userCancelled)
                return
            }
            
            let credentialDict: CFDictionary = unsafeBitCast(CFArrayGetValueAtIndex(credentials, 0), to: CFDictionary.self)
            
            let account: String = self._getValue(for: kSecAttrAccount, from: credentialDict)
            let password: String = self._getValue(for: kSecSharedPassword, from: credentialDict)
            let server: String = self._getValue(for: kSecAttrServer, from: credentialDict)
            let port: Int = self._getPort(from: credentialDict)
            
            completion(.credential((account, password, server, port)))
        }
    }
    
    // Helpers
    static func _getValue(for key: CFString, from credentialDict: CFDictionary) -> String {
        return unsafeBitCast(self._getUnsafeValue(for: key, from: credentialDict), to: CFString.self) as String
    }
    
    static func _getPort(from credentialDict: CFDictionary) -> Int {
        guard let value: UnsafeRawPointer = self._getUnsafeValue(for: kSecAttrPort, from: credentialDict) else {
            // As documented here: https://developer.apple.com/documentation/security/1617896-secrequestsharedwebcredential
            return 443
        }
        return (unsafeBitCast(value, to: CFNumber.self) as NSNumber).intValue
    }
    
    static func _getUnsafeValue(for key: CFString, from credentialDict: CFDictionary) -> UnsafeRawPointer? {
        return CFDictionaryGetValue(credentialDict, Unmanaged.passUnretained(key).toOpaque())
    }
}
