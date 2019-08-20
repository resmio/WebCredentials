//
//  WebCredentials.swift
//  WebCredentials
//
//  Created by Jan Nash (resmio) on 20.08.19.
//  Copyright © 2019 Jan Nash (resmio). All rights reserved.
//

import Security


// MARK: // Public
// MARK: Enum Declaration
public enum WebCredentials {
    // Nested Types
    public typealias Credential = (account: String, password: String)
    
    public enum Result {
        case credential(Credential)
        case noCredentialsFound
        case userCancelled
        case error(Error)
    }
    
    // Credential CRUD
    public static func request(fqdn: String?, completion: @escaping (Result) -> Void) {
        self._request(fqdn: fqdn, completion: completion)
    }
    
    public static func save(credential: Credential, fqdn: String, completion: @escaping (Error?) -> Void) {
        SecAddSharedWebCredential(fqdn as CFString, credential.account as CFString, credential.password as CFString?, completion)
    }
    
    public static func delete(account: String, fqdn: String, completion: @escaping (Error?) -> Void) {
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
        SecRequestSharedWebCredential(fqdn as CFString?, nil) { webCredentials, requestError in
            if let error: CFError = requestError {
                let errorDomain: String = CFErrorGetDomain(error) as String
                let errorCode: Int = CFErrorGetCode(requestError)
                let noCredentialsFound: Bool = errorDomain == NSOSStatusErrorDomain && errorCode == Int(errSecItemNotFound)
                
                if noCredentialsFound {
                    completion(.noCredentialsFound)
                    return
                }
                
                completion(.error(error))
                return
            }
            
            guard let credentials = webCredentials, CFArrayGetCount(credentials) > 0 else {
                completion(.userCancelled)
                return
            }
            
            let unsafeCredential = CFArrayGetValueAtIndex(credentials, 0)
            let credentialDictionary = unsafeBitCast(unsafeCredential, to: CFDictionary.self)
            
            let account: String = self._getValue(for: kSecAttrAccount, from: credentialDictionary)
            let password: String = self._getValue(for: kSecSharedPassword, from: credentialDictionary)
            
            completion(.credential((account, password)))
        }
    }
    
    // Helpers
    static func _getValue(for key: CFString, from credentialDict: CFDictionary) -> String {
        let opaqueKey: UnsafeMutableRawPointer = Unmanaged.passUnretained(key).toOpaque()
        let unsafeValue: UnsafeRawPointer = CFDictionaryGetValue(credentialDict, opaqueKey)
        return unsafeBitCast(unsafeValue, to: CFString.self) as String
    }
}
