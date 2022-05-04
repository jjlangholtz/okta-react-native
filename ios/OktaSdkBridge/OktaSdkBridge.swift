/*
 * Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import Foundation
import OktaOidc

// MARK: - OktaOidcProtocol

protocol OktaOidcProtocol: AnyObject {
    var configuration: OktaOidcConfig { get }
    
    func signInWithBrowser(from presenter: UIViewController,
                           additionalParameters: [String : String],
                           callback: @escaping ((OktaOidcStateManager?, Error?) -> Void))
    
    func signOutOfOkta(_ authStateManager: OktaOidcStateManager,
                       from presenter: UIViewController,
                       callback: @escaping ((Error?) -> Void))
    
    func authenticate(withSessionToken sessionToken: String,
                      callback: @escaping ((OktaOidcStateManager?, Error?) -> Void))
}

extension OktaOidc: OktaOidcProtocol {
    
}

// MARK: - StateManagerProtocol

protocol StateManagerProtocol: AnyObject {
    var accessToken: String? { get }
    var idToken: String? { get }
    var refreshToken: String? { get }
    
    func getUser(_ callback: @escaping ([String:Any]?, Error?) -> Void)
    func renew(callback: @escaping ((OktaOidcStateManager?, Error?) -> Void))
    func revoke(_ token: String?, callback: @escaping (Bool, Error?) -> Void)
    func introspect(token: String?, callback: @escaping ([String : Any]?, Error?) -> Void)
    func removeFromSecureStorage() throws
}

extension OktaOidcStateManager: StateManagerProtocol {
    
}

// MARK: - DeviceSecretProtocol

class DeviceSecretKeychain {
    var key: String
    var group: String

    init(key: String, group: String) {
        self.key = key
        self.group = group
    }

    func get() -> (idToken: String?, deviceSecret: String?) {
        let query: [String: Any] = [
            (kSecClass as String): kSecClassGenericPassword,   // only Password items can use iCloud keychain
            (kSecAttrSynchronizable as String): kCFBooleanTrue!,  // allow iCloud
            (kSecAttrLabel as String): self.key,       // tag to make it easy to search
            (kSecAttrAccessGroup as String): self.group,   // multiple apps can share through this group
            (kSecMatchLimit as String): kSecMatchLimitOne,    // should only have one key
            (kSecReturnAttributes as String): true,
            (kSecReturnData as String): true]
        var item: CFTypeRef?

        SecItemCopyMatching(query as CFDictionary, &item)

        if let existingItem = item as? [String: Any],
            let idToken = existingItem[kSecAttrAccount as String] as? String,
            let deviceSecretData = existingItem[kSecValueData as String] as? Data {
            let deviceSecret = String(data: deviceSecretData, encoding: .utf8)
            return (idToken, deviceSecret)
        }
        return (nil, nil)
    }

    func set(idToken: String, deviceSecret: String) {
        let attributes: [String: Any] = [
            (kSecClass as String): kSecClassGenericPassword,    // only Password items can use iCloud keychain
            (kSecAttrSynchronizable as String): kCFBooleanTrue!,  // allow iCloud
            (kSecAttrLabel as String): self.key,        // tag to make it easy to search
            (kSecAttrAccessGroup as String): self.group,   // multiple apps can share through this group
            (kSecAttrAccount as String): idToken,
            (kSecValueData as String): deviceSecret.data(using: .utf8)!
        ]

        SecItemAdd(attributes as CFDictionary, nil)
    }

    func remove() {
        let query: [String: Any] = [
            (kSecClass as String): kSecClassGenericPassword,  // only Password items can use iCloud keychain
            (kSecAttrSynchronizable as String): kCFBooleanTrue!,  // allow iCloud
            (kSecAttrAccessGroup as String): self.group,   // multiple apps can share through this group
            (kSecAttrLabel as String): self.key]      // tag to make it easy to search

        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - OktaSdkBridge

@objc(OktaSdkBridge)
class OktaSdkBridge: RCTEventEmitter {
    var config: OktaOidcConfig? {
        oktaOidc?.configuration
    }
    
    var storedStateManager: StateManagerProtocol? {
        guard let config = config else {
            print(OktaOidcError.notConfigured.errorDescription ?? "The SDK is not configured.")
            return nil
        }
        
        return OktaOidcStateManager.readFromSecureStorage(for: config)
    }
    
    var oktaOidc: OktaOidcProtocol?
    var deviceSecretKeychain: DeviceSecretKeychain?
    
    override var methodQueue: DispatchQueue { .main }
    
    private var requestTimeout: Int?
    
    func presentedViewController() -> UIViewController? {
        RCTPresentedViewController()
    }
    
    @objc
    func createConfig(_ clientId: String,
                      redirectUrl: String,
                      endSessionRedirectUri: String,
                      discoveryUri: String,
                      scopes: String,
                      keychainGroup: String = "",
                      keychainTag: String = "",
                      userAgentTemplate: String,
                      requestTimeout: Int,
                      promiseResolver: RCTPromiseResolveBlock,
                      promiseRejecter: RCTPromiseRejectBlock) {
        do {
            let uaVersion = OktaUserAgent.userAgentVersion()
            let userAgent = userAgentTemplate.replacingOccurrences(of: "$UPSTREAM_SDK", with: "okta-oidc-ios/\(uaVersion)")
            OktaOidcConfig.setUserAgent(value: userAgent)
            let config = try OktaOidcConfig(with: [
                "issuer": discoveryUri,
                "clientId": clientId,
                "redirectUri": redirectUrl,
                "logoutRedirectUri": endSessionRedirectUri,
                "scopes": scopes
            ])
            
            config.requestCustomizationDelegate = self
            
            oktaOidc = try OktaOidc(configuration: config)
            self.requestTimeout = requestTimeout
            
            if !keychainTag.isEmpty && !keychainGroup.isEmpty {
                self.deviceSecretKeychain = DeviceSecretKeychain(key: keychainTag, group: keychainGroup)
            }

            promiseResolver(true)
        } catch let error {
            promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
        }
    }
    
    @objc
    func signIn(_ options: [String: String] = [:],
                promiseResolver: @escaping RCTPromiseResolveBlock,
                promiseRejecter: @escaping RCTPromiseRejectBlock) {
        
        guard let currOktaOidc = oktaOidc else {
            let error = OktaReactNativeError.notConfigured
            let errorDic = [
                OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
            ]
            
            sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
            promiseRejecter(error.errorCode, error.errorDescription, error)
            
            return
        }
        
        guard let view = presentedViewController() else {
            let error = OktaReactNativeError.noView
            let errorDic = [
                OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
            ]
            
            sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
            promiseRejecter(error.errorCode, error.errorDescription, error)
            
            return
        }
        
        if #available(iOS 13.0, *) {
            let noSSOEnabled = options["noSSO"] == "true"
            config?.noSSO = noSSOEnabled
        }
        
        currOktaOidc.signInWithBrowser(from: view, additionalParameters: options) { stateManager, error in
            if let error = error {
                if case OktaOidcError.userCancelledAuthorizationFlow = error {
                    self.sendEvent(withName: OktaSdkConstant.ON_CANCELLED,
                                   body: [OktaSdkConstant.RESOLVE_TYPE_KEY: OktaSdkConstant.CANCELLED])

                    promiseRejecter(OktaReactNativeError.cancelled.errorCode, OktaReactNativeError.cancelled.localizedDescription, OktaReactNativeError.cancelled)
                    
                    return
                }
                
                let errorDic = [
                    OktaSdkConstant.ERROR_CODE_KEY: OktaReactNativeError.oktaOidcError.errorCode,
                    OktaSdkConstant.ERROR_MSG_KEY: error.localizedDescription
                ]
                
                self.sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
                promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
                
                return
            }
            
            guard let currStateManager = stateManager else {
                let error = OktaReactNativeError.noStateManager
                let errorDic = [
                    OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                    OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
                ]
                
                self.sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
                promiseRejecter(error.errorCode, error.errorDescription, error)
                
                return
            }
            
            currStateManager.writeToSecureStorage()
            let result = [
                OktaSdkConstant.RESOLVE_TYPE_KEY: OktaSdkConstant.AUTHORIZED,
                OktaSdkConstant.ACCESS_TOKEN_KEY: stateManager?.accessToken
            ]
            
            self.sendEvent(withName: OktaSdkConstant.SIGN_IN_SUCCESS, body: result)
            promiseResolver(result)
        }
    }
    
    @objc
    func signOut(_ promiseResolver: @escaping RCTPromiseResolveBlock,
                 promiseRejecter: @escaping RCTPromiseRejectBlock) {
        
        guard let currOktaOidc = oktaOidc else {
            let error = OktaReactNativeError.notConfigured
            let errorDic = [
                OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
            ]
            
            sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
            promiseRejecter(error.errorCode, error.errorDescription, error)
            
            return
        }
        
        guard let view = presentedViewController() else {
            let error = OktaReactNativeError.noView
            let errorDic = [
                OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
            ]
            
            sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
            promiseRejecter(error.errorCode, error.errorDescription, error)
            
            return
        }
        
        guard let stateManager = storedStateManager as? OktaOidcStateManager else {
            let error = OktaReactNativeError.unauthenticated
            let errorDic = [
                OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
            ]
            
            sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
            promiseRejecter(error.errorCode, error.errorDescription, error)
            
            return
        }
        
        currOktaOidc.signOutOfOkta(stateManager, from: view) { error in
            if let error = error {
                if case OktaOidcError.userCancelledAuthorizationFlow = error {
                    self.sendEvent(withName: OktaSdkConstant.ON_CANCELLED,
                                   body: [OktaSdkConstant.RESOLVE_TYPE_KEY: OktaSdkConstant.CANCELLED])

                    promiseRejecter(OktaReactNativeError.cancelled.errorCode, OktaReactNativeError.cancelled.localizedDescription, OktaReactNativeError.cancelled)
                    
                    return
                }
                
                let errorDic = [
                    OktaSdkConstant.ERROR_CODE_KEY: OktaReactNativeError.oktaOidcError.errorCode,
                    OktaSdkConstant.ERROR_MSG_KEY: error.localizedDescription
                ]
                
                self.sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
                promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
                
                return
            }
            
            let result = [
                OktaSdkConstant.RESOLVE_TYPE_KEY: OktaSdkConstant.SIGNED_OUT
            ]
            
            stateManager.clear()
            
            self.sendEvent(withName: OktaSdkConstant.SIGN_OUT_SUCCESS, body: result)
            promiseResolver(result)
        }
    }
    
    @objc
    func authenticate(_ sessionToken: String,
                      promiseResolver: @escaping RCTPromiseResolveBlock,
                      promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard config != nil, let currOktaOidc = oktaOidc else {
            let error = OktaReactNativeError.notConfigured
            let errorDic = [
                OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
            ]
            sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
            promiseRejecter(errorDic[OktaSdkConstant.ERROR_CODE_KEY]!, 
                            errorDic[OktaSdkConstant.ERROR_MSG_KEY]!, error)
            return
        }
        
        currOktaOidc.authenticate(withSessionToken: sessionToken) { stateManager, error in
            if let error = error {
                let errorDic = [
                    OktaSdkConstant.ERROR_CODE_KEY: OktaReactNativeError.oktaOidcError.errorCode,
                    OktaSdkConstant.ERROR_MSG_KEY: error.localizedDescription
                ]
                self.sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
                promiseRejecter(errorDic[OktaSdkConstant.ERROR_CODE_KEY]!, 
                                errorDic[OktaSdkConstant.ERROR_MSG_KEY]!, error)
                return
            }
            
            guard let currStateManager = stateManager else {
                let error = OktaReactNativeError.noStateManager
                let errorDic = [
                    OktaSdkConstant.ERROR_CODE_KEY: error.errorCode,
                    OktaSdkConstant.ERROR_MSG_KEY: error.errorDescription
                ]
                self.sendEvent(withName: OktaSdkConstant.ON_ERROR, body: errorDic)
                promiseRejecter(errorDic[OktaSdkConstant.ERROR_CODE_KEY]!, 
                                errorDic[OktaSdkConstant.ERROR_MSG_KEY]!, error)
                return
            }
            
            currStateManager.writeToSecureStorage()

            if let keychain = self.deviceSecretKeychain {
                keychain.remove()
                keychain.set(
                    idToken: currStateManager.idToken!,
                    deviceSecret: currStateManager.authState.lastTokenResponse!.additionalParameters!["device_secret"]! as! String
                )
            }

            let dic = [
                OktaSdkConstant.RESOLVE_TYPE_KEY: OktaSdkConstant.AUTHORIZED,
                OktaSdkConstant.ACCESS_TOKEN_KEY: stateManager?.accessToken
            ]
            
            self.sendEvent(withName: OktaSdkConstant.SIGN_IN_SUCCESS, body: dic)
            promiseResolver(dic)
        }
    }

    @objc
    func signInWithDeviceSecret(_ promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        // we are here when we are not logged in
        // first try to find device_secret and exchange a token

        if self.deviceSecretKeychain == nil {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }

        let (idToken, deviceSecret) = self.deviceSecretKeychain!.get()

        if idToken == nil {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }

        // try exchange for token
        let requestConfiguration = OKTServiceConfiguration.init(
            authorizationEndpoint: URL(string: config!.issuer + "/v1/authorize")!,
            tokenEndpoint: URL(string: config!.issuer + "/v1/token")!
        )

        let request = OKTTokenRequest(configuration: requestConfiguration,
                                      grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
                                      authorizationCode: nil,
                                      redirectURL: nil,
                                      clientID: config!.clientId,
                                      clientSecret: nil,
                                      scope: "openid offline_access",
                                      refreshToken: nil,
                                      codeVerifier: nil,
                                      additionalParameters: ["actor_token" : deviceSecret!,
                                                             "actor_token_type" : "urn:x-oath:params:oauth:token-type:device-secret",
                                                             "subject_token" : idToken!,
                                                             "subject_token_type" : "urn:ietf:params:oauth:token-type:id_token",
                                                             "audience" : "api://default"])

        // perform token exchange
        OKTAuthorizationService.perform(request, delegate: nil) { tokenResponse, error in
            if error != nil {
              promiseRejecter(error.debugDescription, error.debugDescription, error)
              return
            }

            // successfully exchanged token, try to save
            // construct AuthState from a fake request, because we did not make a real OIDC request to begin with
            let authState = OKTAuthState(authorizationResponse:
                                         OKTAuthorizationResponse(request:
                                                                    OKTAuthorizationRequest(configuration: requestConfiguration,
                                                                                            clientId: self.config!.clientId,
                                                                                            scopes: ["openid"],
                                                                                            redirectURL: URL(string: "any")!,
                                                                                            responseType: "code",
                                                                                            additionalParameters: nil),
                                                                                    parameters: ["any": "any" as NSString]))

            // tokenResponse has the real tokens that we need to save
            authState.update(with: tokenResponse, error: error)
            
            let stateManager = OktaOidcStateManager(authState: authState)
            // Store instance of stateManager into the local iOS keychain
            stateManager.writeToSecureStorage()

            let result = [
                OktaSdkConstant.RESOLVE_TYPE_KEY: OktaSdkConstant.AUTHORIZED,
                OktaSdkConstant.ACCESS_TOKEN_KEY: stateManager.accessToken
            ]

            self.sendEvent(withName: OktaSdkConstant.SIGN_IN_SUCCESS, body: result)
            promiseResolver(result)
        }
    }
    
    @objc(getAccessToken:promiseRejecter:)
    func getAccessToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        guard let accessToken = stateManager.accessToken else {
            let error = OktaReactNativeError.noAccessToken
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        let dic = [
            OktaSdkConstant.ACCESS_TOKEN_KEY: accessToken
        ]
        
        promiseResolver(dic)
    }
    
    @objc(getIdToken:promiseRejecter:)
    func getIdToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {        
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        guard let idToken = stateManager.idToken else {
            let error = OktaReactNativeError.noIdToken
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        let dic = [
            OktaSdkConstant.ID_TOKEN_KEY: idToken
        ]
        
        promiseResolver(dic)
        return
    }
    
    @objc(getUser:promiseRejecter:)
    func getUser(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        stateManager.getUser { response, error in
            if let error = error {
                promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
                return
            }
            
            promiseResolver(response)
        }
    }

    @objc
    func getNativeSSOCredentials(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        if self.deviceSecretKeychain == nil {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }

        let (idToken, deviceSecret) = self.deviceSecretKeychain!.get()
        let credentials = [
            "id_token": idToken,
            "device_secret": deviceSecret
        ]

        promiseResolver(credentials)
    }
    
    @objc(isAuthenticated:promiseRejecter:)
    func isAuthenticated(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        var promiseResult = [
            OktaSdkConstant.AUTHENTICATED_KEY: false
        ]
        
        guard let stateManager = storedStateManager else {
            promiseResolver(promiseResult)
            return
        }
        
        // State Manager returns non expired (fresh) tokens.
        let areTokensValidAndFresh = stateManager.idToken != nil && stateManager.accessToken != nil
        promiseResult[OktaSdkConstant.AUTHENTICATED_KEY] = areTokensValidAndFresh
        
        promiseResolver(promiseResult)
    }
    
    @objc(revokeAccessToken:promiseRejecter:)
    func revokeAccessToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        revokeToken(tokenName: OktaSdkConstant.ACCESS_TOKEN_KEY, promiseResolver: promiseResolver, promiseRejecter: promiseRejecter)
    }
    
    @objc(revokeIdToken:promiseRejecter:)
    func revokeIdToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        revokeToken(tokenName: OktaSdkConstant.ID_TOKEN_KEY, promiseResolver: promiseResolver, promiseRejecter: promiseRejecter)
    }
    
    @objc(revokeRefreshToken:promiseRejecter:)
    func revokeRefreshToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        revokeToken(tokenName: OktaSdkConstant.REFRESH_TOKEN_KEY, promiseResolver: promiseResolver, promiseRejecter: promiseRejecter)
    }
    
    @objc(introspectAccessToken:promiseRejecter:)
    func introspectAccessToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        introspectToken(tokenName: OktaSdkConstant.ACCESS_TOKEN_KEY, promiseResolver: promiseResolver, promiseRejecter: promiseRejecter)
    }
    
    @objc(introspectIdToken:promiseRejecter:)
    func introspectIdToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        introspectToken(tokenName: OktaSdkConstant.ID_TOKEN_KEY, promiseResolver: promiseResolver, promiseRejecter: promiseRejecter)
    }
    
    @objc(introspectRefreshToken:promiseRejecter:)
    func introspectRefreshToken(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        introspectToken(tokenName: OktaSdkConstant.REFRESH_TOKEN_KEY, promiseResolver: promiseResolver, promiseRejecter: promiseRejecter)
    }
    
    @objc(refreshTokens:promiseRejecter:)
    func refreshTokens(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        stateManager.renew { newAccessToken, error in
            if let error = error {
                promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
                return
            }
            
            guard let newStateManager = newAccessToken else {
                let error = OktaReactNativeError.noStateManager
                promiseRejecter(error.errorCode, error.errorDescription, error)
                return
            }
            
            newStateManager.writeToSecureStorage()
            let dic = [
                OktaSdkConstant.ACCESS_TOKEN_KEY: newStateManager.accessToken,
                OktaSdkConstant.ID_TOKEN_KEY: newStateManager.idToken,
                OktaSdkConstant.REFRESH_TOKEN_KEY: newStateManager.refreshToken
            ]
            
            promiseResolver(dic)
        }
    }
    
    @objc(clearTokens:promiseRejecter:)
    func clearTokens(promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        do {
            try stateManager.removeFromSecureStorage()
            promiseResolver(true)
        } catch {
            promiseResolver(false)
        }
    }
    
    func introspectToken(tokenName: String, promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        var token: String?
        
        switch tokenName {
        case OktaSdkConstant.ACCESS_TOKEN_KEY:
            token = stateManager.accessToken
        case OktaSdkConstant.ID_TOKEN_KEY:
            token = stateManager.idToken
        case OktaSdkConstant.REFRESH_TOKEN_KEY:
            token = stateManager.refreshToken
        default:
            assertionFailure("Incorrect token name.")
            let error = OktaReactNativeError.errorTokenType
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        stateManager.introspect(token: token) { payload, error in
            if let error = error {
                promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
                return
            }
            
            guard let payload = payload else {
                let error = OktaReactNativeError.errorPayload
                promiseRejecter(error.errorCode, error.errorDescription, error)
                return
            }
            
            promiseResolver(payload)
        }
    }
    
    func revokeToken(tokenName: String, promiseResolver: @escaping RCTPromiseResolveBlock, promiseRejecter: @escaping RCTPromiseRejectBlock) {
        guard let stateManager = storedStateManager else {
            let error = OktaReactNativeError.unauthenticated
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        var token: String?
        
        switch tokenName {
        case OktaSdkConstant.ACCESS_TOKEN_KEY:
            token = stateManager.accessToken
        case OktaSdkConstant.ID_TOKEN_KEY:
            token = stateManager.idToken
        case OktaSdkConstant.REFRESH_TOKEN_KEY:
            token = stateManager.refreshToken
        default:
            let error = OktaReactNativeError.errorTokenType
            promiseRejecter(error.errorCode, error.errorDescription, error)
            return
        }
        
        stateManager.revoke(token) { response, error in
            if let error = error {
                promiseRejecter(OktaReactNativeError.oktaOidcError.errorCode, error.localizedDescription, error)
                return
            }
            
            promiseResolver(true)
        }
    }
    
    override static func requiresMainQueueSetup() -> Bool {
        true
    }
    
    override func supportedEvents() -> [String]! {
        [
            OktaSdkConstant.SIGN_IN_SUCCESS,
            OktaSdkConstant.SIGN_OUT_SUCCESS,
            OktaSdkConstant.ON_ERROR,
            OktaSdkConstant.ON_CANCELLED
        ]
    }
}

extension OktaSdkBridge: OktaNetworkRequestCustomizationDelegate {
    func customizableURLRequest(_ request: URLRequest?) -> URLRequest? {
        guard let timeout = requestTimeout,
              let incommingRequest = request,
              let mutableRequestCopy = (incommingRequest as NSURLRequest).mutableCopy() as? NSMutableURLRequest else
        {
            return request
        }
        
        mutableRequestCopy.timeoutInterval = TimeInterval(timeout)
        
        return mutableRequestCopy as URLRequest
    }
    
    func didReceive(_ response: URLResponse?) {
        // Not needed
    }
}
