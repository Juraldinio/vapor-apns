import Foundation
import JSON
import JWT
import Console

open class VaporAPNS {
    fileprivate var options: Options
    private var lastGeneratedToken: (date: Date, token: String)?
    
    private lazy var urlSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.httpShouldUsePipelining = true
        config.httpAdditionalHeaders = ["User-Agent": "VaporAPNS/1.0.1",
                                        "Accept": "application/json",
                                        "Content-Type": "application/json"]
        let session = URLSession(configuration: config)
        return session
    }()
    
    public init(options: Options) throws {
        self.options = options
        
        if self.options.usesCertificateAuthentication {
            // TODO: Make sure we support that
        }
        
    }
    
    @available(*, unavailable)
    open func send(_ message: ApplePushMessage, to deviceToken: String) -> Result {
        fatalError("say send(,to:,completionHandler")
    }
    
    open func send(_ message: ApplePushMessage, to deviceToken: String, completionHandler: @escaping (Result) -> Void) {
        // Set URL
        let urlString = ("\(self.hostURL(message.sandbox))/3/device/\(deviceToken)")
        guard let url  = URL(string: urlString) else {
            completionHandler(Result.networkError(error: ServiceStatus.badRequest))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        // Setup payload
        do {
            guard let payloadStringData = toNullTerminatedUtf8String(try message.payload.makeJSON().serialize(prettyPrint: false))
                else { throw SimpleError.string(message: "Could not convert string") }
            request.httpBody = payloadStringData
        } catch {
            let result = Result.error(apnsId: message.messageId, deviceToken: deviceToken, error: .unknownError(error: "Could not serialize payload"))
            completionHandler(result)
            return
        }

        // Headers
        let headers = self.requestHeaders(for: message)
        
        // Add token auth headers
        if !options.usesCertificateAuthentication {
            let token: String
            if let recentToken = lastGeneratedToken, abs(recentToken.date.timeIntervalSinceNow) < 59 * 60 {
                token = recentToken.token
            } else {
                let privateKey = options.privateKey!.bytes.base64Decoded
                let claims: [Claim] = [
                    IssuerClaim(string: options.teamId!),
                    IssuedAtClaim()
                ]
                let jwt = try! JWT(additionalHeaders: [KeyID(options.keyId!)],
                                   payload: JSON(claims),
                                   signer: ES256(key: privateKey))
                
                let tokenString = try! jwt.createToken()
                
                let publicKey = options.publicKey!.bytes.base64Decoded
                
                do {
                    let jwt2 = try JWT(token: tokenString)
                    do {
                        try jwt2.verifySignature(using: ES256(key: publicKey))
                    } catch {
                        // If we fail here, its an invalid signature
                        let result = Result.error(apnsId: message.messageId, deviceToken: deviceToken, error: .invalidSignature)
                        completionHandler(result)
                        return
                    }
                    
                } catch {
                    print ("Couldn't verify token. This is a non-fatal error, we'll try to send the notification anyway.")
                    if options.debugLogging {
                        print("\(error)")
                    }
                }
                
                token = tokenString.replacingOccurrences(of: " ", with: "")
                lastGeneratedToken = (date: Date(), token: token)
            }
            
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        // Global headers are configured as part of the URL session
        for header in headers {
            request.addValue(header.value, forHTTPHeaderField: header.key)
        }
        
        let dataTask = self.urlSession.dataTask(with: request) { (data, response, error) in
            let result: Result
            defer { completionHandler(result) }
            
            if let error = error {
                result = Result.networkError(error: error)
            } else if let httpResponse = response as? HTTPURLResponse {
                let serviceStatus = ServiceStatus(responseStatusCode: httpResponse.statusCode)
                
                if let data = data, let string = String(data: data, encoding: .utf8) {
                    let jsonNode = JSON(.string(string)).makeNode(in: nil)
                    if let reason = jsonNode["reason"]?.string {
                        result = Result.error(apnsId: message.messageId,
                                              deviceToken: deviceToken,
                                              error: APNSError.init(errorReason: reason))
                    } else if serviceStatus == .success {
                        result = Result.success(apnsId: message.messageId,
                                                deviceToken: deviceToken,
                                                serviceStatus: .success)
                    } else {
                        result = Result.error(apnsId: message.messageId,
                                              deviceToken: deviceToken,
                                              error: APNSError.unknownError(error: "ServiceStatus: \(serviceStatus)"))
                    }
                } else {
                    result = Result.error(apnsId: message.messageId,
                                          deviceToken: deviceToken,
                                          error: APNSError.unknownError(error: "No response data"))
                }
            } else {
                result = Result.networkError(error: SimpleError.string(message: "No HTTP response"))
            }
        }
        dataTask.resume()
    }
    
    open func send(_ message: ApplePushMessage, to deviceTokens: [String], perDeviceResultHandler: @escaping ((_ result: Result) -> Void)) {
        for deviceToken in deviceTokens {
            self.send(message, to: deviceToken) { result in
                perDeviceResultHandler(result)
            }
        }
    }
    
    open func toNullTerminatedUtf8String(_ str: [UTF8.CodeUnit]) -> Data? {
//        let cString = str.cString(using: String.Encoding.utf8)
        return str.withUnsafeBufferPointer() { buffer -> Data? in
            return buffer.baseAddress != nil ? Data(bytes: buffer.baseAddress!, count: buffer.count) : nil
        }
    }
    
    fileprivate func requestHeaders(for message: ApplePushMessage) -> [String: String] {
        var headers: [String : String] = [
            "apns-id": message.messageId,
            "apns-expiration": "\(Int(message.expirationDate?.timeIntervalSince1970.rounded() ?? 0))",
            "apns-priority": "\(message.priority.rawValue)",
            "apns-topic": message.topic ?? options.topic
        ]
        
        if let collapseId = message.collapseIdentifier {
            headers["apns-collapse-id"] = collapseId
        }
        
        if let threadId = message.threadIdentifier {
            headers["thread-id"] = threadId
        }
        
        return headers
    }
    
    fileprivate class WriteStorage {
        var data = Data()
    }
    
    // MARK: URLSessionDataDelegate
    
    

}

extension VaporAPNS {
    fileprivate func hostURL(_ development: Bool) -> String {
        if development {
            return "https://api.development.push.apple.com" //   "
        } else {
            return "https://api.push.apple.com" //   /3/device/"
        }
    }
}

struct KeyID: Header {
    static let name = "kid"
    var node: Node
    init(_ keyID: String) {
        node = Node(keyID)
    }
}
