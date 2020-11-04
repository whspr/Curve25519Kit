//
//  Copyright (c) 2020 Open Whisper Systems. All rights reserved.
//

import Foundation
import SignalCoreKit
import SignalClient

// Work around Swift's lack of factory initializers.
// See https://bugs.swift.org/browse/SR-5255.
public protocol ECKeyPairFromIdentityKeyPair {}
public extension ECKeyPairFromIdentityKeyPair {
    init(_ keyPair: IdentityKeyPair) {
        self = ECKeyPairImpl(keyPair) as! Self
    }
}
extension ECKeyPair: ECKeyPairFromIdentityKeyPair {}

// TODO: Eventually we should define ECKeyPair entirely in Swift as a wrapper around IdentityKeyPair,
// but doing that right now would break clients that are importing Curve25519.h and nothing else.
// For now, just provide the API we'd like to have in the future via its subclass.
public extension ECKeyPair {
    var identityKeyPair: IdentityKeyPair {
        (self as! ECKeyPairImpl).storedKeyPair
    }

    // TODO: Rename to publicKey(), rename existing publicKey() method to publicKeyData().
    func ecPublicKey() throws -> ECPublicKey {
        return ECPublicKey(self.identityKeyPair.publicKey)
    }

    // TODO: Rename to privateKey(), rename existing privateKey() method to privateKeyData().
    func ecPrivateKey() throws -> ECPrivateKey {
        return ECPrivateKey(self.identityKeyPair.privateKey)
    }
}

/// A transitionary class. Do not use directly; continue using ECKeyPair instead.
public class ECKeyPairImpl: ECKeyPair {
    fileprivate let storedKeyPair: IdentityKeyPair

    fileprivate init(_ keyPair: IdentityKeyPair) {
        storedKeyPair = keyPair
        super.init(fromClassClusterSubclassOnly: ())
    }

    private override init(fromClassClusterSubclassOnly: ()) {
        fatalError("only used as an intermediary initializer")
    }

    public override convenience init(publicKeyData: Data, privateKeyData: Data) throws {
        // Go through ECPublicKey to handle the public key data without a type byte.
        let publicKey = try ECPublicKey(keyData: publicKeyData).key
        let privateKey = try PrivateKey(privateKeyData)

        self.init(IdentityKeyPair(publicKey: publicKey, privateKey: privateKey))
    }

    public override var classForCoder: AnyClass {
        return ECKeyPair.self
    }

    @objc private class func generateKeyPair() -> ECKeyPair {
        return ECKeyPairImpl(try! IdentityKeyPair.generate())
    }

    @objc private func sign(_ data: Data) throws -> Data {
        return Data(try identityKeyPair.privateKey.generateSignature(message: data))
    }

    public override var publicKey: Data {
        return Data(try! identityKeyPair.publicKey.keyBytes())
    }

    public override var privateKey: Data {
        return Data(try! identityKeyPair.privateKey.serialize())
    }
}
