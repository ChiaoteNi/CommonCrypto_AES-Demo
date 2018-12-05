//
//  AESCryptoDemoTests.swift
//  AESCryptoDemoTests
//
//  Created by Chiao on 2018/12/3.
//  Copyright © 2018年 iosTaipei. All rights reserved.
//

import XCTest
@testable import AESCryptoDemo

class AESCryptoDemoTests: XCTestCase {

    var cryptoHelper: CryptoHelper!
    let txt: String = "demo!＝.～-->\\(-.-)///嗨嗨"
    
    override func setUp() {
        cryptoHelper = CryptoHelper()
    }

    override func tearDown() {
        cryptoHelper = nil
    }
    
    func testCryptoData() {
        let data = Data.init(bytes: [UInt8](txt.utf8))
        guard let encryptResult = cryptoHelper.encode(data: data) else { return assert(false) }
        
        let time = Int(encryptResult.time.timeIntervalSince1970)
        guard let decryptoData = cryptoHelper.decode(data: encryptResult.data,
                                                    timeStamp: time) else { return assert(false) }
        guard let cryptoTxt = String.init(data: decryptoData,
                                           encoding: .utf8) else { return assert(false) }
        
        assert(cryptoTxt == txt, cryptoTxt)
    }
    
    func testCryptoTxt() {
        guard let encryptResult = cryptoHelper.encode(txt: txt) else { return assert(false) }
        
        let time = Int(encryptResult.time.timeIntervalSince1970)
        let encryptoTxt = encryptResult.base64EncodeTxt
        guard let decryptoTxt = cryptoHelper.decode(base64Txt: encryptoTxt,
                                                   timeStamp: time) else { return assert(false) }
        
        print(encryptResult.base64EncodeTxt)
        print(decryptoTxt)
        assert(decryptoTxt == txt, decryptoTxt)
    }
}
