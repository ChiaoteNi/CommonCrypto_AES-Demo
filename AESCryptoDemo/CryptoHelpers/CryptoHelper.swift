//
//  CryptoHelper.swift
//  AESCryptoDemo
//
//  Created by Chiao on 2018/12/3.
//  Copyright © 2018年 iosTaipei. All rights reserved.
//

import Foundation
import CommonCrypto

class CryptoHelper {
    
    enum CryptType {
        case encrypt
        case decrypt
    }
    
    private let timeStampFormate = "ssmmHHddMMyyyy"
    
    private let preKey           = "MyAESDEMO!!"
    private let ivSalt           = "dm"
    private let ivTimeZone       = "Asia/Taipei"
    
    private let prefixSaltSize   = 1
    private let suffixSaltSize   = 6
    
    private let dateFormatter = DateFormatter()
    
    init() {
        dateFormatter.dateFormat = timeStampFormate
        dateFormatter.timeZone = TimeZone(identifier: ivTimeZone) //設定為台灣時區
    }
    
    //MARK: - 加密相關
    func getValueOfHeader(date: Date) -> String {
        let dateValue = date.timeIntervalSince1970
        let timeInterval = UInt64( dateValue * 1_000)
        return String(timeInterval / 1000 )
    }
    
    func encode(txt: String, encodeFailHandling: (()->Void)? = nil ) -> (base64EncodeTxt: String, iv: String, time: Date)? {
        let data = Data.init(bytes: [UInt8](txt.utf8))
        guard let result = encode(data: data) else {
            assert(false, "crypt fail, preKey=\(preKey), target=\(txt)")
            return nil
        }
        let encryptTxt = result.data.base64EncodedString(options: [])
        return (encryptTxt, result.iv, result.time)
    }
    
    func encode(data: Data, encodeFailHandling: (()->Void)? = nil ) -> (data: Data, iv: String, time: Date)? {
        let date = Date()
        let ivString = getIv(with: date)
        let keyString = getKey(with: date)
        
        guard let cryptoData = cryptWithData(.encrypt, key: keyString, iv: ivString, target: data) else {
            assert(false, "crypt fail, preKey=\(preKey), iv=\(ivString)")
            return nil
        }
        return (cryptoData, ivString, date)
    }
    
    //MARK: - 解密
    func decode(base64Txt txt: String, timeStamp: Int, decodeFailHandling: (()->Void)? = nil ) -> String? {
        guard let data = Data.init(base64Encoded: txt, options: [.ignoreUnknownCharacters]) else {
            assert(false, "data base64Encoded fail")
            return nil
        }
        guard let result = decode(data: data, timeStamp: timeStamp) else {
            assert(false, "crypt fail, timeStamp=\(timeStamp), txt=\(txt)")
            return nil
        }
        let resultStr = String.init(data: result, encoding: .utf8)
        return resultStr
    }
    
    func decode(data: Data, timeStamp: Int, decodeFailHandling: (()->Void)? = nil ) -> Data? {
        let date = Date(timeIntervalSince1970: Double(timeStamp))
        let ivString = getIv(with: date)
        let keyString = getKey(with: date)
        
        guard let result = cryptWithData(.decrypt, key: keyString, iv: ivString, target: data) else {
            assert(false, "crypt fail, iv=\(ivString), timeStamp=\(timeStamp)")
            return nil
        }
        return result
    }
    
    // MARK: - 加解密核心func
    func cryptWithData(_ type: CryptType, key: String, iv: String, target: Data) -> Data? {
        guard let data = type == .decrypt ? removeSalt(for: target) : target else {
            assert(false, "ＣryptErr, target removeSalt fail, target = \(target)")
            return nil
        }
        guard var result = coreCrypt(type, data, key: key, iv: iv) else {
            assert(false, "ＣryptErr, fail, iv=\(iv), targrt=\(data)")
            return nil
        }
        if type == .encrypt { addSalt(to: &result) }
        return result
    }
    
    func coreCrypt(_ type: CryptType,_ contentData: Data, key: String, iv: String) -> Data? {
        // 取得iv byte array
        let ivByte = [UInt8].init(iv.utf8) // 如果設nil 預設為Array.init(repeat: 16)
        // 取得key byte array
        let keyBytes = [UInt8].init(key.utf8)
        // 取得目標字串的 byte array
        let contentByte = [UInt8].init(contentData)
        let contentDataLength = size_t(contentData.count)
        
        // 設定要output的實體
        let bufferSize: Int = kCCBlockSizeAES128 * 8
        let cryptoData: [UInt8] = [UInt8](repeating: 0, count: bufferSize)
        let cryptoPointer = UnsafeMutableRawPointer(mutating: cryptoData)
        let cryptLength: Int = cryptoData.count
        var resultLength: Int = 0 // real output data length
        
        // 設定加密參數
        let keyLength = size_t(kCCKeySizeAES256)
        let crypt = (type == .encrypt) ? kCCEncrypt : kCCDecrypt
        let operation   = CCOperation(crypt)
        let alogorithm  = CCAlgorithm(kCCAlgorithmAES) // AES/DES
        let option      = CCOptions(kCCOptionPKCS7Padding)
        
        let cryptStatus = CCCrypt(
            // 加密參數設定
            operation, alogorithm, option,
            // 加密內容設定
            keyBytes, keyLength, ivByte, contentByte, contentDataLength,
            // 加密結果輸出
            cryptoPointer, cryptLength, &resultLength)
        
        guard cryptStatus == kCCSuccess else {
            assert(false, "ＣryptErr, CCCrypt fail, type=\(type), iv=\(iv)")
            return nil
        }
        return Data(bytes: cryptoData, count: resultLength)
    }
    
    //MARK: - common funcs
    private func getIv(with date: Date) -> String {
        let ivstr = dateFormatter.string(from: date)
        return ivstr + self.ivSalt
    }
    
    private func getKey(with date: Date) -> String {
        let ivStr = String(Int(date.timeIntervalSince1970))
        let keyStr = preKey + ivStr
        return keyStr.md5() ?? ""
    }
}

// MARK: - Salt
extension CryptoHelper {
    
    private func addSalt(to data: inout Data) {
        var byteArr = Array.init(data)
        print("加鹽前:\(byteArr)")
        let preSalt = getRandomLemStr(amount: prefixSaltSize)
        let suffSalt = getRandomLemStr(amount: suffixSaltSize)
        byteArr.insert(contentsOf: preSalt, at: 0)
        byteArr.append(contentsOf: suffSalt)
        data = Data.init(bytes: byteArr)
        print("加鹽後:\(byteArr)")
    }
    
    private func removeSalt(for data: Data?) -> Data? {
        guard let data = data else { return nil }
        var byteArr = Array.init(data)
                print("去鹽前:\(byteArr)")
        byteArr.removeFirst(prefixSaltSize)
        byteArr.removeLast(suffixSaltSize)
                print("去鹽後:\(byteArr)")
        return Data.init(bytes: byteArr)
    }
    
    private func getRandomLemStr(amount: Int) -> [UInt8] {
        var arr = [UInt8]()
        for _ in 0 ..< amount {
            let number = UInt8(arc4random_uniform(128))
            arr.append(number)
        }
        return arr
    }
}
