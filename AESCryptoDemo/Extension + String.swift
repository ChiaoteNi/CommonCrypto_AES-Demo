//
//  Extension + String.swift
//  AESCryptoDemo
//
//  Created by Chiao on 2018/12/4.
//  Copyright © 2018年 iosTaipei. All rights reserved.
//

import Foundation
import CommonCrypto

extension String {
    public func md5() -> String? {
        guard let (result, length) = md5toPoint(of: self) else {
            print("md5toPoint fail, string=\(self)")
            return nil
        }
        
        guard let str = pointerToString(for: result, length: length) else {
            print("pointerToString fail, string=\(self), result=\(result), length=\(length)")
            return nil
        }
        return str
    }
    
    private func md5toPoint(of targetStr: String) -> (result: UnsafeMutablePointer<CUnsignedChar>, length: Int)? {
        guard let str = targetStr.cString(using: .utf8) else {
            print("fail, targetStr.count = \(targetStr.count)")
            return nil
        }
        let strLen = CUnsignedInt(targetStr.lengthOfBytes(using: .utf8))
        let digestLen = Int(CC_MD5_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        CC_MD5(str, strLen, result)
        return (result, digestLen)
    }
    
    private func pointerToString(for pointer: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String? {
        let hash = NSMutableString()
        for i in 0 ..< length {
            hash.appendFormat("%02x", pointer[i])
        }
        pointer.deinitialize(count: length)
        return String(format: hash as String)
    }
}
