import Foundation
import AES128

public extension AES128 {
    func encryptCBC<D, I, M>(_ input: D, withIV iv: I, to output: inout M) where D: DataProtocol, I: DataProtocol, M: MutableDataProtocol {
        precondition(iv.count == Self.blockSize)
        
        var input = input.pkcs7Padded()[...]
        
        var xoredBlock = zip(input, iv).map(^)
        self.encrypt(block: xoredBlock, to: &output)
        input = input.dropFirst(Self.blockSize)
        
        while !input.isEmpty {
            zip(input, output.suffix(Self.blockSize)).enumerated().forEach { (i, bytes) in
                xoredBlock[i] = bytes.0 ^ bytes.1
            }
            self.encrypt(block: xoredBlock, to: &output)
            input = input.dropFirst(Self.blockSize)
        }
    }
    
    func encryptCBC<D, I>(_ input: D, withIV iv: I) -> [UInt8] where D: DataProtocol, I: DataProtocol{
        var output = [UInt8]()
        output.reserveCapacity(input.count + Self.blockSize)
        self.encryptCBC(input, withIV: iv, to: &output)
        return output
    }
    
    func decryptCBC<D, I, M>(_ input: D, withIV iv: I, to output: inout M) throws where D: DataProtocol, I: DataProtocol, M: MutableDataProtocol {
        precondition(input.count.isMultiple(of: Self.blockSize))
        precondition(iv.count == Self.blockSize)
        
        let inputLength = input.count
        
        self.decrypt(block: input.prefix(Self.blockSize), to: &output)
        output.xorLastBlock(with: iv)
        var lastInput = input[...]
        var input = input.dropFirst(Self.blockSize)
        
        while !input.isEmpty {
            self.decrypt(block: input.prefix(Self.blockSize), to: &output)
            output.xorLastBlock(with: lastInput)
            lastInput = input
            input = input.dropFirst(Self.blockSize)
        }
        
        guard let paddingLength = output.suffix(inputLength).pkcs7PaddingLength() else {
            throw AES128Error.couldNotDecrypt
        }
        
        output.removeLast(paddingLength)
    }
    
    func decryptCBC<D, I>(_ input: D, withIV iv: I) throws -> [UInt8] where D: DataProtocol, I: DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count + Self.blockSize)
        try self.decryptCBC(input, withIV: iv, to: &output)
        return output
    }
}

fileprivate extension MutableDataProtocol {
    mutating func xorLastBlock<D>(with block: D) where D: DataProtocol {
        zip(indices.suffix(AES128.blockSize), block).forEach { i, byte in
            self[i] ^= byte
        }
    }
}
