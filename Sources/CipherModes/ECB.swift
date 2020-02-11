import Foundation
import AES128

public extension AES128 {
    func encryptECB<D, M>(_ input: D, to output: inout M) where D: DataProtocol, M: MutableDataProtocol {
        self.encryptECBWithoutPadding(input.pkcs7Padded(), to: &output)
    }
    
    func encryptECBWithoutPadding<D, M>(_ input: D, to output: inout M) where D: DataProtocol, M: MutableDataProtocol {
        precondition(input.count.isMultiple(of: Self.blockSize))
        
        var input = input[...]
        
        while !input.isEmpty {
            self.encrypt(block: input.prefix(Self.blockSize), to: &output)
            input = input.dropFirst(Self.blockSize)
        }
    }
    
    func encryptECB<D>(_ input: D) -> [UInt8] where D: DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        self.encryptECB(input, to: &output)
        return output
    }
    
    func encryptECBWithoutPadding<D>(_ input: D) -> [UInt8] where D: DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        self.encryptECBWithoutPadding(input, to: &output)
        return output
    }
    
    func decryptECB<D, M>(_ input: D, to output: inout M) throws where D: DataProtocol, M: MutableDataProtocol {
        self.decryptECBWithoutPadding(input, to: &output)
        
        guard let paddingLength = output.suffix(input.count).pkcs7PaddingLength() else {
            throw AES128Error.couldNotDecrypt
        }
        
        output.removeLast(paddingLength)
    }
    
    func decryptECBWithoutPadding<D, M>(_ input: D, to output: inout M) where D: DataProtocol, M: MutableDataProtocol {
        precondition(input.count.isMultiple(of: Self.blockSize))
        
        var input = input[...]
        
        while !input.isEmpty {
            self.decrypt(block: input.prefix(Self.blockSize), to: &output)
            input = input.dropFirst(Self.blockSize)
        }
    }
    
    func decryptECB<D>(_ input: D) throws -> [UInt8] where D: DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        try self.decryptECB(input, to: &output)
        return output
    }
    
    func decryptECBWithoutPadding<D>(_ input: D) -> [UInt8] where D: DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        self.decryptECBWithoutPadding(input, to: &output)
        return output
    }
}
