import Foundation
import AES128

public extension AES128 {
    func encryptCTR<D, M>(_ input: D, nonce: UInt64, to output: inout M) where D: DataProtocol, M: MutableDataProtocol {
        var input = input[...]
        var counter: UInt64 = 0
        
        var nonceAndCounter = nonce.littleEndianBytes + counter.littleEndianBytes
        var keystreamBlock = [UInt8](repeating: 0, count: Self.blockSize)
        
        while !input.isEmpty {
            nonceAndCounter.write(counter)
            keystreamBlock.removeAll(keepingCapacity: true)
            
            self.encrypt(block: nonceAndCounter, to: &keystreamBlock)
            zip(input, keystreamBlock).forEach {
                output.append($0.0 ^ $0.1)
            }
            
            input = input.dropFirst(Self.blockSize)
            counter += 1
        }
    }
    
    func encryptCTR<D>(_ input: D, nonce: UInt64) -> [UInt8] where D: DataProtocol {
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        self.encryptCTR(input, nonce: nonce, to: &output)
        return output
    }
    
    func decryptCTR<D, M>(_ input: D, nonce: UInt64, to output: inout M) where D: DataProtocol, M: MutableDataProtocol {
        self.encryptCTR(input, nonce: nonce, to: &output)
    }
    
    func decryptCTR<D>(_ input: D, nonce: UInt64) -> [UInt8] where D: DataProtocol {
        self.encryptCTR(input, nonce: nonce)
    }
}

fileprivate extension UInt64 {
    var littleEndianBytes: [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: self &>> ($0 &* 8)) }
    }
}

fileprivate extension Array where Element == UInt8 {
    mutating func write(_ counter: UInt64) {
        assert(count == 16)
        var counter = counter
        for i in 8..<16 {
            self[i] = UInt8(truncatingIfNeeded: counter)
            counter &>>= 8
        }
    }
}
