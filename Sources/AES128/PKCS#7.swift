import Foundation

public extension DataProtocol {
    func pkcs7Padded(blockSize: Int = AES128.blockSize) -> [UInt8] {
        precondition((1..<256).contains(blockSize))
        let paddingLength = blockSize - count % blockSize
        return self + [UInt8](repeating: UInt8(paddingLength), count: paddingLength)
    }
    
    func pkcs7PaddingLength(blockSize: Int = AES128.blockSize) -> Int? {
        precondition((1..<256).contains(blockSize))
        
        guard count.isMultiple(of: blockSize) else {
            return nil
        }
        
        guard let lastByte = last else {
            return nil
        }
        let paddingLength = Int(lastByte)
        
        guard (1...blockSize).contains(paddingLength) else {
            return nil
        }
        
        guard self.suffix(paddingLength).allSatisfy({ $0 == lastByte }) else {
            return nil
        }
        
        return paddingLength
    }
    
    func pkcs7PaddingStripped(blockSize: Int = AES128.blockSize) -> Self.SubSequence? {
        guard let paddingLength = self.pkcs7PaddingLength(blockSize: blockSize) else {
            return nil
        }
        return self.dropLast(paddingLength)
    }
}
