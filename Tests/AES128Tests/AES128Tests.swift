import XCTest
import AES128
import CipherModes

final class AES128Tests: XCTestCase {
    func testAES128() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: AES128.blockSize)
        
        var encrypted = [UInt8]()
        var decrypted = [UInt8]()
        
        aes.encrypt(block: input, to: &encrypted)
        aes.decrypt(block: encrypted, to: &decrypted)
        XCTAssertEqual(input, decrypted)
    }
    
    func testECB() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: .random(in: 0..<1024))
        
        let encrypted = aes.encryptECB(input)
        let decrypted = try! aes.decryptECB(encrypted)
        XCTAssertEqual(input, decrypted)
    }
    
    func testCBC() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: .random(in: 0..<1024))
        let iv = [UInt8].random(count: AES128.blockSize)
        
        let encrypted = aes.encryptCBC(input, withIV: iv)
        let decrypted = try! aes.decryptCBC(encrypted, withIV: iv)
        XCTAssertEqual(input, decrypted)
    }
    
    func testCTR() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: .random(in: 0..<1024))
        let nonce = UInt64.random(in: 0..<UInt64.max)
        
        let encrypted = aes.encryptCTR(input, nonce: nonce)
        let decrypted = aes.decryptCTR(encrypted, nonce: nonce)
        XCTAssertEqual(input, decrypted)
    }
}

fileprivate extension Array where Element == UInt8 {
    static func random(count: Int) -> Self {
        var rng = SystemRandomNumberGenerator()
        return (0..<count).map { _ in rng.next() }
    }
}
