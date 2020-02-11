import XCTest
import AES128
import CipherModes

final class AES128Tests: XCTestCase {
    func testAES128() {
        let aes = AES128(key: [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        ])
        
        let plaintext: [UInt8] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]
        let ciphertext: [UInt8] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
        ]
        
        XCTAssertEqual(aes.encryptECBWithoutPadding(plaintext), ciphertext)
        XCTAssertEqual(aes.decryptECBWithoutPadding(ciphertext), plaintext)
    }
    
    func testAES128RoundTrip() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: AES128.blockSize)
        
        var encrypted = [UInt8]()
        var decrypted = [UInt8]()
        
        aes.encrypt(block: input, to: &encrypted)
        aes.decrypt(block: encrypted, to: &decrypted)
        XCTAssertEqual(input, decrypted)
    }
    
    func testECBRoundTrip() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: .random(in: 0..<1024))
        
        let encrypted = aes.encryptECB(input)
        let decrypted = try! aes.decryptECB(encrypted)
        XCTAssertEqual(input, decrypted)
    }
    
    func testCBCRoundTrip() {
        let aes = AES128(key: [UInt8].random(count: AES128.blockSize))
        let input = [UInt8].random(count: .random(in: 0..<1024))
        let iv = [UInt8].random(count: AES128.blockSize)
        
        let encrypted = aes.encryptCBC(input, withIV: iv)
        let decrypted = try! aes.decryptCBC(encrypted, withIV: iv)
        XCTAssertEqual(input, decrypted)
    }
    
    func testCTRRoundTrip() {
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
