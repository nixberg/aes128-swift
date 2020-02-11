// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "AES128",
    products: [
        .library(
            name: "AES128",
            targets: ["AES128", "CipherModes"]),
    ],
    targets: [
        .target(
            name: "AES128",
            swiftSettings: [.unsafeFlags(["-Ounchecked"])]),
        .target(
            name: "CipherModes",
            dependencies: ["AES128"]),
        .testTarget(
            name: "AES128Tests",
            dependencies: ["AES128", "CipherModes"]),
    ]
)
