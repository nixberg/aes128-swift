// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "AES128",
    products: [
        .library(
            name: "AES128",
            targets: ["AES128"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "AES128",
            dependencies: []),
        .testTarget(
            name: "AES128Tests",
            dependencies: ["AES128"]),
    ]
)
