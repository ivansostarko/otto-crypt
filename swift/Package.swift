// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OttoCryptSwiftDemo",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .executable(name: "otto-swift-demo", targets: ["OttoCryptSwiftDemo"])
    ],
    dependencies: [
        .package(path: "../OttoCryptSwift")
    ],
    targets: [
        .executableTarget(
            name: "OttoCryptSwiftDemo",
            dependencies: [
                .product(name: "IvanSostarkoOttoCrypt", package: "OttoCryptSwift")
            ]
        )
    ]
)
