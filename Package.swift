// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "fingerlock",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "fingerlock", path: "Sources/fingerlock")
    ]
)
