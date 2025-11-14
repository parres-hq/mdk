import Foundation

/// Simple smoke test exercising the UniFFI Swift bindings on macOS.
/// Builds an MDK instance backed by a temp SQLite file, performs a few queries,
/// and intentionally triggers an error to ensure error bridging works.
@main
struct MdkBindingSmokeTest {
    static func main() throws {
        print("🔧 Starting MDK Swift binding test…")

        let tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("mdk-swift-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let dbPath = tempDir.appendingPathComponent("mdk.sqlite").path

        let mdk = try newMdk(dbPath: dbPath)
        print("📁 Database path: \(dbPath)")

        let groups = try mdk.getGroups()
        print("📚 Existing groups: \(groups.count)")

        let samplePubkey = "b2f6da3ae1d9bd501f72e6714bb7a8a798edc2cc74e07bcb35c50a64811d5cfa"
        let keyPackage = try mdk.createKeyPackageForEvent(
            publicKey: samplePubkey,
            relays: ["wss://relay.example.com"]
        )
        print("🔑 Key package bytes: \(keyPackage.keyPackage.count) chars")
        print("   Tags: \(keyPackage.tags)")

        let pendingWelcomes = try mdk.getPendingWelcomes()
        print("📨 Pending welcomes: \(pendingWelcomes.count)")

        // Demonstrate error propagation by feeding invalid JSON into parseKeyPackage.
        do {
            try mdk.parseKeyPackage(eventJson: "{}")
            print("⚠️ Unexpected success parsing malformed key package JSON")
            exit(1)
        } catch let err as MdkUniffiError {
            print("✅ Received expected error from parseKeyPackage: \(err)")
        }

        print("✅ MDK Swift binding test completed successfully.")
    }
}
