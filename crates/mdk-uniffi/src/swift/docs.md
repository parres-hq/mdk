# MDK Swift Bindings Documentation

## Installation

Add the MDK package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/parres-hq/mdk-swift.git", from: "0.5.2")
]
```

Or add it via Xcode: File → Add Packages → Enter the repository URL.

## Basic Usage

### Import and Initialize

```swift
import MDKBindings

// Create an MDK instance with a SQLite database path
let dbPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("mdk.db").path

let mdk = try newMdk(dbPath: dbPath)
```

### Create and Publish Key Package

```swift
let publicKey = "your_hex_public_key"
let relays = ["wss://relay.example.com", "wss://another-relay.com"]

let result = try mdk.createKeyPackageForEvent(
    publicKey: publicKey,
    relays: relays
)

// result.keyPackage contains the hex-encoded key package
// result.tags contains Nostr event tags
// Publish as a Nostr event (kind 443) to your relays
```

### Parse Key Packages

```swift
// When you receive a key package event from Nostr
let eventJson = """
{
    "id": "...",
    "kind": 443,
    "content": "hex_key_package...",
    ...
}
"""

try mdk.parseKeyPackage(eventJson: eventJson)
```

### Create a Group

```swift
let creatorPublicKey = "your_hex_public_key"
let memberKeyPackageEvents = ["{...}", "{...}"] // JSON strings of key package events
let name = "My Group"
let description = "A secure group chat"
let relays = ["wss://relay.example.com"]
let admins = ["your_hex_public_key"]

let result = try mdk.createGroup(
    creatorPublicKey: creatorPublicKey,
    memberKeyPackageEventsJson: memberKeyPackageEvents,
    name: name,
    description: description,
    relays: relays,
    admins: admins
)

// result.group contains the created group
// result.welcomeRumorsJson contains welcome messages for initial members
```

### Get Groups

```swift
let groups = try mdk.getGroups()

for group in groups {
    print("Group: \(group.name)")
    print("ID: \(group.mlsGroupId)")
    print("Members: \(group.members.count)")
}
```

### Get a Specific Group

```swift
if let group = try mdk.getGroup(mlsGroupId: "hex_group_id") {
    print("Found group: \(group.name)")
} else {
    print("Group not found")
}
```

### Add Members to a Group

```swift
let mlsGroupId = "hex_group_id"
let keyPackageEvents = ["{...}", "{...}"] // JSON strings of key package events

let result = try mdk.addMembers(
    mlsGroupId: mlsGroupId,
    keyPackageEventsJson: keyPackageEvents
)

// result.evolutionEventJson contains the group update event
// result.welcomeRumorsJson contains welcome messages for new members
```

### Remove Members from a Group

```swift
let mlsGroupId = "hex_group_id"
let memberPublicKeys = ["hex_pubkey1", "hex_pubkey2"]

let result = try mdk.removeMembers(
    mlsGroupId: mlsGroupId,
    memberPublicKeys: memberPublicKeys
)
```

### Accept Welcome Messages

```swift
// Get pending welcomes
let welcomes = try mdk.getPendingWelcomes()

for welcome in welcomes {
    print("Invited to: \(welcome.groupName)")
    print("By: \(welcome.senderPublicKey)")
    
    // Accept the welcome
    try mdk.acceptWelcome(welcomeJson: welcome.welcomeJson)
}
```

### Create and Send Messages

```swift
let mlsGroupId = "hex_group_id"
let senderPublicKey = "your_hex_public_key"
let content = "Hello, group!"
let kind: UInt16 = 1 // Message kind

let eventJson = try mdk.createMessage(
    mlsGroupId: mlsGroupId,
    senderPublicKey: senderPublicKey,
    content: content,
    kind: kind
)

// eventJson is a JSON string of the encrypted Nostr event
// Publish this to your Nostr relays
```

### Get Messages

```swift
let messages = try mdk.getMessages(mlsGroupId: "hex_group_id")

for message in messages {
    print("From: \(message.senderPublicKey)")
    print("Content: \(message.content)")
    print("Kind: \(message.kind)")
}
```

### Process Incoming Messages

```swift
// When you receive a message event from Nostr
let eventJson = """
{
    "id": "...",
    "kind": 1059,
    "content": "encrypted_content...",
    ...
}
"""

let result = try mdk.processMessage(eventJson: eventJson)

switch result {
case .newMessage(let message):
    print("New message: \(message.content)")
case .duplicate:
    print("Message already processed")
case .error(let error):
    print("Error processing: \(error)")
}
```

## Error Handling

All MDK operations can throw `MdkUniffiError`:

```swift
do {
    let groups = try mdk.getGroups()
    // Use groups...
} catch MdkUniffiError.storage(let message) {
    print("Storage error: \(message)")
} catch MdkUniffiError.mdk(let message) {
    print("MDK error: \(message)")
} catch MdkUniffiError.invalidInput(let message) {
    print("Invalid input: \(message)")
} catch {
    print("Unexpected error: \(error)")
}
```

## Data Types

### Group

```swift
struct Group {
    let mlsGroupId: String        // Hex-encoded MLS group ID
    let name: String
    let description: String
    let relays: [String]          // Relay URLs
    let admins: [String]          // Admin public keys (hex)
    let createdAt: UInt64         // Timestamp
}
```

### Message

```swift
struct Message {
    let eventId: String            // Nostr event ID (hex)
    let mlsGroupId: String
    let senderPublicKey: String   // Hex-encoded
    let content: String           // Decrypted content
    let kind: UInt16
    let createdAt: UInt64
}
```

### Welcome

```swift
struct Welcome {
    let welcomeJson: String       // Welcome message JSON
    let groupName: String
    let groupDescription: String
    let senderPublicKey: String   // Hex-encoded
}
```

### KeyPackageResult

```swift
struct KeyPackageResult {
    let keyPackage: String        // Hex-encoded key package
    let tags: [[String]]          // Nostr event tags
}
```

## Thread Safety

MDK instances are thread-safe internally, but you should avoid sharing a single instance across multiple threads. Instead:

- Create separate MDK instances for different threads if needed
- Or serialize access to a single instance within your application

## iOS Integration

The Swift package includes an XCFramework that supports both iOS device and simulator. The package automatically links against `sqlite3` and `c++` as required.

## Example: Complete Workflow

```swift
import MDKBindings

// 1. Initialize
let dbPath = "/path/to/mdk.db"
let mdk = try newMdk(dbPath: dbPath)

// 2. Create and publish key package
let keyPackage = try mdk.createKeyPackageForEvent(
    publicKey: myPublicKey,
    relays: ["wss://relay.example.com"]
)
// Publish keyPackage.keyPackage as Nostr event kind 443

// 3. Create a group
let group = try mdk.createGroup(
    creatorPublicKey: myPublicKey,
    memberKeyPackageEventsJson: [memberKeyPackageEventJson],
    name: "My Group",
    description: "A test group",
    relays: ["wss://relay.example.com"],
    admins: [myPublicKey]
)

// 4. Send a message
let messageEvent = try mdk.createMessage(
    mlsGroupId: group.group.mlsGroupId,
    senderPublicKey: myPublicKey,
    content: "Hello!",
    kind: 1
)
// Publish messageEvent to Nostr relays

// 5. Retrieve messages
let messages = try mdk.getMessages(mlsGroupId: group.group.mlsGroupId)
for message in messages {
    print("\(message.senderPublicKey): \(message.content)")
}
```

