# MDK Kotlin/Android Bindings Documentation

## Building the AAR

1. Ensure the native libraries produced by `just _build-uniffi-android …` are copied into `src/main/jniLibs/<abi>/libmdk_uniffi.so`.
   (The `just gen-binding-kotlin` command handles this for you).
2. From `crates/mdk-uniffi/src/kotlin` run:

```bash
./gradlew build
```

The resulting AAR can be found in `build/outputs/aar/mdk-release.aar` (assuming you ran a release build).

## Publishing

To publish to a local Maven repository (useful for testing integration):

```bash
./gradlew publishReleasePublicationToMavenLocal
```

## Installation

Once published (e.g. via JitPack or local maven) reference it in your Android project:

```kotlin
dependencies {
    implementation("org.parres:mdk:0.5.2")
}
```

## Basic Usage

### Import and Initialize

```kotlin
import org.parres.mdk.*

// Create an MDK instance with a SQLite database path
val dbPath = context.filesDir.resolve("mdk.db").absolutePath
val mdk = newMdk(dbPath)
```

### Create and Publish Key Package

```kotlin
val publicKey = "your_hex_public_key"
val relays = listOf("wss://relay.example.com", "wss://another-relay.com")

val result = mdk.createKeyPackageForEvent(
    publicKey = publicKey,
    relays = relays
)

// result.keyPackage contains the hex-encoded key package
// result.tags contains Nostr event tags (List<List<String>>)
// Publish as a Nostr event (kind 443) to your relays
```

#### Build and Publish a Kind 443 Event

`KeyPackageResult` already contains the payload (`keyPackage`) and all tags that
need to go on the Nostr event. You only need to wrap it in your preferred Nostr
event type, sign it, and push it to the relays you want to advertise on:

```kotlin
data class UnsignedEvent(
    val pubkey: String,
    val created_at: Long,
    val kind: Int,
    val tags: List<List<String>>,
    val content: String
)

val keyPackageResult = mdk.createKeyPackageForEvent(
    publicKey = myPublicKey,
    relays = listOf("wss://relay.example.com")
)

val unsigned = UnsignedEvent(
    pubkey = myPublicKey,
    created_at = System.currentTimeMillis() / 1000,
    kind = 443,
    tags = keyPackageResult.tags,
    content = keyPackageResult.keyPackage
)

val signedEventJson = nostrSigner.signAndSerialize(unsigned)
relays.forEach { relay -> nostrClient.publish(relay, signedEventJson) }
```

Use whatever signer/client you already have; the key point is that the MDK
gives you the correct content and tags for the key package, which you then
embed in a standard Nostr event.

### Parse Key Packages

```kotlin
// When you receive a key package event from Nostr
val eventJson = """
{
    "id": "...",
    "kind": 443,
    "content": "hex_key_package...",
    ...
}
""".trimIndent()

mdk.parseKeyPackage(eventJson = eventJson)
```

### Create a Group

```kotlin
val creatorPublicKey = "your_hex_public_key"
val memberKeyPackageEvents = listOf("{...}", "{...}") // JSON strings of key package events
val name = "My Group"
val description = "A secure group chat"
val relays = listOf("wss://relay.example.com")
val admins = listOf("your_hex_public_key")

val result = mdk.createGroup(
    creatorPublicKey = creatorPublicKey,
    memberKeyPackageEventsJson = memberKeyPackageEvents,
    name = name,
    description = description,
    relays = relays,
    admins = admins
)

// result.group contains the created group
// result.welcomeRumorsJson contains welcome messages for initial members
```

### Get Groups

```kotlin
val groups = mdk.getGroups()

groups.forEach { group ->
    println("Group: ${group.name}")
    println("ID: ${group.mlsGroupId}")
    println("Members: ${group.members.size}")
}
```

### Get a Specific Group

```kotlin
val group = mdk.getGroup(mlsGroupId = "hex_group_id")
if (group != null) {
    println("Found group: ${group.name}")
} else {
    println("Group not found")
}
```

### Get Members

```kotlin
val members = mdk.getMembers(mlsGroupId = "hex_group_id")
println("Group has ${members.size} members")
members.forEach { member ->
    println("  - $member")
}
```

### Add Members to a Group

```kotlin
val mlsGroupId = "hex_group_id"
val keyPackageEvents = listOf("{...}", "{...}") // JSON strings of key package events

val result = mdk.addMembers(
    mlsGroupId = mlsGroupId,
    keyPackageEventsJson = keyPackageEvents
)

// result.evolutionEventJson contains the group update event
// result.welcomeRumorsJson contains welcome messages for new members
```

### Remove Members from a Group

```kotlin
val mlsGroupId = "hex_group_id"
val memberPublicKeys = listOf("hex_pubkey1", "hex_pubkey2")

val result = mdk.removeMembers(
    mlsGroupId = mlsGroupId,
    memberPublicKeys = memberPublicKeys
)
```

### Update Group Metadata

```kotlin
val mlsGroupId = "hex_group_id"
val newName = "Updated Group Name"
val newDescription = "New description"
val newRelays = listOf("wss://new-relay.com")

val result = mdk.updateGroupMetadata(
    mlsGroupId = mlsGroupId,
    name = newName,
    description = newDescription,
    relays = newRelays
)
```

### Accept Welcome Messages

```kotlin
// Get pending welcomes
val welcomes = mdk.getPendingWelcomes()

welcomes.forEach { welcome ->
    println("Invited to: ${welcome.groupName}")
    println("By: ${welcome.senderPublicKey}")
    
    // Accept the welcome
    mdk.acceptWelcome(welcomeJson = welcome.welcomeJson)
}
```

### Decline Welcome Messages

```kotlin
val welcome = welcomes.first()
mdk.declineWelcome(welcomeJson = welcome.welcomeJson)
```

### Create and Send Messages

```kotlin
val mlsGroupId = "hex_group_id"
val senderPublicKey = "your_hex_public_key"
val content = "Hello, group!"
val kind: UShort = 1u // Message kind

val eventJson = mdk.createMessage(
    mlsGroupId = mlsGroupId,
    senderPublicKey = senderPublicKey,
    content = content,
    kind = kind
)

// eventJson is a JSON string of the encrypted Nostr event
// Publish this to your Nostr relays
```

### Get Messages

```kotlin
val messages = mdk.getMessages(mlsGroupId = "hex_group_id")

messages.forEach { message ->
    println("From: ${message.senderPublicKey}")
    println("Content: ${message.content}")
    println("Kind: ${message.kind}")
}
```

### Get a Specific Message

```kotlin
val message = mdk.getMessage(eventId = "hex_event_id")
if (message != null) {
    println("Message: ${message.content}")
}
```

### Process Incoming Messages

```kotlin
// When you receive a message event from Nostr
val eventJson = """
{
    "id": "...",
    "kind": 1059,
    "content": "encrypted_content...",
    ...
}
""".trimIndent()

val result = mdk.processMessage(eventJson = eventJson)

when (result) {
    is MessageProcessingResult.NewMessage -> {
        println("New message: ${result.newMessage.content}")
    }
    is MessageProcessingResult.Duplicate -> {
        println("Message already processed")
    }
    is MessageProcessingResult.Error -> {
        println("Error processing: ${result.error}")
    }
}
```

### Process Multiple Messages

```kotlin
val eventJsons = listOf("{...}", "{...}", "{...}")
val results = mdk.processMessages(eventJsons = eventJsons)

results.forEach { result ->
    if (result is MessageProcessingResult.NewMessage) {
        println("Processed: ${result.newMessage.content}")
    }
}
```

## Error Handling

All MDK operations can throw `MdkUniffiError`:

```kotlin
try {
    val groups = mdk.getGroups()
    // Use groups...
} catch (e: MdkUniffiError.Storage) {
    println("Storage error: ${e.message}")
} catch (e: MdkUniffiError.Mdk) {
    println("MDK error: ${e.message}")
} catch (e: MdkUniffiError.InvalidInput) {
    println("Invalid input: ${e.message}")
}
```

## Data Types

### Group

```kotlin
data class Group(
    val mlsGroupId: String,        // Hex-encoded MLS group ID
    val name: String,
    val description: String,
    val relays: List<String>,      // Relay URLs
    val admins: List<String>,      // Admin public keys (hex)
    val createdAt: ULong           // Timestamp
)
```

### Message

```kotlin
data class Message(
    val eventId: String,            // Nostr event ID (hex)
    val mlsGroupId: String,
    val senderPublicKey: String,   // Hex-encoded
    val content: String,           // Decrypted content
    val kind: UShort,
    val createdAt: ULong
)
```

### Welcome

```kotlin
data class Welcome(
    val welcomeJson: String,        // Welcome message JSON
    val groupName: String,
    val groupDescription: String,
    val senderPublicKey: String    // Hex-encoded
    val createdAt: ULong
)
```

### KeyPackageResult

```kotlin
data class KeyPackageResult(
    val keyPackage: String,         // Hex-encoded key package
    val tags: List<List<String>>    // Nostr event tags
)
```

## Thread Safety

MDK instances are thread-safe internally, but you should avoid sharing a single instance across multiple threads. Instead:

- Create separate MDK instances for different threads if needed
- Or use coroutines and ensure serialized access within your application

## Android Integration

### Native Libraries

The package includes native libraries for:
- `arm64-v8a` (64-bit ARM)
- `armeabi-v7a` (32-bit ARM)

Place the `.so` files in your `src/main/jniLibs/` directory structure, or use the packaged AAR which includes them automatically.

### Coroutines Example

```kotlin
import kotlinx.coroutines.*
import org.parres.mdk.*

class MdkManager(private val context: Context) {
    private val mdk = newMdk(context.filesDir.resolve("mdk.db").absolutePath)
    
    suspend fun getGroupsAsync(): List<Group> = withContext(Dispatchers.IO) {
        mdk.getGroups()
    }
    
    suspend fun createMessageAsync(
        groupId: String,
        content: String
    ): String = withContext(Dispatchers.IO) {
        mdk.createMessage(
            mlsGroupId = groupId,
            senderPublicKey = myPublicKey,
            content = content,
            kind = 1u
        )
    }
}
```

## Example: Complete Workflow

```kotlin
import org.parres.mdk.*

// 1. Initialize
val dbPath = "/path/to/mdk.db"
val mdk = newMdk(dbPath)

// 2. Create and publish key package
val keyPackage = mdk.createKeyPackageForEvent(
    publicKey = myPublicKey,
    relays = listOf("wss://relay.example.com")
)
// Publish keyPackage.keyPackage as Nostr event kind 443

// 3. Create a group
val groupResult = mdk.createGroup(
    creatorPublicKey = myPublicKey,
    memberKeyPackageEventsJson = listOf(memberKeyPackageEventJson),
    name = "My Group",
    description = "A test group",
    relays = listOf("wss://relay.example.com"),
    admins = listOf(myPublicKey)
)

// 4. Send a message
val messageEvent = mdk.createMessage(
    mlsGroupId = groupResult.group.mlsGroupId,
    senderPublicKey = myPublicKey,
    content = "Hello!",
    kind = 1u
)
// Publish messageEvent to Nostr relays

// 5. Retrieve messages
val messages = mdk.getMessages(mlsGroupId = groupResult.group.mlsGroupId)
messages.forEach { message ->
    println("${message.senderPublicKey}: ${message.content}")
}
```

## Integration with Android ViewModel

```kotlin
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.parres.mdk.*

class GroupViewModel(private val mdk: MdkInterface) : ViewModel() {
    private val _groups = MutableStateFlow<List<Group>>(emptyList())
    val groups: StateFlow<List<Group>> = _groups
    
    init {
        loadGroups()
    }
    
    private fun loadGroups() {
        viewModelScope.launch {
            try {
                _groups.value = mdk.getGroups()
            } catch (e: Exception) {
                // Handle error
            }
        }
    }
    
    fun sendMessage(groupId: String, content: String) {
        viewModelScope.launch {
            try {
                val eventJson = mdk.createMessage(
                    mlsGroupId = groupId,
                    senderPublicKey = myPublicKey,
                    content = content,
                    kind = 1u
                )
                // Publish to Nostr
            } catch (e: Exception) {
                // Handle error
            }
        }
    }
}
```
