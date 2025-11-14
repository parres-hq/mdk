# MDK Python Bindings Documentation

## Installation

```bash
pip install mdk
```

Or install from source:

```bash
git clone https://github.com/parres-hq/mdk-python.git
cd mdk-python
pip install .
```

## Basic Usage

### Import and Initialize

```python
from mdk import new_mdk

# Create an MDK instance with a SQLite database path
db_path = "/path/to/mdk.db"
mdk = new_mdk(db_path)
```

### Create and Publish Key Package

```python
public_key = "your_hex_public_key"
relays = ["wss://relay.example.com", "wss://another-relay.com"]

result = mdk.create_key_package_for_event(
    public_key=public_key,
    relays=relays
)

# result.key_package contains the hex-encoded key package
# result.tags contains Nostr event tags (list of lists)
# Publish as a Nostr event (kind 443) to your relays
```

### Parse Key Packages

```python
# When you receive a key package event from Nostr
event_json = """
{
    "id": "...",
    "kind": 443,
    "content": "hex_key_package...",
    ...
}
"""

mdk.parse_key_package(event_json=event_json)
```

### Create a Group

```python
creator_public_key = "your_hex_public_key"
member_key_package_events = ["{...}", "{...}"]  # JSON strings of key package events
name = "My Group"
description = "A secure group chat"
relays = ["wss://relay.example.com"]
admins = ["your_hex_public_key"]

result = mdk.create_group(
    creator_public_key=creator_public_key,
    member_key_package_events_json=member_key_package_events,
    name=name,
    description=description,
    relays=relays,
    admins=admins
)

# result.group contains the created group
# result.welcome_rumors_json contains welcome messages for initial members
```

### Get Groups

```python
groups = mdk.get_groups()

for group in groups:
    print(f"Group: {group.name}")
    print(f"ID: {group.mls_group_id}")
    print(f"Members: {len(group.members)}")
```

### Get a Specific Group

```python
group = mdk.get_group(mls_group_id="hex_group_id")
if group:
    print(f"Found group: {group.name}")
else:
    print("Group not found")
```

### Get Members

```python
members = mdk.get_members(mls_group_id="hex_group_id")
print(f"Group has {len(members)} members")
for member in members:
    print(f"  - {member}")
```

### Add Members to a Group

```python
mls_group_id = "hex_group_id"
key_package_events = ["{...}", "{...}"]  # JSON strings of key package events

result = mdk.add_members(
    mls_group_id=mls_group_id,
    key_package_events_json=key_package_events
)

# result.evolution_event_json contains the group update event
# result.welcome_rumors_json contains welcome messages for new members
```

### Remove Members from a Group

```python
mls_group_id = "hex_group_id"
member_public_keys = ["hex_pubkey1", "hex_pubkey2"]

result = mdk.remove_members(
    mls_group_id=mls_group_id,
    member_public_keys=member_public_keys
)
```

### Update Group Metadata

```python
mls_group_id = "hex_group_id"
new_name = "Updated Group Name"
new_description = "New description"
new_relays = ["wss://new-relay.com"]

result = mdk.update_group_metadata(
    mls_group_id=mls_group_id,
    name=new_name,
    description=new_description,
    relays=new_relays
)
```

### Accept Welcome Messages

```python
# Get pending welcomes
welcomes = mdk.get_pending_welcomes()

for welcome in welcomes:
    print(f"Invited to: {welcome.group_name}")
    print(f"By: {welcome.sender_public_key}")
    
    # Accept the welcome
    mdk.accept_welcome(welcome_json=welcome.welcome_json)
```

### Decline Welcome Messages

```python
welcome = welcomes[0]
mdk.decline_welcome(welcome_json=welcome.welcome_json)
```

### Create and Send Messages

```python
mls_group_id = "hex_group_id"
sender_public_key = "your_hex_public_key"
content = "Hello, group!"
kind = 1  # Message kind

event_json = mdk.create_message(
    mls_group_id=mls_group_id,
    sender_public_key=sender_public_key,
    content=content,
    kind=kind
)

# event_json is a JSON string of the encrypted Nostr event
# Publish this to your Nostr relays
```

### Get Messages

```python
messages = mdk.get_messages(mls_group_id="hex_group_id")

for message in messages:
    print(f"From: {message.sender_public_key}")
    print(f"Content: {message.content}")
    print(f"Kind: {message.kind}")
```

### Get a Specific Message

```python
message = mdk.get_message(event_id="hex_event_id")
if message:
    print(f"Message: {message.content}")
```

### Process Incoming Messages

```python
# When you receive a message event from Nostr
event_json = """
{
    "id": "...",
    "kind": 1059,
    "content": "encrypted_content...",
    ...
}
"""

result = mdk.process_message(event_json=event_json)

if result.new_message:
    print(f"New message: {result.new_message.content}")
elif result.duplicate:
    print("Message already processed")
elif result.error:
    print(f"Error processing: {result.error}")
```

### Process Multiple Messages

```python
event_jsons = ["{...}", "{...}", "{...}"]
results = mdk.process_messages(event_jsons=event_jsons)

for result in results:
    if result.new_message:
        print(f"Processed: {result.new_message.content}")
```

## Error Handling

All MDK operations can raise `MdkUniffiError`:

```python
from mdk import MdkUniffiError

try:
    groups = mdk.get_groups()
except MdkUniffiError.Storage as e:
    print(f"Storage error: {e}")
except MdkUniffiError.Mdk as e:
    print(f"MDK error: {e}")
except MdkUniffiError.InvalidInput as e:
    print(f"Invalid input: {e}")
```

## Data Types

### Group

```python
class Group:
    mls_group_id: str        # Hex-encoded MLS group ID
    name: str
    description: str
    relays: list[str]        # Relay URLs
    admins: list[str]        # Admin public keys (hex)
    created_at: int         # Timestamp
```

### Message

```python
class Message:
    event_id: str            # Nostr event ID (hex)
    mls_group_id: str
    sender_public_key: str  # Hex-encoded
    content: str            # Decrypted content
    kind: int
    created_at: int
```

### Welcome

```python
class Welcome:
    welcome_json: str        # Welcome message JSON
    group_name: str
    group_description: str
    sender_public_key: str  # Hex-encoded
```

### KeyPackageResult

```python
class KeyPackageResult:
    key_package: str         # Hex-encoded key package
    tags: list[list[str]]    # Nostr event tags
```

## Thread Safety

MDK instances are thread-safe internally, but you should avoid sharing a single instance across multiple threads. Instead:

- Create separate MDK instances for different threads if needed
- Or use thread-local storage or locks to serialize access

## Example: Complete Workflow

```python
from mdk import new_mdk

# 1. Initialize
db_path = "/path/to/mdk.db"
mdk = new_mdk(db_path)

# 2. Create and publish key package
key_package = mdk.create_key_package_for_event(
    public_key=my_public_key,
    relays=["wss://relay.example.com"]
)
# Publish key_package.key_package as Nostr event kind 443

# 3. Create a group
group_result = mdk.create_group(
    creator_public_key=my_public_key,
    member_key_package_events_json=[member_key_package_event_json],
    name="My Group",
    description="A test group",
    relays=["wss://relay.example.com"],
    admins=[my_public_key]
)

# 4. Send a message
message_event = mdk.create_message(
    mls_group_id=group_result.group.mls_group_id,
    sender_public_key=my_public_key,
    content="Hello!",
    kind=1
)
# Publish message_event to Nostr relays

# 5. Retrieve messages
messages = mdk.get_messages(mls_group_id=group_result.group.mls_group_id)
for message in messages:
    print(f"{message.sender_public_key}: {message.content}")
```

## Integration with Nostr SDK

```python
from nostr_sdk import Client, Keys, EventBuilder, Kind, Tag

# Initialize Nostr client
keys = Keys.generate()
client = Client(keys)

# Create key package and publish
key_package = mdk.create_key_package_for_event(
    public_key=keys.public_key().to_hex(),
    relays=["wss://relay.example.com"]
)

event = EventBuilder(Kind(443), key_package.key_package)
tags = [Tag.parse(tag) for tag in key_package.tags]
await client.send_event_builder(event.tags(tags))
```

