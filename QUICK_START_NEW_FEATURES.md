# Quick Start Guide - New Passbolt API Features

## 🚀 Quick Reference

### 1. Filter Resources by Parent Folder

```python
from passboltapi import PassboltAPI

api = PassboltAPI(config_path="config.ini")

# Get all resources in a specific folder
resources = api.list_resources(has_parent="folder-uuid-here")

# Resources automatically include tags and permissions
for resource in resources:
    print(f"Resource: {resource.name}")
    print(f"  Permissions: {len(resource.permissions)}")
    print(f"  Tags: {[tag.tag for tag in resource.tags]}")
```

---

### 2. Bulk Share Resources in a Folder

```python
# Share all resources in a folder with a group (Read permission)
result = api.apply_sharing_rules(
    has_parent="folder-uuid",
    permissions=[{
        "aro": "Group",
        "aro_foreign_key": "group-uuid",
        "type": 1  # 1=Read, 7=Update, 15=Owner
    }],
    replace=False  # Add to existing, don't replace
)

# Check results
print(f"✅ Successfully shared: {result['succeeded']}")
print(f"❌ Failed: {result['failed_count']}")

# See details of failures
for failure in result['failed']:
    print(f"  {failure['name']}: {failure['error']}")
```

---

### 3. Share Resources by Tag

```python
# Share all "production" resources with a user (Update permission)
result = api.apply_sharing_rules(
    has_tag="production",
    permissions=[{
        "aro": "User",
        "aro_foreign_key": "user-uuid",
        "type": 7  # Update permission
    }]
)

print(f"Updated {result['succeeded']} production resources")
```

---

### 4. Rule-Based Sharing (Advanced)

```python
# Complex example: Share all resources in a specific folder
# that match a search term with multiple groups

result = api.apply_sharing_rules(
    has_parent="folder-uuid",
    permissions=[
        {
            "aro": "Group",
            "aro_foreign_key": "dev-team-uuid",
            "type": 7  # Update permission
        },
        {
            "aro": "Group",
            "aro_foreign_key": "qa-team-uuid",
            "type": 1  # Read permission
        }
    ],
    replace=False
)

# Detailed results
print(f"Total resources processed: {result['total']}")
print(f"Succeeded: {result['succeeded']}")
print(f"Failed: {result['failed_count']}")

# Success details
for success in result['success']:
    print(f"✅ {success['name']} ({success['resource_id']})")

# Failure details
for failure in result['failed']:
    print(f"❌ {failure['name']}: {failure['error']}")
```

---

### 5. Access Tags and Permissions

```python
# Read a resource with tags and permissions included
resource = api.read_resource("resource-uuid")

# Access permissions (always a list)
for perm in resource.permissions:
    entity_type = perm.aro  # "User" or "Group"
    entity_id = perm.aro_foreign_key
    permission_type = perm.type  # 1, 7, or 15
    print(f"{entity_type} {entity_id}: Type {permission_type}")

# Access tags (always a list)
for tag in resource.tags:
    print(f"Tag: {tag.tag} (shared: {tag.is_shared})")
```

---

## 📋 Permission Types

| Type | Name   | Description                           |
|------|--------|---------------------------------------|
| 1    | Read   | Can view resource                     |
| 7    | Update | Can view and modify resource          |
| 15   | Owner  | Full control (view, modify, delete, share) |

---

## 🎯 Common Use Cases

### Use Case 1: Share Entire Folder with Team
```python
# Give a team read access to all resources in a project folder
api.apply_sharing_rules(
    has_parent="project-folder-uuid",
    permissions=[{"aro": "Group", "aro_foreign_key": "team-uuid", "type": 1}]
)
```

### Use Case 2: Grant Access to Tagged Resources
```python
# Share all "staging" resources with QA team
api.apply_sharing_rules(
    has_tag="staging",
    permissions=[{"aro": "Group", "aro_foreign_key": "qa-team-uuid", "type": 1}]
)
```

### Use Case 3: Bulk Permission Update
```python
# Upgrade permissions for specific resources
api.apply_sharing_rules(
    has_id=["resource-1", "resource-2", "resource-3"],
    permissions=[{"aro": "User", "aro_foreign_key": "user-uuid", "type": 7}],
    replace=False  # Add/update without removing existing permissions
)
```

### Use Case 4: Find and Share Resources in Nested Structure
```python
# List all resources in a parent folder (not including child folders)
parent_resources = api.list_resources(has_parent="parent-folder-uuid")

# Each resource has its metadata
for resource in parent_resources:
    print(f"Resource: {resource.name}")
    print(f"  Folder: {resource.folder_parent_id}")
    print(f"  Current Permissions: {len(resource.permissions)}")
```

---

## ⚠️ Important Notes

1. **Cache Clearing**: `apply_sharing_rules` automatically clears cache to ensure fresh data
2. **Error Handling**: Bulk operations collect all errors and continue processing
3. **Server Compatibility**: Works with Passbolt CE 3.x and 4.x
4. **Empty Lists**: `tags` and `permissions` default to empty lists (`[]`) if none exist

---

## 🔗 API Reference

### `list_resources(**filters)`
**New Parameters:**
- `has_parent` (str): Filter by parent folder UUID

**Returns:** List of `PassboltResourceTuple` with tags and permissions included (when filtered)

---

### `read_resource(resource_id)`
**Returns:** `PassboltResourceTuple` with tags and permissions included

**Schema:**
```python
PassboltResourceTuple(
    id: str,
    name: str,
    permissions: List[PassboltPermissionTuple],  # NEW: always a list
    tags: List[PassboltTagTuple],                # NEW: always a list
    # ... other fields
)
```

---

### `apply_sharing_rules(permissions, replace=False, **filters)`
**Parameters:**
- `permissions` (list): List of permission dicts
- `replace` (bool): Replace all permissions (True) or add/update (False)
- `**filters`: Any filter supported by `list_resources`

**Returns:** Dict with keys:
- `success` (list): Successfully shared resources
- `failed` (list): Failed resources with error messages
- `total` (int): Total resources processed
- `succeeded` (int): Number of successful shares
- `failed_count` (int): Number of failures

---

## 🧪 Testing

Run the comprehensive test suite:
```bash
# Run new feature tests only
pytest tests/test_new_features.py -v

# Run all tests
pytest tests/test_passbolt_api.py tests/test_new_features.py -v

# Run specific test
pytest tests/test_new_features.py::TestApplySharingRules::test_apply_sharing_rules_multiple_resources -v
```

---

## 📚 Further Documentation

- Full test results: `TEST_RESULTS_SUMMARY.md`
- API documentation: `passbolt-api-docs.yaml`
- Original tests: `tests/test_passbolt_api.py`
- New feature tests: `tests/test_new_features.py`

---

**Questions or Issues?**
- Check the comprehensive test suite for more examples
- Review `TEST_RESULTS_SUMMARY.md` for detailed information
- All features are backward compatible with existing code
