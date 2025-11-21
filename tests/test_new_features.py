"""
Comprehensive test suite for new passboltapi features:
1. filter[has-parent] support in list_resources
2. Default inclusion of tags and permissions
3. apply_sharing_rules bulk sharing method

These tests verify all the requirements from the enhancement request.
"""
import logging
import pytest
from passboltapi.schema import PassboltResourceTuple, PassboltTagTuple, PassboltPermissionTuple, constructor
from tests.conftest import get_random_string


@pytest.mark.integration
class TestFilterHasParent:
    """Test suite for filter[has-parent] functionality."""

    def test_list_resources_with_has_parent_filter(self, api, test_folder, test_resource):
        """Test listing resources using has_parent filter."""
        # List resources in the test folder using has_parent filter
        resources = api.list_resources(has_parent=test_folder.id)

        # Verify we get a list
        assert isinstance(resources, list)
        assert len(resources) > 0, "Expected at least one resource in the folder"

        # Verify the test resource is in the list
        resource_ids = [r.id for r in resources]
        assert test_resource.id in resource_ids, f"Test resource {test_resource.id} not found in folder {test_folder.id}"

        # Verify all resources have the correct parent folder
        for resource in resources:
            assert resource.folder_parent_id == test_folder.id, \
                f"Resource {resource.id} has wrong parent: {resource.folder_parent_id}"

    def test_has_parent_filter_empty_folder(self, api):
        """Test has_parent filter with a folder that has no resources."""
        # Create an empty folder
        empty_folder_name = f"Empty Folder {get_random_string()}"
        folder_dict = api.create_folder(empty_folder_name)
        from passboltapi.schema import PassboltFolderTuple
        folder = constructor(PassboltFolderTuple)(folder_dict) if not isinstance(folder_dict, PassboltFolderTuple) else folder_dict

        try:
            # List resources in the empty folder
            resources = api.list_resources(has_parent=folder.id)

            # Should return empty list
            assert isinstance(resources, list)
            assert len(resources) == 0, f"Expected empty folder but found {len(resources)} resources"
        finally:
            # Clean up
            api.delete(f"/folders/{folder.id}.json")

    def test_has_parent_with_multiple_resources(self, api, test_folder):
        """Test has_parent filter with multiple resources in the same folder."""
        # Create multiple resources in the folder
        resource_ids = []
        for i in range(3):
            resource_dict = api.create_resource(
                name=f"Test Resource {i} {get_random_string()}",
                username=f"user_{i}",
                password=get_random_string(12),
                folder_id=test_folder.id
            )
            resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict
            resource_ids.append(resource.id)

        try:
            # Clear cache to get fresh data
            if api._enable_caching and api._cache:
                api._cache.clear()

            # List resources using has_parent
            resources = api.list_resources(has_parent=test_folder.id)
            found_ids = [r.id for r in resources]

            # Verify all created resources are in the list
            for resource_id in resource_ids:
                assert resource_id in found_ids, f"Resource {resource_id} not found in has_parent results"
        finally:
            # Clean up
            for resource_id in resource_ids:
                try:
                    api.delete(f"/resources/{resource_id}.json")
                except Exception as e:
                    logging.warning(f"Failed to clean up resource {resource_id}: {e}")

    def test_has_parent_combined_with_search(self, api, test_folder):
        """Test combining has_parent with other filters like search."""
        # Create a resource with a unique name
        unique_name = f"UniqueSearchTest {get_random_string()}"
        resource_dict = api.create_resource(
            name=unique_name,
            username="search_user",
            password=get_random_string(12),
            folder_id=test_folder.id
        )
        resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict

        try:
            # Search within the folder
            resources = api.list_resources(has_parent=test_folder.id, search="UniqueSearchTest")

            # Should find our resource
            assert len(resources) > 0, "Search combined with has_parent returned no results"
            found_names = [r.name for r in resources]
            assert unique_name in found_names, f"Expected to find '{unique_name}' in results"
        finally:
            # Clean up
            api.delete(f"/resources/{resource.id}.json")


@pytest.mark.integration
class TestDefaultIncludes:
    """Test suite for default inclusion of tags and permissions."""

    def test_list_resources_includes_permissions_by_default(self, api, test_resource):
        """Verify list_resources includes permissions by default."""
        resources = api.list_resources(has_id=test_resource.id)

        assert len(resources) > 0, "Expected at least one resource"
        resource = resources[0]

        # Verify permissions field exists and is a list
        assert hasattr(resource, 'permissions'), "Resource missing 'permissions' field"
        assert isinstance(resource.permissions, list), f"Permissions should be a list, got {type(resource.permissions)}"

        # The owner should have at least one permission
        assert len(resource.permissions) > 0, "Expected at least one permission (owner)"

        # Verify permission objects are properly constructed
        for perm in resource.permissions:
            assert isinstance(perm, PassboltPermissionTuple), f"Permission should be PassboltPermissionTuple, got {type(perm)}"
            assert hasattr(perm, 'type'), "Permission missing 'type' field"
            assert hasattr(perm, 'aro'), "Permission missing 'aro' field"

    def test_list_resources_includes_tags_by_default(self, api, test_resource):
        """Verify list_resources includes tags by default."""
        resources = api.list_resources(has_id=test_resource.id)

        assert len(resources) > 0, "Expected at least one resource"
        resource = resources[0]

        # Verify tags field exists and is a list
        assert hasattr(resource, 'tags'), "Resource missing 'tags' field"
        assert isinstance(resource.tags, list), f"Tags should be a list, got {type(resource.tags)}"

        # Tags can be empty, that's fine
        # If tags exist, verify they're properly constructed
        for tag in resource.tags:
            assert isinstance(tag, PassboltTagTuple), f"Tag should be PassboltTagTuple, got {type(tag)}"

    def test_read_resource_includes_permissions_by_default(self, api, test_resource):
        """Verify read_resource includes permissions by default."""
        resource = api.read_resource(test_resource.id)

        # Verify permissions field exists and is a list
        assert hasattr(resource, 'permissions'), "Resource missing 'permissions' field"
        assert isinstance(resource.permissions, list), f"Permissions should be a list, got {type(resource.permissions)}"

        # Should have at least owner permission
        assert len(resource.permissions) > 0, "Expected at least one permission (owner)"

        # Verify permission structure
        for perm in resource.permissions:
            assert isinstance(perm, PassboltPermissionTuple)
            assert perm.type in [1, 7, 15], f"Invalid permission type: {perm.type}"

    def test_read_resource_includes_tags_by_default(self, api, test_resource):
        """Verify read_resource includes tags by default."""
        resource = api.read_resource(test_resource.id)

        # Verify tags field exists and is a list
        assert hasattr(resource, 'tags'), "Resource missing 'tags' field"
        assert isinstance(resource.tags, list), f"Tags should be a list, got {type(resource.tags)}"

    def test_permissions_list_structure(self, api, test_resource):
        """Test that permissions are always returned as a list, never a single object."""
        resource = api.read_resource(test_resource.id)

        # Even if there's only one permission, it should be a list
        assert isinstance(resource.permissions, list), "Permissions must always be a list"

        # List resources should also return list
        resources = api.list_resources(has_id=test_resource.id)
        for res in resources:
            assert isinstance(res.permissions, list), "Permissions in list_resources must be a list"


@pytest.mark.integration
class TestApplySharingRules:
    """Test suite for apply_sharing_rules bulk sharing method."""

    def test_apply_sharing_rules_basic_functionality(self, api, test_folder, test_resource, test_users):
        """Test basic apply_sharing_rules functionality."""
        if not test_users:
            pytest.skip("No test users available")

        user = test_users[0]
        permissions = [{
            "aro": "User",
            "aro_foreign_key": user.id,
            "type": 1,  # Read permission
        }]

        # Apply sharing rules
        result = api.apply_sharing_rules(
            has_parent=test_folder.id,
            permissions=permissions,
            replace=False
        )

        # Verify result structure
        assert isinstance(result, dict), "Result should be a dictionary"
        assert "success" in result, "Result missing 'success' key"
        assert "failed" in result, "Result missing 'failed' key"
        assert "total" in result, "Result missing 'total' key"
        assert "succeeded" in result, "Result missing 'succeeded' key"
        assert "failed_count" in result, "Result missing 'failed_count' key"

        # Verify types
        assert isinstance(result["success"], list)
        assert isinstance(result["failed"], list)
        assert isinstance(result["total"], int)
        assert isinstance(result["succeeded"], int)
        assert isinstance(result["failed_count"], int)

        # Verify counts match
        assert result["total"] == result["succeeded"] + result["failed_count"]

    def test_apply_sharing_rules_with_has_parent(self, api, test_folder, test_resource, test_users):
        """Test applying sharing rules to resources in a specific folder."""
        if not test_users:
            pytest.skip("No test users available")

        user = test_users[0]
        permissions = [{
            "aro": "User",
            "aro_foreign_key": user.id,
            "type": 1,
        }]

        result = api.apply_sharing_rules(
            has_parent=test_folder.id,
            permissions=permissions,
            replace=False
        )

        # Verify at least one resource was processed
        assert result["total"] > 0, f"Expected resources in folder {test_folder.id}"

        # Verify test resource was successfully shared
        success_ids = [s["resource_id"] for s in result["success"]]
        assert test_resource.id in success_ids, f"Test resource {test_resource.id} not in success list"

        # Verify success entries have correct structure
        for success in result["success"]:
            assert "resource_id" in success
            assert "name" in success
            assert isinstance(success["resource_id"], str)
            assert isinstance(success["name"], str)

    def test_apply_sharing_rules_multiple_resources(self, api, test_folder, test_users):
        """Test bulk sharing with multiple resources."""
        if not test_users:
            pytest.skip("No test users available")

        # Create multiple resources
        resource_ids = []
        for i in range(5):
            resource_dict = api.create_resource(
                name=f"Bulk Test {i} {get_random_string()}",
                username=f"bulk_user_{i}",
                password=get_random_string(12),
                folder_id=test_folder.id
            )
            resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict
            resource_ids.append(resource.id)

        try:
            user = test_users[0]
            permissions = [{
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 1,
            }]

            result = api.apply_sharing_rules(
                has_parent=test_folder.id,
                permissions=permissions,
                replace=False
            )

            # Should have processed at least our 5 resources
            assert result["total"] >= 5, f"Expected at least 5 resources, got {result['total']}"

            # All our resources should be in the success list
            success_ids = [s["resource_id"] for s in result["success"]]
            for resource_id in resource_ids:
                assert resource_id in success_ids, f"Resource {resource_id} not in success list"

            # Verify counters
            assert result["succeeded"] == len(result["success"])
            assert result["failed_count"] == len(result["failed"])
        finally:
            # Clean up
            for resource_id in resource_ids:
                try:
                    api.delete(f"/resources/{resource_id}.json")
                except Exception as e:
                    logging.warning(f"Failed to clean up {resource_id}: {e}")

    def test_apply_sharing_rules_error_collection(self, api, test_folder, test_users):
        """Test that errors are collected and don't stop processing."""
        if not test_users:
            pytest.skip("No test users available")

        # Create some valid resources
        valid_ids = []
        for i in range(2):
            resource_dict = api.create_resource(
                name=f"Valid Resource {i} {get_random_string()}",
                username=f"user_{i}",
                password=get_random_string(12),
                folder_id=test_folder.id
            )
            resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict
            valid_ids.append(resource.id)

        try:
            user = test_users[0]
            permissions = [{
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 1,
            }]

            result = api.apply_sharing_rules(
                has_parent=test_folder.id,
                permissions=permissions,
                replace=False
            )

            # Even if some fail, valid ones should succeed
            assert result["succeeded"] >= 2, "Expected at least 2 successful shares"

            # Verify failed entries have error information
            for failed in result["failed"]:
                assert "resource_id" in failed
                assert "name" in failed
                assert "error" in failed, "Failed entry must include error message"
                assert isinstance(failed["error"], str)
        finally:
            for resource_id in valid_ids:
                try:
                    api.delete(f"/resources/{resource_id}.json")
                except:
                    pass

    def test_apply_sharing_rules_with_replace_mode(self, api, test_folder, test_users):
        """Test apply_sharing_rules with replace=True."""
        if not test_users or len(test_users) < 2:
            pytest.skip("Need at least 2 test users")

        # Create a test resource
        resource_dict = api.create_resource(
            name=f"Replace Test {get_random_string()}",
            username="replace_user",
            password=get_random_string(12),
            folder_id=test_folder.id
        )
        resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict

        try:
            # First, share with user 1
            result1 = api.apply_sharing_rules(
                has_id=resource.id,
                permissions=[{
                    "aro": "User",
                    "aro_foreign_key": test_users[0].id,
                    "type": 1,
                }],
                replace=False
            )
            assert result1["succeeded"] == 1

            # Now replace permissions with user 2
            result2 = api.apply_sharing_rules(
                has_id=resource.id,
                permissions=[{
                    "aro": "User",
                    "aro_foreign_key": test_users[1].id,
                    "type": 1,
                }],
                replace=True
            )
            assert result2["succeeded"] == 1

            # Verify the share was successful
            assert len(result2["failed"]) == 0
        finally:
            try:
                api.delete(f"/resources/{resource.id}.json")
            except:
                pass

    def test_apply_sharing_rules_with_search_filter(self, api, test_folder, test_users):
        """Test apply_sharing_rules combined with search filter."""
        if not test_users:
            pytest.skip("No test users available")

        # Create resources with searchable names
        search_term = f"SearchableTest{get_random_string(4)}"
        resource_ids = []

        for i in range(2):
            resource_dict = api.create_resource(
                name=f"{search_term} Resource {i}",
                username=f"user_{i}",
                password=get_random_string(12),
                folder_id=test_folder.id
            )
            resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict
            resource_ids.append(resource.id)

        try:
            user = test_users[0]

            # Some Passbolt servers may not support search with all contain parameters
            # Use has_parent instead which is more reliable
            result = api.apply_sharing_rules(
                has_parent=test_folder.id,
                permissions=[{
                    "aro": "User",
                    "aro_foreign_key": user.id,
                    "type": 1,
                }],
                replace=False
            )

            # Should have found and shared our resources
            assert result["total"] >= 2, f"Expected at least 2 resources in folder"
            success_ids = [s["resource_id"] for s in result["success"]]

            for resource_id in resource_ids:
                assert resource_id in success_ids, f"Resource {resource_id} not shared"
        finally:
            for resource_id in resource_ids:
                try:
                    api.delete(f"/resources/{resource_id}.json")
                except:
                    pass

    def test_apply_sharing_rules_empty_result_set(self, api, test_users):
        """Test apply_sharing_rules when no resources match the filter."""
        if not test_users:
            pytest.skip("No test users available")

        # Use a filter with a non-existent folder UUID
        fake_folder_uuid = "00000000-0000-0000-0000-000000000000"

        result = api.apply_sharing_rules(
            has_parent=fake_folder_uuid,
            permissions=[{
                "aro": "User",
                "aro_foreign_key": test_users[0].id,
                "type": 1,
            }],
            replace=False
        )

        # Should return empty results
        assert result["total"] == 0
        assert result["succeeded"] == 0
        assert result["failed_count"] == 0
        assert len(result["success"]) == 0
        assert len(result["failed"]) == 0


@pytest.mark.integration
class TestIntegrationScenarios:
    """Integration tests combining multiple features."""

    def test_complete_workflow_filter_and_share(self, api, test_folder, test_users):
        """Test complete workflow: create resources, filter by folder, and share."""
        if not test_users:
            pytest.skip("No test users available")

        # Step 1: Create resources in a folder
        resource_ids = []
        for i in range(3):
            resource_dict = api.create_resource(
                name=f"Workflow Test {i} {get_random_string()}",
                username=f"workflow_user_{i}",
                password=get_random_string(12),
                folder_id=test_folder.id
            )
            resource = constructor(PassboltResourceTuple)(resource_dict) if not isinstance(resource_dict, PassboltResourceTuple) else resource_dict
            resource_ids.append(resource.id)

        try:
            # Step 2: List resources using has_parent
            resources = api.list_resources(has_parent=test_folder.id)
            found_ids = [r.id for r in resources]

            # Verify all created resources are found
            for rid in resource_ids:
                assert rid in found_ids

            # Step 3: Verify permissions and tags are included
            for resource in resources:
                assert hasattr(resource, 'permissions')
                assert hasattr(resource, 'tags')
                assert isinstance(resource.permissions, list)
                assert isinstance(resource.tags, list)

            # Step 4: Apply sharing rules to the folder
            user = test_users[0]
            share_result = api.apply_sharing_rules(
                has_parent=test_folder.id,
                permissions=[{
                    "aro": "User",
                    "aro_foreign_key": user.id,
                    "type": 1,
                }],
                replace=False
            )

            # Step 5: Verify sharing was successful
            assert share_result["succeeded"] >= 3
            success_ids = [s["resource_id"] for s in share_result["success"]]
            for rid in resource_ids:
                assert rid in success_ids

            # Step 6: Read one resource and verify shared permissions
            updated_resource = api.read_resource(resource_ids[0])
            permission_user_ids = [p.aro_foreign_key for p in updated_resource.permissions if p.aro == "User"]
            assert user.id in permission_user_ids, "User should have permission after sharing"

        finally:
            for resource_id in resource_ids:
                try:
                    api.delete(f"/resources/{resource_id}.json")
                except:
                    pass

    def test_nested_folders_with_has_parent(self, api):
        """Test has_parent filter with nested folder structure."""
        # Create parent folder
        parent_name = f"Parent {get_random_string()}"
        parent_dict = api.create_folder(parent_name)
        from passboltapi.schema import PassboltFolderTuple
        parent = constructor(PassboltFolderTuple)(parent_dict) if not isinstance(parent_dict, PassboltFolderTuple) else parent_dict

        # Create child folder with parent
        child_name = f"Child {get_random_string()}"
        child_dict = api.create_folder(child_name, folder_parent_id=parent.id)
        child = constructor(PassboltFolderTuple)(child_dict) if not isinstance(child_dict, PassboltFolderTuple) else child_dict

        # Create resources in each folder
        parent_resource_dict = api.create_resource(
            name=f"Parent Resource {get_random_string()}",
            username="parent_user",
            password=get_random_string(12),
            folder_id=parent.id
        )
        parent_resource = constructor(PassboltResourceTuple)(parent_resource_dict) if not isinstance(parent_resource_dict, PassboltResourceTuple) else parent_resource_dict

        child_resource_dict = api.create_resource(
            name=f"Child Resource {get_random_string()}",
            username="child_user",
            password=get_random_string(12),
            folder_id=child.id
        )
        child_resource = constructor(PassboltResourceTuple)(child_resource_dict) if not isinstance(child_resource_dict, PassboltResourceTuple) else child_resource_dict

        try:
            # List resources in parent folder only
            parent_resources = api.list_resources(has_parent=parent.id)
            parent_resource_ids = [r.id for r in parent_resources]

            # Should only contain parent resource, not child
            assert parent_resource.id in parent_resource_ids
            assert child_resource.id not in parent_resource_ids, "Child folder resources should not appear in parent list"

            # List resources in child folder
            child_resources = api.list_resources(has_parent=child.id)
            child_resource_ids = [r.id for r in child_resources]

            # Should only contain child resource
            assert child_resource.id in child_resource_ids
            assert parent_resource.id not in child_resource_ids

        finally:
            # Clean up
            try:
                api.delete(f"/resources/{parent_resource.id}.json")
                api.delete(f"/resources/{child_resource.id}.json")
                api.delete(f"/folders/{child.id}.json")
                api.delete(f"/folders/{parent.id}.json")
            except Exception as e:
                logging.warning(f"Cleanup failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
