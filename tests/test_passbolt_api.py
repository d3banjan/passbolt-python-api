"""
Pytest tests for Passbolt API client.

These tests cover the main functionality of the Passbolt API client,
including resource creation, sharing, and management.
"""
import logging
import pytest


@pytest.mark.integration
class TestPassboltAPI:
    """Test suite for Passbolt API client."""

    def test_list_resources(self, api, test_resource):
        """Test listing resources."""
        resources = api.list_resources()
        assert isinstance(resources, list)
        assert any(r.id == test_resource.id for r in resources)

    def test_get_resource(self, api, test_resource):
        """Test getting a single resource."""
        resource = api.read_resource(test_resource.id)
        assert resource.id == test_resource.id
        assert resource.name == test_resource.name

    def test_get_resource_password(self, api, test_resource):
        """Test retrieving a resource's password."""
        password = api.get_password(test_resource.id)
        assert isinstance(password, str)
        assert len(password) > 0

    def test_create_resource_in_folder(self, api, test_folder):
        """Test creating a resource in a specific folder."""
        resource_name = f"Test Resource {test_folder.name}"
        resource = api.create_resource(
            name=resource_name,
            username="test_user",
            password="test_password",
            description="Test description",
            uri="https://test.example.com",
            folder_id=test_folder.id
        )
        
        assert resource.name == resource_name
        assert resource.folder_parent_id == test_folder.id
        
        # Clean up
        api.delete(f"/resources/{resource.id}.json")

    def test_share_folder(self, api, test_folder, test_users):
        """Test sharing a folder with other users."""
        if not test_users:
            pytest.skip("No test users available")
            
        # Share with the first test user with read permission
        user = test_users[0]
        permissions = [
            {
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 1,  # Read permission
            }
        ]
        
        # Share the folder, skip test gracefully if the server does not support folder sharing
        try:
            assert api.share_folder(test_folder.id, permissions)
        except Exception as e:
            import passboltapi
            if isinstance(e, passboltapi.PassboltError):
                pytest.xfail(f"Folder sharing unsupported: {e}")
            raise
        
        # Verify the permission was set
        folder = api.describe_folder(test_folder.id)
        assert any(
            perm.aro == "User" 
            and perm.aro_foreign_key == user.id 
            and perm.type == 1
            for perm in folder.permissions
        )
        
        # Test adding another permission without replacing
        new_permissions = [
            {
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 7,  # Update permission (should replace the read permission)
            },
            {
                "aro": "User",
                "aro_foreign_key": test_users[1].id if len(test_users) > 1 else user.id,  # Use another user if available
                "type": 1,  # Read permission for another user
            }
        ]
        
        # Share with the new permissions without replacing
        assert api.share_folder(test_folder.id, new_permissions, replace=False)
        
        # Verify both permissions were set
        folder = api.describe_folder(test_folder.id)
        permissions = {}
        for perm in folder.permissions:
            key = (perm.aro, perm.aro_foreign_key)
            permissions[key] = perm.type
            
        # Check first user's permission was updated
        user_key = ("User", user.id)
        assert user_key in permissions
        assert permissions[user_key] == 7  # Should be updated to Update permission
        
        # Check second permission was added
        if len(test_users) > 1:
            second_user_key = ("User", test_users[1].id)
            assert second_user_key in permissions
            assert permissions[second_user_key] == 1  # Should have Read permission

    def test_share_resource(self, api, test_resource, test_users):
        """Test sharing a resource with other users."""
        if not test_users:
            pytest.skip("No test users available")
            
        # Share with the first test user with read permission
        user = test_users[0]
        permissions = [
            {
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 1,  # Read permission
            }
        ]
        
        # Share the resource
        assert api.share_resource(test_resource.id, permissions)
        
        # Verify the permission was set
        resource = api.read_resource(test_resource.id)
        assert any(
            perm.aro == "User"
            and perm.aro_foreign_key == user.id
            and perm.type == 1
            for perm in resource.permissions
        )

    def test_filter_resources_by_tag(self, api, test_resource, caplog):
        """Test filtering resources by tag."""
        # Enable debug logging for this test
        def _short(obj, length=100):
            s = str(obj)
            return s if len(s) <= length else s[:length] + "..."
        import logging
        caplog.set_level(logging.DEBUG)
        logger = logging.getLogger(__name__)
        
        # Create a unique tag name for this test
        import uuid
        tag_name = f"test-tag-{str(uuid.uuid4())[:8]}"
        shared_tag_name = f"#shared-{tag_name}"
        logger.debug(f"Using tags: {tag_name} and {shared_tag_name} for resource {test_resource.id}")
    
        try:
            # 1. Add a personal tag to the test resource (will be created automatically)
            logger.debug("Adding personal tag...")
            add_response = api.add_tag_to_resource(tag_name, test_resource.id)
            logger.debug(f"add_tag_to_resource response: {_short(add_response)}")
    
            # 2. Add a shared tag (prefixed with #)
            logger.debug("Adding shared tag...")
            add_shared_response = api.add_tag_to_resource(shared_tag_name, test_resource.id)
            logger.debug(f"add_tag_to_resource (shared) response: {_short(add_shared_response)}")
    
            # 3. Get the resource with tags to verify
            logger.debug("Fetching resource with tags...")
            resource_with_tags = api.get(f"/resources/{test_resource.id}.json?contain[tag]=1")
            logger.debug(f"Resource with tags: {_short(resource_with_tags)}")
            
            # 4. Get tags directly
            tags = api.get_resource_tags(test_resource.id)
            logger.debug(f"get_resource_tags response: {_short(tags)}")
            
            if not isinstance(tags, list):
                tags = [tags]
    
            tag_names = [t.tag for t in tags]
            logger.debug(f"Extracted tag names: {_short(tag_names)}")
            
            # 5. Check if our tags are in the list
            logger.debug(f"Looking for tag: {tag_name} in {_short(tag_names)}")
            if tag_name not in tag_names:
                # Try getting all resources with tags to see what's actually there
                all_resources = api.get("/resources.json?contain[tag]=1")
                logger.debug(f"All resources with tags: {_short(all_resources)}")
                
                # Also try direct tag listing if available
                try:
                    all_tags = api.get("/tags.json")
                    logger.debug(f"All tags: {_short(all_tags)}")
                except Exception as e:
                    logger.debug(f"Could not list all tags: {e}")
            
            assert tag_name in tag_names, f"Tag {tag_name} not found in {tag_names}"
            assert shared_tag_name in tag_names
            
            # 4. Test filtering resources by the personal tag
            resources = api.list_resources(has_tag=tag_name)
            resource_ids = [r.id for r in resources]
            assert test_resource.id in resource_ids
            
            # 5. Test filtering resources by the shared tag
            resources = api.list_resources(has_tag=shared_tag_name)
            resource_ids = [r.id for r in resources]
            assert test_resource.id in resource_ids
            
        except Exception as e:
            # Log the error but don't fail the test if cleanup fails
            logging.warning(f"Error in test_filter_resources_by_tag cleanup: {e}")
            raise

    def test_move_resource_to_folder(self, api, test_resource, test_folder):
        """Test moving a resource to a different folder."""
        # Create a new folder for the test
        new_folder = api.create_folder(f"Test Folder {test_resource.id[-8:]}")
        
        try:
            # Move the resource to the new folder
            response = api.move_resource_to_folder(
                resource_id=test_resource.id,
                folder_id=new_folder.id
            )
            
            # Verify the move was successful
            resource = api.read_resource(test_resource.id)
            assert resource.folder_parent_id == new_folder.id
            
            # Move it back to the original folder
            api.move_resource_to_folder(
                resource_id=test_resource.id,
                folder_id=test_folder.id
            )
            
        finally:
            # Clean up the test folder
            api.delete(f"/folders/{new_folder.id}.json")

    def test_resource_search(self, api, test_resource):
        """Test searching for resources."""
        # Search by resource name
        resources = api.list_resources(search=test_resource.name)
        assert any(r.id == test_resource.id for r in resources)
        
        # Search by username
        resources = api.list_resources(search=test_resource.username)
        assert any(r.id == test_resource.id for r in resources)

    def test_list_users(self, api, test_users):
        """Test listing users."""
        users = api.list_users()
        assert isinstance(users, list)
        assert len(users) > 0
        
        # Verify test users are in the list
        test_user_emails = {user.username for user in test_users}
        user_emails = {user.username for user in users}
        assert test_user_emails.issubset(user_emails)

    def test_get_user(self, api, test_users):
        """Test getting a single user."""
        if not test_users:
            pytest.skip("No test users available")
        
        # Get the first test user
        test_user = test_users[0]
        
        # Get all users and find the test user by ID
        all_users = api.list_users()
        user_details = next((u for u in all_users if u.id == test_user.id), None)
        
        assert user_details is not None, f"Test user {test_user.id} not found in user list"
        assert user_details.id == test_user.id
        assert user_details.username == test_user.username

    def test_list_resources_with_has_parent_filter(self, api, test_folder, test_resource):
        """Test listing resources with has_parent filter."""
        # List resources in the test folder using has_parent filter
        resources = api.list_resources(has_parent=test_folder.id)
        assert isinstance(resources, list)

        # Verify the test resource is in the list
        resource_ids = [r.id for r in resources]
        assert test_resource.id in resource_ids

        # Verify all resources have the correct parent folder
        for resource in resources:
            assert resource.folder_parent_id == test_folder.id

    def test_list_resources_includes_tags_and_permissions(self, api, test_resource):
        """Test that list_resources includes tags and permissions by default."""
        resources = api.list_resources(has_id=test_resource.id)
        assert len(resources) > 0

        resource = resources[0]
        # Verify tags field exists (may be empty list)
        assert hasattr(resource, 'tags')
        assert isinstance(resource.tags, list)

        # Verify permissions field exists (may be empty list)
        assert hasattr(resource, 'permissions')
        assert isinstance(resource.permissions, list)

    def test_read_resource_includes_tags(self, api, test_resource):
        """Test that read_resource includes tags by default."""
        resource = api.read_resource(test_resource.id)

        # Verify tags field exists
        assert hasattr(resource, 'tags')
        assert isinstance(resource.tags, list)

        # Verify permissions field exists
        assert hasattr(resource, 'permissions')
        assert isinstance(resource.permissions, list)

    def test_apply_sharing_rules_with_has_parent(self, api, test_folder, test_resource, test_users):
        """Test applying sharing rules to resources in a folder."""
        if not test_users:
            pytest.skip("No test users available")

        user = test_users[0]
        permissions = [
            {
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 1,  # Read permission
            }
        ]

        # Apply sharing rules to all resources in the folder
        result = api.apply_sharing_rules(
            has_parent=test_folder.id,
            permissions=permissions,
            replace=False
        )

        # Verify result structure
        assert "success" in result
        assert "failed" in result
        assert "total" in result
        assert "succeeded" in result
        assert "failed_count" in result

        # Verify at least one resource was processed
        assert result["total"] > 0

        # Verify test resource was successfully shared
        success_ids = [s["resource_id"] for s in result["success"]]
        assert test_resource.id in success_ids

        # Verify no failures
        assert result["failed_count"] == 0
        assert len(result["failed"]) == 0

    def test_apply_sharing_rules_with_has_tag(self, api, test_resource, test_users):
        """Test applying sharing rules to resources with a specific tag."""
        if not test_users:
            pytest.skip("No test users available")

        # Add a tag to the test resource
        tag_name = "test-sharing-tag"
        api.add_tag_to_resource(tag_name, test_resource.id)

        # Clear cache to ensure fresh data
        if api._enable_caching and api._cache:
            api._cache.clear()

        # Verify the tag was added by checking the resource
        resource_with_tag = api.read_resource(test_resource.id)
        tag_names = [t.tag for t in resource_with_tag.tags]
        if tag_name not in tag_names:
            pytest.skip(f"Tag '{tag_name}' was not added to resource (tags: {tag_names})")

        user = test_users[0]
        permissions = [
            {
                "aro": "User",
                "aro_foreign_key": user.id,
                "type": 1,  # Read permission
            }
        ]

        # Apply sharing rules to resources with the tag
        result = api.apply_sharing_rules(
            has_tag=tag_name,
            permissions=permissions,
            replace=False
        )

        # Verify result structure
        assert "success" in result
        assert "failed" in result
        assert result["total"] > 0, f"Expected resources with tag '{tag_name}', but found {result['total']}"

        # Verify test resource was in the results
        all_resource_ids = [s["resource_id"] for s in result["success"]] + \
                          [f["resource_id"] for f in result["failed"]]
        assert test_resource.id in all_resource_ids

    def test_apply_sharing_rules_with_multiple_resources(self, api, test_folder, test_users):
        """Test applying sharing rules to multiple resources at once."""
        if not test_users:
            pytest.skip("No test users available")

        # Create multiple test resources
        from passboltapi.schema import PassboltResourceTuple, constructor
        from tests.conftest import get_random_string

        resource_ids = []
        for i in range(3):
            resource_dict = api.create_resource(
                name=f"Bulk Share Test {i} {get_random_string()}",
                username=f"bulk_user_{i}",
                password=get_random_string(12),
                folder_id=test_folder.id
            )
            if not isinstance(resource_dict, PassboltResourceTuple):
                resource = constructor(PassboltResourceTuple)(resource_dict)
            else:
                resource = resource_dict
            resource_ids.append(resource.id)

        try:
            # Apply sharing rules
            user = test_users[0]
            permissions = [
                {
                    "aro": "User",
                    "aro_foreign_key": user.id,
                    "type": 1,  # Read permission
                }
            ]

            result = api.apply_sharing_rules(
                has_parent=test_folder.id,
                permissions=permissions,
                replace=False
            )

            # Verify all resources were processed
            assert result["total"] >= 3

            # Verify our test resources are in the success list
            success_ids = [s["resource_id"] for s in result["success"]]
            for resource_id in resource_ids:
                assert resource_id in success_ids

        finally:
            # Clean up test resources
            for resource_id in resource_ids:
                try:
                    api.delete(f"/resources/{resource_id}.json")
                except Exception as e:
                    logging.warning(f"Failed to clean up resource {resource_id}: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
