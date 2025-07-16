import os
import pytest
import random
import string

from passboltapi import PassboltAPI

# Test configuration
TEST_FOLDER_NAME = "Test Folder"
TEST_RESOURCE_NAME = "Test Resource"
TEST_USER_EMAIL = "scripter@igaming.com" #"test@example.com"
TEST_USER_FIRST_NAME = "Scripter-API"
TEST_USER_LAST_NAME = "Scripter-API"

# List of test user emails (these should be valid emails that can receive invites)
TEST_USERS = [
    "debanjan.basu@nexern.com",
    # "user2@example.com",
    # "user3@example.com",
]


def get_random_string(length=8):
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


@pytest.fixture(scope="session")
def api():
    """Fixture that provides an authenticated Passbolt API client."""
    config_path = os.environ.get("PASSBOLT_CONFIG", "config.ini")
    api = PassboltAPI(config_path=config_path)
    
    # Import public keys for all users
    api.import_public_keys()
    
    yield api
    
    # Clean up after all tests
    api.close_session()


@pytest.fixture(scope="module")
def test_folder(api):
    """Fixture that creates a test folder and cleans it up after tests."""
    from passboltapi.schema import PassboltFolderTuple, constructor
    
    # Check if folder already exists
    folders = [f for f in api.iterate_resources() if f.get('name') == TEST_FOLDER_NAME]
    if folders:
        folder_dict = folders[0]
        # Convert to named tuple
        folder = constructor(PassboltFolderTuple)(folder_dict)
    else:
        # Create test folder
        folder_dict = api.create_folder(TEST_FOLDER_NAME)
        # Ensure we have a proper named tuple
        if not isinstance(folder_dict, PassboltFolderTuple):
            folder = constructor(PassboltFolderTuple)(folder_dict)
        else:
            folder = folder_dict
    
    yield folder
    
    # Clean up: Delete the test folder and all its contents
    try:
        api.delete(f"/folders/{folder.id}.json")
    except Exception as e:
        print(f"Error cleaning up test folder: {e}")


@pytest.fixture(scope="function")
def test_resource(api, test_folder):
    """Fixture that creates a test resource and cleans it up after each test."""
    from passboltapi.schema import PassboltResourceTuple, constructor
    
    # Generate a unique resource name for each test
    resource_name = f"{TEST_RESOURCE_NAME} {get_random_string()}"
    
    # Create test resource
    resource_dict = api.create_resource(
        name=resource_name,
        username=f"user_{get_random_string(4)}",
        password=get_random_string(12),
        description="Test resource created by pytest",
        uri="https://test.example.com",
        folder_id=test_folder.id if hasattr(test_folder, 'id') else test_folder.get('id')
    )
    
    # Ensure we have a proper named tuple
    if not isinstance(resource_dict, PassboltResourceTuple):
        resource = constructor(PassboltResourceTuple)(resource_dict)
    else:
        resource = resource_dict
    
    yield resource
    
    # Clean up: Delete the test resource
    try:
        api.delete(f"/resources/{resource.id}.json")
    except Exception as e:
        print(f"Error cleaning up test resource: {e}")


@pytest.fixture(scope="module")
def test_users(api):
    """Fixture that ensures test users exist and cleans them up after tests."""
    from passboltapi.schema import PassboltUserTuple, constructor
    
    users = []
    
    # Ensure test users exist
    for email in TEST_USERS:
        # Check if user exists
        existing_users = [u for u in api.list_users() if u.username == email]
        
        if not existing_users:
            # Create user if they don't exist (needs admin permissions)
            user_data = {
                "username": email,
                "profile": {
                    "first_name": email.split('@')[0].capitalize(),
                    "last_name": "User"
                }
            }
            response = api.post("/users.json", user_data)
            user_dict = response["body"]
            # Convert to named tuple
            user = constructor(PassboltUserTuple)(user_dict)
        else:
            user = existing_users[0]
            # Ensure we have a proper named tuple
            if not isinstance(user, PassboltUserTuple):
                user = constructor(PassboltUserTuple)(user)
        
        users.append(user)
    
    yield users
    
    # Note: We don't delete users as they might be real users in a test environment
    # In a real test environment, you might want to clean up test users


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (needs Passbolt server)"
    )


def pytest_collection_modifyitems(session, config, items):
    """Reorder collected tests so that assumption tests (filename contains 'assumptions') run first.
    This helps fail fast on unmet server capabilities before heavier integration flows start.
    """
    items.sort(key=lambda item: 0 if "assumptions" in item.nodeid else 1)
