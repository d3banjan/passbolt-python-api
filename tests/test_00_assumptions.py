import random
import string
import pytest

from passboltapi import PassboltAPI


def _rand_str(prefix: str = "tmp", length: int = 8) -> str:
    letters = string.ascii_lowercase
    return f"{prefix}_{''.join(random.choice(letters) for _ in range(length))}"


def _create_temp_resource(api: PassboltAPI, name_prefix: str = "AssRes"):
    """Create a disposable resource; caller must clean up."""
    name = _rand_str(name_prefix)
    resource = api.create_resource(
        name=name,
        username=_rand_str("user", 5),
        password=_rand_str("pwd", 12),
        description="Assumption test resource",
        uri="https://example.com",
    )
    return resource


@pytest.fixture()
def temp_resource(api: PassboltAPI):
    """Yield a temp resource and delete afterwards."""
    res = _create_temp_resource(api)
    yield res
    try:
        api.delete(f"/resources/{res.id}.json")
    except Exception:
        # Cleanup best effort
        pass


def test_tag_creation_visibility_and_filter(api: PassboltAPI, temp_resource):
    """Assumption: creating a tag on a resource immediately makes it visible via contain[tag] & /tags.json & filter."""
    tag_name = _rand_str("tag")

    # 1. Add the tag (personal)
    api.add_tag_to_resource(tag_name, temp_resource.id)

    # 2. Fetch resource with contain[tag]=1 and assert our tag is there
    res_with_tags = api.get(f"/resources/{temp_resource.id}.json?contain[tags]=1")
    tag_objs = res_with_tags.get("tags") or res_with_tags.get("body", {}).get("tags", [])
    tag_names = [t.get("tag") if isinstance(t, dict) else getattr(t, "tag", None) for t in tag_objs]
    assert tag_name in tag_names, "Tag should be present in resource representation when using contain[tag]=1"

    # 3. List all tags and ensure our tag appears
    all_tags = api.get("/tags.json")
    all_tag_names = [t.get("name") or t.get("tag") for t in all_tags]
    assert tag_name in all_tag_names, "Tag should appear in /tags.json list"

    # 4. Filter resources by tag (personal tag)
    filtered = api.get(f"/resources.json?filter[has-tag][]={tag_name}")
    filtered_ids = [r.get("id") for r in filtered]
    assert temp_resource.id in filtered_ids, "Resource should appear in filter[has-tag] query"


@pytest.mark.xfail(reason="Folder sharing may not be enabled on some servers", strict=False)
def test_folder_sharing_endpoint_available(api: PassboltAPI, test_folder):
    """Assumption: folder sharing endpoint exists (optional)."""
    try:
        # Expect 200 or 403 (permission) but not 404
        api.post(f"/shares/folder/{test_folder.id}.json", {"users": []})
    except Exception as e:
        if "404" in str(e):
            pytest.xfail("Folder sharing endpoint not available")
