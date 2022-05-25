import json
import sys

from cpg_utils.storage import get_data_manager


def append_metadata(
    dataset: str, bucket_type: str, blob_path: str, metadata_str: str
) -> None:
    """Reads a Json object from blob storage, appends a new object, and writes back out."""
    data_mgr = get_data_manager()

    metadata_bytes = data_mgr.get_blob(dataset, bucket_type, blob_path)
    metadata_old = json.loads(metadata_bytes.decode('utf-8')) if metadata_bytes else []

    # Convert to list for append.
    if type(metadata_old) is not list:
        metadata_old = [metadata_old]

    metadata_new = json.dumps(metadata_old + [json.loads(metadata_str)])
    data_mgr.set_blob(
        dataset, bucket_type, blob_path, bytes(metadata_new, encoding='utf-8')
    )


if __name__ == '__main__':
    append_metadata(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
