import hashlib


def calculate_file_hash(file_path, hash_type='md5'):
    """
    Calculate the hash of a file.

    Args:
        file_path (str): The path to the file.
        hash_type (str): The type of hash to calculate (e.g., 'md5', 'sha256').

    Returns:
        str: The calculated hash.
    """
    hash_func = getattr(hashlib, hash_type)()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()
