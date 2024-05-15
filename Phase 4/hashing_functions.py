import hashlib


# Hashing functions
def sha256_hash(data):
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(data)
    return sha256_hasher.hexdigest()


def md5_hash(data):
    md5_hasher = hashlib.md5()
    md5_hasher.update(data)
    return md5_hasher.hexdigest()
