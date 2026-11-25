"""Password-protected ZIP and 7z archives (#1023).

The fixtures are WinZip AES-256 and a non-solid 7z with an encrypted header,
both protected with ``correct-horse`` (see ``fixtures/README.md``).
"""

import pytest

import exarch

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"
ARCHIVES = ["encrypted-aes256.zip", "encrypted-header.7z"]
PASSWORD = b"correct-horse"
WRONG_REASON = {
    "encrypted-aes256.zip": "wrong_password",
    "encrypted-header.7z": "wrong_password_or_corrupt",
}


def _password():
    return bytearray(PASSWORD)


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_with_the_password_decrypts(temp_dir, name):
    report = exarch.extract_archive(FIXTURES / name, temp_dir / "out", password=_password())

    assert report.files_extracted == 2
    assert (temp_dir / "out" / "hello.txt").read_bytes() == b"hello encrypted\n"


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_without_a_password_is_a_typed_security_violation(temp_dir, name):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(FIXTURES / name, temp_dir / "out")

    assert caught.value.sub_code == "ENCRYPTED"
    assert caught.value.reason == "password_required"
    assert not (temp_dir / "out" / "hello.txt").exists()


@pytest.mark.parametrize("name", ARCHIVES)
def test_a_wrong_password_is_refused_and_never_quoted(temp_dir, name):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(
            FIXTURES / name, temp_dir / "out", password=bytearray(b"s3cr3t-wrong")
        )

    assert caught.value.sub_code == "ENCRYPTED"
    assert caught.value.reason == WRONG_REASON[name]
    assert "s3cr3t" not in str(caught.value) + repr(caught.value)


@pytest.mark.parametrize("name", ARCHIVES)
def test_list_and_verify_take_the_password(name):
    listed = exarch.list_archive(FIXTURES / name, password=_password())
    report = exarch.verify_archive(FIXTURES / name, password=_password())

    assert any(entry.path.endswith("inner.txt") for entry in listed.entries)
    assert report.issues == []


@pytest.mark.parametrize("secret", [b"correct-horse", "correct-horse"])
def test_bytes_and_str_passwords_are_refused(temp_dir, secret):
    with pytest.raises(TypeError):
        exarch.extract_archive(FIXTURES / "encrypted-aes256.zip", temp_dir / "out", password=secret)


def test_an_empty_password_is_a_value_error(temp_dir):
    with pytest.raises(ValueError):
        exarch.extract_archive(
            FIXTURES / "encrypted-aes256.zip", temp_dir / "out", password=bytearray()
        )


def test_a_needless_password_is_ignored(temp_dir, sample_tar_gz):
    report = exarch.extract_archive(sample_tar_gz, temp_dir / "out", password=_password())

    assert report.files_extracted == 2


@pytest.mark.parametrize("name", ARCHIVES)
@pytest.mark.parametrize("with_progress", [False, True])
def test_the_bytes_forms_of_list_and_verify_take_the_password(name, with_progress):
    data = (FIXTURES / name).read_bytes()
    list_fn = (
        exarch.list_archive_bytes_with_progress if with_progress else exarch.list_archive_bytes
    )
    verify_fn = (
        exarch.verify_archive_bytes_with_progress if with_progress else exarch.verify_archive_bytes
    )

    listed = list_fn(data, password=_password())
    report = verify_fn(data, password=_password())

    assert any(entry.path.endswith("inner.txt") for entry in listed.entries)
    assert report.issues == []


def test_the_bytes_forms_without_a_password_refuse_an_encrypted_header():
    data = (FIXTURES / "encrypted-header.7z").read_bytes()

    for call in (exarch.list_archive_bytes, exarch.verify_archive_bytes):
        with pytest.raises(exarch.SecurityViolationError) as caught:
            call(data)

        assert caught.value.sub_code == "ENCRYPTED"
        assert caught.value.reason == "password_required"


@pytest.mark.parametrize("call_name", ["list_archive_bytes", "verify_archive_bytes"])
def test_the_bytes_forms_refuse_bytes_str_and_empty_passwords(call_name):
    data = (FIXTURES / "encrypted-aes256.zip").read_bytes()
    call = getattr(exarch, call_name)

    for secret in (b"correct-horse", "correct-horse"):
        with pytest.raises(TypeError):
            call(data, password=secret)
    with pytest.raises(ValueError):
        call(data, password=bytearray())


def test_the_security_config_never_holds_the_password():
    config = exarch.SecurityConfig()

    assert "password" not in repr(config).lower()
    assert config.max_kdf_work == 1 << 27


def test_concurrent_7z_operations_with_different_passwords_each_succeed(temp_dir):
    """#1352: two 7z archives with different passwords extract on several threads
    under a tight ``max_kdf_work``. Each operation derives its own keys, so the
    operations do not evict each other's key and charge it again."""
    from concurrent.futures import ThreadPoolExecutor

    jobs = [
        (FIXTURES / "encrypted-header.7z", b"correct-horse"),
        (FIXTURES / "encrypted-content-plain-header.7z", b"exarch"),
    ]
    # The encrypted-header archive adds a fixed header reserve of 2**24 to the budget.
    config = exarch.SecurityConfig().with_max_kdf_work((1 << 24) + (1 << 21))

    def run(index):
        archive, secret = jobs[index % 2]
        report = exarch.extract_archive(
            archive, temp_dir / f"out-{index}", config, password=bytearray(secret)
        )
        return report.files_extracted == 2

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(run, range(80)))
