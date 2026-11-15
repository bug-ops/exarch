"""Password-protected ZIP and 7z archives (#1023).

The fixtures are WinZip AES-256 and a non-solid 7z with an encrypted header,
both protected with ``correct-horse`` (see ``fixtures/README.md``).
"""

import pytest

import exarch

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"
ARCHIVES = ["encrypted-aes256.zip", "encrypted-header.7z"]
PASSWORD = b"correct-horse"


def _password():
    return bytearray(PASSWORD)


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_with_the_password_decrypts(temp_dir, name):
    report = exarch.extract_archive(
        FIXTURES / name, temp_dir / "out", password=_password()
    )

    assert report.files_extracted == 2
    assert (temp_dir / "out" / "hello.txt").read_bytes() == b"hello encrypted\n"


@pytest.mark.parametrize("name", ARCHIVES)
def test_extract_without_a_password_is_a_typed_security_violation(temp_dir, name):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(FIXTURES / name, temp_dir / "out")

    assert caught.value.sub_code == "ENCRYPTED"
    assert not (temp_dir / "out" / "hello.txt").exists()


@pytest.mark.parametrize("name", ARCHIVES)
def test_a_wrong_password_is_refused_and_never_quoted(temp_dir, name):
    with pytest.raises(exarch.SecurityViolationError) as caught:
        exarch.extract_archive(
            FIXTURES / name, temp_dir / "out", password=bytearray(b"s3cr3t-wrong")
        )

    assert caught.value.sub_code == "ENCRYPTED"
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
        exarch.extract_archive(
            FIXTURES / "encrypted-aes256.zip", temp_dir / "out", password=secret
        )


def test_an_empty_password_is_a_value_error(temp_dir):
    with pytest.raises(ValueError):
        exarch.extract_archive(
            FIXTURES / "encrypted-aes256.zip", temp_dir / "out", password=bytearray()
        )


def test_a_needless_password_is_ignored(temp_dir, sample_tar_gz):
    report = exarch.extract_archive(sample_tar_gz, temp_dir / "out", password=_password())

    assert report.files_extracted == 2


def test_the_security_config_never_holds_the_password():
    config = exarch.SecurityConfig()

    assert "password" not in repr(config).lower()
    assert config.max_kdf_work == 1 << 27
