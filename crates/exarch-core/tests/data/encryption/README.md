Encrypted fixtures for the #1023 acceptance tests, generated with `7z` (p7zip 17.05) from `hello.txt` ("hello encrypted\n") and `dir/inner.txt` ("inner payload\n"). Password: `correct-horse`.

- `aes256.zip`: WinZip AES-256 (`-mem=AES256`)
- `zipcrypto.zip`: legacy ZipCrypto (`-mem=ZipCrypto`)
- `content.7z`: 7z, encrypted content (`-p`)
- `header.7z`: 7z, encrypted header and content (`-mhe=on`)
- `plain.zip`, `plain.7z`: unencrypted twins
