#!/usr/bin/env bash
# Generate ZIP-family test fixtures for exarch-core.
#
# These formats all sit on top of the ZIP container but add their own
# structural requirements. The fixtures here are minimal but include the
# structure that actually matters for extraction:
#
#   - simple.jar  : MANIFEST.MF under META-INF/ (JVM artifact shape)
#   - simple.apk  : Android manifest + classes.dex placeholder + resources.arsc
#                   placeholder, unsigned (no signing block)
#   - simple.whl  : dist-info/ with METADATA, WHEEL, RECORD (checksums)
#   - simple.epub : mimetype as the FIRST entry, STORED (no deflate),
#                   followed by container.xml and content files
#   - simple.vsix : extension.vsixmanifest + [Content_Types].xml
#
# Requires: zip (Info-ZIP), sha256sum, base64, xxd, GNU stat (-c%s).
# Tested on Linux; not portable to macOS/BSD without tweaks (bare
# `mktemp -d`, `sha256sum`, `stat -c%s` are GNU-isms).
# shellcheck disable=SC2035

set -euo pipefail

[[ "$(uname)" == "Linux" ]] || { echo "Requires Linux (GNU stat, sha256sum)"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/zip-family"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$FIXTURES_DIR"

# Make the script idempotent: `zip` appends to an existing archive
# rather than replacing it, so re-running would grow the fixtures with
# duplicate entries. Clear anything we're about to produce.
rm -f "$FIXTURES_DIR"/simple.jar \
      "$FIXTURES_DIR"/simple.apk \
      "$FIXTURES_DIR"/simple.whl \
      "$FIXTURES_DIR"/simple.epub \
      "$FIXTURES_DIR"/simple.vsix

echo "Generating ZIP-family test fixtures in $FIXTURES_DIR..."

# -----------------------------------------------------------------------------
# 1. simple.jar
# -----------------------------------------------------------------------------
# A JAR is a ZIP with META-INF/MANIFEST.MF as (conventionally) the first
# entry. `jar` would set this up for us but we want to avoid a JDK dep.
JAR_WORK="$TEMP_DIR/jar"
mkdir -p "$JAR_WORK/META-INF" "$JAR_WORK/com/example"
cat > "$JAR_WORK/META-INF/MANIFEST.MF" <<'EOF'
Manifest-Version: 1.0
Created-By: exarch-fixtures
Main-Class: com.example.Hello

EOF
echo "placeholder class bytes" > "$JAR_WORK/com/example/Hello.class"
(cd "$JAR_WORK" && zip -qr "$FIXTURES_DIR/simple.jar" META-INF com)
echo "✓ Created simple.jar"

# -----------------------------------------------------------------------------
# 2. simple.apk
# -----------------------------------------------------------------------------
# Unsigned APK. Contains the files an APK usually has but none of them are
# functional - we only care that extraction works. No signing block, so
# this is structurally just a ZIP.
APK_WORK="$TEMP_DIR/apk"
mkdir -p "$APK_WORK/META-INF" "$APK_WORK/res/values" "$APK_WORK/lib/arm64-v8a"
# AndroidManifest.xml is normally binary XML; placeholder bytes are fine
# for extraction-only testing.
printf '\x03\x00\x08\x00placeholder-binary-xml' > "$APK_WORK/AndroidManifest.xml"
printf 'dex\n035\x00placeholder-dex-bytes' > "$APK_WORK/classes.dex"
printf 'placeholder-arsc' > "$APK_WORK/resources.arsc"
echo "<resources/>" > "$APK_WORK/res/values/strings.xml"
printf 'placeholder-native-lib' > "$APK_WORK/lib/arm64-v8a/libnative.so"
(cd "$APK_WORK" && zip -qr "$FIXTURES_DIR/simple.apk" .)
echo "✓ Created simple.apk (unsigned)"

# -----------------------------------------------------------------------------
# 3. simple.whl
# -----------------------------------------------------------------------------
# Minimal valid-ish wheel. PEP 427 layout: {dist}-{ver}.dist-info/ with
# METADATA, WHEEL, RECORD. RECORD contains sha256 hashes of the other
# files so we generate it last.
WHL_WORK="$TEMP_DIR/whl"
DIST="exarch_fixture-0.1.0"
mkdir -p "$WHL_WORK/$DIST.dist-info" "$WHL_WORK/exarch_fixture"
cat > "$WHL_WORK/exarch_fixture/__init__.py" <<'EOF'
def hello() -> str:
    return "hello from exarch fixture"
EOF
cat > "$WHL_WORK/$DIST.dist-info/METADATA" <<'EOF'
Metadata-Version: 2.1
Name: exarch-fixture
Version: 0.1.0
Summary: Test fixture for exarch ZIP-family extraction
EOF
cat > "$WHL_WORK/$DIST.dist-info/WHEEL" <<'EOF'
Wheel-Version: 1.0
Generator: exarch-fixtures
Root-Is-Purelib: true
Tag: py3-none-any
EOF
# Build RECORD: path,sha256=BASE64URLNOPAD,size (one entry per file).
# The RECORD file itself appears with empty hash and size per spec.
record_file="$WHL_WORK/$DIST.dist-info/RECORD"
: > "$record_file"
while IFS= read -r -d '' file; do
    rel="${file#"$WHL_WORK/"}"
    size=$(stat -c%s "$file")
    sha_b64=$(sha256sum "$file" | cut -d' ' -f1 | xxd -r -p | base64 | tr -d '=' | tr '/+' '_-')
    printf '%s,sha256=%s,%s\n' "$rel" "$sha_b64" "$size" >> "$record_file"
done < <(find "$WHL_WORK" -type f ! -name RECORD -print0)
printf '%s/RECORD,,\n' "$DIST.dist-info" >> "$record_file"
(cd "$WHL_WORK" && zip -qr "$FIXTURES_DIR/simple.whl" .)
echo "✓ Created simple.whl (PEP 427 layout with RECORD)"

# -----------------------------------------------------------------------------
# 4. simple.epub
# -----------------------------------------------------------------------------
# EPUB is the interesting one: the spec requires mimetype to be the FIRST
# entry and STORED (no deflate). `zip -0 -X` writes stored without extra
# fields; then we append everything else normally. A reader that can't
# cope with stored-first + deflated-rest would trip on this.
EPUB_WORK="$TEMP_DIR/epub"
mkdir -p "$EPUB_WORK/META-INF" "$EPUB_WORK/OEBPS"
printf 'application/epub+zip' > "$EPUB_WORK/mimetype"
cat > "$EPUB_WORK/META-INF/container.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>
EOF
cat > "$EPUB_WORK/OEBPS/content.opf" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<package version="3.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="bookid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="bookid">exarch-fixture</dc:identifier>
    <dc:title>Exarch Fixture</dc:title>
    <dc:language>en</dc:language>
  </metadata>
  <manifest>
    <item id="ch1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine>
    <itemref idref="ch1"/>
  </spine>
</package>
EOF
cat > "$EPUB_WORK/OEBPS/chapter1.xhtml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Chapter 1</title></head>
<body><p>Hello from the exarch EPUB fixture.</p></body>
</html>
EOF
# Step 1: mimetype, stored (no compression), no extra fields.
# The global cleanup at the top of the script already removed the file.
(cd "$EPUB_WORK" && zip -q0X "$FIXTURES_DIR/simple.epub" mimetype)
# Step 2: rest of the book, deflated as normal.
(cd "$EPUB_WORK" && zip -qr "$FIXTURES_DIR/simple.epub" META-INF OEBPS)
echo "✓ Created simple.epub (mimetype STORED as first entry)"

# -----------------------------------------------------------------------------
# 5. simple.vsix
# -----------------------------------------------------------------------------
# VSIX is an OPC package (same family as .docx). Needs
# extension.vsixmanifest and [Content_Types].xml at the root.
VSIX_WORK="$TEMP_DIR/vsix"
mkdir -p "$VSIX_WORK/extension"
cat > "$VSIX_WORK/extension.vsixmanifest" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="exarch.fixture" Version="0.0.1" Publisher="exarch"/>
    <DisplayName>Exarch Fixture</DisplayName>
    <Description>Test fixture</Description>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
  </Assets>
</PackageManifest>
EOF
cat > "$VSIX_WORK/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
</Types>
EOF
cat > "$VSIX_WORK/extension/package.json" <<'EOF'
{"name": "exarch-fixture", "version": "0.0.1", "publisher": "exarch"}
EOF
(cd "$VSIX_WORK" && zip -qr "$FIXTURES_DIR/simple.vsix" .)
echo "✓ Created simple.vsix"

echo ""
echo "All ZIP-family fixtures generated in $FIXTURES_DIR"
echo "These cover the main shape variations: plain JAR, APK layout,"
echo "wheel with dist-info/RECORD, EPUB with stored mimetype, VSIX/OPC."
