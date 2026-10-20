import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Writes ZIP archives with java.util.zip.ZipOutputStream, the producer behind
 * most Java tooling (jar, Maven, Gradle). Usage: java ZipProducer.java OUT_DIR
 */
public class ZipProducer {
    public static void main(String[] args) throws IOException {
        Path out = Path.of(args[0]);
        byte[] text = "hello world ".repeat(500).getBytes(StandardCharsets.UTF_8);

        // DEFLATED entries are streamed: sizes and CRC follow in data descriptors.
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(out.resolve("java_deflated.zip")))) {
            zip.putNextEntry(new ZipEntry("dir/"));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("dir/a.txt"));
            zip.write(text);
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("empty"));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry("café.txt"));
            zip.write("unicode".getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            zip.setComment("PK\u0003\u0004 archive comment");
        }

        // STORED entries must declare size and CRC up front.
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(out.resolve("java_stored.zip")))) {
            zip.setLevel(0);
            for (String name : new String[] {"a.bin", "b.bin"}) {
                ZipEntry entry = new ZipEntry(name);
                CRC32 crc = new CRC32();
                crc.update(text);
                entry.setMethod(ZipEntry.STORED);
                entry.setSize(text.length);
                entry.setCompressedSize(text.length);
                entry.setCrc(crc.getValue());
                zip.putNextEntry(entry);
                zip.write(text);
                zip.closeEntry();
            }
        }
    }
}
