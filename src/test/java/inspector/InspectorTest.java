package inspector;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;

/** Dependency-free regression tests. All fixtures are inert bytes/text. */
public final class InspectorTest {
    private static int tests;
    private static void check(boolean condition, String name) {
        if (!condition) throw new AssertionError(name);
        System.out.println("PASS " + name); tests++;
    }
    private static Inspector.Result text(String value) {
        return Inspector.inspectBytes("sample.txt", value.getBytes(StandardCharsets.UTF_8));
    }
    public static void main(String[] args) throws Exception {
        check(text("abc").sha256().equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "known SHA-256 vector");
        check(text("Hello, world!").findings().isEmpty(), "ordinary text has no findings");
        check(text("").source().equals(""), "empty file is readable");
        check(text("// example\nnew ProcessBuilder(\"example\");").findings().stream().anyMatch(f -> f.rule().equals("PROCESS_LAUNCH") && f.line() == 2), "process rule and line number");
        check(text("eval(value)\nbase64\nhttps://example.invalid\ncrontab").findings().size() == 4, "all other pattern categories");
        check(text("# eval(example)").findings().size() == 1, "comments intentionally trigger context review");
        Inspector.Result disguised = Inspector.inspectBytes("photo.jpg", new byte[]{0x4d, 0x5a, 0, 1});
        check(disguised.findings().stream().anyMatch(f -> f.rule().equals("TYPE_EXTENSION_MISMATCH")), "disguised executable signature");
        check(disguised.source() == null, "recognized binary is not treated as source");
        check(Inspector.inspectBytes("app.jar", new byte[]{0x50,0x4b,3,4}).findings().isEmpty(), "JAR is compatible with ZIP signature");
        check(Inspector.inspectBytes("unknown.dat", new byte[]{(byte)0xc3,0x28}).source() == null, "malformed UTF-8 rejected");
        check(Inspector.inspectBytes("binary.dat", new byte[]{0, 1, 2}).source() == null, "control-character binary rejected");
        check(Inspector.inspectBytes("source.txt", new byte[]{(byte)0xff,(byte)0xfe,65,0}).source().equals("A"), "UTF-16 BOM text decoded");
        byte[] large = new byte[Inspector.MAX_TEXT_BYTES + 1]; Arrays.fill(large, (byte)'a');
        check(Inspector.inspectBytes("large.txt", large).source() == null, "text limit skips content checks explicitly");
        check(text("eval(x)\n".repeat(250)).findings().size() == 200, "finding count bounded");
        check(text("eval(x)\n".repeat(250)).report().contains("Additional lines were not checked"), "capped scan disclosed");
        check(Inspector.safe("abc\u202etxt").equals("abc\\u202etxt"), "bidirectional control escaped");
        check(disguised.report().contains("NOT PERFORMED"), "binary report discloses skipped source checks");
        Path directory = Files.createTempDirectory("inspector-tests-");
        Path fixture = directory.resolve("fixture.txt");
        try {
            Files.writeString(fixture, "abc");
            byte[] original = Files.readAllBytes(fixture);
            check(Inspector.inspect(fixture).sha256().equals(text("abc").sha256()), "file inspection equals byte inspection");
            check(Arrays.equals(original, Files.readAllBytes(fixture)), "inspection leaves input unchanged");
            boolean rejected = false;
            try { Inspector.inspect(directory); } catch (java.io.IOException expected) { rejected = true; }
            check(rejected, "directories rejected");
            try (var file = new java.io.RandomAccessFile(fixture.toFile(), "rw")) { file.setLength(Inspector.MAX_FILE_BYTES + 1L); }
            rejected = false;
            try { Inspector.inspect(fixture); } catch (java.io.IOException expected) { rejected = true; }
            check(rejected, "oversize file rejected");
        } finally { Files.deleteIfExists(fixture); Files.deleteIfExists(directory); }
        System.out.println("\n" + tests + " tests passed.");
    }
}
