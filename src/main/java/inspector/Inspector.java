package inspector;

import java.io.*;
import java.nio.*;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.util.*;
import java.util.regex.Pattern;

/** Local, static inspection only. No input is executed or uploaded. */
public final class Inspector {
    public static final int MAX_FILE_BYTES = 20 * 1024 * 1024;
    public static final int MAX_TEXT_BYTES = 1024 * 1024;
    private static final int MAX_FINDINGS = 200;
    public record Finding(String level, String rule, int line, String explanation) {}
    public record Result(String name, long size, String type, String sha256,
                         String source, List<Finding> findings, List<String> limitations) {
        public String report() {
            StringBuilder out = new StringBuilder("FILE SECURITY INSPECTOR - BASIC v1.0.0\n\n");
            out.append("File: ").append(safe(name).replace("\n", "\\n").replace("\t", "\\t")).append("\nSize: ").append(size)
               .append(" bytes\nDetected type: ").append(type).append("\nSHA-256: ").append(sha256).append("\n\n");
            out.append("Checks performed: file signature recognition, extension comparison, SHA-256 fingerprint.\n");
            out.append(source == null ? "Readable-text pattern checks: NOT PERFORMED.\n" : "Readable-text pattern checks: performed, subject to the finding limit described below.\n");
            out.append("\n").append(findings.isEmpty()
                ? "No suspicious indicators detected by the checks performed. This is not a safety guarantee.\n"
                : "Indicators found: " + findings.size() + ". Review the context; indicators do not prove malware.\n");
            for (Finding f : findings) out.append("\n[").append(f.level()).append("] ").append(f.rule())
                .append(f.line() > 0 ? " - line " + f.line() : "").append("\n").append(f.explanation()).append("\n");
            out.append("\nLIMITATIONS\n");
            for (String note : limitations) out.append("- ").append(note).append("\n");
            out.append("- No antivirus signatures, reputation lookup, decompilation, archive inspection, or behavior analysis.\n")
               .append("- Remote server code, encrypted content, and hidden or obfuscated behavior may not be visible.\n")
               .append("- A SHA-256 fingerprint identifies these bytes; it does not establish trust.\n");
            return out.toString();
        }
    }
    private record Rule(String id, String level, Pattern pattern, String explanation) {}
    private static Rule rule(String id, String level, String regex, String explanation) {
        return new Rule(id, level, Pattern.compile(regex, Pattern.CASE_INSENSITIVE), explanation);
    }
    private static final List<Rule> RULES = List.of(
        rule("PROCESS_LAUNCH", "REVIEW", "Runtime\\s*\\.\\s*getRuntime|ProcessBuilder\\s*\\(|subprocess\\s*\\.|os\\s*\\.\\s*system\\s*\\(|child_process|Start-Process|Invoke-Expression|\\bIEX\\b", "A process-launch or command-evaluation API is referenced. Legitimate tools also use these APIs."),
        rule("DYNAMIC_CODE", "REVIEW", "\\b(?:eval|exec)\\s*\\(|new\\s+Function\\s*\\(", "Dynamic code execution is referenced. Check where its input comes from."),
        rule("ENCODED_CONTENT", "REVIEW", "base64|FromBase64String|EncodedCommand|\\batob\\s*\\(", "Encoding or decoding is referenced. Encoding is common in legitimate software and does not itself indicate malware."),
        rule("NETWORK_REFERENCE", "INFO", "https?://|\\b(?:requests|urllib)\\s*\\.|\\bfetch\\s*\\(|HttpClient|\\bSocket\\s*\\(", "A network address or networking API is referenced. Inspect the destination and any data sent."),
        rule("PERSISTENCE_REFERENCE", "REVIEW", "CurrentVersion[\\\\/]+Run\\b|\\bschtasks\\b|\\bcrontab\\b|\\.config/autostart", "A startup or scheduled-task mechanism is referenced. Review whether persistence is intended.")
    );

    public static Result inspect(Path path) throws IOException {
        BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile()) throw new IOException("Select a regular file. Directories and symbolic links are not supported.");
        if (before.size() > MAX_FILE_BYTES) throw new IOException("Basic v1 supports files up to 20 MiB.");
        byte[] bytes;
        // Bound the actual read too: a file can grow after the size check.
        try (SeekableByteChannel channel = Files.newByteChannel(path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
             InputStream input = java.nio.channels.Channels.newInputStream(channel)) {
            bytes = input.readNBytes(MAX_FILE_BYTES + 1);
        }
        if (bytes.length > MAX_FILE_BYTES) throw new IOException("File exceeded the 20 MiB limit while reading.");
        BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!after.isRegularFile() || before.size() != after.size() || bytes.length != after.size()
            || !before.lastModifiedTime().equals(after.lastModifiedTime()) || !Objects.equals(before.fileKey(), after.fileKey()))
            throw new IOException("The file changed during inspection. Try again after it stops changing.");
        return inspectBytes(path.getFileName().toString(), bytes);
    }

    static Result inspectBytes(String name, byte[] bytes) {
        String type = signature(bytes);
        List<String> limitations = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();
        String source = null;
        if (type.equals("Unrecognized")) {
            if (bytes.length <= MAX_TEXT_BYTES) source = decodeText(bytes);
            if (source != null) type = "Readable text (language not verified)";
        }
        if (source == null) limitations.add(bytes.length > MAX_TEXT_BYTES
            ? "Readable-text inspection was skipped: file exceeds the 1 MiB text limit or has a binary signature."
            : "No readable source inspected. Binary or unsupported text content is not evidence of safety.");
        else limitations.add("Pattern checks are line-based heuristics, not a language parser. Comments and examples can trigger findings; multiline or disguised code can evade them.");
        String extension = extension(name);
        Set<String> allowed = extensionsFor(type);
        if (allowed != null && !allowed.contains(extension)) findings.add(new Finding("REVIEW", "TYPE_EXTENSION_MISMATCH", 0,
            "The recognized file signature does not match the filename extension. Verify the file's origin and intended format."));
        if (type.startsWith("Readable") && Set.of("exe", "dll", "pdf", "png", "jpg", "jpeg", "zip", "jar", "class", "gz").contains(extension))
            findings.add(new Finding("REVIEW", "TYPE_EXTENSION_MISMATCH", 0, "Readable text was found where the extension suggests a binary format."));
        if (source != null) {
            String[] lines = source.split("\\R", -1);
            boolean capped = false;
            outer: for (int i = 0; i < lines.length; i++) for (Rule rule : RULES) {
                if (rule.pattern().matcher(lines[i]).find()) {
                    if (findings.size() >= MAX_FINDINGS) { capped = true; break outer; }
                    findings.add(new Finding(rule.level(), rule.id(), i + 1, rule.explanation()));
                }
            }
            if (capped) limitations.add("The report reached its 200-finding limit. Additional lines were not checked.");
        }
        String hash;
        try { hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
        return new Result(name, bytes.length, type, hash, source, List.copyOf(findings), List.copyOf(limitations));
    }

    private static String extension(String name) {
        int dot = name.lastIndexOf('.');
        return dot < 0 ? "" : name.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
    private static Set<String> extensionsFor(String type) {
        return switch (type) {
            case "Windows executable candidate (MZ)" -> Set.of("exe", "dll", "sys", "scr", "com");
            case "ELF binary" -> Set.of("", "elf", "so", "bin", "out");
            case "ZIP container" -> Set.of("zip", "jar", "war", "ear", "apk", "docx", "xlsx", "pptx", "odt", "ods", "epub");
            case "PDF document" -> Set.of("pdf"); case "PNG image" -> Set.of("png");
            case "JPEG image" -> Set.of("jpg", "jpeg"); case "GZIP container" -> Set.of("gz", "tgz");
            case "Java class / CAFEBABE signature" -> Set.of("class"); default -> null;
        };
    }
    private static boolean starts(byte[] b, int... signature) {
        if (b.length < signature.length) return false;
        for (int i = 0; i < signature.length; i++) if ((b[i] & 255) != signature[i]) return false;
        return true;
    }
    private static String signature(byte[] b) {
        if (starts(b, 0x4d, 0x5a)) return "Windows executable candidate (MZ)";
        if (starts(b, 0x7f, 0x45, 0x4c, 0x46)) return "ELF binary";
        if (starts(b, 0x50, 0x4b, 3, 4) || starts(b, 0x50, 0x4b, 5, 6) || starts(b, 0x50, 0x4b, 7, 8)) return "ZIP container";
        if (starts(b, 0x25, 0x50, 0x44, 0x46, 0x2d)) return "PDF document";
        if (starts(b, 0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10)) return "PNG image";
        if (starts(b, 0xff, 0xd8, 0xff)) return "JPEG image";
        if (starts(b, 0x1f, 0x8b)) return "GZIP container";
        if (starts(b, 0xca, 0xfe, 0xba, 0xbe)) return "Java class / CAFEBABE signature";
        return "Unrecognized";
    }
    private static String decodeText(byte[] b) {
        Charset charset = StandardCharsets.UTF_8;
        int offset = 0;
        if (starts(b, 0xff, 0xfe)) { charset = StandardCharsets.UTF_16LE; offset = 2; }
        else if (starts(b, 0xfe, 0xff)) { charset = StandardCharsets.UTF_16BE; offset = 2; }
        else if (starts(b, 0xef, 0xbb, 0xbf)) offset = 3;
        try {
            String text = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b, offset, b.length - offset)).toString();
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isISOControl(c) && c != '\n' && c != '\r' && c != '\t') return null;
            }
            return text;
        } catch (CharacterCodingException e) { return null; }
    }
    /** Escape invisible formatting characters so filenames and source cannot visually spoof the report. */
    public static String safe(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((Character.isISOControl(c) && c != '\n' && c != '\t') || Character.getType(c) == Character.FORMAT)
                out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.toString();
    }
}

