# File Security Inspector — Basic

A Java desktop and command-line tool for inspecting one local file without executing it. Built as a cybersecurity learning project by Joseph Rabuffetti.

## What v1 does

- Select a file through a desktop file chooser, or pass its path on the command line.
- Calculate its SHA-256 fingerprint.
- Recognize a small set of leading file signatures and compare them with the extension.
- Display readable source/text with line numbers.
- Flag references to process launching, dynamic execution, encoding, networking, and persistence mechanisms.
- Show findings with explanations and export a plain-text report.

All inspection is local. There is no network connection, file upload, external dependency, or execution of the selected file. An indicator is a reason to review context, not a malware verdict. A result with no findings is **not proof that a file is safe**.

## Requirements

Use a **JDK 21** to build; Java 21 or newer to run. The graphical interface requires a desktop environment. No Maven, Gradle, or third-party libraries are required.

Check `java -version` and `javac -version`. If Java 8 is selected, set `JAVA_HOME` to a newer JDK and use its `bin/java` executable.

## Build and test

Windows PowerShell, from this folder:

```powershell
.\build.ps1
```

Linux/macOS:

```sh
sh build.sh
```

Both scripts compile the source, run the regression tests, and create `dist/file-security-inspector.jar`.

## Run

Desktop interface:

```sh
java -jar dist/file-security-inspector.jar
```

Command-line report:

```sh
java -jar dist/file-security-inspector.jar --scan samples/review-example.txt
java -jar dist/file-security-inspector.jar --scan samples/ordinary.txt
```

Use `--help` for usage. Exit codes: `0` means inspection completed, including when findings exist; `1` means inspection failed; `2` means invalid arguments. Exit `0` never means a file is guaranteed safe.

In the desktop app, select **Choose file & inspect**, read **Findings & fingerprint**, then view **Readable contents**. **Save report** writes the displayed report to a location you choose; existing files require confirmation before replacement.

## Supported content and boundaries

Files must be regular files no larger than **20 MiB**. Symbolic links and directories are rejected. Reads are bounded even if the selected file grows. A before/after metadata check rejects detected changes during inspection; it cannot guarantee consistency against an adversary modifying a file concurrently. Inspect a stable copy.

Signature recognition covers MZ executable candidates, ELF, ZIP, PDF, PNG, JPEG, GZIP, and CAFEBABE. Signatures are hints, not structural validation: they can be spoofed, and CAFEBABE has other uses. ZIP-based extensions such as JAR and DOCX are recognized as compatible containers; their contents are **not opened or inspected**.

Text inspection accepts valid UTF-8 (with or without BOM) and BOM-marked UTF-16, up to **1 MiB**. It rejects unsupported control characters. Recognized binary signatures bypass text inspection. Compiled programs are not converted into source code. Unknown or unsupported content is explicitly reported as uninspected.

Rules are case-insensitive, line-based heuristics. Comments and documentation can trigger findings. Multiline expressions, obfuscation, unknown APIs, malicious logic, and indirect behavior can evade them. Reports stop at **200 findings** and disclose when the remaining lines were not checked. There is no confidence score or "safe" badge.

The source viewer escapes invisible formatting characters to make them visible. Findings and source are shown as plain text, never rendered as HTML or executed.

## Testing

The included dependency-free test runner checks hashing against a known vector, line numbers and rule categories, binary/type mismatches, encoding behavior, resource limits, report limitations, and preservation of input bytes. The sample files are inert text; no live malware is included.

## Repository layout

```text
src/main/java/inspector/Inspector.java  inspection engine and report
src/main/java/inspector/Main.java       desktop interface and CLI
src/test/java/inspector/InspectorTest.java
samples/                              inert demonstration inputs
build.ps1 / build.sh                   build, tests, packaging
.github/workflows/test.yml             GitHub test workflow
```

## Future scope (not implemented)

Version 2 may add archive inspection and antivirus integration. Advanced work may add decompilation or isolated behavioral analysis. None of these capabilities is claimed by this basic release.
