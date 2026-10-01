#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ -n "${JAVA_HOME:-}" ]; then PATH="$JAVA_HOME/bin:$PATH"; export PATH; fi
mkdir -p build/classes build/test-classes dist
javac -source 21 -target 21 -encoding UTF-8 -d build/classes src/main/java/inspector/Inspector.java src/main/java/inspector/Main.java
javac -source 21 -target 21 -encoding UTF-8 -d build/test-classes src/main/java/inspector/Inspector.java src/test/java/inspector/InspectorTest.java
java -cp 'build/test-classes' inspector.InspectorTest
jar --create --file dist/file-security-inspector.jar --main-class inspector.Main -C build/classes .
printf 'Ready: dist/file-security-inspector.jar\n'
