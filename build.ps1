$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
Push-Location $projectRoot
try {
    $compiler = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/javac.exe' } else { 'javac' }
    $runtime = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { 'java' }
    $archiver = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/jar.exe' } else { 'jar' }
    New-Item -ItemType Directory -Force build/classes,build/test-classes,dist | Out-Null
    & $compiler -source 21 -target 21 -encoding UTF-8 -d build/classes src/main/java/inspector/Inspector.java src/main/java/inspector/Main.java
    if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }
    & $compiler -source 21 -target 21 -encoding UTF-8 -d build/test-classes src/main/java/inspector/Inspector.java src/test/java/inspector/InspectorTest.java
    if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed.' }
    & $runtime -cp 'build/test-classes' inspector.InspectorTest
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    & $archiver --create --file dist/file-security-inspector.jar --main-class inspector.Main -C build/classes .
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed.' }
    Write-Host 'Ready: dist/file-security-inspector.jar'
} finally { Pop-Location }
