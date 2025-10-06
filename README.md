# go-skipverify

This tool is intended to patch Go binaries to bypass SSL verification and is based on CyberArk's blog post (https://www.cyberark.com/resources/threat-research-blog/how-to-bypass-golang-ssl-verification). I started with their python example and converted it to Go. I also added patches for newer versions of Go.

## Overview

To identify a patch perform the following steps:

1. Compile the binary with debug symbols using the version of Go and architecture you want to find a patch for

2. Look at the source code for the "verifyServerCertificate" function in the specific Go version (https://github.com/golang/go/blob/master/src/crypto/tls/handshake_client.go)

![](assets/go-verifyservercertificate-code.png)

3. Load the compiled binary in Ghidra (or other decompiler)
4. Find the "verifyServerCertificate" function and identify the code to patch out

![](assets/go-verifyservercertificate-ghidra.png)

## Install Specific Go Version

You can use Go to install other versions of Go using the example below.

```bash
# Install go1.24.1
go install golang.org/dl/go1.24.1@latest

# Then you need to download it
go1.24.1 download

# Check version
go1.24.1 version
go version go1.24.1 darwin/arm64

# Then compile like normal
```

## Usage

You can test the patch by performing the following steps:

1. Compile the example code

```bash
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o go-skipverify-example-Darwin64 main.go
```

2. Test the binary by providing a proxy via environment variables. You can see it cannot verify the certificate.

```bash
HTTPS_PROXY=http://127.0.0.1:8080 ./example/go-skipverify-example-Darwin64
2025/10/05 13:13:31 Get "https://ipinfo.io/": tls: failed to verify certificate: x509: certificate signed by unknown authority
```

3. Patch the binary using the Go or python program.

```bash
./go-skipverify -in example/go-skipverify-example-Darwin64 -out example/go-skipverify-example-Darwin64-patched
Go version: go1.25.1
Major Go version: 1.25
File: example/go-skipverify-example-Darwin64
OS: macOS
Arch: AMD64
Patching for version: 1.25
Successfully patched and saved to: example/go-skipverify-example-Darwin64-patched
```

4. Run the patched binary and see it accept the certificate

```bash
HTTPS_PROXY=http://127.0.0.1:8080 ./example/go-skipverify-example-Darwin64-patched
2025/10/05 13:14:01 {
  "ip": "xx.xx.xx.xx",
  "city": "CITY",
  "region": "STATE",
  "country": "US",
  "loc": "xx.xxxx,-xx.xxxx",
  "org": "ISP COMPANY NAME",
  "postal": "12345",
  "timezone": "America/Chicago",
  "readme": "https://ipinfo.io/missingauth"
}
```

Only supply the "-in" flag if you only want to check if the binary was compiled with Go and which version.

```bash
./go-skipverify -in example/go-skipverify-example
Go version: go1.24.1
Major Go version: 1.24
File: example/go-skipverify-example
OS: macOS
Arch: ARM64
```

## macOS ARM64

If you are patching a macOS binary it may be killed when trying to run it. It is probably based on the following:

- All system and App Store binaries — and many Go binaries — are code signed.
- When you edit any byte of a signed section, the signature hash no longer matches.
- macOS will silently kill the process at launch — no stack trace, no crash report.

You can check the code signature using the following command:

```bash
codesign --verify --verbose example/go-skipverify-example-patched
example/go-skipverify-example-patched: invalid signature (code or signature have been modified)
In architecture: arm64
```

You can sign the patched binary using the following command:

```bash
codesign --force --sign - example/go-skipverify-example-patched
example/go-skipverify-example-patched: replacing existing signature
```


# References

- [CyberArk - How to Bypass Golang SSL Verification](https://www.cyberark.com/resources/threat-research-blog/how-to-bypass-golang-ssl-verification)
