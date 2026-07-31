# Incremental Vision ServerHello Classification

## Failure

Production workers accumulated in the blocking Vision bridge even though most
clients used modern browsers. Runtime phase instrumentation showed that genuine
TLS 1.2 was a small minority. The unexpected sessions were TLS connections for
which the client ClientHello was recognized but the server classification was
exhausted without enabling direct copy.

Modern TLS 1.3 ServerHello messages observed in the field carried large hybrid
key-share extensions. Representative record and handshake lengths were 1210
and 1206 bytes. The old classifier buffered at most 1024 bytes, rejected these
messages, and permanently disabled further inspection. The Xray server could
still switch its direction to direct copy, but the Zig client could not hand
the connection to the raw reactor until both directions were direct.

ClientHello inspection also counted socket reads rather than protocol data. A
fragmented prefix could consume the inspection budget before the ServerHello
arrived and end Vision padding too early.

## Fix

The classifier now streams the TLS record and ServerHello structure:

- TLS record and handshake headers are assembled across arbitrary reads.
- Session IDs and extension payloads are skipped incrementally.
- Only the selected cipher suite and `supported_versions` result are retained.
- ServerHello messages may span TLS records and may contain up to 64 KiB of
  handshake data without a matching allocation or stack buffer.
- ClientHello detection assembles its six-byte prefix before consuming one
  inspection attempt.

The deterministic regression builds a 1215-byte TLS 1.3 ServerHello containing
a 1156-byte extension and feeds it in seven-byte fragments. The delayed-preface
field regression continues to cover a fragmented ClientHello arriving after
the initial Vision padding timeout.
