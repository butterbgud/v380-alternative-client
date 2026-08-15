# Build an open V380-compatible client

This ExecPlan is a living document and follows the workspace guidance in
`../PLANS.md`. It records how to turn the current V380 investigation into a
public, safe, open-source project without publishing credentials, captures, or
vendor binaries.

## Purpose / Big Picture

The project should let owners of compatible V380 cameras inspect their own
traffic and eventually view a camera, take snapshots, and control supported
functions without the official application. The first public milestone is a
reproducible packet-analysis toolkit and protocol documentation. A working
client will follow only after the relay handshake and authentication behavior
are understood and tested against an authorized camera.

## Progress

- [x] (2026-08-15 20:55 Europe/Tallinn) Confirmed the supplied capture uses a relay at TCP/8800 rather than the displayed LAN address.
- [x] (2026-08-15 20:55 Europe/Tallinn) Defined public-repository safety boundaries: no credentials, proprietary executables, or private packet captures.
- [x] (2026-08-15 20:55 Europe/Tallinn) Added the initial public-safe repository structure and standard-library capture summary tool.
- [x] (2026-08-15 21:35 Europe/Tallinn) Added dependency-free incremental V380 frame parsing with tests for TCP chunk boundaries and malformed input.
- [x] (2026-08-15 21:37 Europe/Tallinn) Added TCP/8800 reassembly and capture-derived frame-envelope summary without payload output.
- [x] (2026-08-15 21:43 Europe/Tallinn) Confirmed and encoded the relay handshake sequence 1167 -> 1168, 301 -> 401, 303 -> framed media.
- [x] (2026-08-15 21:43 Europe/Tallinn) Added command-ID constants and tests without embedding credentials or payloads.
- [x] (2026-08-15 21:57 Europe/Tallinn) Built an opt-in read-only relay probe with password prompt, chunk-safe reads, and status-only output.
- [x] (2026-08-15 21:44 Europe/Tallinn) Added credential-safe handshake packet builders and response parsers; socket probing remains separate and opt-in.
- [x] (2026-08-15 21:58 Europe/Tallinn) Identified and corrected the relay-specific 520-byte authentication layout from the capture.
- [x] (2026-08-15 22:00 Europe/Tallinn) Ran the read-only probe against the observed relay; it reached the service and returned V380 auth result 1002, so transport/layout work, not connectivity, is now validated.
- [ ] Obtain or verify the camera/device password before retrying authentication; do not guess credentials.
- [ ] Add tests for broader pcapng packet parsing and capture-derived edge cases.
- [ ] Document the relay handshake using redacted packet excerpts.
- [ ] Implement a read-only handshake probe against an explicitly supplied camera endpoint.
- [ ] Capture and map snapshot and PTZ actions with user-controlled test captures.
- [ ] Implement authenticated viewing and snapshot retrieval.
- [ ] Publish to a GitHub repository after local review and license/repository-name confirmation.

## Surprises & Discoveries

- Observation: the official client displayed a LAN address, but the capture contained no packets to that address.
  Evidence: the app connected to a public relay on TCP/8800 and sent a device-domain hostname.
- Observation: the relay returned substantial TCP/8800 payloads, consistent with a video stream.
  Evidence: many inbound payloads use the legacy-looking `0x7f` frame marker and carry large payloads.
- Observation: the old open-source client is useful as a structural reference but does not complete this camera's stream handshake.
  Evidence: it receives compatibility response `-11` and encounters unknown command `0x9c`.

## Decision Log

- Decision: begin with a public-safe analysis toolkit instead of committing a packet capture or vendor executable.
  Rationale: captures may contain login/session material, and the official binary is not ours to redistribute.
  Date/Author: 2026-08-15 / Clop.
- Decision: use Python standard library for the first parser.
  Rationale: contributors can inspect capture metadata without downloading a dependency; richer dissectors can be added later.
  Date/Author: 2026-08-15 / Clop.
- Decision: treat relay support as the primary path and LAN support as an optional optimization.
  Rationale: the observed official session used the relay even though the UI displayed a LAN address.
  Date/Author: 2026-08-15 / Clop.

## Outcomes & Retrospective

At this milestone the project has a safe public shape and a reproducible way
to summarize endpoint and V380 framing evidence. It is not yet a client and
must not claim snapshot support until a snapshot is obtained from an
authorized camera.

## Context and Orientation

`references/` contains prior community implementations and is reference
material, not a promise that their older protocol works with every camera.
`tools/` contains dependency-free analysis utilities. `docs/` contains public
protocol notes. Private files such as `.pcapng`, `.exe`, credentials, and local
test output are ignored by Git.

## Plan of Work

First keep the repository harmless to publish: ignore private artifacts and
write a README explaining scope, authorization, and current limitations. Then
add a parser that reports only endpoints, ports, and safe frame statistics.
Next add fixtures made from synthetic packets rather than real credentials.
After the parser is tested, redact and document the relay handshake. Only then
should a client adapter be attempted, with read-only behavior first and a
separate opt-in layer for snapshots or controls.

## Concrete Steps

From `/home/clop/.openclaw/workspace/v380-re`, run:

    python3 tools/pcap_summary.py --help
    python3 tools/pcap_summary.py path/to/private-capture.pcapng

The tool must never print payload contents, usernames, passwords, or tokens.
It should report packet count, IPv4 endpoint pairs, TCP ports, and counts of
payloads beginning with the known V380 `0x7f` frame marker.

## Validation and Acceptance

The initial milestone is accepted when the tool runs with only Python 3,
parses a pcapng file without Wireshark installed, and emits endpoint/frame
statistics without exposing payload bytes. Unit tests must pass once added.
The client milestone is accepted only when an authorized camera produces a
real snapshot and the result is verified as an image, not merely a successful
TCP connection.

## Idempotence and Recovery

All initial files are additive. Private captures can be analyzed in place but
must remain ignored. If a future test accidentally writes sensitive output,
delete it from the working tree before committing and rotate any exposed
credential. Never use a broad recursive deletion command.

## Artifacts and Notes

The current private evidence is a local pcapng capture; it must not be
committed. The observed relay endpoint and device domain are documented in
the private diary, while public documentation uses placeholders.

## Interfaces and Dependencies

The first tool exposes a command-line interface:

    python3 tools/pcap_summary.py CAPTURE.pcapng

It uses only Python 3's `argparse`, `collections`, `ipaddress`, `socket`, and
`struct` modules. Later client code should isolate transport, packet framing,
authentication, and media extraction so protocol changes do not require
rewriting the whole application.

## Change Note

2026-08-15: created the initial plan and public-safe milestone after finding
that the official app used a relay rather than the displayed camera IP.
