# Current protocol analysis

This document contains only redacted, public-safe findings. It deliberately
does not include credentials, packet payloads, device identifiers, or a raw
capture.

## Observed session

The official client used TCP port 8800 to reach a relay host selected for the
camera's device domain. The computer's local address was different from the
camera address shown in the application. No direct packets to the displayed
camera address appeared in the capture.

The session contained an authentication phase followed by a stream phase. The
older community implementation describes commands commonly associated with
these phases as authentication command 1167, stream login command 301, and
stream start command 303. The observed newer session should not be assumed to
accept those commands unchanged.

## Framing

The older implementation identifies a 12-byte stream header beginning with
`0x7f`. It carries a media/type byte, frame counters, and a payload length.
The captured relay stream contains the same broad marker pattern, followed by
large payloads. Payload contents are not documented here because they may be
encrypted or session-specific.

## What remains unknown

The relay handshake variant, authentication transformation, exact media codec
boundaries, snapshot command, and PTZ command behavior still need to be
validated. A successful TCP connection is not sufficient evidence of support;
the acceptance test is a verified image from an authorized camera.

## How to contribute evidence

Capture one action at a time, using a private Wireshark file: connect/live
view, snapshot, and PTZ. Record the approximate timestamp of each action and
share only a redacted summary or an approved private capture. Never publish
passwords, login tokens, or unrelated network traffic.
