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

## Relay handshake model

The redacted capture confirms this command sequence on separate TCP/8800
connections:

    1167 authentication request -> 1168 authentication response
    301 stream login -> 401 stream-login response
    303 stream start -> 0x7f-framed media/control traffic

These identifiers match the older community implementation, but the relay
transport and newer response behavior still need to be reproduced carefully.
The public client exposes these identifiers as constants without embedding any
device credentials or captured payloads.

The relay capture also shows an extended 520-byte authentication request: the
device domain begins at offset 17, while the username and encrypted password
begin at offsets 71 and 103. This differs from the shorter LAN-oriented
layout in older clients and explains why blindly reusing that layout failed.

With the relay layout, an authorized probe completed authentication with
result `1001` and negotiated stream status `4`. The first bytes after stream
start begin with `0x1f`, matching the outer stream header seen in the capture;
the inner `0x7f` media envelopes follow it.

The client now validates that fixed 12-byte outer prefix and parses the inner
envelopes incrementally without interpreting or logging their payloads. Live
traffic currently contains several envelope types, but no standard JPEG or
Annex-B video signature has been established; the payload may be encrypted or
require an additional multiplexing layer.

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
