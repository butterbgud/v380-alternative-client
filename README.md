# Open V380 client research

Tools and documentation for interoperating with V380-compatible cameras that
you own or are authorized to test.

This is an early research project, not a finished camera client. The current
goal is to document protocol variants and build a safe, open implementation
for live view and snapshots. The observed official Windows client used a
relay-mediated TCP/8800 session even while displaying a local camera address.

## Privacy and authorization

Only analyze cameras and traffic you are authorized to access. Do not commit
packet captures, credentials, vendor executables, or session tokens. The Git
ignore rules intentionally exclude these artifacts. Redact device IDs and
public endpoints in issues unless the owner has explicitly approved sharing
them.

## Current status

- Older community clients provide useful packet-structure references.
- A newer camera variant returned a stream-handshake compatibility error to
  the old client.
- The official app's captured session used a relay and emitted V380-style
  framed stream data.
- Snapshot retrieval is not implemented yet.

## Capture analysis

The dependency-free analyzer reports safe metadata without dumping payloads:

    python3 tools/pcap_summary.py path/to/your-capture.pcapng
    python3 tools/pcap_v380_frames.py path/to/your-capture.pcapng

See `docs/protocol-analysis.md` for the current public findings and `PLAN.md`
for the roadmap.

## Development

The first protocol library parses only the V380 stream envelope; it does not
decrypt or save media. Run its tests with:

    python3 -m unittest discover -v

The experimental probe is opt-in and prompts for the password without echoing
or saving it. It performs authentication and stream negotiation only:

    python3 tools/v380_probe.py --host HOST --device-id ID --domain DOMAIN --username USER

Use it only with a camera and relay you are authorized to test. It does not
send PTZ or other movement commands.

## License

MIT. See `LICENSE`.
