# Decoder boundary notes

These notes describe observations from the locally installed, user-authorized
V380 client. They intentionally omit captured bytes, credentials, addresses,
and vendor binaries.

## Confirmed runtime path

The official client reached `mi_h265decoder_decodeframe` in
`libmi_decoder.dll`; the H.264 export did not receive a hit during the same
live-view session. The client therefore uses H.265 for this camera/session.

## Static ABI shape

Disassembly of the exported 32-bit function shows three stack arguments:

```text
mi_h265decoder_decodeframe(
    decoder_context*,
    input_packet*,
    output_frame*
)
```

The input packet is accessed as:

```text
struct InputPacket {
    const void *data;
    int         size;
};
```

The function reads the input pointer and length before passing them to the
internal HEVC decoder. The third argument is written with status and decoded
frame metadata. Exact field meanings still require one controlled runtime
observation or further static tracing.

## Next safe experiment

At the confirmed breakpoint, record only the argument values and a small
bounded view of the input buffer privately. Do not publish memory dumps: the
buffer contains camera media and may be accompanied by session material. The
public client should eventually receive already-separated H.265 access units,
then decode them with a normal open codec rather than copying vendor code.

Snapshot acceptance remains unchanged: produce and verify an actual image
from an authorized camera before claiming snapshot support.
