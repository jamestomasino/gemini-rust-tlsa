# Gemini Rust TLSA

This is a proof of concept Gemini client written in Rust. It attempts to check
the server for a TLSA/DANE record and will verify that first. If there is no
such record we fall back on TOFU. TOFU certs are saved locally to check against
in the future.

The client does little in the way of rendering and doesn't allow for any
navigation. It simply takes a Gemini URL as a command line parameter and
performs the fetch of that resource.

It also handles the response as a stream and does not wait for a TLS close
before processing data line-by-line.


## Use

```bash
cargo run cosmic.voyage
```
or

```bash
cargo run gemini://cosmic.voyage
```

## The future

My hope for this project is to illustrate to other client authors that it's
a viable model for cert validation. The more clients that use it, the more we
can encourage gemini server maintainers to implement TLSA on their domains. We
can move beyond TOFU and its criticisms over time.
