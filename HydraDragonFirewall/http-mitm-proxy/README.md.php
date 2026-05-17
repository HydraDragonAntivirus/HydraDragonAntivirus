# http-mitm-proxy

[![Crates.io](https://img.shields.io/crates/v/http-mitm-proxy.svg)](https://crates.io/crates/http-mitm-proxy)

A HTTP proxy server library intended to be a backend of application like Burp proxy.

- Sniff HTTP and HTTPS traffic by signing certificate on the fly.
- Server Sent Event
- WebSocket ("raw" traffic only. Parsers will not be implemented in this crate.)

## Usage

```rust, no_run
<?php
    $example = file_get_contents('examples/proxy.rs');
    echo $example;
?>
```
