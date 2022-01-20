# smtpbis

[![crates.io](http://meritbadge.herokuapp.com/smtpbis)](https://crates.io/crates/smtpbis)

Extensible SMTP server library

Built on top of [rustyknife] and [tokio] for native performance.

The ESMTP extensions that affect the socket layer are directly
implemented in the base server. Extensions such as DSN that merely
attributes are implemented via the Handler interface.

Features:
* SMTPUTF8 support
* CHUNKING support
* Pluggable STARTTLS support

[rustyknife]: https://crates.io/crates/rustyknife
[tokio]: https://tokio.rs/

## Usage

```
cargo run --example smtpbis-server
```