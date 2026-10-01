# QUIC HTTP/3 Application Boundary

The `elixir_quic_http3` application and its `QuicHttp3` modules now live in
[`gsmlg-dev/ex_quic`](https://github.com/gsmlg-dev/ex_quic/tree/main/apps/elixir_quic_http3).
This repository no longer contains or declares a dependency on that app.

HTTP/3 and WebTransport remain separate application protocols above QUIC.
Moving the app does not enable either feature here: the HTTP/3 and QUIC
WebTransport selectors continue to return explicit unsupported results until
independent integration and interoperability work is complete.
