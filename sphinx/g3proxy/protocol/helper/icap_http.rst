.. _protocol_helper_icap_http:

=============
ICAP for HTTP
=============

g3proxy support to enable ICAP reqmod and respmod services for HTTP 1.x request and response.

The following headers will be added in the ICAP request header:

- X-Transformed-From

  For requests (REQMOD), the value is **HTTP** or **HTTPS**, telling whether the
  client side of this request was carried over TLS.

  For responses (RESPMOD), the value is still **HTTP/1.0**.

  .. versionchanged:: 1.13.0 REQMOD reports the scheme instead of the protocol version

- X-Http-Version

  For requests (REQMOD) only. The value is **1.0** or **1.1**, the protocol version
  the client actually spoke; the version is no longer carried by *X-Transformed-From*.

  .. versionadded:: 1.13.0

- X-Body-Framing

  Only for the upload audit submissions (the ones that copy the request body aside
  while forwarding it). The value is **content-length**, **chunked** or **stream**,
  telling how the client framed its body.

  .. versionadded:: 1.13.0

- X-HTTP-Upgrade

  The Upgrade header in request will be converted to X-HTTP-Upgrade header in ICAP request with the same value.
