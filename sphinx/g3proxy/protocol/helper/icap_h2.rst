.. _protocol_helper_icap_h2:

===========
ICAP for H2
===========

g3proxy support to enable ICAP reqmod and respmod services for H2 request and response.

The H2 request and response is convert to HTTP/1.1 first, and then send to ICAP server.
And the response from the ICAP server will be convert back to H2.

The following headers will be added in the ICAP request header:

- X-Transformed-From

  For requests (REQMOD), the value is **HTTP** or **HTTPS**, telling whether the
  client side of this request was carried over TLS.

  For responses (RESPMOD), the value is still **HTTP/2.0**.

  .. versionchanged:: 1.13.0 REQMOD reports the scheme instead of the protocol version

- X-Http-Version

  For requests (REQMOD) only. The value is **2.0**, the protocol version the
  client actually spoke; the version is no longer carried by *X-Transformed-From*.

  .. versionadded:: 1.13.0

- X-Body-Framing

  Only for the upload audit submissions (the ones that copy the request body aside
  while forwarding it). The value is **content-length** or **stream**, telling
  whether the h2 request carried a *content-length* pseudo-declared body.

  .. versionadded:: 1.13.0

- X-HTTP-Upgrade

  The value will be the Protocol value set in Extended CONNECT request.
