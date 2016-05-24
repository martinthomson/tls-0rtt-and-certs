---
title: "Cipher Suites for Negotiating Zero Round Trip (0-RTT) Transport Layer Security (TLS) with Renewed Certificate Authentication"
abbrev: TLS 0-RTT Certificates
docname: draft-thomson-tls-0rtt-and-certs-latest
date: 2016
category: std
ipr: trust200902
updates: I-D.ietf-tls-tls13

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: martin.thomson@gmail.com


normative:
  RFC2119:
  RFC3447:
  RFC5116:
  RFC7539:
  I-D.ietf-tls-tls13:
  I-D.ietf-tls-cached-info:
  DH:
        title: "New Directions in Cryptography"
        author:
          - ins: W. Diffie
          - ins: M. Hellman
        date: 1977-06
        seriesinfo: IEEE Transactions on Information Theory, V.IT-22 n.6
  X962:
       title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
       date: 1998
       author:
         org: ANSI
       seriesinfo:
         ANSI: X9.62
  FIPS180-4:
    title: NIST FIPS 180-4, Secure Hash Standard
    author:
      name: NIST
      ins: National Institute of Standards and Technology, U.S. Department of Commerce
    date: 2012-03
    target: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf

informative:
  RFC0793:
  RFC5288:
  RFC7301:
  I-D.ietf-tls-chacha20-poly1305:


--- abstract

New cipher suites are defined that allow a client to use zero round trip (0-RTT)
with Transport Layer Security (TLS), while also enabling the peers to renewed
certificate-based authentication.


--- middle

# Introduction

Transport Layer Security version 1.3 (TLS 1.3) [I-D.ietf-tls-tls13] defines a
zero round trip (0-RTT) handshake mode for connections where client and server
have previously communicated.  In the two defined 0-RTT modes, keying material
from a previous connection is used as a pre-shared key.

A 0-RTT handshake can rely entirely on the pre-shared key.  These handshakes use
cipher suites denoted `TLS_PSK_WITH_*`.  Alternative modes use the pre-shared
key to authenticate the connection and secure any 0-RTT data, but then a fresh
ephemeral Diffie-Hellman (or elliptic curve Diffie-Hellman) key exchange is
performed.  These handshakes use cipher suites denoted `TLS_DHE_PSK_WITH_*` or
`TLS_ECDHE_PSK_WITH_*`.

Neither of the two 0-RTT handshake modes permits either client or server to send
the Certificate and CertificateVerify authentication messages.  Endpoints are
expected to store any authentication state with any resumption state.  This
means that endpoints are unable to update their understanding that a peer has
continuing access to authentication keys without choosing a one round trip
handshake mode and sacrificing any potential performance gained by 0-RTT.

This document defines a third mode for 0-RTT, where the pre-shared key is used
to authenticate and protect 0-RTT data only.  The remainder of the handshake is
identical to a regular one round trip handshake with the only difference being
that the resumption secret is mixed into the key schedule.  This allows peers to
provide fresh proof that they control authentication keys without losing the
latency advantages provided by the 0-RTT mode.


## Notational Conventions

The words "MUST", "MUST NOT", "SHOULD", and "MAY" are used in this document.
It's not shouting; when they are capitalized, they have the special meaning
defined in [RFC2119].


# New Cipher Suites

The following cipher suites are defined:

~~~
TLS_ECDHE_PSK_ECDSA_WITH_AES_128_GCM_SHA256 = 0xXXXX
TLS_ECDHE_PSK_RSA_WITH_AES_128_GCM_SHA256 = 0xXXXX
TLS_DHE_PSK_RSA_WITH_AES_128_GCM_SHA256 = 0xXXXX
TLS_ECDHE_PSK_ECDSA_WITH_AES_256_GCM_SHA384 = 0xXXXX
TLS_ECDHE_PSK_RSA_WITH_AES_256_GCM_SHA384 = 0xXXXX
TLS_DHE_PSK_RSA_WITH_AES_256_GCM_SHA384 = 0xXXXX
TLS_ECDHE_PSK_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xXXXX
TLS_ECDHE_PSK_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xXXXX
TLS_DHE_PSK_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xXXXX
~~~

All these cipher suites include the use of pre-shared keys and therefore permit
the use of 0-RTT.  These cipher suites can only be used with TLS 1.3.  All
include server authentication.  A server MAY request client authentication by
sending a CertificateRequest if it negotiates one of these cipher suites.

All the necessary cryptographic operations and the key schedule are as described
in [I-D.ietf-tls-tls13].

These cipher suites use a pre-shared key for 0-RTT data, with subsequent data
protected by both the PSK and an ephemeral key exchange using finite field or
elliptic curve Diffie-Hellman.  The pre-shared key forms the static secret (SS)
and the ephemeral key exchange produces the ephemeral secret (ES).  DHE_PSK_RSA
suites use finite field Diffie-Hellman key exchange [DH]; ECDHE_PSK_ECDSA and
ECDHE_PSK_RSA suites use elliptic curve Diffie-Hellman key exchange [X962].

These cipher suites are all authenticated using both the pre-shared key and a
signature, either from an RSA certificate [RFC3447] (for DHE_PSK_RSA and
ECDHE_PSK_RSA), or an ECDSA certificate (for ECDHE_PSK_ECDSA) [X962].

AES_128_GCM and AES_256_GCM use the AEAD_AES_128_GCM and AEAD_AES_256_GCM
authenticated encryption defined in [RFC5116].  These are similar to the other
AES-GCM modes that are described in [RFC5288].  CHACHA20_POLY1305 cipher suites
use the authenticated encryption defined in [RFC7539].  Other ChaCha20-Poly1305
modes are described in [I-D.ietf-tls-chacha20-poly1305].  All authenticated
encryption modes use the nonce formulation from [I-D.ietf-tls-tls13].

Suites ending with SHA256 use SHA-256 for the pseudorandom function; suites
ending with SHA384 use SHA-384 [FIPS180-4].


# Combining Certificate and PSK Authentication

TLS 1.3 forbids a server from selecting different values for many of the
connection parameters when resuming a connection.  Though a client might need to
offer a choice in order to support a fallback to a 1-RTT handshake, a server
cannot change parameters such as the selected application layer protocol
[RFC7301].  Though it is theoretically possible to offer a different certificate
with these cipher suites, servers MUST NOT change certificates when resuming.
When resuming, clients MUST treat a change in certificate as a fatal error.

Outside of their use with 0-RTT, these cipher suites also permit the use of a
combination of pre-shared key and certificate authentication.  No real use case
for this has been unearthed other than with the use of resumption.

The cached-info extension [I-D.ietf-tls-cached-info] can be used to reduce the
size of a handshake, allowing more space for application data.  Since the server
certificate is not permitted to change when using 0-RTT with one of these cipher
suites, this extension trivially saves a considerable amount of space.


# Signaling Support

A TLS server that supports these cipher suites needs to indicate that it does so
in the NewSessionTicket message.  A new `allow_dhe_cert_resumption` value is
added to TicketFlags that, when set, indicates that the server will accept
resumption with cipher suites that do both (EC)DHE and certificate
authentication.

~~~
   enum {
     allow_early_data(1),
     allow_dhe_resumption(2),
     allow_psk_resumption(4),
     allow_dhe_cert_resumption(8) // new
   } TicketFlags;
~~~

There is no IANA registry for these values, so [I-D.ietf-tls-tls13] is updated
to include this value.


# Security Considerations

Data sent after the Finished messages in the complete handshake are protected
based on both the ephemeral key exchange and the pre-shared key.  Learning
either an (EC)DHE private key or the pre-shared key is insufficient to
compromise the record protection.

The combination of pre-shared key and certificate authentication relies on peers
maintaining the confidentiality of the pre-shared key for the confidentiality
and integrity of 0-RTT data.


# IANA Considerations

IANA is requested to add the following entries in the TLS Cipher Suite Registry:

~~~
TLS_ECDHE_PSK_ECDSA_WITH_AES_128_GCM_SHA256 = 0xXXXX
TLS_ECDHE_PSK_RSA_WITH_AES_128_GCM_SHA256 = 0xXXXX
TLS_DHE_PSK_RSA_WITH_AES_128_GCM_SHA256 = 0xXXXX
TLS_ECDHE_PSK_ECDSA_WITH_AES_256_GCM_SHA384 = 0xXXXX
TLS_ECDHE_PSK_RSA_WITH_AES_256_GCM_SHA384 = 0xXXXX
TLS_DHE_PSK_RSA_WITH_AES_256_GCM_SHA384 = 0xXXXX
TLS_ECDHE_PSK_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xXXXX
TLS_ECDHE_PSK_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xXXXX
TLS_DHE_PSK_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xXXXX
~~~


--- back

# Acknowledgments

TBD.
