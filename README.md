# pyotp2289

pyotp2289 is a pure Python 3 implementation of "A One-Time Password System" -
RFC-2289.

It requires no additional libraries.


## General

The main reason for writing this library was the need to login into my
FreeBSD servers using the [opiepasswd]
(https://www.freebsd.org/cgi/man.cgi?query=opiepasswd&sektion=1&manpath=freebsd-release-ports)
as described in [FreeBSD Handbook]
(https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/one-time-passwords.html).

I decided to license the library under the
[Simplified BSD License / 2-clause BSD license](LICENSE) and not under the
(L)GPL-3 as I usually do.

I hope that somebody will find it useful.


## Overview of RFC-2289

RFC-2289 describes a one-time password authentication system (OTP):

"The system provides authentication for system access (login) and other
applications requiring authentication that is secure against passive attacks
based on replaying captured reusable passwords. OTP evolved from the S/KEY
(S/KEY is a trademark of Bellcore) One-Time Password System that was released
by Bellcore."

"One form of attack on networked computing systems is eavesdropping on
network connections to obtain authentication information such as the
login IDs and passwords of legitimate users. Once this information is
captured, it can be used at a later time to gain access to the
system. One-time password systems are designed to counter this type
of attack, called a 'replay attack'."

The authentication system described in RFC-2289 "uses a secret
pass-phrase to generate a sequence of one-time (single use)
passwords.  With this system, the user's secret pass-phrase never
needs to cross the network at any time such as during authentication
or during pass-phrase changes. Thus, it is not vulnerable to replay
attacks.  Added security is provided by the property that no secret
information need be stored on any system, including the server being
protected."

"There are two entities in the operation of the OTP one-time password
system. The **generator** must produce the appropriate one-time password
from the user's secret pass-phrase and from information provided in
the **challenge** from the **server**. The server must send a challenge that
includes the appropriate generation parameters to the generator, must
verify the one-time password received, must store the last valid
one-time password it received, and must store the corresponding one-
time password sequence number. The server must also facilitate the
changing of the user's secret pass-phrase in a secure manner."


## Examples

TODO


## Author

Simeon Simeonov - sgs @ Freenode


## [License](LICENSE)

Copyright (c) 2020, Simeon Simeonov
All rights reserved.

[licensed](LICENSE) under the BSD 2-clause.
SPDX-License-Identifier: BSD-2-Clause-FreeBSD
