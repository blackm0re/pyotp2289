# pyotp2289

*pyotp2289* is a pure Python 3 implementation of "A One-Time Password System" -
RFC-2289.

It requires no additional libraries.


## General

The main reason for writing this library was the need to login into my
FreeBSD servers using the [opiepasswd](https://www.freebsd.org/cgi/man.cgi?query=opiepasswd&sektion=1&manpath=freebsd-release-ports)
as described in [FreeBSD Handbook](https://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/one-time-passwords.html).

I decided to license the library under the
[Simplified BSD License / 2-clause BSD license](https://github.com/blackm0re/pyotp2289/blob/master/LICENSE) and not under the
(L)GPL-3 as I usually do.

I hope that somebody will find it useful.


## Installation

### pip (pypi)

   ```bash
   pip install pyotp2289
   ```


### FreeBSD

*pyotp2289* is included in the official ports-tree.

   ```bash
   cd /usr/ports/security/py-pyotp2289
   make install clean
   ```


### Gentoo

   ```bash
   # add sgs' custom repository using app-eselect/eselect-repository
   eselect repository add sgs

   # ... or using app-portage/layman (obsolete)
   layman -a sgs

   emerge dev-python/pyotp2289
   ```


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

"The OTP system generator passes the user's secret pass-phrase, along
with a seed received from the server as part of the challenge,
through multiple iterations of a secure hash function to produce a
one-time password. After each successful authentication, the number
of secure hash function iterations is reduced by one.  Thus, a unique
sequence of passwords is generated.  The server verifies the one-time
password received from the generator by computing the secure hash
function once and comparing the result with the previously accepted
one-time password."


## Examples

We define the two entities: *client* and *server*. The entire application of
RFC-2289 consists of interactions between them.

   ```python
   import getpass  # client only

   import otp2289  # client and server

   # the server starts by picking:
   # - algorithm (MD5 or SHA1) to use
   # - seed - 1 to 16 alphanumeric characters. The seed must never be reused.
   # - initial step - number (int) that will be decremented for each OTP.
   # In FreeBSD, the following default values are used:
   # - MD5
   # - the first two letters of the hostname + 5 random digits for seed
   # - initial step: 500

   # the client receives those values, chooses a strong password and creates
   # initialization digest (hash). The password 'This is a test.' will give you
   # the same results as in the following example.
   passwd_bytes = getpass.getpass().encode()  # Fetch the password as bytes
   generator = otp2289.generator.OTPGenerator(passwd_bytes,
                                              'TesT',
                                              otp2289.OTP_ALGO_MD5)
   digest = generator.generate_otp_hexdigest(500)
   # digest is now: 0x2b8d82b6ac14346c
   # the client sends it to the server

   # the server creates the first state. Note that step is decremented by 1:
   state = otp2289.server.OTPState(digest, 499, 'TesT', otp2289.OTP_ALGO_MD5)
   # the state can be stored in a OTPStore container:
   store = otp2289.server.OTPStore()
   # key can be any str that can be used to reference the state (f.i username)
   store.add_state('myusername', state)  # where key can be any str that can be
   # OTPStore is provided only for convenience as it is not part of RFC-2289.
   # The server can store states any way it wants. A normal dict is also fine.
   # Once the initial state is set on the server, the client can authenticate.

   # Upon authentication request (f.i. login), the server issues a challenge
   # based on the state:
   challenge = state.challenge_string  # challenge is now 'otp-md5 499 TesT '

   # the client can now respond by using (or recreating) the same generator
   # created earlier. RFC-2289 defines two types of responses:
   # - hex (like '0x2b8d82b6ac14346c') - more suited for automation
   # - tokens consisting of 6 short words - better when responding manually
   hex_response = generator.generate_otp_hexdigest(499)  # '0x6323f96296a2526b'
   token_response = generator.generate_otp_words(499)
   # token_response is now: 'CANT JAW BITS NU LO PUP'
   # a possible shortcut may be to use the challenge-string directly:
   hex_response = generator.generate_otp_hexdigest_from_challenge(challenge)
   token_response = generator.generate_otp_words_from_challenge(challenge)
   # ... giving the same results.

   # once the response is received, the server validates it by yet again using
   # the current state:
   result = state.response_validates(hex_response)
   # or
   result = state.response_validates(token_response)
   # result should be True if the response matches the state, False if not
   # in case of invalid response or response checksum doesn't match, a
   # otp2289.server.OTPInvalidResponse exception is raised.

   # once the state has successfully validated the corresponding response,
   # the state **must never be used again** and a state corresponding to the
   # "next" (498) step created.
   state = state.get_next_state()

   # the next authentication attempt...
   challenge = state.challenge_string  # challenge is now 'otp-md5 498 TesT '
   # ... and on the client side...
   hex_response = generator.generate_otp_hexdigest_from_challenge(challenge)
   # etc. etc...
   ```

Please visit the
[API documentation](http://gnulover.simeonov.no/docs/api/pyotp2289/latest/) for
a complete reference.

If you don't care about developing applications in Python and only care about
generating one-time passwords (tokens / hex digests) and authenticating with
existing solutions (f.i. FreeBSD servers), *pyotp2289* comes with a simple CLI:

   ```bash
   python -m otp2289 --generate-otp-response -f token -i 498 -s TesT
   ```

... will prompt for password and generate a 6 words (token) response.

   ```bash
   python -m otp2289 --generate-otp-range -f token -i 498 -s TesT
   ```

... will prompt for password and generate a range of 4 one-time passwords
starting from (and including) 498.


## Support and contributing

*pyotp2289* is hosted on GitHub: https://github.com/blackm0re/pyotp2289


## Author

Simeon Simeonov - sgs @ LiberaChat


## [License](https://github.com/blackm0re/pyotp2289/blob/master/LICENSE)

Copyright (c) 2020-2023 Simeon Simeonov
All rights reserved.

[Licensed](https://github.com/blackm0re/pyotp2289/blob/master/LICENSE) under the BSD 2-clause.
SPDX-License-Identifier: BSD-2-Clause-FreeBSD
