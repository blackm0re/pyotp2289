# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2020, Simeon Simeonov
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""A pure Python implementation of the RFC-2289 OTP server"""
import binascii
import hashlib

from .generator import (OTP_ALGO_MD5,
                        OTPGenerator,
                        OTPGeneratorException)


class OTPStateException(Exception):
    """OTPStateException class"""


class OTPInvalidResponse(Exception):
    """OTPInvalidResponse class"""


class OTPState:
    """
    OTPState class

    The OTPState class represents a single state on the server side that can:
    - generate a challenge
    - validate the corresponding generated response from the generator
    """

    def __init__(self, ot_hex, current_step, seed, hash_algo=OTP_ALGO_MD5):
        """
        Constructs an OTPState object with the given arguments.

        Keyword Arguments:
        :param ot_hex: The one-time hex from the last successful
                       authentication or the first OTP of a newly
                       initialized sequence
        :type ot_hex: str

        :param current_step: The current step that is sent with the challenge
        :type current_step: int

        :param seed: The seed that is sent with the challenge
        :type seed: str

        :param hash_algo: The hash algo, defaults to OTP_ALGO_MD5
        :type hash_algo: int or str

        :raises OTPStateException: In case the input does not validate
        """
        # enforce the rfc2289 constraints
        try:
            self._seed = OTPGenerator.validate_seed(seed)
            self._hash_algo = OTPGenerator.validate_hash_algo(hash_algo)
            self._step = OTPGenerator.validate_step(current_step)
        except OTPGeneratorException as exp:
            raise OTPStateException(exp.args[0])
        self._current_digest = self.validate_hex(ot_hex)
        self._new_digest_hex = None  # set upon a successful validation

    def __str__(self):
        """Duplicate the challenge string"""
        return f'otp-{self._hash_algo} {self._step} {self._seed} '

    @property
    def challenge_string(self):
        """challenge_string-property"""
        # RFC-2289: "...the entire challenge string MUST be
        # terminated with either a space or a new line."
        return f'otp-{self._hash_algo} {self._step} {self._seed} '

    @property
    def validated(self):
        """validated-property"""
        return bool(self._new_digest_hex)

    @staticmethod
    def response_to_bytes(response):
        """
        A wrapper that handles/validates the response as specified by RFC-2289.

        The method first checks if response is a token and tries to convert
        it to bytes. If that fails, the method assumes that response is a hex.
        If neither of those attempts succeeds OTPInvalidResponse is raised.
        It is up to the caller to run another iteration and compare the result
        to an existing digest in this state.

        :param response: The response to this state (its challenge)
        :type response: str

        :raises OTPInvalidResponse: If the response is corrupt / illegal,
                                    but not if it simply does not validate

        :return: The bytes representation of response (if any)
        :rtype: bytes
        """
        try:
            return OTPGenerator.tokens_to_bytes(response)
        except OTPGeneratorException:
            # now assume hex...
            try:
                return OTPState.validate_hex(response)
            except OTPStateException:
                raise OTPInvalidResponse(
                    'The response is neither a valid token or hex')

    @staticmethod
    def validate_hex(ot_hex):
        """
        Validates the provided hexidigest.

        :param ot_hex: The one-time hex to validate
        :type ot_hex: str

        :raises OTPStateException: In case hex does not validate

        :return: The validated hex (without leading 0x) converted to bytes
        :rtype: bytes
        """
        if not isinstance(ot_hex, str):
            raise OTPStateException('OT-hex must be a str')
        if ot_hex.startswith('0x'):
            ot_hex = ot_hex[2:]
            ot_hex = ot_hex.strip().lower()
        if len(ot_hex) != 16:
            raise OTPStateException('The length of the hex should be 16 '
                                    '(representing 64 bits digest)')
        try:
            return binascii.unhexlify(ot_hex)
        except binascii.Error:
            raise OTPStateException('Invalid OT-hex')

    def response_validates(self, response, store_valid_response=True):
        """
        Validates the incoming response as specified by RFC-2289.

        :param response: The response to this state (its challenge)
        :type response: str

        :param store_valid_response: Should a valid response be stored
        :type store_valid_response: bool

        :raises OTPInvalidResponse: If the response does not match this state

        :return: Returns True if response validates, False otherwise
        :rtype: bool
        """
        # self.response_to_bytes raises OTPInvalidResponse in case response
        # is corrupt or in a wrong format
        response_bytes = self.response_to_bytes(response)
        if self._hash_algo == 'md5':
            digest = hashlib.md5(response_bytes).digest()
            if (
                    OTPGenerator.strxor(digest[0:8], digest[8:]) ==
                    self._current_digest
            ):
                if store_valid_response:
                    self._new_digest_hex = binascii.hexlify(
                        response_bytes).decode()
                return True
            return False
        if self._hash_algo == 'sha1':
            digest = hashlib.sha1(response_bytes).digest()
            if (
                    OTPGenerator.sha1_digest_folding(
                        hashlib.sha1(
                            response_bytes).digest()) == self._current_digest
            ):
                if store_valid_response:
                    self._new_digest_hex = binascii.hexlify(
                        response_bytes).decode()
                return True
            return False
        # this should not happen since the hash_algo is validated by the caller
        raise OTPInvalidResponse(f'Ivalid hash_algo: {self._hash_algo}')
