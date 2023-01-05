# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2020-2023 Simeon Simeonov
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

from .generator import OTP_ALGO_MD5, OTPGenerator, OTPGeneratorException


class OTPStateException(Exception):
    """OTPStateException class"""


class OTPStoreException(Exception):
    """OTPStoreException class"""


class OTPInvalidResponse(Exception):
    """OTPInvalidResponse class"""


class OTPState:
    """
    OTPState class

    The OTPState class represents a single state on the server side that can:
    - generate a challenge
    - validate the corresponding generated response from the generator
    """

    def __init__(
        self,
        ot_hex: str,
        current_step: int,
        seed: str,
        hash_algo=OTP_ALGO_MD5,
    ):
        """
        Constructs an OTPState object with the given arguments.

        Keyword Arguments:
        :param ot_hex: The one-time hex from the last successful authentication
                       or None for a newly initialized sequence.
        :type ot_hex: str or None

        :param current_step: The current step that is sent with the challenge
        :type current_step: int

        :param seed: The seed that is sent with the challenge
        :type seed: str

        :param hash_algo: The hash algo, defaults to OTP_ALGO_MD5
        :type hash_algo: int or str

        :raises otp2289.OTPStateException: If the input does not validate
        """
        # enforce the rfc2289 constraints
        try:
            self._seed = OTPGenerator.validate_seed(seed)
            self._hash_algo = OTPGenerator.validate_hash_algo(hash_algo)
            self._step = OTPGenerator.validate_step(current_step)
        except OTPGeneratorException as exp:
            raise OTPStateException(exp.args[0]) from None
        self._current_digest = None
        if ot_hex is not None:
            self._current_digest = self.validate_hex(ot_hex)
        self._new_digest_hex = None  # set upon a successful validation

    def __repr__(self):
        """repr implementation"""
        return (
            f'{self.__class__} at {id(self)} '
            f'(ot_hex={self._current_digest}, current_step={self._step}, '
            f'seed={self._seed}, '
            f'hash_algo={self._hash_algo})'
        )

    @property
    def challenge_string(self) -> str:
        """challenge_string-property"""
        # RFC-2289: "...the entire challenge string MUST be
        # terminated with either a space or a new line."
        return f'otp-{self._hash_algo} {self._step} {self._seed} '

    @property
    def current_digest(self) -> bytes:
        """current_digest-property"""
        return self._current_digest

    @property
    def hash_algo(self) -> str:
        """hash_algo-property"""
        return self._hash_algo

    @property
    def ot_hex(self) -> str:
        """ot_hex-property"""
        if self._current_digest is None:
            return ''
        return binascii.hexlify(self._current_digest).decode()

    @property
    def seed(self) -> str:
        """seed-property"""
        return self._seed

    @property
    def step(self) -> int:
        """step-property"""
        return self._step

    @property
    def validated(self) -> bool:
        """validated-property"""
        return bool(self._new_digest_hex)

    @classmethod
    def from_dict(cls, dict_obj: dict):
        """
        Returns an OTPState object from the dict-object

        :param dict_obj: The dict object
        :type dict_obj: dict

        :return: A new OTPState object
        :rtype: otp2289.OTPStore
        """
        return cls(**dict_obj)

    @staticmethod
    def response_to_bytes(response: str) -> bytes:
        """
        A wrapper that handles/validates the response as specified by RFC-2289.

        The method first checks if response is a token and tries to convert
        it to bytes. If that fails, the method assumes that response is a hex.
        If neither of those attempts succeeds OTPInvalidResponse is raised.
        It is up to the caller to run another iteration and compare the result
        to an existing digest in this state.

        :param response: The response to this state (its challenge)
        :type response: str

        :raises otp2289.OTPInvalidResponse: If the response is corrupt/illegal,
                                            but not if it simply does not
                                            validate

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
                    'The response is neither a valid token or hex'
                ) from None

    @staticmethod
    def validate_hex(ot_hex: str) -> bytes:
        """
        Validates the provided hexidigest.

        :param ot_hex: The one-time hex to validate
        :type ot_hex: str

        :raises otp2289.OTPStateException: If hex does not validate

        :return: The validated hex (without leading 0x) converted to bytes
        :rtype: bytes
        """
        if not isinstance(ot_hex, str):
            raise OTPStateException('OT-hex must be a str')
        if ot_hex.startswith('0x'):
            ot_hex = ot_hex[2:]
            ot_hex = ot_hex.strip().lower()
        if len(ot_hex) != 16:
            raise OTPStateException(
                'The length of the hex should be 16 '
                '(representing 64 bits digest)'
            )
        try:
            return binascii.unhexlify(ot_hex)
        except binascii.Error:
            raise OTPStateException('Invalid OT-hex') from None

    def get_next_state(self):
        """
        Returns the next state for a validated OTPState.

        This is a brand new OTPState object with the same hash_algo and seed
        where step -= 1 and ot_hex = self._new_digest_hex

        :return: The next OTPState if validated, None otherwise
        :rtype: otp2289.OTPState or None
        """
        if self._new_digest_hex is None:
            return None
        return OTPState(
            self._new_digest_hex,
            self._step - 1,
            self._seed,
            self._hash_algo,
        )

    def response_validates(
        self,
        response: str,
        store_valid_response: str = True,
    ) -> bool:
        """
        Validates the incoming response as specified by RFC-2289.

        :param response: The response to this state (its challenge)
        :type response: str

        :param store_valid_response: Should a valid response be stored
        :type store_valid_response: bool

        :raises otp2289.OTPInvalidResponse: If the response does not match
                                            this state

        :return: Returns True if response validates, False otherwise
        :rtype: bool
        """
        # self.response_to_bytes raises OTPInvalidResponse in case response
        # is corrupt or in a wrong format
        response_bytes = self.response_to_bytes(response)
        if self._hash_algo == 'md5':
            digest = hashlib.md5(response_bytes).digest()
            if (
                self._current_digest is None
                or OTPGenerator.strxor(digest[0:8], digest[8:])
                == self._current_digest
            ):
                if store_valid_response:
                    self._new_digest_hex = binascii.hexlify(
                        response_bytes
                    ).decode()
                return True
            return False
        if self._hash_algo == 'sha1':
            digest = hashlib.sha1(response_bytes).digest()
            if (
                self._current_digest is None
                or OTPGenerator.sha1_digest_folding(
                    hashlib.sha1(response_bytes).digest()
                )
                == self._current_digest
            ):
                if store_valid_response:
                    self._new_digest_hex = binascii.hexlify(
                        response_bytes
                    ).decode()
                return True
            return False
        # this should not happen since the hash_algo is validated by the caller
        raise OTPInvalidResponse(f'Ivalid hash_algo: {self._hash_algo}')

    def to_dict(self) -> dict:
        """
        Returns a dict representation of the object.

        This could be the base for a JSON serialization.

        :return: The dict representation of the object
        :rtype: dict
        """
        ot_hex = self._current_digest
        if ot_hex is not None:
            ot_hex = binascii.hexlify(self._current_digest).decode()
        return {
            'ot_hex': ot_hex,
            'current_step': self._step,
            'seed': self._seed,
            'hash_algo': self._hash_algo,
        }


class OTPStore:
    """
    OTPStore class

    A helper / container class that stores OTPState objects in a 2 layered
    dict structure represented by [domain][key].

    The class could serve as a base class when implementing store backends.
    """

    def __init__(self, data=None):
        """
        Constructs an OTPStore object from data

        :param data: The data object, defaults to None
        :type data: object or None
        """
        self._data = {}  # {key1: {state1-data...}, key2: {state2-data...}}
        self._states = {}  # OTPState: (domain, key) - dict
        if data is not None:
            self._add_data(data)

    def __contains__(self, state):
        """membership test"""
        return state in self._states

    def __iter__(self):
        """iterator for OTPStore"""
        return iter(self._data)

    def __len__(self):
        """len() implementation"""
        return len(self._data)

    @property
    def data(self) -> dict:
        """
        data-property

        Exposes the entire raw-data structure (dict).
        Use the high level methods when possible!
        """
        return self._data

    @property
    def states(self) -> dict:
        """
        states-property

        Exposes the entire states structure (dict).
        Use the high level methods when possible!
        """
        return self._states

    def add_state(self, key: str, state: OTPState):
        """
        Adds an OTPState object with a given key.

        :param key: The key under which to add the state
        :type key: str

        :param state: The OTPState object
        :type state: otp2289.OTPState

        :raises otp2289.OTPStoreException: On failure
        """
        if not isinstance(key, str):
            raise OTPStoreException('key must be a str')
        if not isinstance(state, OTPState):
            raise OTPStoreException('state must be an OTPState-object')
        self._data[key] = state
        self._states[state] = key

    def get(self, key, default=None):
        """A wrapper for dict.get"""
        return self._data.get(key, default)

    def items(self):
        """A wrapper for dict.items"""
        return self._data.items()

    def pop_state(self, key: str) -> OTPState:
        """
        Removes specified key and returns the corresponding OTPState-object.

        :param key: The key
        :type key: str

        :raises KeyError: If key does not exist

        :raises otp2289.OTPStoreException: On failure

        :return: The state corresponding to the key
        :rtype: otp2289.OTPState
        """
        if not isinstance(key, str):
            raise OTPStoreException('key must be a str')
        state = self._data.pop(key)
        self._states.pop(state)
        return state

    def response_validates(
        self,
        key: str,
        response: str,
        store_valid_response: bool = True,
    ) -> bool:
        """
        A method that wraps around OTPState.response_validates and
        OTPState.get_next_state.

        The response is validated against the OTPState object that corresponds
        to key (if any). If store_valid_response is True, the state is replaced
        by the next state on successful validation.

        :param key: The key
        :type key: str

        :param response: The response to this state (its challenge)
        :type response: str

        :param store_valid_response: Should a valid response be stored
        :type store_valid_response: bool

        :raises KeyError: If the key is not present

        :raises otp2289.OTPInvalidResponse: If the response does not match
                                            this state

        :return: Returns True if response validates, False otherwise
        :rtype: bool
        """
        state = self._data[key]
        rvalue = state.response_validates(response, store_valid_response)
        if rvalue and store_valid_response:
            next_state = state.get_next_state()
            self._data[key] = next_state
            self._states[next_state] = key
            self._states.pop(state)
        return rvalue

    def to_dict(self) -> dict:
        """
        Returns a dict representation of the object.

        This could be the base for a JSON serialization.

        :return: The dict representation of the object
        :rtype: dict
        """
        return {key: state.to_dict() for key, state in self._data.items()}

    def _add_data(self, dict_obj: dict) -> dict:
        """
        Adds data from a dict object (dict_obj).

        This method should probably be either overloaded or wrapped
        in a child class.

        dict_obj has the following format:
        {
            'key': {
                'ot_hex': val1,
                'current_step': val2,
                'seed': val3,
                'hash_algo': val4
            },
            ...,
            ...,
        }

        :param dict_obj: The dict-object
        :type dict_obj: dict
        """
        if not dict_obj:
            return
        for key, state_dict in dict_obj.items():
            self.add_state(key, OTPState(**state_dict))
