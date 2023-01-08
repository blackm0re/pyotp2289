# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2020-2023, Simeon Simeonov
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
"""Tests for otp2289.server"""
import json

import pytest

import otp2289


def test_state_caller_exceptions():
    """Tests the exceptions when calling the OTPState objects"""
    state = otp2289.OTPState(
        '0x7965e05436f5029f',
        1,
        'TeSt',
        otp2289.OTP_ALGO_MD5,
    )
    with pytest.raises(otp2289.OTPInvalidResponse) as exc_info:
        state.response_validates('bla')
    assert exc_info.type is otp2289.OTPInvalidResponse
    assert exc_info.value.args[0] == (
        'The response is neither a valid token or hex'
    )


def test_state_constructor_exceptions():
    """Tests the exceptions when initializing new OTPState objects"""
    with pytest.raises(otp2289.OTPStateException) as exc_info:
        otp2289.OTPState(
            '0x7965e05436f5029t',
            1,
            'TeStø'.encode(),
            otp2289.OTP_ALGO_MD5,
        )
    assert exc_info.type is otp2289.OTPStateException
    assert exc_info.value.args[0] == 'Seed must be a string'
    with pytest.raises(otp2289.OTPStateException) as exc_info:
        otp2289.OTPState(
            '0x7965e05436f5029t',
            '1',
            'TeSt',
            otp2289.OTP_ALGO_MD5,
        )
    assert exc_info.type is otp2289.OTPStateException
    assert exc_info.value.args[0] == 'Step value MUST be an int'


def test_state_validation_md5():
    """Tests the OTPState validation functionality for MD5"""
    state = otp2289.OTPState(
        '0x7965e05436f5029f',
        1,
        'TeSt',
        otp2289.OTP_ALGO_MD5,
    )
    assert state.validated is False
    assert state.response_validates('0x9e876134d90499dd') is True
    assert state.response_validates('INCH SEA ANNE LONG AHEM TOUR') is True
    assert state.ot_hex == '7965e05436f5029f'
    assert state.validated is True


def test_state_validation_sha1():
    """Tests the OTPState validation functionality for SHA1"""
    state = otp2289.OTPState(
        '0x63d936639734385b',
        1,
        'TeSt',
        otp2289.OTP_ALGO_SHA1,
    )
    assert state.validated is False
    assert state.response_validates('0xbb9e6ae1979d8ff4') is True
    assert state.response_validates('MILT VARY MAST OK SEES WENT') is True
    assert state.ot_hex == '63d936639734385b'
    assert state.validated is True


def test_store():
    """Tests the OTPStore functionality"""
    store_data = {
        'sgs': {
            'ot_hex': '0x7965e05436f5029f',
            'current_step': 1,
            'seed': 'TeSt',
            'hash_algo': 'md5',
        },
        'blackmore': {
            'ot_hex': '0x63d936639734385b',
            'current_step': 1,
            'seed': 'TeSt',
            'hash_algo': 'sha1',
        },
    }
    store = otp2289.OTPStore(store_data)
    assert len(store) == 2
    assert isinstance(json.dumps(store.to_dict()), str)  # serializable?
    assert store.response_validates('sgs', '0x9e876134d90499dd') is True
    assert store.response_validates('sgs', '0x9e876134d90499dd') is False
    sgs_state = store.get('sgs')
    assert sgs_state in store
    store.pop_state('sgs')
    assert bool(store) is True
    store.pop_state('blackmore')
    assert bool(store) is False
