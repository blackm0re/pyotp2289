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
"""Tests for otp2289.generator"""
import pytest

import otp2289


def test_caller_exceptions():
    """Tests the exceptions when calling an initialized object"""
    gen = otp2289.OTPGenerator(
        'This is a test.'.encode(),
        'TeSt',
        otp2289.OTP_ALGO_MD5,
    )
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        gen.generate_otp_words('3')
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == 'Step value MUST be an int'
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        gen.generate_otp_hexdigest(-1)
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == 'Step value MUST be >= 0'
    with pytest.raises(otp2289.OTPChallengeException) as exc_info:
        gen.generate_otp_hexdigest_from_challenge(b'md5 fbd TeSt')
    assert exc_info.type is otp2289.OTPChallengeException
    assert exc_info.value.args[0] == 'Challenge must be str'
    with pytest.raises(otp2289.OTPChallengeException) as exc_info:
        gen.generate_otp_hexdigest_from_challenge('md5 fbd TeSt')
    assert exc_info.type is otp2289.OTPChallengeException
    assert exc_info.value.args[0] == 'Invalid challenge'
    with pytest.raises(otp2289.generator.OTPChallengeException) as exc_info:
        gen.generate_otp_hexdigest_from_challenge('otp-md5 fbd TeSt')
    assert exc_info.type is otp2289.generator.OTPChallengeException
    assert exc_info.value.args[0] == 'Invalid challenge'


def test_constructor_exceptions():
    """
    Tests the exceptions when initializing a new object (in the constructor)
    """
    # test the otp2289.OTPGenerator __init__ and validators
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator(
            'This is a test.'.encode(),
            'TeStø'.encode(),
            otp2289.OTP_ALGO_MD5,
        )
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == 'Seed must be a string'
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator(
            'This is a test.'.encode(),
            'TeStøtEsTteSTteStTest',
            otp2289.OTP_ALGO_SHA1,
        )
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == (
        'The seed MUST be of 1 to 16 characters in length'
    )
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator(
            'This is a test.'.encode(),
            'TeStø',
            otp2289.OTP_ALGO_SHA1,
        )
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == (
        'The seed MUST consist of purely alphanumeric characters'
    )
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator(
            'This is a test.'.encode(),
            'TeSt',
            9,
        )
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == (
        'hash_algo is not among the known algorithms'
    )
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator(
            'This is a test.'.encode(),
            'TeSt',
            b'md5',
        )
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == 'hash_algo must be an int or a str'
    # test the package structure as well
    with pytest.raises(otp2289.generator.OTPGeneratorException) as exc_info:
        otp2289.generator.OTPGenerator(
            'This is a test.'.encode(),
            'TeSt',
            'foo',
        )
    assert exc_info.type is otp2289.generator.OTPGeneratorException
    assert exc_info.value.args[0] == (
        'foo is not supported by this version of the hashlib module'
    )
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator('1234567', 'TeSt', otp2289.OTP_ALGO_MD5)
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == 'Password must be a byte-string'
    with pytest.raises(otp2289.OTPGeneratorException) as exc_info:
        otp2289.OTPGenerator(
            '1234567'.encode(),
            'TeSt',
            otp2289.OTP_ALGO_MD5,
        )
    assert exc_info.type is otp2289.OTPGeneratorException
    assert exc_info.value.args[0] == 'Password must be longer than 10 bytes'


def test_md5():
    """
    Tests the MD5 functionality of the OTPGenerator as described in the RFC

    Those are the tests from 'RFC-2289 Appendix C - OTP Verification Examples'
    """
    # We could run this in a loop, but I guess "Readability counts."
    # pass='This is a test.', seed='TeSt'
    gen = otp2289.OTPGenerator(
        'This is a test.'.encode(),
        'TeSt',
        otp2289.OTP_ALGO_MD5,
    )
    res_words = gen.generate_otp_words(0)
    res_hex = gen.generate_otp_hexdigest(0)
    assert isinstance(res_words, str)
    assert isinstance(res_hex, str)
    assert res_hex == '0x9e876134d90499dd'
    assert res_words == 'INCH SEA ANNE LONG AHEM TOUR'
    # step 1
    assert gen.generate_otp_hexdigest(1) == '0x7965e05436f5029f'
    assert gen.generate_otp_words(1) == 'EASE OIL FUM CURE AWRY AVIS'
    assert gen.generate_otp_hexdigest_from_challenge('otp-md5 1   TeSt') == (
        '0x7965e05436f5029f'
    )
    assert gen.generate_otp_words_from_challenge('otp-md5 1 TeSt') == (
        'EASE OIL FUM CURE AWRY AVIS'
    )
    # step 99
    assert gen.generate_otp_hexdigest(99) == '0x50fe1962c4965880'
    assert gen.generate_otp_words(99) == 'BAIL TUFT BITS GANG CHEF THY'
    assert gen.generate_otp_hexdigest_from_challenge('otp-md5 99   TeSt') == (
        '0x50fe1962c4965880'
    )
    assert gen.generate_otp_words_from_challenge('otp-md5 99   TeSt') == (
        'BAIL TUFT BITS GANG CHEF THY'
    )
    # iterator test
    hexdigests = list(gen.hexdigest_range(105))  # testing the range itself
    words = list(gen.words_range(99))
    hexdigests.reverse()
    words.reverse()
    assert hexdigests[0] == '0x9e876134d90499dd'
    assert hexdigests[1] == '0x7965e05436f5029f'
    assert hexdigests[99] == '0x50fe1962c4965880'
    assert words[0] == 'INCH SEA ANNE LONG AHEM TOUR'
    assert words[1] == 'EASE OIL FUM CURE AWRY AVIS'
    assert words[99] == 'BAIL TUFT BITS GANG CHEF THY'
    # pass='AbCdEfGhIjK', seed='alpha1'
    gen = otp2289.OTPGenerator(
        'AbCdEfGhIjK'.encode(),
        'alpha1',
        otp2289.OTP_ALGO_MD5,
    )
    assert gen.generate_otp_hexdigest(0) == '0x87066dd9644bf206'
    assert gen.generate_otp_words(0) == 'FULL PEW DOWN ONCE MORT ARC'
    assert gen.generate_otp_hexdigest(1) == '0x7cd34c1040add14b'
    assert gen.generate_otp_words(1) == 'FACT HOOF AT FIST SITE KENT'
    assert gen.generate_otp_hexdigest(99) == '0x5aa37a81f212146c'
    assert gen.generate_otp_words(99) == 'BODE HOP JAKE STOW JUT RAP'
    # pass="OTP's are good", seed='correct'
    gen = otp2289.OTPGenerator(
        "OTP's are good".encode(),
        'correct',
        otp2289.OTP_ALGO_MD5,
    )
    assert gen.generate_otp_hexdigest(0) == '0xf205753943de4cf9'
    assert gen.generate_otp_words(0) == 'ULAN NEW ARMY FUSE SUIT EYED'
    assert gen.generate_otp_hexdigest(1) == '0xddcdac956f234937'
    assert gen.generate_otp_words(1) == 'SKIM CULT LOB SLAM POE HOWL'
    assert gen.generate_otp_hexdigest(99) == '0xb203e28fa525be47'
    assert gen.generate_otp_words(99) == 'LONG IVY JULY AJAR BOND LEE'


def test_sha1():
    """
    Tests the SHA-1 functionality of the OTPGenerator as described in the RFC

    Those are the tests from 'RFC-2289 Appendix C - OTP Verification Examples'
    """
    # pass='This is a test.', seed='TeSt'
    gen = otp2289.OTPGenerator(
        'This is a test.'.encode(),
        'TeSt',
        otp2289.OTP_ALGO_SHA1,
    )
    # step=0
    res_hex = gen.generate_otp_hexdigest(0)
    res_words = gen.generate_otp_words(0)
    assert isinstance(res_words, str)
    assert isinstance(res_hex, str)
    assert res_hex == '0xbb9e6ae1979d8ff4'
    assert res_words == 'MILT VARY MAST OK SEES WENT'
    assert gen.generate_otp_hexdigest(1) == '0x63d936639734385b'
    assert gen.generate_otp_words(1) == 'CART OTTO HIVE ODE VAT NUT'
    assert gen.generate_otp_hexdigest_from_challenge('otp-sha1 1 TeSt') == (
        '0x63d936639734385b'
    )
    assert gen.generate_otp_words_from_challenge('otp-sha1 1 TeSt') == (
        'CART OTTO HIVE ODE VAT NUT'
    )
    assert gen.generate_otp_hexdigest(99) == '0x87fec7768b73ccf9'
    assert gen.generate_otp_words(99) == 'GAFF WAIT SKID GIG SKY EYED'
    assert gen.generate_otp_hexdigest_from_challenge('otp-sha1 99   TeSt') == (
        '0x87fec7768b73ccf9'
    )
    assert gen.generate_otp_words_from_challenge('otp-sha1 99  TeSt') == (
        'GAFF WAIT SKID GIG SKY EYED'
    )
    # iterator test
    hexdigests = list(gen.hexdigest_range(105))
    words = list(gen.words_range(99))
    hexdigests.reverse()
    words.reverse()
    assert hexdigests[0] == '0xbb9e6ae1979d8ff4'
    assert hexdigests[1] == '0x63d936639734385b'
    assert hexdigests[99] == '0x87fec7768b73ccf9'
    assert words[0] == 'MILT VARY MAST OK SEES WENT'
    assert words[1] == 'CART OTTO HIVE ODE VAT NUT'
    assert words[99] == 'GAFF WAIT SKID GIG SKY EYED'
    # pass='AbCdEfGhIjK', seed='alpha1'
    gen = otp2289.OTPGenerator(
        'AbCdEfGhIjK'.encode(),
        'alpha1',
        otp2289.OTP_ALGO_SHA1,
    )
    assert gen.generate_otp_hexdigest(0) == '0xad85f658ebe383c9'
    assert gen.generate_otp_words(0) == 'LEST OR HEEL SCOT ROB SUIT'
    assert gen.generate_otp_hexdigest(1) == '0xd07ce229b5cf119b'
    assert gen.generate_otp_words(1) == 'RITE TAKE GELD COST TUNE RECK'
    assert gen.generate_otp_hexdigest(99) == '0x27bc71035aaf3dc6'
    assert gen.generate_otp_words(99) == 'MAY STAR TIN LYON VEDA STAN'
    # pass="OTP's are good", seed='correct'
    gen = otp2289.OTPGenerator(
        "OTP's are good".encode(),
        'correct',
        otp2289.OTP_ALGO_SHA1,
    )
    assert gen.generate_otp_hexdigest(0) == '0xd51f3e99bf8e6f0b'
    assert gen.generate_otp_words(0) == 'RUST WELT KICK FELL TAIL FRAU'
    assert gen.generate_otp_hexdigest(1) == '0x82aeb52d943774e4'
    assert gen.generate_otp_words(1) == 'FLIT DOSE ALSO MEW DRUM DEFY'
    assert gen.generate_otp_hexdigest(99) == '0x4f296a74fe1567ec'
    assert gen.generate_otp_words(99) == 'AURA ALOE HURL WING BERG WAIT'
