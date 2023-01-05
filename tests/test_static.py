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
"""Tests for the static methods and basic bit, byte, token functionality"""
import binascii
import os

import otp2289


def test_bytes_and_tokens():
    """Tests the official hex and tokens defined in RFC2289"""
    assert binascii.unhexlify('9e876134d90499dd') == (
        otp2289.OTPGenerator.tokens_to_bytes('INCH SEA ANNE LONG AHEM TOUR')
    )
    assert binascii.unhexlify('7965e05436f5029f') == (
        otp2289.OTPGenerator.tokens_to_bytes('EASE OIL FUM CURE AWRY AVIS')
    )
    assert binascii.unhexlify('50fe1962c4965880') == (
        otp2289.OTPGenerator.tokens_to_bytes('BAIL TUFT BITS GANG CHEF THY')
    )
    assert binascii.unhexlify('87066dd9644bf206') == (
        otp2289.OTPGenerator.tokens_to_bytes('FULL PEW DOWN ONCE MORT ARC')
    )
    assert binascii.unhexlify('7cd34c1040add14b') == (
        otp2289.OTPGenerator.tokens_to_bytes('FACT HOOF AT FIST SITE KENT')
    )
    assert binascii.unhexlify('5aa37a81f212146c') == (
        otp2289.OTPGenerator.tokens_to_bytes('BODE HOP JAKE STOW JUT RAP')
    )
    assert binascii.unhexlify('f205753943de4cf9') == (
        otp2289.OTPGenerator.tokens_to_bytes('ULAN NEW ARMY FUSE SUIT EYED')
    )
    assert binascii.unhexlify('ddcdac956f234937') == (
        otp2289.OTPGenerator.tokens_to_bytes('SKIM CULT LOB SLAM POE HOWL')
    )
    assert binascii.unhexlify('b203e28fa525be47') == (
        otp2289.OTPGenerator.tokens_to_bytes('LONG IVY JULY AJAR BOND LEE')
    )
    assert binascii.unhexlify('bb9e6ae1979d8ff4') == (
        otp2289.OTPGenerator.tokens_to_bytes('MILT VARY MAST OK SEES WENT')
    )
    assert binascii.unhexlify('63d936639734385b') == (
        otp2289.OTPGenerator.tokens_to_bytes('CART OTTO HIVE ODE VAT NUT')
    )
    assert binascii.unhexlify('87fec7768b73ccf9') == (
        otp2289.OTPGenerator.tokens_to_bytes('GAFF WAIT SKID GIG SKY EYED')
    )
    assert binascii.unhexlify('ad85f658ebe383c9') == (
        otp2289.OTPGenerator.tokens_to_bytes('LEST OR HEEL SCOT ROB SUIT')
    )
    assert binascii.unhexlify('d07ce229b5cf119b') == (
        otp2289.OTPGenerator.tokens_to_bytes('RITE TAKE GELD COST TUNE RECK')
    )
    assert binascii.unhexlify('27bc71035aaf3dc6') == (
        otp2289.OTPGenerator.tokens_to_bytes('MAY STAR TIN LYON VEDA STAN')
    )
    assert binascii.unhexlify('d51f3e99bf8e6f0b') == (
        otp2289.OTPGenerator.tokens_to_bytes('RUST WELT KICK FELL TAIL FRAU')
    )
    assert binascii.unhexlify('82aeb52d943774e4') == (
        otp2289.OTPGenerator.tokens_to_bytes('FLIT DOSE ALSO MEW DRUM DEFY')
    )
    assert binascii.unhexlify('4f296a74fe1567ec') == (
        otp2289.OTPGenerator.tokens_to_bytes('AURA ALOE HURL WING BERG WAIT')
    )


def test_random_bytes():
    """Implement a few tests with random bytes"""
    for _ in range(10):
        rnd_bytes = os.urandom(8)  # 64 bits
        tokens = otp2289.OTPGenerator.bytes_to_tokens(rnd_bytes)
        assert rnd_bytes == otp2289.OTPGenerator.tokens_to_bytes(tokens)
