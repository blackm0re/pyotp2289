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
"""A pure Python implementation of RFC-2289"""
from .generator import (
    OTP_ALGO_MD5,
    OTP_ALGO_SHA1,
    OTPChallengeException,
    OTPGenerator,
    OTPGeneratorException,
)
from .server import (
    OTPInvalidResponse,
    OTPState,
    OTPStateException,
    OTPStore,
    OTPStoreException,
)

__author__ = 'Simeon Simeonov'
__version__ = '1.2.0'
__license__ = 'BSD 2-Clause'


def int_or_str(value):
    """Returns int value of value when possible"""
    try:
        return int(value)
    except ValueError:
        return value


VERSION = tuple(map(int_or_str, __version__.split('.')))

__all__ = [
    'OTP_ALGO_MD5',
    'OTP_ALGO_SHA1',
    'OTPChallengeException',
    'OTPGenerator',
    'OTPGeneratorException',
    'OTPInvalidResponse',
    'OTPState',
    'OTPStateException',
    'OTPStore',
    'OTPStoreException',
]
