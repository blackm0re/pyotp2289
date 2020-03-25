# -*- coding: utf-8 -*-
"""A pure Python implementation of RFC-2289"""

from .generator import (OTP_ALGO_MD5,
                        OTP_ALGO_SHA1,
                        OTPGenerator,
                        OTPGeneratorException)


__author__ = 'Simeon Simeonov'
__version__ = '1.0.0'
__license__ = 'GPL3'


def int_or_str(value):
    """Returns int value of value when possible"""
    try:
        return int(value)
    except ValueError:
        return value


VERSION = tuple(map(int_or_str, __version__.split('.')))

__all__ = ['OTP_ALGO_MD5',
           'OTP_ALGO_SHA1',
           'OTPGenerator',
           'OTPGeneratorException']
