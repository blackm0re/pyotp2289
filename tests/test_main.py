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
"""Tests for otp2289.__main__"""
import os
import unittest.mock

import pytest

from otp2289.__main__ import main


def test_main_generate_otp_response(capsys):
    """tests main"""
    args = [
        '--generate-otp-response',
        '-a',
        'sha1',
        '-i',
        '99',
        '-s',
        'TesT',
        '-p',
        'This is a test.',
    ]
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'Seed: TesT, Step: 99, Hash: sha1{os.linesep}'
        f'0x87fec7768b73ccf9{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.extend(['-f', 'token'])
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'Seed: TesT, Step: 99, Hash: sha1{os.linesep}'
        f'GAFF WAIT SKID GIG SKY EYED{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.append('-q')
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == f'GAFF WAIT SKID GIG SKY EYED{os.linesep}'
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0


def test_main_generate_otp_response_env_passwd(capsys):
    """tests main by fetching password from the env. var. 'OTP2289_PASSWORD'"""
    args = [
        '--generate-otp-response',
        '-a',
        'sha1',
        '-i',
        '99',
        '-s',
        'TesT',
    ]
    with unittest.mock.patch.dict(
        os.environ, {'OTP2289_PASSWORD': 'This is a test.'}
    ):
        with pytest.raises(SystemExit) as exit_info:
            main(args)
        captured = capsys.readouterr()
        assert captured.out == (
            f'Seed: TesT, Step: 99, Hash: sha1{os.linesep}'
            f'0x87fec7768b73ccf9{os.linesep}'
        )
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        args.extend(['-f', 'token'])
        with pytest.raises(SystemExit) as exit_info:
            main(args)
        captured = capsys.readouterr()
        assert captured.out == (
            f'Seed: TesT, Step: 99, Hash: sha1{os.linesep}'
            f'GAFF WAIT SKID GIG SKY EYED{os.linesep}'
        )
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0
        args.append('-q')
        with pytest.raises(SystemExit) as exit_info:
            main(args)
        captured = capsys.readouterr()
        assert captured.out == f'GAFF WAIT SKID GIG SKY EYED{os.linesep}'
        assert exit_info.type == SystemExit
        assert exit_info.value.code == 0


def test_main_generate_otp_range(capsys):
    """tests main"""
    args = [
        '--generate-otp-range',
        '-i',
        '2',
        '-s',
        'TesT',
        '-r',
        '5',
        '-p',
        'This is a test.',
    ]
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'Seed: TesT, Step: 2, Hash: md5, Range: 3'
        f'{os.linesep}'
        f'2: 0x4049f8b161669b7b{os.linesep}'
        f'1: 0x7965e05436f5029f{os.linesep}'
        f'0: 0x9e876134d90499dd{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.append('-q')
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'2: 0x4049f8b161669b7b{os.linesep}'
        f'1: 0x7965e05436f5029f{os.linesep}'
        f'0: 0x9e876134d90499dd{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.extend(['-f', 'token'])
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'2: THY AVON NO NECK COKE MOLL{os.linesep}'
        f'1: EASE OIL FUM CURE AWRY AVIS{os.linesep}'
        f'0: INCH SEA ANNE LONG AHEM TOUR{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0


@pytest.mark.parametrize(
    'args',
    [
        [
            '--generate-otp-range',
            '-i',
            '2',
            '-s',
            'TesT',
            '-r',
            '5',
        ],
        [
            '--generate-otp-range',
            '-i',
            '2',
            '-s',
            'TesT',
            '-r',
            '5',
            '-P',
        ],
    ],
)
@unittest.mock.patch('getpass.getpass', lambda *args: 'This is a test.')
def test_main_generate_otp_range_passwd_prompt(capsys, args):
    """tests main by prompting for password (with or without -P)"""
    args = [
        '--generate-otp-range',
        '-i',
        '2',
        '-s',
        'TesT',
        '-r',
        '5',
    ]
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'Seed: TesT, Step: 2, Hash: md5, Range: 3'
        f'{os.linesep}'
        f'2: 0x4049f8b161669b7b{os.linesep}'
        f'1: 0x7965e05436f5029f{os.linesep}'
        f'0: 0x9e876134d90499dd{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.append('-q')
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'2: 0x4049f8b161669b7b{os.linesep}'
        f'1: 0x7965e05436f5029f{os.linesep}'
        f'0: 0x9e876134d90499dd{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.extend(['-f', 'token'])
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'2: THY AVON NO NECK COKE MOLL{os.linesep}'
        f'1: EASE OIL FUM CURE AWRY AVIS{os.linesep}'
        f'0: INCH SEA ANNE LONG AHEM TOUR{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0


def test_main_initiate(capsys):
    """tests main"""
    args = [
        '--initiate-new-sequence',
        '-i',
        '500',
        '-s',
        'TesT',
        '-p',
        'This is a test.',
    ]
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == (
        f'Seed: TesT, Step: 500, Hash: md5{os.linesep}'
        f'0x2b8d82b6ac14346c{os.linesep}'
    )
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
    args.append('-q')
    with pytest.raises(SystemExit) as exit_info:
        main(args)
    captured = capsys.readouterr()
    assert captured.out == f'0x2b8d82b6ac14346c{os.linesep}'
    assert exit_info.type == SystemExit
    assert exit_info.value.code == 0
