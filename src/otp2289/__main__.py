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
"""
CLI entry point for the otp2289 package

Examples:
python -m otp2289 --initiate-new-sequence -s TesT

python -m otp2289 --generate-otp-response -c "otp-md5 499 TesT " -f token
python -m otp2289 --generate-otp-response -s TesT -i 499 -f token
"""
import argparse
import errno
import getpass
import io
import os
import secrets
import string
import sys

import otp2289


def eprint(*arg, **kwargs):
    """stdderr print wrapper"""
    print(*arg, file=sys.stderr, flush=True, **kwargs)


def generate_otp_response(args: argparse.Namespace) -> str:
    """
    Generates a response based on the parameters sent from the parser

    :param args: The arguments assigned from argparse
    :type args: argparse.Namespace

    :raises otp2289.OTPChallengeException: If the challenge is invalid

    :raises otp2289.OTPGeneratorException: If generator parameters are wrong

    :return: The response string
    :rtype: str
    """
    generator = otp2289.generator.OTPGenerator(
        args.password.encode(),
        args.seed,
        args.hash_algo,
    )
    if args.challenge_string:
        if args.output_format == 'token':
            return generator.generate_otp_words_from_challenge(
                args.challenge_string
            )
        return generator.generate_otp_hexdigest_from_challenge(
            args.challenge_string
        )
    # regular parameters
    header = ''
    if not args.quiet:
        header = (
            f'Seed: {args.seed}, Step: {args.step}, '
            f'Hash: {args.hash_algo}{os.linesep}'
        )
    if args.output_format == 'token':
        return header + generator.generate_otp_words(args.step)
    return header + generator.generate_otp_hexdigest(args.step)


def generate_otp_range(args: argparse.Namespace) -> str:
    """
    Generates range of responses based on the parameters sent from the parser

    :param args: The arguments assigned from argparse
    :type args: argparse.Namespace

    :raises otp2289.OTPChallengeException: If the challenge is invalid

    :raises otp2289.OTPGeneratorException: If generator parameters are wrong

    :return: The responses string
    :rtype: str
    """
    generator = otp2289.generator.OTPGenerator(
        args.password.encode(),
        args.seed,
        args.hash_algo,
    )
    if args.output_format == 'token':
        method = generator.generate_otp_words
    else:
        method = generator.generate_otp_hexdigest
    # handle most cases explicitly
    if args.range == 1:
        return f'{args.step}: ' + method(args.step)
    if args.range > args.step + 1:
        args.range = args.step + 1
    # any need for quiet?
    header = ''
    if not args.quiet:
        header = (
            f'Seed: {args.seed}, Step: {args.step}, '
            f'Hash: {args.hash_algo}, Range: {args.range}{os.linesep}'
        )
    return header + os.linesep.join(
        [
            f'{step}: ' + method(step)
            for step in range(
                args.step,
                args.step - args.range,
                -1,
            )
        ]
    )


def get_password(args: argparse.Namespace) -> str:
    """
    Extract the provided password using the defined argparse arguments

    :param args: The arguments assigned from argparse
    :type args: argparse.Namespace

    :raises KeyboardInterrupt: If the password prompt is interrupted

    :return: The extrated password string
    :rtype: str
    """
    if args.force_password_prompt:
        while True:
            password = getpass.getpass()
            if not args.initiate_new_sequence or password == getpass.getpass(
                'Repeat password: '
            ):
                break
            eprint('The passwords do not match')
        return password

    if not args.password:
        password = os.environ.get('OTP2289_PASSWORD')
        if password is not None:
            return password
        while True:
            password = getpass.getpass()
            if not args.initiate_new_sequence or password == getpass.getpass(
                'Repeat password: '
            ):
                break
            eprint('The passwords do not match')
        return password

    if os.path.isfile(args.password):
        with io.open(args.password, 'r', encoding='utf-8') as fp:
            return fp.readline().strip()

    return args.password


def get_rnd_seed() -> str:
    """
    Returns a random seed in the format:

    2 random letters (capitalize()) + 5 random digits
    """
    rnd = secrets.SystemRandom()
    return ''.join(
        rnd.choices(string.ascii_lowercase, k=2)
    ).capitalize() + ''.join(rnd.choices(string.digits, k=5))


def initiate_new_sequence(args: argparse.Namespace) -> str:
    """
    Generates a new sequence based on the parameters sent from the parser.

    :param args: The arguments assigned from argparse
    :type args: argparse.Namespace

    :raises otp2289.OTPChallengeException: If the challenge is invalid

    :raises otp2289.OTPGeneratorException: If generator parameters are wrong

    :return: The response string
    :rtype: str
    """
    if not args.seed:
        args.seed = get_rnd_seed()
    header = ''
    if not args.quiet:
        header = (
            f'Seed: {args.seed}, Step: {args.step}, '
            f'Hash: {args.hash_algo}{os.linesep}'
        )
    generator = otp2289.generator.OTPGenerator(
        args.password.encode(),
        args.seed,
        args.hash_algo,
    )
    if args.challenge_string:
        return header + generator.generate_otp_hexdigest_from_challenge(
            args.challenge_string
        )
    return header + generator.generate_otp_hexdigest(args.step)


def main(args=None):
    """the main entry point"""
    parser = argparse.ArgumentParser(
        prog=__package__,
        epilog=(
            f'%(prog)s {otp2289.__version__} by Simeon Simeonov '
            '(sgs @ LiberaChat)'
        ),
        description='The following options are available',
    )
    group = parser.add_mutually_exclusive_group(required=True)
    password_group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--generate-otp-range',
        action='store_true',
        dest='generate_otp_range',
        default=False,
        help='Generates a range of OTP responses',
    )
    group.add_argument(
        '--generate-otp-response',
        action='store_true',
        dest='generate_otp_response',
        default=False,
        help='Generates a new OTP response',
    )
    group.add_argument(
        '--initiate-new-sequence',
        action='store_true',
        dest='initiate_new_sequence',
        default=False,
        help=(
            'Initiates a new OTP sequence. Essentially the same as '
            '--generate-otp-response only it prompts twice for password '
            'and always outputs hex (ignores -f).'
        ),
    )
    password_group.add_argument(
        '-P',
        '--force-password-prompt',
        dest='force_password_prompt',
        action='store_true',
        help=(
            'Force password prompt even if the env. variable '
            '"OTP2289_PASSWORD" is set'
        ),
    )
    password_group.add_argument(
        '-p',
        '--password',
        metavar='<PASSWORD[FILE]>',
        type=str,
        dest='password',
        default='',
        help=(
            'The password or path to password file '
            '(default & recommended: prompt for passwd)'
        ),
    )
    parser.add_argument(
        '-a',
        '--hash-algorithm',
        metavar='<md5 | sha1>',
        type=str,
        dest='hash_algo',
        default='md5',
        help='The hash algorithm to use. Possible values: md5 (default), sha1',
    )
    parser.add_argument(
        '-c',
        '--challenge-string',
        metavar='<challenge string>',
        type=str,
        dest='challenge_string',
        default='',
        help='Use challenge string when generating response',
    )
    parser.add_argument(
        '-f',
        '--output-format',
        metavar='<hex | token>',
        type=str,
        dest='output_format',
        default='hex',
        help='The output format to use. Possible values: hex (default), token',
    )
    parser.add_argument(
        '-i',
        '--step',
        metavar='<step>',
        type=int,
        dest='step',
        default=500,
        help='The step. Default for initiating a new sequence is: 500',
    )
    parser.add_argument(
        '-q',
        '--quiet',
        action='store_true',
        dest='quiet',
        default=False,
        help='Dot not show headers. Only hex / tokens',
    )
    parser.add_argument(
        '-r',
        '--range',
        metavar='<range>',
        type=int,
        dest='range',
        default=1,
        help='Amount of consecutive OTP hex/tokens to generate. default: 1',
    )
    parser.add_argument(
        '-s',
        '--seed',
        metavar='[seed]',
        type=str,
        dest='seed',
        default='',
        help=(
            'The seed to use (1 to 16 alphanumeric characters) '
            '(default & recommended: random seed)'
        ),
    )
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=f'%(prog)s {otp2289.__version__}',
        help='display program-version and exit',
    )
    args = parser.parse_args(args)
    # handle the password before everything else
    try:
        args.password = get_password(args)
    except KeyboardInterrupt:
        eprint(os.linesep + 'Prompt terminated')
        sys.exit(errno.EACCES)
    except Exception as exp:
        eprint(f'Unable to fetch password: {exp}')
        sys.exit(1)
    try:
        if args.initiate_new_sequence:
            print(initiate_new_sequence(args))
        if args.generate_otp_range:
            print(generate_otp_range(args))
        if args.generate_otp_response:
            print(generate_otp_response(args))
        sys.exit(0)
    except otp2289.generator.OTPGeneratorException as exp:
        eprint(f'GeneratorException: {exp}')
    except otp2289.generator.OTPChallengeException as exp:
        eprint(f'ChallengeException: {exp}')
    except Exception as exp:
        eprint(f'Unknown error: {exp}')
    sys.exit(1)


if __name__ == '__main__':
    main()
