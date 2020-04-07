# -*- coding: utf-8 -*-

import setuptools

import otp2289


with open('README.md', 'r') as fh:
    long_description = fh.read()


setuptools.setup(
    name='pyotp2289',
    version=otp2289.__version__,
    author=otp2289.__author__,
    author_email='sgs@pichove.org',
    description='A pure Python implementation of "A One-Time Password System"',
    license=otp2289.__license__,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/blackm0re/pyotp2289',
    packages=setuptools.find_packages(),
    exclude_package_data={'': ['.gitignore']},
    entry_points={
        'console_scripts': [
            'otp2289=otp2289.__main__:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography'
    ],
    keywords='2289 freebsd unix security cryptography otp password',
    project_urls={
        'Bug Reports': 'https://github.com/blackm0re/pyotp2289/issues',
        'Source': 'https://github.com/blackm0re/pyotp2289',
        'API Documentation': (
            'http://gnulover.simeonov.no/docs/api/pyotp2289/latest/')
    },
    python_requires='>=3.6',
)
