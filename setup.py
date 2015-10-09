#!/usr/bin/env python

from distutils.core import setup

setup(name = 'datahugs',
      version = '0.1',
      py_modules = ['datahugs'],
      description='Script to checksum all files in a directory and report via email',
      url='https://github.com/freedryk/datahugs',
      author='Jordan Dawe',
      author_email='freedryk@gmail.com',
      license='MIT',
      keywords='checksum',
      entry_points={
          'console_scripts': [
              'datahugs=datahugs:main',
          ],
      },
      )
