import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "YaraParser",
    version = "1.0.0",
    author = "Joshua Brawner",
    author_email = "jrbbrawner@gmail.com",
    description = ("Parse and easily work with Yara rules."),
    license = "Apache Software License",
    keywords = "yara parser",
    long_description_content_type = 'text/markdown',
    url = "https://www.github.com/jrbrawner/YaraParser",
    packages=['YaraParser'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: Apache Software License",
        'Programming Language :: Python :: 3',
    ],
    install_requires = [
        "ply=3.11",
        "plyara=2.1.1",
        "yara-python=4.3.1"
    ]
)