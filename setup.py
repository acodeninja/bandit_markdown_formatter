import os
from setuptools import setup

setup(
    name="bandit_markdown_formatter",
    version="1.0.0",
    author="Lawrence Goldstien",
    author_email="lawrence@acode.ninja",
    description="A report formatter for producing markdown from a bandit run.",
    license="MIT",
    keywords="bandit report markdown",
    url="https://github.com/acodeninja/bandit_markdown_formatter",
    entry_points={'bandit.formatters': ['markdown = bandit_markdown_formatter:markdown']},
    packages=['bandit_markdown_formatter'],
    install_requires=[
        'bandit>=1.7.4',
        'jinja2>=3.1.2',
    ],
    long_description=open(os.path.join(os.path.dirname(__file__), 'README.md')).read(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
)
