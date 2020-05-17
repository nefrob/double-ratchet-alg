# Ref: https://packaging.python.org/tutorials/packaging-projects/
# python3 setup.py develop

from setuptools import setup, find_packages

setup(
    name='double-ratchet',
    version='0.1.',
    packages=find_packages(),
    description="Double Ratchet Algorithm",
    author="Robert Neff",
    author_email="rneff@cs.stanford.edu",
    url="https://github.com/nefrob/double-ratchet-alg",
    zip_safe = False,
    install_requires=['cryptography'],
    python_requires='>=3.7'
)