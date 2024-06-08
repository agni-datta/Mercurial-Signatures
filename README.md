---
title: Mercurial-Signatures
linter-yaml-title-alias: Mercurial-Signatures
date created: Friday, April 26th 2024, 00:18:16
date modified: Monday, June 3rd 2024, 05:50:10
aliases: [Mercurial-Signatures]
---

[![DOI](https://zenodo.org/badge/285924323.svg)](https://zenodo.org/badge/latestdoi/285924323)

# Mercurial-Signatures

We implement Delegatable Anonymous Credentials in python using Mercurial  
Signatures following E. Crites’s  
[dissertation](https://doi.org/10.26300/tj7d-3h94). The implementation itself  
relies on the [miracl/core](https://github.com/burkh4rt/miracl-core)  
cryptographic library, in particular on its BN-254 pairing-friendly curve  
implementation and related utility functions (cf.  
[Barreto \& Naehrig](https://eprint.iacr.org/2005/133)).

The code is mainly intended to be proof-of-concept, following E.C.‘s Section  
3.2 for the construction of a mercurial signature scheme from a type III  
bilinear pairing and then Section 4.3 for the construction of delegatable  
anonymous credentials using said signature scheme. The C/C++ and rust code only  
implements Mercurial Signatures (not credentials).
