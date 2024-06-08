"""
This module implements a Delegatable Anonymous Credential
Scheme using two Mercurial Signature Schemes,
one for even issuers and one for odd issuers.

The DelegatableAnonCredScheme class provides methods for key generation, pseudonym generation,
issuing credentials, and verifying the integrity of the credential chain.

Attributes:
    even_issuer_scheme (MercurialSignatureDual): Mercurial Signature Scheme
    instance for even issuers.
    odd_issuer_scheme (MercurialSignatureScheme): Mercurial Signature Scheme
    instance for odd issuers.
    key_length (int): Length of the key pairs.
    initial_pk (list): Public key for the initial issuer.
    initial_sk (list): Secret key for the initial issuer.
    initial_nym (tuple): Initial pseudonym.
"""

from mercurial_signature_scheme import (MercurialSignatureDual,
                                        MercurialSignatureScheme)


class DelegatableAnonCredScheme:
    """
    Delegatable Anonymous Credential Scheme implementation.

    This class implements a Delegatable Anonymous Credential
    Scheme using two Mercurial Signature Schemes,
    one for even issuers and one for odd issuers.

    Attributes:
        even_issuer_scheme (MercurialSignatureDual): Mercurial Signature Scheme
        instance for even issuers.
        odd_issuer_scheme (MercurialSignatureScheme): Mercurial Signature Scheme
        instance for odd issuers.
        key_length (int): Length of the key pairs.
        initial_pk (list): Public key for the initial issuer.
        initial_sk (list): Secret key for the initial issuer.
        initial_nym (tuple): Initial pseudonym.
    """

    def __init__(self, key_length):
        """
        Initializes the Delegatable Anonymous Credential Scheme.

        Args:
            key_length (int): Length of the key pairs.
        """
        self.even_issuer_scheme = MercurialSignatureDual()
        self.odd_issuer_scheme = MercurialSignatureScheme()
        self.key_length = key_length
        self.initial_pk, self.initial_sk = self.even_issuer_scheme.key_gen(
            self.key_length
        )
        self.initial_nym = (self.initial_pk, None)

    def key_gen(self):
        """
        Generates secret and public keys for both issuers.

        Returns:
            tuple: A tuple containing the keys for both issuers.
        """
        even_pk, even_sk = self.even_issuer_scheme.key_gen(self.key_length)
        odd_pk, odd_sk = self.odd_issuer_scheme.key_gen(self.key_length)
        return (even_pk, even_sk), (odd_pk, odd_sk)

    def nym_gen(self, even_pk, even_sk, odd_pk, odd_sk):
        """
        Generates pseudonyms for both issuers.

        Args:
            even_pk (list): Public key for the even issuer.
            even_sk (list): Secret key for the even issuer.
            odd_pk (list): Public key for the odd issuer.
            odd_sk (list): Secret key for the odd issuer.

        Returns:
            tuple: A tuple containing the pseudonyms for both issuers.
        """
        even_rho = self.even_issuer_scheme.random_zp()
        even_sk = self.even_issuer_scheme.convert_secret_key(even_sk, even_rho)
        even_nym = self.even_issuer_scheme.convert_public_key(even_pk, even_rho)
        odd_rho = self.odd_issuer_scheme.random_zp()
        odd_sk = self.odd_issuer_scheme.convert_secret_key(odd_sk, odd_rho)
        odd_nym = self.odd_issuer_scheme.convert_public_key(odd_pk, odd_rho)
        return (even_nym, even_sk), (odd_nym, odd_sk)

    def issue_first(self, initial_nym):
        """
        Issues the first credential.

        Args:
            initial_nym (list): Pseudonym for the initial issuer.

        Returns:
            tuple: A tuple containing the issued pseudonym and its signature.
        """
        sig1 = self.even_issuer_scheme.sign(self.initial_sk, initial_nym)
        return [initial_nym], [sig1]

    def issue_next(self, cred_chain, new_nym, sk):
        """
        Issues subsequent credentials in the credential chain.

        Args:
            cred_chain (tuple): A tuple containing the credential chain.
            new_nym (list): New pseudonym to be added to the chain.
            sk (list): Secret key for signing the new pseudonym.

        Returns:
            tuple: A tuple containing the updated credential chain.
        """
        nym_list, sig_list = cred_chain
        assert len(nym_list) == len(sig_list)
        rho = self.even_issuer_scheme.random_zp()
        nym_list[0], sig_list[0] = self.even_issuer_scheme.change_representation(
            self.initial_pk, nym_list[0], sig_list[0], rho
        )
        assert self.even_issuer_scheme.verify(self.initial_pk, nym_list[0], sig_list[0])
        for i in range(len(nym_list) - 1):
            issuer_scheme = (
                self.odd_issuer_scheme if i % 2 == 0 else self.even_issuer_scheme
            )
            sig_tilde = issuer_scheme.convert_signature(
                nym_list[i], nym_list[i + 1], sig_list[i + 1], rho
            )
            rho = issuer_scheme.random_zp()
            nym_list[i + 1], sig_list[i + 1] = issuer_scheme.change_representation(
                nym_list[i], nym_list[i + 1], sig_tilde, rho
            )
            assert issuer_scheme.verify(nym_list[i], nym_list[i + 1], sig_list[i + 1])
        nym_list.append(new_nym)
        issuer_scheme = (
            self.odd_issuer_scheme
            if len(nym_list) % 2 == 0
            else self.even_issuer_scheme
        )
        sk = issuer_scheme.convert_secret_key(sk, rho)
        sig_list.append(issuer_scheme.sign(sk, new_nym))
        assert issuer_scheme.verify(nym_list[-2], nym_list[-1], sig_list[-1])
        return nym_list, sig_list

    def verify_chain(self, cred_chain):
        """
        Verifies the integrity of the credential chain.

        Args:
            cred_chain (tuple): A tuple containing the credential chain.

        Returns:
            bool: True if the credential chain is valid, False otherwise.
        """
        nym_list, sig_list = cred_chain
        assert len(nym_list) == len(sig_list)
        if not self.even_issuer_scheme.verify(
            self.initial_pk, nym_list[0], sig_list[0]
        ):
            return False
        for i in range(len(nym_list) - 1):
            issuer_scheme = (
                self.odd_issuer_scheme if i % 2 == 0 else self.even_issuer_scheme
            )
            if not issuer_scheme.verify(nym_list[i], nym_list[i + 1], sig_list[i + 1]):
                return False
        return True
