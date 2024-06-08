"""
Mercurial Signature Scheme

This module implements the Mercurial Signature Scheme using the BN254 elliptic curve.
The Mercurial Signature Scheme is a cryptographic signature scheme that provides security
based on the hardness of the discrete logarithm problem in elliptic curves.

The module includes classes for key generation, signing, verification,
and conversion of keys and signatures.

Classes:
    - MercurialSignatureScheme: Implements the Mercurial Signature Scheme.
    - MercurialSignatureDual: Implements the Dual Mercurial Signature Scheme.

"""

import hashlib
from functools import reduce

from bn254 import big, curve, ecp, ecp2, fp12, pair


class MercurialSignatureScheme:
    """
    Mercurial Signature Scheme implementation using the BN254 elliptic curve.

    This class provides an implementation of the Mercurial Signature Scheme
    using the BN254 elliptic curve.
    It includes methods for key generation, signing, verification,
    and conversion of keys and signatures.

    Attributes:
        g1 (ecp.ECp): Generator point on the first curve.
        g2 (ecp2.ECp2): Generator point on the second curve.
        gt (fp12.Fp12): Result of pairing operation.
        p (ecp.ECp): Generator point on the first curve.
        phat (ecp2.ECp2): Generator point on the second curve.
        e (pair.e): Pairing function.
        curve (curve): Elliptic curve parameters.
    """

    def __init__(self):
        """
        Initializes the Mercurial Signature Scheme.
        """
        self.g1 = ecp.ECp()
        self.g2 = ecp2.ECp2()
        self.gt = fp12.Fp12()
        self.p = ecp.generator().copy()
        self.phat = ecp2.generator().copy()
        self.e = pair.e
        self.curve = curve

    def key_gen(self, ell: int) -> tuple:
        """
        Generates secret and public keys.

        Args:
            ell (int): The length of the key pairs.

        Returns:
            tuple: A tuple containing the public key and secret key.
        """
        secret_key = []
        public_key = []
        for _ in range(ell):
            x = self.random_zp()
            w = x * self.phat
            secret_key.append(x)
            public_key.append(w)
        return public_key, secret_key

    def sign(self, secret_key, message) -> tuple:
        """
        Signs a message using the provided secret key.

        Args:
            secret_key (list): The secret key.
            message (list): The message to sign.

        Returns:
            tuple: A tuple containing the signature components.
        """
        y = self.random_zp()
        z = y * reduce(
            lambda a, b: a.add(b), [xi * mi for xi, mi in zip(secret_key, message)]
        )
        y_inv = big.invmodp(y, self.curve.r)
        y_inv_p = y_inv * self.p
        y_inv_phat = y_inv * self.phat
        return z, y_inv_p, y_inv_phat

    def verify(self, public_key, message, signature) -> bool:
        """
        Verifies the authenticity of a message's signature.

        Args:
            public_key (list): The public key.
            message (list): The message to verify.
            signature (tuple): The signature components.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        z, y_inv_p, y_inv_phat = signature
        q1 = reduce(
            lambda a, b: a * b, [self.e(xi, mi) for xi, mi in zip(public_key, message)]
        )
        return q1 == self.e(y_inv_phat, z) and self.e(self.phat, y_inv_p) == self.e(
            y_inv_phat, self.p
        )

    def convert_secret_key(self, secret_key, rho) -> list:
        """
        Converts a secret key to a different representation.

        Args:
            secret_key (list): The original secret key.
            rho (big): The conversion factor.

        Returns:
            list: The converted secret key.
        """
        return [rho * xi for xi in secret_key]

    def convert_public_key(self, public_key, rho) -> list:
        """
        Converts a public key to a different representation.

        Args:
            public_key (list): The original public key.
            rho (big): The conversion factor.

        Returns:
            list: The converted public key.
        """
        return [rho * Xi for Xi in public_key]

    def convert_signature(self, public_key, message, signature, rho) -> tuple:
        """
        Converts a signature to a different representation.

        Args:
            public_key (list): The public key.
            message (list): The message.
            signature (tuple): The original signature.
            rho (big): The conversion factor.

        Returns:
            tuple: The converted signature.
        """
        z, y, yhat = signature
        psi = self.random_zp()
        return (
            psi * rho * z,
            big.invmodp(psi, self.curve.r) * y,
            big.invmodp(psi, self.curve.r) * yhat,
        )

    def change_representation(self, public_key, message, signature, mu) -> tuple:
        """
        Changes the representation of a message and signature.

        Args:
            public_key (list): The public key.
            message (list): The message.
            signature (tuple): The original signature.
            mu (big): The conversion factor.

        Returns:
            tuple: The new representation of the message and signature.
        """
        z, y, yhat = signature
        psi = self.random_zp()
        message0 = [mu * m for m in message]
        signature0 = (
            psi * mu * z,
            big.invmodp(psi, self.curve.r) * y,
            big.invmodp(psi, self.curve.r) * yhat,
        )
        return message0, signature0

    @staticmethod
    def hash_message(message) -> ecp.ECp:
        """
        Hashes a message to a point on the elliptic curve.

        Args:
            message (str): The message to hash.

        Returns:
            ecp.ECp: The hashed point.
        """
        h = hashlib.shake_256()
        h.update(bytes(message, "utf-8"))
        hm = big.from_bytes(h.digest(curve.EFS))
        hm_point = ecp.ECp()
        while not hm_point.set(hm):
            hm = hm + 1
        hm_point = curve.x * hm_point
        return hm_point

    @staticmethod
    def random_zp() -> big:
        """
        Generates a random element in the finite field Zp.

        Returns:
            big: A random element in Zp.
        """
        return big.rand(curve.r)


class MercurialSignatureDual(MercurialSignatureScheme):
    """
    Dual Mercurial Signature Scheme implementation using the BN254 elliptic curve.

    This class provides an implementation of the Dual Mercurial Signature Scheme
    using the BN254 elliptic curve.
    It inherits from the MercurialSignatureScheme class and overrides
    some methods specific to the dual scheme.

    Attributes:
        Inherits attributes from MercurialSignatureScheme.
    """

    def key_gen(self, ell: int) -> tuple:
        """
        Generates secret and public keys for the dual scheme.

        Overrides the key_gen method in the base class.

        Args:
            ell (int): The length of the key pairs.

        Returns:
            tuple: A tuple containing the public key and secret key.
        """
        secret_key = []
        public_key = []
        for _ in range(ell):
            x = self.random_zp()
            w = x * self.p
            secret_key.append(x)
            public_key.append(w)
        return public_key, secret_key

    def sign(self, secret_key, message) -> tuple:
        """
        Signs a message using the provided secret key for the dual scheme.

        Overrides the sign method in the base class.

        Args:
            secret_key (list): The secret key.
            message (list): The message to sign.

        Returns:
            tuple: A tuple containing the signature components.
        """
        y = self.random_zp()
        z = y * reduce(
            lambda a, b: a.add(b), [Xi * mi for Xi, mi in zip(secret_key, message)]
        )
        y_inv = big.invmodp(y, self.curve.r)
        y_inv_p = y_inv * self.phat
        y_inv_phat = y_inv * self.p
        return z, y_inv_p, y_inv_phat

    def verify(self, public_key, message, signature) -> bool:
        """
        Verifies the authenticity of a message's signature for the dual scheme.

        Overrides the verify method in the base class.

        Args:
            public_key (list): The public key.
            message (list): The message to verify.
            signature (tuple): The signature components.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        z, y_inv_p, y_inv_phat = signature
        q1 = reduce(
            lambda a, b: a * b, [self.e(mi, Xi) for Xi, mi in zip(public_key, message)]
        )
        return q1 == self.e(z, y_inv_phat) and self.e(y_inv_p, self.p) == self.e(
            self.phat, y_inv_phat
        )

    @staticmethod
    def hash_message(message) -> ecp2.ECp2:
        """
        Hashes a message to a point on the second elliptic curve for the dual scheme.

        Overrides the hash_message method in the base class.

        Args:
            message (str): The message to hash.

        Returns:
            ecp2.ECp2: The hashed point on the second curve.
        """
        # not a real hash but sufficient for testing purposes
        return big.rand(curve.r) * ecp2.generator().copy()
