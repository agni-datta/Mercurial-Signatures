import unittest

from mercurial_signature_scheme import (MercurialSignatureDual,
                                        MercurialSignatureScheme)


class TestMercurialSignatureScheme(unittest.TestCase):
    """
    Unit tests for the Mercurial Signature Scheme.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """
        Set up instances of MercurialSignatureScheme for testing.
        """
        cls.scheme1: MercurialSignatureScheme = MercurialSignatureScheme()
        cls.scheme2: MercurialSignatureDual = MercurialSignatureDual()

    def test_verify(self) -> None:
        """
        Test signature verification.
        """
        for scheme in [self.scheme1, self.scheme2]:
            public_key, secret_key = scheme.key_gen(3)
            messages = [scheme.hash_message(m) for m in ["this", "is a", "test"]]
            signature = scheme.sign(secret_key, messages)
            self.assertTrue(
                scheme.verify(public_key, messages, signature),
                "Signature verification passes",
            )

    def test_convert_sig(self) -> None:
        """
        Test signature conversion.
        """
        for scheme in [self.scheme1, self.scheme2]:
            public_key, secret_key = scheme.key_gen(4)
            messages = [
                scheme.hash_message(m) for m in ["this", "is", "another", "test"]
            ]
            signature = scheme.sign(secret_key, messages)
            rho = scheme.random_zp()
            converted_public_key = scheme.convert_public_key(public_key, rho)
            converted_signature = scheme.convert_signature(
                public_key, messages, signature, rho
            )
            self.assertTrue(
                scheme.verify(converted_public_key, messages, converted_signature),
                "Signature conversion verification passes",
            )
            messages[0] = scheme.hash_message("oh noes")
            self.assertFalse(
                scheme.verify(converted_public_key, messages, converted_signature),
                "Forgery does not verify",
            )

    def test_change_rep(self) -> None:
        """
        Test signature change of representation.
        """
        for scheme in [self.scheme1, self.scheme2]:
            public_key, secret_key = scheme.key_gen(5)
            messages = [
                scheme.hash_message(m) for m in ["this", "is", "also", "a", "test"]
            ]
            signature = scheme.sign(secret_key, messages)
            mu = scheme.random_zp()
            modified_messages, modified_signature = scheme.change_representation(
                public_key, messages, signature, mu
            )
            self.assertTrue(
                scheme.verify(public_key, modified_messages, modified_signature),
                "Change of representation verification passes",
            )
            modified_messages[-1] = scheme.hash_message("is bad")
            self.assertFalse(
                scheme.verify(public_key, modified_messages, modified_signature),
                "Forgery does not verify",
            )

    def test_underlying_groups(self) -> None:
        """
        Test underlying group properties.
        """
        for scheme in [self.scheme1]:  # Same groups for both signature schemes
            self.assertEqual(
                (scheme.curve.r + 1) * scheme.p,
                scheme.p,
                "ECp group order check passes",
            )
            self.assertEqual(
                (scheme.curve.r + 1) * scheme.phat,
                scheme.phat,
                "ECp2 group order check passes",
            )

    def test_hash(self) -> None:
        """
        Test hash function.
        """
        for scheme in [self.scheme1]:  # Real hash
            self.assertEqual(scheme.hash_message("foo"), scheme.hash_message("foo"))
            self.assertEqual(scheme.hash_message("bar"), scheme.hash_message("bar"))
        for scheme in [self.scheme1, self.scheme2]:
            self.assertNotEqual(scheme.hash_message("foo"), scheme.hash_message("bar"))
            self.assertNotEqual(scheme.hash_message("bar"), scheme.hash_message("baz"))


if __name__ == "__main__":
    unittest.main()
