import unittest
from typing import List, Tuple

from delegatable_anon_cred_scheme import DelegatableAnonCredScheme


class TestDelegatableAnonCredScheme(unittest.TestCase):
    """
    Unit tests for the Delegatable Anonymous Credential Scheme.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """
        Set up instances of DelegatableAnonCredScheme for testing.
        """
        cls.scheme1: DelegatableAnonCredScheme = DelegatableAnonCredScheme(2)
        cls.scheme2: DelegatableAnonCredScheme = DelegatableAnonCredScheme(3)
        cls.scheme3: DelegatableAnonCredScheme = DelegatableAnonCredScheme(4)

    def test_credential_chain(self) -> None:
        """
        Test the credential chain generation and verification.
        """
        for scheme in [self.scheme1, self.scheme2, self.scheme3]:

            # User 1 generates keys, nyms, and gets on the credential chain
            even_keys1: Tuple[List[int], List[int]] = scheme.key_gen()
            odd_keys1: Tuple[List[int], List[int]] = scheme.key_gen()
            (nym_even1, sk_even1), (nym_odd1, sk_odd1) = scheme.nym_gen(
                *even_keys1, *odd_keys1
            )
            cred_chain: Tuple[List[List[int]], List[Tuple[int, int, int]]] = (
                scheme.issue_first(nym_odd1)
            )
            self.assertTrue(scheme.verify_chain(cred_chain), "User 1 verification")

            # User 2 generates keys, nyms, and gets on the credential chain
            even_keys2: Tuple[List[int], List[int]] = scheme.key_gen()
            odd_keys2: Tuple[List[int], List[int]] = scheme.key_gen()
            (nym_even2, sk_even2), (nym_odd2, sk_odd2) = scheme.nym_gen(
                *even_keys2, *odd_keys2
            )
            cred_chain = scheme.issue_next(cred_chain, nym_even2, sk_odd1)
            self.assertTrue(scheme.verify_chain(cred_chain), "User 2 verification")

            # User 3 generates keys, nyms, and gets on the credential chain
            even_keys3: Tuple[List[int], List[int]] = scheme.key_gen()
            odd_keys3: Tuple[List[int], List[int]] = scheme.key_gen()
            (nym_even3, sk_even3), (nym_odd3, sk_odd3) = scheme.nym_gen(
                *even_keys3, *odd_keys3
            )
            cred_chain = scheme.issue_next(cred_chain, nym_odd3, sk_even2)
            self.assertTrue(scheme.verify_chain(cred_chain), "User 3 verification")

            # User 4 generates keys, nyms, and gets on the credential chain
            even_keys4: Tuple[List[int], List[int]] = scheme.key_gen()
            odd_keys4: Tuple[List[int], List[int]] = scheme.key_gen()
            (nym_even4, sk_even4), (nym_odd4, sk_odd4) = scheme.nym_gen(
                *even_keys4, *odd_keys4
            )
            cred_chain = scheme.issue_next(cred_chain, nym_even4, sk_odd3)
            self.assertTrue(scheme.verify_chain(cred_chain), "User 4 verification")

            # User 5 generates keys, nyms, and gets on the credential chain
            even_keys5: Tuple[List[int], List[int]] = scheme.key_gen()
            odd_keys5: Tuple[List[int], List[int]] = scheme.key_gen()
            (nym_even5, sk_even5), (nym_odd5, sk_odd5) = scheme.nym_gen(
                *even_keys5, *odd_keys5
            )
            cred_chain = scheme.issue_next(cred_chain, nym_odd5, sk_even4)
            self.assertTrue(scheme.verify_chain(cred_chain), "User 5 verification")


if __name__ == "__main__":
    unittest.main()
