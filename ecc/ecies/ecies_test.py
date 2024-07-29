import base64
import unittest
from ecies import decrypt, ECIES_CONFIG


class TestStringMethods(unittest.TestCase):
    def test_secp256k1_aes256gcm_12bit_nonce_sha256_hkdf(self):
        ECIES_CONFIG.symmetric_nonce_length = 16
        ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
        secp_k = '8d5a6fe64ceda8b818836c6bdbd7a3430da9f2f9ec8d5b2e7f692e1a2f15c3b6'

        ciphertext = base64.b64decode('BL0d+HM4gQi8l1PO7bYl2pBK+CbO+gCNHFk2cmSi/cD9OTrdBiuQazCiDzfPkw7gEIVoP3Txj+hVqr' +
                                      '+r7Hik5bOLD9qQ+nbfJPtcjGrJotN/ufZhfeQCR45Ku338DJMhlYzJw2uDwVF6QH4swg==')

        self.assertEqual(decrypt(secp_k, ciphertext), b'hello world!')


if __name__ == '__main__':
    unittest.main()
