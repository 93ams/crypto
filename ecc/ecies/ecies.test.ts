import { describe, expect, test } from "bun:test"
import { decrypt, PrivateKey, ECIES_CONFIG } from 'eciesjs'

describe("ECIES", () => {
	test("secp256k1 with, aes-256-gcm 12 bit nonce, and hkdf-sha256", () => {
		ECIES_CONFIG.ellipticCurve = "secp256k1"
		ECIES_CONFIG.symmetricAlgorithm = "aes-256-gcm"
		ECIES_CONFIG.symmetricNonceLength = 16

		const ciphertext = Buffer.from('BL0d+HM4gQi8l1PO7bYl2pBK+CbO+gCNHFk2cmSi/cD9OTrdBiuQazCiDzfPkw7gEIVoP3Txj+hVqr' +
			'+r7Hik5bOLD9qQ+nbfJPtcjGrJotN/ufZhfeQCR45Ku338DJMhlYzJw2uDwVF6QH4swg==', "base64")
		const pk = PrivateKey.fromHex("8d5a6fe64ceda8b818836c6bdbd7a3430da9f2f9ec8d5b2e7f692e1a2f15c3b6")
		expect(decrypt(pk.secret, ciphertext).toString()).toBe("hello world!")
	})
})