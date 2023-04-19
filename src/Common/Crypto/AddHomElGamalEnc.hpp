/**
 * @file AddHomElGamalEnc.hpp
 * 
 * @brief
 * @version 0.1
 *
 * Copied and adapted from libscapi ElGamalOnGroupElement.hpp
 */

#pragma once
#include "mid_layer/ElGamalEnc.hpp"
#include "infra/Common.hpp"
#include "primitives/Dlog.hpp"
#include "primitives/DlogOpenSSL.hpp"
#include "primitives/Kdf.hpp"
#include "primitives/PrfOpenSSL.hpp"

/**
 * @brief Class that implements the additive homomorphic 'lifted' ElGamal sheme with various performance improvements and features.
 *
 * @warning For performance issues, at some locations, rerandomizations have been removed.
 * 			Rerandomization is (often) necessary at the end of all homomorphic calculations.
 * 			Overall: Experimental Code, no warranties at all.
 *
 */
class AddHomElGamalEnc : public ElGamalEnc
{
protected:
	/**
	 * ElGamal decrypt function can be optimized if, instead of using the x value in the private key as is,
	 * we change it to be q-x, while q is the dlog group order.
	 * This function computes this changing and saves the new private value as the private key member.
	 * @param privateKey to change.
	 */
	void initPrivateKey(const shared_ptr<ElGamalPrivateKey> &privateKey) override;

	shared_ptr<AsymmetricCiphertext> completeEncryption(const shared_ptr<GroupElement> &c1, GroupElement *hy, Plaintext *plaintext) override;

public:
	AddHomElGamalEnc() {}

	shared_ptr<DlogGroup> getDlog() { return dlog; }
	shared_ptr<PrgFromOpenSSLAES> getRandomGen() { return random; } // Source of randomness
	biginteger getQMinusOne() { return qMinusOne; }
	/**
	 * Constructor that gets a DlogGroup and sets it to the underlying group.
	 * It lets SCAPI choose and source of randomness.
	 * @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	 * @throws SecurityLevelException if the Dlog Group is not DDH secure
	 */
	AddHomElGamalEnc(const shared_ptr<DlogGroup> &dlogGroup, const shared_ptr<PrgFromOpenSSLAES> &random = get_seeded_prg()) : ElGamalEnc(dlogGroup, random) {}

	shared_ptr<AsymmetricCiphertext> encryptWithSecretKey(biginteger &plaintext);

	/**
	 * El-Gamal encryption scheme has a limit of the byte array length to generate a plaintext from.
	 * @return true.
	 */
	bool hasMaxByteArrayLengthForPlaintext() override { return true; }

	/**
	 * Returns the maximum size of the byte array that can be passed to generatePlaintext function.
	 * This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	 */
	int getMaxLengthOfByteArrayForPlaintext() override { return dlog->getMaxLengthOfByteArrayForEncoding(); }

	/**
	 * Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	 * @param text byte array to convert to a Plaintext object.
	 * @throws invalid_argument if the given message's length is greater than the maximum.
	 */
	shared_ptr<Plaintext> generatePlaintext(vector<byte> &text) override;

	/**
	 * Decrypts the given ciphertext using ElGamal encryption scheme.
	 * DOES NOT RETURN THE ORIGINAL PLAINTEXT m BUT g^m.
	 *
	 * @param cipher MUST be of type ElGamalOnGroupElementCiphertext contains the cipher to decrypt.
	 * @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
	 * @throws KeyException if no private key was set.
	 * @throws invalid_argument if the given cipher is not instance of ElGamalOnGroupElementCiphertext.
	 */
	shared_ptr<Plaintext> decrypt(AsymmetricCiphertext *cipher) override;

	/**
	 * Generates a byte array from the given plaintext.
	 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
	 * and therefore he is working on byte array.
	 * @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
	 * @return the byte array generated from the given plaintext.
	 * @throws invalid_argument if the given plaintext is not an instance of GroupElementPlaintext.
	 */
	vector<byte> generateBytesFromPlaintext(Plaintext *plaintext) override;

	shared_ptr<AsymmetricCiphertext> getAdditiveNeutral();

	/**
	 * Receives two ciphertexts and return their addition.
	 * @return the addition result
	 * @throws IllegalStateException if no public key was set.
	 * @throws invalid_argument if the given ciphertexts do not match this asymmetric encryption.
	 */
	shared_ptr<AsymmetricCiphertext> add(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2);

	AsymmetricCiphertext *addPointer(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2);

	/**
	 * Calculates the ciphertext resulting of adding two given ciphertexts.
	 * Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
	 *
	 * There are cases when the random value is used after the function, for example, in sigma protocol.
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user
	 * since this can cause problems when the multiply function is called more than one time.
	 * Instead, we decided to have an additional addition function that gets the random value from the user.
	 *
	 * @throws IllegalStateException if no public key was set.
	 * @throws invalid_argument in the following cases:
	 * 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	 */
	shared_ptr<AsymmetricCiphertext> add(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2, biginteger &r);

	shared_ptr<AsymmetricCiphertext> subtract(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2);

	/**
	 * Receives a cipher and a constant number and returns their multiplication.
	 * @return the multiplication result.
	 * @throws IllegalStateException if no public key was set.
	 * @throws invalid_argument if the given ciphertext does not match this asymmetric encryption.
	 */
	shared_ptr<AsymmetricCiphertext> multByConst(AsymmetricCiphertext *cipher, biginteger &constNumber);

	/**
	 * Receives a cipher and a constant number and returns their multiplication.<p>
	 * There are cases when the random value is used after the function, for example, in sigma protocol.
	 * In these cases the random value should be known to the user. We decided not to have function that return it to the user
	 * since this can cause problems when the multByConst function is called more than one time.
	 * Instead, we decided to have an additional multByConst function that gets the random value from the user.
	 * @param cipher
	 * @param constNumber
	 * @param r The random value to use in the function.
	 * @throws IllegalStateException if no public key was set.
	 * @throws invalid_argument in the following cases:
	 * 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	 */
	shared_ptr<AsymmetricCiphertext> multByConst(AsymmetricCiphertext *cipher, biginteger &constNumber, biginteger &r);

	AsymmetricCiphertext *multByConstPointer(AsymmetricCiphertext *cipher, biginteger &constNumber);

	AsymmetricCiphertext *elementXorByConstPointer(AsymmetricCiphertext *cipher, biginteger &elem);

	shared_ptr<AsymmetricCiphertext> xorByConst(AsymmetricCiphertext *cipher, bool constNumber);

	shared_ptr<AsymmetricCiphertext> homomorphicInnerProduct(vector<AsymmetricCiphertext *> &indexVector, vector<biginteger> &plaintextVector);

	shared_ptr<AsymmetricCiphertext> randomizedEquality(AsymmetricCiphertext *minusCompareElement, AsymmetricCiphertext *secondCompareElement, AsymmetricCiphertext *encryptedZero);

	shared_ptr<AsymmetricCiphertext> randomizedEquality(AsymmetricCiphertext *minusCompareElement, biginteger &plaintext, AsymmetricCiphertext *encryptedZero);

	shared_ptr<AsymmetricCiphertext> indexedRandomizedEquality(vector<AsymmetricCiphertext *> &indexVector, vector<biginteger> &plaintextVector,
															   AsymmetricCiphertext *minusCompareElement, AsymmetricCiphertext *encryptedZero);

	shared_ptr<AsymmetricCiphertext> customIndexedRandomizedEquality(vector<AsymmetricCiphertext *> &indexVector, vector<biginteger> &plaintextVector,
																	 AsymmetricCiphertext *minusCompareElement, AsymmetricCiphertext *encryptedZero, biginteger &randomness);

	bool decryptsToZero(AsymmetricCiphertext *cipher);

	/**
	 * @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	 */
	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(AsymmetricCiphertextSendableData *data) override;

	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(const vector<unsigned char> &data, bool checkMembership = true);

	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(const string &data, bool checkMembership = true);

	AsymmetricCiphertext *reconstructCiphertextPointer(const string &data, bool checkMembership = true);

	AsymmetricCiphertext *reconstructCiphertextPointer(const vector<unsigned char> &data, bool checkMembership = true);
};
