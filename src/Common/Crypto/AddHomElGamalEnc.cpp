/**
 * @file AddHomElGamalEnc.cpp
 * 
 * @version 0.1
 *
 * Copied and adapted from libscapi ElGamalEnc.cpp
 *
 */
#include "AddHomElGamalEnc.hpp"

/**
 * Stores the ElGamal private key. Does not use improvements for decryption which are not benefitial for our protocol.
 * @param privateKey to change.
 */
void AddHomElGamalEnc::initPrivateKey(const shared_ptr<ElGamalPrivateKey> &privateKey)
{
	this->privateKey = privateKey;
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::completeEncryption(const shared_ptr<GroupElement> &c1, GroupElement *hy, Plaintext *plaintext)
{
	auto plain = dynamic_cast<BigIntegerPlainText *>(plaintext);
	if (plain == NULL)
	{
		throw invalid_argument("plaintext should be instance of BigIntegerPlainText");
	}

	// Gets the element.
	auto plainInt = plain->getX();

	// Exponentiate message
	auto msgElement = dlog->exponentiateWithPreComputedValues(dlog->getGenerator(), plainInt);

	auto c2 = dlog->multiplyGroupElements(hy, msgElement.get());

	// Returns an ElGamalCiphertext with c1, c2.
	return make_shared<ElGamalOnGroupElementCiphertext>(c1, c2);
}

/**
 * @brief Method to (slightly) improve encryption performance by using the secret key.
 *
 * @param plaintext to be encrypted
 * @return shared_ptr<AsymmetricCiphertext> of the encrypted plaintext
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::encryptWithSecretKey(biginteger &plaintext)
{

	// Currently not use, random element generation is inefficient
	auto randomEl = dlog->createRandomElement();

	// Exponentiate message
	auto msgElement = dlog->exponentiateWithPreComputedValues(dlog->getGenerator(), plaintext);

	auto vTemp = dlog->exponentiate(randomEl.get(), privateKey->getX());

	auto v = dlog->multiplyGroupElements(msgElement.get(), vTemp.get());

	return make_shared<ElGamalOnGroupElementCiphertext>(randomEl, v);
}

/**
 * Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
 * @param text byte array to convert to a Plaintext object.
 * @throws IllegalArgumentException if the given message's length is greater than the maximum.
 */
shared_ptr<Plaintext> AddHomElGamalEnc::generatePlaintext(vector<byte> &text)
{
	if ((int)text.size() > getMaxLengthOfByteArrayForPlaintext())
	{
		throw invalid_argument("the given text is too big for plaintext");
	}
	std::string s(text.begin(), text.end());
	return make_shared<BigIntegerPlainText>(s);
}

/**
 * Decrypts the given ciphertext using ElGamal encryption scheme.
 * DOES NOT RETURN THE ORIGINAL PLAIN TEXT m BUT g^m
 *
 * @param cipher MUST be of type ElGamalOnGroupElementCiphertext contains the cipher to decrypt.
 * @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
 * @throws KeyException if no private key was set.
 * @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnGroupElementCiphertext.
 */
shared_ptr<Plaintext> AddHomElGamalEnc::decrypt(AsymmetricCiphertext *cipher)
{
	/*
	 * Pseudo-code:
	 * 		Calculate s = ciphertext.getC1() ^ x^(-1)
	 *		Calculate m = ciphertext.getC2() * s
	 */

	// If there is no private key, throws exception.
	if (privateKey == NULL)
	{
		throw KeyException("in order to decrypt a message, this object must be initialized with private key");
	}

	// Ciphertext should be ElGamal ciphertext.
	auto ciphertext = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);
	if (ciphertext == NULL)
	{
		throw invalid_argument("ciphertext should be instance of ElGamalOnGroupElementCiphertext");
	}

	// Calculates sInv = ciphertext.getC1() ^ x.
	auto sInv = dlog->exponentiate(ciphertext->getC1().get(), dlog->getOrder() - privateKey->getX());
	// Calculates the plaintext element m = ciphertext.getC2() * sInv.
	auto m = dlog->multiplyGroupElements(ciphertext->getC2().get(), sInv.get());

	// Creates a plaintext object with the element and returns it.
	return make_shared<GroupElementPlaintext>(m);
}

/**
 * Generates a byte array from the given plaintext.
 * This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
 * and therefore he is working on byte array.
 * @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
 * @return the byte array generated from the given plaintext.
 * @throws IllegalArgumentException if the given plaintext is not an instance of GroupElementPlaintext.
 */
vector<byte> AddHomElGamalEnc::generateBytesFromPlaintext(Plaintext *plaintext)
{

	auto plain = dynamic_cast<BigIntegerPlainText *>(plaintext);
	if (plain == NULL)
	{
		throw invalid_argument("plaintext should be an instance of BigIntegerPlainText");
	}
	string plainString = plain->toString();
	std::vector<byte> v(plainString.begin(), plainString.end());
	return v;
}

/**
 * @brief Simply generates and returns the tuple (g,g^s).
 * 		  Acts as additive neutral element to avoid some if statements.
 * @return shared_ptr<AsymmetricCiphertext>
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::getAdditiveNeutral()
{

	auto u = dlog->getGenerator();
	auto v = dynamic_cast<ElGamalPublicKey *>(getPublicKey().get())->getH();

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

/**
 * Calculates the ciphertext resulting of adding two given ciphertexts.
 * Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
 * @throws IllegalStateException if no public key was set.
 * @throws IllegalArgumentException in the following cases:
 * 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::add(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2)
{

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher1);
	auto c2 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher2);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	if (c1 == NULL || c2 == NULL)
	{
		throw invalid_argument("ciphertexts should be instance of ElGamalCiphertext");
	}

	// Gets the groupElements of the ciphers.
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();
	auto u2 = c2->getC1().get();
	auto v2 = c2->getC2().get();

	// if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)) || !(dlog->isMember(u2)) || !(dlog->isMember(v2)))
	// {
	// 	throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	// }

	// // Check that the r random value passed to this function is in Zq.
	// if (!((r >= 0) && (r <= qMinusOne)))
	// {
	// 	throw invalid_argument("the given random value must be in Zq");
	// }

	// Calculates u = g^w*u1*u2.
	// auto gExpW = dlog->exponentiate(dlog->getGenerator().get(), r);
	// auto gExpWmultU1 = dlog->multiplyGroupElements(gExpW.get(), u1);
	auto u = dlog->multiplyGroupElements(u1, u2);

	// Calculates v = h^w*v1*v2.
	// auto hExpW = dlog->exponentiate(publicKey->getH().get(), r);
	// auto hExpWmultV1 = dlog->multiplyGroupElements(hExpW.get(), v1);
	auto v = dlog->multiplyGroupElements(v1, v2);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

/**
 * @brief adds two ciphertexts together. Returns a simple pointer instead of a shared pointer.
 *
 * @param cipher1
 * @param cipher2
 * @return AsymmetricCiphertext*
 */
AsymmetricCiphertext *AddHomElGamalEnc::addPointer(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2)
{

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher1);
	auto c2 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher2);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	if (c1 == NULL || c2 == NULL)
	{
		throw invalid_argument("ciphertexts should be instance of ElGamalCiphertext");
	}

	// Gets the groupElements of the ciphers.
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();
	auto u2 = c2->getC1().get();
	auto v2 = c2->getC2().get();

	// if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)) || !(dlog->isMember(u2)) || !(dlog->isMember(v2)))
	// {
	// 	throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	// }

	// // Check that the r random value passed to this function is in Zq.
	// if (!((r >= 0) && (r <= qMinusOne)))
	// {
	// 	throw invalid_argument("the given random value must be in Zq");
	// }

	// Calculates u = g^w*u1*u2.
	// auto gExpW = dlog->exponentiate(dlog->getGenerator().get(), r);
	// auto gExpWmultU1 = dlog->multiplyGroupElements(gExpW.get(), u1);
	auto u = dlog->multiplyGroupElements(u1, u2);

	// Calculates v = h^w*v1*v2.
	// auto hExpW = dlog->exponentiate(publicKey->getH().get(), r);
	// auto hExpWmultV1 = dlog->multiplyGroupElements(hExpW.get(), v1);
	auto v = dlog->multiplyGroupElements(v1, v2);

	return new ElGamalOnGroupElementCiphertext(u, v);
}
/**
 * Calculates the ciphertext resulting of adding two given ciphertexts.<P>
 * Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.<p>
 *
 * There are cases when the random value is used after the function, for example, in sigma protocol.
 * In these cases the random value should be known to the user. We decided not to have function that return it to the user
 * since this can cause problems when the addition function is called more than one time.
 * Instead, we decided to have an additional addition function that gets the random value from the user.
 *
 * @throws IllegalStateException if no public key was set.
 * @throws IllegalArgumentException in the following cases:
 * 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
 * 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::add(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2, biginteger &r)
{
	/*
	 * Pseudo-Code:
	 * 	c1 = (u1, v1); c2 = (u2, v2)
	 * 	COMPUTE u = g^w*u1*u2
	 * 	COMPUTE v = h^w*v1*v2
	 * 	OUTPUT c = (u,v)
	 */

	// If there is no public key can not encrypt, throws exception.
	// if (!ElGamalEnc::isKeySet())
	// {
	// 	throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	// }

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher1);
	auto c2 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher2);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	if (c1 == NULL || c2 == NULL)
	{
		throw invalid_argument("ciphertexts should be instance of ElGamalCiphertext");
	}

	// Gets the groupElements of the ciphers.
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();
	auto u2 = c2->getC1().get();
	auto v2 = c2->getC2().get();

	// if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)) || !(dlog->isMember(u2)) || !(dlog->isMember(v2)))
	// {
	// 	throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	// }

	// // Check that the r random value passed to this function is in Zq.
	// if (!((r >= 0) && (r <= qMinusOne)))
	// {
	// 	throw invalid_argument("the given random value must be in Zq");
	// }

	// Calculates u = g^w*u1*u2.
	// auto gExpW = dlog->exponentiate(dlog->getGenerator().get(), r);
	// auto gExpWmultU1 = dlog->multiplyGroupElements(gExpW.get(), u1);
	auto u = dlog->multiplyGroupElements(u1, u2);

	// Calculates v = h^w*v1*v2.
	// auto hExpW = dlog->exponentiate(publicKey->getH().get(), r);
	// auto hExpWmultV1 = dlog->multiplyGroupElements(hExpW.get(), v1);
	auto v = dlog->multiplyGroupElements(v1, v2);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

/**
 * @brief Method to subtract one ciphertext from another.
 *
 * @param cipher1
 * @param cipher2
 * @return shared_ptr<AsymmetricCiphertext> that encrypts cipher1 - cipher2
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::subtract(AsymmetricCiphertext *cipher1, AsymmetricCiphertext *cipher2)
{
	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher1);
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();

	// TODO Performance improvement by unroll
	auto c2 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher2);
	auto u2Inv = dlog->getInverse(c2->getC1().get());
	auto v2Inv = dlog->getInverse(c2->getC2().get());

	auto u = dlog->multiplyGroupElements(u1, u2Inv.get());
	auto v = dlog->multiplyGroupElements(v1, v2Inv.get());
	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

/**
 * Receives a cipher and a constant number and returns their multiplication.
 * @return the multiplication result.
 * @throws IllegalStateException if no public key was set.
 * @throws invalid_argument if the given ciphertext does not match this asymmetric encryption.
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::multByConst(AsymmetricCiphertext *cipher, biginteger &constNumber)
{
	// Highly Simplifies! Normally use additional randomness
	// biginteger w = getRandomInRange(0, qMinusOne, random.get());
	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);

	// Calculates u = u1^c.
	// Call the other function that computes the multiplication.
	auto u = dlog->exponentiate(c1->getC1().get(), constNumber);

	// Calculates v = v1^c.
	auto v = dlog->exponentiate(c1->getC2().get(), constNumber);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

/**
 * Receives a cipher and a constant number and returns their multiplication.<p>
 * There are cases when the random value is used after the function, for example, in sigma protocol.
 * In these cases the random value should be known to the user. We decided not to have function that return it to the user
 * since this can cause problems when the multByConst function is called more than one time.
 * Instead, we decided to have an additional multByConst function that gets the random value from the user.
 * @param cipher
 * @param constNumber
 * @param r The random value to use in the function.
 * @throws NotImplementedException
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::multByConst(AsymmetricCiphertext *cipher, biginteger &constNumber, biginteger &r)
{
	/*
	 * Pseudo-Code:
	 * 	c1 = (u1, v1);
	 * 	COMPUTE u = g^w*u1^c
	 * 	COMPUTE v = h^w*v1^c
	 * 	OUTPUT c = (u,v)
	 */

	// If there is no public key can not encrypt, throws exception.
	// if (!ElGamalEnc::isKeySet())
	// {
	// 	throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	// }

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	// if (c1 == NULL)
	// {
	// 	throw invalid_argument("ciphertext should be instance of ElGamalCiphertext");
	// }

	// Gets the groupElements of the ciphers.
	// auto u1 = c1->getC1().get();
	// auto v1 = c1->getC2().get();

	// if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)))
	// {
	// 	throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	// }

	// Check that the r random value passed to this function is in Zq.
	// if (!((r >= 0) && (r <= qMinusOne)))
	// {
	// 	throw invalid_argument("the given random value must be in Zq");
	// }

	// Calculates u = g^w*u1^c.
	// auto gExpW = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto u = dlog->exponentiate(c1->getC1().get(), constNumber);
	// auto u = dlog->multiplyGroupElements(gExpW.get(), gExpWmultU1.get());

	// Calculates v = h^w*v1^c.
	// auto hExpW = dlog->exponentiate(publicKey->getH().get(), r);
	auto v = dlog->exponentiate(c1->getC2().get(), constNumber);
	// auto v = dlog->multiplyGroupElements(hExpW.get(), hExpWmultV1.get());

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

/**
 * @brief Method to multiply a ciphertext with a plaintext. Returns a pointer instead of a shared pointer.
 *
 * @param cipher
 * @param constNumber
 * @return AsymmetricCiphertext*
 */
AsymmetricCiphertext *AddHomElGamalEnc::multByConstPointer(AsymmetricCiphertext *cipher, biginteger &constNumber)
{

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);

	// Calculates u = g^w*u1^c.
	// auto gExpW = dlog->exponentiate(dlog->getGenerator().get(), r);
	auto u = dlog->exponentiate(c1->getC1().get(), constNumber);
	// auto u = dlog->multiplyGroupElements(gExpW.get(), gExpWmultU1.get());

	// Calculates v = h^w*v1^c.
	// auto hExpW = dlog->exponentiate(publicKey->getH().get(), r);
	auto v = dlog->exponentiate(c1->getC2().get(), constNumber);
	// auto v = dlog->multiplyGroupElements(hExpW.get(), hExpWmultV1.get());

	return new ElGamalOnGroupElementCiphertext(u, v);
}
/**
 * @brief If elem is encrypted, outputs encryption of 0, if 0 is encrypted outputs encryption of elem.
 * 		  Returns simple pointer instead of shared pointer.
 *
 * @param cipher encrypting 0 or 1
 * @param elem
 * @return AsymmetricCiphertext*
 */
AsymmetricCiphertext *AddHomElGamalEnc::elementXorByConstPointer(AsymmetricCiphertext *cipher, biginteger &elem)
{

	// if (!ElGamalEnc::isKeySet())
	// {
	// 	throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	// }

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	// if (c1 == NULL)
	// {
	// 	throw invalid_argument("ciphertext should be instance of ElGamalCiphertext");
	// }

	// Gets the groupElements of the ciphers.
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();

	// if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)))
	// {
	// 	throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	// }

	// Check that the r random value passed to this function is in Zq. (Currently no rerandomization!)
	//  if (!((r >= 0) && (r <=qMinusOne))) {
	//  	throw invalid_argument("the given random value must be in Zq");
	//  }

	std::shared_ptr<GroupElement> add = dlog->exponentiateWithPreComputedValues(dlog->getGenerator(), elem);

	auto u = dlog->getInverse(u1);
	auto v = dlog->multiplyGroupElements(dlog->getInverse(v1).get(), add.get());

	return new ElGamalOnGroupElementCiphertext(u, v);
}

/**
 * @brief If elem is encrypted, outputs encryption of 0, if 0 is encrypted outputs encryption of elem.
 *
 * @param cipher encrypting 0 or 1
 * @param elem
 * @return shared_ptr<AsymmetricCiphertext>
 */
shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::xorByConst(AsymmetricCiphertext *cipher, bool constBool)
{
	// Assume that ciphertext ecrypts 0 or 1

	// if (!ElGamalEnc::isKeySet())
	// {
	// 	throw new IllegalStateException("in order to encrypt a message this object must be initialized with public key");
	// }

	auto c1 = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);

	// Cipher1 and cipher2 should be ElGamal ciphertexts.
	// if (c1 == NULL)
	// {
	// 	throw invalid_argument("ciphertext should be instance of ElGamalCiphertext");
	// }

	// Gets the groupElements of the ciphers.
	auto u1 = c1->getC1().get();
	auto v1 = c1->getC2().get();

	// if (!(dlog->isMember(u1)) || !(dlog->isMember(v1)))
	// {
	// 	throw invalid_argument("GroupElements in the given ciphertexts must be a members in the DlogGroup of type " + dlog->getGroupType());
	// }

	// Check that the r random value passed to this function is in Zq. (Currently no rerandomization!)
	//  if (!((r >= 0) && (r <=qMinusOne))) {
	//  	throw invalid_argument("the given random value must be in Zq");
	//  }

	if (!constBool)
	{
		return make_shared<ElGamalOnGroupElementCiphertext>(c1->getC1(), c1->getC2());
	}

	auto u = dlog->getInverse(u1);
	auto v = dlog->multiplyGroupElements(dlog->getInverse(v1).get(), dlog->getGenerator().get());

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::homomorphicInnerProduct(vector<AsymmetricCiphertext *> &indexVector, vector<biginteger> &plaintextVector)
{

	vector<shared_ptr<GroupElement>> uVector(indexVector.size());
	vector<shared_ptr<GroupElement>> vVector(indexVector.size());

	for (size_t i = 0; i < indexVector.size(); i++)
	{
		auto c = dynamic_cast<ElGamalOnGroupElementCiphertext *>(indexVector[i]);
		// if (c == NULL)
		// {
		// 	throw invalid_argument("ciphertext should be instance of ElGamalCiphertext");
		// }
		uVector[i] = c->getC1();
		vVector[i] = c->getC2();
	}

	auto u = dlog->simultaneousMultipleExponentiations(uVector, plaintextVector);
	auto v = dlog->simultaneousMultipleExponentiations(vVector, plaintextVector);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::randomizedEquality(AsymmetricCiphertext *minusCompareElement, AsymmetricCiphertext *secondCompareElement, AsymmetricCiphertext *encryptedZero)
{

	biginteger r = getRandomInRange(1, qMinusOne, random.get());

	auto ciphertext = add(minusCompareElement, secondCompareElement);
	ciphertext = add(ciphertext.get(), encryptedZero);
	return multByConst(ciphertext.get(), r);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::randomizedEquality(AsymmetricCiphertext *minusCompareElement, biginteger &plaintext, AsymmetricCiphertext *encryptedZero)
{
	auto c = dynamic_cast<ElGamalOnGroupElementCiphertext *>(minusCompareElement);

	biginteger r = getRandomInRange(1, qMinusOne, random.get());

	auto gExpPlain = dlog->exponentiateWithPreComputedValues(dlog->getGenerator(), plaintext);
	auto vTemp = dlog->multiplyGroupElements(gExpPlain.get(), c->getC2().get());
	auto v = dlog->exponentiate(vTemp.get(), r);
	auto u = dlog->exponentiate(c->getC1().get(), r);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::indexedRandomizedEquality(vector<AsymmetricCiphertext *> &indexVector,
																			 vector<biginteger> &plaintextVector,
																			 AsymmetricCiphertext *minusCompareElement,
																			 AsymmetricCiphertext *encryptedZero)
{
	auto indexedElement = homomorphicInnerProduct(indexVector, plaintextVector);

	return randomizedEquality(indexedElement.get(), minusCompareElement, encryptedZero);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::customIndexedRandomizedEquality(vector<AsymmetricCiphertext *> &indexVector,
																				   vector<biginteger> &plaintextVector,
																				   AsymmetricCiphertext *minusCompareElement,
																				   AsymmetricCiphertext *encryptedZero,
																				   biginteger &randomness)
{

	vector<shared_ptr<GroupElement>> uVector(indexVector.size() + 2);
	vector<shared_ptr<GroupElement>> vVector(indexVector.size() + 2);

	for (size_t i = 0; i < indexVector.size(); i++)
	{
		auto c = dynamic_cast<ElGamalOnGroupElementCiphertext *>(indexVector[i]);
		// if (c == NULL)
		// {
		// 	throw invalid_argument("ciphertext should be instance of ElGamalCiphertext");
		// }
		uVector[i] = c->getC1();
		vVector[i] = c->getC2();
	}

	auto minComp = dynamic_cast<ElGamalOnGroupElementCiphertext *>(minusCompareElement);
	uVector[indexVector.size()] = minComp->getC1();
	vVector[indexVector.size()] = minComp->getC2();
	plaintextVector.push_back(randomness);

	auto precMask = dynamic_cast<ElGamalOnGroupElementCiphertext *>(encryptedZero);
	uVector[indexVector.size() + 1] = precMask->getC1();
	vVector[indexVector.size() + 1] = precMask->getC2();
	plaintextVector.push_back(1);

	auto u = dlog->simultaneousMultipleExponentiations(uVector, plaintextVector);
	auto v = dlog->simultaneousMultipleExponentiations(vVector, plaintextVector);

	return make_shared<ElGamalOnGroupElementCiphertext>(u, v);
}

bool AddHomElGamalEnc::decryptsToZero(AsymmetricCiphertext *cipher)
{

	auto c = dynamic_cast<ElGamalOnGroupElementCiphertext *>(cipher);
	// if (c == NULL)
	// {
	// 	throw invalid_argument("ciphertext should be instance of ElGamalCiphertext");
	// }
	auto compCipher = dlog->exponentiate(c->getC1().get(), privateKey->getX());

	return (c->getC2()->operator==(*(compCipher.get())));
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::reconstructCiphertext(AsymmetricCiphertextSendableData *data)
{
	auto data1 = dynamic_cast<ElGamalOnGrElSendableData *>(data);
	if (data1 == NULL)
		throw invalid_argument("The input data has to be of type ElGamalOnGrElSendableData");

	auto cipher1 = dlog->reconstructElement(true, data1->getCipher1().get());
	auto cipher2 = dlog->reconstructElement(true, data1->getCipher2().get());
	return make_shared<ElGamalOnGroupElementCiphertext>(cipher1, cipher2);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::reconstructCiphertext(const vector<unsigned char> &byteVector, bool checkMembership)
{
	const byte *uc = &(byteVector[0]);
	std::string s(reinterpret_cast<char const *>(uc), byteVector.size());
	return reconstructCiphertext(s, checkMembership);
}

shared_ptr<AsymmetricCiphertext> AddHomElGamalEnc::reconstructCiphertext(const string &data, bool checkMembership)
{
	AsymmetricCiphertext *cipherText = reconstructCiphertextPointer(data, checkMembership);
	return shared_ptr<AsymmetricCiphertext>(cipherText);
}

AsymmetricCiphertext *AddHomElGamalEnc::reconstructCiphertextPointer(const string &data, bool checkMembership)
{
	auto str_vec = explode(data, ':');
	if (str_vec.size() == 2)
	{
		throw new NotImplementedException("Error reconstruct this type of ciphertext not implemented");
	}

	biginteger u1 = biginteger(str_vec[0]);
	biginteger u2 = biginteger(str_vec[1]);
	vector<biginteger> u{u1, u2};

	biginteger v1 = biginteger(str_vec[2]);
	biginteger v2 = biginteger(str_vec[3]);
	vector<biginteger> v{v1, v2};

	shared_ptr<GroupElement> c1 = dlog->generateElement(checkMembership, u);
	shared_ptr<GroupElement> c2 = dlog->generateElement(checkMembership, v);
	return new ElGamalOnGroupElementCiphertext(c1, c2);
}

AsymmetricCiphertext *AddHomElGamalEnc::reconstructCiphertextPointer(const vector<unsigned char> &byteVector, bool checkMembership)
{
	const byte *uc = &(byteVector[0]);
	std::string s(reinterpret_cast<char const *>(uc), byteVector.size());
	return reconstructCiphertextPointer(s, checkMembership);
}