/**
 * @file ElGamalPIE.cpp
 * 
 * @brief
 * @version 0.1
 * @date 2022-05-24
 *
 *
 */

#include "ElGamalPIE.hpp"

#ifndef CHECKED
#define CHECKED
#endif

ElGamalPIE::ElGamalPIE(AddHomElGamalEnc &cryptor,
                       CuckooHashTable &ct) : HIPPIE(ct, ct.getBinSize() * ct.getNumberOfHashFunctions() + ct.stash.size()), cryptor(cryptor)
{

    shared_ptr<Plaintext> plainZero = make_shared<BigIntegerPlainText>(0);
    encryptedZeros = vector<shared_ptr<AsymmetricCiphertext>>(numberOfResultElements);
    for (uint i = 0; i < numberOfResultElements; i++)
    {
        encryptedZeros[i] = cryptor.encrypt(plainZero);
    }

    if (precalcRandom)
    {
        randomness = vector<vector<biginteger>>(ct.getNumberOfHashFunctions(),
                                                vector<biginteger>(ct.getBinSize()));

        if (!ct.hasMultipleTables())
        {
            throw invalid_argument("Error, precalc PIE randomness only supported for simple multi tables.");
        }
        for (uint hfInd = 0; hfInd < ct.getNumberOfHashFunctions(); hfInd++)
        {

            for (size_t binIndex = 0; binIndex < ct.getBinSize(); binIndex++)
            {
                randomness[hfInd][binIndex] = getRandomInRange(1, cryptor.getQMinusOne(), cryptor.getRandomGen().get());

                for (size_t itemIndex = 0; itemIndex < ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex].size(); itemIndex++)
                {

                    ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex][itemIndex] =
                        (ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex][itemIndex] * randomness[hfInd][binIndex]) % cryptor.getDlog()->getOrder();
                }
            }
        }
    }
}

void ElGamalPIE::run()
{
    int resultIndex = 0;
    for (uint hfInd = 0; hfInd < ct.getNumberOfHashFunctions(); hfInd++)
    {

        for (size_t binIndex = 0; binIndex < ct.cuckooTable[ct.getTableIndex(hfInd)].size(); binIndex++)
        {
#ifdef CHECKED
            assert(indexMatrix[hfInd].size() == ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex].size());
#endif
            if (precalcRandom)
            {

                auto &randomn = randomness[hfInd][binIndex];
                shuffledResultList[permutationVector[resultIndex]] = cryptor.customIndexedRandomizedEquality(indexMatrix[hfInd],
                                                                                                             ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex],
                                                                                                             minusCompareElement, encryptedZeros[resultIndex].get(), randomn);
            }
            else
            {
                shuffledResultList[permutationVector[resultIndex]] = cryptor.indexedRandomizedEquality(indexMatrix[hfInd],
                                                                                                       ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex],
                                                                                                       minusCompareElement, encryptedZeros[resultIndex].get());
                // important
            }
            resultIndex++;
        }
    }

    for (uint stashInd = 0; stashInd < ct.stash.size(); stashInd++)
    {
        shuffledResultList[permutationVector[resultIndex]] = cryptor.randomizedEquality(minusCompareElement, ct.stash[stashInd], encryptedZeros[resultIndex].get());
        // important
        resultIndex++;
    }
}