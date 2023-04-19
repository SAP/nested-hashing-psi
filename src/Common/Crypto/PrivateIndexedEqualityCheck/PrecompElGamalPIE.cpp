/**
 * @file PrecompElGamalPIE.hpp
 * 
 * @version 0.1
 *
 *
 */
#include "PrecompElGamalPIE.hpp"

PrecompElGamalPIE::PrecompElGamalPIE(AddHomElGamalEnc &cryptor, CuckooHashTable &ct) : HIPPIE(ct, ct.getBinSize() * ct.getNumberOfHashFunctions() + ct.stash.size()),
                                                                                       cryptor(cryptor)
{

    shared_ptr<Plaintext> plainZero = make_shared<BigIntegerPlainText>(0);
    encryptedZeros = vector<shared_ptr<AsymmetricCiphertext>>(numberOfResultElements);
    for (uint i = 0; i < numberOfResultElements; i++)
    {
        encryptedZeros[i] = cryptor.encrypt(plainZero);
    }

    // Ugly
    encryptedMessageMatrix = vector<vector<vector<AsymmetricCiphertext *>>>(ct.getNumberOfHashFunctions(),
                                                                            vector<vector<AsymmetricCiphertext *>>(ct.cuckooTable[0].size(),
                                                                                                                   vector<AsymmetricCiphertext *>(ct.cuckooTable[0][0].size())));

    negatedMessageMatrix = vector<vector<vector<AsymmetricCiphertext *>>>(ct.getNumberOfHashFunctions(),
                                                                          vector<vector<AsymmetricCiphertext *>>(ct.cuckooTable[0].size(),
                                                                                                                 vector<AsymmetricCiphertext *>(ct.cuckooTable[0][0].size())));
}

void PrecompElGamalPIE::precomp()
{

    if (indexMatrix.size() == 0)
    {

        throw logic_error("Index Matrix not set when try to precompute.");
    }

    // Exponentiate indexVector
    for (size_t i = 0; i < indexMatrix.size(); i++)
    {

        for (size_t j = 0; j < indexMatrix[i].size(); j++)
        {

            for (size_t k = 0; k < ct.getBinSize(); k++)
            {

                encryptedMessageMatrix[i][k][j] = cryptor.multByConstPointer(indexMatrix[i][j], ct.cuckooTable[ct.getTableIndex(i)][k][j]);
                negatedMessageMatrix[i][k][j] = cryptor.elementXorByConstPointer(encryptedMessageMatrix[i][k][j], ct.cuckooTable[ct.getTableIndex(i)][k][j]);
            }
        }
    }
};

void PrecompElGamalPIE::setBitVector(boost::dynamic_bitset<unsigned char> &&xorVector)
{
    this->xorVector = xorVector;
}

void PrecompElGamalPIE::run()
{

    int resultIndex = 0;
    int bitVectorIndex = 0;
    for (uint hfInd = 0; hfInd < ct.getNumberOfHashFunctions(); hfInd++)
    {

        for (size_t binIndex = 0; binIndex < ct.cuckooTable[ct.getTableIndex(hfInd)].size(); binIndex++)
        {
#ifdef CHECKED
            assert(indexMatrix[hfInd].size() == ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex].size());
#endif

            // Result elem init
            AsymmetricCiphertext *addUp;
            if (xorVector[bitVectorIndex])
            {
                addUp = negatedMessageMatrix[hfInd][binIndex][0];
            }
            else
            {
                addUp = encryptedMessageMatrix[hfInd][binIndex][0];
            }
            bitVectorIndex++;
            for (uint i = 1; i < ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex].size(); i++)
            {
                if (xorVector[bitVectorIndex])
                {
                    addUp = cryptor.addPointer(addUp, negatedMessageMatrix[hfInd][binIndex][i]);
                }
                else
                {
                    addUp = cryptor.addPointer(addUp, encryptedMessageMatrix[hfInd][binIndex][i]);
                }

                // Clean
                // delete negatedMessageMatrix[hfInd][binIndex][i];
                // delete encryptedMessageMatrix[hfInd][binIndex][i];

                bitVectorIndex++;
            }
            shuffledResultList[permutationVector[resultIndex]] = cryptor.randomizedEquality(minusCompareElement, addUp,
                                                                                            encryptedZeros[resultIndex].get());
            // important
            resultIndex++;
        }
    }

    for (uint stashInd = 0; stashInd < ct.stash.size(); stashInd++)
    {
        shuffledResultList[permutationVector[resultIndex]] = cryptor.randomizedEquality(minusCompareElement, ct.stash[stashInd],
                                                                                        encryptedZeros[resultIndex].get());
        // important
        resultIndex++;
    }
}
