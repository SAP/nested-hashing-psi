/**
 * @file SimpleElGamalPSIClient.cpp
 * 
 * @version 0.1
 *
 */
#include "SimpleElGamalPSIClient.hpp"

SimpleElGamalPSIClient::SimpleElGamalPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams) : ElGamalPSIClient(dataIH, clientParams, htParams, protocolName())
{
}
void SimpleElGamalPSIClient::runSetUpPhase()
{

    setUpElGamalPSI();
}
void SimpleElGamalPSIClient::runOfflinePhase()
{

    clientHashTable->insertAll(clientSet);

    encryptedCuckooTable = vector<vector<shared_ptr<AsymmetricCiphertext>>>(clientHashTable->getNumberOfTables(),
                                                                            vector<shared_ptr<AsymmetricCiphertext>>(htParams.eachSimpleTableSize));

    encryptedCuckooIndexMatrices = vector<vector<indexVectorType *>>(clientHashTable->getNumberOfTables(),
                                                                     vector<indexVectorType *>(htParams.eachSimpleTableSize));

    // Iterate over all cuckoo table entries, assumes bin size is 1 (second cuckoo table axis)
    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            biginteger &currentElem = clientHashTable->cuckooTable[i][0][j];
            // Encrypt Element
            shared_ptr<BigIntegerPlainText> elemPlain;
            if (currentElem == 0)
            {
                elemPlain = make_shared<BigIntegerPlainText>("1");
            }
            else
            {
                elemPlain = make_shared<BigIntegerPlainText>(-currentElem);
            }
            encryptedCuckooTable[i][j] = encryptor.encrypt(elemPlain);

            // Create Index Vector
            encryptedCuckooIndexMatrices[i][j] = generateIndexMatrix(currentElem);
        }
    }
}
void SimpleElGamalPSIClient::runOnlinePhase()
{
    // Iterate over all cuckoo table entries, assumes bin size is 1 (second cuckoo table axis)
    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            sendIndexMatrix(encryptedCuckooIndexMatrices[i][j]);

            sendMinusCompareElement(encryptedCuckooTable[i][j]);
        }
    }
    // Iterate over all cuckoo table entries, assumes bin size is 1 (second cuckoo table axis)
    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            bool included = receiveResult();

            if (included)
            {
                intersectionCalculated.push_back(clientHashTable->cuckooTable[i][0][j]);
            }
        }
    }
}

/**
 * @brief Generate encrypted PIE index matrix. Enc(1) at the correct positions, Enc(0) otherwise.
 *
 * @param element for which the encrypted PIE index vectors shall be created
 * @return indexVectorType* Pointer to the encrypted index vector
 */
indexVectorType *SimpleElGamalPSIClient::generateIndexMatrix(biginteger &element)
{
    indexVectorType *indexMatrix = new indexVectorType(htParams.numberOfCuckooHashFunctions,
                                                       vector<shared_ptr<AsymmetricCiphertext>>(htParams.eachCuckooTableSize));
    shared_ptr<BigIntegerPlainText> plainOne = make_shared<BigIntegerPlainText>("1");
    shared_ptr<BigIntegerPlainText> plainZero = make_shared<BigIntegerPlainText>("0");

    for (uint hfInd = 0; hfInd < htParams.numberOfCuckooHashFunctions; hfInd++)
    {
        uint_fast64_t hashIndex = calculateHashIndex(hashfunction, element, hfInd + htParams.numberOfSimpleHashFunctions, htParams.eachCuckooTableSize);

        for (uint64_t vectorIndex = 0; vectorIndex < htParams.eachCuckooTableSize; vectorIndex++)
        {
            shared_ptr<BigIntegerPlainText> plain;
            if (vectorIndex == hashIndex)
            {
                plain = plainOne;
            }
            else
            {
                plain = plainZero;
            }
            shared_ptr<AsymmetricCiphertext> encryptedIndex = encryptor.encrypt(plain);
            (*indexMatrix)[hfInd][vectorIndex] = encryptedIndex;
        }
    }
    return indexMatrix;
}

/**
 * @brief Sends a previously generated encrypted PIE index matrix to the server.
 *
 * @todo Consider clean up of the matrix
 * @param indexMatrix to send
 */
void SimpleElGamalPSIClient::sendIndexMatrix(indexVectorType *indexMatrix)
{

    for (size_t i = 0; i < indexMatrix->size(); i++)
    {
        for (size_t j = 0; j < (*indexMatrix)[i].size(); j++)
        {

            string cipherTextString = (*indexMatrix)[i][j]->generateSendableData()->toString();
            channel->writeWithSize(cipherTextString);
        }
    }
}
