/**
 * @file PrecompElGamalPSIClient.cpp
 * 
 * @version 0.1
 *
 */
#include "PrecompElGamalPSIClient.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "primitives/Prg.hpp"
#include "boost/dynamic_bitset.hpp"

PrecompElGamalPSIClient::PrecompElGamalPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams)
    : ElGamalPSIClient(dataIH, clientParams, htParams, protocolName())
{
}

void PrecompElGamalPSIClient::runSetUpPhase()
{
    // Set up OpenSSL ECC lifted ElGamal specific stuff.
    setUpElGamalPSI();

    prg = PrgFromOpenSSLAES();
    prgSecretKey = prg.generateKey(128); // fixed key size 128bit
    prg.setKey(prgSecretKey);

    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {
            // Create AND Send Random Index Vector
            createAndSendRandomIndexMatrix();
        }
    }
}

void PrecompElGamalPSIClient::runOfflinePhase()
{

    clientHashTable->insertAll(clientSet);

    encryptedCuckooTable = vector<vector<shared_ptr<AsymmetricCiphertext>>>(clientHashTable->getNumberOfTables(),
                                                                            vector<shared_ptr<AsymmetricCiphertext>>(htParams.eachSimpleTableSize));
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
                elemPlain = make_shared<BigIntegerPlainText>(1);
            }
            else
            {
                elemPlain = make_shared<BigIntegerPlainText>(-currentElem);
            }
            encryptedCuckooTable[i][j] = encryptor.encrypt(elemPlain);
        }
    }
}
void PrecompElGamalPSIClient::runOnlinePhase()
{
    prg.setKey(prgSecretKey); // Reset PRG

    // Iterate over all cuckoo table entries, assumes bin size is 1 (second cuckoo table axis)
    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            createAndSendPlainBitvector(clientHashTable->cuckooTable[i][0][j]);

            sendMinusCompareElement(encryptedCuckooTable[i][j]);
        }
    }

    // Iterate over all cuckoo table entries, assumes bin size is 1 (second cuckoo table axis), receive PIE result
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
 * @brief Method to send encrypted index vectors (zeroes or ones) to the server.
 *
 */
void PrecompElGamalPSIClient::createAndSendRandomIndexMatrix()
{
    shared_ptr<BigIntegerPlainText> plainOne = make_shared<BigIntegerPlainText>("1");
    shared_ptr<BigIntegerPlainText> plainZero = make_shared<BigIntegerPlainText>("0");

    size_t randomVectorSize = (htParams.numberOfCuckooHashFunctions * htParams.eachCuckooTableSize + 7) / 8; // Round up to bytes
    vector<byte> randomBits(randomVectorSize);
    prg.getPRGBytes(randomBits, 0, randomVectorSize);
    boost::dynamic_bitset<byte> mbitset(randomBits.begin(), randomBits.end());
    for (uint hfInd = 0; hfInd < htParams.numberOfCuckooHashFunctions; hfInd++)
    {
        for (uint64_t vectorIndex = 0; vectorIndex < htParams.eachCuckooTableSize; vectorIndex++)
        {
            shared_ptr<BigIntegerPlainText> plain;
            if (mbitset[hfInd * htParams.eachCuckooTableSize + vectorIndex])
            {
                plain = plainOne;
            }
            else
            {
                plain = plainZero;
            }
            shared_ptr<AsymmetricCiphertext> encryptedIndex = encryptor.encrypt(plain);
            channel->writeWithSize(encryptedIndex->generateSendableData()->toString());
        }
    }
}

/**
 * @brief Method to send plain index vectors (zeroes and ones) to the server.
 *        XOR between sent encrypted and plain bit vectors are zero except the indexed positions which is are one.
 */
void PrecompElGamalPSIClient::createAndSendPlainBitvector(biginteger &element)
{

    size_t randomVectorSize = (htParams.numberOfCuckooHashFunctions * htParams.eachCuckooTableSize + 7) / 8; // Round up to bytes
    vector<byte> randomBits(randomVectorSize);
    prg.getPRGBytes(randomBits, 0, randomVectorSize);
    boost::dynamic_bitset<byte> mbitset(randomBits.begin(), randomBits.end());
    // Flip correct bits
    for (uint hfInd = 0; hfInd < htParams.numberOfCuckooHashFunctions; hfInd++)
    {
        uint_fast64_t hashIndex = calculateHashIndex(hashfunction, element, hfInd + htParams.numberOfSimpleHashFunctions, htParams.eachCuckooTableSize);
        mbitset[hfInd * htParams.eachCuckooTableSize + hashIndex].flip();
    }
    to_block_range(mbitset, randomBits.begin());
    string sendS(randomBits.begin(), randomBits.end());
    channel->writeWithSize(sendS);
}