/**
 * @file ElGamalPSIClient.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "src/Client/PSIClient.hpp"
#include "src/Common/Hashing/CuckooHashTable.hpp"
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "src/Common/Parameter/HashTableParameter.hpp"
/**
 * @brief Abstract class for PSI client implementations based on the additive 'lifted' ElGamal sheme on elliptic curve groups.
 *        Separates code that is used by all concrete ElGamal-based PSI client classes.
 */
class ElGamalPSIClient : public PSIClient
{

protected:
    const HashTableParameter &htParams;
    shared_ptr<CuckooHashTable> clientHashTable;
    shared_ptr<DlogEllipticCurve> dlog;
    AddHomElGamalEnc encryptor;
    TabulationHashing hashfunction;

    // vector to store the encrypted elements during the offline phase
    vector<vector<shared_ptr<AsymmetricCiphertext>>> encryptedCuckooTable;

    // The number of elements to decrypt per cuckoo table position
    int resultSize;

    ElGamalPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams, string protocolName)
        : PSIClient(dataIH, clientParams, protocolName + clientParams.curveName), htParams(htParams)
    {
    }

    void setUpElGamalPSI()
    {

        // Choose right NIST curve from OpenSSL
        if (clientParams.curveName[0] == 'P')
        {
            dlog = make_shared<OpenSSLDlogECFp>(OpenSSLCurveDir, clientParams.curveName);
        }
        else if (clientParams.curveName[0] == 'B' or clientParams.curveName[0] == 'K')
        {
            dlog = make_shared<OpenSSLDlogECF2m>(OpenSSLCurveDir, clientParams.curveName);
        }
        else
        {
            throw invalid_argument("Cannot find curveName");
        }

        encryptor = AddHomElGamalEnc(dlog);
        resultSize = htParams.maxItemsPerPosition * htParams.numberOfCuckooHashFunctions + htParams.serverStashSize;

        // number of needed hashfunctions
        uint64_t neededHfs = htParams.numberOfSimpleHashFunctions + htParams.numberOfCuckooHashFunctions;
        hashfunction = TabulationHashing(clientParams.hashSeed, neededHfs);

        // Cuckoo hashing uses Hashfunctions indexed by [0,htParams.numberOfCuckooHashFunctions)
        uint startingHashId = 0;

        // Assume client stash to be zero
        uint64_t maxStashSize = 0;

        clientHashTable = make_shared<CuckooHashTable>(hashfunction,
                                                       htParams.eachSimpleTableSize, htParams.numberOfSimpleHashFunctions, startingHashId, maxStashSize,
                                                       htParams.simpleMultiTable);

        pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> pair = encryptor.generateKey();
        encryptor.setKey(pair.first, pair.second);
#ifdef VERBOSE
        cout << "Send public key to server" << endl;
#endif
        sendPublicKey(pair.first);
    }

    void sendPublicKey(shared_ptr<PublicKey> &publicKey)
    {
        string pk = ((ElGamalPublicKey *)(publicKey.get()))->generateSendableData()->toString();
        channel->writeWithSize(pk);
    }

    void sendMinusCompareElement(shared_ptr<AsymmetricCiphertext> &minusEncryptedElement)
    {
        string cipherTextString = minusEncryptedElement->generateSendableData()->toString();
        channel->writeWithSize(cipherTextString);
    }

    /**
     * @brief Method that receives the server result for one cuckoo table position.
     *        Avoids decryption if element has already been found.
     *
     * @return true if element is in the client set
     * @return false otherwise
     */
    bool receiveResult()
    {
        bool found = false;

        for (int i = 0; i < resultSize; i++)
        {
            vector<unsigned char> cipherVector;
            channel->readWithSizeIntoVector(cipherVector);
            if (!found)
            {
                auto cipherText = encryptor.reconstructCiphertext(cipherVector, false);
                if (encryptor.decryptsToZero(cipherText.get()))
                {
                    found = true;
                }
            }
        }
        return found;
    }
};