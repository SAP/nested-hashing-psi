/**
 * @file ElGamalPSIServer.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "../PSIServer.hpp"
#include "src/Common/Hashing/HierarchicalCuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/PIECollection.hpp"
#include "src/Common/Parameter/HashTableParameter.hpp"

class ElGamalPSIServer : public PSIServer
{

protected:
    const HashTableParameter &htParams;
    shared_ptr<HierarchicalCuckooHashTable> serverHashTable;
    shared_ptr<DlogGroup> dlog;
    AddHomElGamalEnc encryptor;
    TabulationHashing hashfunction;
    vector<boost::thread *> threadsPIE;
    size_t nPiesToHandle;
    size_t piesPerCollection;

    ElGamalPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams,
                     HashTableParameter &htParams, std::string protocolName) : PSIServer(dataIH, serverParams, protocolName + "ElGamal-" + serverParams.curveName),
                                                                               htParams(htParams)
    {
    }

    shared_ptr<DlogGroup> createDlogGroup()
    {
        if (serverParams.curveName[0] == 'P')
        {
            return make_shared<OpenSSLDlogECFp>(OpenSSLCurveDir, serverParams.curveName);
        }
        else if (serverParams.curveName[0] == 'B' or serverParams.curveName[0] == 'K')
        {
            return make_shared<OpenSSLDlogECF2m>(OpenSSLCurveDir, serverParams.curveName);
        }
        else
        {
            throw invalid_argument("Cannot find curve: " + serverParams.curveName);
        }
    }

    void setUpElGamalPSI()
    {
        dlog = createDlogGroup();
        encryptor = AddHomElGamalEnc(dlog);
        uint64_t neededHfs = htParams.numberOfSimpleHashFunctions + htParams.numberOfCuckooHashFunctions;
        hashfunction = TabulationHashing(serverParams.hashSeed, neededHfs);

        if (serverParams.numberOfThreads < 1)
        {
            throw invalid_argument("Number of threads need to be larger than 0");
        }
#ifdef VERBOSE
        cout << "Receive public key from client" << endl;
#endif
        receiveAndSetPublicKey();

        serverHashTable = make_shared<HierarchicalCuckooHashTable>(hashfunction,
                                                                   htParams.eachSimpleTableSize, htParams.eachCuckooTableSize,
                                                                   htParams.serverStashSize, htParams.numberOfSimpleHashFunctions,
                                                                   htParams.numberOfCuckooHashFunctions, htParams.simpleMultiTable,
                                                                   htParams.cuckooMultiTable, htParams.maxItemsPerPosition);

        threadsPIE = vector<boost::thread *>(serverParams.numberOfThreads);

        nPiesToHandle = serverHashTable->getNumberOfSimpleTables() * serverHashTable->getEachSimpleTableSize();

        if (nPiesToHandle % serverParams.numberOfThreads != 0)
        {
            throw invalid_argument("Error: Number of Threads does not divide number of PIEs");
        }

        piesPerCollection = nPiesToHandle / serverParams.numberOfThreads;
    }

    void receiveAndSetPublicKey()
    {
        vector<unsigned char> pkVector;
        channel->readWithSizeIntoVector(pkVector);
        shared_ptr<GroupElementSendableData> dummy = dlog.get()->getGenerator().get()->generateSendableData();
        ElGamalPublicKeySendableData pkS(dummy);
        pkS.initFromByteVector(pkVector);
        auto pkP = encryptor.reconstructPublicKey(&pkS);
        encryptor.setKey(pkP);
    }

    AsymmetricCiphertext *receiveMinusCompareElement()
    {
        vector<unsigned char> cipherVector;
        channel->readWithSizeIntoVector(cipherVector);
        return encryptor.reconstructCiphertextPointer(cipherVector, false);
    }

    void sendResult(vector<shared_ptr<AsymmetricCiphertext>> &resultVector)
    {
        for (size_t i = 0; i < resultVector.size(); i++)
        {
            string cipherTextString = resultVector[i]->generateSendableData()->toString();
            channel->writeWithSize(cipherTextString);
        }
    }
};