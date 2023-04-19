/**
 * @file BatchedFHEPSIServer.cpp
 * 
 * @version 0.1
 *
 */
#include "BatchedFHEPSIServer.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

BatchedFHEPSIServer::BatchedFHEPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams)
    : PSIServer(dataIH, serverParams, protocolName()), htParams(htParams)
{
    omp_set_num_threads(serverParams.numberOfThreads);
}

void BatchedFHEPSIServer::receiveAndSetContextAndKeys()
{

    // Dererialize crypto context
    vector<unsigned char> contextVector;
    channel->readWithSizeIntoVector(contextVector);
    auto contextStream = std::istringstream(std::string(contextVector.begin(), contextVector.end()));
    lbcrypto::Serial::Deserialize(cryptoContext, contextStream, defaultSerType);

#ifdef VERBOSE
    std::cout << "The cryptocontext has been deserialized. Size:" << contextVector.size() << std::endl;
#endif

    // Deserialize public key
    vector<unsigned char> pkVector;
    channel->readWithSizeIntoVector(pkVector);
    auto pKStream = std::istringstream(std::string(pkVector.begin(), pkVector.end()));
    lbcrypto::Serial::Deserialize(pK, pKStream, defaultSerType);

#ifdef VERBOSE
    std::cout << "The public key has been deserialized. Size:" << pkVector.size() << std::endl;
#endif

    // Deserialize Mult Keys

    vector<unsigned char> mKVector;
    channel->readWithSizeIntoVector(mKVector);
    auto mKStream = std::istringstream(std::string(mKVector.begin(), mKVector.end()));
    cryptoContext->DeserializeEvalMultKey(mKStream, defaultSerType);

#ifdef VERBOSE
    std::cout << "The mult key has been deserialized. Size:" << pkVector.size() << std::endl;
#endif
}

void BatchedFHEPSIServer::runSetUpPhase()
{

    uint64_t neededHfs = htParams.numberOfSimpleHashFunctions + htParams.numberOfCuckooHashFunctions;
    hashfunction = TabulationHashing(serverParams.hashSeed, neededHfs);

    if (serverParams.numberOfThreads < 1)
    {
        throw invalid_argument("Number of threads need to be larger than 0");
    }

    receiveAndSetContextAndKeys();

    serverHashTable = make_shared<HierarchicalCuckooHashTable>(hashfunction,
                                                               htParams.eachSimpleTableSize, htParams.eachCuckooTableSize,
                                                               htParams.serverStashSize, htParams.numberOfSimpleHashFunctions,
                                                               htParams.numberOfCuckooHashFunctions, htParams.simpleMultiTable,
                                                               htParams.cuckooMultiTable, htParams.maxItemsPerPosition);
}
void BatchedFHEPSIServer::runOfflinePhase()
{
    chrono::steady_clock::time_point end;
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();

    // Insert Elements into Cuckoo table
    serverHashTable->insertAll(serverSet);

    /** Build PIE (WARNING currently need to do this after the cuckoo table has been inserted with items
     * because of item type conversion during PIE creation)
     */
    batchedEqualityTest = make_shared<BatchedFHEHIPPIE>(cryptoContext, pK, (*serverHashTable.get()));

    end = chrono::steady_clock::now();
    offlineComputation = chrono::duration_cast<chrono::microseconds>(end - begin).count();
}

void BatchedFHEPSIServer::runOnlinePhase()
{
    auto encMinEl = receiveEncryptedMinusElements();
    auto indMatrix = receiveIndexMatrix();


    chrono::steady_clock::time_point end;
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    
    batchedEqualityTest->setMinusCompareElement(encMinEl);
    batchedEqualityTest->setIndex(std::move(indMatrix));
    batchedEqualityTest->run();

    end = chrono::steady_clock::now();
    onlineComputation = chrono::duration_cast<chrono::microseconds>(end - begin).count();

    sendResult(batchedEqualityTest->getResultList());
    if (serverParams.exportPerformance) {
        exportMeasurements();
    }
}

lbcrypto::Ciphertext<FHEEncType> BatchedFHEPSIServer::receiveEncryptedMinusElements()
{
    lbcrypto::Ciphertext<FHEEncType> encryptedMinusElements;
    vector<unsigned char> cipherVector;
    channel->readWithSizeIntoVector(cipherVector);
    auto ctSS = std::istringstream(std::string(cipherVector.begin(), cipherVector.end()));
    lbcrypto::Serial::Deserialize(encryptedMinusElements, ctSS, defaultSerType);
    return encryptedMinusElements;
}

vector<vector<lbcrypto::Ciphertext<FHEEncType>>> BatchedFHEPSIServer::receiveIndexMatrix()
{
    vector<vector<lbcrypto::Ciphertext<FHEEncType>>> indexMatrix(htParams.numberOfCuckooHashFunctions,
                                                                 vector<lbcrypto::Ciphertext<FHEEncType>>(htParams.eachCuckooTableSize));
    for (uint outerIndex = 0; outerIndex < htParams.numberOfCuckooHashFunctions; outerIndex++)
    {
        for (size_t innerIndex = 0; innerIndex < htParams.eachCuckooTableSize; innerIndex++)
        {
            lbcrypto::Ciphertext<FHEEncType> ciphertext;
            vector<unsigned char> cipherVector;
            channel->readWithSizeIntoVector(cipherVector);
            auto ctSS = std::istringstream(std::string(cipherVector.begin(), cipherVector.end()));
            lbcrypto::Serial::Deserialize(ciphertext, ctSS, defaultSerType);
            indexMatrix[outerIndex][innerIndex] = ciphertext;
        }
    }
    return indexMatrix;
}

void BatchedFHEPSIServer::sendResult(vector<lbcrypto::Ciphertext<FHEEncType>> &resultVector)
{

    for (size_t i = 0; i < resultVector.size(); i++)
    {
        auto cSerStream = std::ostringstream();
        lbcrypto::Serial::Serialize(resultVector[i], cSerStream, defaultSerType);
        channel->writeWithSize(cSerStream.str());
    }
}
